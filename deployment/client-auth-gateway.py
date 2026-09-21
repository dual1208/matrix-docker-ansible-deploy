#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Release-certificate-gated native login gateway."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DATABASE = os.environ.get("CLIENT_AUTH_DATABASE", "/data/client-auth.sqlite3")
MAS_BASE_URL = os.environ.get(
    "CLIENT_AUTH_MAS_BASE_URL", "http://matrix-authentication-service:8080/auth"
).rstrip("/")
MAX_LOGIN_BODY = 8_192
LOCALPART = re.compile(r"^[0-9a-z._=-]{1,64}$")
MATRIX_DOMAIN = os.environ.get("CLIENT_AUTH_MATRIX_DOMAIN", "8.163.2.191")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


UPSTREAM = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    NoRedirect(),
)


def matrix_error(status: int, errcode: str, message: str, **extra: object) -> tuple[int, dict]:
    return status, {"errcode": errcode, "error": message, **extra}


class Gateway(BaseHTTPRequestHandler):
    server_version = "FamilyClientAuth/1"
    sys_version = ""

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def send_json(self, status: int, document: dict) -> None:
        payload = json.dumps(document, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def read_body(self, maximum: int) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise ValueError("Invalid Content-Length") from error
        if not 1 <= length <= maximum:
            raise ValueError("Request body has an invalid size")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("Request body ended early")
        return body

    def release_identity(self) -> tuple[str, str] | None:
        forwarded = self.headers.get("X-Forwarded-Tls-Client-Cert")
        if not forwarded:
            return None
        leaf = forwarded.split(",", 1)[0]
        try:
            der = base64.b64decode(leaf, validate=True)
        except (ValueError, base64.binascii.Error):
            return None
        if not der or len(der) > 16_384:
            return None
        fingerprint = hashlib.sha256(der).hexdigest()
        with sqlite3.connect(DATABASE) as connection:
            row = connection.execute(
                """SELECT release_id FROM release_certificates
                   WHERE fingerprint_sha256=? AND enabled=1 AND revoked_at IS NULL
                     AND not_after_epoch>?""",
                (fingerprint, int(time.time())),
            ).fetchone()
        return (fingerprint, row[0]) if row else None

    def consume_bucket(self, key: str, burst: float, per_second: float) -> tuple[bool, int]:
        now = time.time()
        with sqlite3.connect(DATABASE, timeout=5) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT tokens, updated_at FROM rate_buckets WHERE bucket_key=?", (key,)
            ).fetchone()
            tokens = burst if row is None else min(burst, row[0] + (now - row[1]) * per_second)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            connection.execute(
                """INSERT INTO rate_buckets (bucket_key, tokens, updated_at) VALUES (?, ?, ?)
                   ON CONFLICT(bucket_key) DO UPDATE SET tokens=excluded.tokens,
                     updated_at=excluded.updated_at""",
                (key, tokens, now),
            )
        retry_ms = 0 if allowed else max(1_000, int((1.0 - tokens) / per_second * 1_000))
        return allowed, retry_ms

    def proxy_json(self, path: str, document: dict) -> tuple[int, dict]:
        request = urllib.request.Request(
            MAS_BASE_URL + path,
            data=json.dumps(document, separators=(",", ":")).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self.perform_upstream(request)

    @staticmethod
    def perform_upstream(request: urllib.request.Request) -> tuple[int, dict]:
        try:
            with UPSTREAM.open(request, timeout=15) as response:
                payload = response.read(65_537)
                if len(payload) > 65_536:
                    raise ValueError("Upstream response too large")
                document = json.loads(payload)
                if not isinstance(document, dict):
                    raise ValueError("Upstream response is not an object")
                return response.status, document
        except urllib.error.HTTPError as error:
            payload = error.read(65_537)
            try:
                document = json.loads(payload) if len(payload) <= 65_536 else {}
            except (ValueError, TypeError):
                document = {}
            if error.code in {400, 401, 403, 429} and isinstance(document, dict):
                safe = {
                    key: value
                    for key, value in document.items()
                    if key
                    in {
                        "errcode",
                        "error",
                        "retry_after_ms",
                    }
                }
                if safe.get("errcode"):
                    return error.code, safe
            status, document = matrix_error(
                503, "M_UNAVAILABLE", "Authentication service unavailable"
            )
            return status, document
        except (OSError, TimeoutError, ValueError, json.JSONDecodeError):
            status, document = matrix_error(
                503, "M_UNAVAILABLE", "Authentication service unavailable"
            )
            return status, document

    def login(self) -> tuple[int, dict]:
        identity = self.release_identity()
        if identity is None:
            return matrix_error(403, "M_RELEASE_NOT_ALLOWED", "Release is not allowed")
        try:
            document = json.loads(self.read_body(MAX_LOGIN_BODY))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return matrix_error(400, "M_BAD_JSON", "Malformed login request")
        if not isinstance(document, dict) or set(document) != {
            "username",
            "password",
            "initial_device_display_name",
        }:
            return matrix_error(400, "M_BAD_JSON", "Malformed login request")
        username = document.get("username")
        password = document.get("password")
        display_name = document.get("initial_device_display_name")
        if (
            not isinstance(username, str)
            or not LOCALPART.fullmatch(username)
            or not isinstance(password, str)
            or not 1 <= len(password) <= 1_024
            or not isinstance(display_name, str)
            or not 1 <= len(display_name) <= 128
        ):
            return matrix_error(400, "M_BAD_JSON", "Malformed login request")
        fingerprint, _release_id = identity
        account_key = hashlib.sha256(username.encode()).hexdigest()
        for key, burst, rate in (
            (f"release:{fingerprint}", 10.0, 1.0 / 30.0),
            (f"account:{account_key}", 5.0, 1.0 / 300.0),
        ):
            allowed, retry_ms = self.consume_bucket(key, burst, rate)
            if not allowed:
                return matrix_error(
                    429,
                    "M_LIMIT_EXCEEDED",
                    "Too many login attempts",
                    retry_after_ms=retry_ms,
                )
        status, response = self.proxy_json(
            "/_matrix/client/v3/login",
            {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": username},
                "password": password,
                "initial_device_display_name": display_name,
                "refresh_token": False,
            },
        )
        if status != 200:
            return status, response
        if not isinstance(response, dict):
            return matrix_error(503, "M_UNAVAILABLE", "Authentication service unavailable")
        expected = (response.get("access_token"), response.get("user_id"), response.get("device_id"))
        if not all(isinstance(value, str) and value for value in expected):
            return matrix_error(503, "M_UNAVAILABLE", "Authentication service unavailable")
        if expected[1] != f"@{username}:{MATRIX_DOMAIN}":
            return matrix_error(503, "M_UNAVAILABLE", "Authentication service unavailable")
        return 200, dict(zip(("access_token", "user_id", "device_id"), expected, strict=True))

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(
                403,
                {"errcode": "M_AUTH_ROUTE_DISABLED", "error": "Route disabled"},
            )

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/client-auth/login":
            status, document = self.login()
        else:
            status, document = matrix_error(
                403, "M_AUTH_ROUTE_DISABLED", "Route disabled"
            )
        self.send_json(status, document)


if __name__ == "__main__":
    os.umask(0o077)
    ThreadingHTTPServer(("0.0.0.0", 8080), Gateway).serve_forever()
