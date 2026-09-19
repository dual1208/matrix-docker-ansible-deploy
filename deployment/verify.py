#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify the deployed IP certificate, Matrix discovery, MAS, and RTC endpoints."""

import json
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

HOST = "8.163.2.191"
BASE = f"https://{HOST}"


def read_json(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=20) as response:
        assert response.status == 200, (path, response.status)
        return json.load(response)


def check_tls(port: int) -> dict:
    with socket.create_connection((HOST, port), timeout=15) as tcp:
        with ssl.create_default_context().wrap_socket(tcp, server_hostname=HOST) as tls:
            cert = tls.getpeercert()
            assert ("IP Address", HOST) in cert["subjectAltName"], cert["subjectAltName"]
            expires = ssl.cert_time_to_seconds(cert["notAfter"])
            assert expires - time.time() > 86400, "IP certificate expires within one day"
            return {"port": port, "protocol": tls.version(), "expires": cert["notAfter"]}


def check_turn_udp() -> dict:
    transaction = secrets.token_bytes(12)
    request = struct.pack("!HHI", 0x0001, 0, 0x2112A442) + transaction
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(10)
        udp.sendto(request, (HOST, 3479))
        response, source = udp.recvfrom(2048)
    assert source[0] == HOST and response[8:20] == transaction
    message_type, length, cookie = struct.unpack("!HHI", response[:8])
    assert cookie == 0x2112A442 and len(response) >= 20 + length
    assert message_type == 0x0101, f"STUN binding failed: {message_type:#x}"
    return {"port": 3479, "binding": "success"}


def check_discovery() -> dict:
    discovery = read_json("/.well-known/matrix/client")
    assert discovery["m.homeserver"]["base_url"].rstrip("/") == BASE
    assert discovery["org.matrix.msc4143.rtc_foci"][0]["type"] == "livekit"
    return discovery


def check_versions() -> dict:
    versions = read_json("/_matrix/client/versions")
    assert "v1.11" in versions["versions"]
    return {"versions": versions["versions"]}


def check_oidc() -> dict:
    oidc = read_json("/auth/.well-known/openid-configuration")
    assert oidc["issuer"] == BASE + "/auth/"
    assert "S256" in oidc["code_challenge_methods_supported"]
    return {"issuer": oidc["issuer"], "pkce": "S256"}


def check_rtc_auth() -> dict:
    with urllib.request.urlopen(BASE + "/livekit-jwt-service/healthz", timeout=15) as response:
        assert response.status == 200
        return {"status": response.status}


def check_rtc_tcp() -> dict:
    with socket.create_connection((HOST, 7881), timeout=15):
        return {"port": 7881}


def run_check(check: tuple[str, Callable[[], dict]]) -> dict:
    name, operation = check
    try:
        return {"name": name, "passed": True, "result": operation()}
    except Exception as error:
        return {"name": name, "passed": False, "error": f"{type(error).__name__}: {error}"}


def main() -> None:
    operations = [
        ("matrix_tls", lambda: check_tls(443)),
        ("turn_tls", lambda: check_tls(5350)),
        ("openid_tls", lambda: check_tls(8448)),
        ("existing_service_tls", lambda: check_tls(2357)),
        ("discovery", check_discovery),
        ("matrix_versions", check_versions),
        ("oidc", check_oidc),
        ("rtc_auth", check_rtc_auth),
        ("turn_udp", check_turn_udp),
        ("rtc_tcp", check_rtc_tcp),
    ]
    with ThreadPoolExecutor(max_workers=4) as executor:
        checks = list(executor.map(run_check, operations))
    passed = all(check["passed"] for check in checks)
    print(json.dumps({"host": HOST, "checks": checks, "passed": passed}, indent=2))
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
