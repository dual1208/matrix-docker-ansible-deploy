#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Issue and revoke release-scoped client identities without printing keys."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import shutil
import sqlite3
import ssl
import subprocess
from email.utils import parsedate_to_datetime
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS release_certificates (
  fingerprint_sha256 TEXT PRIMARY KEY,
  serial_hex TEXT NOT NULL UNIQUE,
  platform TEXT NOT NULL CHECK (platform IN ('android', 'ios')),
  release_id TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  not_after TEXT NOT NULL,
  not_after_epoch INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket_key TEXT PRIMARY KEY,
  tokens REAL NOT NULL,
  updated_at REAL NOT NULL
);
"""


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/matrix/client-auth")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init-ca")
    issue = commands.add_parser("issue")
    issue.add_argument("--platform", choices=("android", "ios"), required=True)
    issue.add_argument("--release-id", required=True)
    issue.add_argument("--days", type=int, default=365)
    allow = commands.add_parser("allow-cert")
    allow.add_argument("--certificate", required=True)
    allow.add_argument("--platform", choices=("android", "ios"), required=True)
    allow.add_argument("--release-id", required=True)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--fingerprint", required=True)
    commands.add_parser("list")
    return parser.parse_args()


def run(*command: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {Path(command[0]).name}")
    return result.stdout.strip()


def prepare(root: Path) -> tuple[Path, Path, Path]:
    pki = root / "pki"
    exports = root / "exports"
    data = root / "data"
    for directory, mode in ((root, 0o700), (pki, 0o700), (exports, 0o700)):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(mode)
    data.mkdir(parents=True, exist_ok=True)
    data.chmod(0o750)
    database = data / "client-auth.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(SCHEMA)
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(release_certificates)")
        }
        if "not_after_epoch" not in columns:
            connection.execute(
                "ALTER TABLE release_certificates ADD COLUMN not_after_epoch INTEGER NOT NULL DEFAULT 0"
            )
        for fingerprint, not_after in connection.execute(
            "SELECT fingerprint_sha256, not_after FROM release_certificates WHERE not_after_epoch=0"
        ):
            connection.execute(
                "UPDATE release_certificates SET not_after_epoch=? WHERE fingerprint_sha256=?",
                (int(parsedate_to_datetime(not_after).timestamp()), fingerprint),
            )
    database.chmod(0o640)
    try:
        matrix = pwd.getpwnam("matrix")
    except KeyError:
        pass
    else:
        os.chown(data, matrix.pw_uid, matrix.pw_gid)
        os.chown(database, matrix.pw_uid, matrix.pw_gid)
    return pki, exports, database


def init_ca(pki: Path) -> dict:
    key = pki / "ca.key"
    certificate = pki / "ca.pem"
    if key.exists() or certificate.exists():
        if key.is_file() and certificate.is_file():
            return {"action": "existing", "ca_certificate": str(certificate)}
        raise RuntimeError("Partial CA state exists; refusing to overwrite it")
    run(
        "openssl",
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        str(key),
    )
    key.chmod(0o600)
    run(
        "openssl",
        "req",
        "-x509",
        "-new",
        "-sha256",
        "-days",
        "3650",
        "-key",
        str(key),
        "-subj",
        "/CN=Family Chat Client CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-out",
        str(certificate),
    )
    certificate.chmod(0o644)
    return {"action": "created", "ca_certificate": str(certificate)}


def certificate_metadata(certificate: Path) -> tuple[str, str, str, int]:
    pem = certificate.read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    fingerprint = hashlib.sha256(der).hexdigest()
    serial = run("openssl", "x509", "-in", str(certificate), "-noout", "-serial")
    not_after = run("openssl", "x509", "-in", str(certificate), "-noout", "-enddate")
    not_after = not_after.removeprefix("notAfter=")
    not_after_epoch = int(parsedate_to_datetime(not_after).timestamp())
    return fingerprint, serial.removeprefix("serial=").lower(), not_after, not_after_epoch


def register(
    database: Path,
    certificate: Path,
    platform: str,
    release_id: str,
) -> tuple[str, str]:
    fingerprint, serial, not_after, not_after_epoch = certificate_metadata(certificate)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            INSERT INTO release_certificates
              (fingerprint_sha256, serial_hex, platform, release_id, enabled,
               not_after, not_after_epoch)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            """,
            (fingerprint, serial, platform, release_id, not_after, not_after_epoch),
        )
    return fingerprint, serial


def issue(
    pki: Path,
    exports: Path,
    database: Path,
    platform: str,
    release_id: str,
    days: int,
) -> dict:
    if not release_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for character in release_id):
        raise RuntimeError("Release ID contains unsupported characters")
    if not 1 <= days <= 825:
        raise RuntimeError("Certificate lifetime must be between 1 and 825 days")
    with sqlite3.connect(database) as connection:
        existing = connection.execute(
            "SELECT 1 FROM release_certificates WHERE release_id=?",
            (release_id,),
        ).fetchone()
    if existing:
        raise RuntimeError("Release ID already exists, including revoked releases")
    ca_key = pki / "ca.key"
    ca_certificate = pki / "ca.pem"
    if not ca_key.is_file() or not ca_certificate.is_file():
        raise RuntimeError("Client CA is not initialized")
    destination = exports / release_id
    if destination.exists():
        raise RuntimeError("Release export already exists; refusing to replace it")
    destination.mkdir(mode=0o700)
    key = destination / "family-client.key"
    request = destination / "family-client.csr"
    certificate = destination / "family-client.pem"
    bundle = destination / "family-client.p12"
    extensions = destination / "client-auth.ext"
    try:
        run(
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(key),
        )
        key.chmod(0o600)
        run(
            "openssl",
            "req",
            "-new",
            "-sha256",
            "-key",
            str(key),
            "-subj",
            f"/CN={release_id}",
            "-out",
            str(request),
        )
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=critical,clientAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
        )
        extensions.chmod(0o600)
        lock = pki / ".issue.lock"
        with lock.open("w") as lock_file:
            lock.chmod(0o600)
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            run(
                "openssl",
                "x509",
                "-req",
                "-sha256",
                "-days",
                str(days),
                "-in",
                str(request),
                "-CA",
                str(ca_certificate),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-extfile",
                str(extensions),
                "-out",
                str(certificate),
            )
        certificate.chmod(0o600)
        run(
            "openssl",
            "pkcs12",
            "-export",
            "-keypbe",
            "PBE-SHA1-3DES",
            "-certpbe",
            "PBE-SHA1-3DES",
            "-macalg",
            "sha1",
            "-iter",
            "2048",
            "-passout",
            "pass:",
            "-name",
            "family-client",
            "-inkey",
            str(key),
            "-in",
            str(certificate),
            "-certfile",
            str(ca_certificate),
            "-out",
            str(bundle),
        )
        bundle.chmod(0o600)
        shutil.copyfile(ca_certificate, destination / "client-ca.pem")
        (destination / "client-ca.pem").chmod(0o600)
        fingerprint, serial = register(database, certificate, platform, release_id)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return {
        "action": "issued",
        "platform": platform,
        "release_id": release_id,
        "fingerprint_sha256": fingerprint,
        "serial_hex": serial,
        "pkcs12": str(bundle),
        "ca_certificate": str(destination / "client-ca.pem"),
    }


def execute(args: argparse.Namespace) -> None:
    root = Path(args.root)
    pki, exports, database = prepare(root)
    if args.command == "init-ca":
        result = init_ca(pki)
    elif args.command == "issue":
        result = issue(pki, exports, database, args.platform, args.release_id, args.days)
    elif args.command == "allow-cert":
        fingerprint, serial = register(
            database,
            Path(args.certificate),
            args.platform,
            args.release_id,
        )
        result = {
            "action": "allowed",
            "platform": args.platform,
            "release_id": args.release_id,
            "fingerprint_sha256": fingerprint,
            "serial_hex": serial,
        }
    elif args.command == "revoke":
        fingerprint = args.fingerprint.lower().replace(":", "")
        with sqlite3.connect(database) as connection:
            changed = connection.execute(
                """UPDATE release_certificates SET enabled=0, revoked_at=CURRENT_TIMESTAMP
                   WHERE fingerprint_sha256=? AND enabled=1""",
                (fingerprint,),
            ).rowcount
        result = {"action": "revoked" if changed else "unchanged", "fingerprint_sha256": fingerprint}
    else:
        with sqlite3.connect(database) as connection:
            rows = connection.execute(
                """SELECT fingerprint_sha256, serial_hex, platform, release_id,
                          enabled, not_after
                   FROM release_certificates ORDER BY release_id"""
            ).fetchall()
        result = {"releases": [dict(zip(("fingerprint_sha256", "serial_hex", "platform", "release_id", "enabled", "not_after"), row, strict=True)) for row in rows]}
    print(json.dumps(result, sort_keys=True))


def main() -> None:
    os.umask(0o077)
    args = arguments()
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    with (root / ".admin.lock").open("a") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        execute(args)


if __name__ == "__main__":
    main()
