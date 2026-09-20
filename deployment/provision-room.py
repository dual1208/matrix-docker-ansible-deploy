#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Provision and verify one private encrypted Matrix room using temporary MAS sessions."""

import argparse
import json
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


class ProvisionError(RuntimeError):
    """A safe-to-report provisioning failure which contains no credentials."""


@dataclass
class TemporarySession:
    localpart: str
    access_token: str
    device_id: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--homeserver-url", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--members", required=True, help="Comma-separated localparts")
    parser.add_argument("--room-id", default="")
    parser.add_argument(
        "--mas-cli",
        default="/matrix/matrix-authentication-service/bin/mas-cli",
    )
    return parser.parse_args()


class Provisioner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.base_url = args.homeserver_url.rstrip("/")
        self.domain = args.domain
        self.name = args.name
        self.owner = args.owner
        self.members = list(dict.fromkeys([args.owner, *args.members.split(",")]))
        self.expected_room_id = args.room_id
        self.mas_cli = args.mas_cli
        self.context = ssl.create_default_context()
        self.sessions: dict[str, TemporarySession] = {}

    def mxid(self, localpart: str) -> str:
        return f"@{localpart}:{self.domain}"

    def issue_session(self, localpart: str) -> TemporarySession:
        device_id = "ROOM_PROVISION_" + secrets.token_hex(10).upper()
        process = subprocess.run(
            [self.mas_cli, "manage", "issue-compatibility-token", localpart, device_id],
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            raise ProvisionError(f"MAS refused a temporary session for {localpart}")
        match = re.search(
            r"Compatibility token issued:\s*(\S+)",
            process.stdout + "\n" + process.stderr,
        )
        if not match:
            raise ProvisionError(f"Could not parse the temporary MAS session for {localpart}")
        return TemporarySession(localpart, match.group(1), device_id)

    def request(
        self,
        localpart: str,
        method: str,
        path: str,
        body: dict | None = None,
        expected_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict]:
        session = self.sessions[localpart]
        headers = {"Authorization": f"Bearer {session.access_token}"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                response_body = response.read()
                document = json.loads(response_body) if response_body else {}
                if response.status not in expected_statuses:
                    raise ProvisionError(f"Unexpected HTTP {response.status} for {method} {path}")
                return response.status, document
        except urllib.error.HTTPError as error:
            if error.code in expected_statuses:
                return error.code, {}
            raise ProvisionError(f"HTTP {error.code} for {method} {path}") from None
        except urllib.error.URLError as error:
            raise ProvisionError(f"Connection failed for {method} {path}: {error.reason}") from None

    @staticmethod
    def encoded_room_id(room_id: str) -> str:
        return urllib.parse.quote(room_id, safe="")

    def room_state(self, localpart: str, room_id: str) -> list[dict]:
        encoded = self.encoded_room_id(room_id)
        return self.request(localpart, "GET", f"/_matrix/client/v3/rooms/{encoded}/state")[1]

    @staticmethod
    def state_map(events: list[dict]) -> dict[tuple[str, str], dict]:
        return {(event.get("type", ""), event.get("state_key", "")): event for event in events}

    def discover_room(self) -> str:
        rooms = self.request(self.owner, "GET", "/_matrix/client/v3/joined_rooms")[1].get(
            "joined_rooms", []
        )
        matches = []
        for room_id in rooms:
            state = self.state_map(self.room_state(self.owner, room_id))
            if state.get(("m.room.name", ""), {}).get("content", {}).get("name") == self.name:
                matches.append(room_id)
        if len(matches) > 1:
            raise ProvisionError(f"Multiple rooms named {self.name!r} are joined by the owner")
        return matches[0] if matches else ""

    def create_room(self) -> str:
        invitees = [self.mxid(member) for member in self.members if member != self.owner]
        body = {
            "name": self.name,
            "preset": "private_chat",
            "visibility": "private",
            "is_direct": False,
            "invite": invitees,
            "creation_content": {"m.federate": False},
            "initial_state": [
                {
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": {"algorithm": "m.megolm.v1.aes-sha2"},
                },
                {
                    "type": "m.room.history_visibility",
                    "state_key": "",
                    "content": {"history_visibility": "shared"},
                },
                {
                    "type": "m.room.guest_access",
                    "state_key": "",
                    "content": {"guest_access": "forbidden"},
                },
                {
                    "type": "m.room.join_rules",
                    "state_key": "",
                    "content": {"join_rule": "invite"},
                },
            ],
        }
        document = self.request(self.owner, "POST", "/_matrix/client/v3/createRoom", body)[1]
        room_id = document.get("room_id", "")
        if not room_id:
            raise ProvisionError("Room creation returned no room ID")
        return room_id

    def ensure_membership(self, room_id: str) -> bool:
        changed = False
        encoded = self.encoded_room_id(room_id)
        state = self.state_map(self.room_state(self.owner, room_id))
        for member in self.members:
            if member == self.owner:
                continue
            mxid = self.mxid(member)
            membership = state.get(("m.room.member", mxid), {}).get("content", {}).get("membership")
            if membership == "join":
                continue
            if membership != "invite":
                self.request(
                    self.owner,
                    "POST",
                    f"/_matrix/client/v3/rooms/{encoded}/invite",
                    {"user_id": mxid},
                )
                changed = True
            self.request(member, "POST", f"/_matrix/client/v3/join/{encoded}", {})
            changed = True
        return changed

    def verify_room(self, room_id: str, *, require_empty: bool = False) -> dict[str, bool]:
        state = self.state_map(self.room_state(self.owner, room_id))
        content = lambda event_type: state.get((event_type, ""), {}).get("content", {})
        memberships = {
            key[1]: event.get("content", {}).get("membership")
            for key, event in state.items()
            if key[0] == "m.room.member"
        }
        expected_members = {self.mxid(member) for member in self.members}
        active_members = {
            mxid
            for mxid, membership in memberships.items()
            if membership in {"invite", "join", "knock"}
        }
        create = state.get(("m.room.create", ""), {})
        encoded = self.encoded_room_id(room_id)
        visibility = self.request(
            self.owner, "GET", f"/_matrix/client/v3/directory/list/room/{encoded}"
        )[1].get("visibility")
        checks = {
            "name": content("m.room.name").get("name") == self.name,
            "owner": create.get("sender") == self.mxid(self.owner),
            "federate_disabled": create.get("content", {}).get("m.federate") is False,
            "encrypted": content("m.room.encryption").get("algorithm")
            == "m.megolm.v1.aes-sha2",
            "shared_history": content("m.room.history_visibility").get("history_visibility")
            == "shared",
            "guests_forbidden": content("m.room.guest_access").get("guest_access")
            == "forbidden",
            "invite_only": content("m.room.join_rules").get("join_rule") == "invite",
            "private_directory": visibility == "private",
            "expected_members_joined": all(
                memberships.get(mxid) == "join" for mxid in expected_members
            ),
            "only_expected_members": active_members == expected_members,
        }
        if require_empty:
            messages = self.request(
                self.owner,
                "GET",
                f"/_matrix/client/v3/rooms/{encoded}/messages?dir=b&limit=20",
            )[1].get("chunk", [])
            checks["no_messages"] = not any(
                event.get("type") in {"m.room.message", "m.room.encrypted"} for event in messages
            )
        failed = [name for name, passed in checks.items() if not passed]
        if failed:
            raise ProvisionError("Room verification failed: " + ", ".join(failed))
        return checks

    def revoke_sessions(self) -> list[str]:
        failures = []
        for localpart in reversed(list(self.sessions)):
            try:
                self.request(localpart, "POST", "/_matrix/client/v3/logout", {})
                for delay in (0.0, 0.25, 0.5, 1.0, 2.0, 2.0, 2.0):
                    if delay:
                        time.sleep(delay)
                    status, _ = self.request(
                        localpart,
                        "GET",
                        "/_matrix/client/v3/account/whoami",
                        expected_statuses=(200, 401),
                    )
                    if status == 401:
                        break
                else:
                    raise ProvisionError("Temporary session remained usable after logout")
            except ProvisionError:
                failures.append(localpart)
        return failures

    def run(self) -> dict:
        for localpart in self.members:
            self.sessions[localpart] = self.issue_session(localpart)

        room_id = self.expected_room_id or self.discover_room()
        action = "verified"
        changed = False
        created = not room_id
        if created:
            room_id = self.create_room()
            action = "created"
            changed = True
        elif self.expected_room_id and room_id != self.expected_room_id:
            raise ProvisionError("Discovered room does not match the configured room ID")

        membership_changed = self.ensure_membership(room_id)
        if membership_changed and action == "verified":
            action = "membership-repaired"
        changed = changed or membership_changed
        checks = self.verify_room(room_id, require_empty=created)
        return {"action": action, "changed": changed, "checks": checks, "room_id": room_id}


def main() -> None:
    provisioner = Provisioner(parse_args())
    result = None
    error = None
    try:
        result = provisioner.run()
    except (ProvisionError, ValueError) as caught:
        error = str(caught)
    finally:
        failures = provisioner.revoke_sessions()

    if failures:
        print(json.dumps({"error": "Temporary session revocation failed", "users": failures}))
        sys.exit(1)
    if error:
        print(json.dumps({"error": error}))
        sys.exit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
