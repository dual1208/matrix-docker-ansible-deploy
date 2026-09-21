#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Allow ordinary members to publish their MatrixRTC membership state."""

from __future__ import annotations

import argparse
import copy
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


CALL_MEMBER_EVENT_LEVELS = {
    "m.call.member": 0,
    "org.matrix.msc3401.call.member": 0,
}


class RepairError(RuntimeError):
    """A safe-to-report error which never contains credentials."""


@dataclass
class TemporarySession:
    localpart: str
    access_token: str
    device_id: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--homeserver-url", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--rooms-json", required=True)
    parser.add_argument("--probe-room-key", default="development")
    parser.add_argument("--probe-localpart", default="tcnowifi")
    parser.add_argument(
        "--mas-cli",
        default="/matrix/matrix-authentication-service/bin/mas-cli",
    )
    return parser.parse_args()


class Repairer:
    def __init__(self, args: argparse.Namespace) -> None:
        self.base_url = args.homeserver_url.rstrip("/")
        self.domain = args.domain
        self.rooms = json.loads(args.rooms_json)
        self.probe_room_key = args.probe_room_key
        self.probe_localpart = args.probe_localpart
        self.mas_cli = args.mas_cli
        self.context = ssl.create_default_context()
        if not isinstance(self.rooms, list) or not self.rooms:
            raise RepairError("Managed room configuration is empty")
        if len({room.get("key") for room in self.rooms}) != len(self.rooms):
            raise RepairError("Managed room keys are not unique")

    def mxid(self, localpart: str) -> str:
        return f"@{localpart}:{self.domain}"

    @staticmethod
    def encoded(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    def issue_session(self, localpart: str) -> TemporarySession:
        device_id = "CALL_POWER_REPAIR_" + secrets.token_hex(10).upper()
        process = subprocess.run(
            [
                self.mas_cli,
                "manage",
                "issue-compatibility-token",
                localpart,
                device_id,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if process.returncode != 0:
            raise RepairError(f"MAS refused a temporary session for {localpart}")
        match = re.search(
            r"Compatibility token issued:\s*(\S+)",
            process.stdout + "\n" + process.stderr,
        )
        if not match:
            raise RepairError(f"Could not parse the temporary MAS session for {localpart}")
        return TemporarySession(localpart, match.group(1), device_id)

    def request(
        self,
        session: TemporarySession,
        method: str,
        path: str,
        body: dict | None = None,
        expected_statuses: tuple[int, ...] = (200,),
    ) -> tuple[int, dict]:
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
                    raise RepairError(f"Unexpected HTTP {response.status} for {method} {path}")
                return response.status, document
        except urllib.error.HTTPError as error:
            if error.code in expected_statuses:
                return error.code, {}
            raise RepairError(f"HTTP {error.code} for {method} {path}") from None
        except urllib.error.URLError as error:
            raise RepairError(f"Connection failed for {method} {path}: {error.reason}") from None

    def revoke_session(self, session: TemporarySession) -> None:
        self.request(session, "POST", "/_matrix/client/v3/logout", {})
        for delay in (0.0, 0.25, 0.5, 1.0, 2.0, 2.0, 2.0):
            if delay:
                time.sleep(delay)
            status, _ = self.request(
                session,
                "GET",
                "/_matrix/client/v3/account/whoami",
                expected_statuses=(200, 401),
            )
            if status == 401:
                return
        raise RepairError(f"Temporary session remained usable for {session.localpart}")

    def with_session(self, localpart: str, operation):
        session = self.issue_session(localpart)
        operation_error = None
        result = None
        try:
            result = operation(session)
        except Exception as error:  # Preserve cleanup while reporting only safe errors below.
            operation_error = error
        try:
            self.revoke_session(session)
        except RepairError as error:
            raise error from operation_error
        if operation_error is not None:
            raise operation_error
        return result

    def power_levels_path(self, room_id: str) -> str:
        return (
            f"/_matrix/client/v3/rooms/{self.encoded(room_id)}/state/"
            "m.room.power_levels/"
        )

    def get_power_levels(self, session: TemporarySession, room_id: str) -> dict:
        content = self.request(session, "GET", self.power_levels_path(room_id))[1]
        if not isinstance(content, dict):
            raise RepairError("Power-level content is not an object")
        events = content.get("events", {})
        users = content.get("users", {})
        if not isinstance(events, dict) or not isinstance(users, dict):
            raise RepairError("Power-level users or events map is invalid")
        return content

    def owner_can_repair(
        self,
        content: dict,
        owner_localpart: str,
        owner_is_v12_creator: bool,
    ) -> bool:
        # Room version 12 creators have implicit creator power and therefore do
        # not need an entry in m.room.power_levels.content.users.
        if owner_is_v12_creator:
            return True
        owner_level = content.get("users", {}).get(
            self.mxid(owner_localpart), content.get("users_default", 0)
        )
        required_level = content.get("events", {}).get(
            "m.room.power_levels", content.get("state_default", 50)
        )
        return (
            isinstance(owner_level, int)
            and isinstance(required_level, int)
            and owner_level >= required_level
        )

    def owner_is_v12_creator(
        self,
        session: TemporarySession,
        room_id: str,
        owner_localpart: str,
    ) -> bool:
        path = f"/_matrix/client/v3/rooms/{self.encoded(room_id)}/state"
        state = self.request(session, "GET", path)[1]
        if not isinstance(state, list):
            raise RepairError("Room state is not an array")
        create_events = [
            event
            for event in state
            if event.get("type") == "m.room.create" and event.get("state_key") == ""
        ]
        if len(create_events) != 1:
            raise RepairError("Room does not have exactly one creation event")
        create = create_events[0]
        return (
            create.get("sender") == self.mxid(owner_localpart)
            and create.get("content", {}).get("room_version") == "12"
        )

    @staticmethod
    def call_events_allowed(content: dict) -> bool:
        events = content.get("events", {})
        return all(
            events.get(event_type) == level
            for event_type, level in CALL_MEMBER_EVENT_LEVELS.items()
        )

    def repair_room(self, room: dict) -> dict:
        room_id = room.get("room_id", "")
        owner = room.get("owner_localpart", "")
        key = room.get("key", "")
        if not room_id or not owner or not key:
            raise RepairError("Managed room entry is incomplete")

        def operation(session: TemporarySession) -> dict:
            before = self.get_power_levels(session, room_id)
            owner_is_v12_creator = self.owner_is_v12_creator(session, room_id, owner)
            if not self.owner_can_repair(before, owner, owner_is_v12_creator):
                raise RepairError(f"Configured owner cannot update power levels for {key}")
            desired = copy.deepcopy(before)
            desired_events = dict(desired.get("events", {}))
            desired_events.update(CALL_MEMBER_EVENT_LEVELS)
            desired["events"] = desired_events
            changed = desired != before
            if changed:
                self.request(session, "PUT", self.power_levels_path(room_id), desired)
            after = self.get_power_levels(session, room_id)
            if after != desired:
                raise RepairError(f"Power-level verification failed for {key}")
            if not self.call_events_allowed(after):
                raise RepairError(f"Call membership remains blocked for {key}")
            return {"key": key, "room_id": room_id, "changed": changed}

        return self.with_session(owner, operation)

    def probe_path(self, room_id: str, localpart: str) -> str:
        state_key = f"_@{localpart}:{self.domain}_SERVER_PROBE_m.call"
        return (
            f"/_matrix/client/v3/rooms/{self.encoded(room_id)}/state/"
            f"{self.encoded('org.matrix.msc3401.call.member')}/{self.encoded(state_key)}"
        )

    def probe(self, room: dict, localpart: str, expected_status: int) -> int:
        room_id = room["room_id"]

        def operation(session: TemporarySession) -> int:
            status, _ = self.request(
                session,
                "PUT",
                self.probe_path(room_id, localpart),
                {"m.calls": []},
                expected_statuses=(expected_status,),
            )
            return status

        return self.with_session(localpart, operation)

    def run(self) -> dict:
        probe_rooms = [room for room in self.rooms if room.get("key") == self.probe_room_key]
        if len(probe_rooms) != 1:
            raise RepairError("Expected exactly one isolated probe room")
        probe_room = probe_rooms[0]
        if probe_room.get("owner_localpart") != "api30":
            raise RepairError("The isolated probe room must be owned by api30")
        if self.probe_localpart == probe_room.get("owner_localpart"):
            raise RepairError("The isolated probe user must not own the room")
        if self.probe_localpart not in probe_room.get("member_localparts", []):
            raise RepairError("The isolated probe user must already be a room member")

        def read_probe_levels(session: TemporarySession) -> dict:
            return self.get_power_levels(session, probe_room["room_id"])

        before_probe_levels = self.with_session(self.probe_localpart, read_probe_levels)
        red_status = None
        if not self.call_events_allowed(before_probe_levels):
            red_status = self.probe(probe_room, self.probe_localpart, 403)

        results = [self.repair_room(room) for room in self.rooms]
        green_status = self.probe(probe_room, self.probe_localpart, 200)
        return {
            "changed": any(result["changed"] for result in results),
            "red_probe_status": red_status,
            "green_probe_status": green_status,
            "rooms": results,
            "temporary_sessions_revoked": True,
        }


def main() -> None:
    try:
        result = Repairer(parse_args()).run()
    except (RepairError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        raise SystemExit(1) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
