# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline regression tests for guarded Family room provisioning."""

import argparse
import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("provision-room.py")
SPEC = importlib.util.spec_from_file_location("provision_room", MODULE_PATH)
assert SPEC and SPEC.loader
provision_room = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provision_room)


class FakeProvisioner(provision_room.Provisioner):
    def __init__(self, *, encrypted: bool = False) -> None:
        super().__init__(
            argparse.Namespace(
                homeserver_url="https://example.com",
                domain="example.com",
                name="Family",
                owner="owner",
                members="owner,member",
                display_names="{}",
                room_id="!family:example.com",
                mas_cli="mas-cli",
            )
        )
        self.encrypted = encrypted
        self.mutations: list[str] = []

    def issue_session(self, localpart: str):
        return provision_room.TemporarySession(localpart, f"token-{localpart}", f"device-{localpart}")

    def room_state(self, localpart: str, room_id: str) -> list[dict]:
        events = [
            {
                "type": "m.room.create",
                "state_key": "",
                "sender": "@owner:example.com",
                "content": {"m.federate": False},
            },
            {"type": "m.room.name", "state_key": "", "content": {"name": "Family"}},
            {
                "type": "m.room.history_visibility",
                "state_key": "",
                "content": {"history_visibility": "shared"},
            },
            {"type": "m.room.guest_access", "state_key": "", "content": {"guest_access": "forbidden"}},
            {"type": "m.room.join_rules", "state_key": "", "content": {"join_rule": "invite"}},
            {"type": "m.room.member", "state_key": "@owner:example.com", "content": {"membership": "join"}},
            {"type": "m.room.member", "state_key": "@member:example.com", "content": {"membership": "left"}},
        ]
        if self.encrypted:
            events.append(
                {
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": {"algorithm": "m.megolm.v1.aes-sha2"},
                }
            )
        return events

    def request(self, localpart, method, path, body=None, expected_statuses=(200,)):
        if method == "GET" and "/directory/list/room/" in path:
            return 200, {"visibility": "private"}
        if method == "POST":
            self.mutations.append(path)
            return 200, {}
        raise AssertionError(f"Unexpected request: {method} {path}")


class ProvisionerGuardTests(unittest.TestCase):
    def test_insecure_room_is_not_mutated(self) -> None:
        provisioner = FakeProvisioner(encrypted=True)

        with self.assertRaisesRegex(provision_room.ProvisionError, "unencrypted"):
            provisioner.run()

        self.assertEqual(provisioner.mutations, [])

if __name__ == "__main__":
    unittest.main()
