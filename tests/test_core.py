import tempfile
import unittest
from pathlib import Path

from vpn_core.auth import Authenticator
from vpn_core.config_loader import load_config
from vpn_core.crypto import decrypt_message, encrypt_message
from vpn_core.routing import RoutingTable


class CoreTests(unittest.TestCase):
    def test_encrypt_round_trip(self):
        token = encrypt_message("secret", b"payload")
        self.assertEqual(decrypt_message("secret", token), b"payload")

    def test_authentication(self):
        users = {"alice": Authenticator.hash_password("alice123")}
        auth = Authenticator(users)
        self.assertTrue(auth.validate("alice", "alice123"))
        self.assertFalse(auth.validate("alice", "wrong"))

    def test_routing_table(self):
        routes = RoutingTable()
        routes.add_route("10.8.0.2", "alice")
        self.assertEqual(routes.resolve("10.8.0.2"), "alice")
        routes.remove_route("10.8.0.2")
        self.assertIsNone(routes.resolve("10.8.0.2"))

    def test_json_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"key": "value"}', encoding="utf-8")
            self.assertEqual(load_config(str(path))["key"], "value")


if __name__ == "__main__":
    unittest.main()
