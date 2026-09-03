"""Authentication helpers for VPN endpoints."""

from __future__ import annotations

import hmac
import os
from hashlib import pbkdf2_hmac
from typing import Dict, Optional


class Authenticator:
    def __init__(self, users: Optional[Dict[str, str]] = None):
        self._users = users or {}

    @staticmethod
    def hash_password(password: str, *, iterations: int = 200_000) -> str:
        salt = os.urandom(16)
        digest = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"

    def validate(self, username: str, password: str) -> bool:
        expected = self._users.get(username)
        if not expected:
            return False

        try:
            algorithm, iterations, salt_hex, expected_hex = expected.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            actual = pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt_hex),
                int(iterations),
            )
        except (ValueError, TypeError):
            return False

        return hmac.compare_digest(actual.hex(), expected_hex)
