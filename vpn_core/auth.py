"""Authentication helpers for VPN endpoints."""

from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Dict, Optional


class Authenticator:
    def __init__(self, users: Optional[Dict[str, str]] = None):
        self._users = users or {}

    @staticmethod
    def hash_password(password: str) -> str:
        return sha256(password.encode("utf-8")).hexdigest()

    def validate(self, username: str, password: str) -> bool:
        expected = self._users.get(username)
        if not expected:
            return False
        return hmac.compare_digest(expected, self.hash_password(password))
