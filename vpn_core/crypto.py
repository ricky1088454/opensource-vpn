"""Encryption helpers for VPN payload transport."""

from __future__ import annotations

import os
from base64 import b64decode, b64encode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_SALT = b"opensource-vpn-salt"
_ITERATIONS = 200_000
_KEY_LENGTH = 32
_NONCE_LENGTH = 12


def derive_key(shared_secret: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=_KEY_LENGTH,
        salt=_SALT,
        iterations=_ITERATIONS,
    )
    return kdf.derive(shared_secret.encode("utf-8"))


def encrypt_message(shared_secret: str, plaintext: bytes) -> str:
    key = derive_key(shared_secret)
    nonce = os.urandom(_NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_message(shared_secret: str, token: str) -> bytes:
    data = b64decode(token.encode("utf-8"))
    nonce = data[:_NONCE_LENGTH]
    ciphertext = data[_NONCE_LENGTH:]
    key = derive_key(shared_secret)
    return AESGCM(key).decrypt(nonce, ciphertext, None)
