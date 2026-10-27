"""Authenticated encryption for bank identifiers, with versioned local keys.

This is a file-backed key provider, not an HSM. Protect the host and key backups.
"""
import base64
import os
import re
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import canonical, strict_json
from .errors import BridgeError


def new_keyring():
    return {"active": "key1", "keys": {"key1": base64.b64encode(secrets.token_bytes(32)).decode()}}


class Vault:
    def __init__(self, filename="", allow_plaintext=False):
        self.active, self.keys, self.allow_plaintext = None, {}, allow_plaintext
        if not filename:
            return
        path = Path(filename)
        if os.name == "posix" and path.stat().st_mode & 0o077:
            raise ValueError("vault keyring requires owner-only permissions")
        try:
            config = strict_json(path.read_bytes())
            if set(config) != {"active", "keys"} or not isinstance(config["keys"], dict) or not 1 <= len(config["keys"]) <= 32:
                raise ValueError()
            for kid, encoded in config["keys"].items():
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", kid):
                    raise ValueError()
                key = base64.b64decode(encoded, validate=True)
                if len(key) != 32:
                    raise ValueError()
                self.keys[kid] = AESGCM(key)
            if config["active"] not in self.keys:
                raise ValueError()
            self.active = config["active"]
        except (ValueError, TypeError, KeyError):
            raise ValueError("invalid vault keyring") from None

    @staticmethod
    def context(tenant, table, identifier):
        return canonical(["ScoutBankAI", "bank_id", tenant, table, identifier])

    def seal(self, value, tenant, table, identifier):
        if not self.active:
            if self.allow_plaintext:
                return value
            raise BridgeError("vault_not_configured", 503)
        nonce = secrets.token_bytes(12)
        encrypted = self.keys[self.active].encrypt(nonce, value.encode(), self.context(tenant, table, identifier))
        return ".".join(["sbv1", self.active, base64.b64encode(nonce).decode(), base64.b64encode(encrypted).decode()])

    def open(self, value, tenant, table, identifier, *, migration=False):
        if not value.startswith("sbv1."):
            if self.allow_plaintext or migration:
                return value
            raise BridgeError("unencrypted_bank_identifier", 503)
        try:
            prefix, kid, nonce, ciphertext = value.split(".")
            nonce = base64.b64decode(nonce, validate=True)
            ciphertext = base64.b64decode(ciphertext, validate=True)
            if len(nonce) != 12 or len(ciphertext) > 512:
                raise ValueError()
            return self.keys[kid].decrypt(nonce, ciphertext, self.context(tenant, table, identifier)).decode()
        except (ValueError, KeyError, TypeError, InvalidTag, UnicodeError):
            raise BridgeError("vault_integrity_failure", 503) from None
