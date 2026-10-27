import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class Settings:
    database: str
    audit_key: bytes
    nonce_key: bytes
    origin: str = "http://127.0.0.1:8090"
    mode: str = "development"
    issuer: str = ""
    audience: str = "scoutbankai"
    jwks_file: str = ""
    vault_keyring_file: str = ""
    connector: dict = field(default_factory=dict)
    supervisor: dict = field(default_factory=lambda: {"mode": "rules"})

    def validate(self):
        url = urlsplit(self.origin)
        if url.path or url.query or url.fragment or url.username or not url.hostname:
            raise ValueError("origin must be a scheme and authority, without a path")
        if self.mode not in {"development", "integrated"}:
            raise ValueError("mode must be development or integrated")
        if len(self.audit_key) < 32 or len(self.nonce_key) < 32 or self.audit_key == self.nonce_key:
            raise ValueError("independent audit and nonce keys of at least 32 bytes are required")
        if self.mode == "integrated":
            if url.scheme != "https" or not self.issuer.startswith("https://") or not self.jwks_file:
                raise ValueError("integrated mode requires HTTPS, an issuer and its pinned JWKS file")
            if not self.connector.get("base_url", "").startswith("https://"):
                raise ValueError("integrated mode requires an HTTPS bank connector")
        elif url.scheme != "http" or url.hostname not in {"localhost", "127.0.0.1", "testserver"}:
            raise ValueError("development mode only accepts a loopback origin")
        if self.supervisor.get("mode") not in {"rules", "openai"}:
            raise ValueError("unknown supervisor")
        return self

    @classmethod
    def load(cls, filename: str):
        path = Path(filename).resolve()
        raw = json.loads(path.read_text())
        def resolve(value):
            return str((path.parent / value).resolve())
        raw["database"] = resolve(raw["database"])
        secrets = {name: Path(resolve(raw.pop(name + "_file"))) for name in ("audit_key", "nonce_key")}
        raw.update({name: file.read_bytes() for name, file in secrets.items()})
        if raw.get("jwks_file"):
            raw["jwks_file"] = resolve(raw["jwks_file"])
        if raw.get("vault_keyring_file"):
            raw["vault_keyring_file"] = resolve(raw["vault_keyring_file"])
        for name in ("ca_file", "cert_file", "key_file", "token_file"):
            if raw.get("connector", {}).get(name):
                raw["connector"][name] = resolve(raw["connector"][name])
        if raw.get("mode") == "integrated" and os.name == "posix":
            # Private files must not be accessible to other local users.
            for name, file in secrets.items():
                if file.stat().st_mode & 0o077:
                    raise ValueError(f"{name}_file requires owner-only permissions")
            for name in ("key_file", "token_file"):
                if raw.get("connector", {}).get(name) and Path(raw["connector"][name]).stat().st_mode & 0o077:
                    raise ValueError(f"connector {name} requires owner-only permissions")
        return cls(**raw).validate()

