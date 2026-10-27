import base64
import re
from dataclasses import dataclass
from pathlib import Path

import jwt

from .crypto import digest, strict_json
from .errors import BridgeError

ROLES = {"operator", "reviewer", "auditor", "customer"}
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$")


@dataclass(frozen=True)
class Principal:
    tenant: str
    subject: str
    role: str
    consent_hash: str | None = None
    consent_time: int | None = None
    consent_id: str | None = None
    actor_type: str = "human"


class Authenticator:
    def __init__(self, settings, store, clock):
        self.settings, self.store, self.clock = settings, store, clock

    def authenticate(self, token: str, roles: set[str]) -> Principal:
        if not token or len(token) > 16000:
            raise BridgeError("unauthenticated", 401)
        if self.settings.mode == "development":
            rows = self.store.rows("SELECT * FROM principals WHERE hash=? AND expires>?", (digest(token), self.clock()))
            if not rows:
                raise BridgeError("unauthenticated", 401)
            row = rows[0]
            principal = Principal(row["tenant"], row["subject"], row["role"])
        else:
            try:
                pieces = token.split(".")
                if len(pieces) != 3:
                    raise ValueError()
                for piece in pieces[:2]:
                    strict_json(base64.urlsafe_b64decode(piece + "=" * (-len(piece) % 4)))
                header = jwt.get_unverified_header(token)
                if header.get("alg") not in {"RS256", "ES256"} or not isinstance(header.get("kid"), str):
                    raise ValueError()
                if any(name in header for name in ("jku", "x5u", "jwk", "crit")):
                    raise ValueError()
                keys = strict_json(Path(self.settings.jwks_file).read_bytes())["keys"]
                matches = [k for k in keys if k.get("kid") == header["kid"] and k.get("alg") == header["alg"] and k.get("use", "sig") == "sig"]
                if len(matches) != 1:
                    raise ValueError()
                key = jwt.PyJWK.from_dict(matches[0]).key
                claims = jwt.decode(token, key, algorithms=[header["alg"]], issuer=self.settings.issuer,
                                    audience=self.settings.audience,
                                    options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant", "role"]})
                if any(type(claims[k]) is not int for k in ("exp", "iat")) or not 0 < claims["exp"] - claims["iat"] <= 900:
                    raise ValueError()
                if not all(isinstance(claims[k], str) and ID.fullmatch(claims[k]) for k in ("sub", "tenant")):
                    raise ValueError()
                if not isinstance(claims["role"], str) or claims["role"] not in ROLES:
                    raise ValueError()
                actor_type = claims.get("scout_actor_type", "unknown")
                if not isinstance(actor_type, str) or actor_type not in {"human", "service", "unknown"}:
                    raise ValueError()
                if claims["role"] in {"operator", "reviewer"} and actor_type != "human":
                    raise ValueError()
                receipt = claims.get("scout_action") == "grant_mandate"
                if receipt and (not isinstance(claims.get("scout_policy_sha256"), str)
                                or not re.fullmatch(r"[0-9a-f]{64}", claims["scout_policy_sha256"])
                                or type(claims.get("auth_time")) is not int
                                or not isinstance(claims.get("jti"), str)
                                or not 16 <= len(claims["jti"]) <= 128):
                    raise ValueError()
                principal = Principal(claims["tenant"], claims["sub"], claims["role"],
                                      claims["scout_policy_sha256"] if receipt else None,
                                      claims["auth_time"] if receipt else None, claims["jti"] if receipt else None, actor_type)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, jwt.PyJWTError):
                raise BridgeError("unauthenticated", 401) from None
        if principal.role not in roles:
            raise BridgeError("role_not_permitted", 403)
        if not self.store.rows("SELECT id FROM tenants WHERE id=?", (principal.tenant,)):
            raise BridgeError("tenant_not_enabled", 403)
        return principal

