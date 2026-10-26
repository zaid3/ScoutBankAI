"""DPoP resource-server checks with ScoutBankAI body/idempotency bindings.

The extension claims are not a claim of OAuth/FAPI certification.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from .errors import BridgeError


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value: bytes | str) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def strict_json(raw: bytes | str):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite number")))


def public_jwk(key) -> dict:
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}


def validate_jwk(value: dict):
    if not isinstance(value, dict) or set(value) != {"kty", "crv", "x", "y"}:
        raise BridgeError("invalid_public_key")
    if value["kty"] != "EC" or value["crv"] != "P-256":
        raise BridgeError("unsupported_key")
    try:
        for field in ("x", "y"):
            encoded = value[field]
            if not isinstance(encoded, str) or len(encoded) != 43:
                raise ValueError()
            decoded = base64.urlsafe_b64decode(encoded + "=")
            if len(decoded) != 32 or b64(decoded) != encoded:
                raise ValueError()
        return jwt.algorithms.ECAlgorithm.from_jwk(value)
    except (ValueError, TypeError, KeyError, jwt.PyJWTError):
        raise BridgeError("invalid_public_key") from None


def thumbprint(value: dict) -> str:
    validate_jwk(value)
    return b64(hashlib.sha256(canonical(value)).digest())


def new_key():
    return ec.generate_private_key(ec.SECP256R1())


def make_nonce(secret: bytes, token: str, now: int) -> str:
    part = f"{now}.{secrets.token_urlsafe(24)}"
    mac = hmac.new(secret, f"{digest(token)}.{part}".encode(), hashlib.sha256).digest()
    return part + "." + b64(mac)


def verify_nonce(nonce, secret: bytes, token: str, now: int):
    try:
        timestamp, random_part, signature = nonce.split(".")
        if not 0 <= now - int(timestamp) <= 60 or not 24 <= len(random_part) <= 64:
            raise ValueError()
        expected = b64(hmac.new(secret, f"{digest(token)}.{timestamp}.{random_part}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise BridgeError("use_dpop_nonce", 401) from None


def proof(key, token: str, method: str, url: str, body: bytes, nonce: str,
          idempotency_key: str = "", now: int | None = None, jti: str | None = None) -> str:
    claims = {"jti": jti or secrets.token_urlsafe(24), "htm": method, "htu": url,
              "iat": int(time.time()) if now is None else now,
              "ath": b64(hashlib.sha256(token.encode()).digest()), "nonce": nonce,
              "scout_body_sha256": digest(body), "scout_idempotency_key": idempotency_key}
    return jwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk(key)})


def verify_proof(encoded: str, token: str, expected_thumbprint: str, method: str, url: str,
                 body: bytes, idempotency_key: str, nonce_secret: bytes, now: int) -> str:
    try:
        if not isinstance(encoded, str) or len(encoded) > 8192:
            raise ValueError()
        pieces = encoded.split(".")
        if len(pieces) != 3:
            raise ValueError()
        for piece in pieces[:2]:
            strict_json(base64.urlsafe_b64decode(piece + "=" * (-len(piece) % 4)))
        header = jwt.get_unverified_header(encoded)
        if set(header) != {"alg", "typ", "jwk"} or header["alg"] != "ES256" or header["typ"] != "dpop+jwt":
            raise ValueError()
        key = validate_jwk(header["jwk"])
        if not hmac.compare_digest(thumbprint(header["jwk"]), expected_thumbprint):
            raise ValueError()
        claims = jwt.decode(encoded, key, algorithms=["ES256"], options={"verify_iat": False, "verify_aud": False})
        if (type(claims.get("iat")) is not int or not -10 <= now - claims["iat"] <= 60
                or claims.get("htm") != method or claims.get("htu") != url
                or claims.get("ath") != b64(hashlib.sha256(token.encode()).digest())
                or claims.get("scout_body_sha256") != digest(body)
                or claims.get("scout_idempotency_key") != idempotency_key
                or not isinstance(claims.get("jti"), str) or not 16 <= len(claims["jti"]) <= 128):
            raise ValueError()
        verify_nonce(claims.get("nonce"), nonce_secret, token, now)
        return digest(expected_thumbprint + ":" + claims["jti"])
    except BridgeError as exc:
        if exc.code == "use_dpop_nonce":
            raise
        raise BridgeError("invalid_dpop_proof", 401) from None
    except (ValueError, TypeError, KeyError, jwt.PyJWTError):
        raise BridgeError("invalid_dpop_proof", 401) from None

