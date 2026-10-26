"""Small agent client; the private key never leaves the caller's process."""
import re
import ssl
from urllib.parse import urlsplit

import httpx

from .crypto import canonical, proof


class ScoutClient:
    def __init__(self, origin, access_token, private_key, *, ca_file=None, transport=None):
        url = urlsplit(origin)
        if url.path or url.query or url.fragment or url.username or not url.hostname:
            raise ValueError("origin must not contain a path, query or credentials")
        if url.scheme != "https" and not (url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "testserver"}):
            raise ValueError("HTTPS required outside loopback")
        self.origin, self.token, self.key = origin, access_token, private_key
        self.http = httpx.Client(timeout=30, follow_redirects=False, trust_env=False,
                                 verify=ssl.create_default_context(cafile=ca_file), transport=transport)

    def _call(self, method, path, body=b"", idempotency_key=""):
        auth = {"Authorization": "DPoP " + self.token}
        nonce_response = self.http.post(self.origin + "/v1/nonce", headers=auth)
        nonce_response.raise_for_status()
        nonce = nonce_response.json()["nonce"]
        headers = {**auth, "DPoP": proof(self.key, self.token, method, self.origin + path, body, nonce, idempotency_key)}
        if body:
            headers["Content-Type"] = "application/json"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        response = self.http.request(method, self.origin + path, content=body, headers=headers)
        response.raise_for_status()
        return response.json()

    def create_payment(self, payment, idempotency_key):
        return self._call("POST", "/v1/payments", canonical(payment), idempotency_key)

    def get_payment(self, payment_id):
        if not re.fullmatch(r"pay_[a-f0-9]{24}", payment_id):
            raise ValueError("invalid payment ID")
        return self._call("GET", "/v1/payments/" + payment_id)

    def close(self):
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

