"""Fixed-origin bank gateway connector. See docs/bank-adapter-contract.md."""
import os
import re
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .crypto import strict_json


@dataclass(frozen=True)
class BankResult:
    status: str
    bank_id: str | None = None


class HTTPBankAdapter:
    def __init__(self, config, mode="integrated", transport=None):
        self.config, self.mode = config, mode
        self.base = config["base_url"].rstrip("/")
        url = urlsplit(self.base)
        if url.username or url.password or url.query or url.fragment or not url.hostname:
            raise ValueError("invalid bank gateway URL")
        if url.scheme != "https" and not (mode == "development" and url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost", "testbank"}):
            raise ValueError("bank gateway requires HTTPS")
        tls = ssl.create_default_context(cafile=config.get("ca_file"))
        if config.get("cert_file") and config.get("key_file"):
            tls.load_cert_chain(config["cert_file"], config["key_file"])
        elif mode == "integrated" and transport is None:
            raise ValueError("integrated worker requires a bank client certificate and key")
        self.client = httpx.Client(timeout=httpx.Timeout(15, connect=5), verify=tls,
                                   follow_redirects=False, trust_env=False, transport=transport)

    def _token(self):
        if self.config.get("token_file"):
            value = Path(self.config["token_file"]).read_text().strip()
        else:
            value = os.environ.get(self.config.get("token_env", "SCOUT_BANK_TOKEN"), "")
        if not value or len(value) > 16000 or any(c.isspace() for c in value):
            raise ValueError("bank credential unavailable")
        return value

    def _request(self, method, path, payment):
        try:
            headers = {"Authorization": "Bearer " + self._token(), "Accept": "application/json"}
            if method == "POST":
                headers["Idempotency-Key"] = payment["id"]
            with self.client.stream(method, self.base + path, headers=headers,
                                    json=payment if method == "POST" else None) as response:
                if response.status_code not in {200, 201, 202}:
                    return BankResult("unknown")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > 65536:
                        return BankResult("unknown")
            result = strict_json(raw)
            if result.get("idempotency_key") != payment["id"] or result.get("request_hash") != payment["request_hash"]:
                return BankResult("unknown")
            status = result.get("status")
            bank_id = result.get("bank_id")
            if status not in {"accepted", "settled", "rejected", "unknown"}:
                return BankResult("unknown")
            if status in {"accepted", "settled", "rejected"} and (not isinstance(bank_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", bank_id)):
                return BankResult("unknown")
            return BankResult(status, bank_id)
        except (httpx.HTTPError, OSError, ValueError, TypeError, AttributeError):
            return BankResult("unknown")

    def submit(self, payment):
        return self._request("POST", "/payments", payment)

    def lookup(self, payment):
        return self._request("GET", "/payments/by-idempotency/" + payment["id"], payment)

    def close(self):
        self.client.close()


class MemoryBank:
    """Deterministic test fixture, never selected by an integrated deployment."""
    def __init__(self, outcome="settled"):
        self.outcome, self.records, self.submissions = outcome, {}, 0

    def submit(self, payment):
        self.submissions += 1
        if payment["id"] not in self.records:
            self.records[payment["id"]] = BankResult("settled" if self.outcome == "lost_response" else self.outcome, "bank_" + payment["id"])
        if self.outcome == "lost_response":
            raise TimeoutError("simulated lost response after commit")
        return self.records[payment["id"]]

    def lookup(self, payment):
        return self.records.get(payment["id"], BankResult("unknown"))

