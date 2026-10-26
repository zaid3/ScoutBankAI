"""Separate HTTP test bank. No real accounts, funds, credentials or banking claims."""
import hmac
import json
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def create_mock_bank(database: str, token_file: str):
    app = FastAPI(title="ScoutBankAI test bank", docs_url=None, redoc_url=None)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, body TEXT NOT NULL, response TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS balance(id TEXT PRIMARY KEY, amount INTEGER NOT NULL)")
        db.execute("INSERT OR IGNORE INTO balance VALUES('sample-checking',10000000)")
    Path(database).chmod(0o600)

    @app.middleware("http")
    async def authenticate(request, call_next):
        expected = "Bearer " + Path(token_file).read_text().strip()
        if not hmac.compare_digest(request.headers.get("authorization", ""), expected):
            return JSONResponse({"error": "unauthorised"}, status_code=401)
        return await call_next(request)

    @app.post("/payments")
    async def payment(request: Request):
        data = await request.json()
        idem = request.headers.get("idempotency-key")
        if not isinstance(data, dict) or idem != data.get("id") or type(data.get("amount_minor")) is not int or data["amount_minor"] <= 0:
            return JSONResponse({"error": "invalid_payment"}, status_code=400)
        serialized = json.dumps(data, sort_keys=True)
        with sqlite3.connect(database, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT body,response FROM records WHERE id=?", (idem,)).fetchone()
            if existing:
                if existing[0] != serialized:
                    return JSONResponse({"error": "idempotency_conflict"}, status_code=409)
                return json.loads(existing[1])
            valid = data.get("debtor_account") == "sample-checking" and data.get("creditor_account") == "sample-supplier" and data.get("currency") == "GBP"
            changed = db.execute("UPDATE balance SET amount=amount-? WHERE id=? AND amount>=?", (data["amount_minor"], "sample-checking" if valid else "none", data["amount_minor"])).rowcount
            response = {"status": "settled" if changed else "rejected", "bank_id": "mock_" + idem,
                        "idempotency_key": idem, "request_hash": data["request_hash"]}
            db.execute("INSERT INTO records VALUES(?,?,?)", (idem, serialized, json.dumps(response)))
            return response

    @app.get("/payments/by-idempotency/{identifier}")
    def status(identifier: str):
        with sqlite3.connect(database) as db:
            row = db.execute("SELECT response FROM records WHERE id=?", (identifier,)).fetchone()
        if not row:
            return JSONResponse({"status": "unknown"}, status_code=404)
        return json.loads(row[0])

    return app

