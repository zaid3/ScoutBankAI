import argparse
import json
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from .bootstrap import initialize, sample_authority, submit_sample
from .config import Settings
from .connectors import HTTPBankAdapter, MemoryBank
from .errors import BridgeError
from .models import ReviewRequest
from .operations import backup, check, configure, reencrypt_vault
from .service import Service
from .worker import Worker


def main():
    parser = argparse.ArgumentParser(prog="scoutbankai")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Create private development credentials and empty state")
    init.add_argument("--directory", default=".state")
    init.add_argument("--origin", default="http://127.0.0.1:8090")
    demo = sub.add_parser("demo", help="Exercise real controls using a simulated bank")
    demo.add_argument("--directory", default=".state")
    demo.add_argument("--output")
    config = sub.add_parser("configure", help="Create integrated settings and independent local keys; bank files must be provisioned")
    config.add_argument("--directory", required=True)
    config.add_argument("--origin", required=True)
    config.add_argument("--issuer", required=True)
    config.add_argument("--bank-url", required=True)
    for name in ("serve", "worker", "sample", "mock-bank", "audit", "enable-tenant", "check", "backup", "vault-reencrypt"):
        command = sub.add_parser(name)
        command.add_argument("--config", default=".state/config.json")
        if name == "serve":
            command.add_argument("--host", default="127.0.0.1")
            command.add_argument("--port", type=int, default=8090)
        if name == "worker":
            command.add_argument("--once", action="store_true")
        if name == "audit":
            command.add_argument("--anchor")
            command.add_argument("--output")
        if name == "enable-tenant":
            command.add_argument("tenant")
        if name == "backup":
            command.add_argument("--directory", required=True)
            command.add_argument("--anchor")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "configure":
            print(json.dumps(configure(args.directory, args.origin, args.issuer, args.bank_url), indent=2))
            return
        if args.command == "init":
            settings, _, _ = initialize(args.directory, args.origin)
            print(json.dumps({"config": str(Path(args.directory).resolve() / "config.json"), "credentials": "credentials.json in the same private directory", "mode": settings.mode}))
            return
        if args.command == "demo":
            settings, service, credentials = initialize(args.directory)
            authority = sample_authority(service, credentials)
            records = []
            for label, amount in (("Approved invoice", 5000), ("Limit exceeded", 60000), ("Independent review", 25000)):
                try:
                    payment = submit_sample(service, authority, amount)
                    records.append({"scenario": label, "status": payment["status"], "payment_id": payment["id"]})
                except BridgeError as exc:
                    records.append({"scenario": label, "status": "denied", "reason": exc.code})
            bank = MemoryBank(outcome="lost_response")
            worker = Worker(service, bank)
            worker.dispatch_one()
            before = service.store.rows("SELECT status FROM payments WHERE status='unknown'")
            worker.reconcile(force=True)
            records.append({"scenario": "Lost bank response", "unresolved_before_reconciliation": len(before), "bank_submissions": bank.submissions, "settled_after_lookup": len(service.store.rows("SELECT id FROM payments WHERE status='settled'"))})
            service.revoke(authority["customer"], authority["mandate"])
            records.append({"scenario": "Consent revoked", "pending_cancelled": len(service.store.rows("SELECT id FROM payments WHERE status='cancelled'"))})
            result = {"product": "ScoutBankAI", "bank": "simulated", "scenarios": records, "audit_checkpoint": service.store.verify_audit()}
            output = json.dumps(result, indent=2)
            if args.output:
                Path(args.output).write_text(output + "\n")
            print(output)
            return
        settings = Settings.load(args.config)
        service = Service(settings)
        if args.command == "check":
            print(json.dumps(check(service), indent=2))
        elif args.command == "backup":
            anchor = json.loads(Path(args.anchor).read_text()) if args.anchor else None
            print(json.dumps(backup(service, args.directory, anchor), indent=2))
        elif args.command == "serve":
            if settings.mode == "development" and args.host not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("development credentials require loopback binding")
            import uvicorn
            from .api import create_app
            uvicorn.run(create_app(settings, service), host=args.host, port=args.port, proxy_headers=False, access_log=False)
        elif args.command == "worker":
            bank = HTTPBankAdapter(settings.connector, settings.mode)
            worker = Worker(service, bank)
            stopping = False
            def stop(*_):
                nonlocal stopping
                stopping = True
            signal.signal(signal.SIGTERM, stop)
            signal.signal(signal.SIGINT, stop)
            try:
                while not stopping:
                    worker.recover_screening()
                    worker.reconcile()
                    payment_id = worker.dispatch_one()
                    if args.once:
                        print(json.dumps({"dispatched": payment_id}))
                        break
                    time.sleep(0.2 if payment_id else 2)
            finally:
                bank.close()
        elif args.command in {"sample", "mock-bank"}:
            if settings.mode != "development":
                raise ValueError("test fixtures are unavailable in integrated mode")
            parent = Path(args.config).resolve().parent
            if args.command == "sample":
                credentials = json.loads((parent / "credentials.json").read_text())
                authority = sample_authority(service, credentials)
                from .client import ScoutClient
                import secrets
                with ScoutClient(settings.origin, authority["token"], authority["key"]) as client:
                    print(json.dumps(client.create_payment({"mandate_id": authority["mandate"],
                        "payee_id": authority["payee"], "amount_minor": 5000,
                        "currency": "GBP", "reference": "Sample invoice"}, secrets.token_urlsafe(24))))
            else:
                import uvicorn
                from .mock_bank import create_mock_bank
                uvicorn.run(create_mock_bank(str(parent / "mock-bank.db"), str(parent / "bank-token.key")), host="127.0.0.1", port=8091, access_log=False)
        elif args.command == "vault-reencrypt":
            print(json.dumps(reencrypt_vault(service), indent=2))
        elif args.command == "audit":
            anchor = json.loads(Path(args.anchor).read_text()) if args.anchor else None
            checkpoint = service.store.verify_audit(anchor)
            output = json.dumps(checkpoint, indent=2)
            if args.output:
                Path(args.output).write_text(output + "\n")
            print(output)
        elif args.command == "enable-tenant":
            import re
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", args.tenant):
                raise ValueError("invalid tenant")
            with service.store.transaction() as db:
                db.execute("INSERT INTO tenants(id) VALUES(?)", (args.tenant,))
                service.store.event(db, args.tenant, "tenant_enabled", "host_operator", service.clock())
            print(json.dumps({"tenant": args.tenant, "status": "enabled"}))
    except (BridgeError, ValueError, OSError, sqlite3.Error) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)

