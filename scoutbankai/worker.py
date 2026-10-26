from .connectors import BankResult


class Worker:
    def __init__(self, service, bank):
        self.service, self.store, self.bank = service, service.store, bank

    def _wire(self, db, row):
        account = db.execute("SELECT bank_id FROM accounts WHERE id=? AND tenant=?", (row["account"], row["tenant"])).fetchone()
        payee = db.execute("SELECT bank_id FROM payees WHERE id=? AND tenant=?", (row["payee"], row["tenant"])).fetchone()
        return {"id": row["id"], "tenant": row["tenant"], "request_hash": row["request_hash"],
                "debtor_account": account[0], "creditor_account": payee[0], "amount_minor": row["amount"],
                "currency": row["currency"], "reference": row["reference"]}

    def dispatch_one(self):
        now, wire = self.service.clock(), None
        with self.store.transaction() as db:
            rows = db.execute("SELECT p.* FROM payments p JOIN tenants t ON p.tenant=t.id WHERE p.status='queued' AND t.paused=0 ORDER BY p.created,p.id LIMIT 50").fetchall()
            for row in rows:
                mandate = db.execute("SELECT * FROM mandates WHERE id=?", (row["mandate"],)).fetchone()
                agent = db.execute("SELECT active FROM agents WHERE id=?", (row["agent"],)).fetchone()
                if mandate["revoked"] or mandate["expires"] <= now or not agent[0]:
                    self.service.cancel(db, row, "authority_expired", "worker")
                    continue
                # This commit is the dispatch boundary. Later revocation cannot recall a bank request.
                wire = self._wire(db, row)
                db.execute("UPDATE payments SET status='dispatching',reason='bank_request_started',updated=? WHERE id=?", (now, row["id"]))
                self.store.event(db, row["tenant"], "bank_dispatch_started", "worker", now, payment_id=row["id"])
                break
        if wire is None:
            return None
        try:
            outcome = self.bank.submit(wire)
        except Exception:
            outcome = BankResult("unknown")
        self._complete(wire, outcome)
        return wire["id"]

    def _complete(self, wire, outcome):
        if not isinstance(outcome, BankResult) or outcome.status not in {"accepted", "settled", "rejected", "unknown"}:
            outcome = BankResult("unknown")
        status = {"accepted": "submitted", "settled": "settled", "rejected": "rejected", "unknown": "unknown"}[outcome.status]
        with self.store.transaction() as db:
            row = db.execute("SELECT * FROM payments WHERE id=?", (wire["id"],)).fetchone()
            if row["status"] not in {"dispatching", "submitted", "unknown"}:
                return
            if row["bank_id"] and outcome.bank_id and row["bank_id"] != outcome.bank_id:
                status, outcome = "unknown", BankResult("unknown", row["bank_id"])
            if status == "rejected":
                db.execute("UPDATE mandates SET budget_remaining=budget_remaining+? WHERE id=?", (row["amount"], row["mandate"]))
            db.execute("UPDATE payments SET status=?,reason=?,bank_id=COALESCE(?,bank_id),updated=? WHERE id=?",
                       (status, "bank_" + status, outcome.bank_id, self.service.clock(), row["id"]))
            self.store.event(db, row["tenant"], "bank_status_recorded", "worker", self.service.clock(), payment_id=row["id"], status=status, bank_id=outcome.bank_id)

    def reconcile(self, force=False):
        now = self.service.clock()
        db = self.store.connect()
        try:
            rows = db.execute("SELECT * FROM payments WHERE (status IN ('submitted','unknown') AND updated<=?) OR (status='dispatching' AND updated<=?) LIMIT 50",
                              (now if force else now - 15, now - 60)).fetchall()
            wires = [self._wire(db, row) for row in rows]
        finally:
            db.close()
        for wire in wires:
            try:
                outcome = self.bank.lookup(wire)
            except Exception:
                outcome = BankResult("unknown")
            self._complete(wire, outcome)
        return len(wires)

    def recover_screening(self):
        # A crash during an advisory call must never turn silence into approval.
        with self.store.transaction() as db:
            for row in db.execute("SELECT * FROM payments WHERE status='screening' AND updated<?", (self.service.clock() - 60,)).fetchall():
                db.execute("UPDATE payments SET status='review',reason='supervision_interrupted',updated=? WHERE id=?", (self.service.clock(), row["id"]))
                self.store.event(db, row["tenant"], "supervision_interrupted", "worker", self.service.clock(), payment_id=row["id"])

