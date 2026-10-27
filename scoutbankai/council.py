"""Repeated cross-audits, immutable evidence and independently labelled scores."""
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from threading import BoundedSemaphore

from .audit_models import AuditContext, AuditReport, CouncilConfig, ROLES
from .auditors import OpenAIAuditor, RuleAuditor, deterministic_findings
from .crypto import canonical, digest
from .errors import BridgeError

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_runs(
 payment TEXT PRIMARY KEY REFERENCES payments(id), tenant TEXT NOT NULL, request_hash TEXT NOT NULL,
 context TEXT NOT NULL, context_hash TEXT NOT NULL, config TEXT NOT NULL,
 rounds INTEGER NOT NULL, status TEXT NOT NULL, require_review INTEGER NOT NULL DEFAULT 1,
 reason TEXT NOT NULL, result_hash TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_reports(
 payment TEXT NOT NULL REFERENCES audit_runs(payment), round INTEGER NOT NULL,
 role TEXT NOT NULL, model TEXT NOT NULL, status TEXT NOT NULL, report TEXT,
 report_hash TEXT NOT NULL, PRIMARY KEY(payment,round,role));
CREATE TABLE IF NOT EXISTS audit_feedback(
 payment TEXT PRIMARY KEY REFERENCES audit_runs(payment), tenant TEXT NOT NULL,
 evaluator TEXT NOT NULL, label TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_scores(
 payment TEXT NOT NULL REFERENCES audit_feedback(payment), role TEXT NOT NULL, points INTEGER NOT NULL,
 details TEXT NOT NULL, PRIMARY KEY(payment,role));
CREATE INDEX IF NOT EXISTS audit_runs_tenant ON audit_runs(tenant,created DESC);
CREATE TRIGGER IF NOT EXISTS audit_reports_no_update BEFORE UPDATE ON audit_reports BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_reports_no_delete BEFORE DELETE ON audit_reports BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_feedback_no_update BEFORE UPDATE ON audit_feedback BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_feedback_no_delete BEFORE DELETE ON audit_feedback BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_scores_no_update BEFORE UPDATE ON audit_scores BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_scores_no_delete BEFORE DELETE ON audit_scores BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_runs_no_delete BEFORE DELETE ON audit_runs BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER IF NOT EXISTS audit_run_identity_immutable BEFORE UPDATE ON audit_runs
 WHEN NEW.payment<>OLD.payment OR NEW.tenant<>OLD.tenant OR NEW.request_hash<>OLD.request_hash
 OR NEW.context<>OLD.context OR NEW.context_hash<>OLD.context_hash OR NEW.config<>OLD.config OR NEW.rounds<>OLD.rounds
 OR OLD.status<>'running' BEGIN SELECT RAISE(ABORT,'immutable audit run'); END;
"""


@dataclass(frozen=True)
class AuditOutcome:
    require_review: bool
    reason: str


def report_hash(payment, round_number, role, model, status, report):
    return digest(canonical({"payment": payment, "round": round_number, "role": role, "model": model,
                             "status": status, "report": report}))


def result_hash(run, reports):
    return digest(canonical({"payment": run["payment"], "request_hash": run["request_hash"],
                             "context_hash": run["context_hash"], "config": json.loads(run["config"]),
                             "require_review": bool(run["require_review"]), "reason": run["reason"],
                             "reports": [r["report_hash"] for r in reports]}))


def verified_reports(db, run):
    """Check stored evidence before it is displayed, backed up or used at dispatch."""
    try:
        AuditContext(**json.loads(run["context"]))
        config = CouncilConfig(**json.loads(run["config"]))
        payment = db.execute("SELECT tenant,request_hash FROM payments WHERE id=?", (run["payment"],)).fetchone()
        if (not payment or payment["tenant"] != run["tenant"] or payment["request_hash"] != run["request_hash"]
                or digest(run["context"]) != run["context_hash"] or config.rounds != run["rounds"]):
            raise ValueError("audit identity changed")
        reports = [dict(row) for row in db.execute("SELECT * FROM audit_reports WHERE payment=? ORDER BY round,role", (run["payment"],))]
        previous = {}
        for r in reports:
            r["report"] = json.loads(r["report"]) if r["report"] else None
            if (r["role"] not in ROLES or not 1 <= r["round"] <= config.rounds
                    or r["model"] != config.models.get(r["role"], "rules-v1")
                    or r["status"] not in {"valid", "invalid", "unavailable"}
                    or (r["status"] == "valid") != (r["report"] is not None)
                    or report_hash(run["payment"], r["round"], r["role"], r["model"], r["status"], r["report"]) != r["report_hash"]):
                raise ValueError("audit report changed")
            if r["report"]:
                report = AuditReport(**r["report"])
                expected = {(role, previous[(r["round"] - 1, role)]) for role in ROLES if role != r["role"]} if r["round"] > 1 else set()
                observed = [(p.role, p.report_hash) for p in report.peer_checks]
                if report.context_hash != run["context_hash"] or len(observed) != len(expected) or set(observed) != expected:
                    raise ValueError("audit peer binding changed")
            previous[(r["round"], r["role"])] = r["report_hash"]
        if run["status"] == "completed" and (len(reports) != config.rounds * 3 or result_hash(run, reports) != run["result_hash"]):
            raise ValueError("audit result changed")
        return reports
    except (ValueError, TypeError, KeyError, IndexError):
        raise BridgeError("cross_audit_integrity_failure", 503) from None


def verify_audits(db):
    count = 0
    for run in db.execute("SELECT * FROM audit_runs"):
        verified_reports(db, run)
        count += 1
    return {"verified_runs": count}


class AuditCouncil:
    def __init__(self, service, auditors=None):
        self.service, self.store = service, service.store
        self.config = CouncilConfig(**service.settings.audit_council)
        self.slots = BoundedSemaphore(self.config.max_concurrent_audits)
        self.auditors = auditors or {role: (RuleAuditor(role) if self.config.mode == "rules" else
            OpenAIAuditor(role, self.config.models[role], self.config.token_env)) for role in ROLES}
        if set(self.auditors) != set(ROLES):
            raise ValueError("three distinct audit roles are required")

    def _call(self, payment, round_number, role, context, context_hash, previous):
        # Do not transmit peer summaries, scores, staff identity or any payment identifiers.
        peers = [{"role": r["role"], "report_hash": r["report_hash"], "status": r["status"],
                  "require_review": r["report"]["require_review"] if r["report"] else True,
                  "finding_codes": r["report"]["finding_codes"] if r["report"] else []}
                 for r in previous if r["role"] != role]
        packet = {"role": role, "round": round_number, "context": context,
                  "context_hash": context_hash, "peers": peers}
        report, status = None, "unavailable"
        auditor = self.auditors[role]
        try:
            raw = auditor.assess(json.loads(canonical(packet)))
            # Revalidate even an already constructed model; custom providers cannot bypass it.
            report = AuditReport.model_validate(raw.model_dump() if isinstance(raw, AuditReport) else raw).model_dump()
            expected = {(p["role"], p["report_hash"]) for p in peers}
            observed = [(p["role"], p["report_hash"]) for p in report["peer_checks"]]
            if report["context_hash"] != context_hash or len(observed) != len(expected) or set(observed) != expected:
                raise ValueError("incorrect audit binding or peer coverage")
            status = "valid"
        except (ValueError, TypeError, KeyError, AttributeError):
            report, status = None, "invalid"
        except Exception:
            # Do not retain provider exception strings: they may contain credentials or payloads.
            report, status = None, "unavailable"
        model = self.config.models.get(role, "rules-v1")
        return {"payment": payment, "round": round_number, "role": role, "model": model,
                "status": status, "report": report,
                "report_hash": report_hash(payment, round_number, role, model, status, report)}

    def assess(self, payment_id, context):
        context = AuditContext(**context).model_dump()
        now, context_hash = self.service.clock(), digest(canonical(context))
        acquired = self.slots.acquire(blocking=False)
        try:
            with self.store.transaction() as db:
                payment = db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
                if not payment or payment["status"] != "screening":
                    return AuditOutcome(True, "cross_audit_interrupted")
                if db.execute("SELECT 1 FROM audit_runs WHERE payment=?", (payment_id,)).fetchone():
                    return AuditOutcome(True, "cross_audit_already_started")
                status = "running" if acquired else "capacity_limited"
                db.execute("INSERT INTO audit_runs(payment,tenant,request_hash,context,context_hash,config,rounds,status,reason,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           (payment_id, payment["tenant"], payment["request_hash"], canonical(context).decode(), context_hash,
                            canonical(self.config.model_dump()).decode(), self.config.rounds, status,
                            "cross_audit_pending" if acquired else "cross_audit_capacity", now, now))
                self.store.event(db, payment["tenant"], "cross_audit_started", "audit_coordinator", now,
                                 payment_id=payment_id, context_hash=context_hash, mode=self.config.mode, rounds=self.config.rounds, status=status)
            if not acquired:
                return AuditOutcome(True, "cross_audit_capacity")
            previous, all_reports = [], []
            for round_number in range(1, self.config.rounds + 1):
                with ThreadPoolExecutor(max_workers=3, thread_name_prefix="scout-audit") as pool:
                    futures = [pool.submit(self._call, payment_id, round_number, role, context, context_hash, previous) for role in ROLES]
                    reports = [future.result() for future in futures]
                with self.store.transaction() as db:
                    run = db.execute("SELECT * FROM audit_runs WHERE payment=?", (payment_id,)).fetchone()
                    state = db.execute("SELECT status FROM payments WHERE id=?", (payment_id,)).fetchone()[0]
                    if run["status"] != "running":
                        return AuditOutcome(True, "cross_audit_interrupted")
                    if state != "screening":
                        self.interrupt(db, payment_id)
                        return AuditOutcome(True, "cross_audit_interrupted")
                    for report in reports:
                        db.execute("INSERT INTO audit_reports VALUES(?,?,?,?,?,?,?)",
                                   (payment_id, round_number, report["role"], report["model"], report["status"],
                                    canonical(report["report"]).decode() if report["report"] else None, report["report_hash"]))
                        self.store.event(db, run["tenant"], "cross_audit_report", report["role"], self.service.clock(),
                                         payment_id=payment_id, round=round_number, report_hash=report["report_hash"], status=report["status"],
                                         model=report["model"], mode=self.config.mode,
                                         require_review=report["report"]["require_review"] if report["report"] else True,
                                         finding_codes=report["report"]["finding_codes"] if report["report"] else [])
                    db.execute("UPDATE audit_runs SET updated=? WHERE payment=?", (self.service.clock(), payment_id))
                    db.execute("UPDATE payments SET updated=? WHERE id=?", (self.service.clock(), payment_id))
                previous, all_reports = reports, all_reports + reports
            unavailable = any(r["status"] != "valid" for r in all_reports)
            disagreement = any(len({r["report"]["require_review"] for r in all_reports if r["round"] == n and r["report"]}) > 1
                               for n in range(1, self.config.rounds + 1))
            disagreement |= any(p["verdict"] != "supported" for r in all_reports if r["report"] for p in r["report"]["peer_checks"])
            flagged = any(r["report"] and r["report"]["require_review"] for r in all_reports)
            # A unanimous model mistake cannot waive even these bounded deterministic checks.
            hard_findings = deterministic_findings(context)
            require_review = unavailable or disagreement or flagged or bool(hard_findings)
            reason = ("cross_audit_unavailable" if unavailable else "cross_audit_disagreement" if disagreement else
                      "cross_audit_review" if require_review else "cross_audit_clear")
            with self.store.transaction() as db:
                run = dict(db.execute("SELECT * FROM audit_runs WHERE payment=?", (payment_id,)).fetchone())
                if run["status"] != "running":
                    return AuditOutcome(True, "cross_audit_interrupted")
                run.update(require_review=int(require_review), reason=reason)
                ordered = sorted(all_reports, key=lambda r: (r["round"], r["role"]))
                signature = result_hash(run, ordered)
                db.execute("UPDATE audit_runs SET status='completed',require_review=?,reason=?,result_hash=?,updated=? WHERE payment=?",
                           (int(require_review), reason, signature, self.service.clock(), payment_id))
                self.store.event(db, run["tenant"], "cross_audit_completed", "audit_coordinator", self.service.clock(),
                                 payment_id=payment_id, require_review=bool(require_review), result_hash=signature, reason=reason)
            return AuditOutcome(bool(require_review), reason)
        finally:
            if acquired:
                self.slots.release()

    def interrupt(self, db, payment):
        row = db.execute("SELECT tenant FROM audit_runs WHERE payment=? AND status='running'", (payment,)).fetchone()
        if row:
            db.execute("UPDATE audit_runs SET status='interrupted',reason='cross_audit_interrupted',updated=? WHERE payment=?",
                       (self.service.clock(), payment))
            self.store.event(db, row[0], "cross_audit_interrupted", "audit_coordinator", self.service.clock(), payment_id=payment)

    def detail(self, actor, payment):
        rows = self.store.rows("SELECT * FROM audit_runs WHERE payment=? AND tenant=?", (payment, actor.tenant))
        if not rows:
            raise BridgeError("cross_audit_not_found", 404)
        run = rows[0]
        with self.store.transaction() as db:
            # Read the run and its reports from the same snapshot during active rounds.
            run = dict(db.execute("SELECT * FROM audit_runs WHERE payment=? AND tenant=?", (payment, actor.tenant)).fetchone())
            reports = verified_reports(db, run)
        feedback = self.store.rows("SELECT evaluator,label,created FROM audit_feedback WHERE payment=?", (payment,))
        return {"payment_id": payment, "status": run["status"], "context_hash": run["context_hash"],
                "request_hash": run["request_hash"], "context": json.loads(run["context"]), "mode": json.loads(run["config"])["mode"],
                "rounds": run["rounds"], "require_review": bool(run["require_review"]), "reason": run["reason"],
                "result_hash": run["result_hash"], "reports": reports,
                "feedback": {**feedback[0], "label": json.loads(feedback[0]["label"])} if feedback else None}

    def evaluate(self, actor, payment, model):
        if actor.role != "evaluator" or (self.service.settings.mode == "integrated" and actor.actor_type != "human"):
            raise BridgeError("independent_evaluator_required", 403)
        detail = self.detail(actor, payment)
        if detail["status"] != "completed" or detail["result_hash"] != model.result_hash:
            raise BridgeError("audit_evaluation_state_changed", 409)
        mandatory = deterministic_findings(detail["context"]) & {"threshold_exceeded", "account_review_required", "supervisor_review_required"}
        if not mandatory.issubset(model.confirmed_findings):
            raise BridgeError("evaluation_contradicts_mandatory_controls", 409)
        with self.store.transaction() as db:
            row = db.execute("SELECT p.reviewed_by,a.owner,m.customer FROM payments p JOIN agents a ON a.id=p.agent JOIN mandates m ON m.id=p.mandate WHERE p.id=? AND p.tenant=?", (payment, actor.tenant)).fetchone()
            if not row or actor.subject in {row["reviewed_by"], row["owner"], row["customer"]}:
                raise BridgeError("independent_evaluator_required", 403)
            try:
                db.execute("INSERT INTO audit_feedback VALUES(?,?,?,?,?)", (payment, actor.tenant, actor.subject, canonical(model.model_dump()).decode(), self.service.clock()))
            except sqlite3.IntegrityError:
                raise BridgeError("audit_already_evaluated", 409) from None
            for report in detail["reports"]:
                if report["round"] != detail["rounds"]:
                    continue
                if report["status"] != "valid":
                    # Failing to return a usable report must not outscore a missed risk.
                    points, breakdown = -10, {"unusable_report": -10}
                else:
                    observed, confirmed = set(report["report"]["finding_codes"]), set(model.confirmed_findings)
                    verdict = report["report"]["require_review"]
                    verdict_points = 1 if verdict == model.review_required else (-5 if model.review_required else -2)
                    breakdown = {"confirmed_findings": 2 * len(observed & confirmed),
                                 "unsupported_findings": -2 * len(observed - confirmed),
                                 "missed_findings": -3 * len(confirmed - observed), "verdict": verdict_points}
                    points = max(-10, min(10, sum(breakdown.values())))
                db.execute("INSERT INTO audit_scores VALUES(?,?,?,?)", (payment, report["role"], points, canonical(breakdown).decode()))
            self.store.event(db, actor.tenant, "cross_audit_evaluated", actor.subject, self.service.clock(),
                             payment_id=payment, result_hash=model.result_hash, label_hash=digest(canonical(model.model_dump())), rubric="quality-v1")
        return {"payment_id": payment, "rubric": "quality-v1", "scores": self.store.rows("SELECT role,points FROM audit_scores WHERE payment=? ORDER BY role", (payment,))}

    def overview(self, actor):
        rows = self.store.rows("SELECT payment,status,reason,rounds,created FROM audit_runs WHERE tenant=? ORDER BY created DESC,payment LIMIT 100", (actor.tenant,))
        scores = self.store.rows("""SELECT s.role,r.model,json_extract(a.config,'$.mode') AS mode,
            count(*) AS evaluated,sum(s.points) AS points,avg(s.points) AS average_points
            FROM audit_scores s JOIN audit_feedback f ON f.payment=s.payment JOIN audit_runs a ON a.payment=s.payment
            JOIN audit_reports r ON r.payment=s.payment AND r.role=s.role AND r.round=a.rounds
            WHERE f.tenant=? GROUP BY s.role,r.model,json_extract(a.config,'$.mode')""", (actor.tenant,))
        by_role = {r["role"]: r for r in scores if r["mode"] == self.config.mode and r["model"] == self.config.models.get(r["role"], "rules-v1")}
        return {"mode": self.config.mode, "rounds": self.config.rounds, "roles": list(ROLES),
                "configured_models": self.config.models, "distinct_models": len(set(self.config.models.values())),
                "rubric": "quality-v1", "scores": [by_role.get(role, {"role": role, "evaluated": 0, "points": 0, "average_points": None}) for role in ROLES],
                "runs": rows, "limit": 100, "score_effect": "reporting_only_no_execution_authority"}
