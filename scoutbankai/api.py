import json
import secrets
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.openapi.utils import get_openapi
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.concurrency import run_in_threadpool

from . import __version__
from .crypto import digest, strict_json
from .errors import BridgeError
from .models import AccountRegistration, AgentRegistration, MandateRequest, PauseRequest, PayeeRegistration, PaymentRequest, ReviewRequest
from .service import Service


def create_app(settings, service=None):
    service = service or Service(settings)
    app = FastAPI(title="ScoutBankAI", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.service = service
    static = Path(__file__).parent / "static"
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=[urlsplit(settings.origin).hostname])

    def rate_limit(address, token):
        now = service.clock()
        with service.store.transaction() as db:
            db.execute("DELETE FROM rate_limits WHERE expires<?", (now,))
            for identity, limit in (("ip:" + address, 600), ("credential:" + digest(token), 120)):
                bucket = digest(identity) + ":" + str(now // 60)
                db.execute("INSERT INTO rate_limits VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1", (bucket, now + 120))
                if db.execute("SELECT count FROM rate_limits WHERE bucket=?", (bucket,)).fetchone()[0] > limit:
                    raise BridgeError("rate_limited", 429)

    @app.middleware("http")
    async def bounds(request: Request, call_next):
        request_id = secrets.token_hex(12)
        try:
            for name in ("authorization", "dpop", "idempotency-key", "content-length", "content-type", "origin", "host"):
                if len(request.headers.getlist(name)) > 1:
                    raise BridgeError("duplicate_header")
            if request.url.query:
                raise BridgeError("query_parameters_not_supported")
            if request.headers.get("origin") not in {None, settings.origin}:
                raise BridgeError("origin_not_permitted", 403)
            if len(request.headers.get("authorization", "")) > 16000 or len(request.headers.get("dpop", "")) > 8192:
                raise BridgeError("headers_too_large", 431)
            if int(request.headers.get("content-length", "0")) > 32768:
                raise BridgeError("body_too_large", 413)
            raw = bytearray()
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > 32768:
                    raise BridgeError("body_too_large", 413)
            request._body = bytes(raw)
            if raw:
                if request.headers.get("content-type", "").split(";")[0] != "application/json":
                    raise BridgeError("json_required", 415)
                try:
                    strict_json(raw)
                except (ValueError, UnicodeError):
                    raise BridgeError("invalid_json") from None
            if request.url.path.startswith("/v1/"):
                # Bounded persistent buckets. Proxies must enforce transport-level limits too.
                address = request.client.host if request.client else "unknown"
                token = request.headers.get("authorization", "")
                await run_in_threadpool(rate_limit, address, token)
            response = await call_next(request)
        except BridgeError as exc:
            response = JSONResponse({"error": exc.code}, status_code=exc.status)
        except (ValueError, UnicodeError):
            response = JSONResponse({"error": "invalid_request"}, status_code=400)
        except sqlite3.Error:
            response = JSONResponse({"error": "storage_unavailable"}, status_code=503)
        response.headers.update({"X-Request-ID": request_id, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                                 "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
        if settings.mode == "integrated":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(BridgeError)
    async def bridge_error(request, exc):
        headers = {}
        if exc.code == "use_dpop_nonce":
            try:
                headers["DPoP-Nonce"] = service.nonce(agent_token(request))
                headers["WWW-Authenticate"] = 'DPoP error="use_dpop_nonce"'
            except BridgeError:
                pass
        return JSONResponse({"error": exc.code}, status_code=exc.status, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse({"error": "validation_failed", "fields": [".".join(str(x) for x in e["loc"]) for e in exc.errors()]}, status_code=422)

    def principal(request, roles):
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise BridgeError("unauthenticated", 401)
        return service.auth.authenticate(authorization[7:], set(roles))

    def agent_token(request):
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("DPoP "):
            raise BridgeError("agent_identity_required", 401)
        return authorization[5:]

    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    @app.get("/app.js")
    def script():
        return FileResponse(static / "app.js", media_type="text/javascript")

    @app.get("/style.css")
    def style():
        return FileResponse(static / "style.css", media_type="text/css")

    @app.get("/healthz")
    def health():
        service.store.rows("SELECT 1")
        return {"status": "ok", "version": __version__}

    @app.get("/v1/openapi.json")
    def schema(request: Request):
        principal(request, {"operator", "auditor"})
        return app.openapi()

    @app.get("/v1/overview")
    def overview(request: Request):
        actor = principal(request, {"operator", "reviewer", "auditor"})
        return {"role": actor.role, **service.overview(actor)}

    @app.post("/v1/agents", status_code=201)
    def agents(request: Request, model: AgentRegistration):
        return service.register_agent(principal(request, {"operator"}), model)

    @app.post("/v1/accounts", status_code=201)
    def accounts(request: Request, model: AccountRegistration):
        return service.register_account(principal(request, {"operator"}), model)

    @app.post("/v1/payees", status_code=201)
    def payees(request: Request, model: PayeeRegistration):
        return service.register_payee(principal(request, {"operator"}), model)

    @app.post("/v1/mandates", status_code=201)
    def mandates(request: Request, model: MandateRequest):
        return service.create_mandate(principal(request, {"customer"}), model)

    @app.post("/v1/mandates/{mandate_id}/tokens", status_code=201)
    def tokens(mandate_id: str, request: Request):
        return service.mint_token(principal(request, {"customer"}), mandate_id)

    @app.post("/v1/mandates/{mandate_id}/revoke")
    def revoke(mandate_id: str, request: Request):
        return service.revoke(principal(request, {"customer", "operator"}), mandate_id)

    @app.post("/v1/agents/{agent_id}/suspend")
    def suspend(agent_id: str, request: Request):
        return service.suspend(principal(request, {"operator"}), agent_id)

    @app.post("/v1/pause")
    def pause(request: Request, model: PauseRequest):
        return service.pause(principal(request, {"operator"}), model.paused)

    @app.post("/v1/nonce")
    def nonce(request: Request):
        value = service.nonce(agent_token(request))
        return JSONResponse({"nonce": value}, headers={"DPoP-Nonce": value})

    @app.post("/v1/payments", status_code=202)
    async def payments(request: Request, model: PaymentRequest):
        return await run_in_threadpool(service.create_payment, agent_token(request), request.headers.get("dpop", ""),
                                       await request.body(), request.headers.get("idempotency-key", ""), model)

    @app.get("/v1/payments/{payment_id}")
    def get_payment(payment_id: str, request: Request):
        return service.get_agent_payment(agent_token(request), request.headers.get("dpop", ""), payment_id)

    @app.post("/v1/payments/{payment_id}/review")
    def review(payment_id: str, request: Request, model: ReviewRequest):
        return service.review(principal(request, {"reviewer"}), payment_id, model)

    @app.get("/v1/audit/verify")
    def verify(request: Request):
        principal(request, {"operator", "auditor"})
        return {"integrity": "verified", "checkpoint": service.store.verify_audit(),
                "scope": "installation_chain", "truncation_protection": "retain checkpoint outside this installation"}

    def openapi():
        if app.openapi_schema:
            return app.openapi_schema
        document = get_openapi(title=app.title, version=app.version, routes=app.routes)
        document["components"]["securitySchemes"] = {
            "BankIdentity": {"type": "http", "scheme": "bearer", "description": "Bank-issued role and tenant token; exact consent receipt required for integrated grants."},
            "AgentToken": {"type": "apiKey", "in": "header", "name": "Authorization", "description": "DPoP <permission-bound access token>"},
            "AgentProof": {"type": "apiKey", "in": "header", "name": "DPoP", "description": "Fresh ES256 proof with nonce, body and idempotency bindings."},
        }
        for path, operations in document["paths"].items():
            for method, operation in operations.items():
                if method not in {"get", "post"} or not path.startswith("/v1/"):
                    continue
                if path == "/v1/nonce":
                    operation["security"] = [{"AgentToken": []}]
                elif path in {"/v1/payments", "/v1/payments/{payment_id}"}:
                    operation["security"] = [{"AgentToken": [], "AgentProof": []}]
                    if method == "post":
                        operation.setdefault("parameters", []).append({"in": "header", "name": "Idempotency-Key", "required": True,
                            "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"}})
                else:
                    operation["security"] = [{"BankIdentity": []}]
        app.openapi_schema = document
        return document

    app.openapi = openapi

    return app

