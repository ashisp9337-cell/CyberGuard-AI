import logging
import os
from contextlib import asynccontextmanager

# scikit-learn's helper asks Windows for the number of PHYSICAL cores with "wmic", which Windows 11 removed,
# and warns when that fails. It only skips the question when the limit is BELOW the logical core count, so
# give it half the logical cores (= the physical cores on a normal hyper-threaded CPU).
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(max(1, (os.cpu_count() or 2) // 2)))
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import get_settings, security_problems
from app.db.database import engine
from app.db import models  # noqa: F401 — ensures models are registered before create_all
from app.api.routes import auth, analysis, scans, dashboard, events, reports, settings as settings_route, threat_intelligence, monitoring, chat, contacts, email as email_route, alerts as alerts_route, incidents as incidents_route, automation as automation_route, iocs as iocs_route, audit as audit_route, mitre as mitre_route, quarantine as quarantine_route

settings = get_settings()

logging.basicConfig(level=logging.INFO if not settings.is_production else logging.WARNING)
logger = logging.getLogger("cyberguard")

# Refuse to run in production with unsafe settings; warn loudly in development.
_problems = security_problems(settings)
if _problems:
    if settings.is_production:
        raise RuntimeError("Unsafe production settings: " + "; ".join(_problems))
    for _p in _problems:
        logger.warning("SECURITY: %s", _p)

def _schema_status() -> str:
    """'' if the PostgreSQL schema is at the newest Alembic migration, else a warning (the tables are created and
    upgraded ONLY by Alembic: `alembic upgrade head`)."""
    try:
        from alembic.config import Config
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cfg = Config(os.path.join(here, "alembic.ini"))
        cfg.set_main_option("script_location", os.path.join(here, "alembic"))
        heads = set(ScriptDirectory.from_config(cfg).get_heads())
        with engine.connect() as conn:
            current = set(MigrationContext.configure(conn).get_current_heads())
        if current != heads:
            return (f"database schema is not up to date (database: {', '.join(sorted(current)) or 'empty'}, "
                    f"code: {', '.join(sorted(heads))}). Stop the backend and run:  alembic upgrade head")
    except Exception as exc:  # noqa: BLE001 -- report, never crash on the check itself
        return f"could not check the database schema ({type(exc).__name__}: {str(exc)[:200]})"
    return ""

from app.core.rate_limit import limiter  # shared with routes (per-route limits)

@asynccontextmanager
async def lifespan(_app):
    # Automatic protection: background watchers (Gmail, sign-ins, Windows logons, Downloads). Off in tests.
    from app.automation import manager
    _schema = _schema_status()
    if _schema:
        logger.error("DATABASE: %s", _schema)
    if settings.AUTOMATION_ENABLED:
        manager.start_all()
    if settings.WARM_UP_MODELS:
        import threading

        def _warm():
            from app.services.analysis_service import warm_up
            t0 = time.time()
            done = warm_up()
            slow = {k: v for k, v in done.items() if not isinstance(v, int) or v > 200}
            logger.info("models loaded in the background in %.1f s%s", time.time() - t0, f" ({slow})" if slow else "")
        threading.Thread(target=_warm, name="model-warm-up", daemon=True).start()
    yield
    manager.stop_all()


_docs = settings.ENABLE_API_DOCS and not settings.is_production   # the API map is never public in production
app = FastAPI(
    lifespan=lifespan,
    title="CyberGuard AI API",
    description="Backend for the CyberGuard AI cyber threat, phishing & deepfake detection platform.",
    version="1.0.0",
    docs_url="/docs" if _docs else None,
    redoc_url="/redoc" if _docs else None,
    openapi_url="/openapi.json" if _docs else None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in settings.cors_origin_list if o != "*"],   # exact origins only (cookies are sent)
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    max_age=600,
)


@app.middleware("http")
async def request_logging(request: Request, call_next):
    request_id = uuid.uuid4().hex[:12]
    start = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 1)
    logger.info(f"[{request_id}] {request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)")
    response.headers["X-Request-ID"] = request_id
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "strict-origin-when-cross-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    ctype = h.get("content-type", "")
    if ctype.startswith(("application/json", "text/event-stream")):
        # API data: never rendered as a page, never cached (it holds private scan results)
        h["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        h["Cache-Control"] = "no-store"
    if settings.COOKIE_SECURE:          # only behind HTTPS
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "error" in detail:
        payload = detail
    else:
        payload = {"error": {"code": "HTTP_ERROR", "message": str(detail)}}
    return JSONResponse(status_code=exc.status_code, content=payload)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Only where and why -- never echo the submitted values back (they may be passwords or codes).
    details = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"error": {"code": "VALIDATION_ERROR", "message": "Invalid request.", "details": details}})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error")          # full details stay in the server log
    if settings.DEBUG and not settings.is_production:
        return JSONResponse(status_code=500, content={"error": {"code": "INTERNAL_ERROR", "message": str(exc)}})
    return JSONResponse(status_code=500, content={"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred."}})


app.include_router(automation_route.router)
app.include_router(iocs_route.router)
app.include_router(audit_route.router)
app.include_router(mitre_route.router)
app.include_router(quarantine_route.router)



@app.get("/api/health")
def health():
    return {"status": "ok"}          # no environment/version details for anonymous callers


app.include_router(auth.router)
app.include_router(analysis.router)
app.include_router(scans.router)
app.include_router(dashboard.router)
app.include_router(events.router)
app.include_router(reports.router)
app.include_router(settings_route.router)
app.include_router(threat_intelligence.router)
app.include_router(monitoring.router)
app.include_router(chat.router)
app.include_router(contacts.router)
app.include_router(email_route.router)
app.include_router(alerts_route.router)
app.include_router(incidents_route.router)