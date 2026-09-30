import asyncio
import logging
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import Base, engine, ensure_schema, SessionLocal
from rate_limit import limiter
import models  # noqa: F401 — ensures models are registered on Base before create_all
from routers import ip, url, files, history
from services.blocklists import registry, IP_REFRESH_SECONDS
from services.ip_intel import backfill_security_checks as backfill_ip_security_checks
from services.ip_intel import backfill_reverse_dns
from services.url_intel import backfill_security_checks as backfill_url_security_checks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("intel")

Base.metadata.create_all(bind=engine)
ensure_schema()

app = FastAPI(title="Intel Threat Lookup API")

# Per-client-IP rate limiting — this is a free, keyless, publicly-reachable
# lookup service that fans each request out to several upstream sources
# (ip-api.com, RDAP, WHOIS, URLhaus); without a limit here a single caller
# could hammer those upstreams through us, or exhaust the WHOIS/RDAP quota
# other users share. Tighter per-route limits live on the expensive lookup
# routes themselves (services/../routers/*.py); this default covers everything
# else and wires the limiter + the 429 handler into the app.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS_ALLOWED_ORIGINS="https://intelreport.in,https://www.intelreport.in" in prod;
# left unset (-> "*") for local dev so the Vite dev server on any port still works.
_allowed_origins = os.environ.get("CORS_ALLOWED_ORIGINS")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins.split(",") if _allowed_origins else ["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return response


app.include_router(ip.router)
app.include_router(url.router)
app.include_router(files.router)
app.include_router(history.router)


@app.on_event("startup")
async def load_blocklists():
    def _load():
        logger.info("Loading threat-intel vendor feeds...")
        registry.refresh_all()
        logger.info("Blocklists loaded: %s", registry.stats)

        # Catch up any rows cached before security_checks existed, so results
        # don't silently miss the new panel until their 24h cache happens to expire.
        db = SessionLocal()
        try:
            ip_count = backfill_ip_security_checks(db)
            url_count = backfill_url_security_checks(db)
            if ip_count or url_count:
                logger.info("Backfilled security_checks: %d IP row(s), %d URL row(s)", ip_count, url_count)
            rdns_count = backfill_reverse_dns(db)
            if rdns_count:
                logger.info("Backfilled reverse_dns: %d IP row(s)", rdns_count)
        finally:
            db.close()

    await asyncio.to_thread(_load)

    async def refresh_loop():
        while True:
            await asyncio.sleep(IP_REFRESH_SECONDS)
            await asyncio.to_thread(registry.refresh_all)
            logger.info("Blocklists refreshed: %s", registry.stats)

    asyncio.create_task(refresh_loop())


@app.get("/api/health")
def health():
    return {"status": "ok", "blocklist_stats": registry.stats if registry._loaded else "loading"}
