"""
AuthShield Backend API
Branch: feature/backend-api
Owner:  Person C

Responsibilities of this file:
- Run a FastAPI server with CORS enabled (so the Chrome extension's
  background.js, which runs on a chrome-extension:// origin, is allowed
  to call http://localhost:8000)
- Expose POST /verify which receives {domain, dom_hash} and returns
  {status, message}
- Talk to database.py (Person D's module) to look up trusted portal
  baselines - this file does NOT touch SQLite directly

INTERFACE CONTRACT EXPECTED FROM database.py (Person D):
    get_portal_by_domain(domain: str) -> dict | None
        Returns {"domain": str, "dom_hash": str, "name": str} if this
        domain is a known/registered portal, else None.

    get_portal_by_hash(dom_hash: str) -> dict | None
        Returns {"domain": str, "dom_hash": str, "name": str} for ANY
        trusted portal whose baseline hash equals dom_hash, else None.
        (This is what makes clone detection possible - see logic below.)

If database.py doesn't have get_portal_by_hash yet, flag it to Person D -
without it, the core "cloned portal" detection case cannot work.
"""

import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

import database  # Person D's module: database.py

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="AuthShield Verification API", version="1.0.0")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("authshield")

# CORS: a Chrome extension's background.js calls this API from a
# chrome-extension://<id> origin, which browsers treat as cross-origin.
# Without CORS enabled, the fetch() in background.js would be blocked
# by the browser before it ever reaches this server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to ["chrome-extension://<your-extension-id>"] before shipping
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas (must match the STRICT DATA CONTRACTS exactly)
# ---------------------------------------------------------------------------

class VerifyRequest(BaseModel):
    domain: str = Field(..., min_length=1, description="e.g. webmail.college.edu")
    dom_hash: str = Field(..., description="SHA-256 hex digest of the cleaned DOM")

    @field_validator("dom_hash")
    @classmethod
    def hash_must_be_sha256_hex(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError("dom_hash must be a 64-character SHA-256 hex digest")
        return v

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        return v.strip().lower()


class VerifyResponse(BaseModel):
    status: str  # "SAFE" | "DANGER" | "UNKNOWN"
    message: str


# ---------------------------------------------------------------------------
# Core route
# ---------------------------------------------------------------------------

@app.post("/verify", response_model=VerifyResponse)
async def verify_dom_hash(payload: VerifyRequest):
    """
    Detection logic (this is the actual anti-phishing decision):

    1. Is this domain one we already trust (registered baseline)?
       - Hash matches its baseline -> SAFE. This is the real portal.
       - Hash does NOT match       -> UNKNOWN. The real site's own layout
         changed, or something odd is going on; we don't have enough
         evidence to call it a clone, so we don't cry wolf.

    2. If the domain is NOT one we trust:
       - Does this exact DOM hash match some OTHER trusted portal's
         baseline? That means someone copied a real login form's
         structure pixel-for-pixel and is now serving it from a
         different domain. That IS the clone-phishing pattern ->
         DANGER.
       - No match anywhere -> UNKNOWN. We simply have no baseline for
         this site; we're not saying it's safe, just that we can't
         verify it yet.
    """
    try:
        known_domain_record = database.get_portal_by_domain(payload.domain)

        if known_domain_record is not None:
            if known_domain_record["dom_hash"].lower() == payload.dom_hash:
                return VerifyResponse(
                    status="SAFE",
                    message=f"Verified. This matches the known baseline for {payload.domain}.",
                )
            return VerifyResponse(
                status="UNKNOWN",
                message=(
                    f"{payload.domain} is a registered portal, but its form "
                    "structure doesn't match our stored baseline. It may have "
                    "been redesigned, or something has changed - treat with caution."
                ),
            )

        # Domain isn't registered at all - check if its DOM is a clone of
        # some other trusted portal.
        cloned_from = database.get_portal_by_hash(payload.dom_hash)
        if cloned_from is not None:
            return VerifyResponse(
                status="DANGER",
                message=(
                    f"Cloned Portal Detected! Form structure matches "
                    f"{cloned_from.get('name', cloned_from['domain'])}, "
                    f"but this domain ({payload.domain}) is not the official one."
                ),
            )

        return VerifyResponse(
            status="UNKNOWN",
            message=f"No baseline exists for {payload.domain} yet. Cannot verify.",
        )

    except AttributeError as exc:
        # Raised if database.py hasn't implemented the expected function yet
        logger.exception("database.py is missing an expected function")
        raise HTTPException(
            status_code=500,
            detail=f"Backend misconfiguration: {exc}",
        )
    except Exception:
        logger.exception("Unexpected error while verifying domain hash")
        raise HTTPException(status_code=500, detail="Internal verification error")


# ---------------------------------------------------------------------------
# Health check - handy for confirming the server is up before wiring the
# extension to it, and for teammates testing independently
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "authshield-backend"}


# ---------------------------------------------------------------------------
# Local dev entrypoint: `python main.py`
# (In practice you'll more often run: uvicorn main:app --reload)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)