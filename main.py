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
from difflib import SequenceMatcher

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

import database  # Person D's module: database.py
import tranco_client  # Tranco popularity fallback (see tranco_client.py)

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
    feature_signature: str = Field(default="", max_length=12000)

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
    similarity_score: float | None = None
    similar_portal: str | None = None
    domain_similarity_score: float | None = None
    similar_domain: str | None = None
    # Tranco fallback fields — populated ONLY for the catch-all "no baseline"
    # case (domain absent from trusted_portals and no clone/phishing/lookalike
    # match). Always None on every other verdict path. See tranco_client.py.
    tranco_rank: int | None = None
    tranco_source: str | None = None


class ReportRequest(VerifyRequest):
    report_type: str = Field(..., pattern="^(trusted|phishing)$")


SIMILARITY_DANGER_THRESHOLD = 75.0
DOMAIN_LOOKALIKE_THRESHOLD = 82.0

# Tranco fallback tuning. Only consulted for the catch-all "no baseline"
# case (see verify_dom_hash) — never affects hash matching, phishing
# signatures, or the domain-lookalike-vs-our-own-registry check above,
# all of which are resolved before Tranco is ever touched.
TRANCO_ESTABLISHED_RANK_THRESHOLD = 100_000  # top 100k = "well-established" site


def find_most_similar_portal(feature_signature: str) -> tuple[dict | None, float]:
    """Compare normalized, non-sensitive form metadata only."""
    if not feature_signature:
        return None, 0.0
    best_portal, best_score = None, 0.0
    for portal in database.get_portals_with_feature_signatures():
        score = SequenceMatcher(None, feature_signature, portal["feature_signature"]).ratio() * 100
        if score > best_score:
            best_portal, best_score = portal, score
    return best_portal, round(best_score, 1)


def normalize_hostname(hostname: str) -> str:
    """Hostname-only normalization; URLs and paths are never compared."""
    return hostname.strip().lower().rstrip(".")


def find_most_similar_domain(current_domain: str) -> tuple[dict | None, float]:
    """Find likely typosquats without treating a string match as trust."""
    current = normalize_hostname(current_domain)
    best_portal, best_score = None, 0.0
    for portal in database.get_all_portals():
        trusted = normalize_hostname(portal["domain"])
        if current == trusted:
            continue
        score = SequenceMatcher(None, current, trusted).ratio() * 100
        if score > best_score:
            best_portal, best_score = portal, score
    return best_portal, round(best_score, 1)


async def _safe_get_domain_popularity(domain: str) -> dict:
    """
    Wraps tranco_client.get_domain_popularity() with an extra safety net so
    a Tranco outage or unexpected exception can NEVER take down /verify.
    tranco_client already fails closed internally; this is a belt-and-braces
    guard around it.
    """
    try:
        return await tranco_client.get_domain_popularity(domain)
    except Exception:
        logger.exception("Tranco fallback lookup failed for %s", domain)
        return {"domain": domain, "rank": None, "source": "unavailable", "checked_at": None}


def _build_no_baseline_message(domain: str, popularity: dict) -> str:
    """
    Builds the UNKNOWN message for the catch-all "no baseline" case, using
    Tranco rank purely as extra context for the person reading the banner -
    it never changes the UNKNOWN status itself.
    """
    rank = popularity.get("rank")

    if rank is not None and rank <= TRANCO_ESTABLISHED_RANK_THRESHOLD:
        return (
            f"No baseline exists for {domain} yet, so we can't verify this specific "
            f"login form. For context: {domain} is a well-established site (Tranco "
            f"popularity rank {rank:,}), which makes it less likely to be disposable "
            "phishing infrastructure - but this is not a substitute for a verified "
            "baseline. Treat with normal caution."
        )

    if rank is not None:
        return (
            f"No baseline exists for {domain} yet. It does have some measurable public "
            f"traffic (Tranco rank {rank:,}), but not enough to meaningfully vouch for "
            "it. Cannot verify - proceed with caution."
        )

    return (
        f"No baseline exists for {domain} yet, and it has no measurable public traffic "
        "footprint (unranked in Tranco's top 1M sites). This is common for both brand-new "
        "legitimate sites and freshly stood-up phishing infrastructure, so it does not "
        "confirm anything either way - we simply cannot verify this site. Exercise extra "
        "caution before entering credentials."
    )


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
        similar_portal, similarity_score = find_most_similar_portal(payload.feature_signature)
        similar_domain_portal, domain_similarity_score = find_most_similar_domain(payload.domain)

        if (similar_portal is not None
                and similarity_score >= SIMILARITY_DANGER_THRESHOLD
                and payload.domain != similar_portal["domain"]):
            return VerifyResponse(
                status="DANGER",
                message=(
                    f"Login form is {similarity_score:.1f}% similar to {similar_portal['name']}, "
                    f"but {payload.domain} is not an approved domain."
                ),
                similarity_score=similarity_score,
                similar_portal=similar_portal["domain"],
                domain_similarity_score=domain_similarity_score or None,
                similar_domain=similar_domain_portal["domain"] if similar_domain_portal else None,
            )

        if known_domain_record is not None:
            if known_domain_record["dom_hash"].lower() == payload.dom_hash:
                database.save_feature_signature(payload.domain, payload.feature_signature)
                return VerifyResponse(
                    status="SAFE",
                    message=f"Verified. This matches the known baseline for {payload.domain}.",
                    similarity_score=similarity_score or None,
                    similar_portal=similar_portal["domain"] if similar_portal else None,
                    domain_similarity_score=domain_similarity_score or None,
                    similar_domain=similar_domain_portal["domain"] if similar_domain_portal else None,
                )
            return VerifyResponse(
                status="UNKNOWN",
                message=(
                    f"{payload.domain} is a registered portal, but its form "
                    "structure doesn't match our stored baseline. It may have "
                    "been redesigned, or something has changed - treat with caution."
                ),
                similarity_score=similarity_score or None,
                similar_portal=similar_portal["domain"] if similar_portal else None,
                domain_similarity_score=domain_similarity_score or None,
                similar_domain=similar_domain_portal["domain"] if similar_domain_portal else None,
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
                similarity_score=100.0,
                similar_portal=cloned_from["domain"],
                domain_similarity_score=domain_similarity_score or None,
                similar_domain=similar_domain_portal["domain"] if similar_domain_portal else None,
            )

        known_phishing = database.get_phishing_signature_by_hash(payload.dom_hash)
        if known_phishing is not None:
            return VerifyResponse(
                status="DANGER",
                message=(
                    "Known phishing form signature detected: "
                    f"{known_phishing['description']}. Do not enter credentials."
                ),
                similarity_score=similarity_score or None,
                similar_portal=similar_portal["domain"] if similar_portal else None,
                domain_similarity_score=domain_similarity_score or None,
                similar_domain=similar_domain_portal["domain"] if similar_domain_portal else None,
            )

        # This runs only because content.js found a login form. A close
        # hostname by itself never makes a site SAFE; it is a typosquat risk.
        if (similar_domain_portal is not None
                and domain_similarity_score >= DOMAIN_LOOKALIKE_THRESHOLD):
            return VerifyResponse(
                status="DANGER",
                message=(
                    f"Domain {payload.domain} is {domain_similarity_score:.1f}% similar to "
                    f"approved portal {similar_domain_portal['domain']}, but is not approved."
                ),
                similarity_score=similarity_score or None,
                similar_portal=similar_portal["domain"] if similar_portal else None,
                domain_similarity_score=domain_similarity_score,
                similar_domain=similar_domain_portal["domain"],
            )

        # ------------------------------------------------------------
        # Fallback: nothing in trusted_portals, no hash clone, no known
        # phishing signature, no lookalike match against our own registry.
        # This is the ONLY place Tranco is consulted - it is a popularity
        # enrichment signal for an otherwise-blind "no baseline" verdict,
        # never a replacement for structural verification. It can never
        # upgrade this to SAFE and never downgrade an existing DANGER,
        # because every DANGER/SAFE branch above already returned.
        # ------------------------------------------------------------
        popularity = await _safe_get_domain_popularity(payload.domain)
        message = _build_no_baseline_message(payload.domain, popularity)

        return VerifyResponse(
            status="UNKNOWN",
            message=message,
            similarity_score=similarity_score or None,
            similar_portal=similar_portal["domain"] if similar_portal else None,
            domain_similarity_score=domain_similarity_score or None,
            similar_domain=similar_domain_portal["domain"] if similar_domain_portal else None,
            tranco_rank=popularity["rank"],
            tranco_source=popularity["source"],
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


@app.post("/reports")
async def submit_report(payload: ReportRequest):
    """Store an untrusted suggestion; it cannot change verdicts by itself."""
    report_id = database.create_pending_report(
        payload.domain, payload.dom_hash, payload.feature_signature, payload.report_type
    )
    return {
        "status": "PENDING_REVIEW",
        "message": "Submission recorded. A project maintainer must approve it before the registry changes.",
        "report_id": report_id,
    }


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
