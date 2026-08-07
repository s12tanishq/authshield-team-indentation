"""
AuthShield - tranco_client.py
Extension: Tranco popularity fallback for domain verification

Responsibilities:
  - Query the Tranco API (https://tranco-list.eu/api/ranks/domain/{domain})
    for a domain's public popularity rank.
  - Cache results in authshield.db (table: tranco_cache) so we don't hit
    the external API on every single page load - content.js can fire this
    verification repeatedly, and Tranco's list only updates daily anyway.
  - Fail closed to "unknown popularity", never raise. A Tranco outage must
    never break /verify - it is a FALLBACK ENRICHMENT signal only, used by
    main.py strictly for domains that:
        1. Are NOT in our own trusted_portals registry, AND
        2. Did not already match a clone-hash, a known phishing signature,
           or a domain-lookalike-against-our-own-registry check.
    It never produces a SAFE verdict and never overrides a DANGER verdict
    reached via hash matching or form/domain similarity - those checks run
    entirely before this module is ever consulted (see main.py).

Public API:
    async def get_domain_popularity(domain: str) -> dict
        Returns:
            {
                "domain": str,
                "rank": int | None,     # None if unranked / lookup failed
                "source": "cache" | "api" | "unavailable",
                "checked_at": ISO8601 str,
            }
"""

import logging
from datetime import datetime, timedelta

import httpx
import tldextract

import database

logger = logging.getLogger("authshield.tranco")

TRANCO_API_BASE = "https://tranco-list.eu/api"
REQUEST_TIMEOUT_SECONDS = 4.0

# Tranco publishes a fresh combined list daily - no point re-querying more
# often than that, and it keeps us well clear of any fair-use limits on
# their free, unauthenticated endpoint.
CACHE_TTL = timedelta(hours=24)

# Tranco ranks pay-level/registrable domains (e.g. "amazon.in"), not every
# individual hostname string - "www.amazon.in" or "accounts.google.com"
# have no entry of their own even though the site is obviously huge. A
# naive `.lstrip("www.")` is not enough (breaks on "sub.example.co.uk",
# ".edu" sites, etc.), so we use tldextract's public-suffix-list-aware
# parser to get the actual registrable domain before querying/caching.
# `suffix_list_urls=()` disables any live fetch of the public suffix list
# at runtime - we only ever use the snapshot bundled with the package, so
# this never depends on outbound network access beyond the Tranco call
# itself.
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def _registrable_domain(hostname: str) -> str:
    """
    Returns the registrable (pay-level) domain for `hostname`, e.g.
    "accounts.google.com" -> "google.com", "sub.example.co.uk" ->
    "example.co.uk". Falls back to the original hostname unchanged for
    inputs with no recognizable public suffix (localhost, our "local-file"
    / "unknown-origin" sentinels from content.js, bare IPs, etc).
    """
    ext = _extractor(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname


async def get_domain_popularity(domain: str) -> dict:
    """
    Returns Tranco popularity info for `domain`, using the local cache
    when fresh, and falling back to a live API call otherwise.

    Internally this queries/caches by the REGISTRABLE domain (see
    _registrable_domain) since that's what Tranco actually ranks - a
    lookup for "www.amazon.in" or "accounts.google.com" would otherwise
    come back unranked even though the underlying site is huge. The
    returned "domain" field still reflects what was actually looked up
    (the registrable domain), so the caller/UI can be transparent about it.

    Never raises. On any failure (network error, timeout, malformed
    response, cache error) this returns rank=None / source="unavailable"
    so callers can proceed with a plain "we don't know" fallback message
    rather than losing the response entirely.
    """
    normalized = domain.strip().lower()
    registrable = _registrable_domain(normalized)

    try:
        cached = database.get_cached_tranco_rank(registrable)
        if cached is not None:
            checked_at = datetime.fromisoformat(cached["checked_at"])
            if datetime.utcnow() - checked_at < CACHE_TTL:
                return {
                    "domain": registrable,
                    "rank": cached["rank"],
                    "source": "cache",
                    "checked_at": cached["checked_at"],
                }
    except Exception:
        # Cache read failure should never block a live lookup attempt.
        logger.exception("[tranco_client] cache read failed for %s", registrable)

    rank = await _fetch_rank_from_api(registrable)
    checked_at = datetime.utcnow().isoformat()

    try:
        database.set_cached_tranco_rank(registrable, rank, checked_at)
    except Exception:
        # Cache write failure is non-fatal - we still return the live result.
        logger.exception("[tranco_client] cache write failed for %s", registrable)

    return {
        "domain": registrable,
        "rank": rank,
        "source": "unavailable" if rank is None else "api",
        "checked_at": checked_at,
    }


async def _fetch_rank_from_api(domain: str) -> int | None:
    """
    Calls GET https://tranco-list.eu/api/ranks/domain/{domain}

    Expected response shape:
        {"ranks": [{"date": "YYYY-MM-DD", "rank": 12345}, ...]}
    ordered with the most recent date last (or first - we don't rely on
    order, we just take the entry with the max date).

    Returns the most recent rank as an int, or None if the domain is
    unranked / the request failed / the response was malformed.
    """
    url = f"{TRANCO_API_BASE}/ranks/domain/{domain}"

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(
                url,
                headers={"User-Agent": "AuthShield/1.0 (+https://github.com/authshield)"},
            )
    except httpx.RequestError as exc:
        # logger.exception (not .warning) so the full traceback - including
        # the underlying SSL/connection error class - always lands in the
        # uvicorn console. On macOS with the python.org installer, this is
        # very often ssl.SSLCertVerificationError because the interpreter's
        # bundled CA bundle was never installed - see the fix instructions
        # in the "Install Certificates.command" script shipped alongside
        # python.org's Python. If you see CERTIFICATE_VERIFY_FAILED below,
        # that's it.
        logger.exception("[tranco_client] request failed for %s (%s)", domain, type(exc).__name__)
        return None

    if response.status_code == 404:
        # Domain has no ranking history at all - a legitimate "unranked" result.
        return None

    if response.status_code != 200:
        logger.warning(
            "[tranco_client] unexpected status %s for %s — body: %.200s",
            response.status_code, domain, response.text,
        )
        return None

    try:
        payload = response.json()
        ranks = payload.get("ranks") or []
        if not ranks:
            return None
        latest = max(ranks, key=lambda entry: entry.get("date", ""))
        rank = latest.get("rank")
        return int(rank) if rank is not None else None
    except (ValueError, TypeError, AttributeError) as exc:
        logger.warning("[tranco_client] malformed response for %s: %s", domain, exc)
        return None
