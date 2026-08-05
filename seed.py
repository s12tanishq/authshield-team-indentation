"""
AuthShield - seed.py
Branch: feature/backend-db

Responsibilities:
  1. Auto-create authshield.db and trusted_portals table if they don't exist
     (independently of database.py — both handle this on their own).
  2. Pre-load known authentic portal records into trusted_portals.
  3. Idempotent — safe to run multiple times. Skips any domain that is
     already registered; never duplicates or overwrites existing records.

Usage:
    python seed.py
    Then: uvicorn main:app --reload

Seeded Portals:
    - College ERP Portal (erp.college.edu)

===============================================================
FULL CROSS-FILE VERIFICATION — ALL CONTRACTS CONFIRMED
(same as database.py — see database.py docstring for full list)
===============================================================

  ⚠ NOTE ON DOM HASHES IN SEED DATA — READ BEFORE MERGING
  ─────────────────────────────────────────────────────────
  The dom_hash values below are PLACEHOLDER hashes.
  They MUST be replaced with real hashes before production use.

  How to capture a real hash — via main.py (Person C) RECOMMENDED:

    1. Ask Person C to temporarily add this log line in main.py /verify:
           logger.info(f"[SEED] domain={payload.domain} hash={payload.dom_hash}")
       The logger is already set up in main.py — just add the one line.
       ✔ Pydantic has already normalized hash to lowercase 64-char hex
         by the time it reaches the logger — exact value, ready to paste.

    2. Start the backend:
           uvicorn main:app --reload

    3. Load the authentic portal (e.g. https://erp.college.edu) in Chrome
       with the AuthShield extension loaded and enabled.

    4. content.js computes hash → background.js POSTs to /verify →
       hash appears in the uvicorn terminal output.

    5. Copy the hash, replace the PLACEHOLDER value in SEED_PORTALS below.

    6. Re-run: python seed.py

    7. Ask Person C to remove the temporary log line.

  ✔ Why this is the cleanest approach:
    - main.py's Pydantic validator normalizes domain + hash to exact
      database format before logging — no manual formatting needed.
    - background.js "return true" is confirmed present — the POST to
      /verify will always complete before background.js responds.
  ─────────────────────────────────────────────────────────────────
"""

from database import get_connection, insert_portal, get_all_portals, DB_PATH, TABLE_NAME
from datetime import datetime

# ------------------------------------------------------------------
# Seed Data
# ------------------------------------------------------------------

# Each entry:
#   "domain"      — exact hostname, lowercase, no https://, no trailing slash
#   "dom_hash"    — SHA-256 hex string from content.js  ← REPLACE PLACEHOLDERS
#   "portal_name" — human-readable label.
#                   Appears in main.py DANGER message as:
#                   "Cloned Portal Detected! Form structure matches <portal_name>"
#                   Confirmed from main.py code:
#                   cloned_from.get("name", cloned_from["domain"])
#                   database.py maps portal_name → "name" via _row_to_dict() ✔

SEED_PORTALS = [
    {
        "domain":      "erp.college.edu",
        "dom_hash":    "PLACEHOLDER_REPLACE_WITH_REAL_SHA256_HASH_FROM_CONTENT_JS",
        "portal_name": "College ERP Portal",
    },
    # ── Add more authentic portals here as the registry grows ────────
    # {
    #     "domain":      "webmail.college.edu",
    #     "dom_hash":    "PLACEHOLDER_REPLACE_WITH_REAL_SHA256_HASH",
    #     "portal_name": "College Webmail",
    # },
]


# ------------------------------------------------------------------
# Seed Runner
# ------------------------------------------------------------------

def run_seed():
    """
    Creates the database/table if needed, then inserts each portal in
    SEED_PORTALS if it doesn't already exist. Prints clear status per portal.
    """
    print("=" * 60)
    print("  AuthShield — seed.py")
    print(f"  Database : {DB_PATH}")
    print(f"  Table    : {TABLE_NAME}")
    print(f"  Time     : {datetime.utcnow().isoformat()} UTC")
    print("=" * 60)

    # Trigger independent DB + table creation (seed.py is self-sufficient).
    # get_connection() in database.py runs CREATE TABLE IF NOT EXISTS.
    conn = get_connection()
    conn.close()
    print(f"\n✔ Database and table verified / created at: {DB_PATH}\n")

    existing = {p["domain"] for p in get_all_portals()}

    inserted = 0
    skipped  = 0

    print("  Seeding portals:")
    print("  " + "-" * 56)

    for portal in SEED_PORTALS:
        domain      = portal["domain"]
        dom_hash    = portal["dom_hash"]
        portal_name = portal["portal_name"]

        if domain in existing:
            print(f"  ⏭  SKIPPED  | {portal_name} ({domain})")
            print(f"              | Already registered — not overwriting.")
            skipped += 1
            continue

        if "PLACEHOLDER" in dom_hash.upper():
            print(f"  ⚠  WARNING  | {portal_name} ({domain})")
            print(f"              | Inserting PLACEHOLDER hash.")
            print(f"              | Replace with real hash before production.")
            print(f"              | See module docstring for capture instructions.")

        success = insert_portal(domain, dom_hash, portal_name)

        if success:
            print(f"  ✔  INSERTED | {portal_name} ({domain})")
            print(f"              | Hash: {dom_hash[:24]}...")
            inserted += 1
        else:
            print(f"  ✘  FAILED   | {portal_name} ({domain})")
            print(f"              | insert_portal() returned False — check logs.")

    print("  " + "-" * 56)
    print(f"\n  Summary: {inserted} inserted, {skipped} skipped.")

    print("\n  Current trusted_portals registry:")
    print("  " + "-" * 56)
    all_portals = get_all_portals()
    if not all_portals:
        print("  (empty)")
    for p in all_portals:
        print(f"  [{p['id']:>3}] {p['portal_name']}")
        print(f"        Domain : {p['domain']}")
        print(f"        Hash   : {p['dom_hash'][:24]}...")
        print(f"        Added  : {p['created_at']}")

    print("\n" + "=" * 60)
    print("  Seed complete.")
    print("  Next: uvicorn main:app --reload")
    print("=" * 60 + "\n")


# ------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------

if __name__ == "__main__":
    run_seed()