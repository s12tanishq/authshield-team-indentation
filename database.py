"""
database.py — AuthShield Backend
Branch: feature/backend-db (Person D)

Responsibilities (per the branch matrix):
- Open/close connections to authshield.db (SQLite)
- Look up trusted portals by domain and by DOM hash
- Decide SAFE / DANGER / UNKNOWN and hand that back to main.py

NOTE: This file only READS from "trusted_portals". Creating the table and
inserting the baseline hashes is seed.py's job, not this file's.
"""

import sqlite3
from contextlib import contextmanager
from typing import Optional

DB_PATH = "authshield.db"


@contextmanager
def get_connection():
    """
    Opens a connection to authshield.db and guarantees it gets closed,
    even if something goes wrong in between. Any code that needs the DB
    should use this with a 'with' block instead of opening sqlite3 directly.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us read columns by name: row["domain"]
    try:
        yield conn
    finally:
        conn.close()


def get_portal_by_domain(domain: str) -> Optional[sqlite3.Row]:
    """Return the trusted_portals row for this exact domain, or None."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT domain, dom_hash FROM trusted_portals WHERE domain = ?",
            (domain,)
        )
        return cursor.fetchone()


def get_portal_by_hash(dom_hash: str) -> Optional[sqlite3.Row]:
    """Return the trusted_portals row whose dom_hash matches this hash, or None."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT domain, dom_hash FROM trusted_portals WHERE dom_hash = ?",
            (dom_hash,)
        )
        return cursor.fetchone()


def verify_dom_hash(domain: str, dom_hash: str) -> dict:
    """
    Main function main.py will call from the /verify route.
    Returns the exact API Response Schema from the contract:
    { "status": "SAFE" | "DANGER" | "UNKNOWN", "message": string }
    """

    # Case 1 — SAFE: this domain is registered AND its hash matches the baseline.
    own_record = get_portal_by_domain(domain)
    if own_record and own_record["dom_hash"] == dom_hash:
        return {
            "status": "SAFE",
            "message": f"'{domain}' matches its verified baseline structure."
        }

    # Case 2 — DANGER: this exact hash belongs to a DIFFERENT trusted domain.
    # This is the actual clone attack: someone copies a real login page's
    # HTML byte-for-byte and hosts it on a fake domain. Same hash, wrong domain.
    hash_owner = get_portal_by_hash(dom_hash)
    if hash_owner and hash_owner["domain"] != domain:
        return {
            "status": "DANGER",
            "message": (
                f"Cloned Portal Detected! Form structure matches "
                f"{hash_owner['domain']}, but domain '{domain}' is fraudulent."
            )
        }

    # Case 3 — UNKNOWN: no baseline record explains this domain or this hash.
    return {
        "status": "UNKNOWN",
        "message": f"No baseline record found for '{domain}'."
    }
