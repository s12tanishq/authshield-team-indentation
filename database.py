"""
AuthShield - database.py
Branch: feature/backend-db

Responsibilities:
  1. Manage SQLite connection to authshield.db.
  2. Auto-create the database and trusted_portals table if they don't exist
     (independently of seed.py — both handle this on their own).
  3. Expose two lookup functions consumed directly by main.py (Person C):
       - get_portal_by_domain(domain)  → dict | None
       - get_portal_by_hash(dom_hash)  → dict | None
  4. Expose utilities used by seed.py:
       - get_all_portals()             → list[dict]
       - insert_portal(...)            → bool

===============================================================
FULL CROSS-FILE VERIFICATION — ALL CONTRACTS CONFIRMED
===============================================================

✔ content.js (Person B):
    Sends   : { action: "VERIFY_DOM_HASH", domain, hash }
    hash    : 64-char lowercase SHA-256 hex (crypto.subtle)
    Reads   : response.status / response.message

✔ background.js (Person A):
    Receives: message.domain, message.hash from content.js
    POSTs   : { domain, dom_hash: hash } to http://localhost:8000/verify
    Has     : "return true" in onMessage → async channel stays open ✔
    Stores  : { domain, status, message, timestamp } in chrome.storage.session
    Sends   : { status, message } back to content.js

✔ manifest.json (Person A):
    Permissions     : "storage", "activeTab", "scripting" ✔
    host_permissions: "http://localhost:8000/*" ✔
    content_scripts : content.js at "document_idle" on "<all_urls>" ✔

✔ popup.js (Person A):
    Reads   : chrome.storage.session key `tabStatus_${activeTab.id}`
    Matches : background.js writes `tabStatus_${tabId}` ✔
    Uses    : record.status / record.message / record.domain ✔

✔ popup.html (Person A):
    Elements: #status-badge, #status-text, #status-message,
              #domain-value, #refresh-button — all match popup.js ✔

✔ main.py (Person C):
    Validates: domain → lowercase, dom_hash → 64-char lowercase hex
    Calls   : database.get_portal_by_domain(payload.domain)
              database.get_portal_by_hash(payload.dom_hash)
    Returns : VerifyResponse(status, message) — no "detail" field ✔

✔ database.py (Person D — this file):
    Exposes : get_portal_by_domain(), get_portal_by_hash()
    Returns : dict with "name" alias for main.py compatibility
    Inserts : domain.strip().lower(), dom_hash.strip().lower()
    Queries : domain.strip().lower(), dom_hash.strip().lower()
    Casing  : matches Pydantic normalization in main.py ✔

===============================================================
"""

import sqlite3
import os
from datetime import datetime

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

# Database file lives in the same directory as this file.
# If main.py and database.py are ever moved to different folders,
# update DB_PATH accordingly and inform Person C.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "authshield.db")

# Table name — must match seed.py exactly.
TABLE_NAME = "trusted_portals"


# ------------------------------------------------------------------
# Schema Definition
# ------------------------------------------------------------------

# trusted_portals table columns:
#   id          — auto-increment primary key (readability + future admin use)
#   domain      — registered authentic hostname e.g. "erp.college.edu" UNIQUE
#   dom_hash    — SHA-256 hash of the cleaned structural DOM of the login form
#   portal_name — human-readable label e.g. "College ERP Portal"
#   created_at  — ISO timestamp when the record was first inserted
#   updated_at  — ISO timestamp when dom_hash was last updated

CREATE_TABLE_SQL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    domain      TEXT     NOT NULL UNIQUE,
    dom_hash    TEXT     NOT NULL,
    portal_name TEXT     NOT NULL,
    created_at  TEXT     NOT NULL,
    updated_at  TEXT     NOT NULL
);
"""


# ------------------------------------------------------------------
# Connection Helper
# ------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """
    Opens and returns a connection to authshield.db.
    Auto-creates the database file and trusted_portals table
    if they do not already exist.

    Returns:
        sqlite3.Connection with row_factory = sqlite3.Row so all
        columns are accessible by name (row["domain"], row["dom_hash"], etc.)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(CREATE_TABLE_SQL)
    conn.commit()
    return conn


# ------------------------------------------------------------------
# Public Functions — consumed directly by main.py (Person C)
# ------------------------------------------------------------------

def get_portal_by_domain(domain: str) -> dict | None:
    """
    Looks up a trusted portal record by its registered domain.

    Called by main.py as:
        known_domain_record = database.get_portal_by_domain(payload.domain)

    main.py then checks:
        if known_domain_record is not None:
            if known_domain_record["dom_hash"].lower() == payload.dom_hash:
                → SAFE   (domain known, hash matches baseline)
            else:
                → UNKNOWN (domain known, hash changed — possible redesign)

    Args:
        domain (str): Hostname from background.js. Already lowercased by
                      main.py's Pydantic normalize_domain validator before
                      this function is called.

    Returns:
        dict with keys: id, domain, dom_hash, portal_name, name,
                        created_at, updated_at
        None if domain is not registered in trusted_portals.
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT * FROM {TABLE_NAME} WHERE domain = ?",
            (domain.strip().lower(),)
        )
        row = cursor.fetchone()
        return _row_to_dict(row) if row else None

    except sqlite3.Error as db_err:
        print(f"[AuthShield][database.py] get_portal_by_domain() error: {db_err}")
        return None
    finally:
        if conn:
            conn.close()


def get_portal_by_hash(dom_hash: str) -> dict | None:
    """
    Looks up a trusted portal record by its baseline DOM hash.

    Called by main.py as:
        cloned_from = database.get_portal_by_hash(payload.dom_hash)

    main.py then checks:
        if cloned_from is not None:
            → DANGER: form structure matches a known portal served
              from a different (fraudulent) domain — clone phishing.
            Uses: cloned_from.get("name", cloned_from["domain"])
            to name the authentic portal that was cloned in the
            DANGER message shown to the user via content.js banner
            and popup.js status display.

    This is the CORE of clone-phishing detection:
    An unregistered domain whose DOM hash matches a different trusted
    portal's baseline = login form copied from a real site and served
    from a fraudulent domain.

    Args:
        dom_hash (str): SHA-256 hex string from content.js. Already
                        validated to 64-char lowercase by main.py's
                        Pydantic hash_must_be_sha256_hex validator.

    Returns:
        dict with keys: id, domain, dom_hash, portal_name, name,
                        created_at, updated_at
        None if no trusted portal has this hash as its baseline.

    ✔ "name" key confirmed required by main.py:
        main.py reads: cloned_from.get("name", cloned_from["domain"])
        _row_to_dict() maps portal_name → "name" — KeyError impossible.
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT * FROM {TABLE_NAME} WHERE dom_hash = ?",
            (dom_hash.strip().lower(),)
        )
        row = cursor.fetchone()
        return _row_to_dict(row) if row else None

    except sqlite3.Error as db_err:
        print(f"[AuthShield][database.py] get_portal_by_hash() error: {db_err}")
        return None
    finally:
        if conn:
            conn.close()


# ------------------------------------------------------------------
# Internal Helper
# ------------------------------------------------------------------

def _row_to_dict(row: sqlite3.Row) -> dict:
    """
    Converts a sqlite3.Row to a plain dict and adds the "name" alias
    required by main.py alongside the original "portal_name" key.

    Both keys carry the same value:
        "portal_name" → used by seed.py / admin tooling
        "name"        → used by main.py (confirmed from code review)
    """
    d = dict(row)
    d["name"] = d["portal_name"]
    return d


# ------------------------------------------------------------------
# Utilities — used by seed.py and future admin tooling
# ------------------------------------------------------------------

def get_all_portals() -> list[dict]:
    """
    Returns all registered portals as a list of dicts.
    Used by seed.py to check existing records before inserting.
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {TABLE_NAME}")
        rows = cursor.fetchall()
        return [_row_to_dict(row) for row in rows]
    except sqlite3.Error as db_err:
        print(f"[AuthShield][database.py] get_all_portals() error: {db_err}")
        return []
    finally:
        if conn:
            conn.close()


def insert_portal(domain: str, dom_hash: str, portal_name: str) -> bool:
    """
    Inserts a new portal record into trusted_portals.
    Used by seed.py. Skips silently if domain already exists (idempotent).

    Args:
        domain      (str): Authentic hostname e.g. "erp.college.edu"
        dom_hash    (str): SHA-256 hash of the cleaned login form DOM
        portal_name (str): Human-readable label e.g. "College ERP Portal"
                           Stored as both "portal_name" and aliased as
                           "name" by _row_to_dict() for main.py compatibility.

    Returns:
        True  — record inserted successfully.
        False — domain already existed (skipped) or an error occurred.
    """
    now = datetime.utcnow().isoformat()
    conn = None
    try:
        conn = get_connection()
        conn.execute(
            f"""
            INSERT INTO {TABLE_NAME} (domain, dom_hash, portal_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (domain.strip().lower(), dom_hash.strip().lower(), portal_name, now, now)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # UNIQUE constraint on domain — already exists, skip cleanly.
        return False
    except sqlite3.Error as db_err:
        print(f"[AuthShield][database.py] insert_portal() error: {db_err}")
        return False
    finally:
        if conn:
            conn.close()