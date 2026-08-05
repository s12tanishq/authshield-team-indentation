"""
seed.py — AuthShield Backend
Branch: feature/backend-db (Person D)

Responsibilities:
- Create authshield.db (the SQLite file) if it doesn't already exist
- Create the "trusted_portals" table
- Insert baseline (domain, dom_hash) pairs for known-authentic college portals

Run once, or whenever the trusted-portal list changes:
    python seed.py
"""

import sqlite3

DB_PATH = "authshield.db"

# Baseline trusted portals: (domain, dom_hash, portal_name)
# In a real deployment, each dom_hash comes from actually running content.js's
# hashing logic against the real, verified login page — never typed by hand.
# These are placeholder hashes for development/testing only.
TRUSTED_PORTALS = [
    ("webmail.college.edu", "a7f93e21c8b4d5e6f7890a1b2c3d4e5f6789a0b1c2d3e4f5a6b7c8d9e0f1a2b3", "College Webmail"),
    ("portal.college.edu", "b8e04f32d9c5e6f7801b2c3d4e5f67890a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5", "Student Portal"),
]


def create_table(conn: sqlite3.Connection) -> None:
    """Creates the trusted_portals table if it doesn't already exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS trusted_portals (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL UNIQUE,
            dom_hash    TEXT NOT NULL,
            portal_name TEXT,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)


def seed_data(conn: sqlite3.Connection) -> None:
    """Inserts baseline portals. Skips any domain that's already present."""
    conn.executemany(
        """
        INSERT OR IGNORE INTO trusted_portals (domain, dom_hash, portal_name)
        VALUES (?, ?, ?)
        """,
        TRUSTED_PORTALS
    )


def main():
    conn = sqlite3.connect(DB_PATH)
    try:
        create_table(conn)
        seed_data(conn)
        conn.commit()
        print(f"authshield.db ready with {len(TRUSTED_PORTALS)} baseline portal(s).")
    finally:
        conn.close()


if __name__ == "__main__":
    main()