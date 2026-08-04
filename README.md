# AuthShield

Browser security system that protects users from credential-harvesting on cloned/phishing college portals. AuthShield fingerprints a login form's DOM structure, hashes it (SHA-256), and checks it against a backend registry of known authentic portals — flagging cases where the form structure matches a trusted portal but the domain doesn't.

## How It Works

1. **content.js** scans the page for login forms, strips dynamic attributes (CSRF tokens, ids, session values), and serializes the cleaned structure into a standardized string.
2. The string is hashed client-side using the native Web Crypto API (`crypto.subtle`).
3. **background.js** sends the domain + hash to the backend and relays the verdict back.
4. **main.py** checks the hash against a SQLite registry of trusted portals and returns a status.
5. Depending on the result, content.js injects a warning banner (and disables the form on confirmed threats), while the **popup** shows the current tab's status at a glance.

## Architecture

1. **Webpage DOM** — user visits a page containing a login form.
2. **content.js** scans the form, cleans it, and computes a SHA-256 hash.
3. **background.js** receives the hash via a Chrome runtime message and forwards it to the backend.
4. **main.py** looks up the hash in **database.py / authshield.db** and returns a verdict.
5. **background.js** relays the verdict back to **content.js** (for the in-page banner) and saves it to `chrome.storage.session`.
6. **popup.js / popup.html** reads the saved verdict from storage and displays it in the toolbar popup.


## Repository Structure

| Branch | Owner | Files |
|---|---|---|
| `feature/extension-bg` | Person A | `manifest.json`, `background.js`, `popup.html`, `popup.js` |
| `feature/dom-hashing` | Person B | `content.js` |
| `feature/backend-api` | Person C | `main.py`, `requirements.txt` |
| `feature/backend-db` | Person D | `database.py`, `seed.py`, `authshield.db` |

## Data Contracts

**Chrome messaging** — content.js → background.js:
```json
{ "action": "VERIFY_DOM_HASH", "domain": "webmail.college.edu", "hash": "a7f93e21c8b4..." }
```

**API request** — background.js → `POST /verify`:
```json
{ "domain": "webmail.college.edu", "dom_hash": "a7f93e21c8b4..." }
```

**API response** — main.py → background.js → content.js:
```json
{ "status": "SAFE" | "DANGER" | "UNKNOWN", "message": "..." }
```

These contracts are fixed across all branches. Any deviation must be flagged and agreed on before merging.

## Setup

### Backend
```bash
cd backend
pip install -r requirements.txt
python seed.py        # seeds authshield.db with trusted portal hashes
uvicorn main:app --reload --port 8000
```

### Extension
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the extension's root folder
4. Visit any page with a login form to trigger a scan; click the toolbar icon to view status

## Status Meanings

| Status | Meaning | UI Behavior |
|---|---|---|
| `SAFE` | Hash and domain both match a trusted portal | No banner; popup shows green |
| `DANGER` | Hash matches a trusted portal but domain doesn't | Red banner, form disabled |
| `UNKNOWN` | No matching record found, or backend unreachable | Yellow advisory banner, form stays enabled |

## Notes

- Backend runs on `http://localhost:8000` by default — update `host_permissions` in `manifest.json` if deployed elsewhere.
- All dynamic/volatile DOM attributes (CSRF tokens, generated ids, framework-specific attributes) are stripped before hashing so the same portal always produces the same hash across page loads.
