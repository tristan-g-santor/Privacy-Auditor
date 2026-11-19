# Privacy Auditor

A capstone project that scans a website and audits its privacy posture: which third-party
domains it contacts, what cookies it sets, which security headers it sends, and the TLS/certificate
configuration of everything it talks to.

**Status:** core engine + deployed. Core scanner, API, and a bare-minimum frontend are working.
Entity-based first/third-party classification, a risk-scoring layer, and persistence are still
in progress.

## How it works

1. **Scanner** (`backend/scanner/scantest.py`) :  an async Playwright script that loads a URL in a
   real (headless) browser and listens to every network request/response it makes while loading.
   For each response it collects:
   - Which domains were contacted, split into first-party (same registrable domain as the site)
     and third-party (everything else), via `tldextract`
   - Cookies set during the visit (name, domain, `httpOnly`, `secure`, `sameSite`, expiry)
   - Security-relevant response headers (CSP, HSTS, X-Frame-Options, Referrer-Policy,
     Permissions-Policy), attributed per domain
   - TLS/certificate info per domain contacted (protocol version, issuer, validity window)

2. **API** (`backend/main.py`) : a FastAPI app that wraps the scanner behind a single endpoint:

   ```
   POST /scan?url=<url>
   ```

   returning the scan result as JSON.

3. **Frontend** (`frontend/`) : a React (Vite) app: enter a URL, see counts for each category of
   finding, and expand a raw-JSON view for debugging.

## Scan history: PostgreSQL and session IDs

Every completed scan is saved to PostgreSQL so a user can come back to past results. There are
no accounts. Instead, each browser gets an anonymous **session ID**, and history is scoped to it.

### How a session ID is created

On first load, the frontend (`frontend/src/App.jsx`, `getSessionId()`) generates a random UUID
with `crypto.randomUUID()` and stores it in `localStorage` under `privacylens-session-id`. Every
later visit from the same browser reuses that ID. If `localStorage` is unavailable (for example
in some private-browsing modes), a fresh ID is used for that page load only.

The ID is sent on every API call as a request header:

```
X-Session-Id: 3f1c9a2e-...
```

All three endpoints require this header. A request without it is rejected with `422`.

| Endpoint | What the session ID does |
|---|---|
| `POST /scan?url=...` | The scan is saved with this `session_id`. |
| `GET /history` | Returns only scans whose `session_id` matches. Supports `url`, `grade`, `tls`, `sort`, `limit`, `offset`. |
| `GET /scans/{id}` | Returns the scan only if it belongs to this session. Otherwise it returns `404`, so scan IDs from other users can't be read by guessing numbers. |

### What's stored (`backend/db.py`)

The schema is created automatically at startup (`CREATE TABLE IF NOT EXISTS`), so there's no
separate migration step.

- **`scans`**: one row per scan. Rescanning the same site adds a new row, which builds up a
  history over time. Key columns:
  - `host`: the normalized hostname (`https://WWW.Example.com/a` → `example.com`), used to group
    rescans of the same site
  - `score`, `grade`, `likelihood`, `impact`: the risk score
  - `tracker_count`, `cookie_count`, `tls_protocol`: summary values used for filtering and sorting
  - `session_id`: the anonymous owner
  - `scan_duration_ms`, `scanned_at`
  - `result`: the full scan result as `JSONB`, so a past scan can be re-rendered exactly
- **`scan_trackers`**: one row per tracker domain found in a scan (`entity`, `prevalence`,
  `categories`, `fingerprinting`), linked to `scans` with `ON DELETE CASCADE`.

Indexes on `(session_id, scanned_at)` and `(host, scanned_at)` keep the history queries fast.

Before anything is written, `build_scan_row()` validates the result (score 0–100, a valid
grade, finite numbers, a session ID of at most 64 characters). Invalid data raises an error
instead of being stored. The scan and its trackers are inserted in a single transaction, so a
scan is never saved half-way.

### When the database isn't available

- **`DATABASE_URL` not set:** the API still works. Scans run and return results with a
  `save_error` message, and `/history` returns `503`.
- **A save fails:** the scan result is still returned to the user, with `scan_id: null` and a
  `save_error` message, instead of the whole request failing.

The connection string format is
`postgresql://<user>:<password>@<host>:5432/<database>`. Azure Database for PostgreSQL also
needs `?sslmode=require` at the end.

### Limits of this approach

A session ID is **not authentication**. It works like a bearer token: anyone who has the ID can
read that session's history. It's also tied to one browser. Clearing site data or switching
browsers starts a new, empty history. Because the client controls the ID, scan rate limiting is
keyed by IP address, not session ID (see `backend/rate_limiter.py`).

## Running it locally

**Backend:**
```
cd backend
pip install -r requirements.txt
playwright install chromium
python -m uvicorn main:app
```
(No `--reload` : it conflicts with Playwright's subprocess launch on Windows.)

**Frontend:**
```
cd frontend
npm install
npm run dev
```

## Known limitations

- First/third-party classification currently compares registrable domains only (via
  `tldextract`). It correctly groups a site's own subdomains together, but doesn't recognize
  when a different registrable domain (e.g. a CDN) is operated by the same company that
  requires entity-ownership data, which is planned but not yet integrated.
- Sites with bot/automation detection (Cloudflare challenge pages, AWS WAF, etc.) may return a
  challenge page instead of real content, producing misleadingly sparse results. Not currently
  flagged in the output.
- History is tied to an anonymous, per-browser session ID rather than user accounts (see
  [Scan history](#scan-history-postgresql-and-session-ids)).

## Roadmap

- [x] Standalone Playwright scanner
- [x] FastAPI wrapper
- [x] Bare-minimum React frontend
- [x] Entity-based domain classification (DuckDuckGo Tracker Radar)
- [x] Risk-scoring algorithm (early stages)
- [x] PostgreSQL persistence + historical diffing
- [ ] Dashboard (Recharts)
- [ ] Docker Compose + CI
- [ ] Polish, peer testing, documentation
