# Privacy Auditor

A capstone project that scans a website and audits its privacy posture: which third-party
domains it contacts, what cookies it sets, which security headers it sends, and the TLS/certificate
configuration of everything it talks to.

**Status:** early development. Core scanner, API, and a bare-minimum frontend are working.
Entity-based first/third-party classification, a risk-scoring layer, and persistence are still
in progress.

**Due:** December 10, 2026.

## How it works

1. **Scanner** (`backend/scanner/scantest.py`) — an async Playwright script that loads a URL in a
   real (headless) browser and listens to every network request/response it makes while loading.
   For each response it collects:
   - Which domains were contacted, split into first-party (same registrable domain as the site)
     and third-party (everything else), via `tldextract`
   - Cookies set during the visit (name, domain, `httpOnly`, `secure`, `sameSite`, expiry)
   - Security-relevant response headers (CSP, HSTS, X-Frame-Options, Referrer-Policy,
     Permissions-Policy), attributed per domain
   - TLS/certificate info per domain contacted (protocol version, issuer, validity window)

2. **API** (`backend/main.py`) — a FastAPI app that wraps the scanner behind a single endpoint:

   ```
   POST /scan?url=<url>
   ```

   returning the scan result as JSON.

3. **Frontend** (`frontend/`) — a React (Vite) app: enter a URL, see counts for each category of
   finding, and expand a raw-JSON view for debugging.

## Running it locally

**Backend:**
```
cd backend
pip install -r requirements.txt
playwright install chromium
python -m uvicorn main:app
```
(No `--reload` — it conflicts with Playwright's subprocess launch on Windows.)

**Frontend:**
```
cd frontend
npm install
npm run dev
```

## Known limitations

- First/third-party classification currently compares registrable domains only (via
  `tldextract`). It correctly groups a site's own subdomains together, but doesn't recognize
  when a different registrable domain (e.g. a CDN) is operated by the same company — that
  requires entity-ownership data, which is planned but not yet integrated.
- Sites with bot/automation detection (Cloudflare challenge pages, AWS WAF, etc.) may return a
  challenge page instead of real content, producing misleadingly sparse results. Not currently
  flagged in the output.
- No persistence yet — each scan is a one-off; nothing is stored between requests.

## Roadmap

- [x] Standalone Playwright scanner
- [x] FastAPI wrapper
- [x] Bare-minimum React frontend
- [ ] Entity-based domain classification (DuckDuckGo Tracker Radar)
- [ ] Risk-scoring algorithm
- [ ] PostgreSQL persistence + historical diffing
- [ ] Dashboard (Recharts)
- [ ] Docker Compose + CI
- [ ] Polish, peer testing, documentation
