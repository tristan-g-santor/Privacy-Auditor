# PrivacyLens: Frontend

React + TypeScript dashboard for the PrivacyLens web privacy auditor.

## What it does

Provides the user interface for submitting URLs and displaying scan results returned by the FastAPI backend. The dashboard surfaces four categories of findings:

- Third party tracker classification (company name, category, prevalence)
- Cookie security flag analysis (HttpOnly, Secure, SameSite per cookie)
- Security header checklist (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- TLS/SSL certificate status and protocol version

Results include an overall A-F risk grade derived from the backend scoring algorithm.

## Tech stack

- React 18 + TypeScript
- Vite (dev server and build)
- Tailwind CSS (styling)
- Recharts (data visualizations) — in progress

## Project structure

```
frontend/
├── src/
│   ├── App.jsx          # URL input, scan trigger, result rendering
│   ├── App.css
│   ├── main.jsx
│   └── index.css
├── public/
├── index.html
├── vite.config.js
└── package.json
```

## Getting started

Install dependencies:

```bash
npm install
```

Start the dev server:

```bash
npm run dev
```

The frontend runs on `http://localhost:5173` by default. The FastAPI backend must be running on `http://localhost:8000` for scans to work.

## Connecting to the backend

The frontend sends a POST request to the backend scan endpoint:

```
POST http://localhost:8000/scan?url=https://example.com
```

Response shape the frontend expects:

```json
{
  "url": "https://example.com",
  "final_url": "https://example.com/",
  "score": {
    "score": 42,
    "grade": "D",
    "breakdown": {
      "likelihood": 18.5,
      "impact": 21.0
    }
  },
  "trackers": [
    {
      "domain": "snap.licdn.com",
      "entity": "LinkedIn",
      "categories": ["Advertising"],
      "prevalence": 0.42
    }
  ],
  "cookies": [
    {
      "name": "_ga",
      "domain": ".example.com",
      "httpOnly": false,
      "secure": true,
      "sameSite": "None"
    }
  ],
  "main_document": {
    "security_headers": {
      "strict-transport-security": "max-age=31536000"
    }
  },
  "tls_info": {
    "example.com": {
      "protocol": "TLS 1.3",
      "issuer": "Let's Encrypt",
      "validFrom": 1700000000,
      "validTo": 1800000000
    }
  },
  "first_party_domains": ["www.example.com", "cdn.example.com"]
}
```

## Current status

- URL input and scan trigger working
- Loading state with step-by-step pipeline labels
- Results display: grade, tracker list, cookie table, header checklist, TLS section
- Scan history: placeholder (PostgreSQL integration in progress)
- Recharts visualizations: in progress

## Known limitations

- First party domains displayed as plain hostnames only" no entity enrichment
- Per-tracker risk values computed frontend-side by category (Advertising/Session Replay = high, Analytics = medium, Unclassified = low)
- Scan history not yet persistent: PostgreSQL integration coming in Q2 Week 3

## Related

- [Backend README](../backend/README.md)
- [PrivacyLens capstone project](https://github.com/tristangsantor/privacy-auditor)
