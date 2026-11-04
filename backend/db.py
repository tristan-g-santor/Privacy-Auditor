#PostgreSQL storage for historical scans
#every scan is its own row (no unique constraint on url) so rescans of the same
#site build up a history users can compare over time
import json, math, os, asyncpg
from urllib.parse import urlparse

VALID_GRADES = {"A", "B", "C", "D", "F"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              BIGSERIAL PRIMARY KEY,
    url             TEXT        NOT NULL,
    host            TEXT        NOT NULL,
    final_url       TEXT,
    score           SMALLINT    NOT NULL CHECK (score BETWEEN 0 AND 100),
    grade           CHAR(1)     NOT NULL CHECK (grade IN ('A','B','C','D','F')),
    likelihood      DOUBLE PRECISION NOT NULL CHECK (likelihood >= 0),
    impact          DOUBLE PRECISION NOT NULL CHECK (impact >= 0),
    tracker_count   INTEGER     NOT NULL CHECK (tracker_count >= 0),
    cookie_count    INTEGER     NOT NULL CHECK (cookie_count >= 0),
    tls_protocol    TEXT,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    result          JSONB       NOT NULL
);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS session_id TEXT;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_duration_ms INTEGER CHECK (scan_duration_ms >= 0);

CREATE INDEX IF NOT EXISTS scans_host_time_idx ON scans (host, scanned_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS scans_session_time_idx ON scans (session_id, scanned_at DESC, id DESC);


CREATE TABLE IF NOT EXISTS scan_trackers (
    scan_id         BIGINT  NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    domain          TEXT    NOT NULL,
    entity          TEXT,
    prevalence      DOUBLE PRECISION CHECK (prevalence BETWEEN 0 AND 1),
    categories      TEXT[]  NOT NULL DEFAULT '{}',
    fingerprinting  SMALLINT,
    PRIMARY KEY (scan_id, domain)
);
"""

_pool = None

"""
URL host convert toe hte normalized hostname, removes the paths and just the hostname
"""
def normalize_host(url):
    """Grouping key for history: 'https://WWW.Example.com/a' and 'example.com' both -> 'example.com'."""
    if "://" not in url:
        url = "https://" + url
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _finite_number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number, got {value!r}")
    return float(value)


def build_scan_row(result, session_id):
    """Validate a scored scan result and shape it for insert. Raises ValueError on bad data
    so nothing inaccurate gets written to history."""
    score = result.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise ValueError(f"score must be an integer 0-100, got {score!r}")

    grade = result.get("grade")
    if grade not in VALID_GRADES:
        raise ValueError(f"grade must be one of {sorted(VALID_GRADES)}, got {grade!r}")

    host = normalize_host(result.get("url") or "")
    if not host:
        raise ValueError(f"could not determine host from url {result.get('url')!r}")

    breakdown = result.get("breakdown") or {}
    likelihood = _finite_number(breakdown.get("likelihood"), "breakdown.likelihood")
    impact = _finite_number(breakdown.get("impact"), "breakdown.impact")

    #scan_duration + session id 
    scan_duration_ms = result.get("scan_duration_ms")
    if scan_duration_ms is not None and (
        isinstance(scan_duration_ms, bool) or not isinstance(scan_duration_ms, int) or scan_duration_ms < 0
    ):
        raise ValueError(f"scan_duration_ms must be a non-negative integer, got {scan_duration_ms!r}")

    if not isinstance(session_id, str) or not session_id or len(session_id) > 64:
        raise ValueError(f"session_id must be a non-empty string up to 64 chars, got {session_id!r}")


    # TLS can be missing entirely (http://, failed handshake, redirect to another host) - store NULL
    final_url = result.get("final_url")
    tls_host = urlparse(final_url).hostname if final_url else None
    tls_protocol = ((result.get("tls_info") or {}).get(tls_host) or {}).get("protocol") or None

    trackers = [build_tracker_row(t) for t in (result.get("trackers") or [])]


    return {
        "url": result["url"],
        "host": host,
        "final_url": final_url,
        "score": score,
        "grade": grade,
        "likelihood": likelihood,
        "impact": impact,
        "tracker_count": len(trackers),
        "cookie_count": len(result.get("cookies") or []),
        "tls_protocol": tls_protocol,
        "result": json.dumps(result, allow_nan=False, default=sorted),
        "trackers": trackers,
        "session_id" : session_id,
        "scan_duration_ms": scan_duration_ms,
    }


def build_tracker_row(tracker):
    domain = tracker.get("domain")
    if not domain:
        raise ValueError(f"tracker is missing a domain: {tracker!r}")

    prevalence = tracker.get("prevalence")
    if prevalence is not None:
        prevalence = _finite_number(prevalence, f"prevalence for {domain}")
        if not 0 <= prevalence <= 1:
            raise ValueError(f"prevalence for {domain} must be 0-1, got {prevalence!r}")

    fingerprinting = tracker.get("fingerprinting")
    if fingerprinting is not None and (isinstance(fingerprinting, bool) or not isinstance(fingerprinting, int)):
        raise ValueError(f"fingerprinting for {domain} must be an integer, got {fingerprinting!r}")

    return (domain, tracker.get("entity"), prevalence, list(tracker.get("categories") or []), fingerprinting)


async def init_db(dsn=None):
    """Create the pool and schema. Returns False (history disabled) when no DATABASE_URL is set."""
    global _pool
    dsn = dsn or os.environ.get("DATABASE_URL")
    if not dsn:
        return False
    _pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5)
    async with _pool.acquire() as conn:
        await conn.execute(SCHEMA)
    return True


async def close_db():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


def is_enabled():
    return _pool is not None


async def save_scan(result, session_id):
    """Insert one scan + its trackers in a single transaction. Returns the new scan id."""
    row = build_scan_row(result, session_id)
    async with _pool.acquire() as conn:
        async with conn.transaction():
            scan_id = await conn.fetchval(
                """
                INSERT INTO scans (url, host, final_url, score, grade, likelihood, impact,
                                   tracker_count, cookie_count, tls_protocol, result,
                                   session_id, scan_duration_ms)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13)
                RETURNING id
                """,
                row["url"], row["host"], row["final_url"], row["score"], row["grade"],
                row["likelihood"], row["impact"], row["tracker_count"], row["cookie_count"],
                row["tls_protocol"], row["result"],
                row["session_id"], row["scan_duration_ms"],
            )
            if row["trackers"]:
                # one batched round trip, so 50+ trackers don't mean 50+ separate inserts
                await conn.executemany(
                    """
                    INSERT INTO scan_trackers (scan_id, domain, entity, prevalence, categories, fingerprinting)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                    [(scan_id, *t) for t in row["trackers"]],
                )
    return scan_id


SORT_COLUMNS = {
    "most-recent": "scanned_at DESC, id DESC",
    "worst-score": "score ASC, id DESC",
    "best-score": "score DESC, id DESC",
    "most-trackers": "tracker_count DESC, id DESC",
}


async def get_history(url=None, limit=5, offset=0, grade=None, tls_protocols=None, sort="most-recent", session_id=None):
    """Every scan, newest first by default. session_id/url/grade/tls_protocols narrow the results; sort picks the ordering."""
    conditions = []
    params = []

    if session_id:
        params.append(session_id)
        conditions.append(f"session_id = ${len(params)}")

    if url:
        params.append(normalize_host(url))
        conditions.append(f"host = ${len(params)}")

    if grade:
        params.append(grade)
        conditions.append(f"grade = ${len(params)}")

    if tls_protocols:
        params.append(list(tls_protocols))
        conditions.append(f"tls_protocol = ANY(${len(params)})")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    order_by = SORT_COLUMNS.get(sort, SORT_COLUMNS["most-recent"])

    params.append(limit)
    limit_idx = len(params)
    params.append(offset)
    offset_idx = len(params)

    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, url, final_url, score, grade, likelihood, impact,
                   tracker_count, cookie_count, tls_protocol, scan_duration_ms, scanned_at
            FROM scans
            {where}
            ORDER BY {order_by}
            LIMIT ${limit_idx} OFFSET ${offset_idx}
            """,
            *params,
        )
    return [{**dict(r), "scanned_at": r["scanned_at"].isoformat()} for r in rows]


async def get_scan(scan_id, session_id):
    """Full stored result for one past scan, or None if it doesn't exist or belongs to another session."""
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, scanned_at, result FROM scans WHERE id = $1 AND session_id = $2",
            scan_id, session_id,
        )
    if not row:
        return None
    return {**json.loads(row["result"]), "scan_id": row["id"], "scanned_at": row["scanned_at"].isoformat()}


if __name__ == "__main__":
    import asyncio
    #test case
    async def test():
        await init_db()  # reads DATABASE_URL from the environment
        fake_result = {
            "url": "https://example.com",
            "final_url": "https://example.com",
            "score": 85,
            "grade": "B",
            "breakdown": {"likelihood": 5, "impact": 10},
            "cookies": [],
            "trackers": [],
            "tls_info": {},
            "scan_duration_ms": 1234,
        }
        scan_id = await save_scan(fake_result, "test-session")
        print("Saved scan id:", scan_id)
        print("History:", await get_history("example.com"))
        print("Single scan:", await get_scan(scan_id, "test-session"))
        print("Other session:", await get_scan(scan_id, "someone-else"))
        await close_db()

    asyncio.run(test())

 