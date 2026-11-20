#QA stress test for the Playwright scan engine + scoring, calling scan() and compute_score() directly
#(no FastAPI, no rate limiter, no Postgres - nothing is saved anywhere except the report CSV).
#
#Part 1 - edge cases against a local test server (fast, offline, always run):
#  python -m pytest tests/test_scoring.py -v
#
#Part 2 - every site in tests/test_sites.csv (opt-in, roughly 20-40 min):
#  PowerShell:  $env:RUN_LIVE_TESTS=1; python -m pytest tests/test_scoring.py -s -rfxX
#  bash:        RUN_LIVE_TESTS=1 python -m pytest tests/test_scoring.py -s -rfxX
#  -s shows live progress, -rfxX lists every failure and every expected failure (bot walls etc.) at the end.
#
#Live options (env vars):
#  LIVE_CONCURRENCY   scans at once (default 3, same as the server; each one is a Chromium, ~300 MB)
#  LIVE_TIMEOUT       seconds per scan (default 30, same as the server)
#  LIVE_SAMPLE        N sites spread evenly across all categories, e.g. 25 for a quick representative run
#  LIVE_LIMIT         only the first N sites in file order, e.g. 10 for a trial run
#  LIVE_CATEGORY      only one category from the CSV, e.g. health
#  LIVE_MIN_COVERAGE  share of sites that must scan cleanly for the summary test to pass (default 0.6)
#Report: tests/results/live_<timestamp>.csv, one row per site.
#
#Outcomes every scan is sorted into:
#  ok            scanned and scored                                          -> must pass the score checks
#  bot_blocked   Cloudflare / AWS WAF / DataDome / PerimeterX / Akamai wall  -> xfail (known limitation)
#  redirect_loop Chromium gave up after 20 redirects                         -> xfail
#  timeout       no result within the timeout                                -> xfail
#  load_failed   DNS, TLS or connection error                                -> xfail
#  http_error    site answered 4xx/5xx without a bot wall                    -> xfail
#  incomplete    scan "succeeded" but data is missing - would show a misleading grade -> FAIL
#  blocked_url   SSRF guard rejected a public site from the list             -> FAIL
#  crash         unexpected exception in our code                            -> FAIL
import asyncio, csv, os, statistics, sys, time
from collections import Counter, defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlparse
import pytest

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)
import entity_scoring
from entity_scoring import compute_score, grade_from_score, SCORING_CONFIG
from scanner import url_guard, engine_populate
from scanner.url_guard import BlockedURLError
from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
SITES_CSV = os.path.join(TESTS_DIR, "test_sites.csv")
RESULTS_DIR = os.path.join(TESTS_DIR, "results")


# ---------- classifying a scan ----------

CHALLENGE_HOST_MARKERS = (
    "challenges.cloudflare.com",                        # Cloudflare managed challenge / Turnstile
    "awswaf.com",                                       # AWS WAF captcha + JS challenge
    "captcha-delivery.com", "datadome",                 # DataDome
    "px-cdn.net", "px-cloud.net", "perimeterx.net",     # HUMAN / PerimeterX
    "incapsula", "imperva",                             # Imperva
    "hcaptcha.com", "arkoselabs.com", "funcaptcha.com", # standalone captcha walls
)
CHALLENGE_URL_MARKERS = (
    "/sorry/",          # Google captcha
    "js_challenge",     # e.g. reddit's JS challenge (?js_challenge=1&jsc_token=...)
    "bot-detection",    # e.g. glassdoor ?reason=bot-detection
    "captcha",
)
BLOCK_STATUSES = {
    202: "HTTP 202 (AWS WAF challenge)",
    401: "HTTP 401 (login/bot wall on a public homepage)",
    403: "HTTP 403",
    429: "HTTP 429 (rate limited)",
    503: "HTTP 503 (Cloudflare challenge or outage)",
}


def all_hosts(result):
    return result["third_party_domains"] | result["first_party_domains"] | result["unknown_hosts"]


def bot_block_signals(result):
    signals = []
    status = (result.get("main_document") or {}).get("status")
    if status in BLOCK_STATUSES:
        signals.append(BLOCK_STATUSES[status])
    final_url = (result.get("final_url") or "").lower()
    signals += [f"final URL contains {m!r}" for m in CHALLENGE_URL_MARKERS if m in final_url]
    signals += [f"challenge host {h}" for h in sorted(all_hosts(result))
                if any(m in h for m in CHALLENGE_HOST_MARKERS)]
    return signals


def classify_result(result):
    """Sort a scan that returned normally. Returns (outcome, detail)."""
    doc = result.get("main_document")
    final_url = result.get("final_url") or ""
    if not doc:
        return "incomplete", "no main document response"
    if not final_url.startswith(("http://", "https://")):
        return "incomplete", f"final URL is {final_url!r}"
    if not all_hosts(result):
        return "incomplete", "no network responses recorded"
    signals = bot_block_signals(result)
    if signals:
        return "bot_blocked", "; ".join(signals)
    if doc["status"] >= 400:
        return "http_error", f"HTTP {doc['status']}"
    final_host = urlparse(final_url).hostname or ""
    if not engine_populate.is_ip(final_host) and not result["first_party_domains"]:
        return "incomplete", "no first-party hosts recorded"
    return "ok", ""


def classify_error(exc):
    """Sort a scan that raised. Returns (outcome, detail)."""
    if isinstance(exc, BlockedURLError):
        return "blocked_url", str(exc)
    if isinstance(exc, (asyncio.TimeoutError, PlaywrightTimeoutError)):
        return "timeout", "no result within the timeout"
    if isinstance(exc, PlaywrightError):
        message = str(exc)
        first_line = message.splitlines()[0][:200] if message else type(exc).__name__
        if "ERR_TOO_MANY_REDIRECTS" in message:
            return "redirect_loop", "Chromium gave up after 20 redirects"
        if "ERR_HTTP2_PROTOCOL_ERROR" in message:
            return "bot_blocked", "connection killed mid-load (typical Akamai bot block)"
        return "load_failed", first_line
    return "crash", f"{type(exc).__name__}: {str(exc)[:200]}"


def score_problems(scored, result):
    """Invariants every score must satisfy (OWASP Risk Rating structure). Returns what's wrong."""
    cfg, problems = SCORING_CONFIG, []
    score, grade, severity = scored["score"], scored["grade"], scored["severity"]
    b = scored["breakdown"]
    if not 0 <= score <= 100:
        problems.append(f"score {score} outside 0-100")
    if grade != grade_from_score(score):
        problems.append(f"grade {grade} does not match score {score}")
    for name, value in b["factors"].items():
        if not 0 <= value <= 9:
            problems.append(f"factor {name}={value} outside 0-9")
    for part in ("likelihood", "impact"):
        if not 0 <= b[part] <= 9:
            problems.append(f"{part} {b[part]} outside 0-9")
        if b[f"{part}_level"] != entity_scoring.level(b[part]):
            problems.append(f"{part}_level {b[f'{part}_level']} does not match {part} {b[part]}")
    if severity != cfg["severity_matrix"][b["impact_level"]][b["likelihood_level"]]:
        problems.append(f"severity {severity} does not follow the OWASP matrix")
    if grade != cfg["grades"][severity]["grade"]:
        problems.append(f"grade {grade} does not match severity {severity}")
    third_party = [t for t in scored["trackers"] if not t["same_owner"]]
    if len(third_party) != len(result["third_party_domains"]):
        problems.append("third-party tracker count differs from third-party domain count")
    if any(not f.get("owasp") for f in scored["findings"]):
        problems.append("a finding has no OWASP label")
    return problems


# ---------- Part 1: edge cases against a local server ----------

class LocalSite:
    """Tiny HTTP server; each route is (status, headers, body, delay_seconds)."""

    def __init__(self, routes):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status, headers, body, delay = routes.get(self.path, (404, {}, "", 0))
                if delay:
                    time.sleep(delay)
                try:
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body.encode())
                except ConnectionError:
                    pass  # the browser gave up first (reset/aborted/broken pipe) - expected in the hang tests

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.block_on_close = False  # don't wait for deliberately hanging handlers
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def page(body, status=200):
    return (status, {"Content-Type": "text/html"}, f"<html><body>{body}</body></html>", 0)


EDGE_ROUTES = {
    "/ok": page("<p>plain page</p>"),
    "/loop": (302, {"Location": "/loop"}, "", 0),                      # redirects to itself
    "/ping": (302, {"Location": "/pong"}, "", 0),                      # two-page loop
    "/pong": (302, {"Location": "/ping"}, "", 0),
    "/js-reload": page("<script>location.reload()</script>"),         # reloads forever
    "/meta-refresh": (200, {"Content-Type": "text/html"},
                      '<html><head><meta http-equiv="refresh" content="0"></head></html>', 0),
    "/server-error": page("<h1>Internal Server Error</h1>", status=500),
    "/challenge": page("<title>Just a moment...</title>", status=403), # what a Cloudflare wall returns
    "/hang": (200, {"Content-Type": "text/html"}, "<html></html>", 60),  # never answers in time
    "/slow-pixel": page('<p>content</p><img src="/never">'),           # page is fine, one image hangs
    "/never": (200, {"Content-Type": "image/gif"}, "", 60),
}
LOCAL_TIMEOUT = 15


@pytest.fixture
def edge(monkeypatch):
    server = LocalSite(EDGE_ROUTES)
    real_resolve = url_guard.resolve_public

    # Let the scanner reach 127.0.0.1 for these tests only (same trick as test_url_guard.py).
    async def allow_test_server(host):
        return host == "127.0.0.1" or await real_resolve(host)

    monkeypatch.setattr(url_guard, "resolve_public", allow_test_server)
    monkeypatch.setattr(engine_populate, "resolve_public", allow_test_server)
    yield server
    server.close()


def scan_local(url, timeout=LOCAL_TIMEOUT):
    """Scan one URL with a hard timeout. Returns (outcome, detail, result, seconds)."""
    started = time.perf_counter()
    try:
        result = asyncio.run(asyncio.wait_for(engine_populate.scan(url), timeout))
        outcome, detail = classify_result(result)
    except Exception as e:
        result, (outcome, detail) = None, classify_error(e)
    return outcome, detail, result, time.perf_counter() - started


def test_plain_page_scans_and_scores(edge):
    outcome, detail, result, _ = scan_local(edge.url + "/ok")
    assert outcome == "ok", detail
    scored = asyncio.run(compute_score(result))
    assert score_problems(scored, result) == []


@pytest.mark.parametrize("path", ["/loop", "/ping"], ids=["self-redirect", "two-page-loop"])
def test_infinite_redirect_fails_fast_and_cleanly(edge, path):
    outcome, detail, _, seconds = scan_local(edge.url + path)
    assert outcome == "redirect_loop", f"{outcome}: {detail}"
    assert seconds < 10, f"took {seconds:.1f}s to give up on a redirect loop"


@pytest.mark.parametrize("path", [
    pytest.param("/js-reload", marks=pytest.mark.xfail(strict=True, reason=(
        "known: a page that reloads itself before DOMContentLoaded never finishes navigating, so goto() "
        "runs to its timeout and the scan is lost. Fix: keep partial results when goto() times out. "
        "Remove this marker once fixed."))),
    "/meta-refresh",
])
def test_client_side_reload_loop_does_not_hang_or_crash(edge, path):
    # either outcome is acceptable; hanging until the timeout or crashing is not
    outcome, detail, _, seconds = scan_local(edge.url + path)
    assert outcome in ("ok", "load_failed"), f"{outcome}: {detail}"
    assert seconds < LOCAL_TIMEOUT


def test_server_error_is_reported_not_scored_as_clean(edge):
    outcome, detail, _, _ = scan_local(edge.url + "/server-error")
    assert outcome == "http_error", f"{outcome}: {detail}"


def test_challenge_status_is_flagged_as_bot_block(edge):
    outcome, detail, _, _ = scan_local(edge.url + "/challenge")
    assert outcome == "bot_blocked", f"{outcome}: {detail}"


def test_unresponsive_server_times_out_cleanly(edge):
    outcome, detail, _, seconds = scan_local(edge.url + "/hang", timeout=8)
    assert outcome == "timeout", f"{outcome}: {detail}"
    assert seconds < 12, f"timeout of 8s took {seconds:.1f}s to take effect"


def test_slow_subresource_still_produces_a_report(edge):
    # regression test: goto() used to wait for the 'load' event, so one never-ending image or
    # tracker pixel threw away the whole scan. Fixed with wait_until='domcontentloaded' + settle.
    outcome, detail, _, _ = scan_local(edge.url + "/slow-pixel")
    assert outcome == "ok", f"{outcome}: {detail}"


# ---------- Part 2: every site in test_sites.csv (opt-in) ----------

LIVE = bool(os.environ.get("RUN_LIVE_TESTS"))
LIVE_CONCURRENCY = int(os.environ.get("LIVE_CONCURRENCY", "3"))
LIVE_TIMEOUT = int(os.environ.get("LIVE_TIMEOUT", "30"))
LIVE_MIN_COVERAGE = float(os.environ.get("LIVE_MIN_COVERAGE", "0.6"))
live = pytest.mark.skipif(not LIVE, reason="set RUN_LIVE_TESTS=1 to scan every site in test_sites.csv")

EXPECTED_FAILURES = {"bot_blocked", "redirect_loop", "timeout", "load_failed", "http_error"}
FACTOR_COLUMNS = list(SCORING_CONFIG["likelihood_factors"]) + list(SCORING_CONFIG["impact_factors"])


def load_sites():
    with open(SITES_CSV, newline="", encoding="utf-8") as f:
        sites = [row for row in csv.DictReader(f) if row.get("url")]
    if os.environ.get("LIVE_CATEGORY"):
        sites = [s for s in sites if s["category"] == os.environ["LIVE_CATEGORY"]]
    if os.environ.get("LIVE_SAMPLE"):
        # take sites round-robin across categories, so a small run still covers every kind of site
        queues = defaultdict(list)
        for s in sites:
            queues[s["category"]].append(s)
        queues, picked, i = list(queues.values()), [], 0
        while len(picked) < int(os.environ["LIVE_SAMPLE"]) and any(queues):
            if queues[i % len(queues)]:
                picked.append(queues[i % len(queues)].pop(0))
            i += 1
        sites = sorted(picked, key=lambda s: int(s["id"]))
    if os.environ.get("LIVE_LIMIT"):
        sites = sites[:int(os.environ["LIVE_LIMIT"])]
    return sites


SITES = load_sites()


async def scan_site(site):
    record = {"id": site["id"], "url": site["url"], "category": site["category"],
              "outcome": "", "detail": "", "status": None, "final_url": "",
              "score": None, "grade": None, "severity": None,
              "likelihood": None, "likelihood_level": None, "impact": None, "impact_level": None,
              **{f: None for f in FACTOR_COLUMNS},
              "third_party_domains": None, "tracking_domains": None, "cookies": None,
              "score_problems": "", "duration_s": 0}
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(engine_populate.scan(site["url"]), LIVE_TIMEOUT)
    except Exception as e:
        record["outcome"], record["detail"] = classify_error(e)
    else:
        record.update(status=(result.get("main_document") or {}).get("status"),
                      final_url=result.get("final_url") or "",
                      third_party_domains=len(result["third_party_domains"]),
                      cookies=len(result["cookies"]))
        record["outcome"], record["detail"] = classify_result(result)
        if record["outcome"] == "ok":
            try:
                scored = await compute_score(result)
            except Exception as e:
                record["outcome"] = "crash"
                record["detail"] = f"compute_score: {type(e).__name__}: {str(e)[:200]}"
            else:
                b = scored["breakdown"]
                record.update(score=scored["score"], grade=scored["grade"], severity=scored["severity"],
                              likelihood=b["likelihood"], likelihood_level=b["likelihood_level"],
                              impact=b["impact"], impact_level=b["impact_level"],
                              **{f: b["factors"][f] for f in FACTOR_COLUMNS},
                              tracking_domains=sum(1 for t in scored["trackers"] if entity_scoring.is_tracking(t)),
                              score_problems="; ".join(score_problems(scored, result)))
    record["duration_s"] = round(time.perf_counter() - started, 1)
    return record


async def scan_all(sites):
    slots = asyncio.Semaphore(LIVE_CONCURRENCY)
    records, done = {}, 0

    async def one(site):
        nonlocal done
        async with slots:
            record = await scan_site(site)
        records[site["id"]] = record
        done += 1
        shown = f"{record['score']} {record['grade']}" if record["outcome"] == "ok" else record["detail"][:60]
        print(f"[{done:>3}/{len(sites)}] {record['outcome']:<13} {site['url']:<42} "
              f"{record['duration_s']:>5}s  {shown}", flush=True)

    # same setup as the server: one shared Chromium, one context per scan
    await engine_populate.start_browser()
    try:
        await asyncio.gather(*(one(site) for site in sites))
    finally:
        await engine_populate.stop_browser()
    return records


def write_report(records):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = f"{datetime.now():%Y%m%d_%H%M%S}"
    path = os.path.join(RESULTS_DIR, f"live_{stamp}.csv")
    rows = sorted(records.values(), key=lambda r: int(r["id"]))
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture(scope="session")
def live_scans():
    # One category lookup per domain for the whole run. Without this, GitHub throttling during a
    # long run silently returns "no categories" and quietly changes scores.
    original = entity_scoring.get_category_info
    memo = {}

    async def memoized(domain):
        key = entity_scoring.tldextract.extract(domain).top_domain_under_public_suffix
        if key not in memo:
            memo[key] = await original(domain)
        return memo[key]

    entity_scoring.get_category_info = memoized
    print(f"\nScanning {len(SITES)} sites, {LIVE_CONCURRENCY} at a time, {LIVE_TIMEOUT}s timeout each")
    try:
        records = asyncio.run(scan_all(SITES))
    finally:
        entity_scoring.get_category_info = original
    print(f"\nReport written to {write_report(records)}")
    return records


@live
@pytest.mark.parametrize("site", SITES, ids=[f"{s['id']}-{urlparse(s['url']).hostname}" for s in SITES])
def test_live_site(site, live_scans):
    record = live_scans[site["id"]]
    if record["outcome"] in EXPECTED_FAILURES:
        pytest.xfail(f"{record['outcome']}: {record['detail']}")
    assert record["outcome"] == "ok", f"{record['outcome']}: {record['detail']}"
    assert not record["score_problems"], record["score_problems"]


@live
def test_live_summary(live_scans):
    records = list(live_scans.values())
    counts = Counter(r["outcome"] for r in records)
    ok = [r for r in records if r["outcome"] == "ok"]
    durations = sorted(r["duration_s"] for r in records)

    print("\n\n=== Outcomes ===")
    for outcome, n in counts.most_common():
        print(f"  {outcome:<14} {n:>4}  ({n / len(records):.0%})")

    print("\n=== Scan time ===")
    print(f"  median {statistics.median(durations)}s, "
          f"p95 {durations[int(len(durations) * 0.95) - 1]}s, max {durations[-1]}s")

    print("\n=== By category (coverage, mean score of clean scans) ===")
    by_category = defaultdict(list)
    for r in records:
        by_category[r["category"]].append(r)
    for category, rows in sorted(by_category.items()):
        scores = [r["score"] for r in rows if r["outcome"] == "ok"]
        mean = f"{statistics.mean(scores):5.1f}" if scores else "    -"
        print(f"  {category:<26} {len(scores):>3}/{len(rows):<3} ok   mean {mean}")

    print("\n=== Clean scans, best to worst (OWASP risk rating) ===")
    print(f"  {'site':<30} {'L':>5} {'I':>5}  {'L level':<7} {'I level':<7} {'severity':<9} grade score")
    for r in sorted(ok, key=lambda r: r["score"], reverse=True):
        print(f"  {urlparse(r['url']).hostname:<30} {r['likelihood']:>5} {r['impact']:>5}  "
              f"{r['likelihood_level']:<7} {r['impact_level']:<7} {r['severity']:<9} {r['grade']:>5} {r['score']:>5}")

    coverage = len(ok) / len(records)
    print(f"\nCoverage: {len(ok)}/{len(records)} = {coverage:.0%} (minimum {LIVE_MIN_COVERAGE:.0%})")
    assert counts["crash"] == 0, "the scanner crashed on some sites - see the failed test_live_site cases"
    assert coverage >= LIVE_MIN_COVERAGE
