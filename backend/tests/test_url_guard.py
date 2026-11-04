#SSRF guard + scan-input edge cases: every kind of thing a user could type into the scan box
#run from backend/:  python -m pytest tests/test_url_guard.py -v
#run inside the production image (same Python, DNS and Chromium as deploy) from the repo root:
#  docker compose build backend
#  docker compose run --rm --no-deps -v ./backend/tests:/app/tests backend python -m pytest tests/test_url_guard.py -v -p no:cacheprovider
#real websites with bot protection are opt-in (slow, and results depend on your IP):  add -e RUN_LIVE_TESTS=1
import asyncio, os, socket, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import url_guard, engine_populate
from scanner.url_guard import BlockedURLError, validate_url, _is_public

BLOCKED = "BLOCKED"
IN_DOCKER = os.path.exists("/.dockerenv")


def _has_dns():
    try:
        socket.getaddrinfo("mozilla.org", None)
        return True
    except OSError:
        return False


needs_dns = pytest.mark.skipif(not _has_dns(), reason="no internet/DNS")
live = pytest.mark.skipif(not os.environ.get("RUN_LIVE_TESTS"), reason="set RUN_LIVE_TESTS=1 to scan real websites")
docker_only = pytest.mark.skipif(not IN_DOCKER, reason="compose service names only resolve inside the docker network")


def check(url):
    """validate_url's verdict: the normalized url, or BLOCKED. Any other exception escapes on purpose -
    in main.py only BlockedURLError becomes a clean 400, anything else is a 500 for the user."""
    try:
        return asyncio.run(validate_url(url))
    except BlockedURLError:
        return BLOCKED


# ---------- Layer 1: what the user types (validate_url) ----------

PUBLIC_INPUTS = [
    ("bare domain", "mozilla.org", "https://mozilla.org"),
    ("full url with path/query/fragment", "https://www.mozilla.org/en-US/?q=1#top", "https://www.mozilla.org/en-US/?q=1#top"),
    ("uppercase scheme + host", "HTTPS://MOZILLA.ORG", "HTTPS://MOZILLA.ORG"),
    ("plain http", "http://example.com", "http://example.com"),
    ("non-standard port", "http://example.com:8080", "http://example.com:8080"),
    ("public IPv4 literal", "1.1.1.1", "https://1.1.1.1"),
    ("public IPv6 literal", "http://[2606:4700:4700::1111]", "http://[2606:4700:4700::1111]"),
    ("unicode (IDN) domain", "münchen.de", "https://münchen.de"),
    ("leading/trailing spaces (copy-paste)", "  mozilla.org  ", "https://mozilla.org"),
]

LOCALHOST_INPUTS = [
    ("localhost", "localhost"),
    ("localhost + port + path", "localhost:8000/history"),
    ("uppercase LOCALHOST", "http://LOCALHOST"),
    ("trailing-dot localhost.", "http://localhost."),
    ("subdomain of localhost", "http://api.localhost"),
    ("public DNS -> 127.0.0.1 (localtest.me)", "http://localtest.me"),
    ("public DNS -> 127.0.0.1 (nip.io)", "http://127.0.0.1.nip.io"),
]

PRIVATE_IP_INPUTS = [
    ("loopback 127.0.0.1", "http://127.0.0.1"),
    ("loopback other 127/8", "http://127.0.0.2"),
    ("short form 127.1", "http://127.1"),
    ("decimal 2130706433", "http://2130706433"),
    ("hex 0x7f000001", "http://0x7f000001"),
    ("octal 0177.0.0.1", "http://0177.0.0.1"),
    ("unspecified 0.0.0.0", "http://0.0.0.0"),
    ("bare 0", "http://0"),
    ("IPv6 loopback [::1]", "http://[::1]"),
    ("IPv6 unspecified [::]", "http://[::]"),
    ("IPv4-mapped IPv6 [::ffff:127.0.0.1]", "http://[::ffff:127.0.0.1]"),
    ("IPv4-mapped IPv6 hex [::ffff:7f00:1]", "http://[::ffff:7f00:1]"),
    ("private 10/8", "http://10.0.0.1"),
    ("private 172.16/12 (docker range)", "http://172.17.0.1"),
    ("private 192.168/16 (home router)", "http://192.168.1.1"),
    ("cloud metadata 169.254.169.254", "http://169.254.169.254/latest/meta-data/"),
    ("carrier-grade NAT 100.64/10", "http://100.64.0.1"),
    ("IPv6 link-local [fe80::1]", "http://[fe80::1]"),
    ("IPv6 unique-local [fc00::1]", "http://[fc00::1]"),
    ("multicast 224.0.0.1", "http://224.0.0.1"),
    ("broadcast 255.255.255.255", "http://255.255.255.255"),
]

SCHEME_INPUTS = [
    ("file:///etc/passwd", "file:///etc/passwd"),
    ("file: single slash", "file:/etc/passwd"),
    ("ftp", "ftp://ftp.mozilla.org"),
    ("javascript:", "javascript:alert(1)"),
    ("data: url", "data:text/html,<h1>hi</h1>"),
    ("view-source:", "view-source:https://mozilla.org"),
    ("chrome:// internal page", "chrome://settings"),
    ("websocket ws://", "ws://mozilla.org"),
    ("gopher (classic SSRF scheme)", "gopher://127.0.0.1:6379/_PING"),
]

DOCKER_NAME_INPUTS = [
    ("compose service: redis", "http://redis:6379"),
    ("compose service: db", "http://db:5432"),
    ("compose service: backend", "http://backend:8000/history"),
    ("docker host gateway", "http://host.docker.internal"),
    ("GCP metadata hostname", "http://metadata.google.internal"),
]

PARSER_TRICK_INPUTS = [
    ("userinfo hides real host: public@private", "http://mozilla.org@127.0.0.1"),
    ("userinfo with port", "http://mozilla.org:443@127.0.0.1:8000"),
    ("fragment hides @", "http://127.0.0.1#@mozilla.org"),
    ("backslash before @ (browser/python disagree)", "http://127.0.0.1\\@mozilla.org"),
    ("backslash-only separator", "http:\\\\127.0.0.1"),
]

MALFORMED_INPUTS = [
    ("empty string", ""),
    ("only spaces", "   "),
    ("scheme with no host", "https://"),
    ("scheme-relative //host", "//mozilla.org"),
    ("space inside host", "http://exa mple.com"),
    ("nonexistent domain", "doesnotexist-xyz123.com"),
    ("label longer than 63 chars", "https://" + "a" * 64 + ".com"),
    ("hostname longer than 253 chars", "https://" + ".".join(["a" * 60] * 5) + ".com"),
    ("null byte in host", "http://mozilla\x00.org"),
    ("port out of range", "http://mozilla.org:99999"),
    ("non-numeric port", "http://mozilla.org:abc"),
]


@needs_dns
@pytest.mark.parametrize("url,expected", [p[1:] for p in PUBLIC_INPUTS], ids=[p[0] for p in PUBLIC_INPUTS])
def test_public_input_allowed(url, expected):
    assert check(url) == expected


@pytest.mark.parametrize("url", [p[1] for p in LOCALHOST_INPUTS], ids=[p[0] for p in LOCALHOST_INPUTS])
def test_localhost_blocked(url):
    assert check(url) == BLOCKED


@pytest.mark.parametrize("url", [p[1] for p in PRIVATE_IP_INPUTS], ids=[p[0] for p in PRIVATE_IP_INPUTS])
def test_private_ip_blocked(url):
    assert check(url) == BLOCKED


@pytest.mark.parametrize("url", [p[1] for p in SCHEME_INPUTS], ids=[p[0] for p in SCHEME_INPUTS])
def test_non_http_scheme_blocked(url):
    assert check(url) == BLOCKED


@pytest.mark.parametrize("url", [p[1] for p in DOCKER_NAME_INPUTS], ids=[p[0] for p in DOCKER_NAME_INPUTS])
def test_internal_hostname_blocked(url):
    assert check(url) == BLOCKED


@docker_only
@pytest.mark.parametrize("host", ["redis", "db"])
def test_compose_names_are_blocked_because_private_not_because_missing(host):
    # inside docker these DO resolve (to 172.x) - prove the guard blocks them on the IP, not on a DNS failure
    addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    assert addresses and not any(_is_public(a) for a in addresses)


@pytest.mark.parametrize("url", [p[1] for p in PARSER_TRICK_INPUTS], ids=[p[0] for p in PARSER_TRICK_INPUTS])
def test_parser_trick_blocked(url):
    assert check(url) == BLOCKED


@pytest.mark.parametrize("url", [p[1] for p in MALFORMED_INPUTS], ids=[p[0] for p in MALFORMED_INPUTS])
def test_malformed_input_is_a_clean_400(url):
    # blocked with BlockedURLError (400) - not a crash (500) and not let through to the browser
    assert check(url) == BLOCKED


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("172.31.255.255", False), ("192.168.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False),
    ("::ffff:127.0.0.1", False), ("::ffff:8.8.8.8", True), ("fe80::1", False), ("fd00::1", False),
])
def test_is_public(ip, public):
    assert _is_public(ip) is public


# ---------- Layers 2 + 3: what the scanned page loads, and where it redirects (real Chromium) ----------
# A local "trap" site plays the attacker's public page. The guard is told 127.0.0.1 is public so the trap
# can be scanned; "localhost" stays private and plays the internal service (redis, metadata, ...).

class _Server:
    def __init__(self, routes):
        self.hits = []
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                status, headers, body = routes(self.path)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body.encode())

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def internal():
    server = _Server(lambda path: (200, {"Content-Type": "text/plain", "Set-Cookie": "internal_secret=1",
                                         "Content-Security-Policy": "internal-only"}, "SECRET"))
    yield server
    server.close()


@pytest.fixture
def trap(internal, monkeypatch):
    inside = f"http://localhost:{internal.port}"
    html = lambda body: (200, {"Content-Type": "text/html"}, f"<html><body>{body}</body></html>")
    pages = {
        "/ok": html("<p>nothing here</p>"),
        "/subresources": html(f"""
            <img src="{inside}/img">
            <script src="{inside}/script.js"></script>
            <iframe src="{inside}/iframe"></iframe>
            <link rel="stylesheet" href="{inside}/style.css">
            <script>fetch("{inside}/fetch").catch(() => {{}})</script>"""),
        "/redirect": (302, {"Location": f"{inside}/main-redirect"}, ""),
        "/img-redirect-page": html('<img src="/img-redirect">'),
        "/img-redirect": (302, {"Location": f"{inside}/img-redirect-target"}, ""),
        "/redirect-public": (302, {"Location": "/ok"}, ""),
    }
    server = _Server(lambda path: pages.get(path, (404, {}, "")))

    real_resolve = url_guard.resolve_public

    async def trap_is_public(host):
        return host == "127.0.0.1" or await real_resolve(host)

    monkeypatch.setattr(url_guard, "resolve_public", trap_is_public)
    monkeypatch.setattr(engine_populate, "resolve_public", trap_is_public)
    server.url = f"http://127.0.0.1:{server.port}"
    yield server
    server.close()


def all_hosts(result):
    return result["third_party_domains"] | result["first_party_domains"] | result["unknown_hosts"]


def test_control_trap_page_scans_normally(trap):
    result = asyncio.run(engine_populate.scan(trap.url + "/ok"))
    assert result["main_document"]["status"] == 200


def test_layer1_typed_internal_url_never_launches_browser(internal):
    with pytest.raises(BlockedURLError):
        asyncio.run(engine_populate.scan(f"http://localhost:{internal.port}/"))
    assert internal.hits == []


def test_layer2_page_cannot_load_internal_subresources(trap, internal):
    result = asyncio.run(engine_populate.scan(trap.url + "/subresources"))
    assert internal.hits == []                        # img/script/iframe/css/fetch never reached the service
    assert "localhost" not in all_hosts(result)       # and nothing about it appears in the report
    assert "localhost" not in result["security_headers"]
    assert not any(c["name"] == "internal_secret" for c in result["cookies"])


def test_layer2_same_origin_redirect_to_public_page_allowed(trap):
    result = asyncio.run(engine_populate.scan(trap.url + "/redirect-public"))
    assert result["final_url"].endswith("/ok")


def test_layer3_main_page_redirect_to_internal_is_discarded(trap, internal):
    with pytest.raises(BlockedURLError):
        asyncio.run(engine_populate.scan(trap.url + "/redirect"))
    # known limitation: route() can't stop a redirect hop, so the internal service may see ONE request -
    # Layer 3 guarantees its response never reaches the user. A network firewall closes this fully.
    print(f"\ninternal service hits during main-page redirect: {internal.hits}")
    assert len(internal.hits) <= 1


def test_layer3_subresource_redirect_to_internal_is_discarded(trap, internal):
    with pytest.raises(BlockedURLError):
        asyncio.run(engine_populate.scan(trap.url + "/img-redirect-page"))
    print(f"\ninternal service hits during image redirect: {internal.hits}")
    assert len(internal.hits) <= 1


def test_backslash_trick_end_to_end_is_a_clean_400(internal):
    # python reads the host as mozilla.org, Chromium reads it as localhost - must still be a 400, not a 500
    url = f"http://localhost:{internal.port}\\@mozilla.org"
    with pytest.raises(BlockedURLError):
        asyncio.run(engine_populate.scan(url))
    assert internal.hits == []


# ---------- real websites (opt-in) ----------
# The goal is to scan everything, so a bot-protection wall counts as a FAILED scan even though the
# scanner "worked": the report would describe the challenge page, not the real site.

CHALLENGE_HOST_MARKERS = ("challenges.cloudflare.com", "hcaptcha.com", "captcha-delivery.com",
                          "px-cdn.net", "px-cloud.net", "perimeterx.net")


def bot_block_signals(result):
    signals = []
    status = (result.get("main_document") or {}).get("status")
    if status in (403, 429, 503):
        signals.append(f"HTTP {status}")
    if "/sorry/" in (result.get("final_url") or ""):
        signals.append("redirected to Google /sorry/ captcha")
    signals += [f"challenge host {h}" for h in all_hosts(result) if any(m in h for m in CHALLENGE_HOST_MARKERS)]
    return signals


@needs_dns
@live
def test_live_public_site_scans():
    result = asyncio.run(engine_populate.scan("https://example.com"))
    assert result["main_document"]["status"] == 200 and not bot_block_signals(result)


BOT_SITES = [
    ("cloudflare: nowsecure.nl", "https://nowsecure.nl", True),
    ("datadome: g2.com", "https://www.g2.com", True),
    ("google search captcha", "https://www.google.com/search?q=privacy+auditor", True),
    ("perimeterx: zillow.com", "https://www.zillow.com", True),
    ("datadome: tripadvisor.com", "https://www.tripadvisor.com", True),
    # akamai doesn't serve a challenge page - it kills the connection (net::ERR_HTTP2_PROTOCOL_ERROR)
    ("akamai: minecraft.net (silent block)", "https://www.minecraft.net/en-us", True),
    ("recaptcha widget on page (not a wall)", "https://www.google.com/recaptcha/api2/demo", False),
]


@needs_dns
@live
@pytest.mark.parametrize("url,protected", [p[1:] for p in BOT_SITES], ids=[p[0] for p in BOT_SITES])
def test_live_bot_protected_site(url, protected, request):
    if protected:
        request.applymarker(pytest.mark.xfail(reason="bot protection blocks the headless scanner (known, not fixed)"))
    result = asyncio.run(engine_populate.scan(url))
    signals = bot_block_signals(result)
    print(f"\n{url}: status={(result.get('main_document') or {}).get('status')} "
          f"final={result.get('final_url')} signals={signals}")
    assert not signals, f"scan hit a bot wall: {signals}"
