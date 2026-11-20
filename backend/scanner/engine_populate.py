import asyncio, ipaddress, json, os, tldextract #built in library to write code using async/wait
from scanner.url_guard import validate_url, resolve_public, BlockedURLError
from urllib.parse import urlparse #breaks down the components into a string (protocol, domain, and path)
from playwright.async_api import async_playwright, Error as PlaywrightError # this lets you launch the browser instance

# Navigation timing. goto() returns at "domcontentloaded" (HTML parsed) instead of "load" (every
# image, ad and pixel finished) - ad-heavy sites often never reach "load", which timed the whole
# scan out. The settle wait then gives deferred trackers time to fire before we collect.
# Budget: goto (20 s) + settle (3 s) + collection stays under the server's 30 s scan timeout.
GOTO_TIMEOUT_MS = int(os.environ.get("SCAN_GOTO_TIMEOUT_MS", "20000"))
SETTLE_MS = int(os.environ.get("SCAN_SETTLE_MS", "3000"))

# Shared browser: one Chromium for the whole server, started by FastAPI's lifespan (start_browser).
# Each scan gets its own browser context - a fresh incognito-style profile with its own cookies,
# cache and storage - so scans can't see each other's data. Launching Chromium per scan cost
# ~1-2 s and ~300 MB each; a context costs a fraction of that.
# If start_browser() was never called (tests, scripts), scan() falls back to its own Chromium.
_playwright = None
_browser = None
_browser_lock = None


async def start_browser():
    global _playwright, _browser, _browser_lock
    if _browser is not None:
        return
    _browser_lock = asyncio.Lock()  # created here so it belongs to the running event loop
    _playwright = await async_playwright().start()
    _browser = await _playwright.chromium.launch()


async def stop_browser():
    global _playwright, _browser, _browser_lock
    try:
        if _browser is not None:
            await _browser.close()
    except PlaywrightError:
        pass  # already gone
    finally:
        if _playwright is not None:
            await _playwright.stop()
        _playwright = _browser = _browser_lock = None


async def _shared_browser():
    """The shared browser, relaunched first if Chromium crashed."""
    global _browser
    async with _browser_lock:  # so two scans noticing a crash don't both relaunch
        if not _browser.is_connected():
            _browser = await _playwright.chromium.launch()
    return _browser




SECURITY_HEADERS_TO_CHECK = [
    "content-security-policy",
    "strict-transport-security",
    "set-cookie",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
]

# Load once at import time 
ENTITY_MAP_PATH = os.path.join(os.path.dirname(__file__), "entity_map.json")
with open(ENTITY_MAP_PATH, encoding="utf-8") as f:
    _ddgo_entity_map = json.load(f)

# Flip {entity name: {properties: [domains]}} into {domain: entity name} for O(1) lookups
DOMAIN_TO_ENTITY = {}
for _entity_name, _entity_data in _ddgo_entity_map.items():
    for _domain in _entity_data.get("properties", []):
        DOMAIN_TO_ENTITY[_domain] = _entity_name


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def classify_host(host, request_etld1, main_etld1):
    """Returns 'first_party', 'third_party', or 'unknown'."""
    # IPs and hosts like 'localhost' have no registrable domain, so we can't judge ownership
    if not host or is_ip(host) or not request_etld1:
        return "unknown"

    request_entity = DOMAIN_TO_ENTITY.get(request_etld1)
    main_entity = DOMAIN_TO_ENTITY.get(main_etld1)

    if request_entity and main_entity:
        # Both sides are known entities - compare by company, not by domain string
        return "first_party" if request_entity == main_entity else "third_party"

    # Not in the entity dataset - fall back to registrable-domain comparison
    return "first_party" if request_etld1 == main_etld1 else "third_party"


#referrer-policy — controls how much of the current page's URL leaks to third parties when a user clicks a link or a resource loads. This is arguably one of the most privacy-relevant headers that exists, and it's currently absent from your list.
#permissions-policy — controls whether the page (or embedded third parties) can access camera, microphone, geolocation, etc. Also directly privacy-relevant.

#low priority 
#x-content-type-options — general security hygiene, less privacy-specific
#cross-origin-opener-policy / cross-origin-embedder-policy — more about isolation/security than user privacy

#show every network request the page has fired off when loading the specified website 
#if a website uses a Service Worker, some requestts can be invisible to that unless
#we block service works using serviceWorkers: "block"
async def scan(url):
    #structure for url
    url =  await validate_url(url)
    result = {
        "url": url,
        "third_party_domains": set(),
        "first_party_domains": set(),
        "cookies": [],
        "security_headers": {},
        "tls_info": {},
        "unknown_hosts": set(),
        "main_document": None,
    }

    seen_hosts =  set()  # Keep track of hosts we've already processed to avoid duplicates


    checked_hosts = {}         # host -> True/False (public or not), so each host is only resolved once per scan
    requested_hosts = set()    # every host the browser asked for, including redirect hops

    async def is_allowed(host):
        if host not in checked_hosts:
            checked_hosts[host] = await resolve_public(host)
        return checked_hosts[host]

    async def guard_request(route):
        host = urlparse(route.request.url).hostname
        if host and await is_allowed(host):
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    async def handle_responses(response):
        req_domain = urlparse(response.url).hostname
        if req_domain:
            seen_hosts.add(req_domain)

        try:
            headers = await response.all_headers() #hardcoded list of header names to consider
            security_details = await response.security_details()
        except PlaywrightError:
            return  # the context closed while this late response was still being read

        found = {} #collects all matching headers for specific response
        for h in SECURITY_HEADERS_TO_CHECK:
            if h in headers:
                found[h] = headers[h]

        if found:
            result["security_headers"].setdefault(req_domain, {}).update(found)

        #TLS config
        if security_details:
            result["tls_info"][req_domain] = security_details

    #core engine: one fresh context (own cookies/cache/storage) per scan, always closed afterwards
    async def collect(browser):
        context = await browser.new_context(service_workers="block")
        try:
            await context.route("**/*", guard_request)
            page = await context.new_page()
            page.on("request", lambda req: requested_hosts.add(urlparse(req.url).hostname))
            page.on("response", handle_responses)

            main_response = await page.goto(url, wait_until="domcontentloaded", timeout=GOTO_TIMEOUT_MS)
            await page.wait_for_timeout(SETTLE_MS)  # let deferred trackers, ads and beacons fire

            if main_response:
                main_headers = await main_response.all_headers()
                result["main_document"] = {
                    "url": main_response.url,
                    "status": main_response.status,
                    "security_headers": {
                        h: main_headers[h] for h in SECURITY_HEADERS_TO_CHECK if h in main_headers
                    },
                }
            result["cookies"] = await context.cookies()

            result["final_url"] = page.url
            site_etld1 = tldextract.extract(urlparse(page.url).hostname or "").top_domain_under_public_suffix

            for host in seen_hosts:
                request_etld1 = tldextract.extract(host).top_domain_under_public_suffix
                category = classify_host(host, request_etld1, site_etld1)
                if category == "third_party":
                    result["third_party_domains"].add(host)
                elif category == "first_party":
                    result["first_party_domains"].add(host)
                else:
                    result["unknown_hosts"].add(host)

            #Layer 3: any host reached through a redirect hop must also be public
            for host in requested_hosts - checked_hosts.keys():
                if host and not await is_allowed(host):
                    raise BlockedURLError(f"Site redirected to a non-public address ({host})")
        finally:
            try:
                await context.close()
            except PlaywrightError:
                pass  # browser crashed mid-scan; the original error is what matters

    if _browser is not None:
        await collect(await _shared_browser())
    else:
        # no shared browser (tests, scripts): launch a private one just for this scan
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            try:
                await collect(browser)
            finally:
                await browser.close()

    return result


"""
Sample main for testing 
"""
if __name__ == "__main__":
    output = asyncio.run(scan("https://www.roblox.com/home"))
    #Converts each set into a sorted list in palce
    #ssince we cant serialize a python set itll crash with a type error
    output["third_party_domains"] = sorted(output["third_party_domains"])
    output["first_party_domains"] = sorted(output["first_party_domains"])
    output["unknown_hosts"] = sorted(output["unknown_hosts"])
    print(json.dumps(output, indent=2))