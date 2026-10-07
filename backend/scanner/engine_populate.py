import asyncio, ipaddress, json, os, tldextract #built in library to write code using async/wait

from urllib.parse import urlparse #breaks down the components into a string (protocol, domain, and path)
from playwright.async_api import async_playwright # this lets you launch the browser instance



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
    async def handle_responses(response):
        req_domain = urlparse(response.url).hostname
        if req_domain:
            seen_hosts.add(req_domain)


        headers = await response.all_headers() #hardcoded list of header names to consider
        found = {} #collects all matching headers for specific response
        for h in SECURITY_HEADERS_TO_CHECK:
            if h in headers:
                found[h] = headers[h]

        if found:
            result["security_headers"].setdefault(req_domain, {}).update(found)

        #TLS config
        security_details = await response.security_details()
        if security_details:
            result["tls_info"][req_domain] = security_details

    #Start playwright as p
    #navigate the website and
    async with async_playwright() as p:
        #launch a new browser and new page to setup and track network traffic
        #need to change instead of launching everytime instead of startup 
        #need to be aware of that
        browser = await p.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()
        page.on("response", handle_responses)

        main_response = await page.goto(url)
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


        await page.wait_for_timeout(500)  # let any trailing response handlers finish
        await browser.close()

    return result



if __name__ == "__main__":
    output = asyncio.run(scan("https://www.roblox.com/home"))
    #Converts each set into a sorted list in palce
    #ssince we cant serialize a python set itll crash with a type error
    output["third_party_domains"] = sorted(output["third_party_domains"])
    output["first_party_domains"] = sorted(output["first_party_domains"])
    output["unknown_hosts"] = sorted(output["unknown_hosts"])
    print(json.dumps(output, indent=2))