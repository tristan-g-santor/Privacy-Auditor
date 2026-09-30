import asyncio, json, os, tldextract, requests #built in library to write code using async/wait

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


def is_third_party(request_etld1, main_etld1):
    if not request_etld1:
        return False

    request_entity = DOMAIN_TO_ENTITY.get(request_etld1)
    main_entity = DOMAIN_TO_ENTITY.get(main_etld1)

    if request_entity and main_entity:
        # Both sides are known entities - compare by company, not by domain string
        return request_entity != main_entity

    # Not in the entity dataset - fall back to registrable-domain comparison
    return request_etld1 != main_etld1

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
        "tls_info": {}
    }

    main_domain = urlparse(url).netloc

    async def handle_responses(response):
        req_domain = urlparse(response.url).netloc
        # Only add if it does not match the main domain (this is a)
        con_domain = urlparse(response.frame.page.url).netloc
       
        #extract the tld domains
        #A DeprecationWarning is Python's way of saying: "this still works right now, but the library's authors plan to remove it in a future version 
        #— you should switch to the new name before that happens
        """main_domain_etld1 = tldextract.extract(main_domain).registered_domain
            context_etld1 = tldextract.extract(con_domain).registered_domain
            request_etld1 = tldextract.extract(req_domain).registered_domain
        """
        main_domain_etld1 = tldextract.extract(main_domain).top_domain_under_public_suffix
        context_etld1 = tldextract.extract(con_domain).top_domain_under_public_suffix
        request_etld1 = tldextract.extract(req_domain).top_domain_under_public_suffix
        

        if is_third_party(request_etld1, main_domain_etld1):
            result["third_party_domains"].add(req_domain)
        else:
            result["first_party_domains"].add(req_domain)

        headers = response.headers  #hardcoded list of header names to consider
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
        browser = await p.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()
        page.on("response", handle_responses)

        await page.goto(url)
        result["cookies"] = await context.cookies()
        await browser.close()

    return result


#def audit_domain(): 





if __name__ == "__main__":
    output = asyncio.run(scan("https://www.roblox.com/home"))
    #Converts each set into a sorted list in palce
    #ssince we cant serialize a python set itll crash with a type error
    output["third_party_domains"] = sorted(output["third_party_domains"])
    output["first_party_domains"] = sorted(output["first_party_domains"])
    print(json.dumps(output, indent=2))