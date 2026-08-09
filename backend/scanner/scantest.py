import asyncio, json #built in library to write code using async/wait

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
        "cookies": [],
        "security_headers": {},
        "tls_info": {}
    }

    main_domain = urlparse(url).netloc

    async def handle_responses(response):
        req_domain = urlparse(response.url).netloc
        # Only add if it does not match the main domain
        if req_domain and req_domain != main_domain:
            result["third_party_domains"].add(req_domain)

        headers = response.headers
        #hardcoded list of header names to consider
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


if __name__ == "__main__":
    output = asyncio.run(scan("https://roblox.com/"))
    output["third_party_domains"] = sorted(output["third_party_domains"])
    print(json.dumps(output, indent=2))