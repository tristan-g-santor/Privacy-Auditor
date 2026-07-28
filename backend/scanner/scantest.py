import asyncio #built in library to write code using async/wait
from urllib.parse import urlparse #breaks down the components into a string (protocol, domain, and path)

from playwright.sync_api import sync_playwright # this lets you launch the browser instance

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
def scan(url): 
    #structure for url
    result = {"url": url, "third_party_domains": set(), "cookies": [], "security_headers": {}}
    def handle_request(request):
        print("REQ:",request.url)

    def handle_responses(response):
        req_domain = urlparse(response.url).netloc
        # Only add if it does not match the main domain
        if req_domain and req_domain != main_domain:
            result["third_party_domains"].add(req_domain)

        
        #print( "RES: ", response.status, response.url)
        headers = response.headers
        #hardcoded list of header names to consider 
        found = {} #collects all matching headers for specific response 
        for h in SECURITY_HEADERS_TO_CHECK:
            if h in headers:
                #print("RES HEADER:", response.url, h, "=", headers[h])
                found[h] = headers[h]

        if found:
            result["security_headers"].setdefault(req_domain,{}).update(found)

    #Start playwright as p
    #navigate the website and 
    with sync_playwright() as p:
        #launc a new browser and new page to setup and track network traffic 
        browser = p.chromium.launch()
        context = browser.new_context()
        page = context.new_page()   
        page.on("request", handle_request)
        page.on("response", handle_responses)   
        main_domain = urlparse(url).netloc

        page.goto(url)
        result["cookies"] = context.cookies()
        browser.close()


    return result


if __name__ == "__main__":
    output = scan("https://www.cnn.com")
    print("Test scan output")
    print(output)