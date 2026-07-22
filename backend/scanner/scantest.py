from playwright.sync_api import sync_playwright


#show every network request the page has fired off when loading the specified website 

#if a website uses a Service Worker, some requestts can be invisible to that unless
#we block service works using serviceWorkers: "block"
def handle_request(request):
    print("REQ:",request.url)

def handle_responses(response):
    print( "RES: ", response.status, response.url)
    headers = response.headers
    for h in ["content-security-policy", "strict-transport-security", "set-cookie", "x-frame-options"]:
        if h in headers:
            print("RES HEADER:", response.url, h, "=", headers[h])

#Start playwright as p
#navigate the website and 
with sync_playwright() as p:
    browser = p.chromium.launch()
    context = browser.new_context() #cookies 
    page = context.new_page()

    page.on("request", handle_request)    #requests
    page.on("response", handle_responses)
    page.goto("https://www.cnn.com")
    print(page.title())
    print(context.cookies())
    print(page.title())
    browser.close()

