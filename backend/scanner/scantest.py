from playwright.sync_api import sync_playwright


#Start playwright as p
#navigate the website and 
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto("https://www.roblox.com/home")
    print(page.title())
    browser.close()

