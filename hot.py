from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import re
import base64

user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1"

def get_urls(driver, urls):
    for url in urls:
        if url:
            if not url.startswith('http'):
                url = 'http://' + url
            driver.get(url)
            driver.switch_to.new_window('tab')
            driver.implicitly_wait(45)

def decode_urls(encoded_urls):
    decoded_urls_string = base64.b64decode(encoded_urls).decode('ascii')
    decoded_urls = decoded_urls_string.split('<br>')
    return [url.strip(' ') for url in decoded_urls]

if __name__ == "__main__":
    opts = Options()

    # [READ] The following is intentional [READ]
    # At the moment, having resistFingerprinting on and setting the useragent
    # override pref. causes useragent not to apply properly, feel free to test.
    # Therefor, we allow websites to fingerprint us, we just make sure to 
    # give them bogus fingerprinting info
    opts.set_preference("privacy.resistFingerprinting", False)

    opts.set_preference("browser.safebrowsing.phishing.enabled", False)
    opts.set_preference("general.useragent.override", user_agent)
    user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1"
    window_width = 512  
    window_height = 1024

    urls_txt = "links.txt"
    urls = None

    #urls = decode_urls(input("Enter Base64 Encoded url string: "))
    with open('links.txt','r') as f:
        urls = [url.strip('\n') for url in f.readlines()]

    with webdriver.Firefox(options = opts) as driver:
        driver.set_window_size(window_width, window_height)
        driver.set_page_load_timeout(60)
        if urls:
            get_urls(driver, urls)
        print('done, holding...')
        while True:
            pass