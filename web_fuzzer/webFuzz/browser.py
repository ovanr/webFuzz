"""
Just a simple use of selenium with Chrome
Please download the same version as your Chrome Browser:
https://chromedriver.chromium.org/downloads
"""

from selenium import webdriver, common
from os.path import dirname

def get_cookies(driver_location, url):

    # driver_location = dirname(__file__) + "chromedriver"
    driver = webdriver.Chrome(executable_path=driver_location)
    driver.get(url)

    while True:
        try:
            driver.get_window_size()
            x = driver.get_cookies()
            if x != None:
                cookies = x

        except common.exceptions.WebDriverException:
            break
    

    
    return cookies

if __name__ == "__main__":
    get_cookies(dirname(__file__) + "/chromedriver", "http://localhost:8888/")
