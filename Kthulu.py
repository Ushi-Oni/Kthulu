from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from datetime import datetime
from pathlib import Path
import time
import whois
import shutil
import os
import re
import pyminizip


#####################################################################
###                     Directory Input                           ###
#####################################################################
loot_dirs = [                                                                   # Full filpaths to check for a cred dump file
        # Examples: "/pwned/dump.txt", "/hax0r/results.txt", etc
        # You could probably sub in some items from SecLists 
        # (check it out if you're unfamiliar!)
        ]
links_file = "links.txt"                                                        # List of urls to check for status code and credentials
results_dir = "./results/"                                                      # Base location for all resulting items
dumps_dir = results_dir + "dumps/"                                              # Location to place located credential dumps
pics_dir = results_dir + "pics/"                                                # Location for screenshots of base url after redirects (if applicable)
htmlsource_dir = results_dir + "html/"                                          # Location for html source code to be saved tor
redirects = results_dir + "redirects"                                           # Filepath for file that holds all redirect information gathered.
bads = results_dir + "bads"                                                     # File path for file that holds all dead, fail, and error urls
goods = results_dir + "goods"                                                   # File path for file that holds all cred and non_cred urls
creds = results_dir + "creds"                                                   # Log file for URLs which had a dump file located.
abuse_info = results_dir + "abuse_info"                                         # Where to write abuse info for alive && relevant domains

dir_list = [results_dir, dumps_dir, pics_dir, htmlsource_dir]
#####################################################################
###                      Regex Input                              ###
#####################################################################
domain_ptrn= re.compile(r'(?:https?://)([^/]+)')                                # no touchy! (unless you're a regex nerd)
base_ptrn = re.compile(r'(https?://[^/]+)')                                     # no touchy! (unless you're a regex nerd)
base_ptrn_non_grouped_str = r'(https?://[^/]+)'                                 # no touchy! (unless you're a regex nerd)

org_ptrn = re.compile(r'')                                                      # Put regex here you want to match on - what might be some important, relevant keywords?
#####################################################################
###                      Selenium Inputs                          ###
#####################################################################
user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1"
window_width = 720
window_height = 1024
#####################################################################

#########################################################
#   isAlive(url):
#       url: the url (str) to check the alive status for
#   Descr:
#       - Remove newline in string TODO: Fix this overall
#       - Check if protocol is included, else add it (http default)
#       - Get the status code for the url specified
#   Return:
#       True  = 200 received
#       False = 404 received
#       Otherwise return the status code
#########################################################
def isAlive(url):
    url = url.rstrip('\n')
    if not url.startswith('http'):
        url = 'http://' + url
    s_code = getStatusCode(url)
    if (s_code == 200):
        return True
    elif s_code == 404:
        return False
    else:
        return s_code

#########################################################
#   isRelatedToOrg(content):
#       content: webpage contents (str) to regex search
#   Descr:
#       - Sub all nonalphabetic chars in content w/ nothing
#   Return:
#       True  =  we were able to match content to our orgs
#                regex (org_ptrn)
#       False =  couldnt find any matches in content
#########################################################
def isRelatedToOrg(content):
    content = re.sub(r'[^a-zA-Z]+', '', content)
    if org_ptrn.match(content):
        return True
    else:
        print(content)
        return False

#########################################################
#   parseUrl(operation, url):
#       operation: the operation (str) to perform (domain, base)
#       url: the url (str) to do the operation transform on
#   Descr:
#       - First we separate the protocol and domain from
#         the directories
#           - https://abc.com/a/b/c -> [https://abc.com , /a/b/c]
#       - Next we grab the last element (-1)
#       - Now we create a list from that and split on '/'
#           - /a/b/c -> ['','a','b','c']
#           - /a/b/c/ -> ['','a','b','c', '']
#       - Now get rid of empty items
#   Return:
#       - dirs (list) if our operation was 'dirs'
#       - Various regex pattern matches (str):
#           - Basically converts url -> domain transform
#             or to a base form (protocol + domain)
#       - Otherwise returns None - operation was invalid
#########################################################
def parseUrl(operation, url):
    if operation == "dirs":
        dirs = re.split(base_ptrn_non_grouped_str,url)[-1]     #pull out the base pattern so we're only left with the dirs part of the URL abc.com/a/b/c -> /a/b/c
        dirs = dirs.split('/')
        dirs.pop(0)
        if not dirs[-1] == " ":
            dirs.pop(-1)
        return dirs
    else:
        matches = {
                "domain" : domain_ptrn.match(url),
                "base" : base_ptrn.match(url),
            }
        if matches[operation]:
            return matches[operation].group(1)
        else:
            #print(f"ERROR: Did not find '{operation}' pattern match in matches dictionary for {url})")
            return None

#########################################################
#   writeContentToFilepath(filepath, ext, content, doAppend):
#       filepath: the filepath (str) to write to
#       ext: the file extension (str) to include in filename
#       content: the content (str) to write
#       doAppend: (bool) whether or not we should append
#   Descr:
#       - Pretty self-explanatory but, we write 'content'
#         to 'filepath' + 'ext' and optionally do it as an append
#   Return:
#       n/a
#########################################################
def writeContentToFilepath(filepath, ext = None, content = None, doAppend = False):
    if not content:
        print(f"CRITICAL: Content to write was invalid: [ {content} ]")
        exit()
    if not Path(filepath + ext).exists():
        with open(filepath + ext,"w") as f:
                f.write(content)
    else:
        if doAppend:
            with open(filepath + ext,"a") as f:
                f.write(content)
        else:
            with open(filepath+str(datetime.bw().time())+ ext,"w") as f:
                f.write(content)

#########################################################
#   getStatusCode(url):
#       url: the url (str) to check the status code for
#   Descr:
#       - Selenium loads the specified URL in the browser
#       - Force a wait period for 5 seconds
#       - Executes an async. script from getScriptString
#   Return:
#       - -1 = error getting status code/running XHR script
#       - 0 = a selenium exception occurred (various errs)
#             we also write to the bad urls file here
#       - otherwise returns the status code (int)
#########################################################
def getStatusCode(url):
    try:
        driver.get(url)
        cur_url = driver.current_url
        driver.implicitly_wait(5)  #let the page load for 5 sec
        script_result = driver.execute_async_script(getScriptString(cur_url))
        if type(script_result) is str:
            print(f"{url},{cur_url},'XHR Error'")
            return -1
        else:
            return script_result
    except WebDriverException as e:
        writeContentToFilepath(bads, ".txt", f"failure, {url},'" + e.msg + f"'\n", True)
        return 0

#########################################################
#   getScriptString(url):
#       url: the url (str) to call this script within
#   Descr:
#       - returns the crafted script which will be used
#         to execute an XHR to check the current status
#         code (404, 403, 200, etc)
#   Return:
#       - constructed script string
#########################################################
def getScriptString(url):
    return '''
                let callback = arguments[0];
                let xhr = new XMLHttpRequest();
                xhr.open('GET', ''' + "'" + url + "'" + ''', true);
                xhr.onload = function () {
                    if (this.readyState === 4) {
                        callback(this.status)
                    }            
                };
                xhr.onerror = function () {
                    callback('XHR request threw an error')
                };
                xhr.send(null);
                '''

#########################################################
#   getScriptTags(url):
#       url: the url (str) to check for script tags
#   Descr:
#       - grabs all elements that match the (specified)
#         type of script tag. CHANGE this if you want
#         something different
#       - For each elem, grab the actual script content
#           - Write the script contents w/ domain and the
#             unique element id as the filename
#   Return:
#       n/a
#########################################################
def getScriptTags(url):
    scripts = driver.find_elements(By.XPATH, '//script[@type="text/javascript"]')
    domain = parseUrl("domain",url)
    for script in scripts:
        html_path = htmlsource_dir + domain + script._id
        content = script.get_attribute('innerHTML')
        if content:
            writeContentToFilepath(html_path, ".js", content, False)

#########################################################
#   getLoot(url):
#       url: the url (str) to download content from
#   Descr:
#       - write the current webpage contents to .txt file
#         where the name is again the domain.
#   Return:
#       n/a
#   Notes:
#       This will return whatever the webpage contents 
#       are, including html tags, you will need to parse
#       that stuff out. TODO: Add this functionality here
#########################################################
def getLoot(url):
    domain = parseUrl("domain",url)
    if domain:
        dump_path = dumps_dir + domain
        content = driver.page_source
        writeContentToFilepath(dump_path, ".txt", content)
    else:
        #print(f"Failed to match domain regex against {url}")
        pass

#########################################################
#   checkForLoot(url):
#       url: the url (str) to check for credential dumps
#   Descr:
#       - iter over each loot dir listed in loot_dir(list)
#       - concatenate loot dir to url and exec isAlive()
#       - if isAlive() mark found_creds & exec getLoot()
#   Return:
#       - found_creds (bool)
#########################################################
def checkForLoot(url):
    found_creds = False
    if url:
        for loot_dir in loot_dirs:
            loot_url = url + loot_dir
            if isAlive(loot_url):
                found_creds = True
                getLoot(loot_url)
            else:
                #print(f"{loot_url} did not find loot. StatusCode: " + str(getStatusCode(loot_url)))
                pass
    else:
        #print(f"{url} was skipped (None means the regex didn't match, so the first_dir wasn't found)")
        pass
    return found_creds

#########################################################
#   checkUrl(url):
#      url: the url (str) to check for credential dumps.
#
#   Descr: 
#       - Get domain-only formating of specified url
#           - https://abc.com/x/y --> abc.com
#       - Save a png of this website with domain as name
#       - Save html with domain again as filename
#       - Call checkForLoot() (see checkForLoot())
#   Return:
#       - found_creds (bool) (redundant, but easier 2 debug)
#########################################################
def hasCredentials(url):
    domain = parseUrl("domain",url)
    found_creds = False
    if domain:
        driver.save_screenshot(pics_dir + parseUrl("domain", url)+ ".png")
        html_path = htmlsource_dir + domain
        content = driver.page_source
        writeContentToFilepath(html_path, ".html", content)
        #getScriptTags(url)
        temp_base = parseUrl("base",url)
        checkForLoot(temp_base)
        dirs_to_iter = parseUrl("dirs", url)
        url_iter = temp_base
        for i in range(len(dirs_to_iter)):
            url_iter += ("/" + dirs_to_iter[i])
            if checkForLoot(url_iter):
                found_creds = True
    else:
        #print(f"Failed to match domain regex against {url} in checkURL() method")
        pass
    return found_creds

#########################################################
#   setupFolders():
# 
#   Descr:
#       - Pretty simple, create our various result folders
#   Return:
#       n/a
#########################################################
def setupFolders():
    for directory in dir_list:
        os.mkdir(directory)

#########################################################
#   packageResults():
#
#   Descr:
#       - Does an Walk function on the current results dir
#       - This returns a list of all items and their location
#       - Keep a running list of files and their full path
#       - Keep a running list of their associated folder paths
#       - Next, pass this all to pyminizip
#       - This does an encrypted zip with a password
#         the user enters TODO: Figure out how secure that really is
#       - Lastly, delete the results folder
#         
#   Return:
#       n/a
#########################################################
def packageResults():
    walker = os.walk('results')
    targets = []
    paths = []

    for loc,dirs,files in walker:
        for ifile in files:
            targets.append(os.getcwd() + "/" + loc + "/" + ifile)
            paths.append("/" + loc + "/")
            
    pyminizip.compress_multiple(targets,paths,datetime.now().strftime('%Y-%m-%d-%I%p') + '_results.zip',input('set zip password: '),1)
    shutil.rmtree("./results/")

def handleAbuse(urls):
    abuseDictionary = {}
    for url in urls:
        current_domain = parseUrl('domain', url)
        if current_domain in abuseDictionary.keys():
            abuseDictionary[current_domain]['originals'] += [url]
        else:
            abuseDictionary[current_domain] = {'originals': [url]}
            abuseDictionary[current_domain]['abuse'] = whois.getAbuseInfo(current_domain)
        abuse_contacts = abuseDictionary[current_domain]['abuse']
        writeContentToFilepath(abuse_info, '.txt', f'{url},{current_domain},{abuse_contacts}\n',True)
#########################################################
#   main():
#   Descr:
#       - If the url isAlive and isRelatedToOrg, mark in redirects file
#       - Otherwise, false isAlive writes to bad urls file with dead as url type
#       - Otherwise, if isAlive = -1 
#       - Otherwise, if isRelated = false write to bad urls file w/ error as url type
#       - Otherwise, if isAlive = 0 pass
#       - Otherwise, we have a catch all that prints to the console.
#       - Back to isAlive and isRelatedToOrg now...
#       - Write to our redirects file the original url
#         and url we got redirected to.
#       - write new redirected destination urls to our list
#         of checked urls
#       - write the original url to the existing dictionary
#         entry so that we can keep track
#
#         convenient info graphic:
#           checked_urls dictionary:
#           {
#             phishing.com : [short.ly/1, short.ly/2, short.ly/3]
#             smishing.com : [shrt.ly/1, s.id/999]
#             etc
#           }
#        - now, we just do the cred dump checks on the keys
#          (on the phishing, smishing etc) This ensures
#          that we're moving optimally and only scanning
#          common domains once.
#        - we write the sites that had cred dumps to the creds file
#   Return:
#       need_abuse_lookup (dict) where key,value is:
#            final_url (str), og_urls (list of str)
#########################################################
def main():
    need_abuse_lookup = []
    with open(redirects + ".txt", "w") as f:
        f.write("")
    with open(links_file, 'r+') as f:
        urls_with_creds = {}
        for raw_url in f:
            orig_url = raw_url.rstrip('\n')
            url = raw_url.rstrip("\n")
            url_isAlive = isAlive(url)
            time.sleep(5)  #let the page load so content isn't empty + javascript loader
            url_isRelated = isRelatedToOrg(driver.page_source)
            url = driver.current_url
            if (url_isAlive == True) and (url_isRelated):
                base = parseUrl("base", url)
                need_abuse_lookup += [orig_url,url]
                writeContentToFilepath(redirects, ".txt", f"{orig_url} -> {url}\n", True)
                if not base in urls_with_creds.keys():
                    urls_with_creds[base] = ""
                    if hasCredentials(url):
                        #print(f"Adding new redirected url to dict {base} with new referrer list {orig_url}")
                        urls_with_creds[base] = [orig_url]
                    else:
                        writeContentToFilepath(creds, ".txt", f"no creds,{orig_url},{url}", True)
                    
                else:
                    redirected_url_cur_values = urls_with_creds[base]
                    if not redirected_url_cur_values == "": # i.e. if this redirected url entry has original urls listed, then we should add, otherwise dont bother
                        #print(f"Adding new referrer url to existing entry @ {base}: {orig_url}")
                        urls_with_creds[base].append(orig_url)
            elif url_isAlive == False:
                writeContentToFilepath(bads, ".txt", f"dead,{orig_url},{url}\n", True)
            elif (url_isAlive == -1) or (not url_isRelated):
                print(url_isAlive)
                print(url_isRelated)
                writeContentToFilepath(bads,".txt", f"error,{orig_url},{url}\n", True)
            elif url_isAlive == 0:
                pass 
            else:
                print(f"Caught: {orig_url} -> {url} returned {url_isAlive}, and isRelated was {url_isRelated}")
            
        final_urls_with_creds = urls_with_creds.keys()
        for final_url in final_urls_with_creds:
            referer_urls = urls_with_creds[final_url]
            for referer_url in referer_urls:
                if not referer_url == "":
                    #print(f"Writing to cred file referer {referer_url}, from final_url {final_url}")
                    writeContentToFilepath(creds, ".txt", f"creds,{referer_url},{final_url}\n",True)
        return need_abuse_lookup

if __name__ == "__main__":
    setupFolders()
    
    opts = Options()
    # [READ] The following is intentional [READ]
    # At the moment, having resistFingerprinting on and setting the useragent
    # override pref. causes useragent not to apply properly, feel free to test.
    opts.set_preference("privacy.resistFingerprinting", False)
    opts.set_preference("browser.safebrowsing.phishing.enabled", False)
    opts.set_preference("general.useragent.override", user_agent)

    driver = webdriver.Firefox(options = opts)
    driver.set_window_size(window_width, window_height)
    driver.set_page_load_timeout(60)
    
    need_abuse_lookup = main()
    driver.quit()
    
    #TODO make this into a standalone function - writeAbuseInfo(domain)
    #go through the urls and transform them into 'domain' form, store as set (no repeat entries)
    handleAbuse(need_abuse_lookup)
    packageResults()
