"""
By: InfoSecV9Y
Purpose:    This script is used to delete the cookie matched with reg_exp pattern from Burp Cookie Jar.
Pre-Conditions: This script needs to run as a Macro using Session Handling rules.
Version: 0.3
Last modified: 2021.Oct.18 08:00 PM
Known Bugs:
Upto 0.2: re.IGNORECASE is not available

Pending Enhancements:

Updates:
0.3: Trying to ignore deleting the previous cookie from macro (optimising)
0.2: Multiple regex patterns can be added
0.1: Pattern based cookie will be removed for only one pattern at a time

Ref:
    This script source was from:
        Script Source:
            1.https://gist.github.com/ryan-wendel/ec69e77dcac6410f6535d6f9278eabf7
            2.https://github.com/HannahLaw-Portswigger/DeleteCookies
            Blog:   https://www.ryanwendel.com/2019/09/27/application-enumeration-tips-using-aquatone-and-burp-suite/
            3.https://github.com/justm0rph3u5/BurpSuite-CustomHeader
            Blog: https://justm0rph3u5.medium.com/automating-burp-suite-4-understanding-and-customising-custom-header-from-response-via-burp-macro-214332dda012


        Portswigger response:
            https://forum.portswigger.net/thread/macro-clear-cookie-jar-1ee87e563ac65
            https://forum.portswigger.net/thread/emptying-cookie-jar-with-new-session-15ed127d

        Combining regexp patterns: https://stackoverflow.com/questions/3040716/python-elegant-way-to-check-if-at-least-one-regex-in-list-matches-a-string/47017995
"""
# python imports
import re
import sys

# Burp specific imports
from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import ICookie
import datetime

# For using the debugging tools from
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class Cookie(ICookie):

    def getDomain(self):
        return self.cookie_domain

    def getPath(self):
        return self.cookie_path

    def getExpiration(self):
        return self.cookie_expiration

    def getName(self):
        return self.cookie_name

    def getValue(self):
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None,
                 cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration


class BurpExtender(IBurpExtender, ISessionHandlingAction):
    #
    # Define config and gui variables
    #
    cookieName = 'jwt'
    cookieDomain = 'dummy.com'
    pattern = [".AspNetCore.Correlation.OpenIdConnect*",".AspNetCore.OpenIdConnect.Nonce*"] #['__Host-*', 'NID*']
    cookie_name_list = ['.AspNetCore.Correlation.OpenIdConnect', '.AspNetCore.OpenIdConnect.Nonce.']
    domain_list_to_consider = ['\\', '\\temp']
    domain_list_to_ignore = ['\\', '\\temp']

    combined = "(" + ")|(".join(pattern) + ")"  # Make a regex that matches if any of our regexes match.

    #
    # Define some cookie functions
    #
    # Below function is to remove all matched cookies from cookie jar based on RegEx
    def deleteCookie(self):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            # self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))
            # if cookie.getDomain() == domain and cookie.getName() == name:
            if re.match(self.combined, cookie.getName(), re.IGNORECASE):
                cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(),
                                            cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_nuked)
                print("[" + datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S") + "] Cookie '" + cookie.getName() + "' nuked for pattern: " + self.combined)

    # Below function is to remove the matched cookies from cookie jar while ignore the cookies received form the macro/sessionhandling
    def deleteCookieFromMacro(self, cookie_whitelist):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:

            #use the following condition to skip the validations based on cookie domain name

            #if cookie.getDomain() not in domain_list_to_consider:          #   Whitelist to scan
            if cookie.getDomain() in domain_list_to_ignore:                 #   Blacklist to ignore
                continue

            for cookie_name_list in self.cookie_name_list:
                print("7.Cookie Name: " + cookie.getName() + "\t cookie_name_list: "+cookie_name_list)
                if cookie_name_list in cookie.getName():
                    #Cookie present in the Burp Cookie Jar
                    if  cookie.getName() not in cookie_whitelist:
                        cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(),
                                                    cookie.getExpiration())
                        self.callbacks.updateCookieJar(cookie_to_be_nuked)
                        print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] Cookie nuked: " + cookie.getName())

                    else:
                        print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] Whitelisted cookie detected: " + cookie.getName())
                        #for whitelisted_cookie in cookie_whitelist:
                        # self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))
                        # if cookie.getDomain() == domain and cookie.getName() == name:
                        #if cookie.getName() != whitelisted_cookie:


                        # Below code is to match based on RegEx
                        # if re.match(self.combined, cookie.getName(), re.IGNORECASE):
                        #     cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(),
                        #                                 cookie.getExpiration())
                        #     print("[" + datetime.datetime.now().strftime(
                        #         "%Y-%m-%d %H:%M:%S") + "] Cookie '" + cookie.getName() + "' nuked for pattern: " + self.combined)


    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self.callbacks = callbacks

        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("V9Y - Remove matched cookies - Macro analysis")

        # register ourselves a Session Handling Action
        callbacks.registerSessionHandlingAction(self)

        # Used by the custom debugging tools
        sys.stdout = callbacks.getStdout()

        print("DEBUG: V9Y - V9Y - Remove matched cookies - Macro analysis - Enabled!")

        return

    #
    # Implement ISessionHandlingAction
    #
    def getActionName(self):
        return "V9Y - Remove matched cookies - Macro analysis"

    def performAction(self, current_request, macro_items):

        # self.deleteCookie()
        # return
        cookie_whitelist = []  # This is to get the list of latest cookies retrieved from macros/session handling rules
        print("1.Looking for list of macros ")
        if len(macro_items) >= 0:
            print("2.Macro list is >= 0 \t\t len(macro_items) >= 0")
            macro_response_info = self.helpers.analyzeResponse(macro_items[0].getResponse())
            # get the list of headers from the response, if token is present in the response header then we need to list all the header and extract the value
            macro_body_offset = macro_response_info.getHeaders()

            # from the macro body(which contains the response headers), we are extracting dynamic value of the header
            new_header = macro_body_offset.get(1)[14:]

            # To list all the headers and iterate one by one to
            headers = macro_response_info.getCookies()
            head_delete = ''
            print("3.Going to look for all cookies")

            for header in headers:
                print("4.Cookie is: " + str(header.getName()))
                for cookie_name in self.cookie_name_list:
                    if cookie_name in str(header.getName()):
                        print("5.Value found:" + cookie_name + ". Adding this cookie to the white list")
                        cookie_whitelist.append(str(header.getName()))
                        # head_delete = header
            print("6.Cookie enumeration completed. Going to nuke the cookie from cookie jar")
        else:
            print("The macro list is empty hence removing all matched cookies from cookie jar")

        self.deleteCookieFromMacro(cookie_whitelist)


        return
        # Below is the actual code and above is the custom code
        if len(macro_items) >= 0:
            # grab some stuff from the current request
            req_text = self.helpers.bytesToString(current_request.getRequest())

            current_macro = macro_items[0]
            macro_resp = current_macro.getResponse()
            macro_resp_info = self.helpers.analyzeResponse(macro_resp)

            # parse the response & search for jwt
            if macro_resp:
                macro_resp_body = macro_resp[macro_resp_info.getBodyOffset():]
                macro_resp_text = self.helpers.bytesToString(macro_resp_body)
                search_re = '"%s":"(.*?)"' % self.cookieName
                search = re.search(search_re, macro_resp_text, re.IGNORECASE)

                # we have a jwt in the macro response
                if search:
                    jwt = search.group(1)

                    # set the cookie value in the cookie jar
                    self.createCookie(self.cookieDomain, self.cookieName, jwt)

                    # replace the old token with the stored value
                    header_replace = "%s: %s" % (self.cookieName, jwt)
                    req_text = re.sub(r"\r\n" + self.cookieName + ": .*\r\n", "\r\n" + header_replace + "\r\n",
                                      req_text)

                    # set the current request
                    current_request.setRequest(self.helpers.stringToBytes(req_text))


try:
    FixBurpExceptions()
except:
    pass
