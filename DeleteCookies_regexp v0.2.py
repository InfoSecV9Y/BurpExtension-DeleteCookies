"""
By: InfoSecV9Y
Purpose:    This script is used to delete the cookie matched with reg_exp pattern from Burp Cookie Jar.
Pre-Conditions: This script needs to run as a Macro using Session Handling rules.
Version: 0.2
Last modified: 2021.Oct.15 12:26 AM
Known Bugs:

Pending Enhancements:
    *Fetch the cookies from macro response and delete the remaining cookies with similar pattern on cookie jar

Updates:
0.2: Multiple regex patterns can be added
0.1: Pattern based cookie will be removed for only one pattern at a time

Ref:
    This script source was from:
        Script Source:
            1.https://gist.github.com/ryan-wendel/ec69e77dcac6410f6535d6f9278eabf7
            2.https://github.com/HannahLaw-Portswigger/DeleteCookies
        Blog:   https://www.ryanwendel.com/2019/09/27/application-enumeration-tips-using-aquatone-and-burp-suite/


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

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
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
    pattern = ['__Host-*','NID*']
    combined = "(" + ")|(".join(pattern) + ")"    # Make a regex that matches if any of our regexes match.

    #
    # Define some cookie functions
    #
    def deleteCookie(self):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            #self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))
            #if cookie.getDomain() == domain and cookie.getName() == name:
            if re.match(self.combined,cookie.getName()):
                cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_nuked)
                print("["+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Cookie '" + cookie.getName() + "' nuked for pattern: " + self.combined)

    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self.callbacks = callbacks

        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("V9Y - Remove matched cookies")

        # register ourselves a Session Handling Action
        callbacks.registerSessionHandlingAction(self)

        # Used by the custom debugging tools
        sys.stdout = callbacks.getStdout()

        print("DEBUG: V9Y - Remove matched cookies - Enabled!")

        return

    #
    # Implement ISessionHandlingAction
    #
    def getActionName(self):
        return "V9Y - Remove matched cookies"

    def performAction(self, current_request, macro_items):

        self.deleteCookie()
        return

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