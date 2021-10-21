"""
By: InfoSecV9Y
Purpose:    This script is used to delete the cookie matched with reg_exp pattern from Burp Cookie Jar.
Pre-Conditions: This script needs to run as a Macro using Session Handling rules.
Version: 0.1
Last modified: 2021.Oct.14 11:26 PM
Known Bugs:

Pending Enhancements:
    *List of cookies can be added for more than one cookie items
    *Fetch the cookies from macro response and delete the remaining cookies with similar pattern on cookie jar

Updates:

Ref:
    This script source was from:
        Script Source:
            1.https://gist.github.com/ryan-wendel/ec69e77dcac6410f6535d6f9278eabf7
            2.https://github.com/HannahLaw-Portswigger/DeleteCookies
        Blog:   https://www.ryanwendel.com/2019/09/27/application-enumeration-tips-using-aquatone-and-burp-suite/


        Portswigger response:
            https://forum.portswigger.net/thread/macro-clear-cookie-jar-1ee87e563ac65
            https://forum.portswigger.net/thread/emptying-cookie-jar-with-new-session-15ed127d

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
    pattern = '__Host-*'
    #nuke_only_one_cookie = 1    #use this if you want to nuke the first matching pattern and then exit

    #
    # Define some cookie functions
    #
    def deleteCookie(self):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            #self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))
            #if cookie.getDomain() == domain and cookie.getName() == name:
            if re.match(self.pattern,cookie.getName()):
                cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_nuked)
                print("["+datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+"] Cookie '" + cookie.getName() + "' nuked for pattern: " + self.pattern)
                break    #Comment this if there are no duplicates or wish to nuke only one cookie

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

try:
    FixBurpExceptions()
except:
    pass