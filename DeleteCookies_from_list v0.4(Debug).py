"""
By: InfoSecV9Y
Purpose:    This script is used to delete the cookie matched with cookie_name_list from Burp Cookie Jar.
Pre-Conditions: This script needs to run as a Macro using Session Handling rules.
Version: 0.4
Last modified: 2021.Oct.21 04:00 PM
Known Bugs:
    0.3: Only look for one macro (least macro) and not properly tested with actual simulation
    upto 0.2: re.IGNORECASE is not available

Pending Enhancements:
    *Fetch the whitelisted cookies from macro/session handling rule requests

Updates:
    0.4: Deleting the known cookies except the latest cookies from the macro / session handling rules (not limited to last)
    0.3: Deleting the known cookies except the latest cookies from the last (one) macro / session handling rules (optimising)
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
# import sys

# Burp specific imports
from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import ICookie
from java.lang import Exception
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
    # cookieName = 'jwt'
    # cookieDomain = 'dummy.com'
    # pattern = [".AspNetCore.Correlation.OpenIdConnect*", ".AspNetCore.OpenIdConnect.Nonce*"]  # ['__Host-*', 'NID*']
    # combined = "(" + ")|(".join(pattern) + ")"  # Make a regex that matches if any of our regexes match.

    cookie_name_list = ['.AspNetCore.Correlation.OpenIdConnect', '.AspNetCore.OpenIdConnect.Nonce.', 'NID', '1P_JAR']
    # domain_list_to_consider = ['\\', '\\temp']
    # domain_list_to_ignore = ['\\', '\\temp']


    #
    # Define some cookie functions
    #
    # Below function is to remove all matched cookies from cookie jar based on RegEx
    # def deleteCookie(self):
    #     cookies = self.callbacks.getCookieJarContents()
    #     for cookie in cookies:
    #         # self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))
    #         # if cookie.getDomain() == domain and cookie.getName() == name:
    #         if re.match(self.combined, cookie.getName(), re.IGNORECASE):
    #             cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(),
    #                                         cookie.getExpiration())
    #             self.callbacks.updateCookieJar(cookie_to_be_nuked)
    #             print("[" + datetime.datetime.now().strftime(
    #                 "%Y-%m-%d %H:%M:%S") + "] Cookie '" + cookie.getName() + "' nuked for pattern: " + self.combined)

    # def createCookie(self, domain, name, value, path=None, expiration=None):
    #     cookie_to_be_created = Cookie(domain, name, value, path, expiration)
    #     self.callbacks.updateCookieJar(cookie_to_be_created)

    # Below function is to remove the matched cookies from cookie jar while ignore the cookies received form the macro/sessionhandling
    def deleteCookieFromMacro(self, cookie_whitelist):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:

            # use the following condition to skip the validations based on cookie domain name

            # if cookie.getDomain() not in self.domain_list_to_consider:          #   Whitelist to analyze
            # if cookie.getDomain() in self.domain_list_to_ignore:  # Blacklist to ignore
            #     continue

            for cookie_name_list in self.cookie_name_list:
                print(
                    "  8.Checking the cookie: '" + cookie.getName() + "' against the cookie_name_list: " + cookie_name_list)
                if cookie_name_list in cookie.getName():
                    # Cookie present in the Burp Cookie Jar
                    if cookie.getName() not in cookie_whitelist:
                        cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(),
                                                    cookie.getExpiration())
                        self.callbacks.updateCookieJar(cookie_to_be_nuked)
                        print("   9.1.Cookie nuked: " + cookie.getName())
                        # print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] Cookie nuked: " + cookie.getName())

                    else:
                        print(
                            "   9.2.Cookie is newly received in session handling rules, hence ignored: " + cookie.getName())
                        # for whitelisted_cookie in cookie_whitelist:
                        # self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue()))
                        # if cookie.getDomain() == domain and cookie.getName() == name:
                        # if cookie.getName() != whitelisted_cookie:

                        # Below code is to match based on RegEx
                        # if re.match(self.combined, cookie.getName(), re.IGNORECASE):
                        #     cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(),
                        #                                 cookie.getExpiration())
                        #     print("[" + datetime.datetime.now().strftime(
                        #         "%Y-%m-%d %H:%M:%S") + "] Cookie '" + cookie.getName() + "' nuked for pattern: " + self.combined)
                    break
        else:
            print("  10.Repeated cookies were deleted from Burp Suite Cookie Jar. Task completed.\n")

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
        # sys.stdout = callbacks.getStdout()
        print("\n\n----------[" + datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S") + "] DEBUG: V9Y - Remove matched cookies - Macro analysis - Enabled!\t----------\n")
        # set few cookies for testing (Kind of test data)
        # self.createCookie("dom1", ".AspNetCore.OpenIdConnect.Nonce.1.First_cookie", "First_cookie")
        # self.createCookie("dom1", ".AspNetCore.OpenIdConnect.Nonce.2.Second_cookie", "Second_cookie")
        # self.createCookie("dom1", ".AspNetCore.OpenIdConnect.Nonce.3.Third_cookie", "Third_cookie")
        # self.createCookie("dom1", ".AspNetCore.OpenIdConnect.Nonce.4.Fourth_cookie", "Fourth_cookie")
        # self.createCookie("2dom2xx2", ".AspNetCore.Correlation.OpenIdConnect.1.First_cookie", "First_cookie")
        # self.createCookie("2dom2xx2", ".AspNetCore.Correlation.OpenIdConnect.2.Second_cookie", "Second_cookie")
        # self.createCookie("2dom2xx2", ".AspNetCore.Correlation.OpenIdConnect.3.Third_cookie", "Third_cookie")
        # self.createCookie("2dom2xx2", ".AspNetCore.Correlation.OpenIdConnect.4.Fourth_cookie", "Fourth_cookie")
        # self.createCookie("3dom1", "MSISAuth.1.First_cookie", "First_cookie")
        # self.createCookie("3dom1", "MSISAuth.2.Second_cookie", "Second_cookie")
        # self.createCookie("3dom1", "MSISAuth.3.Third_cookie", "Third_cookie")
        # self.createCookie("3dom1", "MSISAuth.4.Fourth_cookie", "Fourth_cookie")
        # self.createCookie(".google.com", "1P_JAR_First_cookie", "2021-10-21-03")
        # self.createCookie(".google.com", "NID_First_cookie", "511=eS2cdwQ8dKA_N5KI5MhKUCUy3Kk")
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
        print("\n----------[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "]----------")

        # Checking if Macro list is empty or not.       #print("Data type of macro_items is: " + str(type(macro_items)))
        if macro_items is None:
            print("*The macro list is empty hence removing all matched cookies from cookie jar")
        else:
            print("1.Burp extension started. Looking for list of macros. Number of macros to process: " + str(
                len(macro_items)))
            for i in range(len(macro_items)):  # if len(macro_items) >= 0:
                print("  2.Processing the macro with index: " + str(i))
                macro_response_info = None
                try:
                    macro_response_info = self.helpers.analyzeResponse(macro_items[i].getResponse())
                except Exception as e:
                    print(
                        "  Exception Raised: " + str(e) + "\t Value of macro_response_info:" + str(macro_response_info))
                    pass
                if macro_response_info is None:  # looks like exception raised
                    print("    Looks like we got exception. Skipping the remaining execution for this request")
                else:
                    # To list all the headers and iterate one by one
                    cookies = macro_response_info.getCookies()
                    head_delete = ''
                    print("    3.Going to look for all cookies in the macro with index: " + str(i))

                    for cookie in cookies:
                        print("      4.Cookie is: " + str(cookie.getName()))
                        for cookie_name in self.cookie_name_list:
                            if cookie_name in str(cookie.getName()):
                                print("        5.Cookie name '" + cookie_name + "' found in received cookie '" + str(
                                    cookie.getName()) + "'. Adding this cookie to the white list")
                                cookie_whitelist.append(str(cookie.getName()))
                                # head_delete = cookie
                    print("    6.Cookie enumeration completed for all cookies in the macro with index: " + str(i))
            print("7.List of cookies whitelisted based on macro's are: " + str(cookie_whitelist))
        self.deleteCookieFromMacro(cookie_whitelist)
        return


try:
    FixBurpExceptions()
except:
    pass
