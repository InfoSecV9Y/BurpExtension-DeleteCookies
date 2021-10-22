"""
By: InfoSecV9Y
Purpose:    This script is used to keep the cookies received in the Macros and then delete the blacklisted cookies(from new list) and old cookies from Burp Cookie Jar.
Pre-Conditions: This script needs to run as a Macro using Session Handling rules.
Version: 0.5
Last modified: 2021.Oct.22 06:00 PM
Known Bugs:
    0.5: Exceptions may arise if the "CUSTOMIZATION SECTION" is not handled properly
    0.4: No known bugs
    0.3: Only look for one macro (least macro) and not properly tested with actual simulation
    upto 0.2: re.IGNORECASE is not available

Pending Enhancements:

Updates:
    0.5:
        * Get the new cookies list from macro/session handling rule requests
        * Do not delete the old cookies based on 4 possible scenarios
        * Delete a new cookie if a scenario matched (Blacklist based approach)
        * Section markers provided for quick modification of the script to reduce the load and increase the performance
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
    # Define config variables. Sample values are provided in the comments for quick reference.
    #
    #---- CUSTOMIZATION SECTION [ 1 ] START ----
    cookie_name_to_ignore = []          # cookie_name_to_ignore = ['1P_JAR', 'NID']
    cookie_domain_to_ignore = []        # cookie_domain_to_ignore = ['fb.com', 'google.com']
    cookie_path_to_ignore = []          # cookie_path_to_ignore = ['/sign-in', '/path2']
    # Format for "cookies_BLACKLIST_to_NUKE" or "cookies_list_to_ignore" is [[Name, Domain, Path],[N,D,P],[N,D,P],]
    cookies_list_to_ignore = [[],[]]    # cookies_list_to_ignore = [['1P_JAR', 'google.com', '/'], ['MSISAuth.2.Second_cookie', '3dom1', '/test']]
    cookies_BLACKLIST_to_NUKE = [[], []]  # cookies_BLACKLIST_to_NUKE = [['1P_JAR', 'google.com', '/'], ['COOKIE_NAME', 'DOMAIN', 'PATH']]
    #---- CUSTOMIZATION SECTION [ 1 ] END ----

    # This section could be useful if you want to add few cookies for testing the extension. Part (1 of 2)
    # def createCookie(self, domain, name, value, path=None, expiration=None):
    #     cookie_to_be_created = Cookie(domain, name, value, path, expiration)
    #     self.callbacks.updateCookieJar(cookie_to_be_created)

    # Below function is to ignore the cookies received form the macro/sessionhandling and then remove the remaining cookies from cookie jar
    def deleteCookieFromMacro2(self, cookie_whitelist):
        cookies = self.callbacks.getCookieJarContents()
        string_with_whitelist = "2.Keep the following cookies and nuke the remaining: "

        # ---- CUSTOMIZATION SECTION [ 2.1 ] START ----
        try:
            string_with_whitelist += "\n\t * Delete new cookies from cookies_BLACKLIST_to_NUKE : " + str(self.cookies_BLACKLIST_to_NUKE)
        except Exception as e:
            pass
        # ---- CUSTOMIZATION SECTION [ 2.1 ] END ----

        string_with_whitelist += "\n\t * Ignore new cookies from macro's: " + str(cookie_whitelist)
        string_with_whitelist += "\n\t * Ignore the user provided custom whitelist scenarios (if any):"

        # ---- CUSTOMIZATION SECTION [ 2.2 ] START ----
        try:
            string_with_whitelist += "\n\t\t * cookie_name_to_ignore : " + str(self.cookie_name_to_ignore)
        except Exception as e:
            pass
        try:
            string_with_whitelist += "\n\t\t * cookie_domain_to_ignore : " + str(self.cookie_domain_to_ignore)
        except Exception as e:
            pass
        try:
            string_with_whitelist += "\n\t\t * cookie_path_to_ignore : " + str(self.cookie_path_to_ignore)
        except Exception as e:
            pass
        try:
            string_with_whitelist += "\n\t\t * cookies_list_to_ignore : " + str(self.cookies_list_to_ignore)
        except Exception as e:
            pass
        # ---- CUSTOMIZATION SECTION [ 2.2 ] END ----

        print(string_with_whitelist)
        for cookie in cookies:
            DELETE_THIS_COOKIE = True
            cookie_details_from_cookie_jar = [cookie.getName(), cookie.getDomain(), cookie.getPath()]

            print("  *Checking the cookie: '" + str(cookie_details_from_cookie_jar))
            if cookie_details_from_cookie_jar in cookie_whitelist:
                # Comment the following if there is no blacklisted cookies to be removed from the new list

                # ---- CUSTOMIZATION SECTION [ 3.1 ] START ----
                # print("     ** [WHITELISTED COOKIE] Macro cookie found: '" + str(
                #     cookie_details_from_cookie_jar) + "' in " + str(cookie_whitelist))
                # DELETE_THIS_COOKIE = False  # Don't nuke this cookie

                if cookie_details_from_cookie_jar in self.cookies_BLACKLIST_to_NUKE:
                    print("     ** [BLACK-LISTED COOKIE - NUKE] Macro cookie found: '" + str(
                        cookie_details_from_cookie_jar) + "' in " + str(self.cookies_BLACKLIST_to_NUKE))
                else:
                    print("     ** [WHITELISTED COOKIE] Macro cookie found: '" + str(
                        cookie_details_from_cookie_jar) + "' in " + str(cookie_whitelist))
                    DELETE_THIS_COOKIE = False  # Don't nuke this cookie
                # ---- CUSTOMIZATION SECTION [ 3.1 ] END ----

            # The below code is to ignore old cookies from being nuked. Approach based on: COOKIE NAME
            # ---- CUSTOMIZATION SECTION [ 3.2 ] START ----
            elif cookie.getName() in self.cookie_name_to_ignore:
                print("     ** [OLD COOKIE IGNORED] Old cookie found: '" + str(
                    cookie.getName()) + "'. Filter list(cookie_name_to_ignore): " + str(self.cookie_name_to_ignore))
                DELETE_THIS_COOKIE = False  # Don't nuke this cookie

            # The below code is to ignore old cookies from being nuked. Approach based on: COOKIE DOMAIN
            elif cookie.getDomain() in self.cookie_domain_to_ignore:
                print("     ** [OLD COOKIE IGNORED] Old cookie found: '" + str(
                    cookie.getDomain()) + "'. Filter list(cookie_domain_to_ignore): " + str(
                    self.cookie_domain_to_ignore))
                DELETE_THIS_COOKIE = False  # Don't nuke this cookie

            # The below code is to ignore old cookies from being nuked. Approach based on: COOKIE PATH
            elif cookie.getPath() in self.cookie_path_to_ignore:
                print("     ** [OLD COOKIE IGNORED] Old cookie found: '" + str(
                    cookie.getPath()) + "'. Filter list(cookie_path_to_ignore): " + str(self.cookie_path_to_ignore))
                DELETE_THIS_COOKIE = False  # Don't nuke this cookie

            # The below code is to ignore old cookies from being nuked. Approach based on: COOKIE[NAME && DOMAIN && PATH]
            elif cookie_details_from_cookie_jar in self.cookies_list_to_ignore:
                print("     ** [OLD COOKIE IGNORED] Old cookie found: '" + str(
                    cookie_details_from_cookie_jar) + "'. Filter list(cookies_list_to_ignore): " + str(
                    self.cookies_list_to_ignore))
                DELETE_THIS_COOKIE = False  # Don't nuke this cookie
            # ---- CUSTOMIZATION SECTION [ 3.2 ] END ----

            # Nuke the cookies which are not found on macro list
            if DELETE_THIS_COOKIE:
                self.callbacks.updateCookieJar(Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(),
                                                      cookie.getExpiration()))
                print("       ***Cookie nuked: " + str(cookie_details_from_cookie_jar))
        else:
            # Burp Extension execution completed. Going to exit.
            print("*** Cookies are deleted from Burp Suite Cookie Jar based on the provided scenarios. Task completed ***")

            # Following is a failed code. This code always retrieve the nuked cookies from Burp Cookie Jar
            # print("*Old cookies were deleted from Burp Suite Cookie Jar. ")
            # print("*Here is the summary: ")
            # print("\n\t *Latest cookies from macro's: '" + str(cookie_whitelist))
            # cookie_jar = []
            # for cookie in cookies:
            #     print("Cookie Name: '" + cookie.getName() + "' Cookie Value:'" + cookie.getValue() + "'")
            #     if cookie.getValue() != '':
            #         cookie_jar.append([cookie.getName(),cookie.getDomain(), cookie.getPath()])
            # print("\t *Latest cookies from Cookie jar: '" + str(cookie_jar))
            # print("******* Task completed *******")

    #
    # implement IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self.callbacks = callbacks

        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("V9Y - Keep only new cookies - Macro analysis")

        # register ourselves a Session Handling Action
        callbacks.registerSessionHandlingAction(self)

        # Used by the custom debugging tools
        # sys.stdout = callbacks.getStdout()
        print("\n\n----------[" + datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S") + "] DEBUG: V9Y - Keep only new cookies - Macro analysis - Enabled!\t----------\n")

        # This section could be useful if you want to add few cookies for testing the extension. Part (2 of 2)
        # self.createCookie("google.com", "Ignore_this_based_on_DOMAIN", "First_cookie")
        # self.createCookie(".google.com", "DELETE_this_based_on_DOMAIN", "First_cookie")
        # self.createCookie("dom2", ".AspNetCore.OpenIdConnect.Nonce.2.Second_cookie", "Second_cookie")
        # self.createCookie("2dom2xx2", "Ignore_this_based_on_PATH", "Third_cookie", "/sign-in")
        # self.createCookie("2dom2xx2", "DELETE_this_based_on_PATH", "Third_cookie", "sign-in")
        # self.createCookie("2dom2xx2", ".AspNetCore.Correlation.OpenIdConnect.4.Fourth_cookie", "Fourth_cookie")
        # self.createCookie("3dom1", "1P_JAR", "Ignore_this_based_on_NAME")
        # self.createCookie("3dom1", "1P_JAR1", "DELETE_this_based_on_NAME")
        # self.createCookie("3dom1", "MSISAuth.2.Second_cookie", "Ignore_this_based_on_ALL_FIELDS", "/test")
        # self.createCookie("3dom1", "MSISAuth.2.Second_cookie2", "DELETE_this_based_on_ALL_FIELDS", "/test")
        # self.createCookie("3dom1", "MSISAuth.3.Third_cookie", "Third_cookie")
        # self.createCookie("3dom1", "MSISAuth.4.Fourth_cookie", "Fourth_cookie")
        # self.createCookie(".google.com.sg", "1P_JARR", "2023-02-03-03")
        # self.createCookie(".google.com.sg", "NIDD", "511=4r23432d4t3456g5")
        return

    #
    # Implement ISessionHandlingAction
    #
    def getActionName(self):
        return "V9Y - Keep only new cookies - Macro analysis"

    def performAction(self, current_request, macro_items):
        cookie_whitelist = []  # This is to get the list of latest cookies retrieved from macros/session handling rules
        print("\n----------[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "]----------")

        if macro_items is None:
            print("1.The macro list is empty hence removing all matched cookies from cookie jar")
        else:
            print("1.Burp extension started. Looking for list of macros. Number of macros to process: " + str(
                len(macro_items)))
            for i in range(len(macro_items)):  # if len(macro_items) >= 0:
                print("  *Processing the macro with index: " + str(i))
                macro_response_info = None
                try:
                    macro_response_info = self.helpers.analyzeResponse(macro_items[i].getResponse())
                except Exception as e:
                    print(
                        "    **[EXCEPTION] Cookie enumeration ignore for this MACRO Request. Details: " + str(e))
                if macro_response_info is not None:  # If no exceptions
                    # To list all the headers and iterate one by one to
                    cookies = macro_response_info.getCookies()
                    print("    **Going to look for all cookies in the macro with index: " + str(i))

                    for cookie in cookies:
                        cookie_whitelist.append([str(cookie.getName()), str(cookie.getDomain()), str(cookie.getPath())])
                        print("      ***Whitelisting the entry: " + str(cookie_whitelist[-1]))
                    print("    **Cookie enumeration completed for all cookies in the macro with index: " + str(i))
            print("  *List of cookies whitelisted based on macro's are: " + str(cookie_whitelist))
        self.deleteCookieFromMacro2(cookie_whitelist)
        return


try:
    FixBurpExceptions()
except:
    pass
