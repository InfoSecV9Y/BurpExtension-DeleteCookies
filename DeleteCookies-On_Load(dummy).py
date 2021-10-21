"""
By: Burp Official Source with debug statements
Purpose:    This script is used to delete all the cookie when the extension is loaded. This is useless for running with session handling rules.
Version: NA
Last modified: NA
Known Bugs: NA
Pending Enhancements: A lot. Refer to other scripts in the same channel.
Updates: NA

Ref:
    https://forum.portswigger.net/thread/macro-clear-cookie-jar-1ee87e563ac65
    https://forum.portswigger.net/thread/emptying-cookie-jar-with-new-session-15ed127d
"""
from burp import IBurpExtender, ICookie
from java.io import PrintWriter
from exceptions_fix import FixBurpExceptions
import sys

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks( self, callbacks):
        extName = "Delete Cookies"
        # keep a reference to our callbacks object and add helpers
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        sys.stdout = callbacks.getStdout()
        # set our extension name
        callbacks.setExtensionName(extName)

        # obtain our output streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        cookies = self._callbacks.getCookieJarContents()
        for cookie in cookies:
            self._stdout.println("\n---------------------------\n1. Cookie: "+ cookie.getName())
            new_cookie = Cookie(cookie.getDomain(), cookie.getName(), None, cookie.getPath(), cookie.getExpiration())
            self._stdout.println("\n2.1 Before deleting the cookie -getDomain"+str(new_cookie.getDomain())+ " -getName "+str(new_cookie.getName())+ " -getPath "+str(new_cookie.getPath())+ " -getExpiration "+str(new_cookie.getExpiration()))
            self._callbacks.updateCookieJar(new_cookie)
            self._stdout.println("2.2 Cookie deleted!")

class Cookie(ICookie):
    def getDomain(self):
        print("\n4.1 self.cookie_domain: " + str(self.cookie_domain))
        return self.cookie_domain

    def getPath(self):
        print("4.2 self.cookie_path: " + str(self.cookie_path))
        return self.cookie_path

    def getExpiration(self):
        print("4.3 self.cookie_expiration: " + str(self.cookie_expiration))
        return self.cookie_expiration

    def getName(self):
        print("4.4 self.cookie_name: " + str(self.cookie_name))
        return self.cookie_name

    def getValue(self):
        print("4.5 self.cookie_value: " + str(self.cookie_value))
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        print("\n3.0 Cookie(ICookie) -> __init__: ")
        print("3.0.1 cookie_domain: " + str(cookie_domain))
        print("3.0.2 cookie_path: " + str(cookie_path))
        print("3.0.3 cookie_expiration: " + str(cookie_expiration))
        print("3.0.4 cookie_name: " + str(cookie_name))
        print("3.0.5 cookie_value: " + str(cookie_value))
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration
        print("\n3.1 self.cookie_domain: " + str(self.cookie_domain))
        print("3.2 self.cookie_path: " + str(self.cookie_path))
        print("3.3 self.cookie_expiration: " + str(self.cookie_expiration))
        print("3.4 self.cookie_name: " + str(self.cookie_name))
        print("3.5 self.cookie_value: " + str(self.cookie_value))

FixBurpExceptions()