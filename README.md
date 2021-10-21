# BurpExtension-DeleteCookies

This script is used to delete the cookie matched with cookie_name_list from Burp Cookie Jar.

**Purpose:** This script is designed to clear the unnecessary cookies from the Burp Suite Cookie Jar, especially when using macros for Auto-Login on the ADFS(Active Directory Federation Services) web portal pentest. 

The challenge I faced in my previous project was, whenever the session handling rule detected the session has been expired, the Burp suite macros will be executed to get the valid session. During this process, the ADFS server gives the required values as cookie name but not as cookie value. For example: **".AspNetCore.Correlation.OpenIdConnect.\*"** and **".AspNetCore.OpenIdConnect.Nonce.\*"**. Since the cookie name is different, the Burp cookie jar is not cleared for old cookies (no overwrite due to change in the cookie name itself) and sending old cookies along with new cookie as part of getting valid session, which makes the request suspecious and get rejected by the ADFS server.  


#### **Burp Extension:** DeleteCookies_from_list v0.4
**Purpose:** To delete the list of cookies from the BurpSuite Cookie Jar. This script can ignore the cookies retrieved on session handling rules/macros and remove the remaining cookies(or cookie name pattrens) from the list. You may need to modify the variable cookie_name_list for this purpose

**Usecase:** To delete the cookie based on given pattern and it has the ability to ignore the new cookies received on the session handling rules. You can use this script on "Check if session is invalid" rule actions and run using "After running the macro, invoke a Burp extension action handler." option. 

#### Burp Extension: DeleteCookies_regexp v0.2
**Purpose:** To delete the list of cookies from the BurpSuite Cookie Jar. This script will remove all the cookies from the cookie jar which match the Regular expression pattern. You may need to modify the variable cookie_name_list for this purpose

**Usecase:** To delete the cookie based on regular expression using session handling rules. Since this script doesn't have ability to compare the cookies from macro's or session handling rules, you can use this as an additional "Rule Action" just to remove the cookies when an "Invalid Session" detected. 


#### **Burp Extension:** DeleteCookies-Nuke_All
**Purpose:** To delete all cookies from the BurpSuite Cookie Jar. This script will remove all the cookies from the cookie jar.

**Usecase:** To delete all cookies using session handling rules. This script is straight forwarded, hence, you can use this as an additional "Rule Action" just to remove the cookies when an "Invalid Session" detected. 


#### **Burp Extension:** DeleteCookies-On_Load(dummy)
**Purpose:** To delete all cookies from the BurpSuite Cookie Jar when it is loaded. This is useless for my requirement. Just added for reference.


