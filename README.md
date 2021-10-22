# BurpExtension-DeleteCookies

This script is used to delete the cookie matched with cookie_name_list from Burp Cookie Jar.

**Purpose:** This script is designed to clear the unnecessary cookies from the Burp Suite Cookie Jar, especially when using macros for Auto-Login on the ADFS(Active Directory Federation Services) web portal pentest. 

The challenge I faced in my previous project was, whenever the session handling rule detected the session has been expired, the Burp suite macros will be executed to get the valid session. During this process, the ADFS server gives the required values as cookie name but not as cookie value. For example: **".AspNetCore.Correlation.OpenIdConnect.\*"** and **".AspNetCore.OpenIdConnect.Nonce.\*"**. Since the cookie name is different, the Burp cookie jar is not cleared for old cookies (no overwrite due to change in the cookie name itself) and sending old cookies along with new cookie as part of getting valid session, which makes the request suspecious and get rejected by the ADFS server.  



## **Burp Extension:** DeleteCookies_IgnoreMacroCookies v0.5
**Purpose:** To keep the following cookies and then delete the remaining cookies from the BurpSuite Cookie Jar: 

1. Delete new cookies(cookies received fon Session handling macros) is matches with predifined BLACKLIST

2. Ignore new cookies from macro's/session handling macros

3. Ignore the user provided custom whitelist scenarios:

   3.1. Cookie Name

   3.2  Cookie Domain

   3.3. Cookie Path

   3.4. Predefined cookie list with the format like [[Name, Domain, Path],[Name, Domain, Path],[Name, Domain, Path]]

### Terminology: 
**Old cookie:** Cookie that was already present in the Burp Suite Cookie Jar (before running the session handling macros)

**New Cookie:** Cookie recevied during the execusion of session handling macros. For example, the cookies received during the Auto-login automation using session handling rules. 


### Features: 
1. This script can work with or without any macros. Means that, if a session handling rules is cofigured without any macros, the script still work without any issue. This case is used when you wish to remove all the old cookies.

2. If the session handling macro doesn't have any response, then this extension doesn't exit due to exception. Instead, it proceed with analyzing new macro from the session handling rules list.

3. This is designed with the customization in mind. Means you can remove the new cookie or can keep the old cookie based on your convinience. A minimal version is also provided in this channel if you don't need any customization.

4. Detailed debug(print) statements are provided along with the timestamps for easy troubleshooting. You may save logs to file using "Burp Extender >> Burp Extension >> Output >> Save to file" and then open with the tools like snaketail for convinience. 

### Limitations: 
1. This script can only be used to run with Session Handling Rules (Burp >> Project Options >> Sessions >> Session handling Rules) and this is the purpose of writing this extension ;) 

### TO DO:
* Planning to provide the walkthough of installing the extension and testing the same 

* No other plans on enhancing this script (v0.5) further. Some other usecases were covered in previous versions. Any suggestions are welcome.

### Workflow:

1. Working with New cookies (to delete any new cookies if you dont want)

	1.1. collect the list of cookies from the session handling macros list
		
	1.2. Compare with *"cookies_BLACKLIST_to_NUKE"*. If any new cookie matches with the blacklist, the cookie will be nuked from cookie jar

2. Working with old cookies ( to keep the old cookies if you want)

	2.1. Ignore the cookie if the COOKIE NAME matches with *"cookie_name_to_ignore"* 
		
	2.2. Ignore the cookie if the COOKIE DOMAIN matches with *"cookie_domain_to_ignore"* 
		
	2.3 Ignore the cookie if the COOKIE PATH matches with *"cookie_path_to_ignore"* 
		
	2.4 Ignore the cookie if the COOKIE[NAME && DOMAIN && PATH] matches with *"cookies_list_to_ignore"* 
		
	2.5 If any old cookie in the cookie jar that doesn't match with the above 4 rules, it will be removed from Burp cookie jar.


### Note: 
A minimal version of this script is also uploaded into the git hub (look for the scripts ends with keywork *mini*). Which is useful if you don't want addition features like ignoring the old cookies. Since the code is less, it is advised to go with this version if you are concerned about the script performance.


### Usecase: 
To keep the latest cookies (means the cookies received through Burp Macro's during the session handling) and delete the remaining cookies from Cookie Jar. You may need to use this script while configuring the session handling rules with *"Rule Action: Check if session is invalid"* and run using *"After running the macro, invoke a Burp extension action handler."* option. 



## **Burp Extension:** DeleteCookies_from_list v0.4
**Purpose:** To delete the list of cookies from the BurpSuite Cookie Jar. This script can ignore the cookies retrieved on session handling rules/macros and remove the remaining cookies(or cookie name pattrens) from the list. You may need to modify the variable *cookie_name_list* for this purpose

**Usecase:** To delete the cookie based on given pattern and it has the ability to ignore the new cookies received on the session handling rules. You can use this script while configuring the session handling rules with *"Rule Action: Check if session is invalid"* and run using *"After running the macro, invoke a Burp extension action handler."* option.



## Burp Extension: DeleteCookies_regexp v0.2
**Purpose:** To delete the list of cookies from the BurpSuite Cookie Jar. This script will remove all the cookies from the cookie jar which match the Regular expression pattern. You may need to modify the variable *pattern* for this purpose

**Usecase:** To delete the cookie based on regular expression using session handling rules. Since this script doesn't have ability to compare the cookies from macro's or session handling rules, you can use this as an additional *"Rule Action"* just to remove the cookies when an "Invalid Session" detected. 



## **Burp Extension:** DeleteCookies-Nuke_All
**Purpose:** To delete all cookies from the BurpSuite Cookie Jar. This script will remove all the cookies from the cookie jar.

**Usecase:** To delete all cookies using session handling rules. This script is straight forwarded, hence, you can use this as an additional "Rule Action" just to remove the cookies when an "Invalid Session" detected. 



## **Burp Extension:** DeleteCookies-On_Load(dummy)
**Purpose:** To delete all cookies from the BurpSuite Cookie Jar when it is loaded. This is useless for my requirement. Just added for reference.


