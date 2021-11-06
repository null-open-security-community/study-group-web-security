---
sidebar_position: 1
---

# Notes

(CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. With a little help of social engineering (such as sending a link via email or chat), an attacker may trick the users of a web application into executing actions of the attacker’s choosing. If the victim is a normal user, a successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application.

## Impact
In a successful CSRF attack, the attacker causes the victim user to carry out an action unintentionally. For example, this might be to change the email address on their account, to change their password, or to make a funds transfer. Depending on the nature of the action, the attacker might be able to gain full control over the user's account. If the compromised user has a privileged role within the application, then the attacker might be able to take full control of all the application's data and functionality.

## Why Do People Carry Out CSRF Attacks?

The motivations of CSRF attacks are either financially fuelled or intended to change key information within a user account or within an application or website.

For instance, in the examples of CSRF attacks that we are aware of, they have been used to carry out the below functions:

* Amend a user password or force a password reset
* Move money from a bank account
* Amend the delivery address for a purchase
* Utilise a Content Management System (CMS) to remove or add content to a website
* Upvote Answers, Follow or Like Social Media Accounts
* Exploitation of an administrative application
* Amend a content number or email on a user account
* Amend a cart or shopping basket online
* Alter firewall and router configuration

Categorization based on OWASP 2017 - Broken Access Control: Authorization

## Types/Patterns OF CSRF

* https://medium.com/@asfiyashaikh10/cross-site-request-forgery-csrf-8ce6f9ee0379

### SameSite Attribute : Paparazzi Attribute moment

* https://www.kevel.co/blog/chrome-samesite/

The SameSite attribute tells browsers when and how to fire cookies in first- or third-party situations. SameSite is used by a variety of browsers to identify whether or not to allow a cookie to be accessed.

* https://web.dev/samesite-cookies-explained/

Sure thing! Values for the SameSite attribute include 'strict', 'lax', or 'none':

* 'lax' enables only first-party cookies to be sent/accessed
* 'strict' is a subset of 'lax' and won’t fire if the incoming link is from an external site
* 'none' signals that the cookie data can be shared with third parties/external sites (for advertising, embedded content, etc)

## Steps

1. CSRF occurs when an attacker make a target's browser send an HTTP Request to another website.

2. Attack relies on the target being previously authenticated on the vulnerable website = Mean victim must be sign-in on target

3. So, the action is submitted and occurs without the target's knowledge.

4.If attack is successful, attacker can modify server side information and is even possible to achieve to account takeover.

## Background of the Attack

* CSRF attack take advantage of weakness in the process website use to Authenticate Requests.
* Authentication

### CSRF with GET Request
Useful Tag - `<img>`
Example - `<img src="https://www.bank.com/transfer?from=victim&to=attacker&amount=1000">`

### CSRF with POST Request 
Attacker will depend on the content of POST request rather then `<img>` tag here, `<iframe>` and `<form>` this tag then can be beneficial.

```html title="csrf-poc.html"
<iframe style="display:none" name="csrf-frame"></iframe>

<form method='POST' action='http://bank.com/transfer' target="csrf-frame" id="csrf-form">

<input type='hidden' name='from' value='Victim'>
<input type='hidden' name='to' value='Attacker'>
<input type='hidden' name='amount' value='500'>
<input type='submit' value='submit'>

</form>

<script>document.getElementById("csrf-form").submit()</script>
```

## Pointers
* When looking for CSRF vulnerabilities, look for GET request that can modify server-side data

* Remember website API’s endpoints and its web pages.

* Fool CORS Protection by changing the content-type header to application/x-www-form-url encoded, multipart/form-data, or text/plain.

## Add-Ons

### Bypasses

There are several ways to bypass Anti-CSRF Tokens such as: 
1. Remove Anti-CSRF Token
2. Spoof Anti-CSRF Token by Changing a few bits 
3. Using Same Anti-CSRF Token 
4. Weak Cryptography to generate Anti-CSRF Token 
5. Guessable Anti-CSRF Token 
6. Stealing Token with other attacks such as XSS. 
7. Converting POST Request to GET Request to bypass the CSRF Token Check.

## Resources

* https://www.bugbountytips.tech/category/csrf/
* https://portswigger.net/web-security/csrf
* https://owasp.org/www-community/attacks/csrf
* https://medium.com/@vbharad/2-fa-bypass-via-csrf-attack-8f2f6a6e3871
* https://medium.com/@asfiyashaikh10/cross-site-request-forgery-csrf-8ce6f9ee0379 
* https://vickieli.dev/csrf/csrf-updates/ (Detailed)
* https://hacktoryga.medium.com/one-click-for-victims-one-huge-leap-for-attackers-ff983eea520a (for demo examples).
* https://medium.com/bugbountywriteup/account-takeover-via-csrf-78add8c99526
* https://techsolutions.cc/security/complete-guide-csrf-xsrf/
* https://medium.com/@swapmaurya20/csrf-to-account-takeover-8d6638289f67
* https://medium.com/@armaanpathan/chain-the-vulnerabilities-and-take-your-report-impact-on-the-moon-csrf-to-html-injection-which-608fa6e74236
* https://medium.com/bugbountywriteup/account-takeover-via-csrf-78add8c99526
* https://medium.com/bugbountywriteup/lets-bypass-csrf-protection-password-confirmation-to-takeover-victim-accounts-d-4a21297847ff
* https://www.slideshare.net/mobile/0ang3el/neat-tricks-to-bypass-csrfprotection
* https://blog.reconless.com/samesite-by-default/
* https://tools.ietf.org/html/draft-west-cookie-incrementalism-00
* https://tipstrickshack.blogspot.com/2012/10/how-to-exploit-csfr-vulnerabilitycsrf.html
* https://hackerone.com/reports/127703
* https://hackerone.com/reports/111216/

## Contributor
* Simran Sankhala