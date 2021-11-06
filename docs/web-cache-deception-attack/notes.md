---
sidebar_position: 1
---
# Notes
_By Muffaddal Masalawala_

## Normal Scenario

* Website http://www.example.com is configured to go through a reverse proxy.
* A dynamic page (after authentication) that is stored on the server and returns personal content of users, such as http://www.example.com/home.php, will have to create it dynamically per user, since the data is different for each user. This kind of data, or at least its personalized parts, isn't cached.
* What's more reasonable and common to cache are static, public files: style sheets (css), scripts (js), text files (txt), images (png, bmp, gif), etc as these files usually don't contain any sensitive information.

![Reverse Proxy Working](https://miro.medium.com/max/625/0*YVcUk4-Qv7lb06L1.jpg)

:::note
* All static files that are meant to be public, are cached disregarding their HTTP caching headers.
* **Various static file extensions could be used to cache pages**: aif, aiff, au, avi, bin, bmp, cab, carb, cct, cdf, class, css, doc, dcr, dtd, gcf, gff, gif, grv, hdml, hqx, ico, ini, jpeg, jpg, js, mov, mp3, nc, pct, ppc, pws, swa, swf, txt, vbs, w32, wav, wbmp, wml, wmlc, wmls, wmlsc, xsd, zip

:::

## Attack Scenario

* A GET request to the URL http://www.example.com/home.php/non-existent.css is made
* Depending on its technology and configuration (the URL structure might need to be built slightly different for different servers), the server returns the content of http://www.example.com/home.php.
* The URL remains http://www.example.com/home.php/non-existent.css
* The HTTP headers will be the same as for accessing http://www.example.com/home.php directly: same caching headers and same content type (text/html, in this case)

### Detailed

1. Browser requests http://www.example.com/home.php/non-existent.css.
2. Server returns the content of http://www.example.com/home.php, most probably with HTTP caching headers that instruct to not cache this page.
3. The response goes through the proxy.
4. The proxy identifies that the file has a css extension.
5. Under the cache directory, the proxy creates a directory named home.php, and caches the imposter "CSS" file (non-existent.css) inside.
6. When next time a user requests non-existent.css file, reverse proxy will not send that request to the web server, instead, it will serve the user with the data that it had stored in its cache. Thus, the request for static data is not reaching the web server again.

## Exploit Scenario

* An attacker who lures a logged-on user to access http://www.example.com/home.php/logo.png will cause this page – containing the user's personal content – to be cached and thus publicly-accessible.
* It could get even worse, if the body of the response contains (for some reason) the session identifier, security answers or CSRF tokens.
* All the attacker has to do now is to access this page on his own and expose this data.

![Exploit Flow](https://1.bp.blogspot.com/-zDck8_k-E4Y/WLP6c7VCu-I/AAAAAAAAGcI/lHhHh8SgO5cEVQ3iRBCAVPvdd3Fe-YB8ACLcB/s640/Web_Cache_Manipulation.png)

## Impact

Video Reference: https://vimeo.com/249130093

## Conditions to check Web Cache Deception Attack

1. The victim must be authenticated while accessing the malicious URL
2. Web cache functionality is set for the web application to cache files by their extensions, disregarding any caching header.
3. When accessing a page like http://www.example.com/home.php/non-existent.css, the web server will return the content of "home.php" for that URL.

## Mitigation
1. Configure the cache mechanism to cache files only if their HTTP caching headers allow. That will solve the root cause of this issue.
2. Store all static files in a designated directory and cache only that directory.
3. If the cache component provides the option, configure it to cache files by their content type.
4. Configure the web server so that for pages such as http://www.example.com/home.php/non-existent.css, the web server doesn’t return the content of "home.php" with this URL. Instead, for example, the server should respond with a 404 or 302 response.

## Misc. Resources

* https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack-wp.pdf