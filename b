Insecure cookie setting: missing Secure flag
Confirmed

URL
    https://www.inflectra.com/
Cookie Name
    ASP.NET_SessionId, __AntiXsrfToken
Evidence
    Set-Cookie: ASP.NET_SessionId=xknujmquxvlwq3adgy4tnfah Set-Cookie: __AntiXsrfToken=0202bfaba04f46988d69f401e1a4ac27 

Vulnerability description
    We found that a cookie has been set without the Secure flag, which means the browser will send it over an unencrypted channel (plain HTTP) if such a request is made. The root cause for this usually revolves around misconfigurations in the code or server settings.
Risk description
    The risk exists that an attacker will intercept the clear-text communication between the browser and the server and he will steal the cookie of the user. If this is a session cookie, the attacker could gain unauthorized access to the victim's web session.
Recommendation
    Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.

Robots.txt file found
Confirmed

URL
    https://www.inflectra.com/robots.txt

Vulnerability description
    We found the robots.txt on the target server. This file instructs web crawlers what URLs and endpoints of the web application they can visit and crawl. Website administrators often misuse this file while attempting to hide some web pages from the users.
Risk description
    There is no particular security risk in having a robots.txt file. However, it's important to note that adding endpoints in it should not be considered a security measure, as this file can be directly accessed and read by anyone.
Recommendation
    We recommend you to manually review the entries from robots.txt and remove the ones which lead to sensitive locations in the website (ex. administration panels, configuration files, etc).

Server software and technology found
	
Google Analytics	Analytics
Google Tag Manager	Tag managers
core-js 3.26.1	JavaScript libraries
Open Graph	Miscellaneous
PWA	Miscellaneous
ActiveCampaign	Marketing automation, Email
Microsoft ASP.NET	Web frameworks
RSS	Miscellaneous

Vulnerability description
    We noticed that server software and technology details are exposed, potentially aiding attackers in tailoring specific exploits against identified systems and versions.
Risk description
    The risk is that an attacker could use this information to mount specific attacks against the identified software type and version.
Recommendation
    We recommend you to eliminate the information which permits the identification of software platform, technology, server and operating system: HTTP server headers, HTML meta information, etc.

Missing security header: Strict-Transport-Security
Confirmed

URL
    https://www.inflectra.com/
Evidence
    Response headers do not include the HTTP Strict-Transport-Security header 

Vulnerability description
    We noticed that the target application lacks the HTTP Strict-Transport-Security header in its responses. This security header is crucial as it instructs browsers to only establish secure (HTTPS) connections with the web server and reject any HTTP connections.
Risk description
    The risk is that lack of this header permits an attacker to force a victim user to initiate a clear-text HTTP connection to the server, thus opening the possibility to eavesdrop on the network traffic and extract sensitive information (e.g. session cookies).
Recommendation
    The Strict-Transport-Security HTTP header should be sent with each HTTPS response. The syntax is as follows: `Strict-Transport-Security: max-age=<seconds>[; includeSubDomains]` The parameter `max-age` gives the time frame for requirement of HTTPS in seconds and should be chosen quite high, e.g. several months. A value below 7776000 is considered as too low by this scanner check. The flag `includeSubDomains` defines that the policy applies also for sub domains of the sender of the response.

Missing security header: Referrer-Policy
Confirmed

URL
    https://www.inflectra.com/
Evidence
    Response headers do not include the Referrer-Policy HTTP security header as well as the <meta> tag with name 'referrer' is not present in the response. 

Vulnerability description
    We noticed that the target application's server responses lack the Referrer-Policy HTTP header, which controls how much referrer information the browser will send with each request originated from the current web application.
Risk description
    The risk is that if a user visits a web page (e.g. "http://example.com/pricing/") and clicks on a link from that page going to e.g. "https://www.google.com", the browser will send to Google the full originating URL in the `Referer` header, assuming the Referrer-Policy header is not set. The originating URL could be considered sensitive information and it could be used for user tracking.
Recommendation
    The Referrer-Policy header should be configured on the server side to avoid user tracking and inadvertent information leakage. The value `no-referrer` of this header instructs the browser to omit the Referer header entirely.

Missing security header: Content-Security-Policy
Confirmed

URL
    https://www.inflectra.com/
Evidence
    Response does not include the HTTP Content-Security-Policy security header or meta tag 

Vulnerability description
    We noticed that the target application lacks the Content-Security-Policy (CSP) header in its HTTP responses. The CSP header is a security measure that instructs web browsers to enforce specific security rules, effectively preventing the exploitation of Cross-Site Scripting (XSS) vulnerabilities.
Risk description
    The risk is that if the target application is vulnerable to XSS, lack of this header makes it easily exploitable by attackers.
Recommendation
    Configure the Content-Security-Header to be sent with each HTTP response in order to apply the specific policies needed by the application.

Missing security header: X-Content-Type-Options
Confirmed

URL
    https://www.inflectra.com/
Evidence
    Response headers do not include the X-Content-Type-Options HTTP security header 

Vulnerability description
    We noticed that the target application's server responses lack the X-Content-Type-Options header. This header is particularly important for preventing Internet Explorer from reinterpreting the content of a web page (MIME-sniffing) and thus overriding the value of the Content-Type header.
Risk description
    The risk is that lack of this header could make possible attacks such as Cross-Site Scripting or phishing in Internet Explorer browsers.
Recommendation
    We recommend setting the X-Content-Type-Options header such as `X-Content-Type-Options: nosniff`.

Nothing was found for unsafe HTTP header Content Security Policy.
Nothing was found for HttpOnly flag of cookie.
Nothing was found for domain too loose set for cookies.
Nothing was found for directory listing.
Nothing was found for secure communication.
HTTP OPTIONS enabled
Confirmed

URL
    https://www.inflectra.com/
Method
    OPTIONS
Summary
    We did a HTTP OPTIONS request. The server responded with a 405 status code and the header: `Allow: GET, HEAD, OPTIONS, TRACE` 

Vulnerability description
    We have noticed that the webserver responded with an Allow HTTP header when an OPTIONS HTTP request was sent. This method responds to requests by providing information about the methods available for the target resource.
Risk description
    The only risk this might present nowadays is revealing debug HTTP methods that can be used on the server. This can present a danger if any of those methods can lead to sensitive information, like authentication information, secret keys.
Recommendation
    We recommend that you check for unused HTTP methods or even better, disable the OPTIONS method. This can be done using your webserver configuration.

Nothing was found for enabled HTTP debug methods.
Nothing was found for use of untrusted certificates.
Security.txt file is missing
Confirmed

URL
    Missing: https://www.inflectra.com/.well-known/security.txt

Vulnerability description
    We have noticed that the server is missing the security.txt file, which is considered a good practice for web security. It provides a standardized way for security researchers and the public to report security vulnerabilities or concerns by outlining the preferred method of contact and reporting procedures.
Risk description
    There is no particular risk in not having a security.txt file for your server. However, this file is important because it offers a designated channel for reporting vulnerabilities and security issues.
Recommendation
    We recommend you to implement the security.txt file according to the standard, in order to allow researchers or users report any security issues they find, improving the defensive mechanisms of your server.

Nothing was found for client access policies.
Nothing was found for vulnerabilities of server-side software.
Website is accessible.
