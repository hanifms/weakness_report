# weakness_report
group assignment (HAI)

## Table of Contents for Link 1
1. [Executive Summary](#link-1-executive-summary)
2. [Summary of findings](#link-1-summary-of-findings)
3. [Detailed Findings](#link-1-detailed-findings)
    - [1. Failure to Define Directive with no Fallback](#link-1-1-failure-to-define-directive-with-no-fallback)
    - [3. Wildcard Directive](#link-1-3-wildcard-directive)
    - [5. script-src unsafe-inline](#link-1-5-script-src-unsafe-inline)
    - [4. style-src unsafe-inline](#link-1-4-style-src-unsafe-inline)
    - [6. Cross-Domain Misconfiguration](#link-1-6-cross-domain-misconfiguration)
    - [8. HTTP to HTTPS Insecure Transition in Form Post](#link-1-8-http-to-https-insecure-transition-in-form-post)
    - [10. Strict-Transport-Security Header Not Set](#link-1-10-strict-transport-security-header-not-set)
    - [12. Big Redirect Detected (Potential Sensitive Information Leak)](#link-1-12-big-redirect-detected-potential-sensitive-information-leak)
    - [11. Cookie Without Secure Flag](#link-1-11-cookie-without-secure-flag)
    - [12. Cookie No HTTPOnly Flag](#link-1-12-cookie-no-httponly-flag)
    - [13. Cookie without SameSite Attribute](#link-1-13-cookie-without-samesite-attribute)
    - [14. Cross-Domain JavaScript Source File Inclusion](#link-1-14-cross-domain-javascript-source-file-inclusion)
    - [15. Authentication Request Identified](#link-1-15-authentication-request-identified)

## Table of Contents for Link 2
1. [Executive Summary](#link-2-executive-summary)
2. [Summary of findings](#link-2-summary-of-findings)
3. [Detailed Findings](#link-2-detailed-findings)
    - [1. Server Version Disclosure](#link-2-1-server-version-disclosure)
    - [2. Absence of Anti‑CSRF Tokens](#link-2-2-absence-of-anti‑csrf-tokens)
    - [3. Content Security Policy (CSP) Header Not Set](#link-2-3-content-security-policy-csp-header-not-set)
    - [4. Subresource Integrity Missing](#link-2-4-subresource-integrity-missing)
    - [5. Vulnerable JS Libraries](#link-2-5-vulnerable-js-libraries)
    - [6. Cookies Without Secure Flags](#link-2-6-cookies-without-secure-flags)
    - [7. Missing Permissions Policy Header](#link-2-7-missing-permissions-policy-header)
    - [8. Missing Cross‑Origin Resource Policy](#link-2-8-missing-cross‑origin-resource-policy)
    - [9. Information Disclosure via JS Comments](#link-2-9-information-disclosure-via-js-comments)
    - [10. HTTPS/TLS Not Enforced](#link-2-10-httpstls-not-enforced)
4. [Recommendations & Next Steps](#link-2-recommendations--next-steps)
5. [Appendix](#link-2-appendix)

<a name="link-1-executive-summary"></a>
## Link 1 (http://ezpay.iium.edu.my)

<a name="link-1-summary-of-findings"></a>
### 1. Executive Summary

| Metric                        | Value   |
| ----------------------------- | ------- |
| Total Issues Identified       | 20      |
| Critical Issues               | 0       |
| High-Risk Issues              | 0       |
| Medium-Risk Issues            | 6       |
| Low-Risk/Informational Issues | 14      |
| Remediation Status            | Pending |

<a name="link-1-detailed-findings"></a>
### 2. Summary of findings

| Risk Level | Number of Issues | Example Vulnerability                        |
| ---------- | ---------------- | ---------------------------------------------|
| Critical   | 0                | —                                            |
| High       | 0                | —                                            |
| Medium     | 6                | Croos-Domain misconfiguration                |
| Low        | 7                | Cookie without secure flag                   |
| Info       | 7                | Information Disclodure - Suspicious comments |

<a name="link-1-1-failure-to-define-directive-with-no-fallback"></a>
**1. Failure to Define Directive with no Fallback**

    Severity: Medium

    Description: The Content Security Policy fails to define one of the directives that has no fallback. Missing/excluding them is the same as allowing anything.

    Affected URL:

        http://ezpay.iium.edu.my

        http://ezpay.iium.edu.my/faq

        http://ezpay.iium.edu.my/login

    Business Impact: Hackers can inject harmful scripts, steal user data or hijack sessions. This can lead to data breaches, loss of user trust, and legal issues.

    Classification: CWE‑693

    Recommendation: Add all key CSP rules such as default-src, script-src and object-src.

    Prevention Strategy:

        Always define important CSP rules.
        - (Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self';)

        Test your policy with tools like CSP Evaluator.

    Responsible Team: DevOps


<a name="link-1-3-wildcard-directive"></a>
**3. Wildcard Directive**

    Severity: Medium

    Description: Content Security Policy (CSP) helps protect websites from attacks like XSS by allowing only trusted sources to load things like scripts, styles, images and media. However, the following rules are missing, too open or use wildcards which weakens security.

    Affected URL:

        http://ezpay.iium.edu.my/contact-us

        http://ezpay.iium.edu.my/disclaimer

    Business Impact: Weak CSP settings can let attackers run harmful scripts, steal data, or damage the website.
   
    Classification: CWE‑693

    Recommendation: Use trusted CDNs or your own domain to serve content like JavaScript, CSS, fonts, and images.

    Prevention Strategy:

        Monitor CSP violation reports 

        Work closely with developers to ensure new content is added using allowed sources only.
        - reviews all new features in development or code to ensure:
        - No usage of * such as script-src *;

    Responsible Team: Security team


<a name="link-1-5-script-src-unsafe-inline"></a>
**5. script-src unsafe-inline**

    Severity: Medium

    Description: The script-src directive includes unsafe-inline, which allows inline JavaScript. This weakens CSP and can let attackers inject malicious scripts.

    Affected URL:

        http://ezpay.iium.edu.my/privacy-policy

        http://ezpay.iium.edu.my/register

    Business Impact: Attackers may exploit this to run harmful scripts, steal user data, or compromise the site.
   
    Classification: CWE‑693

    Recommendation: Remove unsafe-inline from script-src.

    Prevention Strategy: 

        Use nonces or hashes instead of unsafe-inline.
        - Backend generates a random nonce on each request
        - Add to CSP header: Content-Security-Policy: script-src 'self' 'nonce-abc123';
        - Apply nounce to every <script> tag: <script nonce="abc123">console.log('secure');</script>

        Deploy in Report-Only mode first

    Responsible Team: DevOps


<a name="link-1-4-style-src-unsafe-inline"></a>
**4. style-src unsafe-inline**

    Severity: Medium

    Description: The style-src directive includes unsafe-inline, which allows inline CSS styles. This reduces CSP effectiveness and can be exploited to inject malicious styles.

    Affected URL:

        http://ezpay.iium.edu.my/home-alt

        http://ezpay.iium.edu.my/services

    Business Impact: Attackers could inject harmful CSS to manipulate the appearance of the site, trick users, or hide malicious content.
   
    Classification: CWE‑693

    Recommendation: Remove unsafe-inline from style-src.

    Prevention Strategy: 

        Use nonces or hashes instead of unsafe-inline.
        - Use nounce for inline styles: <style nonce="xyz789">.secure { color: green; }</style>

        Move inline styles to external CSS files where possible.
        - Move all styles to external .css files.

    Responsible Team: DevOps


<a name="link-1-6-cross-domain-misconfiguration"></a>
**6. Cross-Domain Misconfiguration**

    Severity: Medium

    Description: The web server has a CORS misconfiguration that allows any third-party website to make read requests to its APIs without authentication.
   
    Affected URL:

        http://ezpay.iium.edu.my/payment/request

    Business Impact: This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner.
   
    Classification: CWE‑264

    Recommendation: Restrict CORS to allow only trusted domains.

    Prevention Strategy: 

        Use proper authentication and check permissions on all API endpoints.
        - All API endpoints must require auth tokens
        - Implement permission checks (role-based access control)

        Configure the server to specify allowed domains explicitly in the CORS policy.
        - Restrict CORS (Laravel): header('Access-Control-Allow-Origin: https://trusted.iium.edu.my');

    Responsible Team: Security Team


<a name="link-1-8-http-to-https-insecure-transition-in-form-post"></a>
**8. HTTP to HTTPS Insecure Transition in Form Post**

    Severity: Medium

    Description: This check looks for insecure HTTP pages that host HTTPS forms. The issue is that an insecure HTTP page can easily be hijacked through MITM and the secure HTTPS form can be replaced or spoofed.
   
    Affected URL:

        http://ezpay.iium.edu.my

    Business Impact: Users may unknowingly submit sensitive data like passwords or payment info to fake or altered forms which can be data theft or fraud.
   
    Classification: CWE‑319

    Recommendation: Serve all pages that collect or submit sensitive data entirely over HTTPS. Avoid mixing HTTP and HTTPS content.

    Prevention Strategy: 

        Redirect all HTTP traffic to HTTPS.
        - Force HTTPS using server redirect (NGINX):
   
        - if ($scheme = http) {
              return 301 https://$host$request_uri;
          }

        Review and update all forms to ensure they are hosted on secure HTTPS pages.
        - Update form URLs to https://... and ensure they're not embedded in HTTP pages.
        - <form action="https://ezpay.iium.edu.my/login">

    Responsible Team: DevOps


<a name="link-1-10-strict-transport-security-header-not-set"></a>
**10. Strict-Transport-Security Header Not Set**

    Severity: Low

    Description: HTTP Strict Transport Security (HSTS) tells browsers to always use HTTPS when connecting to the site. Without this header, users might accidentally connect over insecure HTTP which can be intercepted.
   
    Affected URL:

        http://ezpay.iium.edu.my/dashboard-cas

        http://ezpay.iium.edu.my/flywire.png

    Business Impact: Without HSTS, attackers can perform man-in-the-middle attacks by forcing users to connect over HTTP which could potentially leads to stealing or altering data.
   
    Classification: CWE‑319

    Recommendation: Ensure that all assets such as images, scripts and styles are served over HTTPS to prevent security warnings and possible bypasses.

    Prevention Strategy: 

        Implement the HSTS header on all HTTPS responses.
        - Add HSTS header:
        - apache: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        - NGINX: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";

        Monitor and ensure no content is served over HTTP.
        - All assests load via https://
        - No hardcoded HTTP links exist in templates or configuration

    Responsible Team: Web Development 


<a name="link-1-12-big-redirect-detected-potential-sensitive-information-leak"></a>
**12. Big Redirect Detected (Potential Sensitive Information Leak)**

    Severity: Low

    Description: The server sends a redirect response but also includes a large response body. This may accidentally expose sensitive data like personal information.
   
    Affected URL:

        http://ezpay.iium.edu.my/language

        http://ezpay.iium.edu.my/login

    Business Impact: Sensitive information could be leaked through the response body during redirects which increase the risk of data exposure.
   
    Classification: CWE‑201

    Recommendation: Ensure redirect responses have minimal or no body content to avoid exposing sensitive data.

    Prevention Strategy: 

        Do not include sensitive data in redirect responses.
        - Avoid embedding user data or error messages in 3xx response pages
        - What not to do in Laravel: return response("Redirecting user: JohnDoe to /dashboard", 302);
    
        Configure the server to send clean and safe redirects.
        - Use proper redirect methods

        - In laravel:
          - Don't do: return response()->view('home')->setStatusCode(302);
          - Do: return redirect('/home');



   Responsible Team: DevOps


<a name="link-1-11-cookie-without-secure-flag"></a>
**11. Cookie Without Secure Flag**

    Severity:Low
    
    Description:
    A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.
    
    Affected URL:
    ```
    https://ezpay.iium.edu.my/robots.txt
    ```
    Business Impact:
    If this cookie carries session identifiers or sensitive data, it could be intercepted by an attacker via a man-in-the-middle (MITM) attack. This may result in     session hijacking or data theft, potentially compromising user accounts and violating data protection policies.
    
    Classification: CWE-614
    
    Recommendation:
    Set the Secure flag on all cookies, especially those that store session tokens or sensitive information. This ensures cookies are only transmitted over            encrypted HTTPS connections.
    
    Prevention Strategy
    ```
    Review all cookie settings in the application.
    
    Ensure cookies are set with the Secure attribute by default.
    
    Redirect all HTTP requests to HTTPS to enforce encrypted communication.
    ```
    
    Responsible team:
    DevOps
     
<a name="link-1-12-cookie-no-httponly-flag"></a>
**12. Cookie No HTTPOnly Flag**
    
    Severity:Low
    
    Description:
    A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then     the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.
    
    Affected URL:
    ```
    https://ezpay.iium.edu.my/sitemap.xml
    ```
    Business Impact:
    Cookies accessible via JavaScript are vulnerable to theft through XSS (Cross-Site Scripting) attacks. If the stolen cookie is used to maintain user sessions,      this could lead to session hijacking, impersonation, and unauthorized access to user accounts.
    
    Classification: CWE-1004
    
    Recommendation:
    Set the HttpOnly attribute for all cookies, especially those related to authentication, sessions, and user data. This prevents the cookie from being accessed      by JavaScript.
    
    Prevention Strategy
    ```
    Ensure all sensitive cookies are created with the HttpOnly flag.
    
    Configure the application framework or web server to set this by default.
    ```
    
    Responsible team:
    Back-End Development

<a name="link-1-13-cookie-without-samesite-attribute"></a>
**13. Cookie without SameSite Attribute**
    
    Severity:Low
    
    Description:
    A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is     an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.
    
    Affected URL:
    ```
    https://ezpay.iium.edu.my/robots.txt
    ```
    Business Impact:
    Without the SameSite attribute, attackers can exploit CSRF to perform unauthorized actions on behalf of authenticated users. This could lead to unwanted           changes in user settings, data manipulation, or even session hijacking.
    
    Classification: CWE-1275
    
    Recommendation:
    Set the SameSite attribute to either:
    ```
    Strict – for sensitive session cookies
    
    Lax – for less strict control where cross-site functionality is needed
    ```
    Prevention Strategy
    ```
    Update cookie settings in the web framework or server config.
    
    Use:
        Set-Cookie: cookiesession1=value; SameSite=Strict; Secure; HttpOnly
    ```
    
    Responsible team:
    Back-End Development

<a name="link-1-14-cross-domain-javascript-source-file-inclusion"></a>
**14. Cross-Domain JavaScript Source File Inclusion**
    
    Severity:Low
    
    Description:
    The page includes one or more script files from a third-party domain.
    
    Affected URL:
    ```
    https://ezpay.iium.edu.my/services/student-fee
    ```
    Business Impact:
    If a third-party script is modified maliciously or compromised, it can execute arbitrary code in the context of your application, potentially stealing user         data or compromising the integrity of the system.
    
    Classification: CWE-829
    
    Recommendation:
    
    ```
    Load JavaScript files only from trusted, integrity-verified sources.
    
    If using third-party scripts, enable Subresource Integrity (SRI) to verify content has not been tampered with.
    ```
    
    Prevention Strategy
    ```
     Use integrity attributes with third-party scripts:
        <script src="..." integrity="sha384-...=="
                crossorigin="anonymous"></script>
    
    Host critical scripts locally to avoid external dependency.
    ```
    
    Responsible team:
    Front-End Development

<a name="link-1-15-authentication-request-identified"></a>
**15. Authentication Request Identified**
    
    Severity:Informational
    
    Description:
    The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant           fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the          request identified.
    
    Affected URL:
    ```
    https://ezpay.iium.edu.my/login
    ```
    Business Impact:
    This is an informational alert only. However, if login pages are not properly protected (e.g., lack of rate limiting, CAPTCHA, or HTTPS), they may become          targets for brute-force or credential stuffing attacks. In this case, no such vulnerability was confirmed.
    
    Classification: CWE-0
    
    Recommendation:
    None required. However, it’s good practice to:
    ```
    Log authentication attempts
    
    Protect login forms with CAPTCHA and rate limiting
    
    Always serve them over HTTPS
    ```
    Prevention Strategy
    ```
    No immediate action needed.
    
    Review login security mechanisms regularly as part of defense-in-depth.
    ```
    
    Responsible team:
    Application Security Team



# Table of Contents for Link 2
1. [Executive Summary](#link-2-executive-summary)
2. [Summary of findings](#link-2-summary-of-findings)
3. [Detailed Findings](#link-2-detailed-findings)
    - [1. Server Version Disclosure](#link-2-1-server-version-disclosure)
    - [2. Absence of Anti‑CSRF Tokens](#link-2-2-absence-of-anti‑csrf-tokens)
    - [3. Content Security Policy (CSP) Header Not Set](#link-2-3-content-security-policy-csp-header-not-set)
    - [4. Subresource Integrity Missing](#link-2-4-subresource-integrity-missing)
    - [5. Vulnerable JS Libraries](#link-2-5-vulnerable-js-libraries)
    - [6. Cookies Without Secure Flags](#link-2-6-cookies-without-secure-flags)
    - [7. Missing Permissions Policy Header](#link-2-7-missing-permissions-policy-header)
    - [8. Missing Cross‑Origin Resource Policy](#link-2-8-missing-cross‑origin-resource-policy)
    - [9. Information Disclosure via JS Comments](#link-2-9-information-disclosure-via-js-comments)
    - [10. HTTPS/TLS Not Enforced](#link-2-10-httpstls-not-enforced)
4. [Recommendations & Next Steps](#link-2-recommendations--next-steps)
5. [Appendix](#link-2-appendix)

<a name="link-2-executive-summary"></a>
## Link 2 (http://epic.iium.edu.my)

<a name="link-2-summary-of-findings"></a>
### 1. Executive Summary

| Metric                        | Value   |
| ----------------------------- | ------- |
| Total Issues Identified       | 15      |
| Critical Issues               | 0       |
| High-Risk Issues              | 0       |
| Medium-Risk Issues            | 4       |
| Low-Risk/Informational Issues | 11      |
| Remediation Status            | Pending |

<a name="link-2-detailed-findings"></a>
### 2. Summary of findings

| Risk Level | Number of Issues | Example Vulnerability                  |
| ---------- | ---------------- | -------------------------------------- |
| Critical   | 0                | —                                      |
| High       | 0                | —                                      |
| Medium     | 4                | Absence of Anti‑CSRF Tokens            |
| Low        | 5                | Cookie without HttpOnly/SameSite Flags |
| Info       | 6                | Suspicious Comments in JS              |

<a name="link-2-1-server-version-disclosure"></a>
**1. Server Version Disclosure**

    Severity: Low

    Description: The Server HTTP header reveals Apache/2.4.6, OpenSSL and PHP versions.

    Affected URL:

        http://epic.iium.edu.my

    Business Impact: Attackers can fingerprint the server and look up specific known exploits.

    Classification: CWE‑497

    Recommendation: Remove or genericize the Server header in web server configuration.

    Prevention Strategy:

        Set ServerTokens Prod (Apache) or equivalent.

        Suppress version details at all layers.

    Responsible Team: Infrastructure
    

<a name="link-2-2-absence-of-anti‑csrf-tokens"></a>
**2. Absence of Anti‑CSRF Tokens**

    Severity: Medium

    Description: Forms do not include CSRF tokens to prevent forged requests.

    Affected URLs (sample):

        http://epic.iium.edu.my/index.html

        http://epic.iium.edu.my/users/profile

    Business Impact: Attackers could trick authenticated users into submitting unwanted actions.

    Classification: CWE‑352

    Recommendation: Implement per‑form unique, unpredictable CSRF tokens (e.g., OWASP CSRFGuard).

    Prevention Strategy:

        Use framework‑built CSRF defenses.

        Verify token on every state‑changing request.

    Responsible Team: Application Dev
    

<a name="link-2-3-content-security-policy-csp-header-not-set"></a>
**3. Content Security Policy (CSP) Header Not Set**

    Severity: Medium

    Description: No Content-Security-Policy header present to restrict allowed sources.

    Affected URLs:

        http://epic.iium.edu.my/ and all sub‑resources

    Business Impact: Increases risk of XSS and data‑injection attacks.

    Classification: CWE‑693

    Recommendation: Define a strict CSP (e.g., only allow same‑origin scripts/styles).

    Prevention Strategy:

        Add Content-Security-Policy header in server configuration.

        Gradually tighten directives.

    Responsible Team: DevOps
    

<a name="link-2-4-subresource-integrity-missing"></a>
**4. Subresource Integrity Missing**

    Severity: Medium

    Description: External scripts/styles lack integrity attributes to verify content.

    Affected URLs:

        http://epic.iium.edu.my/js/epic/app.js

        http://epic.iium.edu.my/js/epic/plugins.js

    Business Impact: A compromised CDN could serve malicious code.

    Classification: CWE‑345

    Recommendation: Add SRI hashes (integrity attribute) for all third‑party resources.

    Prevention Strategy:

        Generate and include integrity hashes.

        Serve scripts over HTTPS only.

    Responsible Team: Front‑End Dev
    

<a name="link-2-5-vulnerable-js-libraries"></a>
**5. Vulnerable JS Libraries**

    Severity: Medium

    Description: Outdated libraries (jQuery 1.11.1, jQuery UI 1.10.4, Bootstrap 3.2.0) with known CVEs.

    Affected URLs:

        http://epic.iium.edu.my/js/epic/vendor/jquery-1.11.1.min.js

        http://epic.iium.edu.my/js/epic/plugins.js

        http://epic.iium.edu.my/js/epic/vendor/bootstrap.min.js

    Business Impact: Attackers can exploit library vulnerabilities to inject code or escalate attacks.

    Classification: CWE‑1395

    Recommendation: Upgrade to the latest patched versions of each library.

    Prevention Strategy:

        Regularly review dependencies.

        Automate vulnerability alerts on library updates.

    Responsible Team: Application Dev
    

<a name="link-2-6-cookies-without-secure-flags"></a>
**6. Cookies Without Secure Flags**

    Severity: Low

    Description: Several session cookies lack HttpOnly and/or SameSite attributes.

    Affected Cookies & URLs (sample):

        CAKEPHP, SESSION on http://epic.iium.edu.my/

    Business Impact: JavaScript can access cookies (risk of theft), and CSRF risk increases.

    Classification: CWE‑1004 (HttpOnly), CWE‑1275 (SameSite)

    Recommendation:

        Set HttpOnly; SameSite=Strict; Secure on all cookies.

    Prevention Strategy:

        Configure framework cookie settings.

        Enforce Secure flag when HTTPS is in use.

    Responsible Team: Back‑End Dev
    

<a name="link-2-7-missing-permissions-policy-header"></a>
**7. Missing Permissions Policy Header**

    Severity: Low

    Description: No Permissions-Policy header to limit browser features.

    Affected URLs: All application endpoints

    Business Impact: Unrestricted use of features like camera, microphone, geolocation could be abused.

    Classification: CWE‑693

    Recommendation: Define a Permissions-Policy header to disable unused features.

    Prevention Strategy:

        Set header via web server or middleware.

        Start with a deny‑all policy and enable only needed features.

    Responsible Team: DevOps
    

<a name="link-2-8-missing-cross-origin-resource-policy"></a>
**8. Missing Cross‑Origin Resource Policy**

    Severity: Low

    Description: No Cross-Origin-Resource-Policy header to prevent Spectre‑style side‑channels.

    Affected URLs: Static assets (CSS, images, JS)

    Business Impact: Potential cross‑origin data leakage via side‑channel attacks.

    Classification: CWE‑693

    Recommendation: Set Cross-Origin-Resource-Policy: same-origin on all resources.

    Prevention Strategy:

        Configure header in server.

        Verify support in target browsers.

    Responsible Team: DevOps
    

<a name="link-2-9-information-disclosure-via-js-comments"></a>
**9. Information Disclosure via JS Comments**

    Severity: Informational

    Description: Suspicious comments in JS and HTML reveal implementation hints.

    Affected URLs:

        http://epic.iium.edu.my/js/epic/app.js

        http://epic.iium.edu.my/robots.txt

    Business Impact: Attackers may leverage comments to understand logic or endpoints.

    Classification: CWE‑615

    Recommendation: Remove sensitive comments and debug traces from production code.

    Prevention Strategy:

        Strip comments during build/minification.

        Follow secure code‑review checklists.

    Responsible Team: Application Dev
    

<a name="link-2-10-httpstls-not-enforced"></a>
**10. HTTPS/TLS Not Enforced**

    Severity: Informational

    Description: The application is served over HTTP only; no TLS configuration detected.

    Affected URLs: All

    Business Impact: Data in transit is exposed to eavesdropping and tampering.

    Classification: N/A

    Recommendation: Obtain and install a valid TLS certificate and redirect all traffic to HTTPS.

    Prevention Strategy:

        Enforce HSTS after deploying HTTPS.

        Periodically scan for certificate expiry.

    Responsible Team: Infrastructure
    
<a name="link-2-recommendations--next-steps"></a>
4. Recommendations & Next Steps

    Immediate Fixes: Address all Medium‑risk issues (CSRF, CSP, SRI, JS libraries) within the next two weeks.

    Cookies Hardening: Enforce secure cookie flags as soon as HTTPS is in place.

    Deploy HTTPS: Move to TLS/SSL to protect data in transit.

    Re‑scan & Validate: Perform a follow‑up ZAP scan after remediation.

    Secure SDLC: Integrate security checks into CI/CD (linting headers, dependency checks).

    Periodic Reviews: Schedule monthly passive and quarterly active scans.

    Penetration Test: Engage a third‑party pen test post‑deployment for deeper coverage.
<a name="link-2-appendix"></a>
Appendix

OWASP ZAP generated report for this link can be downloaded at the top 
![image](https://github.com/user-attachments/assets/ff4d8c93-6dad-4c1d-9c52-483affce3f06)

Prepared by:

Team HAI

Hanif Asyraf Bin Mohd Sabri

hanifasyrafms@gmail.com

25-5-2025


Mohamad Arman Izuddin Bin Mohamad Nazri

mohaizuddin010@gmail.com

28-5-2025

Muhammad Iz'aan bin Suhaimi

mdizaansuhaimi@gmail.com

18-6-2025

