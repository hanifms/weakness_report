# weakness_report
group assignment (HAI)


# Link 1 (http://ezpay.iium.edu.my)

1. Executive Summary

| Metric                        | Value   |
| ----------------------------- | ------- |
| Total Issues Identified       | 20      |
| Critical Issues               | 0       |
| High-Risk Issues              | 0       |
| Medium-Risk Issues            | 6       |
| Low-Risk/Informational Issues | 14      |
| Remediation Status            | Pending |

2. Summary of findings

| Risk Level | Number of Issues | Example Vulnerability                        |
| ---------- | ---------------- | ---------------------------------------------|
| Critical   | 0                | —                                            |
| High       | 0                | —                                            |
| Medium     | 6                | Croos-Domain misconfiguration                |
| Low        | 7                | Cookie without secure flag                   |
| Info       | 7                | Information Disclodure - Suspicious comments |

3. Detailed Findings

1. Failure to Define Directive with no Fallback

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

        Test your policy with tools like CSP Evaluator.

    Responsible Team: DevOps


2. Wildcard Directive

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

    Responsible Team: Security team


3. script-src unsafe-inline

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

        Deploy in Report-Only mode first

    Responsible Team: DevOps


4. style-src unsafe-inline

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

        Move inline styles to external CSS files where possible.

    Responsible Team: DevOps


5. Cross-Domain Misconfiguration

    Severity: Medium

    Description: The web server has a CORS misconfiguration that allows any third-party website to make read requests to its APIs without authentication.
   
    Affected URL:

        http://ezpay.iium.edu.my/payment/request

    Business Impact: This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner.
   
    Classification: CWE‑264

    Recommendation: Restrict CORS to allow only trusted domains.

    Prevention Strategy: 

        Use proper authentication and check permissions on all API endpoints.

        Configure the server to specify allowed domains explicitly in the CORS policy.

    Responsible Team: Security Team


6. HTTP to HTTPS Insecure Transition in Form Post

    Severity: Medium

    Description: This check looks for insecure HTTP pages that host HTTPS forms. The issue is that an insecure HTTP page can easily be hijacked through MITM and the secure HTTPS form can be replaced or spoofed.
   
    Affected URL:

        http://ezpay.iium.edu.my

    Business Impact: Users may unknowingly submit sensitive data like passwords or payment info to fake or altered forms which can be data theft or fraud.
   
    Classification: CWE‑319

    Recommendation: Serve all pages that collect or submit sensitive data entirely over HTTPS. Avoid mixing HTTP and HTTPS content.

    Prevention Strategy: 

        Redirect all HTTP traffic to HTTPS.

        Review and update all forms to ensure they are hosted on secure HTTPS pages.

    Responsible Team: DevOps


7. Strict-Transport-Security Header Not Set

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

        Monitor and ensure no content is served over HTTP.

    Responsible Team: Web Development 


8. Big Redirect Detected (Potential Sensitive Information Leak)

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

        Configure the server to send clean and safe redirects.

   Responsible Team: DevOps


9. Cookie Without Secure Flag

10. Cookie No HTTPOnly Flag

11. Cookie without SameSite Attribute

12. Cross-Domain JavaScript Source File Inclusion

13. Authentication Request Identified




# Link 2 (http://epic.iium.edu.my)

![image](https://github.com/user-attachments/assets/4563e002-c6f4-40cb-bcd2-da11c83dac33)

1. Executive Summary 

| Metric                        | Value   |
| ----------------------------- | ------- |
| Total Issues Identified       | 15      |
| Critical Issues               | 0       |
| High-Risk Issues              | 0       |
| Medium-Risk Issues            | 4       |
| Low-Risk/Informational Issues | 11      |
| Remediation Status            | Pending |

2. Summary of findings

| Risk Level | Number of Issues | Example Vulnerability                  |
| ---------- | ---------------- | -------------------------------------- |
| Critical   | 0                | —                                      |
| High       | 0                | —                                      |
| Medium     | 4                | Absence of Anti‑CSRF Tokens            |
| Low        | 5                | Cookie without HttpOnly/SameSite Flags |
| Info       | 6                | Suspicious Comments in JS              |

3. Detailed Findings
1. Server Version Disclosure

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
    

2. Absence of Anti‑CSRF Tokens

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
    

3. Content Security Policy (CSP) Header Not Set

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
    

4. Subresource Integrity Missing

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
    

5. Vulnerable JS Libraries

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
    

6. Cookies Without Secure Flags

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
    

7. Missing Permissions Policy Header

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
    

8. Missing Cross‑Origin Resource Policy

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
    

9. Information Disclosure via JS Comments

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
    

10. HTTPS/TLS Not Enforced

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
    

4. Recommendations & Next Steps

    Immediate Fixes: Address all Medium‑risk issues (CSRF, CSP, SRI, JS libraries) within the next two weeks.

    Cookies Hardening: Enforce secure cookie flags as soon as HTTPS is in place.

    Deploy HTTPS: Move to TLS/SSL to protect data in transit.

    Re‑scan & Validate: Perform a follow‑up ZAP scan after remediation.

    Secure SDLC: Integrate security checks into CI/CD (linting headers, dependency checks).

    Periodic Reviews: Schedule monthly passive and quarterly active scans.

    Penetration Test: Engage a third‑party pen test post‑deployment for deeper coverage.

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

