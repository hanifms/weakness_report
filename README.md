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

1. 




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

