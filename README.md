# IIUM Web Application Security Report
Case Study Report

Web Application Security
INFO 4345

Dr. MUHAMAD SADRY ABU SEMAN

---

## Prepared by : Group Last

---

## Table of Contents

1. [Overview](#overview)
2. [Assigned Web Application](#assigned-web-application)
3. [Objectives](#objectives)
4. [Identified Vulnerabilities](#identified-vulnerabilities)
5. [Evaluation of Vulnerabilities](#evaluation-of-vulnerabilities)
6. [Prevention Measures](#prevention-measures)
7. [List of Figures](#list-of-figures)
8. [List of Tables](#list-of-tables)
9. [References](#references)

---

### Group Members

| Name              | Matric No | Task                                                  |
|-------------------|-----------|-------------------------------------------------------|
| Raja Muhamad Umar | 2119191   | Scanned (https://hrservice.iium.edu.my using) OWASP ZAP |
| Muhammad Afzal | 2123023   | Scanned (http://hrservice.iium.edu.my/apariium) using OWASP ZAP |
| Muhammad Afiff Firdaus | 2120573   | Scanned (http://hrservice.iium.edu.my/adm) using OWASP ZAP |

### Scan Information

| URL              | Date of scan | Scan type  | Scan Duration |
|------------------|--------------|--------------|-------------------------------------------------------|
|(https://hrservice.iium.edu.my) | 23/5/2025 | Automated scan/Manual explore | 10 minutes |
| (http://hrservice.iium.edu.my/apariium) | 22/5/2025 | Automated scan/Manual explore | 15 Minutes |
| (http://hrservice.iium.edu.my/adm) |  20/5/2025  | Automated scan/Manual explore | 15 minutes | |

---
### Metric Values

1. Raja Muhamad Umar bin Raja Kamarul Izham (2119191)

| *Metric*                         | *Value*         |
|-----------------------------------|-------------------|
| Total Issues Identified           | 4                 |
| Critical Issues                   | 0                 |
| High-Risk Issues                  | 0                 |
| Medium-Risk Issues                | 2                 |
| Low-Risk/Informational Issues     | 2                 |
| Remediation Status                | Pending           |

2. Muhammad Afzal Bin Mohd Nor (2123032)

| *Metric*                         | *Value*         |
|----------------------------------|------------------|
| Total Issues Identified          | 5                |
| Critical Issues                  | 0                |
| High-Risk Issues                 | 0                |
| Medium-Risk Issues               | 3                |
| Low-Risk/Informational Issues    | 2                |
| Remediation Status               | Pending          |

3. Muhammad Afiff Firdaus Bin Abdullah (2120573)

| *Metric*                         | *Value*         |
|----------------------------------|------------------|
| Total Issues Identified          | 4                |
| Critical Issues                  | 0                |
| High-Risk Issues                 | 0                |
| Medium-Risk Issues               | 2                |
| Low-Risk/Informational Issues    | 2                |
| Remediation Status               | Pending          |

---
### Key takeaways

| URL              | Key takeaways |
|------------------|--------------|
|(https://hrservice.iium.edu.my) | The scan revealed *2 medium-risk vulnerabilities* that impact client-side security (missing CSP and anti-clickjacking headers). These should be addressed soon. No critical or high-risk issues were found. Two informational findings were also recorded. |
| (http://hrservice.iium.edu.my/apariium) | The scan reveals several medium to high-risk vulnerabilities that expose the site to threats like cross-site scripting, clickjacking, and insecure cross-origin access. The absence of key security headers such as CSP and X-Frame-Options, combined with outdated JavaScript libraries, increases the risk of code injection and unauthorized access. Immediate attention should be given to implementing proper security headers, updating vulnerable components, and reviewing cross-domain policies to reduce the site’s exposure to common web attacks.|
| (http://hrservice.iium.edu.my/adm) |  The security assessment identified several medium-risk and informational vulnerabilities in the application, primarily due to missing security headers, lack of anti-CSRF protections, and outdated JavaScript libraries. These weaknesses increase the risk of common web attacks such as cross-site scripting (XSS), cross-site request forgery (CSRF), and clickjacking. Addressing these issues through the recommended security measures will significantly strengthen the application's resilience against exploitation and enhance overall web security.  |

---

## Assigned Web Application

**Name**: IIUM Human Resource Services  
**URL**:
1. https://hrservice.iium.edu.my/
2. http://hrservice.iium.edu.my/apariium
3. http://hrservice.iium.edu.my/adm

---

## Objectives

- Scan and analyze vulnerabilities using OWASP ZAP.
- Evaluate the potential risks and impact.
- Suggest mitigation steps to enhance web application security.

---

### Identified Vulnerabilities  

1. Raja Muhamad Umar bin Raja Kamarul Izham (2119191)
URL: https://hrservice.iium.edu.my

| No | Vulnerability       | Risk   | Affected URL   | CWE ID   | Description                                   | Suggested Fix         |
|----|---------------------|--------|----------------|----------|-----------------------------------------------|-----------------------|
| 1 | Cross-Domain Misconfiguration | Medium | (https://fonts.googleapis.com/css%3Ffamily=Lato:700,400,300,100%257CSignika:400,700%257CCourgette) | CWE-264 | Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server. | Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header |
| 2 | Missing Anti-clickjacking Header | Medium | (https://hrservice.iium.edu.my/) | CWE-1021 | The response does not protect against 'ClickJacking' attacks | Ensure one the Modern Web Browser supports the Content-Security-Policy and X-Frame-Options HTTP headers of them is set on all web pages returned by your site/app |
| 3 | Vulnerable JS Library | Medium | (https://nvd.nist.gov/vuln/detail/CVE-2024-6485) | CWE-1395 | The identified library appears to be vulnerable. | Upgrade to the latest version of the affected library. |
| 4 | Information Disclosure - Sensitive Information in URL | Medium(Informational) | (https://hrservice.iium.edu.my/adm/j_spring_cas_security_check%3Fticket=ST-1228398-Y4HU63-WgweM2Nt-6wFTebR-QJs-cas1) | CWE-598 | he request appeared to contain sensitive information leaked in the URL. | Do not pass sensitive information in URIs |




2. Muhammad Afzal Bin Mohd Nor (2123032)
URL: http://hrservice.iium.edu.my/apariium

| No | Vulnerability       | Risk   | Affected URL   | CWE ID   | Description                                   | Suggested Fix         |
|----|---------------------|--------|----------------|----------|-----------------------------------------------|-----------------------|
| 1 | Content Security Policy (CSP) Header Not Set | Medium (High) | (https://cas.iium.edu.my:8448/cas/login%3Fservice=https%253A%252F%252Fhrservice.iium.edu.my%252Fapariium%252Flogin%252Fcas) | CWE-693 | CSP is a security feature that blocks threats like XSS by letting sites control which content sources browsers can load.| Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.|
| 2 | Cross-Domain Misconfiguration | Medium | (https://fonts.googleapis.com/css%3Ffamily=Lato:700,400,300,100%257CSignika:400,700%257CCourgette) | CWE-264 | Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server. | Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance) |
| 3 | Missing Anti-clickjacking Header | Medium | (https://hrservice.iium.edu.my/) | CWE-1021 | The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options | Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.|
| 4 | Vulnerable JS Library | Medium | (https://cas.iium.edu.my:8448/cas/webjars/bootstrap/3.3.7-1/js/bootstrap.min.js) | CWE-1395 | The identified library appears to be vulnerable. | Upgrade to the latest version of the affected library.|



4. Muhammad Afiff Firdaus Bin Abdullah (2120573)
URL: http://hrservice.iium.edu.my/adm

| No | Vulnerability                               | Risk           | Affected URL                                                                                                           | CWE ID    | Description                                                                                                                    | Suggested Fix                                                                                                  |
|----|---------------------------------------------|----------------|------------------------------------------------------------------------------------------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| 1  | Content Security Policy (CSP) Header Not Set| Medium (High)  | https://hrservice.iium.edu.my/robots.txt                                                                              | CWE-693   | CSP is a security feature that blocks threats like XSS by letting sites control which content sources browsers can load.       | Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header. |
| 2  | Absence of Anti-CSRF Tokens                 | Medium         | http://hrservice.iium.edu.my/adm                                                                                       | CWE-352   | No anti-CSRF tokens detected, making the site vulnerable to cross-site request forgery attacks.                                | Implement anti-CSRF tokens on forms and sensitive actions.                                                     |
| 3  | Session Management Response Identified      | Informational  | https://hrservice.iium.edu.my/adm/                                                                                     | -         | Session management response detected; informational only, but check if session management is secure.                           | Review session management implementation for security best practices.                                           |


---

## Evaluation of Vulnerabilities

URL: https://hrservice.iium.edu.my/
- Cross-Domain Misconfiguration: This could allow attackers to load or manipulate external resources
- Missing Anti-clickjacking Header: Without X-Frame-Options or Content-Security-Policy, the site is vulnerable to clickjacking attacks — tricking users into clicking hidden elements embedded via iframes. This is a common and preventable issue.
- Vulnerable JavaScript Library: Usage of an outdated JS library (linked to a known CVE) can open the application to a wide range of exploits including XSS or logic manipulation, depending on the vulnerability. This is a serious issue if the library is actively used.
- Information Disclosure in URL: 	Sensitive tokens in URLs are risky because they may be logged in browser history or server logs. In the worst case, a leaked token could allow session hijacking or unauthorized access.


URL: http://hrservice.iium.edu.my/apariium
- Content Security Policy (CSP) Header Not Set: Without CSP, the site is more exposed to XSS and code injection attacks.
- Cross-Domain Misconfiguration: Misconfigured cross-domain policies can allow unauthorized domains to access sensitive resources.
- Missing Anti-clickjacking Header: Lack of headers like X-Frame-Options makes the site vulnerable to clickjacking attacks.
- Vulnerable JS Library: Using outdated or insecure JavaScript libraries can expose the site to known exploits.


URL: http://hrservice.iium.edu.my/adm
- Lack of Security Headers:The absence of important security headers such as Content Security Policy (CSP) and anti-CSRF tokens exposes the application to common web threats, including cross-site scripting (XSS), clickjacking, and cross-site request forgery (CSRF) attacks.
- Session and Cookie Security Weaknesses:The scan detected missing security attributes in session management and cookies (e.g., missing HttpOnly, Secure, and SameSite flags), which increases the risk of session hijacking and unauthorized access via browser-based attacks.
- Use of Outdated or Vulnerable Components:The presence of vulnerable JavaScript libraries (e.g., old Bootstrap version) can introduce exploitable weaknesses, allowing attackers to leverage known vulnerabilities if not promptly updated.
- Potential Information Disclosure:Informational issues, such as session management response identification, may not be directly exploitable but could aid attackers in gathering intelligence about the application’s structure and behavior, potentially supporting future attacks.


---

## Prevention Measures (With Code & Explanation)

### URL: `https://hrservice.iium.edu.my/`

| Vulnerability                    | Recommendation (Code)                                                                                                                             | Explanation                                                                              |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Cross-Domain Misconfiguration    | **Apache**:`Header set Access-Control-Allow-Origin "https://yourdomain.com"`**Express.js**:`app.use(cors({ origin: 'https://yourdomain.com' }));` | Prevents external websites from loading your resources and making unauthorized requests. |
| Missing Anti-clickjacking Header | **Apache**:`Header set X-Frame-Options "DENY"`**Express.js**:`app.use(helmet.frameguard({ action: 'deny' }))`                                     | Prevents clickjacking by stopping your site from being embedded in an iframe.            |
| Vulnerable JS Library            | Replace outdated versions:`<script src="https://code.jquery.com/jquery-3.6.4.min.js"></script>`                                                   | Ensures libraries are secure and not exploitable via known CVEs.                         |
| Information Disclosure in URL    | Use POST instead of GET:`<form method="POST"><input type="hidden" name="ticket" value="secure-token"></form>`                                     | Prevents session tokens from being exposed in browser history or server logs.            |

---

### URL: `http://hrservice.iium.edu.my/apariium`

| Vulnerability                    | Recommendation (Code)                                                                                                              | Explanation                                                                         |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| CSP Header Not Set               | **Apache**:`Header set Content-Security-Policy "default-src 'self';"`**Express.js**:`app.use(helmet.contentSecurityPolicy({...}))` | Restricts which domains can load content like scripts or styles, reducing XSS risk. |
| Cross-Domain Misconfiguration    | **Apache**:`Header always set Access-Control-Allow-Origin "https://trusted-domain.com"`                                            | Controls access to web resources by only allowing trusted domains.                  |
| Missing Anti-clickjacking Header | Same as above:`X-Frame-Options: DENY` or `Content-Security-Policy: frame-ancestors 'none'`                                         | Protects against clickjacking by preventing the site from being framed by others.   |
| Vulnerable JS Library            | Replace outdated library:`<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>`    | Ensures the JS codebase does not include components with known security holes.      |

---

### URL: `http://hrservice.iium.edu.my/adm`

| Vulnerability                          | Recommendation (Code)                                                                                                           | Explanation                                                                       |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| CSP Header Not Set                     | Same as above:`Header set Content-Security-Policy "default-src 'self';"`                                                        | Prevents unauthorized script loading, protecting against XSS.                     |
| Absence of Anti-CSRF Tokens            | **Laravel Blade:**`@csrf`**PHP:**`<input type='hidden' name='csrf_token' value='<?php echo $_SESSION['csrf_token']; ?>'>`       | Ensures requests are legitimate and not forged from another origin.               |
| Vulnerable JS Library                  | Update to latest version:`<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>` | Old JS libraries are prone to exploitation; always use supported versions.        |
| Session Management Response Identified | **PHP**:`session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);`                            | Enhances session token security against hijacking and CSRF via cookie attributes. |

---

## Appendices

### Appendix A: ZAP Scan Reports
These are the exported vulnerability scan reports from OWASP ZAP for each assigned system. The reports include detected issues, risk levels, confidence ratings, affected URLs, and recommendations.

**Files Attached (in GitHub repo):**
- [scan-report-hrservice.html](./scan-report-hrservice.html)
- [scan-report-apariium.html](./scan-report-apariium.html)
- [scan-report-adm.html](./scan-report-adm.html)

---

### Appendix B: Summary of Alerts

#### URL: https://hrservice.iium.edu.my

| Vulnerability                     | Risk Level        | CWE ID  |
|----------------------------------|-------------------|---------|
| Information Disclosure in URL    | Informational     | CWE-598 |
| Missing Anti-clickjacking Header | Medium            | CWE-1021|
| Vulnerable JavaScript Library    | Medium            | CWE-1104|
| Cross-Domain Misconfiguration    | Medium            | CWE-264 |

---

#### URL: http://hrservice.iium.edu.my/apariium

| Vulnerability                     | Risk Level        | CWE ID  |
|----------------------------------|-------------------|---------|
| CSP Header Not Set               | Medium            | CWE-693 |
| Cross-Domain Misconfiguration    | Medium            | CWE-264 |
| Missing Anti-clickjacking Header | Medium            | CWE-1021|
| Vulnerable JavaScript Library    | Medium            | CWE-1104|
| Session Token Identified         | Informational     | -       |

---

#### URL: http://hrservice.iium.edu.my/adm

| Vulnerability                          | Risk Level    | CWE ID  |
|---------------------------------------|---------------|---------|
| CSP Header Not Set                    | Medium        | CWE-693 |
| Absence of Anti-CSRF Tokens           | Medium        | CWE-352 |
| Session Management Response Identified| Informational | -       |

---

### Appendix C: Vulnerable JS Library Details

- **Library Name:** jQuery 1.x, Bootstrap 3.3.7  
- **Risk:** Known vulnerabilities include XSS and DOM-based injection  
- **Reference:**  
  - https://snyk.io/vuln/npm:jquery  
  - https://snyk.io/vuln/npm:bootstrap  

---

### Appendix D: Tools Used

- **OWASP ZAP v2.16.1** – Used for scanning and exporting reports  
- **Browser (ZAP Internal Firefox)** – Manual exploration  
- **VS Code + GitHub** – Documentation and submission  
