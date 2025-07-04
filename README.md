# IIUM Web Application Security Report
Case Study Report

Web Application Security
INFO 4345

Dr. MUHAMAD SADRY ABU SEMAN

---

## Prepared by : Group Last

---

## Table of Contents

1. [Assigned Web Application](#assigned-web-application)
2. [Objectives](#objectives)
3. [Identified Vulnerabilities](#identified-vulnerabilities)
4. [Evaluation of Vulnerabilities](#evaluation-of-vulnerabilities)
5. [Prevention Measures](#prevention-measures)
6. [References](#references)
7. [Appendices](#appendices)

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
| Total Issues Identified           | 6                 |
| Critical Issues                   | 0                 |
| High-Risk Issues                  | 0                 |
| Medium-Risk Issues                | 2                 |
| Low-Risk/Informational Issues     | 4                 |


2. Muhammad Afzal Bin Mohd Nor (2123032)

| *Metric*                         | *Value*         |
|----------------------------------|------------------|
| Total Issues Identified          | 15               |
| Critical Issues                  | 0                |
| High-Risk Issues                 | 0                |
| Medium-Risk Issues               | 5                |
| Low-Risk/Informational Issues    | 10               |


3. Muhammad Afiff Firdaus Bin Abdullah (2120573)

| *Metric*                         | *Value*         |
|----------------------------------|------------------|
| Total Issues Identified          | 4                |
| Critical Issues                  | 0                |
| High-Risk Issues                 | 0                |
| Medium-Risk Issues               | 2                |
| Low-Risk/Informational Issues    | 2                |


---
### Key takeaways

| URL              | Key takeaways |
|------------------|--------------|
|(https://hrservice.iium.edu.my) | The scan revealed *2 medium-risk vulnerabilities* that impact client-side security (missing CSP and anti-clickjacking headers). These should be addressed soon. No critical or high-risk issues were found. Two informational findings were also recorded. |
| (http://hrservice.iium.edu.my/apariium) | All three scanned websites showed CSRF-related alerts, indicating a widespread lack of proper CSRF protection across IIUM web applications. This suggests a systemic issue where security measures like CSRF tokens or SameSite cookie attributes are either missing or not properly configured. It highlights the urgent need for developers to implement stronger CSRF defenses to prevent unauthorized actions being performed on behalf of users.|
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
**URL:** https://hrservice.iium.edu.my

| No | Vulnerability                          | Risk       | Affected URL                                | CWE ID  | Description                                                                                   | Suggested Fix                                                                                          |
|----|----------------------------------------|------------|---------------------------------------------|---------|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| 1  | Content Security Policy Header Missing | Medium     | https://hrservice.iium.edu.my/              | CWE-693 | No CSP set in HTTP response, increasing risk of cross-site scripting (XSS).                  | Configure Content-Security-Policy header to restrict allowable sources for scripts and styles.         |
| 2  | Missing Anti-clickjacking Header       | Medium     | https://hrservice.iium.edu.my/              | CWE-1021| No X-Frame-Options or frame-ancestors CSP found.                                               | Use 'X-Frame-Options: DENY' or CSP 'frame-ancestors' to prevent UI redress attacks.                    |
| 3  | Server Leaks Version Information via "Server" HTTP Response Header Field              | Informational | https://hrservice.iium.edu.my/           | CWE-497 | HTTP response reveals the server version, which can assist attackers in targeted exploits.    | Configure server to hide version details using Apache or Nginx directives.                            |
| 4  | Strict-Transport-Security Missing      | Medium     | https://hrservice.iium.edu.my/              | CWE-319 | Lack of HSTS header allows attackers to downgrade HTTPS connections.                         | Set Strict-Transport-Security header to enforce secure communication over HTTPS.                       |
| 5  | X-Content-Type-Options Missing         | Medium     | https://hrservice.iium.edu.my/              | CWE-693  | Without this header, browsers may MIME-sniff responses, leading to execution of malicious files.| Add 'X-Content-Type-Options: nosniff' in the HTTP response headers.                                |
| 6  | Re-examine Cache-control Directives    | Informational | https://hrservice.iium.edu.my/           | CWE-525 | Response headers allow content caching, which may leak sensitive data.                        | Configure cache-control headers to prevent sensitive content from being cached.                       |


2. Muhammad Afzal Bin Mohd Nor (2123032)
URL: http://hrservice.iium.edu.my/apariium

| No | Vulnerability                       | Risk         | Affected URL                                                                                           | CWE ID   | Description                                                                                 | Suggested Fix                                                                 |
|----|-------------------------------------|--------------|----------------------------------------------------------------------------------------------------------|----------|---------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| 1  | CSP Header Not Set                  | Medium (High)| https://cas.iium.edu.my:8448/cas/login?service=https%3A%2F%2Fhrservice.iium.edu.my%2Fapariium%2Flogin%2Fcas | CWE-693 | CSP blocks threats like XSS by controlling which sources browsers can load.                | Configure the server to set the `Content-Security-Policy` header.             |
| 2  | Cross-Domain Misconfiguration       | Medium       | https://fonts.googleapis.com/css?family=Lato,Signika,Courgette                                           | CWE-264 | CORS misconfig may expose data across origins.                                             | Restrict access to trusted domains or use IP whitelisting.                    |
| 3  | Missing Anti-clickjacking Header    | Medium       | https://hrservice.iium.edu.my/                                                                           | CWE-1021 | The site does not prevent Clickjacking via headers.                                        | Add `X-Frame-Options` or `Content-Security-Policy: frame-ancestors`.          |
| 4  | Vulnerable JS Library               | Medium       | https://cas.iium.edu.my:8448/cas/webjars/bootstrap/3.3.7-1/js/bootstrap.min.js                           | CWE-1395 | An outdated JS library was found with known vulnerabilities.                              | Upgrade to the latest version of Bootstrap.                                   |




4. Muhammad Afiff Firdaus Bin Abdullah (2120573)
URL: http://hrservice.iium.edu.my/adm

| No | Vulnerability                               | Risk           | Affected URL                                                                                                           | CWE ID    | Description                                                                                                                    | Suggested Fix                                                                                                  |
|----|---------------------------------------------|----------------|------------------------------------------------------------------------------------------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| 1  | Content Security Policy (CSP) Header Not Set| Medium (High)  | https://hrservice.iium.edu.my/robots.txt                                                                              | CWE-693   | CSP is a security feature that blocks threats like XSS by letting sites control which content sources browsers can load.       | Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header. |
| 2  | Absence of Anti-CSRF Tokens                 | Medium         | http://hrservice.iium.edu.my/adm                                                                                       | CWE-352   | No anti-CSRF tokens detected, making the site vulnerable to cross-site request forgery attacks.                                | Implement anti-CSRF tokens on forms and sensitive actions.                                                     |
| 3  | Session Management Response Identified      | Informational  | https://hrservice.iium.edu.my/adm/                                                                                     | -         | Session management response detected; informational only, but check if session management is secure.                           | Review session management implementation for security best practices.                                           |


---

## Evaluation of Vulnerabilities

URL: https://hrservice.iium.edu.my
- **Content Security Policy (CSP) Header Not Set:** This leaves the site open to XSS attacks by allowing any inline scripts or external sources to be executed.
- **Missing Anti-clickjacking Header:** Without X-Frame-Options or `frame-ancestors`, the site is vulnerable to clickjacking attacks where attackers trick users into interacting with invisible UI elements.
- **Server Version Disclosure:** Revealing the server version can allow attackers to tailor their attacks using known exploits.
- **Strict-Transport-Security Header Missing:** Without HSTS, users could be downgraded from HTTPS to HTTP via MITM attacks.
- **X-Content-Type-Options Missing:** Without this header, browsers might incorrectly guess content types, which could lead to file execution.
- **Cache-control Directives Not Set Properly:** Caching sensitive content might expose user data in shared or public environments.


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

| Vulnerability                              | Recommendation (Code)                                                                                                                                                     | Explanation                                                                                              |
|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| Content Security Policy (CSP) Header Not Set | **Apache**: `Header set Content-Security-Policy "default-src 'self';"`<br>**Express.js**: `app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"] } }))` | CSP restricts what content (e.g., scripts, styles) the browser is allowed to load, preventing XSS risks. |
| Missing Anti-clickjacking Header          | **Apache**: `Header set X-Frame-Options "DENY"`<br>**Express.js**: `app.use(helmet.frameguard({ action: 'deny' }))`                                                         | Prevents clickjacking by blocking your pages from being embedded in iframes.                           |
| Server Version Disclosure via HTTP Header | **Apache**: `ServerTokens Prod` and `ServerSignature Off`<br>**Nginx**: `server_tokens off;`                                                                               | Hides server version to reduce fingerprinting and minimize attack vectors.                             |
| Strict-Transport-Security Header Missing  | **Apache**: `Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"`<br>**Express.js**: `app.use(helmet.hsts({ maxAge: 63072000 }))`     | Enforces HTTPS and prevents protocol downgrade attacks.                                                  |
| X-Content-Type-Options Header Missing     | **Apache**: `Header set X-Content-Type-Options "nosniff"`<br>**Express.js**: `app.use(helmet.noSniff())`                                                                   | Stops browsers from trying to MIME-sniff the content type, reducing XSS risks.                         |
| Re-examine Cache-control Directives       | **Apache**: `Header set Cache-Control "no-store, no-cache, must-revalidate"`                                                                                             | Prevents sensitive content from being cached by browsers or proxies.    

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

## References
1. OWASP Top 10: https://owasp.org/www-project-top-ten/
2. OWASP ZAP: https://owasp.org/www-project-zap/
3. CWE Database: https://cwe.mitre.org/
4. Helmet.js Docs: https://helmetjs.github.io/

---

## Appendices

### Appendix A: ZAP Scan Reports
These are the exported vulnerability scan reports from OWASP ZAP for each assigned system. The reports include detected issues, risk levels, confidence ratings, affected URLs, and recommendations.

**Files Attached (in GitHub repo):**
- [scan-report-hrservice.html](./scan-report-hrservice.html)
- [scan-report-hrservice-apariium.html](./scan-report-hrservice-apariium.html)

---

### Appendix B: Summary of Alerts

#### URL: https://hrservice.iium.edu.my

| Vulnerability                          | Risk Level    | CWE ID   |
|---------------------------------------|---------------|----------|
| Content Security Policy Header Missing| Medium        | CWE-693  |
| Missing Anti-clickjacking Header      | Medium        | CWE-1021 |
| Server Version Disclosure             | Informational | CWE-497  |
| Strict-Transport-Security Missing     | Medium        | CWE-319  |
| X-Content-Type-Options Missing        | Medium        | CWE-693  |
| Cache-Control Insecure Settings       | Informational | CWE-525  |

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

---

### Appendix E: Screenshots

#### URL: https://hrservice.iium.edu.my

Zap Alerts:
![zap Alerts](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Zap-Alerts.png)

Sites Included:
![Sites Included](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Sites%20Included.png)

Risk and Confidence levels:
![Risk and Confidence levels](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Risk%20and%20Confidence%20Levels.png)

Alert counts by risk and confidence:
![Alert counts by risk and confidence)](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Alert%20Counts%20by%20Risk%20and%20Confidence.png)

Alert counts by site and risk:
![Alert counts by site and risk](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Alert%20counts%20by%20site%20and%20risk.png)

Alert counts by alert type:
![Alert counts by alert type)](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Alert%20Counts%20by%20Alert%20Type.png)

Alerts:
![Alerts 1)](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Alerts.png)
![Alerts 2)](https://github.com/Marumar29/CASE-STUDY-EXERCISE/blob/main/images/Screenshot%202025-07-04%20222830.png)



#### URL: http://hrservice.iium.edu.my/apariium

Zap Alerts:

![zap Alerts](https://github.com/user-attachments/assets/abb5ad35-6a31-40ff-8b1c-1eccce0700f4)

Sites Included:

![Sites Included](https://github.com/user-attachments/assets/2648b79f-c72e-4f0a-bbbb-28b0857cfdda)

Risk and Confidence levels:

![Risk and Confidence levels](https://github.com/user-attachments/assets/ab52ead5-48c3-42dd-8e94-a3bf5337ef12)

Alert counts by risk and confidence:

![Alert counts by risk and confidence)](https://github.com/user-attachments/assets/e1dafa6e-10ab-4e08-9e47-a5618015fc8c)

Alert counts by site and risk:

![Alert counts by site and risk](https://github.com/user-attachments/assets/6fc4b5f5-d1b8-4009-8faa-9720fbcf9e85)

Alert counts by alert type:

![Alert counts by alert type)](https://github.com/user-attachments/assets/9c840042-cf86-4f4a-8463-efbff60b459c)

Alerts:

![Alerts 1)](https://github.com/user-attachments/assets/cd5f4740-cad7-4c5e-9c41-246468687e80)

![Alerts 2)](https://github.com/user-attachments/assets/c57ca930-d038-4d64-b826-10f5b1946876)


#### URL: http://hrservice.iium.edu.my/adm
