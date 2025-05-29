# IIUM Web Application Security Report
Case Study Report

Web Application Security
INFO 4345

Dr. MUHAMAD SADRY ABU SEMAN

---

## Group Name: Group Last
---
### Group Members
| Name              | Matric No | Task                                                  |
|-------------------|-----------|-------------------------------------------------------|
| Raja Muhamad Umar | 2119191   | Scanned (https://hrservice.iium.edu.my using) OWASP ZAP |
| Muhammad Afzal | 2123023   | Scanned (http://hrservice.iium.edu.my/apariium) using OWASP ZAP |
| Muhammad Afiff Firdaus | 2120573   | Scanned (http://hrservice.iium.edu.my/adm) using OWASP ZAP |

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

## Prevention Measures
URL: https://hrservice.iium.edu.my/
| Vulnerability                 | Recommendation                                  |
|-------------------------------|-------------------------------------------------|
| Cross-Domain Misconfiguration | Limit cross-origin access using strict CORS rules. Do not allow unauthenticated or public domains to load critical resources. |
| Missing Anti-clickjacking Header | Implement one of the following HTTP headers: X-Frame-Options: DENY or SAMEORIGIN, Content-Security-Policy: frame-ancestors 'none'; |
| Vulnerable JS Library | Check which library is affected (e.g., jQuery, Bootstrap). Update to the latest version after verifying compatibility. Avoid using unsupported or unmaintained libraries. |
| Information Disclosure in URL | Move sensitive tokens (e.g., session tickets) into secure HTTP headers or encrypted cookies instead of placing them in GET URLs. Also consider using POST for secure data exchange. |

URL: http://hrservice.iium.edu.my/apariium
| Vulnerability                 | Recommendation                                  |
|-------------------------------|-------------------------------------------------|
| Content Security Policy (CSP) Header Not Set | Add a CSP header to control which sources the browser is allowed to load content from. This helps prevent cross-site scripting and code injection attacks. |
| Cross-Domain Misconfiguration | Limit access to your site’s resources by only allowing trusted domains. Avoid using wildcards (*) in cross-origin settings. |
| Missing Anti-clickjacking Header | Use security headers like X-Frame-Options or Content-Security-Policy to prevent your site from being embedded in other pages, which protects against clickjacking. |
| Vulnerable JS Library | Keep all JavaScript libraries up to date. Remove unused ones and avoid using versions with known security issues. |

URL: http://hrservice.iium.edu.my/adm
| Vulnerability                 | Recommendation                                  |
|-------------------------------|-------------------------------------------------|
| Content Security Policy (CSP) Header Not Set| Add a CSP header to control which sources the browser is allowed to load content from. This helps prevent cross-site scripting and code injection attacks. |
| Cross-Domain Misconfiguration              | Limit access to your site’s resources by only allowing trusted domains. Avoid using wildcards (*) in cross-origin settings.               |
| Missing Anti-clickjacking Header            | Use security headers like X-Frame-Options or Content-Security-Policy to prevent your site from being embedded in other pages, which protects against clickjacking. |
| Vulnerable JS Library                       | Keep all JavaScript libraries up to date. Remove unused ones and avoid using versions with known security issues.                        |


---

## List of Figures


---

## List of Tables


---

## References
1. OWASP Top 10
2. https://owasp.org/www-project-zap/
3. CWE Database: https://cwe.mitre.org/

