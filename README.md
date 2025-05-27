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
| Maru | 1234567   | Scanned (http://hrservice.iium.edu.my/adm) using OWASP ZAP |

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
| 1 | Cross-Domain Misconfiguration | Medium | (https://fonts.googleapis.com/css%3Ffamily=Lato:700,400,300,100%257CSignika:400,700%257CCourgette) | CWE-264 | Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server. | Ensure that sensitive data is not available in an unauthenticated manner |
| 2 | Missing Anti-clickjacking Header | Medium | (https://hrservice.iium.edu.my/) | CWE-1021 | The response does not protect against 'ClickJacking' attacks | Ensure one the Modern Web Browser supports the Content-Security-Policy and X-Frame-Options HTTP headers of them is set on all web pages returned by your site/app |
| 3 | Vulnerable JS Library | Medium | (https://nvd.nist.gov/vuln/detail/CVE-2024-6485) | CWE-1395 | The identified library appears to be vulnerable. | Upgrade to the latest version of the affected library. |
| 4 | Information Disclosure - Sensitive Information in URL | Medium(Informational) | (https://hrservice.iium.edu.my/adm/j_spring_cas_security_check%3Fticket=ST-1228398-Y4HU63-WgweM2Nt-6wFTebR-QJs-cas1) | CWE-598 | he request appeared to contain sensitive information leaked in the URL. | Do not pass sensitive information in URIs |




2. A
URL:

3. A
URL:



---

## Evaluation of Vulnerabilities
URL: https://hrservice.iium.edu.my/
- Cross-Domain Misconfiguration: This could allow attackers to load or manipulate external resources
- Missing Anti-clickjacking Header: Without X-Frame-Options or Content-Security-Policy, the site is vulnerable to clickjacking attacks — tricking users into clicking hidden elements embedded via iframes. This is a common and preventable issue.
- Vulnerable JavaScript Library: Usage of an outdated JS library (linked to a known CVE) can open the application to a wide range of exploits including XSS or logic manipulation, depending on the vulnerability. This is a serious issue if the library is actively used.
- Information Disclosure in URL: 	Sensitive tokens in URLs are risky because they may be logged in browser history or server logs. In the worst case, a leaked token could allow session hijacking or unauthorized access.


URL: 
URL: 

---

## Prevention Measures
URL: https://hrservice.iium.edu.my/
| Vulnerability                 | Recommendation                                  |
|-------------------------------|-------------------------------------------------|
| Cross-Domain Misconfiguration | Limit cross-origin access using strict CORS rules. Do not allow unauthenticated or public domains to load critical resources. |
| Missing Anti-clickjacking Header | Implement one of the following HTTP headers: X-Frame-Options: DENY or SAMEORIGIN, Content-Security-Policy: frame-ancestors 'none'; |
| Vulnerable JS Library | Check which library is affected (e.g., jQuery, Bootstrap). Update to the latest version after verifying compatibility. Avoid using unsupported or unmaintained libraries. |
| Information Disclosure in URL | Move sensitive tokens (e.g., session tickets) into secure HTTP headers or encrypted cookies instead of placing them in GET URLs. Also consider using POST for secure data exchange. |

URL:
| Vulnerability                 | Recommendation                                  |
|-------------------------------|-------------------------------------------------|
|                               |                                                 |

URL: 
| Vulnerability                 | Recommendation                                  |
|-------------------------------|-------------------------------------------------|
|                               |                                                 |

---

## List of Figures


---

## List of Tables


---

## References
1. OWASP Top 10
2. https://owasp.org/www-project-zap/
3. CWE Database: https://cwe.mitre.org/

