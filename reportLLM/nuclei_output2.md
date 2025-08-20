
# Nuclei Scan Results for test-target.com

## Findings

### [CVE-2021-41773] - Path Traversal in Apache 2.4.49

- **Template ID:** cve-2021-41773.yaml
- **Severity:** high
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd
- **Description:** Path traversal vulnerability in Apache HTTP Server 2.4.49 allows an attacker to map URLs to files outside the expected document root.

### [wordpress-login-enum] - WordPress Username Enumeration

- **Template ID:** wordpress-username-enumeration.yaml
- **Severity:** medium
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/?author=1
- **Description:** The WordPress application is vulnerable to username enumeration by accessing author archives.

### [exposed-panel] - Exposed Admin Panel

- **Template ID:** exposed-panels.yaml
- **Severity:** high
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/admin/login.php
- **Description:** An administrative panel was discovered, which could be a target for brute-force attacks.

### [tech-detect] - Technology Detected: WordPress

- **Template ID:** tech-detect.yaml
- **Severity:** info
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com
- **Description:** The web server is running WordPress.

### [default-login] - Default Login Location

- **Template ID:** default-logins.yaml
- **Severity:** medium
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/login.php
- **Description:** A default login page was found. These are common targets for credential stuffing.
