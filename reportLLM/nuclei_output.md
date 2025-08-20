# Nuclei Scan Results for test-target.com

## Summary

| ID | Name | Host | Severity |
|---|---|---|---|
| exposed-panels | Exposed Admin Panel | https://test-target.com | high |
| wordpress-login-enum | WordPress Username Enumeration | https://test-target.com | medium |
| wordpress-version | WordPress Version Detected | https://test-target.com | info |
| wp-json-api | WordPress WP-JSON API Enabled | https://test-target.com | info |

## Findings

### [exposed-panels] - Exposed Admin Panel

- **Template ID:** exposed-panels.yaml
- **Severity:** high
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/admin/login.php
- **Tags:** tech,panel,login
- **Description:** An administrative panel was discovered at `/admin/login.php`. These are often targeted for brute-force attacks.

### [wordpress-login-enum] - WordPress Username Enumeration

- **Template ID:** wordpress-username-enumeration.yaml
- **Severity:** medium
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/?author=1
- **Tags:** wordpress,wp,cve,recon
- **Description:** The WordPress application is vulnerable to username enumeration by accessing author archives. An attacker can discover valid usernames.

### [wordpress-version] - WordPress Version Detected

- **Template ID:** wordpress-version-detection.yaml
- **Severity:** info
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/feed/
- **Tags:** tech,wordpress,wp
- **Description:** WordPress version 6.2.1 was detected. Outdated versions can have known vulnerabilities.

### [wp-json-api] - WordPress WP-JSON API Enabled

- **Template ID:** wp-json-api.yaml
- **Severity:** info
- **Host:** https://test-target.com
- **Matched At:** https://test-target.com/wp-json/
- **Tags:** wordpress,wp,api
- **Description:** The WordPress WP-JSON API is enabled, which can expose user data and other information if not properly configured.