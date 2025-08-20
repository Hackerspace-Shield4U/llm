# Nuclei Scan Results for wordpress-site.org

## Summary

| ID | Name | Host | Severity |
|---|---|---|---|
| wp-user-enum | WordPress Username Enumeration | https://wordpress-site.org | medium |
| wp-xmlrpc | WordPress XML-RPC Enabled | https://wordpress-site.org | medium |
| wp-backup-disclosure | WordPress Backup File Disclosure | https://wordpress-site.org | high |

## Findings

### [wp-user-enum] - WordPress Username Enumeration

- **Template ID:** wordpress-username-enumeration.yaml
- **Severity:** medium
- **Host:** https://wordpress-site.org
- **Matched At:** https://wordpress-site.org/?author=1
- **Tags:** wordpress,wp,recon
- **Description:** The WordPress application is vulnerable to username enumeration by accessing author archives.

### [wp-xmlrpc] - WordPress XML-RPC Enabled

- **Template ID:** wordpress-xmlrpc.yaml
- **Severity:** medium
- **Host:** https://wordpress-site.org
- **Matched At:** https://wordpress-site.org/xmlrpc.php
- **Tags:** wordpress,wp,xmlrpc
- **Description:** WordPress XML-RPC is enabled. This can be abused for brute-force attacks or DDoS amplification.

### [wp-backup-disclosure] - WordPress Backup File Disclosure

- **Template ID:** wordpress-backup-files.yaml
- **Severity:** high
- **Host:** https://wordpress-site.org
- **Matched At:** https://wordpress-site.org/wp-config.php.bak
- **Tags:** wordpress,wp,exposure,backup
- **Description:** A WordPress backup file (wp-config.php.bak) was found, which may contain database credentials and other sensitive information.