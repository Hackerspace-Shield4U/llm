# Analyze LLM

### requirements
- openai>=1.0.0
- pydantic>=1.10.0
- pyyaml>=6.0

### input example
```
  {
  "url": "https://target.example.com/login",
  "dom": {
    "title": "Admin Login",
    "meta": {
      "generator": "WordPress 6.5.3"
    },
    "scripts": [
      "/wp-includes/js/jquery.js",
      "/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9"
    ],
    "links": [
      "/wp-content/themes/twentytwenty/style.css?ver=2.6"
    ],
    "comments_or_text_leaks": [
      {"type": "api_key", "snippet": "API_KEY=AIzaSy..."},
      {"type": "debug",   "snippet": "DEBUG=true"},
      {"type": "stack",   "snippet": "PHP Warning: ..."}
    ],
    "forms": [
      {
        "action": "/login",
        "method": "POST",
        "enctype": "application/x-www-form-urlencoded",
        "inputs": ["username", "password", "csrf_token"]
      }
    ],
    "visible_links": [
      "/admin", "/wp-login.php", "/.git/"
    ],
    "visible_text_sample": "© 2025 Example Inc. Powered by WordPress"
  },

  "fingerprints": {
    "cms": ["wordpress 6.5.3"],
    "plugins": [
      {"name": "contact-form-7", "version": "5.9"}
    ],
    "tech": ["jquery", "php", "apache?"]  // 물음표는 약한 신호
  },

  "panel_login_signals": {
    "is_admin_like": true,
    "candidates": ["/admin", "/login", "/wp-login.php"]
  },

  "osint_exposure": {
    "emails": ["sec@example.com"],
    "phones": [],
    "socials": ["https://twitter.com/acme"],
    "open_directory_ui": ["/public/"],
    "cloud_links": ["https://s3.amazonaws.com/bucket-name/"]
  }

}
```

### output example
```
[
  {
    "tag": "panel",
    "confidence": "high",
    "reason": "로그인 폼(action=/login)과 관리자 문구 확인",
    "targets": ["https://target.example.com/login", "https://target.example.com/admin"],
    "suggested_templates": ["tags:panel", "tags:login"]
  },
  {
    "tag": "wordpress",
    "confidence": "high",
    "reason": "meta.generator=WordPress 6.5.3, /wp-content/ 경로 존재",
    "targets": ["https://target.example.com/"],
    "suggested_templates": ["tags:wordpress", "tags:wp", "tags:wp-plugin"]
  },
  {
    "tag": "exposure",
    "confidence": "high",
    "reason": "HTML 주석에 API_KEY 노출",
    "targets": ["https://target.example.com/"],
    "evidence": [{"type": "api_key", "snippet": "API_KEY=AIzaSy***"}],
    "suggested_templates": ["tags:exposure", "tags:info-leak"]
  },
  {
    "tag": "tech",
    "confidence": "medium",
    "reason": "jQuery, theme, plugin 버전 노출",
    "targets": ["https://target.example.com/"],
    "suggested_templates": ["tags:tech"]
  },
  {
    "tag": "osint",
    "confidence": "high",
    "reason": "푸터에 보안 연락 이메일, 트위터 링크",
    "targets": ["https://target.example.com/contact"],
    "evidence": {"emails": ["sec@example.com"], "socials": ["https://twitter.com/acme"]},
    "suggested_templates": ["tags:osint", "tags:osint-social"]
  }
]
```
