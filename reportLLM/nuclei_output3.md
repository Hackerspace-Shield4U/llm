# Nuclei Scan Results for demo-target.com

## Summary

| ID | Name | Host | Severity |
|---|---|---|---|
| exposed-git | Exposed .git Repository | https://demo-target.com | high |
| generic-sqli | Possible SQL Injection (Boolean-Based) | https://demo-target.com | high |
| dir-listing | Directory Listing Enabled | https://demo-target.com | medium |
| cors-misconfig | CORS Misconfiguration | https://demo-target.com | medium |
| clickjack | Clickjacking (Missing X-Frame-Options) | https://demo-target.com | medium |
| server-version | Server Version Disclosure | https://demo-target.com | info |

## Findings

### [exposed-git] - Exposed .git Repository
- **Template ID:** exposed-git-config.yaml  
- **Severity:** high  
- **Host:** https://demo-target.com  
- **Matched At:** https://demo-target.com/.git/HEAD  
- **Tags:** git,leak,source,tech  
- **Description:** 원격에서 `.git/` 디렉터리에 접근 가능하여 커밋 이력/소스 유출 위험이 있음. 공격자는 코드/비밀키/경로 정보를 추출할 수 있음.

---

### [generic-sqli] - Possible SQL Injection (Boolean-Based)
- **Template ID:** sql-injection-boolean-based.yaml  
- **Severity:** high  
- **Host:** https://demo-target.com  
- **Matched At:** https://demo-target.com/products?id=10%20AND%201=1  
- **Tags:** sqli,inj,web,tech  
- **Description:** `id` 파라미터에 Boolean 기반 SQLi 의심 반응이 관찰됨. 인증 우회, 데이터베이스 덤프 등 심각한 영향 가능.

---

### [dir-listing] - Directory Listing Enabled
- **Template ID:** apache-directory-listing.yaml  
- **Severity:** medium  
- **Host:** https://demo-target.com  
- **Matched At:** https://demo-target.com/uploads/  
- **Tags:** dirlisting,misconfig,apache,web  
- **Description:** 디렉터리 인덱싱이 활성화되어 파일 목록이 노출됨. 내부 파일 구조/백업/스크립트가 노출될 수 있음.

---

### [cors-misconfig] - CORS Misconfiguration
- **Template ID:** cors-misconfig.yaml  
- **Severity:** medium  
- **Host:** https://demo-target.com  
- **Matched At:** https://demo-target.com/api/profile (Access-Control-Allow-Origin: *)  
- **Tags:** cors,misconfig,api,web  
- **Description:** 와일드카드 CORS 허용으로 잠재적 크로스도메인 데이터 접근 위험. 토큰 탈취/민감 정보 노출 가능.

