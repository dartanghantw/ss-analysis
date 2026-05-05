Red team scanner project.

This project is a small cli library that can be used by a security expert to identity possible breaches in a given network-based system.

# Command
ss-analysis: This is the base command line that will execute the CLI. All output will be always a table with the information gathered

## surface subcommand: Just check open ports of a given host or ip, requires a DNS name or an IP to start the scanning. Only shows the base open ports and if they are using UDP TCP or other protocol.

### Option --http: Analyse all ports and try to identify if the port is a REST port expecting HTTP requests.

### Option --check: Perform a validation of the following checks on the HTTP/HTTPS ports

# HTTP/HTTPS Vulnerability Checklist

## Transport / TLS
- [ ] SSL/TLS outdated versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
- [ ] Weak cipher suites (RC4, DES, 3DES, NULL)
- [ ] BEAST — CBC cipher attack on TLS 1.0
- [ ] POODLE — Padding oracle on SSLv3
- [ ] DROWN — SSLv2 decryption of TLS traffic
- [ ] CRIME / BREACH — Compression-based info leak
- [ ] HEARTBLEED — OpenSSL memory disclosure (CVE-2014-0160)
- [ ] ROBOT — RSA PKCS#1 padding oracle
- [ ] Weak DH params — Logjam (keys < 2048 bits)
- [ ] Certificate expired / self-signed
- [ ] Missing HSTS header
- [ ] HTTP downgrade — HTTPS server accepts plain HTTP
- [ ] Mixed content — HTTPS page loading HTTP resources

## HTTP Headers
- [ ] Missing X-Frame-Options — Clickjacking
- [ ] Missing Content-Security-Policy — XSS / data injection
- [ ] Missing X-Content-Type-Options — MIME sniffing
- [ ] Missing Referrer-Policy — Info leakage
- [ ] Missing Permissions-Policy — Browser feature abuse
- [ ] Missing X-XSS-Protection
- [ ] Server header exposed — Version fingerprinting
- [ ] X-Powered-By exposed — Tech stack disclosure
- [ ] CORS misconfiguration — Access-Control-Allow-Origin: *
- [ ] Cookie missing Secure flag
- [ ] Cookie missing HttpOnly flag
- [ ] Cookie missing SameSite attribute

## Authentication & Session
- [ ] Brute force — No rate limiting on login
- [ ] Credential stuffing — No account lockout
- [ ] Weak password policy
- [ ] Default credentials (admin/admin, admin/password)
- [ ] Session fixation — Reuses session ID after login
- [ ] Session not invalidated after logout
- [ ] JWT none algorithm accepted
- [ ] JWT weak secret — Brute-forceable HS256
- [ ] JWT algorithm confusion — RS256 to HS256 downgrade
- [ ] Missing MFA on sensitive endpoints
- [ ] Predictable tokens — Sequential or weak random IDs
- [ ] OAuth misconfiguration — Open redirect in redirect_uri

## Injection
- [ ] SQL injection — ' OR 1=1--
- [ ] Blind SQL injection — Time-based / boolean-based
- [ ] NoSQL injection — MongoDB operator injection
- [ ] Command injection — ; ls, | whoami
- [ ] LDAP injection
- [ ] XPath injection
- [ ] Server-Side Template Injection (SSTI) — {{7*7}}
- [ ] XML External Entity (XXE)
- [ ] HTTP header injection — CRLF (\r\n)
- [ ] Log injection — Fake log entries

## Cross-Site
- [ ] XSS Reflected — <script> in URL params
- [ ] XSS Stored — Persisted malicious script
- [ ] XSS DOM-based — Client-side JS manipulation
- [ ] CSRF — Forged cross-site requests
- [ ] SSRF — Server fetches attacker-controlled URL
- [ ] Blind SSRF — No direct response but backend reaches out
- [ ] Open Redirect — redirect=https://evil.com
- [ ] Clickjacking — iframe embedding attack

## Authorization
- [ ] IDOR — Access other users' objects by ID
- [ ] Broken object level authorization
- [ ] Privilege escalation — Horizontal / vertical
- [ ] Mass assignment — Unfiltered JSON body overwrites fields
- [ ] Path traversal — ../../etc/passwd
- [ ] Forced browsing — Accessing unlinked pages
- [ ] BOLA — Broken Object Level Authorization (API)

## HTTP Protocol
- [ ] HTTP Request Smuggling — CL.TE / TE.CL desync
- [ ] HTTP Response Splitting — CRLF in headers
- [ ] HTTP Method tampering — PUT/DELETE/TRACE enabled
- [ ] TRACE method enabled — Cross-Site Tracing (XST)
- [ ] OPTIONS exposes allowed methods
- [ ] Cache poisoning — Via headers
- [ ] Cache deception — Trick cache into storing private data
- [ ] Host header injection
- [ ] X-Forwarded-For injection — Bypass IP controls

## Information Disclosure
- [ ] Directory listing enabled
- [ ] .git exposed — /.git/config publicly accessible
- [ ] .env exposed — Leaks credentials
- [ ] Stack traces in error responses
- [ ] Backup files accessible (.bak, .old, .swp)
- [ ] API docs exposed (/swagger.json, /openapi.yaml)
- [ ] Debug endpoints accessible (/debug, /actuator, /metrics)
- [ ] Source code disclosure (.php~, .asp.bak)
- [ ] Verbose 404/500 — Reveals internal paths

## Denial of Service
- [ ] No rate limiting on endpoints
- [ ] Slowloris — Keeps connections open indefinitely
- [ ] ReDoS — Regex denial of service
- [ ] Large payload — No max body size enforcement
- [ ] XML bomb — Billion laughs attack
- [ ] ZIP bomb — Compressed payload explosion
- [ ] Resource exhaustion via complex queries

## API Specific
- [ ] GraphQL introspection enabled
- [ ] GraphQL batching attack
- [ ] Mass assignment — Extra fields accepted silently
- [ ] Excessive data exposure — API returns more than needed
- [ ] Broken API versioning — Old versions still active
- [ ] Missing pagination — Returns all records without limit

