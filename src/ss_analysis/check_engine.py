from __future__ import annotations

import re
from dataclasses import dataclass

from ss_analysis.http_context import HttpCheckContext


@dataclass(frozen=True)
class CheckResult:
    category: str
    item: str
    status: str
    notes: str


def _weak_cipher(name: str | None) -> bool:
    if not name:
        return False
    n = name.upper()
    return any(x in n for x in ("RC4", "DES-CBC", "NULL", "3DES", "EXPORT", "IDEA", "ADH", "AECDH"))


def _tls_outdated(ver: str | None) -> bool:
    if not ver:
        return False
    return ver in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _beast_risk(ver: str | None, cipher: str | None) -> bool:
    return ver == "TLSv1" and cipher is not None and "CBC" in cipher.upper()


def _cookie_flags(set_cookie_lines: list[str]) -> tuple[bool | None, bool | None, bool | None]:
    if not set_cookie_lines:
        return None, None, None
    miss_s = miss_h = miss_ss = False
    for line in set_cookie_lines:
        low = line.lower()
        if "secure" not in low:
            miss_s = True
        if "httponly" not in low:
            miss_h = True
        if "samesite" not in low:
            miss_ss = True
    return miss_s, miss_h, miss_ss


def _header_present(h: dict[str, str], name: str) -> bool:
    return bool(h.get(name.lower()))


def _cors_star(h: dict[str, str]) -> bool:
    acao = h.get("access-control-allow-origin", "").strip()
    return acao == "*"


def _server_version_exposed(server: str) -> bool:
    if not server:
        return False
    return bool(re.search(r"\d+\.\d+", server))


def _mixed_http_urls(body: str) -> bool:
    if not body:
        return False
    return bool(re.search(r'=["\']?http://', body, re.I))


def _directory_listing(body: str) -> bool:
    b = body.lower()
    return "index of /" in b or "<title>index of" in b


def _stack_trace_hint(body: str) -> bool:
    b = body.lower()
    return "traceback" in b or "exception in thread" in b or "nested exception" in b


def _verbose_error_paths(status_line: str, body: str) -> bool:
    if not status_line:
        return False
    m = re.match(r"HTTP/\d\.\d\s+(4\d\d|5\d\d)", status_line)
    if not m:
        return False
    return any(x in body for x in ("/var/", "/usr/", "C:\\", "D:\\", "/home/", 'File "'))


def _graphql_batching_hint(h: dict[str, str]) -> bool:
    return "application/batch+json" in h.get("content-type", "").lower()


def run_checklist(ctx: HttpCheckContext) -> list[CheckResult]:
    h = ctx.headers_lower
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    allow = (ctx.options_allow or "").upper()
    miss_secure, miss_httponly, miss_samesite = _cookie_flags(ctx.set_cookie_lines)

    git_head = ctx.path_probes.get("/.git/HEAD", (0, ""))
    git_cfg = ctx.path_probes.get("/.git/config", (0, ""))
    dot_env = ctx.path_probes.get("/.env", (0, ""))
    swagger = ctx.path_probes.get("/swagger.json", (0, ""))
    openapi_j = ctx.path_probes.get("/openapi.json", (0, ""))
    openapi_y = ctx.path_probes.get("/openapi.yaml", (0, ""))
    api_docs = ctx.path_probes.get("/v3/api-docs", (0, ""))
    debug_p = ctx.path_probes.get("/debug/", (0, ""))
    actuator = ctx.path_probes.get("/actuator/", (0, ""))
    metrics = ctx.path_probes.get("/metrics", (0, ""))

    def ok_git(c: tuple[int, str]) -> bool:
        code, snip = c
        if code != 200:
            return False
        s = snip.lower()
        return "ref:" in s or "[core]" in s or "repositoryformatversion" in s

    rows: list[CheckResult] = []

    def add(cat: str, item: str, status: str, notes: str = "") -> None:
        rows.append(CheckResult(cat, item, status, notes))

    if not ctx.used_tls:
        add("Transport / TLS", "SSL/TLS outdated versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)", "n/a", "Cleartext HTTP")
        add("Transport / TLS", "Weak cipher suites (RC4, DES, 3DES, NULL)", "n/a", "No TLS on this binding")
        add("Transport / TLS", "BEAST — CBC cipher attack on TLS 1.0", "n/a", "")
        add("Transport / TLS", "POODLE — Padding oracle on SSLv3", "n/a", "")
        add("Transport / TLS", "DROWN — SSLv2 decryption of TLS traffic", "manual", "Requires SSLv2 endpoint tests")
        add("Transport / TLS", "CRIME / BREACH — Compression-based info leak", "n/a", "")
        add("Transport / TLS", "HEARTBLEED — OpenSSL memory disclosure (CVE-2014-0160)", "manual", "Not probed (intrusive)")
        add("Transport / TLS", "ROBOT — RSA PKCS#1 padding oracle", "manual", "Not probed (intrusive)")
        add("Transport / TLS", "Weak DH params — Logjam (keys < 2048 bits)", "manual", "DH strength not parsed here")
        add("Transport / TLS", "Certificate expired / self-signed", "n/a", "No TLS on this binding")
        add("Transport / TLS", "Missing HSTS header", "n/a", "Not HTTPS")
        add("Transport / TLS", "HTTP downgrade — HTTPS server accepts plain HTTP", "manual", "Probe port 80 separately")
        add("Transport / TLS", "Mixed content — HTTPS page loading HTTP resources", "n/a", "Not HTTPS")
    else:
        tv = ctx.tls_version or "unknown"
        tc = ctx.tls_cipher or "unknown"
        add(
            "Transport / TLS",
            "SSL/TLS outdated versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)",
            "fail" if _tls_outdated(ctx.tls_version) else "pass",
            f"Negotiated: {tv}",
        )
        add(
            "Transport / TLS",
            "Weak cipher suites (RC4, DES, 3DES, NULL)",
            "fail" if _weak_cipher(ctx.tls_cipher) else "pass",
            tc,
        )
        add(
            "Transport / TLS",
            "BEAST — CBC cipher attack on TLS 1.0",
            "fail" if _beast_risk(ctx.tls_version, ctx.tls_cipher) else "pass",
            tv,
        )
        add(
            "Transport / TLS",
            "POODLE — Padding oracle on SSLv3",
            "pass" if ctx.tls_version != "SSLv3" else "fail",
            tv,
        )
        add("Transport / TLS", "DROWN — SSLv2 decryption of TLS traffic", "manual", "SSLv2 not exercised")
        comp = ctx.tls_compression or "none"
        comp_risk = comp not in ("none", "", None)
        add(
            "Transport / TLS",
            "CRIME / BREACH — Compression-based info leak",
            "fail" if comp_risk else "pass",
            f"compression={comp}",
        )
        add("Transport / TLS", "HEARTBLEED — OpenSSL memory disclosure (CVE-2014-0160)", "manual", "Use dedicated TLS scanner")
        add("Transport / TLS", "ROBOT — RSA PKCS#1 padding oracle", "manual", "Use dedicated TLS scanner")
        add("Transport / TLS", "Weak DH params — Logjam (keys < 2048 bits)", "manual", "Cipher: " + tc)
        if ctx.cert_expired is True:
            add("Transport / TLS", "Certificate expired / self-signed", "fail", "Expired; notAfter=" + str(ctx.cert_not_after))
        elif ctx.cert_self_signed is True:
            add("Transport / TLS", "Certificate expired / self-signed", "warn", "Self-signed / issuer==subject")
        elif ctx.cert_expired is False and ctx.cert_self_signed is False:
            add("Transport / TLS", "Certificate expired / self-signed", "pass", str(ctx.cert_not_after or ""))
        else:
            add("Transport / TLS", "Certificate expired / self-signed", "warn", "Could not read certificate")
        add(
            "Transport / TLS",
            "Missing HSTS header",
            "fail" if not _header_present(h, "strict-transport-security") else "pass",
            "",
        )
        add("Transport / TLS", "HTTP downgrade — HTTPS server accepts plain HTTP", "manual", "Probe cleartext port separately")
        add(
            "Transport / TLS",
            "Mixed content — HTTPS page loading HTTP resources",
            "fail" if _mixed_http_urls(ctx.body_sample) else "pass",
            "Heuristic on GET / body",
        )

    add(
        "HTTP Headers",
        "Missing X-Frame-Options — Clickjacking",
        "fail"
        if not _header_present(h, "x-frame-options") and not _header_present(h, "content-security-policy")
        else "pass",
        "CSP frame-ancestors can substitute",
    )
    add(
        "HTTP Headers",
        "Missing Content-Security-Policy — XSS / data injection",
        "fail" if not _header_present(h, "content-security-policy") else "pass",
        "",
    )
    add(
        "HTTP Headers",
        "Missing X-Content-Type-Options — MIME sniffing",
        "fail" if not _header_present(h, "x-content-type-options") else "pass",
        "",
    )
    add(
        "HTTP Headers",
        "Missing Referrer-Policy — Info leakage",
        "warn" if not _header_present(h, "referrer-policy") else "pass",
        "",
    )
    add(
        "HTTP Headers",
        "Missing Permissions-Policy — Browser feature abuse",
        "warn" if not _header_present(h, "permissions-policy") and not _header_present(h, "feature-policy") else "pass",
        "",
    )
    add(
        "HTTP Headers",
        "Missing X-XSS-Protection",
        "warn" if not _header_present(h, "x-xss-protection") else "pass",
        "Header deprecated; listed per PROJECT.md",
    )
    add(
        "HTTP Headers",
        "Server header exposed — Version fingerprinting",
        "warn" if _server_version_exposed(server) else ("pass" if not server else "warn"),
        server[:80] if server else "(absent)",
    )
    add(
        "HTTP Headers",
        "X-Powered-By exposed — Tech stack disclosure",
        "fail" if powered else "pass",
        powered[:80] if powered else "",
    )
    add(
        "HTTP Headers",
        "CORS misconfiguration — Access-Control-Allow-Origin: *",
        "fail" if _cors_star(h) else "pass",
        h.get("access-control-allow-origin", "")[:60],
    )
    if ctx.set_cookie_lines:
        add(
            "HTTP Headers",
            "Cookie missing Secure flag",
            "fail" if miss_secure else "pass",
            f"{len(ctx.set_cookie_lines)} Set-Cookie",
        )
        add("HTTP Headers", "Cookie missing HttpOnly flag", "fail" if miss_httponly else "pass", "")
        add("HTTP Headers", "Cookie missing SameSite attribute", "warn" if miss_samesite else "pass", "")
    else:
        add("HTTP Headers", "Cookie missing Secure flag", "n/a", "No Set-Cookie on GET /")
        add("HTTP Headers", "Cookie missing HttpOnly flag", "n/a", "")
        add("HTTP Headers", "Cookie missing SameSite attribute", "n/a", "")

    auth_items = (
        "Brute force — No rate limiting on login",
        "Credential stuffing — No account lockout",
        "Weak password policy",
        "Default credentials (admin/admin, admin/password)",
        "Session fixation — Reuses session ID after login",
        "Session not invalidated after logout",
        "JWT none algorithm accepted",
        "JWT weak secret — Brute-forceable HS256",
        "JWT algorithm confusion — RS256 to HS256 downgrade",
        "Missing MFA on sensitive endpoints",
        "Predictable tokens — Sequential or weak random IDs",
        "OAuth misconfiguration — Open redirect in redirect_uri",
    )
    for it in auth_items:
        add("Authentication & Session", it, "manual", "Requires authenticated flows")

    inj = (
        "SQL injection — ' OR 1=1--",
        "Blind SQL injection — Time-based / boolean-based",
        "NoSQL injection — MongoDB operator injection",
        "Command injection — ; ls, | whoami",
        "LDAP injection",
        "XPath injection",
        "Server-Side Template Injection (SSTI) — {{7*7}}",
        "XML External Entity (XXE)",
        "HTTP header injection — CRLF (\\r\\n)",
        "Log injection — Fake log entries",
    )
    for it in inj:
        add("Injection", it, "manual", "Not actively fuzzed")

    xs = (
        "XSS Reflected — <script> in URL params",
        "XSS Stored — Persisted malicious script",
        "XSS DOM-based — Client-side JS manipulation",
        "CSRF — Forged cross-site requests",
        "SSRF — Server fetches attacker-controlled URL",
        "Blind SSRF — No direct response but backend reaches out",
        "Open Redirect — redirect=https://evil.com",
    )
    for it in xs:
        add("Cross-Site", it, "manual", "Not actively fuzzed")

    add(
        "Cross-Site",
        "Clickjacking — iframe embedding attack",
        "fail"
        if not _header_present(h, "x-frame-options") and not _header_present(h, "content-security-policy")
        else "pass",
        "Framing headers",
    )

    authz = (
        "IDOR — Access other users' objects by ID",
        "Broken object level authorization",
        "Privilege escalation — Horizontal / vertical",
        "Mass assignment — Unfiltered JSON body overwrites fields",
        "Path traversal — ../../etc/passwd",
        "Forced browsing — Accessing unlinked pages",
        "BOLA — Broken Object Level Authorization (API)",
    )
    for it in authz:
        add("Authorization", it, "manual", "Not actively fuzzed")

    allow_tokens = [p.strip() for p in re.split(r"[,\s]+", allow) if p.strip()] if allow else []
    trace_on = "TRACE" in allow_tokens
    put_del = any(p in ("PUT", "DELETE", "CONNECT") for p in allow_tokens)
    add("HTTP Protocol", "HTTP Request Smuggling — CL.TE / TE.CL desync", "manual", "Requires specialized tests")
    add("HTTP Protocol", "HTTP Response Splitting — CRLF in headers", "manual", "")
    add(
        "HTTP Protocol",
        "HTTP Method tampering — PUT/DELETE/TRACE enabled",
        "warn" if (put_del or trace_on) else "pass",
        f"Allow: {allow[:120] if allow else '(none)'}",
    )
    add(
        "HTTP Protocol",
        "TRACE method enabled — Cross-Site Tracing (XST)",
        "fail" if trace_on else "pass",
        allow[:120] if allow else "",
    )
    add(
        "HTTP Protocol",
        "OPTIONS exposes allowed methods",
        "warn" if allow and len(allow) > 40 else "pass",
        "Verbose Allow header",
    )
    add("HTTP Protocol", "Cache poisoning — Via headers", "manual", "")
    add("HTTP Protocol", "Cache deception — Trick cache into storing private data", "manual", "")
    add("HTTP Protocol", "Host header injection", "manual", "")
    add("HTTP Protocol", "X-Forwarded-For injection — Bypass IP controls", "manual", "")

    add(
        "Information Disclosure",
        "Directory listing enabled",
        "fail" if _directory_listing(ctx.body_sample) else "pass",
        "GET / heuristic",
    )
    add(
        "Information Disclosure",
        ".git exposed — /.git/config publicly accessible",
        "fail" if ok_git(git_head) or ok_git(git_cfg) else "pass",
        f"HEAD {git_head[0]} config {git_cfg[0]}",
    )
    add(
        "Information Disclosure",
        ".env exposed — Leaks credentials",
        "fail" if dot_env[0] == 200 and "=" in dot_env[1] else "pass",
        f"HTTP {dot_env[0]}",
    )
    add(
        "Information Disclosure",
        "Stack traces in error responses",
        "fail" if _stack_trace_hint(ctx.body_sample) else "pass",
        "",
    )
    add("Information Disclosure", "Backup files accessible (.bak, .old, .swp)", "manual", "Not exhaustively crawled")
    exposed_docs = (
        (swagger[0] == 200 and "swagger" in swagger[1].lower())
        or (openapi_j[0] == 200 and ("openapi" in openapi_j[1].lower() or "paths" in openapi_j[1].lower()))
        or (openapi_y[0] == 200)
        or (api_docs[0] == 200)
    )
    add(
        "Information Disclosure",
        "API docs exposed (/swagger.json, /openapi.yaml)",
        "fail" if exposed_docs else "pass",
        f"swagger={swagger[0]} openapi={openapi_j[0]}",
    )
    debug_risk = debug_p[0] == 200 or metrics[0] == 200 or actuator[0] == 200
    debug_warn = actuator[0] == 401 or debug_p[0] in (301, 302, 401)
    add(
        "Information Disclosure",
        "Debug endpoints accessible (/debug, /actuator, /metrics)",
        "fail" if debug_risk else ("warn" if debug_warn else "pass"),
        f"debug={debug_p[0]} actuator={actuator[0]} metrics={metrics[0]}",
    )
    add("Information Disclosure", "Source code disclosure (.php~, .asp.bak)", "manual", "")
    add(
        "Information Disclosure",
        "Verbose 404/500 — Reveals internal paths",
        "warn" if _verbose_error_paths(ctx.status_line, ctx.body_sample) else "pass",
        ctx.status_line[:60],
    )

    dos = (
        "No rate limiting on endpoints",
        "Slowloris — Keeps connections open indefinitely",
        "ReDoS — Regex denial of service",
        "Large payload — No max body size enforcement",
        "XML bomb — Billion laughs attack",
        "ZIP bomb — Compressed payload explosion",
        "Resource exhaustion via complex queries",
    )
    for it in dos:
        add("Denial of Service", it, "manual", "Not stress-tested")

    g_intro = ctx.graphql_introspection_hint is True
    add(
        "API Specific",
        "GraphQL introspection enabled",
        "fail" if g_intro else "pass",
        "POST /graphql and /api/graphql { __typename }",
    )
    add(
        "API Specific",
        "GraphQL batching attack",
        "warn" if _graphql_batching_hint(h) else "pass",
        h.get("content-type", "")[:60],
    )
    for it in (
        "Mass assignment — Extra fields accepted silently",
        "Excessive data exposure — API returns more than needed",
        "Broken API versioning — Old versions still active",
        "Missing pagination — Returns all records without limit",
    ):
        add("API Specific", it, "manual", "Requires API semantics")

    return rows
