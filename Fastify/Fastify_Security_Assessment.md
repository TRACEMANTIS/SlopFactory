# independent security research. — Fastify v5.7.4 Security Assessment Report

**Date:** February 18, 2026
**Assessor:** [REDACTED] Security Assessment Team
**Target:** Fastify v5.7.4 (Node.js web framework) + plugins
**Platform:** Kali Linux VM (local only)
**Test Harness:** http://127.0.0.1:3000 (35 routes, 12 attack surface categories)

---

## Executive Summary

This assessment evaluated **Fastify v5.7.4** (released February 2, 2026), a high-performance Node.js web framework with ~5 million weekly npm downloads. Testing encompassed 9 phases covering source code audit, dynamic testing, fuzzing, and CVE regression validation across the core framework and 14 dependencies.

### Key Metrics

| Metric | Value |
|--------|-------|
| Total Test Cases | 223+ |
| Validated Findings | 13 (1 HIGH-Novel, 2 HIGH, 4 MEDIUM, 4 LOW, 2 INFO) |
| Source Code Lines Audited | ~12,000 (across 14 repos) |
| Scripts Written | 8 attack scripts + 1 pristine validator |
| CVE Regression Tests | 6/6 PATCHED |
| Server Crashes | 0 |
| Novel Finding | 1 (fast-json-stringify date-time JSON injection) |

### Findings Summary

| # | Severity | Finding | Component |
|---|----------|---------|-----------|
| 1 | **HIGH (Novel)** | JSON injection via format:date-time string passthrough | fast-json-stringify v6.3.0 |
| 2 | HIGH | Content-based body schema dispatch bypass | fastify core v5.7.4 |
| 3 | HIGH | .env file served with dotfiles:allow | @fastify/static v9.0.0 |
| 4 | MEDIUM | CSRF via @fastify/formbody bypassing JSON schema | fastify + @fastify/formbody |
| 5 | MEDIUM | Empty schema {} leaks all nested data | fast-json-stringify v6.3.0 |
| 6 | MEDIUM | Login timing oracle (52ms differential) | Test harness (app-level) |
| 7 | MEDIUM | CORS wildcard origin with credentials | Test harness (config) |
| 8 | LOW | No timeout on request-lifecycle async hooks | fastify core v5.7.4 |
| 9 | LOW | Error messages leak internal paths | fastify core v5.7.4 |
| 10 | LOW | Missing security response headers | fastify core (no defaults) |
| 11 | LOW | WebSocket uses JSON.parse (not secure-json-parse) | Test harness (app-level) |
| 12 | INFO | Prototype poisoning safe defaults (positive) | fastify core v5.7.4 |
| 13 | INFO | SSTI via direct EJS.render() | Test harness (app-level) |

---

## Finding Details

### Finding 1: fast-json-stringify JSON Injection via format:date-time (HIGH — NOVEL)

**Component:** fast-json-stringify v6.3.0
**Location:** `lib/serializer.js` lines 65-89 (asDateTime, asDate, asTime functions)
**CVSS Estimate:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Description:**
When a string value (not a Date object) is passed to a schema field with `format: "date-time"`, `format: "date"`, or `format: "time"`, the serializer wraps the value in double quotes with **zero escaping**. An attacker controlling the string content can inject arbitrary JSON structure, including overwriting properties that appear later in the serialized output.

**Root Cause:**
```javascript
// lib/serializer.js:85 (asDateTime)
if (typeof date === 'string') {
  return `"${date}"` // NO ESCAPING of double quotes
}
```

Compare with safe handling of regular strings:
```javascript
// lib/serializer.js:23 (asString)
return JSON.stringify(str) // Uses JSON.stringify which escapes properly
```

**Exploitation:**
```
GET /api/event?startDate=2026-01-01","role":"admin","x":"
```

**Raw response (verified):**
```json
{"id":1,"title":"Test Event","startDate":"2026-01-01","role":"admin","x":"","endDate":"2026-02-18T20:45:58.368Z","role":"user"}
```

The injected `"role":"admin"` appears **before** the legitimate `"role":"user"`. Impact depends on the downstream JSON parser:

| Parser | Behavior | Parsed `role` |
|--------|----------|---------------|
| PHP `json_decode()` | First value wins | **admin** (EXPLOITABLE) |
| Java (some libs) | First value wins | **admin** (EXPLOITABLE) |
| Python `json.loads()` | Last value wins | user (safe) |
| JavaScript `JSON.parse()` | Last value wins | user (safe) |
| Go `encoding/json` | Last value wins | user (safe) |

**Preconditions:**
1. Route has response schema with `format: "date-time"`, `format: "date"`, or `format: "time"`
2. Handler returns a string value (not Date object) for that field
3. Attacker can influence the string content (via query params, DB data, etc.)

**Pristine Validation:** CONFIRMED in isolated environment using only `fast-json-stringify@6.3.0` (see `cve-validation/datetime_injection_pristine.js`).

**Suggested Fix:**
```javascript
// Replace: return `"${str}"`
// With:    return JSON.stringify(str)
```

**Disclosure:** Report to fast-json-stringify GitHub Security Advisories.

---

### Finding 2: Content-Based Body Schema Dispatch Bypass (HIGH)

**Component:** fastify core v5.7.4
**Location:** `lib/validation.js` lines 161-171

**Description:**
When a route uses per-content-type body schemas (`body.content`) and a request arrives with a Content-Type that has a registered parser but no matching body schema, the body is parsed but NOT validated. The `validateParam(null, ...)` call returns false (no error), allowing unvalidated data to reach the handler.

**Impact:** Schema validation bypass for requests with non-matching content types. An attacker can send any Content-Type with a registered parser and bypass body validation entirely.

**Note:** Only affects routes using the `body.content` schema syntax, which is less common than standard body schemas.

---

### Finding 3: .env File Served via Static (HIGH — Config-Dependent)

**Component:** @fastify/static v9.0.0
**Configuration:** `dotfiles: 'allow'`

**Description:**
With `dotfiles: 'allow'` configuration, `.env` files containing secrets (API keys, database passwords, secret keys) are served to any requestor.

**Evidence:**
```
GET /static/.env HTTP/1.1

SECRET_KEY=test_secret_do_not_expose
DB_PASSWORD=hunter2
API_TOKEN=sk-fake-token-12345
```

**Note:** Framework default is `dotfiles: 'ignore'`. This is a config-level finding.

---

### Finding 4: CSRF via @fastify/formbody Bypassing JSON Schema (MEDIUM)

**Component:** fastify core + @fastify/formbody v8.0.2
**Related:** CVE-2022-41919 (different vector, same class)

**Description:**
When `@fastify/formbody` is registered, `application/x-www-form-urlencoded` bodies are parsed into flat objects that pass JSON body schema validation. Since form-urlencoded is a CORS "simple" content type, cross-origin form submissions can invoke schema-validated routes without CORS preflight.

**Exploitation:**
```html
<form action="http://target.com/api/users" method="POST">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="role" value="admin">
    <input type="submit">
</form>
```

**Verified Result:** HTTP 200, user created with `role: "admin"`.

Also confirmed on enum-validated route (`/api/json-only`): `action=delete` passes enum validation via form submission.

**Mitigation:** Use `@fastify/csrf-protection` on routes that accept both JSON and form-encoded bodies.

---

### Finding 5: Empty Schema {} Leaks All Nested Data (MEDIUM)

**Component:** fast-json-stringify v6.3.0
**Location:** `index.js` lines 972-973

**Description:**
Properties defined with empty schema `{}` (no type field) fall through to `JSON.stringify()`, serializing the entire value with all nested properties. This defeats the purpose of response schema filtering.

**Evidence:**
```javascript
// Schema: preferences: {}
// Response includes ALL nested data:
{
  "preferences": {
    "theme": "dark",
    "internal_notes": "Employee SSN: 123-45-6789",
    "api_token": "secret-api-token-xyz",
    "manager_email": "manager@internal.corp"
  }
}
```

Top-level `password` field was correctly filtered (has no schema entry), but `preferences` subtree is fully leaked because `{}` schema disables filtering.

---

### Finding 6: Login Timing Oracle (MEDIUM — App-Level)

52.0ms average difference between valid username (admin: 54.8ms) and invalid username (2.8ms). Intentional 50ms delay in test harness enables reliable user enumeration.

### Finding 7: CORS Wildcard with Credentials (MEDIUM — Config)

CORS configured with `origin: true` + `credentials: true` reflects any Origin header including `http://evil.com`. Config-dependent, not framework default.

### Finding 8: No Timeout on Async Hooks (LOW)

`hookRunnerGenerator` in `lib/hooks.js` has no timeout mechanism. A never-resolving Promise holds the connection indefinitely.

### Finding 9: Error Message Path Leak (LOW)

`FST_ERR_SCH_VALIDATION_BUILD` includes internal paths. Stack traces correctly stripped.

### Finding 10: Missing Security Headers (LOW)

No CSP, HSTS, X-Content-Type-Options, X-Frame-Options headers by default. Use `@fastify/helmet`.

### Finding 11: WebSocket Uses JSON.parse (LOW — App-Level)

WebSocket handler uses standard `JSON.parse()` instead of `secure-json-parse`. `__proto__` keys are echoed in responses.

### Finding 12: Prototype Poisoning Safe Defaults (INFO — Positive)

Default `onProtoPoisoning: 'error'` and `onConstructorPoisoning: 'error'`. All 11 tested JSON PP payloads correctly rejected (400).

### Finding 13: SSTI via Direct EJS.render() (INFO — App-Level)

Direct template rendering with user input enables RCE (`global.process.mainModule.require` bypass). App-level misuse, not framework vulnerability.

---

## Security-Positive Findings

1. **secure-json-parse v4.1.0 is robust** — All bypass vectors tested (unicode escapes, BOM, nested, duplicate keys, homoglyphs) correctly blocked
2. **Prototype poisoning defaults are safe** — `onProtoPoisoning: 'error'` is the default
3. **HTTP request smuggling fully blocked** — All CL-TE, TE-CL, double TE, obfuscated TE tests rejected (400)
4. **Path traversal in static serving blocked** — All 6 traversal vectors rejected (403/404)
5. **Body size limits enforced** — 1MB limit working, oversized files rejected (413)
6. **connectionTimeout working** — 30s timeout correctly closes incomplete connections
7. **Request IDs unique** — 100/100 unique via `crypto.randomUUID()`
8. **No server crashes** — 0 crashes across 223+ test cases
9. **JWT none algorithm rejected** — `@fastify/jwt` correctly rejects none/empty algorithm tokens
10. **Signed cookies verified** — Tampered signed cookies correctly rejected

---

## CVE Regression Results

| CVE | Description | Status |
|-----|-------------|--------|
| CVE-2026-25224 | DoS via unbounded memory in sendWebStream | **PATCHED** ✅ |
| CVE-2024-58027 | Content-Type tab bypass | **PATCHED** ✅ |
| CVE-2025-32442 | Content-Type case/whitespace bypass | **PATCHED** ✅ |
| CVE-2022-41919 | Content-Type CSRF | **PATCHED** ✅ |
| CVE-2022-39288 | DoS via malicious Content-Type | **PATCHED** ✅ |
| Prototype pollution defaults | onProtoPoisoning='error' | **SAFE** ✅ |

---

## Testing Methodology

### Phases

| Phase | Focus | Tests | Findings |
|-------|-------|-------|----------|
| 1 | Reconnaissance & Static Analysis | 47 | 10 |
| 2 | Content-Type & Schema Validation | 71 | 4 |
| 3 | Prototype Pollution & Injection | 48 | 2 |
| 4 | Auth, Session & Cookie Attacks | 26 | 3 |
| 5 | Protocol, Streaming & DoS | 17 | 0 |
| 6 | File Upload & Static Serving | 34 | 1 |
| 7 | CVE Regression Testing | (included in Phase 6) | 0 |
| 8 | Novel Finding Deep-Dive | 5 | 4 |
| 9 | Pristine Validation & Report | 6 | 0 |

### Tools & Techniques
- **Source Code Audit:** 14 repositories, 4 parallel audit agents, ~12,000 lines reviewed
- **Dynamic Testing:** 8 Python attack scripts with socket-level control
- **Pristine Validation:** Isolated `fast-json-stringify@6.3.0` installation
- **Dependencies:** Python 3.13, requests, websocket-client, Node.js v22.22.0

---

## Disclosure Plan

| Finding | Channel | Priority |
|---------|---------|----------|
| #1 (date-time injection) | fast-json-stringify GitHub Security Advisories | HIGH — Novel |
| #4 (CSRF via formbody) | Fastify HackerOne VDP | MEDIUM |
| #2 (CT dispatch bypass) | Fastify HackerOne VDP (with #4) | MEDIUM |
| #5 (empty schema leak) | fast-json-stringify issue tracker | LOW |

**Fastify HackerOne:** https://hackerone.com/fastify (no monetary bounty)
**Contact:** [VENDOR-CONTACT]
**Timeline:** 90-day coordinated disclosure

---

## Files & Evidence

```
Fastify/
├── [REDACTED]_Fastify_Security_Assessment.md   # This report

├── evidence/
│   ├── phase1_recon.json                   # Phase 1 evidence (47 tests, 10 findings)
│   ├── phase2_content_type.json            # Phase 2 evidence (71 tests, 4 findings)
│   ├── phase3_prototype_pollution.json     # Phase 3 evidence (48 tests, 2 findings)
│   ├── phase4_auth_session.json            # Phase 4 evidence (26 tests, 3 findings)
│   ├── phase5_protocol_dos.json            # Phase 5 evidence (17 tests, 0 findings)
│   ├── phase6_7_upload_cve.json            # Phase 6+7 evidence (34 tests, 1 finding)
│   └── phase8_novel_hunting.json           # Phase 8 evidence (5 tests, 4 findings)
├── cve-validation/
│   └── datetime_injection_pristine.js      # Pristine validation (6 tests, all confirmed)
├── scripts/
│   ├── phase2_content_type_attacks.py
│   ├── phase3_prototype_pollution.py
│   ├── phase4_auth_session.py
│   ├── phase5_protocol_dos.py
│   ├── phase6_upload_static.py
│   └── phase8_novel_hunting.py
├── scans/
│   └── nmap_tcp.txt
├── source/                                 # 14 cloned repos for source audit
└── testapp/                                # Test harness (35 routes)
    ├── server.js
    ├── views/
    ├── public/
    └── node_modules/
```
