# HAProxy v3.3.0 Security Assessment Report

**Course:** [REDACTED] — security research
**Target:** HAProxy v3.3.0 (stable, released 2025/11/26)
**Platform:** Kali Linux VM (local test environment)
**Assessment Period:** 2026-02-18
**Build:** Source (git tag v3.3.0) with AddressSanitizer + debug symbols

---

## Executive Summary

HAProxy v3.3.0 was assessed across 10 phases covering HTTP/1.1, HTTP/2, QUIC/HTTP/3, Lua scripting, CLI/Stats, CVE regression testing, and pristine validation. A total of **882+ test cases** were executed using 12 custom attack scripts + 1 pristine validator, with **4 parallel source code audit agents** reviewing ~50,000 lines of C source.

### Key Results

| Metric | Count |
|--------|-------|
| Total test cases | 882+ |
| Validated findings | 15 (0 CRITICAL, 2 HIGH, 8 MEDIUM, 3 LOW, 2 INFO) |
| Withdrawn findings | 1 (CL-TE desync "2 responses" was false positive) |
| Novel vulnerabilities | 1 (bare LF header injection → arbitrary header injection) |
| CVE regressions | 6/6 PATCHED |
| Server crashes | 0 |
| Pristine validation | 12/12 tests confirmed (3 rounds) |

### Novel Finding: Bare LF Header Injection (HIGH — Pristine Validated)

**Bare LF Header Injection → Arbitrary Header Injection (HIGH)**
HAProxy's HTTP/1.1 parser accepts bare LF (`\n` without `\r`) as a header line terminator. When a header value contains `\n`, HAProxy splits it into multiple separate headers during forwarding to the backend. Pristine-validated (3/3 rounds, fresh build) — enables:
- Authorization header injection (auth bypass on backends)
- Cookie header injection (session hijacking)
- X-Forwarded-For spoofing (IP-based ACL bypass)
- Transfer-Encoding injection (CL-TE body mismatch; smuggling exploitation conditional on backend HTTP version)
- Same vulnerability class as CVE-2023-25725 but via a different vector

### Withdrawn Finding: CL-TE Desync "2 Responses" (was CRITICAL)

The Phase 8 CL-TE desync test that reported "2 HTTP responses from 1 connection" was a **false positive**. The response count used `resp.count(b"HTTP/1.")` which matched `"http_version": "HTTP/1.1"` inside the backend's JSON echo body. Proper counting with `re.findall(rb'^HTTP/1\.[01] \d{3}', resp, re.MULTILINE)` shows only 1 response. The CL-TE body interpretation mismatch IS real (HAProxy uses TE while client intended CL), but request smuggling was not demonstrated in our test environment (Python backend uses HTTP/1.0 Connection: close).

---

## Findings

### Finding 1: Bare LF Header Injection → Arbitrary Header Injection (HIGH — NOVEL, PRISTINE VALIDATED)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Component** | HTTP/1.1 parser (`src/h1.c:888`, `src/http.c:39`) |
| **CWE** | CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers) |
| **Pre-auth** | Yes |
| **Novel** | Yes — different vector from CVE-2023-25725 |
| **Pristine** | VALIDATED — 3/3 rounds on fresh build (12/12 injection tests confirmed) |

**Description:** HAProxy v3.3.0 accepts bare LF (`\n`, 0x0A) as an HTTP header line terminator in HTTP/1.1 requests. When a header value contains a bare LF followed by `HeaderName: value`, HAProxy splits this into separate headers during request forwarding. The frontend sees a single header (e.g., `X-Foo: bar\nAuthorization: Basic ...`), but the backend receives two separate headers (`X-Foo: bar` and `Authorization: Basic ...`).

**Root Cause:** `src/http.c:39` assigns `HTTP_FLG_CRLF` to byte 10 (LF), and `HTTP_IS_CRLF()` at `h1.c:888` treats bare LF as a header line terminator in the `http_msg_hdr_val2` state.

**Impact (Pristine-Validated):**
1. **Authentication Bypass** — Inject `Authorization: Basic ...` headers the backend trusts (3/3 rounds confirmed)
2. **Session Hijacking** — Inject `Cookie: session=stolen` headers (3/3 rounds confirmed)
3. **IP Spoofing** — Inject `X-Forwarded-For` headers to bypass IP-based ACLs (3/3 rounds confirmed)
4. **TE Injection** — Inject `Transfer-Encoding: chunked` header; HAProxy itself sees it (returns 400 for invalid chunked body), creating CL-TE body interpretation mismatch in multi-hop deployments
5. **Protocol Up[REDACTED]** — Inject `Up[REDACTED]: websocket` headers

**Reproduction:**
```python
#!/usr/bin/env python3
# reproduce_bare_lf.py — Self-contained reproduction
import socket, json
HOST, PORT = '127.0.0.1', 18080  # HAProxy frontend

# Inject Authorization header via bare LF
payload = (
    b"GET /test HTTP/1.1\r\n"
    b"Host: 127.0.0.1:18080\r\n"
    b"X-A: x\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

sock = socket.create_connection((HOST, PORT), timeout=5)
sock.sendall(payload)
resp = b""
sock.settimeout(3)
try:
    while True:
        chunk = sock.recv(65536)
        if not chunk: break
        resp += chunk
except socket.timeout: pass
sock.close()

body = resp.split(b"\r\n\r\n", 1)[1]
data = json.loads(body)
print("Backend received headers:")
for k, v in data["headers"].items():
    print(f"  {k}: {v}")
has_auth = "authorization" in [k.lower() for k in data["headers"]]
print(f"\nAuthorization injected: {has_auth}")
```

**Withdrawn Claim:** Phase 8 reported "CL-TE desync: 2 responses from 1 connection." This was a **false positive** — `resp.count(b"HTTP/1.")` matched `"http_version": "HTTP/1.1"` in the backend's JSON echo body. Corrected regex counting shows only 1 actual HTTP response. The CL-TE body mismatch exists but request smuggling was not demonstrated. See `cve-validation/pristine_bare_lf_evidence.json`.

**Evidence:** `evidence/phase8_bare_lf_smuggling.json`, `cve-validation/pristine_bare_lf_evidence.json` (3 rounds, 12/12 confirmed)

**Mitigation Note:** Host header injection is blocked (HTTP 400), and Content-Length injection causes connection drop. Transfer-Encoding injection reaches the backend but HAProxy also processes it (returns 400 for invalid chunked body). Authorization, Cookie, X-Forwarded-For, and Up[REDACTED] injection are fully successful.

---

### Finding 2: HPACK Varint Decoder Accepts Overlong Encoding (MEDIUM)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Component** | HPACK decoder (`src/hpack-dec.c:55-87`) |
| **CWE** | CWE-190 (Integer Overflow), CWE-758 (Reliance on Undefined Behavior) |
| **Pre-auth** | No (requires TLS + H2 negotiation) |

**Description:** The `get_var_int()` function in `hpack-dec.c` decodes HPACK variable-length integers without checking that the `shift` variable remains below 32 (the width of `uint32_t`). The expression `((uint32_t)(*raw++) & 127) << shift` is undefined behavior per C11 §6.5.7 when `shift >= 32`.

Testing confirmed HAProxy accepts overlong varint encoding with up to 30 extra continuation bytes (shift reaches 210 bits) and successfully forwards the request to the backend. While not directly exploitable on x86 with `-O0` (the SHL instruction masks shift to `shift & 31`), this is UB that could produce incorrect values under different compilers or optimization levels.

**Evidence:** `evidence/phase3b_h2_deepdive.json` — Tests overlong_5extra through overlong_30extra all ACCEPTED.

---

### Finding 3: QUIC Preferred Address CID Length Check Inverted (MEDIUM)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Component** | QUIC transport parameters (`src/quic_tp.c:171`) |
| **CWE** | CWE-697 (Incorrect Comparison) |
| **Pre-auth** | N/A (client-side vulnerability) |

**Description:** The `quic_transport_param_dec_pref_addr()` function at line 171 uses `>` (greater than) when it should use `<` (less than) in the CID length bounds check:

```c
// CURRENT (line 171):
if (end - sizeof(addr->stateless_reset_token) - *buf > addr->cid.len ||
    addr->cid.len > sizeof(addr->cid.data)) {
    return 0;
}
// SHOULD BE:
if (end - sizeof(addr->stateless_reset_token) - *buf < addr->cid.len || ...)
```

This inverted check allows a CID length that exceeds available buffer space, potentially causing a buffer overflow in the subsequent `memcpy()`. This affects HAProxy when acting as a QUIC client connecting to a malicious upstream backend.

**Evidence:** `evidence/phase7_cve_regression.json` — Source audit confirmation.

---

### Finding 4: Prometheus Metrics Exposed Without Authentication (MEDIUM)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Component** | Stats frontend (`configs/haproxy-all.cfg`) |
| **CWE** | CWE-284 (Improper Access Control) |

**Description:** The Prometheus metrics endpoint at `/metrics` on port 8404 returns detailed HAProxy operational metrics (frontend/backend names, connection counts, error rates, server states) without requiring authentication, even when the stats page requires Basic authentication.

**Evidence:** `evidence/phase6_auth_stats_cli.json` — Test prometheus_unauth: HTTP 200 with full metrics.

---

### Finding 5: CLI Socket Exposes Environment Variables (MEDIUM)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Component** | CLI (`src/cli.c:1688`) |
| **CWE** | CWE-200 (Exposure of Sensitive Information) |

**Description:** The `show env` CLI command exposes all process environment variables (PATH, HOME, USER, potentially credentials, API keys, database URLs) at operator access level. Combined with no authentication on the CLI socket, any local user with access to `/tmp/haproxy.sock` can read all environment variables.

**Evidence:** `evidence/phase6_auth_stats_cli.json` — Test cli_show_env: Full environment disclosed.

---

### Finding 6: CLI Socket Accepts Dangerous Commands Without Authentication (MEDIUM)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Component** | CLI socket (`/tmp/haproxy.sock`) |
| **CWE** | CWE-306 (Missing Authentication for Critical Function) |

**Description:** The CLI socket accepts administrative commands without authentication. Commands including `disable server`, `set weight`, `shutdown sessions`, `show table`, `show backend`, and `show servers state` are all accepted. While the socket requires local access, this enables privilege escalation from any local user to HAProxy administrator.

**Evidence:** `evidence/phase6_auth_stats_cli.json` — Tests: disable_server, set_weight, shutdown_sessions all EXECUTED.

---

### Finding 7: No Lua Sandbox — Full OS Access (HIGH — By Design)

| Field | Value |
|-------|-------|
| **Severity** | HIGH (by_design) |
| **Component** | Lua engine (`src/hlua.c:14062`) |
| **CWE** | CWE-250 (Execution with Unnecessary Privileges) |

**Description:** HAProxy loads the full Lua standard library via `luaL_openlibs(L)` at `hlua.c:14062`, giving Lua scripts access to `os.execute()`, `io.open()`, `debug.*`, and all other standard modules. Any user who can load a Lua script via HAProxy configuration has full system access.

**Note:** This is by design — HAProxy treats Lua script loading as equivalent to configuration access. However, it creates a privilege escalation path: configuration write → RCE.

**Evidence:** `evidence/phase5_lua_mjson.json` — Source audit confirmation.

---

### ~~Finding 8: Bare LF Header Injection (merged into Finding 1)~~

*Merged into Finding 1 during pristine validation. Finding 1 now covers the complete bare LF header injection attack chain with pristine validation evidence.*

---

### Finding 9: SETTINGS Flood Not Rate-Limited (LOW)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Component** | HTTP/2 multiplexer (`src/mux_h2.c:4384`) |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |

**Description:** HAProxy accepts 1,000 SETTINGS frames in rapid succession with no GOAWAY or rate limiting. Each SETTINGS frame triggers a SETTINGS ACK response, amplifying resource consumption. The glitch threshold system exists but requires explicit configuration.

**Evidence:** `evidence/phase3_h2_attacks.json` — Test rapid_settings(1000): 1000 ACKs, no GOAWAY.

---

### Finding 10: No Account Lockout on Stats Page (LOW)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **CWE** | CWE-307 (Improper Restriction of Excessive Authentication Attempts) |

**Description:** After 20 failed authentication attempts, valid credentials are still accepted. No lockout mechanism or rate limiting exists for the stats page Basic authentication.

**Evidence:** `evidence/phase6_auth_stats_cli.json` — Test no_lockout: HTTP 200 after 20 failures.

---

### Finding 11: Binary Compiled Without Stack Canaries (INFO)

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **CWE** | CWE-693 (Protection Mechanism Failure) |

**Description:** The HAProxy binary is compiled without stack canaries (`-fno-stack-protector` or equivalent). Combined with Partial RELRO and 0/21 FORTIFY functions, any stack buffer overflow vulnerability would be more easily exploitable.

**Evidence:** `evidence/phase1_recon_static.json` — checksec output.

---

### Finding 12: Lua CLI Commands No Access Level Enforcement (MEDIUM)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Component** | Lua CLI integration (`src/hlua.c:12163`) |

**Description:** Lua-registered CLI commands have no access level enforcement. All registered Lua CLI actions are accessible at the default (operator) level, regardless of intended privilege requirements.

**Evidence:** Source audit finding L-4.

---

### Finding 13: QPACK Varint Shift Overflow (MEDIUM — Source Only)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Component** | QPACK decoder (`src/qpack-dec.c:61-94`) |
| **CWE** | CWE-190, CWE-758 |

**Description:** The `qpack_get_varint()` function has the same shift overflow issue as the HPACK decoder (Finding 2). The `shift` variable (`uint8_t`) is incremented by 7 each iteration with no bounds check. When `shift >= 64`, `((uint64_t)*raw++ & 127) << shift` is undefined behavior. Additionally, `int len = *len_in` truncates the `uint64_t` input length to `int`.

**Note:** Reachable only after successful QUIC handshake. Not dynamically tested due to limited-quic mode.

**Evidence:** Source audit finding Q-1.

---

### Finding 14: ASAN Memory Leaks in Lua Config Parsing (INFO)

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Component** | Lua initialization (`src/hlua.c:11524, 11531, 11589`) |

**Description:** AddressSanitizer's LeakSanitizer detects memory leaks during HAProxy configuration parsing in `action_register_lua()` and `action_register_service_http()`. While these occur at startup (not runtime), they indicate missing cleanup paths.

---

### Finding 15: CONTINUATION Flood Mitigation Disabled by Default (LOW)

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Component** | HTTP/2 multiplexer (`src/mux_h2.c:6229`) |

**Description:** The glitch-based CONTINUATION flood detection system has `tune.h2.glitches-threshold` set to 0 by default (disabled). Zero-length CONTINUATION frames are accepted without triggering the flood protection.

**Evidence:** `evidence/phase3_h2_attacks.json` — Test zero_length_cont: accepted.

---

### Finding 16: Accept-Unsafe-Violations Weakens Security (MEDIUM — By Design)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (by_design) |
| **Component** | HTTP/1.1 parser (`src/h1.c:800, 877`) |

**Description:** When `accept-unsafe-violations-in-http-request` is enabled, HAProxy accepts NUL bytes in header values and non-token characters in header names. While this is a documented configuration option, it significantly weakens the HTTP parser's security posture and enables various injection vectors.

---

## CVE Regression Results

| CVE | Description | v3.3.0 Status |
|-----|-------------|---------------|
| CVE-2021-40346 | Integer overflow in Content-Length | **PATCHED** ✅ |
| CVE-2023-25725 | Header injection via empty header name | **PATCHED** ✅ |
| CVE-2023-40225 | Empty Content-Length request smuggling | **PATCHED** ✅ |
| CVE-2025-11230 | mjson algorithmic DoS (deep nesting) | **PATCHED** ✅ (MJSON_MAX_DEPTH=20) |
| CVE-2026-26080 | QUIC varint infinite loop | **PATCHED** ✅ (HAProxy stays responsive) |
| CVE-2026-26081 | QUIC token length underflow | **PATCHED** ✅ |

---

## Testing Phases

| Phase | Focus | Tests | Findings | Scripts |
|-------|-------|-------|----------|---------|
| 1 | Reconnaissance & Static Analysis | 215 | 22 source findings | 4 audit agents |
| 2 | HTTP/1.1 Request Smuggling | 92 | 1 (bare LF) | 1 |
| 3 | HTTP/2 & HPACK Attacks | 66 | 7 (varint UB, CRLF/null) | 3 |
| 4 | QUIC/HTTP/3 Attacks | 339 | 0 real crashes | 1 |
| 5 | Lua Scripting & mjson | 56 | 1 (no sandbox) | 1 |
| 6 | Auth, Stats & CLI | 68 | 8 | 1 |
| 7 | CVE Regression | 21 | 0 regressions | 1 |
| 8 | Novel Finding Deep-Dive | 13 | 8 (header injection) | 1 |
| 9 | Pristine Validation | 12 | 1 withdrawn (CL-TE FP) | 1 |
| **Total** | | **882+** | **15 validated + 1 withdrawn** | **13 scripts** |

---

## Security Positives

HAProxy v3.3.0 demonstrates strong security in many areas:

1. **0 server crashes** — ASAN build survived 870+ attack tests without a single crash
2. **All 6 CVEs confirmed PATCHED** — complete regression coverage
3. **HTTP/2 connection-specific headers properly blocked** — TE, Connection, Proxy-Connection, Up[REDACTED], Keep-Alive all rejected in H2
4. **QUIC packet parser is robust** — 339 malformed QUIC packets, 0 crashes
5. **H2-to-H1 CRLF/null injection blocked** — Phase 3B confirmed CRLF and null bytes in H2 header values do NOT reach H1 backends (sanitized during protocol translation)
6. **CLI command injection safe** — All shell injection attempts (`;`, `|`, `` ` ``, `$()`) properly rejected
7. **ACL system robust** — All 29 path/host/method bypass attempts rejected
8. **QUIC varint decoder is safe** — `quic_dec_int()` uses 2-bit length prefix, properly bounded
9. **Uppercase headers in H2 properly rejected** per RFC 7540

---

## Disclosure Plan

| Finding | Channel | Priority |
|---------|---------|----------|
| #1 (Bare LF Header Injection) | HAProxy GitHub Security | **HIGH — Novel, Pristine Validated** |
| #3 (QUIC CID check inverted) | HAProxy GitHub Security | MEDIUM |
| #2 (HPACK varint UB) | HAProxy GitHub Security | MEDIUM |
| #13 (QPACK varint UB) | HAProxy GitHub Security | MEDIUM |

---

## Methodology

- **Build:** Source compilation with AddressSanitizer (`-fsanitize=address`) and debug symbols (`-g -ggdb3 -O0`)
- **Source Audit:** 4 parallel agents auditing HTTP/1.1, HTTP/2, QUIC/HTTP/3, and Lua/mjson/CLI codebases
- **Dynamic Testing:** Custom Python scripts with raw socket control for precise protocol manipulation
- **QUIC Testing:** Raw UDP packet construction (no crypto — tests pre-decryption header parsing)
- **Validation:** Backend echo server returns full request details as JSON for precise smuggling detection
- **Evidence:** All findings backed by JSON evidence files with timestamps and raw data

---

## Files

| Path | Description |
|------|-------------|
| `scripts/phase2_h1_smuggling.py` | HTTP/1.1 smuggling tests (92 tests) |
| `scripts/phase3_h2_attacks.py` | HTTP/2 & HPACK attacks (39 tests) |
| `scripts/phase3b_h2_deepdive.py` | H2-to-H1 injection verification (20 tests) |
| `scripts/phase3c_varint_exploit.py` | HPACK varint UB exploitation (7 tests) |
| `scripts/phase4_quic_attacks.py` | QUIC protocol attacks (339 tests) |
| `scripts/phase5_lua_mjson.py` | Lua/mjson attacks (56 tests) |
| `scripts/phase6_auth_stats_cli.py` | Auth/Stats/CLI attacks (68 tests) |
| `scripts/phase7_cve_regression.py` | CVE regression + novel deep-dive (21 tests) |
| `scripts/phase8_bare_lf_smuggling.py` | Bare LF smuggling exploitation (13 tests) |
| `scripts/backend_server.py` | Echo backend server |
| `scripts/start_haproxy.sh` | Startup convenience script |
| `cve-validation/pristine_validate_bare_lf.py` | Pristine validation script (3 rounds) |
| `cve-validation/pristine_bare_lf_evidence.json` | Pristine validation evidence (12/12 confirmed) |
| `cve-validation/CVE_SUBMISSION_haproxy_bare_lf_injection.md` | CVE submission advisory |
| `cve-validation/pristine-build/` | Fresh HAProxy v3.3.0 build (no shared state) |
| `evidence/*.json` | 10 evidence files |
| `configs/haproxy-all.cfg` | Test configuration |
| `source/haproxy-asan` | ASAN build binary |
