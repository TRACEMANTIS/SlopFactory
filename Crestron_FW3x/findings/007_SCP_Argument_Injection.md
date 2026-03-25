# [REDACTED-ID]_007: SCP Argument Injection via sshShell.sh

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_007 |
| **Title** | Authenticated Privilege Escalation via SCP Argument Injection in sshShell.sh |
| **Severity** | HIGH (CVSS 3.1: 7.8 — AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |
| **Type** | CWE-88: Improper Neutralization of Argument Delimiters in a Command (Argument Injection) |
| **Related CVE** | CVE-2025-47421 (affects FW 3.001.0031–3.001.0034, fixed in 3.002.0040) |
| **Affected Products** | Crestron devices with SSH access (TSW touchscreens, control processors) |
| **Firmware Analyzed** | TSW-XX60 v3.002.1061 |
| **Discovery Method** | Static analysis of `sshShell.sh` startup script + Ghidra RE of custom `scp` binary |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## 1. Executive Summary

Crestron devices restrict SSH access through a custom login shell (`sshShell.sh`) that intercepts SSH commands and routes them through a controlled SCP binary. The script extracts command arguments using `busybox awk` and passes them to the custom `scp` binary — but the extracted arguments are **unquoted** in the final command invocation, creating an argument injection vulnerability.

Additionally, the script's operator write-restriction check uses a simple `grep " -t"` to detect SCP upload mode (`-t` flag), which can be bypassed by embedding `-t` in a filename.

This finding is closely related to **CVE-2025-47421**, which affects firmware versions 3.001.0031–3.001.0034 and was fixed in 3.002.0040. Our analyzed firmware (3.002.1061) is newer than the fix, so the core CVE is **likely patched**. However, the underlying `sshShell.sh` pattern (unquoted variable expansion + `awk`-based argument extraction) remains in the codebase and represents a fragile defense.

---

## 2. Technical Root Cause

### 2.1 The sshShell.sh Script

```bash
#!/bin/sh
# sshShell.sh — SSH login shell for Crestron devices
# Intercepts SSH commands and routes through controlled SCP binary

# Line 77: Extract command arguments using awk
new_cmd=`echo "$@" | busybox awk '{print $2 " " $3 " " $4 " " $5 " " $6 " " $7 " " $8 " " $9 " " $10}'`

# $new_cmd is UNQUOTED in the following scp invocation:
scp -U $SCP_PARAM $new_cmd
#                  ^^^^^^^^ UNQUOTED — word splitting applies
```

### 2.2 Vulnerability #1: Unquoted Variable Expansion

When `$new_cmd` is expanded without quotes, the shell performs **word splitting** on its contents. This means:
- Filenames containing spaces are split into multiple arguments
- Each "word" is interpreted as a separate argument to `scp`
- Crafted filenames can inject additional SCP flags or paths

**Example:**
```
# Intended: scp -t /mnt/sdcard/ROMDISK/my file.txt
# awk output: -t /mnt/sdcard/ROMDISK/my file.txt
# After word splitting: scp -U $SCP_PARAM -t /mnt/sdcard/ROMDISK/my file.txt
#                                          ↑ intended path    ↑ INJECTED ARGUMENT
```

### 2.3 Vulnerability #2: Weak Operator Write Check

```bash
# Operator mode: check if upload is attempted
echo $@ | grep " -t" > /dev/null
if [ $? == "0" ]; then
    # Upload detected — restrict for operators
    ...
fi
```

The `grep " -t"` check:
- Requires a space before `-t`
- A filename containing `-t` at a word boundary would match (false positive)
- Conversely, encoding the `-t` flag differently could bypass the check

### 2.4 Custom SCP Binary Mitigations

The custom `scp` binary (26KB, ARM32) includes hardcoded security measures:
- `-oPermitLocalCommand=no` — prevents `!command` execution
- `-oRemoteCommand=none` — disables remote command execution
- Links against `libAuditLog` — actions are logged

These mitigations significantly reduce the impact of argument injection. The custom binary does NOT support all standard SCP options, limiting what an attacker can inject.

### 2.5 Role-Based Access Control

| Role | Access Level | Chroot Path | Write Allowed? |
|------|-------------|-------------|----------------|
| Admin (0x1f) | Full | `/mnt/sdcard/ROMDISK` | Yes |
| Programmer (0x0f) | Program files | `/mnt/sdcard/ftpprog` | Yes |
| Operator (0x07) | Read only | `/mnt/sdcard/ftpprog` | No (grep -t check) |

---

## 3. Proof of Concept

### 3.1 Theoretical: Argument Injection via Filename

```bash
# Attacker is an authenticated SSH user (Operator role)
# Craft an SCP upload with a filename that bypasses the -t check

# The awk extraction + unquoted expansion could allow:
scp operator@device:"--some-flag /path/to/sensitive/file" /tmp/

# Or inject additional paths to read files outside chroot:
scp operator@device:"/mnt/sdcard/ftpprog/legit -O /etc/shadow" /tmp/
```

### 3.2 Operator Write Bypass (Theoretical)

```bash
# grep " -t" check bypass — embed -t flag without a preceding space:
# If the command can be crafted so -t appears at position $2 in awk output:
ssh operator@device "scp -t/path/to/upload"
# awk splits: $2="-t/path/to/upload" — grep " -t" does NOT match (no space before -t)
```

---

## 4. Impact

| Scenario | Severity | Likelihood |
|----------|----------|------------|
| Operator bypasses write restriction | HIGH | LOW (CVE-2025-47421 likely patched) |
| Chroot escape via argument injection | HIGH | LOW (custom scp binary limits options) |
| File read outside chroot path | MEDIUM | LOW (depends on scp binary behavior) |
| Privilege escalation from Operator → Admin | HIGH | LOW |

### Why Likelihood Is Low

1. **CVE-2025-47421 is likely patched** in our firmware (3.002.1061 > 3.002.0040)
2. **Custom SCP binary** hardens against most exploitation vectors
3. **Requires authenticated SSH access** — not remotely exploitable without credentials
4. **Chroot enforcement** limits filesystem access even if argument injection succeeds

---

## 5. Firmware Evidence

| File | Location | Relevance |
|------|----------|-----------|
| `sshShell.sh` | `/system/bin/` | Login shell with unquoted variable expansion and weak `-t` check |
| `scp` | `/system/bin/` | Custom 26KB SCP binary with `-oPermitLocalCommand=no` hardcoded |
| `libAuditLog.so` | `/system/lib/` | Audit logging for SSH/SCP operations |

---

## 6. CVE Regression Status

| CVE | Affected Versions | Our Version | Status |
|-----|-------------------|-------------|--------|
| CVE-2025-47421 | 3.001.0031–3.001.0034 | 3.002.1061 | **Likely PATCHED** (newer than fix version 3.002.0040) |

The underlying `sshShell.sh` pattern (unquoted expansion) persists in the codebase even after the CVE fix. The fix likely added additional validation or quoting around the specific exploitation vector, but the fragile coding pattern remains — future modifications to the script could reintroduce the vulnerability.

---

## 7. Suggested Remediation

1. **Quote all variable expansions**: Change `scp -U $SCP_PARAM $new_cmd` to `scp -U "$SCP_PARAM" "$new_cmd"` throughout the script
2. **Use arrays instead of string splitting**: Parse SCP arguments into a bash array rather than relying on word splitting
3. **Strengthen operator check**: Replace `grep " -t"` with proper argument parsing (e.g., `getopt` or positional parameter analysis)
4. **Enforce chroot in scp binary**: Validate all paths are within the allowed chroot before opening files, regardless of command-line arguments

---

## 8. Limitations

- **No live SSH access**: The emulation environment does not include sshd with the custom sshShell.sh. This analysis is entirely from static analysis of the script and binary.
- **Likely patched**: Our firmware is newer than the CVE-2025-47421 fix. The vulnerable pattern persists in the code, but the specific exploitation path may be mitigated.
- **Requires authentication**: This is an authenticated-only vulnerability — the attacker must have valid SSH credentials.
