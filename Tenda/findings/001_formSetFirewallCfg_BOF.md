# [REDACTED-ID]_001: Stack Buffer Overflow in formSetFirewallCfg via "firewallEn" Parameter

## Summary

The `formSetFirewallCfg` handler in Tenda AC15 firmware V15.03.05.19 and AC20 firmware V16.03.08.12 contains a stack-based buffer overflow vulnerability. User-supplied input from the HTTP POST parameter `firewallEn` is copied to a fixed-size stack buffer using `strcpy()` without bounds checking, allowing an attacker to overwrite the return address and achieve remote code execution.

## Affected Products

| Product | Firmware Version | Architecture | Binary |
|---------|-----------------|-------------|--------|
| Tenda AC15 | V15.03.05.19 | ARM 32-bit (EABI5) | /bin/httpd |
| Tenda AC20 | V16.03.08.12 | MIPS 32-bit | /bin/httpd |

## Vulnerability Details

### Root Cause

In the `formSetFirewallCfg` function (AC15: vaddr 0x000ad470, size 3232 bytes), the handler reads the `firewallEn` HTTP POST parameter using the `websGetVar` wrapper function (`fcn.0002bd4c`), then copies it to a stack buffer using `strcpy()` without any length validation.

### Vulnerable Code Path (AC15 ARM)

```
1. 0x000ad83c: Load string "firewallEn" as parameter name
2. 0x000ad850: Call websGetVar wrapper (fcn.0002bd4c) to get user input
3. 0x000ad854: Store result at [src] on stack
4. 0x000ad85c: Call strlen() on input
5. 0x000ad864: Compare length > 3 (only minimum length check, NO maximum)
6. 0x000ad87c: strcpy(dest, src) — VULNERABLE
   - dest = stack buffer at var_34h (offset 0x34 from frame pointer)
   - src = unbounded user input from "firewallEn" parameter
```

### Stack Layout

- Stack frame size: 0x2f8 (760 bytes)
- Buffer location: var_34h (offset 52 from frame pointer)
- Saved registers: {r4, r5, r6, r7, fp, lr} pushed at function entry
- Distance from buffer to saved LR: ~708 bytes (760 - 52)

### Security Mitigations

| Mitigation | AC15 | AC20 |
|-----------|------|------|
| Stack Canary | **None** | **None** |
| NX | Enabled | **Disabled** |
| PIE | None | None |
| RELRO | None | None |

The AC20 (MIPS) has NX disabled, meaning the stack is executable — a buffer overflow can directly execute shellcode placed on the stack.

### Additional Attack Surface

The same function also contains:
- 11x `doSystemCmd()` calls with format strings like `"iptables -t filter -D INPUT -i %s -p icmp..."`
- A second `strcpy()` call copying `getWispIfName()` result to `var_298h`
- 2x `sprintf()` calls into stack buffers

The `doSystemCmd()` calls pass the interface name (from `var_298h`) directly into iptables commands. If the interface name can be controlled (stored command injection), this is a second RCE vector.

## Reproduction Steps

### Static Analysis Reproduction (r2)

```bash
# Disassemble the vulnerable function
r2 -q -e bin.cache=true -e scr.color=0 \
  -c "aaa; s sym.formSetFirewallCfg; pdf" \
  firmware/binaries/httpd_ac15

# Observe:
# 1. websGetVar("firewallEn") at 0x000ad850
# 2. strcpy(stack_buf, user_input) at 0x000ad87c
# 3. No bounds check between input and copy
```

### PoC Request (for emulated environment)

```http
POST /goform/SetFirewallCfg HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Cookie: password=admin

firewallEn=AAAAAAAAAA...(760+ bytes)...AAAA
```

**Note:** This endpoint requires authentication (not in the R7WebsSecurityHandler whitelist). However, the default admin password is empty (`sys.userpass=` in NVRAM defaults), and the password is stored in a plaintext cookie.

## Impact

- **Confidentiality:** High — Full device compromise allows access to all stored credentials and traffic
- **Integrity:** High — Attacker can modify device configuration, redirect traffic
- **Availability:** High — Device crash or persistent compromise

## CVSS v3.1

**Score: 8.8 (High)** — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

(PR:L because authentication is required, but default password is empty)

## CWE Classification

- **CWE-121:** Stack-based Buffer Overflow
- **CWE-120:** Buffer Copy without Checking Size of Input
- **CWE-787:** Out-of-bounds Write

## Related CVEs

- **CVE-2024-40891:** Similar vulnerability in Tenda AC6/AC8/AC10U/AC15 SetFirewallCfg
- This finding may be a rediscovery if the firmware version matches, or a regression if supposedly patched

## Status

- **Discovery:** Static analysis via r2 disassembly
- **Validation:** Pending (requires emulation or hardware)
- **Disclosure:** Pending
