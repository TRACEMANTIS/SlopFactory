# [REDACTED-ID]_005: Stack Buffer Overflow in formWifiBasicSet via WiFi Password Parameters

## Summary

The `formWifiBasicSet` handler in Tenda AC15 V15.03.05.19 copies WiFi password parameters (`wrlPwd`, `wrlPwd_5g`) to fixed-size stack buffers using `strcpy()` without bounds checking, enabling stack buffer overflow and potential remote code execution.

## Affected Products

| Product | Firmware Version | Architecture |
|---------|-----------------|-------------|
| Tenda AC15 | V15.03.05.19 | ARM 32-bit |
| Tenda AC20 | V16.03.08.12 | MIPS 32-bit (shared handler) |

## Vulnerability Details

### Function: `formWifiBasicSet` (AC15: 0x00092154, size: 6384 bytes)

This is one of the largest handler functions, processing 10+ user input parameters for WiFi configuration.

### Vulnerable Code Path

```
1. websGetVar("wrlPwd", "12345678")  → user-controlled WiFi password
2. strcpy(fp-0x9d, wrlPwd)           → copy to small stack buffer (~64 bytes)
   No bounds checking between step 1 and 2

3. websGetVar("wrlPwd_5g", "12345678") → user-controlled 5GHz password
4. strcpy(fp-0x5d, wrlPwd_5g)          → copy to adjacent stack buffer
   No bounds checking
```

### User Input Parameters

The function reads at least these parameters via websGetVar:
- `wrlPwd` — 2.4GHz WiFi password
- `wrlPwd_5g` — 5GHz WiFi password
- `security` — Security mode
- `security_5g` — 5GHz security mode
- `ssid` — SSID name
- `ssid_5g` — 5GHz SSID
- Additional radio/channel parameters

### Stack Layout

- Stack frame size: Large (6384 byte function)
- `wrlPwd` buffer at fp-0x9d (~64 bytes before next variable)
- `wrlPwd_5g` buffer at fp-0x5d (~64 bytes)
- WPA2 passwords are typically 8-63 characters — buffers are sized for "normal" use

### Exploitation

WiFi passwords in WPA2 can be 8-63 characters. If an attacker sends a password longer than 64 bytes, the `strcpy` overflows the stack buffer, potentially overwriting:
- Adjacent local variables
- Saved frame pointer
- Saved link register (return address)

With no stack canary and no PIE, the return address is at a fixed offset.

## CVSS v3.1

**Score: 8.8 (High)** — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## CWE Classification

- **CWE-121:** Stack-based Buffer Overflow
- **CWE-120:** Buffer Copy without Checking Size of Input

## Status

- **Discovery:** Static analysis via r2 disassembly
- **Validation:** Pending
