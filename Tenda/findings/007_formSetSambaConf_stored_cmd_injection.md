# [REDACTED-ID]_007: Stored Command Injection in formSetSambaConf via "guestuser" Parameter

## Summary

The `formSetSambaConf` handler in Tenda AC15 firmware V15.03.05.19 stores the user-supplied `guestuser` HTTP POST parameter to NVRAM configuration via `SetValue("usb.samba.guest.user", guestuser)`. On subsequent handler invocations (non-delete path), the stored value is retrieved via `GetValue("usb.samba.guest.user")` and passed unsanitized to `doSystemCmd("busybox deluser %s", stored_value)`, enabling stored/persistent command injection as root.

## Affected Products

| Product | Firmware Version | Architecture |
|---------|-----------------|-------------|
| Tenda AC15 | V15.03.05.19 (EN) | ARM 32-bit |

## Vulnerability Details

### Function: `formSetSambaConf` (vaddr: 0x000a6320, size: 892 bytes)

### Vulnerable Code Path (Two-Step Attack)

**Step 1: Store malicious username**
```
1. websGetVar(wp, "guestuser", "")  -> var_28h
2. SetValue("usb.samba.guest.user", guestuser)    ; stores to NVRAM
3. CommitCfm()                                     ; persists config
```

**Step 2: Trigger command execution**
```
4. GetValue("usb.samba.guest.user", buf)  -> buf contains attacker's value
5. if (buf[0] != 0):
6.   doSystemCmd("busybox deluser %s", buf)  ; COMMAND INJECTION
```

### Disassembly (ARM) - Step 2 (Injection Point)

```asm
; GetValue("usb.samba.guest.user", stack_buf)
0x000a6518: ldr r2, [0x000a66e4]     ; "usb.samba.guest.user"
0x000a651c: sub r3, fp, 0x70         ; stack buffer destination
0x000a6524: bl  sym.imp.GetValue     ; retrieves stored guestuser

; Check if value is non-empty
0x000a652c: ldrb r3, [fp - 0x70]     ; first byte of stored value
0x000a6530: cmp r3, 0                ; empty check
0x000a6534: beq 0xa6550              ; skip if empty

; doSystemCmd("busybox deluser %s", stored_value)
0x000a653c: ldr r2, [0x000a66e8]     ; format string address
0x000a6540: add r2, r4, r2           ; "busybox deluser %s"
0x000a6544: mov r0, r2               ; format
0x000a6548: sub r3, fp, 0x70         ; arg1 = stored guestuser (UNSANITIZED)
0x000a654c: bl  sym.imp.doSystemCmd   ; STORED COMMAND INJECTION
```

### Format String

The executed command is:
```
busybox deluser <STORED_ATTACKER_VALUE>
```

### Authentication Requirement

This endpoint requires authentication. However:
- Default admin password is **empty**
- Password is stored in plaintext cookie

## Exploitation Path

1. **Store payload**: `POST /goform/SetSambaConf` with `action=set&guestuser=test;id>/tmp/pwned`
   - This stores `test;id>/tmp/pwned` to NVRAM key `usb.samba.guest.user`

2. **Trigger execution**: The `busybox deluser %s` code path executes on subsequent handler invocations when the stored value is non-empty (the "set" path of the handler)

3. **Result**: `busybox deluser test;id>/tmp/pwned` is executed via `system()`, which the shell interprets as two commands:
   - `busybox deluser test` (may fail, does not matter)
   - `id>/tmp/pwned` (arbitrary command as root)

### Persistence

Since the malicious value is stored in NVRAM, the injection payload **survives reboots** and will be triggered every time the Samba configuration handler processes the stored value.

## Binary Protections

| Protection | Status |
|-----------|--------|
| RELRO | No RELRO |
| Stack Canary | No canary found |
| NX | NX enabled |
| PIE | No PIE |
| FORTIFY | No |

## Impact

- **Persistent Remote Code Execution** as root
- Payload survives device reboots (stored in NVRAM)
- Full device compromise
- Requires two-step exploitation (store then trigger)

## Severity Justification

Rated **HIGH** rather than CRITICAL because:
- Requires two separate HTTP requests (store + trigger)
- The trigger condition (non-delete Samba config path) may require specific setup
- [REDACTED-ID]_006 provides a simpler single-request injection path in the same handler

## Analysis Method

Static reverse engineering using radare2. Identified by tracing `guestuser` websGetVar input through SetValue("usb.samba.guest.user") to GetValue retrieval and ultimately to `doSystemCmd("busybox deluser %s")`.

## References

- Related: [REDACTED-ID]_006 (direct injection in same handler via `usbName`)
- Binary: `firmware/binaries/httpd_ac15` (ARM 32-bit, stripped)
- Evidence: `evidence/phase4_targeted_r2_analysis.json`
