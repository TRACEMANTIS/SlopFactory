# [REDACTED-ID]_005: CWS Unauthenticated Endpoint (Auth-Ticket Exclusion) -- Static Only

| Field | Value |
|-------|-------|
| **Finding ID** | [REDACTED-ID]_005 |
| **Title** | CWS Endpoint Excluded from Authentication (Backend Not Running) |
| **Severity** | N/A -- Backend service not running on any tested device |
| **Type** | CWE-306: Missing Authentication for Critical Function (configuration-level) |
| **Affected Products** | DMPS3-4K-STR, DM-TXRX-100-STR, DGE-100, TS-1542, DM-DGE-200-C, TS-1542-C, MERCURY, and all Crestron devices sharing the FW 2.x codebase |
| **Firmware Analyzed** | DMPS3 AirMedia PufVersion 1.5010.00023 (Build: February 23, 2024) |
| **Discovery Method** | Static analysis of lighttpd configuration + libRXModeHandler.so binary |
| **Live Validation** | CWS backend confirmed DEAD on all [REDACTED-COUNT] FW 2.x devices in device survey |
| **Date Discovered** | 2026-03-03 |
| **Researchers** | [REDACTED] Team |

---

## Summary

The lighttpd web server configuration in FW 2.x firmware excludes the `/cws` (Crestron Web Scripting) endpoint from `mod_auth_ticket` authentication enforcement, following the same pattern identified in FW 3.x ([REDACTED-ID]_004). The CWS FastCGI backend (`libRXModeHandler.so`) routes to port 40235 and contains administrative operations including `uploadProject`, `upgradeFirmware`, `runCommandAtBashPrompt`, `rebootDevice`, `restoreDevice`, and `setCtpCommand` -- none of which implement internal authentication checks.

**However, the CWS backend service was not running on any of the [REDACTED-COUNT] FW 2.x devices tested during the device survey scan.** All multiple test devices returned connection refused or timeout on the CWS endpoint. This matches the FW 3.x assessment (CrestronFW3x), where the CWS backend was also dead across all tested hosts.

This finding is documented for completeness and defense-in-depth assessment. The auth exclusion represents a latent vulnerability that would become exploitable if the CWS backend is enabled in a future firmware update, a configuration change, or on a device variant not represented in the tested fleet.

---

## Affected Component

| Component | Details |
|-----------|---------|
| **Lighttpd Config** | `lighttpd-fcgihandler.conf` |
| **Auth Config** | Auth-ticket exclusion regex includes `/cws` |
| **FastCGI Port** | 40235 (CWS backend) |
| **Handler Library** | `libRXModeHandler.so` (532 KB, ARM32 EABI5) |
| **Backend Status** | **NOT RUNNING** on all multiple tested FW 2.x devices |

---

## Technical Details

### 2.1 Lighttpd Auth Exclusion

The lighttpd configuration routes `/cws` requests to a FastCGI backend on port 40235:

```
# lighttpd-fcgihandler.conf
fastcgi.server += ("/cws" =>
    ((
        "host" => "127.0.0.1",
        "port" => 40235,
        "check-local" => "disable"
    ))
)
```

The authentication configuration excludes `/cws` from the `mod_auth_ticket` validation, using the same regex pattern as FW 3.x:

```
$HTTP["url"] !~ "^/styles.css|^/scripts.js|...|^/cws" {
    auth-ticket.override = 1
    auth-ticket.timeout  = 3600
    ...
}
```

The `!~` negative match means: apply authentication to all URLs **except** those matching the pattern. Since `/cws` is in the exception list, requests to `/cws/*` bypass authentication entirely at the lighttpd layer.

### 2.2 CWS Handler Functions (libRXModeHandler.so)

The CWS handler binary contains the following administrative operations, as identified through static analysis:

| Function | Operation | Impact if Exploitable |
|----------|-----------|----------------------|
| `uploadProject()` | Upload Crestron program to device | Code execution via `system()` calls with filename |
| `upgradeFirmware()` | Trigger firmware up[REDACTED] | Code execution via `runCommandAtBashPrompt()` |
| `runCommandAtBashPrompt()` | Direct bash command execution | Arbitrary command execution as root |
| `rebootDevice()` | Reboot the device | Denial of service |
| `restoreDevice()` | Factory reset the device | Destruction of configuration |
| `setCtpCommand()` | Send arbitrary CTP command | Full CTP console access |
| `resetPassword()` | Reset admin password | Account takeover |

### 2.3 No Internal Authentication in CWS Handler

Consistent with the FW 3.x finding ([REDACTED-ID]_004), the `libRXModeHandler.so` binary contains zero internal authentication enforcement:

- No references to `HTTP_COOKIE`, `Authorization`, `AuthByPasswd`, `REMOTE_USER`, `session`, `token`, or `Bearer`
- No HTTP 401/403 response generation
- No cookie validation or session checking in `processRequestMethod()`
- All security relies entirely on the lighttpd auth-ticket exclusion regex

### 2.4 CWS Backend Status: DEAD on All Tested Devices

The device survey scan ([REDACTED-COUNT] FW 2.x devices) tested CWS endpoint availability:

```json
{
    "cws_alive_count": 1,  // This single device was FW 3.x, not 2.x
    "fw_2x_count": 63      // All [REDACTED-COUNT] FW 2.x devices had CWS backend dead
}
```

On all [REDACTED-COUNT] FW 2.x devices:
- HTTP requests to `/cws/` returned connection errors (FastCGI backend not listening on port 40235)
- lighttpd returned 502/503 errors or connection timeouts
- The CWS FastCGI process was not started by the boot sequence on these device models

### 2.5 Comparison with [REDACTED-ID]_004 (FW 3.x)

| Aspect | [REDACTED-ID]_004 (FW 3.x) | [REDACTED-ID]_005 (FW 2.x) |
|--------|-------------------|-------------------|
| Auth exclusion present | YES | YES |
| CWS handler has internal auth | NO | NO |
| Backend running on tested fleet | NO (0 of [N]) | NO (0 of [N]) |
| Administrative operations in binary | YES (same set) | YES (same set) |
| Exploitable | NOT EXPLOITABLE (backend dead) | NOT EXPLOITABLE (backend dead) |

---

## Impact

### Current Impact: NONE

The CWS backend is not running on any tested FW 2.x device. The authentication exclusion exists in configuration but has no practical effect because there is no backend service to handle the requests.

### Latent Risk Assessment

| Scenario | Impact | Likelihood |
|----------|--------|------------|
| CWS backend enabled in future firmware update | CRITICAL -- unauthenticated admin access | LOW-MEDIUM |
| Device variant with CWS enabled (not in tested fleet) | CRITICAL -- unauthenticated admin access | LOW |
| Third-party service binds to port 40235 | HIGH -- unauthenticated access to that service | VERY LOW |
| Configuration change enables CWS on existing devices | CRITICAL -- unauthenticated admin access | LOW |

### Defense-in-Depth Assessment

Even though the backend is not running, the configuration represents a **defense-in-depth failure**:
- The auth exclusion should not exist for an endpoint capable of device-level administrative operations
- If the backend is ever started (intentionally or accidentally), it will be immediately accessible without authentication
- The CWS handler binary ships on every device, meaning the code is present and only needs to be executed

---

## Evidence

### Lighttpd Configuration Evidence

Auth exclusion regex includes `/cws`:
```
$HTTP["url"] !~ "...|^/cws" { auth-ticket.override = 1 ... }
```

FastCGI routing to port 40235:
```
fastcgi.server += ("/cws" => (("host" => "127.0.0.1", "port" => 40235, ...)))
```

### Fleet Fingerprint Evidence

From `evidence/fleet_fingerprint.json`:
- [REDACTED-COUNT] FW 2.x devices probed
- 0 devices had CWS backend responding
- CWS endpoint returned connection errors on all FW 2.x hosts

### Binary Evidence

`libRXModeHandler.so` (532 KB) contains all CWS handler functions but the corresponding FastCGI process is not started during device boot on FW 2.x device models.

---

## Reproduction Steps (for vendor)

1. Obtain the DMPS3 AirMedia firmware PUF file (version 1.5010.00023)
2. Extract the `system.img` filesystem:
   ```bash
   binwalk -e dmps3_airmedia_1.5010.00023.puf
   mount -o loop,ro system.img /mnt/fw
   ```
3. Confirm the auth exclusion:
   ```bash
   grep -r "cws" /mnt/fw/system/crestron/webserver/sdcard/web/conf/
   # Look for /cws in auth-ticket exclusion regex and FastCGI routing
   ```
4. Confirm the handler binary ships with admin functions:
   ```bash
   strings /mnt/fw/system/lib/libRXModeHandler.so | grep -E "uploadProject|upgradeFirmware|rebootDevice|restoreDevice|runCommandAtBashPrompt"
   ```
5. Attempt to access CWS on a running FW 2.x device:
   ```bash
   curl -sk https://<device_ip>/cws/
   # Expected: 502/503 or connection error (backend not running)
   ```
6. Confirm no CWS FastCGI process is running:
   ```bash
   # On device (if shell access available):
   ps aux | grep -i cws
   netstat -tlnp | grep 40235
   # Expected: no process listening on port 40235
   ```

---

## Suggested Fix

1. **Remove `/cws` from the auth-ticket exclusion regex.** Even though the backend is not currently running, the auth exclusion should not exist for an endpoint with administrative capabilities. If CWS is ever enabled, it should require authentication.
2. **Add authentication enforcement to `libRXModeHandler.so`.** The CWS handler should validate the `AuthByPasswd` cookie or `REMOTE_USER` before dispatching to any module handler. This provides defense-in-depth regardless of lighttpd configuration.
3. **Remove the CWS handler binary if unused.** If CWS is not intended to run on FW 2.x devices, remove `libRXModeHandler.so` from the firmware image to reduce the attack surface.
4. **Restrict the FastCGI port.** If the CWS backend must ship but not run, ensure port 40235 is firewalled or bound to a non-routeable interface.

---

## Status

| Item | Status |
|------|--------|
| **Auth exclusion** | Confirmed via static analysis of lighttpd configuration |
| **Handler functions** | Confirmed via static analysis of libRXModeHandler.so |
| **No internal auth** | Confirmed via Ghidra decompilation (zero auth references) |
| **Backend running** | **NOT RUNNING** on all multiple tested FW 2.x devices |
| **Exploitability** | **NOT EXPLOITABLE** (backend dead) |
| **Classification** | Defense-in-depth failure / latent vulnerability |

---

## CWE Reference

- **CWE-306:** Missing Authentication for Critical Function (auth exclusion + no internal auth in handler)
- **Related:** CWE-288 (Authentication Bypass Using an Alternate Path or Channel)
- **Cross-reference:** [REDACTED-ID]_004 (identical pattern in FW 3.x firmware)
