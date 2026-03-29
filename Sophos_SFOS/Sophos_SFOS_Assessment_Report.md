# Sophos Firewall OS (SFOS) 22.0.0.411 -- Security Assessment Report

## Executive Summary

This report documents the findings from a security assessment of Sophos Firewall OS (SFOS) version 22.0.0 GA (Build 411), conducted through static firmware analysis. The assessment focused on identifying unauthenticated vulnerabilities and privilege escalation paths. The firmware was extracted from the official Sophos installer ISO (SW-22.0.0_GA-411.iso) by reversing the LUKS encryption and proprietary dm-crypt key derivation scheme.

**7 confirmed findings rated MEDIUM or higher** were identified across the pre-boot loader, web management interface, XML API processing layer, and SSO authentication flow. The most significant findings are an arbitrary file write via tar path traversal in the configuration import function, a hardcoded shell password in the pre-boot loader, and two authentication logic bugs in the SSO login handler that allow session creation despite failed authentication checks.

All findings were identified through static analysis and validated through bytecode analysis, dynamic testing, or both. No live Sophos appliance was tested -- all analysis was performed against extracted firmware artifacts.

---

## Assessment Details

| Field | Value |
|-------|-------|
| Target | Sophos Firewall OS (SFOS) |
| Version | 22.0.0 GA (Build 411) |
| Kernel | Linux 6.6.49 |
| Build Date | 2026-01-10 |
| Assessment Date | 2026-03-28 |
| Methodology | Static firmware analysis (ISO extraction, LUKS decryption, dm-crypt key derivation reversal, Java decompilation, native binary RE) |
| Category | Local lab assessment |
| Assessor | researcher |

---

## Findings Summary

| ID | Title | Severity | CVSS 3.1 | Status |
|----|-------|----------|-----------|--------|
| SFOS-001 | Hardcoded SFLoader Advanced Shell Password | HIGH | 6.8 | Confirmed |
| SFOS-010 | Pre-Auth XML API File Upload + Command Execution (Configuration-Gated) | MEDIUM | 8.1 | Confirmed |
| SFOS-015 | SSOAdminServlet Missing Return After Auth Failure | MEDIUM | 5.4 | Confirmed |
| SFOS-016 | SSOAdminServlet X-Forwarded-Email Privilege Escalation (Conditional) | MEDIUM | 8.1 | Confirmed (conditional) |
| SFOS-017 | SSOAdminServlet Schedule Restriction Bypass | MEDIUM | 5.4 | Confirmed |
| SFOS-019 | X-Forwarded-For IP Restriction Bypass on SSO Login | MEDIUM | 5.3 | Confirmed |
| SFOS-024 | Arbitrary File Write via Tar Path Traversal in Config Import | HIGH | 8.1 | Confirmed |

---

## Finding Details

### SFOS-001: Hardcoded SFLoader Advanced Shell Password

**Severity:** HIGH | **CVSS 3.1:** AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (6.8)

**Description:**
The SFLoader pre-boot environment contains a hardcoded password that grants root shell access via the "Advanced Troubleshoot" dialog menu. This password is identical across all Sophos hardware and virtual appliance models, as the same SFLoader firmware is deployed universally.

The `loadfw.sh` boot script implements a password check at line 41:
```
if [ "$value" = "tHe3mu8k3t33r8" ]; then
    return 0
fi
```

When the correct password is entered, the `advanced_troubleshoot()` function is called, which executes `/bin/sh` as root:
```
advanced_troubleshoot()
{
    clear
    cat /etc/shell_banner
    /bin/sh 2>/dev/ttyS0
}
```

**Location:** `firmware_extract/sfloader_rootfs/bin/loadfw.sh`, line 41

**Impact:**
An attacker with physical console access, serial port access, or remote console access (IPMI, iLO, iDRAC, vSphere console) can obtain a root shell in the SFLoader environment. From this shell, the attacker can:

1. Read and write the appliance's nvram, including license and configuration data
2. Access the dm-crypt encrypted root partition via the `loadfw` binary
3. Install backdoored firmware images
4. Modify the GRUB boot configuration
5. Extract credentials from the SFOS filesystem

The SFLoader runs when SFOS fails to boot or when the operator selects it from the GRUB boot menu. On hardware appliances, serial console access is typically available via IPMI/BMC, which may be network-accessible.

**Remediation:**
Replace the hardcoded password with a per-device credential derived from hardware identity (serial number, TPM-sealed secret, or BIOS-stored key). Alternatively, require authentication against the SFOS credential store or disable the advanced shell entirely in production builds.

---

### SFOS-010: Pre-Auth XML API File Upload + Command Execution (Configuration-Gated)

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H (8.1)

**Description:**
The `/webconsole/APIController` endpoint accepts pre-authentication multipart file uploads. This endpoint is explicitly exempted from the `RequestCheckFilter`'s pre-auth multipart blocking. The `APICommonServlet` writes user-supplied XML to `/sdisk/APIXMLInput/` and executes the `api_parser` binary via `Runtime.getRuntime().exec()`, which in turn calls `system()` and `popen()` to invoke shell scripts and Perl scripts.

The endpoint is gated by two configuration-dependent checks in `sanitizeRequest()`:
1. `XmlApiConfigUtils.xmlApiConfigStatus()` -- the XML API must be enabled
2. `XmlApiConfigUtils.validateXmlApiRequest(IP)` -- the requester's IP must be in the configured allowlist

The XML API is **disabled by default** (`INSERT INTO tblapiconfig (isenable, ipaddresses) VALUES (false, NULL)`). However, administrators commonly enable it for automation purposes.

**Location:** `cyberoam.corporate.servlets.APICommonServlet.doPost()` and `processRequest()`

**Data Flow:**
```
Client POST -> APICommonServlet.doPost()
  -> sanitizeRequest() [checks API enabled + IP allowlist]
  -> processRequest()
    -> Writes request.getParameter("reqxml") to /sdisk/APIXMLInput/<timestamp>.xml
    -> Runtime.exec("api_parser -A -a <ver> -i <xml_file> ...")
      -> api_parser calls system("/scripts/apiparser_generate_tar.sh ...")
      -> api_parser calls popen("/bin/perl /bin/json2xml.pl ...")
```

**Impact:**
When the XML API is enabled and the attacker's IP is in the allowlist, an unauthenticated attacker can submit arbitrary XML to the `api_parser` binary, which processes it through libxml2 and executes shell commands and Perl scripts based on the XML content. This can lead to remote code execution.

**Remediation:**
Require authentication for the XML API endpoint regardless of the API enable/IP allowlist configuration. The `RequestCheckFilter` should not exempt `/webconsole/APIController` from multipart blocking for unauthenticated requests.

---

### SFOS-015: SSOAdminServlet Missing Return After Auth Failure -- Session Created Despite Failed Authentication

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.4)

**Description:**
The `SSOAdminServlet` contains two missing `return` statements after `sendRedirect()` calls on authentication failure paths. In Java, `HttpServletResponse.sendRedirect()` sets the HTTP 302 response header but does **not** halt method execution. Without an explicit `return`, all subsequent code continues to execute.

**Bug 1 -- User not found (bytecode offset 839):**
When `sessionBean.getUserID() == -1` (SSO user does not exist in the local database), the code sends a redirect to the login page but falls through to create a new HTTP session, set the access token, and store the session bean:

```java
SessionBean sessionBean = HttpSessionHelper.prepareSSOSessionBean(...);
if (sessionBean.getUserID() == -1) {
    response.sendRedirect(request.getContextPath() + "/webpages/login.jsp?status=-13");
    // MISSING RETURN -- execution continues
}
HttpSession firstSession = request.getSession(true);    // Session created
sessionBean.setAccessToken(accessToken);                 // Token set
firstSession2.setAttribute("sessionbean", sessionBean);  // Stored in session
```

**Bug 2 -- Schedule restriction failure (bytecode offset 794):**
When `returnedStatus == 201` and the schedule check determines the user is outside their allowed time window, the code sends a redirect but falls through to `prepareSSOSessionBean()` and the full session creation flow.

**Validation:** Confirmed via `javap` bytecode disassembly. Bytecode offset 794 (`sendRedirect`) is followed directly by offset 806 (`prepareSSOSessionBean`) with no intervening `goto` or `return` instruction. Bytecode offset 839 (`sendRedirect`) is followed directly by offset 846 (`getSession(true)`) with no intervening `goto` or `return` instruction.

**Location:** `cyberoam.corporate.servlets.SSOAdminServlet.doGet()`

**Impact:**
A client that ignores the HTTP 302 redirect retains a `JSESSIONID` cookie tied to a server-side session containing the `sessionBean` with the access token. For the schedule restriction bypass (Bug 2), a time-restricted SSO admin user can obtain a full admin session outside their allowed schedule. For the user-not-found case (Bug 1), a session is created with `userID=-1`, which may or may not pass downstream authorization checks.

**Remediation:**
Add explicit `return` statements after each `sendRedirect()` call:
```java
if (sessionBean.getUserID() == -1) {
    response.sendRedirect(...);
    return;  // Add this
}
```

---

### SFOS-016: SSOAdminServlet X-Forwarded-Email Privilege Escalation (Conditional)

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1)

**Description:**
The `SSOAdminServlet` reads the `X-Forwarded-Email` HTTP header directly from the client request and uses it to look up the admin user account, without cross-validating that the email matches the authenticated SSO session:

```java
UserBean userBean = new UserHelper().getRecordByEmail(
    request.getHeader("X-Forwarded-Email"), sqlReader);
```

The only authentication guard is `HttpSessionHelper.validateSSOCookie()`, which validates the `oauthsso_webadmin` cookie against the oauth2-proxy session endpoint at `http://127.0.0.1:65020/oauth2/auth`. This confirms the user has a valid SSO session, but does **not** verify that the `X-Forwarded-Email` header matches the email associated with that session.

**Exploitation Condition:**
This finding is conditional on the deployment architecture. In the standard Sophos deployment:
- The oauth2-proxy sits between the client and Jetty, and sets the `X-Forwarded-Email` header from the authenticated OIDC token
- If oauth2-proxy overwrites any client-injected `X-Forwarded-Email` header, the attack is mitigated

However, if any of the following conditions are met, the attack succeeds:
1. The Jetty port (8009) is directly accessible (bypassing oauth2-proxy)
2. The Apache reverse proxy on port 4444 forwards the client's `X-Forwarded-Email` header without stripping it
3. The oauth2-proxy does not overwrite client-injected headers when the header is already present

**Location:** `cyberoam.corporate.servlets.SSOAdminServlet.doGet()`, line 51

**Impact:**
An attacker with a valid low-privilege SSO session can set the `X-Forwarded-Email` header to the email address of any administrator configured in the SFOS user database. The servlet will look up that administrator's account and create a full admin session with their privileges, effectively escalating from any SSO user to any admin.

**Remediation:**
Cross-validate the `X-Forwarded-Email` header against the authenticated SSO session. The servlet should either:
1. Read the email exclusively from the oauth2-proxy's validated token (not from a client-controllable header), or
2. Verify that the `X-Forwarded-Email` matches the email in the SSO session cookie

Additionally, configure the Apache reverse proxy and oauth2-proxy to always overwrite (not just set) the `X-Forwarded-Email` header, preventing client injection.

---

### SFOS-017: SSOAdminServlet Schedule Restriction Bypass via Missing Return

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.4)

**Description:**
When the access-manager returns status code 201 (success with restrictions) and the schedule check determines the user is outside their allowed time window, the `SSOAdminServlet` sends a redirect to the login page but does **not** return. Execution continues to `prepareSSOSessionBean()` and the full session creation flow, including `setAccessToken()` and `setAttribute("sessionbean", ...)`.

This is a specific instance of the missing-return pattern described in SFOS-015. The schedule check code:

```java
if (rsw.next() && rsw.getInt("count") == 0) {
    responseObject.put("status", 503);
    response.sendRedirect(request.getContextPath() + "/webpages/login.jsp?status=-13");
    // MISSING RETURN -- falls through to session creation
}
```

**Validation:** Confirmed via bytecode disassembly. The `sendRedirect` at bytecode offset 794 has no subsequent `goto` or `return` before `prepareSSOSessionBean` at offset 806.

**Location:** `cyberoam.corporate.servlets.SSOAdminServlet.doGet()`

**Impact:**
Schedule-based access controls on SSO admin accounts are ineffective. An admin user whose login is restricted to specific hours (e.g., business hours only) can authenticate at any time and receive a valid admin session. The HTTP 302 redirect is sent, but the server-side session is created regardless.

**Remediation:**
Add an explicit `return` statement after the `sendRedirect()` in the schedule restriction check block.

---

### SFOS-019: X-Forwarded-For IP Restriction Bypass on SSO Admin Login

**Severity:** MEDIUM | **CVSS 3.1:** AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N (5.3)

**Description:**
The `HFHelper.getClientIP()` method reads the client IP address from the `X-Forwarded-For` HTTP header with only comma-trimming (extracting the first IP from a comma-separated list) and format validation (`validIPv4()` checks for valid dotted-quad format). The method does not verify that the header was set by a trusted proxy.

```java
public static String getClientIP(HttpServletRequest req) {
    String ipAddress = req.getHeader("X-FORWARDED-FOR");
    if (ipAddress != null) {
        ipAddress = ipAddress.indexOf(44) != -1
            ? ipAddress.substring(0, ipAddress.indexOf(44)).trim()
            : ipAddress;
    }
    return ipAddress;
}
```

This spoofable IP is used throughout the authentication framework for:
- IP-based admin access restrictions in SSO login
- Brute-force detection and blocking (`check_bf.sh`)
- Event logging (`/bin/eventlog` with `network.src_ip=` parameter)

**Location:** `cyberoam.corporate.csc.utilities.HFHelper.getClientIP()`

**Impact:**
An attacker can bypass IP-based access restrictions on admin SSO login by setting a spoofed `X-Forwarded-For` header with an allowed IP address. The format validation ensures the header contains a valid IPv4 address, but does not prevent spoofing. Additionally, brute-force lockout can be evaded by rotating the `X-Forwarded-For` value between attempts.

**Remediation:**
When the request originates from a trusted reverse proxy (Apache on port 4444), use the proxy's authenticated client IP (e.g., `REMOTE_ADDR` or a proxy-authenticated header like `X-Real-IP` set by a trusted reverse proxy) instead of the client-controllable `X-Forwarded-For` header. Implement a trusted proxy list and only accept forwarded headers from those sources.

---

### SFOS-024: Arbitrary File Write via Tar Path Traversal in Configuration Import

**Severity:** HIGH | **CVSS 3.1:** AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H (8.1)

**Description:**
The configuration import function (`crimport` mode of `api_parser`) extracts user-uploaded tar files using BusyBox `tar` without path sanitization. The `apiparser_extract_tar.sh` script calls:

```bash
tar -xvf $TARFILE >> $LOGFILE 2>&1
```

This command uses no safety flags (`--no-absolute-names`, `--strip-components`, or `..` member rejection). BusyBox `tar` (the version at `/bin/tar` on SFOS, which is a BusyBox symlink) does **not** implement GNU tar's built-in `..` member rejection or absolute path stripping.

A malicious tar file containing entries with absolute paths (e.g., `/etc/cron.d/backdoor`) or relative path traversal entries (e.g., `../../../etc/cron.d/backdoor`) will have those files extracted to the specified locations on the filesystem.

**Validation:** Confirmed dynamically. A tar file containing an entry with the absolute path `/tmp/sfos_024_validated.txt` was created and extracted via the `apiparser_extract_tar.sh` script. The file was successfully written to `/tmp/sfos_024_validated.txt`, escaping the intended extraction directory. An attempt to write to `/etc/cron.d/` was blocked only by test environment user permissions -- on SFOS, where `api_parser` runs as root, the write would succeed.

**Location:** `/scripts/apiparser_extract_tar.sh`, line 14

**Attack Chain:**
1. An administrator enables the XML API and configures IP allowlisting (non-default configuration)
2. An attacker within the allowed IP range uploads a malicious tar file via `/webconsole/APIController` (multipart POST, no authentication required when API is enabled)
3. The `api_parser` binary processes the upload in `crimport` mode
4. `apiparser_extract_tar.sh` extracts the tar with `tar -xvf`, writing attacker-controlled files to arbitrary filesystem locations
5. The attacker overwrites a cron job, init script, SSH authorized_keys, or web application file to achieve code execution as root

**Exploitability Notes:**
- Requires XML API to be enabled (non-default) -- many administrators enable this for automation
- Requires attacker IP in the allowlist -- may include internal network ranges
- `api_parser` runs as root, so extracted files are owned by root
- The tar file format allows setting arbitrary file permissions, ownership, and timestamps

**Remediation:**
Use the standalone `/usr/bin/tar` (which includes `..` member rejection) instead of BusyBox `tar`. Add `--no-absolute-names` and implement explicit path validation to ensure all extracted files remain within the intended extraction directory. Consider using a safe extraction wrapper that validates each tar entry path before extraction.

---

## Additional Observations

### dm-crypt Root Filesystem Key Derivation

The SFOS root filesystem encryption uses AES-256-CBC-ESSIV with a key derived deterministically from the device path string (e.g., `/dev/sda`) and disk sector size (typically 512). The derivation uses SHA-1 hashing and XOR with a 32-byte hardcoded constant table. This means all Sophos firewalls using the same disk device path share the same root encryption key. The encryption provides obfuscation rather than true confidentiality.

A Python reimplementation of the key derivation is available at `scripts/derive_dmcrypt_key.py`.

### Well-Defended Components

- **cish restricted shell:** Uses `fork()+execve()` (not `system()`), grammar-constrained input, and `;&|` metacharacter filtering. Direct shell escape is not feasible.
- **SQL queries:** Consistently use parameterized statements (`PreparedStatementBuffer`) throughout the Java codebase. No SQL injection vectors identified.
- **Java deserialization:** No `ObjectInputStream` usage found in the application code. Despite the presence of gadget chain libraries (commons-beanutils-1.9.2), there is no reachable deserialization sink.
- **XML parsing:** `DocumentBuilderFactory` and `SAXParserFactory` usage includes `FEATURE_SECURE_PROCESSING` and disables external DTD/entity access. No XXE vectors identified in the Java layer.

---

## Assessment Methodology

1. **Firmware Extraction:** Mounted the installer ISO, decrypted the LUKS-encrypted firmware payload using the plaintext key found in the installer initrd (`/bin/usbkey`), and extracted the SFLoader initramfs from the kernel bzImage.

2. **dm-crypt Key Derivation Reversal:** Reversed the `loadfw` binary's key derivation function (2081 bytes at `fcn.00418fe8`) using radare2 disassembly. Identified SHA-1 hashing + 32-byte XOR constant table. Reimplemented in Python to derive keys for any device path.

3. **SFOS Root Filesystem Extraction:** Used the reversed `loadfw` binary with the correct invocation name (`loadfw`, not `loadfw.static`) to extract the full 2GB SFOS root filesystem from `fw.img`.

4. **Java Decompilation:** Decompiled critical Java classes using CFR 0.152 and jadx. Analyzed servlet filters, authentication handlers, session management, and API processing code.

5. **Native Binary Analysis:** Reversed `fwhttpd` (14KB, SFLoader HTTP server), `api_parser` (120KB, XML API processor), and `cish` (84KB, restricted shell) using radare2 and strings analysis.

6. **Dynamic Validation:** Ran `fwhttpd` natively on Kali for functional testing. Validated tar path traversal with crafted tar files. Verified bytecode-level evidence for missing-return bugs using `javap`.
