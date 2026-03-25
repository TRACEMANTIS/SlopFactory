#!/usr/bin/env python3
"""
Phase 6: Auth, Stats & CLI Attacks
Target: HAProxy v3.3.0

Tests stats page auth, CLI socket access, ACL bypass, and stick-table attacks.
"""

import socket
import time
import json
import os
import traceback
import base64
import hashlib
import itertools

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy/evidence"
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "phase6_auth_stats_cli.json")

HOST = "127.0.0.1"
STATS_PORT = 8404
HTTP_PORT = 8180
HTTPS_PORT = 8443
LUA_PORT = 8085
CLI_SOCKET = "/tmp/haproxy.sock"

# Known credentials
STATS_USER = "admin"
STATS_PASS = "TestPass123"


class EvidenceCollector:
    def __init__(self):
        self.findings = []
        self.tests = []
        self.test_count = 0
        self.anomaly_count = 0
        self.finding_count = 0

    def add_test(self, category, name, result, details="", severity=None, raw_data=None):
        self.test_count += 1
        entry = {"id": self.test_count, "category": category, "name": name,
                 "result": result, "details": details, "timestamp": time.time()}
        if severity: entry["severity"] = severity
        if raw_data: entry["raw_data"] = raw_data
        self.tests.append(entry)
        if result == "ANOMALY": self.anomaly_count += 1
        elif result in ("VULNERABLE", "FINDING"):
            self.finding_count += 1
            self.findings.append(entry)
        status = f"[{result}]"
        sev = f" ({severity})" if severity else ""
        print(f"  {status:14s} {category}/{name}{sev}")
        if details and result in ("VULNERABLE", "FINDING", "ANOMALY"):
            for line in str(details).split("\n")[:3]:
                print(f"               {line}")

    def save(self):
        data = {"phase": "Phase 6: Auth, Stats & CLI Attacks",
                "target": "HAProxy v3.3.0", "timestamp": time.time(),
                "summary": {"total_tests": self.test_count,
                           "anomalies": self.anomaly_count,
                           "findings": self.finding_count},
                "findings": self.findings, "tests": self.tests}
        with open(EVIDENCE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\n[*] Evidence saved: {EVIDENCE_FILE}")
        print(f"    Tests: {self.test_count} | Anomalies: {self.anomaly_count} | Findings: {self.finding_count}")


evidence = EvidenceCollector()


def http_request(host, port, request, timeout=5):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(request)
        resp = b""
        sock.settimeout(timeout)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk: break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        return resp
    except Exception as e:
        return str(e).encode()


def cli_command(cmd, timeout=3):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(CLI_SOCKET)
        sock.sendall((cmd + "\n").encode())
        resp = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk: break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        return resp.decode('utf-8', errors='replace')
    except Exception as e:
        return f"ERROR: {e}"


# ============================================================
# Category 1: Stats Page Authentication
# ============================================================
def test_stats_auth():
    print("\n[*] Category 1: Stats Page Authentication")

    # Test 1.1: Access without auth
    resp = http_request(HOST, STATS_PORT, b"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\n\r\n")
    status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
    evidence.add_test("Stats-Auth", "no_auth",
                     "SAFE" if status_code == b"401" else "FINDING",
                     f"No auth: HTTP {status_code.decode()}")

    # Test 1.2: Valid credentials
    creds = base64.b64encode(f"{STATS_USER}:{STATS_PASS}".encode()).decode()
    resp = http_request(HOST, STATS_PORT,
                       f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Basic {creds}\r\n\r\n".encode())
    status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
    evidence.add_test("Stats-Auth", "valid_creds",
                     "SAFE" if status_code == b"200" else "ANOMALY",
                     f"Valid creds: HTTP {status_code.decode()}")

    # Test 1.3: Invalid credentials
    bad_creds = base64.b64encode(b"admin:wrong").decode()
    resp = http_request(HOST, STATS_PORT,
                       f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Basic {bad_creds}\r\n\r\n".encode())
    status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
    evidence.add_test("Stats-Auth", "invalid_creds",
                     "SAFE" if status_code == b"401" else "FINDING",
                     f"Bad creds: HTTP {status_code.decode()}")

    # Test 1.4: Timing oracle — measure response times for valid vs invalid users
    times_valid_user = []
    times_invalid_user = []
    for _ in range(10):
        # Valid user, wrong password
        cred = base64.b64encode(b"admin:wrongpass").decode()
        start = time.time()
        http_request(HOST, STATS_PORT,
                    f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Basic {cred}\r\n\r\n".encode(),
                    timeout=3)
        times_valid_user.append(time.time() - start)

        # Invalid user
        cred = base64.b64encode(b"nonexistent:wrongpass").decode()
        start = time.time()
        http_request(HOST, STATS_PORT,
                    f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Basic {cred}\r\n\r\n".encode(),
                    timeout=3)
        times_invalid_user.append(time.time() - start)

    avg_valid = sum(times_valid_user) / len(times_valid_user)
    avg_invalid = sum(times_invalid_user) / len(times_invalid_user)
    diff_ms = abs(avg_valid - avg_invalid) * 1000

    evidence.add_test("Stats-Auth", "timing_oracle",
                     "FINDING" if diff_ms > 5 else "SAFE",
                     f"Valid user avg: {avg_valid*1000:.1f}ms, Invalid user avg: {avg_invalid*1000:.1f}ms, Diff: {diff_ms:.1f}ms",
                     "MEDIUM" if diff_ms > 5 else None,
                     {"avg_valid_ms": avg_valid*1000, "avg_invalid_ms": avg_invalid*1000,
                      "diff_ms": diff_ms})

    # Test 1.5: Auth bypass attempts
    bypass_tests = [
        ("empty_auth", b"Authorization: Basic \r\n"),
        ("null_password", base64.b64encode(b"admin:\x00").decode()),
        ("double_colon", base64.b64encode(b"admin:Test:Pass123").decode()),
        ("unicode_user", base64.b64encode("admin\u0000:TestPass123".encode()).decode()),
        ("case_user", base64.b64encode(b"Admin:TestPass123").decode()),
        ("trailing_space", base64.b64encode(b"admin :TestPass123").decode()),
        ("bearer_token", None),  # Use Bearer instead of Basic
    ]
    for label, cred in bypass_tests:
        if label == "empty_auth":
            req = f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\n{cred.decode()}\r\n".encode()
        elif label == "bearer_token":
            req = f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Bearer faketoken\r\n\r\n".encode()
        else:
            req = f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Basic {cred}\r\n\r\n".encode()
        resp = http_request(HOST, STATS_PORT, req)
        status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
        evidence.add_test("Stats-Auth", f"bypass_{label}",
                         "SAFE" if status_code == b"401" else "FINDING",
                         f"Bypass {label}: HTTP {status_code.decode()}",
                         "HIGH" if status_code != b"401" else None)

    # Test 1.6: No account lockout
    for i in range(20):
        cred = base64.b64encode(f"admin:wrong{i}".encode()).decode()
        http_request(HOST, STATS_PORT,
                    f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Basic {cred}\r\n\r\n".encode(),
                    timeout=2)
    # Try valid creds after 20 failed attempts
    creds = base64.b64encode(f"{STATS_USER}:{STATS_PASS}".encode()).decode()
    resp = http_request(HOST, STATS_PORT,
                       f"GET /stats HTTP/1.1\r\nHost: 127.0.0.1:8404\r\nAuthorization: Basic {creds}\r\n\r\n".encode())
    status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
    evidence.add_test("Stats-Auth", "no_lockout",
                     "ANOMALY" if status_code == b"200" else "SAFE",
                     f"After 20 failed attempts, valid login: HTTP {status_code.decode()}",
                     "LOW" if status_code == b"200" else None)


# ============================================================
# Category 2: Prometheus Metrics & Info Disclosure
# ============================================================
def test_info_disclosure():
    print("\n[*] Category 2: Information Disclosure")

    # Test 2.1: Prometheus metrics (may be unauthenticated)
    resp = http_request(HOST, STATS_PORT, b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:8404\r\n\r\n")
    status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    has_metrics = b"haproxy_" in body
    evidence.add_test("Info-Disclosure", "prometheus_unauth",
                     "FINDING" if has_metrics and status_code == b"200" else "SAFE",
                     f"Prometheus: HTTP {status_code.decode()}, has metrics: {has_metrics}",
                     "MEDIUM" if has_metrics else None,
                     {"has_metrics": has_metrics, "sample": body[:500].decode('utf-8', errors='replace')})

    # Test 2.2: CLI show info
    resp = cli_command("show info")
    has_version = "version" in resp.lower() and "haproxy" in resp.lower()
    evidence.add_test("Info-Disclosure", "cli_show_info",
                     "FINDING" if has_version else "SAFE",
                     f"CLI show info: {'version disclosed' if has_version else 'restricted'}",
                     "INFO" if has_version else None,
                     {"response_preview": resp[:500]})

    # Test 2.3: CLI show env
    resp = cli_command("show env")
    has_env = "PATH=" in resp or "HOME=" in resp or "USER=" in resp
    evidence.add_test("Info-Disclosure", "cli_show_env",
                     "FINDING" if has_env else "SAFE",
                     f"CLI show env: {'EXPOSES ALL ENVIRONMENT VARIABLES' if has_env else 'restricted'}",
                     "MEDIUM" if has_env else None,
                     {"has_sensitive": has_env, "preview": resp[:500]})

    # Test 2.4: CLI show proc
    resp = cli_command("show proc")
    evidence.add_test("Info-Disclosure", "cli_show_proc",
                     "ANOMALY" if "pid" in resp.lower() else "SAFE",
                     f"CLI show proc: {resp.strip()[:200]}")

    # Test 2.5: CLI show pools
    resp = cli_command("show pools")
    evidence.add_test("Info-Disclosure", "cli_show_pools",
                     "ANOMALY" if "pool" in resp.lower() else "SAFE",
                     f"CLI show pools: {resp.strip()[:200]}")

    # Test 2.6: Error pages version disclosure
    resp = http_request(HOST, HTTP_PORT, b"GET /nonexistent HTTP/1.1\r\nHost: 127.0.0.1:8180\r\n\r\n")
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    has_version = b"haproxy" in body.lower()
    evidence.add_test("Info-Disclosure", "error_page_version",
                     "ANOMALY" if has_version else "SAFE",
                     f"Error page version disclosure: {has_version}",
                     "INFO" if has_version else None)

    # Test 2.7: Server header disclosure
    server_header = b""
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"server:"):
            server_header = line
            break
    evidence.add_test("Info-Disclosure", "server_header",
                     "ANOMALY" if server_header else "SAFE",
                     f"Server header: {server_header.decode('utf-8', errors='replace')[:200]}")


# ============================================================
# Category 3: CLI Socket Security
# ============================================================
def test_cli_security():
    print("\n[*] Category 3: CLI Socket Security")

    # Test 3.1: CLI access without auth
    resp = cli_command("help")
    has_help = "show" in resp.lower() or "help" in resp.lower()
    evidence.add_test("CLI-Security", "no_auth_access",
                     "FINDING" if has_help else "SAFE",
                     f"CLI access without auth: {'GRANTED' if has_help else 'denied'}",
                     "MEDIUM" if has_help else None)

    # Test 3.2: Attempt to modify runtime config
    dangerous_cmds = [
        ("disable_server", "disable server webfarm/web1"),
        ("enable_server", "enable server webfarm/web1"),
        ("set_weight", "set weight webfarm/web1 50%"),
        ("shutdown_sessions", "shutdown sessions server webfarm/web1"),
        ("clear_counters", "clear counters"),
        ("show_stat", "show stat"),
        ("show_servers", "show servers state"),
        ("show_backend", "show backend"),
        ("show_sess", "show sess"),
        ("show_table", "show table"),
    ]
    for label, cmd in dangerous_cmds:
        resp = cli_command(cmd)
        is_error = "unknown" in resp.lower() or "permission" in resp.lower() or "error" in resp.lower()
        is_success = resp.strip() and not is_error
        if "disable" in cmd or "shutdown" in cmd or "set" in cmd or "clear" in cmd:
            evidence.add_test("CLI-Security", label,
                             "FINDING" if is_success and not is_error else "SAFE",
                             f"CLI '{cmd}': {'EXECUTED' if is_success else 'blocked'}\n{resp.strip()[:200]}",
                             "HIGH" if is_success and not is_error else None)
        else:
            evidence.add_test("CLI-Security", label,
                             "ANOMALY" if is_success else "SAFE",
                             f"CLI '{cmd}': {resp.strip()[:200]}")

    # Test 3.3: Command injection via CLI
    injection_cmds = [
        ("semicolon", "show info; id"),
        ("pipe", "show info | id"),
        ("backtick", "show info `id`"),
        ("dollar", "show info $(id)"),
        ("newline", "show info\nid"),
    ]
    for label, cmd in injection_cmds:
        resp = cli_command(cmd)
        has_uid = "uid=" in resp
        evidence.add_test("CLI-Security", f"inject_{label}",
                         "FINDING" if has_uid else "SAFE",
                         f"Injection '{label}': {'COMMAND EXECUTED!' if has_uid else 'safe'}\n{resp.strip()[:200]}",
                         "CRITICAL" if has_uid else None)

    # Test 3.4: Buffer overflow attempt in CLI
    long_cmd = "show " + "A" * 10000
    resp = cli_command(long_cmd)
    evidence.add_test("CLI-Security", "buffer_overflow",
                     "SAFE", f"Long command: {resp.strip()[:200]}")

    # Test 3.5: Null byte in CLI command
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(CLI_SOCKET)
        sock.sendall(b"show info\x00secret_command\n")
        resp = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk: break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        evidence.add_test("CLI-Security", "null_byte",
                         "SAFE", f"Null byte in command: {resp.decode('utf-8', errors='replace')[:200]}")
    except Exception as e:
        evidence.add_test("CLI-Security", "null_byte", "ERROR", str(e))


# ============================================================
# Category 4: ACL Bypass
# ============================================================
def test_acl_bypass():
    print("\n[*] Category 4: ACL Bypass Attempts")

    # Test 4.1: Host header manipulation
    hosts = [
        ("normal", b"127.0.0.1:8180"),
        ("localhost", b"localhost:8180"),
        ("ipv6_loopback", b"[::1]:8180"),
        ("double_host", b"127.0.0.1:8180\r\nHost: evil.com"),
        ("empty_host", b""),
        ("space_host", b" 127.0.0.1:8180"),
        ("tab_host", b"\t127.0.0.1:8180"),
        ("case_host", b"127.0.0.1:8180"),
    ]
    for label, host_val in hosts:
        if label == "double_host":
            req = b"GET / HTTP/1.1\r\nHost: " + host_val + b"\r\n\r\n"
        else:
            req = b"GET / HTTP/1.1\r\nHost: " + host_val + b"\r\n\r\n"
        resp = http_request(HOST, HTTP_PORT, req)
        status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
        evidence.add_test("ACL-Bypass", f"host_{label}",
                         "SAFE", f"Host={host_val[:50]}: HTTP {status_code.decode()}")

    # Test 4.2: Method-based ACL bypass
    methods = [b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"OPTIONS",
               b"HEAD", b"TRACE", b"CONNECT", b"PROPFIND", b"CUSTOM"]
    for method in methods:
        req = method + b" / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\n\r\n"
        resp = http_request(HOST, HTTP_PORT, req)
        status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
        evidence.add_test("ACL-Bypass", f"method_{method.decode()}",
                         "SAFE", f"Method {method.decode()}: HTTP {status_code.decode()}")

    # Test 4.3: Path-based ACL bypass
    paths = [
        ("/stats", b"/stats"),
        ("/stats/", b"/stats/"),
        ("/Stats", b"/Stats"),
        ("/STATS", b"/STATS"),
        ("/../stats", b"/../stats"),
        ("/.%2e/stats", b"/.%2e/stats"),
        ("/stats%00", b"/stats\x00"),
        ("/stats;param", b"/stats;param"),
        ("/stats?query", b"/stats?query"),
        ("/stats#frag", b"/stats#frag"),
    ]
    for label, path in paths:
        req = b"GET " + path + b" HTTP/1.1\r\nHost: 127.0.0.1:8180\r\n\r\n"
        resp = http_request(HOST, HTTP_PORT, req)
        status_code = resp.split(b" ")[1] if len(resp.split(b" ")) > 1 else b"0"
        evidence.add_test("ACL-Bypass", f"path_{label}",
                         "SAFE", f"Path {label}: HTTP {status_code.decode()}")


# ============================================================
# Category 5: Stick-Table & Rate Limiting
# ============================================================
def test_stick_table():
    print("\n[*] Category 5: Stick-Table & Rate Limiting")

    # Test 5.1: Show stick tables
    resp = cli_command("show table")
    has_tables = "table" in resp.lower() and resp.strip()
    evidence.add_test("Stick-Table", "list_tables",
                     "ANOMALY" if has_tables else "SAFE",
                     f"Stick tables: {resp.strip()[:300]}")

    # Test 5.2: Rapid request flood (check if rate limiting exists)
    start = time.time()
    success_count = 0
    for i in range(50):
        resp = http_request(HOST, HTTP_PORT,
                           b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\n\r\n", timeout=2)
        if b"200" in resp.split(b"\r\n")[0]:
            success_count += 1
    elapsed = time.time() - start
    evidence.add_test("Stick-Table", "rapid_flood_50",
                     "ANOMALY" if success_count == 50 else "SAFE",
                     f"50 rapid requests in {elapsed:.2f}s: {success_count}/50 succeeded\n"
                     f"Rate: {50/elapsed:.0f} req/s — {'no rate limiting' if success_count > 45 else 'rate limited'}",
                     "LOW" if success_count == 50 else None)


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("Phase 6: Auth, Stats & CLI Attacks")
    print(f"Target: HAProxy v3.3.0 @ {HOST}")
    print("=" * 70)

    try:
        test_stats_auth()
        test_info_disclosure()
        test_cli_security()
        test_acl_bypass()
        test_stick_table()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        traceback.print_exc()
    finally:
        evidence.save()
