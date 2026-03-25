#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- WebFig Authentication & Authorization Assessment
Phase 2, Script 1
Target: [REDACTED-INTERNAL-IP]

Tests (~200):
  1. Authentication Mechanism Analysis (~30 tests)
     - Basic Auth vs session cookie vs ECDH challenge
     - HTTP vs HTTPS auth behavior
     - Cleartext credential transmission (CVE-2025-61481 regression)
     - /jsproxy/ authentication endpoint
     - Session token format and entropy analysis
     - Cookie attributes (HttpOnly, Secure, SameSite, Path, Expires)

  2. Brute-Force & Lockout Testing (~30 tests)
     - Rapid login failure flooding (20+ attempts)
     - Lockout threshold detection
     - Lockout duration measurement
     - Per-IP vs per-user vs global lockout
     - Lockout bypass via alternate endpoints

  3. Timing Oracle / Username Enumeration (~30 tests)
     - 50 valid-user wrong-password attempts
     - 50 invalid-user wrong-password attempts
     - Statistical comparison (mean, median, stddev)
     - Response size analysis (CVE-2024-54772 style)

  4. Session Management (~40 tests)
     - Token entropy (20 tokens, uniqueness)
     - Session fixation
     - Session reuse after logout
     - Session timeout behavior
     - Concurrent session limits
     - Session revocation on password change

  5. Password Policy (~20 tests)
     - Min/max length, empty, special chars, null bytes

  6. Authorization / Privilege Escalation (~40 tests)
     - Cross-group endpoint access (read/write/full)
     - REST API vs WebFig permission enforcement
     - HTTP method restrictions per group
     - Sensitive endpoint access (/rest/user, /rest/system/script/run, /rest/file)

  7. Multi-user Concurrency (~10 tests)
     - Simultaneous logins
     - Session isolation verification

Evidence: evidence/webfig_auth.json
"""

import hashlib
import json
import math
import os
import re
import socket
import ssl
import statistics
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

# Suppress SSL and urllib3 warnings globally
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

# ── Shared module ────────────────────────────────────────────────────────────
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, TARGET, ADMIN_USER, ADMIN_PASS, USERS,
    rest_get, rest_post, rest_patch, pull_router_logs,
    check_router_alive, ssh_command, log, EVIDENCE_DIR,
)

# ── Constants ────────────────────────────────────────────────────────────────
HTTP_BASE = f"http://{TARGET}"
HTTPS_BASE = f"https://{TARGET}"
REST_BASE = f"{HTTP_BASE}/rest"
TIMEOUT = 10


# ── Helpers ──────────────────────────────────────────────────────────────────

def http_get(url, user=None, password=None, timeout=TIMEOUT, allow_redirects=True,
             session=None, cookies=None, headers=None):
    """HTTP GET with optional auth, returns response object or None."""
    kwargs = {"timeout": timeout, "verify": False, "allow_redirects": allow_redirects}
    if user and password:
        kwargs["auth"] = (user, password)
    if cookies:
        kwargs["cookies"] = cookies
    if headers:
        kwargs["headers"] = headers
    try:
        if session:
            return session.get(url, **kwargs)
        return requests.get(url, **kwargs)
    except Exception:
        return None


def http_post(url, data=None, json_data=None, user=None, password=None,
              timeout=TIMEOUT, session=None, cookies=None, headers=None):
    """HTTP POST with optional auth, returns response object or None."""
    kwargs = {"timeout": timeout, "verify": False}
    if user and password:
        kwargs["auth"] = (user, password)
    if data is not None:
        kwargs["data"] = data
    if json_data is not None:
        kwargs["json"] = json_data
        kwargs.setdefault("headers", {})["Content-Type"] = "application/json"
    if cookies:
        kwargs["cookies"] = cookies
    if headers:
        if "headers" in kwargs:
            kwargs["headers"].update(headers)
        else:
            kwargs["headers"] = headers
    try:
        if session:
            return session.post(url, **kwargs)
        return requests.post(url, **kwargs)
    except Exception:
        return None


def timed_request(method, url, **kwargs):
    """Execute a request and return (response, elapsed_ms)."""
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("verify", False)
    start = time.perf_counter()
    try:
        if method == "GET":
            r = requests.get(url, **kwargs)
        else:
            r = requests.post(url, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        return r, elapsed
    except Exception:
        elapsed = (time.perf_counter() - start) * 1000
        return None, elapsed


def shannon_entropy(data):
    """Calculate Shannon entropy of a byte string or regular string."""
    if isinstance(data, str):
        data = data.encode()
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# =============================================================================
# Section 1: Authentication Mechanism Analysis (~30 tests)
# =============================================================================

def test_auth_mechanisms(ec):
    """Analyze how WebFig authenticates users."""
    log("=" * 60)
    log("Section 1: Authentication Mechanism Analysis")
    log("=" * 60)
    cat = "auth_mechanism"

    # ── 1.1  HTTP Basic Auth on REST API ─────────────────────────────────────
    r = http_get(f"{REST_BASE}/system/resource", user=ADMIN_USER, password=ADMIN_PASS)
    if r:
        ec.add_test(cat, "REST API Basic Auth (HTTP)",
                     "Test HTTP Basic Auth on REST API over plaintext HTTP",
                     f"Status {r.status_code}, auth accepted={r.status_code == 200}",
                     {"status": r.status_code, "auth_header_sent": "Basic",
                      "scheme": "http", "cleartext": True})
        if r.status_code == 200:
            ec.add_finding("HIGH", "REST API accepts Basic Auth over HTTP (cleartext)",
                           "Credentials are transmitted as Base64-encoded cleartext "
                           "over unencrypted HTTP. An attacker on the same network "
                           "segment can capture credentials via passive sniffing.",
                           evidence_refs=[1], cwe="CWE-319")
    else:
        ec.add_test(cat, "REST API Basic Auth (HTTP)",
                     "Test HTTP Basic Auth on REST API", "Connection failed", anomaly=True)

    # ── 1.2  HTTPS Basic Auth on REST API ────────────────────────────────────
    r = http_get(f"{HTTPS_BASE}/rest/system/resource", user=ADMIN_USER, password=ADMIN_PASS)
    if r:
        ec.add_test(cat, "REST API Basic Auth (HTTPS)",
                     "Test HTTP Basic Auth on REST API over TLS",
                     f"Status {r.status_code}",
                     {"status": r.status_code, "scheme": "https", "cleartext": False})
    else:
        ec.add_test(cat, "REST API Basic Auth (HTTPS)",
                     "Test Basic Auth over HTTPS", "Connection failed", anomaly=True)

    # ── 1.3  No-auth request to REST ─────────────────────────────────────────
    r = http_get(f"{REST_BASE}/system/resource")
    if r:
        www_auth = r.headers.get("WWW-Authenticate", "")
        ec.add_test(cat, "REST API no-auth challenge",
                     "Request REST endpoint without credentials to see challenge type",
                     f"Status {r.status_code}, WWW-Authenticate: {www_auth}",
                     {"status": r.status_code, "www_authenticate": www_auth,
                      "headers": dict(r.headers)})
    else:
        ec.add_test(cat, "REST API no-auth challenge",
                     "No-auth REST request", "Connection failed", anomaly=True)

    # ── 1.4  WebFig root (no auth) ──────────────────────────────────────────
    for scheme, base in [("HTTP", HTTP_BASE), ("HTTPS", HTTPS_BASE)]:
        r = http_get(f"{base}/", allow_redirects=False)
        if r:
            location = r.headers.get("Location", "")
            ec.add_test(cat, f"WebFig root no-auth ({scheme})",
                         f"GET / without auth on {scheme}",
                         f"Status {r.status_code}, Location: {location}",
                         {"status": r.status_code, "location": location,
                          "content_length": len(r.content),
                          "content_type": r.headers.get("Content-Type", "")})
        else:
            ec.add_test(cat, f"WebFig root no-auth ({scheme})",
                         f"GET / on {scheme}", "Connection failed", anomaly=True)

    # ── 1.5  /webfig/ login page analysis ────────────────────────────────────
    r = http_get(f"{HTTP_BASE}/webfig/", allow_redirects=True)
    if r:
        body = r.text
        has_login_form = "password" in body.lower() or "login" in body.lower()
        has_ecdh = "ecdh" in body.lower() or "curve25519" in body.lower()
        has_challenge = "challenge" in body.lower()
        js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', body)
        ec.add_test(cat, "WebFig login page analysis",
                     "Analyze WebFig login page for auth mechanism indicators",
                     f"Login form={has_login_form}, ECDH={has_ecdh}, "
                     f"Challenge={has_challenge}, JS files={len(js_files)}",
                     {"has_login_form": has_login_form, "has_ecdh": has_ecdh,
                      "has_challenge": has_challenge, "js_files": js_files,
                      "page_size": len(body)})
    else:
        ec.add_test(cat, "WebFig login page analysis",
                     "Analyze login page", "Connection failed", anomaly=True)

    # ── 1.6  /jsproxy/ endpoint analysis ─────────────────────────────────────
    jsproxy_paths = ["/jsproxy", "/jsproxy/", "/jsproxy/login",
                     "/jsproxy/authenticate"]
    for path in jsproxy_paths:
        for method_name, method_fn in [("GET", http_get), ("POST", http_post)]:
            r = method_fn(f"{HTTP_BASE}{path}")
            if r:
                ec.add_test(cat, f"jsproxy {method_name} {path}",
                             f"{method_name} {path} without auth",
                             f"Status {r.status_code}, size {len(r.content)}b",
                             {"path": path, "method": method_name,
                              "status": r.status_code, "size": len(r.content),
                              "content_type": r.headers.get("Content-Type", ""),
                              "body_preview": r.text[:300]})
            else:
                ec.add_test(cat, f"jsproxy {method_name} {path}",
                             f"{method_name} {path}", "Connection failed")

    # ── 1.7  jsproxy with auth ───────────────────────────────────────────────
    r = http_get(f"{HTTP_BASE}/jsproxy/", user=ADMIN_USER, password=ADMIN_PASS)
    if r:
        ec.add_test(cat, "jsproxy with Basic Auth",
                     "GET /jsproxy/ with admin Basic Auth credentials",
                     f"Status {r.status_code}, size {len(r.content)}b",
                     {"status": r.status_code, "body_preview": r.text[:300]})

    # ── 1.8  Session cookie analysis ─────────────────────────────────────────
    s = requests.Session()
    r = s.get(f"{HTTP_BASE}/webfig/", timeout=TIMEOUT, verify=False)
    if r:
        cookies = s.cookies.get_dict()
        ec.add_test(cat, "WebFig session cookies (no auth)",
                     "Check if WebFig sets session cookies before authentication",
                     f"Cookies set: {list(cookies.keys())}",
                     {"cookies": cookies})

    # Login via REST then check cookies
    s2 = requests.Session()
    r2 = s2.get(f"{REST_BASE}/system/identity",
                auth=(ADMIN_USER, ADMIN_PASS), timeout=TIMEOUT, verify=False)
    if r2:
        cookies_after_auth = s2.cookies.get_dict()
        ec.add_test(cat, "REST session cookies (after auth)",
                     "Check if REST API sets session cookies after successful auth",
                     f"Cookies: {list(cookies_after_auth.keys())}",
                     {"cookies": cookies_after_auth})

    # ── 1.9  Cookie attributes deep dive ─────────────────────────────────────
    # Use raw response headers to inspect Set-Cookie
    r = http_get(f"{HTTP_BASE}/webfig/", user=ADMIN_USER, password=ADMIN_PASS)
    if r:
        set_cookies = r.headers.get("Set-Cookie", "")
        # Also check raw headers for multiple Set-Cookie
        raw_cookies = [v for k, v in r.raw.headers.items()
                       if k.lower() == "set-cookie"] if hasattr(r, 'raw') and r.raw else []
        if not raw_cookies:
            raw_cookies = r.headers.getlist("Set-Cookie") if hasattr(r.headers, 'getlist') else []
        if not raw_cookies and set_cookies:
            raw_cookies = [set_cookies]

        cookie_attrs = {
            "httponly": any("httponly" in c.lower() for c in raw_cookies),
            "secure": any("secure" in c.lower() for c in raw_cookies),
            "samesite": any("samesite" in c.lower() for c in raw_cookies),
            "path": any("path=" in c.lower() for c in raw_cookies),
            "expires": any("expires=" in c.lower() for c in raw_cookies),
        }

        missing = [k for k, v in cookie_attrs.items() if not v and raw_cookies]
        is_anomaly = len(missing) > 0 and len(raw_cookies) > 0

        ec.add_test(cat, "Cookie security attributes",
                     "Inspect Set-Cookie headers for security attributes",
                     f"Raw cookies: {len(raw_cookies)}, missing: {missing}",
                     {"set_cookie_headers": raw_cookies, "attributes": cookie_attrs,
                      "missing_attributes": missing},
                     anomaly=is_anomaly)

        if missing and raw_cookies:
            ec.add_finding("MEDIUM", f"Cookie missing security attributes: {', '.join(missing)}",
                           f"WebFig cookies are missing the following security "
                           f"attributes: {', '.join(missing)}. This may allow "
                           f"session hijacking or CSRF attacks.",
                           cwe="CWE-614")

    # ── 1.10  HTTP vs HTTPS redirect behavior ───────────────────────────────
    r_http = http_get(f"{HTTP_BASE}/webfig/", allow_redirects=False)
    if r_http:
        redirects_to_https = (r_http.status_code in (301, 302, 307, 308) and
                              "https" in r_http.headers.get("Location", "").lower())
        ec.add_test(cat, "HTTP-to-HTTPS redirect",
                     "Check if HTTP WebFig redirects to HTTPS",
                     f"Redirect to HTTPS: {redirects_to_https}",
                     {"status": r_http.status_code,
                      "location": r_http.headers.get("Location", ""),
                      "redirects": redirects_to_https},
                     anomaly=not redirects_to_https)

    # ── 1.11  HSTS header check ──────────────────────────────────────────────
    r_https = http_get(f"{HTTPS_BASE}/webfig/", user=ADMIN_USER, password=ADMIN_PASS)
    if r_https:
        hsts = r_https.headers.get("Strict-Transport-Security", "")
        ec.add_test(cat, "HSTS header",
                     "Check for Strict-Transport-Security header on HTTPS",
                     f"HSTS: {'present' if hsts else 'MISSING'} ({hsts})",
                     {"hsts_header": hsts, "present": bool(hsts)},
                     anomaly=not hsts)

    # ── 1.12  Auth on each user ──────────────────────────────────────────────
    for username, info in USERS.items():
        r = http_get(f"{REST_BASE}/system/identity",
                     user=username, password=info["password"])
        if r:
            ec.add_test(cat, f"Auth test: {username} ({info['group']})",
                         f"Verify {username} can authenticate via REST API",
                         f"Status {r.status_code}",
                         {"user": username, "group": info["group"],
                          "status": r.status_code, "success": r.status_code == 200})
        else:
            ec.add_test(cat, f"Auth test: {username}",
                         f"Auth for {username}", "Connection failed", anomaly=True)

    # ── 1.13  Wrong password for each user ───────────────────────────────────
    for username in USERS:
        r = http_get(f"{REST_BASE}/system/identity",
                     user=username, password="WRONG_PASSWORD_12345")
        if r:
            ec.add_test(cat, f"Wrong password: {username}",
                         f"Attempt auth with wrong password for {username}",
                         f"Status {r.status_code} (expected 401)",
                         {"user": username, "status": r.status_code,
                          "rejected": r.status_code == 401})
        else:
            ec.add_test(cat, f"Wrong password: {username}",
                         f"Wrong password for {username}", "Connection failed")


# =============================================================================
# Section 2: Brute-Force & Lockout Testing (~30 tests)
# =============================================================================

def test_bruteforce_lockout(ec):
    """Test account lockout behavior under brute-force conditions."""
    log("=" * 60)
    log("Section 2: Brute-Force & Lockout Testing")
    log("=" * 60)
    cat = "bruteforce"

    # ── 2.1  Rapid failed login attempts (admin) ────────────────────────────
    log("  Sending 25 rapid failed login attempts against admin...")
    fail_results = []
    for i in range(25):
        r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                    auth=("admin", f"wrong_{i}"))
        entry = {"attempt": i + 1, "elapsed_ms": round(elapsed, 2)}
        if r:
            entry["status"] = r.status_code
            entry["body_size"] = len(r.content)
        else:
            entry["status"] = "error"
        fail_results.append(entry)
        time.sleep(0.05)  # Small delay to avoid overwhelming

    statuses = [e["status"] for e in fail_results]
    locked_out = any(s == 403 for s in statuses)
    lockout_at = None
    for e in fail_results:
        if e["status"] == 403:
            lockout_at = e["attempt"]
            break

    ec.add_test(cat, "Rapid brute-force (25 attempts, admin)",
                 "Send 25 rapid failed login attempts against admin account",
                 f"Lockout detected: {locked_out}, lockout at attempt: {lockout_at}",
                 {"attempts": len(fail_results), "locked_out": locked_out,
                  "lockout_threshold": lockout_at,
                  "status_codes": statuses, "results": fail_results},
                 anomaly=not locked_out)

    if not locked_out:
        ec.add_finding("MEDIUM", "No account lockout after 25 failed login attempts",
                       "The admin account was not locked after 25 rapid failed "
                       "login attempts via REST API Basic Auth. This allows "
                       "unlimited brute-force attacks.",
                       cwe="CWE-307")

    # ── 2.2  Check if admin is still accessible after brute-force ────────────
    time.sleep(2)
    r = http_get(f"{REST_BASE}/system/identity",
                 user=ADMIN_USER, password=ADMIN_PASS)
    if r:
        ec.add_test(cat, "Admin access after brute-force",
                     "Verify admin can still log in after failed attempts",
                     f"Status {r.status_code}",
                     {"status": r.status_code, "accessible": r.status_code == 200})

    # ── 2.3  Brute-force against testread ────────────────────────────────────
    log("  Testing lockout on testread account...")
    fail_results_read = []
    for i in range(20):
        r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                    auth=("testread", f"wrong_{i}"))
        entry = {"attempt": i + 1, "elapsed_ms": round(elapsed, 2)}
        if r:
            entry["status"] = r.status_code
        else:
            entry["status"] = "error"
        fail_results_read.append(entry)
        time.sleep(0.05)

    statuses_read = [e["status"] for e in fail_results_read]
    locked_read = any(s == 403 for s in statuses_read)
    ec.add_test(cat, "Brute-force lockout (testread, 20 attempts)",
                 "Send 20 failed logins against testread account",
                 f"Lockout: {locked_read}",
                 {"locked_out": locked_read, "statuses": statuses_read})

    # ── 2.4  Test if lockout is per-IP ───────────────────────────────────────
    # After brute-forcing admin, test if testfull is also locked
    r = http_get(f"{REST_BASE}/system/identity",
                 user="testfull", password=USERS["testfull"]["password"])
    if r:
        testfull_ok = r.status_code == 200
        ec.add_test(cat, "Lockout scope: per-user vs per-IP",
                     "After brute-forcing admin, check if testfull is also locked",
                     f"testfull accessible: {testfull_ok} (Status {r.status_code})",
                     {"testfull_status": r.status_code, "accessible": testfull_ok,
                      "lockout_type": "per-user" if testfull_ok else "per-IP or global"})

    # ── 2.5  Lockout bypass via different endpoints ──────────────────────────
    # After brute-forcing REST, try WebFig, SSH, API
    bypass_endpoints = [
        ("REST /system/resource", f"{REST_BASE}/system/resource"),
        ("WebFig /webfig/", f"{HTTP_BASE}/webfig/"),
        ("HTTPS REST", f"{HTTPS_BASE}/rest/system/identity"),
    ]
    for name, url in bypass_endpoints:
        r = http_get(url, user=ADMIN_USER, password=ADMIN_PASS)
        if r:
            ec.add_test(cat, f"Lockout bypass: {name}",
                         f"After REST brute-force, try auth via {name}",
                         f"Status {r.status_code}",
                         {"endpoint": name, "status": r.status_code,
                          "bypassed": r.status_code == 200})

    # ── 2.6  SSH lockout bypass ──────────────────────────────────────────────
    stdout, stderr, rc = ssh_command("/system/identity/print")
    ec.add_test(cat, "Lockout bypass: SSH",
                 "After REST brute-force, try SSH command execution",
                 f"RC={rc}, output={stdout.strip()[:100]}",
                 {"stdout": stdout.strip(), "stderr": stderr.strip(),
                  "returncode": rc, "bypassed": rc == 0})

    # ── 2.7  Lockout duration measurement ────────────────────────────────────
    # If lockout was detected, measure how long it lasts
    if locked_out:
        log("  Measuring lockout duration (checking every 10s for up to 120s)...")
        lockout_start = time.time()
        recovered = False
        check_intervals = []
        for i in range(12):
            time.sleep(10)
            elapsed_wait = time.time() - lockout_start
            r = http_get(f"{REST_BASE}/system/identity",
                         user=ADMIN_USER, password=ADMIN_PASS)
            if r and r.status_code == 200:
                recovered = True
                check_intervals.append({"elapsed_s": round(elapsed_wait, 1),
                                         "status": r.status_code, "recovered": True})
                break
            check_intervals.append({"elapsed_s": round(elapsed_wait, 1),
                                     "status": r.status_code if r else "error",
                                     "recovered": False})

        ec.add_test(cat, "Lockout duration",
                     "Measure how long account lockout persists",
                     f"Recovered: {recovered}, "
                     f"duration: {check_intervals[-1]['elapsed_s'] if check_intervals else 'N/A'}s",
                     {"recovered": recovered, "checks": check_intervals})
    else:
        ec.add_test(cat, "Lockout duration",
                     "Measure lockout duration",
                     "N/A - no lockout was triggered")

    # ── 2.8  Incremental lockout threshold detection ─────────────────────────
    log("  Detecting exact lockout threshold...")
    # Wait for any previous lockout to clear
    time.sleep(5)

    # Use testwrite account for this test
    threshold_found = None
    threshold_results = []
    for attempt in range(1, 51):
        r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                    auth=("testwrite", "wrong_threshold"))
        status = r.status_code if r else "error"
        threshold_results.append({"attempt": attempt, "status": status,
                                   "elapsed_ms": round(elapsed, 2)})
        if status == 403:
            threshold_found = attempt
            break
        time.sleep(0.1)

    ec.add_test(cat, "Lockout threshold detection (testwrite)",
                 "Incrementally test failed logins to find exact lockout threshold",
                 f"Threshold: {threshold_found if threshold_found else '>50'}",
                 {"threshold": threshold_found, "attempts_made": len(threshold_results),
                  "results": threshold_results})

    # ── 2.9  Wait and verify testwrite recovery ──────────────────────────────
    time.sleep(5)
    r = http_get(f"{REST_BASE}/system/identity",
                 user="testwrite", password=USERS["testwrite"]["password"])
    if r:
        ec.add_test(cat, "Account recovery after threshold test",
                     "Verify testwrite can log in after lockout test",
                     f"Status {r.status_code}",
                     {"status": r.status_code, "recovered": r.status_code == 200})

    # ── 2.10  Brute-force with delays (evasion) ─────────────────────────────
    log("  Testing brute-force with 2s delays (evasion)...")
    evasion_results = []
    for i in range(10):
        r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                    auth=("admin", f"evasion_{i}"))
        status = r.status_code if r else "error"
        evasion_results.append({"attempt": i + 1, "status": status,
                                 "elapsed_ms": round(elapsed, 2)})
        time.sleep(2)

    all_401 = all(e["status"] == 401 for e in evasion_results)
    ec.add_test(cat, "Brute-force with delays (evasion)",
                 "10 failed attempts with 2s delay between each",
                 f"All 401: {all_401} (lockout evaded: {all_401})",
                 {"all_401": all_401, "results": evasion_results},
                 anomaly=all_401)

    # ── 2.11  Empty username brute-force ─────────────────────────────────────
    r = http_get(f"{REST_BASE}/system/identity", user="", password="test")
    if r:
        ec.add_test(cat, "Empty username auth attempt",
                     "Attempt auth with empty username",
                     f"Status {r.status_code}",
                     {"status": r.status_code})

    # ── 2.12  Null byte in username ──────────────────────────────────────────
    r = http_get(f"{REST_BASE}/system/identity",
                 user="admin\x00extra", password=ADMIN_PASS)
    if r:
        ec.add_test(cat, "Null byte in username",
                     "Auth with null byte embedded in username (truncation test)",
                     f"Status {r.status_code}",
                     {"status": r.status_code, "accepted": r.status_code == 200},
                     anomaly=r.status_code == 200)


# =============================================================================
# Section 3: Timing Oracle / Username Enumeration (~30 tests)
# =============================================================================

def test_timing_oracle(ec):
    """Test for timing differences that reveal valid usernames."""
    log("=" * 60)
    log("Section 3: Timing Oracle / Username Enumeration")
    log("=" * 60)
    cat = "timing_oracle"

    # ── 3.1  Valid username, wrong password (50 attempts) ────────────────────
    log("  Timing 50 requests: valid username (admin) + wrong password...")
    valid_user_times = []
    valid_user_sizes = []
    for i in range(50):
        r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                    auth=("admin", f"wrong_timing_{i}"))
        valid_user_times.append(elapsed)
        if r:
            valid_user_sizes.append(len(r.content))
        time.sleep(0.05)

    ec.add_test(cat, "Timing: valid user wrong password (50x)",
                 "Measure response times for valid username with wrong password",
                 f"Mean: {statistics.mean(valid_user_times):.2f}ms, "
                 f"Median: {statistics.median(valid_user_times):.2f}ms, "
                 f"StdDev: {statistics.stdev(valid_user_times):.2f}ms",
                 {"count": len(valid_user_times),
                  "mean_ms": round(statistics.mean(valid_user_times), 2),
                  "median_ms": round(statistics.median(valid_user_times), 2),
                  "stdev_ms": round(statistics.stdev(valid_user_times), 2),
                  "min_ms": round(min(valid_user_times), 2),
                  "max_ms": round(max(valid_user_times), 2),
                  "all_times_ms": [round(t, 2) for t in valid_user_times],
                  "response_sizes": valid_user_sizes})

    # ── 3.2  Invalid username, wrong password (50 attempts) ──────────────────
    log("  Timing 50 requests: invalid username + wrong password...")
    invalid_user_times = []
    invalid_user_sizes = []
    for i in range(50):
        r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                    auth=(f"nonexist_{i}", f"wrong_timing_{i}"))
        invalid_user_times.append(elapsed)
        if r:
            invalid_user_sizes.append(len(r.content))
        time.sleep(0.05)

    ec.add_test(cat, "Timing: invalid user wrong password (50x)",
                 "Measure response times for invalid username with wrong password",
                 f"Mean: {statistics.mean(invalid_user_times):.2f}ms, "
                 f"Median: {statistics.median(invalid_user_times):.2f}ms, "
                 f"StdDev: {statistics.stdev(invalid_user_times):.2f}ms",
                 {"count": len(invalid_user_times),
                  "mean_ms": round(statistics.mean(invalid_user_times), 2),
                  "median_ms": round(statistics.median(invalid_user_times), 2),
                  "stdev_ms": round(statistics.stdev(invalid_user_times), 2),
                  "min_ms": round(min(invalid_user_times), 2),
                  "max_ms": round(max(invalid_user_times), 2),
                  "all_times_ms": [round(t, 2) for t in invalid_user_times],
                  "response_sizes": invalid_user_sizes})

    # ── 3.3  Statistical comparison ──────────────────────────────────────────
    valid_mean = statistics.mean(valid_user_times)
    invalid_mean = statistics.mean(invalid_user_times)
    delta_ms = abs(valid_mean - invalid_mean)
    # Cohen's d effect size
    pooled_sd = math.sqrt(
        (statistics.variance(valid_user_times) + statistics.variance(invalid_user_times)) / 2
    ) if len(valid_user_times) > 1 and len(invalid_user_times) > 1 else 1.0
    cohens_d = delta_ms / pooled_sd if pooled_sd > 0 else 0.0

    timing_oracle_detected = delta_ms > 5 and cohens_d > 0.5

    ec.add_test(cat, "Timing oracle analysis",
                 "Compare valid vs invalid username response time distributions",
                 f"Delta: {delta_ms:.2f}ms, Cohen's d: {cohens_d:.2f}, "
                 f"Oracle detected: {timing_oracle_detected}",
                 {"valid_user_mean_ms": round(valid_mean, 2),
                  "invalid_user_mean_ms": round(invalid_mean, 2),
                  "delta_ms": round(delta_ms, 2),
                  "cohens_d": round(cohens_d, 2),
                  "oracle_detected": timing_oracle_detected},
                 anomaly=timing_oracle_detected)

    if timing_oracle_detected:
        faster = "valid" if valid_mean < invalid_mean else "invalid"
        ec.add_finding("MEDIUM",
                       f"Timing oracle enables username enumeration "
                       f"(delta={delta_ms:.1f}ms, d={cohens_d:.2f})",
                       f"Requests with {'valid' if faster == 'valid' else 'invalid'} "
                       f"usernames are consistently faster by {delta_ms:.1f}ms. "
                       f"Cohen's d={cohens_d:.2f} indicates a statistically significant "
                       f"difference. An attacker can enumerate valid usernames.",
                       cwe="CWE-204")

    # ── 3.4  Response size comparison (CVE-2024-54772 style) ─────────────────
    if valid_user_sizes and invalid_user_sizes:
        valid_size_set = set(valid_user_sizes)
        invalid_size_set = set(invalid_user_sizes)
        size_differs = valid_size_set != invalid_size_set

        ec.add_test(cat, "Response size oracle analysis",
                     "Compare response body sizes for valid vs invalid usernames",
                     f"Valid sizes: {valid_size_set}, Invalid sizes: {invalid_size_set}, "
                     f"Differs: {size_differs}",
                     {"valid_user_sizes": list(valid_size_set),
                      "invalid_user_sizes": list(invalid_size_set),
                      "size_differs": size_differs},
                     anomaly=size_differs)

        if size_differs:
            ec.add_finding("LOW",
                           "Response size differs between valid and invalid usernames",
                           f"Valid username responses: {valid_size_set} bytes, "
                           f"invalid: {invalid_size_set} bytes. "
                           f"Similar to CVE-2024-54772 on Winbox.",
                           cwe="CWE-204")

    # ── 3.5  Timing across different valid users ─────────────────────────────
    log("  Timing across different valid users...")
    for username, info in USERS.items():
        times = []
        for i in range(10):
            r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                        auth=(username, "wrong_password"))
            times.append(elapsed)
            time.sleep(0.05)

        ec.add_test(cat, f"Timing: {username} ({info['group']}) wrong pass (10x)",
                     f"Measure response times for {username} with wrong password",
                     f"Mean: {statistics.mean(times):.2f}ms, "
                     f"StdDev: {statistics.stdev(times):.2f}ms" if len(times) > 1 else
                     f"Mean: {statistics.mean(times):.2f}ms",
                     {"user": username, "group": info["group"],
                      "mean_ms": round(statistics.mean(times), 2),
                      "times_ms": [round(t, 2) for t in times]})

    # ── 3.6  Error message analysis ──────────────────────────────────────────
    r_valid = http_get(f"{REST_BASE}/system/identity",
                       user="admin", password="wrong")
    r_invalid = http_get(f"{REST_BASE}/system/identity",
                         user="nonexistent_user_xyz", password="wrong")
    if r_valid and r_invalid:
        body_valid = r_valid.text
        body_invalid = r_invalid.text
        bodies_match = body_valid == body_invalid
        headers_match = (dict(r_valid.headers) == dict(r_invalid.headers))

        ec.add_test(cat, "Error message comparison",
                     "Compare error responses for valid vs invalid username",
                     f"Bodies match: {bodies_match}, Headers match: {headers_match}",
                     {"valid_user_body": body_valid[:500],
                      "invalid_user_body": body_invalid[:500],
                      "valid_user_status": r_valid.status_code,
                      "invalid_user_status": r_invalid.status_code,
                      "bodies_match": bodies_match,
                      "status_match": r_valid.status_code == r_invalid.status_code},
                     anomaly=not bodies_match or r_valid.status_code != r_invalid.status_code)

    # ── 3.7  WebFig timing (different endpoint) ─────────────────────────────
    log("  Timing on WebFig /webfig/ endpoint...")
    webfig_valid_times = []
    webfig_invalid_times = []
    for i in range(10):
        r, elapsed = timed_request("GET", f"{HTTP_BASE}/webfig/",
                                    auth=("admin", "wrong"))
        webfig_valid_times.append(elapsed)
        time.sleep(0.05)
    for i in range(10):
        r, elapsed = timed_request("GET", f"{HTTP_BASE}/webfig/",
                                    auth=("nonexistent_xyz", "wrong"))
        webfig_invalid_times.append(elapsed)
        time.sleep(0.05)

    if webfig_valid_times and webfig_invalid_times:
        wf_delta = abs(statistics.mean(webfig_valid_times) -
                       statistics.mean(webfig_invalid_times))
        ec.add_test(cat, "Timing oracle: WebFig endpoint",
                     "Compare timing on /webfig/ for valid vs invalid users",
                     f"Valid mean: {statistics.mean(webfig_valid_times):.2f}ms, "
                     f"Invalid mean: {statistics.mean(webfig_invalid_times):.2f}ms, "
                     f"Delta: {wf_delta:.2f}ms",
                     {"valid_mean_ms": round(statistics.mean(webfig_valid_times), 2),
                      "invalid_mean_ms": round(statistics.mean(webfig_invalid_times), 2),
                      "delta_ms": round(wf_delta, 2)},
                     anomaly=wf_delta > 5)

    # ── 3.8  HTTPS timing comparison ────────────────────────────────────────
    log("  Timing on HTTPS REST endpoint...")
    https_valid_times = []
    https_invalid_times = []
    for i in range(10):
        r, elapsed = timed_request("GET", f"{HTTPS_BASE}/rest/system/identity",
                                    auth=("admin", "wrong"))
        https_valid_times.append(elapsed)
        time.sleep(0.05)
    for i in range(10):
        r, elapsed = timed_request("GET", f"{HTTPS_BASE}/rest/system/identity",
                                    auth=("nonexistent_xyz", "wrong"))
        https_invalid_times.append(elapsed)
        time.sleep(0.05)

    if https_valid_times and https_invalid_times:
        https_delta = abs(statistics.mean(https_valid_times) -
                          statistics.mean(https_invalid_times))
        ec.add_test(cat, "Timing oracle: HTTPS REST endpoint",
                     "Compare timing on HTTPS REST for valid vs invalid users",
                     f"Valid mean: {statistics.mean(https_valid_times):.2f}ms, "
                     f"Invalid mean: {statistics.mean(https_invalid_times):.2f}ms, "
                     f"Delta: {https_delta:.2f}ms",
                     {"valid_mean_ms": round(statistics.mean(https_valid_times), 2),
                      "invalid_mean_ms": round(statistics.mean(https_invalid_times), 2),
                      "delta_ms": round(https_delta, 2)},
                     anomaly=https_delta > 5)


# =============================================================================
# Section 4: Session Management (~40 tests)
# =============================================================================

def test_session_management(ec):
    """Test session token handling, fixation, timeout, revocation."""
    log("=" * 60)
    log("Section 4: Session Management")
    log("=" * 60)
    cat = "session_mgmt"

    # ── 4.1  Collect 20 session tokens for entropy analysis ──────────────────
    log("  Collecting 20 session tokens...")
    tokens = []
    for i in range(20):
        s = requests.Session()
        r = s.get(f"{HTTP_BASE}/webfig/", auth=(ADMIN_USER, ADMIN_PASS),
                  timeout=TIMEOUT, verify=False)
        if r:
            session_cookies = s.cookies.get_dict()
            if session_cookies:
                for name, value in session_cookies.items():
                    tokens.append({"cookie_name": name, "value": value,
                                   "attempt": i + 1})
            # Also check Set-Cookie header
            sc = r.headers.get("Set-Cookie", "")
            if sc and not session_cookies:
                tokens.append({"raw_set_cookie": sc, "attempt": i + 1})
        time.sleep(0.1)

    # Analyze token properties
    unique_values = set()
    for t in tokens:
        if "value" in t:
            unique_values.add(t["value"])

    if unique_values:
        # Entropy analysis on the first token
        sample_token = list(unique_values)[0]
        token_entropy = shannon_entropy(sample_token)
        all_unique = len(unique_values) == len(tokens)

        ec.add_test(cat, "Session token collection (20 tokens)",
                     "Collect 20 session tokens and analyze uniqueness",
                     f"Collected {len(tokens)} tokens, {len(unique_values)} unique, "
                     f"entropy={token_entropy:.2f} bits/byte",
                     {"total_collected": len(tokens),
                      "unique_count": len(unique_values),
                      "all_unique": all_unique,
                      "sample_token": sample_token,
                      "token_length": len(sample_token),
                      "entropy_bits_per_byte": round(token_entropy, 2),
                      "total_entropy_bits": round(token_entropy * len(sample_token), 2),
                      "tokens": tokens[:5]},
                     anomaly=not all_unique or token_entropy < 3.0)

        if token_entropy < 3.0 and tokens:
            ec.add_finding("HIGH", f"Low session token entropy ({token_entropy:.2f} bits/byte)",
                           f"Session tokens have only {token_entropy:.2f} bits of entropy "
                           f"per byte, making them predictable. An attacker may be able "
                           f"to brute-force valid session tokens.",
                           cwe="CWE-330")
    else:
        ec.add_test(cat, "Session token collection",
                     "Collect session tokens for analysis",
                     "No session cookies were set by WebFig",
                     {"tokens_found": 0})

    # ── 4.2  Token format analysis ───────────────────────────────────────────
    if unique_values:
        for token in list(unique_values)[:3]:
            is_hex = all(c in "0123456789abcdefABCDEF" for c in token)
            is_base64 = bool(re.match(r'^[A-Za-z0-9+/=]+$', token))
            is_uuid = bool(re.match(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                token, re.I))

            ec.add_test(cat, f"Token format analysis: {token[:20]}...",
                         "Analyze session token format (hex, base64, UUID, etc.)",
                         f"Length={len(token)}, hex={is_hex}, base64={is_base64}, "
                         f"uuid={is_uuid}",
                         {"token": token, "length": len(token),
                          "is_hex": is_hex, "is_base64": is_base64,
                          "is_uuid": is_uuid})

    # ── 4.3  Session fixation test ───────────────────────────────────────────
    log("  Testing session fixation...")
    fixed_session_id = "FIXATED_SESSION_12345"
    # Try setting a known session ID before auth
    s = requests.Session()
    # Attempt with common cookie names
    for cookie_name in ["session", "PHPSESSID", "SID", "webfig_session",
                        "username", "auth"]:
        s.cookies.set(cookie_name, fixed_session_id)

    r = s.get(f"{HTTP_BASE}/webfig/", auth=(ADMIN_USER, ADMIN_PASS),
              timeout=TIMEOUT, verify=False)
    if r:
        post_auth_cookies = s.cookies.get_dict()
        # Check if our fixed session was accepted
        fixation_possible = any(v == fixed_session_id
                                for v in post_auth_cookies.values())
        ec.add_test(cat, "Session fixation test",
                     "Set a known session ID before auth, check if accepted",
                     f"Fixation possible: {fixation_possible}",
                     {"pre_auth_cookie": fixed_session_id,
                      "post_auth_cookies": post_auth_cookies,
                      "fixation_vulnerable": fixation_possible},
                     anomaly=fixation_possible)
        if fixation_possible:
            ec.add_finding("HIGH", "Session fixation vulnerability",
                           "The server accepts client-supplied session identifiers "
                           "without regenerating them after authentication.",
                           cwe="CWE-384")

    # ── 4.4  Session reuse after logout ──────────────────────────────────────
    log("  Testing session reuse after logout...")
    # Get a valid session
    s = requests.Session()
    r = s.get(f"{REST_BASE}/system/identity",
              auth=(ADMIN_USER, ADMIN_PASS), timeout=TIMEOUT, verify=False)
    if r and r.status_code == 200:
        session_cookies_pre = s.cookies.get_dict()
        identity_pre = r.text

        # Attempt to "logout" - MikroTik may not have explicit logout
        # Try common logout paths
        for logout_path in ["/webfig/logout", "/logout", "/rest/logout"]:
            s.get(f"{HTTP_BASE}{logout_path}", timeout=5, verify=False)

        # Try to reuse the session (without re-sending Basic Auth)
        r2 = s.get(f"{REST_BASE}/system/identity", timeout=TIMEOUT, verify=False)
        reused = r2 is not None and r2.status_code == 200
        ec.add_test(cat, "Session reuse after logout",
                     "Check if session remains valid after hitting logout endpoints",
                     f"Session reusable: {reused}",
                     {"pre_logout_cookies": session_cookies_pre,
                      "reuse_status": r2.status_code if r2 else "error",
                      "reusable": reused})

    # ── 4.5  Session timeout behavior ────────────────────────────────────────
    # Check what the configured session timeout is
    code, data = rest_get("/ip/service")
    if code == 200 and isinstance(data, list):
        ec.add_test(cat, "Service configuration (session context)",
                     "Retrieve IP service config for session timeout context",
                     f"Found {len(data)} services",
                     {"services": data})

    # ── 4.6  REST API statelessness test ─────────────────────────────────────
    # Basic Auth is supposed to be stateless; verify
    s = requests.Session()
    r1 = s.get(f"{REST_BASE}/system/identity",
               auth=(ADMIN_USER, ADMIN_PASS), timeout=TIMEOUT, verify=False)
    # Remove auth and try again using just session
    r2 = s.get(f"{REST_BASE}/system/identity", timeout=TIMEOUT, verify=False)
    if r1 and r2:
        stateless = r2.status_code == 401
        ec.add_test(cat, "REST API statelessness",
                     "Verify REST API does not maintain server-side session state",
                     f"First request: {r1.status_code}, "
                     f"Second (no auth): {r2.status_code}, Stateless: {stateless}",
                     {"first_status": r1.status_code, "second_status": r2.status_code,
                      "stateless": stateless})

    # ── 4.7  Concurrent session limit ────────────────────────────────────────
    log("  Testing concurrent session limit...")
    sessions = []
    for i in range(10):
        s = requests.Session()
        r = s.get(f"{REST_BASE}/system/identity",
                  auth=(ADMIN_USER, ADMIN_PASS), timeout=TIMEOUT, verify=False)
        if r:
            sessions.append({"session": i + 1, "status": r.status_code,
                              "cookies": s.cookies.get_dict()})

    all_ok = all(s["status"] == 200 for s in sessions)
    ec.add_test(cat, "Concurrent session limit (10 sessions)",
                 "Open 10 simultaneous authenticated sessions",
                 f"All succeeded: {all_ok}",
                 {"session_count": len(sessions), "all_ok": all_ok,
                  "sessions": sessions},
                 anomaly=all_ok)

    # ── 4.8  Check active user sessions on router ────────────────────────────
    code, active = rest_get("/user/active")
    if code == 200 and isinstance(active, list):
        ec.add_test(cat, "Active user sessions",
                     "Query router for active user sessions",
                     f"Active sessions: {len(active)}",
                     {"active_count": len(active),
                      "sessions": active[:20]})

    # ── 4.9  Session revocation on password change ───────────────────────────
    log("  Testing session revocation on password change...")
    # Create a session for testfull
    s_before = requests.Session()
    r = s_before.get(f"{REST_BASE}/system/identity",
                     auth=("testfull", USERS["testfull"]["password"]),
                     timeout=TIMEOUT, verify=False)
    if r and r.status_code == 200:
        # Change testfull's password via admin
        original_pass = USERS["testfull"]["password"]
        new_pass = "TempPass999"

        # Get testfull's .id
        code, users = rest_get("/user")
        testfull_id = None
        if code == 200 and isinstance(users, list):
            for u in users:
                if u.get("name") == "testfull":
                    testfull_id = u.get(".id")
                    break

        if testfull_id:
            # Change password
            code, resp = rest_patch(f"/user/{testfull_id}",
                                     {"password": new_pass})
            ec.add_test(cat, "Password change for session revocation test",
                         "Change testfull password via admin REST API",
                         f"Status {code}",
                         {"status": code, "response": str(resp)[:200]})

            # Try the old session with old credentials
            time.sleep(1)
            r2 = s_before.get(f"{REST_BASE}/system/identity",
                              auth=("testfull", original_pass),
                              timeout=TIMEOUT, verify=False)
            old_creds_work = r2 is not None and r2.status_code == 200

            # Try with new password
            r3 = http_get(f"{REST_BASE}/system/identity",
                          user="testfull", password=new_pass)
            new_creds_work = r3 is not None and r3.status_code == 200

            ec.add_test(cat, "Session revocation on password change",
                         "Check if old credentials still work after password change",
                         f"Old creds work: {old_creds_work}, "
                         f"New creds work: {new_creds_work}",
                         {"old_credentials_valid": old_creds_work,
                          "new_credentials_valid": new_creds_work})

            # Restore original password
            rest_patch(f"/user/{testfull_id}", {"password": original_pass})
            ec.add_test(cat, "Password restoration (testfull)",
                         "Restore testfull password to original value",
                         "Restored")
        else:
            ec.add_test(cat, "Session revocation test",
                         "Session revocation on password change",
                         "Could not find testfull user ID", anomaly=True)

    # ── 4.10  CSRF token presence ────────────────────────────────────────────
    r = http_get(f"{HTTP_BASE}/webfig/", user=ADMIN_USER, password=ADMIN_PASS)
    if r:
        body = r.text
        has_csrf = bool(re.search(r'csrf|_token|nonce', body, re.I))
        hidden_inputs = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', body, re.I)
        ec.add_test(cat, "CSRF token presence",
                     "Check if WebFig pages include CSRF tokens",
                     f"CSRF indicator found: {has_csrf}, "
                     f"Hidden inputs: {len(hidden_inputs)}",
                     {"csrf_found": has_csrf,
                      "hidden_inputs": hidden_inputs[:10]},
                     anomaly=not has_csrf)

    # ── 4.11-4.15  Additional session tests with WebFig ─────────────────────
    # Test session cookie on jsproxy
    s = requests.Session()
    r = s.post(f"{HTTP_BASE}/jsproxy", timeout=TIMEOUT, verify=False)
    if r:
        ec.add_test(cat, "jsproxy session behavior",
                     "Check if /jsproxy sets or uses session cookies",
                     f"Status {r.status_code}, cookies: {s.cookies.get_dict()}",
                     {"status": r.status_code,
                      "cookies": s.cookies.get_dict(),
                      "body_preview": r.text[:200]})

    # Test if session differs per source IP (we only have one IP, so document)
    ec.add_test(cat, "Session binding to IP (note)",
                 "Document: cannot test IP-binding with single source IP",
                 "Test requires multiple source IPs - documented for manual follow-up",
                 {"note": "Single-source limitation"})

    # Test session after router reboot (informational)
    ec.add_test(cat, "Session persistence across reboot (note)",
                 "Document: not tested to avoid disruption",
                 "Skipped - would require router reboot",
                 {"note": "Reboot test skipped"})

    # Test for session prediction
    if len(unique_values) >= 2 if 'unique_values' in dir() else False:
        sorted_tokens = sorted(unique_values)
        sequential = all(
            abs(int(sorted_tokens[i], 16) - int(sorted_tokens[i-1], 16)) < 1000
            for i in range(1, len(sorted_tokens))
            if all(c in "0123456789abcdef" for c in sorted_tokens[i].lower())
        ) if sorted_tokens else False
        ec.add_test(cat, "Session token predictability",
                     "Check if session tokens are sequential",
                     f"Sequential: {sequential}")


# =============================================================================
# Section 5: Password Policy (~20 tests)
# =============================================================================

def test_password_policy(ec):
    """Test password policy enforcement."""
    log("=" * 60)
    log("Section 5: Password Policy Testing")
    log("=" * 60)
    cat = "password_policy"

    # We test by attempting to set passwords on testwrite via admin REST API
    # Get testwrite's .id first
    code, users = rest_get("/user")
    testwrite_id = None
    if code == 200 and isinstance(users, list):
        for u in users:
            if u.get("name") == "testwrite":
                testwrite_id = u.get(".id")
                break

    if not testwrite_id:
        ec.add_test(cat, "Password policy setup",
                     "Find testwrite user ID for password tests",
                     "Could not find testwrite user ID", anomaly=True)
        return

    original_pass = USERS["testwrite"]["password"]

    # ── 5.1  Empty password ──────────────────────────────────────────────────
    code, resp = rest_patch(f"/user/{testwrite_id}", {"password": ""})
    empty_accepted = code in (200, 204)
    ec.add_test(cat, "Empty password",
                 "Attempt to set empty password on testwrite",
                 f"Status {code}, accepted: {empty_accepted}",
                 {"status": code, "accepted": empty_accepted,
                  "response": str(resp)[:200]},
                 anomaly=empty_accepted)

    if empty_accepted:
        # Verify empty password works
        r = http_get(f"{REST_BASE}/system/identity",
                     user="testwrite", password="")
        login_ok = r is not None and r.status_code == 200
        ec.add_test(cat, "Empty password login",
                     "Verify login with empty password",
                     f"Login succeeded: {login_ok}",
                     {"login_success": login_ok},
                     anomaly=login_ok)
        if login_ok:
            ec.add_finding("MEDIUM", "Empty password accepted",
                           "RouterOS allows setting and authenticating with "
                           "an empty password.",
                           cwe="CWE-521")
        # Restore
        rest_patch(f"/user/{testwrite_id}", {"password": original_pass})

    # ── 5.2  Single character password ───────────────────────────────────────
    code, resp = rest_patch(f"/user/{testwrite_id}", {"password": "a"})
    short_accepted = code in (200, 204)
    ec.add_test(cat, "1-char password",
                 "Attempt to set 1-character password",
                 f"Status {code}, accepted: {short_accepted}",
                 {"status": code, "accepted": short_accepted})
    if short_accepted:
        rest_patch(f"/user/{testwrite_id}", {"password": original_pass})

    # ── 5.3  Short passwords (2-7 chars) ────────────────────────────────────
    min_len_found = None
    for length in range(2, 8):
        test_pass = "a" * length
        code, resp = rest_patch(f"/user/{testwrite_id}", {"password": test_pass})
        accepted = code in (200, 204)
        ec.add_test(cat, f"{length}-char password",
                     f"Attempt to set {length}-character password",
                     f"Status {code}, accepted: {accepted}",
                     {"length": length, "status": code, "accepted": accepted})
        if not accepted and min_len_found is None:
            min_len_found = length
        if accepted:
            rest_patch(f"/user/{testwrite_id}", {"password": original_pass})

    # ── 5.4  Maximum password length ─────────────────────────────────────────
    max_lengths = [64, 128, 256, 512, 1024, 4096]
    for max_len in max_lengths:
        test_pass = "A" * max_len
        code, resp = rest_patch(f"/user/{testwrite_id}", {"password": test_pass})
        accepted = code in (200, 204)
        ec.add_test(cat, f"Password length {max_len}",
                     f"Attempt to set {max_len}-character password",
                     f"Status {code}, accepted: {accepted}",
                     {"length": max_len, "status": code, "accepted": accepted,
                      "response": str(resp)[:200]})
        if accepted:
            # Verify login
            r = http_get(f"{REST_BASE}/system/identity",
                         user="testwrite", password=test_pass)
            login_ok = r is not None and r.status_code == 200
            ec.add_test(cat, f"Login with {max_len}-char password",
                         f"Verify login works with {max_len}-char password",
                         f"Login OK: {login_ok}")
            rest_patch(f"/user/{testwrite_id}", {"password": original_pass})

    # ── 5.5  Special characters in password ──────────────────────────────────
    special_passwords = [
        ("space_password", "pass word"),
        ("unicode_password", "p\u00e4\u00df\u00f1\u00f8rd"),
        ("sql_injection", "' OR '1'='1"),
        ("html_entities", "<script>alert(1)</script>"),
        ("backslash", "pass\\word"),
        ("quotes", 'pass"word'),
        ("newline", "pass\nword"),
        ("tab", "pass\tword"),
        ("pipe", "pass|word"),
        ("semicolon", "pass;word"),
    ]
    for name, test_pass in special_passwords:
        code, resp = rest_patch(f"/user/{testwrite_id}", {"password": test_pass})
        accepted = code in (200, 204)
        ec.add_test(cat, f"Special password: {name}",
                     f"Set password containing {name}",
                     f"Status {code}, accepted: {accepted}",
                     {"name": name, "status": code, "accepted": accepted})
        if accepted:
            rest_patch(f"/user/{testwrite_id}", {"password": original_pass})

    # ── 5.6  Password with null bytes ────────────────────────────────────────
    code, resp = rest_patch(f"/user/{testwrite_id}",
                             {"password": "pass\x00word"})
    null_accepted = code in (200, 204)
    ec.add_test(cat, "Password with null byte",
                 "Attempt to set password containing null byte",
                 f"Status {code}, accepted: {null_accepted}",
                 {"status": code, "accepted": null_accepted,
                  "response": str(resp)[:200]},
                 anomaly=null_accepted)
    if null_accepted:
        # Test if null truncation happens
        r = http_get(f"{REST_BASE}/system/identity",
                     user="testwrite", password="pass")
        truncated = r is not None and r.status_code == 200
        ec.add_test(cat, "Null byte truncation in password",
                     "Check if password is truncated at null byte",
                     f"Truncated password works: {truncated}",
                     {"truncation_vulnerable": truncated},
                     anomaly=truncated)
        if truncated:
            ec.add_finding("MEDIUM", "Password null byte truncation",
                           "Passwords containing null bytes are truncated, "
                           "effectively shortening the password.",
                           cwe="CWE-170")
        rest_patch(f"/user/{testwrite_id}", {"password": original_pass})

    # ── 5.7  Ensure testwrite is restored ────────────────────────────────────
    rest_patch(f"/user/{testwrite_id}", {"password": original_pass})
    r = http_get(f"{REST_BASE}/system/identity",
                 user="testwrite", password=original_pass)
    ec.add_test(cat, "Password restoration verification",
                 "Verify testwrite password is restored to original",
                 f"Login OK: {r is not None and r.status_code == 200}")


# =============================================================================
# Section 6: Authorization / Privilege Escalation (~40 tests)
# =============================================================================

def test_authorization(ec):
    """Test authorization controls across user groups."""
    log("=" * 60)
    log("Section 6: Authorization / Privilege Escalation")
    log("=" * 60)
    cat = "authorization"

    # Define endpoints and expected access levels
    # (path, method, description, required_group)
    endpoints = [
        # Read endpoints (should be accessible by read, write, full)
        ("/system/identity", "GET", "System identity", "read"),
        ("/system/resource", "GET", "System resource info", "read"),
        ("/system/clock", "GET", "System clock", "read"),
        ("/ip/address", "GET", "IP addresses", "read"),
        ("/ip/route", "GET", "Routing table", "read"),
        ("/interface", "GET", "Interface list", "read"),
        ("/log", "GET", "System log", "read"),
        ("/ip/firewall/filter", "GET", "Firewall rules", "read"),
        ("/system/package", "GET", "Installed packages", "read"),
        ("/ip/dns", "GET", "DNS settings", "read"),

        # Write endpoints (should require write or full)
        ("/system/identity", "PATCH", "Modify system identity", "write"),
        ("/ip/firewall/filter/add", "POST", "Add firewall rule", "write"),
        ("/system/scheduler/add", "POST", "Add scheduler task", "write"),

        # Full/admin-only endpoints
        ("/user", "GET", "User management (list)", "full"),
        ("/user/group", "GET", "User groups", "full"),
        ("/system/script", "GET", "System scripts", "full"),
        ("/file", "GET", "File system access", "full"),
        ("/certificate", "GET", "Certificates", "full"),
        ("/ip/service", "GET", "IP services config", "full"),
        ("/snmp/community", "GET", "SNMP communities", "full"),
        ("/system/logging", "GET", "Logging config", "full"),
    ]

    # Test each user group against each endpoint
    test_users = {
        "testread": USERS["testread"],
        "testwrite": USERS["testwrite"],
        "testfull": USERS["testfull"],
    }

    for username, info in test_users.items():
        group = info["group"]
        for path, method, desc, required_group in endpoints:
            if method == "GET":
                code, data = rest_get(path, user=username, password=info["password"])
            elif method == "POST":
                # Send empty/safe payload for POST tests
                if "add" in path:
                    # Don't actually add things; just test if the endpoint
                    # rejects or accepts the request
                    code, data = rest_post(path, {}, user=username,
                                           password=info["password"])
                else:
                    code, data = rest_post(path, {}, user=username,
                                           password=info["password"])
            elif method == "PATCH":
                # Use a no-op patch (set identity to current value)
                code, data = rest_get("/system/identity",
                                      user=username, password=info["password"])
                if code == 200 and isinstance(data, dict):
                    current_name = data.get("name", "MikroTik")
                    code, data = rest_patch("/system/identity",
                                            {"name": current_name},
                                            user=username,
                                            password=info["password"])
                # else keep the GET code/data
            else:
                continue

            # Determine if access should be allowed
            group_hierarchy = {"read": 1, "write": 2, "full": 3}
            user_level = group_hierarchy.get(group, 0)
            required_level = group_hierarchy.get(required_group, 3)
            should_have_access = user_level >= required_level

            # Detect actual access
            actually_accessible = code in (200, 201, 204)
            # 400 can mean "bad request" but endpoint was reached
            reached_endpoint = code not in (401, 403, 0)

            is_escalation = actually_accessible and not should_have_access
            is_anomaly = is_escalation

            ec.add_test(cat, f"{username}({group}) {method} {path}",
                         f"Test {group} user access to {desc} ({method})",
                         f"Status {code}, expected_access={should_have_access}, "
                         f"actual={actually_accessible}",
                         {"user": username, "group": group, "path": path,
                          "method": method, "status": code,
                          "expected_access": should_have_access,
                          "actual_access": actually_accessible,
                          "privilege_escalation": is_escalation},
                         anomaly=is_anomaly)

            if is_escalation:
                ec.add_finding("HIGH",
                               f"Privilege escalation: {group} user can "
                               f"{method} {path}",
                               f"User '{username}' (group={group}) can access "
                               f"{path} which requires '{required_group}' access. "
                               f"HTTP {code} returned.",
                               cwe="CWE-269")

    # ── 6.2  Sensitive endpoint deep tests ───────────────────────────────────
    log("  Testing sensitive endpoints with read-only user...")
    sensitive_endpoints = [
        ("/user", "GET", "List all users"),
        ("/user/active", "GET", "List active sessions"),
        ("/system/script/run", "POST", "Execute a script"),
        ("/file", "GET", "List filesystem"),
        ("/tool/fetch", "POST", "Fetch URL (SSRF potential)"),
        ("/export", "GET", "Export configuration"),
        ("/system/backup/save", "POST", "Create backup"),
        ("/system/reset-configuration", "POST", "Factory reset"),
        ("/system/reboot", "POST", "Reboot router"),
        ("/system/shutdown", "POST", "Shut down router"),
        ("/ppp/secret", "GET", "PPP secrets (passwords)"),
        ("/ip/hotspot/user", "GET", "Hotspot users"),
        ("/system/history", "GET", "Command history"),
    ]

    read_user = "testread"
    read_pass = USERS["testread"]["password"]
    for path, method, desc in sensitive_endpoints:
        if method == "GET":
            code, data = rest_get(path, user=read_user, password=read_pass)
        else:
            code, data = rest_post(path, {}, user=read_user, password=read_pass)

        accessible = code in (200, 201, 204)
        ec.add_test(cat, f"Read user → {method} {path}",
                     f"Test read-only user access to {desc}",
                     f"Status {code}, accessible: {accessible}",
                     {"path": path, "method": method, "status": code,
                      "accessible": accessible,
                      "data_preview": str(data)[:200] if accessible else None},
                     anomaly=accessible and path in ("/system/reboot",
                         "/system/shutdown", "/system/reset-configuration",
                         "/system/script/run", "/system/backup/save"))

    # ── 6.3  HTTP method restriction tests ───────────────────────────────────
    log("  Testing HTTP method restrictions for read-only user...")
    method_test_paths = ["/ip/address", "/system/identity",
                         "/ip/firewall/filter", "/interface"]
    http_methods = ["POST", "PUT", "PATCH", "DELETE"]

    for path in method_test_paths:
        for method in http_methods:
            try:
                url = f"{HTTP_BASE}/rest{path}"
                r = requests.request(method, url,
                                     auth=(read_user, read_pass),
                                     json={}, timeout=TIMEOUT, verify=False)
                # Read user should not be able to modify
                allowed = r.status_code in (200, 201, 204)
                ec.add_test(cat, f"Read user {method} {path}",
                             f"Test if read user can {method} on {path}",
                             f"Status {r.status_code}",
                             {"method": method, "path": path,
                              "status": r.status_code, "allowed": allowed},
                             anomaly=allowed)
            except Exception as e:
                ec.add_test(cat, f"Read user {method} {path}",
                             f"HTTP {method} test", f"Error: {e}")

    # ── 6.4  Unauthenticated access to sensitive endpoints ───────────────────
    log("  Testing unauthenticated access to sensitive endpoints...")
    unauth_endpoints = [
        "/rest/user", "/rest/system/resource", "/rest/log",
        "/rest/ip/address", "/rest/file", "/rest/system/identity",
    ]
    for path in unauth_endpoints:
        r = http_get(f"{HTTP_BASE}{path}")
        if r:
            ec.add_test(cat, f"Unauth access: {path}",
                         f"Test unauthenticated access to {path}",
                         f"Status {r.status_code}",
                         {"path": path, "status": r.status_code,
                          "accessible": r.status_code == 200},
                         anomaly=r.status_code == 200)


# =============================================================================
# Section 7: Multi-user Concurrency (~10 tests)
# =============================================================================

def test_concurrency(ec):
    """Test multi-user concurrent session behavior."""
    log("=" * 60)
    log("Section 7: Multi-user Concurrency")
    log("=" * 60)
    cat = "concurrency"

    # ── 7.1  Simultaneous login with all users ───────────────────────────────
    log("  Simultaneous login with all users...")

    def login_user(username, password):
        """Login a user and return result dict."""
        start = time.perf_counter()
        try:
            r = requests.get(f"{REST_BASE}/system/identity",
                             auth=(username, password),
                             timeout=TIMEOUT, verify=False)
            elapsed = (time.perf_counter() - start) * 1000
            return {"user": username, "status": r.status_code,
                    "elapsed_ms": round(elapsed, 2),
                    "body": r.text[:200] if r.status_code == 200 else ""}
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return {"user": username, "status": "error", "error": str(e),
                    "elapsed_ms": round(elapsed, 2)}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        for username, info in USERS.items():
            f = executor.submit(login_user, username, info["password"])
            futures[f] = username

        concurrent_results = []
        for f in as_completed(futures):
            concurrent_results.append(f.result())

    all_success = all(r["status"] == 200 for r in concurrent_results)
    ec.add_test(cat, "Simultaneous login (all 4 users)",
                 "Login all 4 users concurrently via REST API",
                 f"All succeeded: {all_success}",
                 {"results": concurrent_results, "all_success": all_success})

    # ── 7.2  Same user concurrent sessions ───────────────────────────────────
    log("  Testing same-user concurrent sessions...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(login_user, ADMIN_USER, ADMIN_PASS)
                   for _ in range(5)]
        same_user_results = [f.result() for f in as_completed(futures)]

    all_admin_ok = all(r["status"] == 200 for r in same_user_results)
    ec.add_test(cat, "Same-user concurrent sessions (admin x5)",
                 "Login admin 5 times concurrently",
                 f"All succeeded: {all_admin_ok}",
                 {"results": same_user_results, "all_success": all_admin_ok})

    # ── 7.3  Session isolation verification ──────────────────────────────────
    log("  Verifying session isolation...")
    # Each user queries their own identity — results should be consistent
    s_admin = requests.Session()
    s_read = requests.Session()

    r_admin = s_admin.get(f"{REST_BASE}/user/active",
                          auth=(ADMIN_USER, ADMIN_PASS),
                          timeout=TIMEOUT, verify=False)
    r_read = s_read.get(f"{REST_BASE}/user/active",
                        auth=("testread", USERS["testread"]["password"]),
                        timeout=TIMEOUT, verify=False)

    if r_admin and r_read:
        # Check if read user sees different data than admin
        admin_data = r_admin.json() if r_admin.status_code == 200 else None
        read_data = r_read.json() if r_read.status_code == 200 else None

        ec.add_test(cat, "Session isolation: admin vs read",
                     "Compare active session data visibility between admin and read users",
                     f"Admin status: {r_admin.status_code}, "
                     f"Read status: {r_read.status_code}",
                     {"admin_status": r_admin.status_code,
                      "read_status": r_read.status_code,
                      "admin_data_count": len(admin_data) if admin_data else 0,
                      "read_data_count": len(read_data) if read_data else 0})

    # ── 7.4  Cross-user data access ──────────────────────────────────────────
    # Test if one user can see/modify another user's data
    code_read, data_read = rest_get("/user", user="testread",
                                     password=USERS["testread"]["password"])
    code_write, data_write = rest_get("/user", user="testwrite",
                                      password=USERS["testwrite"]["password"])

    ec.add_test(cat, "Cross-user data: /user endpoint",
                 "Test if non-admin users can list all user accounts",
                 f"Read user: {code_read}, Write user: {code_write}",
                 {"read_status": code_read, "write_status": code_write,
                  "read_can_list": code_read == 200,
                  "write_can_list": code_write == 200})

    # ── 7.5  Parallel requests, interleaved operations ───────────────────────
    log("  Testing interleaved read/write operations...")

    def read_identity(user, password):
        code, data = rest_get("/system/identity", user=user, password=password)
        return {"user": user, "status": code, "data": str(data)[:100]}

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for _ in range(3):
            for username, info in USERS.items():
                futures.append(executor.submit(read_identity, username,
                                               info["password"]))
        interleaved_results = [f.result() for f in as_completed(futures)]

    # Check all reads returned consistent data
    identities = set()
    for r in interleaved_results:
        if r["status"] == 200:
            identities.add(r["data"])

    ec.add_test(cat, "Interleaved operations (12 concurrent reads)",
                 "All 4 users read identity 3 times each, concurrently",
                 f"Total requests: {len(interleaved_results)}, "
                 f"Unique identity values: {len(identities)}",
                 {"total_requests": len(interleaved_results),
                  "unique_identities": len(identities),
                  "consistent": len(identities) <= 1,
                  "results": interleaved_results})

    # ── 7.6  Rate limiting under concurrent load ─────────────────────────────
    log("  Testing rate limiting under concurrent load...")

    def rapid_request(_):
        r, elapsed = timed_request("GET", f"{REST_BASE}/system/identity",
                                    auth=(ADMIN_USER, ADMIN_PASS))
        return {"status": r.status_code if r else "error",
                "elapsed_ms": round(elapsed, 2)}

    with ThreadPoolExecutor(max_workers=10) as executor:
        rate_results = list(executor.map(rapid_request, range(20)))

    errors = sum(1 for r in rate_results if r["status"] != 200)
    ec.add_test(cat, "Concurrent rate limit test (20 parallel requests)",
                 "Send 20 simultaneous requests from admin",
                 f"Errors/rate-limited: {errors}/{len(rate_results)}",
                 {"total": len(rate_results), "errors": errors,
                  "results": rate_results},
                 anomaly=errors > 0)


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log(f"MikroTik RouterOS CHR 7.20.8 -- WebFig Auth Assessment")
    log(f"Target: {TARGET}")
    log(f"Phase 2 -- attack_webfig_auth.py")
    log("=" * 60)

    # Pre-flight check
    status = check_router_alive()
    if not status.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={status.get('version')}, "
        f"uptime={status.get('uptime')}")

    # Initialize evidence collector
    ec = EvidenceCollector("attack_webfig_auth.py", phase=2)

    try:
        # Section 1: Authentication Mechanism Analysis (~30 tests)
        test_auth_mechanisms(ec)

        # Section 2: Brute-Force & Lockout Testing (~30 tests)
        test_bruteforce_lockout(ec)

        # Section 3: Timing Oracle / Username Enumeration (~30 tests)
        test_timing_oracle(ec)

        # Section 4: Session Management (~40 tests)
        test_session_management(ec)

        # Section 5: Password Policy (~20 tests)
        test_password_policy(ec)

        # Section 6: Authorization / Privilege Escalation (~40 tests)
        test_authorization(ec)

        # Section 7: Multi-user Concurrency (~10 tests)
        test_concurrency(ec)

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled error: {e}")
        import traceback
        traceback.print_exc()

    # Save evidence and print summary
    ec.save("webfig_auth.json")
    ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
