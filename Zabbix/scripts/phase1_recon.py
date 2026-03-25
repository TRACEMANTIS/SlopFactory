#!/usr/bin/env python3
"""
Security Research II -- Phase 1: Reconnaissance & API Mapping
Maps Zabbix JSON-RPC API endpoints, tests auth requirements,
checks security headers, and enumerates the attack surface.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/scripts')

from zabbix_common import *

banner("Phase 1: Reconnaissance & API Mapping")

ec = EvidenceCollector("phase1_recon", phase="phase1")

# ===========================================================================
# TEST 1: API Version & Fingerprinting (unauthenticated)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: Unauthenticated API Fingerprinting")
print("=" * 60)

# apiinfo.version -- should work without auth
resp = requests.post(API_URL,
    json={"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1},
    headers={"Content-Type": "application/json-rpc"})

version_data = resp.json()
api_version = version_data.get("result", "unknown")
print(f"\n  API version (no auth): {api_version}")
print(f"  HTTP status: {resp.status_code}")
print(f"  Content-Type: {resp.headers.get('Content-Type', 'N/A')}")

ec.add_test(
    "RECON-001", "Unauthenticated API version disclosure",
    "POST /api_jsonrpc.php apiinfo.version (no auth)",
    f"Version: {api_version}",
    result="ANOMALOUS"  # version disclosure without auth
)

# ===========================================================================
# TEST 2: Security Response Headers
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: Security Response Headers")
print("=" * 60)

security_headers = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
]

# Test multiple endpoints
endpoints_to_check = [
    ("GET", "/", "Main page"),
    ("GET", "/index.php", "Login page"),
    ("POST", "/api_jsonrpc.php", "JSON-RPC API"),
]

for method, path, desc in endpoints_to_check:
    if method == "GET":
        resp = requests.get(f"{ZABBIX_URL}{path}", timeout=10, allow_redirects=False)
    else:
        resp = requests.post(f"{ZABBIX_URL}{path}",
            json={"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1},
            headers={"Content-Type": "application/json-rpc"}, timeout=10)

    present = 0
    missing = 0
    print(f"\n  {desc} ({path}):")
    for header in security_headers:
        value = resp.headers.get(header, None)
        if value:
            print(f"    [+] {header}: {value}")
            present += 1
        else:
            print(f"    [ ] {header}: MISSING")
            missing += 1

    ec.add_test(
        f"HEADERS-{path.replace('/', '_')[:15]}",
        f"Security headers on {desc}",
        f"{method} {path}",
        f"Present: {present}/9, Missing: {missing}/9",
        result="PASS" if present >= 6 else ("ANOMALOUS" if present >= 3 else "FAIL"),
    )
    rate_limit(0.2)

# ===========================================================================
# TEST 3: Session Cookie Analysis
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: Session Cookie Analysis")
print("=" * 60)

import base64
resp = requests.get(f"{ZABBIX_URL}/", timeout=10, allow_redirects=False)
cookies = resp.cookies
for cookie in cookies:
    print(f"\n  Cookie: {cookie.name}")
    print(f"    Domain: {cookie.domain}")
    print(f"    Path: {cookie.path}")
    print(f"    Secure: {cookie.secure}")
    print(f"    HttpOnly: {cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in str(cookie).lower()}")

    if cookie.name == "zbx_session":
        try:
            decoded = base64.b64decode(cookie.value + "==")
            import json as _json
            session_data = _json.loads(decoded)
            print(f"    Decoded: {_json.dumps(session_data, indent=6)}")
            print(f"    sessionid length: {len(session_data.get('sessionid', ''))}")
            print(f"    sign length: {len(session_data.get('sign', ''))}")

            # Check for CVE-2024-36466 pattern -- is the sign predictable?
            if len(session_data.get('sign', '')) == 64:
                print(f"    Sign appears to be SHA-256 HMAC (64 hex chars)")
        except Exception as e:
            print(f"    Decode error: {e}")

    ec.add_test(
        f"COOKIE-{cookie.name}",
        f"Session cookie analysis: {cookie.name}",
        f"GET / -> Set-Cookie",
        f"Secure={cookie.secure}, HttpOnly={'httponly' in str(cookie).lower()}, Value={cookie.value[:30]}...",
        result="PASS" if cookie.secure or "httponly" in str(cookie).lower() else "ANOMALOUS",
    )

# ===========================================================================
# TEST 4: Setup.php Access (CVE-2022-23134)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: setup.php Access (CVE-2022-23134)")
print("=" * 60)

resp = requests.get(f"{ZABBIX_URL}/setup.php", timeout=10, allow_redirects=False)
print(f"\n  GET /setup.php: HTTP {resp.status_code}")

has_login_redirect = "You are not logged in" in resp.text or "login" in resp.text.lower()
has_setup_form = "agreement" in resp.text.lower() or "step" in resp.text.lower()

if resp.status_code == 200 and has_login_redirect:
    print(f"  Result: Returns 200 but requires login")
    result = "PASS"
elif resp.status_code == 200 and has_setup_form:
    print(f"  [!!] SETUP ACCESSIBLE WITHOUT AUTH -- CVE-2022-23134 UNPATCHED")
    result = "VULN"
    ec.add_finding(
        "SETUP-001", "CRITICAL",
        "Unauthenticated setup.php access (CVE-2022-23134)",
        "setup.php is accessible without authentication",
    )
elif resp.status_code in (302, 403):
    print(f"  Result: Properly restricted (HTTP {resp.status_code})")
    result = "PASS"
else:
    print(f"  Result: HTTP {resp.status_code}")
    result = "PASS"

ec.add_test(
    "CVE-2022-23134", "setup.php unauthenticated access",
    "GET /setup.php (no auth)",
    f"HTTP {resp.status_code}, login_redirect={has_login_redirect}",
    result=result,
)

# ===========================================================================
# TEST 5: API Method Enumeration (authenticated as admin)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: API Method Enumeration")
print("=" * 60)

zs = ZabbixSession()
if not zs.test_connection():
    print("  [-] Cannot connect")
    ec.save()
    sys.exit(1)

# Comprehensive list of Zabbix API objects
api_objects = [
    "action", "alert", "apiinfo", "auditlog", "authentication",
    "autoregistration", "configuration", "connector", "correlation",
    "dashboard", "discovery", "discoverycheck", "discoveryrule",
    "drule", "dservice", "event", "graph", "graphitem",
    "graphprototype", "hanode", "history", "host", "hostgroup",
    "hostinterface", "hostprototype", "housekeeping", "httptest",
    "iconmap", "image", "item", "itemprototype", "maintenance",
    "map", "mediatype", "mfa", "module", "problem", "proxy",
    "proxygroup", "regexp", "report", "role", "script",
    "service", "settings", "sla", "task", "template",
    "templategroup", "templatedashboard", "token",
    "trend", "trigger", "triggerprototype", "user",
    "usergroup", "userdirectory", "usermacro", "valuemap",
]

# Common CRUD methods
method_suffixes = ["get", "create", "update", "delete"]

accessible_methods = []
denied_methods = []
error_methods = []

print(f"\n  Testing {len(api_objects)} API objects x {len(method_suffixes)} methods...")

for obj in api_objects:
    for suffix in method_suffixes:
        method = f"{obj}.{suffix}"
        result = zs.api_call(method, {})

        if "error" in result:
            error = result["error"]
            code = error.get("code", 0)
            msg = error.get("message", "")
            data = error.get("data", "")

            if "No permissions" in str(data) or code == -32602:
                denied_methods.append(method)
            elif "Invalid method" in str(data) or code == -32601:
                pass  # Method doesn't exist
            elif "Invalid params" in str(data):
                accessible_methods.append((method, "accessible (invalid params)"))
            else:
                error_methods.append((method, f"{msg}: {data}"))
        elif "result" in result:
            accessible_methods.append((method, f"returned data ({type(result['result']).__name__})"))

        rate_limit(0.05)

print(f"\n  Accessible methods (admin): {len(accessible_methods)}")
for method, note in accessible_methods[:30]:
    print(f"    {method}: {note}")
if len(accessible_methods) > 30:
    print(f"    ... and {len(accessible_methods) - 30} more")

print(f"\n  Denied methods: {len(denied_methods)}")
print(f"  Error methods: {len(error_methods)}")
for method, err in error_methods[:10]:
    print(f"    {method}: {err}")

ec.add_test(
    "API-ENUM",
    f"API method enumeration ({len(api_objects)} objects)",
    f"Tested {len(api_objects) * len(method_suffixes)} method combinations",
    f"Accessible: {len(accessible_methods)}, Denied: {len(denied_methods)}, Errors: {len(error_methods)}",
    result="PASS",
)

# ===========================================================================
# TEST 6: API Access Without Auth
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 6: Unauthenticated API Access")
print("=" * 60)

# Test which methods work without authentication
unauth_test_methods = [
    ("apiinfo.version", {}, "Version disclosure"),
    ("user.login", {"username": "Admin", "password": "wrongpass"}, "Login with wrong password"),
    ("user.get", {"output": ["userid", "username"]}, "User enumeration"),
    ("host.get", {"output": ["hostid", "host"]}, "Host enumeration"),
    ("script.get", {"output": "extend"}, "Script enumeration"),
    ("settings.get", {"output": "extend"}, "Settings disclosure"),
    ("authentication.get", {"output": "extend"}, "Auth config disclosure"),
    ("configuration.export", {"options": {"hosts": ["10084"]}, "format": "json"}, "Config export"),
    ("problem.get", {"output": "extend", "limit": 1}, "Problem list"),
    ("alert.get", {"output": "extend", "limit": 1}, "Alert list"),
]

print()
for method, params, desc in unauth_test_methods:
    resp = requests.post(API_URL,
        json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        headers={"Content-Type": "application/json-rpc"}, timeout=10)

    data = resp.json()
    if "result" in data:
        result_preview = str(data["result"])[:80]
        print(f"  [!!] {method}: ACCESSIBLE (result: {result_preview})")
        test_result = "ANOMALOUS"
    elif "error" in data:
        error_msg = data["error"].get("data", data["error"].get("message", ""))
        if "Not authorized" in str(error_msg) or "Not authorised" in str(error_msg) or "re-login" in str(error_msg):
            print(f"  [  ] {method}: Requires auth")
            test_result = "PASS"
        elif "Login name or password is incorrect" in str(error_msg):
            print(f"  [  ] {method}: Auth error (expected for wrong password)")
            test_result = "PASS"
        else:
            print(f"  [?]  {method}: Error: {error_msg[:60]}")
            test_result = "ANOMALOUS"
    else:
        print(f"  [?]  {method}: Unexpected response")
        test_result = "ANOMALOUS"

    ec.add_test(
        f"UNAUTH-{method.replace('.', '_')[:20]}",
        f"Unauthenticated access: {desc}",
        f"POST api_jsonrpc.php {method} (no auth)",
        f"HTTP {resp.status_code}: {str(data)[:100]}",
        result=test_result,
    )
    rate_limit(0.1)

# ===========================================================================
# TEST 7: User Enumeration via Login
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 7: User Enumeration via Login")
print("=" * 60)

login_tests = [
    ("Admin", "wrongpass", "Valid user, wrong password"),
    ("nonexistent_user_12345", "wrongpass", "Invalid user, wrong password"),
    ("guest", "wrongpass", "Guest user, wrong password"),
    ("admin", "wrongpass", "admin (lowercase), wrong password"),
    ("", "", "Empty credentials"),
    ("Admin", "", "Valid user, empty password"),
]

print()
for username, password, desc in login_tests:
    resp = requests.post(API_URL,
        json={"jsonrpc": "2.0", "method": "user.login",
              "params": {"username": username, "password": password}, "id": 1},
        headers={"Content-Type": "application/json-rpc"}, timeout=10)

    data = resp.json()
    if "error" in data:
        error_msg = data["error"].get("data", "")
        print(f"  {desc}:")
        print(f"    Error: {error_msg[:80]}")
    elif "result" in data:
        print(f"  {desc}:")
        print(f"    [!!] LOGIN SUCCEEDED: token={data['result'][:16]}...")

    ec.add_test(
        f"ENUM-{desc[:20].replace(' ', '_')}",
        f"Login: {desc}",
        f"user.login({username}, {password[:5]}...)",
        f"{str(data)[:100]}",
        result="PASS" if "error" in data else "ANOMALOUS",
    )
    rate_limit(0.3)

# ===========================================================================
# TEST 8: Viewer User Access to Admin-Only Methods
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 8: Privilege Escalation - Viewer Access to Admin Methods")
print("=" * 60)

viewer = ZabbixSession(VIEWER_USER, VIEWER_PASS)
if not viewer.auth_token:
    print("  [-] Viewer login failed")
else:
    admin_methods = [
        ("user.get", {"output": "extend"}, "List all users"),
        ("user.get", {"output": "extend", "selectMedias": "extend"}, "List users with media"),
        ("host.get", {"output": "extend"}, "List all hosts"),
        ("script.get", {"output": "extend"}, "List all scripts"),
        ("authentication.get", {"output": "extend"}, "Auth configuration"),
        ("settings.get", {"output": "extend"}, "Server settings"),
        ("autoregistration.get", {"output": "extend"}, "Autoregistration config"),
        ("role.get", {"output": "extend"}, "List all roles"),
        ("usergroup.get", {"output": "extend"}, "List all user groups"),
        ("mediatype.get", {"output": "extend"}, "List all media types"),
        ("proxy.get", {"output": "extend"}, "List proxies"),
        ("auditlog.get", {"output": "extend", "limit": 3}, "Audit log"),
        ("token.get", {"output": "extend"}, "API tokens"),
        ("housekeeping.get", {"output": "extend"}, "Housekeeping config"),
        ("regexp.get", {"output": "extend"}, "Regular expressions"),
        ("connector.get", {"output": "extend"}, "Connectors"),
    ]

    print()
    for method, params, desc in admin_methods:
        result = viewer.api_call(method, params)

        if "error" in result:
            error_data = result["error"].get("data", "")
            if "No permissions" in str(error_data):
                print(f"  [  ] {method}: No permissions (correctly denied)")
                test_result = "PASS"
            else:
                print(f"  [?]  {method}: {error_data[:60]}")
                test_result = "ANOMALOUS"
        elif "result" in result:
            r = result["result"]
            if isinstance(r, list):
                print(f"  [!!] {method}: ACCESSIBLE ({len(r)} items)")
            elif isinstance(r, dict):
                print(f"  [!!] {method}: ACCESSIBLE ({len(r)} keys)")
            else:
                print(f"  [!!] {method}: ACCESSIBLE ({r})")
            test_result = "ANOMALOUS"
        else:
            print(f"  [?]  {method}: Unexpected response")
            test_result = "ANOMALOUS"

        ec.add_test(
            f"PRIVESC-{method.replace('.', '_')[:20]}",
            f"Viewer access: {desc}",
            f"{method} as viewer01 (roleid=1)",
            f"{str(result)[:150]}",
            result=test_result,
        )
        rate_limit(0.1)

    viewer.logout()

# ===========================================================================
# TEST 9: SCIM API Access
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 9: SCIM API Endpoint")
print("=" * 60)

scim_tests = [
    ("GET", "/api_scim.php/Users", "SCIM Users (no auth)"),
    ("GET", "/api_scim.php/Groups", "SCIM Groups (no auth)"),
    ("GET", "/api_scim.php/ServiceProviderConfig", "SCIM ServiceProviderConfig"),
    ("GET", "/api_scim.php/Schemas", "SCIM Schemas"),
]

for method, path, desc in scim_tests:
    resp = requests.request(method, f"{ZABBIX_URL}{path}", timeout=10)
    print(f"\n  {desc}:")
    print(f"    HTTP {resp.status_code}")
    print(f"    Body: {resp.text[:100]}")

    ec.add_test(
        f"SCIM-{desc[:20].replace(' ', '_')}",
        f"SCIM: {desc}",
        f"{method} {path}",
        f"HTTP {resp.status_code}: {resp.text[:100]}",
        result="ANOMALOUS" if resp.status_code == 200 and "error" not in resp.text.lower() else "PASS",
    )
    rate_limit(0.2)

# ===========================================================================
# TEST 10: Web Frontend Unauthenticated Pages
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 10: Unauthenticated Web Frontend Pages")
print("=" * 60)

unauth_pages = [
    ("/", "Root"),
    ("/index.php", "Login page"),
    ("/setup.php", "Setup wizard"),
    ("/browserwarning.php", "Browser warning"),
    ("/robots.txt", "Robots.txt"),
    ("/favicon.ico", "Favicon"),
    ("/chart.php", "Chart"),
    ("/chart2.php", "Chart2"),
    ("/graph.php", "Graph"),
    ("/history.php", "History"),
    ("/map.php", "Map"),
    ("/jsrpc.php", "JS RPC"),
    ("/api_jsonrpc.php", "JSON-RPC API"),
    ("/api_scim.php", "SCIM API"),
]

print()
for path, desc in unauth_pages:
    resp = requests.get(f"{ZABBIX_URL}{path}", timeout=10, allow_redirects=False)
    is_redirected = resp.status_code in (301, 302)
    has_login_msg = "not logged in" in resp.text.lower() or "login" in resp.text.lower()
    content_length = len(resp.content)

    status_str = f"HTTP {resp.status_code}"
    if is_redirected:
        status_str += f" -> {resp.headers.get('Location', '?')}"

    accessible = resp.status_code == 200 and not has_login_msg
    print(f"  {'[!!]' if accessible else '[  ]'} {path}: {status_str} ({content_length}b)")

    ec.add_test(
        f"UNAUTH-PAGE-{path.replace('/', '_')[:15]}",
        f"Unauth page: {desc}",
        f"GET {path} (no auth)",
        f"{status_str}, login_redirect={has_login_msg}",
        result="ANOMALOUS" if accessible else "PASS",
    )
    rate_limit(0.1)

# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 1 SUMMARY")
print("=" * 60)

ec.save()
