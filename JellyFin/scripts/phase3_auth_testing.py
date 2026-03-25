#!/usr/bin/env python3
"""
COBALT STRIKE II -- Phase 3: Authentication & Authorization Testing
Tests session management, privilege escalation, IDOR, and auth bypass vectors.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *
import hashlib

banner("Phase 3: Authentication & Authorization Testing")

ec = EvidenceCollector("phase3_auth_testing", phase="phase3")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)

admin_token = js.access_token
admin_user_id = js.user_id


# ===========================================================================
# TEST 1: Create non-admin test user
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: Create Non-Admin Test User")
print("=" * 60)

viewer_id = create_test_user(js, username="cobalt_viewer", password="ViewerPass123")

# Authenticate as viewer
viewer_session = JellyfinSession()
viewer_session.base_url = js.base_url
viewer_session.username = "cobalt_viewer"
viewer_session.password = "ViewerPass123"
if viewer_session.authenticate():
    print(f"  Authenticated as viewer: {viewer_session.user_id}")
    print(f"  Token: {viewer_session.access_token[:20]}...")
else:
    print("  [-] Failed to authenticate as viewer")


# ===========================================================================
# TEST 2: Vertical privilege escalation (viewer -> admin)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: Vertical Privilege Escalation")
print("=" * 60)

if viewer_session.access_token:
    # Try admin-only endpoints with viewer token
    admin_endpoints = [
        ("GET", "/System/Info", "Full system info (admin)"),
        ("GET", "/System/Configuration", "Server configuration"),
        ("GET", "/System/Logs", "Server log files"),
        ("GET", "/Users", "List all users"),
        ("GET", "/Devices", "Registered devices"),
        ("GET", "/Auth/Keys", "API keys"),
        ("GET", "/ScheduledTasks", "Scheduled tasks"),
        ("GET", "/System/ActivityLog/Entries", "Activity log"),
        ("GET", "/Plugins", "Installed plugins"),
        ("GET", "/Sessions", "Active sessions"),
        ("POST", "/Users/New", "Create new user"),
        ("POST", "/Auth/Keys", "Create API key"),
        ("GET", "/System/Configuration/livetv", "Live TV config"),
        ("POST", "/LiveTv/TunerHosts", "Add tuner host"),
    ]

    print("\n  Testing admin endpoints with viewer token:\n")

    for method, endpoint, desc in admin_endpoints:
        try:
            if method == "GET":
                resp = viewer_session.get(endpoint)
            else:
                resp = viewer_session.post(endpoint, data={})

            status = resp.status_code
            is_blocked = status in (401, 403)

            if is_blocked:
                print(f"  [  ] BLOCKED: {method} {endpoint} -> {status} ({desc})")
            else:
                print(f"  [!!] ACCESSIBLE: {method} {endpoint} -> {status} ({desc})")
                if status == 200:
                    ec.add_finding(
                        f"PRIVESC-{endpoint.replace('/', '-')[1:][:25]}",
                        "HIGH",
                        f"Privilege escalation: viewer can access {endpoint}",
                        f"Non-admin user accessed admin endpoint {method} {endpoint} "
                        f"and received HTTP {status}.",
                    )

            ec.add_test(
                f"PRIVESC-{endpoint.replace('/', '-')[1:][:20]}",
                f"Privesc: {desc[:35]}",
                f"{method} {endpoint} (viewer token)",
                f"HTTP {status}",
                result="VULN" if not is_blocked and status == 200 else "PASS",
            )

            rate_limit(0.1)
        except Exception as e:
            print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 3: IDOR -- Access other user's data
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: IDOR Testing")
print("=" * 60)

if viewer_session.access_token:
    print("\n  Testing cross-user data access (viewer -> admin's data):\n")

    idor_tests = [
        # Try to access admin's profile as viewer
        ("GET", f"/Users/{admin_user_id}", "Admin profile via viewer"),
        # Try to update admin user
        ("POST", f"/Users/{admin_user_id}", "Update admin user via viewer"),
        # Try to set admin password
        ("POST", f"/Users/{admin_user_id}/Password",
         "Change admin password via viewer"),
        # Try to access admin's items
        ("GET", f"/Users/{admin_user_id}/Items", "Admin items via viewer"),
        # Try to access admin's views
        ("GET", f"/Users/{admin_user_id}/Views", "Admin views via viewer"),
        # Try to delete admin user
        ("DELETE", f"/Users/{admin_user_id}", "Delete admin user via viewer"),
    ]

    for method, endpoint, desc in idor_tests:
        try:
            if method == "GET":
                resp = viewer_session.get(endpoint)
            elif method == "POST":
                resp = viewer_session.post(endpoint, data={})
            elif method == "DELETE":
                resp = viewer_session.delete(endpoint)

            status = resp.status_code
            is_blocked = status in (401, 403)

            if is_blocked:
                print(f"  [  ] BLOCKED: {method} {endpoint[:60]} -> {status}")
            elif status == 200:
                print(f"  [!!] ACCESSIBLE: {method} {endpoint[:60]} -> {status}")
                data = resp.text[:200]
                ec.add_finding(
                    f"IDOR-{desc[:20]}",
                    "HIGH",
                    f"IDOR: {desc}",
                    f"Viewer user accessed {method} {endpoint} and got {status}. "
                    f"Response: {data}",
                )
            else:
                print(f"  [  ] {method} {endpoint[:60]} -> {status}")

            ec.add_test(
                f"IDOR-{desc[:20]}",
                f"IDOR: {desc[:35]}",
                f"{method} {endpoint[:60]} (viewer token)",
                f"HTTP {status}",
                result="VULN" if status == 200 and not is_blocked else "PASS",
            )

            rate_limit(0.1)
        except Exception as e:
            print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 4: Session management analysis
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Session Management")
print("=" * 60)

print("\n  Token analysis:\n")

# Token entropy analysis
admin_tok = admin_token
viewer_tok = viewer_session.access_token if viewer_session.access_token else ""

print(f"  Admin token:  {admin_tok[:30]}... (len={len(admin_tok)})")
print(f"  Viewer token: {viewer_tok[:30]}... (len={len(viewer_tok)})")
print(f"  Token format: {'hex' if all(c in '0123456789abcdef' for c in admin_tok) else 'other'}")

# Check token reuse/fixation
print("\n  Testing token behavior:\n")

# Authenticate again to get a new token
js2 = JellyfinSession()
js2.base_url = js.base_url
js2.username = "root"
js2.password = ""
js2.authenticate()
new_admin_token = js2.access_token

print(f"  Old admin token: {admin_tok[:30]}...")
print(f"  New admin token: {new_admin_token[:30]}...")
print(f"  Tokens are {'SAME' if admin_tok == new_admin_token else 'DIFFERENT'}")

# Test if old token still works
resp = js.get("/System/Info")
print(f"  Old token still valid: {'YES' if resp.status_code == 200 else 'NO'}")

ec.add_test("SESSION-TOKEN-REUSE", "Token reuse across logins",
           "Authenticate twice, compare tokens",
           f"Old: {admin_tok[:20]}..., New: {new_admin_token[:20]}..., "
           f"Same: {admin_tok == new_admin_token}, OldValid: {resp.status_code == 200}",
           result="PASS")

# Test session invalidation (logout)
print("\n  Testing logout:\n")
logout_resp = js2.post("/Sessions/Logout")
print(f"  Logout: HTTP {logout_resp.status_code}")

# Check if token still works after logout
rate_limit(0.5)
check_resp = js2.get("/System/Info")
print(f"  Token after logout: HTTP {check_resp.status_code}")

ec.add_test("SESSION-LOGOUT", "Token invalidation on logout",
           "POST /Sessions/Logout then GET /System/Info",
           f"Logout: {logout_resp.status_code}, After: {check_resp.status_code}",
           result="VULN" if check_resp.status_code == 200 else "PASS")


# ===========================================================================
# TEST 5: API key testing
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: API Key Testing")
print("=" * 60)

print("\n  Creating and testing API key...\n")

api_key = get_api_key(js)
if api_key:
    print(f"  API key created: {api_key[:20]}...")

    # Test API key access scope
    api_endpoints = [
        "/System/Info",
        "/Users",
        "/System/Configuration",
        f"/Users/{admin_user_id}",
    ]

    for ep in api_endpoints:
        resp = js.session.get(
            f"{js.base_url}{ep}",
            headers={"X-Emby-Token": api_key},
            timeout=10,
        )
        print(f"  API key -> {ep}: HTTP {resp.status_code}")

        ec.add_test(
            f"APIKEY-{ep.replace('/', '-')[1:][:20]}",
            f"API key access: {ep[:30]}",
            f"GET {ep} with X-Emby-Token",
            f"HTTP {resp.status_code}",
            result="PASS",
        )

    # Clean up API key
    keys_resp = js.get("/Auth/Keys")
    if keys_resp.status_code == 200:
        for key in keys_resp.json().get("Items", []):
            if key.get("AccessToken") == api_key:
                js.delete(f"/Auth/Keys/{key.get('AccessToken', '')}")
else:
    print("  [-] Failed to create API key")


# ===========================================================================
# TEST 6: Authentication bypass attempts
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 6: Authentication Bypass Attempts")
print("=" * 60)

print("\n  Testing various auth bypass techniques:\n")

bypass_tests = [
    {
        "name": "empty_token",
        "headers": {"X-Emby-Authorization": 'MediaBrowser Token=""'},
        "desc": "Empty token in auth header",
    },
    {
        "name": "null_token",
        "headers": {"X-Emby-Authorization": 'MediaBrowser Token="null"'},
        "desc": "Null string token",
    },
    {
        "name": "admin_header",
        "headers": {
            "X-Emby-Authorization": 'MediaBrowser Client="Jellyfin Web", '
            'Device="Chrome", DeviceId="admin", Version="10.11.6"'
        },
        "desc": "Auth header without token",
    },
    {
        "name": "api_key_param",
        "headers": {},
        "endpoint": "/System/Info?api_key=admin",
        "desc": "api_key query parameter",
    },
    {
        "name": "x_emby_token",
        "headers": {"X-Emby-Token": "invalid_token_12345"},
        "desc": "Invalid X-Emby-Token header",
    },
]

for test in bypass_tests:
    try:
        endpoint = test.get("endpoint", "/System/Info")
        resp = js.session.get(
            f"{js.base_url}{endpoint}",
            headers=test["headers"],
            timeout=10,
        )
        status = resp.status_code

        if status == 200:
            print(f"  [!!] BYPASS: {test['name']} -> {status} ({test['desc']})")
            ec.add_finding(
                f"AUTH-BYPASS-{test['name']}",
                "CRITICAL",
                f"Authentication bypass: {test['desc']}",
                f"Accessing {endpoint} with {test['desc']} returned HTTP 200.",
            )
        else:
            print(f"  [  ] Blocked: {test['name']} -> {status}")

        ec.add_test(
            f"AUTH-BYPASS-{test['name']}",
            f"Auth bypass: {test['desc'][:35]}",
            f"GET {endpoint} with {test['name']}",
            f"HTTP {status}",
            result="VULN" if status == 200 else "PASS",
        )

        rate_limit(0.1)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 7: User enumeration
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 7: User Enumeration")
print("=" * 60)

print("\n  Testing username enumeration via login response timing/content:\n")

# Test with valid and invalid usernames
test_users = [
    ("root", "", "Valid admin (no password)"),
    ("root", "wrongpassword", "Valid admin (wrong password)"),
    ("nonexistent", "test", "Non-existent user"),
    ("admin", "admin", "Common admin username"),
]

import time as time_module

for username, password, desc in test_users:
    try:
        start = time_module.time()
        headers = {
            "Content-Type": "application/json",
            "X-Emby-Authorization": js._auth_header(token=None),
        }
        resp = js.session.post(
            f"{js.base_url}/Users/AuthenticateByName",
            headers=headers,
            json={"Username": username, "Pw": password},
            timeout=10,
        )
        elapsed = time_module.time() - start

        status = resp.status_code
        # Check if error messages differ
        error_msg = resp.text[:100] if status != 200 else "SUCCESS"

        print(f"  {desc:35s} -> {status} ({elapsed:.3f}s) {error_msg[:50]}")

        ec.add_test(
            f"USERENUM-{username[:10]}",
            f"User enum: {desc[:30]}",
            f"POST /Users/AuthenticateByName user={username}",
            f"HTTP {status}, {elapsed:.3f}s, {error_msg[:80]}",
            result="PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# CLEANUP
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP")
print("=" * 60)

# Delete test user
if viewer_id:
    resp = js.delete(f"/Users/{viewer_id}")
    print(f"  Deleted viewer user: HTTP {resp.status_code}")


# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 3 SUMMARY")
print("=" * 60)

ec.save()
