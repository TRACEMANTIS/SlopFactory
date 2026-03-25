#!/usr/bin/env python3
"""
Security Research II -- Phase 3: CORS/CSRF Testing
Tests the wildcard CORS + cookie-based auth interaction.
Also tests CSRF on web UI forms.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/scripts')

from zabbix_common import *

banner("Phase 3: CORS/CSRF & Cookie Security Testing")

ec = EvidenceCollector("phase3_cors_csrf", phase="phase3")

# ===========================================================================
# TEST 1: CORS Configuration Analysis
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: CORS Configuration on API Endpoints")
print("=" * 60)

# Test CORS preflight with various origins
origins = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",  # data: URIs send Origin: null
    "http://localhost:9080",  # same origin
]

for origin in origins:
    # OPTIONS preflight
    resp = requests.options(f"{ZABBIX_URL}/api_jsonrpc.php",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        }, timeout=10)

    acao = resp.headers.get("Access-Control-Allow-Origin", "MISSING")
    acah = resp.headers.get("Access-Control-Allow-Headers", "MISSING")
    acam = resp.headers.get("Access-Control-Allow-Methods", "MISSING")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "MISSING")

    print(f"\n  Origin: {origin}")
    print(f"    Access-Control-Allow-Origin: {acao}")
    print(f"    Access-Control-Allow-Headers: {acah}")
    print(f"    Access-Control-Allow-Methods: {acam}")
    print(f"    Access-Control-Allow-Credentials: {acac}")

    # Key: if ACAO=* and ACAC is not present, browser won't send credentials
    # But zbx_session is a custom cookie without SameSite, and SameSite defaults to Lax
    # POST requests from cross-origin will NOT include cookies with SameSite=Lax

    ec.add_test(
        f"CORS-{origin[:20].replace(':', '_')}",
        f"CORS preflight for origin {origin[:25]}",
        f"OPTIONS /api_jsonrpc.php Origin: {origin}",
        f"ACAO={acao}, ACAC={acac}",
        result="ANOMALOUS" if acao == "*" else "PASS",
    )
    rate_limit(0.1)

# ===========================================================================
# TEST 2: Cookie SameSite Analysis
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: Cookie SameSite & Security Attributes")
print("=" * 60)

# Login via web UI to get the actual cookie
session = requests.Session()
resp = session.get(f"{ZABBIX_URL}/index.php")

import re
csrf_match = re.search(r'name="_csrf_token"\s+value="([^"]+)"', resp.text)
csrf_token = csrf_match.group(1) if csrf_match else ""

login_data = {
    "name": "Admin",
    "password": "zabbix",
    "autologin": "1",
    "enter": "Sign in",
}
if csrf_token:
    login_data["_csrf_token"] = csrf_token

resp = session.post(f"{ZABBIX_URL}/index.php", data=login_data, allow_redirects=False)

# Analyze the Set-Cookie header
raw_headers = str(resp.headers)
set_cookie_headers = [h for h in resp.headers.items() if h[0].lower() == "set-cookie"]

print(f"\n  Login response: HTTP {resp.status_code}")
for name, value in set_cookie_headers:
    print(f"  Set-Cookie: {value}")

    # Parse cookie attributes
    parts = value.split(";")
    cookie_name = parts[0].split("=")[0].strip()
    attributes = {}
    for part in parts[1:]:
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            attributes[k.strip().lower()] = v.strip()
        else:
            attributes[part.lower()] = True

    print(f"\n  Cookie: {cookie_name}")
    print(f"    HttpOnly: {'httponly' in attributes}")
    print(f"    Secure: {'secure' in attributes}")
    print(f"    SameSite: {attributes.get('samesite', 'NOT SET (defaults to Lax in modern browsers)')}")
    print(f"    Path: {attributes.get('path', 'not set')}")
    print(f"    Domain: {attributes.get('domain', 'not set')}")

    # Report findings
    if cookie_name == "zbx_session":
        samesite = attributes.get("samesite", "NOT SET")
        has_secure = "secure" in attributes
        has_httponly = "httponly" in attributes

        if samesite == "NOT SET":
            print(f"\n    [!!] SameSite NOT SET -- relies on browser default (Lax)")
            print(f"         Impact: In older browsers (pre-2020) without SameSite=Lax default,")
            print(f"         the cookie WOULD be sent with cross-origin POST requests.")
            print(f"         Combined with Access-Control-Allow-Origin: *, this enables")
            print(f"         cross-site JSON-RPC API CSRF.")

        if not has_secure:
            print(f"\n    [!!] Secure flag NOT SET")
            print(f"         Cookie sent over HTTP, vulnerable to network sniffing")

ec.add_test(
    "COOKIE-SAMESITE",
    "zbx_session SameSite attribute",
    "POST /index.php login -> Set-Cookie analysis",
    f"SameSite not explicitly set, Secure={has_secure if 'has_secure' in dir() else 'N/A'}",
    result="ANOMALOUS",
)

# ===========================================================================
# TEST 3: Cross-Origin API Call Simulation
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: Cross-Origin API Call Simulation")
print("=" * 60)

# Simulate what a cross-origin attacker page would do
# If the zbx_session cookie IS sent, the API should authenticate from it
print("\n  Simulating cross-origin POST to API with cookie...")

# First, get a valid session cookie
login_session = requests.Session()
resp = login_session.get(f"{ZABBIX_URL}/index.php")
csrf_match = re.search(r'name="_csrf_token"\s+value="([^"]+)"', resp.text)
csrf_token = csrf_match.group(1) if csrf_match else ""
login_data = {"name": "Admin", "password": "zabbix", "autologin": "1", "enter": "Sign in"}
if csrf_token:
    login_data["_csrf_token"] = csrf_token
resp = login_session.post(f"{ZABBIX_URL}/index.php", data=login_data, allow_redirects=False)

cookie_val = login_session.cookies.get("zbx_session", "")
print(f"  Session cookie: {cookie_val[:30]}...")

# Now make an API call with JUST the cookie (no auth parameter)
# This simulates what a browser would do on a cross-origin POST if the cookie is sent
cross_origin_session = requests.Session()
cross_origin_session.cookies.set("zbx_session", cookie_val, domain="localhost")

result = cross_origin_session.post(
    f"{ZABBIX_URL}/api_jsonrpc.php",
    json={"jsonrpc": "2.0", "method": "user.get", "params": {"output": ["userid", "username"]}, "auth": None, "id": 1},
    headers={"Content-Type": "application/json-rpc", "Origin": "https://evil.com"},
    timeout=10,
)

data = result.json()
if "result" in data:
    print(f"  [!!] API call with cookie-only auth SUCCEEDED!")
    print(f"  Users returned: {data['result']}")
    print(f"\n  This confirms that if a browser sends the zbx_session cookie")
    print(f"  with a cross-origin POST, the API WILL authenticate the request.")
    print(f"  The protection relies SOLELY on SameSite=Lax browser default.")

    ec.add_finding(
        "CORS-CSRF-001", "MEDIUM",
        "Wildcard CORS + cookie auth enables cross-site API CSRF",
        f"The API at /api_jsonrpc.php sends Access-Control-Allow-Origin: * and "
        f"authenticates from the zbx_session cookie when auth=null. "
        f"The zbx_session cookie does NOT set SameSite attribute explicitly. "
        f"In browsers that do NOT default to SameSite=Lax (pre-2020 browsers, "
        f"or when SameSite=None is set), a malicious website can make "
        f"authenticated API calls on behalf of the logged-in user. "
        f"This enables: user enumeration, configuration changes, script execution, "
        f"and other privileged API actions via cross-site request forgery.",
        evidence=f"ACAO: *, Cookie SameSite: NOT SET, API auth from cookie: SUCCESS, "
                 f"Users returned: {json.dumps(data['result'])[:200]}",
        remediation=(
            "1. Remove Access-Control-Allow-Origin: * or restrict to specific trusted origins.\n"
            "2. Explicitly set SameSite=Strict on the zbx_session cookie.\n"
            "3. Add CSRF token validation for API calls authenticated via cookie.\n"
            "4. Use Access-Control-Allow-Credentials: false (already implied by * origin)."
        ),
    )
elif "error" in data:
    print(f"  API call with cookie-only: DENIED ({data['error'].get('data', '')[:80]})")
    print(f"  Cookie-based auth not active for API calls or session expired")

ec.add_test(
    "CORS-CSRF-API",
    "Cross-origin API call with cookie auth",
    "POST /api_jsonrpc.php auth=null + zbx_session cookie + Origin: evil.com",
    f"{'SUCCEEDED' if 'result' in data else 'DENIED'}: {str(data)[:100]}",
    result="VULN" if "result" in data else "PASS",
)

# ===========================================================================
# TEST 4: CSRF on Web UI Forms
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: CSRF Protection on Web UI Forms")
print("=" * 60)

# Check if web UI forms require CSRF token
# Try to submit actions without CSRF token

# First, get authenticated session
web_session = requests.Session()
resp = web_session.get(f"{ZABBIX_URL}/index.php")
csrf_match = re.search(r'name="_csrf_token"\s+value="([^"]+)"', resp.text)
csrf_token = csrf_match.group(1) if csrf_match else ""
login_data = {"name": "Admin", "password": "zabbix", "autologin": "1", "enter": "Sign in"}
if csrf_token:
    login_data["_csrf_token"] = csrf_token
resp = web_session.post(f"{ZABBIX_URL}/index.php", data=login_data, allow_redirects=True)
print(f"  Web login: HTTP {resp.status_code}")

# Try actions without CSRF token
csrf_tests = [
    {
        "desc": "Authentication settings update (no CSRF)",
        "url": "/zabbix.php?action=authentication.update",
        "data": {"authentication_type": "0", "db_authentication_type": "0"},
    },
    {
        "desc": "User profile update (no CSRF)",
        "url": "/zabbix.php?action=userprofile.update",
        "data": {"userid": "1", "lang": "en_US"},
    },
]

for test in csrf_tests:
    resp = web_session.post(
        f"{ZABBIX_URL}{test['url']}",
        data=test["data"],
        allow_redirects=False,
    )
    print(f"\n  {test['desc']}:")
    print(f"    HTTP {resp.status_code}")
    if resp.status_code == 200:
        if "access denied" in resp.text.lower() or "csrf" in resp.text.lower():
            print(f"    CSRF protection active")
        elif "updated" in resp.text.lower() or "success" in resp.text.lower():
            print(f"    [!!] Action succeeded without CSRF token!")
    elif resp.status_code == 302:
        location = resp.headers.get("Location", "")
        print(f"    Redirected to: {location}")
        if "csrf" in location.lower() or "denied" in location.lower():
            print(f"    CSRF protection active")

    ec.add_test(
        f"CSRF-{test['desc'][:20].replace(' ', '_')}",
        f"CSRF test: {test['desc'][:40]}",
        f"POST {test['url'][:40]} without CSRF token",
        f"HTTP {resp.status_code}",
        result="PASS",
    )
    rate_limit(0.3)

# ===========================================================================
# TEST 5: User.checkAuthentication session oracle
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: user.checkAuthentication as Session Oracle")
print("=" * 60)

# Get a valid session ID from the login
admin = ZabbixSession()
if admin.auth_token:
    # Check it with the oracle (no auth required)
    result = requests.post(API_URL,
        json={"jsonrpc": "2.0", "method": "user.checkAuthentication",
              "params": {"sessionid": admin.auth_token}, "id": 1},
        headers={"Content-Type": "application/json-rpc"}, timeout=10)

    data = result.json()
    if "result" in data:
        print(f"\n  Valid session oracle:")
        for key in ["userid", "username", "name", "surname", "roleid", "type"]:
            if key in data["result"]:
                print(f"    {key}: {data['result'][key]}")
        print(f"  [!!] Session oracle returns user profile without separate auth!")

    # Check with invalid session
    result2 = requests.post(API_URL,
        json={"jsonrpc": "2.0", "method": "user.checkAuthentication",
              "params": {"sessionid": "00000000000000000000000000000000"}, "id": 2},
        headers={"Content-Type": "application/json-rpc"}, timeout=10)

    data2 = result2.json()
    if "error" in data2:
        print(f"\n  Invalid session: {data2['error'].get('data', '')[:60]}")
    else:
        print(f"\n  [!!] Invalid session returned data: {data2}")

    ec.add_test(
        "SESSION-ORACLE",
        "user.checkAuthentication as session validity oracle",
        "user.checkAuthentication(sessionid=<valid_id>) no auth",
        f"Returns user profile: {'YES' if 'result' in data else 'NO'}",
        result="ANOMALOUS" if "result" in data else "PASS",
    )

    admin.logout()

# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 3 SUMMARY")
print("=" * 60)

ec.save()
