#!/usr/bin/env python3
"""
Security Research II -- Phase 6: SSRF, Information Disclosure, and Additional Attack Vectors
Tests SSRF via URL type scripts, item configurations, media type webhooks,
and information disclosure through various API endpoints.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/scripts')

from zabbix_common import *
import re

banner("Phase 6: SSRF, Info Disclosure & Additional Vectors")

ec = EvidenceCollector("phase6_ssrf_additional", phase="phase6")

admin = ZabbixSession(ADMIN_USER, ADMIN_PASS)
viewer = ZabbixSession(VIEWER_USER, VIEWER_PASS)

if not admin.auth_token:
    print("  [-] Admin login failed")
    ec.save()
    sys.exit(1)

# ===========================================================================
# TEST 1: URL-type Script SSRF
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: URL-type Script SSRF Testing")
print("=" * 60)

# URL scripts (type=2) open a URL with macro substitution
# Check if internal URLs can be accessed
ssrf_urls = [
    ("http://127.0.0.1:10051/", "Zabbix server internal"),
    ("http://localhost:5432/", "PostgreSQL"),
    ("file:///etc/passwd", "Local file read"),
    ("http://[REDACTED-IP]/latest/meta-data/", "AWS metadata"),
    ("gopher://127.0.0.1:5432/", "Gopher to PostgreSQL"),
]

for url, desc in ssrf_urls:
    result = admin.api_call("script.create", {
        "name": f"SecTest-SSRF-{desc[:15]}",
        "type": 2,  # URL type
        "url": url,
        "scope": 2,
        "new_window": 1,
    })
    if "result" in result:
        sid = result["result"]["scriptids"][0]
        print(f"  Created URL script ({desc}): {sid}")
        # URL scripts aren't "executed" server-side -- they open in the user's browser
        # But check if the URL is validated
        admin.api_call("script.delete", [sid])
    else:
        err = result.get("error", {}).get("data", "")
        print(f"  {desc}: {err[:80]}")

    ec.add_test(
        f"SSRF-URL-SCRIPT-{desc[:15].replace(' ', '_')}",
        f"URL script with {desc}",
        f"script.create type=2 url={url[:40]}",
        f"{'Created (client-side only)' if 'result' in result else 'Rejected: ' + result.get('error', {}).get('data', '')[:40]}",
        result="PASS",
    )
    rate_limit(0.2)

# ===========================================================================
# TEST 2: HTTP Agent Item SSRF
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: HTTP Agent Item SSRF")
print("=" * 60)

hosts = admin.api_call("host.get", {"output": ["hostid"], "filter": {"host": "Zabbix server"}})
host_id = hosts["result"][0]["hostid"]

# HTTP agent items (type=19) make server-side HTTP requests
ssrf_targets = [
    ("http://127.0.0.1:10051/", "Zabbix server port"),
    ("http://127.0.0.1:5432/", "PostgreSQL port"),
    ("http://[REDACTED-IP]/latest/meta-data/", "AWS metadata"),
]

created_items = []
for url, desc in ssrf_targets:
    result = admin.api_call("item.create", {
        "name": f"SecTest-SSRF-{desc[:20]}",
        "key_": f"sectest.ssrf[{len(created_items)}]",
        "hostid": host_id,
        "type": 19,  # HTTP agent
        "value_type": 4,  # Text
        "url": url,
        "timeout": "5s",
        "delay": "0",  # Don't auto-run
    })
    if "result" in result:
        iid = result["result"]["itemids"][0]
        created_items.append(iid)
        print(f"  Created HTTP agent item ({desc}): {iid}")
    else:
        created_items.append(None)
        print(f"  Failed ({desc}): {result.get('error', {}).get('data', '')[:80]}")

    ec.add_test(
        f"SSRF-HTTP-ITEM-{desc[:15].replace(' ', '_')}",
        f"HTTP agent item to {desc}",
        f"item.create type=19 url={url[:40]}",
        f"{'Created' if 'result' in result else 'Rejected'}",
        result="PASS",
    )
    rate_limit(0.2)

# ===========================================================================
# TEST 3: Viewer Information Disclosure via API
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: Viewer Information Disclosure")
print("=" * 60)

if viewer.auth_token:
    # Check what sensitive information the viewer can access
    disclosure_tests = [
        ("settings.get", {"output": "extend"}, "Global settings"),
        ("housekeeping.get", {"output": "extend"}, "Housekeeping config"),
        ("authentication.get", {"output": "extend"}, "Authentication settings"),
        ("autoregistration.get", {"output": "extend"}, "Auto-registration config"),
        ("proxy.get", {"output": "extend"}, "Proxy list"),
        ("mediatype.get", {"output": "extend", "selectMessageTemplates": "extend"}, "Media types with templates"),
        ("script.get", {"output": "extend"}, "All scripts"),
        ("user.get", {"output": ["userid", "username", "name", "surname", "roleid"]}, "User list"),
        ("usergroup.get", {"output": "extend"}, "User groups"),
        ("role.get", {"output": "extend", "selectRules": "extend"}, "Roles with rules"),
        ("token.get", {"output": "extend"}, "API tokens"),
        ("connector.get", {"output": "extend"}, "Connectors"),
    ]

    for method, params, desc in disclosure_tests:
        result = viewer.api_call(method, params)
        if "result" in result:
            count = len(result["result"]) if isinstance(result["result"], list) else 1
            print(f"  [+] {desc:35s}: {count} records")

            # Check for sensitive data in specific responses
            if method == "authentication.get":
                auth_data = result["result"]
                print(f"      Auth type: {auth_data.get('authentication_type', 'N/A')}")
                print(f"      LDAP config: {auth_data.get('ldap_userdirectoryid', 'N/A')}")
                print(f"      SAML enabled: {auth_data.get('saml_auth_enabled', 'N/A')}")
                print(f"      MFA status: {auth_data.get('mfa_status', 'N/A')}")
                print(f"      Passwd min len: {auth_data.get('passwd_min_length', 'N/A')}")

            elif method == "script.get":
                for s in result["result"]:
                    if "{MANUALINPUT}" in s.get("command", ""):
                        print(f"      Script with MANUALINPUT: {s['name']} (cmd: {s['command'][:60]})")
                    # Viewer can see script commands -- potential info disclosure
                    if "password" in s.get("command", "").lower() or "secret" in s.get("command", "").lower():
                        print(f"      [!!] Script with sensitive content: {s['name']}")

            elif method == "token.get":
                for t in result["result"]:
                    print(f"      Token: {t.get('name', 'N/A')} (userid: {t.get('userid', 'N/A')}, "
                          f"status: {t.get('status', 'N/A')})")
        else:
            err = result.get("error", {}).get("data", result.get("error", {}).get("message", ""))
            print(f"  [-] {desc:35s}: DENIED - {err[:40]}")

        ec.add_test(
            f"VIEWER-DISCLOSURE-{method[:20]}",
            f"Viewer access to {desc[:30]}",
            f"{method} as viewer",
            f"{'Accessible: ' + str(count if 'count' in dir() else 'N/A') + ' records' if 'result' in result else 'Denied'}",
            result="ANOMALOUS" if "result" in result and method in ["authentication.get", "autoregistration.get"] else "PASS",
        )
        rate_limit(0.2)

# ===========================================================================
# TEST 4: API Key / Session Token Leaks
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Session Token Entropy & Predictability")
print("=" * 60)

# Collect multiple session tokens to check entropy
tokens = []
for i in range(5):
    s = ZabbixSession(ADMIN_USER, ADMIN_PASS)
    if s.auth_token:
        tokens.append(s.auth_token)
        s.logout()
    rate_limit(0.1)

print(f"  Collected {len(tokens)} session tokens")
for t in tokens:
    print(f"    {t}")

# Check for patterns
if len(tokens) >= 2:
    # All should be unique
    unique = len(set(tokens)) == len(tokens)
    print(f"  All unique: {unique}")

    # Check length consistency
    lengths = set(len(t) for t in tokens)
    print(f"  Lengths: {lengths}")

    # Check hex character set
    all_hex = all(all(c in "0123456789abcdef" for c in t) for t in tokens)
    print(f"  All hex: {all_hex}")

    # Simple sequential check
    if all_hex and len(tokens) >= 2:
        int_tokens = [int(t, 16) for t in tokens]
        diffs = [int_tokens[i+1] - int_tokens[i] for i in range(len(int_tokens)-1)]
        sequential = any(0 < d < 1000 for d in diffs)
        print(f"  Sequential pattern: {sequential}")

ec.add_test(
    "SESSION-TOKEN-ENTROPY",
    "Session token entropy and predictability check",
    f"Collected {len(tokens)} tokens",
    f"Unique: {unique if 'unique' in dir() else 'N/A'}, Hex: {all_hex if 'all_hex' in dir() else 'N/A'}",
    result="PASS",
)

# ===========================================================================
# TEST 5: SCIM API Testing
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: SCIM API Authentication & Access")
print("=" * 60)

scim_endpoints = [
    ("/api_scim.php/ServiceProviderConfig", "GET", "SCIM Service Provider Config"),
    ("/api_scim.php/Users", "GET", "SCIM Users"),
    ("/api_scim.php/Groups", "GET", "SCIM Groups"),
]

for endpoint, method, desc in scim_endpoints:
    url = f"{ZABBIX_URL}{endpoint}"

    # Without auth
    if method == "GET":
        resp = requests.get(url, timeout=10)
    else:
        resp = requests.post(url, json={}, timeout=10)

    print(f"\n  {desc} (no auth):")
    print(f"    HTTP {resp.status_code}")
    if resp.status_code == 200:
        try:
            data = resp.json()
            print(f"    Response: {json.dumps(data)[:150]}")
        except:
            print(f"    Response: {resp.text[:100]}")
    else:
        print(f"    Response: {resp.text[:100]}")

    ec.add_test(
        f"SCIM-{desc[:20].replace(' ', '_')}",
        f"SCIM: {desc} (unauthenticated)",
        f"{method} {endpoint}",
        f"HTTP {resp.status_code}",
        result="ANOMALOUS" if resp.status_code == 200 and "Users" in endpoint else "PASS",
    )

    # With admin auth token as Bearer
    headers = {"Authorization": f"Bearer {admin.auth_token}"}
    if method == "GET":
        resp2 = requests.get(url, headers=headers, timeout=10)
    else:
        resp2 = requests.post(url, headers=headers, json={}, timeout=10)

    print(f"  {desc} (with auth):")
    print(f"    HTTP {resp2.status_code}")
    if resp2.status_code == 200:
        try:
            data2 = resp2.json()
            print(f"    Response: {json.dumps(data2)[:150]}")
        except:
            pass

    rate_limit(0.2)

# ===========================================================================
# CLEANUP
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP")
print("=" * 60)

for iid in created_items:
    if iid:
        admin.api_call("item.delete", [iid])
        print(f"  Deleted item {iid}")
        rate_limit(0.1)

# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 6 SUMMARY")
print("=" * 60)

viewer.logout()
admin.logout()
ec.save()
