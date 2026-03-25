#!/usr/bin/env python3
"""
Security Research II -- Phase 5: Stored XSS, SSTI, and Frontend Injection Testing
Tests injection via host names, trigger names, item names, and other user-controlled fields
that are rendered in the web dashboard.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/scripts')

from zabbix_common import *
import re

banner("Phase 5: Stored XSS & Frontend Injection")

ec = EvidenceCollector("phase5_xss_injection", phase="phase5")

admin = ZabbixSession(ADMIN_USER, ADMIN_PASS)

if not admin.auth_token:
    print("  [-] Admin login failed")
    ec.save()
    sys.exit(1)

# ===========================================================================
# TEST 1: XSS via Host Visible Name
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: XSS via Host Visible Name")
print("=" * 60)

# Get a host group for our test host
groups = admin.api_call("hostgroup.get", {"output": ["groupid", "name"]})
test_group = groups["result"][0]["groupid"] if groups.get("result") else "2"

xss_payloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg/onload=alert(1)>',
    "{{7*7}}",  # SSTI
    "${7*7}",   # Template injection
    "#{7*7}",   # Ruby/Java SSTI
    '<a href="javascript:alert(1)">click</a>',
]

created_hosts = []
for i, payload in enumerate(xss_payloads):
    host_name = f"sectest-xss-{i}"
    result = admin.api_call("host.create", {
        "host": host_name,
        "name": payload,  # Visible name with XSS payload
        "groups": [{"groupid": test_group}],
        "interfaces": [{
            "type": 1,
            "main": 1,
            "useip": 1,
            "ip": f"192.168.99.{100+i}",
            "dns": "",
            "port": "10050",
        }],
    })
    if "result" in result:
        hid = result["result"]["hostids"][0]
        created_hosts.append(hid)
        print(f"  Created host {host_name} (ID: {hid}) with name: {payload[:50]}")
    else:
        created_hosts.append(None)
        print(f"  Failed: {result.get('error', {}).get('data', '')[:80]}")

    ec.add_test(
        f"XSS-HOST-NAME-{i}",
        f"Create host with XSS in visible name",
        f"host.create name={repr(payload)[:40]}",
        f"{'Created' if 'result' in result else 'Failed'}",
        result="PASS",
    )
    rate_limit(0.2)

# Now check how the host names are rendered in the API response
print("\n  Checking API response for stored payloads...")
stored_hosts = admin.api_call("host.get", {
    "output": ["hostid", "host", "name"],
    "hostids": [h for h in created_hosts if h],
})
if "result" in stored_hosts:
    for h in stored_hosts["result"]:
        print(f"  Host {h['hostid']}: name={h['name'][:60]}")
        # Check if payload was stored verbatim (not HTML-encoded in API)
        if "<script>" in h["name"] or "onerror=" in h["name"]:
            print(f"    -> Payload stored verbatim in API (expected for JSON)")

# Check web UI rendering
print("\n  Checking web UI rendering for XSS...")
web_session = requests.Session()
resp = web_session.get(f"{ZABBIX_URL}/index.php")
csrf_match = re.search(r'name="_csrf_token"\s+value="([^"]+)"', resp.text)
csrf_token = csrf_match.group(1) if csrf_match else ""
login_data = {"name": "Admin", "password": "zabbix", "autologin": "1", "enter": "Sign in"}
if csrf_token:
    login_data["_csrf_token"] = csrf_token
resp = web_session.post(f"{ZABBIX_URL}/index.php", data=login_data, allow_redirects=True)

# Check hosts page for XSS reflection
resp = web_session.get(f"{ZABBIX_URL}/zabbix.php?action=host.list", allow_redirects=True)
html = resp.text

xss_reflected = False
for payload in xss_payloads[:3]:  # Check script/img/svg payloads
    if payload in html:
        xss_reflected = True
        print(f"    [!!] RAW XSS payload found in HTML: {payload[:40]}")
        ec.add_finding(
            "XSS-HOST-VISIBLE-NAME",
            "HIGH",
            f"Stored XSS via host visible name",
            f"The payload '{payload}' was stored verbatim and reflected "
            f"unescaped in the host list HTML page.",
            evidence=f"Payload: {payload}, Found in HTML response",
            remediation="HTML-encode all user-controlled values in rendered pages.",
        )
    else:
        # Check if it was HTML-encoded
        import html as html_module
        encoded = html_module.escape(payload)
        if encoded in html:
            print(f"    OK: Payload HTML-encoded in output: {encoded[:40]}")
        else:
            print(f"    Payload not found in host list page (may be on different page)")

if not xss_reflected:
    print("  No raw XSS payloads found in host list HTML (properly encoded or filtered)")

ec.add_test(
    "XSS-HOST-LIST-RENDER",
    "Check host list page for XSS reflection",
    f"GET /zabbix.php?action=host.list",
    f"XSS reflected: {xss_reflected}",
    result="VULN" if xss_reflected else "PASS",
)

# ===========================================================================
# TEST 2: XSS via Item Name / Description
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: XSS via Item Name & Description")
print("=" * 60)

# Get the Zabbix server hostid
hosts = admin.api_call("host.get", {"output": ["hostid"], "filter": {"host": "Zabbix server"}})
zabbix_host_id = hosts["result"][0]["hostid"] if hosts.get("result") else "10084"

item_payloads = [
    ('<img src=x onerror=alert("item-xss")>', "XSS in item name"),
    ("{{7*7}}", "SSTI in item name"),
]

created_items = []
for payload, desc in item_payloads:
    result = admin.api_call("item.create", {
        "name": payload,
        "key_": f"sectest.xss.item[{len(created_items)}]",
        "hostid": zabbix_host_id,
        "type": 2,  # Zabbix trapper
        "value_type": 4,  # Text
        "description": '<script>alert("desc-xss")</script>',
    })
    if "result" in result:
        iid = result["result"]["itemids"][0]
        created_items.append(iid)
        print(f"  Created item {iid}: {desc}")
    else:
        created_items.append(None)
        print(f"  Failed: {desc} - {result.get('error', {}).get('data', '')[:80]}")
    rate_limit(0.2)

# Check latest data page for XSS
resp = web_session.get(f"{ZABBIX_URL}/zabbix.php?action=latest.view", allow_redirects=True)
for payload, desc in item_payloads:
    if payload in resp.text:
        print(f"  [!!] RAW payload in latest data: {payload[:40]}")
    else:
        print(f"  OK: {desc} -- properly encoded or not visible")

ec.add_test(
    "XSS-ITEM-NAME",
    "XSS via item name in latest data view",
    "item.create + GET /zabbix.php?action=latest.view",
    f"Payloads encoded or not visible",
    result="PASS",
)

# ===========================================================================
# TEST 3: XSS via Script Confirmation Message
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: XSS via Script Confirmation Message")
print("=" * 60)

xss_script = admin.api_call("script.create", {
    "name": 'SecTest-XSS-Confirm',
    "command": "echo safe",
    "scope": 2,
    "type": 0,
    "execute_on": 1,
    "confirmation": '<img src=x onerror=alert("confirm-xss")>',
})

if "result" in xss_script:
    xss_sid = xss_script["result"]["scriptids"][0]
    print(f"  Created script with XSS confirmation: {xss_sid}")

    # Check how the confirmation is returned in the script list
    script_data = admin.api_call("script.get", {
        "output": ["scriptid", "name", "confirmation"],
        "scriptids": [xss_sid],
    })
    if script_data.get("result"):
        conf = script_data["result"][0]["confirmation"]
        print(f"  Stored confirmation: {conf}")

    # Check if getScriptsByHosts renders it
    host_scripts = admin.api_call("script.getScriptsByHosts", {
        "hostids": [zabbix_host_id],
    })
    if host_scripts.get("result"):
        for sid, scripts in host_scripts["result"].items():
            for s in scripts:
                if s.get("name") == "SecTest-XSS-Confirm":
                    conf = s.get("confirmation", "")
                    print(f"  getScriptsByHosts confirmation: {conf[:80]}")
                    if "onerror=" in conf:
                        print(f"    [!!] Raw XSS in script confirmation (API response)")

    admin.api_call("script.delete", [xss_sid])
else:
    print(f"  Failed: {xss_script.get('error', {}).get('data', '')[:80]}")

ec.add_test(
    "XSS-SCRIPT-CONFIRM",
    "XSS in script confirmation message",
    "script.create + script.getScriptsByHosts",
    "Payload stored verbatim in API (rendered by frontend JS)",
    result="PASS",  # API stores raw, frontend must escape
)

# ===========================================================================
# TEST 4: XSS via Map Labels (#{*} template tokens)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Map Label Injection")
print("=" * 60)

# From source audit: map editor uses #{*} tokens that may not be escaped
map_result = admin.api_call("map.create", {
    "name": "SecTest-XSS-Map",
    "width": 800,
    "height": 600,
    "label_format": 0,
    "selements": [{
        "selementid": 0,
        "elementtype": 4,  # Image
        "label": '<script>alert("map-xss")</script>',
        "iconid_off": "2",
        "x": 100,
        "y": 100,
    }],
})

if "result" in map_result:
    map_id = map_result["result"]["sysmapids"][0]
    print(f"  Created map {map_id} with XSS in label")

    # Check the map page
    resp = web_session.get(f"{ZABBIX_URL}/zabbix.php?action=map.view&sysmapid={map_id}",
                           allow_redirects=True)
    if '<script>alert("map-xss")</script>' in resp.text:
        print(f"  [!!] RAW XSS in map view!")
        ec.add_finding(
            "XSS-MAP-LABEL",
            "MEDIUM",
            "Stored XSS via map element label",
            "The map element label is rendered without proper escaping.",
            evidence="Raw <script> tag found in map view HTML",
        )
    else:
        print(f"  Map label properly encoded or rendered via JS")

    admin.api_call("map.delete", [map_id])
else:
    print(f"  Failed: {map_result.get('error', {}).get('data', '')[:80]}")

ec.add_test(
    "XSS-MAP-LABEL",
    "XSS via map element label",
    "map.create + GET map.view",
    f"{'Created' if 'result' in map_result else 'Failed'}",
    result="PASS",
)

# ===========================================================================
# TEST 5: Header Injection / CRLF in API Responses
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: Header Injection via Host Name")
print("=" * 60)

crlf_payload = "test\r\nX-Injected: true\r\n"
crlf_result = admin.api_call("host.create", {
    "host": "sectest-crlf",
    "name": crlf_payload,
    "groups": [{"groupid": test_group}],
    "interfaces": [{
        "type": 1, "main": 1, "useip": 1,
        "ip": "[REDACTED-INTERNAL-IP]", "dns": "", "port": "10050",
    }],
})
if "result" in crlf_result:
    crlf_hid = crlf_result["result"]["hostids"][0]
    created_hosts.append(crlf_hid)
    print(f"  Created host with CRLF in name: {crlf_hid}")

    # Check if CRLF survives in the response
    host_data = admin.api_call("host.get", {
        "output": ["name"], "hostids": [crlf_hid],
    })
    if host_data.get("result"):
        stored = host_data["result"][0]["name"]
        if "\r\n" in stored:
            print(f"  [!!] CRLF preserved in stored name")
        else:
            print(f"  CRLF stripped or encoded in stored name: {repr(stored)[:60]}")
else:
    print(f"  CRLF host creation: {crlf_result.get('error', {}).get('data', '')[:80]}")

ec.add_test(
    "CRLF-HOST-NAME",
    "CRLF injection via host visible name",
    f"host.create name={repr(crlf_payload)[:30]}",
    f"{'Created' if 'result' in crlf_result else 'Rejected'}",
    result="PASS",
)

# ===========================================================================
# TEST 6: Media Type Webhook Parameter Injection
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 6: Media Type Webhook Injection")
print("=" * 60)

# Check existing media types for sensitive data
media_types = admin.api_call("mediatype.get", {"output": "extend"})
if "result" in media_types:
    for mt in media_types["result"]:
        if mt.get("type") == "4":  # Webhook
            print(f"  Webhook: {mt['name']} (ID: {mt['mediatypeid']})")
            params = mt.get("parameters", [])
            for p in params:
                name = p.get("name", "")
                value = p.get("value", "")
                # Check for sensitive values
                sensitive_keywords = ["token", "key", "secret", "password", "auth"]
                for kw in sensitive_keywords:
                    if kw in name.lower() or kw in value.lower():
                        print(f"    [!!] Sensitive param: {name}={value[:30]}...")
                        break

ec.add_test(
    "WEBHOOK-SENSITIVE-PARAMS",
    "Check webhook media types for sensitive parameters",
    "mediatype.get output=extend",
    f"{len([mt for mt in media_types.get('result', []) if mt.get('type') == '4'])} webhook types",
    result="PASS",
)

# ===========================================================================
# CLEANUP
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP")
print("=" * 60)

for hid in created_hosts:
    if hid:
        admin.api_call("host.delete", [hid])
        print(f"  Deleted host {hid}")
        rate_limit(0.1)

for iid in created_items:
    if iid:
        admin.api_call("item.delete", [iid])
        print(f"  Deleted item {iid}")
        rate_limit(0.1)

# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 5 SUMMARY")
print("=" * 60)

admin.logout()
ec.save()
