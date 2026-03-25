#!/usr/bin/env python3
"""
COBALT STRIKE II — Phase 1: Reconnaissance & API Mapping
Maps all REST API endpoints, checks auth requirements, analyzes headers.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *

banner("Phase 1: Jellyfin Reconnaissance & API Mapping")

ec = EvidenceCollector("phase1_recon", phase="phase1")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Server Information Gathering
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("  1. Server Information Gathering")
print("=" * 60)

# Public info (unauthenticated)
print("\n[*] Public system info (unauthenticated)...\n")
resp = js.raw_get("/System/Info/Public")
if resp.status_code == 200:
    pub_info = resp.json()
    for k, v in pub_info.items():
        print(f"    {k}: {v}")
    ec.add_test("RECON-001", "Public system info", "GET /System/Info/Public",
               json.dumps(pub_info, indent=2), result="PASS")

# Full system info (authenticated)
print("\n[*] Full system info (authenticated)...\n")
resp = js.get("/System/Info")
if resp.status_code == 200:
    full_info = resp.json()
    sensitive_keys = [
        "OperatingSystem", "OperatingSystemDisplayName", "Architecture",
        "LocalAddress", "ServerName", "Version", "HasPendingRestart",
        "HasUpdateAvailable", "InternalMetadataPath", "LogPath",
        "TranscodingTempPath", "CachePath", "WebPath", "ProgramDataPath",
        "ItemsByNamePath", "CanSelfRestart", "CanSelfUpdate",
        "SupportsLibraryMonitor", "EncoderLocation", "SystemArchitecture",
    ]
    for k in sensitive_keys:
        if k in full_info:
            print(f"    {k}: {full_info[k]}")
    ec.add_test("RECON-002", "Full system info (authenticated)", "GET /System/Info",
               json.dumps({k: full_info.get(k) for k in sensitive_keys}, indent=2),
               result="PASS")

# Response headers analysis
print("\n[*] Analyzing response headers...\n")
resp = js.raw_get("/")
for header in ["Content-Security-Policy", "X-Content-Type-Options",
               "X-Frame-Options", "Strict-Transport-Security",
               "X-XSS-Protection", "Server", "X-Powered-By",
               "Access-Control-Allow-Origin", "X-Response-Time-ms"]:
    value = resp.headers.get(header, "NOT SET")
    print(f"    {header}: {value}")

csp = resp.headers.get("Content-Security-Policy", "")
ec.add_test("RECON-003", "Response headers analysis",
           "GET /", json.dumps(dict(resp.headers), indent=2)[:1000],
           result="PASS")

# ═══════════════════════════════════════════════════════════════════════════════
# 2. API Endpoint Discovery & Unauthenticated Access Testing
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("  2. API Endpoint Discovery & Auth Testing")
print("=" * 60)

# Key endpoints to test (from source code analysis)
endpoints = [
    # System
    ("GET", "/System/Info/Public", "Public server info"),
    ("GET", "/System/Info", "Full server info (admin)"),
    ("GET", "/System/Configuration", "Server configuration"),
    ("GET", "/System/Logs", "Server log files"),
    ("GET", "/System/Logs/Log", "Download server log"),
    ("POST", "/System/Restart", "Restart server"),
    ("POST", "/System/Shutdown", "Shutdown server"),

    # Auth & Users
    ("GET", "/Users", "List all users"),
    ("GET", "/Users/Public", "Public user list"),
    ("POST", "/Users/AuthenticateByName", "Login endpoint"),
    ("POST", "/Users/ForgotPassword", "Password reset"),

    # Library & Items
    ("GET", "/Items", "Browse library items"),
    ("GET", "/Library/VirtualFolders", "Library folders"),
    ("GET", "/Library/MediaFolders", "Media folders"),

    # Images (SSRF surface)
    ("GET", "/Images/Remote?imageUrl=http://127.0.0.1:8096/System/Info/Public", "Remote image fetch (SSRF)"),
    ("GET", "/Items/RemoteSearch/Image", "Remote search image"),

    # Video/Audio (FFmpeg surface)
    ("GET", "/Videos/test/stream", "Video stream"),
    ("GET", "/Audio/test/stream", "Audio stream"),

    # Encoding & Transcoding
    ("GET", "/System/MediaEncoder/Path", "FFmpeg path"),
    ("GET", "/Encoding/MediaInfo", "Encoding info"),

    # DLNA
    ("GET", "/Dlna/Profiles", "DLNA profiles"),
    ("GET", "/Dlna/Info", "DLNA info"),

    # API docs
    ("GET", "/api-docs/openapi.json", "OpenAPI spec"),
    ("GET", "/api-docs/swagger", "Swagger UI"),

    # Sessions
    ("GET", "/Sessions", "Active sessions"),

    # Devices
    ("GET", "/Devices", "Registered devices"),

    # Plugins
    ("GET", "/Plugins", "Installed plugins"),
    ("GET", "/Repositories", "Plugin repositories"),

    # Scheduled Tasks
    ("GET", "/ScheduledTasks", "Scheduled tasks"),

    # Activity Log
    ("GET", "/System/ActivityLog/Entries", "Activity log"),

    # Branding
    ("GET", "/Branding/Configuration", "Branding config"),
    ("GET", "/Branding/Css", "Custom CSS"),

    # Quick Connect
    ("GET", "/QuickConnect/Enabled", "Quick Connect status"),

    # Search
    ("GET", "/Search/Hints?searchTerm=test", "Search"),

    # Notifications
    ("GET", "/Notifications/Types", "Notification types"),

    # Package/Update info
    ("GET", "/Packages", "Available packages"),

    # Playback
    ("GET", "/Playback/BitrateTest", "Bitrate test"),

    # Environment
    ("GET", "/Environment/DefaultDirectoryBrowser", "Directory browser"),

    # Auth keys
    ("GET", "/Auth/Keys", "API keys"),
]

print(f"\n[*] Testing {len(endpoints)} endpoints for authentication requirements...\n")

unauth_accessible = []
auth_required = []
not_found = []

for method, endpoint, desc in endpoints:
    try:
        # Test unauthenticated first
        if method == "GET":
            resp_noauth = js.raw_get(endpoint)
        else:
            resp_noauth = js.raw_post(endpoint)

        unauth_code = resp_noauth.status_code

        # Test authenticated
        if method == "GET":
            resp_auth = js.get(endpoint)
        else:
            resp_auth = js.post(endpoint)

        auth_code = resp_auth.status_code

        # Classify
        if unauth_code == 200:
            unauth_accessible.append((endpoint, desc))
            status = "UNAUTH"
            marker = "[!]"
        elif auth_code == 200:
            auth_required.append((endpoint, desc))
            status = "AUTH"
            marker = "[+]"
        elif auth_code in (404, 405):
            not_found.append((endpoint, desc))
            status = "N/A"
            marker = "[-]"
        else:
            status = f"UNAUTH:{unauth_code}/AUTH:{auth_code}"
            marker = "[?]"

        print(f"  {marker} {method:4s} {endpoint:55s} → unauth:{unauth_code} auth:{auth_code} ({desc})")

        result = "VULN" if unauth_code == 200 else "PASS"
        severity = "HIGH" if unauth_code == 200 and endpoint not in [
            "/System/Info/Public", "/Users/Public", "/Branding/Configuration",
            "/Branding/Css", "/QuickConnect/Enabled", "/api-docs/openapi.json",
            "/api-docs/swagger",
        ] else "INFO"

        ec.add_test(
            f"ENDPOINT-{endpoint.replace('/', '-')[1:][:30]}",
            f"{method} {endpoint} — {desc}",
            f"{method} {endpoint} (unauthenticated)",
            f"Unauth: HTTP {unauth_code}, Auth: HTTP {auth_code}",
            result=result,
            severity=severity,
        )

        rate_limit(0.1)

    except Exception as e:
        print(f"  [!] Error: {endpoint} — {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# 3. OpenAPI Spec Analysis
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("  3. OpenAPI Specification Analysis")
print("=" * 60)

resp = js.raw_get("/api-docs/openapi.json")
if resp.status_code == 200:
    try:
        spec = resp.json()
        paths = spec.get("paths", {})
        total_endpoints = sum(len(methods) for methods in paths.values())
        print(f"\n  [+] OpenAPI spec loaded: {len(paths)} paths, {total_endpoints} total endpoints")

        # Count by method
        method_counts = {}
        for path, methods in paths.items():
            for method in methods:
                method_counts[method.upper()] = method_counts.get(method.upper(), 0) + 1

        for m, c in sorted(method_counts.items()):
            print(f"      {m}: {c}")

        # Find endpoints that don't require auth (no security requirement)
        no_auth_endpoints = []
        for path, methods in paths.items():
            for method, details in methods.items():
                security = details.get("security", spec.get("security", []))
                if not security or security == [{}]:
                    no_auth_endpoints.append(f"{method.upper()} {path}")

        if no_auth_endpoints:
            print(f"\n  [!] Endpoints without security requirement in spec: {len(no_auth_endpoints)}")
            for ep in no_auth_endpoints[:20]:
                print(f"      {ep}")
            if len(no_auth_endpoints) > 20:
                print(f"      ... and {len(no_auth_endpoints) - 20} more")

        ec.add_test("OPENAPI-001", f"OpenAPI spec: {len(paths)} paths, {total_endpoints} endpoints",
                   "GET /api-docs/openapi.json",
                   f"Paths: {len(paths)}, Endpoints: {total_endpoints}, No-auth: {len(no_auth_endpoints)}",
                   result="PASS")

        # Save endpoint list for reference
        with open("/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scans/api_endpoints.json", "w") as f:
            endpoint_list = []
            for path, methods in sorted(paths.items()):
                for method, details in methods.items():
                    endpoint_list.append({
                        "method": method.upper(),
                        "path": path,
                        "summary": details.get("summary", ""),
                        "tags": details.get("tags", []),
                    })
            json.dump(endpoint_list, f, indent=2)
        print(f"\n  [+] Saved endpoint list to scans/api_endpoints.json")

    except Exception as e:
        print(f"  [-] Failed to parse OpenAPI spec: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Library Setup — Add Media for Testing
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("  4. Library Setup")
print("=" * 60)

# Add media library
print("\n[*] Adding media library...\n")

libraries_resp = js.get("/Library/VirtualFolders")
if libraries_resp.status_code == 200:
    existing = libraries_resp.json()
    if not existing:
        # Add movies library
        add_resp = js.post("/Library/VirtualFolders?collectionType=movies&refreshLibrary=true&name=TestMovies",
                          data={"LibraryOptions": {"PathInfos": [{"Path": "/media/movies"}]}})
        if add_resp.status_code in (200, 201, 204):
            print("  [+] Added TestMovies library")
        else:
            print(f"  [-] Library add failed: HTTP {add_resp.status_code}: {add_resp.text[:200]}")

        # Add music library
        add_resp = js.post("/Library/VirtualFolders?collectionType=music&refreshLibrary=true&name=TestMusic",
                          data={"LibraryOptions": {"PathInfos": [{"Path": "/media/music"}]}})
        if add_resp.status_code in (200, 201, 204):
            print("  [+] Added TestMusic library")
        else:
            print(f"  [-] Music library add failed: HTTP {add_resp.status_code}: {add_resp.text[:200]}")
    else:
        print(f"  [+] {len(existing)} libraries already exist")
        for lib in existing:
            print(f"      {lib.get('Name', '?')}: {lib.get('Locations', [])}")


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("  PHASE 1 SUMMARY")
print("=" * 60)

print(f"\n  Endpoints tested: {len(endpoints)}")
print(f"  Unauthenticated access: {len(unauth_accessible)}")
for ep, desc in unauth_accessible:
    print(f"    → {ep} ({desc})")
print(f"  Auth required: {len(auth_required)}")
print(f"  Not found/N/A: {len(not_found)}")

ec.save()
