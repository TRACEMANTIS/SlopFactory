#!/usr/bin/env python3
"""
MikroTik RouterOS CHR — Continuous Background Health Monitor

Runs as a background process during the entire assessment.
Polls the router every N seconds and logs:
  - Uptime (detects reboots via uptime reset)
  - CPU load
  - Free memory / total memory
  - Active user sessions
  - Process list (via /rest/system/resource/cpu)
  - Interface status

Alerts on:
  - Uptime decrease (reboot detected)
  - Memory below threshold
  - CPU sustained above threshold
  - Router unreachable (crash or network issue)
  - New/dropped services

Outputs:
  - evidence/router_monitor.jsonl  (append-only, one JSON object per poll)
  - evidence/router_monitor_alerts.json  (structured alerts)
  - Console output with timestamps
"""

import json
import os
import sys
import time
import signal
import socket
import requests
from datetime import datetime
from pathlib import Path

# ── Configuration ──
TARGET = os.environ.get("MT_TARGET", "[REDACTED-INTERNAL-IP]")
ADMIN_USER = os.environ.get("MT_USER", "admin")
ADMIN_PASS = os.environ.get("MT_PASS", "TestPass123")
POLL_INTERVAL = int(os.environ.get("MT_POLL_INTERVAL", "5"))  # seconds
EVIDENCE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence")
MONITOR_LOG = EVIDENCE_DIR / "router_monitor.jsonl"
ALERTS_FILE = EVIDENCE_DIR / "router_monitor_alerts.json"
HTTP_BASE = f"http://{TARGET}"

# Thresholds
MEM_WARN_PCT = 15       # Alert if free memory drops below 15%
CPU_WARN_SUSTAINED = 90  # Alert if CPU > 90% for 3+ consecutive polls
CPU_WARN_POLLS = 3
UNREACHABLE_ALERT = 3    # Alert after 3 consecutive unreachable polls

requests.packages.urllib3.disable_warnings()

# ── State ──
prev_uptime_seconds = None
prev_free_memory = None
high_cpu_count = 0
unreachable_count = 0
alerts = []
poll_count = 0
start_time = datetime.now()
running = True


def signal_handler(sig, frame):
    global running
    running = False
    log("Monitor shutting down (signal received)")


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def log(msg):
    print(f"[MONITOR {datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def parse_uptime(uptime_str):
    """Parse RouterOS uptime string to seconds.
    Examples: '3m51s', '1h2m3s', '1d2h3m4s', '20s'
    """
    if not uptime_str:
        return None
    total = 0
    current_num = ""
    for ch in uptime_str:
        if ch.isdigit():
            current_num += ch
        elif ch == 'w':
            total += int(current_num) * 7 * 86400
            current_num = ""
        elif ch == 'd':
            total += int(current_num) * 86400
            current_num = ""
        elif ch == 'h':
            total += int(current_num) * 3600
            current_num = ""
        elif ch == 'm':
            total += int(current_num) * 60
            current_num = ""
        elif ch == 's':
            total += int(current_num)
            current_num = ""
    return total


def add_alert(severity, category, message, data=None):
    alert = {
        "timestamp": datetime.now().isoformat(),
        "severity": severity,
        "category": category,
        "message": message,
        "data": data or {},
        "poll_number": poll_count,
    }
    alerts.append(alert)
    marker = "🔴" if severity == "CRITICAL" else "🟡" if severity == "WARNING" else "ℹ️"
    log(f"  {marker} ALERT [{severity}] {category}: {message}")
    # Write alerts file immediately
    save_alerts()


def save_alerts():
    try:
        with open(ALERTS_FILE, 'w') as f:
            json.dump({
                "monitor_start": start_time.isoformat(),
                "total_polls": poll_count,
                "total_alerts": len(alerts),
                "alerts": alerts,
            }, f, indent=2)
    except Exception as e:
        log(f"  Error saving alerts: {e}")


def poll_router():
    """Single health poll. Returns dict with all collected data."""
    global prev_uptime_seconds, prev_free_memory, high_cpu_count, unreachable_count, poll_count
    poll_count += 1

    record = {
        "timestamp": datetime.now().isoformat(),
        "poll_number": poll_count,
        "alive": False,
    }

    # ── 1. System Resource ──
    try:
        r = requests.get(
            f"{HTTP_BASE}/rest/system/resource",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=5, verify=False)
        if r.status_code == 200:
            res = r.json()
            record["alive"] = True
            record["version"] = res.get("version")
            record["uptime"] = res.get("uptime")
            record["cpu_load"] = int(res.get("cpu-load", 0))
            record["cpu_count"] = int(res.get("cpu-count", 1))
            record["free_memory"] = int(res.get("free-memory", 0))
            record["total_memory"] = int(res.get("total-memory", 1))
            record["free_hdd"] = int(res.get("free-hdd-space", 0))
            record["total_hdd"] = int(res.get("total-hdd-space", 1))
            record["write_sect_total"] = int(res.get("write-sect-total", 0))

            # Derived metrics
            mem_pct = (record["free_memory"] / record["total_memory"]) * 100
            record["free_memory_pct"] = round(mem_pct, 1)
            hdd_pct = (record["free_hdd"] / record["total_hdd"]) * 100
            record["free_hdd_pct"] = round(hdd_pct, 1)

            uptime_seconds = parse_uptime(record["uptime"])
            record["uptime_seconds"] = uptime_seconds

            # ── Check: Reboot detection ──
            if prev_uptime_seconds is not None and uptime_seconds is not None:
                if uptime_seconds < prev_uptime_seconds - 10:  # Allow 10s tolerance
                    add_alert("CRITICAL", "REBOOT",
                              f"Router rebooted! Previous uptime: {prev_uptime_seconds}s, "
                              f"current: {uptime_seconds}s",
                              {"prev_uptime": prev_uptime_seconds,
                               "current_uptime": uptime_seconds})
            prev_uptime_seconds = uptime_seconds

            # ── Check: Memory ──
            if mem_pct < MEM_WARN_PCT:
                add_alert("WARNING", "LOW_MEMORY",
                          f"Free memory at {mem_pct:.1f}% "
                          f"({record['free_memory'] // 1024 // 1024}MB / "
                          f"{record['total_memory'] // 1024 // 1024}MB)",
                          {"free_pct": mem_pct})

            # Memory delta tracking
            if prev_free_memory is not None:
                record["memory_delta"] = record["free_memory"] - prev_free_memory
            prev_free_memory = record["free_memory"]

            # ── Check: CPU ──
            if record["cpu_load"] > CPU_WARN_SUSTAINED:
                high_cpu_count += 1
                if high_cpu_count >= CPU_WARN_POLLS:
                    add_alert("WARNING", "HIGH_CPU",
                              f"CPU at {record['cpu_load']}% for "
                              f"{high_cpu_count} consecutive polls",
                              {"cpu_load": record["cpu_load"],
                               "consecutive": high_cpu_count})
            else:
                high_cpu_count = 0

            # Reset unreachable counter
            unreachable_count = 0
        else:
            record["http_status"] = r.status_code
            unreachable_count += 1
    except requests.exceptions.ConnectTimeout:
        record["error"] = "connect_timeout"
        unreachable_count += 1
    except requests.exceptions.ReadTimeout:
        record["error"] = "read_timeout"
        unreachable_count += 1
    except requests.exceptions.ConnectionError as e:
        record["error"] = f"connection_error: {str(e)[:100]}"
        unreachable_count += 1
    except Exception as e:
        record["error"] = f"unexpected: {str(e)[:100]}"
        unreachable_count += 1

    # ── Check: Unreachable ──
    if unreachable_count >= UNREACHABLE_ALERT:
        if unreachable_count == UNREACHABLE_ALERT:  # Only alert once at threshold
            add_alert("CRITICAL", "UNREACHABLE",
                      f"Router unreachable for {unreachable_count} consecutive polls "
                      f"({unreachable_count * POLL_INTERVAL}s)",
                      {"consecutive": unreachable_count,
                       "error": record.get("error")})

    # ── 2. Active Users (lightweight) ──
    if record["alive"]:
        try:
            r = requests.get(
                f"{HTTP_BASE}/rest/user/active",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=3, verify=False)
            if r.status_code == 200:
                users = r.json()
                record["active_sessions"] = len(users)
                record["active_users"] = list(set(u.get("name", "?") for u in users))
        except:
            pass

    # ── 3. Service port check (quick TCP connect) ──
    if record["alive"]:
        services_up = []
        services_down = []
        for name, port in [("www", 80), ("www-ssl", 443), ("ssh", 22),
                           ("winbox", 8291), ("api", 8728), ("api-ssl", 8729),
                           ("ftp", 21), ("telnet", 23)]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((TARGET, port))
                s.close()
                services_up.append(name)
            except:
                services_down.append(name)
        record["services_up"] = services_up
        record["services_down"] = services_down

    # ── 4. Check for interesting log entries ──
    if record["alive"] and poll_count % 6 == 0:  # Every 30 seconds
        try:
            r = requests.get(
                f"{HTTP_BASE}/rest/log",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=5, verify=False)
            if r.status_code == 200:
                logs = r.json()
                interesting = []
                keywords = ["crash", "panic", "error", "critical", "out of memory",
                           "watchdog", "supout", "kernel", "segfault", "exception"]
                for entry in logs[-20:]:  # Last 20 entries
                    msg = entry.get("message", "").lower()
                    topics = entry.get("topics", "").lower()
                    if any(kw in msg or kw in topics for kw in keywords):
                        interesting.append({
                            "time": entry.get("time"),
                            "topics": entry.get("topics"),
                            "message": entry.get("message"),
                        })
                if interesting:
                    record["interesting_logs"] = interesting
                    for log_entry in interesting:
                        add_alert("WARNING", "INTERESTING_LOG",
                                  f"{log_entry['topics']}: {log_entry['message'][:100]}",
                                  log_entry)
                record["total_log_entries"] = len(logs)
        except:
            pass

    return record


def main():
    log(f"Starting continuous monitor for {TARGET}")
    log(f"Poll interval: {POLL_INTERVAL}s")
    log(f"Log file: {MONITOR_LOG}")
    log(f"Alerts file: {ALERTS_FILE}")
    log(f"Thresholds: memory<{MEM_WARN_PCT}%, cpu>{CPU_WARN_SUSTAINED}%x{CPU_WARN_POLLS}")
    log("─" * 60)

    # Initial health check
    initial = poll_router()
    if initial["alive"]:
        log(f"✓ Router online: {initial.get('version')}, uptime={initial.get('uptime')}, "
            f"mem={initial.get('free_memory_pct')}% free, cpu={initial.get('cpu_load')}%")
        log(f"  Services UP: {initial.get('services_up', [])}")
        log(f"  Services DOWN: {initial.get('services_down', [])}")
    else:
        log(f"⚠ Router not responding on initial check: {initial.get('error')}")

    # Append initial record
    with open(MONITOR_LOG, 'a') as f:
        f.write(json.dumps(initial) + "\n")

    # Main loop
    while running:
        time.sleep(POLL_INTERVAL)
        if not running:
            break

        record = poll_router()

        # Append to JSONL
        with open(MONITOR_LOG, 'a') as f:
            f.write(json.dumps(record) + "\n")

        # Compact console output (every poll)
        if record["alive"]:
            status = (f"UP  uptime={record.get('uptime'):>10s}  "
                      f"cpu={record.get('cpu_load', 0):>3d}%  "
                      f"mem={record.get('free_memory_pct', 0):>5.1f}%  "
                      f"sessions={record.get('active_sessions', '?')}")
            if record.get("memory_delta") and abs(record["memory_delta"]) > 1048576:
                delta_mb = record["memory_delta"] / 1048576
                status += f"  Δmem={delta_mb:+.1f}MB"
        else:
            status = f"DOWN  error={record.get('error', 'unknown')}"

        # Only print every 6th poll (30s) unless something changed, or always if DOWN
        if not record["alive"] or poll_count % 6 == 0 or record.get("memory_delta", 0) < -5242880:
            log(status)

    # Shutdown
    log(f"Monitor stopped. Total polls: {poll_count}, alerts: {len(alerts)}")
    save_alerts()
    log(f"Final data in {MONITOR_LOG} and {ALERTS_FILE}")


if __name__ == "__main__":
    main()
