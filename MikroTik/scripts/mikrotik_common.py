#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Shared Utilities
Common functions used across all assessment scripts.

Provides:
  - Target configuration
  - Evidence recording
  - Router log pulling (REST API + SSH fallback)
  - Router health monitoring (uptime, CPU, memory)
  - Crash detection
  - SSH command execution
  - RouterOS API helpers
"""

import json
import os
import subprocess
import time
import socket
import requests
from datetime import datetime
from pathlib import Path

# ── Target Configuration ──────────────────────────────────────────────────────
TARGET = "[REDACTED-INTERNAL-IP]"
ADMIN_USER = "admin"
ADMIN_PASS = "TestPass123"

USERS = {
    "admin":     {"password": "TestPass123", "group": "full"},
    "testfull":  {"password": "FullTest123", "group": "full"},
    "testread":  {"password": "ReadTest123", "group": "read"},
    "testwrite": {"password": "WriteTest123", "group": "write"},
}

PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23,
    "http": 80, "https": 443,
    "btest": 2000, "winbox": 8291,
    "api": 8728, "api-ssl": 8729,
    "snmp": 161, "mndp": 5678,
}

BASE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
EVIDENCE_DIR = BASE_DIR / "evidence"
SCANS_DIR = BASE_DIR / "scans"
SCRIPTS_DIR = BASE_DIR / "scripts"
CONFIGS_DIR = BASE_DIR / "configs"


# ── Logging ───────────────────────────────────────────────────────────────────

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# ── Router Health & Crash Detection ──────────────────────────────────────────

def check_router_alive(timeout=5):
    """Quick check if the router is responding. Returns dict with status."""
    try:
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=timeout, verify=False)
        if r.status_code == 200:
            data = r.json()
            return {
                "alive": True,
                "uptime": data.get("uptime"),
                "cpu_load": data.get("cpu-load"),
                "free_memory": data.get("free-memory"),
                "version": data.get("version"),
            }
        return {"alive": True, "status_code": r.status_code}
    except:
        pass

    # Fallback to TCP connect on port 80
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, 80))
        s.close()
        return {"alive": True, "method": "tcp_connect"}
    except:
        return {"alive": False}


def wait_for_router(max_wait=60, check_interval=5):
    """Wait for router to come back online after a potential crash."""
    log(f"Waiting for router to come back online (max {max_wait}s)...")
    start = time.time()
    while time.time() - start < max_wait:
        status = check_router_alive(timeout=3)
        if status["alive"]:
            log(f"  Router is back online: {status}")
            return status
        time.sleep(check_interval)
    log(f"  Router did not respond within {max_wait}s!")
    return {"alive": False, "waited": max_wait}


def get_router_health():
    """Get detailed health snapshot from the router."""
    health = {}
    endpoints = {
        "resource": "/rest/system/resource",
        "health": "/rest/system/health",
        "active_users": "/rest/user/active",
        "interfaces": "/rest/interface",
    }
    for key, path in endpoints.items():
        try:
            r = requests.get(
                f"http://{TARGET}{path}",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=5, verify=False)
            health[key] = r.json() if r.status_code == 200 else {"error": r.status_code}
        except Exception as e:
            health[key] = {"error": str(e)}

    health["timestamp"] = datetime.now().isoformat()
    return health


# ── Router Log Collection ────────────────────────────────────────────────────

def pull_router_logs(phase_name):
    """Pull all logs from the MikroTik router via REST API.

    Saves to evidence/router_logs_{phase_name}.json and returns the data.
    Call at the end of each test phase.
    """
    log(f"Pulling router-side logs for phase: {phase_name}...")
    try:
        # Get full log
        r = requests.get(
            f"http://{TARGET}/rest/log",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=15, verify=False)

        if r.status_code != 200:
            log(f"  Failed to pull logs: HTTP {r.status_code}")
            return None

        log_entries = r.json()

        # System resource snapshot
        resource = {}
        try:
            res_r = requests.get(
                f"http://{TARGET}/rest/system/resource",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=5, verify=False)
            resource = res_r.json() if res_r.status_code == 200 else {}
        except:
            pass

        # Active sessions
        active_users = []
        try:
            act_r = requests.get(
                f"http://{TARGET}/rest/user/active",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=5, verify=False)
            active_users = act_r.json() if act_r.status_code == 200 else []
        except:
            pass

        # Categorize log entries
        categories = {}
        interesting = []
        keywords = ["error", "critical", "warning", "login failure",
                    "auth", "denied", "crash", "out of memory", "panic",
                    "segfault", "assertion", "buffer"]

        for entry in log_entries:
            topics = entry.get("topics", "unknown")
            categories[topics] = categories.get(topics, 0) + 1

            msg = entry.get("message", "").lower()
            if any(kw in msg for kw in keywords):
                interesting.append(entry)

        router_log = {
            "phase": phase_name,
            "pulled_at": datetime.now().isoformat(),
            "log_entry_count": len(log_entries),
            "log_entries": log_entries,
            "categories": categories,
            "interesting_entries": interesting,
            "interesting_count": len(interesting),
            "system_resource": resource,
            "active_users": active_users,
        }

        log_file = EVIDENCE_DIR / f"router_logs_{phase_name}.json"
        with open(log_file, "w") as f:
            json.dump(router_log, f, indent=2, default=str)

        log(f"  Router logs saved: {len(log_entries)} entries, "
            f"{len(interesting)} interesting → {log_file}")
        return router_log

    except Exception as e:
        log(f"  Error pulling router logs: {e}")
        return None


def pull_logs_before_destructive_action(action_name):
    """CRITICAL: Pull all logs BEFORE any action that may cause reboot/shutdown.

    Lesson learned from Phase 4: testread user executed /system/reboot,
    router went down immediately, and all logs were lost on reboot.

    Call this before:
      - Any reboot/shutdown test
      - Privilege escalation tests that may trigger reboot
      - Any destructive action (factory reset, firmware operations)
      - DoS tests that may crash the router

    Also sets up syslog forwarding to capture any final log entries.
    """
    log(f"⚠ PRE-DESTRUCTIVE ACTION: Capturing logs before '{action_name}'")
    result = pull_router_logs(f"pre_destructive_{action_name}")

    # Also try to set up remote syslog forwarding if not already done
    try:
        import socket
        my_ip = socket.gethostbyname(socket.gethostname())
        # This would forward logs to us - but requires admin access
        # Only try if we have admin creds
        r = requests.post(
            f"http://{TARGET}/rest/system/logging/action/add",
            auth=(ADMIN_USER, ADMIN_PASS),
            headers={"Content-Type": "application/json"},
            json={"name": "sectest-syslog", "target": "remote",
                  "remote": my_ip, "remote-port": "514"},
            timeout=5, verify=False)
        if r.status_code in (200, 201):
            log(f"  Syslog forwarding configured to {my_ip}:514")
    except:
        pass  # Best effort

    return result


def clear_router_logs():
    """Clear the router log buffer. Call before starting a new phase
    if you want clean per-phase logs."""
    log("Clearing router log buffer...")
    try:
        r = requests.post(
            f"http://{TARGET}/rest/system/logging/action/set",
            auth=(ADMIN_USER, ADMIN_PASS),
            headers={"Content-Type": "application/json"},
            json={".id": "*0"},  # default memory action
            timeout=5, verify=False)
        # Alternative: use SSH
        subprocess.run(
            ["sshpass", "-p", ADMIN_PASS, "ssh", "-o", "StrictHostKeyChecking=no",
             f"{ADMIN_USER}@{TARGET}", "/log/print count-only"],
            capture_output=True, text=True, timeout=10)
    except Exception as e:
        log(f"  Note: log clear may not be supported via REST: {e}")


# ── SSH Command Execution ────────────────────────────────────────────────────

def ssh_command(cmd, user=None, password=None, timeout=15):
    """Execute a command on RouterOS via SSH. Returns (stdout, stderr, returncode)."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS

    try:
        r = subprocess.run(
            ["sshpass", "-p", password, "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5",
             f"{user}@{TARGET}", cmd],
            capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "SSH command timed out", -1
    except Exception as e:
        return "", str(e), -1


# ── REST API Helpers ─────────────────────────────────────────────────────────

def rest_get(path, user=None, password=None, timeout=10):
    """GET a REST API endpoint. Returns (status_code, data_or_text)."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS
    try:
        r = requests.get(
            f"http://{TARGET}/rest{path}",
            auth=(user, password),
            timeout=timeout, verify=False)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def rest_post(path, data, user=None, password=None, timeout=10):
    """POST to a REST API endpoint. Returns (status_code, data_or_text)."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS
    try:
        r = requests.post(
            f"http://{TARGET}/rest{path}",
            auth=(user, password),
            headers={"Content-Type": "application/json"},
            json=data,
            timeout=timeout, verify=False)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def rest_patch(path, data, user=None, password=None, timeout=10):
    """PATCH a REST API endpoint. Returns (status_code, data_or_text)."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS
    try:
        r = requests.patch(
            f"http://{TARGET}/rest{path}",
            auth=(user, password),
            headers={"Content-Type": "application/json"},
            json=data,
            timeout=timeout, verify=False)
        try:
            return r.status_code, r.json()
        except:
            return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


# ── Evidence Framework ───────────────────────────────────────────────────────

class EvidenceCollector:
    """Standard evidence collection for all assessment scripts."""

    def __init__(self, script_name, phase):
        self.results = {
            "metadata": {
                "script": script_name,
                "target": TARGET,
                "phase": phase,
                "start_time": datetime.now().isoformat(),
                "end_time": None,
                "total_tests": 0,
                "anomalies": 0,
                "router_version": None,
            },
            "tests": [],
            "findings": [],
        }

        # Record initial router state
        status = check_router_alive()
        if status.get("alive"):
            self.results["metadata"]["router_version"] = status.get("version")
            self.results["metadata"]["initial_uptime"] = status.get("uptime")

    def add_test(self, category, name, description, result, details=None, anomaly=False):
        """Record a test result."""
        test = {
            "id": self.results["metadata"]["total_tests"] + 1,
            "category": category,
            "name": name,
            "description": description,
            "result": result,
            "anomaly": anomaly,
            "timestamp": datetime.now().isoformat(),
        }
        if details:
            test["details"] = details
        self.results["tests"].append(test)
        self.results["metadata"]["total_tests"] += 1
        if anomaly:
            self.results["metadata"]["anomalies"] += 1
        status = "⚠ ANOMALY" if anomaly else "✓"
        log(f"  [{status}] {name}: {result}")

    def add_finding(self, severity, title, description, evidence_refs=None,
                    cwe=None, cvss=None, reproduction_steps=None):
        """Record a potential security finding."""
        finding = {
            "id": len(self.results["findings"]) + 1,
            "severity": severity,
            "title": title,
            "description": description,
            "timestamp": datetime.now().isoformat(),
        }
        if evidence_refs:
            finding["evidence_refs"] = evidence_refs
        if cwe:
            finding["cwe"] = cwe
        if cvss:
            finding["cvss_estimate"] = cvss
        if reproduction_steps:
            finding["reproduction_steps"] = reproduction_steps
        self.results["findings"].append(finding)
        log(f"  🔴 FINDING [{severity}]: {title}")

    def save(self, filename):
        """Save evidence JSON and pull router logs."""
        self.results["metadata"]["end_time"] = datetime.now().isoformat()

        # Pull router logs
        phase_name = filename.replace(".json", "")
        router_logs = pull_router_logs(phase_name)
        if router_logs:
            self.results["metadata"]["router_log_count"] = router_logs["log_entry_count"]
            self.results["metadata"]["router_interesting_events"] = router_logs["interesting_count"]

        # Final health check
        final_health = check_router_alive()
        self.results["metadata"]["final_health"] = final_health

        out = EVIDENCE_DIR / filename
        with open(out, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        log(f"Evidence saved to {out}")
        return out

    def summary(self):
        """Print summary line."""
        m = self.results["metadata"]
        f = len(self.results["findings"])
        log(f"{'='*60}")
        log(f"Complete: {m['total_tests']} tests, {m['anomalies']} anomalies, {f} findings")
