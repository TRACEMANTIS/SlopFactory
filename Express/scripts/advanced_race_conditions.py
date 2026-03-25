#!/usr/bin/env python3
"""
Phase 4.4 — Race Condition Analysis
Express.js Security Assessment — [REDACTED]

Tests rate limiter bypass, concurrent session issues, TOCTOU.
SCOPE: Framework middleware behavior under concurrency.
"""

import requests
import json
import os
import time
import concurrent.futures
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '4.4', 'name': 'Race Condition Analysis', 'timestamp': datetime.now().isoformat()},
    'tests': [], 'findings': [], 'summary': {}
}
test_count = 0

def log_test(name, ver, data, finding=None):
    global test_count
    test_count += 1
    results['tests'].append({'id': test_count, 'test': name, 'version': ver, 'data': data})
    if finding:
        results['findings'].append({'id': len(results['findings'])+1, **finding, 'version': ver})
        print(f"  [{test_count:3d}] ⚠ {name} ({ver})")
    else:
        print(f"  [{test_count:3d}] ✓ {name} ({ver})")


def test_rate_limiter_bypass():
    """Test express-rate-limit under concurrent requests"""
    print("\n[*] Testing rate limiter bypass via concurrency...")

    for ver, base in TARGETS.items():
        # The rate limit is 1000/min for /auth/ routes — test if concurrent requests bypass
        concurrent_counts = [10, 25, 50]

        for count in concurrent_counts:
            success = 0
            rate_limited = 0
            errors = 0

            with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
                futures = []
                for _ in range(count):
                    futures.append(executor.submit(
                        requests.post, f'{base}/auth/token',
                        json={'username': 'admin', 'password': 'admin123'},
                        timeout=5
                    ))

                for f in concurrent.futures.as_completed(futures):
                    try:
                        r = f.result()
                        if r.status_code == 200:
                            success += 1
                        elif r.status_code == 429:
                            rate_limited += 1
                        else:
                            errors += 1
                    except:
                        errors += 1

            log_test(f'rate_limit_{count}', ver, {
                'concurrent': count,
                'success': success,
                'rate_limited': rate_limited,
                'errors': errors
            })


def test_concurrent_session_modification():
    """Test concurrent session writes"""
    print("\n[*] Testing concurrent session modification...")

    for ver, base in TARGETS.items():
        requests.get(f'{base}/seed', timeout=5)

        # Login and get session
        s = requests.Session()
        s.post(f'{base}/login', json={'username': 'admin', 'password': 'admin123'})

        # Concurrent reads of authenticated endpoint
        success = 0
        errors = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for _ in range(50):
                futures.append(executor.submit(
                    s.get, f'{base}/admin/dashboard', timeout=5
                ))

            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    if r.status_code == 200:
                        success += 1
                    else:
                        errors += 1
                except:
                    errors += 1

        finding = None
        if errors > 5:
            finding = {
                'title': f'Session Race Condition: {errors}/50 Errors Under Concurrency',
                'severity': 'LOW', 'cwe': 'CWE-362',
                'description': f'Concurrent session access caused {errors} errors in MemoryStore',
                'framework_behavior': True
            }

        log_test('session_race', ver, {
            'concurrent_requests': 50,
            'success': success,
            'errors': errors
        }, finding)


def test_double_submit():
    """Test double-submit on state-changing endpoints"""
    print("\n[*] Testing double-submit race conditions...")

    for ver, base in TARGETS.items():
        requests.get(f'{base}/seed', timeout=5)

        # Concurrent user registration with same username
        results_reg = {'success': 0, 'conflict': 0, 'error': 0}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(10):
                futures.append(executor.submit(
                    requests.post, f'{base}/register',
                    json={'username': f'racetest_{ver}', 'password': 'pass123'},
                    timeout=5
                ))

            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    if r.status_code == 201:
                        results_reg['success'] += 1
                    elif r.status_code == 409:
                        results_reg['conflict'] += 1
                    else:
                        results_reg['error'] += 1
                except:
                    results_reg['error'] += 1

        finding = None
        if results_reg['success'] > 1:
            finding = {
                'title': f'Race Condition: {results_reg["success"]} Duplicate Registrations',
                'severity': 'MEDIUM', 'cwe': 'CWE-362',
                'description': f'Concurrent registration allowed {results_reg["success"]} '
                               f'users with same username (should be 1)',
                'framework_behavior': False,
                'note': 'SQLite UNIQUE constraint should prevent this — race window issue'
            }

        log_test('double_register', ver, results_reg, finding)


def test_concurrent_upload():
    """Test concurrent file uploads"""
    print("\n[*] Testing concurrent file uploads...")
    import io

    for ver, base in TARGETS.items():
        results_upload = {'success': 0, 'error': 0}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for i in range(20):
                files = {'file': (f'race_{i}.txt', io.BytesIO(f'content_{i}'.encode()), 'text/plain')}
                futures.append(executor.submit(
                    requests.post, f'{base}/upload', files=files, timeout=10
                ))

            for f in concurrent.futures.as_completed(futures):
                try:
                    r = f.result()
                    if r.status_code == 200:
                        results_upload['success'] += 1
                    else:
                        results_upload['error'] += 1
                except:
                    results_upload['error'] += 1

        log_test('concurrent_upload', ver, results_upload)


def test_keepalive_pipelining():
    """Test HTTP pipelining via keep-alive"""
    print("\n[*] Testing HTTP pipelining...")
    import socket

    for ver, (base, port) in [('v5', ('127.0.0.1', 3000)), ('v4', ('127.0.0.1', 3001))]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((base, port))

            # Send 5 pipelined requests
            pipelined = b''
            for i in range(5):
                pipelined += (
                    b'GET /health HTTP/1.1\r\n'
                    b'Host: 127.0.0.1\r\n'
                    b'Connection: keep-alive\r\n'
                    b'\r\n'
                )

            sock.send(pipelined)
            response = b''
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            sock.close()

            response_count = response.count(b'HTTP/1.1 200')

            log_test('pipelining', ver, {
                'requests_sent': 5,
                'responses_received': response_count,
                'total_response_size': len(response)
            })
        except Exception as e:
            log_test('pipelining', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 4.4 — Race Condition Analysis")
    print("=" * 70)

    test_rate_limiter_bypass()
    test_concurrent_session_modification()
    test_double_submit()
    test_concurrent_upload()
    test_keepalive_pipelining()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'race_condition_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nRace condition analysis complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
