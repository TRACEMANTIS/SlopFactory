#!/usr/bin/env python3
"""
Phase 2.7 — ReDoS Fuzzer
Express.js Security Assessment — [REDACTED]

Tests regex handling in Express routing (path-to-regexp) and user regex endpoints.
SCOPE: Framework routing regex behavior — path-to-regexp ReDoS potential.
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
    'metadata': {'phase': '2.7', 'name': 'ReDoS Fuzzer', 'timestamp': datetime.now().isoformat(),
                 'scope': 'Express routing regex + Node.js regex handling'},
    'tests': [], 'findings': [], 'anomalies': [], 'summary': {}
}
test_count = 0
anomaly_count = 0

def log_test(name, ver, data, finding=None, anomaly=None):
    global test_count, anomaly_count
    test_count += 1
    results['tests'].append({'id': test_count, 'test': name, 'version': ver, 'data': data})
    if finding:
        results['findings'].append({'id': len(results['findings'])+1, **finding, 'version': ver})
        print(f"  [{test_count:3d}] ⚠ {name} ({ver})")
    elif anomaly:
        anomaly_count += 1
        results['anomalies'].append({'id': anomaly_count, **anomaly, 'version': ver})
        print(f"  [{test_count:3d}] ? {name} ({ver})")
    else:
        print(f"  [{test_count:3d}] ✓ {name} ({ver})")


def test_redos_patterns():
    """Test known ReDoS patterns via regex-test endpoint"""
    print("\n[*] Testing ReDoS patterns...")

    redos_payloads = [
        # Classic catastrophic backtracking patterns
        ('exponential_1', '(a+)+$', 'a' * 25 + '!'),
        ('exponential_2', '(a|aa)+$', 'a' * 25 + '!'),
        ('exponential_3', '(a|a?)+$', 'a' * 25 + '!'),
        ('polynomial_1', '(a+)*$', 'a' * 25 + '!'),
        ('nested_quantifier', '(.*a){10}', 'a' * 20 + 'b'),
        ('alternation_deep', '(a|b|ab)+$', 'ab' * 15 + 'c'),
        ('email_like', '^([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9._-]+)+$', 'a@b.c' * 5 + '!'),
        ('url_like', '^(https?://[^/]+/)+$', 'http://a.com/' * 10 + '!'),
        ('safe_pattern', '^[a-z]+$', 'abcdefg'),
        ('safe_number', '^\\d+$', '12345'),

        # Patterns from path-to-regexp context
        ('path_segment', '([^/]+)', '/test/path'),
        ('optional_segment', '([^/]+)?', '/test/'),
        ('wildcard', '(.*)', '/test/a/b/c'),
        ('repeated_slash', '(\\/[^/]+)+', '/' + '/a' * 50),
    ]

    for ver, base in TARGETS.items():
        for name, pattern, input_str in redos_payloads:
            try:
                start = time.time()
                r = requests.get(f'{base}/regex-test',
                                 params={'pattern': pattern, 'input': input_str},
                                 timeout=10)
                wall_time = time.time() - start
                data = r.json() if r.status_code == 200 else {}
                server_time = data.get('elapsedMs', 0)

                finding = None
                anomaly = None

                if server_time > 1000 or wall_time > 2:
                    finding = {
                        'title': f'ReDoS: Pattern "{pattern[:50]}" Blocked Event Loop ({server_time}ms)',
                        'severity': 'HIGH' if server_time > 5000 else 'MEDIUM',
                        'cwe': 'CWE-1333',
                        'description': f'Regex pattern caused {server_time}ms server-side execution. '
                                       f'Node.js single-threaded event loop was blocked.',
                        'framework_behavior': True,
                        'note': 'Node.js/V8 regex engine is single-threaded — catastrophic backtracking blocks all requests'
                    }
                elif server_time > 100:
                    anomaly = {'test': name, 'desc': f'Elevated regex time: {server_time}ms'}

                log_test(f'redos_{name}', ver, {
                    'pattern': pattern, 'input_length': len(input_str),
                    'server_time_ms': server_time, 'wall_time_s': round(wall_time, 3),
                    'status': r.status_code
                }, finding, anomaly)
            except requests.exceptions.Timeout:
                log_test(f'redos_{name}', ver, {
                    'pattern': pattern, 'timeout': True
                }, finding={
                    'title': f'ReDoS: Pattern "{pattern[:50]}" Caused Request Timeout',
                    'severity': 'HIGH', 'cwe': 'CWE-1333',
                    'description': f'Regex pattern caused >10s timeout — complete event loop block.',
                    'framework_behavior': True
                })
            except Exception as e:
                log_test(f'redos_{name}', ver, {'error': str(e)})


def test_route_regex_blocking():
    """Test if ReDoS in regex-test blocks other routes (event loop blocking)"""
    print("\n[*] Testing event loop blocking via ReDoS...")

    for ver, base in TARGETS.items():
        # First, send a slow regex request
        pattern = '(a+)+$'
        input_str = 'a' * 28 + '!'

        try:
            # Send blocking request in background
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                # Submit slow request
                slow_future = executor.submit(
                    requests.get, f'{base}/regex-test',
                    {'params': {'pattern': pattern, 'input': input_str}},
                )

                time.sleep(0.5)  # Wait a bit

                # Try to hit health endpoint while slow request is processing
                start = time.time()
                try:
                    r = requests.get(f'{base}/health', timeout=5)
                    health_time = time.time() - start
                    finding = None
                    if health_time > 1:
                        finding = {
                            'title': f'Event Loop Blocked: /health took {health_time:.1f}s During ReDoS',
                            'severity': 'HIGH',
                            'cwe': 'CWE-400',
                            'description': f'While a ReDoS payload was executing, /health took {health_time:.1f}s '
                                           f'instead of <100ms. Node.js event loop was blocked.',
                            'framework_behavior': True
                        }
                    log_test('event_loop_block', ver, {
                        'health_time_ms': round(health_time * 1000),
                        'blocked': health_time > 1
                    }, finding)
                except:
                    log_test('event_loop_block', ver, {'timeout': True}, finding={
                        'title': 'Event Loop Completely Blocked During ReDoS',
                        'severity': 'HIGH', 'cwe': 'CWE-400',
                        'description': 'Health check timed out during ReDoS attack',
                        'framework_behavior': True
                    })

        except Exception as e:
            log_test('event_loop_block', ver, {'error': str(e)})


def test_path_to_regexp_behavior():
    """Test path-to-regexp routing patterns for ReDoS — FRAMEWORK CORE"""
    print("\n[*] Testing path-to-regexp route matching performance...")

    # These test how Express routes handle various URL patterns
    route_payloads = [
        ('normal_route', '/users/1'),
        ('long_param', '/users/' + 'a' * 1000),
        ('very_long_param', '/users/' + 'a' * 10000),
        ('special_chars_in_param', '/users/' + '%' * 100),
        ('repeated_slashes', '/' + '/'.join(['a'] * 100)),
        ('unicode_in_route', '/users/' + '\u0041' * 1000),
    ]

    for ver, base in TARGETS.items():
        for name, path in route_payloads:
            try:
                start = time.time()
                r = requests.get(f'{base}{path}', timeout=10)
                elapsed = time.time() - start

                anomaly = None
                if elapsed > 1:
                    anomaly = {'test': name, 'desc': f'Route matching took {elapsed:.2f}s'}

                log_test(f'route_{name}', ver, {
                    'path_length': len(path), 'status': r.status_code,
                    'elapsed_ms': round(elapsed * 1000)
                }, anomaly=anomaly)
            except Exception as e:
                log_test(f'route_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 2.7 — ReDoS Fuzzer")
    print("Express.js Security Assessment — Regex & Event Loop Blocking")
    print("=" * 70)

    test_redos_patterns()
    test_route_regex_blocking()
    test_path_to_regexp_behavior()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings']), 'anomalies_count': anomaly_count}
    out_file = os.path.join(EVIDENCE_DIR, 'redos_fuzzer_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nReDoS fuzzer complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
