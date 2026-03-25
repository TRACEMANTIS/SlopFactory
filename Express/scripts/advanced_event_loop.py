#!/usr/bin/env python3
"""
Phase 4.1 — Event Loop & Performance Analysis
Express.js Security Assessment — [REDACTED]

Tests Node.js single-threaded DoS, memory leaks, JSON parse bombs.
SCOPE: Framework/runtime behavior under malicious load.
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
    'metadata': {'phase': '4.1', 'name': 'Event Loop Analysis', 'timestamp': datetime.now().isoformat(),
                 'scope': 'Node.js event loop blocking and resource exhaustion'},
    'tests': [], 'findings': [], 'anomalies': [], 'summary': {}
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


def test_cpu_bound_blocking():
    """Test CPU-bound operation blocking the event loop"""
    print("\n[*] Testing CPU-bound event loop blocking...")

    for ver, base in TARGETS.items():
        # Measure baseline response time
        baseline_times = []
        for _ in range(5):
            start = time.time()
            requests.get(f'{base}/health', timeout=5)
            baseline_times.append(time.time() - start)
        baseline_avg = sum(baseline_times) / len(baseline_times)

        # Send CPU-intensive request while measuring concurrent response time
        iterations_tests = [1000, 10000, 100000, 500000]
        for iters in iterations_tests:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                # Submit slow-hash
                slow_future = executor.submit(
                    requests.get, f'{base}/slow-hash',
                    params={'input': 'test', 'iterations': str(iters)},
                    timeout=30
                )

                time.sleep(0.1)  # Brief delay to ensure slow request is processing

                # Measure health endpoint concurrently
                start = time.time()
                try:
                    r = requests.get(f'{base}/health', timeout=15)
                    health_time = time.time() - start
                except:
                    health_time = 15.0

                try:
                    slow_result = slow_future.result(timeout=30)
                    slow_time = slow_result.json().get('elapsedMs', 0) if slow_result.status_code == 200 else -1
                except:
                    slow_time = -1

                finding = None
                if health_time > baseline_avg * 10 and health_time > 1:
                    finding = {
                        'title': f'Event Loop Blocked: {iters} iterations blocked /health for {health_time:.1f}s',
                        'severity': 'HIGH' if health_time > 5 else 'MEDIUM',
                        'cwe': 'CWE-400',
                        'description': f'CPU-bound operation ({iters} hash iterations, {slow_time}ms) '
                                       f'blocked all concurrent requests for {health_time:.1f}s. '
                                       f'Baseline: {baseline_avg*1000:.0f}ms.',
                        'framework_behavior': True,
                        'note': 'Node.js single-threaded architecture — any CPU work blocks the event loop'
                    }

                log_test(f'cpu_block_{iters}', ver, {
                    'iterations': iters,
                    'slow_hash_ms': slow_time,
                    'health_time_ms': round(health_time * 1000),
                    'baseline_avg_ms': round(baseline_avg * 1000, 1),
                    'blocking_factor': round(health_time / baseline_avg, 1) if baseline_avg > 0 else 0
                }, finding)


def test_json_parse_bomb():
    """Test deeply nested JSON causing parser issues"""
    print("\n[*] Testing JSON parse bomb...")

    for ver, base in TARGETS.items():
        depth_tests = [10, 50, 100, 500, 1000]
        for depth in depth_tests:
            # Build nested JSON
            nested = 'null'
            for _ in range(depth):
                nested = f'{{"a":{nested}}}'

            try:
                start = time.time()
                r = requests.post(f'{base}/method-test', data=nested,
                                  headers={'Content-Type': 'application/json'}, timeout=10)
                elapsed = time.time() - start

                finding = None
                if elapsed > 2:
                    finding = {
                        'title': f'JSON Parse Bomb: Depth {depth} Took {elapsed:.1f}s',
                        'severity': 'MEDIUM', 'cwe': 'CWE-400',
                        'description': f'Deeply nested JSON ({depth} levels) caused {elapsed:.1f}s parse time',
                        'framework_behavior': True
                    }

                log_test(f'json_bomb_{depth}', ver, {
                    'depth': depth, 'status': r.status_code,
                    'elapsed_ms': round(elapsed * 1000)
                }, finding)
            except Exception as e:
                log_test(f'json_bomb_{depth}', ver, {'depth': depth, 'error': str(e)})


def test_query_string_bomb():
    """Test large/deep query strings via qs"""
    print("\n[*] Testing query string resource consumption...")

    for ver, base in TARGETS.items():
        qs_tests = [
            ('many_params_100', '&'.join(f'p{i}=v{i}' for i in range(100))),
            ('many_params_500', '&'.join(f'p{i}=v{i}' for i in range(500))),
            ('many_params_1000', '&'.join(f'p{i}=v{i}' for i in range(1000))),
            ('deep_nesting_5', 'a[b][c][d][e]=deep5'),
            ('deep_nesting_10', 'a[b][c][d][e][f][g][h][i][j]=deep10'),
            ('large_array_20', '&'.join(f'a[{i}]=v{i}' for i in range(20))),
            ('large_array_100', '&'.join(f'a[{i}]=v{i}' for i in range(100))),
            ('long_value', f'key={"A"*100000}'),
        ]

        for name, qs in qs_tests:
            try:
                start = time.time()
                r = requests.get(f'{base}/method-test?{qs}', timeout=10)
                elapsed = time.time() - start

                data = r.json() if r.status_code == 200 else {}
                param_count = len(data.get('query', {}))

                finding = None
                if elapsed > 2:
                    finding = {
                        'title': f'qs Slow Parse: {name} Took {elapsed:.1f}s',
                        'severity': 'MEDIUM', 'cwe': 'CWE-400',
                        'description': f'qs query string parsing took {elapsed:.1f}s for {name}',
                        'framework_behavior': True
                    }

                log_test(f'qs_bomb_{name}', ver, {
                    'qs_length': len(qs), 'status': r.status_code,
                    'elapsed_ms': round(elapsed * 1000),
                    'parsed_params': param_count
                }, finding)
            except Exception as e:
                log_test(f'qs_bomb_{name}', ver, {'error': str(e)})


def test_memory_leak():
    """Test for memory leaks under sustained load"""
    print("\n[*] Testing memory leak detection (200 requests)...")

    for ver, base in TARGETS.items():
        try:
            r = requests.get(f'{base}/health', timeout=5)
            initial_mem = r.json().get('memoryUsage', {}).get('heapUsed', 0)

            for i in range(200):
                requests.get(f'{base}/health', timeout=5)

            r = requests.get(f'{base}/health', timeout=5)
            final_mem = r.json().get('memoryUsage', {}).get('heapUsed', 0)
            growth = final_mem - initial_mem

            finding = None
            if growth > 10 * 1024 * 1024:
                finding = {
                    'title': f'Memory Growth: {growth//1024}KB After 200 Requests',
                    'severity': 'MEDIUM', 'cwe': 'CWE-401',
                    'description': f'Heap grew {growth//1024}KB after 200 simple GET requests',
                    'framework_behavior': True
                }

            log_test('memory_leak', ver, {
                'initial_mb': round(initial_mem / 1024 / 1024, 1),
                'final_mb': round(final_mem / 1024 / 1024, 1),
                'growth_kb': growth // 1024,
                'requests': 200
            }, finding)
        except Exception as e:
            log_test('memory_leak', ver, {'error': str(e)})


def test_connection_exhaustion():
    """Test connection limits"""
    print("\n[*] Testing connection handling...")

    for ver, base in TARGETS.items():
        # Rapid connection test
        start = time.time()
        success = 0
        errors = 0
        for i in range(100):
            try:
                r = requests.get(f'{base}/health', timeout=2)
                if r.status_code == 200:
                    success += 1
                else:
                    errors += 1
            except:
                errors += 1
        elapsed = time.time() - start

        log_test('rapid_connections', ver, {
            'total': 100, 'success': success, 'errors': errors,
            'elapsed_s': round(elapsed, 1),
            'rps': round(100 / elapsed, 1)
        })


def main():
    print("=" * 70)
    print("Phase 4.1 — Event Loop & Performance Analysis")
    print("=" * 70)

    test_cpu_bound_blocking()
    test_json_parse_bomb()
    test_query_string_bomb()
    test_memory_leak()
    test_connection_exhaustion()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'event_loop_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nEvent loop analysis complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
