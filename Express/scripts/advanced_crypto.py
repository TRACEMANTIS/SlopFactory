#!/usr/bin/env python3
"""
Phase 4.3 — Cryptographic Verification
Express.js Security Assessment — [REDACTED]

Tests session ID randomness, cookie signature timing, JWT behavior.
SCOPE: Framework crypto implementation quality.
"""

import requests
import json
import os
import time
import math
import statistics
from collections import Counter
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '4.3', 'name': 'Cryptographic Verification', 'timestamp': datetime.now().isoformat()},
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


def test_session_id_randomness():
    """Statistical tests on 500 session IDs"""
    print("\n[*] Collecting 500 session IDs for randomness analysis...")

    for ver, base in TARGETS.items():
        sids = []
        for _ in range(500):
            try:
                r = requests.get(f'{base}/health', timeout=5)
                sid = r.cookies.get('connect.sid', '')
                if sid and '%3A' in sid:
                    # Extract ID portion: s%3A<id>.<sig>
                    parts = sid.split('%3A', 1)
                    if len(parts) > 1:
                        id_part = parts[1].split('.')[0]
                        sids.append(id_part)
            except:
                pass

        if len(sids) < 100:
            log_test('session_randomness', ver, {'error': f'Only collected {len(sids)} SIDs'})
            continue

        # Uniqueness test
        unique = len(set(sids))
        unique_ratio = unique / len(sids)

        # Length distribution
        lengths = [len(s) for s in sids]
        avg_len = statistics.mean(lengths)
        len_stddev = statistics.stdev(lengths) if len(lengths) > 1 else 0

        # Character frequency analysis
        all_chars = ''.join(sids)
        char_freq = Counter(all_chars)
        total_chars = len(all_chars)
        charset_size = len(char_freq)

        # Shannon entropy
        entropy = -sum((count/total_chars) * math.log2(count/total_chars)
                       for count in char_freq.values())
        total_entropy = entropy * avg_len

        # Chi-square test (simplified)
        expected = total_chars / charset_size
        chi_sq = sum((count - expected) ** 2 / expected for count in char_freq.values())

        finding = None
        if total_entropy < 64:
            finding = {
                'title': f'Session ID Low Entropy: {total_entropy:.0f} bits (< 64 recommended)',
                'severity': 'MEDIUM', 'cwe': 'CWE-330',
                'description': f'Session IDs have ~{total_entropy:.0f} bits of entropy. OWASP recommends ≥64 bits.',
                'framework_behavior': True
            }
        elif unique_ratio < 0.99:
            finding = {
                'title': f'Session ID Collisions: {unique}/{len(sids)} unique',
                'severity': 'HIGH', 'cwe': 'CWE-330',
                'description': f'Only {unique_ratio:.2%} unique session IDs in sample of {len(sids)}',
                'framework_behavior': True
            }

        log_test('session_randomness', ver, {
            'sample_size': len(sids),
            'unique': unique,
            'unique_ratio': round(unique_ratio, 4),
            'avg_length': round(avg_len, 1),
            'length_stddev': round(len_stddev, 2),
            'charset_size': charset_size,
            'entropy_per_char': round(entropy, 3),
            'total_entropy_bits': round(total_entropy, 1),
            'chi_square': round(chi_sq, 2),
            'sample_ids': sids[:5]
        }, finding)


def test_cookie_signature_timing():
    """Test for timing oracle in cookie signature verification"""
    print("\n[*] Testing cookie signature timing oracle...")

    for ver, base in TARGETS.items():
        try:
            # Get valid session
            s = requests.Session()
            requests.get(f'{base}/seed', timeout=5)
            s.post(f'{base}/login', json={'username': 'admin', 'password': 'admin123'})
            valid_cookie = s.cookies.get('connect.sid', '')

            if not valid_cookie:
                log_test('sig_timing', ver, {'error': 'No cookie obtained'})
                continue

            # Test with different cookie values and measure timing
            test_cookies = [
                ('valid', valid_cookie),
                ('invalid_sig', valid_cookie[:-5] + 'AAAAA'),
                ('wrong_sig', valid_cookie[:-10] + 'BBBBBBBBBB'),
                ('no_sig', valid_cookie.split('.')[0] if '.' in valid_cookie else valid_cookie),
                ('random', 's%3Arandomvalue123456.invalidsignature'),
            ]

            timings = {}
            for name, cookie in test_cookies:
                times = []
                for _ in range(50):
                    start = time.time()
                    try:
                        r = requests.get(f'{base}/admin/dashboard',
                                         cookies={'connect.sid': cookie}, timeout=5)
                        elapsed = (time.time() - start) * 1000  # ms
                        times.append(elapsed)
                    except:
                        pass

                if times:
                    avg = statistics.mean(times)
                    std = statistics.stdev(times) if len(times) > 1 else 0
                    timings[name] = {'avg_ms': round(avg, 2), 'std_ms': round(std, 2), 'samples': len(times)}

            # Check for timing differences
            if 'valid' in timings and 'invalid_sig' in timings:
                diff = abs(timings['valid']['avg_ms'] - timings['invalid_sig']['avg_ms'])
                finding = None
                if diff > 5:  # >5ms difference
                    finding = {
                        'title': f'Cookie Signature Timing Oracle: {diff:.1f}ms Difference',
                        'severity': 'LOW', 'cwe': 'CWE-208',
                        'description': f'Valid vs invalid cookie signature timing differs by {diff:.1f}ms. '
                                       f'Valid: {timings["valid"]["avg_ms"]}ms, Invalid: {timings["invalid_sig"]["avg_ms"]}ms',
                        'framework_behavior': True
                    }

                log_test('sig_timing', ver, {
                    'timings': timings,
                    'valid_vs_invalid_diff_ms': round(diff, 2)
                }, finding)
        except Exception as e:
            log_test('sig_timing', ver, {'error': str(e)})


def test_jwt_timing():
    """Test JWT verification timing"""
    print("\n[*] Testing JWT verification timing...")

    for ver, base in TARGETS.items():
        import jwt as pyjwt

        requests.get(f'{base}/seed', timeout=5)
        r = requests.post(f'{base}/auth/token',
                          json={'username': 'admin', 'password': 'admin123'}, timeout=5)
        valid_token = r.json().get('token', '') if r.status_code == 200 else ''

        if not valid_token:
            log_test('jwt_timing', ver, {'error': 'No token obtained'})
            continue

        test_tokens = [
            ('valid', valid_token),
            ('invalid_sig', valid_token[:-5] + 'AAAAA'),
            ('expired', pyjwt.encode({'exp': 0}, 'secret123', algorithm='HS256')),
            ('wrong_key', pyjwt.encode({'test': 1}, 'wrongkey', algorithm='HS256')),
        ]

        timings = {}
        for name, token in test_tokens:
            times = []
            for _ in range(50):
                start = time.time()
                try:
                    requests.get(f'{base}/auth/protected',
                                 headers={'Authorization': f'Bearer {token}'}, timeout=5)
                    times.append((time.time() - start) * 1000)
                except:
                    pass

            if times:
                timings[name] = {
                    'avg_ms': round(statistics.mean(times), 2),
                    'std_ms': round(statistics.stdev(times), 2) if len(times) > 1 else 0
                }

        log_test('jwt_timing', ver, {'timings': timings})


def main():
    print("=" * 70)
    print("Phase 4.3 — Cryptographic Verification")
    print("=" * 70)

    test_session_id_randomness()
    test_cookie_signature_timing()
    test_jwt_timing()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'crypto_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nCrypto verification complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
