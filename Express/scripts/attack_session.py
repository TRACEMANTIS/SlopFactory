#!/usr/bin/env python3
"""
Phase 3.1 — Session & Cookie Attacks
Express.js Security Assessment — [REDACTED]

Tests express-session default behavior, cookie handling, session fixation.
SCOPE: Framework session middleware defaults.
"""

import requests
import json
import os
import time
import string
import math
from collections import Counter
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '3.1', 'name': 'Session & Cookie Attacks', 'timestamp': datetime.now().isoformat(),
                 'scope': 'express-session defaults and cookie security'},
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


def test_session_fixation():
    """Test if express-session regenerates session ID on login"""
    print("\n[*] Testing session fixation...")
    for ver, base in TARGETS.items():
        requests.get(f'{base}/seed', timeout=5)
        try:
            # Get a session before login
            s = requests.Session()
            s.get(f'{base}/health')
            pre_login_sid = s.cookies.get('connect.sid', '')

            # Login
            s.post(f'{base}/login', json={'username': 'admin', 'password': 'admin123'})
            post_login_sid = s.cookies.get('connect.sid', '')

            same_session = pre_login_sid == post_login_sid
            finding = None
            if same_session and pre_login_sid:
                finding = {
                    'title': 'Session Fixation: Session ID Not Regenerated on Login',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-384',
                    'description': 'express-session does not automatically regenerate session ID on authentication. '
                                   'Same connect.sid before and after login.',
                    'framework_behavior': True,
                    'note': 'express-session requires manual req.session.regenerate() — not automatic'
                }

            log_test('session_fixation', ver, {
                'pre_login_sid': pre_login_sid[:20] + '...' if pre_login_sid else 'none',
                'post_login_sid': post_login_sid[:20] + '...' if post_login_sid else 'none',
                'same_session': same_session
            }, finding)
        except Exception as e:
            log_test('session_fixation', ver, {'error': str(e)})


def test_session_id_entropy():
    """Analyze session ID randomness"""
    print("\n[*] Analyzing session ID entropy...")
    for ver, base in TARGETS.items():
        sids = []
        for _ in range(100):
            try:
                r = requests.get(f'{base}/health', timeout=5)
                sid = r.cookies.get('connect.sid', '')
                if sid:
                    # Extract the actual ID part (before the signature)
                    # connect.sid format: s:<id>.<signature>
                    if sid.startswith('s%3A'):
                        sid_parts = sid[4:].split('.')
                        sids.append(sid_parts[0] if sid_parts else sid)
                    else:
                        sids.append(sid)
            except:
                pass

        if sids:
            # Check for uniqueness
            unique = len(set(sids))
            avg_len = sum(len(s) for s in sids) / len(sids)

            # Character distribution
            all_chars = ''.join(sids)
            char_freq = Counter(all_chars)
            charset_size = len(char_freq)

            # Simple entropy estimate
            total = len(all_chars)
            entropy = -sum((c/total) * math.log2(c/total) for c in char_freq.values())

            finding = None
            if unique < len(sids) * 0.9:
                finding = {
                    'title': 'Session ID Collision Detected',
                    'severity': 'HIGH', 'cwe': 'CWE-330',
                    'description': f'Only {unique}/{len(sids)} unique session IDs in sample',
                    'framework_behavior': True
                }

            log_test('session_entropy', ver, {
                'sample_size': len(sids),
                'unique_ids': unique,
                'avg_length': round(avg_len, 1),
                'charset_size': charset_size,
                'bits_per_char': round(entropy, 2),
                'estimated_entropy_bits': round(entropy * avg_len, 1)
            }, finding)
        else:
            log_test('session_entropy', ver, {'error': 'No SIDs collected'})


def test_session_cookie_flags():
    """Audit session cookie security flags"""
    print("\n[*] Auditing session cookie flags...")
    for ver, base in TARGETS.items():
        try:
            r = requests.get(f'{base}/health', timeout=5)
            set_cookie = r.headers.get('Set-Cookie', '')

            flags = {
                'httponly': 'httponly' in set_cookie.lower(),
                'secure': 'secure' in set_cookie.lower(),
                'samesite': 'samesite' in set_cookie.lower(),
                'path': 'path=' in set_cookie.lower(),
                'max_age': 'max-age=' in set_cookie.lower() or 'expires=' in set_cookie.lower(),
            }

            issues = []
            if not flags['httponly']:
                issues.append('Missing HttpOnly flag (XSS can steal session)')
            if not flags['secure']:
                issues.append('Missing Secure flag (sent over HTTP)')
            if not flags['samesite']:
                issues.append('Missing SameSite flag (CSRF vulnerable)')

            finding = None
            if issues:
                finding = {
                    'title': 'express-session Default Cookie Missing Security Flags',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-614',
                    'description': f'Issues: {"; ".join(issues)}',
                    'framework_behavior': True,
                    'note': 'express-session defaults: httpOnly=undefined, secure=false, sameSite=undefined'
                }

            log_test('cookie_flags', ver, {
                'set_cookie_header': set_cookie[:300],
                'flags': flags,
                'issues': issues
            }, finding)
        except Exception as e:
            log_test('cookie_flags', ver, {'error': str(e)})


def test_session_memory_store():
    """Test MemoryStore behavior under load"""
    print("\n[*] Testing MemoryStore under load...")
    for ver, base in TARGETS.items():
        try:
            # Get initial memory
            r = requests.get(f'{base}/health', timeout=5)
            initial_mem = r.json().get('memoryUsage', {}).get('heapUsed', 0)

            # Create many sessions
            for i in range(500):
                requests.get(f'{base}/health', timeout=5)

            # Check memory after
            r = requests.get(f'{base}/health', timeout=5)
            final_mem = r.json().get('memoryUsage', {}).get('heapUsed', 0)
            mem_growth = final_mem - initial_mem

            finding = None
            if mem_growth > 5 * 1024 * 1024:  # >5MB growth
                finding = {
                    'title': f'MemoryStore Memory Growth: {mem_growth//1024}KB from 500 Sessions',
                    'severity': 'LOW',
                    'cwe': 'CWE-400',
                    'description': f'express-session MemoryStore grew {mem_growth//1024}KB with 500 sessions. '
                                   f'Not suitable for production — will leak memory.',
                    'framework_behavior': True,
                    'note': 'MemoryStore emits a warning that it is not for production'
                }

            log_test('memorystore_growth', ver, {
                'initial_heap_mb': round(initial_mem / 1024 / 1024, 1),
                'final_heap_mb': round(final_mem / 1024 / 1024, 1),
                'growth_kb': mem_growth // 1024,
                'sessions_created': 500
            }, finding)
        except Exception as e:
            log_test('memorystore_growth', ver, {'error': str(e)})


def test_cookie_signature_tampering():
    """Test connect.sid cookie signature handling"""
    print("\n[*] Testing cookie signature verification...")
    for ver, base in TARGETS.items():
        try:
            # Get valid session with auth
            s = requests.Session()
            requests.get(f'{base}/seed', timeout=5)
            s.post(f'{base}/login', json={'username': 'admin', 'password': 'admin123'})

            valid_sid = s.cookies.get('connect.sid', '')
            if not valid_sid:
                log_test('cookie_tamper', ver, {'error': 'No cookie obtained'})
                continue

            # Tamper with signature
            tampered_tests = [
                ('remove_sig', valid_sid.split('.')[0] if '.' in valid_sid else valid_sid),
                ('bad_sig', valid_sid.rsplit('.', 1)[0] + '.AAA' if '.' in valid_sid else valid_sid + '.AAA'),
                ('empty_sig', valid_sid.rsplit('.', 1)[0] + '.' if '.' in valid_sid else valid_sid),
                ('random_sid', 's%3Arandom123456.invalidsig'),
            ]

            for tamper_name, tampered_cookie in tampered_tests:
                try:
                    r = requests.get(f'{base}/admin/dashboard',
                                     cookies={'connect.sid': tampered_cookie}, timeout=5)
                    finding = None
                    if r.status_code == 200:
                        finding = {
                            'title': f'Tampered Session Cookie Accepted ({tamper_name})',
                            'severity': 'CRITICAL', 'cwe': 'CWE-565',
                            'description': f'express-session accepted a tampered cookie: {tamper_name}',
                            'framework_behavior': True
                        }
                    log_test(f'cookie_{tamper_name}', ver, {
                        'status': r.status_code,
                        'authenticated': r.status_code == 200
                    }, finding)
                except Exception as e:
                    log_test(f'cookie_{tamper_name}', ver, {'error': str(e)})
        except Exception as e:
            log_test('cookie_tamper', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 3.1 — Session & Cookie Attacks")
    print("=" * 70)

    test_session_fixation()
    test_session_id_entropy()
    test_session_cookie_flags()
    test_session_memory_store()
    test_cookie_signature_tampering()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'session_attack_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nSession attacks complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
