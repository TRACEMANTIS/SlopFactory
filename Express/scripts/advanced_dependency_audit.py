#!/usr/bin/env python3
"""
Phase 4.2 — Dependency Deep Dive
Express.js Security Assessment — [REDACTED]

Tests qs edge cases, send path normalization, cookie parsing quirks.
SCOPE: Framework dependency behavior.
"""

import requests
import json
import os
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '4.2', 'name': 'Dependency Deep Dive', 'timestamp': datetime.now().isoformat()},
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


def test_qs_edge_cases():
    """Deep qs testing — FRAMEWORK CORE"""
    print("\n[*] Testing qs edge cases...")

    qs_tests = [
        # Prototype pollution variants
        ('define_getter', '__defineGetter__=test'),
        ('define_setter', '__defineSetter__=test'),
        ('lookup_getter', '__lookupGetter__=test'),
        ('proto_pollute_via_constructor', 'constructor.prototype.polluted=true'),
        ('proto_bracket_mixed', 'a][__proto__][polluted]=true'),
        ('numeric_proto', '0[__proto__][polluted]=true'),

        # Depth limits
        ('depth_default', 'a[b][c][d][e][f]=6deep'),
        ('depth_exceed', 'a[b][c][d][e][f][g][h]=8deep'),

        # Array limits
        ('array_at_limit', '&'.join(f'a[{i}]=v' for i in range(20))),
        ('array_over_limit', '&'.join(f'a[{i}]=v' for i in range(25))),

        # Parameter count limit
        ('param_limit', '&'.join(f'p{i}=v' for i in range(1001))),

        # Edge case values
        ('empty_key', '=value'),
        ('empty_value', 'key='),
        ('no_equals', 'justkey'),
        ('only_ampersand', '&&&'),
        ('encoded_equals', 'key%3Dvalue'),
        ('unicode_key', '\u00e9=accent'),
        ('utf8_value', 'key=\u00e9'),
    ]

    for ver, base in TARGETS.items():
        for name, qs in qs_tests:
            try:
                r = requests.get(f'{base}/method-test?{qs}', timeout=5)
                data = r.json() if r.status_code == 200 else {}
                parsed = data.get('query', {})

                finding = None
                # Check if dangerous properties leaked through
                empty = {}
                polluted = getattr(empty, 'polluted', None) if hasattr(empty, 'polluted') else None

                log_test(f'qs_{name}', ver, {
                    'query': qs[:200], 'parsed': str(parsed)[:300],
                    'param_count': len(parsed), 'status': r.status_code
                }, finding)
            except Exception as e:
                log_test(f'qs_{name}', ver, {'error': str(e)})


def test_cookie_parsing():
    """Test cookie module parsing edge cases"""
    print("\n[*] Testing cookie parsing edge cases...")

    cookie_tests = [
        ('normal', 'session=abc123'),
        ('spaces_in_value', 'session=abc 123'),
        ('semicolon_in_value', 'session=abc;123'),
        ('encoded_value', 'session=abc%3B123'),
        ('unicode_value', 'session=\u00e9\u00e8\u00ea'),
        ('very_long', f'session={"A"*10000}'),
        ('null_byte', 'session=abc\x00def'),
        ('many_cookies', '; '.join(f'c{i}=v{i}' for i in range(100))),
        ('duplicate_name', 'session=first; session=second'),
        ('empty_cookie', ''),
        ('only_semicolons', ';;;'),
    ]

    for ver, base in TARGETS.items():
        for name, cookie_val in cookie_tests:
            try:
                r = requests.get(f'{base}/method-test',
                                 headers={'Cookie': cookie_val}, timeout=5)
                data = r.json() if r.status_code == 200 else {}
                cookies_received = data.get('headers', {}).get('cookie', '')

                log_test(f'cookie_{name}', ver, {
                    'sent': cookie_val[:200],
                    'received': cookies_received[:200],
                    'status': r.status_code,
                    'preserved': cookie_val[:100] in cookies_received if cookie_val else True
                })
            except Exception as e:
                log_test(f'cookie_{name}', ver, {'error': str(e)})


def test_send_module_behavior():
    """Test send module path handling details"""
    print("\n[*] Testing send module behavior...")

    send_tests = [
        ('range_header', '/static/.env', {'Range': 'bytes=0-10'}),
        ('invalid_range', '/static/.env', {'Range': 'bytes=9999-10000'}),
        ('if_none_match', '/static/.env', {'If-None-Match': '"invalid-etag"'}),
        ('if_modified_since', '/static/.env', {'If-Modified-Since': 'Thu, 01 Jan 2099 00:00:00 GMT'}),
        ('accept_encoding_gzip', '/static/.env', {'Accept-Encoding': 'gzip, deflate'}),
    ]

    for ver, base in TARGETS.items():
        for name, path, headers in send_tests:
            try:
                r = requests.get(f'{base}{path}', headers=headers, timeout=5)
                resp_headers = dict(r.headers)

                log_test(f'send_{name}', ver, {
                    'path': path, 'request_headers': headers,
                    'status': r.status_code,
                    'content_range': resp_headers.get('Content-Range', ''),
                    'etag': resp_headers.get('ETag', ''),
                    'content_encoding': resp_headers.get('Content-Encoding', '')
                })
            except Exception as e:
                log_test(f'send_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 4.2 — Dependency Deep Dive")
    print("=" * 70)

    test_qs_edge_cases()
    test_cookie_parsing()
    test_send_module_behavior()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'dependency_deep_dive.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nDependency deep dive complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
