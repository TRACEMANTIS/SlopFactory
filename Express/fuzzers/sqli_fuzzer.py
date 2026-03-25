#!/usr/bin/env python3
"""
Phase 2.3 — SQL Injection Fuzzer
Express.js Security Assessment — [REDACTED]

Tests how Express/body-parser/qs handle SQL injection payloads.
SCOPE: Framework input handling behavior — how query params and body data are passed to app code.
"""

import requests
import json
import os
import urllib.parse
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '2.3', 'name': 'SQL Injection Fuzzer', 'timestamp': datetime.now().isoformat(),
                 'scope': 'Framework input handling — SQL payloads via qs/body-parser'},
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
        print(f"  [{test_count:3d}] ⚠ FINDING {name} ({ver})")
    elif anomaly:
        anomaly_count += 1
        results['anomalies'].append({'id': anomaly_count, **anomaly, 'version': ver})
        print(f"  [{test_count:3d}] ? ANOMALY {name} ({ver})")
    else:
        print(f"  [{test_count:3d}] ✓ {name} ({ver})")

SQLI_PAYLOADS = [
    ("basic_quote", "' OR '1'='1"),
    ("double_quote", '" OR "1"="1'),
    ("comment", "' OR 1=1--"),
    ("union_basic", "' UNION SELECT 1,2,3,4--"),
    ("union_sqlite_master", "' UNION SELECT 1,name,sql,4 FROM sqlite_master--"),
    ("stacked_query", "'; DROP TABLE products;--"),
    ("blind_boolean", "' AND 1=1--"),
    ("blind_boolean_false", "' AND 1=2--"),
    ("time_blind", "' AND (SELECT 1 FROM (SELECT SLEEP(2)) AS t)--"),
    ("sqlite_version", "' UNION SELECT 1,sqlite_version(),3,4--"),
    ("hex_encode", "' OR 0x31=0x31--"),
    ("char_encode", "' OR CHAR(49)=CHAR(49)--"),
    ("null_byte", "test%00' OR '1'='1"),
    ("backslash_escape", "test\\' OR \\'1\\'=\\'1"),
    ("wide_char", "test%bf%27 OR 1=1--"),
    ("nested_select", "' AND (SELECT COUNT(*) FROM users)>0--"),
    ("like_wildcard", "%"),
    ("like_underscore", "_"),
    ("integer_overflow", "99999999999999999999"),
    ("negative_zero", "-0"),
    ("scientific_notation", "1e309"),
    ("empty_string", ""),
    ("null_literal", "NULL"),
    ("semicolon", ";"),
    ("batch_insert", "'); INSERT INTO users VALUES(999,'evil','evil','admin');--"),
]

def test_sqli():
    print("\n[*] Fuzzing SQL injection payloads...")
    for ver, base in TARGETS.items():
        requests.get(f'{base}/seed', timeout=5)

        for name, payload in SQLI_PAYLOADS:
            # Test safe endpoint (parameterized)
            try:
                r_safe = requests.get(f'{base}/search', params={'q': payload}, timeout=5)
                safe_data = r_safe.json() if r_safe.status_code == 200 else {}
            except: safe_data = {}

            # Test vulnerable endpoint (string concat)
            try:
                r_vuln = requests.get(f'{base}/search-raw', params={'q': payload}, timeout=5)
                vuln_data = r_vuln.json() if r_vuln.status_code == 200 else {}
            except: vuln_data = {}

            finding = None
            anomaly = None

            # Check if qs/Express altered the payload in transit (framework behavior)
            safe_query = safe_data.get('query', '')
            vuln_query = vuln_data.get('query', '')

            if safe_query != payload and safe_query:
                anomaly = {'test': name, 'desc': f'qs modified payload: sent={payload[:50]}, received={safe_query[:50]}'}

            # Check for SQLi indicators in vuln endpoint results
            vuln_error = vuln_data.get('sql_error', False)
            vuln_results = vuln_data.get('results', [])

            # Union-based extraction
            if 'sqlite_master' in name and len(vuln_results) > 10:
                finding = {
                    'title': f'SQLi Union Extraction Successful ({name})',
                    'severity': 'INFO',
                    'cwe': 'CWE-89',
                    'description': 'Note: This is app-level (string concat), not framework. '
                                   'body-parser/qs passed payload unmodified.',
                    'framework_behavior': False,
                    'note': 'Harness vuln — confirms framework does not sanitize SQL in transit'
                }

            log_test(f'sqli_{name}', ver, {
                'payload': payload[:100],
                'safe_status': r_safe.status_code if 'r_safe' in dir() else 'err',
                'vuln_status': r_vuln.status_code if 'r_vuln' in dir() else 'err',
                'safe_count': safe_data.get('count', 0),
                'vuln_count': vuln_data.get('count', 0),
                'vuln_error': vuln_error,
                'payload_preserved': safe_query == payload
            }, finding, anomaly)


def test_type_juggling():
    """Test how qs handles type juggling for SQL params"""
    print("\n[*] Testing type juggling via qs...")

    type_payloads = [
        ('array_param', 'q[]=admin&q[]=user'),
        ('object_param', 'q[key]=value'),
        ('nested_array', 'q[0][0]=test'),
        ('boolean_string', 'q=true'),
        ('number_string', 'q=42'),
    ]

    for ver, base in TARGETS.items():
        for name, qs in type_payloads:
            try:
                r = requests.get(f'{base}/search-raw?{qs}', timeout=5)
                log_test(f'type_{name}', ver, {
                    'query_string': qs,
                    'status': r.status_code,
                    'error': r.json().get('error', '') if r.status_code >= 400 else None,
                    'response': r.text[:200]
                })
            except Exception as e:
                log_test(f'type_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 2.3 — SQL Injection Fuzzer")
    print("=" * 70)

    test_sqli()
    test_type_juggling()

    results['summary'] = {
        'total_tests': test_count, 'findings_count': len(results['findings']),
        'anomalies_count': anomaly_count
    }

    out_file = os.path.join(EVIDENCE_DIR, 'sqli_fuzzer_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nSQLi fuzzer complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
