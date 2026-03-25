#!/usr/bin/env python3
"""
Phase 3.3 — HTTP Parameter Pollution
Express.js Security Assessment — [REDACTED]

Tests how Express/qs handles duplicate params, arrays, and type confusion.
SCOPE: Framework query/body parsing behavior.
"""

import requests
import json
import os
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '3.3', 'name': 'HTTP Parameter Pollution', 'timestamp': datetime.now().isoformat(),
                 'scope': 'Express/qs parameter handling'},
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


def test_duplicate_params():
    """Test how qs handles duplicate query parameters — FRAMEWORK BEHAVIOR"""
    print("\n[*] Testing duplicate parameter handling...")

    dup_tests = [
        ('dup_simple', 'role=user&role=admin'),
        ('dup_triple', 'role=user&role=admin&role=superadmin'),
        ('array_notation', 'role[]=user&role[]=admin'),
        ('mixed_dup_array', 'role=user&role[]=admin'),
        ('dup_with_index', 'role[0]=user&role[1]=admin'),
        ('dup_different_encoding', 'role=user&%72ole=admin'),
        ('dup_case', 'Role=user&role=admin'),
    ]

    for ver, base in TARGETS.items():
        for name, qs in dup_tests:
            try:
                r = requests.get(f'{base}/method-test?{qs}', timeout=5)
                data = r.json() if r.status_code == 200 else {}
                parsed = data.get('query', {})

                finding = None
                # Check if qs converted to array (HPP surface)
                role_val = parsed.get('role') or parsed.get('Role')
                if isinstance(role_val, list):
                    finding = {
                        'title': f'qs Converts Duplicate Params to Array ({name})',
                        'severity': 'LOW',
                        'cwe': 'CWE-235',
                        'description': f'qs converts duplicate params to array: {json.dumps(role_val)}. '
                                       f'Apps expecting string will get array — type confusion risk.',
                        'framework_behavior': True
                    }

                log_test(f'hpp_{name}', ver, {
                    'query': qs, 'parsed': str(parsed)[:200],
                    'role_type': type(role_val).__name__ if role_val else 'undefined',
                    'role_value': str(role_val)[:100] if role_val else None
                }, finding)
            except Exception as e:
                log_test(f'hpp_{name}', ver, {'error': str(e)})


def test_param_precedence():
    """Test query vs body parameter precedence"""
    print("\n[*] Testing parameter precedence (query vs body)...")
    for ver, base in TARGETS.items():
        try:
            r = requests.post(f'{base}/method-test?role=user',
                              json={'role': 'admin'}, timeout=5)
            data = r.json() if r.status_code == 200 else {}

            query_role = data.get('query', {}).get('role')
            body_role = data.get('body', {}).get('role')

            log_test('precedence_query_vs_body', ver, {
                'query_role': query_role,
                'body_role': body_role,
                'note': 'Express provides both separately via req.query and req.body'
            })
        except Exception as e:
            log_test('precedence_query_vs_body', ver, {'error': str(e)})


def test_type_confusion():
    """Test type confusion via qs — FRAMEWORK BEHAVIOR"""
    print("\n[*] Testing type confusion via qs...")

    type_tests = [
        ('string_to_array', 'id[]=1'),
        ('string_to_object', 'id[key]=value'),
        ('nested_deep', 'a[b][c][d][e][f][g]=deep'),
        ('number_key', 'a[0]=zero&a[1]=one'),
        ('boolean_like', 'active=true&active=false'),
        ('null_like', 'value=null'),
        ('empty_object', 'obj[]='),
        ('mixed_types', 'data=string&data[key]=object'),
    ]

    for ver, base in TARGETS.items():
        for name, qs in type_tests:
            try:
                r = requests.get(f'{base}/method-test?{qs}', timeout=5)
                data = r.json() if r.status_code == 200 else {}
                parsed = data.get('query', {})

                finding = None
                # Check for unexpected type conversion
                for k, v in parsed.items():
                    if isinstance(v, (dict, list)) and 'string' in name:
                        finding = {
                            'title': f'qs Type Coercion: String → {type(v).__name__} ({name})',
                            'severity': 'LOW',
                            'cwe': 'CWE-843',
                            'description': f'qs converted query param to {type(v).__name__}: {json.dumps(v)[:100]}',
                            'framework_behavior': True
                        }
                        break

                log_test(f'type_{name}', ver, {
                    'query': qs, 'parsed': str(parsed)[:300],
                    'types': {k: type(v).__name__ for k, v in parsed.items()}
                }, finding)
            except Exception as e:
                log_test(f'type_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 3.3 — HTTP Parameter Pollution")
    print("=" * 70)

    test_duplicate_params()
    test_param_precedence()
    test_type_confusion()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'hpp_attack_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nHPP attacks complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
