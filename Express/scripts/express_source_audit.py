#!/usr/bin/env python3
"""
Phase 1.3 — Express Source Code Audit
Express.js Security Assessment — [REDACTED]

Static analysis of Express core + key dependencies.
SCOPE: Framework source only — identifying security-relevant patterns.
"""

import os
import re
import json
from datetime import datetime
from collections import defaultdict

SOURCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/source'
V5_APP_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/testapp-v5/node_modules'
V4_APP_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/testapp-v4/node_modules'
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {
        'phase': '1.3',
        'name': 'Source Code Audit',
        'timestamp': datetime.now().isoformat(),
        'scope': 'Express core + key dependency source'
    },
    'files_scanned': 0,
    'patterns_found': [],
    'findings': [],
    'regex_extraction': [],
    'prototype_pollution_analysis': [],
    'error_handling_analysis': [],
    'trust_proxy_analysis': [],
    'summary': {}
}

test_count = 0

# Patterns to search for in source
SECURITY_PATTERNS = {
    'dangerous_eval': {
        'regex': r'\beval\s*\(',
        'severity': 'HIGH',
        'cwe': 'CWE-95',
        'description': 'Use of eval() — potential code injection'
    },
    'function_constructor': {
        'regex': r'\bnew\s+Function\s*\(',
        'severity': 'HIGH',
        'cwe': 'CWE-95',
        'description': 'new Function() — dynamic code execution'
    },
    'child_process': {
        'regex': r'child_process|\.exec\s*\(|\.execSync\s*\(|\.spawn\s*\(',
        'severity': 'HIGH',
        'cwe': 'CWE-78',
        'description': 'child_process usage — potential command injection'
    },
    'dynamic_require': {
        'regex': r'require\s*\(\s*[^\'"][^)]*\)',
        'severity': 'MEDIUM',
        'cwe': 'CWE-829',
        'description': 'Dynamic require() with non-literal argument'
    },
    'object_assign': {
        'regex': r'Object\.assign\s*\(',
        'severity': 'LOW',
        'cwe': 'CWE-1321',
        'description': 'Object.assign() — shallow merge, potential prototype pollution sink'
    },
    'proto_access': {
        'regex': r'__proto__|constructor\s*\[|Object\.getPrototypeOf',
        'severity': 'MEDIUM',
        'cwe': 'CWE-1321',
        'description': '__proto__ or constructor access — prototype chain manipulation'
    },
    'for_in_no_hasown': {
        'regex': r'for\s*\(\s*(?:var|let|const)\s+\w+\s+in\s+',
        'severity': 'LOW',
        'cwe': 'CWE-1321',
        'description': 'for...in loop — may iterate prototype properties without hasOwnProperty check'
    },
    'regex_from_input': {
        'regex': r'new\s+RegExp\s*\(\s*(?![\'"\/])',
        'severity': 'MEDIUM',
        'cwe': 'CWE-1333',
        'description': 'new RegExp() from variable — potential ReDoS'
    },
    'stack_trace_exposure': {
        'regex': r'\.stack\b|err\.message|error\.message',
        'severity': 'LOW',
        'cwe': 'CWE-209',
        'description': 'Error stack/message access — potential info disclosure'
    },
    'sensitive_defaults': {
        'regex': r'x-powered-by|X-Powered-By',
        'severity': 'LOW',
        'cwe': 'CWE-200',
        'description': 'X-Powered-By header reference — version disclosure'
    },
}


def scan_file(filepath, relative_path):
    """Scan a single file for security patterns"""
    global test_count
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception:
        return

    results['files_scanned'] += 1

    for pattern_name, pattern_info in SECURITY_PATTERNS.items():
        for i, line in enumerate(lines, 1):
            if re.search(pattern_info['regex'], line):
                test_count += 1
                entry = {
                    'id': test_count,
                    'pattern': pattern_name,
                    'file': relative_path,
                    'line': i,
                    'code': line.strip()[:200],
                    'severity': pattern_info['severity'],
                    'cwe': pattern_info['cwe'],
                    'description': pattern_info['description']
                }
                results['patterns_found'].append(entry)


def extract_regexes(filepath, relative_path):
    """Extract all regex patterns for ReDoS analysis"""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
    except Exception:
        return

    # Match regex literals and new RegExp()
    regex_literal = re.findall(r'(/(?:[^/\\]|\\.)+/[gimsuy]*)', content)
    regex_constructor = re.findall(r'new\s+RegExp\s*\(\s*[\'"]([^"\']+)[\'"]', content)

    for rx in regex_literal + regex_constructor:
        # Check for potentially catastrophic patterns
        is_dangerous = bool(re.search(r'(\(.+\+\)|\(\.\*\)|\(.+\)\+|\(.+\)\*|\(.+\)\{)', rx))
        results['regex_extraction'].append({
            'file': relative_path,
            'regex': rx[:200],
            'potentially_dangerous': is_dangerous
        })


def analyze_prototype_pollution_guards():
    """Check how qs and body-parser handle prototype pollution"""
    print("\n[*] Analyzing prototype pollution guards...")
    global test_count

    # Check qs
    for version_label, base_dir in [('v4', V4_APP_DIR), ('v5', V5_APP_DIR)]:
        qs_parse = os.path.join(base_dir, 'qs', 'lib', 'parse.js')
        if os.path.exists(qs_parse):
            with open(qs_parse, 'r') as f:
                content = f.read()

            has_proto_guard = '__proto__' in content or 'prototype' in content.lower()
            has_constructor_guard = 'constructor' in content

            test_count += 1
            entry = {
                'package': 'qs',
                'version': version_label,
                'file': qs_parse,
                'has_proto_guard': has_proto_guard,
                'has_constructor_guard': has_constructor_guard,
                'guard_details': []
            }

            # Find specific guard implementations
            for i, line in enumerate(content.split('\n'), 1):
                if '__proto__' in line or ('constructor' in line and 'prototype' in line.lower()):
                    entry['guard_details'].append({'line': i, 'code': line.strip()[:200]})

            results['prototype_pollution_analysis'].append(entry)
            guard_status = 'HAS GUARDS' if has_proto_guard else 'NO GUARDS'
            print(f"  [{test_count:3d}] qs ({version_label}): {guard_status}")

    # Check body-parser / express.json
    for version_label, base_dir in [('v4', V4_APP_DIR), ('v5', V5_APP_DIR)]:
        bp_json_path = os.path.join(base_dir, 'body-parser', 'lib', 'types', 'json.js')
        if os.path.exists(bp_json_path):
            with open(bp_json_path, 'r') as f:
                content = f.read()

            has_reviver = 'reviver' in content
            has_proto_filter = '__proto__' in content

            test_count += 1
            entry = {
                'package': 'body-parser',
                'version': version_label,
                'file': bp_json_path,
                'has_reviver_option': has_reviver,
                'has_proto_filter': has_proto_filter,
            }
            results['prototype_pollution_analysis'].append(entry)
            print(f"  [{test_count:3d}] body-parser ({version_label}): reviver={has_reviver}, proto_filter={has_proto_filter}")


def analyze_error_handling():
    """Check Express error handling — finalhandler behavior"""
    print("\n[*] Analyzing error handling...")
    global test_count

    for version_label, base_dir in [('v4', V4_APP_DIR), ('v5', V5_APP_DIR)]:
        fh_path = os.path.join(base_dir, 'finalhandler', 'index.js')
        if os.path.exists(fh_path):
            with open(fh_path, 'r') as f:
                content = f.read()

            exposes_stack = 'stack' in content
            checks_env = 'env' in content or 'NODE_ENV' in content or 'production' in content

            test_count += 1
            entry = {
                'package': 'finalhandler',
                'version': version_label,
                'exposes_stack_trace': exposes_stack,
                'checks_environment': checks_env,
                'lines_with_stack': []
            }

            for i, line in enumerate(content.split('\n'), 1):
                if 'stack' in line.lower() and ('err' in line.lower() or 'error' in line.lower()):
                    entry['lines_with_stack'].append({'line': i, 'code': line.strip()[:200]})

            results['error_handling_analysis'].append(entry)
            print(f"  [{test_count:3d}] finalhandler ({version_label}): stack_exposure={exposes_stack}, env_check={checks_env}")

            if exposes_stack:
                results['findings'].append({
                    'id': len(results['findings']) + 1,
                    'title': f'finalhandler ({version_label}) exposes stack traces in non-production',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-209',
                    'description': 'finalhandler sends stack traces when NODE_ENV !== "production"',
                    'framework_behavior': True
                })


def analyze_trust_proxy():
    """Analyze Express trust proxy implementation"""
    print("\n[*] Analyzing trust proxy implementation...")
    global test_count

    for version_label, base_dir in [('v4', V4_APP_DIR), ('v5', V5_APP_DIR)]:
        req_path = os.path.join(base_dir, 'express', 'lib', 'request.js')
        if os.path.exists(req_path):
            with open(req_path, 'r') as f:
                content = f.read()

            trust_proxy_refs = []
            for i, line in enumerate(content.split('\n'), 1):
                if 'trust proxy' in line.lower() or 'trustproxy' in line.lower() or 'x-forwarded' in line.lower():
                    trust_proxy_refs.append({'line': i, 'code': line.strip()[:200]})

            test_count += 1
            results['trust_proxy_analysis'].append({
                'version': version_label,
                'references': trust_proxy_refs,
                'count': len(trust_proxy_refs)
            })
            print(f"  [{test_count:3d}] trust proxy ({version_label}): {len(trust_proxy_refs)} references")


def scan_directory(base_dir, label):
    """Recursively scan a directory"""
    print(f"\n[*] Scanning {label}...")
    packages = ['express', 'qs', 'body-parser', 'send', 'serve-static',
                'cookie', 'finalhandler', 'path-to-regexp']

    for pkg in packages:
        pkg_dir = os.path.join(base_dir, pkg)
        if not os.path.exists(pkg_dir):
            continue
        for root, dirs, files in os.walk(pkg_dir):
            # Skip test directories and node_modules
            dirs[:] = [d for d in dirs if d not in ('test', 'tests', 'node_modules', '.git')]
            for filename in files:
                if filename.endswith('.js'):
                    filepath = os.path.join(root, filename)
                    relative = os.path.relpath(filepath, base_dir)
                    scan_file(filepath, f'{label}/{relative}')
                    extract_regexes(filepath, f'{label}/{relative}')


def main():
    print("=" * 70)
    print("Phase 1.3 — Express Source Code Audit")
    print("Express.js Security Assessment — Framework Source Only")
    print("=" * 70)

    scan_directory(V4_APP_DIR, 'v4')
    scan_directory(V5_APP_DIR, 'v5')

    analyze_prototype_pollution_guards()
    analyze_error_handling()
    analyze_trust_proxy()

    # Summarize pattern findings
    pattern_summary = defaultdict(int)
    for p in results['patterns_found']:
        pattern_summary[p['pattern']] += 1

    dangerous_regexes = [r for r in results['regex_extraction'] if r['potentially_dangerous']]

    if dangerous_regexes:
        results['findings'].append({
            'id': len(results['findings']) + 1,
            'title': f'{len(dangerous_regexes)} potentially catastrophic regex patterns in framework source',
            'severity': 'MEDIUM',
            'cwe': 'CWE-1333',
            'description': 'Regex patterns with nested quantifiers found in framework source code',
            'framework_behavior': True,
            'details': dangerous_regexes[:10]  # First 10
        })

    results['summary'] = {
        'total_tests': test_count,
        'files_scanned': results['files_scanned'],
        'patterns_found_total': len(results['patterns_found']),
        'pattern_breakdown': dict(pattern_summary),
        'regexes_extracted': len(results['regex_extraction']),
        'dangerous_regexes': len(dangerous_regexes),
        'findings_count': len(results['findings']),
        'findings_by_severity': {}
    }

    for f in results['findings']:
        sev = f.get('severity', 'UNKNOWN')
        results['summary']['findings_by_severity'][sev] = \
            results['summary']['findings_by_severity'].get(sev, 0) + 1

    out_file = os.path.join(EVIDENCE_DIR, 'source_audit_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n{'=' * 70}")
    print(f"Source audit complete:")
    print(f"  Files scanned: {results['files_scanned']}")
    print(f"  Security patterns found: {len(results['patterns_found'])}")
    print(f"  Pattern breakdown: {dict(pattern_summary)}")
    print(f"  Regexes extracted: {len(results['regex_extraction'])}")
    print(f"  Dangerous regexes: {len(dangerous_regexes)}")
    print(f"  Findings: {len(results['findings'])}")
    print(f"Evidence: {out_file}")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
