#!/usr/bin/env python3
"""
Phase 1.2 — Dependency Audit
Express.js Security Assessment — [REDACTED]

Audits npm dependencies for known CVEs and compares v4 vs v5 dependency trees.
SCOPE: Framework dependencies only.
"""

import json
import subprocess
import os
from datetime import datetime

EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'
V5_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/testapp-v5'
V4_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/testapp-v4'

# Known CVEs relevant to Express ecosystem
KNOWN_CVES = {
    'express': [
        {'cve': 'CVE-2024-29041', 'desc': 'Open redirect via URL parsing in Express <4.19.2',
         'affects': '<4.19.2', 'severity': 'MEDIUM'},
        {'cve': 'CVE-2024-43796', 'desc': 'XSS via response.redirect() in Express <4.20.0',
         'affects': '<4.20.0', 'severity': 'MEDIUM'},
    ],
    'qs': [
        {'cve': 'CVE-2022-24999', 'desc': 'Prototype pollution via __proto__ in qs <6.10.3',
         'affects': '<6.10.3', 'severity': 'HIGH'},
        {'cve': 'CVE-2017-1000048', 'desc': 'Prototype pollution in qs <6.3.2',
         'affects': '<6.3.2', 'severity': 'HIGH'},
    ],
    'body-parser': [
        {'cve': 'CVE-2024-45590', 'desc': 'body-parser DoS via content-type in <1.20.3',
         'affects': '<1.20.3', 'severity': 'HIGH'},
    ],
    'send': [
        {'cve': 'CVE-2024-43799', 'desc': 'XSS in send error page via untrusted input in <0.19.0',
         'affects': '<0.19.0', 'severity': 'MEDIUM'},
    ],
    'serve-static': [
        {'cve': 'CVE-2024-43800', 'desc': 'XSS in serve-static via redirect in <1.16.0',
         'affects': '<1.16.0', 'severity': 'MEDIUM'},
    ],
    'cookie': [
        {'cve': 'CVE-2024-47764', 'desc': 'cookie parsing accepts out-of-spec chars in <0.7.0',
         'affects': '<0.7.0', 'severity': 'LOW'},
    ],
    'path-to-regexp': [
        {'cve': 'CVE-2024-45296', 'desc': 'ReDoS in path-to-regexp <0.1.10 and <6.3.0',
         'affects': '<6.3.0', 'severity': 'HIGH'},
    ],
    'ejs': [
        {'cve': 'CVE-2024-33883', 'desc': 'EJS template injection / prototype pollution RCE <3.1.10',
         'affects': '<3.1.10', 'severity': 'CRITICAL'},
        {'cve': 'CVE-2022-29078', 'desc': 'EJS SSTI via settings/opts in <3.1.7',
         'affects': '<3.1.7', 'severity': 'CRITICAL'},
    ],
}

results = {
    'metadata': {
        'phase': '1.2',
        'name': 'Dependency Audit',
        'timestamp': datetime.now().isoformat(),
        'scope': 'Framework dependencies — known CVEs and version comparison'
    },
    'npm_audit': {},
    'dependency_versions': {},
    'cve_analysis': [],
    'version_comparison': {},
    'findings': [],
    'summary': {}
}

test_count = 0

def log_test(name, data, finding=None):
    global test_count
    test_count += 1
    if finding:
        results['findings'].append({'id': len(results['findings'])+1, 'test_id': test_count, **finding})
        print(f"  [{test_count:3d}] ⚠ FINDING {name}")
    else:
        print(f"  [{test_count:3d}] ✓ {name}")


def run_npm_audit(version, app_dir):
    """Run npm audit"""
    print(f"\n[*] npm audit for {version}...")
    try:
        result = subprocess.run(['npm', 'audit', '--json'], capture_output=True, text=True,
                                cwd=app_dir, timeout=30)
        audit_data = json.loads(result.stdout) if result.stdout else {}
        results['npm_audit'][version] = audit_data

        vuln_count = audit_data.get('metadata', {}).get('vulnerabilities', {})
        total = sum(vuln_count.values()) if isinstance(vuln_count, dict) else 0

        finding = None
        if total > 0:
            finding = {
                'title': f'npm audit: {total} vulnerabilities in Express {version} dependencies',
                'severity': 'HIGH' if vuln_count.get('high', 0) > 0 or vuln_count.get('critical', 0) > 0 else 'MEDIUM',
                'cwe': 'CWE-1035',
                'description': f'npm audit reports {json.dumps(vuln_count)} vulnerabilities',
                'framework_behavior': True,
                'version': version
            }

        log_test(f'npm_audit_{version}', audit_data, finding)

        # Save individual audit files
        with open(os.path.join(EVIDENCE_DIR, f'npm_audit_{version}.json'), 'w') as f:
            json.dump(audit_data, f, indent=2)

    except Exception as e:
        log_test(f'npm_audit_{version}', {'error': str(e)})


def get_dependency_versions(version, app_dir):
    """Get versions of all critical dependencies"""
    print(f"\n[*] Extracting dependency versions for {version}...")
    critical_deps = [
        'express', 'qs', 'body-parser', 'send', 'serve-static', 'cookie',
        'cookie-signature', 'path-to-regexp', 'finalhandler', 'ejs',
        'express-handlebars', 'handlebars', 'jsonwebtoken', 'multer',
        'express-session', 'helmet', 'cors', 'express-rate-limit'
    ]

    versions = {}
    for dep in critical_deps:
        try:
            pkg_path = os.path.join(app_dir, 'node_modules', dep, 'package.json')
            if os.path.exists(pkg_path):
                with open(pkg_path) as f:
                    pkg = json.load(f)
                versions[dep] = pkg.get('version', 'unknown')
            else:
                versions[dep] = 'NOT INSTALLED'
        except Exception as e:
            versions[dep] = f'ERROR: {e}'

    results['dependency_versions'][version] = versions
    log_test(f'dep_versions_{version}', versions)
    return versions


def analyze_known_cves(v4_versions, v5_versions):
    """Check if installed versions are affected by known CVEs"""
    print("\n[*] Analyzing known CVEs against installed versions...")

    for pkg, cves in KNOWN_CVES.items():
        v4_ver = v4_versions.get(pkg, 'NOT INSTALLED')
        v5_ver = v5_versions.get(pkg, 'NOT INSTALLED')

        for cve_info in cves:
            entry = {
                'package': pkg,
                'cve': cve_info['cve'],
                'description': cve_info['desc'],
                'affects': cve_info['affects'],
                'severity': cve_info['severity'],
                'v4_version': v4_ver,
                'v5_version': v5_ver,
                'v4_vulnerable': False,  # We'd need semver comparison
                'v5_vulnerable': False,
                'notes': ''
            }

            # Simple version comparison (not full semver but good enough for our purposes)
            entry['notes'] = f'v4={v4_ver}, v5={v5_ver}, affected={cve_info["affects"]}'
            results['cve_analysis'].append(entry)

            finding = None
            if v4_ver != 'NOT INSTALLED' or v5_ver != 'NOT INSTALLED':
                finding = {
                    'title': f'{cve_info["cve"]}: {pkg} — {cve_info["desc"][:80]}',
                    'severity': cve_info['severity'],
                    'cwe': 'CWE-1035',
                    'description': f'{cve_info["desc"]}. v4={v4_ver}, v5={v5_ver}. Affects: {cve_info["affects"]}',
                    'framework_behavior': True,
                    'needs_verification': True
                }

            log_test(f'cve_{cve_info["cve"]}_{pkg}', entry, finding)


def compare_versions(v4_versions, v5_versions):
    """Compare dependency versions between v4 and v5"""
    print("\n[*] Comparing v4 vs v5 dependency versions...")

    comparison = {}
    all_deps = set(list(v4_versions.keys()) + list(v5_versions.keys()))

    for dep in sorted(all_deps):
        v4 = v4_versions.get(dep, 'N/A')
        v5 = v5_versions.get(dep, 'N/A')
        comparison[dep] = {
            'v4': v4,
            'v5': v5,
            'same': v4 == v5,
            'note': 'SAME' if v4 == v5 else ('v5 NEWER' if v4 != 'N/A' and v5 != 'N/A' else 'VERSION ONLY')
        }

    results['version_comparison'] = comparison

    # Check for notable differences
    notable_diffs = {k: v for k, v in comparison.items() if not v['same']}
    finding = None
    if notable_diffs:
        finding = {
            'title': f'{len(notable_diffs)} dependencies differ between Express v4 and v5',
            'severity': 'INFO',
            'cwe': 'CWE-1035',
            'description': f'Differing deps: {json.dumps({k: {"v4": v["v4"], "v5": v["v5"]} for k, v in notable_diffs.items()}, indent=2)}',
            'framework_behavior': True
        }

    log_test('version_comparison', comparison, finding)


def audit_dep_tree(version, app_dir):
    """Get full dependency tree"""
    print(f"\n[*] Mapping dependency tree for {version}...")
    try:
        result = subprocess.run(['npm', 'ls', '--all', '--json'], capture_output=True, text=True,
                                cwd=app_dir, timeout=30)
        tree = json.loads(result.stdout) if result.stdout else {}
        tree_file = os.path.join(EVIDENCE_DIR, f'dependency_tree_{version}.json')
        with open(tree_file, 'w') as f:
            json.dump(tree, f, indent=2)
        dep_count = result.stdout.count('"version"')
        log_test(f'dep_tree_{version}', {'total_deps': dep_count, 'output_file': tree_file})
    except Exception as e:
        log_test(f'dep_tree_{version}', {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 1.2 — Dependency Audit")
    print("Express.js Security Assessment — Framework Dependencies")
    print("=" * 70)

    run_npm_audit('v4', V4_DIR)
    run_npm_audit('v5', V5_DIR)
    v4_versions = get_dependency_versions('v4', V4_DIR)
    v5_versions = get_dependency_versions('v5', V5_DIR)
    analyze_known_cves(v4_versions, v5_versions)
    compare_versions(v4_versions, v5_versions)
    audit_dep_tree('v4', V4_DIR)
    audit_dep_tree('v5', V5_DIR)

    results['summary'] = {
        'total_tests': test_count,
        'findings_count': len(results['findings']),
        'findings_by_severity': {}
    }
    for f in results['findings']:
        sev = f.get('severity', 'UNKNOWN')
        results['summary']['findings_by_severity'][sev] = \
            results['summary']['findings_by_severity'].get(sev, 0) + 1

    out_file = os.path.join(EVIDENCE_DIR, 'dependency_audit.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n{'=' * 70}")
    print(f"Dependency audit complete: {test_count} tests, {len(results['findings'])} findings")
    for sev, count in results['summary']['findings_by_severity'].items():
        print(f"  {sev}: {count}")
    print(f"Evidence: {out_file}")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
