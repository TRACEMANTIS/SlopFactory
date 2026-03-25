#!/usr/bin/env python3
"""
Phase 4.5 — Middleware Ordering Analysis
Express.js Security Assessment — [REDACTED]

Tests how middleware ordering affects security in Express.
SCOPE: Framework middleware pipeline behavior.
"""

import requests
import json
import os
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '4.5', 'name': 'Middleware Ordering Analysis', 'timestamp': datetime.now().isoformat()},
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


def test_security_header_presence():
    """Test which security headers are present (Helmet not enabled = framework default)"""
    print("\n[*] Testing security header presence (no Helmet)...")

    security_headers = [
        'Content-Security-Policy',
        'Cross-Origin-Embedder-Policy',
        'Cross-Origin-Opener-Policy',
        'Cross-Origin-Resource-Policy',
        'X-DNS-Prefetch-Control',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-Download-Options',
        'X-Content-Type-Options',
        'Origin-Agent-Cluster',
        'X-Permitted-Cross-Domain-Policies',
        'Referrer-Policy',
        'X-XSS-Protection',
    ]

    for ver, base in TARGETS.items():
        try:
            r = requests.get(f'{base}/health', timeout=5)
            headers = dict(r.headers)

            present = []
            missing = []
            for h in security_headers:
                if h in headers:
                    present.append(f'{h}: {headers[h]}')
                else:
                    missing.append(h)

            finding = None
            if len(missing) > 5:
                finding = {
                    'title': f'Express Default: {len(missing)} Security Headers Missing',
                    'severity': 'MEDIUM', 'cwe': 'CWE-693',
                    'description': f'Express does not set any security headers by default. '
                                   f'Missing: {", ".join(missing[:5])}... '
                                   f'Helmet.js or manual configuration required.',
                    'framework_behavior': True
                }

            log_test('security_headers', ver, {
                'present_count': len(present),
                'missing_count': len(missing),
                'present': present,
                'missing': missing
            }, finding)
        except Exception as e:
            log_test('security_headers', ver, {'error': str(e)})


def test_error_before_auth():
    """Test if errors before auth middleware leak information"""
    print("\n[*] Testing error handling before authentication...")

    for ver, base in TARGETS.items():
        # Send malformed body to authenticated endpoint (body parser runs before auth)
        try:
            r = requests.post(f'{base}/login', data='not valid json',
                              headers={'Content-Type': 'application/json'}, timeout=5)
            finding = None
            if r.status_code == 400 and ('Unexpected token' in r.text or 'SyntaxError' in r.text):
                finding = {
                    'title': 'Body Parser Error Leaks Details Before Auth Check',
                    'severity': 'LOW', 'cwe': 'CWE-209',
                    'description': f'body-parser returns detailed parse errors before authentication: {r.text[:200]}',
                    'framework_behavior': True,
                    'note': 'body-parser middleware runs before route auth — parse errors bypass auth'
                }

            log_test('error_before_auth', ver, {
                'status': r.status_code,
                'body': r.text[:300],
                'reveals_parser_info': 'Unexpected token' in r.text or 'SyntaxError' in r.text
            }, finding)
        except Exception as e:
            log_test('error_before_auth', ver, {'error': str(e)})


def test_cors_preflight_auth():
    """Test if CORS preflight bypasses authentication"""
    print("\n[*] Testing CORS preflight vs authentication...")

    for ver, base in TARGETS.items():
        try:
            r = requests.options(f'{base}/admin/dashboard', headers={
                'Origin': 'http://evil.com',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'Authorization'
            }, timeout=5)

            finding = None
            cors_headers = {k: v for k, v in r.headers.items() if 'access-control' in k.lower()}
            if r.status_code in (200, 204) and cors_headers:
                finding = {
                    'title': 'CORS Preflight Bypasses Auth on Protected Endpoint',
                    'severity': 'LOW', 'cwe': 'CWE-346',
                    'description': f'OPTIONS /admin/dashboard returns {r.status_code} with CORS headers '
                                   f'without authentication check. CORS middleware runs before auth.',
                    'framework_behavior': True,
                    'note': 'CORS preflight is by design unauthenticated — but reveals endpoint existence'
                }

            log_test('cors_preflight_auth', ver, {
                'status': r.status_code,
                'cors_headers': cors_headers
            }, finding)
        except Exception as e:
            log_test('cors_preflight_auth', ver, {'error': str(e)})


def test_error_handler_ordering():
    """Test error handler info disclosure"""
    print("\n[*] Testing error handler information disclosure...")

    for ver, base in TARGETS.items():
        # Test various error scenarios
        error_tests = [
            ('unhandled_error', '/error-test'),
            ('not_found', '/nonexistent-path-xyz'),
            ('bad_method', '/health'),  # POST to GET-only
        ]

        for name, path in error_tests:
            try:
                if name == 'bad_method':
                    r = requests.post(f'{base}{path}', timeout=5)
                else:
                    r = requests.get(f'{base}{path}', timeout=5)

                body = r.text
                has_stack = 'at ' in body and 'node_modules' in body
                has_paths = '/home/' in body or 'node_modules' in body
                has_env_info = 'development' in body

                finding = None
                if has_stack or has_paths:
                    finding = {
                        'title': f'Error Response Leaks Internal Paths ({name})',
                        'severity': 'LOW', 'cwe': 'CWE-209',
                        'description': f'Error response for {name} reveals stack trace or file paths',
                        'framework_behavior': True
                    }

                log_test(f'error_{name}', ver, {
                    'path': path, 'status': r.status_code,
                    'has_stack_trace': has_stack,
                    'has_file_paths': has_paths,
                    'body_snippet': body[:300]
                }, finding)
            except Exception as e:
                log_test(f'error_{name}', ver, {'error': str(e)})


def test_express_settings_exposure():
    """Test Express internal settings accessibility"""
    print("\n[*] Testing Express settings exposure...")

    for ver, base in TARGETS.items():
        try:
            # Check if env-test endpoint exposes settings
            r = requests.get(f'{base}/env-test', timeout=5)
            data = r.json() if r.status_code == 200 else {}

            finding = None
            if data.get('env') and isinstance(data['env'], dict) and len(data['env']) > 5:
                finding = {
                    'title': 'Full Environment Variables Exposed',
                    'severity': 'INFO', 'cwe': 'CWE-200',
                    'description': f'process.env exposed via API ({len(data["env"])} variables). '
                                   f'Note: App-level issue, not framework default.',
                    'framework_behavior': False
                }

            log_test('settings_exposure', ver, {
                'env_var_count': len(data.get('env', {})),
                'express_version': data.get('expressVersion', ''),
                'node_env': data.get('nodeEnv', '')
            }, finding)
        except Exception as e:
            log_test('settings_exposure', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 4.5 — Middleware Ordering Analysis")
    print("=" * 70)

    test_security_header_presence()
    test_error_before_auth()
    test_cors_preflight_auth()
    test_error_handler_ordering()
    test_express_settings_exposure()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'middleware_order_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nMiddleware analysis complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
