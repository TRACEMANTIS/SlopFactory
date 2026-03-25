#!/usr/bin/env python3
"""
Phase 1.4 — Configuration Security Review
Express.js Security Assessment — [REDACTED]

Tests Express default configuration and security-relevant settings.
SCOPE: Framework defaults only.
"""

import requests
import json
import os
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {
        'phase': '1.4',
        'name': 'Configuration Security Review',
        'timestamp': datetime.now().isoformat(),
        'scope': 'Express framework default configuration'
    },
    'tests': [],
    'findings': [],
    'summary': {}
}

test_count = 0

def log_test(name, version, data, finding=None):
    global test_count
    test_count += 1
    entry = {'id': test_count, 'test': name, 'version': version, 'data': data}
    if finding:
        entry['finding'] = finding
        results['findings'].append({'id': len(results['findings'])+1, 'test_id': test_count, 'version': version, **finding})
    results['tests'].append(entry)
    status = '⚠ FINDING' if finding else '✓'
    print(f"  [{test_count:3d}] {status} {name} ({version})")


def test_express_settings():
    """Test Express application settings"""
    print("\n[*] Testing Express settings...")
    for version, base_url in TARGETS.items():
        try:
            r = requests.get(f'{base_url}/health', timeout=5)
            data = r.json()
            headers = dict(r.headers)

            # Check env setting (default is 'development')
            env = data.get('env', 'unknown')
            finding = None
            if env == 'development':
                finding = {
                    'title': 'Express Defaults to Development Mode',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-489',
                    'description': 'Express defaults NODE_ENV to "development" which enables stack traces, '
                                   'verbose errors, and disables caching. This is a framework default.',
                    'framework_behavior': True
                }
            log_test('env_setting', version, {'env': env, 'node': data.get('node')}, finding)

            # Check ETag setting
            etag_header = headers.get('ETag', 'NOT SET')
            log_test('etag_setting', version, {'etag': etag_header, 'present': 'ETag' in headers})

            # X-Powered-By
            xpb = headers.get('X-Powered-By', 'NOT SET')
            finding = None
            if xpb != 'NOT SET':
                finding = {
                    'title': f'X-Powered-By Header Exposes Framework Version',
                    'severity': 'LOW',
                    'cwe': 'CWE-200',
                    'description': f'X-Powered-By: {xpb} — Express enables this by default',
                    'framework_behavior': True
                }
            log_test('x_powered_by', version, {'value': xpb}, finding)

        except Exception as e:
            log_test('express_settings', version, {'error': str(e)})


def test_session_defaults():
    """Test session configuration defaults"""
    print("\n[*] Testing session configuration...")
    for version, base_url in TARGETS.items():
        try:
            # Login to get a session
            r = requests.post(f'{base_url}/login',
                              json={'username': 'admin', 'password': 'admin123'}, timeout=5)

            cookies = r.cookies
            cookie_dict = {c.name: c for c in cookies}

            session_cookie = cookie_dict.get('connect.sid')
            if session_cookie:
                finding = None
                issues = []

                if not session_cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('httpOnly not set')
                if not session_cookie.secure:
                    issues.append('secure flag not set')
                # Check SameSite
                ss = session_cookie.get_nonstandard_attr('SameSite') if hasattr(session_cookie, 'get_nonstandard_attr') else None

                # Cookie name — default 'connect.sid' reveals session middleware
                if session_cookie.name == 'connect.sid':
                    issues.append('default cookie name reveals express-session')

                if issues:
                    finding = {
                        'title': 'express-session Default Cookie Configuration Insecure',
                        'severity': 'MEDIUM',
                        'cwe': 'CWE-614',
                        'description': f'Session cookie issues: {", ".join(issues)}. '
                                       'express-session defaults do not set httpOnly, secure, or sameSite.',
                        'framework_behavior': True,
                        'note': 'While apps should configure these, the library defaults are insecure'
                    }

                log_test('session_cookie', version, {
                    'name': session_cookie.name,
                    'value_length': len(session_cookie.value),
                    'secure': session_cookie.secure,
                    'path': session_cookie.path,
                    'issues': issues
                }, finding)
            else:
                log_test('session_cookie', version, {'error': 'No session cookie received'})

        except Exception as e:
            log_test('session_cookie', version, {'error': str(e)})


def test_cors_defaults():
    """Test CORS behavior"""
    print("\n[*] Testing CORS configuration...")
    for version, base_url in TARGETS.items():
        try:
            # Preflight request
            r = requests.options(f'{base_url}/api/users', headers={
                'Origin': 'http://evil.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type, Authorization'
            }, timeout=5)

            cors_headers = {
                'Access-Control-Allow-Origin': r.headers.get('Access-Control-Allow-Origin', 'NOT SET'),
                'Access-Control-Allow-Methods': r.headers.get('Access-Control-Allow-Methods', 'NOT SET'),
                'Access-Control-Allow-Headers': r.headers.get('Access-Control-Allow-Headers', 'NOT SET'),
                'Access-Control-Allow-Credentials': r.headers.get('Access-Control-Allow-Credentials', 'NOT SET'),
            }

            log_test('cors_preflight', version, {
                'status': r.status_code,
                'cors_headers': cors_headers,
                'origin_sent': 'http://evil.com'
            })

            # Actual request with evil origin
            r2 = requests.get(f'{base_url}/api/users', headers={'Origin': 'http://evil.com'}, timeout=5)
            acao = r2.headers.get('Access-Control-Allow-Origin', 'NOT SET')
            acac = r2.headers.get('Access-Control-Allow-Credentials', 'NOT SET')

            finding = None
            if acao == '*' and acac == 'true':
                finding = {
                    'title': 'CORS Misconfiguration: Wildcard Origin with Credentials',
                    'severity': 'HIGH',
                    'cwe': 'CWE-346',
                    'description': 'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. '
                                   'Note: Browsers block this combination, but it indicates misconfiguration.',
                    'framework_behavior': False,  # This is app config, but cors middleware allows it
                    'note': 'cors middleware allows this dangerous combination without warning'
                }

            log_test('cors_response', version, {
                'acao': acao,
                'acac': acac
            }, finding)

        except Exception as e:
            log_test('cors', version, {'error': str(e)})


def test_query_parser():
    """Test qs query parser behavior — framework-level"""
    print("\n[*] Testing query parser behavior...")
    for version, base_url in TARGETS.items():
        # Test nested object depth
        test_queries = [
            ('basic', 'q=test'),
            ('array', 'a[0]=1&a[1]=2'),
            ('nested_object', 'a[b][c]=deep'),
            ('deep_nesting', 'a[b][c][d][e][f]=very_deep'),
            ('proto_via_qs', '__proto__[polluted]=true'),
            ('constructor_via_qs', 'constructor[prototype][polluted]=true'),
            ('array_limit', '&'.join(f'a[{i}]={i}' for i in range(25))),
            ('parameter_limit', '&'.join(f'p{i}=v{i}' for i in range(1100))),
        ]

        for test_name, qs in test_queries:
            try:
                r = requests.get(f'{base_url}/method-test?{qs}', timeout=5)
                data = r.json() if r.status_code == 200 else {}
                parsed_query = data.get('query', {})

                finding = None
                if test_name == 'proto_via_qs':
                    # Check if qs allowed __proto__ through
                    if '__proto__' in str(parsed_query):
                        finding = {
                            'title': 'qs Allows __proto__ in Query String',
                            'severity': 'HIGH',
                            'cwe': 'CWE-1321',
                            'description': 'qs module did not filter __proto__ from query parameters',
                            'framework_behavior': True
                        }

                log_test(f'query_parser_{test_name}', version, {
                    'query_string': qs[:200],
                    'parsed': str(parsed_query)[:500],
                    'status': r.status_code
                }, finding)
            except Exception as e:
                log_test(f'query_parser_{test_name}', version, {'error': str(e)})


def test_body_parser_limits():
    """Test body-parser size and type limits"""
    print("\n[*] Testing body parser limits...")
    for version, base_url in TARGETS.items():
        # Test payload size limits
        sizes = [('1kb', 1024), ('100kb', 102400), ('1mb', 1048576)]
        for size_name, size in sizes:
            try:
                payload = {'data': 'A' * size}
                r = requests.post(f'{base_url}/method-test',
                                  json=payload, timeout=10)
                log_test(f'body_size_{size_name}', version, {
                    'sent_size': size,
                    'status': r.status_code,
                    'error': r.json().get('error', '') if r.status_code >= 400 else None
                })
            except Exception as e:
                log_test(f'body_size_{size_name}', version, {'error': str(e)})

        # Test deeply nested JSON
        try:
            nested = {'a': None}
            current = nested
            for _ in range(100):
                current['a'] = {'a': None}
                current = current['a']
            current['a'] = 'deep'

            r = requests.post(f'{base_url}/method-test', json=nested, timeout=10)
            log_test('body_deep_nesting', version, {
                'depth': 100,
                'status': r.status_code
            })
        except Exception as e:
            log_test('body_deep_nesting', version, {'error': str(e)})


def test_static_file_dotfiles():
    """Test express.static dotfiles handling"""
    print("\n[*] Testing static file serving...")
    for version, base_url in TARGETS.items():
        dotfile_tests = [
            ('.env', 'sensitive environment file'),
            ('.git_config_sample', 'git config file'),
            ('.htaccess', 'htaccess file (should not exist)'),
        ]

        for filename, desc in dotfile_tests:
            try:
                r = requests.get(f'{base_url}/static/{filename}', timeout=5)
                finding = None
                if r.status_code == 200 and len(r.text) > 0:
                    finding = {
                        'title': f'express.static Serves Dotfile: {filename}',
                        'severity': 'HIGH' if filename == '.env' else 'MEDIUM',
                        'cwe': 'CWE-538',
                        'description': f'express.static with dotfiles:"allow" serves {filename}. '
                                       f'Note: The default is "ignore" which returns 404 — this tests '
                                       f'framework behavior when misconfigured.',
                        'framework_behavior': True,
                        'note': 'Default dotfiles setting is "ignore" — but "allow" exposes all dotfiles'
                    }

                log_test(f'static_dotfile_{filename}', version, {
                    'filename': filename,
                    'status': r.status_code,
                    'content_length': len(r.text),
                    'content_preview': r.text[:100] if r.status_code == 200 else ''
                }, finding)
            except Exception as e:
                log_test(f'static_dotfile_{filename}', version, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 1.4 — Configuration Security Review")
    print("Express.js Security Assessment — Framework Defaults")
    print("=" * 70)

    test_express_settings()
    test_session_defaults()
    test_cors_defaults()
    test_query_parser()
    test_body_parser_limits()
    test_static_file_dotfiles()

    results['summary'] = {
        'total_tests': test_count,
        'findings_count': len(results['findings']),
        'findings_by_severity': {}
    }
    for f in results['findings']:
        sev = f.get('severity', 'UNKNOWN')
        results['summary']['findings_by_severity'][sev] = \
            results['summary']['findings_by_severity'].get(sev, 0) + 1

    out_file = os.path.join(EVIDENCE_DIR, 'config_audit.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n{'=' * 70}")
    print(f"Config audit complete: {test_count} tests, {len(results['findings'])} findings")
    for sev, count in results['summary']['findings_by_severity'].items():
        print(f"  {sev}: {count}")
    print(f"Evidence: {out_file}")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
