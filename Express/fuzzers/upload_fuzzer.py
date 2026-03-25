#!/usr/bin/env python3
"""
Phase 2.5 — File Upload Fuzzer
Express.js Security Assessment — [REDACTED]

Tests multer middleware file handling behavior.
SCOPE: Framework middleware (multer) file handling.
"""

import requests
import json
import os
import io
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '2.5', 'name': 'File Upload Fuzzer', 'timestamp': datetime.now().isoformat()},
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


def fuzz_uploads():
    print("\n[*] Fuzzing file uploads (multer)...")

    filename_payloads = [
        ('normal', 'test.txt'),
        ('traversal_basic', '../../../etc/evil.txt'),
        ('traversal_encoded', '..%2f..%2f..%2fetc%2fevil.txt'),
        ('null_byte', 'test.txt\x00.exe'),
        ('null_in_ext', 'test\x00.txt'),
        ('double_extension', 'test.txt.exe'),
        ('hidden_file', '.hidden'),
        ('dotdot_name', '..test'),
        ('long_name', 'A' * 256 + '.txt'),
        ('unicode_name', '\u202efdp.exe'),  # RTL override
        ('spaces', 'test file name.txt'),
        ('special_chars', 'test<>:"|?*.txt'),
        ('backslash', 'test\\..\\evil.txt'),
        ('absolute_path', '/tmp/evil.txt'),
        ('windows_path', 'C:\\Windows\\evil.txt'),
        ('pipe_char', 'test|evil.txt'),
        ('semicolon', 'test;evil.txt'),
        ('crlf', 'test\r\nevil.txt'),
    ]

    for ver, base in TARGETS.items():
        for name, filename in filename_payloads:
            content = b'test file content'
            files = {'file': (filename, io.BytesIO(content), 'text/plain')}

            # Test safe upload (multer auto-rename)
            try:
                r = requests.post(f'{base}/upload', files=files, timeout=5)
                safe_data = r.json() if r.status_code == 200 else {}
                log_test(f'upload_safe_{name}', ver, {
                    'filename': filename[:100], 'status': r.status_code,
                    'saved_name': safe_data.get('savedName', ''),
                    'original_preserved': safe_data.get('originalName', '') == filename
                })
            except Exception as e:
                log_test(f'upload_safe_{name}', ver, {'error': str(e)})

            # Test unsafe upload (original filename)
            files = {'file': (filename, io.BytesIO(content), 'text/plain')}
            try:
                r = requests.post(f'{base}/upload-custom', files=files, timeout=5)
                data = r.json() if r.status_code == 200 else {}

                finding = None
                saved = data.get('savedName', '')
                if '..' in saved and r.status_code == 200:
                    finding = {
                        'title': f'Path Traversal in Upload Filename ({name})',
                        'severity': 'HIGH', 'cwe': 'CWE-22',
                        'description': f'multer saved file with traversal chars in name: {saved}',
                        'framework_behavior': True,
                        'note': 'multer diskStorage with user filename does not sanitize path traversal'
                    }

                log_test(f'upload_unsafe_{name}', ver, {
                    'filename': filename[:100], 'status': r.status_code,
                    'saved_name': saved, 'path': data.get('path', '')
                }, finding)
            except Exception as e:
                log_test(f'upload_unsafe_{name}', ver, {'error': str(e)})

    # Size limit tests
    print("\n[*] Testing upload size limits...")
    for ver, base in TARGETS.items():
        for size_name, size in [('1mb', 1*1024*1024), ('5mb', 5*1024*1024), ('6mb', 6*1024*1024), ('10mb', 10*1024*1024)]:
            try:
                content = b'A' * size
                files = {'file': ('big.bin', io.BytesIO(content), 'application/octet-stream')}
                r = requests.post(f'{base}/upload', files=files, timeout=30)
                log_test(f'upload_size_{size_name}', ver, {
                    'size': size, 'status': r.status_code
                })
            except Exception as e:
                log_test(f'upload_size_{size_name}', ver, {'error': str(e)})

    # MIME type tests
    print("\n[*] Testing MIME type handling...")
    for ver, base in TARGETS.items():
        mime_tests = [
            ('exe_as_txt', 'evil.exe', 'text/plain'),
            ('html_as_img', 'evil.html', 'image/png'),
            ('php_file', 'evil.php', 'application/x-php'),
            ('no_mime', 'test.bin', ''),
            ('null_mime', 'test.bin', '\x00'),
        ]
        for name, fname, mime in mime_tests:
            try:
                files = {'file': (fname, io.BytesIO(b'test'), mime or 'application/octet-stream')}
                r = requests.post(f'{base}/upload', files=files, timeout=5)
                data = r.json() if r.status_code == 200 else {}
                log_test(f'mime_{name}', ver, {
                    'filename': fname, 'sent_mime': mime,
                    'status': r.status_code, 'stored_mime': data.get('mimetype', '')
                })
            except Exception as e:
                log_test(f'mime_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 2.5 — File Upload Fuzzer (multer)")
    print("=" * 70)

    fuzz_uploads()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings']), 'anomalies_count': anomaly_count}
    out_file = os.path.join(EVIDENCE_DIR, 'upload_fuzzer_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nUpload fuzzer complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
