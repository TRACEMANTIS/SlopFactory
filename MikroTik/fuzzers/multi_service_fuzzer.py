#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- Multi-Service Raw Packet Fuzzer
Phase 7: Fuzzing -- ~150 test cases across remaining services.

Categories:
  1. Bandwidth-test fuzzer (~30): TCP port 2000
  2. MNDP fuzzer (~25): UDP port 5678
  3. FTP protocol fuzzer (~25): TCP port 21
  4. DNS fuzzer (~25): UDP port 53
  5. SNMP fuzzer (~25): UDP port 161
  6. Telnet fuzzer (~20): TCP port 23

All use raw sockets. Check router alive every 10 tests.
Target: [REDACTED-INTERNAL-IP], admin/TestPass123
"""

import os
import sys
import time
import socket
import struct
import random
import traceback

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ALIVE_CHECK_INTERVAL = 10
RECV_TIMEOUT = 5
CONNECT_TIMEOUT = 5

ec = EvidenceCollector("multi_service_fuzzer.py", phase=7)
global_test_count = 0
crash_events = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def tcp_send_recv(port, data, timeout=RECV_TIMEOUT, recv_size=4096):
    """Connect via TCP, send data, receive response, close."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, port))
    s.sendall(data)
    time.sleep(0.3)
    response = b""
    try:
        while True:
            chunk = s.recv(recv_size)
            if not chunk:
                break
            response += chunk
            if len(response) > 65536:
                break
    except socket.timeout:
        pass
    except ConnectionResetError:
        pass
    s.close()
    return response


def udp_send_recv(port, data, timeout=RECV_TIMEOUT, recv_size=4096):
    """Send UDP datagram and receive response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(data, (TARGET, port))
    response = b""
    try:
        response, addr = s.recvfrom(recv_size)
    except socket.timeout:
        pass
    s.close()
    return response


def tcp_connect_send(port, data, timeout=CONNECT_TIMEOUT):
    """TCP connect and send without waiting for response. Returns success bool."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, port))
        s.sendall(data)
        s.close()
        return True
    except Exception:
        return False


def run_test(category, name, description, test_func):
    """Run a test function, record result, and health-check periodically."""
    global global_test_count
    global_test_count += 1

    try:
        result, details = test_func()
        is_anomaly = details.get("anomaly", False)

        ec.add_test(
            category=category,
            name=name,
            description=description,
            result=result,
            details=details,
            anomaly=is_anomaly,
        )

    except Exception as e:
        ec.add_test(
            category=category,
            name=name,
            description=description,
            result=f"Exception: {e}",
            details={"error": str(e)},
            anomaly=True,
        )

    # Periodic health check
    if global_test_count % ALIVE_CHECK_INTERVAL == 0:
        health = check_router_alive()
        if not health.get("alive"):
            crash_events.append({
                "test_index": global_test_count,
                "test_name": name,
                "category": category,
                "timestamp": time.strftime("%H:%M:%S"),
            })
            log(f"  ROUTER DOWN at test #{global_test_count} ({name})! Waiting...")
            ec.add_finding(
                severity="HIGH",
                title=f"Router crash during multi-service fuzzing: {name}",
                description=f"Router became unresponsive after test '{name}' in category '{category}'",
                evidence_refs=[name],
                cwe="CWE-120",
            )
            wait_for_router(max_wait=120)
            time.sleep(5)


# ---------------------------------------------------------------------------
# Category 1: Bandwidth-Test Fuzzer (~30 tests) -- TCP port 2000
# ---------------------------------------------------------------------------

def fuzz_bandwidth_test():
    log("=" * 60)
    log("Category 1: Bandwidth-Test Protocol Fuzzing (TCP:2000)")
    log("=" * 60)

    BTEST_PORT = PORTS["btest"]  # 2000

    # Random binary payloads of various sizes
    for size_name, size in [("100B", 100), ("1KB", 1024), ("10KB", 10240), ("64KB", 65536)]:
        def _test(sz=size, sn=size_name):
            payload = os.urandom(sz)
            resp = tcp_send_recv(BTEST_PORT, payload, timeout=3)
            return (f"Sent {sz} bytes, got {len(resp)} bytes",
                    {"payload_size": sz, "response_size": len(resp),
                     "response_hex": resp.hex()[:100] if resp else ""})
        run_test("btest", f"random_binary_{size_name}",
                 f"Send {size_name} random binary to btest", _test)

    # Oversized packet (128KB)
    def _test_oversized():
        payload = os.urandom(131072)
        try:
            resp = tcp_send_recv(BTEST_PORT, payload, timeout=5)
            return (f"Sent 128KB, got {len(resp)} bytes",
                    {"payload_size": 131072, "response_size": len(resp)})
        except Exception as e:
            return (f"Error: {e}", {"error": str(e)})
    run_test("btest", "oversized_128KB",
             "Send 128KB to btest", _test_oversized)

    # Partial writes (1 byte at a time for first 10 bytes)
    def _test_partial():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, BTEST_PORT))
            for i in range(10):
                s.send(bytes([random.randint(0, 255)]))
                time.sleep(0.1)
            s.sendall(os.urandom(100))
            time.sleep(0.5)
            resp = b""
            try:
                resp = s.recv(4096)
            except socket.timeout:
                pass
            s.close()
            return (f"Partial write OK, response: {len(resp)} bytes",
                    {"response_size": len(resp)})
        except Exception as e:
            return (f"Error: {e}", {"error": str(e), "anomaly": True})
    run_test("btest", "partial_write",
             "Send bytes one at a time then burst", _test_partial)

    # Rapid connect/disconnect
    def _test_rapid():
        success, fail = 0, 0
        start = time.time()
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                s.connect((TARGET, BTEST_PORT))
                s.close()
                success += 1
            except:
                fail += 1
        elapsed = time.time() - start
        return (f"50 rapid connects: {success} ok, {fail} fail in {elapsed:.2f}s",
                {"success": success, "fail": fail, "elapsed": round(elapsed, 2),
                 "anomaly": fail > 10})
    run_test("btest", "rapid_connect_50",
             "50 rapid TCP connect/disconnect to btest", _test_rapid)

    # All-zero packet
    def _test_zeros():
        resp = tcp_send_recv(BTEST_PORT, b"\x00" * 1000, timeout=3)
        return (f"Sent 1000 zeros, got {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("btest", "all_zeros_1KB",
             "Send 1KB of zero bytes to btest", _test_zeros)

    # All-0xFF packet
    def _test_ff():
        resp = tcp_send_recv(BTEST_PORT, b"\xFF" * 1000, timeout=3)
        return (f"Sent 1000 0xFF bytes, got {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("btest", "all_ff_1KB",
             "Send 1KB of 0xFF bytes to btest", _test_ff)

    # Format strings
    def _test_fmt():
        payload = b"%s%n%x" * 100
        resp = tcp_send_recv(BTEST_PORT, payload, timeout=3)
        return (f"Format strings sent, got {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("btest", "format_strings",
             "Send format string specifiers to btest", _test_fmt)

    # Integer boundary values as binary
    for name, val in [("max_u32", 0xFFFFFFFF), ("max_i32", 0x7FFFFFFF),
                       ("min_i32_neg", 0x80000000), ("zero", 0)]:
        def _test(v=val):
            payload = struct.pack(">I", v) * 250
            resp = tcp_send_recv(BTEST_PORT, payload, timeout=3)
            return (f"Sent {name}, got {len(resp)} bytes",
                    {"response_size": len(resp), "value": v})
        run_test("btest", f"boundary_{name}",
                 f"Send repeated {name} (0x{val:08X}) to btest", _test)

    # HTTP on btest port
    def _test_http():
        payload = f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n".encode()
        resp = tcp_send_recv(BTEST_PORT, payload, timeout=3)
        return (f"HTTP on btest: {len(resp)} bytes",
                {"response_size": len(resp),
                 "response_text": resp.decode("utf-8", errors="replace")[:200]})
    run_test("btest", "http_on_btest",
             "Send HTTP request to btest port (protocol confusion)", _test_http)

    # Multiple concurrent connections holding data
    def _test_concurrent():
        socks = []
        for i in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((TARGET, BTEST_PORT))
                s.send(os.urandom(100))
                socks.append(s)
            except:
                pass
        alive = 0
        for s in socks:
            try:
                s.send(b"\x00")
                alive += 1
            except:
                pass
        for s in socks:
            try:
                s.close()
            except:
                pass
        return (f"{alive}/{len(socks)} connections alive after send",
                {"opened": len(socks), "alive_after": alive})
    run_test("btest", "concurrent_20",
             "Open 20 concurrent btest connections and send data", _test_concurrent)

    # Repeated protocol version probes
    for version in [0x00, 0x01, 0x02, 0x03, 0xFF]:
        def _test(v=version):
            payload = bytes([v]) + b"\x00" * 15
            resp = tcp_send_recv(BTEST_PORT, payload, timeout=3)
            return (f"Version 0x{v:02X}: {len(resp)} bytes",
                    {"version": v, "response_size": len(resp),
                     "response_hex": resp.hex()[:100] if resp else ""})
        run_test("btest", f"proto_version_0x{version:02X}",
                 f"Send protocol version byte 0x{version:02X} to btest", _test)

    # Abrupt RST after connect
    def _test_rst():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        s.connect((TARGET, BTEST_PORT))
        s.send(b"\x01\x00\x00\x00" + os.urandom(100))
        s.close()
        return ("RST sent after data", {"method": "SO_LINGER_RST"})
    run_test("btest", "abrupt_rst",
             "Send data then TCP RST via SO_LINGER(0)", _test_rst)


# ---------------------------------------------------------------------------
# Category 2: MNDP Fuzzer (~25 tests) -- UDP port 5678
# ---------------------------------------------------------------------------

def fuzz_mndp():
    log("=" * 60)
    log("Category 2: MNDP (MikroTik Neighbor Discovery) Fuzzing (UDP:5678)")
    log("=" * 60)

    MNDP_PORT = PORTS["mndp"]  # 5678

    # MNDP uses TLV (Type-Length-Value) format
    # Type: 2 bytes, Length: 2 bytes, Value: variable

    def make_tlv(tlv_type, value):
        """Create a single MNDP TLV."""
        if isinstance(value, str):
            value = value.encode("utf-8")
        return struct.pack(">HH", tlv_type, len(value)) + value

    # Known MNDP TLV types:
    # 0x0001: MAC address
    # 0x0005: Identity
    # 0x0007: Version
    # 0x0008: Platform
    # 0x000A: Uptime
    # 0x000B: Software ID
    # 0x000C: Board name
    # 0x000E: IPv6 address
    # 0x000F: Interface name
    # 0x0010: IPv4 address

    # Normal MNDP discovery packet
    def _test_normal():
        # Just send a minimal MNDP-like packet
        payload = make_tlv(0x0001, b"\x00\x0C\x42\x00\x00\x01")  # fake MAC
        resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
        return (f"Normal MNDP: {len(resp)} bytes response",
                {"response_size": len(resp),
                 "response_hex": resp.hex()[:200] if resp else ""})
    run_test("mndp", "normal_tlv",
             "Send normal MNDP TLV packet", _test_normal)

    # Oversized TLV value
    for size_name, size in [("1KB", 1024), ("10KB", 10240), ("60KB", 60000)]:
        def _test(sz=size, sn=size_name):
            payload = make_tlv(0x0005, b"A" * sz)
            resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
            return (f"Oversized TLV ({sn}): {len(resp)} bytes",
                    {"tlv_value_size": sz, "response_size": len(resp)})
        run_test("mndp", f"oversized_tlv_{size_name}",
                 f"MNDP TLV with {size_name} value", _test)

    # Invalid type fields
    for tlv_type in [0x0000, 0x0002, 0x0003, 0x00FF, 0x0100, 0x7FFF, 0xFFFF]:
        def _test(t=tlv_type):
            payload = make_tlv(t, b"test_value")
            resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
            return (f"Type 0x{t:04X}: {len(resp)} bytes",
                    {"tlv_type": t, "response_size": len(resp)})
        run_test("mndp", f"invalid_type_0x{tlv_type:04X}",
                 f"MNDP TLV with type=0x{tlv_type:04X}", _test)

    # Zero-length TLV value
    def _test_zero_len():
        payload = struct.pack(">HH", 0x0005, 0)  # type + length=0 + no value
        resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
        return (f"Zero-length TLV: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("mndp", "zero_length_tlv",
             "MNDP TLV with length=0", _test_zero_len)

    # TLV length mismatch (says 1000, provide 5)
    def _test_len_mismatch():
        payload = struct.pack(">HH", 0x0005, 1000) + b"hello"
        resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
        return (f"Length mismatch TLV: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("mndp", "length_mismatch",
             "MNDP TLV claiming 1000 bytes but only 5 sent", _test_len_mismatch)

    # Multiple TLVs in one packet
    def _test_multi_tlv():
        payload = b""
        for i in range(20):
            payload += make_tlv(0x0005, f"identity_{i}")
        resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
        return (f"Multi-TLV (20): {len(resp)} bytes",
                {"tlv_count": 20, "response_size": len(resp)})
    run_test("mndp", "multi_tlv_20",
             "MNDP packet with 20 TLV entries", _test_multi_tlv)

    # Random binary as MNDP packet
    for size in [100, 1000, 10000]:
        def _test(sz=size):
            payload = os.urandom(sz)
            resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
            return (f"Random {sz}B: {len(resp)} bytes",
                    {"payload_size": sz, "response_size": len(resp)})
        run_test("mndp", f"random_binary_{size}B",
                 f"Send {size} random bytes to MNDP port", _test)

    # All-zero MNDP packet
    def _test_zeros():
        payload = b"\x00" * 100
        resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
        return (f"All-zeros: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("mndp", "all_zeros",
             "Send 100 zero bytes to MNDP port", _test_zeros)

    # Format strings in TLV value
    def _test_fmt():
        payload = make_tlv(0x0005, b"%s%n%x" * 50)
        resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
        return (f"Format strings in TLV: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("mndp", "format_strings",
             "MNDP TLV with format string specifiers", _test_fmt)

    # Null bytes in TLV value
    def _test_nulls():
        payload = make_tlv(0x0005, b"test\x00null\x00bytes")
        resp = udp_send_recv(MNDP_PORT, payload, timeout=3)
        return (f"Null bytes in TLV: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("mndp", "null_bytes_in_value",
             "MNDP TLV with null bytes in value", _test_nulls)


# ---------------------------------------------------------------------------
# Category 3: FTP Protocol Fuzzer (~25 tests) -- TCP port 21
# ---------------------------------------------------------------------------

def fuzz_ftp():
    log("=" * 60)
    log("Category 3: FTP Protocol Fuzzing (TCP:21)")
    log("=" * 60)

    FTP_PORT = PORTS["ftp"]  # 21

    def ftp_send_cmd(cmd, timeout=5):
        """Connect to FTP, read banner, send command, read response."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((TARGET, FTP_PORT))
            # Read banner
            banner = b""
            try:
                banner = s.recv(4096)
            except socket.timeout:
                pass
            # Send command
            if isinstance(cmd, str):
                cmd = cmd.encode("utf-8", errors="replace")
            if not cmd.endswith(b"\r\n"):
                cmd += b"\r\n"
            s.sendall(cmd)
            time.sleep(0.3)
            resp = b""
            try:
                resp = s.recv(4096)
            except socket.timeout:
                pass
            s.close()
            return banner, resp
        except Exception as e:
            return b"", f"ERROR:{e}".encode()

    # Long commands
    for size_name, size in [("1KB", 1024), ("10KB", 10240)]:
        def _test(sz=size, sn=size_name):
            banner, resp = ftp_send_cmd("USER " + "A" * sz)
            resp_text = resp.decode("utf-8", errors="replace")[:300]
            return (f"Long USER ({sn}): {resp_text[:80]}",
                    {"command_size": sz, "banner": banner.decode("utf-8", errors="replace")[:200],
                     "response": resp_text, "response_size": len(resp)})
        run_test("ftp", f"long_user_{size_name}",
                 f"FTP USER command with {size_name} argument", _test)

    # Invalid FTP verbs
    for verb in ["AAAA", "ZZZZ", "123456", "", "A" * 100, "GET", "POST",
                  "\x00\x01\x02", "USER\x00evil"]:
        def _test(v=verb):
            banner, resp = ftp_send_cmd(v + " test")
            resp_text = resp.decode("utf-8", errors="replace")[:300]
            return (f"Verb '{v[:20]}': {resp_text[:80]}",
                    {"verb": v[:50], "response": resp_text})
        safe_name = verb[:10].replace("\x00", "null").replace(" ", "_")
        run_test("ftp", f"invalid_verb_{safe_name}",
                 f"FTP invalid verb: {safe_name}", _test)

    # CRLF injection in arguments
    def _test_crlf():
        banner, resp = ftp_send_cmd("USER admin\r\nPASS TestPass123\r\n")
        resp_text = resp.decode("utf-8", errors="replace")[:300]
        return (f"CRLF injection: {resp_text[:80]}",
                {"response": resp_text})
    run_test("ftp", "crlf_injection",
             "CRLF injection in FTP USER argument", _test_crlf)

    # Format strings in USER/PASS/CWD/RETR
    for cmd_name, cmd in [("USER", "USER %s%s%s%n%n"),
                           ("PASS", "PASS %n%n%n%x%x"),
                           ("CWD", "CWD %s%s%s%n%n%n"),
                           ("RETR", "RETR %x%x%x%x%x"),
                           ("STOR", "STOR %n%n%n%n")]:
        def _test(c=cmd):
            banner, resp = ftp_send_cmd(c)
            resp_text = resp.decode("utf-8", errors="replace")[:300]
            return (f"Format string {cmd_name}: {resp_text[:80]}",
                    {"command": c, "response": resp_text})
        run_test("ftp", f"format_string_{cmd_name}",
                 f"Format strings in FTP {cmd_name}", _test)

    # Path traversal in CWD
    def _test_traversal():
        # Login first, then CWD
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, FTP_PORT))
            s.recv(4096)  # banner
            s.sendall(b"USER admin\r\n")
            s.recv(4096)
            s.sendall(b"PASS TestPass123\r\n")
            s.recv(4096)
            s.sendall(b"CWD ../../../etc\r\n")
            time.sleep(0.3)
            resp = s.recv(4096)
            s.close()
            resp_text = resp.decode("utf-8", errors="replace")[:300]
            return (f"CWD traversal: {resp_text[:80]}",
                    {"response": resp_text})
        except Exception as e:
            return (f"Error: {e}", {"error": str(e), "anomaly": True})
    run_test("ftp", "cwd_traversal",
             "FTP CWD path traversal (../../../etc)", _test_traversal)

    # Binary data as FTP command
    def _test_binary():
        banner, resp = ftp_send_cmd(os.urandom(500))
        return (f"Binary FTP cmd: {len(resp)} bytes response",
                {"response_size": len(resp)})
    run_test("ftp", "binary_command",
             "Send 500 bytes of random binary as FTP command", _test_binary)

    # Very long password
    def _test_long_pass():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, FTP_PORT))
            s.recv(4096)
            s.sendall(b"USER admin\r\n")
            s.recv(4096)
            s.sendall(("PASS " + "A" * 10000 + "\r\n").encode())
            time.sleep(0.3)
            resp = s.recv(4096)
            s.close()
            return (f"Long PASS: {resp.decode('utf-8', errors='replace')[:80]}",
                    {"password_length": 10000, "response": resp.decode("utf-8", errors="replace")[:300]})
        except Exception as e:
            return (f"Error: {e}", {"error": str(e)})
    run_test("ftp", "long_password_10KB",
             "FTP PASS with 10KB password", _test_long_pass)

    # Rapid FTP connections
    def _test_rapid_ftp():
        success, fail = 0, 0
        for _ in range(30):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((TARGET, FTP_PORT))
                s.recv(4096)
                s.sendall(b"QUIT\r\n")
                s.close()
                success += 1
            except:
                fail += 1
        return (f"30 rapid FTP: {success} ok, {fail} fail",
                {"success": success, "fail": fail, "anomaly": fail > 10})
    run_test("ftp", "rapid_connect_30",
             "30 rapid FTP connect/QUIT cycles", _test_rapid_ftp)


# ---------------------------------------------------------------------------
# Category 4: DNS Fuzzer (~25 tests) -- UDP port 53
# ---------------------------------------------------------------------------

def fuzz_dns():
    log("=" * 60)
    log("Category 4: DNS Fuzzing (UDP:53)")
    log("=" * 60)

    DNS_PORT = 53

    def make_dns_query(name, qtype=1, qclass=1, txid=None, flags=0x0100):
        """Build a minimal DNS query packet."""
        if txid is None:
            txid = random.randint(0, 65535)
        # Header: ID, Flags, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
        # Question: QNAME + QTYPE + QCLASS
        qname = b""
        if isinstance(name, str):
            for label in name.split("."):
                label_bytes = label.encode("utf-8", errors="replace")
                qname += bytes([len(label_bytes)]) + label_bytes
            qname += b"\x00"
        elif isinstance(name, bytes):
            qname = name
        question = qname + struct.pack(">HH", qtype, qclass)
        return header + question

    # Normal DNS query
    def _test_normal():
        payload = make_dns_query("router.local", qtype=1)
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"Normal A query: {len(resp)} bytes",
                {"response_size": len(resp),
                 "response_hex": resp.hex()[:200] if resp else ""})
    run_test("dns", "normal_a_query",
             "Normal DNS A query for router.local", _test_normal)

    # Oversized query name
    for size in [255, 1000, 4000]:
        def _test(sz=size):
            # Build oversized label
            name = b"\x3f" + b"A" * 63  # max label = 63 chars
            labels = (name * (sz // 64 + 1))[:sz]
            labels += b"\x00"
            header = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
            question = labels + struct.pack(">HH", 1, 1)
            payload = header + question
            resp = udp_send_recv(DNS_PORT, payload, timeout=3)
            return (f"Oversized name ({sz}): {len(resp)} bytes",
                    {"name_size": sz, "response_size": len(resp)})
        run_test("dns", f"oversized_name_{size}",
                 f"DNS query with {size}-byte name", _test)

    # Invalid opcodes (opcode is bits 1-4 of flags byte 1)
    for opcode in [1, 2, 3, 4, 5, 15]:  # IQuery, Status, reserved, Notify, Update, reserved
        def _test(op=opcode):
            flags = (op << 11)  # opcode in bits 11-14
            payload = make_dns_query("test.local", flags=flags)
            resp = udp_send_recv(DNS_PORT, payload, timeout=3)
            return (f"Opcode {op}: {len(resp)} bytes",
                    {"opcode": op, "response_size": len(resp),
                     "response_hex": resp.hex()[:100] if resp else ""})
        run_test("dns", f"opcode_{opcode}",
                 f"DNS query with opcode={opcode}", _test)

    # Label compression loops (pointer loop)
    def _test_comp_loop():
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # Compression pointer at offset 12 pointing to itself (offset 12 = 0xC00C)
        question = b"\xC0\x0C" + struct.pack(">HH", 1, 1)
        payload = header + question
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"Compression loop: {len(resp)} bytes",
                {"response_size": len(resp),
                 "response_hex": resp.hex()[:200] if resp else ""})
    run_test("dns", "compression_loop",
             "DNS query with label compression pointer loop", _test_comp_loop)

    # Mutual compression loop
    def _test_mutual_loop():
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # Two pointers pointing to each other
        question = b"\xC0\x0E\xC0\x0C" + struct.pack(">HH", 1, 1)
        payload = header + question
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"Mutual loop: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("dns", "mutual_compression_loop",
             "DNS query with mutual label compression loop", _test_mutual_loop)

    # EDNS0 with large payload size
    def _test_edns():
        base = make_dns_query("test.local")
        # EDNS0 OPT RR: name=0x00, type=41(OPT), UDP_size=65535, ext_rcode=0, version=0, flags=0x8000(DO), rdlength=0
        # Update ARCOUNT to 1
        base = base[:10] + struct.pack(">H", 1) + base[12:]
        opt_rr = b"\x00" + struct.pack(">HH", 41, 65535) + struct.pack(">BBH", 0, 0, 0x8000) + struct.pack(">H", 0)
        payload = base + opt_rr
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"EDNS0 64KB: {len(resp)} bytes",
                {"response_size": len(resp),
                 "response_hex": resp.hex()[:200] if resp else ""})
    run_test("dns", "edns0_large_payload",
             "DNS query with EDNS0 OPT advertising 65535 UDP payload", _test_edns)

    # Truncated DNS packet (just header, no question)
    def _test_truncated():
        payload = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # header only
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"Truncated (header only): {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("dns", "truncated_header_only",
             "DNS packet with header but no question section", _test_truncated)

    # Random binary as DNS
    def _test_random():
        payload = os.urandom(512)
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"Random 512B: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("dns", "random_binary_512B",
             "Send 512 random bytes to DNS port", _test_random)

    # QDCOUNT=65535
    def _test_qdcount():
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 65535, 0, 0, 0)
        question = b"\x04test\x05local\x00" + struct.pack(">HH", 1, 1)
        payload = header + question
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"QDCOUNT=65535: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("dns", "qdcount_65535",
             "DNS query claiming 65535 questions with only 1 provided", _test_qdcount)

    # NULL bytes in query name
    def _test_null_name():
        payload = make_dns_query("test\x00evil.local")
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"Null in name: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("dns", "null_in_name",
             "DNS query with null byte in name", _test_null_name)

    # AXFR request (zone transfer)
    def _test_axfr():
        payload = make_dns_query("local", qtype=252)  # AXFR
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"AXFR query: {len(resp)} bytes",
                {"response_size": len(resp),
                 "response_hex": resp.hex()[:200] if resp else ""})
    run_test("dns", "axfr_query",
             "DNS AXFR (zone transfer) query", _test_axfr)

    # ANY query (deprecated but still processed by many servers)
    def _test_any():
        payload = make_dns_query("router.local", qtype=255)
        resp = udp_send_recv(DNS_PORT, payload, timeout=3)
        return (f"ANY query: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("dns", "any_query",
             "DNS ANY query for router.local", _test_any)


# ---------------------------------------------------------------------------
# Category 5: SNMP Fuzzer (~25 tests) -- UDP port 161
# ---------------------------------------------------------------------------

def fuzz_snmp():
    log("=" * 60)
    log("Category 5: SNMP Fuzzing (UDP:161)")
    log("=" * 60)

    SNMP_PORT = PORTS["snmp"]  # 161

    # ASN.1 BER encoding helpers
    def asn1_length(length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return b"\x81" + bytes([length])
        elif length < 0x10000:
            return b"\x82" + struct.pack(">H", length)
        else:
            return b"\x84" + struct.pack(">I", length)

    def asn1_integer(value):
        """Encode ASN.1 INTEGER."""
        if value == 0:
            return b"\x02\x01\x00"
        # Simple encoding for small positive values
        val_bytes = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True) if value >= 0 else b"\x00"
        return b"\x02" + asn1_length(len(val_bytes)) + val_bytes

    def asn1_octet_string(value):
        """Encode ASN.1 OCTET STRING."""
        if isinstance(value, str):
            value = value.encode("utf-8")
        return b"\x04" + asn1_length(len(value)) + value

    def asn1_oid(oid_str):
        """Encode ASN.1 OID from dotted string."""
        parts = [int(x) for x in oid_str.split(".")]
        if len(parts) < 2:
            parts = [1, 3, 6, 1, 2, 1, 1, 1, 0]
        encoded = bytes([40 * parts[0] + parts[1]])
        for p in parts[2:]:
            if p < 128:
                encoded += bytes([p])
            else:
                # Multi-byte encoding
                tmp = []
                while p > 0:
                    tmp.append(p & 0x7F)
                    p >>= 7
                tmp.reverse()
                for i in range(len(tmp) - 1):
                    tmp[i] |= 0x80
                encoded += bytes(tmp)
        return b"\x06" + asn1_length(len(encoded)) + encoded

    def asn1_null():
        return b"\x05\x00"

    def asn1_sequence(content):
        return b"\x30" + asn1_length(len(content)) + content

    def make_snmp_get(community="public", oid="[REDACTED-IP].[REDACTED-IP].0", version=0):
        """Build an SNMPv1/v2c GetRequest."""
        # VarBind: SEQUENCE { OID, NULL }
        varbind = asn1_sequence(asn1_oid(oid) + asn1_null())
        varbind_list = asn1_sequence(varbind)
        # PDU: GetRequest (0xA0)
        pdu_content = (asn1_integer(1) +          # request-id
                       asn1_integer(0) +          # error-status
                       asn1_integer(0) +          # error-index
                       varbind_list)
        pdu = b"\xA0" + asn1_length(len(pdu_content)) + pdu_content
        # Message: SEQUENCE { version, community, PDU }
        msg_content = asn1_integer(version) + asn1_octet_string(community) + pdu
        return asn1_sequence(msg_content)

    # Normal SNMP GET
    def _test_normal():
        payload = make_snmp_get("public")
        resp = udp_send_recv(SNMP_PORT, payload, timeout=3)
        return (f"Normal GET: {len(resp)} bytes",
                {"response_size": len(resp),
                 "response_hex": resp.hex()[:200] if resp else ""})
    run_test("snmp", "normal_get",
             "Normal SNMPv1 GET sysDescr with 'public' community", _test_normal)

    # Oversized community strings
    for size_name, size in [("256B", 256), ("1KB", 1024), ("10KB", 10240)]:
        def _test(sz=size, sn=size_name):
            payload = make_snmp_get("A" * sz)
            resp = udp_send_recv(SNMP_PORT, payload, timeout=3)
            return (f"Community {sn}: {len(resp)} bytes",
                    {"community_size": sz, "response_size": len(resp)})
        run_test("snmp", f"community_{size_name}",
                 f"SNMP GET with {size_name} community string", _test)

    # Invalid PDU types
    for pdu_type in [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xFF]:
        def _test(pt=pdu_type):
            # Build with custom PDU type
            varbind = asn1_sequence(asn1_oid("[REDACTED-IP].[REDACTED-IP].0") + asn1_null())
            varbind_list = asn1_sequence(varbind)
            pdu_content = asn1_integer(1) + asn1_integer(0) + asn1_integer(0) + varbind_list
            pdu = bytes([pt]) + asn1_length(len(pdu_content)) + pdu_content
            msg_content = asn1_integer(0) + asn1_octet_string("public") + pdu
            payload = asn1_sequence(msg_content)
            resp = udp_send_recv(SNMP_PORT, payload, timeout=3)
            return (f"PDU 0x{pt:02X}: {len(resp)} bytes",
                    {"pdu_type": pt, "response_size": len(resp)})
        run_test("snmp", f"pdu_type_0x{pdu_type:02X}",
                 f"SNMP with PDU type 0x{pdu_type:02X}", _test)

    # GetBulk with extreme repetitions (SNMPv2c, PDU type 0xA5)
    def _test_getbulk():
        varbind = asn1_sequence(asn1_oid("[REDACTED-IP].2.1") + asn1_null())
        varbind_list = asn1_sequence(varbind)
        # GetBulk: non-repeaters=0, max-repetitions=10000
        pdu_content = (asn1_integer(1) +      # request-id
                       asn1_integer(0) +      # non-repeaters
                       asn1_integer(10000) +  # max-repetitions
                       varbind_list)
        pdu = b"\xA5" + asn1_length(len(pdu_content)) + pdu_content
        msg_content = asn1_integer(1) + asn1_octet_string("public") + pdu  # version=1 for v2c
        payload = asn1_sequence(msg_content)
        resp = udp_send_recv(SNMP_PORT, payload, timeout=5)
        return (f"GetBulk max-rep=10000: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("snmp", "getbulk_extreme",
             "SNMP GetBulk with max-repetitions=10000", _test_getbulk)

    # Malformed ASN.1 -- length says 1000 but only 10 bytes
    def _test_malformed():
        payload = b"\x30\x82\x03\xE8" + b"A" * 10  # SEQUENCE claiming 1000 bytes
        resp = udp_send_recv(SNMP_PORT, payload, timeout=3)
        return (f"Malformed ASN.1: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("snmp", "malformed_asn1_length",
             "SNMP with ASN.1 length mismatch (claims 1000, sends 10)", _test_malformed)

    # Random binary as SNMP
    def _test_random():
        payload = os.urandom(500)
        resp = udp_send_recv(SNMP_PORT, payload, timeout=3)
        return (f"Random 500B: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("snmp", "random_binary",
             "Send 500 random bytes to SNMP port", _test_random)

    # Format strings in community
    def _test_fmt():
        payload = make_snmp_get("%s%n%x" * 20)
        resp = udp_send_recv(SNMP_PORT, payload, timeout=3)
        return (f"Format string community: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("snmp", "format_string_community",
             "SNMP GET with format strings as community", _test_fmt)

    # SNMPv3 (version=3)
    def _test_v3():
        payload = make_snmp_get("public", version=3)
        resp = udp_send_recv(SNMP_PORT, payload, timeout=3)
        return (f"SNMPv3: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("snmp", "version_3",
             "SNMP GET with version=3 (wrong message format)", _test_v3)

    # Deeply nested ASN.1 sequences
    def _test_nested():
        inner = asn1_null()
        for _ in range(50):
            inner = asn1_sequence(inner)
        resp = udp_send_recv(SNMP_PORT, inner, timeout=3)
        return (f"50-deep nested SEQUENCE: {len(resp)} bytes",
                {"response_size": len(resp), "nesting_depth": 50})
    run_test("snmp", "nested_asn1_50",
             "50 levels of nested ASN.1 SEQUENCE", _test_nested)

    # Walk request with many OIDs
    def _test_many_oids():
        varbinds = b""
        for i in range(50):
            varbinds += asn1_sequence(asn1_oid(f"[REDACTED-IP].2.1.1.{i+1}.0") + asn1_null())
        varbind_list = asn1_sequence(varbinds)
        pdu_content = asn1_integer(1) + asn1_integer(0) + asn1_integer(0) + varbind_list
        pdu = b"\xA0" + asn1_length(len(pdu_content)) + pdu_content
        msg_content = asn1_integer(0) + asn1_octet_string("public") + pdu
        payload = asn1_sequence(msg_content)
        resp = udp_send_recv(SNMP_PORT, payload, timeout=5)
        return (f"50 OIDs in one GET: {len(resp)} bytes",
                {"oid_count": 50, "response_size": len(resp)})
    run_test("snmp", "many_oids_50",
             "SNMP GET with 50 OIDs in one request", _test_many_oids)


# ---------------------------------------------------------------------------
# Category 6: Telnet Fuzzer (~20 tests) -- TCP port 23
# ---------------------------------------------------------------------------

def fuzz_telnet():
    log("=" * 60)
    log("Category 6: Telnet Fuzzing (TCP:23)")
    log("=" * 60)

    TELNET_PORT = PORTS["telnet"]  # 23

    def telnet_send_recv(data, timeout=5, recv_size=4096):
        """Connect to telnet, optionally read banner, send data."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((TARGET, TELNET_PORT))
            time.sleep(0.5)
            # Read any initial data (banner, IAC negotiations)
            initial = b""
            try:
                initial = s.recv(recv_size)
            except socket.timeout:
                pass
            if isinstance(data, str):
                data = data.encode("utf-8", errors="replace")
            s.sendall(data)
            time.sleep(0.5)
            resp = b""
            try:
                resp = s.recv(recv_size)
            except socket.timeout:
                pass
            s.close()
            return initial, resp
        except Exception as e:
            return b"", f"ERROR:{e}".encode()

    # Long line
    for size_name, size in [("1KB", 1024), ("10KB", 10240), ("64KB", 65536)]:
        def _test(sz=size, sn=size_name):
            initial, resp = telnet_send_recv("A" * sz + "\r\n")
            return (f"Long line ({sn}): {len(resp)} bytes",
                    {"line_size": sz, "response_size": len(resp),
                     "initial_size": len(initial)})
        run_test("telnet", f"long_line_{size_name}",
                 f"Send {size_name} single line to telnet", _test)

    # Binary data
    def _test_binary():
        initial, resp = telnet_send_recv(os.urandom(500))
        return (f"Binary data: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("telnet", "binary_data",
             "Send 500 random binary bytes to telnet", _test_binary)

    # IAC sequence flood
    def _test_iac_flood():
        # IAC = 0xFF, followed by command byte
        # DO = 0xFD, DONT = 0xFE, WILL = 0xFB, WONT = 0xFC
        iac_data = b""
        for cmd in [0xFB, 0xFC, 0xFD, 0xFE]:
            for opt in range(256):
                iac_data += bytes([0xFF, cmd, opt])
        # Send first 3000 bytes (1000 IAC sequences)
        iac_data = iac_data[:3000]
        initial, resp = telnet_send_recv(iac_data)
        return (f"IAC flood (1000 seqs): {len(resp)} bytes",
                {"iac_sequences": 1000, "response_size": len(resp)})
    run_test("telnet", "iac_flood",
             "Send 1000 IAC negotiation sequences", _test_iac_flood)

    # Malformed IAC (0xFF followed by non-command byte)
    def _test_malformed_iac():
        data = b"\xFF\x00\xFF\x01\xFF\x02\xFF\x03"
        initial, resp = telnet_send_recv(data)
        return (f"Malformed IAC: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("telnet", "malformed_iac",
             "Malformed IAC sequences (0xFF + non-command bytes)", _test_malformed_iac)

    # Subnegotiation overflow
    def _test_subneg():
        # IAC SB (subneg start) = FF FA, option, data..., IAC SE (subneg end) = FF F0
        data = b"\xFF\xFA\x18"  # SB TERMINAL-TYPE
        data += b"A" * 10000   # oversized subnegotiation data
        data += b"\xFF\xF0"    # SE
        initial, resp = telnet_send_recv(data)
        return (f"Subneg overflow: {len(resp)} bytes",
                {"subneg_size": 10000, "response_size": len(resp)})
    run_test("telnet", "subneg_overflow_10KB",
             "Telnet subnegotiation with 10KB data", _test_subneg)

    # Rapid negotiation: many WILL/DO for same option
    def _test_rapid_neg():
        data = (b"\xFF\xFB\x01" * 100 +    # 100x WILL ECHO
                b"\xFF\xFD\x01" * 100)       # 100x DO ECHO
        initial, resp = telnet_send_recv(data)
        return (f"Rapid negotiation: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("telnet", "rapid_negotiation",
             "200 rapid WILL/DO ECHO negotiations", _test_rapid_neg)

    # Format strings
    def _test_fmt():
        initial, resp = telnet_send_recv("%s%n%x" * 100 + "\r\n")
        return (f"Format strings: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("telnet", "format_strings",
             "Send format string specifiers to telnet", _test_fmt)

    # Null bytes
    def _test_null():
        initial, resp = telnet_send_recv(b"\x00" * 1000)
        return (f"1000 nulls: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("telnet", "null_bytes_1000",
             "Send 1000 null bytes to telnet", _test_null)

    # Login with long username
    def _test_long_user():
        initial, resp = telnet_send_recv("A" * 10000 + "\r\n")
        return (f"Long username: {len(resp)} bytes",
                {"username_len": 10000, "response_size": len(resp)})
    run_test("telnet", "long_username_10KB",
             "Send 10KB username to telnet login", _test_long_user)

    # Rapid connect/disconnect
    def _test_rapid():
        success, fail = 0, 0
        for _ in range(30):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((TARGET, TELNET_PORT))
                s.close()
                success += 1
            except:
                fail += 1
        return (f"30 rapid: {success} ok, {fail} fail",
                {"success": success, "fail": fail, "anomaly": fail > 10})
    run_test("telnet", "rapid_connect_30",
             "30 rapid telnet connect/disconnect cycles", _test_rapid)

    # CTRL-C and break sequences
    def _test_break():
        data = b"\x03\x03\x03"  # CTRL-C
        data += b"\xFF\xF3"     # IAC BREAK
        data += b"\x1B[A\x1B[B\x1B[C\x1B[D"  # Arrow keys
        data += b"\x04"         # CTRL-D (EOF)
        initial, resp = telnet_send_recv(data)
        return (f"Break sequences: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("telnet", "break_sequences",
             "Send CTRL-C, BREAK, arrow keys, CTRL-D", _test_break)

    # Escape sequence injection
    def _test_escape():
        data = b"\x1B]0;evil-title\x07"  # Set window title
        data += b"\x1B[2J"               # Clear screen
        data += b"\x1B[31mREDTEXT\x1B[0m"  # Color codes
        initial, resp = telnet_send_recv(data)
        return (f"Escape sequences: {len(resp)} bytes",
                {"response_size": len(resp)})
    run_test("telnet", "escape_sequences",
             "Send terminal escape sequences (title, clear, color)", _test_escape)

    # HTTP on telnet port
    def _test_http():
        initial, resp = telnet_send_recv(f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n")
        return (f"HTTP on telnet: {len(resp)} bytes",
                {"response_size": len(resp),
                 "response_text": resp.decode("utf-8", errors="replace")[:200]})
    run_test("telnet", "http_on_telnet",
             "Send HTTP request to telnet port (protocol confusion)", _test_http)

    # Multiple lines rapid fire
    def _test_multiline():
        data = "\r\n".join([f"command_{i}" for i in range(100)]) + "\r\n"
        initial, resp = telnet_send_recv(data)
        return (f"100 rapid lines: {len(resp)} bytes",
                {"line_count": 100, "response_size": len(resp)})
    run_test("telnet", "rapid_100_lines",
             "Send 100 lines rapidly to telnet", _test_multiline)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 -- Multi-Service Raw Packet Fuzzer")
    log(f"Phase 7: Fuzzing -- Target: {TARGET}")
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

    # Run all categories
    categories = [
        ("Bandwidth-Test", fuzz_bandwidth_test),
        ("MNDP", fuzz_mndp),
        ("FTP", fuzz_ftp),
        ("DNS", fuzz_dns),
        ("SNMP", fuzz_snmp),
        ("Telnet", fuzz_telnet),
    ]

    for cat_name, cat_func in categories:
        log(f"\nStarting {cat_name} fuzzing...")
        try:
            cat_func()
        except Exception as e:
            log(f"{cat_name} error: {e}")
            traceback.print_exc()
            ec.add_test(
                category=cat_name.lower().replace("-", "_"),
                name=f"{cat_name.lower()}_error",
                description=f"Unhandled error in {cat_name} fuzzing",
                result=f"ERROR: {e}",
                details={"error": str(e), "traceback": traceback.format_exc()},
                anomaly=True,
            )

        # Inter-category health check
        health = check_router_alive()
        if not health.get("alive"):
            log(f"Router down after {cat_name}! Waiting...")
            wait_for_router(max_wait=120)
            time.sleep(5)

    # Summary
    if crash_events:
        ec.add_finding(
            severity="HIGH" if len(crash_events) >= 3 else "MEDIUM",
            title=f"Multi-service stability: {len(crash_events)} crash events",
            description=(
                f"Router became unresponsive {len(crash_events)} time(s) during "
                f"multi-service fuzzing across {global_test_count} test cases. "
                f"Events: {crash_events}"
            ),
            evidence_refs=["multi_service_fuzzer"],
            cwe="CWE-120",
        )

    # Pull logs and save
    ec.save("multi_service_fuzzer.json")
    ec.summary()

    log(f"\nTotal tests: {global_test_count}")
    log(f"Crash events: {len(crash_events)}")
    log(f"Findings: {len(ec.results['findings'])}")


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
