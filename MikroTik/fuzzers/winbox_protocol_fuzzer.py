#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- Winbox M2 Protocol Fuzzer
Phase 7: Fuzzing -- ~150 test cases targeting Winbox on port 8291.

Custom M2 protocol fuzzer.

M2 Frame Structure:
  - 2-byte big-endian length prefix + body
  - Body: sequence of typed key-value pairs
  - KV: 1 byte type | 3 bytes key_id (big-endian) | value (type-dependent)

Known M2 types:
  0x01: bool (1 byte: 0 or 1)
  0x08: u32 (4 bytes big-endian)
  0x09: u64 (8 bytes big-endian)
  0x10: string (4-byte length + content)
  0x18: message/nested (4-byte length + M2 body)
  0x20: raw/bytes (4-byte length + content)
  0x88: array of u32 (4-byte count + count*4 bytes)

Known key IDs:
  0xFF0001: SYS_TO (handler/destination)
  0xFF0002: SYS_FROM (source)
  0xFF0003: SYS_CMD (command)
  0xFF0005: SYS_TYPE
  0xFF0006: SYS_TAG
  0xFF0007: SYS_REQ_ID

Categories:
  1. Frame header fuzzing (~30)
  2. Key type fuzzing (~30)
  3. Key ID fuzzing (~20)
  4. Value fuzzing (~30)
  5. Routing/handler fuzzing (~20)
  6. Combination fuzzing (~20)

Target: [REDACTED-INTERNAL-IP]:8291, admin/TestPass123
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
WINBOX_PORT = PORTS["winbox"]   # 8291
ALIVE_CHECK_INTERVAL = 10
RECV_TIMEOUT = 5
CONNECT_TIMEOUT = 5

ec = EvidenceCollector("winbox_protocol_fuzzer.py", phase=7)
global_test_count = 0
crash_events = []

# ---------------------------------------------------------------------------
# M2 Protocol Helpers
# ---------------------------------------------------------------------------

# Type constants
M2_BOOL    = 0x01
M2_U32     = 0x08
M2_U64     = 0x09
M2_STRING  = 0x10
M2_MSG     = 0x18
M2_RAW     = 0x20
M2_BOOL_A  = 0x81
M2_U32_A   = 0x88
M2_STRING_A = 0x90

# System key IDs
SYS_TO     = 0xFF0001
SYS_FROM   = 0xFF0002
SYS_CMD    = 0xFF0003
SYS_TYPE   = 0xFF0005
SYS_TAG    = 0xFF0006
SYS_REQ_ID = 0xFF0007


def m2_kv_bool(key_id, value):
    """Create M2 bool KV pair."""
    return bytes([M2_BOOL]) + key_id.to_bytes(3, "big") + bytes([1 if value else 0])


def m2_kv_u32(key_id, value):
    """Create M2 u32 KV pair."""
    return bytes([M2_U32]) + key_id.to_bytes(3, "big") + struct.pack(">I", value & 0xFFFFFFFF)


def m2_kv_u64(key_id, value):
    """Create M2 u64 KV pair."""
    return bytes([M2_U64]) + key_id.to_bytes(3, "big") + struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def m2_kv_string(key_id, value):
    """Create M2 string KV pair."""
    if isinstance(value, str):
        value = value.encode("utf-8", errors="replace")
    return bytes([M2_STRING]) + key_id.to_bytes(3, "big") + struct.pack(">I", len(value)) + value


def m2_kv_raw(key_id, value):
    """Create M2 raw bytes KV pair."""
    return bytes([M2_RAW]) + key_id.to_bytes(3, "big") + struct.pack(">I", len(value)) + value


def m2_kv_msg(key_id, body):
    """Create M2 nested message KV pair."""
    return bytes([M2_MSG]) + key_id.to_bytes(3, "big") + struct.pack(">I", len(body)) + body


def m2_kv_raw_typed(type_byte, key_id, value_bytes):
    """Create a raw KV with explicit type byte and raw value bytes."""
    return bytes([type_byte]) + key_id.to_bytes(3, "big") + value_bytes


def m2_frame(body):
    """Wrap body in M2 frame (2-byte big-endian length prefix)."""
    return struct.pack(">H", len(body)) + body


def m2_frame_raw(length_value, body):
    """Create M2 frame with explicit (potentially wrong) length."""
    return struct.pack(">H", length_value & 0xFFFF) + body


def make_basic_request(sys_to=2, cmd=7):
    """Create a basic M2 request frame (e.g., to list handler)."""
    body = b""
    body += m2_kv_u32(SYS_TO, sys_to)
    body += m2_kv_u32(SYS_CMD, cmd)
    body += m2_kv_u32(SYS_REQ_ID, 1)
    body += m2_kv_u32(SYS_TAG, 0)
    return m2_frame(body)


def winbox_connect(timeout=CONNECT_TIMEOUT):
    """Open TCP connection to Winbox."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, WINBOX_PORT))
    return s


def winbox_send_recv(data, timeout=RECV_TIMEOUT, recv_size=8192):
    """Connect, send data, receive response, close."""
    s = winbox_connect(timeout=timeout)
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


def run_test(category, name, description, data):
    """Run a single test, record result, and periodically health-check."""
    global global_test_count
    global_test_count += 1

    try:
        response = winbox_send_recv(data, timeout=RECV_TIMEOUT)
        resp_preview = response.hex()[:300] if response else "(empty)"

        is_anomaly = len(response) == 0

        ec.add_test(
            category=category,
            name=name,
            description=description,
            result=f"Response: {len(response)} bytes",
            details={
                "payload_size": len(data),
                "payload_hex": data.hex()[:200],
                "response_size": len(response),
                "response_preview": resp_preview,
            },
            anomaly=is_anomaly,
        )

    except ConnectionRefusedError:
        ec.add_test(category, name, description,
                     "Connection refused", anomaly=True,
                     details={"error": "connection_refused"})
    except socket.timeout:
        ec.add_test(category, name, description,
                     "Connection timeout", anomaly=True,
                     details={"error": "timeout"})
    except Exception as e:
        ec.add_test(category, name, description,
                     f"Exception: {e}",
                     details={"error": str(e), "payload_hex": data.hex()[:200]},
                     anomaly=True)

    # Periodic health check
    if global_test_count % ALIVE_CHECK_INTERVAL == 0:
        health = check_router_alive()
        if not health.get("alive"):
            crash_events.append({
                "test_index": global_test_count,
                "test_name": name,
                "timestamp": time.strftime("%H:%M:%S"),
            })
            log(f"  ROUTER DOWN at test #{global_test_count} ({name})! Waiting...")
            ec.add_finding(
                severity="HIGH",
                title=f"Router crash during Winbox fuzzing: {name}",
                description=f"Router became unresponsive after Winbox fuzz test '{name}'. "
                            f"Payload size: {len(data)} bytes, hex: {data.hex()[:100]}",
                evidence_refs=[name],
                cwe="CWE-120",
            )
            wait_for_router(max_wait=120)
            time.sleep(5)


# ---------------------------------------------------------------------------
# Category 1: Frame Header Fuzzing (~30 tests)
# ---------------------------------------------------------------------------

def fuzz_frame_headers():
    log("=" * 60)
    log("Category 1: Frame Header Fuzzing")
    log("=" * 60)

    # Basic body for reuse
    basic_body = m2_kv_u32(SYS_TO, 2) + m2_kv_u32(SYS_CMD, 7)

    # Test: Frame size=0
    data = struct.pack(">H", 0)
    run_test("frame_header", "frame_size_zero",
             "M2 frame with length=0 (empty frame)", data)

    # Test: Frame size=1
    data = struct.pack(">H", 1) + b"\x00"
    run_test("frame_header", "frame_size_1",
             "M2 frame with length=1 (single zero byte body)", data)

    # Test: Frame size=2
    data = struct.pack(">H", 2) + b"\x00\x00"
    run_test("frame_header", "frame_size_2",
             "M2 frame with length=2", data)

    # Test: Frame size=65535 (max uint16)
    data = struct.pack(">H", 65535) + basic_body
    run_test("frame_header", "frame_size_65535",
             "M2 frame claiming length=65535 with short body", data)

    # Test: Frame size matches body exactly
    data = m2_frame(basic_body)
    run_test("frame_header", "frame_size_exact",
             "M2 frame with correct length", data)

    # Test: Size mismatch -- says 100, send 10
    data = m2_frame_raw(100, basic_body[:10])
    run_test("frame_header", "size_mismatch_100_10",
             "Frame says 100 bytes but only 10 sent", data)

    # Test: Size mismatch -- says 10, send 1000
    big_body = basic_body + b"\x00" * 1000
    data = m2_frame_raw(10, big_body)
    run_test("frame_header", "size_mismatch_10_1000",
             "Frame says 10 bytes but 1000+ sent", data)

    # Test: Size mismatch -- says 5, send 100
    data = m2_frame_raw(5, b"\x00" * 100)
    run_test("frame_header", "size_mismatch_5_100",
             "Frame says 5 but 100 bytes sent", data)

    # Test: Multiple frames back-to-back
    data = make_basic_request() + make_basic_request() + make_basic_request()
    run_test("frame_header", "three_frames_backtoback",
             "Three valid M2 frames sent consecutively", data)

    # Test: 20 frames rapid
    data = make_basic_request() * 20
    run_test("frame_header", "20_frames_rapid",
             "20 valid M2 frames in one send", data)

    # Test: Fragmented frame -- send first half, wait, send rest
    full_frame = make_basic_request()
    half = len(full_frame) // 2
    try:
        s = winbox_connect()
        s.sendall(full_frame[:half])
        time.sleep(1)
        s.sendall(full_frame[half:])
        time.sleep(0.5)
        resp = b""
        try:
            resp = s.recv(8192)
        except socket.timeout:
            pass
        s.close()
        ec.add_test("frame_header", "fragmented_frame",
                     "Send first half of frame, wait 1s, send rest",
                     f"Response: {len(resp)} bytes",
                     details={"first_half": half, "total": len(full_frame),
                              "response_size": len(resp)})
    except Exception as e:
        ec.add_test("frame_header", "fragmented_frame",
                     "Fragmented frame test", f"Error: {e}", anomaly=True)

    # Test: Send just the length bytes, nothing else
    try:
        s = winbox_connect()
        s.sendall(struct.pack(">H", 100))
        time.sleep(2)
        resp = b""
        try:
            resp = s.recv(8192)
        except socket.timeout:
            pass
        s.close()
        ec.add_test("frame_header", "length_only_no_body",
                     "Send only 2-byte length prefix (100) with no body",
                     f"Response: {len(resp)} bytes",
                     details={"response_size": len(resp)})
    except Exception as e:
        ec.add_test("frame_header", "length_only_no_body",
                     "Length-only test", f"Error: {e}", anomaly=True)

    # Test: Single byte (incomplete length)
    data = b"\x00"
    run_test("frame_header", "single_byte",
             "Send single byte (incomplete 2-byte length prefix)", data)

    # Test: Three bytes (length + 1 byte body or incomplete)
    data = b"\x00\x01\xFF"
    run_test("frame_header", "three_bytes",
             "Three bytes: length=1 + single 0xFF body", data)

    # Test: Extremely large frame body (64KB of garbage)
    data = m2_frame(os.urandom(60000))
    run_test("frame_header", "large_frame_60KB",
             "M2 frame with 60KB of random body", data)

    # Test: Little-endian length (protocol expects big-endian)
    body_len = len(basic_body)
    data = struct.pack("<H", body_len) + basic_body  # wrong endianness
    run_test("frame_header", "little_endian_length",
             "Frame with little-endian length (wrong byte order)", data)

    # Test: All-zero frame
    data = b"\x00" * 20
    run_test("frame_header", "all_zeros_20",
             "20 zero bytes (could be interpreted as length=0 + more zeros)", data)

    # Test: All-FF frame
    data = b"\xFF" * 20
    run_test("frame_header", "all_ff_20",
             "20 0xFF bytes (max-length frame + garbage)", data)

    # Test: HTTP request to Winbox port
    data = f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n".encode()
    run_test("frame_header", "http_on_winbox",
             "HTTP GET request to Winbox port (protocol confusion)", data)

    # Test: RouterOS API sentence to Winbox port
    from ros_api_boofuzz import make_sentence
    data = make_sentence(["/login"])
    run_test("frame_header", "api_on_winbox",
             "RouterOS API /login sentence to Winbox port", data)

    # Test: Frame with body = just the length of a KV but no actual KV
    data = m2_frame(b"\x08")  # starts like a u32 type but nothing follows
    run_test("frame_header", "truncated_kv_start",
             "Frame body is just a type byte (0x08) with no key_id or value", data)

    # Test: Nested frames (frame inside a frame)
    inner = make_basic_request()
    data = m2_frame(inner)
    run_test("frame_header", "nested_frame",
             "M2 frame wrapping another complete M2 frame", data)

    # Test: Empty body after valid length
    data = struct.pack(">H", 0)
    run_test("frame_header", "zero_length_frame_only",
             "Frame with length=0 and no body bytes", data)

    # Test: Abrupt close after partial frame
    try:
        s = winbox_connect()
        s.sendall(struct.pack(">H", 50))
        s.sendall(b"\x08\xFF\x00\x01")  # partial KV
        time.sleep(0.5)
        s.close()
        ec.add_test("frame_header", "abrupt_close_partial",
                     "Send partial frame then close connection",
                     "Connection closed mid-frame")
    except Exception as e:
        ec.add_test("frame_header", "abrupt_close_partial",
                     "Abrupt close test", f"Error: {e}", anomaly=True)


# ---------------------------------------------------------------------------
# Category 2: Key Type Fuzzing (~30 tests)
# ---------------------------------------------------------------------------

def fuzz_key_types():
    log("=" * 60)
    log("Category 2: Key Type Fuzzing")
    log("=" * 60)

    key_id = 0x000001  # generic key ID

    # Test all type bytes in interesting ranges
    # Known types: 0x01, 0x08, 0x09, 0x10, 0x18, 0x20, 0x81, 0x88, 0x90
    # Test undocumented/invalid types

    interesting_types = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0F, 0x10, 0x11, 0x17, 0x18,
        0x19, 0x1F, 0x20, 0x21, 0x28, 0x30, 0x40, 0x50,
        0x60, 0x70, 0x80, 0x81, 0x88, 0x90, 0xA0, 0xB0,
        0xC0, 0xD0, 0xE0, 0xF0, 0xFE, 0xFF,
    ]

    # For each type, send a frame with that type byte and generic value
    # Use 4 bytes of value data (works for u32, truncated for smaller, partial for larger)
    dummy_value = struct.pack(">I", 0x41414141)

    for type_byte in interesting_types:
        kv = bytes([type_byte]) + key_id.to_bytes(3, "big") + dummy_value
        data = m2_frame(kv)
        run_test("key_type", f"type_0x{type_byte:02X}",
                 f"KV with type byte 0x{type_byte:02X} and dummy u32 value",
                 data)

    # Test: Type byte with no following key_id or value
    for type_byte in [0x01, 0x08, 0x10, 0x18]:
        kv = bytes([type_byte])
        data = m2_frame(kv)
        run_test("key_type", f"type_0x{type_byte:02X}_no_key",
                 f"Type byte 0x{type_byte:02X} alone (no key_id, no value)", data)


# ---------------------------------------------------------------------------
# Category 3: Key ID Fuzzing (~20 tests)
# ---------------------------------------------------------------------------

def fuzz_key_ids():
    log("=" * 60)
    log("Category 3: Key ID Fuzzing")
    log("=" * 60)

    # Known system key IDs use 0xFF00xx range
    test_ids = [
        (0x000000, "id_000000"),
        (0x000001, "id_000001"),
        (0x000002, "id_000002"),
        (0x000010, "id_000010"),
        (0x000100, "id_000100"),
        (0x001000, "id_001000"),
        (0x010000, "id_010000"),
        (0x100000, "id_100000"),
        (0x7FFFFF, "id_7FFFFF"),
        (0x800000, "id_800000"),
        (0xFEFFFF, "id_FEFFFF"),
        (0xFF0000, "id_FF0000"),
        (0xFF0001, "id_SYS_TO"),
        (0xFF0002, "id_SYS_FROM"),
        (0xFF0003, "id_SYS_CMD"),
        (0xFF0005, "id_SYS_TYPE"),
        (0xFF0006, "id_SYS_TAG"),
        (0xFF0007, "id_SYS_REQ_ID"),
        (0xFFFF00, "id_FFFF00"),
        (0xFFFFFF, "id_FFFFFF"),
    ]

    for key_id, name in test_ids:
        body = m2_kv_u32(key_id, 0x41414141)
        data = m2_frame(body)
        run_test("key_id", f"keyid_{name}",
                 f"U32 KV with key_id=0x{key_id:06X}",
                 data)


# ---------------------------------------------------------------------------
# Category 4: Value Fuzzing (~30 tests)
# ---------------------------------------------------------------------------

def fuzz_values():
    log("=" * 60)
    log("Category 4: Value Fuzzing")
    log("=" * 60)

    # --- String type (0x10) value fuzzing ---

    # String with length=0
    body = bytes([M2_STRING]) + SYS_TO.to_bytes(3, "big") + struct.pack(">I", 0)
    data = m2_frame(body)
    run_test("value_fuzz", "string_len_0",
             "String KV with length=0 (empty string)", data)

    # String with length=65535
    content = b"A" * 65535
    body = bytes([M2_STRING]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", 65535) + content
    data = m2_frame(body)
    run_test("value_fuzz", "string_len_65535",
             "String KV with length=65535 (64KB string)", data)

    # String length mismatch (says 1000, send 10)
    body = bytes([M2_STRING]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", 1000) + b"A" * 10
    data = m2_frame(body)
    run_test("value_fuzz", "string_len_mismatch",
             "String KV claiming length=1000 but only 10 bytes", data)

    # String with null bytes
    content = b"hello\x00world\x00evil"
    body = bytes([M2_STRING]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", len(content)) + content
    data = m2_frame(body)
    run_test("value_fuzz", "string_null_bytes",
             "String KV containing embedded null bytes", data)

    # String with binary data
    content = bytes(range(256))
    body = bytes([M2_STRING]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", len(content)) + content
    data = m2_frame(body)
    run_test("value_fuzz", "string_all_bytes",
             "String KV containing all 256 byte values", data)

    # String with format strings
    content = b"%s%s%s%s%n%n%n%x%x%x"
    body = bytes([M2_STRING]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", len(content)) + content
    data = m2_frame(body)
    run_test("value_fuzz", "string_format_strings",
             "String KV with format string specifiers", data)

    # --- U32 type (0x08) value fuzzing ---

    # U32 = 0
    data = m2_frame(m2_kv_u32(0x000001, 0))
    run_test("value_fuzz", "u32_zero", "U32 KV with value=0", data)

    # U32 = 0xFFFFFFFF
    data = m2_frame(m2_kv_u32(0x000001, 0xFFFFFFFF))
    run_test("value_fuzz", "u32_max", "U32 KV with value=0xFFFFFFFF", data)

    # U32 = 0x80000000 (sign bit)
    data = m2_frame(m2_kv_u32(0x000001, 0x80000000))
    run_test("value_fuzz", "u32_signbit", "U32 KV with value=0x80000000 (sign bit)", data)

    # U32 truncated (only 2 bytes of value)
    body = bytes([M2_U32]) + (0x000001).to_bytes(3, "big") + b"\xFF\xFF"
    data = m2_frame(body)
    run_test("value_fuzz", "u32_truncated_2bytes",
             "U32 KV with only 2 bytes of value (truncated)", data)

    # U32 with extra bytes
    body = bytes([M2_U32]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", 42) + b"\xDE\xAD"
    data = m2_frame(body)
    run_test("value_fuzz", "u32_extra_bytes",
             "U32 KV with 2 extra trailing bytes", data)

    # --- Nested message (0x18) value fuzzing ---

    # Empty nested message
    body = bytes([M2_MSG]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", 0)
    data = m2_frame(body)
    run_test("value_fuzz", "nested_empty",
             "Nested message KV with length=0 (empty)", data)

    # Deeply nested messages (10 levels)
    inner = m2_kv_u32(0x000001, 42)
    for _ in range(10):
        inner = m2_kv_msg(0x000001, inner)
    data = m2_frame(inner)
    run_test("value_fuzz", "nested_10_levels",
             "Nested message 10 levels deep", data)

    # Deeply nested messages (50 levels)
    inner = m2_kv_u32(0x000001, 42)
    for _ in range(50):
        inner = m2_kv_msg(0x000001, inner)
    data = m2_frame(inner)
    run_test("value_fuzz", "nested_50_levels",
             "Nested message 50 levels deep", data)

    # Nested message with garbage content
    body = m2_kv_msg(0x000001, os.urandom(200))
    data = m2_frame(body)
    run_test("value_fuzz", "nested_garbage",
             "Nested message containing 200 random bytes", data)

    # Nested message length mismatch
    body = bytes([M2_MSG]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", 500) + b"\x00" * 10
    data = m2_frame(body)
    run_test("value_fuzz", "nested_len_mismatch",
             "Nested message claiming 500 bytes but only 10 sent", data)

    # --- Raw bytes (0x20) fuzzing ---

    # Raw with all zeros
    body = m2_kv_raw(0x000001, b"\x00" * 100)
    data = m2_frame(body)
    run_test("value_fuzz", "raw_zeros_100",
             "Raw KV with 100 zero bytes", data)

    # Raw with binary pattern
    body = m2_kv_raw(0x000001, bytes(range(256)))
    data = m2_frame(body)
    run_test("value_fuzz", "raw_all_bytes",
             "Raw KV with all 256 byte values", data)

    # --- U64 type (0x09) fuzzing ---

    # U64 max value
    data = m2_frame(m2_kv_u64(0x000001, 0xFFFFFFFFFFFFFFFF))
    run_test("value_fuzz", "u64_max",
             "U64 KV with value=0xFFFFFFFFFFFFFFFF", data)

    # U64 truncated (4 bytes instead of 8)
    body = bytes([M2_U64]) + (0x000001).to_bytes(3, "big") + b"\xFF\xFF\xFF\xFF"
    data = m2_frame(body)
    run_test("value_fuzz", "u64_truncated_4bytes",
             "U64 KV with only 4 bytes (truncated)", data)

    # --- Array of u32 (0x88) fuzzing ---

    # Array with count=0
    body = bytes([M2_U32_A]) + (0x000001).to_bytes(3, "big") + struct.pack(">I", 0)
    data = m2_frame(body)
    run_test("value_fuzz", "u32_array_empty",
             "U32 array with count=0", data)

    # Array count mismatch (says 100, provide 2)
    body = (bytes([M2_U32_A]) + (0x000001).to_bytes(3, "big") +
            struct.pack(">I", 100) + struct.pack(">II", 1, 2))
    data = m2_frame(body)
    run_test("value_fuzz", "u32_array_count_mismatch",
             "U32 array claiming count=100 but only 2 elements", data)

    # Large array (1000 elements)
    body = (bytes([M2_U32_A]) + (0x000001).to_bytes(3, "big") +
            struct.pack(">I", 1000) + struct.pack(">" + "I" * 1000, *range(1000)))
    data = m2_frame(body)
    run_test("value_fuzz", "u32_array_1000",
             "U32 array with 1000 elements", data)


# ---------------------------------------------------------------------------
# Category 5: Routing/Handler Fuzzing (~20 tests)
# ---------------------------------------------------------------------------

def fuzz_routing():
    log("=" * 60)
    log("Category 5: Routing/Handler Fuzzing")
    log("=" * 60)

    # Test SYS_TO values 0-24 (known handler range) + edge cases
    sys_to_values = list(range(25)) + [50, 100, 127, 128, 200, 255, 256, 1000, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF]

    for sys_to in sys_to_values:
        body = m2_kv_u32(SYS_TO, sys_to) + m2_kv_u32(SYS_CMD, 7) + m2_kv_u32(SYS_REQ_ID, 1)
        data = m2_frame(body)
        name = f"sys_to_{sys_to}"
        if sys_to > 0xFFFF:
            name = f"sys_to_0x{sys_to:08X}"
        run_test("routing", name,
                 f"Request with SYS_TO={sys_to} (0x{sys_to:X})", data)

    # Test SYS_CMD values
    cmd_values = [0, 1, 2, 3, 4, 5, 6, 7, 8, 255, 0xFFFF, 0xFFFFFFFF]
    for cmd in cmd_values:
        body = m2_kv_u32(SYS_TO, 2) + m2_kv_u32(SYS_CMD, cmd) + m2_kv_u32(SYS_REQ_ID, 1)
        data = m2_frame(body)
        run_test("routing", f"sys_cmd_{cmd}",
                 f"Request with SYS_CMD={cmd} (SYS_TO=2)", data)

    # Test SYS_FROM values
    for sys_from in [0, 1, 2, 0xFF, 0xFFFF, 0xFFFFFFFF]:
        body = (m2_kv_u32(SYS_TO, 2) + m2_kv_u32(SYS_FROM, sys_from) +
                m2_kv_u32(SYS_CMD, 7) + m2_kv_u32(SYS_REQ_ID, 1))
        data = m2_frame(body)
        run_test("routing", f"sys_from_0x{sys_from:X}",
                 f"Request with SYS_FROM=0x{sys_from:X}", data)

    # Test without SYS_TO (missing routing info)
    body = m2_kv_u32(SYS_CMD, 7) + m2_kv_u32(SYS_REQ_ID, 1)
    data = m2_frame(body)
    run_test("routing", "no_sys_to",
             "Request without SYS_TO (missing routing)", data)

    # Test without SYS_CMD
    body = m2_kv_u32(SYS_TO, 2) + m2_kv_u32(SYS_REQ_ID, 1)
    data = m2_frame(body)
    run_test("routing", "no_sys_cmd",
             "Request without SYS_CMD", data)


# ---------------------------------------------------------------------------
# Category 6: Combination Fuzzing (~20 tests)
# ---------------------------------------------------------------------------

def fuzz_combinations():
    log("=" * 60)
    log("Category 6: Combination Fuzzing")
    log("=" * 60)

    # Test: Many KVs in one frame (50 u32 values)
    body = b""
    for i in range(50):
        body += m2_kv_u32(i, i * 100)
    data = m2_frame(body)
    run_test("combination", "50_kvs_u32",
             "Frame with 50 u32 KV pairs", data)

    # Test: Many KVs in one frame (100 string values)
    body = b""
    for i in range(100):
        body += m2_kv_string(i, f"value_{i}")
    data = m2_frame(body)
    run_test("combination", "100_kvs_string",
             "Frame with 100 string KV pairs", data)

    # Test: Duplicate keys
    body = b""
    for _ in range(20):
        body += m2_kv_u32(SYS_TO, random.randint(0, 255))
    data = m2_frame(body)
    run_test("combination", "20_duplicate_sys_to",
             "Frame with 20 duplicate SYS_TO keys (different values)", data)

    # Test: Mixed types for same key
    body = (m2_kv_u32(0x000001, 42) +
            m2_kv_string(0x000001, "hello") +
            m2_kv_bool(0x000001, True) +
            m2_kv_u64(0x000001, 12345))
    data = m2_frame(body)
    run_test("combination", "mixed_types_same_key",
             "Same key_id with u32, string, bool, and u64 types", data)

    # Test: Interleaved valid and garbage KVs
    body = b""
    for i in range(10):
        body += m2_kv_u32(SYS_TO, 2)         # valid
        body += os.urandom(8)                   # garbage
        body += m2_kv_u32(SYS_CMD, 7)         # valid
        body += bytes([0xFE, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF])  # invalid type
    data = m2_frame(body)
    run_test("combination", "interleaved_valid_garbage",
             "Interleaved valid KVs and random garbage bytes", data)

    # Test: Frame entirely of one KV type repeated
    body = m2_kv_bool(0x000001, True) * 200
    data = m2_frame(body)
    run_test("combination", "200_bools",
             "Frame with 200 identical bool KV pairs", data)

    # Test: String values with path traversal
    body = (m2_kv_u32(SYS_TO, 2) + m2_kv_u32(SYS_CMD, 7) +
            m2_kv_string(0x000001, "../../../etc/passwd"))
    data = m2_frame(body)
    run_test("combination", "string_path_traversal",
             "String KV containing path traversal", data)

    # Test: String with command injection
    body = (m2_kv_u32(SYS_TO, 2) + m2_kv_u32(SYS_CMD, 7) +
            m2_kv_string(0x000001, "; /system/reboot"))
    data = m2_frame(body)
    run_test("combination", "string_cmd_injection",
             "String KV containing command injection attempt", data)

    # Test: Maximum complexity frame
    body = b""
    body += m2_kv_u32(SYS_TO, 2)
    body += m2_kv_u32(SYS_FROM, 0)
    body += m2_kv_u32(SYS_CMD, 7)
    body += m2_kv_u32(SYS_TYPE, 0)
    body += m2_kv_u32(SYS_TAG, 0)
    body += m2_kv_u32(SYS_REQ_ID, 1)
    # Add many extra attributes
    for i in range(30):
        body += m2_kv_string(i + 0x100, f"test_value_{i}" * 10)
    data = m2_frame(body)
    run_test("combination", "max_complexity",
             "Frame with all system KVs + 30 extra string attributes", data)

    # Test: Alternating frame sizes (short-long-short-long)
    data = b""
    for i in range(10):
        if i % 2 == 0:
            data += m2_frame(m2_kv_u32(SYS_TO, 2))
        else:
            data += m2_frame(m2_kv_string(0x000001, "A" * 1000))
    run_test("combination", "alternating_sizes",
             "10 alternating small and large frames", data)

    # Test: Frame with every known type at once
    body = (m2_kv_bool(0x000001, True) +
            m2_kv_u32(0x000002, 42) +
            m2_kv_u64(0x000003, 12345678) +
            m2_kv_string(0x000004, "test_string") +
            m2_kv_raw(0x000005, b"\x00\x01\x02\x03") +
            m2_kv_msg(0x000006, m2_kv_u32(0x000001, 1)))
    data = m2_frame(body)
    run_test("combination", "all_types_once",
             "Frame containing one KV of every known type", data)

    # Test: Zero-filled KVs (type=0, key=0, value=0)
    body = b"\x00" * 40
    data = m2_frame(body)
    run_test("combination", "all_zeros_body",
             "Frame with 40 zero bytes as body (ambiguous parsing)", data)

    # Test: Rapid fire different handlers
    data = b""
    for handler in range(20):
        body = m2_kv_u32(SYS_TO, handler) + m2_kv_u32(SYS_CMD, 7)
        data += m2_frame(body)
    run_test("combination", "rapid_20_handlers",
             "20 frames targeting handlers 0-19 in sequence", data)

    # Test: Extremely large single string value (32KB)
    body = m2_kv_string(0x000001, "X" * 32768)
    data = m2_frame(body)
    run_test("combination", "huge_string_32KB",
             "Frame with a single 32KB string KV", data)

    # Test: Send binary garbage that looks like a valid frame header
    data = struct.pack(">H", 8) + b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
    run_test("combination", "deadbeef_frame",
             "Frame with 0xDEADBEEF CAFEBABE as body", data)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 -- Winbox M2 Protocol Fuzzer")
    log(f"Phase 7: Fuzzing -- Target: {TARGET}:{WINBOX_PORT}")
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

    # Verify Winbox port is open
    try:
        s = winbox_connect(timeout=5)
        s.close()
        log(f"Winbox port {WINBOX_PORT} is open")
    except Exception as e:
        log(f"WARNING: Cannot connect to Winbox port {WINBOX_PORT}: {e}")
        log("Continuing anyway -- tests will record connection failures")

    # Run all categories
    categories = [
        ("Frame Header Fuzzing", fuzz_frame_headers),
        ("Key Type Fuzzing", fuzz_key_types),
        ("Key ID Fuzzing", fuzz_key_ids),
        ("Value Fuzzing", fuzz_values),
        ("Routing/Handler Fuzzing", fuzz_routing),
        ("Combination Fuzzing", fuzz_combinations),
    ]

    for cat_name, cat_func in categories:
        try:
            cat_func()
        except Exception as e:
            log(f"{cat_name} error: {e}")
            traceback.print_exc()

        health = check_router_alive()
        if not health.get("alive"):
            log(f"Router down after {cat_name}! Waiting...")
            wait_for_router(max_wait=120)
            time.sleep(5)

    # Summary
    if crash_events:
        ec.add_finding(
            severity="HIGH" if len(crash_events) >= 3 else "MEDIUM",
            title=f"Winbox M2 protocol stability: {len(crash_events)} crash events",
            description=(
                f"Router became unresponsive {len(crash_events)} time(s) during "
                f"Winbox M2 protocol fuzzing across {global_test_count} test cases. "
                f"Events: {crash_events}"
            ),
            evidence_refs=["winbox_protocol_fuzzer"],
            cwe="CWE-120",
        )

    ec.save("winbox_protocol_fuzzer.json")
    ec.summary()

    log(f"\nTotal tests: {global_test_count}")
    log(f"Crash events: {len(crash_events)}")
    log(f"Findings: {len(ec.results['findings'])}")


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
