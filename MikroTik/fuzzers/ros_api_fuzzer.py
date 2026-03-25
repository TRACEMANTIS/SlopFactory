#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — RouterOS API Word Encoding Boundary Fuzzer
Phase 4: Protocol Fuzzing — Binary API on port 8728

~250 test cases across five strategies:
  1. Length boundary fuzzing (~80 tests)
  2. Malformed length encoding (~40 tests)
  3. Sentence structure mutations (~40 tests)
  4. Pre-auth binary injection (~40 tests)
  5. Authentication edge cases (~50 tests)

The RouterOS API protocol uses a custom word-length encoding scheme with
5 tiers (1-byte through 5-byte). This fuzzer targets boundary transitions,
malformed encodings, and sentence-level protocol violations.

Target: [REDACTED-INTERNAL-IP], admin/TestPass123
Evidence: evidence/ros_api_fuzzer.json
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

import hashlib
import os
import random
import socket
import ssl
import struct
import time
import traceback

# ── Configuration ────────────────────────────────────────────────────────────

API_PORT = PORTS["api"]  # 8728
SOCKET_TIMEOUT = 10
ALIVE_CHECK_INTERVAL = 10  # check router health every N tests
MAX_LOG_BYTES = 500  # truncate binary data in evidence to this many bytes

ec = EvidenceCollector("ros_api_fuzzer.py", phase=4)
crash_count = 0
test_counter = 0


# ── RouterOS API Encoding Helpers ────────────────────────────────────────────

def encode_length(length):
    """Encode a word length using RouterOS API encoding scheme.

    Tiers:
      0x00-0x7F:   1 byte  (value = byte itself)
      0x80-0xBF:   2 bytes (value = ((b1 & 0x3F) << 8) | b2)
      0xC0-0xDF:   3 bytes (value = ((b1 & 0x1F) << 16) | (b2 << 8) | b3)
      0xE0-0xEF:   4 bytes (value = ((b1 & 0x0F) << 24) | (b2 << 16) | (b3 << 8) | b4)
      0xF0:         5 bytes (value = next 4 bytes as big-endian u32)
    """
    if length < 0x80:
        return bytes([length])
    elif length < 0x4000:
        return bytes([(length >> 8) | 0x80, length & 0xFF])
    elif length < 0x200000:
        return bytes([(length >> 16) | 0xC0, (length >> 8) & 0xFF, length & 0xFF])
    elif length < 0x10000000:
        return bytes([(length >> 24) | 0xE0, (length >> 16) & 0xFF,
                       (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0xF0]) + length.to_bytes(4, 'big')


def encode_word(word):
    """Encode a single API word (length-prefixed)."""
    if isinstance(word, str):
        word = word.encode()
    return encode_length(len(word)) + word


def encode_sentence(words):
    """Encode a full API sentence (sequence of words + empty terminator)."""
    result = b''
    for w in words:
        result += encode_word(w)
    result += b'\x00'  # empty word = sentence terminator
    return result


def read_response(sock, timeout=SOCKET_TIMEOUT):
    """Read one or more sentences from the API socket.

    Returns list of sentences (each sentence is a list of word strings).
    Returns empty list on timeout or error.
    """
    sock.settimeout(timeout)
    sentences = []
    current_sentence = []

    try:
        while True:
            # Read length
            first = sock.recv(1)
            if not first:
                break
            b = first[0]

            if b == 0x00:
                # Empty word = sentence terminator
                if current_sentence:
                    sentences.append(current_sentence)
                    current_sentence = []
                    # Check if we got a !done or !trap — stop reading
                    last = sentences[-1]
                    if last and (last[0] in ('!done', '!trap', '!fatal')):
                        break
                continue

            # Decode length
            if b < 0x80:
                length = b
            elif b < 0xC0:
                b2 = sock.recv(1)
                if not b2:
                    break
                length = ((b & 0x3F) << 8) | b2[0]
            elif b < 0xE0:
                rest = sock.recv(2)
                if len(rest) < 2:
                    break
                length = ((b & 0x1F) << 16) | (rest[0] << 8) | rest[1]
            elif b < 0xF0:
                rest = sock.recv(3)
                if len(rest) < 3:
                    break
                length = ((b & 0x0F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
            else:
                rest = sock.recv(4)
                if len(rest) < 4:
                    break
                length = struct.unpack('>I', rest)[0]

            # Read word data
            if length > 10 * 1024 * 1024:
                # Safety: don't try to read >10MB
                break
            data = b''
            while len(data) < length:
                chunk = sock.recv(min(length - len(data), 65536))
                if not chunk:
                    break
                data += chunk

            try:
                current_sentence.append(data.decode('utf-8', errors='replace'))
            except:
                current_sentence.append(repr(data))

    except socket.timeout:
        if current_sentence:
            sentences.append(current_sentence)
    except Exception:
        if current_sentence:
            sentences.append(current_sentence)

    return sentences


# ── Connection Helpers ───────────────────────────────────────────────────────

def connect_api(timeout=SOCKET_TIMEOUT):
    """Open a TCP connection to the API port. Returns socket or None."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((TARGET, API_PORT))
        return s
    except Exception as e:
        return None


def api_login(sock, user=ADMIN_USER, password=ADMIN_PASS):
    """Perform RouterOS API login. Returns (success, response_sentences)."""
    # Send /login
    sock.sendall(encode_sentence(["/login"]))
    resp = read_response(sock, timeout=5)

    if not resp:
        return False, []

    # Check for challenge-response (RouterOS < 6.43) or direct login
    first_sentence = resp[0] if resp else []
    ret_word = None
    for w in first_sentence:
        if w.startswith("=ret="):
            ret_word = w[5:]
            break

    if ret_word:
        # Old-style: MD5 challenge-response
        challenge = bytes.fromhex(ret_word)
        md5 = hashlib.md5()
        md5.update(b'\x00')
        md5.update(password.encode())
        md5.update(challenge)
        response_hash = "00" + md5.hexdigest()

        sock.sendall(encode_sentence([
            "/login",
            f"=name={user}",
            f"=response={response_hash}",
        ]))
        resp2 = read_response(sock, timeout=5)
        if resp2 and resp2[0] and resp2[0][0] == '!done':
            return True, resp2
        return False, resp2
    else:
        # New-style: send credentials directly
        sock.sendall(encode_sentence([
            "/login",
            f"=name={user}",
            f"=password={password}",
        ]))
        resp2 = read_response(sock, timeout=5)
        if resp2 and resp2[0] and resp2[0][0] == '!done':
            return True, resp2
        return False, resp2


def send_raw_and_read(data, timeout=SOCKET_TIMEOUT):
    """Connect, send raw bytes, read response. Returns (connected, response_sentences, error)."""
    sock = connect_api(timeout=timeout)
    if not sock:
        return False, [], "Connection refused"
    try:
        sock.sendall(data)
        resp = read_response(sock, timeout=timeout)
        return True, resp, None
    except Exception as e:
        return True, [], str(e)
    finally:
        try:
            sock.close()
        except:
            pass


def send_after_login(data, timeout=SOCKET_TIMEOUT):
    """Connect, authenticate, then send raw bytes. Returns (logged_in, response, error)."""
    sock = connect_api(timeout=timeout)
    if not sock:
        return False, [], "Connection refused"
    try:
        ok, _ = api_login(sock)
        if not ok:
            sock.close()
            return False, [], "Login failed"
        sock.sendall(data)
        resp = read_response(sock, timeout=timeout)
        return True, resp, None
    except Exception as e:
        return True, [], str(e)
    finally:
        try:
            sock.close()
        except:
            pass


# ── Truncation helper ────────────────────────────────────────────────────────

def trunc_bytes(data, maxlen=MAX_LOG_BYTES):
    """Truncate bytes for logging."""
    if len(data) <= maxlen:
        return data.hex()
    return data[:maxlen].hex() + f"...[truncated, total {len(data)} bytes]"


# ── Health Check Wrapper ─────────────────────────────────────────────────────

def periodic_health_check(force=False):
    """Check router health every ALIVE_CHECK_INTERVAL tests."""
    global test_counter, crash_count
    test_counter += 1
    if not force and test_counter % ALIVE_CHECK_INTERVAL != 0:
        return True

    status = check_router_alive(timeout=5)
    if not status.get("alive"):
        log("  ROUTER UNREACHABLE — potential crash!")
        crash_count += 1
        ec.add_finding(
            "CRITICAL", "Router crash detected during API fuzzing",
            f"Router became unreachable after test #{ec.results['metadata']['total_tests']}. "
            f"Crash count: {crash_count}",
            cwe="CWE-119",
        )
        # Wait for recovery
        recovery = wait_for_router(max_wait=60, check_interval=5)
        if not recovery.get("alive"):
            log("  Router did not recover within 60s — stopping fuzzer")
            return False
        log(f"  Router recovered: {recovery}")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# Category 1: Length Boundary Fuzzing (~80 tests)
# ══════════════════════════════════════════════════════════════════════════════

def fuzz_length_boundaries():
    """Test words at each encoding tier boundary."""
    log("Category 1: Length boundary fuzzing")
    cat = "length_boundary"

    # ── Tier 1/2 boundary: 0x7F (127) → 0x80 (128) ──────────────────────
    for length in [0, 1, 126, 127, 128, 129, 255]:
        word_data = b'A' * length
        payload = encode_length(length) + word_data + b'\x00'
        connected, resp, err = send_raw_and_read(payload, timeout=5)

        anomaly = not connected
        ec.add_test(cat, f"tier1_boundary_len{length}",
                    f"Word of exactly {length} bytes (tier 1/2 boundary)",
                    "connected" if connected else f"failed: {err}",
                    details={"length": length, "response": str(resp)[:200],
                             "payload_hex": trunc_bytes(payload)},
                    anomaly=anomaly)
        if not periodic_health_check():
            return

    # ── Tier 2/3 boundary: 0x3FFF (16383) → 0x4000 (16384) ─────────────
    for length in [16382, 16383, 16384, 16385]:
        word_data = b'B' * length
        payload = encode_length(length) + word_data + b'\x00'
        connected, resp, err = send_raw_and_read(payload, timeout=8)

        ec.add_test(cat, f"tier2_boundary_len{length}",
                    f"Word of exactly {length} bytes (tier 2/3 boundary)",
                    "connected" if connected else f"failed: {err}",
                    details={"length": length, "response_count": len(resp)},
                    anomaly=not connected)
        if not periodic_health_check():
            return

    # ── Tier 3/4 boundary: 0x1FFFFF (2097151) ──────────────────────────
    # Announce 2097151 bytes but only send 100 — test truncated read handling
    for announced, actual in [(2097151, 100), (2097152, 100), (0x1FFFFF, 50)]:
        header = encode_length(announced)
        partial_data = b'C' * actual
        payload = header + partial_data
        # Don't add terminator — we're testing partial delivery

        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"tier3_announced{announced}_actual{actual}",
                    f"Announce {announced} bytes, send only {actual}",
                    "connected" if connected else f"failed: {err}",
                    details={"announced": announced, "actual": actual,
                             "header_hex": header.hex(), "response": str(resp)[:200]},
                    anomaly=not connected)
        if not periodic_health_check():
            return

    # ── Tier 4/5 boundary: 0x0FFFFFFF (268435455) → 0xF0 prefix ────────
    # Just send the header announcing 268MB — don't send data
    for announced in [0x0FFFFFFE, 0x0FFFFFFF, 0x10000000, 0xFFFFFFFF]:
        header = encode_length(announced)
        payload = header + b'D' * 16  # tiny amount of data after huge header

        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"tier4_huge_announce_{hex(announced)}",
                    f"Announce {announced} bytes ({announced / (1024*1024):.0f} MB), send 16",
                    "connected" if connected else f"failed: {err}",
                    details={"announced_hex": hex(announced), "header_hex": header.hex(),
                             "response": str(resp)[:200]},
                    anomaly=not connected)
        if not periodic_health_check():
            return

    # ── Length=0 with trailing data ──────────────────────────────────────
    # A zero-length word should be a sentence terminator; data after it is next sentence
    payload = b'\x00' + b'E' * 10 + b'\x00'
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "zero_len_with_trailing_data",
                "Zero-length word (terminator) followed by raw data",
                "connected" if connected else f"failed: {err}",
                details={"payload_hex": payload.hex(), "response": str(resp)[:200]},
                anomaly=False)
    if not periodic_health_check():
        return

    # ── Length=1 with no data ────────────────────────────────────────────
    payload = b'\x01'  # announces 1 byte but sends nothing after
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "len1_no_data",
                "Length byte says 1, but no data follows (EOF)",
                "connected" if connected else f"failed: {err}",
                details={"payload_hex": payload.hex(), "response": str(resp)[:200]},
                anomaly=False)
    if not periodic_health_check():
        return

    # ── Exact boundary: authenticated command with boundary-length attribute
    for attr_len in [127, 128, 16383, 16384]:
        attr_value = 'X' * (attr_len - len("=comment="))
        if attr_len - len("=comment=") < 0:
            continue
        words = ["/system/identity/print", f"=comment={'X' * (attr_len - len('=comment='))}"]
        payload = encode_sentence(words)

        sock = connect_api()
        if sock:
            try:
                ok, _ = api_login(sock)
                if ok:
                    sock.sendall(payload)
                    resp = read_response(sock, timeout=5)
                    ec.add_test(cat, f"auth_boundary_attr_len{attr_len}",
                                f"Authenticated command with {attr_len}-byte attribute word",
                                f"response: {str(resp)[:200]}",
                                details={"attr_length": attr_len, "response": str(resp)[:200]})
                else:
                    ec.add_test(cat, f"auth_boundary_attr_len{attr_len}",
                                f"Authenticated command with {attr_len}-byte attribute word",
                                "login failed", anomaly=True)
            except Exception as e:
                ec.add_test(cat, f"auth_boundary_attr_len{attr_len}",
                            f"Authenticated command with {attr_len}-byte attribute word",
                            f"error: {e}")
            finally:
                sock.close()
        else:
            ec.add_test(cat, f"auth_boundary_attr_len{attr_len}",
                        f"Authenticated command with {attr_len}-byte attribute word",
                        "connection refused", anomaly=True)
        if not periodic_health_check():
            return

    # ── Rapid boundary toggling: alternate between tier1 and tier2 words ─
    for i in range(10):
        words = []
        for j in range(5):
            if j % 2 == 0:
                words.append("A" * 127)  # tier 1
            else:
                words.append("B" * 128)  # tier 2
        payload = encode_sentence(words)
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"tier_toggle_{i}",
                    f"Alternating tier1 (127B) and tier2 (128B) words x5",
                    "connected" if connected else f"failed: {err}",
                    details={"payload_size": len(payload), "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── Maximum single-byte length with command ──────────────────────────
    # 127-byte command that looks like a valid path
    long_cmd = "/" + "a" * 126
    payload = encode_sentence([long_cmd])
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "max_tier1_command",
                "127-byte command word (max single-byte encoding)",
                "connected" if connected else f"failed: {err}",
                details={"cmd_len": len(long_cmd), "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Exactly 0x80 bytes to confirm tier2 encoding ─────────────────────
    for word_len in [0x80, 0x81, 0xFF, 0x100, 0x3FFE, 0x3FFF]:
        word_data = b'Z' * word_len
        encoded = encode_word(word_data)
        payload = encoded + b'\x00'
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"exact_tier2_{hex(word_len)}",
                    f"Word of {word_len} bytes (tier 2 range, hex {hex(word_len)})",
                    "connected" if connected else f"failed: {err}",
                    details={"word_len": word_len, "encoded_header_hex": encoded[:5].hex()})
        if not periodic_health_check():
            return


# ══════════════════════════════════════════════════════════════════════════════
# Category 2: Malformed Length Encoding (~40 tests)
# ══════════════════════════════════════════════════════════════════════════════

def fuzz_malformed_lengths():
    """Send invalid length encoding prefixes."""
    log("Category 2: Malformed length encoding")
    cat = "malformed_length"

    # ── Reserved prefix bytes (0xF1-0xFF) ────────────────────────────────
    for prefix in range(0xF1, 0x100):
        # These bytes are undefined in the RouterOS API encoding
        payload = bytes([prefix]) + b'\x00' * 8
        connected, resp, err = send_raw_and_read(payload, timeout=5)

        anomaly = connected and len(resp) > 0
        ec.add_test(cat, f"reserved_prefix_{hex(prefix)}",
                    f"Reserved length prefix byte {hex(prefix)}",
                    "connected" if connected else f"failed: {err}",
                    details={"prefix": hex(prefix), "response": str(resp)[:200],
                             "payload_hex": payload.hex()},
                    anomaly=anomaly)
        if not periodic_health_check():
            return

    # ── Truncated multi-byte lengths ─────────────────────────────────────
    truncated_cases = [
        ("0x80_no_second", bytes([0x80])),          # 2-byte encoding, only 1 byte
        ("0xC0_one_byte",  bytes([0xC0, 0x01])),    # 3-byte encoding, only 2 bytes
        ("0xC0_no_extra",  bytes([0xC0])),           # 3-byte encoding, only 1 byte
        ("0xE0_two_bytes", bytes([0xE0, 0x01, 0x02])),  # 4-byte, only 3 bytes
        ("0xE0_one_byte",  bytes([0xE0, 0x01])),         # 4-byte, only 2 bytes
        ("0xE0_no_extra",  bytes([0xE0])),               # 4-byte, only 1 byte
        ("0xF0_three_bytes", bytes([0xF0, 0x01, 0x02, 0x03])),  # 5-byte, only 4 bytes
        ("0xF0_two_bytes",   bytes([0xF0, 0x01, 0x02])),         # 5-byte, only 3 bytes
        ("0xF0_one_byte",    bytes([0xF0, 0x01])),               # 5-byte, only 2 bytes
        ("0xF0_no_extra",    bytes([0xF0])),                     # 5-byte, only 1 byte
    ]

    for name, payload in truncated_cases:
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"truncated_{name}",
                    f"Truncated length encoding: {name}",
                    "connected" if connected else f"failed: {err}",
                    details={"payload_hex": payload.hex(), "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── All 0xFF bytes as length ─────────────────────────────────────────
    for count in [1, 2, 4, 5, 8]:
        payload = b'\xFF' * count
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"all_ff_{count}bytes",
                    f"{count} bytes of 0xFF as length prefix",
                    "connected" if connected else f"failed: {err}",
                    details={"payload_hex": payload.hex(), "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── 0xF0 followed by 0xFFFFFFFF (4GB length) ────────────────────────
    payload = bytes([0xF0, 0xFF, 0xFF, 0xFF, 0xFF]) + b'X' * 16
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "f0_4gb_length",
                "0xF0 prefix announcing 4GB word, send 16 bytes",
                "connected" if connected else f"failed: {err}",
                details={"payload_hex": payload.hex(), "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Negative-like lengths (high bits set in every tier) ──────────────
    negative_cases = [
        ("tier2_max", bytes([0xBF, 0xFF])),                     # max 2-byte
        ("tier3_max", bytes([0xDF, 0xFF, 0xFF])),                # max 3-byte
        ("tier4_max", bytes([0xEF, 0xFF, 0xFF, 0xFF])),          # max 4-byte
        ("tier5_max", bytes([0xF0, 0xFF, 0xFF, 0xFF, 0xFE])),   # max 5-byte - 1
    ]
    for name, header in negative_cases:
        payload = header + b'Y' * 32
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"max_tier_{name}",
                    f"Maximum value length encoding: {name}",
                    "connected" if connected else f"failed: {err}",
                    details={"header_hex": header.hex(), "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── Length says 0 but uses multi-byte encoding ───────────────────────
    # e.g., 0x80 0x00 = 2-byte encoding of length 0
    zero_multibyte = [
        ("2byte_zero", bytes([0x80, 0x00])),
        ("3byte_zero", bytes([0xC0, 0x00, 0x00])),
        ("4byte_zero", bytes([0xE0, 0x00, 0x00, 0x00])),
        ("5byte_zero", bytes([0xF0, 0x00, 0x00, 0x00, 0x00])),
    ]
    for name, header in zero_multibyte:
        payload = header + b'\x00'  # empty word + terminator
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"multibyte_zero_{name}",
                    f"Multi-byte encoding of zero length: {name}",
                    "connected" if connected else f"failed: {err}",
                    details={"header_hex": header.hex(), "response": str(resp)[:200]})
        if not periodic_health_check():
            return


# ══════════════════════════════════════════════════════════════════════════════
# Category 3: Sentence Structure Mutations (~40 tests)
# ══════════════════════════════════════════════════════════════════════════════

def fuzz_sentence_structure():
    """Test sentence-level protocol violations."""
    log("Category 3: Sentence structure mutations")
    cat = "sentence_structure"

    # ── Empty sentence (just terminator) ─────────────────────────────────
    payload = b'\x00'
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "empty_sentence",
                "Sentence with 0 words (just terminator byte 0x00)",
                "connected" if connected else f"failed: {err}",
                details={"payload_hex": payload.hex(), "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Sentence with many short words (1000) ────────────────────────────
    words = [f"w{i}" for i in range(1000)]
    payload = encode_sentence(words)
    connected, resp, err = send_raw_and_read(payload, timeout=8)
    ec.add_test(cat, "1000_short_words",
                "Sentence with 1000 short words",
                "connected" if connected else f"failed: {err}",
                details={"word_count": 1000, "payload_size": len(payload),
                         "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Sentence without terminator ──────────────────────────────────────
    # Keep sending words without the final \x00
    words_no_term = b''
    for i in range(20):
        words_no_term += encode_word(f"/system/resource/print")
    # No terminator — just close the connection after sending
    connected, resp, err = send_raw_and_read(words_no_term, timeout=5)
    ec.add_test(cat, "no_terminator",
                "20 words with no sentence terminator",
                "connected" if connected else f"failed: {err}",
                details={"payload_size": len(words_no_term), "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Multiple consecutive terminators ─────────────────────────────────
    payload = b'\x00' * 20
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "20_terminators",
                "20 consecutive sentence terminators (0x00 bytes)",
                "connected" if connected else f"failed: {err}",
                details={"payload_hex": payload.hex(), "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Word containing null byte in middle ──────────────────────────────
    for pos in [0, 5, 10]:
        word_data = b'A' * pos + b'\x00' + b'B' * (20 - pos)
        payload = encode_length(len(word_data)) + word_data + b'\x00'
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"null_in_word_pos{pos}",
                    f"Word with embedded null byte at position {pos}",
                    "connected" if connected else f"failed: {err}",
                    details={"word_len": len(word_data), "null_pos": pos,
                             "payload_hex": trunc_bytes(payload)})
        if not periodic_health_check():
            return

    # ── Very long single sentence (100KB of small words) ─────────────────
    total_size = 0
    long_sentence = b''
    word_count = 0
    while total_size < 100 * 1024:
        w = encode_word(f"=k{word_count}=v{word_count}")
        long_sentence += w
        total_size += len(w)
        word_count += 1
    long_sentence += b'\x00'  # terminator
    connected, resp, err = send_raw_and_read(long_sentence, timeout=10)
    ec.add_test(cat, "100kb_sentence",
                f"100KB sentence with {word_count} small words",
                "connected" if connected else f"failed: {err}",
                details={"word_count": word_count, "payload_size": len(long_sentence),
                         "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Interleaved valid and empty sentences ────────────────────────────
    payload = b''
    for i in range(50):
        if i % 2 == 0:
            payload += encode_sentence(["/system/identity/print"])
        else:
            payload += b'\x00'  # empty sentence
    connected, resp, err = send_raw_and_read(payload, timeout=8)
    ec.add_test(cat, "interleaved_valid_empty",
                "50 alternating valid commands and empty sentences",
                "connected" if connected else f"failed: {err}",
                details={"payload_size": len(payload), "response_count": len(resp)})
    if not periodic_health_check():
        return

    # ── Rapid-fire many sentences ────────────────────────────────────────
    payload = b''
    for i in range(200):
        payload += encode_sentence(["/system/resource/print"])
    connected, resp, err = send_raw_and_read(payload, timeout=10)
    ec.add_test(cat, "200_rapid_sentences",
                "200 valid sentences sent in a single burst",
                "connected" if connected else f"failed: {err}",
                details={"payload_size": len(payload), "response_count": len(resp)})
    if not periodic_health_check():
        return

    # ── Sentence with word containing only special characters ────────────
    special_chars = [
        ("backslashes", "\\" * 100),
        ("newlines", "\n" * 100),
        ("carriage_returns", "\r\n" * 50),
        ("tabs", "\t" * 100),
        ("mixed_whitespace", " \t\n\r" * 25),
        ("equals_signs", "=" * 100),
        ("forward_slashes", "/" * 100),
    ]
    for name, content in special_chars:
        payload = encode_sentence([content])
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"special_{name}",
                    f"Sentence with word of 100 {name}",
                    "connected" if connected else f"failed: {err}",
                    details={"content_type": name, "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── Binary word data (non-UTF8) ──────────────────────────────────────
    binary_data = bytes(range(256))
    payload = encode_word(binary_data) + b'\x00'
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "binary_word_0_255",
                "Word containing all byte values 0x00-0xFF",
                "connected" if connected else f"failed: {err}",
                details={"word_len": 256, "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Word that is just a single \x00 (length 1, value 0x00) ───────────
    payload = bytes([0x01, 0x00, 0x00])  # length=1, data=0x00, terminator=0x00
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "single_null_word",
                "Word of length 1 containing only 0x00",
                "connected" if connected else f"failed: {err}",
                details={"payload_hex": payload.hex(), "response": str(resp)[:200]})
    if not periodic_health_check():
        return


# ══════════════════════════════════════════════════════════════════════════════
# Category 4: Pre-auth Binary Injection (~40 tests)
# ══════════════════════════════════════════════════════════════════════════════

def fuzz_preauth_injection():
    """Send non-API protocol data before authentication."""
    log("Category 4: Pre-auth binary injection")
    cat = "preauth_injection"

    # ── Random bytes ─────────────────────────────────────────────────────
    for size in [1, 16, 256, 1024, 4096]:
        random_data = os.urandom(size)
        connected, resp, err = send_raw_and_read(random_data, timeout=5)
        ec.add_test(cat, f"random_bytes_{size}",
                    f"Send {size} random bytes pre-auth",
                    "connected" if connected else f"failed: {err}",
                    details={"size": size, "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── HTTP request ─────────────────────────────────────────────────────
    http_req = b"GET /rest/system/resource HTTP/1.1\r\nHost: " + TARGET.encode() + b"\r\n\r\n"
    connected, resp, err = send_raw_and_read(http_req, timeout=5)
    ec.add_test(cat, "http_request",
                "Send HTTP GET request to API binary port",
                "connected" if connected else f"failed: {err}",
                details={"response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── M2 (Winbox) frame ────────────────────────────────────────────────
    # Winbox M2 starts with 2-byte length header
    m2_frame = struct.pack('>H', 40) + b'\x01' * 40
    connected, resp, err = send_raw_and_read(m2_frame, timeout=5)
    ec.add_test(cat, "m2_winbox_frame",
                "Send Winbox M2 protocol frame to API port",
                "connected" if connected else f"failed: {err}",
                details={"response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── TLS ClientHello ──────────────────────────────────────────────────
    # Minimal TLS 1.2 ClientHello
    tls_hello = bytes([
        0x16,  # ContentType: Handshake
        0x03, 0x01,  # Version: TLS 1.0 (compat)
        0x00, 0x05,  # Length: 5
        0x01,  # HandshakeType: ClientHello
        0x00, 0x00, 0x01,  # Length: 1
        0x03,  # version byte
    ])
    connected, resp, err = send_raw_and_read(tls_hello, timeout=5)
    ec.add_test(cat, "tls_clienthello",
                "Send TLS ClientHello to plaintext API port",
                "connected" if connected else f"failed: {err}",
                details={"response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── SSH banner ───────────────────────────────────────────────────────
    ssh_banner = b"SSH-2.0-OpenSSH_8.9\r\n"
    connected, resp, err = send_raw_and_read(ssh_banner, timeout=5)
    ec.add_test(cat, "ssh_banner",
                "Send SSH version banner to API port",
                "connected" if connected else f"failed: {err}",
                details={"response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── FTP banner ───────────────────────────────────────────────────────
    ftp_cmd = b"USER admin\r\n"
    connected, resp, err = send_raw_and_read(ftp_cmd, timeout=5)
    ec.add_test(cat, "ftp_command",
                "Send FTP USER command to API port",
                "connected" if connected else f"failed: {err}",
                details={"response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Partial login then garbage ───────────────────────────────────────
    # Send /login, receive challenge, then send random garbage
    for i in range(5):
        sock = connect_api()
        if not sock:
            ec.add_test(cat, f"partial_login_garbage_{i}",
                        "Partial login then random garbage",
                        "connection refused", anomaly=True)
            continue
        try:
            # Send login command
            sock.sendall(encode_sentence(["/login"]))
            # Read challenge response
            resp1 = read_response(sock, timeout=5)

            # Now send garbage instead of proper login response
            garbage = os.urandom(64 + i * 32)
            sock.sendall(garbage)
            resp2 = read_response(sock, timeout=5)

            ec.add_test(cat, f"partial_login_garbage_{i}",
                        f"Send /login, get challenge, send {len(garbage)}B garbage",
                        f"challenge: {len(resp1)} sentences, after garbage: {len(resp2)} sentences",
                        details={"challenge_response": str(resp1)[:200],
                                 "garbage_response": str(resp2)[:200],
                                 "garbage_size": len(garbage)})
        except Exception as e:
            ec.add_test(cat, f"partial_login_garbage_{i}",
                        "Partial login then random garbage",
                        f"error: {e}")
        finally:
            sock.close()
        if not periodic_health_check():
            return

    # ── Interleave valid and invalid sentences ───────────────────────────
    for i in range(5):
        payload = b''
        # Valid login attempt
        payload += encode_sentence(["/login"])
        # Garbage
        payload += os.urandom(32)
        # Another valid sentence
        payload += encode_sentence(["/system/resource/print"])
        # More garbage
        payload += os.urandom(32)

        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"interleave_valid_invalid_{i}",
                    "Interleaved valid API sentences and random bytes",
                    "connected" if connected else f"failed: {err}",
                    details={"payload_size": len(payload), "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── Protocol confusion: send API then HTTP then API ──────────────────
    payload = encode_sentence(["/login"])
    payload += b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    payload += encode_sentence(["/system/resource/print"])
    connected, resp, err = send_raw_and_read(payload, timeout=5)
    ec.add_test(cat, "api_http_api_confusion",
                "API sentence, then HTTP request, then API sentence",
                "connected" if connected else f"failed: {err}",
                details={"payload_size": len(payload), "response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Huge initial burst ───────────────────────────────────────────────
    burst = os.urandom(65536)
    connected, resp, err = send_raw_and_read(burst, timeout=5)
    ec.add_test(cat, "64kb_random_burst",
                "64KB of random bytes as first data",
                "connected" if connected else f"failed: {err}",
                details={"response": str(resp)[:200]})
    if not periodic_health_check():
        return

    # ── Slowloris-style: send 1 byte at a time ──────────────────────────
    sock = connect_api(timeout=10)
    if sock:
        try:
            login_sentence = encode_sentence(["/login"])
            for byte in login_sentence:
                sock.sendall(bytes([byte]))
                time.sleep(0.1)
            resp = read_response(sock, timeout=10)
            ec.add_test(cat, "byte_at_a_time_login",
                        "Send /login one byte at a time (100ms between bytes)",
                        f"response: {str(resp)[:200]}",
                        details={"sentence_len": len(login_sentence),
                                 "response": str(resp)[:200]})
        except Exception as e:
            ec.add_test(cat, "byte_at_a_time_login",
                        "Send /login one byte at a time",
                        f"error: {e}")
        finally:
            sock.close()
    else:
        ec.add_test(cat, "byte_at_a_time_login",
                    "Send /login one byte at a time",
                    "connection refused", anomaly=True)
    periodic_health_check()


# ══════════════════════════════════════════════════════════════════════════════
# Category 5: Authentication Edge Cases (~50 tests)
# ══════════════════════════════════════════════════════════════════════════════

def fuzz_auth_edge_cases():
    """Test authentication handling edge cases."""
    log("Category 5: Authentication edge cases")
    cat = "auth_edge_cases"

    # ── Login with many extra attribute words ────────────────────────────
    for extra_count in [5, 10, 20, 50]:
        words = ["/login", f"=name={ADMIN_USER}", f"=password={ADMIN_PASS}"]
        for i in range(extra_count):
            words.append(f"=extra{i}=value{i}")
        payload = encode_sentence(words)

        connected, resp, err = send_raw_and_read(payload, timeout=5)
        success = resp and any(s[0] == '!done' for s in resp if s)
        ec.add_test(cat, f"login_extra_{extra_count}_attrs",
                    f"/login with {extra_count} extra attribute words",
                    f"login {'succeeded' if success else 'failed'}, resp: {str(resp)[:200]}",
                    details={"extra_count": extra_count, "login_success": success,
                             "response": str(resp)[:200]},
                    anomaly=success)  # Anomaly if login succeeds with extra attrs
        if not periodic_health_check():
            return

    # ── Empty name and password ──────────────────────────────────────────
    empty_cred_cases = [
        ("empty_name", ["/login", "=name=", f"=password={ADMIN_PASS}"]),
        ("empty_pass", ["/login", f"=name={ADMIN_USER}", "=password="]),
        ("both_empty", ["/login", "=name=", "=password="]),
        ("no_value_name", ["/login", "=name", f"=password={ADMIN_PASS}"]),
        ("no_value_pass", ["/login", f"=name={ADMIN_USER}", "=password"]),
        ("no_equals_name", ["/login", f"name={ADMIN_USER}", f"=password={ADMIN_PASS}"]),
    ]
    for name, words in empty_cred_cases:
        payload = encode_sentence(words)
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        success = resp and any(s[0] == '!done' for s in resp if s)
        ec.add_test(cat, f"cred_{name}",
                    f"Login with {name}",
                    f"login {'succeeded' if success else 'failed'}, resp: {str(resp)[:200]}",
                    details={"words": words, "login_success": success},
                    anomaly=success and "empty" in name)
        if not periodic_health_check():
            return

    # ── Name with null bytes and control characters ──────────────────────
    injection_usernames = [
        ("null_middle", "adm\x00in"),
        ("null_end", "admin\x00"),
        ("newline", "admin\n"),
        ("carriage_return", "admin\r"),
        ("tab", "admin\t"),
        ("backspace", "admin\x08"),
        ("utf8_homoglyph", "adm\u0456n"),  # Cyrillic 'i'
        ("utf8_rtl", "admin\u202e"),  # Right-to-left override
        ("long_name", "A" * 1000),
        ("sql_inject", "admin' OR '1'='1"),
        ("cmd_inject", "admin; cat /etc/passwd"),
        ("path_traverse", "../../../etc/passwd"),
    ]
    for name, username in injection_usernames:
        words = ["/login", f"=name={username}", f"=password={ADMIN_PASS}"]
        payload = encode_sentence(words)
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        success = resp and any(s[0] == '!done' for s in resp if s)
        ec.add_test(cat, f"username_{name}",
                    f"Login with injected username: {name}",
                    f"login {'succeeded' if success else 'failed'}",
                    details={"username_type": name, "login_success": success,
                             "response": str(resp)[:200]},
                    anomaly=success)
        if not periodic_health_check():
            return

    # ── Attribute without = prefix ───────────────────────────────────────
    malformed_attr_cases = [
        ("no_prefix", ["/login", f"name={ADMIN_USER}", f"password={ADMIN_PASS}"]),
        ("double_prefix", ["/login", f"==name={ADMIN_USER}", f"==password={ADMIN_PASS}"]),
        ("dot_prefix", ["/login", f".name={ADMIN_USER}", f".password={ADMIN_PASS}"]),
        ("hash_prefix", ["/login", f"#name={ADMIN_USER}", f"#password={ADMIN_PASS}"]),
        ("query_attr", ["/login", f"?name={ADMIN_USER}", f"?password={ADMIN_PASS}"]),
    ]
    for name, words in malformed_attr_cases:
        payload = encode_sentence(words)
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        success = resp and any(s[0] == '!done' for s in resp if s)
        ec.add_test(cat, f"malformed_attr_{name}",
                    f"Login with {name} attribute format",
                    f"login {'succeeded' if success else 'failed'}",
                    details={"words": words, "login_success": success,
                             "response": str(resp)[:200]},
                    anomaly=success)
        if not periodic_health_check():
            return

    # ── Duplicate =name attributes (different values) ────────────────────
    dup_cases = [
        ("same_user", ["/login", f"=name={ADMIN_USER}", f"=name={ADMIN_USER}",
                        f"=password={ADMIN_PASS}"]),
        ("diff_user", ["/login", "=name=nonexistent", f"=name={ADMIN_USER}",
                        f"=password={ADMIN_PASS}"]),
        ("diff_user_rev", ["/login", f"=name={ADMIN_USER}", "=name=nonexistent",
                            f"=password={ADMIN_PASS}"]),
        ("dup_password", ["/login", f"=name={ADMIN_USER}", "=password=wrong",
                          f"=password={ADMIN_PASS}"]),
    ]
    for name, words in dup_cases:
        payload = encode_sentence(words)
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        success = resp and any(s[0] == '!done' for s in resp if s)
        ec.add_test(cat, f"dup_attr_{name}",
                    f"Login with duplicate attributes: {name}",
                    f"login {'succeeded' if success else 'failed'}",
                    details={"words": words, "login_success": success,
                             "response": str(resp)[:200]},
                    anomaly=success and "diff" in name)
        if not periodic_health_check():
            return

    # ── Double login (login, then login again) ───────────────────────────
    sock = connect_api()
    if sock:
        try:
            ok1, resp1 = api_login(sock)
            # Now try to login again on the same connection
            ok2, resp2 = api_login(sock)

            ec.add_test(cat, "double_login",
                        "Login successfully, then login again on same connection",
                        f"first: {'ok' if ok1 else 'fail'}, second: {'ok' if ok2 else 'fail'}",
                        details={"first_login": ok1, "second_login": ok2,
                                 "first_resp": str(resp1)[:200],
                                 "second_resp": str(resp2)[:200]},
                        anomaly=ok2)  # Anomaly if second login also succeeds
        except Exception as e:
            ec.add_test(cat, "double_login",
                        "Double login on same connection",
                        f"error: {e}")
        finally:
            sock.close()
    if not periodic_health_check():
        return

    # ── Login then send command without waiting for response ─────────────
    sock = connect_api()
    if sock:
        try:
            login_sentence = encode_sentence([
                "/login", f"=name={ADMIN_USER}", f"=password={ADMIN_PASS}"])
            cmd_sentence = encode_sentence(["/system/identity/print"])

            # Send both immediately
            sock.sendall(login_sentence + cmd_sentence)
            resp = read_response(sock, timeout=8)

            got_identity = any("name" in str(s).lower() for s in resp)
            ec.add_test(cat, "login_then_immediate_cmd",
                        "Send login + command in single TCP write (no wait)",
                        f"responses: {len(resp)}, got identity: {got_identity}",
                        details={"response_count": len(resp), "got_identity": got_identity,
                                 "responses": str(resp)[:400]})
        except Exception as e:
            ec.add_test(cat, "login_then_immediate_cmd",
                        "Login + immediate command",
                        f"error: {e}")
        finally:
            sock.close()
    if not periodic_health_check():
        return

    # ── Login with very long password ────────────────────────────────────
    for pw_len in [256, 1024, 4096, 16384]:
        words = ["/login", f"=name={ADMIN_USER}", f"=password={'P' * pw_len}"]
        payload = encode_sentence(words)
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        success = resp and any(s[0] == '!done' for s in resp if s)
        ec.add_test(cat, f"long_password_{pw_len}",
                    f"Login with {pw_len}-byte password",
                    f"login {'succeeded' if success else 'failed'}",
                    details={"password_length": pw_len, "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── Command-like login words ─────────────────────────────────────────
    cmd_login_cases = [
        ("with_tag", ["/login", f"=name={ADMIN_USER}", f"=password={ADMIN_PASS}",
                      ".tag=mytag"]),
        ("with_proplist", ["/login", f"=name={ADMIN_USER}", f"=password={ADMIN_PASS}",
                           ".proplist=.id"]),
        ("cancel_tag", ["/cancel", "=tag=12345"]),
        ("login_as_command_path", ["/user/login", f"=name={ADMIN_USER}",
                                    f"=password={ADMIN_PASS}"]),
    ]
    for name, words in cmd_login_cases:
        payload = encode_sentence(words)
        connected, resp, err = send_raw_and_read(payload, timeout=5)
        ec.add_test(cat, f"cmd_login_{name}",
                    f"Login variation: {name}",
                    f"response: {str(resp)[:200]}",
                    details={"words": words, "response": str(resp)[:200]})
        if not periodic_health_check():
            return

    # ── Post-auth: send malformed command after successful login ──────────
    malformed_post_auth = [
        ("empty_command", [""]),
        ("just_slash", ["/"]),
        ("double_slash", ["//"]),
        ("triple_dots", ["/..."]),
        ("null_command", ["\x00"]),
        ("very_long_path", ["/" + "a/" * 500]),
        ("print_with_garbage_filter", ["/system/resource/print",
                                        "?=nonexistent>garbage"]),
    ]
    for name, words in malformed_post_auth:
        sock = connect_api()
        if sock:
            try:
                ok, _ = api_login(sock)
                if ok:
                    sock.sendall(encode_sentence(words))
                    resp = read_response(sock, timeout=5)
                    ec.add_test(cat, f"postauth_malformed_{name}",
                                f"Post-auth malformed command: {name}",
                                f"response: {str(resp)[:200]}",
                                details={"words": words, "response": str(resp)[:200]})
                else:
                    ec.add_test(cat, f"postauth_malformed_{name}",
                                f"Post-auth malformed command: {name}",
                                "login failed", anomaly=True)
            except Exception as e:
                ec.add_test(cat, f"postauth_malformed_{name}",
                            f"Post-auth malformed command: {name}",
                            f"error: {e}")
            finally:
                sock.close()
        if not periodic_health_check():
            return


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("=" * 70)
    log("MikroTik RouterOS API Word Encoding Boundary Fuzzer")
    log(f"Target: {TARGET}:{API_PORT}")
    log("=" * 70)

    # Pre-flight check
    status = check_router_alive()
    if not status.get("alive"):
        log("Router is not responding — aborting")
        ec.add_test("preflight", "router_alive", "Pre-flight connectivity check",
                    "FAILED — router unreachable", anomaly=True)
        ec.save("ros_api_fuzzer.json")
        return

    log(f"Router alive: version={status.get('version')}, uptime={status.get('uptime')}")
    ec.add_test("preflight", "router_alive", "Pre-flight connectivity check",
                f"OK — version {status.get('version')}, uptime {status.get('uptime')}")

    # Verify API port is open
    sock = connect_api(timeout=5)
    if not sock:
        log(f"API port {API_PORT} is not open — aborting")
        ec.add_test("preflight", "api_port_open", "API port connectivity check",
                    f"FAILED — port {API_PORT} unreachable", anomaly=True)
        ec.save("ros_api_fuzzer.json")
        return
    sock.close()
    ec.add_test("preflight", "api_port_open", "API port connectivity check",
                f"OK — port {API_PORT} accepting connections")

    # Verify API login works
    sock = connect_api()
    if sock:
        ok, resp = api_login(sock)
        sock.close()
        if ok:
            ec.add_test("preflight", "api_login", "API authentication check",
                        "OK — login successful")
        else:
            ec.add_test("preflight", "api_login", "API authentication check",
                        f"FAILED — login rejected: {resp}", anomaly=True)
    else:
        ec.add_test("preflight", "api_login", "API authentication check",
                    "FAILED — could not connect", anomaly=True)

    # Run all fuzz categories
    try:
        fuzz_length_boundaries()
        fuzz_malformed_lengths()
        fuzz_sentence_structure()
        fuzz_preauth_injection()
        fuzz_auth_edge_cases()
    except KeyboardInterrupt:
        log("Interrupted by user")
    except Exception as e:
        log(f"Unhandled error: {e}")
        traceback.print_exc()
        ec.add_test("error", "unhandled_exception", "Fuzzer encountered unhandled error",
                    str(e), anomaly=True)

    # Final summary
    ec.results["metadata"]["crash_count"] = crash_count
    ec.summary()
    ec.save("ros_api_fuzzer.json")


if __name__ == "__main__":
    main()
