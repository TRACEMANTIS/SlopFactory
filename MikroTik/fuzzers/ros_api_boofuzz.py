#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 -- RouterOS API Protocol Fuzzer
Phase 7: Fuzzing -- ~150 test cases targeting the RouterOS API on port 8728.

Custom generation-based fuzzer (NOT boofuzz) for the length-encoded word protocol.

RouterOS API Protocol:
  - Word: length_bytes + content_bytes
  - Sentence: word1 + word2 + ... + \\x00 (empty word terminator)
  - Length encoding:
      0x00-0x7F:     1 byte  (value as-is)
      0x80-0xBF xx:  2 bytes (((b0 & 0x3F) << 8) | b1)
      0xC0-0xDF xx xx: 3 bytes
      0xE0-0xEF xx xx xx: 4 bytes
      0xF0 xx xx xx xx: 5 bytes

Categories:
  1. Word length boundary fuzzing (~40)
  2. Sentence structure fuzzing (~30)
  3. Pre-auth binary fuzzing (~30)
  4. Command path fuzzing (~25)
  5. Attribute fuzzing (~25)

Target: [REDACTED-INTERNAL-IP]:8728, admin/TestPass123
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
API_PORT = PORTS["api"]     # 8728
ALIVE_CHECK_INTERVAL = 10
RECV_TIMEOUT = 5
CONNECT_TIMEOUT = 5

ec = EvidenceCollector("ros_api_boofuzz.py", phase=7)
global_test_count = 0
crash_events = []


# ---------------------------------------------------------------------------
# RouterOS API Protocol Helpers
# ---------------------------------------------------------------------------

def encode_length(length):
    """Encode a word length using the RouterOS API length encoding scheme."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x4000:
        return bytes([((length >> 8) & 0x3F) | 0x80, length & 0xFF])
    elif length < 0x200000:
        return bytes([((length >> 16) & 0x1F) | 0xC0,
                       (length >> 8) & 0xFF,
                       length & 0xFF])
    elif length < 0x10000000:
        return bytes([((length >> 24) & 0x0F) | 0xE0,
                       (length >> 16) & 0xFF,
                       (length >> 8) & 0xFF,
                       length & 0xFF])
    else:
        return bytes([0xF0,
                       (length >> 24) & 0xFF,
                       (length >> 16) & 0xFF,
                       (length >> 8) & 0xFF,
                       length & 0xFF])


def make_word(content):
    """Create a RouterOS API word (length-encoded)."""
    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")
    return encode_length(len(content)) + content


def make_sentence(words):
    """Create a RouterOS API sentence (words + empty word terminator)."""
    data = b""
    for w in words:
        data += make_word(w)
    data += b"\x00"  # empty word = sentence terminator
    return data


def api_connect(timeout=CONNECT_TIMEOUT):
    """Open a TCP connection to the RouterOS API."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, API_PORT))
    return s


def api_send_recv(data, timeout=RECV_TIMEOUT, recv_size=4096):
    """Connect, send raw data, receive response, close."""
    s = api_connect(timeout=timeout)
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


def api_send_recv_raw(data, timeout=RECV_TIMEOUT):
    """Send raw bytes (may be malformed) and capture response."""
    try:
        return api_send_recv(data, timeout=timeout)
    except Exception as e:
        return f"ERROR:{e}".encode()


def run_test(category, name, description, data, expect_crash=False):
    """Run a single test case, record result, and periodically health-check."""
    global global_test_count
    global_test_count += 1

    try:
        response = api_send_recv_raw(data, timeout=RECV_TIMEOUT)
        is_error = response.startswith(b"ERROR:")

        if is_error:
            resp_preview = response.decode("utf-8", errors="replace")[:300]
        else:
            resp_preview = response.hex()[:300] if response else "(empty)"

        is_anomaly = is_error or len(response) == 0

        ec.add_test(
            category=category,
            name=name,
            description=description,
            result=f"Response: {len(response)} bytes" if not is_error else resp_preview,
            details={
                "payload_size": len(data),
                "payload_hex": data.hex()[:200],
                "response_size": len(response) if not is_error else 0,
                "response_preview": resp_preview,
                "is_error": is_error,
            },
            anomaly=is_anomaly,
        )

    except Exception as e:
        ec.add_test(
            category=category,
            name=name,
            description=description,
            result=f"Exception: {e}",
            details={"error": str(e), "payload_hex": data.hex()[:200]},
            anomaly=True,
        )

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
                title=f"Router crash during API fuzzing: {name}",
                description=f"Router became unresponsive after API fuzz test '{name}'. "
                            f"Payload size: {len(data)} bytes, hex preview: {data.hex()[:100]}",
                evidence_refs=[name],
                cwe="CWE-120",
            )
            wait_for_router(max_wait=120)
            time.sleep(5)


# ---------------------------------------------------------------------------
# Category 1: Word Length Boundary Fuzzing (~40 tests)
# ---------------------------------------------------------------------------

def fuzz_word_length_boundaries():
    log("=" * 60)
    log("Category 1: Word Length Boundary Fuzzing")
    log("=" * 60)

    # Encoding boundaries:
    # 1-byte: 0x00 - 0x7F (0 - 127)
    # 2-byte: 0x80 - 0x3FFF (128 - 16383)
    # 3-byte: 0x4000 - 0x1FFFFF (16384 - 2097151)
    # 4-byte: 0x200000 - 0xFFFFFFF (2097152 - 268435455)

    boundary_lengths = [
        # 1-byte / 2-byte boundary
        (0x7E, "1byte_near_max_0x7E"),
        (0x7F, "1byte_max_0x7F"),
        (0x80, "2byte_min_0x80"),
        (0x81, "2byte_0x81"),
        # 2-byte / 3-byte boundary
        (0x3FFE, "2byte_near_max_0x3FFE"),
        (0x3FFF, "2byte_max_0x3FFF"),
        (0x4000, "3byte_min_0x4000"),
        (0x4001, "3byte_0x4001"),
        # 3-byte / 4-byte boundary
        (0x1FFFFE, "3byte_near_max_0x1FFFFE"),
        (0x1FFFFF, "3byte_max_0x1FFFFF"),
        (0x200000, "4byte_min_0x200000"),
    ]

    for target_len, name in boundary_lengths:
        # Test 1: Correctly encoded word at this length (content = 'A' * target_len)
        # For very large lengths, we only send the encoded length + partial fill
        # to avoid sending multi-megabyte payloads
        if target_len <= 0x4001:
            # Small enough to send full content
            content = b"/" + b"A" * (target_len - 1) if target_len > 0 else b""
            data = encode_length(len(content)) + content + b"\x00"
            run_test("word_length", f"boundary_correct_{name}",
                     f"Correctly encoded word at length boundary {name} ({target_len} bytes)",
                     data)
        else:
            # For large lengths, send encoded length claiming target_len but only
            # partial content -- tests how server handles truncated data
            content = b"/" + b"A" * min(target_len - 1, 1024)
            data = encode_length(target_len) + content + b"\x00"
            run_test("word_length", f"boundary_truncated_{name}",
                     f"Truncated word at length boundary {name} (claims {target_len}, sends {len(content)})",
                     data)

    # Test: length=0 word (just the length byte)
    data = b"\x00\x00"  # zero-length word + sentence terminator
    run_test("word_length", "zero_length_word",
             "Word with encoded length=0 (empty word before terminator)",
             data)

    # Test: length mismatch -- encoded length says 100 but we send 10 bytes of content
    data = encode_length(100) + b"A" * 10 + b"\x00"
    run_test("word_length", "length_mismatch_100_10",
             "Length says 100 but only 10 bytes of content sent",
             data)

    # Test: length mismatch -- encoded length says 10 but we send 100 bytes
    data = encode_length(10) + b"A" * 100 + b"\x00"
    run_test("word_length", "length_mismatch_10_100",
             "Length says 10 but 100 bytes of content sent",
             data)

    # Test: maximum 5-byte encoded length (0xFFFFFFFF-ish) + minimal content
    data = b"\xF0\xFF\xFF\xFF\xFF" + b"A" * 10 + b"\x00"
    run_test("word_length", "max_5byte_length",
             "5-byte length encoding claiming ~4GB with only 10 bytes of content",
             data)

    # Test: Invalid length encoding byte (0xF8 is not valid in the scheme)
    for invalid_byte in [0xF1, 0xF8, 0xFC, 0xFE, 0xFF]:
        data = bytes([invalid_byte]) + b"\x00" * 4 + b"A" * 10 + b"\x00"
        run_test("word_length", f"invalid_length_byte_0x{invalid_byte:02x}",
                 f"Invalid length prefix byte 0x{invalid_byte:02X}",
                 data)

    # Test: Partial length encoding (2-byte encoding but only send first byte)
    data = b"\x80"  # starts 2-byte encoding but missing second byte
    run_test("word_length", "partial_2byte_encoding",
             "Partial 2-byte length encoding (missing second byte)",
             data)

    # Test: Partial 3-byte encoding
    data = b"\xC0\x40"  # starts 3-byte but missing third
    run_test("word_length", "partial_3byte_encoding",
             "Partial 3-byte length encoding (missing third byte)",
             data)

    # Test: Partial 4-byte encoding
    data = b"\xE0\x20\x00"  # starts 4-byte but missing fourth
    run_test("word_length", "partial_4byte_encoding",
             "Partial 4-byte length encoding (missing fourth byte)",
             data)

    # Test: Partial 5-byte encoding
    data = b"\xF0\x10\x00\x00"  # starts 5-byte but missing fifth
    run_test("word_length", "partial_5byte_encoding",
             "Partial 5-byte length encoding (missing fifth byte)",
             data)

    # Test: Negative-looking length (sign bit set in ways that might confuse signed parsing)
    data = b"\xF0\x80\x00\x00\x00" + b"A" * 10 + b"\x00"
    run_test("word_length", "signbit_length",
             "Length with high bit set in value portion (potential signed int confusion)",
             data)

    # Test: All 0xFF in length bytes
    data = b"\xFF\xFF\xFF\xFF\xFF" + b"A" * 10 + b"\x00"
    run_test("word_length", "all_ff_length",
             "All 0xFF bytes in length field",
             data)

    # Test: Repeated length encodings with no content between them
    data = encode_length(5) + encode_length(5) + encode_length(5) + b"\x00"
    run_test("word_length", "cascaded_lengths",
             "Multiple length encodings cascaded with no content between",
             data)

    # Test: Length = 1 with single characters
    for char in [b"\x00", b"\x01", b"\xff", b"/", b"="]:
        data = encode_length(1) + char + b"\x00"
        run_test("word_length", f"single_byte_word_{char.hex()}",
                 f"Single-byte word containing 0x{char.hex()}",
                 data)


# ---------------------------------------------------------------------------
# Category 2: Sentence Structure Fuzzing (~30 tests)
# ---------------------------------------------------------------------------

def fuzz_sentence_structure():
    log("=" * 60)
    log("Category 2: Sentence Structure Fuzzing")
    log("=" * 60)

    # Test: Multiple zero terminators in a row
    data = b"\x00" * 10
    run_test("sentence_structure", "multiple_terminators_10",
             "10 consecutive zero bytes (sentence terminators)",
             data)

    # Test: Many terminators
    data = b"\x00" * 100
    run_test("sentence_structure", "multiple_terminators_100",
             "100 consecutive zero bytes",
             data)

    # Test: No terminator -- send a valid word but no trailing \x00
    data = make_word("/system/resource/print")  # no sentence terminator
    run_test("sentence_structure", "no_terminator",
             "Valid command word with no sentence terminator",
             data)

    # Test: Sentence with many words (100 words)
    words = [f"=key{i}=value{i}" for i in range(100)]
    data = make_sentence(["/system/resource/print"] + words)
    run_test("sentence_structure", "100_words",
             "Sentence with 100 attribute words",
             data)

    # Test: Sentence with 500 words
    words = [f"=k{i}=v{i}" for i in range(500)]
    data = make_sentence(["/login"] + words)
    run_test("sentence_structure", "500_words",
             "Sentence with 500 attribute words",
             data)

    # Test: Empty first word (terminator immediately after start)
    data = b"\x00\x00"
    run_test("sentence_structure", "empty_first_word",
             "Sentence starting with empty word (immediate terminator then another)",
             data)

    # Test: Only terminators (empty sentences)
    data = b"\x00" * 5
    run_test("sentence_structure", "only_terminators_5",
             "5 empty sentences (just terminators)",
             data)

    # Test: Sentence with duplicate command words
    data = make_sentence(["/login", "/login", "/login"])
    run_test("sentence_structure", "duplicate_commands",
             "Sentence with duplicate /login command words",
             data)

    # Test: Two sentences back-to-back
    s1 = make_sentence(["/login"])
    s2 = make_sentence(["/system/resource/print"])
    data = s1 + s2
    run_test("sentence_structure", "two_sentences",
             "Two complete sentences back-to-back",
             data)

    # Test: 10 sentences rapid fire
    data = b""
    for i in range(10):
        data += make_sentence(["/system/resource/print"])
    run_test("sentence_structure", "10_rapid_sentences",
             "10 /system/resource/print sentences in one TCP send",
             data)

    # Test: 50 sentences rapid fire
    data = b""
    for i in range(50):
        data += make_sentence(["/system/resource/print"])
    run_test("sentence_structure", "50_rapid_sentences",
             "50 sentences in one TCP send",
             data)

    # Test: Interleaved valid and invalid sentences
    data = b""
    for i in range(10):
        data += make_sentence(["/system/resource/print"])
        data += b"\xff\xff\xff\x00"  # garbage + terminator
    run_test("sentence_structure", "interleaved_valid_invalid",
             "Interleaved valid sentences and garbage data",
             data)

    # Test: Sentence where every word is empty except the command
    data = make_word("/system/resource/print")
    for _ in range(20):
        data += make_word("")
    data += b"\x00"
    run_test("sentence_structure", "many_empty_words",
             "Command followed by 20 empty-string words",
             data)

    # Test: Very long single word (10KB command path)
    long_cmd = "/" + "A" * 10240
    data = make_sentence([long_cmd])
    run_test("sentence_structure", "10KB_single_word",
             "Single word of 10KB as command path",
             data)

    # Test: Word containing only whitespace
    data = make_sentence(["   ", "\t\t\t", "\r\n\r\n"])
    run_test("sentence_structure", "whitespace_words",
             "Sentence with whitespace-only words",
             data)

    # Test: Binary sentence (words with all byte values 0-255)
    binary_word = bytes(range(256))
    data = encode_length(len(binary_word)) + binary_word + b"\x00"
    run_test("sentence_structure", "all_byte_values",
             "Word containing all 256 byte values (0x00-0xFF)",
             data)

    # Test: Cancel sentence (send partial then close)
    # This tests server handling of incomplete reads
    partial = make_word("/system/resource/print")  # no terminator
    try:
        s = api_connect()
        s.sendall(partial)
        time.sleep(1)
        # Don't send terminator, just close
        s.close()
        ec.add_test("sentence_structure", "cancel_mid_sentence",
                     "Send partial sentence then close connection",
                     "Connection closed without terminator",
                     details={"partial_size": len(partial)})
    except Exception as e:
        ec.add_test("sentence_structure", "cancel_mid_sentence",
                     "Partial sentence + close", f"Error: {e}", anomaly=True)

    # Test: Send word, wait 10 seconds, send terminator (slow sentence)
    try:
        s = api_connect(timeout=15)
        s.sendall(make_word("/system/resource/print"))
        time.sleep(5)
        s.sendall(b"\x00")  # terminator after delay
        time.sleep(1)
        resp = b""
        try:
            resp = s.recv(4096)
        except socket.timeout:
            pass
        s.close()
        ec.add_test("sentence_structure", "slow_sentence_5s",
                     "Send command word, wait 5 seconds, then send terminator",
                     f"Response: {len(resp)} bytes",
                     details={"delay_seconds": 5, "response_size": len(resp),
                              "response_hex": resp.hex()[:200] if resp else ""})
    except Exception as e:
        ec.add_test("sentence_structure", "slow_sentence_5s",
                     "Slow sentence test", f"Error: {e}", anomaly=True)

    # Test: Fragmented word (send length, wait, send content)
    try:
        s = api_connect(timeout=10)
        word_content = b"/system/resource/print"
        length_bytes = encode_length(len(word_content))
        s.sendall(length_bytes)
        time.sleep(1)
        s.sendall(word_content)
        s.sendall(b"\x00")
        time.sleep(0.5)
        resp = b""
        try:
            resp = s.recv(4096)
        except socket.timeout:
            pass
        s.close()
        ec.add_test("sentence_structure", "fragmented_word",
                     "Send length bytes, wait 1s, then send content",
                     f"Response: {len(resp)} bytes",
                     details={"response_size": len(resp)})
    except Exception as e:
        ec.add_test("sentence_structure", "fragmented_word",
                     "Fragmented word test", f"Error: {e}", anomaly=True)


# ---------------------------------------------------------------------------
# Category 3: Pre-Auth Binary Fuzzing (~30 tests)
# ---------------------------------------------------------------------------

def fuzz_preauth_binary():
    log("=" * 60)
    log("Category 3: Pre-Auth Binary Fuzzing")
    log("=" * 60)

    # Test: Random binary data of various sizes
    for size in [10, 50, 100, 500, 1000, 5000, 10000]:
        data = os.urandom(size)
        run_test("preauth_binary", f"random_binary_{size}B",
                 f"Send {size} bytes of random binary data before any login",
                 data)

    # Test: All zeros
    for size in [100, 1000, 10000]:
        data = b"\x00" * size
        run_test("preauth_binary", f"all_zeros_{size}B",
                 f"Send {size} zero bytes", data)

    # Test: All 0xFF bytes
    for size in [100, 1000, 10000]:
        data = b"\xFF" * size
        run_test("preauth_binary", f"all_ff_{size}B",
                 f"Send {size} 0xFF bytes", data)

    # Test: Repeating pattern
    data = (b"\xDE\xAD\xBE\xEF" * 2500)[:10000]
    run_test("preauth_binary", "deadbeef_10KB",
             "10KB of repeating 0xDEADBEEF pattern", data)

    # Test: Incrementing bytes
    data = bytes(i % 256 for i in range(1000))
    run_test("preauth_binary", "incrementing_1000B",
             "1000 bytes of incrementing values (0x00-0xFF repeating)", data)

    # Test: HTTP request to API port (protocol confusion)
    http_req = f"GET / HTTP/1.1\r\nHost: {TARGET}\r\n\r\n".encode()
    run_test("preauth_binary", "http_on_api_port",
             "Send HTTP GET request to API port (protocol confusion)", http_req)

    # Test: Winbox M2 frame to API port
    m2_frame = struct.pack(">H", 20) + b"\x01" * 20
    run_test("preauth_binary", "winbox_m2_on_api_port",
             "Send Winbox M2 frame to API port (protocol confusion)", m2_frame)

    # Test: SSH banner to API port
    ssh_banner = b"SSH-2.0-OpenSSH_8.0\r\n"
    run_test("preauth_binary", "ssh_banner_on_api_port",
             "Send SSH banner to API port", ssh_banner)

    # Test: Partial RouterOS API length encoding followed by garbage
    data = b"\xF0" + os.urandom(100)
    run_test("preauth_binary", "partial_length_then_garbage",
             "5-byte length prefix (0xF0) followed by 100 random bytes", data)

    # Test: Valid-looking sentence with garbage content
    data = encode_length(50) + os.urandom(50) + b"\x00"
    run_test("preauth_binary", "valid_structure_garbage_content",
             "Properly structured word with random content", data)

    # Test: Rapid connection with single byte
    for byte_val in [0x00, 0x01, 0x7F, 0x80, 0xC0, 0xE0, 0xF0, 0xFF]:
        data = bytes([byte_val])
        run_test("preauth_binary", f"single_byte_0x{byte_val:02x}",
                 f"Single byte 0x{byte_val:02X} to API port", data)


# ---------------------------------------------------------------------------
# Category 4: Command Path Fuzzing (~25 tests)
# ---------------------------------------------------------------------------

def fuzz_command_paths():
    log("=" * 60)
    log("Category 4: Command Path Fuzzing")
    log("=" * 60)

    paths = [
        # Normal paths
        ("/system/resource/print", "valid_sysresource"),
        ("/login", "valid_login"),
        ("/cancel", "valid_cancel"),
        # Path traversal
        ("/../../../etc/passwd", "traversal_etc_passwd"),
        ("/system/../../etc/shadow", "traversal_etc_shadow"),
        # Long paths
        ("/" + "A" * 1000, "long_path_1KB"),
        ("/" + "A" * 10000, "long_path_10KB"),
        ("/" + "/".join(["segment"] * 200), "deep_path_200_segments"),
        # Null bytes
        ("/system\x00/resource/print", "null_in_path"),
        ("/system/resource\x00evil/print", "null_mid_path"),
        # Format strings
        ("/%s%s%s%s%s%s%s%s", "format_string_s"),
        ("/%n%n%n%n%n", "format_string_n"),
        ("/%x%x%x%x%x%x%x%x", "format_string_x"),
        ("/AAAA%08x.%08x.%08x.%08x", "format_string_addr_leak"),
        # Special characters
        ("/system/<script>alert(1)</script>", "xss_in_path"),
        ("/system/'; DROP TABLE; --", "sql_inject_path"),
        ("/system/${7*7}", "template_inject_path"),
        # Unicode
        ("/system/\xc0\xae\xc0\xae/resource", "overlong_utf8_dots"),
        ("/\xff\xfe\xfd\xfc", "high_bytes_path"),
        # Empty and whitespace
        ("", "empty_path"),
        ("/", "root_only"),
        ("   ", "whitespace_path"),
        # RouterOS internal commands
        ("/system/reboot", "reboot_command"),
        ("/system/shutdown", "shutdown_command"),
        ("/export", "export_command"),
    ]

    for path, name in paths:
        data = make_sentence([path])
        run_test("command_path", f"path_{name}",
                 f"Command path fuzzing: {name}",
                 data)


# ---------------------------------------------------------------------------
# Category 5: Attribute Fuzzing (~25 tests)
# ---------------------------------------------------------------------------

def fuzz_attributes():
    log("=" * 60)
    log("Category 5: Attribute Fuzzing")
    log("=" * 60)

    base_cmd = "/login"

    # Normal attribute format: =name=value
    normal_attrs = [
        # Valid login attributes
        ("=name=admin", "=password=TestPass123"),
    ]

    # Test with valid login first
    data = make_sentence([base_cmd, "=name=admin", "=password=TestPass123"])
    run_test("attribute", "valid_login",
             "Valid login sentence with correct credentials", data)

    # Long attribute name
    long_name = "=" + "A" * 1000 + "=value"
    data = make_sentence([base_cmd, long_name])
    run_test("attribute", "long_attr_name_1KB",
             "Attribute with 1KB name", data)

    # Very long attribute name
    long_name = "=" + "A" * 10000 + "=value"
    data = make_sentence([base_cmd, long_name])
    run_test("attribute", "long_attr_name_10KB",
             "Attribute with 10KB name", data)

    # Long attribute value
    long_val = "=name=" + "B" * 10000
    data = make_sentence([base_cmd, long_val])
    run_test("attribute", "long_attr_value_10KB",
             "Attribute with 10KB value", data)

    # Missing = separator
    data = make_sentence([base_cmd, "namevalue"])
    run_test("attribute", "missing_equals",
             "Attribute word without = separator", data)

    # Extra = signs
    data = make_sentence([base_cmd, "=name=val=ue=extra=signs"])
    run_test("attribute", "extra_equals",
             "Attribute with multiple = signs", data)

    # Empty name
    data = make_sentence([base_cmd, "==value"])
    run_test("attribute", "empty_name",
             "Attribute with empty name (==value)", data)

    # Empty value
    data = make_sentence([base_cmd, "=name="])
    run_test("attribute", "empty_value",
             "Attribute with empty value (=name=)", data)

    # Both empty
    data = make_sentence([base_cmd, "=="])
    run_test("attribute", "both_empty",
             "Attribute with empty name and value (==)", data)

    # Just = sign
    data = make_sentence([base_cmd, "="])
    run_test("attribute", "just_equals",
             "Attribute that is just =", data)

    # Null bytes in name
    data = make_sentence([base_cmd, "=na\x00me=value"])
    run_test("attribute", "null_in_name",
             "Null byte in attribute name", data)

    # Null bytes in value
    data = make_sentence([base_cmd, "=name=val\x00ue"])
    run_test("attribute", "null_in_value",
             "Null byte in attribute value", data)

    # Format strings in value
    data = make_sentence([base_cmd, "=name=%s%s%s%s%s%n%n%n"])
    run_test("attribute", "format_string_value",
             "Format string specifiers in attribute value", data)

    # Format strings in name
    data = make_sentence([base_cmd, "=%n%n%n=value"])
    run_test("attribute", "format_string_name",
             "Format string specifiers in attribute name", data)

    # Binary data in value
    binary_val = bytes(range(256))
    word_content = b"=name=" + binary_val
    data = encode_length(len(word_content)) + word_content + b"\x00"
    # Wrap in proper sentence with command
    data = make_word(base_cmd) + encode_length(len(word_content)) + word_content + b"\x00"
    run_test("attribute", "binary_value",
             "All 256 byte values in attribute value", data)

    # Many duplicate attributes
    attrs = ["=name=admin"] * 50
    data = make_sentence([base_cmd] + attrs)
    run_test("attribute", "50_duplicate_attrs",
             "50 duplicate =name=admin attributes", data)

    # Many unique attributes
    attrs = [f"=attr{i}=val{i}" for i in range(100)]
    data = make_sentence([base_cmd] + attrs)
    run_test("attribute", "100_unique_attrs",
             "100 unique attributes in one sentence", data)

    # Query-style attributes (RouterOS uses ? prefix for queries)
    query_attrs = [
        "?name=admin",
        "?#=",
        "?#!",
        "?#|",
        "?#&",
    ]
    data = make_sentence(["/user/print"] + query_attrs)
    run_test("attribute", "query_operators",
             "Query operator attributes (?name=, ?#=, etc.)", data)

    # Tag attribute (.tag=)
    data = make_sentence([base_cmd, "=name=admin", "=password=TestPass123",
                          ".tag=" + "A" * 1000])
    run_test("attribute", "long_tag",
             "Login with 1KB .tag value", data)

    # API attributes with special RouterOS prefixes
    special_attrs = [
        ".id=*0",
        ".proplist=name,password",
        ".query=name=admin",
        "=numbers=*0",
    ]
    data = make_sentence(["/user/print"] + special_attrs)
    run_test("attribute", "special_prefixes",
             "Attributes with special RouterOS prefixes (.id, .proplist, .query)", data)

    # Extremely long sentence (many attributes of moderate length)
    attrs = [f"=key{i}={'V' * 100}" for i in range(200)]
    data = make_sentence([base_cmd] + attrs)
    run_test("attribute", "huge_sentence_200_attrs",
             "Huge sentence with 200 attributes of 100-char values", data)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 -- RouterOS API Protocol Fuzzer")
    log(f"Phase 7: Fuzzing -- Target: {TARGET}:{API_PORT}")
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

    # Verify API port is open
    try:
        s = api_connect(timeout=5)
        s.close()
        log(f"API port {API_PORT} is open")
    except Exception as e:
        log(f"WARNING: Cannot connect to API port {API_PORT}: {e}")
        log("Continuing anyway -- tests will record connection failures")

    # Run all fuzz categories
    try:
        fuzz_word_length_boundaries()
    except Exception as e:
        log(f"Category 1 error: {e}")
        traceback.print_exc()

    health = check_router_alive()
    if not health.get("alive"):
        wait_for_router(max_wait=120)
        time.sleep(5)

    try:
        fuzz_sentence_structure()
    except Exception as e:
        log(f"Category 2 error: {e}")
        traceback.print_exc()

    health = check_router_alive()
    if not health.get("alive"):
        wait_for_router(max_wait=120)
        time.sleep(5)

    try:
        fuzz_preauth_binary()
    except Exception as e:
        log(f"Category 3 error: {e}")
        traceback.print_exc()

    health = check_router_alive()
    if not health.get("alive"):
        wait_for_router(max_wait=120)
        time.sleep(5)

    try:
        fuzz_command_paths()
    except Exception as e:
        log(f"Category 4 error: {e}")
        traceback.print_exc()

    health = check_router_alive()
    if not health.get("alive"):
        wait_for_router(max_wait=120)
        time.sleep(5)

    try:
        fuzz_attributes()
    except Exception as e:
        log(f"Category 5 error: {e}")
        traceback.print_exc()

    # Summary findings
    if crash_events:
        ec.add_finding(
            severity="HIGH" if len(crash_events) >= 3 else "MEDIUM",
            title=f"RouterOS API stability: {len(crash_events)} crash events during fuzzing",
            description=(
                f"Router became unresponsive {len(crash_events)} time(s) during "
                f"API protocol fuzzing across {global_test_count} test cases. "
                f"Crash events: {crash_events}"
            ),
            evidence_refs=["ros_api_boofuzz"],
            cwe="CWE-120",
        )

    # Save and summarize
    ec.save("ros_api_boofuzz.json")
    ec.summary()

    log(f"\nTotal tests: {global_test_count}")
    log(f"Crash events: {len(crash_events)}")
    log(f"Findings: {len(ec.results['findings'])}")


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
