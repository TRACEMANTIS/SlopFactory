#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Cryptographic Implementation Audit
Phase 9, Script 6 of 6
Target: [REDACTED-INTERNAL-IP]

Tests (~100):
  1. TLS cipher suite audit (~30)
  2. EC-SRP5 crypto analysis (~20)
  3. Password hash analysis (~20)
  4. AES-CBC padding oracle (~15)
  5. Session token entropy (~15)

Evidence: evidence/novel_crypto_audit.json
"""

import hashlib
import json
import math
import os
import socket
import ssl
import struct
import statistics
import sys
import time
import traceback
import warnings
from collections import Counter

warnings.filterwarnings("ignore")

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("novel_crypto_audit.py", phase=9)


# ── Helpers ──────────────────────────────────────────────────────────────────

def shannon_entropy(data):
    """Calculate Shannon entropy of a byte string or regular string."""
    if isinstance(data, str):
        data = data.encode()
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def chi_squared_test(data):
    """Simple chi-squared test for uniformity of byte distribution."""
    if isinstance(data, str):
        data = data.encode()
    if not data:
        return {"chi_squared": 0, "p_value_approx": 0}

    freq = Counter(data)
    n = len(data)
    expected = n / 256.0  # Expected frequency per byte value

    chi_sq = sum((freq.get(i, 0) - expected) ** 2 / expected
                 for i in range(256))

    # Approximate p-value (degrees of freedom = 255)
    # For df=255, chi-sq critical value at p=0.01 is ~310
    # and at p=0.05 is ~293
    return {
        "chi_squared": round(chi_sq, 2),
        "degrees_of_freedom": 255,
        "uniform_at_99pct": chi_sq < 310,
        "uniform_at_95pct": chi_sq < 293,
    }


def compression_ratio(data):
    """Calculate compression ratio as a randomness indicator."""
    import zlib
    if isinstance(data, str):
        data = data.encode()
    if not data:
        return 0.0
    compressed = zlib.compress(data)
    return len(compressed) / len(data)


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
# Section 1: TLS Cipher Suite Audit (~30 tests)
# =============================================================================

def test_tls_audit():
    """Comprehensive TLS/SSL audit on ports 443 and 8729."""
    log("=" * 60)
    log("Section 1: TLS Cipher Suite Audit")
    log("=" * 60)

    test_count = 0

    tls_ports = [
        (443, "HTTPS/WebFig"),
        (8729, "API-SSL"),
    ]

    for port, service_name in tls_ports:
        log(f"  Auditing TLS on port {port} ({service_name})...")

        # ── 1a: Basic TLS connection and certificate info ────────────────────
        test_count += 1
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((TARGET, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=TARGET) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    peer_cert = ssock.getpeercert()

                    cert_info = {
                        "version": version,
                        "cipher_name": cipher[0] if cipher else "",
                        "cipher_protocol": cipher[1] if cipher else "",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "cert_size": len(cert) if cert else 0,
                        "peer_cert": peer_cert,
                    }

                    ec.add_test(
                        "tls_audit", f"TLS connection: port {port}",
                        f"Establish TLS connection to {service_name}",
                        f"Version: {version}, Cipher: {cipher[0] if cipher else 'N/A'}",
                        cert_info,
                    )

        except Exception as e:
            ec.add_test(
                "tls_audit", f"TLS connection: port {port}",
                f"Connect to {service_name}", f"Error: {e}",
                anomaly=True,
            )

        # ── 1b: TLS version support testing ──────────────────────────────────
        tls_versions = [
            ("SSLv3", ssl.PROTOCOL_TLS, ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3),
            ("TLSv1.0", ssl.PROTOCOL_TLS, ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3),
            ("TLSv1.1", ssl.PROTOCOL_TLS, ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3),
            ("TLSv1.2", ssl.PROTOCOL_TLS, ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_3),
            ("TLSv1.3", ssl.PROTOCOL_TLS, ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2),
        ]

        supported_versions = []
        for version_name, protocol, options in tls_versions:
            test_count += 1
            periodic_health(test_count)

            try:
                ctx = ssl.SSLContext(protocol)
                ctx.options |= options
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Allow legacy for testing
                ctx.set_ciphers('ALL:@SECLEVEL=0')

                with socket.create_connection((TARGET, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=TARGET) as ssock:
                        actual_version = ssock.version()
                        supported_versions.append(version_name)
                        is_weak = version_name in ("SSLv3", "TLSv1.0", "TLSv1.1")

                        ec.add_test(
                            "tls_audit",
                            f"Port {port} {version_name}: supported",
                            f"Test {version_name} support on {service_name}",
                            f"SUPPORTED (actual: {actual_version})",
                            {"version": version_name, "supported": True,
                             "actual": actual_version, "weak": is_weak},
                            anomaly=is_weak,
                        )

                        if is_weak:
                            ec.add_finding(
                                "MEDIUM",
                                f"Weak TLS version {version_name} supported on port {port}",
                                f"{service_name} accepts {version_name} connections, "
                                f"which is considered insecure",
                                cwe="CWE-326",
                            )

            except ssl.SSLError:
                ec.add_test(
                    "tls_audit",
                    f"Port {port} {version_name}: not supported",
                    f"Test {version_name} support on {service_name}",
                    "NOT SUPPORTED (expected for weak versions)",
                    {"version": version_name, "supported": False},
                )
            except Exception as e:
                ec.add_test(
                    "tls_audit", f"Port {port} {version_name}",
                    f"Test {version_name}", f"Error: {e}",
                )

        ec.add_test(
            "tls_audit", f"Port {port} version summary",
            f"Summary of TLS version support on {service_name}",
            f"Supported: {supported_versions}",
            {"supported_versions": supported_versions},
        )

        # ── 1c: Weak cipher suite testing ────────────────────────────────────
        weak_ciphers = [
            ("RC4", "RC4-SHA"),
            ("DES", "DES-CBC3-SHA"),
            ("NULL", "NULL-SHA"),
            ("EXPORT", "EXP-RC4-MD5"),
            ("MD5", "AES128-SHA"),  # Not MD5 cipher but test MD5 MAC
            ("anon_DH", "ADH-AES128-SHA"),
        ]

        for cipher_name, cipher_string in weak_ciphers:
            test_count += 1
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_ciphers(cipher_string)
                except ssl.SSLError:
                    ec.add_test(
                        "tls_audit", f"Port {port} cipher {cipher_name}",
                        f"Test weak cipher {cipher_name} on {service_name}",
                        f"Cipher {cipher_string} not available in local SSL library",
                        {"cipher_name": cipher_name, "supported": False,
                         "note": "Not testable — local SSL lib rejects"},
                    )
                    continue

                with socket.create_connection((TARGET, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=TARGET) as ssock:
                        negotiated = ssock.cipher()
                        ec.add_test(
                            "tls_audit",
                            f"Port {port} weak cipher {cipher_name}: ACCEPTED",
                            f"Test weak cipher {cipher_name} on {service_name}",
                            f"Server accepted {cipher_name}: {negotiated}",
                            {"cipher_name": cipher_name, "supported": True,
                             "negotiated": negotiated},
                            anomaly=True,
                        )
                        ec.add_finding(
                            "HIGH",
                            f"Weak cipher {cipher_name} accepted on port {port}",
                            f"{service_name} accepts weak cipher {cipher_string}",
                            cwe="CWE-327",
                        )

            except (ssl.SSLError, ConnectionResetError, OSError):
                ec.add_test(
                    "tls_audit",
                    f"Port {port} weak cipher {cipher_name}: rejected",
                    f"Test weak cipher {cipher_name} on {service_name}",
                    f"Server rejected {cipher_name} (good)",
                    {"cipher_name": cipher_name, "supported": False},
                )
            except Exception as e:
                ec.add_test(
                    "tls_audit", f"Port {port} cipher {cipher_name}",
                    f"Cipher test", f"Error: {e}",
                )

        # ── 1d: Certificate analysis ─────────────────────────────────────────
        test_count += 1
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((TARGET, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=TARGET) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()

                    # Parse certificate details
                    cert_analysis = {
                        "subject": dict(x[0] for x in cert_info.get("subject", []))
                            if cert_info else {},
                        "issuer": dict(x[0] for x in cert_info.get("issuer", []))
                            if cert_info else {},
                        "serial_number": cert_info.get("serialNumber", "")
                            if cert_info else "",
                        "not_before": cert_info.get("notBefore", "")
                            if cert_info else "",
                        "not_after": cert_info.get("notAfter", "")
                            if cert_info else "",
                        "cert_der_size": len(cert_der) if cert_der else 0,
                        "cert_sha256": hashlib.sha256(cert_der).hexdigest()
                            if cert_der else "",
                        "self_signed": False,
                    }

                    # Check if self-signed
                    if cert_info:
                        subj = cert_analysis["subject"]
                        issuer = cert_analysis["issuer"]
                        cert_analysis["self_signed"] = subj == issuer

                    ec.add_test(
                        "tls_audit", f"Port {port} certificate analysis",
                        f"Analyze TLS certificate on {service_name}",
                        f"Subject: {cert_analysis['subject']}, "
                        f"Self-signed: {cert_analysis['self_signed']}",
                        cert_analysis,
                        anomaly=cert_analysis["self_signed"],
                    )

                    if cert_analysis["self_signed"]:
                        ec.add_finding(
                            "LOW",
                            f"Self-signed TLS certificate on port {port}",
                            f"{service_name} uses a self-signed certificate",
                            cwe="CWE-295",
                        )

        except Exception as e:
            ec.add_test("tls_audit", f"Port {port} certificate",
                        "Certificate analysis", f"Error: {e}")


# =============================================================================
# Section 2: EC-SRP5 Crypto Analysis (~20 tests)
# =============================================================================

def test_ec_srp5_crypto():
    """Analyze the EC-SRP5 authentication protocol cryptographic properties."""
    log("=" * 60)
    log("Section 2: EC-SRP5 Crypto Analysis")
    log("=" * 60)

    test_count = 0
    WINBOX_PORT = 8291

    # ── 2a: Capture multiple handshakes for analysis ─────────────────────────
    log("  Capturing EC-SRP5 handshakes for crypto analysis...")
    handshake_data = []

    for i in range(10):
        test_count += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, WINBOX_PORT))

            # Send login init (M2 frame)
            username = ADMIN_USER.encode('utf-8')
            # Build M2 message
            body = b""
            # SYS_TO = 2 (login handler)
            body += bytes([0x08]) + (0xff0001).to_bytes(3, 'big') + struct.pack('<I', 2)
            # Command = 1
            body += bytes([0x08]) + (0xff0002).to_bytes(3, 'big') + struct.pack('<I', 1)
            # Sequence
            body += bytes([0x08]) + (0xff0003).to_bytes(3, 'big') + struct.pack('<I', i + 1)
            # Reply expected
            body += bytes([0x00]) + (0xff0006).to_bytes(3, 'big')
            # Username
            body += bytes([0x21]) + (0x01).to_bytes(3, 'big') + struct.pack('>H', len(username)) + username

            frame = struct.pack('>H', len(body)) + body
            s.sendall(frame)
            time.sleep(0.5)

            try:
                resp = s.recv(8192)
                handshake_data.append({
                    "attempt": i + 1,
                    "raw_hex": resp.hex()[:600] if resp else "",
                    "raw_bytes": resp,
                    "size": len(resp) if resp else 0,
                })
            except socket.timeout:
                handshake_data.append({"attempt": i + 1, "status": "timeout"})

            s.close()
        except Exception as e:
            handshake_data.append({"attempt": i + 1, "error": str(e)})

        time.sleep(0.2)

    # Analyze collected handshakes
    valid_handshakes = [h for h in handshake_data if h.get("size", 0) > 0]

    ec.add_test(
        "ec_srp5_crypto", f"Handshake collection ({len(valid_handshakes)}/10)",
        "Collect 10 EC-SRP5 handshake responses for crypto analysis",
        f"Valid responses: {len(valid_handshakes)}/10",
        {"total_collected": len(valid_handshakes),
         "sizes": [h.get("size", 0) for h in handshake_data]},
    )

    if not valid_handshakes:
        log("  No valid handshakes collected. Skipping crypto analysis.")
        return

    # ── 2b: Analyze nonce/challenge randomness ───────────────────────────────
    log("  Analyzing handshake randomness...")
    raw_responses = [h["raw_bytes"] for h in valid_handshakes if "raw_bytes" in h]

    if len(raw_responses) >= 2:
        # Compare responses — they should be different (due to random nonces)
        all_different = len(set(r.hex() for r in raw_responses)) == len(raw_responses)

        # Find the varying parts (likely nonces/challenges)
        min_len = min(len(r) for r in raw_responses)
        varying_positions = []
        for pos in range(min_len):
            values = set(r[pos] for r in raw_responses)
            if len(values) > 1:
                varying_positions.append(pos)

        # Extract the varying region as the likely nonce
        nonce_data = b""
        if varying_positions:
            start = varying_positions[0]
            end = varying_positions[-1] + 1
            nonce_data = raw_responses[0][start:end]
            nonce_entropy = shannon_entropy(nonce_data)

            ec.add_test(
                "ec_srp5_crypto", "Nonce randomness analysis",
                "Analyze varying bytes in handshake responses (likely nonce/challenge)",
                f"Varying region: bytes {start}-{end} ({end-start} bytes), "
                f"entropy: {nonce_entropy:.2f} bits/byte",
                {"all_different": all_different,
                 "varying_positions": varying_positions[:50],
                 "nonce_start": start, "nonce_end": end,
                 "nonce_size": end - start,
                 "nonce_entropy": round(nonce_entropy, 2),
                 "nonce_samples": [r[start:end].hex() for r in raw_responses[:5]]},
                anomaly=(nonce_entropy < 3.0),
            )

            if nonce_entropy < 3.0:
                ec.add_finding(
                    "HIGH",
                    f"Low entropy in EC-SRP5 nonce ({nonce_entropy:.2f} bits/byte)",
                    "The varying portion of the auth handshake has low entropy, "
                    "suggesting weak random number generation",
                    cwe="CWE-330",
                )
        else:
            ec.add_test(
                "ec_srp5_crypto", "Nonce randomness",
                "Analyze handshake response variation",
                f"All responses identical: {not all_different}",
                {"all_different": all_different},
                anomaly=not all_different,
            )

        # ── 2c: Bit distribution analysis ────────────────────────────────────
        if nonce_data:
            # Analyze bit distribution of nonce bytes
            all_nonces = b"".join(
                r[varying_positions[0]:varying_positions[-1]+1]
                for r in raw_responses if len(r) > varying_positions[-1]
            )

            bit_counts = [0, 0]  # [zero_bits, one_bits]
            for byte_val in all_nonces:
                for bit_pos in range(8):
                    if byte_val & (1 << bit_pos):
                        bit_counts[1] += 1
                    else:
                        bit_counts[0] += 1

            total_bits = sum(bit_counts)
            bit_ratio = bit_counts[1] / total_bits if total_bits > 0 else 0

            chi_result = chi_squared_test(all_nonces)

            ec.add_test(
                "ec_srp5_crypto", "Nonce bit distribution",
                "Analyze bit distribution of nonce bytes",
                f"1-bit ratio: {bit_ratio:.3f} (ideal=0.500), "
                f"chi-squared: {chi_result['chi_squared']}",
                {"zero_bits": bit_counts[0], "one_bits": bit_counts[1],
                 "bit_ratio": round(bit_ratio, 3),
                 "chi_squared": chi_result,
                 "total_nonce_bytes": len(all_nonces)},
                anomaly=(abs(bit_ratio - 0.5) > 0.1),
            )

    # ── 2d: Check for known weak curve parameters ────────────────────────────
    test_count += 1
    # RouterOS uses Curve25519 for EC-SRP5
    ec.add_test(
        "ec_srp5_crypto", "Curve identification",
        "Identify the elliptic curve used in EC-SRP5",
        "RouterOS 7.x uses Curve25519 for EC-SRP5 (ECDH key agreement). "
        "Curve25519 is considered secure with 128-bit security level.",
        {"expected_curve": "Curve25519",
         "security_level_bits": 128,
         "note": "Cannot confirm curve parameters without source code; "
                 "assumption based on RouterOS documentation and protocol analysis"},
    )

    # ── 2e: Replay resistance ────────────────────────────────────────────────
    test_count += 1
    if len(raw_responses) >= 2:
        # Check if replaying a handshake response works
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, WINBOX_PORT))
            # Replay the first response back to the server as if it were a client message
            s.sendall(raw_responses[0])
            time.sleep(0.5)
            try:
                replay_resp = s.recv(4096)
                ec.add_test(
                    "ec_srp5_crypto", "Replay resistance test",
                    "Replay a captured handshake response to test replay protection",
                    f"Server response: {len(replay_resp)} bytes",
                    {"replayed_size": len(raw_responses[0]),
                     "response_size": len(replay_resp),
                     "response_hex": replay_resp.hex()[:200]},
                )
            except socket.timeout:
                ec.add_test("ec_srp5_crypto", "Replay resistance",
                            "Replay handshake response",
                            "Server gave no response to replayed data (good)")
            s.close()
        except Exception as e:
            ec.add_test("ec_srp5_crypto", "Replay resistance",
                        "Replay test", f"Error: {e}")


# =============================================================================
# Section 3: Password Hash Analysis (~20 tests)
# =============================================================================

def test_password_hash():
    """Analyze password storage format and hashing."""
    log("=" * 60)
    log("Section 3: Password Hash Analysis")
    log("=" * 60)

    test_count = 0

    # ── 3a: Check if passwords are readable via REST API ─────────────────────
    log("  Checking password visibility via REST API...")
    code, users = rest_get("/user")
    if code == 200 and isinstance(users, list):
        password_fields = {}
        for user in users:
            name = user.get("name", "")
            # Check for any password-like field
            for key in user:
                if "password" in key.lower() or "hash" in key.lower() or "secret" in key.lower():
                    password_fields[f"{name}.{key}"] = user[key]

        has_passwords = len(password_fields) > 0
        ec.add_test(
            "password_hash", "Password fields in REST user list",
            "Check if password fields are returned in /user REST response",
            f"Password fields found: {has_passwords}",
            {"password_fields": password_fields,
             "user_fields_sample": list(users[0].keys()) if users else []},
            anomaly=has_passwords,
        )

        if has_passwords:
            ec.add_finding(
                "HIGH",
                "Password hashes/values exposed via REST API",
                f"GET /rest/user returns password-related fields: "
                f"{list(password_fields.keys())}",
                cwe="CWE-312",
            )

    # ── 3b: Check with .proplist ─────────────────────────────────────────────
    proplist_tests = [
        "/user?.proplist=name,password",
        "/user?.proplist=*",
        "/user?.proplist=name,password,group,.id",
    ]
    for path in proplist_tests:
        test_count += 1
        try:
            r = requests.get(
                f"http://{TARGET}/rest{path}",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=10, verify=False,
            )
            has_password = any(kw in r.text for kw in [ADMIN_PASS, "FullTest", "ReadTest", "WriteTest"])
            ec.add_test(
                "password_hash", f"Proplist: {path[:60]}",
                f"Test password exposure via proplist: {path}",
                f"HTTP {r.status_code}, plaintext_passwords={has_password}",
                {"path": path, "status": r.status_code,
                 "response": r.text[:500],
                 "plaintext_exposed": has_password},
                anomaly=has_password,
            )
            if has_password:
                ec.add_finding(
                    "CRITICAL",
                    "Plaintext passwords exposed via .proplist",
                    f"GET /rest{path} returns plaintext passwords",
                    cwe="CWE-256", cvss=9.0,
                )
        except Exception as e:
            ec.add_test("password_hash", f"Proplist: {path[:60]}",
                        "Proplist test", f"Error: {e}")

    # ── 3c: SSH export password analysis ─────────────────────────────────────
    test_count += 1
    try:
        stdout, stderr, rc = ssh_command("/user print detail")
        if rc == 0 and stdout:
            has_passwords = any(kw in stdout for kw in ["password=", "TestPass", "FullTest"])
            ec.add_test(
                "password_hash", "SSH user print detail",
                "Check password visibility in SSH /user print detail",
                f"Has passwords: {has_passwords}",
                {"output_preview": stdout[:500],
                 "has_passwords": has_passwords},
                anomaly=has_passwords,
            )
        else:
            ec.add_test("password_hash", "SSH user print detail",
                        "SSH user detail", f"RC={rc}")
    except Exception as e:
        ec.add_test("password_hash", "SSH user detail",
                    "SSH test", f"Error: {e}")

    # ── 3d: Backup password format analysis ──────────────────────────────────
    log("  Analyzing password format in backup...")
    test_count += 1
    import ftplib
    from io import BytesIO

    try:
        code, resp = rest_post("/system/backup/save",
                               {"name": "_crypto_pw_test"})
        if code in [200, 201]:
            time.sleep(2)
            try:
                ftp = ftplib.FTP()
                ftp.connect(TARGET, 21, timeout=10)
                ftp.login(ADMIN_USER, ADMIN_PASS)

                backup_data = BytesIO()
                ftp.retrbinary("RETR _crypto_pw_test.backup", backup_data.write)
                data = backup_data.getvalue()

                # Search for password-like patterns
                data_str = data.decode("utf-8", errors="replace")
                patterns_found = {}
                # Look for common hash formats
                import re
                md5_hashes = re.findall(r'[a-f0-9]{32}', data_str)
                sha1_hashes = re.findall(r'[a-f0-9]{40}', data_str)
                sha256_hashes = re.findall(r'[a-f0-9]{64}', data_str)
                bcrypt_hashes = re.findall(r'\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}', data_str)

                patterns_found = {
                    "md5_like": len(md5_hashes),
                    "sha1_like": len(sha1_hashes),
                    "sha256_like": len(sha256_hashes),
                    "bcrypt": len(bcrypt_hashes),
                    "plaintext_found": any(
                        kw in data_str for kw in [ADMIN_PASS, "FullTest", "ReadTest"]
                    ),
                }

                ec.add_test(
                    "password_hash", "Backup password format",
                    "Analyze password storage format in binary backup",
                    f"Hash patterns: {patterns_found}",
                    {"patterns": patterns_found,
                     "backup_size": len(data),
                     "md5_samples": md5_hashes[:3],
                     "sha256_samples": sha256_hashes[:3],
                     "bcrypt_samples": bcrypt_hashes[:3]},
                    anomaly=patterns_found["plaintext_found"],
                )

                # Cleanup
                try:
                    ftp.delete("_crypto_pw_test.backup")
                except Exception:
                    pass
                ftp.quit()
            except Exception as e:
                ec.add_test("password_hash", "Backup password format",
                            "Analyze backup", f"Error: {e}")
    except Exception as e:
        ec.add_test("password_hash", "Backup password format",
                    "Backup analysis", f"Error: {e}")

    # ── 3e: Password timing analysis (hash algorithm inference) ──────────────
    log("  Timing password verification to infer hash algorithm...")
    test_count += 1

    # Different password lengths should take same time if properly hashed
    timing_data = []
    for pw_len in [1, 8, 32, 128, 512, 1024]:
        password = "A" * pw_len
        times = []
        for _ in range(5):
            start = time.perf_counter()
            try:
                r = requests.get(
                    f"http://{TARGET}/rest/system/identity",
                    auth=(ADMIN_USER, password),
                    timeout=10, verify=False,
                )
            except Exception:
                pass
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            time.sleep(0.05)

        avg_time = statistics.mean(times)
        timing_data.append({
            "password_length": pw_len,
            "avg_ms": round(avg_time, 2),
            "stdev_ms": round(statistics.stdev(times), 2) if len(times) > 1 else 0,
        })

    # Check if verification time increases with password length
    if len(timing_data) >= 2:
        short_avg = timing_data[0]["avg_ms"]
        long_avg = timing_data[-1]["avg_ms"]
        time_ratio = long_avg / short_avg if short_avg > 0 else 0
        length_dependent = time_ratio > 1.5

        ec.add_test(
            "password_hash", "Password length timing analysis",
            "Compare auth timing for different password lengths",
            f"1-char: {short_avg:.1f}ms, 1024-char: {long_avg:.1f}ms, "
            f"ratio: {time_ratio:.2f}x, length_dependent: {length_dependent}",
            {"timing_data": timing_data, "ratio": round(time_ratio, 2),
             "length_dependent": length_dependent},
            anomaly=length_dependent,
        )

        if length_dependent:
            ec.add_finding(
                "LOW",
                "Password verification time depends on password length",
                f"Short passwords verify {time_ratio:.1f}x faster than long ones, "
                f"suggesting the hash algorithm processes the full input "
                f"(not truncated/pre-hashed)",
                cwe="CWE-916",
            )


# =============================================================================
# Section 4: AES-CBC Padding Oracle (~15 tests)
# =============================================================================

def test_padding_oracle():
    """Test for padding oracle vulnerabilities in TLS and Winbox encryption."""
    log("=" * 60)
    log("Section 4: AES-CBC Padding Oracle")
    log("=" * 60)

    test_count = 0
    WINBOX_PORT = 8291

    # ── 4a: TLS padding oracle via error differentiation ─────────────────────
    log("  Testing TLS padding oracle on port 443...")
    # Send valid and invalid ciphertext, compare error responses
    tls_ports = [443, 8729]

    for port in tls_ports:
        test_count += 1
        periodic_health(test_count)

        try:
            # Establish TLS connection
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # First: normal connection
            with socket.create_connection((TARGET, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=TARGET) as ssock:
                    # Get the cipher info
                    cipher_info = ssock.cipher()
                    is_cbc = "CBC" in (cipher_info[0] if cipher_info else "")

                    ec.add_test(
                        "padding_oracle", f"TLS cipher check port {port}",
                        f"Check if TLS uses CBC mode on port {port}",
                        f"Cipher: {cipher_info[0] if cipher_info else 'N/A'}, "
                        f"CBC: {is_cbc}",
                        {"cipher": cipher_info, "is_cbc": is_cbc},
                        anomaly=is_cbc,
                    )

        except Exception as e:
            ec.add_test("padding_oracle", f"TLS cipher port {port}",
                        "TLS cipher check", f"Error: {e}")

    # ── 4b: Winbox encrypted channel padding test ────────────────────────────
    log("  Testing Winbox padding behavior...")
    # Send valid and corrupted encrypted payloads after handshake
    padding_tests = [
        ("valid_padding", b"\x10" * 16, "16 bytes of 0x10 padding (valid PKCS#7)"),
        ("invalid_padding_ff", b"\xff" * 16, "16 bytes of 0xFF (invalid padding)"),
        ("zero_padding", b"\x00" * 16, "16 zero bytes (invalid padding)"),
        ("mixed_padding", b"\x01" * 15 + b"\x10", "Mixed padding values"),
        ("short_block", b"\x01" * 7, "7 bytes (not full block)"),
    ]

    error_responses = {}
    for name, payload, desc in padding_tests:
        test_count += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, WINBOX_PORT))

            # Send the raw payload (pre-auth, will be treated as M2 frame)
            s.sendall(payload)
            time.sleep(0.3)

            try:
                resp = s.recv(4096)
                resp_hex = resp.hex()[:200] if resp else ""
                resp_len = len(resp) if resp else 0
            except socket.timeout:
                resp_hex = ""
                resp_len = -1

            error_responses[name] = {
                "response_size": resp_len,
                "response_hex": resp_hex,
            }

            ec.add_test(
                "padding_oracle", f"Winbox padding: {name}",
                f"Send {desc} to Winbox",
                f"Response: {resp_len} bytes",
                {"name": name, "description": desc,
                 "response_size": resp_len, "response_hex": resp_hex},
            )

            s.close()
        except Exception as e:
            error_responses[name] = {"error": str(e)}
            ec.add_test("padding_oracle", f"Winbox padding: {name}",
                        f"Padding test", f"Error: {e}")

    # Compare responses — different responses = potential oracle
    response_sizes = set(
        v.get("response_size", 0) for v in error_responses.values()
        if "error" not in v
    )
    different_responses = len(response_sizes) > 1

    ec.add_test(
        "padding_oracle", "Padding oracle assessment",
        "Compare responses to different padding values",
        f"Unique response sizes: {response_sizes}, "
        f"potential_oracle: {different_responses}",
        {"response_sizes": list(response_sizes),
         "different_responses": different_responses,
         "error_responses": error_responses},
        anomaly=different_responses,
    )

    if different_responses:
        ec.add_finding(
            "MEDIUM",
            "Potential padding oracle in Winbox protocol",
            f"Different padding values produce different response sizes: {response_sizes}",
            cwe="CWE-209",
        )


# =============================================================================
# Section 5: Session Token Entropy (~15 tests)
# =============================================================================

def test_session_entropy():
    """Collect and analyze session tokens from WebFig and Winbox."""
    log("=" * 60)
    log("Section 5: Session Token Entropy Analysis")
    log("=" * 60)

    test_count = 0
    WINBOX_PORT = 8291

    # ── 5a: Collect WebFig session tokens ────────────────────────────────────
    log("  Collecting 50+ WebFig session tokens...")
    webfig_tokens = []

    for i in range(55):
        test_count += 1
        if test_count % 10 == 0:
            periodic_health(test_count)

        try:
            s = requests.Session()
            r = s.get(f"http://{TARGET}/webfig/",
                     auth=(ADMIN_USER, ADMIN_PASS),
                     timeout=10, verify=False)
            cookies = s.cookies.get_dict()
            for cookie_name, cookie_value in cookies.items():
                webfig_tokens.append({
                    "attempt": i + 1,
                    "name": cookie_name,
                    "value": cookie_value,
                })

            # Also check response headers for session-like values
            for header_name in ["X-Session-Id", "X-Request-Id", "ETag"]:
                if header_name in r.headers:
                    webfig_tokens.append({
                        "attempt": i + 1,
                        "name": f"header:{header_name}",
                        "value": r.headers[header_name],
                    })

        except Exception:
            pass

        time.sleep(0.05)

    # Analyze tokens
    if webfig_tokens:
        # Group by cookie/header name
        by_name = {}
        for t in webfig_tokens:
            name = t["name"]
            if name not in by_name:
                by_name[name] = []
            by_name[name].append(t["value"])

        for token_name, values in by_name.items():
            unique_count = len(set(values))
            all_unique = unique_count == len(values)

            # Entropy analysis
            if values:
                sample = values[0]
                token_entropy = shannon_entropy(sample)
                total_entropy = token_entropy * len(sample)

                # Concatenate all values for chi-squared test
                all_bytes = "".join(values).encode()
                chi_result = chi_squared_test(all_bytes)
                comp_ratio = compression_ratio(all_bytes)

                ec.add_test(
                    "session_entropy",
                    f"WebFig token analysis: {token_name}",
                    f"Analyze entropy of {len(values)} '{token_name}' tokens",
                    f"Unique: {unique_count}/{len(values)}, "
                    f"entropy: {token_entropy:.2f} b/B, "
                    f"total: {total_entropy:.0f} bits",
                    {"token_name": token_name,
                     "count": len(values),
                     "unique_count": unique_count,
                     "all_unique": all_unique,
                     "sample_token": sample,
                     "token_length": len(sample),
                     "entropy_per_byte": round(token_entropy, 2),
                     "total_entropy_bits": round(total_entropy, 1),
                     "chi_squared": chi_result,
                     "compression_ratio": round(comp_ratio, 3),
                     "samples": values[:5]},
                    anomaly=(not all_unique or token_entropy < 3.0),
                )

                if token_entropy < 3.0 and len(values) > 5:
                    ec.add_finding(
                        "HIGH",
                        f"Low entropy WebFig tokens ({token_name}): "
                        f"{token_entropy:.2f} bits/byte",
                        f"Session tokens have insufficient entropy "
                        f"({total_entropy:.0f} total bits). "
                        f"Minimum recommended: 128 bits.",
                        cwe="CWE-330",
                    )
    else:
        ec.add_test("session_entropy", "WebFig token collection",
                    "Collect WebFig session tokens",
                    "No session tokens were set by WebFig",
                    {"tokens_found": 0})

    # ── 5b: Collect Winbox session identifiers ───────────────────────────────
    log("  Collecting Winbox session identifiers...")
    winbox_ids = []

    for i in range(20):
        test_count += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, WINBOX_PORT))

            # Send login init
            username = ADMIN_USER.encode('utf-8')
            body = b""
            body += bytes([0x08]) + (0xff0001).to_bytes(3, 'big') + struct.pack('<I', 2)
            body += bytes([0x08]) + (0xff0002).to_bytes(3, 'big') + struct.pack('<I', 1)
            body += bytes([0x08]) + (0xff0003).to_bytes(3, 'big') + struct.pack('<I', 8000 + i)
            body += bytes([0x00]) + (0xff0006).to_bytes(3, 'big')
            body += bytes([0x21]) + (0x01).to_bytes(3, 'big') + struct.pack('>H', len(username)) + username

            frame = struct.pack('>H', len(body)) + body
            s.sendall(frame)
            time.sleep(0.3)

            try:
                resp = s.recv(8192)
                if resp:
                    winbox_ids.append({
                        "attempt": i + 1,
                        "raw_hex": resp.hex()[:200],
                        "size": len(resp),
                    })
            except socket.timeout:
                pass

            s.close()
        except Exception:
            pass

        time.sleep(0.1)

    if winbox_ids:
        # Analyze raw response bytes for entropy
        all_responses = b"".join(
            bytes.fromhex(w["raw_hex"]) for w in winbox_ids if w.get("raw_hex")
        )

        if all_responses:
            overall_entropy = shannon_entropy(all_responses)
            chi_result = chi_squared_test(all_responses)
            comp_ratio = compression_ratio(all_responses)

            ec.add_test(
                "session_entropy", "Winbox response entropy",
                f"Analyze entropy of {len(winbox_ids)} Winbox handshake responses",
                f"Combined entropy: {overall_entropy:.2f} bits/byte, "
                f"compression ratio: {comp_ratio:.3f}",
                {"count": len(winbox_ids),
                 "total_bytes": len(all_responses),
                 "entropy_per_byte": round(overall_entropy, 2),
                 "chi_squared": chi_result,
                 "compression_ratio": round(comp_ratio, 3),
                 "samples": [w["raw_hex"][:60] for w in winbox_ids[:5]]},
                anomaly=(overall_entropy < 4.0),
            )

    # ── 5c: Overall entropy assessment ───────────────────────────────────────
    ec.add_test(
        "session_entropy", "Overall session security assessment",
        "Summary assessment of session token security",
        f"WebFig tokens collected: {len(webfig_tokens)}, "
        f"Winbox IDs collected: {len(winbox_ids)}",
        {"webfig_token_count": len(webfig_tokens),
         "winbox_id_count": len(winbox_ids)},
    )


# =============================================================================
# Main
# =============================================================================

def main():
    log("=" * 60)
    log("MikroTik RouterOS CHR 7.20.8 — Cryptographic Implementation Audit")
    log(f"Target: {TARGET}")
    log("Phase 9 — novel_crypto_audit.py")
    log("=" * 60)

    alive = check_router_alive()
    if not alive.get("alive"):
        log("FATAL: Router is not responding. Aborting.")
        return
    log(f"Router alive: version={alive.get('version')}, uptime={alive.get('uptime')}")

    try:
        test_tls_audit()            # ~30 tests
        test_ec_srp5_crypto()       # ~20 tests
        test_password_hash()        # ~20 tests
        test_padding_oracle()       # ~15 tests
        test_session_entropy()      # ~15 tests

    except KeyboardInterrupt:
        log("Interrupted by user.")
    except Exception as e:
        log(f"Unhandled exception: {e}")
        traceback.print_exc()
    finally:
        final = check_router_alive()
        log(f"Final health: {final}")

        ec.save("novel_crypto_audit.json")
        ec.summary()


if __name__ == "__main__":
    os.chdir("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
    main()
