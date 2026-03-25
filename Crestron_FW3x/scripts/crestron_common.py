"""
Crestron Security Assessment - Common Utilities
EvidenceCollector, CTP client, CIP client
"""
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime


class EvidenceCollector:
    """Standard evidence collection for security assessment."""

    def __init__(self, script_name, output_dir="/home/[REDACTED]/Desktop/[REDACTED-PATH]/Crestron/evidence"):
        self.script_name = script_name
        self.output_dir = output_dir
        self.tests = []
        self.findings = []
        self.anomalies = []
        self.start_time = datetime.now().isoformat()
        os.makedirs(output_dir, exist_ok=True)

    def add_test(self, test_id, description, request, response, status="INFO"):
        self.tests.append({
            "id": test_id,
            "description": description,
            "request": request if isinstance(request, str) else repr(request),
            "response": response if isinstance(response, str) else repr(response),
            "status": status,
            "timestamp": datetime.now().isoformat()
        })

    def add_finding(self, finding_id, severity, title, details):
        self.findings.append({
            "id": finding_id,
            "severity": severity,
            "title": title,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def add_anomaly(self, anomaly_id, description):
        self.anomalies.append({
            "id": anomaly_id,
            "description": description,
            "timestamp": datetime.now().isoformat()
        })

    def save(self, filename=None):
        if filename is None:
            filename = f"{self.script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        data = {
            "script": self.script_name,
            "start_time": self.start_time,
            "end_time": datetime.now().isoformat(),
            "test_count": len(self.tests),
            "finding_count": len(self.findings),
            "anomaly_count": len(self.anomalies),
            "tests": self.tests,
            "findings": self.findings,
            "anomalies": self.anomalies
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[*] Evidence saved to {filepath}")
        print(f"    Tests: {len(self.tests)}, Findings: {len(self.findings)}, Anomalies: {len(self.anomalies)}")
        return filepath


class CTPClient:
    """
    Crestron Toolbox Protocol (CTP) client for port 41795.
    CTP is a text-based console protocol used for device management.
    Commands are sent as plain text lines terminated with \\r\\n.
    """

    def __init__(self, host, port=41795, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.banner = None

    def connect(self):
        """Connect to CTP console."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        # Read banner/prompt
        time.sleep(0.5)
        self.banner = self._recv_all()
        return self.banner

    def send_command(self, command, wait=1.0):
        """Send a CTP console command and return the response."""
        if self.sock is None:
            raise ConnectionError("Not connected")
        cmd = command.strip() + "\r\n"
        self.sock.send(cmd.encode('ascii', errors='replace'))
        time.sleep(wait)
        return self._recv_all()

    def _recv_all(self, bufsize=8192):
        """Receive all available data from socket."""
        data = b""
        self.sock.setblocking(False)
        try:
            while True:
                try:
                    chunk = self.sock.recv(bufsize)
                    if not chunk:
                        break
                    data += chunk
                except BlockingIOError:
                    break
                except socket.error:
                    break
        finally:
            self.sock.setblocking(True)
            self.sock.settimeout(self.timeout)
        return data.decode('ascii', errors='replace')

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


class CIPClient:
    """
    Crestron Internet Protocol (CIP) client for port 41794.
    CIP is a binary protocol for device-to-device communication.

    Message format: type(1 byte) | length(2 bytes BE) | payload(length bytes)

    Message types:
        0x01 - IP ID registration request
        0x02 - IP ID registration response
        0x03 - Program stopping
        0x05 - Data (digital/analog/serial joins)
        0x0D - Heartbeat request
        0x0E - Heartbeat response
        0x0F - Processor response
        0x14 - UDP discovery request
        0x15 - UDP discovery response
    """

    # CIP message types
    MSG_REGISTER = 0x01
    MSG_REGISTER_RESP = 0x02
    MSG_DISCONNECT = 0x03
    MSG_DATA = 0x05
    MSG_HEARTBEAT_REQ = 0x0D
    MSG_HEARTBEAT_RESP = 0x0E
    MSG_PROCESSOR_RESP = 0x0F
    MSG_UDP_DISCOVERY = 0x14
    MSG_UDP_DISCOVERY_RESP = 0x15

    def __init__(self, host, port=41794, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.registered = False

    def connect_tcp(self):
        """Establish TCP connection to CIP port."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        # Wait for processor handshake
        time.sleep(0.5)
        resp = self._recv_message()
        return resp

    def send_udp_probe(self):
        """Send UDP discovery probe (1-byte 0x14) and return response."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(b'\x14', (self.host, self.port))
            data, addr = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return None
        finally:
            sock.close()

    def register_ipid(self, ipid=0x03):
        """Register an IP ID with the control processor."""
        # Registration packet: 0x01 0x00 0x07 0x7F 0x00 0x00 0x01 0x00 <IPID> 0x40
        payload = bytes([0x7F, 0x00, 0x00, 0x01, 0x00, ipid, 0x40])
        self._send_message(self.MSG_REGISTER, payload)
        time.sleep(0.5)
        resp = self._recv_message()
        if resp and resp[0] == self.MSG_REGISTER_RESP:
            self.registered = True
        return resp

    def send_heartbeat(self):
        """Send heartbeat to maintain connection."""
        self._send_message(self.MSG_HEARTBEAT_REQ, b'')
        time.sleep(0.3)
        return self._recv_message()

    def send_digital_join(self, join_number, value):
        """Send a digital join press/release."""
        # Digital join encoding: join number adjusted, MSB indicates state
        join_adj = join_number - 1
        join_high = (join_adj >> 8) & 0xFF
        join_low = join_adj & 0x7F
        if not value:
            join_low |= 0x80  # Set MSB for release/off
        payload = bytes([0x00, 0x00, 0x03, 0x00, join_high, join_low])
        self._send_message(self.MSG_DATA, payload)

    def send_analog_join(self, join_number, value):
        """Send an analog join value (0-65535)."""
        join_adj = join_number - 1
        if join_adj < 256:
            payload = bytes([0x00, 0x00, 0x04, 0x01, join_adj & 0xFF,
                           (value >> 8) & 0xFF, value & 0xFF])
        else:
            payload = bytes([0x00, 0x00, 0x05, 0x01,
                           (join_adj >> 8) & 0xFF, join_adj & 0xFF,
                           (value >> 8) & 0xFF, value & 0xFF])
        self._send_message(self.MSG_DATA, payload)

    def send_serial_join(self, join_number, text):
        """Send a serial join string."""
        # Serial join format: header + "#<join>,<text>\r"
        join_str = f"#{join_number},{text}\r"
        payload = bytes([0x00, 0x00, len(join_str) + 1, 0x02]) + join_str.encode('ascii', errors='replace')
        self._send_message(self.MSG_DATA, payload)

    def send_raw(self, data):
        """Send raw bytes and return response."""
        if isinstance(data, str):
            data = bytes.fromhex(data.replace(' ', ''))
        self.sock.send(data)
        time.sleep(0.5)
        return self._recv_raw()

    def _send_message(self, msg_type, payload):
        """Send a CIP message with proper framing."""
        length = len(payload)
        header = bytes([msg_type, (length >> 8) & 0xFF, length & 0xFF])
        self.sock.send(header + payload)

    def _recv_message(self):
        """Receive and parse a CIP message."""
        try:
            header = b""
            while len(header) < 3:
                chunk = self.sock.recv(3 - len(header))
                if not chunk:
                    return None
                header += chunk
            msg_type = header[0]
            length = (header[1] << 8) | header[2]
            payload = b""
            while len(payload) < length:
                chunk = self.sock.recv(length - len(payload))
                if not chunk:
                    break
                payload += chunk
            return (msg_type, length, payload)
        except socket.timeout:
            return None
        except Exception as e:
            return None

    def _recv_raw(self, bufsize=8192):
        """Receive all available raw data."""
        data = b""
        self.sock.setblocking(False)
        try:
            while True:
                try:
                    chunk = self.sock.recv(bufsize)
                    if not chunk:
                        break
                    data += chunk
                except BlockingIOError:
                    break
        finally:
            self.sock.setblocking(True)
            self.sock.settimeout(self.timeout)
        return data

    def close(self):
        if self.sock:
            try:
                self._send_message(self.MSG_DISCONNECT, b'')
            except:
                pass
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def __enter__(self):
        self.connect_tcp()
        return self

    def __exit__(self, *args):
        self.close()


def parse_udp_response(data):
    """Parse a CIP UDP discovery response (394 bytes)."""
    if not data or len(data) < 10:
        return None
    result = {
        "raw_hex": data.hex(),
        "raw_length": len(data),
        "type_byte": hex(data[0]),
    }
    # Extract hostname and version from response
    # Format: 0x15 + padding + hostname(null-padded) + version_string(null-padded)
    try:
        # Hostname starts at offset ~10, null-terminated with padding
        hostname_start = 10
        hostname_end = data.index(b'\x00', hostname_start)
        result["hostname"] = data[hostname_start:hostname_end].decode('ascii', errors='replace')

        # Version string typically starts around offset 266
        version_area = data[250:]
        # Find first non-null byte
        for i, b in enumerate(version_area):
            if b != 0:
                version_end = version_area.index(b'\x00', i)
                result["version"] = version_area[i:version_end].decode('ascii', errors='replace')
                break
    except (ValueError, IndexError):
        pass

    return result


if __name__ == "__main__":
    print("Crestron Security Assessment - Common Utilities")
    print("Usage: import this module in assessment scripts")
    print()
    print("Classes:")
    print("  EvidenceCollector - Standard evidence collection")
    print("  CTPClient - CTP console protocol client (port 41795)")
    print("  CIPClient - CIP binary protocol client (port 41794)")
    print()
    print("Functions:")
    print("  parse_udp_response() - Parse CIP UDP discovery response")
