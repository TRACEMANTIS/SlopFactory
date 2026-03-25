#!/usr/bin/env python3
"""
fake_cfmd.py - Fake CFM (Configuration Manager) daemon for Tenda httpd emulation

Listens on /var/cfm_socket Unix socket and responds to config queries
from httpd. Sends back empty/default responses to allow httpd to start.

Usage:
  sudo python3 fake_cfmd.py [socket_path]
  Default socket path: /var/cfm_socket (inside chroot)

Protocol reverse-engineered from libCfm.so ConnectCfm/GetCfmValue functions.
"""

import socket
import os
import sys
import struct
import threading
import signal
import time

SOCKET_PATH = sys.argv[1] if len(sys.argv) > 1 else "/var/cfm_socket"

# Default NVRAM-like values for httpd
DEFAULTS = {
    "sys.username": "admin",
    "sys.userpass": "",
    "sys.model": "AC15",
    "sys.fwver": "V15.03.05.19",
    "sys.sn": "000000000000",
    "lan.ip": "[REDACTED-INTERNAL-IP]",
    "lan.mask": "255.255.255.0",
    "lan.dhcp.en": "1",
    "lan.mac": "00:11:22:33:44:55",
    "wan.mode": "dhcp",
    "wan.ip": "[REDACTED-INTERNAL-IP]",
    "wan.dns1": "[REDACTED-IP]",
    "wan.dns2": "[REDACTED-IP]",
    "wan.mac": "00:11:22:33:44:56",
    "wl.ssid": "Tenda_TEST",
    "wl.pwd": "12345678",
    "wl.security": "wpapsk",
    "wl.encrypt": "aes",
    "wl.channel": "6",
    "firewall.en": "0",
    "http.port": "80",
    "http.lan.en": "1",
    "http.wan.en": "0",
    "upnp.en": "1",
    "dmz.en": "0",
    "pptp.en": "0",
    "telnet.en": "0",
    "usb.en": "0",
    "guest.en": "0",
    "wps.pin": "16677883",
    "restore_defaults": "0",
}

running = True

def signal_handler(sig, frame):
    global running
    running = False
    print(f"[fake_cfmd] Caught signal {sig}, shutting down")

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def handle_client(conn, addr):
    """Handle a single cfm client connection"""
    client_id = id(conn) & 0xFFFF
    print(f"[fake_cfmd] Client {client_id:#x} connected")

    try:
        while running:
            # Read incoming data
            data = conn.recv(4096)
            if not data:
                break

            print(f"[fake_cfmd] Client {client_id:#x} sent {len(data)} bytes: {data[:64].hex()}")

            # Try to interpret as a CFM request
            # CFM protocol is simple:
            # - Connect: just accept
            # - GetCfmValue: receive key, send back value
            # - CommitCfm: receive key=value, send ack

            # Try to extract printable strings from the request
            try:
                text = data.decode('ascii', errors='ignore').strip('\x00')
                printable = ''.join(c for c in text if 32 <= ord(c) < 127)
                if printable:
                    print(f"[fake_cfmd] Decoded: '{printable}'")
            except:
                pass

            # Send back a generic "OK" response
            # The exact protocol depends on how libCfm structures messages
            # Try sending null-terminated empty response
            response = b'\x00' * len(data)

            # If the data contains a recognizable key, send the value
            for key, val in DEFAULTS.items():
                if key.encode() in data:
                    # Pack: length(4) + value + null
                    val_bytes = val.encode() + b'\x00'
                    response = struct.pack('>I', len(val_bytes)) + val_bytes
                    print(f"[fake_cfmd] Responding with {key}={val}")
                    break

            try:
                conn.send(response)
            except:
                break

    except Exception as e:
        print(f"[fake_cfmd] Client {client_id:#x} error: {e}")
    finally:
        conn.close()
        print(f"[fake_cfmd] Client {client_id:#x} disconnected")

def main():
    # Clean up old socket
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    # Create parent directory if needed
    socket_dir = os.path.dirname(SOCKET_PATH)
    if socket_dir and not os.path.exists(socket_dir):
        os.makedirs(socket_dir, exist_ok=True)

    # Create Unix socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(SOCKET_PATH)
    server.listen(5)
    server.settimeout(1.0)

    # Make socket world-accessible
    os.chmod(SOCKET_PATH, 0o777)

    print(f"[fake_cfmd] Listening on {SOCKET_PATH}")

    threads = []
    while running:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
            threads.append(t)
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                print(f"[fake_cfmd] Accept error: {e}")
            break

    server.close()
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
    print("[fake_cfmd] Shutdown complete")

if __name__ == "__main__":
    main()
