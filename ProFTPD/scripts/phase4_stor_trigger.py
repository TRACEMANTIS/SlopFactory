#!/usr/bin/env python3
"""
ProFTPD Phase 4 — STOR ≥16384 TCP RST Trigger
Sends STOR with exactly 16384-byte filename and captures raw response.
Run this while strace is attached to ProFTPD to capture syscall trace.
"""
import socket, time, sys, struct

HOST, PORT = "127.0.0.1", 21
USER, PASS = "ftptest", "ftptest123"

def drain(s, timeout=3):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
            decoded = data.decode('utf-8','replace')
            lines = [l for l in decoded.strip().split('\n') if l.strip()]
            if lines:
                last = lines[-1]
                if len(last) >= 4 and last[:3].isdigit() and last[3] == ' ':
                    break
    except socket.timeout:
        pass
    return data

def test_stor_length(length):
    print(f"\n{'='*60}")
    print(f"Testing STOR with {length}-byte filename")
    print(f"{'='*60}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(10)
    s.connect((HOST, PORT))

    # Capture banner
    banner = drain(s)
    print(f"Banner: {banner[:60]}")

    # Auth
    s.sendall(f"USER {USER}\r\n".encode())
    r = drain(s)
    print(f"USER: {r[:60]}")

    s.sendall(f"PASS {PASS}\r\n".encode())
    r = drain(s)
    print(f"PASS: {r[:60]}")

    if b"230" not in r:
        print("AUTH FAILED")
        s.close()
        return

    # Get child PID from server (TYPE command then check)
    s.sendall(b"TYPE A\r\n")
    r = drain(s)

    # Build STOR command with N-byte filename: "A" * length
    filename = "A" * length
    stor_cmd = f"STOR {filename}\r\n".encode()
    print(f"Sending STOR command ({len(stor_cmd)} bytes total)")

    # Send STOR — no PORT/PASV first (passive mode not set up)
    # The pre-command handler runs before data channel check
    s.sendall(stor_cmd)

    # Now try to read the response — any 550? or does the connection drop?
    print("Waiting for server response...")
    s.settimeout(5)
    response = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                print("[!] Connection closed by server (clean EOF)")
                break
            response += chunk
            print(f"Received {len(chunk)} bytes: {chunk[:120]!r}")
            # Check if we have a complete response
            decoded = response.decode('utf-8','replace')
            lines = [l for l in decoded.strip().split('\n') if l.strip()]
            if lines:
                last = lines[-1]
                if len(last) >= 4 and last[:3].isdigit() and last[3] == ' ':
                    print(f"[*] Complete FTP response received")
                    break
    except socket.timeout:
        print("[!] Timeout — no response received within 5 seconds")
    except ConnectionResetError as e:
        print(f"[!] TCP RST received from server: {e}")
    except Exception as e:
        print(f"[!] Exception: {type(e).__name__}: {e}")

    print(f"\nTotal response: {response!r}")
    print(f"Response length: {len(response)} bytes")

    # Try sending another command — is connection still usable?
    try:
        s.settimeout(2)
        s.sendall(b"NOOP\r\n")
        r2 = s.recv(256)
        print(f"Post-STOR NOOP response: {r2!r}")
        print("[*] Connection still alive after STOR!")
    except Exception as e:
        print(f"[*] Connection dead after STOR: {e}")

    s.close()

if __name__ == "__main__":
    # Test different lengths around the boundary
    lengths = [
        1024,   # Normal — should work or give clean 550
        4095,   # PATH_MAX - 1
        4096,   # PATH_MAX exact
        4097,   # PATH_MAX + 1
        8192,   # 2x PATH_MAX
        16384,  # Known-bad from fuzzer
    ]

    if len(sys.argv) > 1:
        lengths = [int(sys.argv[1])]

    for l in lengths:
        test_stor_length(l)
        time.sleep(0.5)
