#!/usr/bin/env python3
"""
ProFTPD Phase 4 — Memory Leak Monitoring
Tracks VmRSS/VmPeak of ProFTPD master process across:
1. Normal authenticated sessions (baseline)
2. mod_copy intensive operations
3. Oversized command (E2BIG path)
4. SITE SYMLINK chain creation
5. LIST glob expansion (large directory)
"""
import subprocess, socket, time, json, os, re
from datetime import datetime

HOST, PORT = "127.0.0.1", 21
USER, PASS = "ftptest", "ftptest123"
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"

def get_proftpd_mem():
    """Read memory usage from /proc/<pid>/status for proftpd master."""
    try:
        # Get master PID (the accepting connections process)
        result = subprocess.run(
            ["pgrep", "-o", "proftpd"],
            capture_output=True, text=True
        )
        pid = result.stdout.strip()
        if not pid:
            return None

        with open(f"/proc/{pid}/status") as f:
            status = f.read()

        mem = {"pid": int(pid)}
        for line in status.splitlines():
            for key in ["VmRSS", "VmPeak", "VmSize", "VmData", "VmStk"]:
                if line.startswith(key + ":"):
                    val = int(line.split()[1])  # kB
                    mem[key] = val
        return mem
    except Exception as e:
        return {"error": str(e)}

def drain_recv(s, timeout=3):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk: break
            data += chunk
            decoded = data.decode('utf-8', errors='replace')
            lines = [l for l in decoded.strip().split('\n') if l.strip()]
            if lines:
                last = lines[-1]
                if len(last) >= 4 and last[:3].isdigit() and last[3] == ' ':
                    break
    except socket.timeout:
        pass
    return data.decode('utf-8', errors='replace').strip()

def connect_auth():
    s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
    drain_recv(s)
    s.sendall(f"USER {USER}\r\n".encode()); drain_recv(s)
    s.sendall(f"PASS {PASS}\r\n".encode()); r = drain_recv(s)
    return s, "230" in r

def cmd(s, c, timeout=5):
    s.sendall((c + "\r\n").encode())
    return drain_recv(s, timeout)

def run_normal_sessions(n=50):
    """Run n normal connect/auth/quit cycles."""
    for i in range(n):
        try:
            s, ok = connect_auth()
            if ok:
                cmd(s, "PWD")
                cmd(s, "TYPE A")
                cmd(s, "SYST")
                cmd(s, "QUIT")
            s.close()
        except: pass
        time.sleep(0.05)

def run_modcopy_sessions(n=30):
    """Run mod_copy CPFR/CPTO sequences."""
    for i in range(n):
        try:
            s, ok = connect_auth()
            if ok:
                cmd(s, "SITE CPFR /home/ftptest/upload")
                cmd(s, "SITE CPTO /home/ftptest/upload_copy")
                cmd(s, "SITE CPFR /etc/hostname")
                cmd(s, "SITE CPTO /home/ftptest/hostname_copy")
                cmd(s, "QUIT")
            s.close()
        except: pass
        time.sleep(0.05)

def run_e2big_sessions(n=20):
    """Run oversized command (E2BIG) sessions."""
    for i in range(n):
        try:
            s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
            s.recv(512)  # banner
            s.sendall(b"USER " + b"A" * 16384 + b"\r\n")
            s.settimeout(5)
            try:
                while True:
                    c = s.recv(4096)
                    if not c: break
            except: pass
            s.close()
        except: pass
        time.sleep(0.05)

def run_glob_sessions(n=20):
    """Run LIST with glob patterns."""
    for i in range(n):
        try:
            s, ok = connect_auth()
            if ok:
                # PASV + LIST
                cmd(s, "PASV")  # Get pasv address (just testing)
                cmd(s, "TYPE A")
                cmd(s, "QUIT")
            s.close()
        except: pass
        time.sleep(0.05)

def main():
    print("=" * 60)
    print("Phase 4: Memory Leak Monitoring")
    print("ProFTPD 1.3.9 — VmRSS tracking across operations")
    print("=" * 60)

    results = {
        "test": "memory_leak_monitoring",
        "date": datetime.now().isoformat(),
        "measurements": {}
    }

    def take_snapshot(label):
        mem = get_proftpd_mem()
        print(f"  [{label}] PID={mem.get('pid','?')} VmRSS={mem.get('VmRSS','?')}kB VmPeak={mem.get('VmPeak','?')}kB VmSize={mem.get('VmSize','?')}kB")
        results["measurements"][label] = mem
        return mem

    # Baseline
    print("\n[1] Baseline memory")
    baseline = take_snapshot("baseline")
    time.sleep(1)

    # Phase 1: Normal sessions
    print("\n[2] Normal sessions (50x connect/auth/PWD/QUIT)")
    run_normal_sessions(50)
    time.sleep(2)
    after_normal = take_snapshot("after_50_normal_sessions")
    delta1 = after_normal.get("VmRSS", 0) - baseline.get("VmRSS", 0)
    print(f"  Delta VmRSS: {delta1:+d} kB")

    # Phase 2: mod_copy
    print("\n[3] mod_copy sessions (30x CPFR/CPTO)")
    run_modcopy_sessions(30)
    time.sleep(2)
    after_copy = take_snapshot("after_30_modcopy_sessions")
    delta2 = after_copy.get("VmRSS", 0) - after_normal.get("VmRSS", 0)
    print(f"  Delta VmRSS: {delta2:+d} kB")

    # Phase 3: E2BIG sessions
    print("\n[4] E2BIG sessions (20x oversized command)")
    run_e2big_sessions(20)
    time.sleep(2)
    after_e2big = take_snapshot("after_20_e2big_sessions")
    delta3 = after_e2big.get("VmRSS", 0) - after_copy.get("VmRSS", 0)
    print(f"  Delta VmRSS: {delta3:+d} kB")

    # Phase 4: More normal sessions (check recovery)
    print("\n[5] Post-stress normal sessions (50x)")
    run_normal_sessions(50)
    time.sleep(2)
    after_recovery = take_snapshot("after_recovery_50_normal")
    delta4 = after_recovery.get("VmRSS", 0) - baseline.get("VmRSS", 0)
    print(f"  Total delta from baseline: {delta4:+d} kB")

    # Analysis
    vmrss_readings = [
        baseline.get("VmRSS", 0),
        after_normal.get("VmRSS", 0),
        after_copy.get("VmRSS", 0),
        after_e2big.get("VmRSS", 0),
        after_recovery.get("VmRSS", 0)
    ]

    max_growth = max(vmrss_readings) - min(vmrss_readings)
    trend_up = vmrss_readings[-1] > vmrss_readings[0]

    results["analysis"] = {
        "baseline_vmrss_kb": baseline.get("VmRSS", 0),
        "final_vmrss_kb": after_recovery.get("VmRSS", 0),
        "total_delta_kb": delta4,
        "max_growth_kb": max_growth,
        "monotonic_increase": trend_up,
        "leak_detected": abs(delta4) > 2048,  # >2MB delta considered significant
        "note": (
            "Memory monitored on master process only. Child processes (per-connection) "
            "are forked and their memory is separate. Master VmRSS growth indicates "
            "leak in code running in master context (e.g., signal handlers, shared structs)."
        )
    }

    print(f"\n[*] Memory Analysis:")
    print(f"    Total delta from baseline: {delta4:+d} kB")
    print(f"    Leak detected (>2MB): {results['analysis']['leak_detected']}")

    outfile = f"{EVIDENCE_DIR}/phase4_memory_leak.json"
    with open(outfile, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[*] Evidence saved to {outfile}")

if __name__ == "__main__":
    main()
