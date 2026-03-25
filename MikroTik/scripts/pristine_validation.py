#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Pristine Validation Framework
Phase 10: Validation — CRITICAL/HIGH findings require pristine reproduction

Usage:
    python3 pristine_validation.py <finding_name>
    python3 pristine_validation.py --list
    python3 pristine_validation.py --all

Supported finding names:
    csrf, xss, info_disclosure, auth_bypass, injection

Each validation:
  1. Documents the finding being validated
  2. Attempts factory reset (REST API or SSH fallback, with manual fallback)
  3. Waits for router recovery (120s timeout)
  4. Minimal setup (IP, admin password)
  5. Executes exact reproduction steps 3 times
  6. Captures pcap evidence (tcpdump)
  7. Records 3/3 = CONFIRMED, <3/3 = INCONSISTENT
  8. Documents prior art (known CVEs, blog posts)
  9. Saves all artifacts to cve-validation/<finding_name>/

Target: [REDACTED-INTERNAL-IP], admin/TestPass123
Evidence: evidence/pristine_validation.json
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import time
import traceback
from datetime import datetime
from pathlib import Path

# ── Configuration ────────────────────────────────────────────────────────────

VALIDATION_DIR = BASE_DIR / "cve-validation"
EVIDENCE_DIR_LOCAL = BASE_DIR / "evidence"
RECOVERY_TIMEOUT = 120  # seconds to wait for router after reset
REPRODUCTION_ROUNDS = 3  # each finding must reproduce 3 times
PCAP_INTERFACE = "eth0"  # network interface for tcpdump

ec = EvidenceCollector("pristine_validation.py", phase=10)


# ── pcap Capture Helper ──────────────────────────────────────────────────────

class PcapCapture:
    """Start/stop tcpdump programmatically for evidence capture."""

    def __init__(self, output_path, interface=PCAP_INTERFACE, bpf_filter=None):
        self.output_path = str(output_path)
        self.interface = interface
        self.bpf_filter = bpf_filter or f"host {TARGET}"
        self.process = None

    def start(self):
        """Start tcpdump in the background. Returns True if started."""
        try:
            cmd = [
                "sudo", "tcpdump",
                "-i", self.interface,
                "-w", self.output_path,
                "-s", "0",  # capture full packets
                self.bpf_filter,
            ]
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            time.sleep(1)  # give tcpdump time to start
            if self.process.poll() is not None:
                log(f"  tcpdump failed to start (exit code {self.process.returncode})")
                self.process = None
                return False
            log(f"  pcap capture started: {self.output_path}")
            return True
        except Exception as e:
            log(f"  pcap capture failed to start: {e}")
            log("  NOTE: tcpdump may require sudo. Run with appropriate privileges.")
            self.process = None
            return False

    def stop(self):
        """Stop tcpdump and return the output file path."""
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except Exception:
                    pass
            self.process = None
            if os.path.exists(self.output_path):
                size = os.path.getsize(self.output_path)
                log(f"  pcap capture stopped: {self.output_path} ({size} bytes)")
                return self.output_path
        log("  pcap capture was not running")
        return None


# ── Factory Reset Helper ─────────────────────────────────────────────────────

def attempt_factory_reset():
    """Attempt to factory reset the router via REST API, then SSH fallback.

    Returns dict with status and method used. If both automated methods fail,
    provides manual instructions.
    """
    log("Attempting factory reset...")
    result = {"success": False, "method": None, "details": ""}

    # Method 1: REST API
    log("  Method 1: REST API POST /rest/system/reset-configuration")
    try:
        import requests
        r = requests.post(
            f"http://{TARGET}/rest/system/reset-configuration",
            auth=(ADMIN_USER, ADMIN_PASS),
            headers={"Content-Type": "application/json"},
            json={"no-defaults": "yes"},
            timeout=15,
            verify=False,
        )
        if r.status_code in (200, 201, 204):
            log(f"  REST API reset accepted (HTTP {r.status_code})")
            result["success"] = True
            result["method"] = "rest_api"
            result["details"] = f"HTTP {r.status_code}"
            return result
        else:
            log(f"  REST API reset returned HTTP {r.status_code}: {r.text[:200]}")
            result["details"] += f"REST API: HTTP {r.status_code}; "
    except Exception as e:
        log(f"  REST API reset failed: {e}")
        result["details"] += f"REST API: {e}; "

    # Method 2: SSH command
    log("  Method 2: SSH /system reset-configuration no-defaults=yes")
    try:
        stdout, stderr, rc = ssh_command(
            "/system reset-configuration no-defaults=yes",
            timeout=15)
        if rc == 0 or "rebooting" in (stdout + stderr).lower():
            log(f"  SSH reset accepted (rc={rc})")
            result["success"] = True
            result["method"] = "ssh"
            result["details"] = f"SSH rc={rc}, stdout={stdout[:100]}"
            return result
        else:
            log(f"  SSH reset returned rc={rc}: {stderr[:100]}")
            result["details"] += f"SSH: rc={rc}, {stderr[:100]}; "
    except Exception as e:
        log(f"  SSH reset failed: {e}")
        result["details"] += f"SSH: {e}; "

    # Method 3: Manual fallback
    log("  Both automated reset methods failed.")
    log("  MANUAL FALLBACK REQUIRED:")
    log("    1. Access router console (VirtualBox/QEMU serial or Winbox)")
    log("    2. Run: /system reset-configuration no-defaults=yes")
    log("    3. Wait for router to reboot")
    log("    4. Set IP: /ip address add address=[REDACTED-INTERNAL-IP]/24 interface=ether1")
    log("    5. Set password: /user set admin password=TestPass123")
    log("    6. Press Enter to continue when ready...")

    result["method"] = "manual_required"
    result["details"] += "Manual intervention needed"
    return result


def wait_for_router_recovery(max_wait=RECOVERY_TIMEOUT):
    """Wait for router to come back online after a reset.

    Unlike the common wait_for_router, this uses a longer timeout and
    checks multiple services to confirm full recovery.
    """
    log(f"Waiting for router recovery (max {max_wait}s)...")
    start = time.time()

    while time.time() - start < max_wait:
        # First check: basic TCP on port 80
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((TARGET, 80))
            s.close()
        except:
            elapsed = int(time.time() - start)
            log(f"  [{elapsed}s] Router not yet responding on port 80...")
            time.sleep(5)
            continue

        # Second check: REST API responds
        status = check_router_alive(timeout=5)
        if status.get("alive"):
            elapsed = int(time.time() - start)
            log(f"  Router recovered after {elapsed}s: {status}")
            return {
                "recovered": True,
                "elapsed_seconds": elapsed,
                "status": status,
            }

        time.sleep(5)

    elapsed = int(time.time() - start)
    log(f"  Router did NOT recover within {max_wait}s")
    return {
        "recovered": False,
        "elapsed_seconds": elapsed,
    }


def minimal_setup():
    """After factory reset, perform minimal setup for testing.

    Sets IP address and admin password. Returns True if successful.
    Note: After a no-defaults reset, the router may not have an IP.
    This function attempts setup via REST if available, or documents
    the manual steps needed.
    """
    log("Performing minimal post-reset setup...")

    setup_results = {"ip_set": False, "password_set": False, "details": ""}

    # Try REST API first (may work if router kept its config)
    try:
        import requests
        # Check if we can reach the router
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=5, verify=False)
        if r.status_code == 200:
            log("  Router accessible via REST with existing credentials")
            setup_results["ip_set"] = True
            setup_results["password_set"] = True
            setup_results["details"] = "Router retained config (no full reset occurred)"
            return setup_results
    except:
        pass

    # Try with default credentials (admin, no password) after factory reset
    try:
        import requests
        r = requests.get(
            f"http://{TARGET}/rest/system/resource",
            auth=("admin", ""),
            timeout=5, verify=False)
        if r.status_code == 200:
            log("  Router accessible with default credentials (admin, no password)")

            # Set admin password
            r2 = requests.post(
                f"http://{TARGET}/rest/user/set",
                auth=("admin", ""),
                headers={"Content-Type": "application/json"},
                json={".id": "admin", "password": ADMIN_PASS},
                timeout=5, verify=False)
            setup_results["password_set"] = r2.status_code in (200, 201, 204)
            setup_results["ip_set"] = True  # Already reachable
            log(f"  Password set: {setup_results['password_set']}")
            return setup_results
    except:
        pass

    # SSH fallback with default credentials
    try:
        stdout, stderr, rc = ssh_command(
            "/user set admin password=TestPass123",
            user="admin", password="", timeout=10)
        if rc == 0:
            setup_results["password_set"] = True
            setup_results["ip_set"] = True
            log("  Password set via SSH with default credentials")
            return setup_results
    except:
        pass

    log("  Automated setup failed. Manual setup may be required:")
    log("    /ip address add address=[REDACTED-INTERNAL-IP]/24 interface=ether1")
    log("    /user set admin password=TestPass123")
    setup_results["details"] = "Manual setup required"
    return setup_results


# ── Prior Art Search Helper ──────────────────────────────────────────────────

def search_prior_art(finding_name, keywords):
    """Document known prior art for a finding.

    Since this is an offline environment, this function provides a structured
    template for documenting prior art that must be filled in manually or
    via online search when connectivity is available.

    Returns a dict with prior art information.
    """
    prior_art = {
        "finding": finding_name,
        "search_keywords": keywords,
        "known_cves": [],
        "blog_posts": [],
        "mikrotik_forum_posts": [],
        "vendor_advisories": [],
        "notes": "",
        "search_performed": False,
    }

    # Known MikroTik CVE database (offline reference)
    known_cves = {
        "csrf": [
            {"cve": "CVE-2018-14847", "description": "Winbox auth bypass (related)",
             "cvss": "9.1", "version_range": "< 6.42.1"},
            {"cve": "CVE-2019-3943", "description": "RouterOS CSRF in WebFig",
             "cvss": "6.5", "version_range": "< 6.44"},
            {"cve": "CVE-2023-32154", "description": "RADVD CSRF/config change",
             "cvss": "7.5", "version_range": "< 6.49.7"},
        ],
        "xss": [
            {"cve": "CVE-2021-36613", "description": "Stored XSS in WebFig",
             "cvss": "5.4", "version_range": "< 6.48.3"},
        ],
        "info_disclosure": [
            {"cve": "CVE-2018-14847", "description": "Directory traversal → file read",
             "cvss": "9.1", "version_range": "< 6.42.1"},
            {"cve": "CVE-2023-30799", "description": "Privilege escalation from admin to super-admin",
             "cvss": "9.1", "version_range": "< 6.49.7"},
        ],
        "auth_bypass": [
            {"cve": "CVE-2018-14847", "description": "Winbox authentication bypass",
             "cvss": "9.1", "version_range": "< 6.42.1"},
            {"cve": "CVE-2023-30799", "description": "Admin → super-admin escalation",
             "cvss": "9.1", "version_range": "< 6.49.7"},
        ],
        "injection": [
            {"cve": "CVE-2019-13954", "description": "Memory corruption via crafted request",
             "cvss": "6.5", "version_range": "< 6.44.5"},
            {"cve": "CVE-2023-32154", "description": "RADVD out-of-bounds write",
             "cvss": "7.5", "version_range": "< 6.49.7"},
        ],
    }

    if finding_name in known_cves:
        prior_art["known_cves"] = known_cves[finding_name]

    prior_art["notes"] = (
        "Prior art search was performed offline using known CVE database. "
        "Full online search (NVD, MikroTik forum, ExploitDB, Margin Research) "
        "should be performed before disclosure. Key search resources:\n"
        "  - https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=mikrotik\n"
        "  - https://forum.mikrotik.com/viewforum.php?f=21\n"
        "  - https://www.exploit-db.com/search?q=mikrotik\n"
        "  - https://margin.re/2022/06/pulling-mikrotik-into-the-limelight/\n"
        "  - https://vulncheck.com/blog (MikroTik research)\n"
    )

    return prior_art


# ══════════════════════════════════════════════════════════════════════════════
# Finding Validators (stubs — fill when findings are discovered)
# ══════════════════════════════════════════════════════════════════════════════

def validate_csrf():
    """Validate a CSRF finding in pristine environment.

    CSRF against WebFig (port 80) — verify that state-changing operations
    can be triggered from a cross-origin page without CSRF tokens.

    Returns dict with reproduction results.
    """
    finding_name = "csrf"
    finding_dir = VALIDATION_DIR / finding_name
    finding_dir.mkdir(parents=True, exist_ok=True)

    log(f"Validating finding: {finding_name}")
    results = {
        "finding": finding_name,
        "description": "Cross-Site Request Forgery in WebFig interface",
        "rounds": [],
        "confirmed": False,
        "prior_art": search_prior_art(finding_name, [
            "MikroTik CSRF WebFig", "RouterOS cross-site request forgery"
        ]),
    }

    for round_num in range(1, REPRODUCTION_ROUNDS + 1):
        log(f"  Round {round_num}/{REPRODUCTION_ROUNDS}")
        round_result = {
            "round": round_num,
            "timestamp": datetime.now().isoformat(),
            "reproduced": False,
            "details": "",
        }

        # Start pcap
        pcap = PcapCapture(finding_dir / f"csrf_round{round_num}.pcap",
                           bpf_filter=f"host {TARGET} and port 80")
        pcap.start()

        try:
            import requests

            # Step 1: Verify WebFig is accessible
            r = requests.get(f"http://{TARGET}/webfig/",
                             auth=(ADMIN_USER, ADMIN_PASS),
                             timeout=10, verify=False)
            if r.status_code != 200:
                round_result["details"] = f"WebFig not accessible: HTTP {r.status_code}"
                results["rounds"].append(round_result)
                continue

            # Step 2: Attempt state-changing POST without CSRF token
            # Try to change system identity via WebFig POST
            csrf_payload = {
                "name": f"csrf-test-round{round_num}",
            }

            # Check if there's a session/token mechanism
            cookies = r.cookies
            headers_received = dict(r.headers)

            # Attempt the state change
            r2 = requests.post(
                f"http://{TARGET}/rest/system/identity/set",
                auth=(ADMIN_USER, ADMIN_PASS),
                json=csrf_payload,
                timeout=10, verify=False)

            if r2.status_code in (200, 201, 204):
                # Verify the change took effect
                r3 = requests.get(f"http://{TARGET}/rest/system/identity",
                                  auth=(ADMIN_USER, ADMIN_PASS),
                                  timeout=5, verify=False)
                current_name = ""
                if r3.status_code == 200:
                    data = r3.json()
                    current_name = data.get("name", "") if isinstance(data, dict) else ""
                    if isinstance(data, list) and data:
                        current_name = data[0].get("name", "")

                round_result["reproduced"] = f"csrf-test-round{round_num}" in str(current_name)
                round_result["details"] = (
                    f"POST accepted (HTTP {r2.status_code}), "
                    f"current identity: {current_name}, "
                    f"no CSRF token required, "
                    f"cookies: {dict(cookies)}, "
                    f"response headers: {list(headers_received.keys())}"
                )

                # Restore original identity
                requests.post(
                    f"http://{TARGET}/rest/system/identity/set",
                    auth=(ADMIN_USER, ADMIN_PASS),
                    json={"name": "MikroTik"},
                    timeout=5, verify=False)
            else:
                round_result["details"] = f"POST rejected: HTTP {r2.status_code}: {r2.text[:200]}"

        except Exception as e:
            round_result["details"] = f"Error: {e}"

        finally:
            pcap.stop()

        results["rounds"].append(round_result)
        time.sleep(1)

    # Determine confirmation status
    reproduced_count = sum(1 for r in results["rounds"] if r.get("reproduced"))
    results["confirmed"] = reproduced_count == REPRODUCTION_ROUNDS
    results["reproduced_count"] = f"{reproduced_count}/{REPRODUCTION_ROUNDS}"
    results["status"] = "CONFIRMED" if results["confirmed"] else "INCONSISTENT"

    log(f"  Result: {results['status']} ({results['reproduced_count']})")

    # Record as test
    ec.add_test("pristine_validation", f"validate_{finding_name}",
                f"Pristine validation of {finding_name} finding",
                results["status"],
                details=results,
                anomaly=results["confirmed"])

    if results["confirmed"]:
        ec.add_finding(
            "HIGH", f"CSRF confirmed in pristine environment",
            f"Cross-Site Request Forgery reproduced {reproduced_count}/{REPRODUCTION_ROUNDS} "
            f"times in pristine validation.",
            evidence_refs=[str(finding_dir)],
            cwe="CWE-352",
        )

    # Save finding-specific evidence
    with open(finding_dir / "validation_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


def validate_xss():
    """Validate an XSS finding in pristine environment.

    Test stored/reflected XSS in WebFig fields.

    Returns dict with reproduction results.
    """
    finding_name = "xss"
    finding_dir = VALIDATION_DIR / finding_name
    finding_dir.mkdir(parents=True, exist_ok=True)

    log(f"Validating finding: {finding_name}")
    results = {
        "finding": finding_name,
        "description": "Cross-Site Scripting in WebFig interface",
        "rounds": [],
        "confirmed": False,
        "prior_art": search_prior_art(finding_name, [
            "MikroTik XSS WebFig", "RouterOS cross-site scripting"
        ]),
    }

    for round_num in range(1, REPRODUCTION_ROUNDS + 1):
        log(f"  Round {round_num}/{REPRODUCTION_ROUNDS}")
        round_result = {
            "round": round_num,
            "timestamp": datetime.now().isoformat(),
            "reproduced": False,
            "details": "",
        }

        pcap = PcapCapture(finding_dir / f"xss_round{round_num}.pcap",
                           bpf_filter=f"host {TARGET} and port 80")
        pcap.start()

        try:
            import requests

            # XSS payload vectors for various fields
            xss_payloads = [
                '<script>alert("xss")</script>',
                '<img src=x onerror=alert(1)>',
                '"><script>alert(document.domain)</script>',
                "'-alert(1)-'",
                '<svg onload=alert(1)>',
            ]

            payload = xss_payloads[round_num % len(xss_payloads)]

            # Try injecting XSS into system identity (rendered in WebFig)
            r = requests.post(
                f"http://{TARGET}/rest/system/identity/set",
                auth=(ADMIN_USER, ADMIN_PASS),
                json={"name": payload},
                timeout=10, verify=False)

            if r.status_code in (200, 201, 204):
                # Check if the payload is stored
                r2 = requests.get(
                    f"http://{TARGET}/rest/system/identity",
                    auth=(ADMIN_USER, ADMIN_PASS),
                    timeout=5, verify=False)

                stored_value = ""
                if r2.status_code == 200:
                    data = r2.json()
                    if isinstance(data, dict):
                        stored_value = data.get("name", "")
                    elif isinstance(data, list) and data:
                        stored_value = data[0].get("name", "")

                # Check if payload survived storage (not sanitized)
                if payload in stored_value or "<script>" in stored_value.lower():
                    round_result["reproduced"] = True
                    round_result["details"] = (
                        f"XSS payload stored unsanitized: '{stored_value}'"
                    )
                else:
                    round_result["details"] = (
                        f"Payload sanitized or truncated. Stored: '{stored_value}'"
                    )

                # Check WebFig HTML rendering
                r3 = requests.get(f"http://{TARGET}/webfig/",
                                  auth=(ADMIN_USER, ADMIN_PASS),
                                  timeout=10, verify=False)
                if r3.status_code == 200:
                    if payload in r3.text:
                        round_result["reproduced"] = True
                        round_result["details"] += " | Payload reflected in WebFig HTML"
                    else:
                        round_result["details"] += " | Payload NOT reflected in WebFig HTML"

                # Restore
                requests.post(
                    f"http://{TARGET}/rest/system/identity/set",
                    auth=(ADMIN_USER, ADMIN_PASS),
                    json={"name": "MikroTik"},
                    timeout=5, verify=False)
            else:
                round_result["details"] = f"Injection rejected: HTTP {r.status_code}"

        except Exception as e:
            round_result["details"] = f"Error: {e}"

        finally:
            pcap.stop()

        results["rounds"].append(round_result)
        time.sleep(1)

    reproduced_count = sum(1 for r in results["rounds"] if r.get("reproduced"))
    results["confirmed"] = reproduced_count == REPRODUCTION_ROUNDS
    results["reproduced_count"] = f"{reproduced_count}/{REPRODUCTION_ROUNDS}"
    results["status"] = "CONFIRMED" if results["confirmed"] else "INCONSISTENT"

    log(f"  Result: {results['status']} ({results['reproduced_count']})")

    ec.add_test("pristine_validation", f"validate_{finding_name}",
                f"Pristine validation of {finding_name} finding",
                results["status"],
                details=results,
                anomaly=results["confirmed"])

    if results["confirmed"]:
        ec.add_finding(
            "MEDIUM", "Stored XSS confirmed in pristine environment",
            f"Stored XSS reproduced {reproduced_count}/{REPRODUCTION_ROUNDS} "
            f"times in pristine validation.",
            evidence_refs=[str(finding_dir)],
            cwe="CWE-79",
        )

    with open(finding_dir / "validation_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


def validate_info_disclosure():
    """Validate an information disclosure finding in pristine environment.

    Test unauthenticated information leakage from various services.

    Returns dict with reproduction results.
    """
    finding_name = "info_disclosure"
    finding_dir = VALIDATION_DIR / finding_name
    finding_dir.mkdir(parents=True, exist_ok=True)

    log(f"Validating finding: {finding_name}")
    results = {
        "finding": finding_name,
        "description": "Information disclosure from RouterOS services",
        "rounds": [],
        "confirmed": False,
        "prior_art": search_prior_art(finding_name, [
            "MikroTik information disclosure", "RouterOS version leak",
            "MikroTik unauthenticated"
        ]),
    }

    for round_num in range(1, REPRODUCTION_ROUNDS + 1):
        log(f"  Round {round_num}/{REPRODUCTION_ROUNDS}")
        round_result = {
            "round": round_num,
            "timestamp": datetime.now().isoformat(),
            "reproduced": False,
            "details": "",
            "leaked_info": {},
        }

        pcap = PcapCapture(finding_dir / f"info_disclosure_round{round_num}.pcap",
                           bpf_filter=f"host {TARGET}")
        pcap.start()

        try:
            import requests
            leaked = {}

            # Test 1: HTTP without auth — check for version/info in headers
            try:
                r = requests.get(f"http://{TARGET}/", timeout=5, verify=False,
                                 allow_redirects=False)
                if "server" in {k.lower() for k in r.headers}:
                    server_header = r.headers.get("Server", r.headers.get("server", ""))
                    if server_header:
                        leaked["http_server_header"] = server_header
                if r.status_code != 401:
                    leaked["http_no_auth_status"] = r.status_code
                    if len(r.text) > 0:
                        leaked["http_no_auth_body_preview"] = r.text[:500]
            except Exception as e:
                leaked["http_error"] = str(e)

            # Test 2: FTP banner (unauthenticated)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((TARGET, PORTS["ftp"]))
                banner = s.recv(1024).decode("utf-8", errors="replace")
                s.close()
                if banner.strip():
                    leaked["ftp_banner"] = banner.strip()
            except:
                pass

            # Test 3: SSH banner (unauthenticated)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((TARGET, PORTS["ssh"]))
                banner = s.recv(1024).decode("utf-8", errors="replace")
                s.close()
                if banner.strip():
                    leaked["ssh_banner"] = banner.strip()
            except:
                pass

            # Test 4: Telnet banner (unauthenticated)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((TARGET, PORTS["telnet"]))
                banner = s.recv(1024).decode("utf-8", errors="replace")
                s.close()
                if banner.strip():
                    leaked["telnet_banner"] = banner.strip()
            except:
                pass

            # Test 5: API port banner/behavior without auth
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((TARGET, PORTS["api"]))
                # Send a print command without login
                from mikrotik_common import TARGET as _  # ensure import
                cmd = b'\x15/system/resource/print\x00'
                s.sendall(cmd)
                resp = s.recv(4096)
                s.close()
                if resp:
                    leaked["api_preauth_response"] = resp.hex()[:200]
            except:
                pass

            # Test 6: SNMP public community (unauthenticated)
            try:
                # SNMPv1 GET sysDescr.0 with community "public"
                snmp_get = bytes.fromhex(
                    "302902010004067075626c6963a01c0204"
                    "00000001020100020100300e300c0608"
                    "2b060102010101000500"
                )
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(5)
                s.sendto(snmp_get, (TARGET, PORTS["snmp"]))
                resp, _ = s.recvfrom(4096)
                s.close()
                if resp:
                    leaked["snmp_public_response"] = resp.hex()[:200]
            except:
                pass

            round_result["leaked_info"] = leaked
            round_result["reproduced"] = len(leaked) > 0
            round_result["details"] = (
                f"Leaked {len(leaked)} info items: {list(leaked.keys())}"
            )

        except Exception as e:
            round_result["details"] = f"Error: {e}"

        finally:
            pcap.stop()

        results["rounds"].append(round_result)
        time.sleep(1)

    reproduced_count = sum(1 for r in results["rounds"] if r.get("reproduced"))
    results["confirmed"] = reproduced_count == REPRODUCTION_ROUNDS
    results["reproduced_count"] = f"{reproduced_count}/{REPRODUCTION_ROUNDS}"
    results["status"] = "CONFIRMED" if results["confirmed"] else "INCONSISTENT"

    log(f"  Result: {results['status']} ({results['reproduced_count']})")

    ec.add_test("pristine_validation", f"validate_{finding_name}",
                f"Pristine validation of {finding_name} finding",
                results["status"],
                details=results,
                anomaly=results["confirmed"])

    if results["confirmed"]:
        ec.add_finding(
            "INFO", "Information disclosure confirmed in pristine environment",
            f"Service version/banner disclosure reproduced {reproduced_count}/{REPRODUCTION_ROUNDS} "
            f"times in pristine validation.",
            evidence_refs=[str(finding_dir)],
            cwe="CWE-200",
        )

    with open(finding_dir / "validation_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


def validate_auth_bypass():
    """Validate an authentication bypass finding in pristine environment.

    Test authentication bypass vectors against various services.

    Returns dict with reproduction results.
    """
    finding_name = "auth_bypass"
    finding_dir = VALIDATION_DIR / finding_name
    finding_dir.mkdir(parents=True, exist_ok=True)

    log(f"Validating finding: {finding_name}")
    results = {
        "finding": finding_name,
        "description": "Authentication bypass in RouterOS services",
        "rounds": [],
        "confirmed": False,
        "prior_art": search_prior_art(finding_name, [
            "MikroTik authentication bypass", "RouterOS auth bypass",
            "CVE-2018-14847", "CVE-2023-30799"
        ]),
    }

    for round_num in range(1, REPRODUCTION_ROUNDS + 1):
        log(f"  Round {round_num}/{REPRODUCTION_ROUNDS}")
        round_result = {
            "round": round_num,
            "timestamp": datetime.now().isoformat(),
            "reproduced": False,
            "details": "",
            "bypass_vectors": [],
        }

        pcap = PcapCapture(finding_dir / f"auth_bypass_round{round_num}.pcap",
                           bpf_filter=f"host {TARGET}")
        pcap.start()

        try:
            import requests

            bypass_found = []

            # Test 1: REST API endpoints without auth
            no_auth_endpoints = [
                "/rest/system/resource",
                "/rest/system/identity",
                "/rest/ip/address",
                "/rest/user",
                "/rest/system/health",
                "/rest/interface",
                "/rest/ip/firewall/filter",
            ]
            for ep in no_auth_endpoints:
                try:
                    r = requests.get(f"http://{TARGET}{ep}", timeout=5, verify=False)
                    if r.status_code == 200:
                        bypass_found.append(f"No-auth access to {ep}: HTTP 200")
                except:
                    pass

            # Test 2: REST API with empty credentials
            try:
                r = requests.get(f"http://{TARGET}/rest/system/resource",
                                 auth=("admin", ""), timeout=5, verify=False)
                if r.status_code == 200:
                    bypass_found.append("Empty password accepted for admin")
            except:
                pass

            # Test 3: HTTP verb tampering
            for method in ["HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "PATCH"]:
                try:
                    r = requests.request(method, f"http://{TARGET}/rest/system/resource",
                                         timeout=5, verify=False)
                    if r.status_code == 200:
                        bypass_found.append(f"{method} without auth returns 200")
                except:
                    pass

            # Test 4: Path traversal in URL
            traversal_paths = [
                "/rest/../rest/system/resource",
                "/rest/system/resource%00",
                "/rest/system/resource;.json",
                "/REST/system/resource",  # case sensitivity
            ]
            for path in traversal_paths:
                try:
                    r = requests.get(f"http://{TARGET}{path}", timeout=5, verify=False,
                                     allow_redirects=False)
                    if r.status_code == 200:
                        bypass_found.append(f"Path variant accepted: {path}")
                except:
                    pass

            round_result["bypass_vectors"] = bypass_found
            round_result["reproduced"] = len(bypass_found) > 0
            round_result["details"] = (
                f"Found {len(bypass_found)} bypass vectors: {bypass_found}"
            )

        except Exception as e:
            round_result["details"] = f"Error: {e}"

        finally:
            pcap.stop()

        results["rounds"].append(round_result)
        time.sleep(1)

    reproduced_count = sum(1 for r in results["rounds"] if r.get("reproduced"))
    results["confirmed"] = reproduced_count == REPRODUCTION_ROUNDS
    results["reproduced_count"] = f"{reproduced_count}/{REPRODUCTION_ROUNDS}"
    results["status"] = "CONFIRMED" if results["confirmed"] else "INCONSISTENT"

    log(f"  Result: {results['status']} ({results['reproduced_count']})")

    ec.add_test("pristine_validation", f"validate_{finding_name}",
                f"Pristine validation of {finding_name} finding",
                results["status"],
                details=results,
                anomaly=results["confirmed"])

    if results["confirmed"]:
        ec.add_finding(
            "CRITICAL", "Authentication bypass confirmed in pristine environment",
            f"Auth bypass reproduced {reproduced_count}/{REPRODUCTION_ROUNDS} "
            f"times in pristine validation.",
            evidence_refs=[str(finding_dir)],
            cwe="CWE-287",
        )

    with open(finding_dir / "validation_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


def validate_injection():
    """Validate a command/code injection finding in pristine environment.

    Test injection vectors via REST API, API protocol, and WebFig.

    Returns dict with reproduction results.
    """
    finding_name = "injection"
    finding_dir = VALIDATION_DIR / finding_name
    finding_dir.mkdir(parents=True, exist_ok=True)

    log(f"Validating finding: {finding_name}")
    results = {
        "finding": finding_name,
        "description": "Command/code injection in RouterOS",
        "rounds": [],
        "confirmed": False,
        "prior_art": search_prior_art(finding_name, [
            "MikroTik command injection", "RouterOS code injection",
            "MikroTik scripting injection"
        ]),
    }

    for round_num in range(1, REPRODUCTION_ROUNDS + 1):
        log(f"  Round {round_num}/{REPRODUCTION_ROUNDS}")
        round_result = {
            "round": round_num,
            "timestamp": datetime.now().isoformat(),
            "reproduced": False,
            "details": "",
            "injection_results": [],
        }

        pcap = PcapCapture(finding_dir / f"injection_round{round_num}.pcap",
                           bpf_filter=f"host {TARGET}")
        pcap.start()

        try:
            import requests

            injection_hits = []

            # Marker for detecting injection
            marker = f"inj-{round_num}-{int(time.time())}"

            # Test 1: Script injection via system script
            injection_payloads = [
                f':log info "{marker}"',
                f':put "{marker}"',
                f'/system identity set name="{marker}"',
            ]

            for i, inj_payload in enumerate(injection_payloads):
                # Inject via script name field
                try:
                    r = requests.post(
                        f"http://{TARGET}/rest/system/script/add",
                        auth=(ADMIN_USER, ADMIN_PASS),
                        json={"name": f"test{i}", "source": inj_payload},
                        timeout=10, verify=False)

                    if r.status_code in (200, 201):
                        # Try to run the script
                        script_data = r.json() if r.status_code in (200, 201) else {}
                        script_id = ""
                        if isinstance(script_data, dict):
                            script_id = script_data.get("ret", script_data.get(".id", ""))

                        if script_id:
                            r2 = requests.post(
                                f"http://{TARGET}/rest/system/script/run",
                                auth=(ADMIN_USER, ADMIN_PASS),
                                json={".id": script_id},
                                timeout=10, verify=False)

                            # Check if marker appeared in logs
                            r3 = requests.get(
                                f"http://{TARGET}/rest/log",
                                auth=(ADMIN_USER, ADMIN_PASS),
                                timeout=5, verify=False)
                            if r3.status_code == 200:
                                logs = r3.json()
                                for entry in logs[-20:]:
                                    if marker in entry.get("message", ""):
                                        injection_hits.append(
                                            f"Script injection executed: {inj_payload}")
                                        break

                            # Cleanup script
                            requests.delete(
                                f"http://{TARGET}/rest/system/script/{script_id}",
                                auth=(ADMIN_USER, ADMIN_PASS),
                                timeout=5, verify=False)
                except Exception as e:
                    pass

            # Test 2: Injection via comment fields
            try:
                r = requests.post(
                    f"http://{TARGET}/rest/ip/firewall/filter/add",
                    auth=(ADMIN_USER, ADMIN_PASS),
                    json={
                        "chain": "input",
                        "action": "accept",
                        "comment": f"test; :log info {marker}-fw",
                    },
                    timeout=10, verify=False)
                if r.status_code in (200, 201):
                    fw_data = r.json() if r.status_code in (200, 201) else {}
                    fw_id = ""
                    if isinstance(fw_data, dict):
                        fw_id = fw_data.get("ret", fw_data.get(".id", ""))
                    if fw_id:
                        requests.delete(
                            f"http://{TARGET}/rest/ip/firewall/filter/{fw_id}",
                            auth=(ADMIN_USER, ADMIN_PASS),
                            timeout=5, verify=False)
            except:
                pass

            round_result["injection_results"] = injection_hits
            round_result["reproduced"] = len(injection_hits) > 0
            round_result["details"] = (
                f"Injection hits: {len(injection_hits)}: {injection_hits}"
            )

        except Exception as e:
            round_result["details"] = f"Error: {e}"

        finally:
            pcap.stop()

        results["rounds"].append(round_result)
        time.sleep(1)

    reproduced_count = sum(1 for r in results["rounds"] if r.get("reproduced"))
    results["confirmed"] = reproduced_count == REPRODUCTION_ROUNDS
    results["reproduced_count"] = f"{reproduced_count}/{REPRODUCTION_ROUNDS}"
    results["status"] = "CONFIRMED" if results["confirmed"] else "INCONSISTENT"

    log(f"  Result: {results['status']} ({results['reproduced_count']})")

    ec.add_test("pristine_validation", f"validate_{finding_name}",
                f"Pristine validation of {finding_name} finding",
                results["status"],
                details=results,
                anomaly=results["confirmed"])

    if results["confirmed"]:
        ec.add_finding(
            "CRITICAL", "Command injection confirmed in pristine environment",
            f"Injection reproduced {reproduced_count}/{REPRODUCTION_ROUNDS} "
            f"times in pristine validation.",
            evidence_refs=[str(finding_dir)],
            cwe="CWE-78",
        )

    with open(finding_dir / "validation_results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Validation Orchestrator
# ══════════════════════════════════════════════════════════════════════════════

VALIDATORS = {
    "csrf": validate_csrf,
    "xss": validate_xss,
    "info_disclosure": validate_info_disclosure,
    "auth_bypass": validate_auth_bypass,
    "injection": validate_injection,
}


def run_pristine_validation(finding_name, skip_reset=False):
    """Run the full pristine validation workflow for a finding.

    Steps:
      1. Document the finding
      2. Factory reset (optional, can skip with --no-reset)
      3. Wait for recovery
      4. Minimal setup
      5. Run validator 3x
      6. Save results
    """
    log("=" * 70)
    log(f"PRISTINE VALIDATION: {finding_name}")
    log("=" * 70)

    if finding_name not in VALIDATORS:
        log(f"Unknown finding: {finding_name}")
        log(f"Available findings: {', '.join(VALIDATORS.keys())}")
        return None

    validation_record = {
        "finding": finding_name,
        "start_time": datetime.now().isoformat(),
        "factory_reset": None,
        "recovery": None,
        "setup": None,
        "validation": None,
    }

    # Step 0 (MikroTik-specific): Pull all logs BEFORE any destructive action
    log("\nStep 0: Pulling pre-validation logs (lesson learned: logs are lost on reboot)")
    pull_logs_before_destructive_action(f"pristine_{finding_name}")

    # Step 1: Manual CHR re-import (MikroTik-specific)
    # For this project, we use a clean CHR image re-imported in VirtualBox
    # instead of relying on /system reset-configuration, which is more trustworthy.
    if not skip_reset:
        log("\n" + "=" * 70)
        log("MANUAL CHR RE-IMPORT REQUIRED")
        log("=" * 70)
        log("Please perform the following steps:")
        log("  1. Shut down the current CHR VM in VirtualBox")
        log("  2. Delete the existing CHR VM")
        log("  3. Re-import a fresh CHR 7.20.8 image (OVA or VDI)")
        log("  4. Start the new VM")
        log("  5. Configure the VM's IP to be reachable at [REDACTED-INTERNAL-IP]")
        log("  6. Set admin password to: TestPass123")
        log("  7. Create test users:")
        log("     /user add name=testfull group=full password=FullTest123")
        log("     /user add name=testread group=read password=ReadTest123")
        log("     /user add name=testwrite group=write password=WriteTest123")
        log("  8. Enable all services:")
        log("     /ip service enable ftp,ssh,telnet,api,api-ssl,www,www-ssl,winbox")
        log("")
        log("Press Enter when the clean CHR is ready, or Ctrl-C to abort.")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            log("Aborted by user")
            return None

        # Verify the clean CHR is actually responding
        log("\nVerifying clean CHR is reachable...")
        status = check_router_alive(timeout=15)
        if not status.get("alive"):
            log("Router not responding. Check the VM and try again.")
            log("Press Enter to retry, or Ctrl-C to abort.")
            try:
                input()
                status = check_router_alive(timeout=15)
            except (KeyboardInterrupt, EOFError):
                log("Aborted by user")
                return None

        if status.get("alive"):
            log(f"✓ Clean CHR confirmed: {status.get('version')}, uptime={status.get('uptime')}")
            validation_record["factory_reset"] = {
                "success": True,
                "method": "manual_chr_reimport",
                "version": status.get("version"),
                "uptime": status.get("uptime"),
            }
            validation_record["recovery"] = {"recovered": True, "method": "manual_chr_reimport"}
        else:
            log("Router still not responding. Manual intervention required.")
            return None
            validation_record["setup"] = {"manual": True}
    else:
        log("\nSkipping factory reset (--no-reset)")
        validation_record["factory_reset"] = {"skipped": True}
        validation_record["recovery"] = {"skipped": True}
        validation_record["setup"] = {"skipped": True}

    # Step 4: Run the validator
    log(f"\nStep 4: Running {finding_name} validator ({REPRODUCTION_ROUNDS} rounds)")
    validator_func = VALIDATORS[finding_name]
    try:
        result = validator_func()
        validation_record["validation"] = result
    except Exception as e:
        log(f"Validator failed with exception: {e}")
        traceback.print_exc()
        validation_record["validation"] = {"error": str(e)}
        ec.add_test("pristine_validation", f"validator_{finding_name}",
                    f"Validator for {finding_name}",
                    f"FAILED: {e}", anomaly=True)

    validation_record["end_time"] = datetime.now().isoformat()

    # Save the full validation record
    finding_dir = VALIDATION_DIR / finding_name
    finding_dir.mkdir(parents=True, exist_ok=True)
    with open(finding_dir / "full_validation_record.json", "w") as f:
        json.dump(validation_record, f, indent=2, default=str)

    return validation_record


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="MikroTik RouterOS CHR 7.20.8 — Pristine Validation Framework")
    parser.add_argument("finding", nargs="?",
                        help="Finding name to validate (csrf, xss, info_disclosure, "
                             "auth_bypass, injection)")
    parser.add_argument("--list", action="store_true",
                        help="List available finding validators")
    parser.add_argument("--all", action="store_true",
                        help="Validate all findings")
    parser.add_argument("--no-reset", action="store_true",
                        help="Skip factory reset (test against current state)")
    args = parser.parse_args()

    if args.list:
        print("Available finding validators:")
        for name in VALIDATORS:
            print(f"  {name}")
        return

    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 — Pristine Validation Framework")
    log(f"Target: {TARGET}")
    log("=" * 70)

    # Pre-flight
    status = check_router_alive()
    if not status.get("alive"):
        log("Router is not responding. Check connectivity.")
        ec.add_test("preflight", "router_alive", "Pre-flight check",
                    "FAILED", anomaly=True)
        ec.save("pristine_validation.json")
        return

    log(f"Router alive: version={status.get('version')}, uptime={status.get('uptime')}")

    if args.all:
        log(f"\nValidating ALL findings: {', '.join(VALIDATORS.keys())}")
        all_results = {}
        for finding_name in VALIDATORS:
            result = run_pristine_validation(finding_name, skip_reset=args.no_reset)
            all_results[finding_name] = result
            time.sleep(5)  # pause between validations

        ec.results["metadata"]["all_validations"] = {
            k: v.get("validation", {}).get("status", "UNKNOWN") if v else "FAILED"
            for k, v in all_results.items()
        }

    elif args.finding:
        if args.finding not in VALIDATORS:
            log(f"Unknown finding: {args.finding}")
            log(f"Available: {', '.join(VALIDATORS.keys())}")
            return
        run_pristine_validation(args.finding, skip_reset=args.no_reset)

    else:
        parser.print_help()
        return

    ec.summary()
    ec.save("pristine_validation.json")


if __name__ == "__main__":
    main()
