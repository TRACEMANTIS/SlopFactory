#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Network Reconnaissance
Phase 1, Script 1 of 2
Target: [REDACTED-INTERNAL-IP]

Tests:
  - nmap TCP SYN scan (full service version + scripts)
  - nmap UDP scan (top 100 ports)
  - nmap vuln scripts
  - WebFig fingerprinting (headers, paths, JavaScript analysis)
  - REST API endpoint enumeration
  - Service banner grabbing (all TCP services)
  - MNDP broadcast capture
  - Bandwidth-test protocol handshake
  - FTP banner + anonymous check
  - Telnet banner capture
  - SSH algorithm enumeration
  - Winbox pre-auth probe
  - SNMP system info walk

Estimated: ~150 tests
Evidence: evidence/recon_network.json, scans/nmap_*.xml
"""

import json
import socket
import ssl
import struct
import subprocess
import sys
import time
import os
import re
import requests
from datetime import datetime
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
TARGET = "[REDACTED-INTERNAL-IP]"
ADMIN_USER = "admin"
ADMIN_PASS = "TestPass123"
BASE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
EVIDENCE_DIR = BASE_DIR / "evidence"
SCANS_DIR = BASE_DIR / "scans"

# ── Globals ───────────────────────────────────────────────────────────────────
results = {
    "metadata": {
        "script": "recon_network.py",
        "target": TARGET,
        "phase": 1,
        "start_time": None,
        "end_time": None,
        "total_tests": 0,
        "anomalies": 0,
    },
    "tests": []
}


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def add_test(category, name, description, result, details=None, anomaly=False):
    """Record a test result."""
    test = {
        "id": results["metadata"]["total_tests"] + 1,
        "category": category,
        "name": name,
        "description": description,
        "result": result,
        "anomaly": anomaly,
        "timestamp": datetime.now().isoformat(),
    }
    if details:
        test["details"] = details
    results["tests"].append(test)
    results["metadata"]["total_tests"] += 1
    if anomaly:
        results["metadata"]["anomalies"] += 1
    status = "⚠ ANOMALY" if anomaly else "✓"
    log(f"  [{status}] {name}: {result}")


def save_evidence():
    """Write evidence JSON."""
    results["metadata"]["end_time"] = datetime.now().isoformat()
    out = EVIDENCE_DIR / "recon_network.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"Evidence saved to {out}")


def pull_router_logs(phase_name, since_minutes=30):
    """Pull logs from the MikroTik router via REST API and save as evidence.

    This should be called at the end of each test phase to capture any
    router-side log entries generated during testing (auth failures,
    crashes, firewall hits, system events, etc.).
    """
    log(f"Pulling router-side logs for phase: {phase_name}...")
    try:
        # Get full log via REST API
        r = requests.get(
            f"http://{TARGET}/rest/log",
            auth=(ADMIN_USER, ADMIN_PASS),
            timeout=15, verify=False)

        if r.status_code == 200:
            log_entries = r.json()

            # Also grab system health/resource at this point for baseline
            res_r = requests.get(
                f"http://{TARGET}/rest/system/resource",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=5, verify=False)
            resource = res_r.json() if res_r.status_code == 200 else {}

            # Grab active users/sessions
            active_r = requests.get(
                f"http://{TARGET}/rest/user/active",
                auth=(ADMIN_USER, ADMIN_PASS),
                timeout=5, verify=False)
            active_users = active_r.json() if active_r.status_code == 200 else []

            router_log = {
                "phase": phase_name,
                "pulled_at": datetime.now().isoformat(),
                "log_entry_count": len(log_entries),
                "log_entries": log_entries,
                "system_resource": resource,
                "active_users": active_users,
            }

            # Save router logs separately for easy cross-reference
            log_file = EVIDENCE_DIR / f"router_logs_{phase_name}.json"
            with open(log_file, "w") as f:
                json.dump(router_log, f, indent=2, default=str)

            # Also add summary to test results
            # Categorize log entries by topic
            categories = {}
            for entry in log_entries:
                topics = entry.get("topics", "unknown")
                categories[topics] = categories.get(topics, 0) + 1

            # Flag interesting entries
            interesting = []
            keywords = ["error", "critical", "warning", "login failure",
                       "auth", "denied", "crash", "out of memory", "panic"]
            for entry in log_entries:
                msg = entry.get("message", "").lower()
                if any(kw in msg for kw in keywords):
                    interesting.append(entry)

            add_test("router_logs", f"Router log pull ({phase_name})",
                     "Captured MikroTik router-side logs for evidence correlation",
                     f"{len(log_entries)} entries, {len(interesting)} interesting, "
                     f"uptime={resource.get('uptime', 'N/A')}",
                     {"total_entries": len(log_entries),
                      "categories": categories,
                      "interesting_count": len(interesting),
                      "interesting_entries": interesting[:50],
                      "log_file": str(log_file),
                      "uptime": resource.get("uptime"),
                      "cpu_load": resource.get("cpu-load"),
                      "free_memory": resource.get("free-memory")},
                     anomaly=len(interesting) > 5)

            log(f"  Router logs saved: {len(log_entries)} entries → {log_file}")
        else:
            add_test("router_logs", f"Router log pull ({phase_name})",
                     "Pull router logs via REST API",
                     f"Failed: HTTP {r.status_code}",
                     anomaly=True)
    except Exception as e:
        add_test("router_logs", f"Router log pull ({phase_name})",
                 "Pull router logs via REST API",
                 f"Error: {e}",
                 anomaly=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 1: nmap Scanning
# ═══════════════════════════════════════════════════════════════════════════════

def run_nmap_tcp():
    """Full TCP SYN scan with service versions and default scripts."""
    log("Running nmap TCP service scan...")
    out_xml = SCANS_DIR / "nmap_tcp_full.xml"
    out_txt = SCANS_DIR / "nmap_tcp_full.txt"
    cmd = [
        "nmap", "-sT", "-sV", "-sC", "-O",
        "-p-", "--open", "-T4",
        "--max-retries", "2",
        "-oX", str(out_xml),
        "-oN", str(out_txt),
        TARGET
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = r.stdout + r.stderr

        # Parse open ports
        ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)
        port_list = {p: s for p, s in ports}

        add_test("nmap", "TCP full port scan",
                 "Full TCP connect scan with service detection and OS fingerprinting",
                 f"Found {len(ports)} open TCP ports",
                 {"ports": port_list, "xml_file": str(out_xml)},
                 anomaly=False)

        # Check for unexpected ports
        expected = {"21", "22", "23", "80", "443", "2000", "8291", "8728", "8729"}
        unexpected = set(port_list.keys()) - expected
        if unexpected:
            add_test("nmap", "Unexpected TCP ports",
                     "Ports open that are not in expected service list",
                     f"Unexpected: {unexpected}",
                     {"unexpected_ports": list(unexpected)},
                     anomaly=True)
        return port_list
    except subprocess.TimeoutExpired:
        add_test("nmap", "TCP full port scan", "Full TCP scan", "TIMEOUT after 300s",
                 anomaly=True)
        return {}


def run_nmap_udp():
    """UDP scan of top 100 ports."""
    log("Running nmap UDP scan (top 100)...")
    out_xml = SCANS_DIR / "nmap_udp_top100.xml"
    cmd = [
        "sudo", "nmap", "-sU", "-sV",
        "--top-ports", "100", "--open", "-T4",
        "--max-retries", "1",
        "-oX", str(out_xml),
        TARGET
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = r.stdout + r.stderr
        ports = re.findall(r'(\d+)/udp\s+open\s+(\S+)', output)
        port_list = {p: s for p, s in ports}

        add_test("nmap", "UDP top-100 scan",
                 "UDP service scan of top 100 ports",
                 f"Found {len(ports)} open UDP ports",
                 {"ports": port_list, "xml_file": str(out_xml)})
        return port_list
    except subprocess.TimeoutExpired:
        add_test("nmap", "UDP top-100 scan", "UDP scan", "TIMEOUT after 180s",
                 anomaly=True)
        return {}


def run_nmap_vuln():
    """Vulnerability scan scripts against open TCP ports."""
    log("Running nmap vuln scripts...")
    out_xml = SCANS_DIR / "nmap_vuln.xml"
    cmd = [
        "nmap", "--script", "vuln",
        "-p", "21,22,23,80,443,2000,8291,8728,8729",
        "-T4", "-oX", str(out_xml),
        TARGET
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = r.stdout

        # Look for VULNERABLE findings
        vulns = re.findall(r'(CVE-\d{4}-\d+)', output)
        vuln_scripts = re.findall(r'\|_?\s*(.*VULNERABLE.*)', output)

        add_test("nmap", "Vulnerability script scan",
                 "nmap vuln scripts against all open TCP ports",
                 f"Found {len(vulns)} CVE references, {len(vuln_scripts)} VULNERABLE flags",
                 {"cves": list(set(vulns)), "vulnerable_flags": vuln_scripts,
                  "xml_file": str(out_xml)},
                 anomaly=len(vuln_scripts) > 0)
    except subprocess.TimeoutExpired:
        add_test("nmap", "Vulnerability script scan", "vuln scripts", "TIMEOUT",
                 anomaly=True)


# ═══════════════════════════════════════════════════════════════════════════════
# Section 2: WebFig Fingerprinting
# ═══════════════════════════════════════════════════════════════════════════════

def fingerprint_webfig():
    """Analyze WebFig HTTP responses, headers, paths, JS."""
    log("Fingerprinting WebFig...")
    base_http = f"http://{TARGET}"
    base_https = f"https://{TARGET}"

    # Test 1: Root response headers
    for scheme, base in [("HTTP", base_http), ("HTTPS", base_https)]:
        try:
            r = requests.get(f"{base}/", timeout=10, verify=False, allow_redirects=False)
            hdrs = dict(r.headers)

            # Check security headers
            security_headers = {
                "X-Frame-Options": hdrs.get("X-Frame-Options"),
                "X-Content-Type-Options": hdrs.get("X-Content-Type-Options"),
                "Content-Security-Policy": hdrs.get("Content-Security-Policy"),
                "Strict-Transport-Security": hdrs.get("Strict-Transport-Security"),
                "X-XSS-Protection": hdrs.get("X-XSS-Protection"),
                "Referrer-Policy": hdrs.get("Referrer-Policy"),
            }
            missing = [k for k, v in security_headers.items() if v is None]

            add_test("webfig", f"WebFig {scheme} root response",
                     f"Analyze {scheme} response headers from WebFig root",
                     f"Status {r.status_code}, {len(hdrs)} headers, server={hdrs.get('Server', 'N/A')}",
                     {"status_code": r.status_code, "headers": hdrs,
                      "security_headers": security_headers, "missing_security": missing})

            if missing:
                add_test("webfig", f"Missing security headers ({scheme})",
                         f"Security headers absent from {scheme} response",
                         f"Missing: {', '.join(missing)}",
                         {"missing": missing},
                         anomaly=True)

            # Server header disclosure
            server = hdrs.get("Server", "")
            if server:
                add_test("webfig", f"Server header disclosure ({scheme})",
                         "Server header reveals software information",
                         f"Server: {server}",
                         {"server_header": server},
                         anomaly=True)
        except Exception as e:
            add_test("webfig", f"WebFig {scheme} root", f"{scheme} root request",
                     f"Error: {e}", anomaly=True)

    # Test 2: Known WebFig paths
    paths = [
        "/webfig/",
        "/webfig/login",
        "/graphs/",
        "/winbox/",
        "/favicon.ico",
        "/jsproxy/",
        "/rest/",
        "/rest/system/resource",
        "/.well-known/",
        "/skins/",
        "/flash/",
        "/rw/",
    ]
    for path in paths:
        try:
            r = requests.get(f"{base_http}{path}", timeout=5, verify=False,
                           allow_redirects=False, auth=None)
            add_test("webfig", f"Path probe: {path}",
                     f"HTTP GET {path} without auth",
                     f"Status {r.status_code}, {len(r.content)} bytes",
                     {"path": path, "status": r.status_code, "size": len(r.content),
                      "content_type": r.headers.get("Content-Type", ""),
                      "redirect": r.headers.get("Location", "")})
        except Exception as e:
            add_test("webfig", f"Path probe: {path}", f"GET {path}", f"Error: {e}")

    # Test 3: WebFig JavaScript analysis
    try:
        r = requests.get(f"{base_http}/webfig/", timeout=10, verify=False)
        content = r.text

        # Extract JavaScript file references
        js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', content)
        add_test("webfig", "WebFig JavaScript files",
                 "Extract JavaScript file references from WebFig page",
                 f"Found {len(js_files)} JS files",
                 {"js_files": js_files})

        # Fetch and analyze each JS file
        for js in js_files[:5]:  # Limit to 5
            if js.startswith("http"):
                js_url = js
            elif js.startswith("/"):
                js_url = f"{base_http}{js}"
            else:
                js_url = f"{base_http}/{js}"
            try:
                jr = requests.get(js_url, timeout=10, verify=False)
                js_content = jr.text

                # Look for interesting patterns
                patterns = {
                    "eval_calls": len(re.findall(r'\beval\s*\(', js_content)),
                    "innerhtml": len(re.findall(r'\.innerHTML\s*=', js_content)),
                    "document_write": len(re.findall(r'document\.write\s*\(', js_content)),
                    "hardcoded_ips": re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', js_content)[:10],
                    "api_endpoints": re.findall(r'["\']/(rest|api|jsproxy)/[^"\']*["\']', js_content)[:20],
                    "base64_strings": re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', js_content)[:5],
                    "crypto_refs": len(re.findall(r'(?:AES|RSA|SHA|MD5|encrypt|decrypt|hash|cipher)', js_content, re.I)),
                }
                size_kb = len(js_content) / 1024

                add_test("webfig", f"JS analysis: {js}",
                         f"Analyze JavaScript file for security-relevant patterns",
                         f"{size_kb:.1f}KB, eval={patterns['eval_calls']}, innerHTML={patterns['innerhtml']}",
                         {"file": js, "size_bytes": len(js_content), "patterns": patterns},
                         anomaly=patterns['eval_calls'] > 0 or patterns['innerhtml'] > 5)
            except Exception as e:
                add_test("webfig", f"JS fetch: {js}", f"Fetch {js}", f"Error: {e}")

    except Exception as e:
        add_test("webfig", "WebFig JS analysis", "JavaScript analysis", f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Section 3: REST API Endpoint Enumeration
# ═══════════════════════════════════════════════════════════════════════════════

def enumerate_rest_api():
    """Enumerate all REST API endpoints and their access controls."""
    log("Enumerating REST API endpoints...")
    base = f"http://{TARGET}/rest"

    # Known RouterOS v7 REST paths (comprehensive list)
    rest_paths = [
        "/system/resource", "/system/identity", "/system/clock",
        "/system/health", "/system/history", "/system/license",
        "/system/logging", "/system/note", "/system/ntp/client",
        "/system/package", "/system/routerboard", "/system/scheduler",
        "/system/script", "/system/watchdog",
        "/ip/address", "/ip/arp", "/ip/dhcp-client", "/ip/dhcp-server",
        "/ip/dns", "/ip/firewall/filter", "/ip/firewall/nat",
        "/ip/firewall/mangle", "/ip/firewall/raw",
        "/ip/neighbor", "/ip/pool", "/ip/route", "/ip/service",
        "/ip/socks", "/ip/ssh", "/ip/traffic-flow", "/ip/upnp",
        "/interface", "/interface/ethernet", "/interface/bridge",
        "/interface/vlan", "/interface/wireless",
        "/user", "/user/group", "/user/active", "/user/ssh-keys",
        "/tool/bandwidth-test", "/tool/dns-update", "/tool/e-mail",
        "/tool/fetch", "/tool/flood-ping", "/tool/graphing",
        "/tool/netwatch", "/tool/ping", "/tool/profile",
        "/tool/sniffer", "/tool/torch", "/tool/traceroute",
        "/file", "/log",
        "/certificate", "/certificate/crl",
        "/snmp", "/snmp/community",
        "/routing/bgp", "/routing/ospf", "/routing/filter",
        "/queue/simple", "/queue/tree", "/queue/type",
        "/ppp/profile", "/ppp/secret", "/ppp/active",
        "/disk", "/partitions",
    ]

    # Test each path with admin creds
    endpoint_map = {}
    for path in rest_paths:
        try:
            r = requests.get(f"{base}{path}", timeout=5, verify=False,
                           auth=(ADMIN_USER, ADMIN_PASS))
            endpoint_map[path] = {
                "status": r.status_code,
                "size": len(r.content),
                "type": r.headers.get("Content-Type", ""),
            }

            # Only log for interesting cases (not 400/404)
            if r.status_code == 200:
                add_test("rest_api", f"REST endpoint: {path}",
                         f"GET {path} with admin credentials",
                         f"Status {r.status_code}, {len(r.content)} bytes",
                         {"path": path, "status": r.status_code, "size": len(r.content)})
        except Exception as e:
            endpoint_map[path] = {"status": "error", "error": str(e)}

    accessible = {k: v for k, v in endpoint_map.items() if v.get("status") == 200}
    denied = {k: v for k, v in endpoint_map.items() if v.get("status") == 401}
    not_found = {k: v for k, v in endpoint_map.items() if v.get("status") in (400, 404)}

    add_test("rest_api", "REST API endpoint map",
             "Comprehensive REST endpoint enumeration with admin credentials",
             f"{len(accessible)} accessible, {len(denied)} denied, {len(not_found)} not found",
             {"accessible_count": len(accessible), "denied_count": len(denied),
              "not_found_count": len(not_found), "accessible_paths": list(accessible.keys()),
              "full_map": endpoint_map})

    # Test unauthenticated access to each accessible endpoint
    log("Testing unauthenticated REST access...")
    unauth_accessible = []
    for path in accessible.keys():
        try:
            r = requests.get(f"{base}{path}", timeout=5, verify=False)
            if r.status_code == 200:
                unauth_accessible.append(path)
        except:
            pass

    if unauth_accessible:
        add_test("rest_api", "Unauthenticated REST endpoints",
                 "REST endpoints accessible without credentials",
                 f"{len(unauth_accessible)} endpoints accessible without auth",
                 {"paths": unauth_accessible},
                 anomaly=True)
    else:
        add_test("rest_api", "Unauthenticated REST endpoints",
                 "REST endpoints accessible without credentials",
                 "All endpoints require authentication")

    return endpoint_map


# ═══════════════════════════════════════════════════════════════════════════════
# Section 4: Service Banner Grabbing
# ═══════════════════════════════════════════════════════════════════════════════

def grab_banners():
    """Grab banners from all TCP services."""
    log("Grabbing service banners...")

    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        2000: "Bandwidth-test",
        8291: "Winbox",
        8728: "RouterOS API",
        8729: "RouterOS API-SSL",
    }

    for port, name in services.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((TARGET, port))

            # Send a probe based on service type
            if port == 80:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + TARGET.encode() + b"\r\n\r\n")
            elif port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ss = ctx.wrap_socket(s, server_hostname=TARGET)
                ss.send(b"HEAD / HTTP/1.0\r\nHost: " + TARGET.encode() + b"\r\n\r\n")
                banner = ss.recv(2048).decode("utf-8", errors="replace")
                cert = ss.getpeercert(binary_form=True)
                ss.close()
                add_test("banners", f"Banner: {name} ({port})",
                         f"TCP banner grab from {name} on port {port}",
                         f"Banner: {banner[:200]}",
                         {"port": port, "service": name, "banner": banner[:500],
                          "tls": True, "cert_size": len(cert) if cert else 0})
                continue
            elif port == 2000:
                # bandwidth-test sends data after connect
                s.send(b"\x01\x00\x00\x00")
            elif port == 8291:
                # Winbox M2 probe - just connect and read
                pass
            elif port in (8728, 8729):
                # RouterOS API - send empty word
                if port == 8729:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=TARGET)
                s.send(b"\x00")  # empty sentence terminator

            banner = s.recv(2048)
            banner_text = banner.decode("utf-8", errors="replace")

            add_test("banners", f"Banner: {name} ({port})",
                     f"TCP banner grab from {name} on port {port}",
                     f"Banner ({len(banner)} bytes): {banner_text[:200]}",
                     {"port": port, "service": name,
                      "banner_raw": banner.hex()[:200],
                      "banner_text": banner_text[:500],
                      "banner_size": len(banner)},
                     anomaly=False)
            s.close()
        except socket.timeout:
            add_test("banners", f"Banner: {name} ({port})",
                     f"TCP banner grab from {name} on port {port}",
                     "No banner (timeout - service may require client-speaks-first)",
                     {"port": port, "service": name, "result": "timeout"})
        except Exception as e:
            add_test("banners", f"Banner: {name} ({port})",
                     f"TCP banner grab from {name} on port {port}",
                     f"Error: {e}",
                     {"port": port, "service": name, "error": str(e)})


# ═══════════════════════════════════════════════════════════════════════════════
# Section 5: FTP Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_ftp():
    """FTP banner, anonymous access, HELP, FEAT commands."""
    log("Analyzing FTP service...")
    import ftplib

    # Test anonymous login
    try:
        ftp = ftplib.FTP(TARGET, timeout=10)
        banner = ftp.getwelcome()
        add_test("ftp", "FTP banner",
                 "FTP service welcome banner",
                 f"Banner: {banner}",
                 {"banner": banner},
                 anomaly="MikroTik" in banner or "RouterOS" in banner)

        try:
            ftp.login("anonymous", "test@test.com")
            add_test("ftp", "FTP anonymous login",
                     "Attempt anonymous FTP login",
                     "Anonymous login SUCCEEDED",
                     anomaly=True)
            ftp.quit()
        except:
            add_test("ftp", "FTP anonymous login",
                     "Attempt anonymous FTP login",
                     "Anonymous login rejected (expected)")

    except Exception as e:
        add_test("ftp", "FTP connection", "FTP connection attempt", f"Error: {e}")

    # Test authenticated - check HELP, FEAT, SYST
    try:
        ftp = ftplib.FTP(TARGET, timeout=10)
        ftp.login(ADMIN_USER, ADMIN_PASS)

        for cmd in ["SYST", "FEAT", "HELP"]:
            try:
                resp = ftp.sendcmd(cmd)
                add_test("ftp", f"FTP {cmd}",
                         f"FTP {cmd} command response",
                         f"Response: {resp[:200]}",
                         {"command": cmd, "response": resp},
                         anomaly=cmd == "SYST")  # SYST discloses system info
            except ftplib.error_perm as e:
                add_test("ftp", f"FTP {cmd}",
                         f"FTP {cmd} command response",
                         f"Rejected: {e}")

        # List root directory
        try:
            files = []
            ftp.retrlines('LIST', files.append)
            add_test("ftp", "FTP directory listing",
                     "Root directory listing via FTP",
                     f"Found {len(files)} entries",
                     {"files": files[:30]})
        except Exception as e:
            add_test("ftp", "FTP directory listing", "LIST /", f"Error: {e}")

        ftp.quit()
    except Exception as e:
        add_test("ftp", "FTP auth test", "Authenticated FTP", f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Section 6: SSH Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_ssh():
    """SSH algorithm enumeration and banner."""
    log("Analyzing SSH service...")

    # SSH banner
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 22))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()

        add_test("ssh", "SSH banner",
                 "SSH service identification banner",
                 f"Banner: {banner}",
                 {"banner": banner},
                 anomaly=True)  # Version disclosure
    except Exception as e:
        add_test("ssh", "SSH banner", "SSH banner grab", f"Error: {e}")

    # SSH algorithm enumeration via nmap
    try:
        r = subprocess.run(
            ["nmap", "--script", "ssh2-enum-algos", "-p", "22", "-T4", TARGET],
            capture_output=True, text=True, timeout=30)

        add_test("ssh", "SSH algorithms",
                 "Enumerate SSH key exchange, cipher, MAC algorithms",
                 f"Output length: {len(r.stdout)} chars",
                 {"output": r.stdout})
    except Exception as e:
        add_test("ssh", "SSH algorithms", "ssh2-enum-algos", f"Error: {e}")

    # SSH auth methods
    try:
        r = subprocess.run(
            ["nmap", "--script", "ssh-auth-methods", "--script-args",
             f"ssh.user=admin", "-p", "22", "-T4", TARGET],
            capture_output=True, text=True, timeout=30)

        add_test("ssh", "SSH auth methods",
                 "Enumerate SSH authentication methods",
                 f"Output length: {len(r.stdout)} chars",
                 {"output": r.stdout})
    except Exception as e:
        add_test("ssh", "SSH auth methods", "ssh-auth-methods", f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Section 7: Telnet Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_telnet():
    """Telnet banner and negotiation analysis."""
    log("Analyzing Telnet service...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 23))
        time.sleep(1)

        # Read initial telnet negotiation
        data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        # Parse telnet options (IAC sequences)
        iac_sequences = []
        i = 0
        while i < len(data):
            if data[i] == 0xFF and i + 2 < len(data):
                cmd = data[i+1]
                opt = data[i+2]
                iac_sequences.append({"cmd": cmd, "option": opt})
                i += 3
            else:
                i += 1

        text_content = data.decode("utf-8", errors="replace")

        add_test("telnet", "Telnet banner and negotiation",
                 "Capture Telnet initial handshake and banner",
                 f"Received {len(data)} bytes, {len(iac_sequences)} IAC sequences",
                 {"raw_hex": data.hex()[:500], "text": text_content[:500],
                  "iac_count": len(iac_sequences), "iac_sequences": iac_sequences[:20]},
                 anomaly="MikroTik" in text_content or "RouterOS" in text_content)
        s.close()
    except Exception as e:
        add_test("telnet", "Telnet analysis", "Telnet connection", f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Section 8: SNMP Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_snmp():
    """SNMP community enumeration and info disclosure."""
    log("Analyzing SNMP service...")

    # System MIB walk
    try:
        r = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", TARGET, "[REDACTED-IP].2.1.1"],
            capture_output=True, text=True, timeout=30)

        lines = r.stdout.strip().split("\n")
        add_test("snmp", "SNMP system MIB",
                 "SNMP v2c walk of system MIB tree",
                 f"Found {len(lines)} OIDs",
                 {"oids": lines},
                 anomaly=len(lines) > 0)  # Info disclosure
    except Exception as e:
        add_test("snmp", "SNMP system MIB", "snmpwalk system", f"Error: {e}")

    # Interface MIB
    try:
        r = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", TARGET, "[REDACTED-IP].2.1.2"],
            capture_output=True, text=True, timeout=30)

        lines = r.stdout.strip().split("\n")
        add_test("snmp", "SNMP interface MIB",
                 "SNMP v2c walk of interface MIB tree",
                 f"Found {len(lines)} OIDs",
                 {"oid_count": len(lines), "sample": lines[:10]})
    except Exception as e:
        add_test("snmp", "SNMP interface MIB", "snmpwalk interfaces", f"Error: {e}")

    # MikroTik enterprise OIDs (14988)
    try:
        r = subprocess.run(
            ["snmpwalk", "-v2c", "-c", "public", TARGET, "[REDACTED-IP].4.1.14988"],
            capture_output=True, text=True, timeout=30)

        lines = [l for l in r.stdout.strip().split("\n") if l]
        add_test("snmp", "SNMP MikroTik enterprise OIDs",
                 "SNMP walk of MikroTik enterprise MIB (OID [REDACTED-IP].4.1.14988)",
                 f"Found {len(lines)} MikroTik-specific OIDs",
                 {"oid_count": len(lines), "oids": lines[:30]},
                 anomaly=len(lines) > 0)
    except Exception as e:
        add_test("snmp", "SNMP MikroTik OIDs", "snmpwalk 14988", f"Error: {e}")

    # Test community strings
    communities = ["public", "private", "mikrotik", "admin", "router", "community"]
    for comm in communities:
        try:
            r = subprocess.run(
                ["snmpget", "-v2c", "-c", comm, "-t", "2", "-r", "0",
                 TARGET, "[REDACTED-IP].[REDACTED-IP].0"],
                capture_output=True, text=True, timeout=5)

            if "Timeout" not in r.stderr and r.returncode == 0:
                add_test("snmp", f"SNMP community: {comm}",
                         f"Test SNMP community string '{comm}'",
                         f"Community '{comm}' ACCEPTED",
                         {"community": comm, "response": r.stdout.strip()},
                         anomaly=comm != "public")
            else:
                add_test("snmp", f"SNMP community: {comm}",
                         f"Test SNMP community string '{comm}'",
                         f"Community '{comm}' rejected")
        except:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# Section 9: MNDP (MikroTik Neighbor Discovery Protocol)
# ═══════════════════════════════════════════════════════════════════════════════

def capture_mndp():
    """Capture and decode MNDP broadcast packets."""
    log("Capturing MNDP broadcasts (5 second window)...")
    try:
        # MNDP uses UDP port 5678
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(6)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", 5678))

        # Also send a discovery request
        s.sendto(b"\x00\x00\x00\x00", (TARGET, 5678))

        packets = []
        start = time.time()
        while time.time() - start < 5:
            try:
                data, addr = s.recvfrom(4096)
                packets.append({
                    "from": addr,
                    "size": len(data),
                    "hex": data.hex()[:200],
                    "text": data.decode("utf-8", errors="replace")[:200]
                })
            except socket.timeout:
                break

        s.close()

        if packets:
            # Try to decode MNDP TLV structure
            decoded = []
            for pkt in packets:
                raw = bytes.fromhex(pkt["hex"][:pkt["size"]*2])
                tlvs = decode_mndp_tlvs(raw)
                decoded.append(tlvs)

            add_test("mndp", "MNDP broadcast capture",
                     "Capture and decode MNDP neighbor discovery broadcasts",
                     f"Captured {len(packets)} MNDP packets",
                     {"packet_count": len(packets), "packets": packets,
                      "decoded_tlvs": decoded},
                     anomaly=True)  # Info disclosure
        else:
            add_test("mndp", "MNDP broadcast capture",
                     "Capture MNDP broadcasts",
                     "No MNDP packets received in 5 seconds")
    except PermissionError:
        # Try with scapy as fallback
        add_test("mndp", "MNDP broadcast capture",
                 "Capture MNDP broadcasts",
                 "Permission denied - need root for raw socket on port 5678")
    except Exception as e:
        add_test("mndp", "MNDP broadcast capture",
                 "Capture MNDP broadcasts",
                 f"Error: {e}")


def decode_mndp_tlvs(data):
    """Decode MNDP TLV (Type-Length-Value) structure."""
    tlvs = {}
    mndp_types = {
        1: "MAC Address",
        5: "Identity",
        7: "Version",
        8: "Platform",
        10: "Uptime",
        11: "Software ID",
        12: "Board",
        14: "Unpack",
        15: "IPv6 Address",
        16: "Interface Name",
        17: "IPv4 Address",
    }

    offset = 4  # Skip header
    while offset + 4 <= len(data):
        try:
            tlv_type = struct.unpack(">H", data[offset:offset+2])[0]
            tlv_len = struct.unpack(">H", data[offset+2:offset+4])[0]
            tlv_data = data[offset+4:offset+4+tlv_len]

            name = mndp_types.get(tlv_type, f"Unknown({tlv_type})")

            if tlv_type == 1:  # MAC
                value = ":".join(f"{b:02x}" for b in tlv_data)
            elif tlv_type == 10:  # Uptime (seconds)
                value = str(struct.unpack("<I", tlv_data)[0]) if len(tlv_data) == 4 else tlv_data.hex()
            else:
                try:
                    value = tlv_data.decode("utf-8")
                except:
                    value = tlv_data.hex()

            tlvs[name] = value
            offset += 4 + tlv_len
        except:
            break

    return tlvs


# ═══════════════════════════════════════════════════════════════════════════════
# Section 10: Bandwidth-test Handshake
# ═══════════════════════════════════════════════════════════════════════════════

def probe_bandwidth_test():
    """Analyze the bandwidth-test protocol handshake."""
    log("Probing bandwidth-test service...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 2000))

        # bandwidth-test handshake - send various probes
        probes = [
            b"\x01\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x01",
        ]

        for i, probe in enumerate(probes):
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(3)
                s2.connect((TARGET, 2000))
                s2.send(probe)
                time.sleep(0.5)
                resp = s2.recv(4096)
                add_test("btest", f"Bandwidth-test probe {i+1}",
                         f"Send {len(probe)}-byte probe to bandwidth-test service",
                         f"Response: {len(resp)} bytes",
                         {"probe_hex": probe.hex(), "response_hex": resp.hex()[:200],
                          "response_size": len(resp)})
                s2.close()
            except socket.timeout:
                add_test("btest", f"Bandwidth-test probe {i+1}",
                         f"Send probe to bandwidth-test",
                         "No response (timeout)")
            except Exception as e:
                add_test("btest", f"Bandwidth-test probe {i+1}",
                         f"Bandwidth-test probe", f"Error: {e}")

        s.close()
    except Exception as e:
        add_test("btest", "Bandwidth-test connection",
                 "Connect to bandwidth-test service",
                 f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Section 11: Winbox Pre-auth Probe
# ═══════════════════════════════════════════════════════════════════════════════

def probe_winbox():
    """Pre-authentication Winbox M2 protocol probing."""
    log("Probing Winbox service...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 8291))

        # Read initial Winbox response
        time.sleep(0.5)
        try:
            initial = s.recv(4096)
            add_test("winbox", "Winbox initial response",
                     "Connect to Winbox and read initial data",
                     f"Received {len(initial)} bytes on connect",
                     {"hex": initial.hex()[:200], "size": len(initial)})
        except socket.timeout:
            add_test("winbox", "Winbox initial response",
                     "Connect to Winbox and read initial data",
                     "No data sent by server on connect (client-speaks-first)")

        # Send M2 header probe
        # M2 frame: size(4 bytes) + data
        # Minimal M2 message for version query
        m2_probes = [
            # Empty frame
            b"\x00\x00\x00\x00",
            # Minimal M2 message (based on Margin Research docs)
            b"\x06\x00\xff\x01\x00\x02\x00\x00\x00",
            # Legacy Winbox probe (pre-M2)
            b"\x01\x00",
        ]

        for i, probe in enumerate(m2_probes):
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(3)
                s2.connect((TARGET, 8291))
                s2.send(probe)
                time.sleep(0.5)
                resp = s2.recv(4096)
                add_test("winbox", f"Winbox M2 probe {i+1}",
                         f"Send M2 protocol probe ({len(probe)} bytes)",
                         f"Response: {len(resp)} bytes",
                         {"probe_hex": probe.hex(), "response_hex": resp.hex()[:300],
                          "response_size": len(resp)})
                s2.close()
            except socket.timeout:
                add_test("winbox", f"Winbox M2 probe {i+1}",
                         f"Send M2 probe", "No response (timeout)")
            except Exception as e:
                add_test("winbox", f"Winbox M2 probe {i+1}",
                         f"Winbox probe", f"Error: {e}")

        s.close()
    except Exception as e:
        add_test("winbox", "Winbox connection",
                 "Connect to Winbox service", f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Section 12: RouterOS API Protocol Probe
# ═══════════════════════════════════════════════════════════════════════════════

def probe_ros_api():
    """Probe RouterOS API protocol characteristics."""
    log("Probing RouterOS API protocol...")

    # Test via library
    try:
        import routeros_api
        conn = routeros_api.RouterOsApiPool(
            TARGET, username=ADMIN_USER, password=ADMIN_PASS,
            plaintext_login=True)
        api = conn.get_api()

        # Get system info
        resource = api.get_resource("/system/resource")
        info = resource.get()
        add_test("ros_api", "RouterOS API system info",
                 "Query system resource via RouterOS API",
                 f"Version: {info[0].get('version', 'N/A')}",
                 {"system_info": info[0] if info else {}})

        # Get user list
        users = api.get_resource("/user")
        user_list = users.get()
        add_test("ros_api", "RouterOS API user enumeration",
                 "List users via RouterOS API",
                 f"Found {len(user_list)} users",
                 {"users": [u.get("name") for u in user_list]})

        # Get interface list
        ifaces = api.get_resource("/interface")
        iface_list = ifaces.get()
        add_test("ros_api", "RouterOS API interface list",
                 "List interfaces via RouterOS API",
                 f"Found {len(iface_list)} interfaces",
                 {"interfaces": [{"name": i.get("name"), "type": i.get("type")}
                                for i in iface_list]})

        # Get packages
        pkgs = api.get_resource("/system/package")
        pkg_list = pkgs.get()
        add_test("ros_api", "RouterOS API package list",
                 "List installed packages via RouterOS API",
                 f"Found {len(pkg_list)} packages",
                 {"packages": [{"name": p.get("name"), "version": p.get("version")}
                              for p in pkg_list]})

        conn.disconnect()
    except Exception as e:
        add_test("ros_api", "RouterOS API probe",
                 "RouterOS API connectivity test", f"Error: {e}", anomaly=True)

    # Raw protocol test - pre-auth behavior
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET, 8728))

        # Send a RouterOS API word: "/login" (length-encoded)
        # Length encoding: 1 byte for lengths < 0x80
        word = b"/login"
        s.send(bytes([len(word)]) + word + b"\x00")  # word + empty word (end of sentence)
        time.sleep(1)
        resp = s.recv(4096)

        add_test("ros_api", "RouterOS API pre-auth /login",
                 "Send /login command without credentials to RouterOS API",
                 f"Response: {len(resp)} bytes",
                 {"response_hex": resp.hex()[:300],
                  "response_text": resp.decode("utf-8", errors="replace")[:300]})
        s.close()
    except Exception as e:
        add_test("ros_api", "RouterOS API raw probe",
                 "Raw RouterOS API protocol test", f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Section 13: TLS Certificate Analysis
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_tls():
    """Analyze TLS configuration on HTTPS and API-SSL."""
    log("Analyzing TLS configuration...")

    for port, name in [(443, "WebFig HTTPS"), (8729, "API-SSL")]:
        try:
            r = subprocess.run(
                ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), "-T4", TARGET],
                capture_output=True, text=True, timeout=30)

            # Parse cipher grades
            weak = re.findall(r'(TLSv\d\.\d).*?([REDACTED] [A-F])', r.stdout, re.DOTALL)

            add_test("tls", f"TLS cipher audit: {name} ({port})",
                     f"Enumerate TLS ciphers on {name}",
                     f"Scan complete",
                     {"port": port, "output": r.stdout, "weak_findings": weak},
                     anomaly=any("[REDACTED]" in w[1] and w[1][-1] in "CDF" for w in weak))
        except Exception as e:
            add_test("tls", f"TLS cipher audit: {name}", f"TLS scan port {port}",
                     f"Error: {e}")

    # Get certificate details
    try:
        r = subprocess.run(
            ["nmap", "--script", "ssl-cert", "-p", "443", "-T4", TARGET],
            capture_output=True, text=True, timeout=30)

        add_test("tls", "TLS certificate details",
                 "Extract TLS certificate information from WebFig HTTPS",
                 f"Cert scan complete",
                 {"output": r.stdout})
    except Exception as e:
        add_test("tls", "TLS certificate", "TLS cert extraction", f"Error: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    import warnings
    warnings.filterwarnings("ignore")  # Suppress SSL warnings

    results["metadata"]["start_time"] = datetime.now().isoformat()
    log(f"Starting network reconnaissance against {TARGET}")
    log(f"=" * 60)

    # Run all recon modules
    run_nmap_tcp()
    run_nmap_udp()
    run_nmap_vuln()
    fingerprint_webfig()
    enumerate_rest_api()
    grab_banners()
    analyze_ftp()
    analyze_ssh()
    analyze_telnet()
    analyze_snmp()
    capture_mndp()
    probe_bandwidth_test()
    probe_winbox()
    probe_ros_api()
    analyze_tls()

    # Pull router-side logs for evidence
    pull_router_logs("recon_network")

    # Save evidence
    save_evidence()

    log(f"=" * 60)
    log(f"Reconnaissance complete: {results['metadata']['total_tests']} tests, "
        f"{results['metadata']['anomalies']} anomalies")


if __name__ == "__main__":
    os.chdir(BASE_DIR)
    main()
