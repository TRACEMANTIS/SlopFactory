#!/usr/bin/env python3
"""
CrestronFW2x Crestron FW 2.x - Shared Utilities
EvidenceCollector, HTTP helpers, CTP client
"""

import json
import time
import os
import sys
import ssl
import socket
import urllib.request
import urllib.error
import base64
from datetime import datetime, timezone

# Rate limiting
DEFAULT_RATE_LIMIT = 0.5  # seconds between requests

# Default credentials
DEFAULT_USER = "admin"
DEFAULT_PASS = "admin"

# Host list
HOSTS_FILE = os.path.join(os.path.dirname(__file__),
    "../../[REDACTED-ID]_Crestron_FW3x/scripts/ipsClean.txt")


def load_hosts(hosts_file=None):
    """Load authorized host list."""
    path = hosts_file or HOSTS_FILE
    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def make_auth_header(user=DEFAULT_USER, password=DEFAULT_PASS):
    """Create Basic Auth header."""
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {creds}"


def https_request(host, path, method="GET", data=None, headers=None,
                  timeout=10, auth=True, user=DEFAULT_USER, password=DEFAULT_PASS):
    """Make HTTPS request to Crestron device, ignoring SSL errors."""
    url = f"https://{host}{path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    hdrs = headers or {}
    if auth:
        hdrs["Authorization"] = make_auth_header(user, password)
    hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode('utf-8', errors='replace')
        return {
            "status": resp.status,
            "headers": dict(resp.headers),
            "body": body,
            "url": url,
            "error": None
        }
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace') if e.fp else ""
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": body,
            "url": url,
            "error": str(e)
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "url": url,
            "error": str(e)
        }


def ctp_connect(host, port=41795, timeout=5):
    """Connect to CTP console (TCP port 41795)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        # Read banner
        banner = sock.recv(4096).decode('utf-8', errors='replace')
        return sock, banner
    except Exception as e:
        sock.close()
        return None, str(e)


def ctp_command(sock, command, timeout=5):
    """Send CTP command and read response."""
    try:
        sock.settimeout(timeout)
        sock.send(f"{command}\r\n".encode())
        time.sleep(0.3)
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        return response.decode('utf-8', errors='replace')
    except Exception as e:
        return f"ERROR: {e}"


class EvidenceCollector:
    """Structured evidence collection for security findings."""

    def __init__(self, script_name, description=""):
        self.script_name = script_name
        self.description = description
        self.start_time = datetime.now(timezone.utc).isoformat()
        self.tests = []
        self.findings = []
        self.anomalies = []
        self.metadata = {
            "assessment": "CrestronFW2x Crestron FW 2.x",
            "firmware": "DMPS3 AirMedia PufVersion 1.5010.00023",
            "script": script_name,
            "description": description,
            "start_time": self.start_time,
        }

    def add_test(self, test_id, description, request_info, response_info, result=""):
        """Record an individual test case."""
        self.tests.append({
            "id": test_id,
            "description": description,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request": request_info,
            "response": response_info,
            "result": result
        })
        print(f"  [TEST] {test_id}: {description} -> {result}")

    def add_finding(self, finding_id, severity, title, details, evidence=None):
        """Record a validated finding."""
        self.findings.append({
            "id": finding_id,
            "severity": severity,
            "title": title,
            "details": details,
            "evidence": evidence or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        print(f"  [FINDING] {finding_id} ({severity}): {title}")

    def add_anomaly(self, anomaly_id, description, details=None):
        """Record an unexpected behavior for investigation."""
        self.anomalies.append({
            "id": anomaly_id,
            "description": description,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        print(f"  [ANOMALY] {anomaly_id}: {description}")

    def save(self, output_path=None):
        """Save evidence to JSON file."""
        if output_path is None:
            evidence_dir = os.path.join(os.path.dirname(__file__), "..", "evidence")
            os.makedirs(evidence_dir, exist_ok=True)
            output_path = os.path.join(evidence_dir,
                f"{self.script_name.replace('.py', '')}_evidence.json")

        data = {
            "metadata": self.metadata,
            "end_time": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_tests": len(self.tests),
                "total_findings": len(self.findings),
                "total_anomalies": len(self.anomalies),
                "findings_by_severity": {}
            },
            "tests": self.tests,
            "findings": self.findings,
            "anomalies": self.anomalies
        }

        # Count by severity
        for f in self.findings:
            sev = f["severity"]
            data["summary"]["findings_by_severity"][sev] = \
                data["summary"]["findings_by_severity"].get(sev, 0) + 1

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\n[EVIDENCE] Saved to {output_path}")
        print(f"  Tests: {len(self.tests)}, Findings: {len(self.findings)}, "
              f"Anomalies: {len(self.anomalies)}")
        return output_path
