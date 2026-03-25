#!/usr/bin/env python3
"""
Security Research II -- Zabbix Security Assessment
Common utilities for all phase scripts.
"""

import requests
import json
import time
import os
import sys
from datetime import datetime

# Ensure unbuffered output
os.environ["PYTHONUNBUFFERED"] = "1"

# Target configuration
ZABBIX_URL = "http://localhost:9080"
API_URL = f"{ZABBIX_URL}/api_jsonrpc.php"
SCIM_URL = f"{ZABBIX_URL}/api_scim.php"

ADMIN_USER = "Admin"
ADMIN_PASS = "zabbix"

VIEWER_USER = "viewer01"
VIEWER_PASS = "S3cur1ty_R3s34rch!"

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/Zabbix/evidence"
os.makedirs(EVIDENCE_DIR, exist_ok=True)


def banner(title):
    """Print a phase banner."""
    width = 70
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * width)


def rate_limit(seconds=0.2):
    """Sleep between requests to avoid overwhelming the target."""
    time.sleep(seconds)


class ZabbixSession:
    """Manages authenticated sessions with the Zabbix JSON-RPC API."""

    def __init__(self, username=None, password=None, auto_login=True):
        self.url = API_URL
        self.base_url = ZABBIX_URL
        self.username = username or ADMIN_USER
        self.password = password or ADMIN_PASS
        self.auth_token = None
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json-rpc"})
        self.request_id = 0
        if auto_login:
            self.login()

    def _next_id(self):
        self.request_id += 1
        return self.request_id

    def api_call(self, method, params=None, auth=True, raw=False):
        """Make a JSON-RPC API call."""
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._next_id(),
        }
        if auth and self.auth_token:
            payload["auth"] = self.auth_token

        try:
            resp = self.session.post(self.url, json=payload, timeout=30)
            if raw:
                return resp
            data = resp.json()
            return data
        except Exception as e:
            return {"error": {"code": -1, "message": str(e)}}

    def login(self):
        """Authenticate and store session token."""
        result = self.api_call(
            "user.login",
            {"username": self.username, "password": self.password},
            auth=False,
        )
        if "result" in result:
            self.auth_token = result["result"]
            return True
        print(f"  [-] Login failed for {self.username}: {result.get('error', {}).get('message', 'unknown')}")
        return False

    def logout(self):
        """Destroy the session."""
        if self.auth_token:
            result = self.api_call("user.logout", {})
            self.auth_token = None
            return "result" in result
        return False

    def test_connection(self):
        """Test API connectivity."""
        result = self.api_call("apiinfo.version", {}, auth=False)
        if "result" in result:
            print(f"  [+] Connected to Zabbix API v{result['result']}")
            return True
        print(f"  [-] Cannot connect to Zabbix API")
        return False

    def raw_get(self, path, params=None, headers=None):
        """Make a raw HTTP GET request to the web frontend."""
        url = f"{self.base_url}{path}"
        return self.session.get(url, params=params, headers=headers, timeout=30, allow_redirects=False)

    def raw_post(self, path, data=None, json_data=None, headers=None):
        """Make a raw HTTP POST request to the web frontend."""
        url = f"{self.base_url}{path}"
        return self.session.post(url, data=data, json=json_data, headers=headers, timeout=30, allow_redirects=False)

    def get_api_version(self):
        """Get the API version."""
        result = self.api_call("apiinfo.version", {}, auth=False)
        return result.get("result", "unknown")

    def get_users(self):
        """Get all users."""
        return self.api_call("user.get", {"output": "extend"})

    def get_hosts(self):
        """Get all hosts."""
        return self.api_call("host.get", {"output": "extend"})

    def get_scripts(self):
        """Get all scripts."""
        return self.api_call("script.get", {"output": "extend"})

    def get_user_groups(self):
        """Get all user groups."""
        return self.api_call("usergroup.get", {"output": "extend"})

    def get_roles(self):
        """Get all roles."""
        return self.api_call("role.get", {"output": "extend"})

    def get_media_types(self):
        """Get all media types."""
        return self.api_call("mediatype.get", {"output": "extend"})


class EvidenceCollector:
    """Collects and saves test evidence in JSON format."""

    def __init__(self, name, phase="unknown"):
        self.name = name
        self.phase = phase
        self.tests = []
        self.findings = []
        self.anomalies = []
        self.metadata = {
            "collector": name,
            "phase": phase,
            "started": datetime.now().isoformat(),
            "target": "Zabbix 7.0.23 LTS",
            "target_url": ZABBIX_URL,
        }

    def add_test(self, test_id, description, request_info, response_info, result="PASS"):
        """Record a test case."""
        self.tests.append({
            "id": test_id,
            "description": description,
            "request": str(request_info)[:500],
            "response": str(response_info)[:500],
            "result": result,
            "timestamp": datetime.now().isoformat(),
        })

    def add_finding(self, finding_id, severity, title, details,
                    evidence=None, remediation=None):
        """Record a validated finding."""
        self.findings.append({
            "id": finding_id,
            "severity": severity,
            "title": title,
            "details": details,
            "evidence": str(evidence)[:2000] if evidence else None,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat(),
        })
        print(f"\n  ** FINDING: [{severity}] {finding_id}: {title}")

    def add_anomaly(self, anomaly_id, description):
        """Record an unexpected behavior for later investigation."""
        self.anomalies.append({
            "id": anomaly_id,
            "description": description,
            "timestamp": datetime.now().isoformat(),
        })

    def save(self):
        """Save evidence to JSON file."""
        self.metadata["completed"] = datetime.now().isoformat()
        self.metadata["test_count"] = len(self.tests)
        self.metadata["finding_count"] = len(self.findings)
        self.metadata["anomaly_count"] = len(self.anomalies)

        output = {
            "metadata": self.metadata,
            "findings": self.findings,
            "anomalies": self.anomalies,
            "tests": self.tests,
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.phase}_{self.name}_{timestamp}.json"
        filepath = os.path.join(EVIDENCE_DIR, filename)

        with open(filepath, "w") as f:
            json.dump(output, f, indent=2, default=str)

        print(f"\n  Evidence saved: {filepath}")
        print(f"  Tests: {len(self.tests)}, Findings: {len(self.findings)}, Anomalies: {len(self.anomalies)}")
        return filepath
