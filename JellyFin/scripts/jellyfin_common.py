#!/usr/bin/env python3
"""
COBALT STRIKE II — Jellyfin Common Utilities
Shared session management, evidence collection, and helper functions.
"""

import requests
import json
import time
import datetime
import os
import sys
import socket
import struct

# ─── Configuration ───────────────────────────────────────────────────────────

JELLYFIN_BASE = os.environ.get("JELLYFIN_BASE", "http://localhost:8096")
JELLYFIN_USER = os.environ.get("JELLYFIN_USER", "root")
JELLYFIN_PASS = os.environ.get("JELLYFIN_PASS", "")

EVIDENCE_DIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/JellyFin/evidence"
os.makedirs(EVIDENCE_DIR, exist_ok=True)


# ─── Evidence Collector ──────────────────────────────────────────────────────

class EvidenceCollector:
    """Records tests, findings, and anomalies for structured JSON evidence output."""

    def __init__(self, script_name, phase=""):
        self.script_name = script_name
        self.phase = phase
        self.tests = []
        self.findings = []
        self.anomalies = []
        self.start_time = datetime.datetime.now().isoformat()

    def add_test(self, test_id, description, request_info, response_info,
                 result="PASS", severity="INFO"):
        self.tests.append({
            "id": test_id,
            "description": description,
            "request": str(request_info)[:2000],
            "response": str(response_info)[:2000],
            "result": result,
            "severity": severity,
            "timestamp": datetime.datetime.now().isoformat(),
        })
        status_icon = {
            "PASS": "[+]", "FAIL": "[-]", "VULN": "[!]",
            "ERROR": "[!]", "ANOMALOUS": "[?]", "BLOCKED": "[?]",
            "INCONCLUSIVE": "[~]",
        }.get(result, "[*]")
        print(f"  {status_icon} {test_id}: {description[:50]} → {result}")

    def add_finding(self, finding_id, severity, title, details,
                    evidence="", remediation=""):
        self.findings.append({
            "id": finding_id,
            "severity": severity,
            "title": title,
            "details": str(details)[:5000],
            "evidence": str(evidence)[:5000],
            "remediation": remediation,
            "timestamp": datetime.datetime.now().isoformat(),
        })
        print(f"\n  [FINDING] [{severity}] {finding_id}: {title}")
        print(f"           {str(details)[:200]}")

    def add_anomaly(self, anomaly_id, description, details=""):
        self.anomalies.append({
            "id": anomaly_id,
            "description": description,
            "details": str(details)[:2000],
            "timestamp": datetime.datetime.now().isoformat(),
        })
        print(f"  [ANOMALY] {anomaly_id}: {description[:80]}")

    def save(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.phase}_{self.script_name}_{ts}.json"
        filepath = os.path.join(EVIDENCE_DIR, filename)

        data = {
            "script": self.script_name,
            "phase": self.phase,
            "target": "Jellyfin 10.11.6",
            "start_time": self.start_time,
            "end_time": datetime.datetime.now().isoformat(),
            "summary": {
                "total_tests": len(self.tests),
                "findings": len(self.findings),
                "anomalies": len(self.anomalies),
            },
            "tests": self.tests,
            "findings": self.findings,
            "anomalies": self.anomalies,
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)

        print(f"\n  [*] Evidence saved: {filepath}")
        print(f"      Tests: {len(self.tests)} | Findings: {len(self.findings)} "
              f"| Anomalies: {len(self.anomalies)}")


# ─── Jellyfin Session Manager ───────────────────────────────────────────────

class JellyfinSession:
    """Handles Jellyfin authentication and API requests."""

    def __init__(self, base_url=None, username=None, password=None,
                 client="[REDACTED-PROJECT]", device="Kali", device_id="cobalt-001",
                 version="1.0.0"):
        self.base_url = (base_url or JELLYFIN_BASE).rstrip("/")
        self.username = username or JELLYFIN_USER
        self.password = password or JELLYFIN_PASS
        self.client = client
        self.device = device
        self.device_id = device_id
        self.version = version
        self.access_token = None
        self.user_id = None
        self.server_id = None
        self.session = requests.Session()
        self.session.verify = False

        # Suppress SSL warnings
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )

    def _auth_header(self, token=None):
        """Build the MediaBrowser Authorization header."""
        parts = [
            f'Client="{self.client}"',
            f'Device="{self.device}"',
            f'DeviceId="{self.device_id}"',
            f'Version="{self.version}"',
        ]
        if token or self.access_token:
            parts.append(f'Token="{token or self.access_token}"')
        return f"MediaBrowser {', '.join(parts)}"

    def authenticate(self):
        """Authenticate and store access token."""
        headers = {
            "Content-Type": "application/json",
            "X-Emby-Authorization": self._auth_header(),
        }
        data = {
            "Username": self.username,
            "Pw": self.password,
        }
        try:
            resp = self.session.post(
                f"{self.base_url}/Users/AuthenticateByName",
                headers=headers, json=data, timeout=10,
            )
            if resp.status_code == 200:
                auth_data = resp.json()
                self.access_token = auth_data.get("AccessToken", "")
                self.user_id = auth_data.get("User", {}).get("Id", "")
                self.server_id = auth_data.get("ServerId", "")
                return True
            else:
                print(f"  [-] Auth failed: HTTP {resp.status_code}: {resp.text[:200]}")
                return False
        except Exception as e:
            print(f"  [-] Auth error: {e}")
            return False

    def test_connection(self):
        """Test connectivity and authenticate."""
        try:
            resp = self.session.get(
                f"{self.base_url}/System/Info/Public", timeout=10,
            )
            if resp.status_code == 200:
                info = resp.json()
                version = info.get("Version", "?")
                server_name = info.get("ServerName", "?")
                server_id = info.get("Id", "?")
                print(f"  [+] Connected to Jellyfin {version}")
                print(f"      Server: {server_name}")
                print(f"      ID: {server_id}")
                print(f"      Wizard Complete: {info.get('StartupWizardCompleted', '?')}")

                # Authenticate
                if self.authenticate():
                    print(f"      Authenticated as: {self.username}")
                    print(f"      User ID: {self.user_id}")
                    print(f"      Token: {self.access_token[:20]}...")
                    return True
                else:
                    print(f"      [-] Authentication failed")
                    return False
            else:
                print(f"  [-] Connection failed: HTTP {resp.status_code}")
                return False
        except Exception as e:
            print(f"  [-] Connection error: {e}")
            return False

    def _headers(self):
        """Standard headers for authenticated requests."""
        return {
            "Content-Type": "application/json",
            "X-Emby-Authorization": self._auth_header(),
        }

    def get(self, endpoint, params=None, **kwargs):
        """Authenticated GET request."""
        url = f"{self.base_url}{endpoint}"
        return self.session.get(url, headers=self._headers(),
                               params=params, timeout=30, **kwargs)

    def post(self, endpoint, data=None, json_data=None, **kwargs):
        """Authenticated POST request."""
        url = f"{self.base_url}{endpoint}"
        if data is not None and json_data is None:
            return self.session.post(url, headers=self._headers(),
                                    json=data, timeout=30, **kwargs)
        elif json_data is not None:
            return self.session.post(url, headers=self._headers(),
                                    json=json_data, timeout=30, **kwargs)
        else:
            return self.session.post(url, headers=self._headers(),
                                    timeout=30, **kwargs)

    def put(self, endpoint, data=None, **kwargs):
        """Authenticated PUT request."""
        url = f"{self.base_url}{endpoint}"
        return self.session.put(url, headers=self._headers(),
                               json=data, timeout=30, **kwargs)

    def delete(self, endpoint, **kwargs):
        """Authenticated DELETE request."""
        url = f"{self.base_url}{endpoint}"
        return self.session.delete(url, headers=self._headers(),
                                  timeout=30, **kwargs)

    def raw_get(self, endpoint, headers=None, **kwargs):
        """GET without auth headers (for unauthenticated testing)."""
        url = f"{self.base_url}{endpoint}"
        return self.session.get(url, headers=headers or {},
                               timeout=30, **kwargs)

    def raw_post(self, endpoint, data=None, headers=None, **kwargs):
        """POST without auth headers (for unauthenticated testing)."""
        url = f"{self.base_url}{endpoint}"
        return self.session.post(url, headers=headers or {},
                                json=data, timeout=30, **kwargs)

    def upload(self, endpoint, files=None, data=None, **kwargs):
        """File upload request (multipart/form-data)."""
        url = f"{self.base_url}{endpoint}"
        headers = {"X-Emby-Authorization": self._auth_header()}
        return self.session.post(url, headers=headers, files=files,
                                data=data, timeout=60, **kwargs)


# ─── Helper Functions ────────────────────────────────────────────────────────

def banner(title):
    """Print a section banner."""
    width = max(60, len(title) + 4)
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def rate_limit(seconds=0.3):
    """Sleep between requests to avoid overwhelming the target."""
    time.sleep(seconds)


def create_test_user(js, username="cobalt_viewer", password="ViewerPass123"):
    """Create a non-admin test user for privilege testing."""
    user_data = {
        "Name": username,
        "Password": password,
    }
    resp = js.post("/Users/New", data=user_data)
    if resp.status_code in (200, 201):
        user_info = resp.json()
        user_id = user_info.get("Id", "")
        print(f"  [+] Created test user: {username} (id: {user_id})")
        return user_id
    else:
        print(f"  [-] Failed to create user: HTTP {resp.status_code}: {resp.text[:200]}")
        return None


def get_api_key(js):
    """Create an API key for testing."""
    resp = js.post("/Auth/Keys", data={"App": "[REDACTED-PROJECT]"})
    if resp.status_code in (200, 201, 204):
        # Fetch the key list
        keys_resp = js.get("/Auth/Keys")
        if keys_resp.status_code == 200:
            keys = keys_resp.json().get("Items", [])
            if keys:
                return keys[-1].get("AccessToken", "")
    return None
