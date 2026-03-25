"""
Security AssessmentI — Tenda SOHO Router Security Assessment
Common Utilities: EvidenceCollector, firmware helpers, r2 wrappers
"""
import json
import os
import re
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Project paths
[REDACTED-ID]_ROOT = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda")
FIRMWARE_DIR = [REDACTED-ID]_ROOT / "firmware"
AC15_ROOT = FIRMWARE_DIR / "ac15"
AC20_ROOT = FIRMWARE_DIR / "ac20"
BINARIES_DIR = FIRMWARE_DIR / "binaries"
EVIDENCE_DIR = [REDACTED-ID]_ROOT / "evidence"
FINDINGS_DIR = [REDACTED-ID]_ROOT / "findings"
SCRIPTS_DIR = [REDACTED-ID]_ROOT / "scripts"

# Also make common_base available
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/secsoft-assessor/skills/security-assessment/scripts')


class EvidenceCollector:
    """Standard evidence collection for Tenda security assessment."""

    def __init__(self, script_name, output_dir=None):
        self.script_name = script_name
        self.output_dir = str(output_dir or EVIDENCE_DIR)
        self.tests = []
        self.findings = []
        self.anomalies = []
        self.start_time = datetime.now().isoformat()
        os.makedirs(self.output_dir, exist_ok=True)

    def add_test(self, test_id, description, request, response, status="INFO"):
        """Record a test result. Status: INFO, PASS, FAIL, VULN, ERROR"""
        self.tests.append({
            "id": test_id,
            "description": description,
            "request": request if isinstance(request, str) else repr(request),
            "response": response if isinstance(response, str) else repr(response),
            "status": status,
            "timestamp": datetime.now().isoformat()
        })

    def add_finding(self, finding_id, severity, title, details, cvss=None,
                    cwe=None, endpoint=None, parameter=None):
        """Record a security finding."""
        finding = {
            "id": finding_id,
            "severity": severity,
            "title": title,
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        if cvss:
            finding["cvss"] = cvss
        if cwe:
            finding["cwe"] = cwe
        if endpoint:
            finding["endpoint"] = endpoint
        if parameter:
            finding["parameter"] = parameter
        self.findings.append(finding)

    def add_anomaly(self, anomaly_id, description):
        """Record an anomaly worth investigating."""
        self.anomalies.append({
            "id": anomaly_id,
            "description": description,
            "timestamp": datetime.now().isoformat()
        })

    def save(self, filename=None):
        """Save evidence to JSON file."""
        if filename is None:
            filename = f"{self.script_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        data = {
            "project": "[REDACTED-ID]_Tenda",
            "script": self.script_name,
            "start_time": self.start_time,
            "end_time": datetime.now().isoformat(),
            "test_count": len(self.tests),
            "finding_count": len(self.findings),
            "anomaly_count": len(self.anomalies),
            "tests": self.tests,
            "findings": self.findings,
            "anomalies": self.anomalies
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[*] Evidence saved to {filepath}")
        print(f"    Tests: {len(self.tests)}, Findings: {len(self.findings)}, Anomalies: {len(self.anomalies)}")
        return filepath


class R2Wrapper:
    """Wrapper for radare2 batch analysis of ARM binaries."""

    def __init__(self, binary_path):
        self.binary = binary_path
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

    def run_cmd(self, r2_commands, timeout=120):
        """Run r2 commands in batch mode. r2_commands is a list of strings."""
        if isinstance(r2_commands, str):
            r2_commands = [r2_commands]
        cmd_str = ";".join(r2_commands)
        try:
            result = subprocess.run(
                ["r2", "-q", "-e", "bin.cache=true", "-c", cmd_str, self.binary],
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] r2 command timed out after {timeout}s"
        except Exception as e:
            return f"[ERROR] {e}"

    def analyze_and_run(self, r2_commands, timeout=300):
        """Run r2 with full analysis (aaa) then commands."""
        if isinstance(r2_commands, str):
            r2_commands = [r2_commands]
        full_cmds = ["aaa"] + r2_commands
        return self.run_cmd(full_cmds, timeout=timeout)

    def get_functions(self, pattern=None):
        """List functions, optionally filtered by pattern."""
        output = self.analyze_and_run("afl")
        if pattern:
            return "\n".join(l for l in output.splitlines() if pattern.lower() in l.lower())
        return output

    def get_strings(self, pattern=None):
        """Get strings from binary, optionally filtered."""
        output = self.run_cmd("izz")
        if pattern:
            return "\n".join(l for l in output.splitlines() if pattern.lower() in l.lower())
        return output

    def get_xrefs_to(self, func_name):
        """Get cross-references to a function."""
        return self.analyze_and_run(f"axt @@ {func_name}")

    def decompile_function(self, func_addr_or_name):
        """Decompile a function using r2's pdc."""
        return self.analyze_and_run([f"s {func_addr_or_name}", "pdc"])

    def disassemble_function(self, func_addr_or_name, lines=100):
        """Disassemble a function."""
        return self.analyze_and_run([f"s {func_addr_or_name}", f"pdf"])


class FirmwareHelper:
    """Helpers for firmware extraction and analysis."""

    @staticmethod
    def extract_firmware(firmware_path, output_dir):
        """Extract firmware using binwalk."""
        result = subprocess.run(
            ["binwalk", "-Me", "-C", output_dir, firmware_path],
            capture_output=True, text=True, timeout=300
        )
        return result.stdout + result.stderr

    @staticmethod
    def find_httpd(rootfs_path):
        """Find the httpd binary in extracted rootfs."""
        for root, dirs, files in os.walk(rootfs_path):
            for f in files:
                if f == "httpd":
                    full_path = os.path.join(root, f)
                    return full_path
        return None

    @staticmethod
    def checksec(binary_path):
        """Run checksec on a binary."""
        try:
            result = subprocess.run(
                ["checksec", "--file=" + binary_path],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"[ERROR] checksec failed: {e}"

    @staticmethod
    def file_info(binary_path):
        """Get file type info."""
        result = subprocess.run(
            ["file", binary_path],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip()

    @staticmethod
    def count_strings(binary_path, pattern):
        """Count strings matching a pattern in a binary."""
        result = subprocess.run(
            ["strings", binary_path],
            capture_output=True, text=True, timeout=30
        )
        matches = [l for l in result.stdout.splitlines() if re.search(pattern, l, re.IGNORECASE)]
        return len(matches), matches

    @staticmethod
    def get_goform_endpoints(binary_path):
        """Extract goform endpoint names from httpd binary."""
        result = subprocess.run(
            ["strings", binary_path],
            capture_output=True, text=True, timeout=30
        )
        endpoints = set()
        for line in result.stdout.splitlines():
            # Match goform/ references
            for m in re.finditer(r'(?:goform/|/goform/)(\w+)', line):
                endpoints.add(m.group(1))
            # Also catch bare handler names that match Tenda patterns
            if re.match(r'^(form|set|get|save|del|add)[A-Z]\w+', line):
                endpoints.add(line.strip())
        return sorted(endpoints)

    @staticmethod
    def get_dangerous_strings(binary_path):
        """Get counts and lists of dangerous function references."""
        result = subprocess.run(
            ["strings", binary_path],
            capture_output=True, text=True, timeout=30
        )
        all_strings = result.stdout.splitlines()

        categories = {
            "unsafe_copy": {"pattern": r"\b(strcpy|strcat|sprintf|vsprintf|gets)\b",
                           "matches": []},
            "safe_copy": {"pattern": r"\b(strncpy|strncat|snprintf|vsnprintf|fgets)\b",
                         "matches": []},
            "exec_sinks": {"pattern": r"\b(system|popen|execve?|doSystemCmd|twsystem)\b",
                          "matches": []},
            "input_sources": {"pattern": r"\b(websGetVar|getenv|fgets|recv|read)\b",
                             "matches": []},
        }

        for s in all_strings:
            for cat_name, cat in categories.items():
                if re.search(cat["pattern"], s):
                    cat["matches"].append(s)

        return {name: {"count": len(c["matches"]), "samples": c["matches"][:20]}
                for name, c in categories.items()}


def find_squashfs_root(extract_dir):
    """Recursively find squashfs-root directory after binwalk extraction."""
    for root, dirs, files in os.walk(extract_dir):
        if "squashfs-root" in dirs:
            return os.path.join(root, "squashfs-root")
    return None


if __name__ == "__main__":
    print("[*] Tenda Common Utilities loaded")
    print(f"    [REDACTED-ID]_ROOT: {[REDACTED-ID]_ROOT}")
    print(f"    FIRMWARE_DIR: {FIRMWARE_DIR}")
    print(f"    EVIDENCE_DIR: {EVIDENCE_DIR}")
