#!/usr/bin/env python3
"""
MikroTik RouterOS CHR 7.20.8 — Assessment Report Generator
Phase 10: Reporting

Reads all evidence JSON files, aggregates metrics, and generates a
comprehensive markdown report suitable for vendor disclosure.

Output: /home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/[REDACTED]_MikroTik_Security_Assessment.md

Usage:
    python3 generate_report.py
"""

import sys
sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts')
from mikrotik_common import *

import glob
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# ── Configuration ────────────────────────────────────────────────────────────

REPORT_PATH = BASE_DIR / "[REDACTED]_MikroTik_Security_Assessment.md"

# Phase names — map phase numbers to descriptions
PHASE_NAMES = {
    1: "Reconnaissance and Static Analysis",
    2: "WebFig Authentication and Session Security",
    3: "REST API and HTTP Attack Surface",
    4: "Protocol Fuzzing (API, Winbox, Network)",
    5: "Service-Level Attacks (SSH, FTP, Telnet, SNMP)",
    6: "Denial-of-Service Resilience",
    7: "Post-Authentication and Privilege Escalation",
    8: "CVE Regression Testing",
    9: "Novel Vulnerability Hunting",
    10: "Reporting and Validation",
}

# Severity ordering for sorting
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# CWE descriptions
CWE_DESCRIPTIONS = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-200": "Information Exposure",
    "CWE-287": "Improper Authentication",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-384": "Session Fixation",
    "CWE-400": "Resource Exhaustion",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Information Exposure Through Log Files",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-614": "Sensitive Cookie Without Secure Flag",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
}


# ══════════════════════════════════════════════════════════════════════════════
# Evidence Loading
# ══════════════════════════════════════════════════════════════════════════════

def load_evidence_files():
    """Load all evidence JSON files from the evidence directory.

    Returns a dict: {filename: parsed_json_data}.
    """
    evidence = {}
    evidence_path = EVIDENCE_DIR

    if not evidence_path.exists():
        log(f"Evidence directory not found: {evidence_path}")
        return evidence

    for json_file in sorted(evidence_path.glob("*.json")):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
            evidence[json_file.name] = data
            log(f"  Loaded: {json_file.name}")
        except Exception as e:
            log(f"  Error loading {json_file.name}: {e}")

    return evidence


def load_router_logs():
    """Load all router_logs_*.json files and return them as a list."""
    logs = []
    for json_file in sorted(EVIDENCE_DIR.glob("router_logs_*.json")):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
            logs.append({"file": json_file.name, "data": data})
        except Exception as e:
            log(f"  Error loading router log {json_file.name}: {e}")
    return logs


# ══════════════════════════════════════════════════════════════════════════════
# Metric Aggregation
# ══════════════════════════════════════════════════════════════════════════════

def aggregate_metrics(evidence):
    """Aggregate test counts, anomalies, and findings across all evidence.

    Returns a dict with summary metrics.
    """
    metrics = {
        "total_tests": 0,
        "total_anomalies": 0,
        "total_findings": 0,
        "findings_by_severity": defaultdict(int),
        "findings_list": [],
        "tests_by_phase": defaultdict(int),
        "anomalies_by_phase": defaultdict(int),
        "scripts": [],
        "date_range": {"earliest": None, "latest": None},
        "crashes": 0,
        "router_version": None,
        "evidence_files": [],
    }

    for filename, data in evidence.items():
        # Skip router log files for test counting
        if filename.startswith("router_logs_"):
            continue

        metrics["evidence_files"].append(filename)

        metadata = data.get("metadata", {})
        tests = metadata.get("total_tests", 0)
        anomalies = metadata.get("anomalies", 0)
        phase = metadata.get("phase", 0)
        script = metadata.get("script", filename)

        metrics["total_tests"] += tests
        metrics["total_anomalies"] += anomalies
        metrics["tests_by_phase"][phase] += tests
        metrics["anomalies_by_phase"][phase] += anomalies

        # Track scripts
        metrics["scripts"].append({
            "name": script,
            "phase": phase,
            "tests": tests,
            "anomalies": anomalies,
            "findings": len(data.get("findings", [])),
            "evidence_file": filename,
        })

        # Collect findings
        for finding in data.get("findings", []):
            severity = finding.get("severity", "UNKNOWN")
            metrics["findings_by_severity"][severity] += 1
            metrics["total_findings"] += 1
            metrics["findings_list"].append({
                **finding,
                "source_script": script,
                "source_file": filename,
                "phase": phase,
            })

        # Track crash count
        crash_count = metadata.get("crash_count", 0)
        if crash_count:
            metrics["crashes"] += crash_count

        # Track router version
        if not metrics["router_version"] and metadata.get("router_version"):
            metrics["router_version"] = metadata["router_version"]

        # Track date range
        start = metadata.get("start_time")
        end = metadata.get("end_time")
        if start:
            if not metrics["date_range"]["earliest"] or start < metrics["date_range"]["earliest"]:
                metrics["date_range"]["earliest"] = start
            if not metrics["date_range"]["latest"] or start > metrics["date_range"]["latest"]:
                metrics["date_range"]["latest"] = start
        if end:
            if not metrics["date_range"]["latest"] or end > metrics["date_range"]["latest"]:
                metrics["date_range"]["latest"] = end

    # Sort findings by severity
    metrics["findings_list"].sort(
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 99))

    # Sort scripts by phase (handle mixed int/str phase values)
    metrics["scripts"].sort(key=lambda s: (int(s["phase"]) if isinstance(s["phase"], (int, float)) else 99, s["name"]))

    return metrics


# ══════════════════════════════════════════════════════════════════════════════
# Router Log Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_router_logs(router_logs):
    """Analyze router-side logs for interesting events.

    Returns a dict with analysis results.
    """
    analysis = {
        "total_log_entries": 0,
        "total_interesting": 0,
        "categories": defaultdict(int),
        "interesting_events": [],
        "log_snapshots": [],
    }

    for log_entry in router_logs:
        data = log_entry.get("data", {})
        analysis["total_log_entries"] += data.get("log_entry_count", 0)
        analysis["total_interesting"] += data.get("interesting_count", 0)

        # Aggregate categories
        for cat, count in data.get("categories", {}).items():
            analysis["categories"][cat] += count

        # Collect interesting events
        for event in data.get("interesting_entries", [])[:20]:
            analysis["interesting_events"].append({
                "phase": data.get("phase", "unknown"),
                "message": event.get("message", ""),
                "topics": event.get("topics", ""),
                "time": event.get("time", ""),
            })

        # Snapshot info
        resource = data.get("system_resource", {})
        if resource:
            analysis["log_snapshots"].append({
                "phase": data.get("phase", "unknown"),
                "uptime": resource.get("uptime", ""),
                "cpu_load": resource.get("cpu-load", ""),
                "free_memory": resource.get("free-memory", ""),
                "total_memory": resource.get("total-memory", ""),
            })

    return analysis


# ══════════════════════════════════════════════════════════════════════════════
# Report Generation
# ══════════════════════════════════════════════════════════════════════════════

def format_date(iso_str):
    """Format ISO date string to human-readable."""
    if not iso_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%B %d, %Y")
    except:
        return iso_str[:10] if len(str(iso_str)) >= 10 else str(iso_str)


def format_date_range(date_range):
    """Format a date range dict to a human-readable string."""
    earliest = format_date(date_range.get("earliest"))
    latest = format_date(date_range.get("latest"))
    if earliest == latest:
        return earliest
    return f"{earliest} -- {latest}"


def generate_report(evidence, metrics, router_logs, log_analysis):
    """Generate the full markdown report."""
    lines = []

    def w(line=""):
        lines.append(line)

    # ── Header ───────────────────────────────────────────────────────────
    w("# [REDACTED] -- MikroTik RouterOS CHR 7.20.8 Security Assessment Report")
    w()
    w(f"**Date:** {datetime.now().strftime('%B %d, %Y')}")
    w("**Assessor:** independent security research.")
    w(f"**Target:** MikroTik RouterOS CHR {metrics.get('router_version', '7.20.8')} (x86_64)")
    w(f"**Platform:** Kali Linux VM (host-only network, target at {TARGET})")
    w()
    w("---")
    w()

    # ── Executive Summary ────────────────────────────────────────────────
    w("## Executive Summary")
    w()

    severity_counts = metrics["findings_by_severity"]
    severity_str = ", ".join(
        f"{severity_counts.get(s, 0)} {s}"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        if severity_counts.get(s, 0) > 0
    )
    if not severity_str:
        severity_str = "0 findings"

    w(f"A comprehensive security assessment was conducted against MikroTik RouterOS "
      f"CHR version {metrics.get('router_version', '7.20.8')} running as a virtual "
      f"machine on a host-only network. The assessment spanned "
      f"{len([p for p in metrics['tests_by_phase'] if metrics['tests_by_phase'][p] > 0])} "
      f"phases, exercising WebFig/HTTP, REST API, RouterOS API (port 8728), "
      f"Winbox (port 8291), SSH, FTP, Telnet, SNMP, and MNDP interfaces.")
    w()
    w("**Key Metrics:**")
    w(f"- **{metrics['total_tests']:,} test cases** across "
      f"{len(metrics['scripts'])} scripts in "
      f"{len([p for p in metrics['tests_by_phase'] if metrics['tests_by_phase'][p] > 0])} phases")
    w(f"- **{metrics['total_findings']} findings** ({severity_str})")
    w(f"- **{metrics['total_anomalies']} anomalies** detected across all phases")
    w(f"- **{metrics['crashes']} router crashes** detected during testing")
    w(f"- **{len(metrics['evidence_files'])} JSON evidence files** documenting all results")
    w(f"- **Assessment period:** {format_date_range(metrics['date_range'])}")
    w()

    # ── Findings Summary Table ───────────────────────────────────────────
    w("### Findings Summary")
    w()

    if metrics["findings_list"]:
        w("| # | Severity | Finding | CWE | Phase |")
        w("|---|----------|---------|-----|-------|")
        for i, finding in enumerate(metrics["findings_list"], 1):
            severity = finding.get("severity", "UNKNOWN")
            title = finding.get("title", "Untitled")
            cwe = finding.get("cwe", "--")
            phase = finding.get("phase", "--")
            phase_name = PHASE_NAMES.get(phase, str(phase))
            w(f"| {i} | {severity} | {title} | {cwe} | {phase} |")
        w()
    else:
        w("*No findings recorded in evidence files.*")
        w()

    w("---")
    w()

    # ── Scope and Methodology ────────────────────────────────────────────
    w("## Scope and Methodology")
    w()
    w("### Target Software")
    w()
    w("| Component | Version | Notes |")
    w("|-----------|---------|-------|")
    w(f"| RouterOS CHR | {metrics.get('router_version', '7.20.8')} | Cloud Hosted Router (x86_64 VM) |")
    w("| WebFig | Built-in | Web management interface (port 80/443) |")
    w("| REST API | Built-in | JSON REST interface (port 80) |")
    w("| RouterOS API | Built-in | Binary protocol (port 8728/8729) |")
    w("| Winbox | Built-in | Proprietary management protocol (port 8291) |")
    w()
    w("### Network Services Assessed")
    w()
    w("| Service | Port | Protocol | Notes |")
    w("|---------|------|----------|-------|")
    w("| WebFig/REST | 80 | TCP/HTTP | Web management and REST API |")
    w("| HTTPS | 443 | TCP/TLS | Encrypted web management |")
    w("| SSH | 22 | TCP | Secure shell access |")
    w("| FTP | 21 | TCP | File transfer |")
    w("| Telnet | 23 | TCP | Plaintext terminal access |")
    w("| Winbox | 8291 | TCP | MikroTik proprietary management |")
    w("| API | 8728 | TCP | RouterOS binary API |")
    w("| API-SSL | 8729 | TCP/TLS | RouterOS encrypted API |")
    w("| BTest | 2000 | TCP | Bandwidth test server |")
    w("| SNMP | 161 | UDP | Simple Network Management Protocol |")
    w("| MNDP | 5678 | UDP | MikroTik Neighbor Discovery |")
    w()
    w("### Methodology")
    w()
    w("The assessment followed a 10-phase methodology:")
    w()
    w("| Phase | Focus | Tests | Anomalies |")
    w("|-------|-------|-------|-----------|")

    total_tests_check = 0
    total_anom_check = 0
    for phase_num in sorted(PHASE_NAMES.keys()):
        tests = metrics["tests_by_phase"].get(phase_num, 0)
        anoms = metrics["anomalies_by_phase"].get(phase_num, 0)
        total_tests_check += tests
        total_anom_check += anoms
        tests_str = f"{tests:,}" if tests > 0 else "--"
        anoms_str = str(anoms) if tests > 0 else "--"
        w(f"| {phase_num} | {PHASE_NAMES[phase_num]} | {tests_str} | {anoms_str} |")
    w(f"| **Total** | | **{total_tests_check:,}** | **{total_anom_check}** |")
    w()

    w("### Tools")
    w()
    w("Python 3.13, nmap, custom Python scripts (socket-level protocol testing, "
      "REST API testing, binary fuzzing), requests, paramiko, tcpdump, strings, "
      "objdump, radare2, strace, Wireshark")
    w()
    w("### Test Accounts")
    w()
    w("| Username | Group | Purpose |")
    w("|----------|-------|---------|")
    for username, info in USERS.items():
        w(f"| {username} | {info['group']} | Testing {info['group']}-level access |")
    w()
    w("---")
    w()

    # ── Detailed Findings ────────────────────────────────────────────────
    w("## Detailed Findings")
    w()

    if metrics["findings_list"]:
        for i, finding in enumerate(metrics["findings_list"], 1):
            severity = finding.get("severity", "UNKNOWN")
            title = finding.get("title", "Untitled")
            cwe = finding.get("cwe", "")
            cwe_desc = CWE_DESCRIPTIONS.get(cwe, "")
            phase = finding.get("phase", "")
            description = finding.get("description", "")
            evidence_refs = finding.get("evidence_refs", [])
            reproduction = finding.get("reproduction_steps", "")
            source_file = finding.get("source_file", "")
            cvss = finding.get("cvss_estimate", "")

            w(f"### Finding {i} -- {severity}: {title}")
            w()
            if cwe:
                w(f"**{cwe}** | {cwe_desc}" if cwe_desc else f"**{cwe}**")
            if cvss:
                w(f"**CVSS Estimate:** {cvss}")
            if phase:
                phase_name = PHASE_NAMES.get(phase, str(phase))
                w(f"**Phase:** {phase} ({phase_name})")
            w()
            w("**Description:**")
            w(description)
            w()

            if reproduction:
                w("**Reproduction Steps:**")
                if isinstance(reproduction, list):
                    for step in reproduction:
                        w(f"1. {step}")
                else:
                    w(str(reproduction))
                w()

            if evidence_refs:
                w("**Evidence:**")
                for ref in evidence_refs:
                    w(f"- `{ref}`")
                w()
            elif source_file:
                w(f"**Evidence:** `evidence/{source_file}`")
                w()

            w("---")
            w()
    else:
        w("*No findings were recorded during this assessment. See phase details below for observations.*")
        w()
        w("---")
        w()

    # ── Testing Phases ───────────────────────────────────────────────────
    w("## Testing Phases")
    w()

    # Group scripts by phase
    scripts_by_phase = defaultdict(list)
    for script in metrics["scripts"]:
        scripts_by_phase[script["phase"]].append(script)

    for phase_num in sorted(PHASE_NAMES.keys()):
        phase_name = PHASE_NAMES[phase_num]
        phase_tests = metrics["tests_by_phase"].get(phase_num, 0)
        phase_anoms = metrics["anomalies_by_phase"].get(phase_num, 0)
        phase_scripts = scripts_by_phase.get(phase_num, [])

        if phase_tests == 0 and not phase_scripts:
            continue

        w(f"### Phase {phase_num}: {phase_name} ({phase_tests:,} tests)")
        w()

        if phase_scripts:
            w("| Script | Tests | Anomalies | Findings |")
            w("|--------|-------|-----------|----------|")
            for script in phase_scripts:
                w(f"| `{script['name']}` | {script['tests']} | {script['anomalies']} | "
                  f"{script['findings']} |")
            w()

        # Phase-specific observations from evidence
        for script in phase_scripts:
            ev_file = script.get("evidence_file", "")
            if ev_file in evidence:
                ev_data = evidence[ev_file]
                findings = ev_data.get("findings", [])
                if findings:
                    w("**Findings from this phase:**")
                    for f in findings:
                        w(f"- [{f.get('severity', 'UNKNOWN')}] {f.get('title', 'N/A')}")
                    w()

        w()

    w("---")
    w()

    # ── CVE Regression Results ───────────────────────────────────────────
    w("## CVE Regression Results")
    w()
    w("Known MikroTik CVEs tested against RouterOS CHR "
      f"{metrics.get('router_version', '7.20.8')}:")
    w()
    w("| CVE | CVSS | Description | Status | Notes |")
    w("|-----|------|-------------|--------|-------|")

    # Check if we have CVE regression evidence
    cve_evidence = None
    for filename, data in evidence.items():
        if "cve" in filename.lower() and "regression" in filename.lower():
            cve_evidence = data
            break

    if cve_evidence and "tests" in cve_evidence:
        cve_results = {}
        for test in cve_evidence["tests"]:
            name = test.get("name", "")
            if name.startswith("CVE-") or "CVE-" in name:
                cve_id = ""
                for part in name.split("_"):
                    if part.startswith("CVE-"):
                        cve_id = part
                        break
                if not cve_id:
                    cve_id = name
                result = test.get("result", "")
                desc = test.get("description", "")
                anomaly = test.get("anomaly", False)
                status = "ANOMALY" if anomaly else ("PATCHED" if "patched" in result.lower()
                          or "blocked" in result.lower() or "rejected" in result.lower()
                          else result[:30])
                if cve_id not in cve_results:
                    cve_results[cve_id] = {"desc": desc, "status": status, "tests": 1}
                else:
                    cve_results[cve_id]["tests"] += 1

        for cve_id, info in sorted(cve_results.items()):
            w(f"| {cve_id} | -- | {info['desc'][:50]} | {info['status']} | "
              f"{info['tests']} tests |")
    else:
        w("| -- | -- | *CVE regression testing evidence not yet available* | -- | -- |")

    w()
    w("*Note: CVE regression results are populated as testing progresses. "
      "Empty entries indicate testing has not yet been performed for those CVEs.*")
    w()
    w("---")
    w()

    # ── Router Health During Assessment ──────────────────────────────────
    w("## Router Health During Assessment")
    w()

    if log_analysis["log_snapshots"]:
        w("| Phase | Uptime | CPU Load | Free Memory | Total Memory |")
        w("|-------|--------|----------|-------------|--------------|")
        for snap in log_analysis["log_snapshots"]:
            free_mb = ""
            total_mb = ""
            try:
                free_val = snap.get("free_memory", 0)
                total_val = snap.get("total_memory", 0)
                if isinstance(free_val, (int, float)) and free_val > 0:
                    free_mb = f"{free_val / (1024*1024):.1f} MB"
                elif isinstance(free_val, str):
                    free_mb = free_val
                if isinstance(total_val, (int, float)) and total_val > 0:
                    total_mb = f"{total_val / (1024*1024):.1f} MB"
                elif isinstance(total_val, str):
                    total_mb = total_val
            except:
                free_mb = str(snap.get("free_memory", ""))
                total_mb = str(snap.get("total_memory", ""))

            w(f"| {snap.get('phase', '--')} | {snap.get('uptime', '--')} | "
              f"{snap.get('cpu_load', '--')}% | {free_mb} | {total_mb} |")
        w()
    else:
        w("*No router health snapshots available in evidence.*")
        w()

    w(f"**Crashes detected during assessment:** {metrics['crashes']}")
    w()

    if metrics["crashes"] > 0:
        w("Router crashes were detected and documented in the relevant phase evidence files. "
          "See the detailed findings section for crash analysis.")
        w()

    w("---")
    w()

    # ── Hardening Recommendations ────────────────────────────────────────
    w("## Hardening Recommendations")
    w()
    w("Based on assessment findings and RouterOS best practices:")
    w()
    w("| # | Recommendation | Rationale |")
    w("|---|---------------|-----------|")
    w("| 1 | Disable unused services (Telnet, FTP, BTest, SNMP if not needed) | "
      "Reduces attack surface |")
    w("| 2 | Enable HTTPS-only for WebFig (`/ip service set www disabled=yes`) | "
      "Prevents credential interception |")
    w("| 3 | Use API-SSL (8729) instead of plaintext API (8728) | "
      "Encrypts API protocol traffic |")
    w("| 4 | Restrict management access by IP (`/ip service set www address=x.x.x.x/32`) | "
      "Limits management plane exposure |")
    w("| 5 | Enable firewall input chain to drop all non-essential traffic | "
      "Defense in depth |")
    w("| 6 | Disable Winbox MAC access (`/tool mac-server set disabled=yes`) | "
      "Prevents Layer 2 management access |")
    w("| 7 | Set strong admin password and create per-operator accounts | "
      "Accountability and credential management |")
    w("| 8 | Enable logging to remote syslog | "
      "Tamper-resistant audit trail |")
    w("| 9 | Keep RouterOS updated to latest stable release | "
      "Patch known vulnerabilities |")
    w("| 10 | Disable MNDP on external interfaces | "
      "Prevents neighbor discovery information leakage |")
    w()
    w("---")
    w()

    # ── Conclusion ───────────────────────────────────────────────────────
    w("## Conclusion")
    w()

    if metrics["total_findings"] == 0:
        w(f"RouterOS CHR {metrics.get('router_version', '7.20.8')} was assessed across "
          f"{metrics['total_tests']:,} test cases spanning "
          f"{len([p for p in metrics['tests_by_phase'] if metrics['tests_by_phase'][p] > 0])} "
          f"phases. No findings were recorded in the current evidence set. "
          f"This may indicate testing is still in progress or that the target "
          f"proved resilient against all tested attack patterns.")
    else:
        critical_high = (severity_counts.get("CRITICAL", 0) +
                         severity_counts.get("HIGH", 0))
        w(f"RouterOS CHR {metrics.get('router_version', '7.20.8')} was assessed across "
          f"{metrics['total_tests']:,} test cases spanning "
          f"{len([p for p in metrics['tests_by_phase'] if metrics['tests_by_phase'][p] > 0])} "
          f"phases with {len(metrics['scripts'])} custom scripts. "
          f"The assessment identified {metrics['total_findings']} findings "
          f"({severity_str}).")
        w()
        if critical_high > 0:
            w(f"**{critical_high} CRITICAL/HIGH findings require immediate attention.** "
              f"See the Detailed Findings section for reproduction steps and "
              f"remediation guidance.")
        else:
            w("No CRITICAL or HIGH findings were identified. The findings are limited to "
              "configuration-level issues and informational observations.")
    w()
    w(f"**{metrics['total_anomalies']} anomalies** were detected across all phases, "
      f"representing unexpected behaviors that were investigated but did not "
      f"constitute confirmed security vulnerabilities.")
    w()
    if metrics["crashes"] > 0:
        w(f"**{metrics['crashes']} router crashes** were detected during testing, "
          f"documented in the relevant phase evidence.")
    else:
        w("**No router crashes** were detected during the assessment, indicating "
          "robust input handling across all tested interfaces.")
    w()
    w("---")
    w()

    # ── Appendix A: Test Case Summary ────────────────────────────────────
    w("## Appendix A: Script Inventory")
    w()

    current_phase = None
    for script in metrics["scripts"]:
        phase = script["phase"]
        if phase != current_phase:
            current_phase = phase
            phase_name = PHASE_NAMES.get(phase, f"Phase {phase}")
            w(f"### {phase_name} (Phase {phase})")
            w()
            w("| Script | Tests | Anomalies | Findings | Evidence File |")
            w("|--------|-------|-----------|----------|---------------|")

        w(f"| `{script['name']}` | {script['tests']} | {script['anomalies']} | "
          f"{script['findings']} | `evidence/{script['evidence_file']}` |")

    w()
    w("---")
    w()

    # ── Appendix B: Router Log Analysis ──────────────────────────────────
    w("## Appendix B: Router Log Analysis")
    w()

    if log_analysis["total_log_entries"] > 0:
        w(f"**Total log entries collected:** {log_analysis['total_log_entries']:,}")
        w(f"**Interesting events (errors, warnings, auth failures):** "
          f"{log_analysis['total_interesting']}")
        w()

        if log_analysis["categories"]:
            w("### Log Categories")
            w()
            w("| Category | Count |")
            w("|----------|-------|")
            for cat, count in sorted(log_analysis["categories"].items(),
                                     key=lambda x: -x[1])[:20]:
                w(f"| {cat} | {count} |")
            w()

        if log_analysis["interesting_events"]:
            w("### Notable Events")
            w()
            w("| Phase | Time | Topics | Message |")
            w("|-------|------|--------|---------|")
            for event in log_analysis["interesting_events"][:30]:
                msg = event.get("message", "")[:80]
                w(f"| {event.get('phase', '--')} | {event.get('time', '--')} | "
                  f"{event.get('topics', '--')} | {msg} |")
            w()
    else:
        w("*No router logs collected. Router log analysis will be available "
          "after running assessment scripts that call `pull_router_logs()`.*")
        w()

    w("---")
    w()

    # ── Appendix C: Evidence Files ───────────────────────────────────────
    w("## Appendix C: Evidence Files")
    w()
    w(f"All evidence stored in `{EVIDENCE_DIR}/`:")
    w()

    if metrics["evidence_files"]:
        w("| File | Phase | Tests | Anomalies | Findings |")
        w("|------|-------|-------|-----------|----------|")
        for script in metrics["scripts"]:
            w(f"| `{script['evidence_file']}` | {script['phase']} | "
              f"{script['tests']} | {script['anomalies']} | {script['findings']} |")
        w()

        # Also list router log files
        router_log_files = [f for f in sorted(EVIDENCE_DIR.glob("router_logs_*.json"))]
        if router_log_files:
            w("### Router Log Files")
            w()
            w("| File | Phase | Log Entries | Interesting |")
            w("|------|-------|-------------|-------------|")
            for rl in router_logs:
                data = rl.get("data", {})
                w(f"| `{rl['file']}` | {data.get('phase', '--')} | "
                  f"{data.get('log_entry_count', 0)} | "
                  f"{data.get('interesting_count', 0)} |")
            w()
    else:
        w("*No evidence files found. Run assessment scripts to generate evidence.*")
        w()

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("=" * 70)
    log("MikroTik RouterOS CHR 7.20.8 — Report Generator")
    log("=" * 70)

    ec_report = EvidenceCollector("generate_report.py", phase=10)

    # Step 1: Load evidence
    log("\nStep 1: Loading evidence files...")
    evidence = load_evidence_files()
    ec_report.add_test("loading", "evidence_files",
                       "Load evidence JSON files",
                       f"Loaded {len(evidence)} files",
                       details={"files": list(evidence.keys())})

    if not evidence:
        log("No evidence files found. Generating skeleton report.")

    # Step 2: Load router logs
    log("\nStep 2: Loading router logs...")
    router_logs = load_router_logs()
    ec_report.add_test("loading", "router_logs",
                       "Load router log files",
                       f"Loaded {len(router_logs)} log files")

    # Step 3: Aggregate metrics
    log("\nStep 3: Aggregating metrics...")
    metrics = aggregate_metrics(evidence)
    log(f"  Total tests:    {metrics['total_tests']:,}")
    log(f"  Total anomalies: {metrics['total_anomalies']}")
    log(f"  Total findings:  {metrics['total_findings']}")
    log(f"  Findings:        {dict(metrics['findings_by_severity'])}")
    log(f"  Scripts:         {len(metrics['scripts'])}")
    log(f"  Crashes:         {metrics['crashes']}")
    log(f"  Date range:      {format_date_range(metrics['date_range'])}")

    ec_report.add_test("aggregation", "metrics",
                       "Aggregate assessment metrics",
                       f"{metrics['total_tests']} tests, {metrics['total_findings']} findings",
                       details={
                           "total_tests": metrics["total_tests"],
                           "total_anomalies": metrics["total_anomalies"],
                           "total_findings": metrics["total_findings"],
                           "findings_by_severity": dict(metrics["findings_by_severity"]),
                           "scripts_count": len(metrics["scripts"]),
                           "crashes": metrics["crashes"],
                       })

    # Step 4: Analyze router logs
    log("\nStep 4: Analyzing router logs...")
    log_analysis = analyze_router_logs(router_logs)
    log(f"  Total log entries:  {log_analysis['total_log_entries']:,}")
    log(f"  Interesting events: {log_analysis['total_interesting']}")
    log(f"  Log categories:     {len(log_analysis['categories'])}")

    ec_report.add_test("analysis", "router_logs",
                       "Analyze router-side logs",
                       f"{log_analysis['total_log_entries']} entries, "
                       f"{log_analysis['total_interesting']} interesting",
                       details={
                           "total_entries": log_analysis["total_log_entries"],
                           "total_interesting": log_analysis["total_interesting"],
                           "categories": dict(log_analysis["categories"]),
                       })

    # Step 5: Generate report
    log("\nStep 5: Generating report...")
    report_text = generate_report(evidence, metrics, router_logs, log_analysis)

    # Write report
    with open(REPORT_PATH, "w") as f:
        f.write(report_text)

    report_size = os.path.getsize(REPORT_PATH)
    line_count = report_text.count("\n")
    log(f"  Report written: {REPORT_PATH}")
    log(f"  Size: {report_size:,} bytes, {line_count} lines")

    ec_report.add_test("generation", "report_file",
                       "Generate markdown report",
                       f"Written to {REPORT_PATH}",
                       details={
                           "path": str(REPORT_PATH),
                           "size_bytes": report_size,
                           "line_count": line_count,
                       })

    # Step 6: Validate report structure
    log("\nStep 6: Validating report structure...")
    required_sections = [
        "Executive Summary",
        "Findings Summary",
        "Scope and Methodology",
        "Detailed Findings",
        "Testing Phases",
        "CVE Regression Results",
        "Router Health During Assessment",
        "Hardening Recommendations",
        "Conclusion",
        "Appendix A",
        "Appendix B",
        "Appendix C",
    ]

    missing_sections = []
    for section in required_sections:
        if section.lower() not in report_text.lower():
            missing_sections.append(section)

    if missing_sections:
        ec_report.add_test("validation", "report_structure",
                           "Validate report has all required sections",
                           f"MISSING: {missing_sections}",
                           anomaly=True)
    else:
        ec_report.add_test("validation", "report_structure",
                           "Validate report has all required sections",
                           f"All {len(required_sections)} sections present")

    # Summary
    ec_report.summary()
    ec_report.save("generate_report.json")

    log(f"\nReport generated: {REPORT_PATH}")
    log(f"  {metrics['total_tests']:,} tests | {metrics['total_findings']} findings | "
        f"{metrics['total_anomalies']} anomalies | {line_count} lines")


if __name__ == "__main__":
    main()
