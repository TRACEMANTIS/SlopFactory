#!/usr/bin/env python3
"""
Security AssessmentI — Tenda SOHO Router Security Assessment
Phase 0: Binary Inventory — httpd_ac15 & httpd_ac20

Collects:
  - file type, checksec mitigations
  - goform endpoint handler names
  - dangerous/safe function string counts
  - input source references
  - linked shared libraries (readelf -d)

Saves evidence to phase0_inventory.json
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/scripts')
from tenda_common import (
    EvidenceCollector, FirmwareHelper, BINARIES_DIR, EVIDENCE_DIR
)

# ── Configuration ──────────────────────────────────────────────────────
BINARIES = {
    "httpd_ac15": str(BINARIES_DIR / "httpd_ac15"),
    "httpd_ac20": str(BINARIES_DIR / "httpd_ac20"),
}

# Patterns for endpoint handler names extracted via strings
HANDLER_PREFIXES = (
    r'^form[A-Z]\w+',
    r'^Set[A-Z]\w+',
    r'^Get[A-Z]\w+',
    r'^save[A-Z]\w+',
    r'^del[A-Z]\w+',
    r'^add[A-Z]\w+',
    r'^Wifi[A-Z]\w+',
    r'^Wan[A-Z]\w+',
    r'^Dhcp[A-Z]\w+',
    r'^Firewall[A-Z]\w+',
    r'^Sys[A-Z]\w+',
    r'^Login[A-Z]\w*',
    r'^Nat[A-Z]\w+',
    r'^Route[A-Z]\w+',
    r'^Vpn[A-Z]\w+',
    r'^Dns[A-Z]\w+',
    r'^Mac[A-Z]\w+',
    r'^Ip[A-Z]\w+',
    r'^Qos[A-Z]\w+',
    r'^Ddns[A-Z]\w+',
    r'^Upnp[A-Z]\w+',
    r'^Pptpd[A-Z]\w*',
    r'^Iptv[A-Z]\w*',
    r'^Up[REDACTED][A-Z]\w*',
    r'^Reboot[A-Z]\w*',
    r'^Reset[A-Z]\w*',
    r'^PPPoE[A-Z]\w*',
    r'^Fast[A-Z]\w+',
    r'^Wps[A-Z]\w+',
    r'^Guest[A-Z]\w+',
    r'^Parent[A-Z]\w+',
    r'^Power[A-Z]\w+',
    r'^Time[A-Z]\w+',
    r'^Log[A-Z]\w+',
    r'^Sched[A-Z]\w+',
    r'^Dmz[A-Z]\w+',
    r'^Portforward[A-Z]\w*',
    r'^Lan[A-Z]\w+',
    r'^Wireless[A-Z]\w+',
    r'^Wlan[A-Z]\w+',
    r'^Net[A-Z]\w+',
    r'^Admin[A-Z]\w+',
    r'^Upload[A-Z]\w*',
    r'^Download[A-Z]\w*',
    r'^Ping[A-Z]\w*',
    r'^Traceroute[A-Z]\w*',
    r'^Diag[A-Z]\w*',
    r'^Snmp[A-Z]\w*',
    r'^Remote[A-Z]\w+',
    r'^Usb[A-Z]\w+',
    r'^Samba[A-Z]\w*',
    r'^Ftp[A-Z]\w+',
    r'^Vlan[A-Z]\w+',
    r'^Arp[A-Z]\w+',
    r'^Black[A-Z]\w+',
    r'^White[A-Z]\w+',
    r'^Filter[A-Z]\w+',
    r'^Url[A-Z]\w+',
    r'^Access[A-Z]\w+',
    r'^Cloud[A-Z]\w+',
    r'^Online[A-Z]\w+',
    r'^Client[A-Z]\w+',
    r'^Device[A-Z]\w+',
    r'^Speed[A-Z]\w+',
    r'^Led[A-Z]\w+',
    r'^Cfg[A-Z]\w+',
)

# Dangerous functions (buffer overflow / command injection sinks)
DANGEROUS_FUNCS = [
    'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets',
    'system', 'popen', 'doSystemCmd', 'execve', 'twsystem',
]

# Safe alternatives
SAFE_FUNCS = [
    'strncpy', 'strncat', 'snprintf', 'vsnprintf', 'fgets',
]

# Input sources
INPUT_SOURCES = [
    'websGetVar', 'getenv',
]

# Combined regex per category  (whole-word match)
COMBINED_HANDLER_RE = re.compile('|'.join(HANDLER_PREFIXES))


# ── Helpers ────────────────────────────────────────────────────────────
def run_cmd(cmd, timeout=30):
    """Run a shell command, return stdout+stderr."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR] {e}"


def parse_checksec(raw):
    """Parse checksec human-readable output into a dict."""
    result = {}
    # Remove ANSI escape codes
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    lines = clean.strip().splitlines()
    if len(lines) >= 2:
        headers = lines[0].split()
        values_line = lines[1]
        # checksec aligns values under headers; parse heuristically
        # Match key patterns
        for pattern, key in [
            (r'(No RELRO|Partial RELRO|Full RELRO)', 'RELRO'),
            (r'(No canary found|Canary found)', 'Stack Canary'),
            (r'(NX enabled|NX disabled)', 'NX'),
            (r'(No PIE|PIE enabled)', 'PIE'),
            (r'(No RPATH|RPATH)', 'RPATH'),
            (r'(No RUNPATH|RUNPATH)', 'RUNPATH'),
            (r'(No Symbols|.*Symbols)', 'Symbols'),
            (r'FORTIFY', 'FORTIFY'),
        ]:
            m = re.search(pattern, values_line)
            if m:
                result[key] = m.group(1).strip()
    # Also get Fortified / Fortifiable counts
    m_fort = re.search(r'(\d+)\s+(\d+)\s+\S*$', clean.splitlines()[-1] if clean.splitlines() else '')
    if m_fort:
        result['Fortified'] = int(m_fort.group(1))
        result['Fortifiable'] = int(m_fort.group(2))
    return result


def get_all_strings(binary_path):
    """Extract all printable strings from binary."""
    r = subprocess.run(['strings', binary_path], capture_output=True, text=True, timeout=60)
    return r.stdout.splitlines()


def count_function_refs(all_strings, func_list):
    """Count exact whole-word matches for each function name."""
    counts = {}
    for func in func_list:
        pat = re.compile(r'\b' + re.escape(func) + r'\b')
        matches = [s for s in all_strings if pat.search(s)]
        counts[func] = len(matches)
    return counts


def extract_handler_names(all_strings):
    """Extract endpoint handler names matching Tenda patterns."""
    handlers = set()
    for s in all_strings:
        s_stripped = s.strip()
        if COMBINED_HANDLER_RE.match(s_stripped):
            # Filter out overly long or binary-garbage strings
            if len(s_stripped) < 80 and s_stripped.isascii():
                handlers.add(s_stripped)
    return sorted(handlers)


def extract_goform_endpoints(all_strings):
    """Extract goform/ endpoint names."""
    endpoints = set()
    for line in all_strings:
        for m in re.finditer(r'(?:/goform/|goform/)(\w+)', line):
            endpoints.add(m.group(1))
    return sorted(endpoints)


def get_linked_libs(binary_path):
    """Parse readelf -d output for NEEDED shared libraries."""
    raw = run_cmd(['readelf', '-d', binary_path], timeout=15)
    libs = []
    for line in raw.splitlines():
        m = re.search(r'Shared library:\s*\[([^\]]+)\]', line)
        if m:
            libs.append(m.group(1))
    return libs


# ── Main Inventory ─────────────────────────────────────────────────────
def inventory_binary(name, path):
    """Run full inventory on a single binary. Returns a dict."""
    print(f"\n{'='*70}")
    print(f"  Inventorying: {name}  ({path})")
    print(f"{'='*70}")

    info = {}

    # 1. file command
    file_out = FirmwareHelper.file_info(path)
    info['file'] = file_out
    print(f"  [file]      {file_out}")

    # 2. checksec
    checksec_raw = FirmwareHelper.checksec(path)
    info['checksec_raw'] = re.sub(r'\x1b\[[0-9;]*m', '', checksec_raw)
    info['checksec'] = parse_checksec(checksec_raw)
    print(f"  [checksec]  {info['checksec']}")

    # 3. Extract all strings once
    all_strings = get_all_strings(path)
    info['total_strings'] = len(all_strings)
    print(f"  [strings]   Total extractable strings: {len(all_strings)}")

    # 4. Goform endpoints
    goform_eps = extract_goform_endpoints(all_strings)
    info['goform_endpoints'] = goform_eps
    info['goform_count'] = len(goform_eps)
    print(f"  [goform]    Endpoints found: {len(goform_eps)}")

    # 5. Handler names (broader pattern match)
    handlers = extract_handler_names(all_strings)
    info['handler_names'] = handlers
    info['handler_count'] = len(handlers)
    print(f"  [handlers]  Handler names found: {len(handlers)}")

    # 6. Dangerous function references
    dangerous = count_function_refs(all_strings, DANGEROUS_FUNCS)
    info['dangerous_functions'] = dangerous
    info['dangerous_total'] = sum(dangerous.values())
    print(f"  [dangerous] Total dangerous refs: {info['dangerous_total']}")
    for func, cnt in sorted(dangerous.items(), key=lambda x: -x[1]):
        if cnt > 0:
            print(f"              {func:20s} = {cnt}")

    # 7. Safe function references
    safe = count_function_refs(all_strings, SAFE_FUNCS)
    info['safe_functions'] = safe
    info['safe_total'] = sum(safe.values())
    print(f"  [safe]      Total safe refs: {info['safe_total']}")
    for func, cnt in sorted(safe.items(), key=lambda x: -x[1]):
        if cnt > 0:
            print(f"              {func:20s} = {cnt}")

    # 8. Input sources
    inputs = count_function_refs(all_strings, INPUT_SOURCES)
    info['input_sources'] = inputs
    info['input_total'] = sum(inputs.values())
    print(f"  [inputs]    Total input source refs: {info['input_total']}")
    for func, cnt in sorted(inputs.items(), key=lambda x: -x[1]):
        if cnt > 0:
            print(f"              {func:20s} = {cnt}")

    # 9. Linked libraries (readelf -d)
    libs = get_linked_libs(path)
    info['linked_libraries'] = libs
    print(f"  [libs]      Linked libraries ({len(libs)}):")
    for lib in libs:
        print(f"              - {lib}")

    # 10. Risk ratio
    if info['safe_total'] > 0:
        info['unsafe_safe_ratio'] = round(info['dangerous_total'] / info['safe_total'], 2)
    else:
        info['unsafe_safe_ratio'] = float('inf')
    print(f"  [ratio]     Unsafe/Safe ratio: {info['unsafe_safe_ratio']}")

    return info


def print_summary(results):
    """Print a formatted comparative summary."""
    print(f"\n{'='*70}")
    print(f"  COMPARATIVE SUMMARY")
    print(f"{'='*70}")

    header = f"{'Metric':<35} {'httpd_ac15':>15} {'httpd_ac20':>15}"
    print(header)
    print("-" * len(header))

    ac15 = results.get('httpd_ac15', {})
    ac20 = results.get('httpd_ac20', {})

    rows = [
        ("Total strings",       ac15.get('total_strings', 0),   ac20.get('total_strings', 0)),
        ("Goform endpoints",    ac15.get('goform_count', 0),    ac20.get('goform_count', 0)),
        ("Handler names",       ac15.get('handler_count', 0),   ac20.get('handler_count', 0)),
        ("Dangerous func refs", ac15.get('dangerous_total', 0), ac20.get('dangerous_total', 0)),
        ("Safe func refs",      ac15.get('safe_total', 0),      ac20.get('safe_total', 0)),
        ("Input source refs",   ac15.get('input_total', 0),     ac20.get('input_total', 0)),
        ("Unsafe/Safe ratio",   ac15.get('unsafe_safe_ratio', 0), ac20.get('unsafe_safe_ratio', 0)),
        ("Linked libraries",    len(ac15.get('linked_libraries', [])), len(ac20.get('linked_libraries', []))),
    ]
    for label, v1, v2 in rows:
        print(f"  {label:<33} {str(v1):>15} {str(v2):>15}")

    # Mitigations
    print(f"\n{'Mitigation':<35} {'httpd_ac15':>15} {'httpd_ac20':>15}")
    print("-" * 65)
    for key in ['RELRO', 'Stack Canary', 'NX', 'PIE']:
        v1 = ac15.get('checksec', {}).get(key, 'N/A')
        v2 = ac20.get('checksec', {}).get(key, 'N/A')
        print(f"  {key:<33} {v1:>15} {v2:>15}")

    # Goform endpoint overlap
    eps15 = set(ac15.get('goform_endpoints', []))
    eps20 = set(ac20.get('goform_endpoints', []))
    shared = eps15 & eps20
    only15 = eps15 - eps20
    only20 = eps20 - eps15
    print(f"\n  Goform endpoint overlap:")
    print(f"    Shared:       {len(shared)}")
    print(f"    AC15-only:    {len(only15)}")
    print(f"    AC20-only:    {len(only20)}")

    # Handler overlap
    h15 = set(ac15.get('handler_names', []))
    h20 = set(ac20.get('handler_names', []))
    h_shared = h15 & h20
    h_only15 = h15 - h20
    h_only20 = h20 - h15
    print(f"\n  Handler name overlap:")
    print(f"    Shared:       {len(h_shared)}")
    print(f"    AC15-only:    {len(h_only15)}")
    print(f"    AC20-only:    {len(h_only20)}")

    # Print all handler names per binary
    print(f"\n  All handler names (AC15): {len(h15)}")
    for h in sorted(h15):
        marker = " [UNIQUE]" if h in h_only15 else ""
        print(f"    - {h}{marker}")

    print(f"\n  All handler names (AC20): {len(h20)}")
    for h in sorted(h20):
        marker = " [UNIQUE]" if h in h_only20 else ""
        print(f"    - {h}{marker}")

    # Print goform endpoints per binary
    print(f"\n  All goform endpoints (AC15): {len(eps15)}")
    for ep in sorted(eps15):
        marker = " [UNIQUE]" if ep in only15 else ""
        print(f"    - /goform/{ep}{marker}")

    print(f"\n  All goform endpoints (AC20): {len(eps20)}")
    for ep in sorted(eps20):
        marker = " [UNIQUE]" if ep in only20 else ""
        print(f"    - /goform/{ep}{marker}")


def main():
    print("[*] Phase 0: Tenda httpd Binary Inventory")
    print(f"[*] Binaries directory: {BINARIES_DIR}")

    ec = EvidenceCollector("phase0_inventory")
    results = {}

    for name, path in BINARIES.items():
        if not os.path.exists(path):
            print(f"[!] Binary not found: {path}")
            ec.add_anomaly(f"missing_{name}", f"Binary not found: {path}")
            continue

        info = inventory_binary(name, path)
        results[name] = info

        # Record test results in evidence collector
        ec.add_test(
            f"{name}_file_info",
            f"File type identification for {name}",
            f"file {path}",
            info['file'],
            "INFO"
        )

        ec.add_test(
            f"{name}_checksec",
            f"Security mitigation check for {name}",
            f"checksec --file={path}",
            json.dumps(info['checksec']),
            "VULN" if info['checksec'].get('Stack Canary') == 'No canary found' else "PASS"
        )

        ec.add_test(
            f"{name}_dangerous_funcs",
            f"Dangerous function string references in {name}",
            "strings + regex match",
            json.dumps(info['dangerous_functions']),
            "VULN" if info['dangerous_total'] > 10 else "INFO"
        )

        ec.add_test(
            f"{name}_safe_funcs",
            f"Safe function string references in {name}",
            "strings + regex match",
            json.dumps(info['safe_functions']),
            "INFO"
        )

        ec.add_test(
            f"{name}_input_sources",
            f"Input source references in {name}",
            "strings + regex match",
            json.dumps(info['input_sources']),
            "INFO"
        )

        ec.add_test(
            f"{name}_goform_endpoints",
            f"Goform endpoints in {name} ({info['goform_count']} found)",
            "strings + goform pattern",
            json.dumps(info['goform_endpoints']),
            "INFO"
        )

        ec.add_test(
            f"{name}_handler_names",
            f"Handler names in {name} ({info['handler_count']} found)",
            "strings + handler prefix patterns",
            json.dumps(info['handler_names']),
            "INFO"
        )

        ec.add_test(
            f"{name}_linked_libs",
            f"Linked shared libraries for {name}",
            f"readelf -d {path}",
            json.dumps(info['linked_libraries']),
            "INFO"
        )

        # Record findings for missing mitigations
        cs = info.get('checksec', {})
        if cs.get('RELRO') == 'No RELRO':
            ec.add_finding(
                f"{name}_no_relro", "MEDIUM",
                f"{name}: No RELRO",
                "Binary compiled without RELRO. GOT entries are writable, enabling GOT overwrite attacks.",
                cwe="CWE-693"
            )
        if cs.get('Stack Canary') == 'No canary found':
            ec.add_finding(
                f"{name}_no_canary", "HIGH",
                f"{name}: No stack canary",
                "Binary compiled without stack canaries. Stack buffer overflows can directly overwrite return addresses.",
                cwe="CWE-693"
            )
        if cs.get('PIE') == 'No PIE':
            ec.add_finding(
                f"{name}_no_pie", "MEDIUM",
                f"{name}: No PIE",
                "Binary is not position-independent. Base address is predictable, simplifying exploitation.",
                cwe="CWE-693"
            )
        if info['unsafe_safe_ratio'] > 3:
            ec.add_finding(
                f"{name}_unsafe_ratio", "MEDIUM",
                f"{name}: High unsafe/safe function ratio ({info['unsafe_safe_ratio']})",
                f"Dangerous functions outnumber safe alternatives {info['unsafe_safe_ratio']}:1. "
                f"Dangerous={info['dangerous_total']}, Safe={info['safe_total']}.",
                cwe="CWE-120"
            )

    # Print comparative summary
    if len(results) == 2:
        print_summary(results)

    # Save evidence JSON
    evidence_data = {
        "inventory": results,
        "binary_count": len(results),
    }
    ec.add_test(
        "inventory_complete",
        "Full binary inventory completed",
        f"Inventoried {len(results)} binaries",
        json.dumps(evidence_data, default=str),
        "INFO"
    )

    # Save to fixed filename
    ec.save("phase0_inventory.json")

    print(f"\n[*] Phase 0 inventory complete.")


if __name__ == "__main__":
    main()
