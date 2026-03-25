#!/usr/bin/env python3
"""
Track A: Ghidra Decompilation of `www` Critical Functions

Uses Ghidra headless analyzer to decompile targeted functions in the www binary
and its linked libraries, then analyzes the decompiled C for vulnerability patterns.

Target functions (by priority):
  P0: 0x0805c906 (sprintf caller, receives read() data)
  P0: 0x08052666 (sprintf caller, listen/startup)
  P1: 0x0805e634 (calls nv::base64Decode)
  P1: 0x0805c13c (27,921B HTTP/JSON giant)
  P2: 0x08050864 (calls Headers::parseHeaderLine)
  P2: 0x08058646 (main)
  P2: 0x08056984 (CC=35, most complex branching)
  P3: 0x0805be28 (calls json::StreamParser::feed)
  P3: 0x08055618 (calls RC4::encrypt)
  P3: 0x0804f92a (handler function)

Also: libjson.so (complete, 103 functions), libwww.so & libuhttp.so key functions.

Evidence: evidence/ghidra_www_decompile.json
"""

import json
import os
import sys
import subprocess
import re
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# ── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
EVIDENCE_DIR = BASE_DIR / "evidence"
GHIDRA_PROJECT = BASE_DIR / "ghidra_project"
GHIDRA_HEADLESS = "/usr/share/ghidra/support/analyzeHeadless"
SCRIPTS_DIR = BASE_DIR / "scripts"
SQUASHFS = BASE_DIR / "source" / "squashfs-root"

# Target binaries
BINARIES = {
    "www": SQUASHFS / "nova" / "bin" / "www",
    "libjson.so": SQUASHFS / "lib" / "libjson.so",
    "libwww.so": SQUASHFS / "lib" / "libwww.so",
    "libuhttp.so": SQUASHFS / "lib" / "libuhttp.so",
}

# www target functions by priority
WWW_TARGET_FUNCTIONS = {
    "P0": [
        ("0x0805c906", "fcn.0805c906", 3218, "sprintf caller, receives read() data"),
        ("0x08052666", "fcn.08052666", 2930, "sprintf caller, listen/startup"),
    ],
    "P1": [
        ("0x0805e634", "fcn.0805e634", 1976, "calls nv::base64Decode"),
        ("0x0805c13c", "fcn.0805c13c", 27921, "largest function - HTTP/JSON giant"),
    ],
    "P2": [
        ("0x08050864", "fcn.08050864", 1284, "calls Headers::parseHeaderLine"),
        ("0x08058646", "main", 2500, "entry point"),
        ("0x08056984", "fcn.08056984", 3081, "CC=35 most complex branching"),
    ],
    "P3": [
        ("0x0805be28", "fcn.0805be28", 500, "calls json::StreamParser::feed"),
        ("0x08055618", "fcn.08055618", 500, "calls RC4::encrypt"),
        ("0x0804f92a", "fcn.0804f92a", 793, "handler function"),
    ],
}

# Vulnerability patterns to search for in decompiled C
VULN_PATTERNS = {
    "sprintf_stack_buffer": {
        "pattern": r'sprintf\s*\(\s*(\w+)\s*,',
        "description": "sprintf with potentially stack-allocated buffer",
        "severity": "HIGH",
        "cwe": "CWE-120",
    },
    "strcpy_unchecked": {
        "pattern": r'strcpy\s*\(',
        "description": "strcpy without bounds checking",
        "severity": "HIGH",
        "cwe": "CWE-120",
    },
    "gets_call": {
        "pattern": r'\bgets\s*\(',
        "description": "gets() - always exploitable",
        "severity": "CRITICAL",
        "cwe": "CWE-120",
    },
    "memcpy_unchecked": {
        "pattern": r'memcpy\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)',
        "description": "memcpy with potentially unchecked length",
        "severity": "MEDIUM",
        "cwe": "CWE-120",
    },
    "sscanf_overflow": {
        "pattern": r'sscanf\s*\(',
        "description": "sscanf - format string + overflow risk",
        "severity": "MEDIUM",
        "cwe": "CWE-134",
    },
    "format_string_user": {
        "pattern": r'(printf|fprintf|sprintf|snprintf)\s*\([^"]*\b(param|arg|buf|input|data|str|msg|request|header|url|path|query|cookie)\w*\s*\)',
        "description": "printf-family with potentially user-controlled format string",
        "severity": "HIGH",
        "cwe": "CWE-134",
    },
    "integer_overflow_size": {
        "pattern": r'(malloc|calloc|realloc|alloca)\s*\(\s*[^)]*[\*\+][^)]*\)',
        "description": "Allocation with arithmetic - integer overflow risk",
        "severity": "MEDIUM",
        "cwe": "CWE-190",
    },
    "stack_buffer_small": {
        "pattern": r'(char|uint8_t|unsigned char)\s+\w+\s*\[\s*(\d+)\s*\]',
        "description": "Stack buffer declaration",
        "severity": "INFO",
        "cwe": "CWE-121",
    },
    "system_call": {
        "pattern": r'\b(system|popen|exec[lv]p?e?)\s*\(',
        "description": "System command execution",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
    },
    "realpath_usage": {
        "pattern": r'realpath\s*\(',
        "description": "Path resolution - traversal/race condition risk",
        "severity": "MEDIUM",
        "cwe": "CWE-22",
    },
}

test_count = 0
anomaly_count = 0
tests = []
findings = []


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def add_test(category, name, description, result, details=None, anomaly=False):
    global test_count, anomaly_count
    test_count += 1
    test = {
        "id": test_count,
        "category": category,
        "name": name,
        "description": description,
        "result": result,
        "anomaly": anomaly,
        "timestamp": datetime.now().isoformat(),
    }
    if details:
        test["details"] = details
    tests.append(test)
    if anomaly:
        anomaly_count += 1
    status = "ANOMALY" if anomaly else "OK"
    log(f"  [{status}] {name}: {result}")


def add_finding(severity, title, description, evidence_refs=None, cwe=None):
    finding = {
        "id": len(findings) + 1,
        "severity": severity,
        "title": title,
        "description": description,
        "timestamp": datetime.now().isoformat(),
    }
    if evidence_refs:
        finding["evidence_refs"] = evidence_refs
    if cwe:
        finding["cwe"] = cwe
    findings.append(finding)
    log(f"  FINDING [{severity}]: {title}")


def run_ghidra_decompile(binary_name, binary_path, addresses, mode="targeted", output_suffix=""):
    """Run Ghidra headless decompilation on a binary.

    Returns parsed JSON output or None on failure.
    """
    output_file = f"/tmp/ghidra_decompile_{binary_name}{output_suffix}.json"

    env = os.environ.copy()
    env["GHIDRA_ADDRESSES"] = ",".join(addresses) if addresses else ""
    env["GHIDRA_OUTPUT"] = output_file
    env["GHIDRA_MODE"] = mode

    # Build Ghidra headless command
    cmd = [
        GHIDRA_HEADLESS,
        str(GHIDRA_PROJECT), "MikroTik_RE",
        "-process", binary_name,
        "-noanalysis",  # Already analyzed during import
        "-postScript", "ghidra_export_functions.py",
        f"ADDRESSES={','.join(addresses) if addresses else ''}",
        f"OUTPUT={output_file}",
        f"MODE={mode}",
        "-scriptPath", str(SCRIPTS_DIR),
    ]

    log(f"  Running Ghidra headless on {binary_name} (mode={mode})...")
    log(f"  Command: {' '.join(cmd[:8])}...")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, env=env
        )

        # Log Ghidra output for debugging
        if result.returncode != 0:
            log(f"  Ghidra returned code {result.returncode}")
            # Log last 30 lines of stderr
            stderr_lines = result.stderr.strip().split('\n')
            for line in stderr_lines[-30:]:
                log(f"  GHIDRA: {line}")

        # Check if output file was created
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                data = json.load(f)
            log(f"  Ghidra produced {len(data.get('decompiled_functions', []))} decompiled functions")
            return data
        else:
            log(f"  No output file produced at {output_file}")
            # Log stdout for clues
            stdout_lines = result.stdout.strip().split('\n')
            for line in stdout_lines[-20:]:
                log(f"  GHIDRA STDOUT: {line}")
            return None

    except subprocess.TimeoutExpired:
        log(f"  Ghidra timed out after 600s")
        return None
    except Exception as e:
        log(f"  Ghidra failed: {e}")
        return None


def analyze_decompiled_c(func_data, binary_name):
    """Analyze decompiled C code for vulnerability patterns."""
    results = {
        "vulnerabilities": [],
        "buffer_analysis": [],
        "control_flow": {},
    }

    c_code = func_data.get("decompiled_c", "")
    if not c_code:
        return results

    func_name = func_data.get("name", "unknown")
    func_addr = func_data.get("address", "unknown")

    # Search for vulnerability patterns
    for vuln_name, vuln_info in VULN_PATTERNS.items():
        matches = list(re.finditer(vuln_info["pattern"], c_code))
        if matches:
            for match in matches:
                # Extract context around the match (5 lines before/after)
                match_pos = match.start()
                lines = c_code[:match_pos].count('\n')
                all_lines = c_code.split('\n')
                start_line = max(0, lines - 5)
                end_line = min(len(all_lines), lines + 6)
                context = '\n'.join(all_lines[start_line:end_line])

                vuln_entry = {
                    "pattern": vuln_name,
                    "severity": vuln_info["severity"],
                    "cwe": vuln_info["cwe"],
                    "function": func_name,
                    "address": func_addr,
                    "binary": binary_name,
                    "match": match.group(0)[:200],
                    "line": lines + 1,
                    "context": context[:500],
                    "description": vuln_info["description"],
                }
                results["vulnerabilities"].append(vuln_entry)

    # Buffer size analysis — find stack buffer declarations and sprintf/strcpy targeting them
    buffer_decls = re.findall(
        r'(char|uint8_t|unsigned\s+char|int8_t)\s+(\w+)\s*\[\s*(\d+)\s*\]',
        c_code
    )

    for buf_type, buf_name, buf_size in buffer_decls:
        buf_size_int = int(buf_size)
        buffer_info = {
            "name": buf_name,
            "type": buf_type,
            "size": buf_size_int,
            "function": func_name,
            "address": func_addr,
            "used_in_sprintf": False,
            "used_in_strcpy": False,
            "used_in_memcpy": False,
        }

        # Check if this buffer is used as destination in dangerous functions
        if re.search(rf'sprintf\s*\(\s*{re.escape(buf_name)}\s*,', c_code):
            buffer_info["used_in_sprintf"] = True
            buffer_info["risk"] = "HIGH" if buf_size_int < 1024 else "MEDIUM"

        if re.search(rf'strcpy\s*\(\s*{re.escape(buf_name)}\s*,', c_code):
            buffer_info["used_in_strcpy"] = True
            buffer_info["risk"] = "HIGH"

        if re.search(rf'memcpy\s*\(\s*{re.escape(buf_name)}\s*,', c_code):
            buffer_info["used_in_memcpy"] = True
            buffer_info["risk"] = "MEDIUM"

        results["buffer_analysis"].append(buffer_info)

    # Control flow complexity
    results["control_flow"] = {
        "if_count": len(re.findall(r'\bif\s*\(', c_code)),
        "while_count": len(re.findall(r'\bwhile\s*\(', c_code)),
        "for_count": len(re.findall(r'\bfor\s*\(', c_code)),
        "switch_count": len(re.findall(r'\bswitch\s*\(', c_code)),
        "return_count": len(re.findall(r'\breturn\b', c_code)),
        "goto_count": len(re.findall(r'\bgoto\b', c_code)),
        "total_lines": c_code.count('\n'),
    }

    return results


def analyze_data_flow_in_c(func_data, all_functions_data):
    """Trace data flow from input parameters to dangerous sinks in decompiled C."""
    c_code = func_data.get("decompiled_c", "")
    if not c_code:
        return {}

    func_name = func_data.get("name", "unknown")
    params = func_data.get("parameters", [])

    flow_results = {
        "function": func_name,
        "tainted_params": [],
        "sink_reachability": [],
    }

    # Mark parameters that flow to dangerous sinks
    for param in params:
        param_name = param.get("name", "")
        if not param_name:
            continue

        # Check if parameter name appears in dangerous function calls
        dangerous_sinks = [
            "sprintf", "strcpy", "strcat", "memcpy", "sscanf",
            "system", "popen", "execve", "execl",
        ]

        for sink in dangerous_sinks:
            # Look for sink(... param_name ...) patterns
            pattern = rf'{sink}\s*\([^)]*\b{re.escape(param_name)}\b[^)]*\)'
            if re.search(pattern, c_code):
                flow_results["tainted_params"].append({
                    "parameter": param_name,
                    "reaches_sink": sink,
                    "risk": "HIGH" if sink in ["sprintf", "strcpy", "system", "execve"] else "MEDIUM",
                })

    return flow_results


# ══════════════════════════════════════════════════════════════════════════════
# Phase A.1: www Binary Decompilation
# ══════════════════════════════════════════════════════════════════════════════

def decompile_www_targets():
    """Decompile targeted www functions via Ghidra."""
    log(f"\n{'='*60}")
    log("TRACK A.1: www Binary — Targeted Function Decompilation")
    log(f"{'='*60}")

    all_addresses = []
    address_info = {}

    for priority, funcs in WWW_TARGET_FUNCTIONS.items():
        for addr, name, size, reason in funcs:
            all_addresses.append(addr)
            address_info[addr] = {
                "priority": priority,
                "name": name,
                "size": size,
                "reason": reason,
            }

    log(f"Targeting {len(all_addresses)} functions across priorities P0-P3")

    # Run Ghidra decompilation
    ghidra_output = run_ghidra_decompile("www", BINARIES["www"], all_addresses, mode="targeted")

    results = {
        "target_info": address_info,
        "decompiled": [],
        "vulnerability_analysis": [],
        "data_flow_analysis": [],
    }

    if not ghidra_output:
        add_test("ghidra_www", "www_decompile", "Ghidra decompilation of www targets",
                "FAILED - Ghidra did not produce output", anomaly=True)
        # Fall back to radare2 decompilation
        log("Falling back to radare2 for decompilation...")
        results["decompiled"] = decompile_via_r2("www", BINARIES["www"], all_addresses)
    else:
        results["decompiled"] = ghidra_output.get("decompiled_functions", [])
        results["dangerous_call_map"] = ghidra_output.get("dangerous_call_map", {})

    # Analyze each decompiled function
    for func_data in results["decompiled"]:
        addr = func_data.get("address", "unknown")
        name = func_data.get("name", "unknown")
        c_code = func_data.get("decompiled_c", "")

        if not c_code:
            add_test("ghidra_www", f"www_decompile_{addr}",
                    f"Decompilation of {name} at {addr}",
                    "No C code produced", anomaly=True)
            continue

        info = address_info.get(addr, {})
        priority = info.get("priority", "?")

        add_test("ghidra_www", f"www_decompile_{addr}",
                f"[{priority}] Decompiled {name} at {addr}",
                f"Success: {len(c_code)} chars, {c_code.count(chr(10))} lines",
                details={
                    "priority": priority,
                    "reason": info.get("reason", ""),
                    "size": func_data.get("size", 0),
                    "params": len(func_data.get("parameters", [])),
                    "locals": len(func_data.get("local_variables", [])),
                    "dangerous_calls": func_data.get("dangerous_calls", []),
                })

        # Vulnerability pattern analysis
        vuln_analysis = analyze_decompiled_c(func_data, "www")
        results["vulnerability_analysis"].append({
            "address": addr,
            "name": name,
            **vuln_analysis,
        })

        # Report findings
        for vuln in vuln_analysis.get("vulnerabilities", []):
            if vuln["severity"] in ("CRITICAL", "HIGH"):
                add_finding(
                    vuln["severity"],
                    f"www: {vuln['pattern']} in {name} at {addr}",
                    f"{vuln['description']}\n\nFunction: {name} ({addr})\n"
                    f"Match: {vuln['match']}\nContext:\n{vuln['context']}",
                    cwe=vuln["cwe"],
                )
            add_test("vuln_analysis", f"www_vuln_{addr}_{vuln['pattern']}",
                    f"Vulnerability pattern: {vuln['pattern']} in {name}",
                    f"[{vuln['severity']}] {vuln['description']}",
                    anomaly=True,
                    details=vuln)

        # Buffer analysis
        for buf in vuln_analysis.get("buffer_analysis", []):
            if buf.get("used_in_sprintf") or buf.get("used_in_strcpy"):
                add_test("buffer_analysis", f"www_buf_{addr}_{buf['name']}",
                        f"Buffer {buf['name']}[{buf['size']}] in {name}",
                        f"sprintf={buf['used_in_sprintf']}, strcpy={buf['used_in_strcpy']}, "
                        f"risk={buf.get('risk', 'UNKNOWN')}",
                        anomaly=True,
                        details=buf)

        # Data flow analysis
        flow = analyze_data_flow_in_c(func_data, results["decompiled"])
        if flow.get("tainted_params"):
            results["data_flow_analysis"].append(flow)
            for tp in flow["tainted_params"]:
                add_test("data_flow", f"www_flow_{addr}_{tp['parameter']}",
                        f"Param '{tp['parameter']}' reaches {tp['reaches_sink']} in {name}",
                        f"TAINTED: parameter flows to dangerous sink",
                        anomaly=True,
                        details=tp)

                if tp["risk"] == "HIGH":
                    add_finding("HIGH",
                              f"www: Parameter '{tp['parameter']}' reaches {tp['reaches_sink']} in {name}",
                              f"Function {name} at {addr}: parameter '{tp['parameter']}' "
                              f"flows directly to {tp['reaches_sink']}. If this parameter "
                              f"carries network input, this is exploitable.",
                              cwe="CWE-120")

    return results


def decompile_via_r2(binary_name, binary_path, addresses):
    """Fallback: use radare2's pdc (pseudocode) for decompilation."""
    log(f"  Radare2 fallback decompilation for {binary_name}...")
    results = []

    for addr in addresses:
        try:
            output = subprocess.run(
                ["r2", "-q", "-e", "bin.cache=true", "-c",
                 f"aaa;s {addr};pdc", str(binary_path)],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "R2_LOG_LEVEL": "0"}
            )
            pseudocode = output.stdout.strip()
            if pseudocode:
                results.append({
                    "address": addr,
                    "name": f"fcn_{addr}",
                    "decompiled_c": pseudocode,
                    "source": "radare2_pdc",
                })
                add_test("r2_fallback", f"r2_decompile_{addr}",
                        f"r2 pseudocode for {addr}",
                        f"Success: {len(pseudocode)} chars")
            else:
                results.append({
                    "address": addr,
                    "name": f"fcn_{addr}",
                    "decompiled_c": None,
                    "error": "empty output",
                })
        except Exception as e:
            results.append({
                "address": addr,
                "error": str(e),
            })

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase A.2: libjson.so Complete Decompilation
# ══════════════════════════════════════════════════════════════════════════════

def decompile_libjson_complete():
    """Decompile all functions in libjson.so (small enough for complete analysis)."""
    log(f"\n{'='*60}")
    log("TRACK A.2: libjson.so — Complete Decompilation (103 functions)")
    log(f"{'='*60}")

    ghidra_output = run_ghidra_decompile(
        "libjson.so", BINARIES["libjson.so"], [], mode="all", output_suffix="_all"
    )

    results = {
        "decompiled": [],
        "vulnerability_analysis": [],
        "parser_analysis": [],
    }

    if not ghidra_output:
        add_test("ghidra_libjson", "libjson_decompile", "Complete libjson.so decompilation",
                "FAILED - Ghidra did not produce output", anomaly=True)
        return results

    results["decompiled"] = ghidra_output.get("decompiled_functions", [])
    add_test("ghidra_libjson", "libjson_decompile_count",
            "libjson.so functions decompiled",
            f"{len(results['decompiled'])} functions decompiled")

    # Analyze each function
    for func_data in results["decompiled"]:
        name = func_data.get("name", "unknown")
        c_code = func_data.get("decompiled_c", "")
        if not c_code:
            continue

        vuln_analysis = analyze_decompiled_c(func_data, "libjson.so")
        if vuln_analysis.get("vulnerabilities"):
            results["vulnerability_analysis"].append({
                "name": name,
                "address": func_data.get("address"),
                **vuln_analysis,
            })

            for vuln in vuln_analysis["vulnerabilities"]:
                add_test("vuln_libjson", f"libjson_vuln_{name[:30]}_{vuln['pattern']}",
                        f"Vulnerability in libjson {name}: {vuln['pattern']}",
                        f"[{vuln['severity']}] {vuln['description']}",
                        anomaly=True, details=vuln)

                if vuln["severity"] in ("CRITICAL", "HIGH"):
                    add_finding(vuln["severity"],
                              f"libjson.so: {vuln['pattern']} in {name}",
                              f"{vuln['description']}\n\n{vuln['context']}",
                              cwe=vuln["cwe"])

        # Special analysis for parser functions (recursion, bounds checking)
        name_lower = name.lower()
        if any(kw in name_lower for kw in ["parse", "feed", "token", "element", "string", "number"]):
            parser_info = {
                "name": name,
                "address": func_data.get("address"),
                "has_recursion": name in c_code.replace(f"/* {name} */", ""),
                "has_bounds_check": bool(re.search(r'if\s*\(.*(>|<|>=|<=).*\blen\b', c_code)),
                "has_null_check": bool(re.search(r'if\s*\(.*==\s*(NULL|0|0x0)\b', c_code)),
                "uses_malloc": "malloc" in c_code,
                "uses_realloc": "realloc" in c_code,
                "control_flow": vuln_analysis.get("control_flow", {}),
            }
            results["parser_analysis"].append(parser_info)

            if parser_info["has_recursion"]:
                add_finding("MEDIUM",
                          f"libjson.so: Recursive function {name}",
                          f"Parser function {name} appears to be recursive. "
                          f"Without depth limits, deeply nested JSON can exhaust stack. "
                          f"No stack canary means clean return address overwrite.",
                          cwe="CWE-674")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase A.3: libwww.so Key Function Decompilation
# ══════════════════════════════════════════════════════════════════════════════

def decompile_libwww_targets():
    """Decompile key HTTP functions in libwww.so."""
    log(f"\n{'='*60}")
    log("TRACK A.3: libwww.so — Key HTTP Function Decompilation")
    log(f"{'='*60}")

    # Use dangerous mode to find all callers of sprintf/strcpy/etc.
    ghidra_output = run_ghidra_decompile(
        "libwww.so", BINARIES["libwww.so"], [], mode="dangerous", output_suffix="_dangerous"
    )

    results = {
        "decompiled": [],
        "vulnerability_analysis": [],
    }

    if not ghidra_output:
        add_test("ghidra_libwww", "libwww_decompile", "libwww.so dangerous function decompilation",
                "FAILED - Ghidra did not produce output", anomaly=True)
        return results

    results["decompiled"] = ghidra_output.get("decompiled_functions", [])
    results["dangerous_call_map"] = ghidra_output.get("dangerous_call_map", {})

    add_test("ghidra_libwww", "libwww_dangerous_count",
            "libwww.so dangerous function callers",
            f"{len(results['decompiled'])} functions decompiled, "
            f"{len(results.get('dangerous_call_map', {}))} dangerous callers mapped")

    for func_data in results["decompiled"]:
        name = func_data.get("name", "unknown")
        c_code = func_data.get("decompiled_c", "")
        if not c_code:
            continue

        vuln_analysis = analyze_decompiled_c(func_data, "libwww.so")
        if vuln_analysis.get("vulnerabilities"):
            results["vulnerability_analysis"].append({
                "name": name,
                "address": func_data.get("address"),
                **vuln_analysis,
            })

            for vuln in vuln_analysis["vulnerabilities"]:
                if vuln["severity"] in ("CRITICAL", "HIGH"):
                    add_finding(vuln["severity"],
                              f"libwww.so: {vuln['pattern']} in {name}",
                              f"{vuln['description']}\n\n{vuln['context']}",
                              cwe=vuln["cwe"])

                add_test("vuln_libwww", f"libwww_vuln_{name[:30]}_{vuln['pattern']}",
                        f"Vulnerability in libwww {name}: {vuln['pattern']}",
                        f"[{vuln['severity']}] {vuln['description']}",
                        anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase A.4: libuhttp.so Key Function Decompilation
# ══════════════════════════════════════════════════════════════════════════════

def decompile_libuhttp_targets():
    """Decompile dangerous functions in libuhttp.so, especially gets() callers."""
    log(f"\n{'='*60}")
    log("TRACK A.4: libuhttp.so — Dangerous Function Decompilation")
    log(f"{'='*60}")

    # Known gets() callers from Phase 1 RE
    known_targets = ["0xd326", "0x7356"]

    # Use dangerous mode to get all callers of dangerous functions
    ghidra_output = run_ghidra_decompile(
        "libuhttp.so", BINARIES["libuhttp.so"], known_targets,
        mode="dangerous", output_suffix="_dangerous"
    )

    results = {
        "decompiled": [],
        "gets_analysis": [],
        "vulnerability_analysis": [],
    }

    if not ghidra_output:
        add_test("ghidra_libuhttp", "libuhttp_decompile", "libuhttp.so decompilation",
                "FAILED - Ghidra did not produce output", anomaly=True)
        return results

    results["decompiled"] = ghidra_output.get("decompiled_functions", [])
    results["dangerous_call_map"] = ghidra_output.get("dangerous_call_map", {})

    add_test("ghidra_libuhttp", "libuhttp_dangerous_count",
            "libuhttp.so dangerous function callers",
            f"{len(results['decompiled'])} functions decompiled")

    # Special focus on gets() callers
    for func_data in results["decompiled"]:
        name = func_data.get("name", "unknown")
        c_code = func_data.get("decompiled_c", "")
        dangerous_calls = func_data.get("dangerous_calls", [])

        if any("gets" in dc.get("function", "").lower() for dc in dangerous_calls):
            results["gets_analysis"].append({
                "function": name,
                "address": func_data.get("address"),
                "c_code_excerpt": c_code[:2000] if c_code else "N/A",
            })

            if c_code:
                add_finding("CRITICAL",
                          f"libuhttp.so: gets() call in {name}",
                          f"Function {name} calls gets() — this is ALWAYS exploitable. "
                          f"No buffer size checking is possible with gets(). "
                          f"With no NX, no canary, no PIE — direct shellcode execution on overflow.\n\n"
                          f"Decompiled excerpt:\n{c_code[:1500]}",
                          cwe="CWE-120")

        # General vulnerability analysis
        if c_code:
            vuln_analysis = analyze_decompiled_c(func_data, "libuhttp.so")
            if vuln_analysis.get("vulnerabilities"):
                results["vulnerability_analysis"].append({
                    "name": name,
                    **vuln_analysis,
                })

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("Track A: Ghidra Decompilation of www Critical Functions")
    log(f"Start: {datetime.now().isoformat()}")

    all_results = {}

    # A.1: www targeted decompilation
    all_results["www"] = decompile_www_targets()

    # A.2: libjson.so complete decompilation
    all_results["libjson"] = decompile_libjson_complete()

    # A.3: libwww.so dangerous function decompilation
    all_results["libwww"] = decompile_libwww_targets()

    # A.4: libuhttp.so dangerous function decompilation
    all_results["libuhttp"] = decompile_libuhttp_targets()

    # ── Cross-library Analysis ──
    log(f"\n{'='*60}")
    log("Cross-Library Vulnerability Correlation")
    log(f"{'='*60}")

    # Identify functions in www that call vulnerable library functions
    www_callees = {}
    for func_data in all_results.get("www", {}).get("decompiled", []):
        for called in func_data.get("called_functions", []):
            callee_name = called.get("name", "")
            if callee_name not in www_callees:
                www_callees[callee_name] = []
            www_callees[callee_name].append(func_data.get("name", "unknown"))

    # Check if any vulnerable library functions are called by www
    lib_vulns = []
    for lib_name in ["libjson", "libwww", "libuhttp"]:
        lib_results = all_results.get(lib_name, {})
        for vuln_func in lib_results.get("vulnerability_analysis", []):
            func_name = vuln_func.get("name", "")
            if func_name in www_callees:
                lib_vulns.append({
                    "library": lib_name,
                    "vulnerable_function": func_name,
                    "called_by_www_functions": www_callees[func_name],
                    "vulnerabilities": [v.get("pattern") for v in vuln_func.get("vulnerabilities", [])],
                })

    if lib_vulns:
        add_test("cross_lib", "cross_lib_vuln_chains",
                "Cross-library vulnerability chains",
                f"{len(lib_vulns)} www→library vulnerability chains identified",
                anomaly=True, details=lib_vulns)

        for chain in lib_vulns:
            add_finding("HIGH",
                      f"Cross-library chain: www → {chain['library']}::{chain['vulnerable_function']}",
                      f"www functions {chain['called_by_www_functions']} call vulnerable "
                      f"library function {chain['vulnerable_function']} in {chain['library']} "
                      f"(vulnerabilities: {chain['vulnerabilities']}). "
                      f"Network input processed by www may reach this vulnerable code path.",
                      cwe="CWE-120")

    all_results["cross_library"] = {"chains": lib_vulns}

    # ── Summary ──
    total_decompiled = sum(
        len(r.get("decompiled", [])) for r in all_results.values() if isinstance(r, dict)
    )
    total_vulns = sum(
        len(r.get("vulnerability_analysis", [])) for r in all_results.values() if isinstance(r, dict)
    )

    # ── Save Evidence ──
    evidence = {
        "metadata": {
            "script": "ghidra_www_decompile.py",
            "track": "A",
            "phase": "Ghidra Decompilation of www Critical Functions",
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_tests": test_count,
            "anomalies": anomaly_count,
            "findings_count": len(findings),
            "total_decompiled": total_decompiled,
        },
        "tests": tests,
        "findings": findings,
        "analysis": {
            "www": {
                "target_functions": WWW_TARGET_FUNCTIONS,
                "decompiled_count": len(all_results.get("www", {}).get("decompiled", [])),
                "vulnerability_analysis": all_results.get("www", {}).get("vulnerability_analysis", []),
                "data_flow": all_results.get("www", {}).get("data_flow_analysis", []),
                # Store first 2000 chars of each decompiled function
                "decompiled_excerpts": [
                    {
                        "address": f.get("address"),
                        "name": f.get("name"),
                        "c_code": f.get("decompiled_c", "")[:2000] if f.get("decompiled_c") else None,
                        "dangerous_calls": f.get("dangerous_calls", []),
                    }
                    for f in all_results.get("www", {}).get("decompiled", [])
                ],
            },
            "libjson": {
                "decompiled_count": len(all_results.get("libjson", {}).get("decompiled", [])),
                "vulnerability_analysis": all_results.get("libjson", {}).get("vulnerability_analysis", []),
                "parser_analysis": all_results.get("libjson", {}).get("parser_analysis", []),
            },
            "libwww": {
                "decompiled_count": len(all_results.get("libwww", {}).get("decompiled", [])),
                "vulnerability_analysis": all_results.get("libwww", {}).get("vulnerability_analysis", []),
                "dangerous_call_map": all_results.get("libwww", {}).get("dangerous_call_map", {}),
            },
            "libuhttp": {
                "decompiled_count": len(all_results.get("libuhttp", {}).get("decompiled", [])),
                "gets_analysis": all_results.get("libuhttp", {}).get("gets_analysis", []),
                "vulnerability_analysis": all_results.get("libuhttp", {}).get("vulnerability_analysis", []),
            },
            "cross_library": all_results.get("cross_library", {}),
        },
    }

    out_file = EVIDENCE_DIR / "ghidra_www_decompile.json"
    with open(out_file, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    log(f"\n{'='*70}")
    log("TRACK A COMPLETE: Ghidra Decompilation Analysis")
    log(f"{'='*70}")
    log(f"Total tests: {test_count}")
    log(f"Anomalies: {anomaly_count}")
    log(f"Findings: {len(findings)}")
    log(f"Functions decompiled: {total_decompiled}")
    log(f"Evidence: {out_file}")

    for f in findings:
        log(f"  [{f['severity']}] {f['title']}")

    log(f"\nEnd: {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
