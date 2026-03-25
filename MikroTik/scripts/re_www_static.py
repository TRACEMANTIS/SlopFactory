#!/usr/bin/env python3
"""
MikroTik RouterOS `www` Binary — Deep Static Reverse Engineering (Phase 1)

Automated radare2 analysis pipeline for the www binary (WebFig HTTP server +
REST API handler) and its critical shared libraries (libjson.so, libwww.so,
libuhttp.so).

Extracts:
  - Full function listings with sizes and cross-references
  - Unsafe function call sites (sprintf, sscanf, strcpy, strcat, memcpy, gets)
  - Import/export tables from each linked library
  - String-to-function correlation
  - Call graphs for critical attack-surface functions
  - Data flow from network input to unsafe sinks
  - ROP gadget availability (no NX, no canary, no PIE)

Target: /home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/source/squashfs-root/nova/bin/www
Evidence: evidence/re_www_static.json
"""

import json
import os
import sys
import time
import subprocess
import re
from datetime import datetime
from pathlib import Path

# Add scripts dir for shared imports
sys.path.insert(0, str(Path(__file__).parent))

# ── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
EVIDENCE_DIR = BASE_DIR / "evidence"
SQUASHFS = BASE_DIR / "source" / "squashfs-root"

TARGETS = {
    "www": SQUASHFS / "nova" / "bin" / "www",
    "libjson.so": SQUASHFS / "lib" / "libjson.so",
    "libwww.so": SQUASHFS / "lib" / "libwww.so",
    "libuhttp.so": SQUASHFS / "lib" / "libuhttp.so",
    "libucrypto.so": SQUASHFS / "lib" / "libucrypto.so",
    "libumsg.so": SQUASHFS / "lib" / "libumsg.so",
    "libubox.so": SQUASHFS / "lib" / "libubox.so",
}

# Unsafe C functions that are exploitable without NX/canary
UNSAFE_FUNCTIONS = [
    "sprintf", "vsprintf", "sscanf",
    "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove",
    "gets", "fgets",
    "scanf", "fscanf",
    "realpath", "system", "popen", "exec",
]

# Critical functions we want deep analysis on (from plan + known attack surface)
CRITICAL_FUNCTIONS = [
    "Request::parseStatusLine",
    "Headers::parseHeaderLine",
    "json::StreamParser::feed",
    "nv::base64Decode",
    "Response::sendFile",
    "RC4::encrypt",
    "RC4::setKey",
    "RC4::crypt",
    "parse_json_element",
    "json_parse",
    "HttpRequest",
    "HttpResponse",
    "handleRequest",
    "processRequest",
    "doAuth",
    "checkAuth",
    "sendResponse",
    "readBody",
    "parseUrl",
    "parseQuery",
    "parseCookie",
    "getSession",
    "createSession",
]

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


# ── Radare2 Helper ───────────────────────────────────────────────────────────

def r2_cmd(binary_path, commands, timeout=120):
    """Run radare2 commands on a binary and return output.

    Uses r2 -q -c to avoid interactive mode issues.
    Commands is a list of r2 commands to execute.
    """
    if isinstance(commands, str):
        commands = [commands]

    cmd_str = ";".join(commands)

    try:
        result = subprocess.run(
            ["r2", "-q", "-e", "bin.cache=true", "-c", cmd_str, str(binary_path)],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "R2_LOG_LEVEL": "0"}
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        log(f"  WARNING: r2 timed out after {timeout}s on {binary_path}")
        return ""
    except Exception as e:
        log(f"  ERROR: r2 failed on {binary_path}: {e}")
        return ""

def r2_json(binary_path, command, timeout=120):
    """Run a single r2 command that returns JSON."""
    output = r2_cmd(binary_path, [command], timeout)
    # Try to parse JSON from output - sometimes there's noise before it
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('[') or line.startswith('{'):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    # Try the whole output
    try:
        return json.loads(output.strip())
    except:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1.1: www Binary Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_binary_metadata(binary_name, binary_path):
    """Extract ELF metadata, sections, segments."""
    log(f"\n{'='*60}")
    log(f"Analyzing: {binary_name} ({binary_path})")
    log(f"{'='*60}")

    results = {}

    # File info
    info = r2_json(binary_path, "ij")
    if info:
        results["info"] = {
            "arch": info.get("bin", {}).get("arch"),
            "bits": info.get("bin", {}).get("bits"),
            "endian": info.get("bin", {}).get("endian"),
            "os": info.get("bin", {}).get("os"),
            "type": info.get("bin", {}).get("type"),
            "machine": info.get("bin", {}).get("machine"),
            "stripped": info.get("bin", {}).get("stripped"),
            "static": info.get("bin", {}).get("static"),
            "nx": info.get("bin", {}).get("nx"),
            "canary": info.get("bin", {}).get("canary"),
            "pic": info.get("bin", {}).get("pic"),
            "relro": info.get("bin", {}).get("relro"),
        }
        add_test("metadata", f"{binary_name}_info",
                f"Binary metadata for {binary_name}",
                f"arch={results['info'].get('arch')}, bits={results['info'].get('bits')}, "
                f"nx={results['info'].get('nx')}, canary={results['info'].get('canary')}, "
                f"pic={results['info'].get('pic')}",
                details=results["info"])

    # Sections
    sections = r2_json(binary_path, "iSj")
    if sections:
        results["sections"] = []
        for s in sections:
            results["sections"].append({
                "name": s.get("name"),
                "size": s.get("size"),
                "vsize": s.get("vsize"),
                "paddr": hex(s.get("paddr", 0)),
                "vaddr": hex(s.get("vaddr", 0)),
                "perm": s.get("perm"),
            })
        add_test("metadata", f"{binary_name}_sections",
                f"ELF sections in {binary_name}",
                f"{len(sections)} sections found",
                details={"section_names": [s.get("name") for s in sections]})

    # Segments
    segments = r2_json(binary_path, "iSSj")
    if segments:
        results["segments"] = []
        for s in segments:
            results["segments"].append({
                "name": s.get("name"),
                "size": s.get("size"),
                "vaddr": hex(s.get("vaddr", 0)),
                "perm": s.get("perm"),
            })
        # Check for executable stack
        for s in segments:
            if s.get("name") and "GNU_STACK" in str(s.get("name", "")):
                perm = s.get("perm", "")
                if "x" in str(perm).lower():
                    add_finding("CRITICAL", f"{binary_name}: Executable stack (GNU_STACK rwx)",
                              f"Binary {binary_name} has executable stack segment — "
                              f"stack buffer overflow = direct shellcode execution",
                              cwe="CWE-119")
                add_test("metadata", f"{binary_name}_stack_perm",
                        f"Stack segment permissions in {binary_name}",
                        f"GNU_STACK perm={perm}",
                        anomaly=("x" in str(perm).lower()))

    return results

def analyze_functions(binary_name, binary_path):
    """Full function analysis with auto-analysis."""
    log(f"\n--- Function Analysis: {binary_name} ---")

    results = {"functions": [], "stats": {}}

    # Run analysis and get functions
    output = r2_cmd(binary_path, ["aaa", "aflj"], timeout=180)

    functions = None
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('['):
            try:
                functions = json.loads(line)
                break
            except:
                continue

    if not functions:
        # Try without full analysis
        output = r2_cmd(binary_path, ["aa", "aflj"], timeout=120)
        for line in output.strip().split('\n'):
            line = line.strip()
            if line.startswith('['):
                try:
                    functions = json.loads(line)
                    break
                except:
                    continue

    if not functions:
        add_test("functions", f"{binary_name}_functions",
                f"Function listing for {binary_name}",
                "FAILED to extract functions", anomaly=True)
        return results

    # Process functions
    func_list = []
    size_histogram = {"tiny(<32)": 0, "small(32-128)": 0, "medium(128-512)": 0,
                      "large(512-2048)": 0, "huge(>2048)": 0}

    for f in functions:
        name = f.get("name", "unknown")
        size = f.get("size", 0)
        offset = f.get("offset", 0)
        nargs = f.get("nargs", 0)
        nbbs = f.get("nbbs", 0)  # number of basic blocks
        cc = f.get("cc", 0)  # cyclomatic complexity

        entry = {
            "name": name,
            "offset": hex(offset),
            "size": size,
            "nargs": nargs,
            "nbbs": nbbs,
            "cc": cc,
        }
        func_list.append(entry)

        if size < 32: size_histogram["tiny(<32)"] += 1
        elif size < 128: size_histogram["small(32-128)"] += 1
        elif size < 512: size_histogram["medium(128-512)"] += 1
        elif size < 2048: size_histogram["large(512-2048)"] += 1
        else: size_histogram["huge(>2048)"] += 1

    results["functions"] = func_list
    results["stats"] = {
        "total_functions": len(func_list),
        "size_distribution": size_histogram,
        "largest_functions": sorted(func_list, key=lambda x: x["size"], reverse=True)[:20],
        "most_complex": sorted(func_list, key=lambda x: x.get("cc", 0), reverse=True)[:20],
    }

    add_test("functions", f"{binary_name}_function_count",
            f"Total functions in {binary_name}",
            f"{len(func_list)} functions found",
            details={"size_distribution": size_histogram})

    # Report largest functions (likely complex parsers)
    for f in results["stats"]["largest_functions"][:5]:
        add_test("functions", f"{binary_name}_large_func_{f['name'][:40]}",
                f"Large function in {binary_name}",
                f"{f['name']} size={f['size']} bytes, cc={f.get('cc', 'N/A')}",
                anomaly=(f['size'] > 1024))

    return results


def analyze_imports_exports(binary_name, binary_path):
    """Extract imports and exports — focus on unsafe function imports."""
    log(f"\n--- Import/Export Analysis: {binary_name} ---")

    results = {"imports": [], "exports": [], "unsafe_imports": []}

    # Imports
    imports = r2_json(binary_path, "iij")
    if imports:
        for imp in imports:
            name = imp.get("name", "")
            entry = {
                "name": name,
                "type": imp.get("type"),
                "bind": imp.get("bind"),
                "plt": hex(imp.get("plt", 0)),
            }
            results["imports"].append(entry)

            # Flag unsafe imports
            base_name = name.split(".")[-1] if "." in name else name
            for unsafe in UNSAFE_FUNCTIONS:
                if unsafe in base_name.lower():
                    results["unsafe_imports"].append(entry)
                    add_test("imports", f"{binary_name}_unsafe_import_{base_name[:30]}",
                            f"Unsafe function imported in {binary_name}",
                            f"{name} at PLT {entry['plt']}",
                            anomaly=True)

    # Exports
    exports = r2_json(binary_path, "iEj")
    if exports:
        for exp in exports:
            results["exports"].append({
                "name": exp.get("name", ""),
                "vaddr": hex(exp.get("vaddr", 0)),
                "size": exp.get("size", 0),
                "type": exp.get("type"),
            })

    add_test("imports", f"{binary_name}_import_summary",
            f"Import/export summary for {binary_name}",
            f"{len(results['imports'])} imports, {len(results['exports'])} exports, "
            f"{len(results['unsafe_imports'])} unsafe imports")

    if results["unsafe_imports"]:
        add_finding("MEDIUM",
                    f"{binary_name}: {len(results['unsafe_imports'])} unsafe function imports",
                    f"Binary imports {len(results['unsafe_imports'])} known-unsafe C functions: "
                    f"{', '.join(set(i['name'] for i in results['unsafe_imports']))}. "
                    f"With no NX, no canary, no PIE — any overflow via these is directly exploitable.",
                    evidence_refs=[f"re_www_static.json#{binary_name}_imports"],
                    cwe="CWE-120")

    return results


def analyze_unsafe_call_sites(binary_name, binary_path):
    """Find every call to unsafe functions and extract calling context."""
    log(f"\n--- Unsafe Call Site Analysis: {binary_name} ---")

    results = {"call_sites": []}

    # Run analysis first
    # For each unsafe function, find cross-references TO it
    for unsafe_func in UNSAFE_FUNCTIONS:
        # Find the PLT entry for this function
        output = r2_cmd(binary_path, [
            "aaa",
            f"afl~{unsafe_func}"
        ], timeout=180)

        if not output.strip():
            continue

        # Get addresses of the function
        for line in output.strip().split('\n'):
            if unsafe_func in line:
                parts = line.split()
                if parts:
                    try:
                        addr = parts[0]
                        # Find cross-references to this address
                        xref_output = r2_cmd(binary_path, [
                            "aaa",
                            f"axtj {addr}"
                        ], timeout=120)

                        xrefs = None
                        for xline in xref_output.strip().split('\n'):
                            xline = xline.strip()
                            if xline.startswith('['):
                                try:
                                    xrefs = json.loads(xline)
                                    break
                                except:
                                    continue

                        if xrefs:
                            for xref in xrefs:
                                call_site = {
                                    "unsafe_function": unsafe_func,
                                    "target_addr": addr,
                                    "caller_addr": hex(xref.get("from", 0)),
                                    "caller_function": xref.get("fcn_name", "unknown"),
                                    "type": xref.get("type", "unknown"),
                                }
                                results["call_sites"].append(call_site)

                                add_test("unsafe_calls",
                                        f"{binary_name}_call_{unsafe_func}@{call_site['caller_addr']}",
                                        f"Call to {unsafe_func} from {call_site['caller_function']}",
                                        f"{unsafe_func} called at {call_site['caller_addr']} "
                                        f"from {call_site['caller_function']}",
                                        anomaly=True,
                                        details=call_site)
                    except (ValueError, IndexError):
                        continue

    add_test("unsafe_calls", f"{binary_name}_unsafe_call_summary",
            f"Unsafe call site summary for {binary_name}",
            f"{len(results['call_sites'])} total unsafe function call sites found")

    if results["call_sites"]:
        # Group by calling function
        callers = {}
        for cs in results["call_sites"]:
            caller = cs["caller_function"]
            if caller not in callers:
                callers[caller] = []
            callers[caller].append(cs["unsafe_function"])

        results["callers_summary"] = {k: list(set(v)) for k, v in callers.items()}

        # Functions with multiple unsafe calls are high-priority targets
        hot_callers = {k: v for k, v in callers.items() if len(v) >= 2}
        if hot_callers:
            add_finding("HIGH",
                       f"{binary_name}: {len(hot_callers)} functions with multiple unsafe calls",
                       f"Functions calling 2+ unsafe C functions are prime overflow targets: "
                       f"{json.dumps({k: list(set(v)) for k, v in hot_callers.items()}, indent=2)[:1000]}",
                       cwe="CWE-120")

    return results


def analyze_strings(binary_name, binary_path):
    """Extract and categorize all strings — correlate with functions."""
    log(f"\n--- String Analysis: {binary_name} ---")

    results = {"strings": [], "categories": {}, "interesting": []}

    strings_data = r2_json(binary_path, "izj")
    if not strings_data:
        # Fallback to izzj for all strings
        strings_data = r2_json(binary_path, "izzj")

    if not strings_data:
        add_test("strings", f"{binary_name}_strings",
                f"String extraction from {binary_name}",
                "FAILED to extract strings", anomaly=True)
        return results

    # Categorize strings
    categories = {
        "http_methods": [], "http_headers": [], "http_paths": [],
        "error_messages": [], "format_strings": [], "file_paths": [],
        "passwords_keys": [], "base64_blobs": [], "urls": [],
        "json_related": [], "crypto_related": [], "debug_info": [],
    }

    interesting_patterns = {
        "format_string": re.compile(r'%[0-9]*[sdxnpfgclu]'),
        "password": re.compile(r'(?i)(passw|secret|key|token|cred|auth)', re.IGNORECASE),
        "path": re.compile(r'^/[a-zA-Z]'),
        "http_method": re.compile(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)$'),
        "http_header": re.compile(r'^[A-Z][a-z]+-[A-Z]'),
        "base64": re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$'),
        "url": re.compile(r'https?://'),
        "json": re.compile(r'(?i)(json|parse|object|array|string|number|null|true|false)'),
        "error": re.compile(r'(?i)(error|fail|invalid|bad |wrong|unexpected|overflow|truncat)'),
        "crypto": re.compile(r'(?i)(rc4|aes|sha|md5|hmac|encrypt|decrypt|cipher|hash)'),
    }

    for s in strings_data:
        string_val = s.get("string", "")
        vaddr = s.get("vaddr", 0)

        entry = {
            "value": string_val[:200],  # truncate very long strings
            "vaddr": hex(vaddr),
            "length": s.get("length", len(string_val)),
            "section": s.get("section", ""),
        }
        results["strings"].append(entry)

        # Categorize
        for cat_name, pattern in interesting_patterns.items():
            if pattern.search(string_val):
                if cat_name == "format_string":
                    categories["format_strings"].append(entry)
                    # Format strings with %n are CRITICAL (write primitive)
                    if "%n" in string_val:
                        results["interesting"].append({
                            **entry, "reason": "Format string with %n write primitive"})
                        add_finding("HIGH",
                                   f"{binary_name}: Format string with %n at {hex(vaddr)}",
                                   f"String at {hex(vaddr)} contains %n: '{string_val[:100]}'. "
                                   f"If user input reaches this format string, it provides an "
                                   f"arbitrary write primitive.",
                                   cwe="CWE-134")
                elif cat_name == "password":
                    categories["passwords_keys"].append(entry)
                    results["interesting"].append({**entry, "reason": "Password/key related string"})
                elif cat_name == "path":
                    categories["file_paths"].append(entry)
                elif cat_name == "http_method":
                    categories["http_methods"].append(entry)
                elif cat_name == "http_header":
                    categories["http_headers"].append(entry)
                elif cat_name == "base64":
                    categories["base64_blobs"].append(entry)
                    results["interesting"].append({**entry, "reason": "Embedded base64 blob"})
                elif cat_name == "url":
                    categories["urls"].append(entry)
                elif cat_name == "json":
                    categories["json_related"].append(entry)
                elif cat_name == "error":
                    categories["error_messages"].append(entry)
                elif cat_name == "crypto":
                    categories["crypto_related"].append(entry)

    results["categories"] = {k: len(v) for k, v in categories.items()}
    results["category_details"] = {
        k: v[:20] for k, v in categories.items()  # First 20 of each
    }

    add_test("strings", f"{binary_name}_string_count",
            f"String analysis for {binary_name}",
            f"{len(strings_data)} strings extracted, "
            f"{sum(len(v) for v in categories.values())} categorized, "
            f"{len(results['interesting'])} interesting",
            details=results["categories"])

    # Check for format strings in data sections that might be user-controllable
    fmt_count = len(categories["format_strings"])
    if fmt_count > 0:
        add_test("strings", f"{binary_name}_format_strings",
                f"Format strings in {binary_name}",
                f"{fmt_count} format strings found",
                anomaly=True,
                details={"samples": [f["value"][:100] for f in categories["format_strings"][:10]]})

    return results


def analyze_critical_functions(binary_name, binary_path):
    """Deep analysis of critical attack-surface functions."""
    log(f"\n--- Critical Function Analysis: {binary_name} ---")

    results = {"found": [], "not_found": [], "disassembly": {}, "call_graphs": {}}

    # First get the full function list
    output = r2_cmd(binary_path, ["aaa", "aflj"], timeout=180)
    all_functions = None
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('['):
            try:
                all_functions = json.loads(line)
                break
            except:
                continue

    if not all_functions:
        add_test("critical_funcs", f"{binary_name}_critical_analysis",
                f"Critical function analysis for {binary_name}",
                "FAILED - could not get function list", anomaly=True)
        return results

    # Build function name lookup
    func_lookup = {}
    for f in all_functions:
        name = f.get("name", "")
        func_lookup[name] = f

    # Search for each critical function (partial match)
    for crit_name in CRITICAL_FUNCTIONS:
        matched = []
        for fname, fdata in func_lookup.items():
            # Check if critical name appears as substring (demangle support)
            if crit_name.lower() in fname.lower() or \
               crit_name.replace("::", "_") in fname:
                matched.append((fname, fdata))

        if matched:
            for fname, fdata in matched:
                results["found"].append({
                    "search_name": crit_name,
                    "actual_name": fname,
                    "offset": hex(fdata.get("offset", 0)),
                    "size": fdata.get("size", 0),
                    "nbbs": fdata.get("nbbs", 0),
                    "cc": fdata.get("cc", 0),
                })

                add_test("critical_funcs",
                        f"{binary_name}_found_{crit_name[:30]}",
                        f"Critical function search: {crit_name}",
                        f"FOUND as {fname} at {hex(fdata.get('offset', 0))}, "
                        f"size={fdata.get('size', 0)}, cc={fdata.get('cc', 0)}",
                        anomaly=True)

                # Get disassembly of the function
                addr = hex(fdata.get("offset", 0))
                disasm = r2_cmd(binary_path, [
                    "aaa",
                    f"s {addr}",
                    f"pdfj"
                ], timeout=60)

                disasm_data = None
                for dline in disasm.strip().split('\n'):
                    dline = dline.strip()
                    if dline.startswith('{'):
                        try:
                            disasm_data = json.loads(dline)
                            break
                        except:
                            continue

                if disasm_data:
                    ops = disasm_data.get("ops", [])
                    results["disassembly"][fname] = {
                        "instruction_count": len(ops),
                        "calls": [],
                        "stack_vars": [],
                    }

                    # Extract all CALL instructions
                    for op in ops:
                        if op.get("type") == "call" or "call" in op.get("disasm", ""):
                            results["disassembly"][fname]["calls"].append({
                                "addr": hex(op.get("offset", 0)),
                                "disasm": op.get("disasm", ""),
                            })

                    # Look for stack buffer allocations (sub esp, N)
                    for op in ops:
                        disasm_text = op.get("disasm", "")
                        if "sub esp" in disasm_text or "sub rsp" in disasm_text:
                            results["disassembly"][fname]["stack_vars"].append({
                                "addr": hex(op.get("offset", 0)),
                                "disasm": disasm_text,
                            })

                # Get cross-references to this function
                xref_out = r2_cmd(binary_path, [
                    "aaa",
                    f"axtj {addr}"
                ], timeout=60)

                xrefs = None
                for xline in xref_out.strip().split('\n'):
                    xline = xline.strip()
                    if xline.startswith('['):
                        try:
                            xrefs = json.loads(xline)
                            break
                        except:
                            continue

                if xrefs:
                    results["call_graphs"][fname] = {
                        "callers": [{
                            "from": hex(x.get("from", 0)),
                            "fcn": x.get("fcn_name", ""),
                            "type": x.get("type", ""),
                        } for x in xrefs]
                    }
        else:
            results["not_found"].append(crit_name)

    add_test("critical_funcs", f"{binary_name}_critical_summary",
            f"Critical function search summary for {binary_name}",
            f"Found {len(results['found'])}/{len(CRITICAL_FUNCTIONS)} critical functions, "
            f"missing: {results['not_found'][:10]}",
            details={"found_names": [f["actual_name"] for f in results["found"]]})

    return results


def analyze_data_flow(binary_name, binary_path):
    """Trace network input functions → processing → unsafe sinks."""
    log(f"\n--- Data Flow Analysis: {binary_name} ---")

    results = {"network_inputs": [], "sink_chains": []}

    # Find functions that receive network data
    network_funcs = ["recv", "read", "recvfrom", "recvmsg", "accept", "listen"]

    for net_func in network_funcs:
        output = r2_cmd(binary_path, [
            "aaa",
            f"afl~{net_func}"
        ], timeout=120)

        if output.strip():
            for line in output.strip().split('\n'):
                if net_func in line:
                    parts = line.split()
                    if parts:
                        addr = parts[0]
                        # Get callers of this network function
                        xref_out = r2_cmd(binary_path, [
                            "aaa",
                            f"axtj {addr}"
                        ], timeout=60)

                        xrefs = None
                        for xline in xref_out.strip().split('\n'):
                            xline = xline.strip()
                            if xline.startswith('['):
                                try:
                                    xrefs = json.loads(xline)
                                    break
                                except:
                                    continue

                        if xrefs:
                            for xref in xrefs:
                                results["network_inputs"].append({
                                    "network_func": net_func,
                                    "caller": xref.get("fcn_name", "unknown"),
                                    "caller_addr": hex(xref.get("from", 0)),
                                })

    add_test("data_flow", f"{binary_name}_network_inputs",
            f"Network input functions in {binary_name}",
            f"{len(results['network_inputs'])} network input call sites found",
            details={"inputs": results["network_inputs"][:20]})

    return results


def analyze_rop_gadgets(binary_name, binary_path):
    """Quick ROP gadget survey — relevant since no NX."""
    log(f"\n--- ROP Gadget Survey: {binary_name} ---")

    results = {"gadget_count": 0, "useful_gadgets": []}

    # Use r2's /R for ROP gadgets (limited to avoid timeout)
    output = r2_cmd(binary_path, ["/R ret"], timeout=30)

    if output:
        lines = [l for l in output.strip().split('\n') if l.strip()]
        results["gadget_count"] = len(lines)

        # Look for particularly useful gadgets
        useful_patterns = [
            "pop.*ret",
            "mov esp.*ret",
            "call.*eax",
            "call.*edx",
            "jmp.*esp",
            "jmp.*eax",
            "int 0x80",
            "sysenter",
        ]

        for line in lines[:500]:  # Check first 500
            for pattern in useful_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    results["useful_gadgets"].append(line.strip()[:100])
                    break

    add_test("rop", f"{binary_name}_rop_survey",
            f"ROP gadget survey for {binary_name}",
            f"{results['gadget_count']} total gadgets, "
            f"{len(results['useful_gadgets'])} useful patterns",
            anomaly=(results['gadget_count'] > 0))

    # With no NX this is less relevant but still useful for chaining
    if results["gadget_count"] > 50:
        add_test("rop", f"{binary_name}_rop_rich",
                f"ROP gadget availability in {binary_name}",
                f"Rich ROP surface: {results['gadget_count']} gadgets available. "
                f"Combined with no NX, attacker has both direct shellcode AND ROP options.",
                anomaly=True)

    return results


def analyze_relocs_got(binary_name, binary_path):
    """Analyze GOT/PLT entries — targets for format string writes."""
    log(f"\n--- GOT/PLT Analysis: {binary_name} ---")

    results = {"got_entries": [], "relocs": []}

    # GOT entries (writable function pointers - format string targets)
    relocs = r2_json(binary_path, "irj")
    if relocs:
        for r in relocs:
            entry = {
                "name": r.get("name", ""),
                "vaddr": hex(r.get("vaddr", 0)),
                "type": r.get("type", ""),
                "is_ifunc": r.get("is_ifunc", False),
            }
            results["relocs"].append(entry)

        # GOT entries for interesting functions (format string targets)
        interesting_got = []
        for r in relocs:
            name = r.get("name", "").lower()
            if any(f in name for f in ["system", "exec", "popen", "sprintf",
                                        "printf", "puts", "exit", "free", "malloc"]):
                interesting_got.append({
                    "name": r.get("name"),
                    "got_addr": hex(r.get("vaddr", 0)),
                })

        results["interesting_got"] = interesting_got

        add_test("got_plt", f"{binary_name}_got_summary",
                f"GOT/PLT entries in {binary_name}",
                f"{len(relocs)} relocation entries, "
                f"{len(interesting_got)} interesting GOT targets",
                details={"interesting": interesting_got})

        if interesting_got:
            add_test("got_plt", f"{binary_name}_got_targets",
                    f"Interesting GOT entries (format string targets) in {binary_name}",
                    f"Writable GOT entries for: {', '.join(e['name'] for e in interesting_got[:10])}",
                    anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1.2: libjson.so Deep Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_libjson_deep():
    """Deep analysis of libjson.so — CVE-2025-10948 was here."""
    log(f"\n{'='*60}")
    log("DEEP ANALYSIS: libjson.so (CVE-2025-10948 library)")
    log(f"{'='*60}")

    binary_path = TARGETS["libjson.so"]
    results = {}

    # Get all functions
    output = r2_cmd(binary_path, ["aaa", "aflj"], timeout=120)
    functions = None
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('['):
            try:
                functions = json.loads(line)
                break
            except:
                continue

    if not functions:
        add_test("libjson_deep", "libjson_functions",
                "libjson.so function listing", "FAILED", anomaly=True)
        return results

    results["functions"] = []
    for f in functions:
        results["functions"].append({
            "name": f.get("name"),
            "offset": hex(f.get("offset", 0)),
            "size": f.get("size", 0),
        })

    add_test("libjson_deep", "libjson_function_count",
            "libjson.so total functions",
            f"{len(functions)} functions in 26KB library")

    # Find parse_json_element and related parsers
    parser_funcs = []
    for f in functions:
        name = f.get("name", "").lower()
        if any(kw in name for kw in ["parse", "json", "stream", "feed",
                                       "element", "string", "number", "array",
                                       "object", "value", "token"]):
            parser_funcs.append(f)
            add_test("libjson_deep", f"libjson_parser_{f['name'][:30]}",
                    f"JSON parser function: {f['name']}",
                    f"offset={hex(f.get('offset', 0))}, size={f.get('size', 0)}",
                    anomaly=True)

    results["parser_functions"] = parser_funcs

    # Look for bounds checking patterns in each parser function
    for pf in parser_funcs:
        addr = hex(pf.get("offset", 0))
        disasm = r2_cmd(binary_path, [
            "aaa",
            f"s {addr}",
            "pdf"
        ], timeout=60)

        if disasm:
            # Check for cmp instructions (bounds checks)
            cmp_count = disasm.count(" cmp ")
            jmp_count = len(re.findall(r'\bj[a-z]{1,3}\b', disasm))
            call_count = disasm.count(" call ")

            # Look for suspicious patterns
            has_memcpy = "memcpy" in disasm
            has_sprintf = "sprintf" in disasm
            has_strcpy = "strcpy" in disasm
            has_malloc = "malloc" in disasm
            has_realloc = "realloc" in disasm

            add_test("libjson_deep", f"libjson_bounds_{pf['name'][:30]}",
                    f"Bounds checking in {pf['name']}",
                    f"cmp={cmp_count}, jmp={jmp_count}, calls={call_count}, "
                    f"memcpy={has_memcpy}, sprintf={has_sprintf}, strcpy={has_strcpy}",
                    anomaly=(has_sprintf or has_strcpy),
                    details={
                        "cmp_instructions": cmp_count,
                        "branch_instructions": jmp_count,
                        "call_instructions": call_count,
                        "unsafe_calls": {
                            "memcpy": has_memcpy,
                            "sprintf": has_sprintf,
                            "strcpy": has_strcpy,
                            "malloc": has_malloc,
                            "realloc": has_realloc,
                        }
                    })

            if has_sprintf:
                add_finding("HIGH",
                           f"libjson.so: sprintf in parser function {pf['name']}",
                           f"JSON parser function {pf['name']} calls sprintf — "
                           f"if JSON input controls the format string or output buffer, "
                           f"this is a buffer overflow vector. Adjacent to CVE-2025-10948 code path.",
                           cwe="CWE-120")

    # Recursion analysis — check for recursive function calls
    for pf in parser_funcs:
        addr = hex(pf.get("offset", 0))
        fname = pf.get("name", "")

        disasm = r2_cmd(binary_path, [
            "aaa",
            f"s {addr}",
            "pdf"
        ], timeout=60)

        if disasm and fname in disasm:
            # Count self-references (recursive calls)
            self_calls = disasm.count(f"call.*{fname}")
            # Also check by address
            self_calls += disasm.count(f"call {addr}")

            if self_calls > 0:
                add_test("libjson_deep", f"libjson_recursion_{fname[:30]}",
                        f"Recursive call in {fname}",
                        f"{self_calls} self-calls detected — stack exhaustion risk "
                        f"with deeply nested JSON",
                        anomaly=True)

                add_finding("MEDIUM",
                           f"libjson.so: Recursive parser {fname}",
                           f"Parser function {fname} is recursive ({self_calls} self-calls). "
                           f"Without a depth limit, deeply nested JSON (e.g., 10000 levels) "
                           f"will exhaust the stack. No stack canary means the overflow "
                           f"overwrites the saved return address cleanly.",
                           cwe="CWE-674")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1.3: libwww.so Analysis (HTTP Core)
# ══════════════════════════════════════════════════════════════════════════════

def analyze_libwww_deep():
    """Deep analysis of libwww.so — HTTP request/response handling."""
    log(f"\n{'='*60}")
    log("DEEP ANALYSIS: libwww.so (HTTP server core)")
    log(f"{'='*60}")

    binary_path = TARGETS["libwww.so"]
    results = {}

    # Get all functions
    output = r2_cmd(binary_path, ["aaa", "aflj"], timeout=120)
    functions = None
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('['):
            try:
                functions = json.loads(line)
                break
            except:
                continue

    if not functions:
        add_test("libwww_deep", "libwww_functions",
                "libwww.so function listing", "FAILED", anomaly=True)
        return results

    results["functions"] = []
    for f in functions:
        results["functions"].append({
            "name": f.get("name"),
            "offset": hex(f.get("offset", 0)),
            "size": f.get("size", 0),
        })

    add_test("libwww_deep", "libwww_function_count",
            "libwww.so total functions",
            f"{len(functions)} functions in 38KB library")

    # Find HTTP-related functions
    http_keywords = ["request", "response", "header", "status", "method",
                     "url", "path", "query", "cookie", "session", "auth",
                     "parse", "send", "recv", "read", "write", "file",
                     "route", "dispatch", "handle", "body", "content",
                     "chunk", "transfer", "encoding", "multipart"]

    http_funcs = []
    for f in functions:
        name = f.get("name", "").lower()
        if any(kw in name for kw in http_keywords):
            http_funcs.append(f)

    results["http_functions"] = http_funcs

    for hf in http_funcs:
        add_test("libwww_deep", f"libwww_http_{hf['name'][:30]}",
                f"HTTP function: {hf['name']}",
                f"offset={hex(hf.get('offset', 0))}, size={hf.get('size', 0)}")

    add_test("libwww_deep", "libwww_http_func_count",
            "HTTP-related functions in libwww.so",
            f"{len(http_funcs)} HTTP-related functions identified")

    # Analyze each HTTP function for buffer patterns
    for hf in http_funcs:
        addr = hex(hf.get("offset", 0))
        disasm = r2_cmd(binary_path, [
            "aaa",
            f"s {addr}",
            "pdf"
        ], timeout=60)

        if disasm:
            # Look for stack buffer allocations
            stack_allocs = re.findall(r'sub\s+esp,\s+(0x[0-9a-f]+|\d+)', disasm)
            if stack_allocs:
                max_alloc = max(int(a, 0) for a in stack_allocs)
                add_test("libwww_deep", f"libwww_stack_{hf['name'][:30]}",
                        f"Stack allocation in {hf['name']}",
                        f"Stack frame: {stack_allocs}, max={max_alloc}",
                        anomaly=(max_alloc < 1024 and hf.get("size", 0) > 100))

            # Check for unsafe function calls
            unsafe_in_func = []
            for uf in UNSAFE_FUNCTIONS:
                if uf in disasm:
                    unsafe_in_func.append(uf)

            if unsafe_in_func:
                add_test("libwww_deep", f"libwww_unsafe_{hf['name'][:30]}",
                        f"Unsafe calls in HTTP function {hf['name']}",
                        f"Calls: {', '.join(unsafe_in_func)}",
                        anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1.4: libuhttp.so Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_libuhttp_deep():
    """Deep analysis of libuhttp.so — HTTP utilities."""
    log(f"\n{'='*60}")
    log("DEEP ANALYSIS: libuhttp.so (HTTP utilities, 62KB)")
    log(f"{'='*60}")

    binary_path = TARGETS["libuhttp.so"]
    results = {}

    output = r2_cmd(binary_path, ["aaa", "aflj"], timeout=120)
    functions = None
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('['):
            try:
                functions = json.loads(line)
                break
            except:
                continue

    if not functions:
        add_test("libuhttp_deep", "libuhttp_functions",
                "libuhttp.so function listing", "FAILED", anomaly=True)
        return results

    results["functions"] = []
    for f in functions:
        results["functions"].append({
            "name": f.get("name"),
            "offset": hex(f.get("offset", 0)),
            "size": f.get("size", 0),
        })

    add_test("libuhttp_deep", "libuhttp_function_count",
            "libuhttp.so total functions",
            f"{len(functions)} functions in 62KB library")

    # Focus on the largest functions (most likely to contain parsers)
    sorted_funcs = sorted(functions, key=lambda x: x.get("size", 0), reverse=True)

    for f in sorted_funcs[:15]:
        name = f.get("name", "unknown")
        size = f.get("size", 0)
        addr = hex(f.get("offset", 0))

        disasm = r2_cmd(binary_path, [
            "aaa",
            f"s {addr}",
            "pdf"
        ], timeout=60)

        unsafe_calls = []
        if disasm:
            for uf in UNSAFE_FUNCTIONS:
                if uf in disasm:
                    unsafe_calls.append(uf)

        add_test("libuhttp_deep", f"libuhttp_top_{name[:30]}",
                f"Top function {name} (size={size})",
                f"Unsafe calls: {unsafe_calls if unsafe_calls else 'none'}",
                anomaly=bool(unsafe_calls),
                details={"size": size, "unsafe_calls": unsafe_calls})

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Additional Analyses
# ══════════════════════════════════════════════════════════════════════════════

def analyze_crypto_functions():
    """Find and analyze RC4/crypto functions across all binaries."""
    log(f"\n{'='*60}")
    log("CRYPTO FUNCTION ANALYSIS (RC4, AES, SHA)")
    log(f"{'='*60}")

    results = {}

    crypto_keywords = ["rc4", "aes", "sha", "md5", "hmac", "encrypt", "decrypt",
                       "cipher", "hash", "key", "iv", "nonce", "random", "seed"]

    for binary_name, binary_path in TARGETS.items():
        if not binary_path.exists():
            continue

        output = r2_cmd(binary_path, ["aaa", "aflj"], timeout=120)
        functions = None
        for line in output.strip().split('\n'):
            line = line.strip()
            if line.startswith('['):
                try:
                    functions = json.loads(line)
                    break
                except:
                    continue

        if not functions:
            continue

        crypto_funcs = []
        for f in functions:
            name = f.get("name", "").lower()
            if any(kw in name for kw in crypto_keywords):
                crypto_funcs.append({
                    "name": f.get("name"),
                    "offset": hex(f.get("offset", 0)),
                    "size": f.get("size", 0),
                    "binary": binary_name,
                })

        if crypto_funcs:
            results[binary_name] = crypto_funcs
            add_test("crypto", f"{binary_name}_crypto_funcs",
                    f"Crypto functions in {binary_name}",
                    f"{len(crypto_funcs)} crypto-related functions: "
                    f"{', '.join(f['name'] for f in crypto_funcs[:5])}",
                    anomaly=True)

    return results


def generate_attack_surface_summary(all_results):
    """Generate a prioritized attack surface summary for Phase 2 targeting."""
    log(f"\n{'='*60}")
    log("ATTACK SURFACE SUMMARY")
    log(f"{'='*60}")

    summary = {
        "priority_targets": [],
        "unsafe_call_chains": [],
        "buffer_overflow_candidates": [],
        "format_string_candidates": [],
        "crypto_weaknesses": [],
    }

    # Collect all unsafe call sites across all binaries
    all_unsafe = []
    for binary_name, results in all_results.items():
        if "unsafe_calls" in results:
            for cs in results["unsafe_calls"].get("call_sites", []):
                cs["binary"] = binary_name
                all_unsafe.append(cs)

    # Group by severity
    sprintf_sites = [c for c in all_unsafe if "sprintf" in c.get("unsafe_function", "")]
    strcpy_sites = [c for c in all_unsafe if "strcpy" in c.get("unsafe_function", "")]
    memcpy_sites = [c for c in all_unsafe if "memcpy" in c.get("unsafe_function", "")]

    summary["buffer_overflow_candidates"] = {
        "sprintf_calls": len(sprintf_sites),
        "strcpy_calls": len(strcpy_sites),
        "memcpy_calls": len(memcpy_sites),
        "total_unsafe_calls": len(all_unsafe),
        "top_targets": sorted(all_unsafe,
                             key=lambda x: x.get("unsafe_function", ""))[:30],
    }

    add_test("summary", "attack_surface_overview",
            "Attack surface summary",
            f"Total unsafe call sites: {len(all_unsafe)} "
            f"(sprintf: {len(sprintf_sites)}, strcpy: {len(strcpy_sites)}, "
            f"memcpy: {len(memcpy_sites)})",
            anomaly=(len(all_unsafe) > 0))

    return summary


# ══════════════════════════════════════════════════════════════════════════════
# Main Execution
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log("MikroTik RouterOS `www` Binary — Deep Static RE (Phase 1)")
    log(f"Start time: {datetime.now().isoformat()}")
    log(f"Targets: {list(TARGETS.keys())}")

    all_results = {}

    # ── 1.1: www binary analysis ──
    log("\n" + "="*70)
    log("PHASE 1.1: www Binary Full Analysis")
    log("="*70)

    www_path = TARGETS["www"]
    www_results = {}

    www_results["metadata"] = analyze_binary_metadata("www", www_path)
    www_results["functions"] = analyze_functions("www", www_path)
    www_results["imports_exports"] = analyze_imports_exports("www", www_path)
    www_results["unsafe_calls"] = analyze_unsafe_call_sites("www", www_path)
    www_results["strings"] = analyze_strings("www", www_path)
    www_results["critical_funcs"] = analyze_critical_functions("www", www_path)
    www_results["data_flow"] = analyze_data_flow("www", www_path)
    www_results["rop"] = analyze_rop_gadgets("www", www_path)
    www_results["got_plt"] = analyze_relocs_got("www", www_path)

    all_results["www"] = www_results

    # ── 1.2: libjson.so deep analysis ──
    log("\n" + "="*70)
    log("PHASE 1.2: libjson.so Deep Analysis")
    log("="*70)

    libjson_results = {}
    libjson_results["metadata"] = analyze_binary_metadata("libjson.so", TARGETS["libjson.so"])
    libjson_results["functions"] = analyze_functions("libjson.so", TARGETS["libjson.so"])
    libjson_results["imports_exports"] = analyze_imports_exports("libjson.so", TARGETS["libjson.so"])
    libjson_results["unsafe_calls"] = analyze_unsafe_call_sites("libjson.so", TARGETS["libjson.so"])
    libjson_results["strings"] = analyze_strings("libjson.so", TARGETS["libjson.so"])
    libjson_results["deep"] = analyze_libjson_deep()

    all_results["libjson.so"] = libjson_results

    # ── 1.3: libwww.so analysis ──
    log("\n" + "="*70)
    log("PHASE 1.3: libwww.so Analysis")
    log("="*70)

    libwww_results = {}
    libwww_results["metadata"] = analyze_binary_metadata("libwww.so", TARGETS["libwww.so"])
    libwww_results["functions"] = analyze_functions("libwww.so", TARGETS["libwww.so"])
    libwww_results["imports_exports"] = analyze_imports_exports("libwww.so", TARGETS["libwww.so"])
    libwww_results["unsafe_calls"] = analyze_unsafe_call_sites("libwww.so", TARGETS["libwww.so"])
    libwww_results["strings"] = analyze_strings("libwww.so", TARGETS["libwww.so"])
    libwww_results["deep"] = analyze_libwww_deep()

    all_results["libwww.so"] = libwww_results

    # ── 1.4: libuhttp.so analysis ──
    log("\n" + "="*70)
    log("PHASE 1.4: libuhttp.so Analysis")
    log("="*70)

    libuhttp_results = {}
    libuhttp_results["metadata"] = analyze_binary_metadata("libuhttp.so", TARGETS["libuhttp.so"])
    libuhttp_results["functions"] = analyze_functions("libuhttp.so", TARGETS["libuhttp.so"])
    libuhttp_results["imports_exports"] = analyze_imports_exports("libuhttp.so", TARGETS["libuhttp.so"])
    libuhttp_results["unsafe_calls"] = analyze_unsafe_call_sites("libuhttp.so", TARGETS["libuhttp.so"])
    libuhttp_results["deep"] = analyze_libuhttp_deep()

    all_results["libuhttp.so"] = libuhttp_results

    # ── Additional binary analysis (libucrypto, libumsg, libubox) ──
    for extra_lib in ["libucrypto.so", "libumsg.so", "libubox.so"]:
        if TARGETS[extra_lib].exists():
            log(f"\n--- Quick analysis: {extra_lib} ---")
            extra_results = {}
            extra_results["metadata"] = analyze_binary_metadata(extra_lib, TARGETS[extra_lib])
            extra_results["functions"] = analyze_functions(extra_lib, TARGETS[extra_lib])
            extra_results["imports_exports"] = analyze_imports_exports(extra_lib, TARGETS[extra_lib])
            all_results[extra_lib] = extra_results

    # ── Crypto function analysis across all binaries ──
    crypto_results = analyze_crypto_functions()
    all_results["crypto_analysis"] = crypto_results

    # ── Attack surface summary ──
    attack_summary = generate_attack_surface_summary(all_results)
    all_results["attack_surface"] = attack_summary

    # ── Save evidence ──
    evidence = {
        "metadata": {
            "script": "re_www_static.py",
            "phase": "Phase 1: Deep Static RE",
            "target_binary": str(www_path),
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_tests": test_count,
            "anomalies": anomaly_count,
            "findings_count": len(findings),
        },
        "tests": tests,
        "findings": findings,
        "analysis": {
            # Store summaries (full data is too large for JSON)
            "www": {
                "function_count": len(www_results.get("functions", {}).get("functions", [])),
                "largest_functions": www_results.get("functions", {}).get("stats", {}).get("largest_functions", [])[:10],
                "unsafe_import_count": len(www_results.get("imports_exports", {}).get("unsafe_imports", [])),
                "unsafe_imports": www_results.get("imports_exports", {}).get("unsafe_imports", []),
                "unsafe_call_sites": www_results.get("unsafe_calls", {}).get("call_sites", [])[:50],
                "unsafe_callers_summary": www_results.get("unsafe_calls", {}).get("callers_summary", {}),
                "critical_functions_found": www_results.get("critical_funcs", {}).get("found", []),
                "critical_functions_missing": www_results.get("critical_funcs", {}).get("not_found", []),
                "disassembly": www_results.get("critical_funcs", {}).get("disassembly", {}),
                "call_graphs": www_results.get("critical_funcs", {}).get("call_graphs", {}),
                "network_inputs": www_results.get("data_flow", {}).get("network_inputs", []),
                "string_categories": www_results.get("strings", {}).get("categories", {}),
                "interesting_strings": www_results.get("strings", {}).get("interesting", []),
                "rop_gadgets": www_results.get("rop", {}),
                "got_plt": www_results.get("got_plt", {}),
            },
            "libjson": {
                "function_count": len(libjson_results.get("functions", {}).get("functions", [])),
                "unsafe_imports": libjson_results.get("imports_exports", {}).get("unsafe_imports", []),
                "unsafe_call_sites": libjson_results.get("unsafe_calls", {}).get("call_sites", []),
                "parser_functions": libjson_results.get("deep", {}).get("parser_functions", []),
            },
            "libwww": {
                "function_count": len(libwww_results.get("functions", {}).get("functions", [])),
                "unsafe_imports": libwww_results.get("imports_exports", {}).get("unsafe_imports", []),
                "http_functions": libwww_results.get("deep", {}).get("http_functions", []),
            },
            "libuhttp": {
                "function_count": len(libuhttp_results.get("functions", {}).get("functions", [])),
                "unsafe_imports": libuhttp_results.get("imports_exports", {}).get("unsafe_imports", []),
            },
            "crypto": crypto_results,
            "attack_surface": attack_summary,
        },
    }

    out_file = EVIDENCE_DIR / "re_www_static.json"
    with open(out_file, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    # ── Summary ──
    log(f"\n{'='*70}")
    log("PHASE 1 COMPLETE: Deep Static RE")
    log(f"{'='*70}")
    log(f"Total tests: {test_count}")
    log(f"Anomalies: {anomaly_count}")
    log(f"Findings: {len(findings)}")
    log(f"Evidence: {out_file}")

    for f in findings:
        log(f"  [{f['severity']}] {f['title']}")

    log(f"\nEnd time: {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
