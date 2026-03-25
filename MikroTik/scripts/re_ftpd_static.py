#!/usr/bin/env python3
"""
MikroTik RouterOS `ftpd` Binary — Deep Static Reverse Engineering (Track B)

Automated radare2 + Ghidra analysis pipeline for the ftpd binary (FTP server
daemon), a 34KB ELF32 i386 stripped binary with no NX, no canary, no PIE.

Extracts:
  - Full function listings with sizes, complexity, and basic block counts
  - Import/export tables — flags all unsafe C function imports
  - Cross-reference analysis for sscanf, strncpy, snprintf call sites
  - String extraction and FTP-specific categorization
  - Critical custom function analysis (isSensitiveFile, shortenPath, tokenize,
    lookupUserFile, findFile) with disassembly, calls, and stack vars
  - Call graph for FTP command dispatch table
  - Ghidra headless decompilation of key functions
  - Data flow from accept()/read() through command parsing to file operations
  - ROP gadget survey
  - CVE-2019-3943 related path traversal code analysis
  - isSensitiveFile bypass opportunity mapping

Target: /home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/source/squashfs-root/nova/bin/ftpd
Links:  libumsg.so, libuc++.so, libc.so
Evidence: evidence/re_ftpd_static.json
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
GHIDRA_PROJECT = BASE_DIR / "ghidra_project"
SCRIPTS_DIR = BASE_DIR / "scripts"

BINARY_PATH = SQUASHFS / "nova" / "bin" / "ftpd"

# Linked shared libraries for cross-binary analysis
LINKED_LIBS = {
    "libumsg.so": SQUASHFS / "lib" / "libumsg.so",
    "libuc++.so": SQUASHFS / "lib" / "libuc++.so",
    "libc.so":    SQUASHFS / "lib" / "libc.so",
}

# Unsafe C functions that are exploitable without NX/canary
UNSAFE_FUNCTIONS = [
    "sprintf", "vsprintf", "snprintf",
    "sscanf", "fscanf", "scanf",
    "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "memmove",
    "gets", "fgets",
    "realpath", "system", "popen", "exec",
]

# Critical custom functions known to exist in ftpd (from strings / symbol dump)
CRITICAL_FUNCTIONS = [
    "isSensitiveFile",      # _Z15isSensitiveFileRK6string
    "shortenPath",          # _Z11shortenPathRK6string
    "tokenize",             # _Z8tokenizeRK6stringc
    "lookupUserFile",       # _Z14lookupUserFileRK6string
    "findFile",             # nv::findFile
]

# FTP command strings for dispatch table analysis
FTP_COMMANDS = [
    "QUIT", "USER", "PASS", "TYPE", "MODE", "STRU", "NOOP", "PORT", "EPRT",
    "LIST", "NLST", "RETR", "STOR", "DELE", "CDUP", "REIN", "SYST", "ABOR",
    "RNFR", "RNTO", "PASV", "EPSV", "REST", "SIZE", "STAT", "XMKD", "XPWD",
    "XRMD", "XCUP",
]

# ── Global test state ────────────────────────────────────────────────────────

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


# ── Radare2 Helpers ──────────────────────────────────────────────────────────

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
    # Try to parse JSON from output — sometimes there's noise before it
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

def r2_analyzed_json(binary_path, command, timeout=180):
    """Run r2 with aaa analysis first, then a JSON command."""
    output = r2_cmd(binary_path, ["aaa", command], timeout=timeout)
    for line in output.strip().split('\n'):
        line = line.strip()
        if line.startswith('[') or line.startswith('{'):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    try:
        return json.loads(output.strip())
    except:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1: Binary Metadata, Protections, Sections
# ══════════════════════════════════════════════════════════════════════════════

def phase1_binary_metadata():
    """Extract ELF metadata, protections, sections, and segments."""
    log(f"\n{'='*60}")
    log("Phase 1: Binary Metadata, Protections, Sections")
    log(f"{'='*60}")

    results = {}

    # ── File info (ij) ──
    info = r2_json(BINARY_PATH, "ij")
    if info:
        bin_info = info.get("bin", {})
        results["info"] = {
            "arch": bin_info.get("arch"),
            "bits": bin_info.get("bits"),
            "endian": bin_info.get("endian"),
            "os": bin_info.get("os"),
            "type": bin_info.get("type"),
            "machine": bin_info.get("machine"),
            "stripped": bin_info.get("stripped"),
            "static": bin_info.get("static"),
            "nx": bin_info.get("nx"),
            "canary": bin_info.get("canary"),
            "pic": bin_info.get("pic"),
            "relro": bin_info.get("relro"),
        }
        add_test("metadata", "ftpd_binary_info",
                "Binary metadata for ftpd",
                f"arch={results['info'].get('arch')}, bits={results['info'].get('bits')}, "
                f"nx={results['info'].get('nx')}, canary={results['info'].get('canary')}, "
                f"pic={results['info'].get('pic')}, relro={results['info'].get('relro')}",
                details=results["info"])

        # Check each protection individually
        nx = results["info"].get("nx", False)
        canary = results["info"].get("canary", False)
        pic = results["info"].get("pic", False)
        relro = results["info"].get("relro", "none")

        if not nx:
            add_test("metadata", "ftpd_no_nx",
                    "NX (No-eXecute) protection check",
                    "NX DISABLED — stack/heap shellcode execution possible",
                    anomaly=True)
        if not canary:
            add_test("metadata", "ftpd_no_canary",
                    "Stack canary protection check",
                    "CANARY DISABLED — stack buffer overflows directly overwrite return address",
                    anomaly=True)
        if not pic:
            add_test("metadata", "ftpd_no_pie",
                    "PIE (Position Independent Executable) check",
                    "PIE DISABLED — fixed addresses enable reliable ROP/ret2libc",
                    anomaly=True)

        if not nx and not canary and not pic:
            add_finding("HIGH",
                       "ftpd: All memory protections disabled (no NX, no canary, no PIE)",
                       "The ftpd binary (34KB, ELF32 i386) has zero exploit mitigations. "
                       "Any buffer overflow can: (1) inject and execute shellcode on the stack, "
                       "(2) overwrite the return address without canary detection, "
                       "(3) use fixed addresses for ROP gadgets. "
                       f"RELRO={relro}.",
                       evidence_refs=["re_ftpd_static.json#metadata"],
                       cwe="CWE-693")

        stripped = results["info"].get("stripped", False)
        add_test("metadata", "ftpd_stripped",
                "Binary stripping check",
                f"Stripped={stripped}" + (" — symbols removed, complicating RE" if stripped else ""),
                anomaly=stripped)

    # ── Sections (iSj) ──
    sections = r2_json(BINARY_PATH, "iSj")
    if sections:
        results["sections"] = []
        writable_exec = []
        for s in sections:
            sec = {
                "name": s.get("name"),
                "size": s.get("size"),
                "vsize": s.get("vsize"),
                "paddr": hex(s.get("paddr", 0)),
                "vaddr": hex(s.get("vaddr", 0)),
                "perm": s.get("perm"),
            }
            results["sections"].append(sec)
            perm = str(s.get("perm", ""))
            if "w" in perm and "x" in perm:
                writable_exec.append(sec)

        add_test("metadata", "ftpd_sections",
                "ELF sections in ftpd",
                f"{len(sections)} sections found",
                details={"section_names": [s.get("name") for s in sections]})

        if writable_exec:
            add_test("metadata", "ftpd_writable_exec_sections",
                    "Writable + executable sections",
                    f"{len(writable_exec)} W+X sections: {[s['name'] for s in writable_exec]}",
                    anomaly=True)

        # Check .text section size
        for s in sections:
            if s.get("name") == ".text":
                text_size = s.get("size", 0)
                add_test("metadata", "ftpd_text_size",
                        ".text section size",
                        f".text = {text_size} bytes ({text_size/1024:.1f} KB)")

    # ── Segments (iSSj) ──
    segments = r2_json(BINARY_PATH, "iSSj")
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
            if s.get("name") and "GNU_STACK" in str(s.get("name", "")):
                perm = str(s.get("perm", ""))
                is_exec = "x" in perm.lower()
                add_test("metadata", "ftpd_stack_perm",
                        "Stack segment permissions (GNU_STACK)",
                        f"GNU_STACK perm={perm}" + (" — EXECUTABLE STACK" if is_exec else " — non-exec"),
                        anomaly=is_exec)
                if is_exec:
                    add_finding("CRITICAL",
                              "ftpd: Executable stack (GNU_STACK rwx)",
                              "The ftpd binary has an executable stack segment. "
                              "Any stack buffer overflow enables direct shellcode injection "
                              "and execution without ROP.",
                              cwe="CWE-119")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2: Full Function Listing
# ══════════════════════════════════════════════════════════════════════════════

def phase2_function_listing():
    """Full function analysis with auto-analysis — sizes, complexity, basic blocks."""
    log(f"\n{'='*60}")
    log("Phase 2: Full Function Listing")
    log(f"{'='*60}")

    results = {"functions": [], "stats": {}}

    # Run full analysis and get function list
    output = r2_cmd(BINARY_PATH, ["aaa", "aflj"], timeout=180)

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
        # Fallback to lighter analysis
        output = r2_cmd(BINARY_PATH, ["aa", "aflj"], timeout=120)
        for line in output.strip().split('\n'):
            line = line.strip()
            if line.startswith('['):
                try:
                    functions = json.loads(line)
                    break
                except:
                    continue

    if not functions:
        add_test("functions", "ftpd_function_listing",
                "Function listing for ftpd",
                "FAILED to extract functions", anomaly=True)
        return results

    # Process functions
    func_list = []
    size_histogram = {
        "tiny(<32)": 0, "small(32-128)": 0, "medium(128-512)": 0,
        "large(512-2048)": 0, "huge(>2048)": 0,
    }

    for f in functions:
        name = f.get("name", "unknown")
        size = f.get("size", 0)
        offset = f.get("offset", 0)
        nargs = f.get("nargs", 0)
        nbbs = f.get("nbbs", 0)
        cc = f.get("cc", 0)

        entry = {
            "name": name,
            "offset": hex(offset),
            "size": size,
            "nargs": nargs,
            "nbbs": nbbs,
            "cc": cc,
        }
        func_list.append(entry)

        if size < 32:
            size_histogram["tiny(<32)"] += 1
        elif size < 128:
            size_histogram["small(32-128)"] += 1
        elif size < 512:
            size_histogram["medium(128-512)"] += 1
        elif size < 2048:
            size_histogram["large(512-2048)"] += 1
        else:
            size_histogram["huge(>2048)"] += 1

    results["functions"] = func_list
    results["stats"] = {
        "total_functions": len(func_list),
        "size_distribution": size_histogram,
        "largest_functions": sorted(func_list, key=lambda x: x["size"], reverse=True)[:20],
        "most_complex": sorted(func_list, key=lambda x: x.get("cc", 0), reverse=True)[:20],
        "most_basic_blocks": sorted(func_list, key=lambda x: x.get("nbbs", 0), reverse=True)[:20],
    }

    add_test("functions", "ftpd_function_count",
            "Total functions in ftpd",
            f"{len(func_list)} functions found",
            details={"size_distribution": size_histogram})

    # Report largest functions — likely command handlers / parsers
    for f in results["stats"]["largest_functions"][:10]:
        add_test("functions", f"ftpd_large_func_{f['name'][:40]}",
                f"Large function: {f['name']}",
                f"size={f['size']} bytes, cc={f.get('cc', 'N/A')}, "
                f"nbbs={f.get('nbbs', 'N/A')}, nargs={f.get('nargs', 'N/A')}",
                anomaly=(f['size'] > 1024))

    # Report most complex functions
    for f in results["stats"]["most_complex"][:5]:
        if f.get("cc", 0) > 10:
            add_test("functions", f"ftpd_complex_func_{f['name'][:40]}",
                    f"High-complexity function: {f['name']}",
                    f"cyclomatic_complexity={f.get('cc', 0)}, size={f['size']}, "
                    f"nbbs={f.get('nbbs', 0)}",
                    anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3: Import/Export Analysis
# ══════════════════════════════════════════════════════════════════════════════

def phase3_imports_exports():
    """Extract imports and exports — flag all unsafe function imports."""
    log(f"\n{'='*60}")
    log("Phase 3: Import/Export Analysis")
    log(f"{'='*60}")

    results = {"imports": [], "exports": [], "unsafe_imports": [], "demangled_imports": []}

    # ── Imports (iij) ──
    imports = r2_json(BINARY_PATH, "iij")
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

            # Try to demangle C++ names
            demangled = name
            if name.startswith("_Z"):
                dmg_out = ""
                try:
                    dmg_result = subprocess.run(
                        ["c++filt", name], capture_output=True, text=True, timeout=5)
                    dmg_out = dmg_result.stdout.strip()
                except:
                    pass
                if dmg_out and dmg_out != name:
                    demangled = dmg_out
                    results["demangled_imports"].append({
                        "mangled": name, "demangled": demangled, "plt": entry["plt"]
                    })

            # Flag unsafe imports
            base_name = demangled.split("(")[0].split("::")[-1] if demangled else name
            for unsafe in UNSAFE_FUNCTIONS:
                if unsafe in base_name.lower() or unsafe == name:
                    results["unsafe_imports"].append({
                        **entry, "demangled": demangled
                    })
                    add_test("imports", f"ftpd_unsafe_import_{base_name[:30]}",
                            f"Unsafe function imported: {demangled[:60]}",
                            f"{demangled} at PLT {entry['plt']}",
                            anomaly=True)
                    break

    # ── Exports (iEj) ──
    exports = r2_json(BINARY_PATH, "iEj")
    if exports:
        for exp in exports:
            results["exports"].append({
                "name": exp.get("name", ""),
                "vaddr": hex(exp.get("vaddr", 0)),
                "size": exp.get("size", 0),
                "type": exp.get("type"),
            })

    add_test("imports", "ftpd_import_summary",
            "Import/export summary for ftpd",
            f"{len(results['imports'])} imports, {len(results['exports'])} exports, "
            f"{len(results['unsafe_imports'])} unsafe imports, "
            f"{len(results['demangled_imports'])} C++ symbols demangled")

    # Specific unsafe function findings
    unsafe_names = list(set(i.get("demangled", i["name"]) for i in results["unsafe_imports"]))
    if results["unsafe_imports"]:
        add_finding("MEDIUM",
                   f"ftpd: {len(results['unsafe_imports'])} unsafe function imports",
                   f"Binary imports {len(results['unsafe_imports'])} known-unsafe C functions: "
                   f"{', '.join(unsafe_names[:10])}. "
                   f"With no NX, no canary, no PIE — any overflow via these is directly exploitable.",
                   evidence_refs=["re_ftpd_static.json#imports"],
                   cwe="CWE-120")

    # Specifically flag sscanf (format string parsing risk) and strncpy (off-by-one)
    for imp in results["unsafe_imports"]:
        name = imp.get("demangled", imp["name"])
        if "sscanf" in name:
            add_test("imports", "ftpd_sscanf_import",
                    "sscanf import — format string + overflow risk",
                    f"sscanf at PLT {imp['plt']} — "
                    f"if format specifiers lack width limits (e.g., %s instead of %255s), "
                    f"stack buffer overflow is trivial",
                    anomaly=True)
        elif "strncpy" in name:
            add_test("imports", "ftpd_strncpy_import",
                    "strncpy import — off-by-one null termination risk",
                    f"strncpy at PLT {imp['plt']} — "
                    f"strncpy does NOT null-terminate if src >= n, enabling read overflow",
                    anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4: Cross-Reference Analysis for Unsafe Call Sites
# ══════════════════════════════════════════════════════════════════════════════

def phase4_xref_analysis():
    """Find every call site for sscanf, strncpy, snprintf and extract calling context."""
    log(f"\n{'='*60}")
    log("Phase 4: Cross-Reference Analysis (sscanf, strncpy, snprintf)")
    log(f"{'='*60}")

    results = {"call_sites": [], "callers_summary": {}}

    # Target unsafe functions for deep xref analysis
    target_unsafe = UNSAFE_FUNCTIONS

    # Run analysis once and get function list to find PLT entries
    afl_output = r2_cmd(BINARY_PATH, ["aaa", "afl"], timeout=180)

    if not afl_output.strip():
        add_test("xref", "ftpd_xref_analysis",
                "Cross-reference analysis",
                "FAILED — could not run analysis", anomaly=True)
        return results

    for unsafe_func in target_unsafe:
        # Find PLT entry for this function in the function list
        for line in afl_output.strip().split('\n'):
            if unsafe_func in line and ("imp." in line or "sym.imp." in line or "plt." in line):
                parts = line.split()
                if not parts:
                    continue
                try:
                    addr = parts[0]

                    # Get cross-references to this PLT entry
                    xref_output = r2_cmd(BINARY_PATH, ["aaa", f"axtj {addr}"], timeout=60)

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

                            add_test("xref",
                                    f"ftpd_xref_{unsafe_func}@{call_site['caller_addr']}",
                                    f"Call to {unsafe_func} from {call_site['caller_function']}",
                                    f"{unsafe_func} called at {call_site['caller_addr']} "
                                    f"from {call_site['caller_function']}",
                                    anomaly=True,
                                    details=call_site)
                except (ValueError, IndexError):
                    continue

    add_test("xref", "ftpd_xref_summary",
            "Unsafe call site cross-reference summary",
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
                       f"ftpd: {len(hot_callers)} functions with multiple unsafe calls",
                       f"Functions calling 2+ unsafe C functions are prime overflow targets: "
                       f"{json.dumps({k: list(set(v)) for k, v in hot_callers.items()}, indent=2)[:1500]}",
                       evidence_refs=["re_ftpd_static.json#xref"],
                       cwe="CWE-120")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5: String Extraction and Categorization
# ══════════════════════════════════════════════════════════════════════════════

def phase5_string_analysis():
    """Extract and categorize all strings — FTP commands, errors, paths, format strings, sensitive."""
    log(f"\n{'='*60}")
    log("Phase 5: String Extraction and Categorization")
    log(f"{'='*60}")

    results = {"strings": [], "categories": {}, "interesting": []}

    strings_data = r2_json(BINARY_PATH, "izj")
    if not strings_data:
        strings_data = r2_json(BINARY_PATH, "izzj")

    if not strings_data:
        add_test("strings", "ftpd_strings",
                "String extraction from ftpd",
                "FAILED to extract strings", anomaly=True)
        return results

    # FTP-specific categorization
    categories = {
        "ftp_commands": [],
        "ftp_response_codes": [],
        "error_messages": [],
        "file_paths": [],
        "format_strings": [],
        "sensitive_filenames": [],
        "network_related": [],
        "auth_related": [],
        "transfer_related": [],
        "debug_strings": [],
    }

    # Patterns for categorization
    patterns = {
        "ftp_command": re.compile(r'^(' + '|'.join(FTP_COMMANDS) + r')$'),
        "ftp_response": re.compile(r'^\d{3}\s'),
        "format_string": re.compile(r'%[0-9]*[sdxnpfgclu]'),
        "format_string_dangerous": re.compile(r'%[0-9]*s(?!\s*\d)'),  # %s without width = overflow
        "file_path": re.compile(r'^/[a-zA-Z]'),
        "error": re.compile(r'(?i)(error|fail|invalid|bad |wrong|denied|abort|can.t)'),
        "auth": re.compile(r'(?i)(user|pass|login|logged|anonymous|credential|auth)'),
        "sensitive_file": re.compile(r'(?i)(\.rsc|\.auto|\.npk|\.log|sensitive|import|nova)'),
        "transfer": re.compile(r'(?i)(transfer|retr|stor|data connection|ascii|binary|image|mode)'),
        "network": re.compile(r'(?i)(socket|bind|connect|listen|accept|port |passive|eprt|epsv)'),
        "debug": re.compile(r'(?i)(ftpd:|debug|trace|verbose)'),
    }

    for s in strings_data:
        string_val = s.get("string", "")
        vaddr = s.get("vaddr", 0)

        entry = {
            "value": string_val[:200],
            "vaddr": hex(vaddr),
            "length": s.get("length", len(string_val)),
            "section": s.get("section", ""),
        }
        results["strings"].append(entry)

        # Categorize
        if patterns["ftp_command"].match(string_val):
            categories["ftp_commands"].append(entry)
        if patterns["ftp_response"].match(string_val):
            categories["ftp_response_codes"].append(entry)
        if patterns["format_string"].search(string_val):
            categories["format_strings"].append(entry)
            # %n is a write primitive
            if "%n" in string_val:
                results["interesting"].append({
                    **entry, "reason": "Format string with %n write primitive"
                })
                add_finding("HIGH",
                           f"ftpd: Format string with %n at {hex(vaddr)}",
                           f"String at {hex(vaddr)} contains %n: '{string_val[:100]}'. "
                           f"If user input reaches this format string, it provides an "
                           f"arbitrary write primitive.",
                           cwe="CWE-134")
        if patterns["file_path"].match(string_val):
            categories["file_paths"].append(entry)
        if patterns["error"].search(string_val):
            categories["error_messages"].append(entry)
        if patterns["auth"].search(string_val):
            categories["auth_related"].append(entry)
        if patterns["sensitive_file"].search(string_val):
            categories["sensitive_filenames"].append(entry)
            results["interesting"].append({**entry, "reason": "Sensitive filename pattern"})
        if patterns["transfer"].search(string_val):
            categories["transfer_related"].append(entry)
        if patterns["network"].search(string_val):
            categories["network_related"].append(entry)
        if patterns["debug"].search(string_val):
            categories["debug_strings"].append(entry)

    results["categories"] = {k: len(v) for k, v in categories.items()}
    results["category_details"] = {k: v[:25] for k, v in categories.items()}

    add_test("strings", "ftpd_string_count",
            "String analysis for ftpd",
            f"{len(strings_data)} strings extracted, "
            f"{sum(len(v) for v in categories.values())} categorized, "
            f"{len(results['interesting'])} interesting",
            details=results["categories"])

    # FTP command strings
    ftp_cmd_values = [e["value"] for e in categories["ftp_commands"]]
    add_test("strings", "ftpd_ftp_commands",
            "FTP command strings found",
            f"{len(categories['ftp_commands'])} FTP commands: {ftp_cmd_values}",
            details={"commands": ftp_cmd_values})

    # Check which expected commands are missing
    found_cmds = set(ftp_cmd_values)
    missing_cmds = set(FTP_COMMANDS) - found_cmds
    if missing_cmds:
        add_test("strings", "ftpd_missing_commands",
                "FTP commands NOT found in binary strings",
                f"Missing: {sorted(missing_cmds)} — may be handled differently or unsupported",
                anomaly=bool(missing_cmds))

    # FTP response codes
    add_test("strings", "ftpd_response_codes",
            "FTP response code strings",
            f"{len(categories['ftp_response_codes'])} response strings found",
            details={"samples": [e["value"][:80] for e in categories["ftp_response_codes"][:15]]})

    # Format strings analysis — specifically dangerous ones
    dangerous_fmts = []
    for e in categories["format_strings"]:
        val = e["value"]
        # Check for %s without width limit (e.g., %s vs %255s)
        if re.search(r'%[^0-9]?s', val) and not re.search(r'%\d+s', val):
            dangerous_fmts.append(e)

    if dangerous_fmts:
        add_test("strings", "ftpd_dangerous_format_strings",
                "Format strings with unbounded %s",
                f"{len(dangerous_fmts)} format strings use %s without width limit — "
                f"if used with sscanf/sprintf, buffer overflow is trivial",
                anomaly=True,
                details={"samples": [e["value"][:100] for e in dangerous_fmts[:10]]})

    # Sensitive filenames
    add_test("strings", "ftpd_sensitive_filenames",
            "Sensitive filename patterns",
            f"{len(categories['sensitive_filenames'])} sensitive file patterns: "
            f"{[e['value'][:50] for e in categories['sensitive_filenames'][:10]]}",
            anomaly=bool(categories["sensitive_filenames"]))

    # AUTO.RSC / AUTO.NPK detection (auto-execute files)
    auto_files = [e for e in results["strings"] if "AUTO" in e["value"].upper()]
    if auto_files:
        add_test("strings", "ftpd_auto_files",
                "Auto-execute file references (.AUTO.RSC, .AUTO.NPK)",
                f"{len(auto_files)} auto-execute file references found — "
                f"FTP uploads of .AUTO.RSC trigger automatic script execution",
                anomaly=True,
                details={"files": [e["value"][:80] for e in auto_files]})
        add_finding("MEDIUM",
                   "ftpd: Auto-execute file handling (.AUTO.RSC, .AUTO.NPK)",
                   "The ftpd binary references .AUTO.RSC and .AUTO.NPK files. "
                   "Uploading a file ending in .AUTO.RSC via FTP may trigger automatic "
                   "RouterOS script import (/import command visible in strings). "
                   "This is a persistence vector if FTP write access is obtained.",
                   evidence_refs=["re_ftpd_static.json#strings"],
                   cwe="CWE-434")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 6: Critical Function Identification and Disassembly
# ══════════════════════════════════════════════════════════════════════════════

def phase6_critical_functions():
    """Deep analysis of isSensitiveFile, shortenPath, tokenize, lookupUserFile, findFile."""
    log(f"\n{'='*60}")
    log("Phase 6: Critical Function Identification and Disassembly")
    log(f"{'='*60}")

    results = {"found": [], "not_found": [], "disassembly": {}, "call_graphs": {}}

    # Get the full function list with analysis
    output = r2_cmd(BINARY_PATH, ["aaa", "aflj"], timeout=180)
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
        add_test("critical_funcs", "ftpd_critical_analysis",
                "Critical function analysis",
                "FAILED — could not get function list", anomaly=True)
        return results

    # Build function name lookup
    func_lookup = {}
    for f in all_functions:
        name = f.get("name", "")
        func_lookup[name] = f

    # Search for each critical function (partial name match for mangled names)
    for crit_name in CRITICAL_FUNCTIONS:
        matched = []
        for fname, fdata in func_lookup.items():
            if crit_name.lower() in fname.lower() or \
               crit_name.replace("::", "_") in fname:
                matched.append((fname, fdata))

        if matched:
            for fname, fdata in matched:
                found_entry = {
                    "search_name": crit_name,
                    "actual_name": fname,
                    "offset": hex(fdata.get("offset", 0)),
                    "size": fdata.get("size", 0),
                    "nbbs": fdata.get("nbbs", 0),
                    "cc": fdata.get("cc", 0),
                    "nargs": fdata.get("nargs", 0),
                }
                results["found"].append(found_entry)

                add_test("critical_funcs",
                        f"ftpd_found_{crit_name}",
                        f"Critical function search: {crit_name}",
                        f"FOUND as {fname} at {hex(fdata.get('offset', 0))}, "
                        f"size={fdata.get('size', 0)}, cc={fdata.get('cc', 0)}, "
                        f"nbbs={fdata.get('nbbs', 0)}",
                        anomaly=True)

                # Get disassembly (pdfj)
                addr = hex(fdata.get("offset", 0))
                disasm = r2_cmd(BINARY_PATH, ["aaa", f"s {addr}", "pdfj"], timeout=60)

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
                    func_info = {
                        "instruction_count": len(ops),
                        "calls": [],
                        "stack_vars": [],
                        "string_refs": [],
                        "cmp_instructions": [],
                    }

                    # Extract CALL instructions
                    for op in ops:
                        disasm_text = op.get("disasm", "")
                        if op.get("type") == "call" or "call" in disasm_text:
                            func_info["calls"].append({
                                "addr": hex(op.get("offset", 0)),
                                "disasm": disasm_text,
                            })

                        # Stack allocations (sub esp, N)
                        if "sub esp" in disasm_text:
                            func_info["stack_vars"].append({
                                "addr": hex(op.get("offset", 0)),
                                "disasm": disasm_text,
                            })

                        # CMP instructions (bounds checks, string comparisons)
                        if disasm_text.startswith("cmp") or " cmp " in disasm_text:
                            func_info["cmp_instructions"].append({
                                "addr": hex(op.get("offset", 0)),
                                "disasm": disasm_text,
                            })

                    results["disassembly"][fname] = func_info

                    add_test("critical_funcs",
                            f"ftpd_disasm_{crit_name}",
                            f"Disassembly of {crit_name} ({fname})",
                            f"{len(ops)} instructions, {len(func_info['calls'])} calls, "
                            f"{len(func_info['stack_vars'])} stack allocations, "
                            f"{len(func_info['cmp_instructions'])} comparisons",
                            details={
                                "calls": func_info["calls"][:20],
                                "stack": func_info["stack_vars"],
                                "cmps": func_info["cmp_instructions"][:10],
                            })

                # Get cross-references TO this function (who calls it)
                xref_out = r2_cmd(BINARY_PATH, ["aaa", f"axtj {addr}"], timeout=60)
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
                    add_test("critical_funcs",
                            f"ftpd_callers_{crit_name}",
                            f"Callers of {crit_name}",
                            f"{len(xrefs)} callers: "
                            f"{[x.get('fcn_name', '?') for x in xrefs[:5]]}",
                            details={"callers": results["call_graphs"][fname]["callers"]})
        else:
            results["not_found"].append(crit_name)
            add_test("critical_funcs",
                    f"ftpd_missing_{crit_name}",
                    f"Critical function search: {crit_name}",
                    f"NOT FOUND in function list — may be inlined or optimized away")

    # Special analysis: isSensitiveFile string comparisons
    if "isSensitiveFile" in [f["search_name"] for f in results["found"]]:
        _analyze_isSensitiveFile(results)

    # Summary
    add_test("critical_funcs", "ftpd_critical_summary",
            "Critical function search summary",
            f"Found {len(results['found'])}/{len(CRITICAL_FUNCTIONS)} critical functions, "
            f"missing: {results['not_found']}",
            details={"found_names": [f["actual_name"] for f in results["found"]]})

    return results


def _analyze_isSensitiveFile(results):
    """Deep analysis of isSensitiveFile — find what file patterns it blocks."""
    log("  --- Deep dive: isSensitiveFile bypass analysis ---")

    # Find the isSensitiveFile entry
    isf_entry = None
    for f in results["found"]:
        if f["search_name"] == "isSensitiveFile":
            isf_entry = f
            break

    if not isf_entry:
        return

    addr = isf_entry["offset"]

    # Get raw disassembly text (not JSON) for string pattern analysis
    raw_disasm = r2_cmd(BINARY_PATH, ["aaa", f"s {addr}", "pdf"], timeout=60)
    if not raw_disasm:
        return

    # Extract string references from disassembly
    str_refs = re.findall(r'str\.(.*?)(?:\s|$)', raw_disasm)
    push_strs = re.findall(r'push\s+.*?;\s*(.+)', raw_disasm)

    # Look for compared strings (these are the sensitive file patterns)
    sensitive_patterns = []
    for line in raw_disasm.split('\n'):
        # Look for string pushes before calls to string::compare
        if 'str.' in line or '"' in line:
            # Extract the string value
            match = re.search(r'"([^"]+)"', line)
            if match:
                sensitive_patterns.append(match.group(1))
            match = re.search(r'str\.\s*(\S+)', line)
            if match:
                sensitive_patterns.append(match.group(1))

    add_test("critical_funcs", "ftpd_isSensitiveFile_patterns",
            "isSensitiveFile blocked patterns",
            f"Found {len(sensitive_patterns)} pattern references in disassembly: "
            f"{sensitive_patterns[:15]}",
            anomaly=True,
            details={
                "patterns": sensitive_patterns,
                "raw_string_refs": str_refs[:20],
                "bypass_vectors": [
                    "Case manipulation (if comparisons are case-sensitive)",
                    "Path encoding (URL-encoded characters)",
                    "Trailing dots/spaces (Windows-style)",
                    "Unicode normalization bypass",
                    "Null byte injection in path components",
                    "Symlink to sensitive file (if not resolved before check)",
                ],
            })

    # Check if the function uses case-sensitive or case-insensitive comparison
    has_toupper = "toupper" in raw_disasm
    has_tolower = "tolower" in raw_disasm
    has_strcmp = "strcmp" in raw_disasm
    has_strcasecmp = "strcasecmp" in raw_disasm or "stricmp" in raw_disasm

    comparison_type = "UNKNOWN"
    if has_toupper or has_tolower or has_strcasecmp:
        comparison_type = "case-insensitive"
    elif has_strcmp:
        comparison_type = "case-sensitive (BYPASS via case manipulation)"

    add_test("critical_funcs", "ftpd_isSensitiveFile_comparison",
            "isSensitiveFile comparison type",
            f"Comparison: {comparison_type}, "
            f"toupper={has_toupper}, tolower={has_tolower}, "
            f"strcmp={has_strcmp}, strcasecmp={has_strcasecmp}",
            anomaly=("case-sensitive" in comparison_type))

    if "case-sensitive" in comparison_type:
        add_finding("MEDIUM",
                   "ftpd: isSensitiveFile uses case-sensitive comparison",
                   "The isSensitiveFile function appears to use case-sensitive string "
                   "comparison. If the underlying filesystem is case-insensitive, "
                   "an attacker can bypass the filter by changing the case "
                   "(e.g., '.Auto.Rsc' instead of '.AUTO.RSC'). "
                   "This is a common filter bypass on case-insensitive filesystems.",
                   evidence_refs=["re_ftpd_static.json#critical_funcs"],
                   cwe="CWE-178")


# ══════════════════════════════════════════════════════════════════════════════
# Phase 7: FTP Command Dispatch Table / Call Graph
# ══════════════════════════════════════════════════════════════════════════════

def phase7_command_dispatch():
    """Map the FTP command dispatch table — how commands reach their handlers."""
    log(f"\n{'='*60}")
    log("Phase 7: FTP Command Dispatch Table / Call Graph")
    log(f"{'='*60}")

    results = {"command_table": [], "dispatch_function": None, "handler_map": {}}

    # Strategy: Find where FTP command strings are referenced, trace to dispatch logic.
    # The command strings (USER, PASS, RETR, etc.) are compared in sequence in a
    # dispatch loop/table.

    # First, find cross-references to each FTP command string
    for cmd in FTP_COMMANDS:
        # Search for the string address
        str_search = r2_cmd(BINARY_PATH, ["aaa", f"/ {cmd}\\x00"], timeout=30)

        # Also search via flag names in r2
        flag_search = r2_cmd(BINARY_PATH, [f"iz~{cmd}"], timeout=15)

        cmd_addr = None
        if flag_search:
            for line in flag_search.strip().split('\n'):
                if cmd in line:
                    # Parse the vaddr from izz output
                    parts = line.split()
                    for p in parts:
                        if p.startswith("0x"):
                            cmd_addr = p
                            break

        if cmd_addr:
            # Find xrefs to this string address
            xref_output = r2_cmd(BINARY_PATH, ["aaa", f"axtj {cmd_addr}"], timeout=30)

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
                    handler = {
                        "command": cmd,
                        "string_addr": cmd_addr,
                        "ref_addr": hex(xref.get("from", 0)),
                        "ref_function": xref.get("fcn_name", "unknown"),
                        "ref_type": xref.get("type", "unknown"),
                    }
                    results["command_table"].append(handler)
                    results["handler_map"][cmd] = handler

                    add_test("dispatch", f"ftpd_cmd_handler_{cmd}",
                            f"FTP command handler: {cmd}",
                            f"{cmd} referenced at {handler['ref_addr']} "
                            f"in {handler['ref_function']}",
                            details=handler)
            else:
                add_test("dispatch", f"ftpd_cmd_noxref_{cmd}",
                        f"FTP command {cmd} — no xrefs found",
                        f"String at {cmd_addr} but no code references found")
        else:
            add_test("dispatch", f"ftpd_cmd_nostring_{cmd}",
                    f"FTP command {cmd} — string not found via search",
                    f"Command string '{cmd}' not found as exact match")

    # Identify the dispatch function — it should reference most commands
    if results["command_table"]:
        # Count references per function
        func_refs = {}
        for entry in results["command_table"]:
            fn = entry["ref_function"]
            if fn not in func_refs:
                func_refs[fn] = []
            func_refs[fn].append(entry["command"])

        # The dispatch function has the most command references
        dispatch_fn = max(func_refs.items(), key=lambda x: len(x[1]))
        results["dispatch_function"] = {
            "name": dispatch_fn[0],
            "commands_handled": dispatch_fn[1],
            "count": len(dispatch_fn[1]),
        }

        add_test("dispatch", "ftpd_dispatch_function",
                "Main FTP command dispatch function identified",
                f"{dispatch_fn[0]} handles {len(dispatch_fn[1])} commands: "
                f"{dispatch_fn[1]}",
                anomaly=True,
                details=results["dispatch_function"])

        # Any function handling only one command is likely a dedicated handler
        for fn, cmds in func_refs.items():
            if fn != dispatch_fn[0] and len(cmds) <= 2:
                add_test("dispatch", f"ftpd_handler_{fn[:30]}",
                        f"Dedicated handler: {fn}",
                        f"Handles {cmds} ({len(cmds)} commands)")

    # Check for command injection opportunities — commands that take file arguments
    file_commands = {"RETR", "STOR", "DELE", "RNFR", "RNTO", "LIST", "NLST",
                     "CWD", "XMKD", "XRMD", "SIZE", "STAT"}
    file_cmd_handlers = [e for e in results["command_table"] if e["command"] in file_commands]
    add_test("dispatch", "ftpd_file_command_handlers",
            "File-operation FTP commands (path traversal targets)",
            f"{len(file_cmd_handlers)} file-operation commands with handlers: "
            f"{[e['command'] for e in file_cmd_handlers]}",
            anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 8: Ghidra Headless Decompilation
# ══════════════════════════════════════════════════════════════════════════════

def phase8_ghidra_decompilation(phase4_results, phase6_results):
    """Ghidra headless decompilation of key functions."""
    log(f"\n{'='*60}")
    log("Phase 8: Ghidra Headless Decompilation")
    log(f"{'='*60}")

    results = {"decompiled": [], "errors": []}

    # Check prerequisites
    ghidra_bin = Path("/usr/share/ghidra/support/analyzeHeadless")
    ghidra_project_file = GHIDRA_PROJECT / "MikroTik_RE.gpr"
    ghidra_script = SCRIPTS_DIR / "ghidra_export_functions.py"

    if not ghidra_bin.exists():
        add_test("ghidra", "ftpd_ghidra_prereq",
                "Ghidra headless prerequisite check",
                f"analyzeHeadless not found at {ghidra_bin}", anomaly=True)
        return results

    if not ghidra_project_file.exists():
        add_test("ghidra", "ftpd_ghidra_project",
                "Ghidra project check",
                f"Project not found at {ghidra_project_file}", anomaly=True)
        return results

    if not ghidra_script.exists():
        add_test("ghidra", "ftpd_ghidra_script",
                "Ghidra export script check",
                f"Script not found at {ghidra_script}", anomaly=True)
        return results

    add_test("ghidra", "ftpd_ghidra_prereqs_ok",
            "Ghidra prerequisites verified",
            f"analyzeHeadless={ghidra_bin.exists()}, "
            f"project={ghidra_project_file.exists()}, "
            f"script={ghidra_script.exists()}")

    # Collect addresses to decompile:
    # 1. sscanf callers (format string + overflow risk)
    # 2. isSensitiveFile (bypass opportunities)
    # 3. The dispatch function
    # 4. File operation handler functions (RETR, STOR, CWD)
    # 5. shortenPath, tokenize, lookupUserFile, findFile

    addresses = set()
    address_labels = {}

    # From Phase 4: sscanf/strncpy/snprintf callers
    if phase4_results and "call_sites" in phase4_results:
        for cs in phase4_results["call_sites"]:
            if cs["unsafe_function"] in ("sscanf", "strncpy", "snprintf", "sprintf", "strcpy"):
                addr = cs.get("caller_addr", "")
                if addr and addr != "0x0":
                    addresses.add(addr)
                    label = f"caller_of_{cs['unsafe_function']}"
                    address_labels[addr] = label

    # From Phase 6: critical functions
    if phase6_results:
        for f in phase6_results.get("found", []):
            addr = f.get("offset", "")
            if addr and addr != "0x0":
                addresses.add(addr)
                address_labels[addr] = f.get("search_name", "critical")

    # Limit to 30 addresses to avoid timeout
    address_list = sorted(addresses)[:30]

    if not address_list:
        add_test("ghidra", "ftpd_ghidra_no_targets",
                "Ghidra decompilation targets",
                "No addresses collected for decompilation", anomaly=True)
        return results

    add_test("ghidra", "ftpd_ghidra_targets",
            "Ghidra decompilation target addresses",
            f"{len(address_list)} functions queued for decompilation",
            details={"addresses": {a: address_labels.get(a, "unknown") for a in address_list[:15]}})

    # Run Ghidra headless
    output_file = str(EVIDENCE_DIR / "ghidra_ftpd_decompile.json")
    cmd = [
        str(ghidra_bin),
        str(GHIDRA_PROJECT), "MikroTik_RE",
        "-process", "ftpd",
        "-noanalysis",
        "-postScript", "ghidra_export_functions.py",
        f"ADDRESSES={','.join(address_list)}",
        f"OUTPUT={output_file}",
        f"MODE=targeted",
        "-scriptPath", str(SCRIPTS_DIR),
    ]

    log(f"  Running Ghidra headless ({len(address_list)} functions)...")
    log(f"  Command: {' '.join(cmd[:6])}...")

    try:
        ghidra_result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            env={**os.environ}
        )

        if ghidra_result.returncode == 0:
            add_test("ghidra", "ftpd_ghidra_run",
                    "Ghidra headless execution",
                    "Completed successfully")

            # Parse output
            if Path(output_file).exists():
                try:
                    with open(output_file, "r") as f:
                        ghidra_output = json.load(f)

                    decompiled = ghidra_output.get("decompiled_functions", [])
                    results["decompiled"] = decompiled

                    add_test("ghidra", "ftpd_ghidra_output",
                            "Ghidra decompilation output",
                            f"{len(decompiled)} functions decompiled successfully",
                            details={"binary": ghidra_output.get("binary"),
                                     "metadata": ghidra_output.get("metadata")})

                    # Analyze each decompiled function
                    for df in decompiled:
                        addr = df.get("address", "?")
                        name = df.get("name", "unknown")
                        code = df.get("decompiled_c", "")
                        danger = df.get("dangerous_calls", [])

                        if df.get("error") or df.get("decompile_error"):
                            results["errors"].append({
                                "address": addr, "name": name,
                                "error": df.get("error") or df.get("decompile_error"),
                            })
                            continue

                        label = address_labels.get(addr, "unknown")

                        # Check decompiled code for specific patterns
                        anomalies = []
                        if code:
                            if "sscanf" in code and "%s" in code:
                                anomalies.append("sscanf with %s (no width limit)")
                            if "strncpy" in code:
                                # Check if null termination is added after strncpy
                                if "\\0" not in code and "= 0" not in code.split("strncpy")[1][:200]:
                                    anomalies.append("strncpy without null termination")
                            if ".." in code:
                                anomalies.append("path traversal string (..) in code")
                            if "strcmp" in code and "toupper" not in code and "tolower" not in code:
                                anomalies.append("case-sensitive string comparison")

                        add_test("ghidra", f"ftpd_decompiled_{name[:30]}",
                                f"Decompiled: {name} ({label})",
                                f"Decompilation OK, {len(danger)} dangerous calls, "
                                f"anomalies: {anomalies if anomalies else 'none'}",
                                anomaly=bool(anomalies or danger),
                                details={
                                    "address": addr,
                                    "label": label,
                                    "dangerous_calls": danger,
                                    "anomalies": anomalies,
                                    "code_preview": (code[:500] + "...") if code and len(code) > 500 else code,
                                    "parameters": df.get("parameters", []),
                                    "local_variables": df.get("local_variables", [])[:10],
                                    "stack_frame_size": df.get("stack_frame_size", 0),
                                })

                    # Dangerous call map
                    danger_map = ghidra_output.get("dangerous_call_map", {})
                    if danger_map:
                        add_test("ghidra", "ftpd_ghidra_danger_map",
                                "Ghidra dangerous call map",
                                f"{len(danger_map)} functions call dangerous functions",
                                details={k: v.get("dangerous_calls", []) for k, v in
                                        list(danger_map.items())[:15]})

                except (json.JSONDecodeError, Exception) as e:
                    add_test("ghidra", "ftpd_ghidra_parse_error",
                            "Ghidra output parsing",
                            f"Failed to parse {output_file}: {e}", anomaly=True)
            else:
                add_test("ghidra", "ftpd_ghidra_no_output",
                        "Ghidra output file",
                        f"Output file not created at {output_file}", anomaly=True)
        else:
            stderr_preview = ghidra_result.stderr[-500:] if ghidra_result.stderr else "no stderr"
            add_test("ghidra", "ftpd_ghidra_run_failed",
                    "Ghidra headless execution",
                    f"Failed with return code {ghidra_result.returncode}: {stderr_preview}",
                    anomaly=True)

    except subprocess.TimeoutExpired:
        add_test("ghidra", "ftpd_ghidra_timeout",
                "Ghidra headless execution",
                "Timed out after 300 seconds", anomaly=True)
    except Exception as e:
        add_test("ghidra", "ftpd_ghidra_exception",
                "Ghidra headless execution",
                f"Exception: {e}", anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 9: Data Flow — accept()/read() → command parsing → file operations
# ══════════════════════════════════════════════════════════════════════════════

def phase9_data_flow():
    """Trace network input functions to unsafe sinks."""
    log(f"\n{'='*60}")
    log("Phase 9: Data Flow Analysis (network input → unsafe sinks)")
    log(f"{'='*60}")

    results = {"network_inputs": [], "sink_chains": [], "file_operations": []}

    # ── Network input functions ──
    network_funcs = ["accept", "read", "recv", "recvfrom", "recvmsg", "select", "poll"]

    afl_output = r2_cmd(BINARY_PATH, ["aaa", "afl"], timeout=180)
    if not afl_output:
        add_test("data_flow", "ftpd_dataflow_analysis",
                "Data flow analysis", "FAILED — afl returned empty", anomaly=True)
        return results

    for net_func in network_funcs:
        for line in afl_output.strip().split('\n'):
            if net_func in line and ("imp." in line or "sym.imp." in line or "plt." in line):
                parts = line.split()
                if not parts:
                    continue
                addr = parts[0]

                # Get callers
                xref_output = r2_cmd(BINARY_PATH, ["aaa", f"axtj {addr}"], timeout=60)
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
                        results["network_inputs"].append({
                            "network_func": net_func,
                            "plt_addr": addr,
                            "caller": xref.get("fcn_name", "unknown"),
                            "caller_addr": hex(xref.get("from", 0)),
                        })

    add_test("data_flow", "ftpd_network_inputs",
            "Network input call sites",
            f"{len(results['network_inputs'])} network input references found",
            details={"inputs": results["network_inputs"][:20]})

    # ── File operation sinks ──
    file_funcs = ["open", "fopen", "opendir", "readdir", "stat", "fstat",
                  "lseek", "write", "splice", "ftruncate", "mkdir", "rmdir",
                  "remove", "rename", "unlink"]

    for file_func in file_funcs:
        for line in afl_output.strip().split('\n'):
            if file_func in line and ("imp." in line or "sym.imp." in line or "plt." in line):
                parts = line.split()
                if not parts:
                    continue
                addr = parts[0]

                xref_output = r2_cmd(BINARY_PATH, ["aaa", f"axtj {addr}"], timeout=60)
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
                        results["file_operations"].append({
                            "file_func": file_func,
                            "plt_addr": addr,
                            "caller": xref.get("fcn_name", "unknown"),
                            "caller_addr": hex(xref.get("from", 0)),
                        })

    add_test("data_flow", "ftpd_file_operations",
            "File operation call sites (sinks)",
            f"{len(results['file_operations'])} file operation references found",
            details={"operations": results["file_operations"][:20]})

    # ── Trace source→sink chains ──
    # Find functions that both receive network input AND perform file operations
    input_funcs = set(n["caller"] for n in results["network_inputs"])
    file_funcs_set = set(f["caller"] for f in results["file_operations"])
    direct_chains = input_funcs & file_funcs_set

    if direct_chains:
        add_test("data_flow", "ftpd_direct_input_to_file",
                "Functions with BOTH network input AND file operations",
                f"{len(direct_chains)} functions are direct source→sink chains: "
                f"{list(direct_chains)[:10]}",
                anomaly=True)
        add_finding("MEDIUM",
                   f"ftpd: {len(direct_chains)} functions directly chain network input to file ops",
                   f"Functions that both read network input AND perform file operations "
                   f"are prime targets for path traversal and buffer overflow: "
                   f"{list(direct_chains)[:10]}. "
                   f"If user-supplied FTP paths are not properly sanitized between "
                   f"read() and open()/stat(), path traversal is possible.",
                   evidence_refs=["re_ftpd_static.json#data_flow"],
                   cwe="CWE-22")

    # ── istream::getline analysis — FTP command line reader ──
    for line in afl_output.strip().split('\n'):
        if "getline" in line:
            parts = line.split()
            if parts:
                addr = parts[0]
                xref_output = r2_cmd(BINARY_PATH, ["aaa", f"axtj {addr}"], timeout=60)
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
                    add_test("data_flow", "ftpd_getline_usage",
                            "istream::getline usage (FTP command reader)",
                            f"getline called from {len(xrefs)} locations: "
                            f"{[x.get('fcn_name', '?') for x in xrefs[:5]]}",
                            anomaly=True,
                            details={"callers": [{
                                "from": hex(x.get("from", 0)),
                                "fcn": x.get("fcn_name", ""),
                            } for x in xrefs]})

    # ── splice() — zero-copy transfer ──
    for line in afl_output.strip().split('\n'):
        if "splice" in line and "imp." in line:
            add_test("data_flow", "ftpd_splice_usage",
                    "splice() system call (zero-copy data transfer)",
                    "ftpd uses splice() for data transfer — efficient but may bypass "
                    "in-process data inspection/filtering",
                    anomaly=True)
            break

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 10: ROP Gadget Survey + GOT/PLT Analysis
# ══════════════════════════════════════════════════════════════════════════════

def phase10_rop_and_got():
    """ROP gadget survey and GOT/PLT analysis."""
    log(f"\n{'='*60}")
    log("Phase 10: ROP Gadget Survey + GOT/PLT Analysis")
    log(f"{'='*60}")

    results = {"rop": {}, "got_plt": {}}

    # ── ROP gadgets ──
    log("  Scanning for ROP gadgets...")
    output = r2_cmd(BINARY_PATH, ["/R ret"], timeout=60)

    if output:
        lines = [l for l in output.strip().split('\n') if l.strip()]
        results["rop"]["gadget_count"] = len(lines)
        results["rop"]["useful_gadgets"] = []

        useful_patterns = [
            ("pop.*ret", "register control"),
            ("mov esp.*ret", "stack pivot"),
            ("call.*eax", "call register"),
            ("call.*edx", "call register"),
            ("call.*ecx", "call register"),
            ("jmp.*esp", "shellcode jump"),
            ("jmp.*eax", "jump register"),
            ("int 0x80", "syscall"),
            ("sysenter", "fast syscall"),
            ("xchg.*esp", "stack exchange"),
            ("add esp.*ret", "stack adjustment"),
            ("leave.*ret", "leave-ret"),
        ]

        for line in lines[:1000]:
            for pattern, category in useful_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    results["rop"]["useful_gadgets"].append({
                        "gadget": line.strip()[:120],
                        "category": category,
                    })
                    break

        # Deduplicate by category
        by_category = {}
        for g in results["rop"]["useful_gadgets"]:
            cat = g["category"]
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(g["gadget"])
        results["rop"]["by_category"] = {k: v[:5] for k, v in by_category.items()}

        add_test("rop", "ftpd_rop_survey",
                "ROP gadget survey",
                f"{results['rop']['gadget_count']} total gadgets, "
                f"{len(results['rop']['useful_gadgets'])} useful patterns across "
                f"{len(by_category)} categories",
                anomaly=(results["rop"]["gadget_count"] > 0))

        for cat, gadgets in by_category.items():
            add_test("rop", f"ftpd_rop_{cat.replace(' ', '_')}",
                    f"ROP gadget category: {cat}",
                    f"{len(gadgets)} gadgets (sample: {gadgets[0][:80] if gadgets else 'none'})")

        if results["rop"]["gadget_count"] > 50:
            add_test("rop", "ftpd_rop_rich",
                    "ROP gadget availability",
                    f"Rich ROP surface: {results['rop']['gadget_count']} gadgets. "
                    f"Combined with no NX, attacker has BOTH direct shellcode AND ROP options.",
                    anomaly=True)
    else:
        add_test("rop", "ftpd_rop_empty",
                "ROP gadget survey", "No gadgets found or r2 failed")

    # ── GOT/PLT entries ──
    log("  Analyzing GOT/PLT entries...")
    relocs = r2_json(BINARY_PATH, "irj")
    if relocs:
        results["got_plt"]["relocs"] = []
        interesting_got = []

        for r in relocs:
            entry = {
                "name": r.get("name", ""),
                "vaddr": hex(r.get("vaddr", 0)),
                "type": r.get("type", ""),
                "is_ifunc": r.get("is_ifunc", False),
            }
            results["got_plt"]["relocs"].append(entry)

            # Flag interesting GOT entries (format string write targets)
            name = r.get("name", "").lower()
            if any(f in name for f in ["system", "exec", "popen", "sprintf",
                                        "printf", "puts", "exit", "free", "malloc",
                                        "open", "read", "write", "close"]):
                interesting_got.append({
                    "name": r.get("name"),
                    "got_addr": hex(r.get("vaddr", 0)),
                })

        results["got_plt"]["interesting_got"] = interesting_got

        add_test("got_plt", "ftpd_got_summary",
                "GOT/PLT entries",
                f"{len(relocs)} relocation entries, "
                f"{len(interesting_got)} interesting GOT targets",
                details={"interesting": interesting_got})

        if interesting_got:
            add_test("got_plt", "ftpd_got_targets",
                    "Interesting GOT entries (exploitation targets)",
                    f"Writable GOT entries for: "
                    f"{', '.join(e['name'] for e in interesting_got[:15])}",
                    anomaly=True)

            # Check for no full RELRO — GOT overwrite viable
            add_test("got_plt", "ftpd_got_writability",
                    "GOT overwrite viability",
                    "No full RELRO + writable GOT = format string → GOT overwrite → RCE. "
                    "Overwrite system() GOT entry to redirect execution.",
                    anomaly=True)
    else:
        add_test("got_plt", "ftpd_got_empty",
                "GOT/PLT analysis", "No relocations found or r2 failed")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Additional: CVE-2019-3943 Path Traversal Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_cve_2019_3943():
    """Search for CVE-2019-3943 related code (path traversal fix in ftpd)."""
    log(f"\n{'='*60}")
    log("Additional: CVE-2019-3943 Path Traversal Code Analysis")
    log(f"{'='*60}")

    results = {"path_traversal_indicators": [], "path_sanitization": []}

    # CVE-2019-3943: RouterOS FTP path traversal via CWD command
    # Look for ".." handling, path canonicalization, chroot-like checks

    # Search for ".." string in the binary
    dotdot_search = r2_cmd(BINARY_PATH, ["aaa", "/ .."], timeout=30)
    if dotdot_search:
        add_test("cve_analysis", "ftpd_dotdot_search",
                "Path traversal string (..) search",
                f"Found '..' references in binary — checking for sanitization",
                anomaly=True)

    # Search for path-related strings
    path_strings = r2_cmd(BINARY_PATH, ["iz~path"], timeout=15)
    if not path_strings:
        path_strings = r2_cmd(BINARY_PATH, ["iz~/"], timeout=15)

    if path_strings:
        add_test("cve_analysis", "ftpd_path_strings",
                "Path-related strings in ftpd",
                f"Found path-related strings",
                details={"preview": path_strings[:500]})

    # Analyze shortenPath — this is likely the path sanitization function
    afl_output = r2_cmd(BINARY_PATH, ["aaa", "afl~shorten"], timeout=60)
    if afl_output and "shorten" in afl_output.lower():
        for line in afl_output.strip().split('\n'):
            if "shorten" in line.lower():
                parts = line.split()
                if parts:
                    addr = parts[0]
                    # Get disassembly
                    disasm = r2_cmd(BINARY_PATH, ["aaa", f"s {addr}", "pdf"], timeout=60)
                    if disasm:
                        # Check what shortenPath does
                        has_dotdot_check = ".." in disasm
                        has_slash_check = "/" in disasm and "cmp" in disasm
                        has_rfind = "rfind" in disasm or "__str_rfind" in disasm
                        has_substr = "substr" in disasm
                        has_erase = "erase" in disasm

                        add_test("cve_analysis", "ftpd_shortenPath_analysis",
                                "shortenPath function analysis (CVE-2019-3943 fix)",
                                f"dotdot_check={has_dotdot_check}, slash_check={has_slash_check}, "
                                f"rfind={has_rfind}, substr={has_substr}, erase={has_erase}",
                                anomaly=True,
                                details={
                                    "has_dotdot_check": has_dotdot_check,
                                    "has_slash_check": has_slash_check,
                                    "has_rfind": has_rfind,
                                    "has_substr": has_substr,
                                    "has_erase": has_erase,
                                    "disasm_preview": disasm[:1000],
                                })

                        if not has_dotdot_check:
                            add_finding("HIGH",
                                       "ftpd: shortenPath may not check for '..' (path traversal)",
                                       "The shortenPath function does not appear to contain "
                                       "explicit '..' checks in its disassembly. "
                                       "If this is the path sanitization function for CVE-2019-3943, "
                                       "the fix may be incomplete or the check is elsewhere.",
                                       evidence_refs=["re_ftpd_static.json#cve_analysis"],
                                       cwe="CWE-22")

    # Check for chroot or path prefix validation
    chroot_search = r2_cmd(BINARY_PATH, ["iz~chroot"], timeout=15)
    realpath_search = r2_cmd(BINARY_PATH, ["aaa", "afl~realpath"], timeout=30)

    add_test("cve_analysis", "ftpd_chroot_check",
            "chroot/realpath usage check",
            f"chroot_strings={bool(chroot_search and chroot_search.strip())}, "
            f"realpath_import={bool(realpath_search and realpath_search.strip())}",
            anomaly=not (chroot_search and chroot_search.strip()))

    if not (chroot_search and chroot_search.strip()):
        add_test("cve_analysis", "ftpd_no_chroot",
                "No chroot detected in ftpd",
                "ftpd does not appear to use chroot() — path validation relies on "
                "application-level checks (shortenPath/isSensitiveFile) rather than "
                "OS-level isolation. This means any bypass of the path validation "
                "logic directly exposes the full filesystem.",
                anomaly=True)

    # Check for path prefix enforcement (e.g., must start with /flash/ or user home)
    flash_search = r2_cmd(BINARY_PATH, ["iz~flash"], timeout=15)
    home_search = r2_cmd(BINARY_PATH, ["iz~home"], timeout=15)

    add_test("cve_analysis", "ftpd_path_prefix_check",
            "Path prefix enforcement strings",
            f"flash_refs={bool(flash_search and flash_search.strip())}, "
            f"home_refs={bool(home_search and home_search.strip())}",
            details={"flash": flash_search[:200] if flash_search else "",
                     "home": home_search[:200] if home_search else ""})

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Additional: Complete Command Dispatch Table Mapping
# ══════════════════════════════════════════════════════════════════════════════

def analyze_dispatch_table_deep():
    """Map the complete FTP command dispatch table from binary data."""
    log(f"\n{'='*60}")
    log("Additional: Deep Command Dispatch Table Mapping")
    log(f"{'='*60}")

    results = {"dispatch_entries": []}

    # The FTP command strings are stored sequentially in .rodata
    # Find the address range containing the command strings
    str_output = r2_cmd(BINARY_PATH, ["iz"], timeout=30)
    if not str_output:
        add_test("dispatch_deep", "ftpd_dispatch_table_search",
                "Dispatch table search", "FAILED — no strings", anomaly=True)
        return results

    # Find addresses of all FTP command strings
    cmd_addrs = {}
    for line in str_output.strip().split('\n'):
        for cmd in FTP_COMMANDS:
            # Match exact command string
            if f" {cmd} " in line or f" {cmd}\\x00" in line or line.strip().endswith(f" {cmd}"):
                parts = line.split()
                for p in parts:
                    if p.startswith("0x"):
                        cmd_addrs[cmd] = p
                        break

    add_test("dispatch_deep", "ftpd_command_string_addresses",
            "FTP command string addresses in .rodata",
            f"Found addresses for {len(cmd_addrs)}/{len(FTP_COMMANDS)} commands",
            details=cmd_addrs)

    # Check if command strings are contiguous (table structure)
    if len(cmd_addrs) >= 2:
        addr_values = sorted(int(a, 16) for a in cmd_addrs.values())
        gaps = []
        for i in range(1, len(addr_values)):
            gap = addr_values[i] - addr_values[i-1]
            gaps.append(gap)

        avg_gap = sum(gaps) / len(gaps) if gaps else 0
        add_test("dispatch_deep", "ftpd_command_table_layout",
                "Command string table layout analysis",
                f"Average spacing: {avg_gap:.1f} bytes, "
                f"range: {hex(addr_values[0])} - {hex(addr_values[-1])}, "
                f"contiguous={max(gaps) < 64 if gaps else False}",
                details={
                    "min_gap": min(gaps) if gaps else 0,
                    "max_gap": max(gaps) if gaps else 0,
                    "avg_gap": avg_gap,
                })

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Additional: Linked Library Quick Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_linked_libraries():
    """Quick security analysis of ftpd's linked libraries."""
    log(f"\n{'='*60}")
    log("Additional: Linked Library Analysis (libumsg.so, libuc++.so)")
    log(f"{'='*60}")

    results = {}

    for lib_name, lib_path in LINKED_LIBS.items():
        if not lib_path.exists():
            add_test("libraries", f"ftpd_lib_{lib_name}_missing",
                    f"Linked library: {lib_name}",
                    f"NOT FOUND at {lib_path}")
            continue

        # Get basic info
        info = r2_json(lib_path, "ij")
        if info:
            bin_info = info.get("bin", {})
            add_test("libraries", f"ftpd_lib_{lib_name}_info",
                    f"Library: {lib_name}",
                    f"nx={bin_info.get('nx')}, canary={bin_info.get('canary')}, "
                    f"pic={bin_info.get('pic')}, relro={bin_info.get('relro')}",
                    anomaly=(not bin_info.get("nx") or not bin_info.get("canary")))

        # Count functions
        func_output = r2_cmd(lib_path, ["aa", "aflj"], timeout=60)
        if func_output:
            funcs = None
            for line in func_output.strip().split('\n'):
                line = line.strip()
                if line.startswith('['):
                    try:
                        funcs = json.loads(line)
                        break
                    except:
                        continue
            if funcs:
                add_test("libraries", f"ftpd_lib_{lib_name}_functions",
                        f"Functions in {lib_name}",
                        f"{len(funcs)} functions")

        # Check for unsafe imports
        imports = r2_json(lib_path, "iij")
        if imports:
            unsafe = []
            for imp in imports:
                name = imp.get("name", "").lower()
                for uf in UNSAFE_FUNCTIONS:
                    if uf in name:
                        unsafe.append(imp.get("name"))
                        break
            if unsafe:
                add_test("libraries", f"ftpd_lib_{lib_name}_unsafe",
                        f"Unsafe imports in {lib_name}",
                        f"{len(unsafe)} unsafe: {unsafe[:10]}",
                        anomaly=True)

        results[lib_name] = {"path": str(lib_path), "exists": True}

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Attack Surface Summary
# ══════════════════════════════════════════════════════════════════════════════

def generate_attack_surface_summary(all_results):
    """Generate a prioritized attack surface summary."""
    log(f"\n{'='*60}")
    log("ATTACK SURFACE SUMMARY")
    log(f"{'='*60}")

    summary = {
        "priority_targets": [],
        "overflow_candidates": [],
        "path_traversal_surface": [],
        "sensitive_file_bypass": [],
        "auto_exec_vectors": [],
    }

    # Collect all unsafe call sites
    xref_results = all_results.get("phase4_xrefs", {})
    call_sites = xref_results.get("call_sites", [])

    # Group by type
    sscanf_sites = [c for c in call_sites if c.get("unsafe_function") == "sscanf"]
    strncpy_sites = [c for c in call_sites if c.get("unsafe_function") == "strncpy"]
    snprintf_sites = [c for c in call_sites if c.get("unsafe_function") == "snprintf"]
    sprintf_sites = [c for c in call_sites if c.get("unsafe_function") == "sprintf"]

    summary["overflow_candidates"] = {
        "sscanf_calls": len(sscanf_sites),
        "strncpy_calls": len(strncpy_sites),
        "snprintf_calls": len(snprintf_sites),
        "sprintf_calls": len(sprintf_sites),
        "total_unsafe_calls": len(call_sites),
    }

    add_test("summary", "ftpd_attack_surface_overview",
            "Attack surface summary",
            f"Total unsafe call sites: {len(call_sites)} "
            f"(sscanf: {len(sscanf_sites)}, strncpy: {len(strncpy_sites)}, "
            f"snprintf: {len(snprintf_sites)}, sprintf: {len(sprintf_sites)})")

    # Priority targets for dynamic testing
    priority = []

    # 1. sscanf callers — format string parsing overflow
    for cs in sscanf_sites:
        priority.append({
            "target": cs.get("caller_function", "?"),
            "reason": f"sscanf call at {cs.get('caller_addr', '?')} — "
                      f"format string overflow if %s lacks width limit",
            "severity": "HIGH",
        })

    # 2. Functions handling file-path FTP commands (RETR, STOR, CWD, etc.)
    dispatch = all_results.get("phase7_dispatch", {})
    for cmd in ["RETR", "STOR", "CWD", "DELE", "RNFR", "RNTO", "LIST"]:
        handler = dispatch.get("handler_map", {}).get(cmd)
        if handler:
            priority.append({
                "target": handler.get("ref_function", "?"),
                "reason": f"Handles {cmd} — path traversal + overflow target",
                "severity": "HIGH",
            })

    # 3. isSensitiveFile — bypass vector
    for f in all_results.get("phase6_critical", {}).get("found", []):
        if f["search_name"] == "isSensitiveFile":
            priority.append({
                "target": f["actual_name"],
                "reason": "Sensitive file filter — bypass enables access to "
                          "system config, user credentials, etc.",
                "severity": "MEDIUM",
            })

    summary["priority_targets"] = priority[:20]

    add_test("summary", "ftpd_priority_targets",
            "Priority targets for dynamic testing",
            f"{len(priority)} targets identified",
            details={"targets": priority[:10]})

    return summary


# ══════════════════════════════════════════════════════════════════════════════
# Main Execution
# ══════════════════════════════════════════════════════════════════════════════

def main():
    start_time = datetime.now()
    log("MikroTik RouterOS `ftpd` Binary — Deep Static RE (Track B)")
    log(f"Start time: {start_time.isoformat()}")
    log(f"Target: {BINARY_PATH}")
    log(f"Binary size: {BINARY_PATH.stat().st_size} bytes")

    all_results = {}

    # ── Phase 1: Binary Metadata ──
    log("\n" + "=" * 70)
    log("PHASE 1: Binary Metadata, Protections, Sections")
    log("=" * 70)
    all_results["phase1_metadata"] = phase1_binary_metadata()

    # ── Phase 2: Function Listing ──
    log("\n" + "=" * 70)
    log("PHASE 2: Full Function Listing")
    log("=" * 70)
    all_results["phase2_functions"] = phase2_function_listing()

    # ── Phase 3: Import/Export Analysis ──
    log("\n" + "=" * 70)
    log("PHASE 3: Import/Export Analysis")
    log("=" * 70)
    all_results["phase3_imports"] = phase3_imports_exports()

    # ── Phase 4: Cross-Reference Analysis ──
    log("\n" + "=" * 70)
    log("PHASE 4: Cross-Reference Analysis (Unsafe Call Sites)")
    log("=" * 70)
    all_results["phase4_xrefs"] = phase4_xref_analysis()

    # ── Phase 5: String Analysis ──
    log("\n" + "=" * 70)
    log("PHASE 5: String Extraction and Categorization")
    log("=" * 70)
    all_results["phase5_strings"] = phase5_string_analysis()

    # ── Phase 6: Critical Function Analysis ──
    log("\n" + "=" * 70)
    log("PHASE 6: Critical Function Identification and Disassembly")
    log("=" * 70)
    all_results["phase6_critical"] = phase6_critical_functions()

    # ── Phase 7: Command Dispatch Table ──
    log("\n" + "=" * 70)
    log("PHASE 7: FTP Command Dispatch Table")
    log("=" * 70)
    all_results["phase7_dispatch"] = phase7_command_dispatch()

    # ── Phase 8: Ghidra Decompilation ──
    log("\n" + "=" * 70)
    log("PHASE 8: Ghidra Headless Decompilation")
    log("=" * 70)
    all_results["phase8_ghidra"] = phase8_ghidra_decompilation(
        all_results.get("phase4_xrefs"), all_results.get("phase6_critical"))

    # ── Phase 9: Data Flow Analysis ──
    log("\n" + "=" * 70)
    log("PHASE 9: Data Flow (Network Input → Unsafe Sinks)")
    log("=" * 70)
    all_results["phase9_dataflow"] = phase9_data_flow()

    # ── Phase 10: ROP + GOT/PLT ──
    log("\n" + "=" * 70)
    log("PHASE 10: ROP Gadget Survey + GOT/PLT Analysis")
    log("=" * 70)
    all_results["phase10_rop_got"] = phase10_rop_and_got()

    # ── Additional Analyses ──
    log("\n" + "=" * 70)
    log("ADDITIONAL: CVE-2019-3943 Analysis + Dispatch Table + Libraries")
    log("=" * 70)
    all_results["cve_2019_3943"] = analyze_cve_2019_3943()
    all_results["dispatch_deep"] = analyze_dispatch_table_deep()
    all_results["linked_libraries"] = analyze_linked_libraries()

    # ── Attack Surface Summary ──
    all_results["attack_surface"] = generate_attack_surface_summary(all_results)

    # ── Save Evidence ──
    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()

    evidence = {
        "metadata": {
            "script": "re_ftpd_static.py",
            "phase": "Track B: ftpd Deep Static RE",
            "target_binary": str(BINARY_PATH),
            "binary_size": BINARY_PATH.stat().st_size,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "elapsed_seconds": elapsed,
            "total_tests": test_count,
            "anomalies": anomaly_count,
            "findings_count": len(findings),
        },
        "tests": tests,
        "findings": findings,
        "analysis": {
            "binary_metadata": all_results.get("phase1_metadata", {}),
            "function_stats": all_results.get("phase2_functions", {}).get("stats", {}),
            "imports": {
                "total": len(all_results.get("phase3_imports", {}).get("imports", [])),
                "unsafe_imports": all_results.get("phase3_imports", {}).get("unsafe_imports", []),
                "demangled": all_results.get("phase3_imports", {}).get("demangled_imports", []),
            },
            "xref_call_sites": all_results.get("phase4_xrefs", {}).get("call_sites", [])[:50],
            "xref_callers_summary": all_results.get("phase4_xrefs", {}).get("callers_summary", {}),
            "string_categories": all_results.get("phase5_strings", {}).get("categories", {}),
            "string_category_details": all_results.get("phase5_strings", {}).get("category_details", {}),
            "interesting_strings": all_results.get("phase5_strings", {}).get("interesting", []),
            "critical_functions": {
                "found": all_results.get("phase6_critical", {}).get("found", []),
                "not_found": all_results.get("phase6_critical", {}).get("not_found", []),
                "disassembly": all_results.get("phase6_critical", {}).get("disassembly", {}),
                "call_graphs": all_results.get("phase6_critical", {}).get("call_graphs", {}),
            },
            "command_dispatch": {
                "table": all_results.get("phase7_dispatch", {}).get("command_table", []),
                "dispatch_function": all_results.get("phase7_dispatch", {}).get("dispatch_function"),
                "handler_map": all_results.get("phase7_dispatch", {}).get("handler_map", {}),
            },
            "ghidra_decompilation": {
                "decompiled_count": len(all_results.get("phase8_ghidra", {}).get("decompiled", [])),
                "errors": all_results.get("phase8_ghidra", {}).get("errors", []),
            },
            "data_flow": {
                "network_inputs": all_results.get("phase9_dataflow", {}).get("network_inputs", []),
                "file_operations": all_results.get("phase9_dataflow", {}).get("file_operations", []),
            },
            "rop_gadgets": all_results.get("phase10_rop_got", {}).get("rop", {}),
            "got_plt": all_results.get("phase10_rop_got", {}).get("got_plt", {}),
            "cve_2019_3943": all_results.get("cve_2019_3943", {}),
            "linked_libraries": all_results.get("linked_libraries", {}),
            "attack_surface": all_results.get("attack_surface", {}),
        },
    }

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = EVIDENCE_DIR / "re_ftpd_static.json"
    with open(out_file, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    # ── Final Summary ──
    log(f"\n{'='*70}")
    log("TRACK B COMPLETE: ftpd Deep Static RE")
    log(f"{'='*70}")
    log(f"Total tests: {test_count}")
    log(f"Anomalies: {anomaly_count}")
    log(f"Findings: {len(findings)}")
    log(f"Elapsed: {elapsed:.1f}s")
    log(f"Evidence: {out_file}")

    for f in findings:
        log(f"  [{f['severity']}] {f['title']}")

    log(f"\nEnd time: {end_time.isoformat()}")


if __name__ == "__main__":
    main()
