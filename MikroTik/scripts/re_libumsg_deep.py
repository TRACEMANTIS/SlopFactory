#!/usr/bin/env python3
"""
MikroTik RouterOS `libumsg.so` — Deep Static Reverse Engineering

Automated radare2 + Ghidra headless analysis pipeline for libumsg.so,
the IPC backbone of ALL RouterOS services (77 linking binaries).

Library stats:
  - 501KB, ELF 32-bit i386, stripped, dynamically linked
  - ~1,289 exports, 291 imports
  - No NX, no canary, no PIE (any overflow → direct shellcode execution)
  - Critical imports: execve(0x21060), sprintf(0x24150), strcpy(0x21e60),
    realpath(0x239a0), sscanf(0x21490), fork(0x21c40)
  - nv::message RPC system with CMD_GET/SET/ADDOBJ/REMOVEOBJ/SHUTDOWN
  - Contains QR code generator, regex engine, XZ decompressor, VL scripting

Analysis phases (~200 tests):
  1. Full function listing — sizes, complexity, namespace patterns
  2. Dangerous import cross-references — all internal callers of unsafe sinks
  3. Ghidra headless decompilation — execve/sprintf/strcpy/realpath callers
  4. Data flow tracing — exports → internal funcs → dangerous imports
  5. String analysis — format strings, command strings, paths, field names
  6. Cross-binary analysis — which network-facing binaries trigger dangerous paths

Evidence output: evidence/re_libumsg_deep.json
"""

import json
import os
import sys
import time
import subprocess
import re
from datetime import datetime
from pathlib import Path
from collections import Counter, defaultdict

# Add scripts dir for shared imports
sys.path.insert(0, str(Path(__file__).parent))

# ── Configuration ────────────────────────────────────────────────────────────

BASE_DIR = Path("/home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik")
EVIDENCE_DIR = BASE_DIR / "evidence"
SQUASHFS = BASE_DIR / "source" / "squashfs-root"
LIBUMSG_PATH = SQUASHFS / "lib" / "libumsg.so"
GHIDRA_PROJECT = BASE_DIR / "ghidra_project"
GHIDRA_HEADLESS = "/usr/share/ghidra/support/analyzeHeadless"
SCRIPTS_DIR = BASE_DIR / "scripts"

# Dangerous imports with known PLT addresses (from initial recon)
DANGEROUS_IMPORTS = {
    "execve":    {"plt": 0x21060, "category": "command_execution", "severity": "CRITICAL"},
    "sprintf":   {"plt": 0x24150, "category": "buffer_overflow",   "severity": "HIGH"},
    "strcpy":    {"plt": 0x21e60, "category": "buffer_overflow",   "severity": "HIGH"},
    "realpath":  {"plt": 0x239a0, "category": "path_resolution",   "severity": "MEDIUM"},
    "sscanf":    {"plt": 0x21490, "category": "format_string",     "severity": "MEDIUM"},
    "fscanf":    {"plt": 0x22500, "category": "format_string",     "severity": "MEDIUM"},
    "fork":      {"plt": 0x21c40, "category": "process_creation",  "severity": "MEDIUM"},
    "snprintf":  {"plt": 0x21690, "category": "buffer_overflow",   "severity": "LOW"},
    "vsnprintf": {"plt": 0x239e0, "category": "buffer_overflow",   "severity": "LOW"},
    "strncpy":   {"plt": 0x22b10, "category": "buffer_overflow",   "severity": "LOW"},
    "fgets":     {"plt": 0x22f40, "category": "input_read",        "severity": "LOW"},
    "memmove":   {"plt": 0x21cc0, "category": "memory_copy",       "severity": "LOW"},
}

# Additional unsafe functions to search for (may not have known PLT)
ADDITIONAL_UNSAFE = [
    "memcpy", "strcat", "strncat", "gets", "scanf",
    "system", "popen", "execl", "execvp",
]

# Network-facing binaries that are high-priority for exploitation
NETWORK_BINARIES = [
    "www", "ftpd", "telnet", "sshd", "bfd", "traceroute",
    "snmp", "mproxy", "romon", "resolve", "dhcp",
    "ppp", "pptp", "l2tp", "ipsec", "ovpn",
    "radius", "upnp", "dude", "winbox", "mactel",
    "smb", "ntp", "dns", "hotspot", "user",
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
    """Run radare2 commands on a binary and return output."""
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

def r2_cmd_analyzed(binary_path, commands, timeout=180):
    """Run r2 commands with full analysis (aaa) prepended."""
    if isinstance(commands, str):
        commands = [commands]
    return r2_cmd(binary_path, ["aaa"] + commands, timeout=timeout)

def r2_json_analyzed(binary_path, command, timeout=180):
    """Run a single r2 JSON command with full analysis."""
    output = r2_cmd_analyzed(binary_path, [command], timeout=timeout)
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


# ── Ghidra Headless Helper ───────────────────────────────────────────────────

def run_ghidra_decompile(addresses, mode="targeted", output_suffix=""):
    """Run Ghidra headless decompilation on specified function addresses.

    Returns parsed JSON output or None on failure.
    """
    output_file = f"/tmp/ghidra_decompile_libumsg{output_suffix}.json"

    addr_str = ",".join(addresses) if addresses else ""

    cmd = [
        GHIDRA_HEADLESS,
        str(GHIDRA_PROJECT), "MikroTik_RE",
        "-process", "libumsg.so",
        "-noanalysis",
        "-postScript", "ghidra_export_functions.py",
        f"ADDRESSES={addr_str}",
        f"OUTPUT={output_file}",
        f"MODE={mode}",
        "-scriptPath", str(SCRIPTS_DIR),
    ]

    log(f"  Running Ghidra headless: mode={mode}, addresses={len(addresses) if addresses else 'all'}")
    log(f"  Output: {output_file}")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600,
            env={**os.environ}
        )

        if result.returncode != 0:
            log(f"  WARNING: Ghidra returned exit code {result.returncode}")
            # Check stderr for clues
            if result.stderr:
                for line in result.stderr.strip().split('\n')[-5:]:
                    log(f"    stderr: {line}")

        # Parse output JSON
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                data = json.load(f)
            log(f"  Ghidra decompiled {len(data.get('decompiled_functions', []))} functions")
            return data
        else:
            log(f"  WARNING: Ghidra output file not found at {output_file}")
            return None

    except subprocess.TimeoutExpired:
        log(f"  WARNING: Ghidra timed out after 600s")
        return None
    except Exception as e:
        log(f"  ERROR: Ghidra failed: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Phase 1: Full Function Listing (~20 tests)
# ══════════════════════════════════════════════════════════════════════════════

def phase1_function_listing():
    """Full function analysis: sizes, complexity, basic blocks, namespaces."""
    log(f"\n{'='*70}")
    log("PHASE 1: Full Function Listing & Characterization")
    log(f"{'='*70}")

    results = {
        "functions": [],
        "stats": {},
        "namespaces": {},
        "size_histogram": {},
    }

    # ── 1.1: Binary metadata ──
    info = r2_json(LIBUMSG_PATH, "ij")
    if info:
        bin_info = info.get("bin", {})
        meta = {
            "arch": bin_info.get("arch"),
            "bits": bin_info.get("bits"),
            "endian": bin_info.get("endian"),
            "os": bin_info.get("os"),
            "type": bin_info.get("type"),
            "stripped": bin_info.get("stripped"),
            "static": bin_info.get("static"),
            "nx": bin_info.get("nx"),
            "canary": bin_info.get("canary"),
            "pic": bin_info.get("pic"),
            "relro": bin_info.get("relro"),
        }
        results["metadata"] = meta
        add_test("phase1", "libumsg_metadata",
                "Binary metadata for libumsg.so",
                f"arch={meta.get('arch')}, bits={meta.get('bits')}, "
                f"nx={meta.get('nx')}, canary={meta.get('canary')}, pic={meta.get('pic')}",
                details=meta,
                anomaly=(not meta.get("nx") or not meta.get("canary")))

    # ── 1.2: Section analysis ──
    sections = r2_json(LIBUMSG_PATH, "iSj")
    if sections:
        sect_info = []
        for s in sections:
            sect_info.append({
                "name": s.get("name"),
                "size": s.get("size"),
                "perm": s.get("perm"),
                "vaddr": hex(s.get("vaddr", 0)),
            })
            # Check for executable stack
            if s.get("name") and "GNU_STACK" in str(s.get("name", "")):
                perm = str(s.get("perm", ""))
                if "x" in perm.lower():
                    add_finding("CRITICAL",
                              "libumsg.so: Executable stack (GNU_STACK rwx)",
                              "Library has executable stack — any stack overflow enables "
                              "direct shellcode execution. Combined with no canary, no NX, "
                              "all 77 linking binaries inherit this weakness.",
                              cwe="CWE-119")
                add_test("phase1", "libumsg_stack_perm",
                        "Stack segment permissions",
                        f"GNU_STACK perm={perm}",
                        anomaly=("x" in perm.lower()))
        add_test("phase1", "libumsg_sections",
                "ELF sections in libumsg.so",
                f"{len(sections)} sections",
                details={"sections": sect_info})

    # ── 1.3: Full function listing with aaa + aflj ──
    log("  Running full analysis (aaa) — this may take 2-3 minutes for 501KB...")
    output = r2_cmd(LIBUMSG_PATH, ["aaa", "aflj"], timeout=300)

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
        add_test("phase1", "libumsg_function_listing",
                "Function listing for libumsg.so",
                "FAILED to extract functions", anomaly=True)
        return results

    # ── 1.4: Process all functions ──
    func_list = []
    size_histogram = {
        "tiny(<32)": 0, "small(32-128)": 0, "medium(128-512)": 0,
        "large(512-2048)": 0, "huge(2048-8192)": 0, "massive(>8192)": 0,
    }
    namespace_counter = Counter()
    complexity_buckets = {"simple(cc<5)": 0, "moderate(5-15)": 0, "complex(15-50)": 0, "very_complex(>50)": 0}

    for f in functions:
        name = f.get("name", "unknown")
        size = f.get("size", 0)
        offset = f.get("offset", 0)
        nbbs = f.get("nbbs", 0)
        cc = f.get("cc", 0)
        nargs = f.get("nargs", 0)

        entry = {
            "name": name,
            "offset": hex(offset),
            "size": size,
            "nargs": nargs,
            "nbbs": nbbs,
            "cc": cc,
        }
        func_list.append(entry)

        # Size histogram
        if size < 32: size_histogram["tiny(<32)"] += 1
        elif size < 128: size_histogram["small(32-128)"] += 1
        elif size < 512: size_histogram["medium(128-512)"] += 1
        elif size < 2048: size_histogram["large(512-2048)"] += 1
        elif size < 8192: size_histogram["huge(2048-8192)"] += 1
        else: size_histogram["massive(>8192)"] += 1

        # Complexity buckets
        if cc < 5: complexity_buckets["simple(cc<5)"] += 1
        elif cc < 15: complexity_buckets["moderate(5-15)"] += 1
        elif cc < 50: complexity_buckets["complex(15-50)"] += 1
        else: complexity_buckets["very_complex(>50)"] += 1

        # Namespace extraction from demangled-ish names
        if "nv." in name or "nv::" in name:
            # Try to extract class: sym.nv__message__get or nv::message::get
            parts = name.replace("sym.", "").replace("__", "::").split("::")
            if len(parts) >= 2:
                namespace_counter[f"nv::{parts[1]}"] += 1
            else:
                namespace_counter["nv::*"] += 1
        elif "m3." in name or "m3::" in name:
            namespace_counter["m3::*"] += 1
        elif "vl." in name or "vl::" in name:
            namespace_counter["vl::*"] += 1
        elif name.startswith("fcn.") or name.startswith("sub."):
            namespace_counter["unnamed"] += 1
        else:
            namespace_counter["other"] += 1

    results["functions"] = func_list
    results["stats"] = {
        "total_functions": len(func_list),
        "size_distribution": size_histogram,
        "complexity_distribution": complexity_buckets,
        "largest_functions": sorted(func_list, key=lambda x: x["size"], reverse=True)[:20],
        "most_complex": sorted(func_list, key=lambda x: x.get("cc", 0), reverse=True)[:20],
        "most_basic_blocks": sorted(func_list, key=lambda x: x.get("nbbs", 0), reverse=True)[:20],
    }
    results["namespaces"] = dict(namespace_counter.most_common(30))

    add_test("phase1", "libumsg_function_count",
            "Total functions in libumsg.so",
            f"{len(func_list)} functions identified by radare2",
            details={"size_distribution": size_histogram, "complexity": complexity_buckets})

    add_test("phase1", "libumsg_size_histogram",
            "Function size distribution",
            f"tiny={size_histogram['tiny(<32)']}, small={size_histogram['small(32-128)']}, "
            f"med={size_histogram['medium(128-512)']}, large={size_histogram['large(512-2048)']}, "
            f"huge={size_histogram['huge(2048-8192)']}, massive={size_histogram['massive(>8192)']}",
            details=size_histogram)

    add_test("phase1", "libumsg_complexity",
            "Function complexity distribution",
            f"simple={complexity_buckets['simple(cc<5)']}, moderate={complexity_buckets['moderate(5-15)']}, "
            f"complex={complexity_buckets['complex(15-50)']}, very_complex={complexity_buckets['very_complex(>50)']}",
            details=complexity_buckets,
            anomaly=(complexity_buckets["very_complex(>50)"] > 0))

    add_test("phase1", "libumsg_namespaces",
            "Namespace distribution",
            f"{len(namespace_counter)} distinct namespaces, top: "
            + ", ".join(f"{k}({v})" for k, v in namespace_counter.most_common(5)),
            details=dict(namespace_counter.most_common(20)))

    # ── 1.5: Top 20 largest functions ──
    for i, f in enumerate(results["stats"]["largest_functions"][:20]):
        add_test("phase1", f"libumsg_largest_{i+1:02d}_{f['name'][:30]}",
                f"Large function #{i+1}: {f['name'][:50]}",
                f"size={f['size']} bytes, cc={f.get('cc', 'N/A')}, nbbs={f.get('nbbs', 'N/A')}",
                anomaly=(f['size'] > 2048))

    # ── 1.6: Top 20 most complex functions ──
    for i, f in enumerate(results["stats"]["most_complex"][:20]):
        add_test("phase1", f"libumsg_complex_{i+1:02d}_{f['name'][:30]}",
                f"Complex function #{i+1}: {f['name'][:50]}",
                f"cc={f.get('cc', 'N/A')}, size={f['size']}, nbbs={f.get('nbbs', 'N/A')}",
                anomaly=(f.get("cc", 0) > 20))

    # ── 1.7: Import/Export counts ──
    imports = r2_json(LIBUMSG_PATH, "iij")
    exports = r2_json(LIBUMSG_PATH, "iEj")

    if imports:
        results["import_count"] = len(imports)
        add_test("phase1", "libumsg_imports",
                "Import count for libumsg.so",
                f"{len(imports)} imported functions")

    if exports:
        results["export_count"] = len(exports)
        add_test("phase1", "libumsg_exports",
                "Export count for libumsg.so",
                f"{len(exports)} exported functions")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2: Dangerous Import Cross-References (~40 tests)
# ══════════════════════════════════════════════════════════════════════════════

def phase2_dangerous_xrefs():
    """Find ALL internal callers of each dangerous import via axtj."""
    log(f"\n{'='*70}")
    log("PHASE 2: Dangerous Import Cross-References")
    log(f"{'='*70}")

    results = {
        "dangerous_call_sites": {},  # import_name -> list of callers
        "caller_summary": {},        # caller_func -> list of dangerous calls
        "hot_functions": [],         # functions calling 2+ different dangerous imports
    }

    caller_to_dangerous = defaultdict(list)

    # Run analysis once and query all PLT xrefs
    log("  Running analysis and cross-reference extraction...")

    for imp_name, imp_info in DANGEROUS_IMPORTS.items():
        plt_addr = imp_info["plt"]
        category = imp_info["category"]
        severity = imp_info["severity"]

        # Find cross-references to this PLT entry
        xref_output = r2_cmd(LIBUMSG_PATH, [
            "aaa",
            f"axtj 0x{plt_addr:x}"
        ], timeout=180)

        xrefs = None
        for line in xref_output.strip().split('\n'):
            line = line.strip()
            if line.startswith('['):
                try:
                    xrefs = json.loads(line)
                    break
                except:
                    continue

        call_sites = []
        if xrefs:
            for xref in xrefs:
                caller_addr = xref.get("from", 0)
                caller_func = xref.get("fcn_name", "unknown")
                ref_type = xref.get("type", "unknown")

                site = {
                    "caller_addr": hex(caller_addr),
                    "caller_function": caller_func,
                    "ref_type": ref_type,
                    "dangerous_import": imp_name,
                    "category": category,
                    "severity": severity,
                    "plt_addr": hex(plt_addr),
                }
                call_sites.append(site)

                # Track per-caller
                caller_to_dangerous[caller_func].append({
                    "import": imp_name,
                    "category": category,
                    "severity": severity,
                    "call_addr": hex(caller_addr),
                })

        results["dangerous_call_sites"][imp_name] = call_sites

        is_anomaly = len(call_sites) > 0
        severity_label = f"[{severity}]" if is_anomaly else ""

        add_test("phase2", f"xref_{imp_name}",
                f"Cross-references to {imp_name}() PLT@0x{plt_addr:x}",
                f"{len(call_sites)} callers found {severity_label}",
                details={
                    "plt_address": hex(plt_addr),
                    "category": category,
                    "caller_count": len(call_sites),
                    "callers": [s["caller_function"] for s in call_sites[:20]],
                },
                anomaly=is_anomaly)

        # Log individual callers for critical imports
        if imp_name in ("execve", "sprintf", "strcpy"):
            for site in call_sites:
                add_test("phase2", f"xref_{imp_name}_from_{site['caller_function'][:30]}",
                        f"{imp_name}() called from {site['caller_function']}",
                        f"at {site['caller_addr']} (type={site['ref_type']})",
                        anomaly=True,
                        details=site)

    # ── Build caller summary ──
    results["caller_summary"] = {}
    for caller, dangerous_calls in caller_to_dangerous.items():
        unique_imports = list(set(d["import"] for d in dangerous_calls))
        results["caller_summary"][caller] = {
            "dangerous_call_count": len(dangerous_calls),
            "unique_dangerous_imports": unique_imports,
            "calls": dangerous_calls,
        }

    # ── Identify hot functions (call 2+ different dangerous imports) ──
    hot_functions = []
    for caller, info in results["caller_summary"].items():
        if len(info["unique_dangerous_imports"]) >= 2:
            hot_functions.append({
                "function": caller,
                "dangerous_imports": info["unique_dangerous_imports"],
                "call_count": info["dangerous_call_count"],
            })

    hot_functions.sort(key=lambda x: x["call_count"], reverse=True)
    results["hot_functions"] = hot_functions

    add_test("phase2", "hot_functions_summary",
            "Functions calling 2+ different dangerous imports",
            f"{len(hot_functions)} hot functions identified",
            details={"hot_functions": hot_functions[:20]},
            anomaly=(len(hot_functions) > 0))

    if hot_functions:
        add_finding("HIGH",
                   f"libumsg.so: {len(hot_functions)} functions call multiple unsafe imports",
                   f"Functions calling 2+ different dangerous C functions are prime targets. "
                   f"With no NX/canary/PIE, any overflow is directly exploitable. "
                   f"Top targets: {', '.join(h['function'] for h in hot_functions[:5])} "
                   f"(each calling {', '.join(str(h['dangerous_imports'][:4]) for h in hot_functions[:5])})",
                   evidence_refs=["re_libumsg_deep.json#phase2_hot_functions"],
                   cwe="CWE-120")

    # ── Also search for additional unsafe functions by name ──
    for extra_func in ADDITIONAL_UNSAFE:
        # Find it in the function list
        afl_output = r2_cmd(LIBUMSG_PATH, ["aaa", f"afl~{extra_func}"], timeout=180)
        if afl_output.strip():
            for line in afl_output.strip().split('\n'):
                if extra_func in line:
                    parts = line.split()
                    if parts:
                        addr = parts[0]
                        xref_out = r2_cmd(LIBUMSG_PATH, [
                            "aaa", f"axtj {addr}"
                        ], timeout=120)

                        xrefs = None
                        for xline in xref_out.strip().split('\n'):
                            xline = xline.strip()
                            if xline.startswith('['):
                                try:
                                    xrefs = json.loads(xline)
                                    break
                                except:
                                    continue

                        caller_count = len(xrefs) if xrefs else 0
                        add_test("phase2", f"xref_extra_{extra_func}",
                                f"Cross-references to {extra_func}() at {addr}",
                                f"{caller_count} callers found",
                                anomaly=(caller_count > 0))

    # ── Totals ──
    total_sites = sum(len(v) for v in results["dangerous_call_sites"].values())
    add_test("phase2", "dangerous_xref_totals",
            "Total dangerous import cross-references",
            f"{total_sites} total call sites across {len(DANGEROUS_IMPORTS)} dangerous imports",
            details={k: len(v) for k, v in results["dangerous_call_sites"].items()})

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 3: Ghidra Headless Decompilation (~50 tests)
# ══════════════════════════════════════════════════════════════════════════════

def phase3_ghidra_decompilation(phase2_results):
    """Decompile all callers of execve, sprintf, strcpy, realpath and analyze C."""
    log(f"\n{'='*70}")
    log("PHASE 3: Ghidra Headless Decompilation")
    log(f"{'='*70}")

    results = {
        "execve_callers": [],
        "sprintf_callers": [],
        "strcpy_callers": [],
        "realpath_callers": [],
        "decompilation_analysis": {},
        "ghidra_raw": None,
    }

    # ── 3.1: Collect addresses of all callers to decompile ──
    all_addresses = set()
    priority_groups = {
        "execve": [],
        "sprintf": [],
        "strcpy": [],
        "realpath": [],
    }

    call_sites = phase2_results.get("dangerous_call_sites", {})

    for imp_name in ["execve", "sprintf", "strcpy", "realpath"]:
        sites = call_sites.get(imp_name, [])
        for site in sites:
            addr = site.get("caller_addr", "")
            if addr and addr != "0x0":
                all_addresses.add(addr)
                priority_groups[imp_name].append(addr)

    add_test("phase3", "decompile_target_count",
            "Functions to decompile",
            f"{len(all_addresses)} unique functions to decompile "
            f"(execve={len(priority_groups['execve'])}, sprintf={len(priority_groups['sprintf'])}, "
            f"strcpy={len(priority_groups['strcpy'])}, realpath={len(priority_groups['realpath'])})",
            details={k: len(v) for k, v in priority_groups.items()})

    if not all_addresses:
        add_test("phase3", "no_targets",
                "No decompilation targets found",
                "No callers of dangerous imports found — skipping Ghidra",
                anomaly=True)
        return results

    # ── 3.2: Run Ghidra on execve callers (HIGHEST PRIORITY) ──
    if priority_groups["execve"]:
        log(f"\n  --- Decompiling {len(priority_groups['execve'])} execve callers (CRITICAL) ---")
        execve_data = run_ghidra_decompile(
            priority_groups["execve"],
            mode="targeted",
            output_suffix="_execve"
        )

        if execve_data:
            results["execve_callers"] = execve_data.get("decompiled_functions", [])
            for func in results["execve_callers"]:
                name = func.get("name", "unknown")
                c_code = func.get("decompiled_c", "") or ""
                addr = func.get("address", "unknown")

                # Analyze C code for command injection patterns
                analysis = analyze_decompiled_c(c_code, "execve")
                results["decompilation_analysis"][f"execve_{addr}"] = analysis

                add_test("phase3", f"decomp_execve_{name[:30]}",
                        f"Decompiled execve caller: {name}",
                        f"at {addr}: {analysis.get('summary', 'no analysis')}",
                        anomaly=analysis.get("is_dangerous", False),
                        details=analysis)

                if analysis.get("is_dangerous"):
                    add_finding("CRITICAL",
                              f"libumsg.so: Potential command injection in {name}",
                              f"Function {name} at {addr} calls execve with {analysis.get('risk_reason', 'unknown risk')}. "
                              f"Decompiled C shows: {c_code[:300] if c_code else 'unavailable'}",
                              evidence_refs=[f"re_libumsg_deep.json#phase3_execve_{addr}"],
                              cwe="CWE-78")
        else:
            add_test("phase3", "ghidra_execve_failed",
                    "Ghidra decompilation of execve callers",
                    "FAILED — Ghidra did not produce output",
                    anomaly=True)

    # ── 3.3: Run Ghidra on sprintf callers ──
    if priority_groups["sprintf"]:
        log(f"\n  --- Decompiling {len(priority_groups['sprintf'])} sprintf callers ---")
        # Limit to first 30 to avoid timeout
        sprintf_addrs = priority_groups["sprintf"][:30]
        sprintf_data = run_ghidra_decompile(
            sprintf_addrs,
            mode="targeted",
            output_suffix="_sprintf"
        )

        if sprintf_data:
            results["sprintf_callers"] = sprintf_data.get("decompiled_functions", [])
            for func in results["sprintf_callers"]:
                name = func.get("name", "unknown")
                c_code = func.get("decompiled_c", "") or ""
                addr = func.get("address", "unknown")

                analysis = analyze_decompiled_c(c_code, "sprintf")
                results["decompilation_analysis"][f"sprintf_{addr}"] = analysis

                add_test("phase3", f"decomp_sprintf_{name[:30]}",
                        f"Decompiled sprintf caller: {name}",
                        f"at {addr}: {analysis.get('summary', 'no analysis')}",
                        anomaly=analysis.get("is_dangerous", False),
                        details=analysis)

                if analysis.get("is_dangerous"):
                    add_finding("HIGH",
                              f"libumsg.so: Stack buffer overflow via sprintf in {name}",
                              f"Function {name} at {addr}: {analysis.get('risk_reason', 'unknown')}. "
                              f"No stack canary — overflow overwrites return address cleanly.",
                              evidence_refs=[f"re_libumsg_deep.json#phase3_sprintf_{addr}"],
                              cwe="CWE-120")
        else:
            add_test("phase3", "ghidra_sprintf_failed",
                    "Ghidra decompilation of sprintf callers",
                    "FAILED", anomaly=True)

    # ── 3.4: Run Ghidra on strcpy callers ──
    if priority_groups["strcpy"]:
        log(f"\n  --- Decompiling {len(priority_groups['strcpy'])} strcpy callers ---")
        strcpy_addrs = priority_groups["strcpy"][:30]
        strcpy_data = run_ghidra_decompile(
            strcpy_addrs,
            mode="targeted",
            output_suffix="_strcpy"
        )

        if strcpy_data:
            results["strcpy_callers"] = strcpy_data.get("decompiled_functions", [])
            for func in results["strcpy_callers"]:
                name = func.get("name", "unknown")
                c_code = func.get("decompiled_c", "") or ""
                addr = func.get("address", "unknown")

                analysis = analyze_decompiled_c(c_code, "strcpy")
                results["decompilation_analysis"][f"strcpy_{addr}"] = analysis

                add_test("phase3", f"decomp_strcpy_{name[:30]}",
                        f"Decompiled strcpy caller: {name}",
                        f"at {addr}: {analysis.get('summary', 'no analysis')}",
                        anomaly=analysis.get("is_dangerous", False),
                        details=analysis)

                if analysis.get("is_dangerous"):
                    add_finding("HIGH",
                              f"libumsg.so: Unbounded strcpy in {name}",
                              f"Function {name} at {addr}: {analysis.get('risk_reason', 'unknown')}. "
                              f"strcpy without prior length check into stack/heap buffer.",
                              evidence_refs=[f"re_libumsg_deep.json#phase3_strcpy_{addr}"],
                              cwe="CWE-120")
        else:
            add_test("phase3", "ghidra_strcpy_failed",
                    "Ghidra decompilation of strcpy callers",
                    "FAILED", anomaly=True)

    # ── 3.5: Run Ghidra on realpath callers ──
    if priority_groups["realpath"]:
        log(f"\n  --- Decompiling {len(priority_groups['realpath'])} realpath callers ---")
        realpath_data = run_ghidra_decompile(
            priority_groups["realpath"],
            mode="targeted",
            output_suffix="_realpath"
        )

        if realpath_data:
            results["realpath_callers"] = realpath_data.get("decompiled_functions", [])
            for func in results["realpath_callers"]:
                name = func.get("name", "unknown")
                c_code = func.get("decompiled_c", "") or ""
                addr = func.get("address", "unknown")

                analysis = analyze_decompiled_c(c_code, "realpath")
                results["decompilation_analysis"][f"realpath_{addr}"] = analysis

                add_test("phase3", f"decomp_realpath_{name[:30]}",
                        f"Decompiled realpath caller: {name}",
                        f"at {addr}: {analysis.get('summary', 'no analysis')}",
                        anomaly=analysis.get("is_dangerous", False),
                        details=analysis)

                if analysis.get("is_dangerous"):
                    add_finding("MEDIUM",
                              f"libumsg.so: Path traversal via realpath in {name}",
                              f"Function {name} at {addr}: {analysis.get('risk_reason', 'unknown')}. "
                              f"realpath resolves symlinks and ../; if user controls input path, "
                              f"this enables directory traversal.",
                              evidence_refs=[f"re_libumsg_deep.json#phase3_realpath_{addr}"],
                              cwe="CWE-22")
        else:
            add_test("phase3", "ghidra_realpath_failed",
                    "Ghidra decompilation of realpath callers",
                    "FAILED", anomaly=True)

    # ── 3.6: Run Ghidra in "dangerous" mode for broad sweep ──
    log(f"\n  --- Running Ghidra 'dangerous' mode (broad sweep) ---")
    dangerous_data = run_ghidra_decompile(
        [],
        mode="dangerous",
        output_suffix="_dangerous"
    )

    if dangerous_data:
        results["ghidra_raw"] = {
            "functions_decompiled": len(dangerous_data.get("decompiled_functions", [])),
            "dangerous_call_map_size": len(dangerous_data.get("dangerous_call_map", {})),
            "metadata": dangerous_data.get("metadata", {}),
        }

        # Analyze the dangerous call map
        dcm = dangerous_data.get("dangerous_call_map", {})
        if dcm:
            add_test("phase3", "ghidra_dangerous_map",
                    "Ghidra dangerous function call map",
                    f"{len(dcm)} functions call at least one dangerous function",
                    details={"map_size": len(dcm), "sample_entries": dict(list(dcm.items())[:10])},
                    anomaly=True)

            # Find functions calling execve that we might have missed
            for addr_str, info in dcm.items():
                for dc in info.get("dangerous_calls", []):
                    if "execve" in dc.get("target", "").lower():
                        add_test("phase3", f"ghidra_execve_caller_{addr_str[:15]}",
                                f"Ghidra found execve caller at {addr_str}: {info.get('function', 'unknown')}",
                                f"Calls {dc.get('target', 'unknown')}",
                                anomaly=True)
    else:
        add_test("phase3", "ghidra_dangerous_failed",
                "Ghidra dangerous mode sweep",
                "FAILED — Ghidra not available or binary not imported",
                anomaly=True)

    # ── Summary ──
    total_decompiled = (len(results["execve_callers"]) + len(results["sprintf_callers"])
                       + len(results["strcpy_callers"]) + len(results["realpath_callers"]))
    dangerous_findings = sum(1 for v in results["decompilation_analysis"].values()
                            if v.get("is_dangerous"))

    add_test("phase3", "decompilation_summary",
            "Ghidra decompilation summary",
            f"{total_decompiled} functions decompiled, {dangerous_findings} flagged as dangerous",
            details={
                "execve_count": len(results["execve_callers"]),
                "sprintf_count": len(results["sprintf_callers"]),
                "strcpy_count": len(results["strcpy_callers"]),
                "realpath_count": len(results["realpath_callers"]),
                "dangerous_findings": dangerous_findings,
            })

    return results


def analyze_decompiled_c(c_code, sink_type):
    """Analyze decompiled C code for dangerous patterns.

    Returns analysis dict with is_dangerous flag and risk details.
    """
    if not c_code:
        return {"summary": "no decompiled code available", "is_dangerous": False}

    analysis = {
        "summary": "",
        "is_dangerous": False,
        "risk_reason": "",
        "patterns_found": [],
        "stack_buffers": [],
        "string_args": [],
    }

    # ── Check for stack buffer declarations ──
    # Match patterns like: char local_buf[256], char acStack_100[256], etc.
    stack_buf_pattern = re.compile(r'char\s+(\w+)\s*\[\s*(\d+)\s*\]')
    for match in stack_buf_pattern.finditer(c_code):
        buf_name = match.group(1)
        buf_size = int(match.group(2))
        analysis["stack_buffers"].append({"name": buf_name, "size": buf_size})

    if sink_type == "execve":
        # Look for user-controlled arguments to execve
        # Pattern: variable or function result passed as argv
        if re.search(r'execve\s*\(', c_code):
            analysis["patterns_found"].append("direct_execve_call")

            # Check if first arg is a string literal (hardcoded = less dangerous)
            execve_match = re.search(r'execve\s*\(\s*"([^"]*)"', c_code)
            if execve_match:
                cmd = execve_match.group(1)
                analysis["patterns_found"].append(f"hardcoded_cmd:{cmd}")
                analysis["string_args"].append(cmd)
                # Hardcoded command — still interesting but lower risk
                analysis["summary"] = f"execve with hardcoded command: {cmd}"
                # If the command has %s or variable interpolation, it IS dangerous
                if "%s" in c_code or "sprintf" in c_code:
                    analysis["is_dangerous"] = True
                    analysis["risk_reason"] = f"execve uses sprintf-constructed command string: {cmd}"
            else:
                # Non-literal first arg — likely variable/computed path
                analysis["is_dangerous"] = True
                analysis["risk_reason"] = "execve with non-literal (potentially user-controlled) command path"
                analysis["summary"] = "execve with computed command path"

            # Check for fork-before-execve (common pattern)
            if "fork" in c_code:
                analysis["patterns_found"].append("fork_exec_pattern")

    elif sink_type == "sprintf":
        # Look for sprintf into stack buffers
        sprintf_matches = re.findall(r'sprintf\s*\(\s*(\w+)', c_code)
        for dest_var in sprintf_matches:
            analysis["patterns_found"].append(f"sprintf_dest:{dest_var}")

            # Check if dest is a stack buffer
            for buf in analysis["stack_buffers"]:
                if buf["name"] in dest_var or dest_var in buf["name"]:
                    analysis["is_dangerous"] = True
                    analysis["risk_reason"] = (
                        f"sprintf into stack buffer {buf['name']}[{buf['size']}] — "
                        f"no bounds checking, no canary"
                    )
                    analysis["summary"] = f"sprintf into {buf['size']}-byte stack buffer"
                    break

            # Even if we can't match to a stack buffer, sprintf without snprintf is risky
            if not analysis["is_dangerous"]:
                analysis["summary"] = f"sprintf to {dest_var} (buffer size unknown)"
                # Check if there's a %s format that could overflow
                if re.search(r'sprintf\s*\([^,]+,\s*"[^"]*%s', c_code):
                    analysis["is_dangerous"] = True
                    analysis["risk_reason"] = f"sprintf with %s format into {dest_var} — unbounded string copy"

    elif sink_type == "strcpy":
        # Look for strcpy without prior strlen/length check
        strcpy_matches = re.findall(r'strcpy\s*\(\s*(\w+)', c_code)
        for dest_var in strcpy_matches:
            analysis["patterns_found"].append(f"strcpy_dest:{dest_var}")

            # Check for preceding strlen or size check
            has_length_check = bool(re.search(
                rf'(strlen|sizeof|\.size|\.length)\s*\([^)]*{re.escape(dest_var)}',
                c_code[:c_code.find(f"strcpy")]
            ))

            for buf in analysis["stack_buffers"]:
                if buf["name"] in dest_var or dest_var in buf["name"]:
                    analysis["is_dangerous"] = True
                    analysis["risk_reason"] = (
                        f"strcpy into stack buffer {buf['name']}[{buf['size']}] "
                        f"{'WITH' if has_length_check else 'WITHOUT'} prior length check"
                    )
                    break

            if not analysis["is_dangerous"] and not has_length_check:
                analysis["is_dangerous"] = True
                analysis["risk_reason"] = f"strcpy to {dest_var} without prior length check"

        analysis["summary"] = f"strcpy: {len(strcpy_matches)} calls, " \
                             f"{'DANGEROUS' if analysis['is_dangerous'] else 'appears safe'}"

    elif sink_type == "realpath":
        # Check if user input reaches realpath
        if re.search(r'realpath\s*\(', c_code):
            analysis["patterns_found"].append("realpath_call")

            # Check if result is used for file operations
            file_ops = ["open", "fopen", "stat", "access", "unlink", "rename", "chmod"]
            for op in file_ops:
                if op in c_code:
                    analysis["patterns_found"].append(f"file_op_after_realpath:{op}")

            # Check for path validation after realpath
            has_prefix_check = bool(re.search(
                r'(strncmp|startswith|memcmp|prefix)', c_code
            ))

            if not has_prefix_check:
                analysis["is_dangerous"] = True
                analysis["risk_reason"] = "realpath without path prefix validation — directory traversal possible"
            analysis["summary"] = f"realpath {'without' if not has_prefix_check else 'with'} prefix validation"

    return analysis


# ══════════════════════════════════════════════════════════════════════════════
# Phase 4: Data Flow Tracing (~30 tests)
# ══════════════════════════════════════════════════════════════════════════════

def phase4_data_flow(phase2_results):
    """Trace data flow from exports → internal functions → dangerous imports.

    Build a transitive call graph to identify "tainted" exports that can
    eventually reach execve/sprintf/strcpy.
    """
    log(f"\n{'='*70}")
    log("PHASE 4: Data Flow Tracing (Export → Sink)")
    log(f"{'='*70}")

    results = {
        "tainted_exports": [],
        "call_graph_fragments": {},
        "message_to_sink_paths": [],
        "network_input_callers": [],
    }

    # ── 4.1: Get exports list ──
    exports = r2_json(LIBUMSG_PATH, "iEj")
    if not exports:
        add_test("phase4", "exports_failed",
                "Failed to get export list", "FAILED", anomaly=True)
        return results

    # Build a set of dangerous caller function names from phase2
    dangerous_callers = set()
    for imp_name, sites in phase2_results.get("dangerous_call_sites", {}).items():
        for site in sites:
            fname = site.get("caller_function", "")
            if fname and fname != "unknown":
                dangerous_callers.add(fname)

    add_test("phase4", "dangerous_caller_set",
            "Unique functions that call dangerous imports",
            f"{len(dangerous_callers)} unique caller functions identified",
            details={"callers": list(dangerous_callers)[:30]})

    # ── 4.2: For key nv::message exports, trace call graph ──
    # Focus on message-related exports (the RPC interface)
    message_exports = []
    for exp in exports:
        name = exp.get("name", "")
        if any(kw in name.lower() for kw in ["message", "handler", "command",
                                               "cmd", "get", "set", "addobj",
                                               "removeobj", "shutdown"]):
            message_exports.append({
                "name": name,
                "vaddr": hex(exp.get("vaddr", 0)),
            })

    add_test("phase4", "message_exports",
            "Message/RPC-related exports",
            f"{len(message_exports)} message-related exports found",
            details={"exports": message_exports[:30]})

    # ── 4.3: Trace call graph from selected exports ──
    # Use r2's agCj (call graph JSON) for key functions
    trace_targets = []

    # Prioritize: nv::message exports, Handler exports, command-related
    for exp in message_exports[:15]:  # Limit to 15 to avoid timeout
        trace_targets.append(exp)

    # Also add any exports whose name suggests network handling
    for exp in exports:
        name = exp.get("name", "")
        if any(kw in name.lower() for kw in ["socket", "recv", "accept", "listen",
                                               "connect", "read", "packet",
                                               "httprequest", "fetch"]):
            if len(trace_targets) < 25:
                trace_targets.append({
                    "name": name,
                    "vaddr": hex(exp.get("vaddr", 0)),
                })

    for target in trace_targets:
        name = target["name"]
        addr = target["vaddr"]

        # Get call graph for this function
        cg_output = r2_cmd(LIBUMSG_PATH, [
            "aaa",
            f"s {addr}",
            "agCj"
        ], timeout=60)

        call_graph = None
        for line in cg_output.strip().split('\n'):
            line = line.strip()
            if line.startswith('[') or line.startswith('{'):
                try:
                    call_graph = json.loads(line)
                    break
                except:
                    continue

        if call_graph:
            # Check if any node in the call graph is a dangerous caller
            callees = set()
            if isinstance(call_graph, list):
                for node in call_graph:
                    for out in node.get("out", []):
                        callees.add(out)
                    # Also check nested
                    callees.add(node.get("name", ""))
            elif isinstance(call_graph, dict):
                for out in call_graph.get("out", []):
                    callees.add(out if isinstance(out, str) else out.get("name", ""))

            # Check if any callee is a dangerous caller
            overlap = callees & dangerous_callers
            reaches_dangerous = len(overlap) > 0

            results["call_graph_fragments"][name] = {
                "address": addr,
                "callees": list(callees)[:30],
                "reaches_dangerous": reaches_dangerous,
                "dangerous_overlap": list(overlap),
            }

            if reaches_dangerous:
                results["tainted_exports"].append({
                    "export_name": name,
                    "export_addr": addr,
                    "reachable_dangerous_funcs": list(overlap),
                })

            add_test("phase4", f"callgraph_{name[:30]}",
                    f"Call graph trace: {name[:50]}",
                    f"{len(callees)} callees, reaches_dangerous={reaches_dangerous}"
                    + (f" → [{', '.join(list(overlap)[:3])}]" if overlap else ""),
                    anomaly=reaches_dangerous,
                    details=results["call_graph_fragments"].get(name))
        else:
            add_test("phase4", f"callgraph_{name[:30]}",
                    f"Call graph trace: {name[:50]}",
                    "No call graph data (function may be too small or leaf)")

    # ── 4.4: Can nv::message::get() data reach execve? ──
    # Look for message-get → ... → execve chains
    for tainted in results["tainted_exports"]:
        for dfunc in tainted.get("reachable_dangerous_funcs", []):
            # Check which dangerous imports this function calls
            caller_info = phase2_results.get("caller_summary", {}).get(dfunc, {})
            for call in caller_info.get("calls", []):
                if call.get("import") in ("execve", "sprintf", "strcpy"):
                    path_entry = {
                        "export": tainted["export_name"],
                        "intermediate_func": dfunc,
                        "dangerous_import": call["import"],
                        "severity": call["severity"],
                    }
                    results["message_to_sink_paths"].append(path_entry)

                    add_test("phase4", f"path_{tainted['export_name'][:20]}_to_{call['import']}",
                            f"Data path: {tainted['export_name'][:30]} → {dfunc[:20]} → {call['import']}",
                            f"Export can transitively reach {call['import']}",
                            anomaly=True,
                            details=path_entry)

    if results["message_to_sink_paths"]:
        execve_paths = [p for p in results["message_to_sink_paths"]
                       if p["dangerous_import"] == "execve"]
        if execve_paths:
            add_finding("CRITICAL",
                       f"libumsg.so: {len(execve_paths)} exported APIs reach execve()",
                       f"Transitive data flow from exported message/handler APIs to execve: "
                       f"{', '.join(p['export'][:30] for p in execve_paths[:5])}. "
                       f"If network input flows through these exports, command injection is possible.",
                       evidence_refs=["re_libumsg_deep.json#phase4_message_to_sink_paths"],
                       cwe="CWE-78")

    # ── 4.5: Network input functions (recv/read/accept callers) ──
    for net_func in ["recv", "read", "recvfrom", "recvmsg", "accept"]:
        afl_out = r2_cmd(LIBUMSG_PATH, ["aaa", f"afl~{net_func}"], timeout=180)
        if afl_out.strip():
            for line in afl_out.strip().split('\n'):
                if net_func in line:
                    parts = line.split()
                    if parts:
                        addr = parts[0]
                        xref_out = r2_cmd(LIBUMSG_PATH, [
                            "aaa", f"axtj {addr}"
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
                                results["network_input_callers"].append({
                                    "network_func": net_func,
                                    "caller": xref.get("fcn_name", "unknown"),
                                    "caller_addr": hex(xref.get("from", 0)),
                                })

    add_test("phase4", "network_input_sources",
            "Network input function callers in libumsg.so",
            f"{len(results['network_input_callers'])} network input call sites",
            details={"sources": results["network_input_callers"][:20]})

    # ── 4.6: Summary ──
    add_test("phase4", "data_flow_summary",
            "Data flow analysis summary",
            f"{len(results['tainted_exports'])} tainted exports, "
            f"{len(results['message_to_sink_paths'])} export-to-sink paths, "
            f"{len(results['network_input_callers'])} network input sites",
            details={
                "tainted_export_count": len(results["tainted_exports"]),
                "path_count": len(results["message_to_sink_paths"]),
                "network_input_count": len(results["network_input_callers"]),
            },
            anomaly=(len(results["tainted_exports"]) > 0))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 5: String Analysis (~30 tests)
# ══════════════════════════════════════════════════════════════════════════════

def phase5_string_analysis():
    """Extract and categorize all strings — format strings, commands, paths."""
    log(f"\n{'='*70}")
    log("PHASE 5: String Analysis")
    log(f"{'='*70}")

    results = {
        "total_strings": 0,
        "categories": {},
        "dangerous_strings": [],
        "command_templates": [],
        "format_strings": [],
        "file_paths": [],
        "nv_field_names": [],
        "error_messages": [],
        "qr_related": [],
        "regex_patterns": [],
    }

    # ── 5.1: Extract all strings ──
    strings_data = r2_json(LIBUMSG_PATH, "izj")
    if not strings_data:
        strings_data = r2_json(LIBUMSG_PATH, "izzj")

    if not strings_data:
        add_test("phase5", "string_extraction",
                "String extraction from libumsg.so",
                "FAILED", anomaly=True)
        return results

    results["total_strings"] = len(strings_data)
    add_test("phase5", "string_count",
            "Total strings in libumsg.so",
            f"{len(strings_data)} strings extracted")

    # ── 5.2: Categorize strings ──
    categories = {
        "format_strings_pcts": [],     # %s, %d, %x patterns
        "format_strings_pctn": [],     # %n (write primitive!)
        "command_strings": [],          # /bin/*, /sbin/*, shell commands
        "file_paths": [],               # /tmp/*, /rw/*, /nova/*, /proc/*
        "error_messages": [],           # error, fail, invalid
        "nv_field_names": [],           # nv::message field identifiers
        "qr_related": [],               # QR code strings
        "regex_patterns": [],           # Regex engine strings
        "xz_related": [],               # XZ decompressor strings
        "crypto_related": [],           # Encryption/hash strings
        "network_related": [],          # IP, socket, port
        "rpc_commands": [],             # CMD_GET, CMD_SET, etc.
        "password_secrets": [],         # password, key, secret, token
        "url_patterns": [],             # http://, https://, URI patterns
    }

    interesting_patterns = {
        "format_string": re.compile(r'%[0-9*]*[sdxnpfgcluhoi]'),
        "format_n": re.compile(r'%[0-9]*n'),
        "command": re.compile(r'(/bin/|/sbin/|/usr/bin/|/usr/sbin/|/nova/bin/|sh\s+-c|exec\s)'),
        "file_path": re.compile(r'^/(tmp|rw|nova|proc|sys|dev|etc|var|lib|flash|home|ram)'),
        "error": re.compile(r'(?i)(error|fail|invalid|bad |wrong|unexpected|overflow|corrupt|denied|refused|timeout)'),
        "nv_field": re.compile(r'^[a-z][a-z0-9]*[-_][a-z]'),  # field-name style
        "qr_code": re.compile(r'(?i)(qr|barcode|matrix|encode.*code)'),
        "regex": re.compile(r'(?i)(regex|regexp|pattern|match|pcre|\(\?[imsx])'),
        "xz": re.compile(r'(?i)(xz|lzma|decompress|compress|inflate|deflate)'),
        "crypto": re.compile(r'(?i)(rc4|aes|sha|md5|hmac|encrypt|decrypt|cipher|hash|digest|key|nonce|iv)'),
        "network": re.compile(r'(?i)(socket|connect|bind|listen|accept|port|addr|inet|tcp|udp|ip)'),
        "rpc": re.compile(r'(?i)(CMD_|command|request|response|message|handler|dispatch)'),
        "password": re.compile(r'(?i)(passw|secret|token|cred|auth|login|session)'),
        "url": re.compile(r'(https?://|ftp://|wss?://|/api/|/rest/)'),
    }

    for s in strings_data:
        string_val = s.get("string", "")
        vaddr = s.get("vaddr", 0)
        section = s.get("section", "")

        if len(string_val) < 3:
            continue  # Skip very short strings

        entry = {
            "value": string_val[:200],
            "vaddr": hex(vaddr),
            "length": len(string_val),
            "section": section,
        }

        # Check each pattern
        if interesting_patterns["format_n"].search(string_val):
            categories["format_strings_pctn"].append(entry)
        if interesting_patterns["format_string"].search(string_val):
            categories["format_strings_pcts"].append(entry)
        if interesting_patterns["command"].search(string_val):
            categories["command_strings"].append(entry)
        if interesting_patterns["file_path"].search(string_val):
            categories["file_paths"].append(entry)
        if interesting_patterns["error"].search(string_val):
            categories["error_messages"].append(entry)
        if interesting_patterns["qr_code"].search(string_val):
            categories["qr_related"].append(entry)
        if interesting_patterns["regex"].search(string_val):
            categories["regex_patterns"].append(entry)
        if interesting_patterns["xz"].search(string_val):
            categories["xz_related"].append(entry)
        if interesting_patterns["crypto"].search(string_val):
            categories["crypto_related"].append(entry)
        if interesting_patterns["network"].search(string_val):
            categories["network_related"].append(entry)
        if interesting_patterns["rpc"].search(string_val):
            categories["rpc_commands"].append(entry)
        if interesting_patterns["password"].search(string_val):
            categories["password_secrets"].append(entry)
        if interesting_patterns["url"].search(string_val):
            categories["url_patterns"].append(entry)

        # nv field names — look for patterns like "name", "address", "enabled"
        # that are likely nv::message property names
        if interesting_patterns["nv_field"].search(string_val) and len(string_val) < 50:
            categories["nv_field_names"].append(entry)

    # ── 5.3: Record results ──
    results["categories"] = {k: len(v) for k, v in categories.items()}

    for cat_name, cat_entries in categories.items():
        results[cat_name] = cat_entries[:50]  # Keep first 50 per category

    add_test("phase5", "string_categories",
            "String category distribution",
            f"format_strings={len(categories['format_strings_pcts'])}, "
            f"commands={len(categories['command_strings'])}, "
            f"paths={len(categories['file_paths'])}, "
            f"errors={len(categories['error_messages'])}, "
            f"nv_fields={len(categories['nv_field_names'])}",
            details=results["categories"])

    # ── 5.4: %n format strings (CRITICAL — write primitive) ──
    if categories["format_strings_pctn"]:
        for entry in categories["format_strings_pctn"]:
            add_test("phase5", f"format_n_{entry['vaddr']}",
                    f"Format string with %n at {entry['vaddr']}",
                    f"'{entry['value'][:80]}' — WRITE PRIMITIVE",
                    anomaly=True)

        add_finding("HIGH",
                   f"libumsg.so: {len(categories['format_strings_pctn'])} format strings with %n",
                   f"Strings containing %n provide arbitrary write primitives if user input "
                   f"reaches them via sprintf/printf. With no ASLR (no PIE), target addresses "
                   f"are predictable. Strings: "
                   + "; ".join(f"'{e['value'][:60]}'" for e in categories["format_strings_pctn"][:5]),
                   evidence_refs=["re_libumsg_deep.json#phase5_format_n"],
                   cwe="CWE-134")

    # ── 5.5: Command strings (execve targets) ──
    if categories["command_strings"]:
        for entry in categories["command_strings"][:15]:
            add_test("phase5", f"cmd_string_{entry['vaddr']}",
                    f"Command string at {entry['vaddr']}",
                    f"'{entry['value'][:80]}'",
                    anomaly=True)

        results["command_templates"] = []
        # Flag strings that look like command templates (%s that get sprintf'd then execve'd)
        for entry in categories["command_strings"]:
            val = entry["value"]
            if "%s" in val or "%d" in val:
                results["command_templates"].append(entry)
                add_test("phase5", f"cmd_template_{entry['vaddr']}",
                        f"COMMAND TEMPLATE at {entry['vaddr']}",
                        f"'{val[:80]}' — contains format specifiers → sprintf→execve chain",
                        anomaly=True)

        if results["command_templates"]:
            add_finding("CRITICAL",
                       f"libumsg.so: {len(results['command_templates'])} command template strings",
                       f"Strings containing shell commands with format specifiers (e.g., '%s') suggest "
                       f"sprintf→execve patterns. If message data controls the format arguments, "
                       f"this is command injection. Templates: "
                       + "; ".join(f"'{e['value'][:60]}'" for e in results["command_templates"][:5]),
                       evidence_refs=["re_libumsg_deep.json#phase5_command_templates"],
                       cwe="CWE-78")

    add_test("phase5", "command_strings_total",
            "Command strings found",
            f"{len(categories['command_strings'])} command strings, "
            f"{len(results.get('command_templates', []))} with format specifiers")

    # ── 5.6: File paths (realpath targets) ──
    if categories["file_paths"]:
        for entry in categories["file_paths"][:10]:
            add_test("phase5", f"path_{entry['vaddr']}",
                    f"File path at {entry['vaddr']}",
                    f"'{entry['value'][:80]}'")

    add_test("phase5", "file_paths_total",
            "File path strings found",
            f"{len(categories['file_paths'])} file path strings")

    # ── 5.7: Format strings with %s (sprintf targets) ──
    pcts_strings = [e for e in categories["format_strings_pcts"]
                   if "%s" in e["value"]]
    if pcts_strings:
        add_test("phase5", "format_pcts_count",
                "Format strings with %s",
                f"{len(pcts_strings)} format strings contain %s",
                anomaly=(len(pcts_strings) > 10),
                details={"samples": [e["value"][:80] for e in pcts_strings[:10]]})

    # ── 5.8: nv::message field names ──
    if categories["nv_field_names"]:
        add_test("phase5", "nv_field_names",
                "Suspected nv::message field names",
                f"{len(categories['nv_field_names'])} potential field names",
                details={"samples": [e["value"][:60] for e in categories["nv_field_names"][:20]]})

    # ── 5.9: RPC command strings ──
    if categories["rpc_commands"]:
        add_test("phase5", "rpc_commands",
                "RPC/command-related strings",
                f"{len(categories['rpc_commands'])} RPC strings",
                details={"samples": [e["value"][:60] for e in categories["rpc_commands"][:15]]})

    # ── 5.10: QR code related ──
    if categories["qr_related"]:
        add_test("phase5", "qr_strings",
                "QR code related strings",
                f"{len(categories['qr_related'])} QR-related strings",
                details={"samples": [e["value"][:60] for e in categories["qr_related"][:10]]})

    # ── 5.11: Password/secret strings ──
    if categories["password_secrets"]:
        add_test("phase5", "password_strings",
                "Password/secret related strings",
                f"{len(categories['password_secrets'])} password/secret strings",
                anomaly=True,
                details={"samples": [e["value"][:60] for e in categories["password_secrets"][:10]]})

    # ── 5.12: URL patterns ──
    if categories["url_patterns"]:
        add_test("phase5", "url_strings",
                "URL pattern strings",
                f"{len(categories['url_patterns'])} URL strings",
                details={"samples": [e["value"][:80] for e in categories["url_patterns"][:10]]})

    # ── 5.13: Error messages (info disclosure) ──
    add_test("phase5", "error_messages",
            "Error/diagnostic messages",
            f"{len(categories['error_messages'])} error messages found",
            details={"samples": [e["value"][:80] for e in categories["error_messages"][:10]]})

    # ── 5.14: Crypto related strings ──
    if categories["crypto_related"]:
        add_test("phase5", "crypto_strings",
                "Crypto-related strings",
                f"{len(categories['crypto_related'])} crypto strings",
                details={"samples": [e["value"][:60] for e in categories["crypto_related"][:10]]})

    # ── 5.15: Cross-reference format strings to sprintf call sites ──
    # For each format string with %s, check if it's near a sprintf call
    # (This is a heuristic — proper taint analysis requires Ghidra)
    for fmt_entry in pcts_strings[:10]:
        fmt_addr = fmt_entry["vaddr"]
        xref_out = r2_cmd(LIBUMSG_PATH, [
            "aaa",
            f"axtj {fmt_addr}"
        ], timeout=60)

        xrefs = None
        for line in xref_out.strip().split('\n'):
            line = line.strip()
            if line.startswith('['):
                try:
                    xrefs = json.loads(line)
                    break
                except:
                    continue

        if xrefs:
            for xref in xrefs:
                caller = xref.get("fcn_name", "unknown")
                add_test("phase5", f"fmtstr_xref_{fmt_addr}_{caller[:20]}",
                        f"Format string '{fmt_entry['value'][:40]}' used by {caller}",
                        f"Xref from {caller} at {hex(xref.get('from', 0))}",
                        anomaly=True)

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Phase 6: Cross-Binary Analysis (~30 tests)
# ══════════════════════════════════════════════════════════════════════════════

def phase6_cross_binary(phase2_results, phase4_results):
    """Identify which binaries link to libumsg.so and map dangerous paths to
    network-facing services.
    """
    log(f"\n{'='*70}")
    log("PHASE 6: Cross-Binary Analysis")
    log(f"{'='*70}")

    results = {
        "linking_binaries": [],
        "network_binaries_linking": [],
        "dangerous_path_mapping": [],
    }

    # ── 6.1: Find all binaries that link to libumsg.so ──
    log("  Scanning squashfs-root for binaries linking to libumsg.so...")

    # Search in nova/bin, nova/lib, lib, sbin, bin
    search_dirs = [
        SQUASHFS / "nova" / "bin",
        SQUASHFS / "nova" / "lib",
        SQUASHFS / "lib",
        SQUASHFS / "sbin",
        SQUASHFS / "bin",
        SQUASHFS / "usr" / "bin",
        SQUASHFS / "usr" / "sbin",
    ]

    all_binaries = []
    for search_dir in search_dirs:
        if search_dir.exists():
            for fpath in search_dir.iterdir():
                if fpath.is_file() and not fpath.is_symlink():
                    all_binaries.append(fpath)

    add_test("phase6", "binary_scan",
            "Total binaries found in squashfs-root",
            f"{len(all_binaries)} executable files found across search directories")

    # Check each binary for libumsg.so linkage
    linking_binaries = []
    for binary_path in all_binaries:
        try:
            # Use r2 to check imports/libraries
            il_output = r2_cmd(binary_path, ["il"], timeout=15)
            if "libumsg" in il_output.lower():
                linking_binaries.append({
                    "name": binary_path.name,
                    "path": str(binary_path),
                    "relative_path": str(binary_path.relative_to(SQUASHFS)),
                })
        except Exception:
            pass

    # Fallback: also try readelf -d for more reliable results
    for binary_path in all_binaries:
        if binary_path.name not in [b["name"] for b in linking_binaries]:
            try:
                result = subprocess.run(
                    ["readelf", "-d", str(binary_path)],
                    capture_output=True, text=True, timeout=10
                )
                if "libumsg" in result.stdout.lower():
                    linking_binaries.append({
                        "name": binary_path.name,
                        "path": str(binary_path),
                        "relative_path": str(binary_path.relative_to(SQUASHFS)),
                    })
            except Exception:
                pass

    # Deduplicate
    seen_names = set()
    unique_linking = []
    for b in linking_binaries:
        if b["name"] not in seen_names:
            seen_names.add(b["name"])
            unique_linking.append(b)

    results["linking_binaries"] = unique_linking

    add_test("phase6", "linking_binary_count",
            "Binaries linking to libumsg.so",
            f"{len(unique_linking)} binaries link to libumsg.so",
            details={"binaries": [b["name"] for b in unique_linking]})

    # ── 6.2: Identify network-facing binaries ──
    network_linking = []
    for binary in unique_linking:
        name_lower = binary["name"].lower()
        is_network = any(net in name_lower for net in NETWORK_BINARIES)
        if is_network:
            network_linking.append(binary)

    results["network_binaries_linking"] = network_linking

    add_test("phase6", "network_binaries",
            "Network-facing binaries linking to libumsg.so",
            f"{len(network_linking)} network-facing binaries: "
            + ", ".join(b["name"] for b in network_linking[:15]),
            details={"network_binaries": [b["name"] for b in network_linking]},
            anomaly=(len(network_linking) > 0))

    # ── 6.3: For each network-facing binary, check which dangerous exports it uses ──
    tainted_exports = phase4_results.get("tainted_exports", [])
    tainted_export_names = [e["export_name"] for e in tainted_exports]

    for binary in network_linking[:10]:  # Limit to 10 to avoid long runtime
        binary_path = Path(binary["path"])
        if not binary_path.exists():
            continue

        # Get this binary's imports from libumsg.so
        imports = r2_json(binary_path, "iij")
        if not imports:
            continue

        # Check which imports match tainted libumsg exports
        imported_tainted = []
        for imp in imports:
            imp_name = imp.get("name", "")
            for tainted_name in tainted_export_names:
                if tainted_name in imp_name or imp_name in tainted_name:
                    imported_tainted.append({
                        "import_name": imp_name,
                        "tainted_export": tainted_name,
                        "binary": binary["name"],
                    })

        if imported_tainted:
            results["dangerous_path_mapping"].extend(imported_tainted)
            add_test("phase6", f"tainted_imports_{binary['name'][:20]}",
                    f"Tainted libumsg imports in {binary['name']}",
                    f"{len(imported_tainted)} tainted exports imported",
                    anomaly=True,
                    details={"tainted_imports": imported_tainted[:10]})
        else:
            add_test("phase6", f"tainted_imports_{binary['name'][:20]}",
                    f"Tainted libumsg imports in {binary['name']}",
                    "No known tainted exports imported")

    # ── 6.4: Check which binaries also import execve/sprintf/strcpy directly ──
    direct_dangerous_binaries = []
    for binary in unique_linking[:30]:
        binary_path = Path(binary["path"])
        if not binary_path.exists():
            continue

        imports = r2_json(binary_path, "iij")
        if not imports:
            continue

        dangerous_direct = []
        for imp in imports:
            name = imp.get("name", "").lower()
            for danger in ["execve", "sprintf", "strcpy", "system", "popen"]:
                if danger == name or name.endswith(f".{danger}"):
                    dangerous_direct.append(name)

        if dangerous_direct:
            direct_dangerous_binaries.append({
                "binary": binary["name"],
                "dangerous_imports": list(set(dangerous_direct)),
            })

    if direct_dangerous_binaries:
        add_test("phase6", "direct_dangerous_imports",
                "Binaries with direct dangerous imports (not via libumsg)",
                f"{len(direct_dangerous_binaries)} binaries also import dangerous functions directly",
                details={"binaries": direct_dangerous_binaries[:15]},
                anomaly=True)

    # ── 6.5: Build the final mapping: dangerous_function → exported_API → binary → service ──
    attack_map = []
    dangerous_sites = phase2_results.get("dangerous_call_sites", {})

    for imp_name in ["execve", "sprintf", "strcpy"]:
        sites = dangerous_sites.get(imp_name, [])
        for site in sites:
            caller = site.get("caller_function", "unknown")

            # Find which export this caller belongs to (if any)
            matching_export = None
            for tainted in tainted_exports:
                if caller in [f for f in tainted.get("reachable_dangerous_funcs", [])]:
                    matching_export = tainted["export_name"]
                    break

            # Find which binaries might trigger this
            triggering_binaries = []
            if matching_export:
                for mapping in results["dangerous_path_mapping"]:
                    if mapping.get("tainted_export") == matching_export:
                        triggering_binaries.append(mapping["binary"])

            if matching_export or triggering_binaries:
                attack_map.append({
                    "dangerous_import": imp_name,
                    "internal_function": caller,
                    "exported_api": matching_export,
                    "triggering_binaries": list(set(triggering_binaries)),
                })

    results["attack_map"] = attack_map

    if attack_map:
        add_test("phase6", "attack_map",
                "Complete attack path mapping",
                f"{len(attack_map)} end-to-end attack paths identified",
                details={"paths": attack_map[:15]},
                anomaly=True)

        add_finding("HIGH",
                   f"libumsg.so: {len(attack_map)} end-to-end attack paths to dangerous sinks",
                   f"Mapping: dangerous_function → libumsg_export → network_binary. "
                   f"These paths connect network-facing services to dangerous C functions "
                   f"through the libumsg IPC backbone. Top paths: "
                   + "; ".join(f"{p['dangerous_import']}←{p['internal_function'][:20]}←"
                              f"{p.get('exported_api', 'unknown')[:20]}←"
                              f"{','.join(p.get('triggering_binaries', ['?'])[:2])}"
                              for p in attack_map[:5]),
                   evidence_refs=["re_libumsg_deep.json#phase6_attack_map"],
                   cwe="CWE-78")

    # ── 6.6: Summary statistics ──
    add_test("phase6", "cross_binary_summary",
            "Cross-binary analysis summary",
            f"{len(unique_linking)} linking binaries, "
            f"{len(network_linking)} network-facing, "
            f"{len(results['dangerous_path_mapping'])} tainted import connections, "
            f"{len(attack_map)} end-to-end paths")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# GOT/PLT & ROP Analysis
# ══════════════════════════════════════════════════════════════════════════════

def analyze_got_plt():
    """Analyze GOT/PLT entries — format string write targets."""
    log(f"\n{'='*70}")
    log("SUPPLEMENTAL: GOT/PLT & Relocation Analysis")
    log(f"{'='*70}")

    results = {"got_entries": [], "interesting_got": []}

    relocs = r2_json(LIBUMSG_PATH, "irj")
    if relocs:
        for r in relocs:
            entry = {
                "name": r.get("name", ""),
                "vaddr": hex(r.get("vaddr", 0)),
                "type": r.get("type", ""),
            }
            results["got_entries"].append(entry)

        # Find GOT entries for critical functions
        interesting = []
        for r in relocs:
            name = r.get("name", "").lower()
            if any(f in name for f in ["system", "exec", "popen", "sprintf",
                                        "printf", "puts", "exit", "free",
                                        "malloc", "strcpy"]):
                interesting.append({
                    "name": r.get("name"),
                    "got_addr": hex(r.get("vaddr", 0)),
                })

        results["interesting_got"] = interesting

        add_test("supplemental", "got_entries",
                "GOT entries in libumsg.so",
                f"{len(relocs)} relocation entries, {len(interesting)} interesting targets",
                details={"interesting": interesting},
                anomaly=(len(interesting) > 0))

        if interesting:
            add_test("supplemental", "got_targets",
                    "Writable GOT entries (format string targets)",
                    f"Targets: {', '.join(e['name'] for e in interesting[:10])}",
                    anomaly=True)

    return results


def analyze_rop_gadgets():
    """Quick ROP gadget survey — relevant since no NX."""
    log(f"\n--- ROP Gadget Survey ---")

    results = {"gadget_count": 0, "useful_gadgets": []}

    output = r2_cmd(LIBUMSG_PATH, ["/R ret"], timeout=30)

    if output:
        lines = [l for l in output.strip().split('\n') if l.strip()]
        results["gadget_count"] = len(lines)

        useful_patterns = [
            "pop.*ret", "mov esp.*ret", "call.*eax",
            "call.*edx", "jmp.*esp", "jmp.*eax",
            "int 0x80", "sysenter",
        ]

        for line in lines[:500]:
            for pattern in useful_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    results["useful_gadgets"].append(line.strip()[:100])
                    break

    add_test("supplemental", "rop_gadgets",
            "ROP gadget survey for libumsg.so",
            f"{results['gadget_count']} total gadgets, "
            f"{len(results['useful_gadgets'])} useful patterns",
            anomaly=(results['gadget_count'] > 50))

    return results


# ══════════════════════════════════════════════════════════════════════════════
# Main Execution
# ══════════════════════════════════════════════════════════════════════════════

def main():
    start_time = datetime.now()

    log("=" * 70)
    log("MikroTik RouterOS libumsg.so — Deep Static Reverse Engineering")
    log(f"Start time: {start_time.isoformat()}")
    log(f"Target: {LIBUMSG_PATH}")
    log(f"File exists: {LIBUMSG_PATH.exists()}")
    log("=" * 70)

    if not LIBUMSG_PATH.exists():
        log(f"FATAL: Target binary not found at {LIBUMSG_PATH}")
        sys.exit(1)

    all_results = {}

    # ── Phase 1: Full function listing (~20 tests) ──
    phase1_results = phase1_function_listing()
    all_results["phase1"] = phase1_results

    # ── Phase 2: Dangerous import cross-references (~40 tests) ──
    phase2_results = phase2_dangerous_xrefs()
    all_results["phase2"] = phase2_results

    # ── Phase 3: Ghidra headless decompilation (~50 tests) ──
    phase3_results = phase3_ghidra_decompilation(phase2_results)
    all_results["phase3"] = phase3_results

    # ── Phase 4: Data flow tracing (~30 tests) ──
    phase4_results = phase4_data_flow(phase2_results)
    all_results["phase4"] = phase4_results

    # ── Phase 5: String analysis (~30 tests) ──
    phase5_results = phase5_string_analysis()
    all_results["phase5"] = phase5_results

    # ── Phase 6: Cross-binary analysis (~30 tests) ──
    phase6_results = phase6_cross_binary(phase2_results, phase4_results)
    all_results["phase6"] = phase6_results

    # ── Supplemental: GOT/PLT & ROP ──
    got_results = analyze_got_plt()
    all_results["got_plt"] = got_results

    rop_results = analyze_rop_gadgets()
    all_results["rop"] = rop_results

    # ── Save evidence ──
    end_time = datetime.now()
    elapsed = (end_time - start_time).total_seconds()

    evidence = {
        "metadata": {
            "script": "re_libumsg_deep.py",
            "phase": "Deep Static RE — libumsg.so IPC backbone",
            "target_binary": str(LIBUMSG_PATH),
            "target_size_bytes": LIBUMSG_PATH.stat().st_size,
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
            "phase1_functions": {
                "total_functions": phase1_results.get("stats", {}).get("total_functions", 0),
                "size_distribution": phase1_results.get("stats", {}).get("size_distribution", {}),
                "complexity_distribution": phase1_results.get("stats", {}).get("complexity_distribution", {}),
                "namespaces": phase1_results.get("namespaces", {}),
                "largest_functions": phase1_results.get("stats", {}).get("largest_functions", [])[:10],
                "most_complex": phase1_results.get("stats", {}).get("most_complex", [])[:10],
                "import_count": phase1_results.get("import_count", 0),
                "export_count": phase1_results.get("export_count", 0),
            },
            "phase2_dangerous_xrefs": {
                "dangerous_call_sites": {
                    k: len(v) for k, v in phase2_results.get("dangerous_call_sites", {}).items()
                },
                "dangerous_call_details": {
                    k: v[:20] for k, v in phase2_results.get("dangerous_call_sites", {}).items()
                },
                "hot_functions": phase2_results.get("hot_functions", [])[:20],
                "caller_summary": {
                    k: v for k, v in list(phase2_results.get("caller_summary", {}).items())[:30]
                },
            },
            "phase3_decompilation": {
                "execve_callers_count": len(phase3_results.get("execve_callers", [])),
                "sprintf_callers_count": len(phase3_results.get("sprintf_callers", [])),
                "strcpy_callers_count": len(phase3_results.get("strcpy_callers", [])),
                "realpath_callers_count": len(phase3_results.get("realpath_callers", [])),
                "decompilation_analysis": phase3_results.get("decompilation_analysis", {}),
                "ghidra_raw_summary": phase3_results.get("ghidra_raw", {}),
                # Store decompiled C code for critical functions (truncated)
                "execve_decompiled": [
                    {
                        "name": f.get("name", "unknown"),
                        "address": f.get("address", "unknown"),
                        "decompiled_c": (f.get("decompiled_c", "") or "")[:2000],
                        "dangerous_calls": f.get("dangerous_calls", []),
                        "stack_frame_size": f.get("stack_frame_size", 0),
                    }
                    for f in phase3_results.get("execve_callers", [])
                ],
                "sprintf_decompiled": [
                    {
                        "name": f.get("name", "unknown"),
                        "address": f.get("address", "unknown"),
                        "decompiled_c": (f.get("decompiled_c", "") or "")[:1000],
                        "dangerous_calls": f.get("dangerous_calls", []),
                        "stack_frame_size": f.get("stack_frame_size", 0),
                    }
                    for f in phase3_results.get("sprintf_callers", [])[:20]
                ],
            },
            "phase4_data_flow": {
                "tainted_exports": phase4_results.get("tainted_exports", []),
                "message_to_sink_paths": phase4_results.get("message_to_sink_paths", []),
                "network_input_callers": phase4_results.get("network_input_callers", [])[:20],
                "call_graph_fragment_count": len(phase4_results.get("call_graph_fragments", {})),
            },
            "phase5_strings": {
                "total_strings": phase5_results.get("total_strings", 0),
                "categories": phase5_results.get("categories", {}),
                "command_templates": phase5_results.get("command_templates", [])[:20],
                "format_strings_pctn": phase5_results.get("format_strings_pctn", [])[:10],
                "command_strings": phase5_results.get("command_strings", [])[:20],
                "file_paths": phase5_results.get("file_paths", [])[:20],
                "nv_field_names": phase5_results.get("nv_field_names", [])[:30],
                "password_secrets": phase5_results.get("password_secrets", [])[:10],
                "rpc_commands": phase5_results.get("rpc_commands", [])[:15],
            },
            "phase6_cross_binary": {
                "total_linking_binaries": len(phase6_results.get("linking_binaries", [])),
                "linking_binary_names": [b["name"] for b in phase6_results.get("linking_binaries", [])],
                "network_binaries": [b["name"] for b in phase6_results.get("network_binaries_linking", [])],
                "dangerous_path_mapping": phase6_results.get("dangerous_path_mapping", [])[:20],
                "attack_map": phase6_results.get("attack_map", [])[:20],
            },
            "got_plt": got_results,
            "rop": rop_results,
        },
    }

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = EVIDENCE_DIR / "re_libumsg_deep.json"
    with open(out_file, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    # ── Final Summary ──
    log(f"\n{'='*70}")
    log("ANALYSIS COMPLETE: libumsg.so Deep Static RE")
    log(f"{'='*70}")
    log(f"Total tests: {test_count}")
    log(f"Anomalies: {anomaly_count}")
    log(f"Findings: {len(findings)}")
    log(f"Elapsed: {elapsed:.1f}s")
    log(f"Evidence: {out_file}")

    if findings:
        log(f"\n--- Findings ---")
        for f in sorted(findings, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["severity"], 5)):
            log(f"  [{f['severity']}] {f['title']}")

    log(f"\nEnd time: {end_time.isoformat()}")


if __name__ == "__main__":
    main()
