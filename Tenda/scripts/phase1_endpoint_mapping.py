#!/usr/bin/env python3
"""
TendaAssmt Phase 1a: Complete goform endpoint enumeration and dangerous sink mapping
Maps ALL /goform/ handlers to their function addresses and analyzes dangerous sinks.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/scripts')
from tenda_common import EvidenceCollector, EVIDENCE_DIR

BINDIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/binaries"

def run_r2(binary, commands, timeout=180):
    """Run r2 commands on a binary."""
    if isinstance(commands, list):
        commands = ";".join(commands)
    try:
        result = subprocess.run(
            ["r2", "-q", "-e", "bin.cache=true", "-c", commands, binary],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception as e:
        return f"ERROR: {e}"

def get_form_handlers(binary):
    """Extract all form* handler functions from symbol table."""
    output = run_r2(binary, "is")
    handlers = {}
    for line in output.splitlines():
        m = re.search(r'0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+GLOBAL\s+FUNC\s+(\d+)\s+(form\w+)', line)
        if m:
            handlers[m.group(4)] = {
                "paddr": f"0x{m.group(1)}",
                "vaddr": f"0x{m.group(2)}",
                "size": int(m.group(3)),
                "name": m.group(4)
            }
    return handlers

def get_all_symbols(binary):
    """Extract all exported symbols."""
    output = run_r2(binary, "is")
    symbols = {}
    for line in output.splitlines():
        m = re.search(r'0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+GLOBAL\s+(FUNC|OBJ)\s+(\d+)\s+(\w+)', line)
        if m:
            symbols[m.group(5)] = {
                "vaddr": f"0x{m.group(2)}",
                "type": m.group(3),
                "size": int(m.group(4))
            }
    return symbols

def get_dangerous_imports(binary):
    """Find dangerous function imports."""
    output = run_r2(binary, "ii")
    dangerous = {
        "strcpy": None, "strcat": None, "sprintf": None, "vsprintf": None, "gets": None,
        "system": None, "popen": None, "doSystemCmd": None, "execve": None, "twsystem": None,
        "websGetVar": None, "strncpy": None, "snprintf": None
    }
    for line in output.splitlines():
        for func_name in dangerous:
            if func_name in line:
                m = re.search(r'0x([0-9a-f]+)', line)
                if m:
                    dangerous[func_name] = f"0x{m.group(1)}"
    return {k: v for k, v in dangerous.items() if v is not None}

def find_xrefs_to_import(binary, import_name, timeout=180):
    """Find cross-references to an imported function."""
    # First find the PLT entry
    output = run_r2(binary, f"aaa; axt @ sym.imp.{import_name}", timeout=timeout)
    xrefs = []
    for line in output.splitlines():
        m = re.search(r'(\w+)\s+0x([0-9a-f]+)', line)
        if m:
            xrefs.append({
                "caller": m.group(1),
                "addr": f"0x{m.group(2)}"
            })
    return xrefs

def analyze_handler_sinks(binary, handler_name, handler_vaddr, handler_size):
    """Analyze a handler function for dangerous sink calls."""
    # Disassemble the function and look for BL/JAL to dangerous functions
    output = run_r2(binary, [
        "aaa",
        f"s {handler_vaddr}",
        f"pd {handler_size // 4}"  # ARM/MIPS instructions are 4 bytes
    ], timeout=300)

    sinks = {
        "strcpy": 0, "strcat": 0, "sprintf": 0, "system": 0,
        "popen": 0, "doSystemCmd": 0, "websGetVar": 0,
        "strncpy": 0, "snprintf": 0, "execve": 0
    }

    for line in output.splitlines():
        for func_name in sinks:
            if func_name in line and ("bl " in line.lower() or "jal " in line.lower() or "call" in line.lower()):
                sinks[func_name] += 1

    return {k: v for k, v in sinks.items() if v > 0}

def main():
    ec = EvidenceCollector("phase1_endpoint_mapping")

    for model, binary_name in [("AC15", "httpd_ac15"), ("AC20", "httpd_ac20")]:
        binary = os.path.join(BINDIR, binary_name)
        print(f"\n{'='*60}")
        print(f"Analyzing {model} ({binary_name})")
        print(f"{'='*60}")

        # Get all form handlers
        handlers = get_form_handlers(binary)
        print(f"\n[*] Found {len(handlers)} form* handler functions")

        # Sort by size (larger = more complex = more bugs)
        sorted_handlers = sorted(handlers.items(), key=lambda x: x[1]['size'], reverse=True)

        # Print handler table
        print(f"\n{'Handler':<45} {'VAddr':<12} {'Size':>6}")
        print("-" * 65)
        for name, info in sorted_handlers:
            print(f"{name:<45} {info['vaddr']:<12} {info['size']:>6}")

        ec.add_test(
            f"{model}-HANDLERS",
            f"Enumerated {len(handlers)} form* handler functions in {binary_name}",
            f"r2 -c 'is' {binary_name} | grep form",
            json.dumps({name: info for name, info in sorted_handlers}, indent=2),
            status="INFO"
        )

        # Get dangerous imports
        imports = get_dangerous_imports(binary)
        print(f"\n[*] Dangerous imports found: {list(imports.keys())}")

        ec.add_test(
            f"{model}-IMPORTS",
            f"Dangerous function imports in {binary_name}",
            f"r2 -c 'ii' {binary_name}",
            json.dumps(imports, indent=2),
            status="INFO"
        )

        # Analyze top 20 largest handlers for dangerous sinks
        print(f"\n[*] Analyzing top 20 largest handlers for dangerous sinks...")
        print(f"{'Handler':<40} {'Size':>6} {'strcpy':>7} {'sprintf':>8} {'system':>7} {'doSysCmd':>9} {'websGet':>8}")
        print("-" * 85)

        high_risk = []
        for name, info in sorted_handlers[:20]:
            sinks = analyze_handler_sinks(binary, name, info['vaddr'], info['size'])

            print(f"{name:<40} {info['size']:>6} {sinks.get('strcpy',0):>7} {sinks.get('sprintf',0):>8} "
                  f"{sinks.get('system',0):>7} {sinks.get('doSystemCmd',0):>9} {sinks.get('websGetVar',0):>8}")

            # Flag high-risk: has user input AND dangerous sink
            has_input = sinks.get('websGetVar', 0) > 0
            has_unsafe = (sinks.get('strcpy', 0) + sinks.get('sprintf', 0) +
                         sinks.get('system', 0) + sinks.get('doSystemCmd', 0)) > 0

            if has_input and has_unsafe:
                risk_info = {
                    "handler": name,
                    "model": model,
                    "vaddr": info['vaddr'],
                    "size": info['size'],
                    "sinks": sinks,
                    "risk": "HIGH - User input flows to dangerous sink"
                }
                high_risk.append(risk_info)
                ec.add_finding(
                    f"{model}-{name}-RISK",
                    "HIGH",
                    f"{name}: User input (websGetVar) flows to dangerous sink(s)",
                    json.dumps(risk_info, indent=2),
                    cwe="CWE-120" if sinks.get('strcpy', 0) > 0 else "CWE-78",
                    endpoint=f"/goform/{name.replace('form', '', 1) if name.startswith('form') else name}"
                )

        if high_risk:
            print(f"\n[!] {len(high_risk)} HIGH-RISK handlers found in {model}:")
            for r in high_risk:
                print(f"    - {r['handler']}: {r['sinks']}")

        # Get all symbols for additional context
        all_symbols = get_all_symbols(binary)
        non_form = {k: v for k, v in all_symbols.items() if not k.startswith('form') and v['type'] == 'FUNC'}

        # Look for interesting non-form functions
        interesting_patterns = ['R7', 'auth', 'login', 'check', 'verify', 'password', 'cgi_', 'cmd', 'exec', 'telnet']
        interesting_funcs = {}
        for name, info in non_form.items():
            for pattern in interesting_patterns:
                if pattern.lower() in name.lower():
                    interesting_funcs[name] = info
                    break

        if interesting_funcs:
            print(f"\n[*] Interesting non-form functions ({len(interesting_funcs)}):")
            for name, info in sorted(interesting_funcs.items()):
                print(f"    {name}: {info['vaddr']} (size: {info['size']})")

            ec.add_test(
                f"{model}-INTERESTING-FUNCS",
                f"Non-form interesting functions in {binary_name}",
                "Symbol table analysis",
                json.dumps(interesting_funcs, indent=2),
                status="INFO"
            )

    # Save evidence
    ec.save("phase1_endpoint_mapping.json")

if __name__ == "__main__":
    main()
