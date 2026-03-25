#!/usr/bin/env python3
"""
TendaAssmt Phase 1b: Systematic dangerous sink mapping for ALL handlers.
Maps every form* handler to its dangerous function calls.
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime

sys.path.insert(0, '/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/scripts')
from tenda_common import EvidenceCollector

BINDIR = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Tenda/firmware/binaries"
WEBSGETVAR_WRAPPER = "fcn.0002bd4c"  # AC15 websGetVar wrapper address

def run_r2(binary, commands, timeout=300):
    if isinstance(commands, list):
        commands = ";".join(commands)
    try:
        result = subprocess.run(
            ["r2", "-q", "-e", "bin.cache=true", "-e", "scr.color=0",
             "-c", commands, binary],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""

def analyze_handler(binary, handler_name, model):
    """Full analysis of a handler function for dangerous patterns."""
    output = run_r2(binary, f"aaa; s sym.{handler_name}; pdf")
    if not output:
        return None

    # Count dangerous function calls
    sinks = {}
    for pattern in ["strcpy", "strcat", "sprintf", "vsprintf",
                    "system", "popen", "doSystemCmd", "execve"]:
        count = len(re.findall(rf"bl sym\.imp\.{pattern}\b", output))
        if count > 0:
            sinks[pattern] = count

    # Count safe alternatives
    safe = {}
    for pattern in ["strncpy", "strncat", "snprintf"]:
        count = len(re.findall(rf"bl sym\.imp\.{pattern}\b", output))
        if count > 0:
            safe[pattern] = count

    # Count user input calls (websGetVar wrapper)
    input_calls = len(re.findall(r"bl fcn\.0002bd4c", output))  # AC15
    if input_calls == 0:
        input_calls = len(re.findall(r"bl fcn\.", output))  # Generic fallback

    # Extract parameter names
    params = re.findall(r'"([^"]+)"', output)
    # Filter to likely parameter names (not format strings, not file paths)
    param_names = [p for p in params if not p.startswith('/') and not p.startswith('%')
                   and not p.startswith('iptables') and len(p) < 50 and '.' not in p
                   and p != "0" and p != "1" and not p.startswith('0x')]

    # Get stack frame size
    frame_match = re.search(r"sub sp, sp, (0x[0-9a-f]+)", output)
    frame_size = int(frame_match.group(1), 16) if frame_match else 0

    # Check for doSystemCmd format strings (potential command injection)
    cmd_injection_strings = []
    for m in re.finditer(r'"([^"]*%s[^"]*)"', output):
        s = m.group(1)
        if any(kw in s for kw in ["iptables", "route", "echo", "kill", "ifconfig",
                                   "insmod", "rmmod", "iwpriv", "telnetd", "reboot",
                                   "rm ", "cp ", "mv ", "cat ", "grep "]):
            cmd_injection_strings.append(s)

    return {
        "handler": handler_name,
        "model": model,
        "dangerous_sinks": sinks,
        "safe_functions": safe,
        "user_input_calls": input_calls,
        "param_names": list(set(param_names)),
        "stack_frame_size": frame_size,
        "cmd_injection_strings": cmd_injection_strings,
        "total_dangerous": sum(sinks.values()),
        "has_user_input": input_calls > 0,
        "has_dangerous_sink": sum(sinks.values()) > 0
    }

def main():
    ec = EvidenceCollector("phase1b_sink_mapper")

    for model, binary_name in [("AC15", "httpd_ac15"), ("AC20", "httpd_ac20")]:
        binary = os.path.join(BINDIR, binary_name)
        print(f"\n{'='*70}")
        print(f"SINK MAPPING: {model} ({binary_name})")
        print(f"{'='*70}")

        # Get all form handlers
        sym_output = run_r2(binary, "is")
        handlers = []
        for line in sym_output.splitlines():
            m = re.search(r'FUNC\s+(\d+)\s+(form\w+)', line)
            if m:
                handlers.append((m.group(2), int(m.group(1))))

        print(f"[*] Analyzing {len(handlers)} handlers...")

        all_results = []
        high_risk = []

        for handler_name, size in sorted(handlers, key=lambda x: x[1], reverse=True):
            result = analyze_handler(binary, handler_name, model)
            if result is None:
                continue

            all_results.append(result)

            if result["total_dangerous"] > 0:
                risk = "HIGH" if result["has_user_input"] and result["has_dangerous_sink"] else "MEDIUM"
                if result.get("cmd_injection_strings"):
                    risk = "CRITICAL"

                high_risk.append(result)
                marker = "!!" if risk == "CRITICAL" else "! " if risk == "HIGH" else "  "
                print(f"  [{marker}] {handler_name}: "
                      f"sinks={result['dangerous_sinks']}, "
                      f"inputs={result['user_input_calls']}, "
                      f"frame={result['stack_frame_size']}")

                if result.get("cmd_injection_strings"):
                    for cs in result["cmd_injection_strings"][:3]:
                        print(f"       CMD: {cs[:80]}")

                # Record finding
                ec.add_finding(
                    f"{model}-{handler_name}-SINK",
                    risk,
                    f"{handler_name}: {result['total_dangerous']} dangerous sink(s) with {result['user_input_calls']} input sources",
                    json.dumps(result, indent=2),
                    cwe="CWE-78" if result.get("cmd_injection_strings") else "CWE-120",
                    endpoint=f"/goform/{handler_name.replace('form', '', 1) if handler_name.startswith('form') else handler_name}"
                )

        # Summary
        print(f"\n[*] {model} Summary:")
        print(f"    Total handlers: {len(all_results)}")
        print(f"    Handlers with dangerous sinks: {len(high_risk)}")
        print(f"    Handlers with both input + dangerous sink: "
              f"{sum(1 for r in high_risk if r['has_user_input'] and r['has_dangerous_sink'])}")
        print(f"    Handlers with cmd injection patterns: "
              f"{sum(1 for r in high_risk if r.get('cmd_injection_strings'))}")

        ec.add_test(
            f"{model}-SINK-MAP",
            f"Complete dangerous sink mapping for {len(all_results)} handlers",
            f"r2 disassembly analysis of all form* functions",
            json.dumps({
                "total": len(all_results),
                "with_sinks": len(high_risk),
                "results": all_results
            }, indent=2),
            status="INFO"
        )

    ec.save("phase1b_sink_mapper.json")
    print(f"\n[*] Phase 1b complete. Evidence saved.")

if __name__ == "__main__":
    main()
