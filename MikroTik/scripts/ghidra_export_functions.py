#!/usr/bin/env python3
# Ghidra headless postScript — Decompile functions at specified addresses
# and export to JSON.
#
# Usage (headless):
#   analyzeHeadless <project_dir> <project_name> \
#     -process <binary> \
#     -postScript ghidra_export_functions.py \
#     -scriptPath /home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts \
#     -propertiesPath /home/[REDACTED]/Desktop/[REDACTED-PATH]/MikroTik/scripts
#
# Script arguments are passed via .properties file or GHIDRA_SCRIPT_PROPS env:
#   ghidra_export_functions.ADDRESSES = 0x0805c906,0x08052666,...
#   ghidra_export_functions.OUTPUT = /path/to/output.json
#   ghidra_export_functions.MODE = targeted|all|dangerous
#
# Modes:
#   targeted  - Decompile only the listed addresses
#   all       - Decompile ALL functions (small binaries like libjson.so)
#   dangerous - Find & decompile all callers of dangerous functions
#                (sprintf, strcpy, sscanf, execve, gets, system, popen)
#
# Output JSON structure:
# {
#   "binary": "www",
#   "decompiled_functions": [
#     {
#       "address": "0x0805c906",
#       "name": "fcn.0805c906",
#       "size": 3218,
#       "decompiled_c": "...",
#       "return_type": "int",
#       "parameters": [...],
#       "local_variables": [...],
#       "called_functions": [...],
#       "callers": [...],
#       "has_sprintf": true,
#       "has_strcpy": false,
#       ...
#     }
#   ],
#   "dangerous_call_map": { ... },
#   "metadata": { ... }
# }
#
# Compatible with Ghidra 11.x+ (Jython 2.7 / PyGhidra)

from __future__ import print_function
import json
import os
import sys
import time

# Ghidra imports (available when running as Ghidra script)
try:
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.model.listing import FunctionManager
    from ghidra.program.model.symbol import SourceType, RefType
    from ghidra.program.model.address import AddressSet
    from ghidra.util.task import ConsoleTaskMonitor
    GHIDRA_ENV = True
except ImportError:
    GHIDRA_ENV = False
    print("[!] Not running inside Ghidra — this script must be run as a Ghidra postScript")


# ── Dangerous functions to track ────────────────────────────────────────────

DANGEROUS_FUNCTIONS = [
    "sprintf", "vsprintf", "snprintf",
    "strcpy", "strncpy", "strcat", "strncat",
    "sscanf", "fscanf", "scanf",
    "memcpy", "memmove",
    "gets", "fgets",
    "execve", "execl", "execvp", "system", "popen",
    "realpath",
]


def get_script_args():
    """Parse script arguments from environment or properties."""
    args = {
        "addresses": [],
        "output": "/tmp/ghidra_decompile_output.json",
        "mode": "targeted",
    }

    # Try environment variables first
    addr_str = os.environ.get("GHIDRA_ADDRESSES", "")
    if addr_str:
        args["addresses"] = [a.strip() for a in addr_str.split(",") if a.strip()]

    output = os.environ.get("GHIDRA_OUTPUT", "")
    if output:
        args["output"] = output

    mode = os.environ.get("GHIDRA_MODE", "")
    if mode:
        args["mode"] = mode

    # Try Ghidra script args (passed via -scriptPath properties or getScriptArgs())
    try:
        script_args = getScriptArgs()
        if script_args:
            for arg in script_args:
                if arg.startswith("ADDRESSES="):
                    args["addresses"] = [a.strip() for a in arg.split("=", 1)[1].split(",") if a.strip()]
                elif arg.startswith("OUTPUT="):
                    args["output"] = arg.split("=", 1)[1]
                elif arg.startswith("MODE="):
                    args["mode"] = arg.split("=", 1)[1]
    except:
        pass

    return args


def decompile_function(decomp, func, monitor):
    """Decompile a single function and extract structured data."""
    result = {
        "address": "0x{:x}".format(func.getEntryPoint().getOffset()),
        "name": func.getName(),
        "size": func.getBody().getNumAddresses(),
        "decompiled_c": None,
        "return_type": None,
        "parameters": [],
        "local_variables": [],
        "called_functions": [],
        "callers": [],
        "stack_frame_size": 0,
        "dangerous_calls": [],
    }

    # Decompile
    try:
        decomp_result = decomp.decompileFunction(func, 120, monitor)
        if decomp_result and decomp_result.decompileCompleted():
            decomp_func = decomp_result.getDecompiledFunction()
            if decomp_func:
                result["decompiled_c"] = decomp_func.getC()

            # Extract high-level function info
            high_func = decomp_result.getHighFunction()
            if high_func:
                proto = high_func.getFunctionPrototype()
                if proto:
                    ret = proto.getReturnType()
                    if ret:
                        result["return_type"] = ret.getName()

                    # Parameters
                    num_params = proto.getNumParams()
                    for i in range(num_params):
                        param = proto.getParam(i)
                        result["parameters"].append({
                            "name": param.getName() if param.getName() else "param_{}".format(i),
                            "type": param.getDataType().getName() if param.getDataType() else "unknown",
                            "size": param.getSize(),
                        })

                # Local variables from high function
                local_symbols = high_func.getLocalSymbolMap()
                if local_symbols:
                    for sym in local_symbols.getSymbols():
                        storage = sym.getStorage()
                        result["local_variables"].append({
                            "name": sym.getName(),
                            "type": sym.getDataType().getName() if sym.getDataType() else "unknown",
                            "size": sym.getSize(),
                            "storage": str(storage) if storage else "unknown",
                        })

        else:
            error_msg = decomp_result.getErrorMessage() if decomp_result else "null result"
            result["decompile_error"] = error_msg
    except Exception as e:
        result["decompile_error"] = str(e)

    # Stack frame
    try:
        frame = func.getStackFrame()
        if frame:
            result["stack_frame_size"] = frame.getFrameSize()
    except:
        pass

    # Called functions (callees)
    try:
        called = func.getCalledFunctions(monitor)
        for callee in called:
            callee_name = callee.getName()
            result["called_functions"].append({
                "name": callee_name,
                "address": "0x{:x}".format(callee.getEntryPoint().getOffset()),
            })

            # Check if this is a dangerous function
            for danger in DANGEROUS_FUNCTIONS:
                if danger in callee_name.lower():
                    result["dangerous_calls"].append({
                        "function": callee_name,
                        "address": "0x{:x}".format(callee.getEntryPoint().getOffset()),
                        "category": danger,
                    })
    except:
        pass

    # Callers (who calls this function)
    try:
        callers = func.getCallingFunctions(monitor)
        for caller in callers:
            result["callers"].append({
                "name": caller.getName(),
                "address": "0x{:x}".format(caller.getEntryPoint().getOffset()),
            })
    except:
        pass

    return result


def find_dangerous_callers(program, func_manager, monitor):
    """Find all functions that call dangerous functions."""
    dangerous_callers = {}

    for func in func_manager.getFunctions(True):
        try:
            called = func.getCalledFunctions(monitor)
            for callee in called:
                callee_name = callee.getName()
                for danger in DANGEROUS_FUNCTIONS:
                    if danger in callee_name.lower():
                        addr_str = "0x{:x}".format(func.getEntryPoint().getOffset())
                        if addr_str not in dangerous_callers:
                            dangerous_callers[addr_str] = {
                                "function": func.getName(),
                                "address": addr_str,
                                "dangerous_calls": [],
                            }
                        dangerous_callers[addr_str]["dangerous_calls"].append({
                            "target": callee_name,
                            "category": danger,
                        })
        except:
            pass

    return dangerous_callers


def run():
    """Main entry point for Ghidra script execution."""
    if not GHIDRA_ENV:
        print("[!] Must run inside Ghidra")
        return

    start_time = time.time()
    monitor = ConsoleTaskMonitor()
    program = getCurrentProgram()
    func_manager = program.getFunctionManager()

    args = get_script_args()
    mode = args["mode"]
    output_path = args["output"]

    print("[*] Ghidra Export Functions Script")
    print("[*] Binary: {}".format(program.getName()))
    print("[*] Mode: {}".format(mode))
    print("[*] Output: {}".format(output_path))

    # Set up decompiler
    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    decomp.openProgram(program)

    output = {
        "binary": program.getName(),
        "binary_path": program.getExecutablePath(),
        "architecture": program.getLanguage().getLanguageID().toString(),
        "image_base": "0x{:x}".format(program.getImageBase().getOffset()),
        "decompiled_functions": [],
        "dangerous_call_map": {},
        "metadata": {
            "mode": mode,
            "ghidra_version": getGhidraVersion() if 'getGhidraVersion' in dir() else "unknown",
            "total_functions": func_manager.getFunctionCount(),
        },
    }

    if mode == "all":
        # Decompile ALL functions
        print("[*] Decompiling ALL {} functions...".format(func_manager.getFunctionCount()))
        count = 0
        for func in func_manager.getFunctions(True):
            result = decompile_function(decomp, func, monitor)
            output["decompiled_functions"].append(result)
            count += 1
            if count % 50 == 0:
                print("[*] Decompiled {}/{} functions...".format(count, func_manager.getFunctionCount()))

    elif mode == "dangerous":
        # Find all callers of dangerous functions, then decompile them
        print("[*] Finding callers of dangerous functions...")
        dangerous_callers = find_dangerous_callers(program, func_manager, monitor)
        output["dangerous_call_map"] = dangerous_callers
        print("[*] Found {} functions calling dangerous functions".format(len(dangerous_callers)))

        # Decompile each dangerous caller
        for addr_str, info in dangerous_callers.items():
            try:
                addr_val = int(addr_str, 16)
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
                func = func_manager.getFunctionContaining(addr)
                if func:
                    result = decompile_function(decomp, func, monitor)
                    output["decompiled_functions"].append(result)
            except Exception as e:
                print("[!] Error decompiling {}: {}".format(addr_str, e))

    elif mode == "targeted":
        # Decompile specific addresses
        addresses = args["addresses"]
        print("[*] Decompiling {} targeted functions...".format(len(addresses)))

        for addr_str in addresses:
            try:
                addr_val = int(addr_str, 16)
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
                func = func_manager.getFunctionContaining(addr)
                if func:
                    result = decompile_function(decomp, func, monitor)
                    output["decompiled_functions"].append(result)
                    print("[+] Decompiled: {} at {}".format(func.getName(), addr_str))
                else:
                    print("[!] No function found at address {}".format(addr_str))
                    output["decompiled_functions"].append({
                        "address": addr_str,
                        "error": "No function found at this address",
                    })
            except Exception as e:
                print("[!] Error processing address {}: {}".format(addr_str, e))
                output["decompiled_functions"].append({
                    "address": addr_str,
                    "error": str(e),
                })

    # Also build the dangerous call map regardless of mode
    if mode != "dangerous":
        print("[*] Building dangerous call map...")
        output["dangerous_call_map"] = find_dangerous_callers(program, func_manager, monitor)

    # Finalize
    elapsed = time.time() - start_time
    output["metadata"]["elapsed_seconds"] = elapsed
    output["metadata"]["functions_decompiled"] = len(output["decompiled_functions"])
    output["metadata"]["dangerous_callers_found"] = len(output["dangerous_call_map"])

    # Write output
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print("[+] Output written to {}".format(output_path))
    except Exception as e:
        # Fallback to /tmp
        fallback = "/tmp/ghidra_export_{}.json".format(program.getName())
        print("[!] Failed to write to {}: {}. Trying {}".format(output_path, e, fallback))
        with open(fallback, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print("[+] Output written to {}".format(fallback))

    print("[*] Done in {:.1f}s: {} functions decompiled, {} dangerous callers mapped".format(
        elapsed, len(output["decompiled_functions"]), len(output["dangerous_call_map"])))

    decomp.dispose()


# Entry point for Ghidra script execution
if GHIDRA_ENV:
    run()
