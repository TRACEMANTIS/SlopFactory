#!/usr/bin/env python3
"""
PyGhidra-based decompiler for MikroTik binaries.
Uses pyghidra (Ghidra 12.x Python API) to decompile functions at specified addresses.

Usage:
    python3 pyghidra_decompile.py <binary_path> <output_json> [mode] [addresses...]

Modes:
    targeted <addr1> <addr2> ...  - Decompile specific addresses
    all                           - Decompile all functions
    dangerous                     - Find & decompile callers of dangerous functions

Examples:
    python3 pyghidra_decompile.py /path/to/www /tmp/out.json targeted 0x0805c906 0x08052666
    python3 pyghidra_decompile.py /path/to/libjson.so /tmp/out.json all
    python3 pyghidra_decompile.py /path/to/libumsg.so /tmp/out.json dangerous
"""

import json
import os
import sys
import time
from pathlib import Path

DANGEROUS_FUNCTIONS = [
    "sprintf", "vsprintf", "snprintf",
    "strcpy", "strncpy", "strcat", "strncat",
    "sscanf", "fscanf", "scanf",
    "memcpy", "memmove",
    "gets", "fgets",
    "execve", "execl", "execvp", "system", "popen",
    "realpath",
]

def log(msg):
    from datetime import datetime
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    binary_path = sys.argv[1]
    output_path = sys.argv[2]
    mode = sys.argv[3]
    addresses = sys.argv[4:] if len(sys.argv) > 4 else []

    log(f"Binary: {binary_path}")
    log(f"Output: {output_path}")
    log(f"Mode: {mode}")
    if addresses:
        log(f"Addresses: {addresses}")

    try:
        import pyghidra
    except ImportError:
        log("ERROR: pyghidra not installed. Run: pip3 install pyghidra")
        sys.exit(1)

    start_time = time.time()

    # Initialize PyGhidra
    log("Initializing PyGhidra (this may take a moment)...")
    pyghidra.start()

    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.flatapi import FlatProgramAPI
    import ghidra.app.util.importer.AutoImporter as AutoImporter
    from ghidra.app.util.importer import MessageLog
    from ghidra.program.model.listing import Program
    from java.io import File

    log("PyGhidra initialized successfully")

    # Open the binary
    log(f"Opening binary: {binary_path}")

    from ghidra.base.project import GhidraProject
    from ghidra.app.util.opinion import LoaderService

    project_dir = Path("/tmp/pyghidra_projects")
    project_dir.mkdir(exist_ok=True)
    project_name = f"mikrotik_{Path(binary_path).stem}"

    # Try to open existing project, create if not found
    try:
        project = GhidraProject.openProject(str(project_dir), project_name, True)
        log("Opened existing project")
    except Exception:
        log("Creating new project...")
        project = GhidraProject.createProject(str(project_dir), project_name, False)

    try:
        program = project.importProgram(File(binary_path))
        log("Imported program")
    except Exception:
        try:
            program = project.openProgram("/", Path(binary_path).name, False)
            log("Opened existing program from project")
        except Exception as e2:
            log(f"Re-importing: {e2}")
            program = project.importProgram(File(binary_path))

    if program is None:
        log("ERROR: Failed to open program")
        sys.exit(1)

    log(f"Program loaded: {program.getName()}")

    # Run auto-analysis
    log("Running auto-analysis...")
    txid = program.startTransaction("analysis")
    try:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(program.getMemory().getLoadedAndInitializedAddressSet())
        mgr.startAnalysis(ConsoleTaskMonitor(), False)
    except Exception as e:
        log(f"Auto-analysis note: {e}")
    finally:
        program.endTransaction(txid, True)

    # Set up decompiler
    log("Setting up decompiler...")
    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    decomp.openProgram(program)
    monitor = ConsoleTaskMonitor()
    func_manager = program.getFunctionManager()

    output = {
        "binary": program.getName(),
        "binary_path": binary_path,
        "decompiled_functions": [],
        "dangerous_call_map": {},
        "metadata": {
            "mode": mode,
            "total_functions": func_manager.getFunctionCount(),
        },
    }

    def decompile_func(func):
        """Decompile a single function."""
        result = {
            "address": f"0x{func.getEntryPoint().getOffset():x}",
            "name": func.getName(),
            "size": func.getBody().getNumAddresses(),
            "decompiled_c": None,
            "parameters": [],
            "local_variables": [],
            "called_functions": [],
            "callers": [],
            "dangerous_calls": [],
            "stack_frame_size": 0,
        }

        try:
            decomp_result = decomp.decompileFunction(func, 120, monitor)
            if decomp_result and decomp_result.decompileCompleted():
                decomp_func_obj = decomp_result.getDecompiledFunction()
                if decomp_func_obj:
                    result["decompiled_c"] = decomp_func_obj.getC()

                high_func = decomp_result.getHighFunction()
                if high_func:
                    proto = high_func.getFunctionPrototype()
                    if proto:
                        ret = proto.getReturnType()
                        if ret:
                            result["return_type"] = ret.getName()
                        for i in range(proto.getNumParams()):
                            param = proto.getParam(i)
                            result["parameters"].append({
                                "name": param.getName() or f"param_{i}",
                                "type": param.getDataType().getName() if param.getDataType() else "unknown",
                                "size": param.getSize(),
                            })

                    local_symbols = high_func.getLocalSymbolMap()
                    if local_symbols:
                        for sym in local_symbols.getSymbols():
                            result["local_variables"].append({
                                "name": sym.getName(),
                                "type": sym.getDataType().getName() if sym.getDataType() else "unknown",
                                "size": sym.getSize(),
                            })
        except Exception as e:
            result["decompile_error"] = str(e)

        try:
            frame = func.getStackFrame()
            if frame:
                result["stack_frame_size"] = frame.getFrameSize()
        except:
            pass

        try:
            for callee in func.getCalledFunctions(monitor):
                callee_name = callee.getName()
                result["called_functions"].append({
                    "name": callee_name,
                    "address": f"0x{callee.getEntryPoint().getOffset():x}",
                })
                for danger in DANGEROUS_FUNCTIONS:
                    if danger in callee_name.lower():
                        result["dangerous_calls"].append({
                            "function": callee_name,
                            "category": danger,
                        })
        except:
            pass

        try:
            for caller in func.getCallingFunctions(monitor):
                result["callers"].append({
                    "name": caller.getName(),
                    "address": f"0x{caller.getEntryPoint().getOffset():x}",
                })
        except:
            pass

        return result

    # Process based on mode
    if mode == "all":
        log(f"Decompiling ALL {func_manager.getFunctionCount()} functions...")
        count = 0
        for func in func_manager.getFunctions(True):
            result = decompile_func(func)
            output["decompiled_functions"].append(result)
            count += 1
            if count % 50 == 0:
                log(f"  Decompiled {count}/{func_manager.getFunctionCount()}...")

    elif mode == "dangerous":
        log("Finding callers of dangerous functions...")
        dangerous_callers = {}
        for func in func_manager.getFunctions(True):
            try:
                for callee in func.getCalledFunctions(monitor):
                    callee_name = callee.getName()
                    for danger in DANGEROUS_FUNCTIONS:
                        if danger in callee_name.lower():
                            addr_str = f"0x{func.getEntryPoint().getOffset():x}"
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

        output["dangerous_call_map"] = dangerous_callers
        log(f"Found {len(dangerous_callers)} callers of dangerous functions")

        for addr_str in dangerous_callers:
            try:
                addr_val = int(addr_str, 16)
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
                func = func_manager.getFunctionContaining(addr)
                if func:
                    result = decompile_func(func)
                    output["decompiled_functions"].append(result)
            except Exception as e:
                log(f"  Error decompiling {addr_str}: {e}")

    elif mode == "targeted":
        log(f"Decompiling {len(addresses)} targeted functions...")
        for addr_str in addresses:
            try:
                addr_val = int(addr_str, 16)
                addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
                func = func_manager.getFunctionContaining(addr)
                if func:
                    result = decompile_func(func)
                    output["decompiled_functions"].append(result)
                    log(f"  + {func.getName()} at {addr_str}")
                else:
                    log(f"  ! No function at {addr_str}")
            except Exception as e:
                log(f"  ! Error at {addr_str}: {e}")

    # Build dangerous map for non-dangerous modes
    if mode != "dangerous":
        log("Building dangerous call map...")
        for func in func_manager.getFunctions(True):
            try:
                for callee in func.getCalledFunctions(monitor):
                    callee_name = callee.getName()
                    for danger in DANGEROUS_FUNCTIONS:
                        if danger in callee_name.lower():
                            addr_str = f"0x{func.getEntryPoint().getOffset():x}"
                            if addr_str not in output["dangerous_call_map"]:
                                output["dangerous_call_map"][addr_str] = {
                                    "function": func.getName(),
                                    "address": addr_str,
                                    "dangerous_calls": [],
                                }
                            output["dangerous_call_map"][addr_str]["dangerous_calls"].append({
                                "target": callee_name,
                                "category": danger,
                            })
            except:
                pass

    # Finalize
    elapsed = time.time() - start_time
    output["metadata"]["elapsed_seconds"] = elapsed
    output["metadata"]["functions_decompiled"] = len(output["decompiled_functions"])
    output["metadata"]["dangerous_callers_found"] = len(output["dangerous_call_map"])

    # Write output
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    log(f"Done in {elapsed:.1f}s: {len(output['decompiled_functions'])} decompiled, "
        f"{len(output['dangerous_call_map'])} dangerous callers")
    log(f"Output: {output_path}")

    # Cleanup
    decomp.dispose()
    project.close()


if __name__ == "__main__":
    main()
