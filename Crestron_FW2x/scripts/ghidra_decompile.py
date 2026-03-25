#!/usr/bin/env python3
# Ghidra headless script to decompile specific functions
# Run with: analyzeHeadless <project> <name> -process <binary> -postScript ghidra_decompile.py

import ghidra
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Target functions to decompile
TARGET_FUNCTIONS = [
    "hashDecryptUsingAes",
    "hashEncryptUsingAes",
    "passwordForAddWebServerCertificate",
    "passwordForAddCertificate",
    "passwordForAddSipCertificate",
    "passwordForAddMachineCertificate",
    "addCertificate",
    "runCommand",
    "runCommandAtBashPrompt",
    "validateCharacters",
    "validatePasswordCharacters",
    "CheckEmbeddedChars",
    "setCtpCommand",
]

# Also decompile any function referencing "openssl" or "system"
SEARCH_STRINGS = ["openssl", "CERTIFICATE ADDF"]

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

output_path = "/home/[REDACTED]/Desktop/[REDACTED-PATH]/[REDACTED-PROJECT]/[REDACTED-ID]_Crestron_FW2x/evidence/ghidra_decompile_output.txt"

with open(output_path, "w") as f:
    f.write("=" * 80 + "\n")
    f.write("GHIDRA DECOMPILATION OUTPUT — %s\n" % currentProgram.getName())
    f.write("=" * 80 + "\n\n")

    for func in fm.getFunctions(True):
        name = func.getName()
        matched = False

        for target in TARGET_FUNCTIONS:
            if target.lower() in name.lower():
                matched = True
                break

        if not matched:
            continue

        f.write("\n" + "=" * 80 + "\n")
        f.write("FUNCTION: %s\n" % name)
        f.write("ADDRESS:  0x%s\n" % func.getEntryPoint())
        f.write("SIZE:     %d bytes\n" % func.getBody().getNumAddresses())
        f.write("=" * 80 + "\n")

        results = decompiler.decompileFunction(func, 60, monitor)
        if results.depiledFunction():
            decomp = results.getDecompiledFunction()
            f.write(decomp.getC() + "\n")
        else:
            f.write("[DECOMPILATION FAILED]\n")

decompiler.dispose()
print("Output written to: %s" % output_path)
