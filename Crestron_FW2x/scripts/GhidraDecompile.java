// Ghidra headless script to decompile specific functions
// Run with: analyzeHeadless <project> <name> -process <binary> -postScript GhidraDecompile.java -noanalysis
//@author CrestronFW2x
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.TaskMonitor;
import java.io.FileWriter;
import java.io.PrintWriter;

public class GhidraDecompile extends GhidraScript {

    private static final String[] TARGET_FUNCTIONS = {
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
        "addUser",
        "resetPassword",
        "modifyUser",
        "createHashFileUsingMd5Sum",
        "validateHashFile",
    };

    @Override
    public void run() throws Exception {
        String outputPath = "/home/[REDACTED]/Desktop/SecSoft/[REDACTED-PROJECT]/CF4_Crestron_FW2x/evidence/ghidra_decompile_output.txt";

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        PrintWriter out = new PrintWriter(new FileWriter(outputPath));
        out.println("=" + "=".repeat(79));
        out.println("GHIDRA DECOMPILATION OUTPUT -- " + currentProgram.getName());
        out.println("=" + "=".repeat(79));
        out.println();

        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            String name = func.getName();

            boolean matched = false;
            for (String target : TARGET_FUNCTIONS) {
                if (name.toLowerCase().contains(target.toLowerCase())) {
                    matched = true;
                    break;
                }
            }

            if (!matched) continue;

            out.println();
            out.println("=" + "=".repeat(79));
            out.println("FUNCTION: " + name);
            out.println("ADDRESS:  0x" + func.getEntryPoint().toString());
            out.println("SIZE:     " + func.getBody().getNumAddresses() + " bytes");
            out.println("=" + "=".repeat(79));

            DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
            if (results.depiledFunction() != null) {
                out.println(results.getDecompiledFunction().getC());
            } else {
                out.println("[DECOMPILATION FAILED]");
            }
            count++;
        }

        out.println();
        out.println("Total functions decompiled: " + count);
        out.close();
        decompiler.dispose();

        println("Decompiled " + count + " functions. Output: " + outputPath);
    }
}
