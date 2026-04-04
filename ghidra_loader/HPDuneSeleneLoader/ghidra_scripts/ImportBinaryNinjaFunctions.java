// Ghidra Script: Import Function Names from Binary Ninja Export
//
// Reads a JSON file produced by binja_export_functions.py and creates /
// renames functions at the corresponding addresses in the current program.
//
// Usage:
//   1. Open the target binary in Ghidra and run auto-analysis.
//   2. Run this script from the Script Manager.
//   3. When prompted, select the *_functions.json file.
//
// @category  Import
// @menupath  Tools.Import BN Function Names

import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;

public class ImportBinaryNinjaFunctions extends GhidraScript {

    @Override
    protected void run() throws Exception {

        File jsonFile = askFile("Select Binary Ninja function export", "Import");
        if (jsonFile == null) {
            println("[!] No file selected -- aborting.");
            return;
        }

        // Read the entire JSON file
        String jsonText;
        try (BufferedReader br = new BufferedReader(new FileReader(jsonFile))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            jsonText = sb.toString();
        }

        // Minimal JSON parsing without external libraries.
        // Extract the "functions" array entries, each with "address" and "name".
        String[] entries = extractFunctionEntries(jsonText);
        if (entries == null || entries.length == 0) {
            println("[!] No functions found in the JSON file.");
            return;
        }

        println("[*] Importing " + entries.length + " functions...");

        Listing listing = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();
        SymbolTable symTab = currentProgram.getSymbolTable();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        int created = 0;
        int renamed = 0;
        int skipped = 0;
        int errors = 0;

        monitor.initialize(entries.length);
        monitor.setMessage("Importing functions...");

        for (String entry : entries) {
            if (monitor.isCancelled()) {
                println("[!] Cancelled by user.");
                break;
            }
            monitor.incrementProgress(1);

            String addrStr = extractJsonString(entry, "address");
            String name = extractJsonString(entry, "name");

            if (addrStr == null || name == null) {
                println("  [-] Malformed entry -- skipping");
                errors++;
                continue;
            }

            // Parse hex address (strip "0x" prefix if present)
            long addrLong;
            try {
                String hex = addrStr.startsWith("0x") ? addrStr.substring(2) : addrStr;
                addrLong = Long.parseUnsignedLong(hex, 16);
            } catch (NumberFormatException e) {
                println("  [-] Invalid address format: " + addrStr);
                errors++;
                continue;
            }

            Address addr = space.getAddress(addrLong);

            // Check the address is within mapped memory
            if (!mem.contains(addr)) {
                println("  [-] Address " + addr + " (" + name + ") not in mapped memory -- skipping");
                skipped++;
                continue;
            }

            // Get or create the function
            Function func = listing.getFunctionAt(addr);

            if (func == null) {
                CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
                if (cmd.applyTo(currentProgram, monitor)) {
                    func = listing.getFunctionAt(addr);
                    created++;
                } else {
                    println("  [-] Could not create function at " + addr + " (" + name + ")");
                    errors++;
                    continue;
                }
            }

            // Skip if already correctly named
            String oldName = func.getName();
            if (oldName.equals(name)) {
                continue;
            }

            // Rename the function
            try {
                func.setName(name, SourceType.IMPORTED);
                renamed++;
            } catch (Exception e) {
                // Name collision -- try appending address to disambiguate
                String fallback = name + "_" + addrStr.replace("0x", "");
                try {
                    func.setName(fallback, SourceType.IMPORTED);
                    renamed++;
                    println("  [~] Name collision for '" + name + "' at " + addr + " -- used '" + fallback + "'");
                } catch (Exception e2) {
                    println("  [-] Failed to rename " + oldName + " at " + addr + ": " + e2.getMessage());
                    errors++;
                }
            }
        }

        println("");
        println("[+] Import complete:");
        println("    Functions created : " + created);
        println("    Functions renamed : " + renamed);
        println("    Skipped (unmapped): " + skipped);
        println("    Errors            : " + errors);
    }

    // ---- Minimal JSON helpers (no external dependencies) ----

    /**
     * Extract individual JSON objects from the "functions" array.
     * Returns each {...} block as a raw string.
     */
    private String[] extractFunctionEntries(String json) {
        // Find the "functions" array
        int arrStart = json.indexOf("\"functions\"");
        if (arrStart < 0) return null;

        int bracketOpen = json.indexOf('[', arrStart);
        if (bracketOpen < 0) return null;

        int bracketClose = findMatchingBracket(json, bracketOpen);
        if (bracketClose < 0) return null;

        String arrayContent = json.substring(bracketOpen + 1, bracketClose);

        // Split on "},{" boundaries to get individual objects
        java.util.List<String> objects = new java.util.ArrayList<>();
        int depth = 0;
        int objStart = -1;

        for (int i = 0; i < arrayContent.length(); i++) {
            char c = arrayContent.charAt(i);
            if (c == '{') {
                if (depth == 0) {
                    objStart = i;
                }
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0 && objStart >= 0) {
                    objects.add(arrayContent.substring(objStart, i + 1));
                    objStart = -1;
                }
            }
        }

        return objects.toArray(new String[0]);
    }

    /**
     * Find the matching closing bracket for an opening '['.
     */
    private int findMatchingBracket(String json, int openPos) {
        int depth = 0;
        boolean inString = false;
        for (int i = openPos; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"' && (i == 0 || json.charAt(i - 1) != '\\')) {
                inString = !inString;
            }
            if (!inString) {
                if (c == '[') depth++;
                else if (c == ']') {
                    depth--;
                    if (depth == 0) return i;
                }
            }
        }
        return -1;
    }

    /**
     * Extract a string value for a given key from a JSON object string.
     * Handles basic escaping. Returns null if key not found.
     */
    private String extractJsonString(String jsonObj, String key) {
        String searchKey = "\"" + key + "\"";
        int keyIdx = jsonObj.indexOf(searchKey);
        if (keyIdx < 0) return null;

        // Find the colon after the key
        int colonIdx = jsonObj.indexOf(':', keyIdx + searchKey.length());
        if (colonIdx < 0) return null;

        // Find the opening quote of the value
        int valStart = jsonObj.indexOf('"', colonIdx + 1);
        if (valStart < 0) return null;

        // Find the closing quote (handle escaped quotes)
        int valEnd = valStart + 1;
        while (valEnd < jsonObj.length()) {
            char c = jsonObj.charAt(valEnd);
            if (c == '\\') {
                valEnd += 2; // skip escaped character
                continue;
            }
            if (c == '"') break;
            valEnd++;
        }

        if (valEnd >= jsonObj.length()) return null;
        return jsonObj.substring(valStart + 1, valEnd);
    }
}
