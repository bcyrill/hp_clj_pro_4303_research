# -*- coding: utf-8 -*-
"""
Ghidra Script: Import Function Names from Binary Ninja Export
=============================================================
Reads a JSON file produced by binja_export_functions.py and creates /
renames functions at the corresponding addresses in the current Ghidra
program.

Usage:
  1. Open the target binary in Ghidra and run auto-analysis.
  2. Run this script from the Script Manager or headless analyzeHeadless.
  3. When prompted, select the *_functions.json file.

The script handles:
  - Creating functions at addresses that Ghidra hasn't discovered yet.
  - Renaming existing functions (including auto-named FUN_* ones).
  - Reporting addresses that fall outside mapped memory.
  - Printing a summary of changes at the end.

@category  Import
@menupath  Tools.Import BN Function Names
"""

# Ghidra's Jython environment provides these implicitly:
#   currentProgram, monitor, askFile, state, ...
# We also use the Ghidra flat API helpers.
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import CreateFunctionCmd
import json


def run():
    json_file = askFile("Select Binary Ninja function export", "Import")
    if json_file is None:
        print("[!] No file selected -- aborting.")
        return

    with open(json_file.absolutePath, "r") as f:
        data = json.load(f)

    functions = data.get("functions", [])
    if not functions:
        print("[!] No functions found in the JSON file.")
        return

    print("[*] Importing %d functions from %s ..." % (len(functions), data.get("binary", "?")))

    listing = currentProgram.getListing()
    mem = currentProgram.getMemory()
    sym_table = currentProgram.getSymbolTable()
    addr_factory = currentProgram.getAddressFactory()
    space = addr_factory.getDefaultAddressSpace()

    created = 0
    renamed = 0
    skipped = 0
    errors = 0

    monitor.initialize(len(functions))
    monitor.setMessage("Importing functions...")

    for entry in functions:
        if monitor.isCancelled():
            print("[!] Cancelled by user.")
            break

        monitor.incrementProgress(1)

        addr_str = entry["address"]
        name = entry["name"]

        # Parse hex address
        try:
            addr_long = int(addr_str, 16)
        except ValueError:
            print("  [-] Invalid address format: %s" % addr_str)
            errors += 1
            continue

        addr = space.getAddress(addr_long)

        # Check the address is within mapped memory
        if not mem.contains(addr):
            print("  [-] Address %s (%s) not in mapped memory -- skipping" % (addr, name))
            skipped += 1
            continue

        # Get or create the function
        func = listing.getFunctionAt(addr)

        if func is None:
            # Try to create the function
            cmd = CreateFunctionCmd(addr)
            if cmd.applyTo(currentProgram, monitor):
                func = listing.getFunctionAt(addr)
                created += 1
            else:
                print("  [-] Could not create function at %s (%s)" % (addr, name))
                errors += 1
                continue

        # Rename the function
        old_name = func.getName()
        if old_name == name:
            # Already has the correct name
            continue

        try:
            func.setName(name, SourceType.IMPORTED)
            renamed += 1
        except Exception as e:
            # Name collision -- try appending the address to disambiguate
            fallback = "%s_%s" % (name, addr_str.replace("0x", ""))
            try:
                func.setName(fallback, SourceType.IMPORTED)
                renamed += 1
                print("  [~] Name collision for '%s' at %s -- used '%s'" % (name, addr, fallback))
            except Exception as e2:
                print("  [-] Failed to rename %s at %s: %s" % (old_name, addr, e2))
                errors += 1

    print("")
    print("[+] Import complete:")
    print("    Functions created : %d" % created)
    print("    Functions renamed : %d" % renamed)
    print("    Skipped (unmapped): %d" % skipped)
    print("    Errors            : %d" % errors)


# Wrap everything in a transaction so changes can be undone in one step.
tx = currentProgram.startTransaction("Import BN Function Names")
try:
    run()
finally:
    currentProgram.endTransaction(tx, True)
