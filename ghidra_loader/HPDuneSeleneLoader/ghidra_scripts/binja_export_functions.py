"""
Binary Ninja Script: Export Function Names
==========================================
Exports all user-defined (non-default) function names and their start
addresses to a JSON file.  The output file is placed next to the binary
with a "_functions.json" suffix.

Usage:
  - Run from Binary Ninja's Script Console or via the Plugin menu.
  - Or headless:  python binja_export_functions.py <binary_path>

Output format (JSON):
  {
    "binary": "dune_selene_nandboot.bin",
    "arch": "armv7",
    "count": 123,
    "functions": [
      {"address": "0x3c200a04", "name": "BootMain"},
      ...
    ]
  }
"""

import json
import os
import sys

def export_functions(bv, output_path=None):
    """Export all named functions from the given BinaryView.

    Parameters
    ----------
    bv : binaryninja.BinaryView
        The open binary view.
    output_path : str, optional
        Destination JSON file.  Defaults to ``<binary>_functions.json``
        next to the original file.
    """

    if output_path is None:
        base = bv.file.filename
        output_path = os.path.splitext(base)[0] + "_functions.json"

    functions = []
    skipped = 0

    for func in sorted(bv.functions, key=lambda f: f.start):
        name = func.name

        # Skip auto-generated names that carry no user information.
        # Binary Ninja names unnamed functions "sub_<hex>".
        if name.startswith("sub_"):
            skipped += 1
            continue

        functions.append({
            "address": hex(func.start),
            "name": name,
        })

    result = {
        "binary": os.path.basename(bv.file.filename),
        "arch": str(bv.arch),
        "count": len(functions),
        "functions": functions,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[+] Exported {len(functions)} functions to {output_path}")
    print(f"    (skipped {skipped} auto-named sub_* functions)")
    return output_path


# ── Interactive use inside Binary Ninja ──────────────────────────────
try:
    import binaryninja
    # If 'bv' is already in scope we're in the script console / GUI
    if "bv" not in dir():
        # Headless invocation
        if len(sys.argv) < 2:
            print("Usage: python binja_export_functions.py <binary_path> [output.json]")
            sys.exit(1)
        binary_path = sys.argv[1]
        out = sys.argv[2] if len(sys.argv) > 2 else None
        print(f"[*] Opening {binary_path} ...")
        with binaryninja.open_view(binary_path) as bv:
            export_functions(bv, out)
    else:
        # Running inside the GUI script console — 'bv' is the current view
        export_functions(bv)  # noqa: F821  (bv injected by BN)
except ImportError:
    # Not running inside Binary Ninja at all
    print("Error: This script requires the Binary Ninja Python API.")
    print("Run it from Binary Ninja's script console or with the BN headless API.")
    sys.exit(1)
