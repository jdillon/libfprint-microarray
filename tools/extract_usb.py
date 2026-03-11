#!/usr/bin/env python3
"""
Standalone PyGhidra script to extract USB protocol from MicroarrayFingerprintDevice.dll
"""
import pyghidra
import os

GHIDRA_HOME = "/home/jason/tools/ghidra_12.0.4_PUBLIC"
DLL_PATH = "/home/jason/tmp/fingerprint-driver/v1/MicroarrayFingerprintDevice.dll"
PROJECT_PATH = "/home/jason/tmp/ghidra-project"
PROJECT_NAME = "MicroarrayRE"

print("Launching PyGhidra...")
pyghidra.start(install_dir=GHIDRA_HOME)

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.program.flatapi as flat

monitor = ConsoleTaskMonitor()

with pyghidra.open_program(DLL_PATH, project_location=PROJECT_PATH,
                            project_name=PROJECT_NAME, analyze=False,
                            nested_project_location=False) as flat_api:
    program = flat_api.getCurrentProgram()
    fm = program.getFunctionManager()
    addrFactory = program.getAddressFactory()
    symbolTable = program.getSymbolTable()

    def addr(offset):
        return addrFactory.getAddress("0x%x" % offset)

    print("\n" + "=" * 70)
    print("RTTI / C++ class names from RTTI analyzer")
    print("=" * 70)
    rtti_found = []
    for sym in symbolTable.getAllSymbols(True):
        name = sym.getName(True)  # with namespace
        if any(x in name for x in ["RTTI", "::", "vtable", "vftable", "typeinfo"]):
            rtti_found.append((str(sym.getAddress()), name))
    for a, n in sorted(rtti_found):
        print(f"  {a}  {n}")
    if not rtti_found:
        print("  (none found)")

    print("\n" + "=" * 70)
    print("Named functions (non-FUN_/thunk_)")
    print("=" * 70)
    for f in fm.getFunctions(True):
        name = f.getName()
        if not name.startswith("FUN_") and not name.startswith("thunk_"):
            size = f.getBody().getNumAddresses()
            print(f"  {name}  @ {f.getEntryPoint()}  size={size}")

    print("\n" + "=" * 70)
    print("External imports by library")
    print("=" * 70)
    extMgr = program.getExternalManager()
    for lib in extMgr.getExternalLibraryNames():
        locs = list(extMgr.getExternalLocations(lib))
        if locs:
            print(f"  [{lib}]")
            for loc in locs:
                print(f"    {loc.getLabel()}")

    print("\n" + "=" * 70)
    print("Decompiling functions (largest first)")
    print("=" * 70)
    decompiler = DecompInterface()
    opts = DecompileOptions()
    decompiler.setOptions(opts)
    decompiler.openProgram(program)

    # Sort by size, get top 5
    all_funcs = list(fm.getFunctions(True))
    all_funcs.sort(key=lambda f: f.getBody().getNumAddresses(), reverse=True)

    for f in all_funcs[:5]:
        fname = f.getName()
        fsize = f.getBody().getNumAddresses()
        faddr = f.getEntryPoint()
        print(f"\n--- {fname} @ {faddr}  ({fsize} bytes) ---")

        result = decompiler.decompileFunction(f, 180, monitor)
        if result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
            out_path = f"/home/jason/tmp/ghidra-decompile-{fname}.c"
            with open(out_path, "w") as out:
                out.write(c_code)
            print(f"  Wrote {len(c_code)} chars to {out_path}")
            # Print first 80 lines
            lines = c_code.split("\n")
            for line in lines[:80]:
                print("  " + line)
            if len(lines) > 80:
                print(f"  ... ({len(lines) - 80} more lines)")
        else:
            print(f"  FAILED: {result.getErrorMessage()}")

    decompiler.dispose()
    print("\nDONE")
