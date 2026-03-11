#!/usr/bin/env python3
"""Decompile image capture + init functions"""
import pyghidra

GHIDRA_HOME = "/home/jason/tools/ghidra_12.0.4_PUBLIC"
DLL_PATH = "/home/jason/tmp/fingerprint-driver/v1/MicroarrayFingerprintDevice.dll"
PROJECT_PATH = "/home/jason/tmp/ghidra-project"
PROJECT_NAME = "MicroarrayRE"

pyghidra.start(install_dir=GHIDRA_HOME)

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()

TARGETS = [
    0x180006bc0,   # case 0x65 in OnControlUnit
    0x180006c60,   # case 0x66
    0x180005da0,   # case 0x67
    0x180006020,   # case 0x6d
    0x180005dd0,   # case 0x6f
    0x180006c10,   # case 0x70
    0x180006cb0,   # case 0x71
    0x1800072c0,   # FUN_1800072c0 (bulk write)
    0x180007270,   # FUN_180007270 (bulk read)
]

with pyghidra.open_program(DLL_PATH, project_location=PROJECT_PATH,
                            project_name=PROJECT_NAME, analyze=False,
                            nested_project_location=False) as flat_api:
    program = flat_api.getCurrentProgram()
    fm = program.getFunctionManager()
    addrFactory = program.getAddressFactory()

    decompiler = DecompInterface()
    opts = DecompileOptions()
    decompiler.setOptions(opts)
    decompiler.openProgram(program)

    for target_offset in TARGETS:
        target_addr = addrFactory.getAddress("0x%x" % target_offset)
        f = fm.getFunctionAt(target_addr)
        if f is None:
            f = fm.getFunctionContaining(target_addr)
        if f is None:
            print(f"\n=== 0x{target_offset:x}: NOT FOUND ===")
            continue

        fname = f.getName()
        fsize = f.getBody().getNumAddresses()
        print(f"\n{'='*60}")
        print(f"Function: {fname} @ {f.getEntryPoint()}  ({fsize} bytes)")
        print('='*60)

        result = decompiler.decompileFunction(f, 120, monitor)
        if result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
            out_path = f"/home/jason/tmp/ghidra-{fname}.c"
            with open(out_path, "w") as out:
                out.write(c_code)
            print(f"Saved to {out_path}")
            lines = c_code.split("\n")
            for line in lines[:100]:
                print(line)
            if len(lines) > 100:
                print(f"... ({len(lines) - 100} more lines in file)")
        else:
            print(f"FAILED: {result.getErrorMessage()}")

    decompiler.dispose()
print("\nDONE")
