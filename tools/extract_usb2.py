#!/usr/bin/env python3
"""
Decompile specific functions: FUN_1800060e0 (USB xfer), FUN_180006050,
FUN_180006d90, FUN_180007170, the big switch at 0x180002aa6
"""
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
    0x1800060e0,   # USB xfer function (cmd_buf, cmd_len, resp_buf, resp_len)
    0x180006050,   # wake/sleep toggle
    0x180006d90,   # enum fingerprints (case 0x65)
    0x180007170,   # enrollment helper
    0x180007fe0,   # debug log (to identify string format)
    0x180001b60,   # CreateUsbIoTargets
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

    # Also find any function containing the big switch at 0x180002aa6
    switch_addr = addrFactory.getAddress("0x180002aa6")
    f_at_switch = fm.getFunctionContaining(switch_addr)
    if f_at_switch:
        TARGETS.insert(0, int(str(f_at_switch.getEntryPoint()), 16))
        print(f"Big switch at 0x180002aa6 is inside: {f_at_switch.getName()} @ {f_at_switch.getEntryPoint()}")

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
            # Print first 120 lines
            lines = c_code.split("\n")
            for line in lines[:120]:
                print(line)
            if len(lines) > 120:
                print(f"... ({len(lines) - 120} more lines in file)")
        else:
            print(f"FAILED: {result.getErrorMessage()}")

    decompiler.dispose()
print("\nDONE")
