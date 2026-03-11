"""
Ghidra headless script — extract USB command protocol from MicroarrayFingerprintDevice.dll
Outputs: RTTI class names, COM vtable calls, command byte sequences

Run via Ghidra analyzeHeadless with -postScript
"""
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType, RefType
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from java.io import StringWriter

monitor = ConsoleTaskMonitor()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
refMgr = currentProgram.getReferenceManager()
symbolTable = currentProgram.getSymbolTable()
addrFactory = currentProgram.getAddressFactory()

def addr(offset):
    return addrFactory.getAddress("0x%x" % offset)

print("=" * 70)
print("RTTI / C++ class names")
print("=" * 70)
for sym in symbolTable.getAllSymbols(True):
    name = sym.getName()
    if "RTTI" in name or "::" in name or "vtable" in name.lower() or "vftable" in name.lower():
        print("  %s  @ %s" % (name, sym.getAddress()))

print()
print("=" * 70)
print("All function names (non-default)")
print("=" * 70)
for f in fm.getFunctions(True):
    name = f.getName()
    if not name.startswith("FUN_") and not name.startswith("thunk_"):
        print("  %s  @ %s  size=%d" % (name, f.getEntryPoint(), f.getBody().getNumAddresses()))

print()
print("=" * 70)
print("Imports / external references")
print("=" * 70)
extSym = currentProgram.getExternalManager()
for lib in extSym.getExternalLibraryNames():
    print("  LIB: %s" % lib)
    for loc in extSym.getExternalLocations(lib):
        print("    %s" % loc.getLabel())

print()
print("=" * 70)
print("Decompiling large function fcn.180001140")
print("=" * 70)
target_func = fm.getFunctionAt(addr(0x180001140))
if target_func is None:
    # search nearby
    print("  Not found at 0x180001140, listing large functions:")
    funcs = list(fm.getFunctions(True))
    funcs.sort(key=lambda f: f.getBody().getNumAddresses(), reverse=True)
    for f in funcs[:10]:
        print("  %s @ %s size=%d" % (f.getName(), f.getEntryPoint(), f.getBody().getNumAddresses()))
    target_func = funcs[0]

print("  Target: %s @ %s" % (target_func.getName(), target_func.getEntryPoint()))

decompiler = DecompInterface()
opts = DecompileOptions()
decompiler.setOptions(opts)
decompiler.openProgram(currentProgram)

result = decompiler.decompileFunction(target_func, 120, monitor)
if result.decompileCompleted():
    c_code = result.getDecompiledFunction().getC()
    # Write full decompilation to file
    out_path = "/home/jason/tmp/ghidra-decompile-main.c"
    with open(out_path, "w") as f:
        f.write(c_code)
    print("  Wrote %d chars to %s" % (len(c_code), out_path))
    # Print first 200 lines
    lines = c_code.split("\n")
    print("  First 100 lines:")
    for line in lines[:100]:
        print("    " + line)
else:
    print("  Decompile FAILED: " + str(result.getErrorMessage()))

print()
print("=" * 70)
print("Decompiling DllGetClassObject")
print("=" * 70)
dll_get = None
for sym in symbolTable.getAllSymbols(True):
    if "DllGetClassObject" in sym.getName():
        f = fm.getFunctionAt(sym.getAddress())
        if f:
            dll_get = f
            break

if dll_get:
    result2 = decompiler.decompileFunction(dll_get, 60, monitor)
    if result2.decompileCompleted():
        c2 = result2.getDecompiledFunction().getC()
        out2 = "/home/jason/tmp/ghidra-decompile-dllgetclassobject.c"
        with open(out2, "w") as f:
            f.write(c2)
        print("  Wrote to %s" % out2)
        print(c2[:3000])
    else:
        print("  Failed: " + str(result2.getErrorMessage()))
else:
    print("  DllGetClassObject not found by symbol")

decompiler.dispose()
print("DONE")
