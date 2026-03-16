# Reverse Engineering Notes

The protocol was reverse-engineered from the official Windows driver:
`MicroarrayFingerprintDevice.dll` v9.47.11.214

The decompiled output and driver binaries are **not** included in this repo
(proprietary, copyright MicroarrayTechnology). The full protocol documentation
derived from that analysis is in `docs/fingerprint-driver-re.md`.

## Reproducing the analysis

### 1. Obtain the Windows driver

The driver is distributed as a WHQL-signed `.cab` file. It can be extracted
from Windows Update or from the vendor:

```
MicroarrayFingerprintDevice.inf  — device INF
MicroarrayFingerprintDevice.dll  — main sensor logic (analyse this one)
MicroarrayFingerprintAdapter.dll — WBF adapter layer
```

Extract the cab:
```bash
mkdir -p re/fingerprint-driver
cabextract microarray-wbdi.cab -d re/fingerprint-driver/
```

### 2. Install Ghidra

```bash
# Fedora
sudo dnf install ghidra
# Or download from https://ghidra-sre.org
```

### 3. Headless analysis

```bash
ghidra/support/analyzeHeadless \
    /tmp/ghidra-project MicroarrayProject \
    -import re/fingerprint-driver/MicroarrayFingerprintDevice.dll \
    -postScript PrintTree.java \
    -scriptPath ghidra/Ghidra/Features/Base/ghidra_scripts
```

### 4. Key functions to decompile

| Address        | Name (reconstructed)  | Purpose                        |
|----------------|-----------------------|--------------------------------|
| FUN_1800063b0  | fsm_sensor_control    | Main enrollment/verify FSM     |
| FUN_180006d90  | fsm_update_enroll     | Sample count logic             |
| FUN_180007170  | mfm_handshake         | CMD 0x23 packet + response     |
| FUN_1800060e0  | fsm_sendcmd           | Packet framing                 |

Decompile each with:
```
Decompiler → Export → C (via Ghidra GUI or headless script)
```

### 5. USB capture cross-reference

The `tools/` directory contains Python scripts to parse Wireshark USB captures
(exported as JSON) and annotate command/response pairs:

```bash
# Export from Wireshark: File > Export Packet Dissections > As JSON
python3 tools/extract_usb_cmds.py capture.json
```
