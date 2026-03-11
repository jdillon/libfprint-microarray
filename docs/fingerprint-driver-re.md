# MicroarrayTechnology MAFP Fingerprint Driver — Linux Reverse Engineering

## Goal

Write a libfprint driver for the `3274:8012` MicroarrayTechnology MAFP fingerprint
reader so it works with fprintd on Linux (PAM login, sudo, KDE lock screen).

---

## Device

| Item | Detail |
|---|---|
| USB ID | `3274:8012` |
| Name | MicroarrayTechnology MAFP General Device |
| Class | Vendor Specific (0xFF) |
| Windows driver | Microarray WBDI (UMDF) |
| INF file | `MicroarrayFingerprintDevice.inf` |
| Driver version | 9.47.11.214 (2024-01-18) |

---

## Driver Files Downloaded

Source: Microsoft Update Catalog (official, signed by Microsoft)

```
/home/jason/tmp/fingerprint-driver/
├── microarray-wbdi-v1.cab          # version 9.47.11.214
├── microarray-wbdi-v2.cab          # version 9.47.11.214 (alt build)
├── v1/
│   ├── MicroarrayFingerprintDevice.inf     # human-readable config — READ THIS FIRST
│   ├── MicroarrayFingerprintDevice.dll     # UMDF USB protocol driver  ← primary RE target
│   ├── MicroarrayFingerprintAdapter.dll    # WinBio engine/matching adapter
│   └── biometrics.cat                      # Microsoft signature
└── v2/
    └── (same structure, slightly different build)
```

---

## Key Findings from INF Analysis

### Architecture

```
[Linux libusb / WinUSB]
        ↓
MicroarrayFingerprintDevice.dll     ← USB command protocol (UMDF driver)
        ↓
MicroarrayFingerprintAdapter.dll    ← Fingerprint matching engine
        ↓
WinBioSensorAdapter.dll             ← Windows built-in (not needed for Linux)
WinBioStorageAdapter.dll            ← Windows built-in (not needed for Linux)
```

**Key insight:** Only `MicroarrayFingerprintDevice.dll` needs RE. The matching engine
(`MicroarrayFingerprintAdapter.dll`) uses Microsoft's WinBio matching — on Linux,
libfprint's built-in NBIS engine handles matching.

### Important constants from INF

| Item | Value |
|---|---|
| Driver CLSID | `{F1CB3C15-A916-47bc-BEA1-D5D4163BC6AE}` |
| Database GUID | `{1BD7719B-CBDF-49D6-AD4A-6529CF180E4D}` |
| Sensor mode | Basic (1) |
| System sensor | Yes (UAC/Winlogon) |
| Also supports | `USB\VID_3274&PID_8008&MI_00` (composite variant) |

---

## USB Endpoint Map

Discovered via `lsusb -v -d 3274:8012`:

| Endpoint | Direction | Type | Max packet | Purpose |
|---|---|---|---|---|
| EP 0x03 | OUT | Bulk | 64 bytes | **Commands TO device** |
| EP 0x83 | IN | Bulk | 64 bytes | **Responses / image data FROM device** |
| EP 0x82 | IN | Interrupt | 16 bytes | **Finger detected / status events** |

---

## Ghidra RE Results

### Tools Used

- Ghidra 12.0.4 headless analysis via PyGhidra 3.0.2
- JDK 21 (`java-21-openjdk-devel`)
- `MicroarrayFingerprintDevice.dll` — 226 KB stripped PE64

### Key Classes Found (via debug strings)

| Class | Method | Role |
|---|---|---|
| `CBiometricDevice` | `OnPrepareHardware` | UMDF init, creates USB pipes |
| `CBiometricDevice` | `OnControlUnit` | Dispatches IOCTL commands |
| `CBiometricDevice` | `CreateUsbIoTargets` | Sets up bulk OUT/IN/interrupt pipes |
| `Sensor` | `fsm_sensor_control` | Main USB command state machine |
| `Sensor` | `fsm_sendcmd` | Core USB packet send/receive |
| `Sensor` | `fsm_create_enroll` | Create enrollment session |
| `Sensor` | `fsm_update_enroll` | Collect fingerprint samples |
| `Sensor` | `fsm_commit_enroll` | Finalize and store enrollment |
| `Sensor` | `fsm_verify` | Verify fingerprint |
| `Sensor` | `fsm_get_char` | Get fingerprint characteristics |
| `Sensor` | `fsm_remove_all` | Erase all stored templates |
| `Sensor` | `mfm_handshake` | Device initialization handshake |
| `Sensor` | `fsm_get_unused_fid` | Find unused fingerprint ID slot |

---

## USB Protocol Format

The device uses the **FPC/GROW fingerprint sensor protocol** (same family as R30X series).

### Packet Structure

```
COMMAND (host → device, EP 0x03):
  Byte 0:   EF          (sync byte 1)
  Byte 1:   01          (sync byte 2)
  Bytes 2-5: FF FF FF FF (device address, broadcast)
  Byte 6:   01          (packet type: 01 = command)
  Byte 7:   len_hi      (payload length, big-endian: cmd_bytes + 2)
  Byte 8:   len_lo
  Bytes 9..: cmd_bytes  (N command bytes)
  Last 2:   csum_hi, csum_lo  (16-bit sum of bytes 6..end-2)

RESPONSE (device → host, EP 0x83):
  Byte 0:   EF
  Byte 1:   01
  Bytes 2-5: FF FF FF FF
  Byte 6:   07          (packet type: 07 = response)
  Byte 7:   len_hi
  Byte 8:   len_lo
  Bytes 9..: response_bytes
  Last 2:   csum_hi, csum_lo
```

### Checksum Calculation

```c
uint16_t checksum = 0;
// Sum: type_byte + len_hi + len_lo + all cmd_bytes
for (int i = 6; i < 6 + 1 + 2 + N; i++)
    checksum += packet[i];
packet[6 + 1 + 2 + N]     = (checksum >> 8) & 0xFF;
packet[6 + 1 + 2 + N + 1] = checksum & 0xFF;
```

---

## Command Reference

### FPC Protocol Commands

Extracted from `Sensor::fsm_sendcmd` (`FUN_1800060e0`) and all callers.
**cmd[0]** = command byte. Values are the raw bytes in the packet payload.

| Hex | Name | cmd bytes | resp bytes | Notes |
|---|---|---|---|---|
| 0x01 | GetImage | `{0x01}` | 3 | Capture fingerprint image; resp[0]=0 on success |
| 0x02 | GenChar | `{0x02, slot}` | 3 | Extract characteristics into slot (1–6) |
| 0x05 | RegModel | `{0x05}` | 3 | Combine slots 1-N into template in buffer |
| 0x06 | StoreChar | `{0x06, 0x01, fid_hi, fid_lo}` | 3 | Store template to FID slot |
| 0x0D | Empty | `{0x0D}` | 3 | Erase all stored templates |
| 0x1F | ReadIndexTable | `{0x1F, 0x00}` | 35 | Bitmap of enrolled FID slots (0x23 bytes) |
| 0x33 | (status) | `{0x33}` | 3 | Status check (case 0x6f in IOCTL) |
| 0x36 | (status) | `{0x36}` | 3 | Status check (case 0x67 in IOCTL) |
| 0x66 | Search | `{0x66, fid_hi, fid_lo}` | 3 | Verify GenChar result against FID; resp[0]=0 match |
| 0x6F | DupCheck | `{0x6F}` | 3 | Duplicate fingerprint check; resp[0]=0 no dup |
| 0x86 | StoreInfo | `{0x86, fid_lo, fid_hi, <128 bytes uid>}` | 3 | Store 128-byte UID metadata |
| 0x87 | LoadChar | `{0x87, fid_hi, fid_lo}` | 131 | Load fingerprint info; [0]=status, [1..128]=UID |
| 0x23 | Handshake | (raw, see below) | 12 | Device init/handshake |

### Handshake (raw packet)

```
TX: EF 01 FF FF FF FF 01 00 02 23 A2   (11 bytes)
RX: 12 bytes (verify with FUN_180006fc0)
```

### Response Format

All standard commands return 3-byte (minimum) response:
- `resp[0]` = status code (0x00 = success)
- `resp[1..N-1]` = data (command-specific)

---

## Enrollment Sequence

```
1. Handshake (CMD 0x23)

2. For each sample i = 1 to N (N = 3-6):
   a. Poll CMD 0x01 until resp[0] == 0 (finger present + image captured)
   b. CMD 0x02 with slot=i  → generate characteristics

3. CMD 0x6F (duplicate check) — optional

4. CMD 0x05 (RegModel) — merge characteristics into template

5. CMD 0x1F (ReadIndexTable) — find unused FID slot

6. CMD 0x06 {0x06, 0x01, fid_hi, fid_lo} (StoreChar) — store template

7. CMD 0x86 {0x86, fid_lo, fid_hi, <128 bytes>} (StoreInfo) — store UID metadata
```

---

## Verification Sequence

```
1. CMD 0x01 (GetImage) — poll until finger present

2. CMD 0x02 {0x02, 0x01} (GenChar into slot 1)

3. CMD 0x66 {0x66, fid_hi, fid_lo} (Search) — compare against enrolled FID
   resp[0] == 0 → match
   resp[0] != 0 → no match
```

---

## libfprint Driver Implementation Plan

Once the USB protocol is understood:

1. **Start from a similar libfprint driver as template**
   - `drivers/goodix.c` or `drivers/synaptics.c` — bulk-transfer sensors with similar command pattern
   - Study `drivers/README` for driver API

2. **Implement required callbacks**

   ```c
   static void dev_init(FpDevice *device)      // open USB, send handshake
   static void dev_deinit(FpDevice *device)    // close device
   static void enroll(FpDevice *device)        // enrollment loop (CMD 01/02/05/06)
   static void verify(FpDevice *device)        // capture + match (CMD 01/02/66)
   ```

3. **USB ID table**

   ```c
   static const FpIdEntry id_table[] = {
       { .vid = 0x3274, .pid = 0x8012 },
       { 0, 0, 0 }, /* terminator */
   };
   ```

4. **Packet helper functions**

   ```c
   /* Build FPC-format command packet */
   static GByteArray *ma_build_packet(uint8_t *cmd, size_t cmd_len)
   {
       GByteArray *pkt = g_byte_array_new();
       static const uint8_t header[] = {0xEF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF};
       uint16_t len = cmd_len + 2;  /* payload + 2 checksum bytes */
       uint16_t csum = 0x01 + (len >> 8) + (len & 0xFF);
       for (size_t i = 0; i < cmd_len; i++) csum += cmd[i];
       g_byte_array_append(pkt, header, 6);
       uint8_t type = 0x01;
       g_byte_array_append(pkt, &type, 1);
       uint8_t lh = len >> 8, ll = len & 0xFF;
       g_byte_array_append(pkt, &lh, 1);
       g_byte_array_append(pkt, &ll, 1);
       g_byte_array_append(pkt, cmd, cmd_len);
       uint8_t ch = csum >> 8, cl = csum & 0xFF;
       g_byte_array_append(pkt, &ch, 1);
       g_byte_array_append(pkt, &cl, 1);
       return pkt;
   }
   ```

5. **Add to libfprint meson.build and udev rules**

6. **Test with fprintd-enroll / fprintd-verify**

---

## Ghidra Analysis Files

All decompiled C files in `/home/jason/tmp/ghidra-*.c`:

- `ghidra-FUN_1800060e0.c` — `Sensor::fsm_sendcmd` (USB send/receive)
- `ghidra-FUN_1800063b0.c` — `Sensor::fsm_sensor_control` (command dispatch)
- `ghidra-FUN_180003490.c` — `CBiometricDevice::OnPrepareHardware`
- `ghidra-FUN_180002870.c` — `CBiometricDevice::OnControlUnit`
- `ghidra-FUN_180001b60.c` — `CBiometricDevice::CreateUsbIoTargets`
- `ghidra-FUN_180007170.c` — `Sensor::mfm_handshake`
- `ghidra-FUN_180006d90.c` — `Sensor::fsm_update_enroll`

---

## Fallback: Windows VM + USB traffic capture

See `windows-vm.md` for full setup instructions.

---

## Legal Note

Reverse engineering for interoperability (writing a Linux driver) is legal under:
- **US:** DMCA §1201(f) — software interoperability exemption
- **EU:** Software Directive Article 6 — decompilation for interoperability

This work is solely for the purpose of enabling the device on Linux.

---

## References

- [libfprint source](https://gitlab.freedesktop.org/libfprint/libfprint)
- [libfprint driver writing guide](https://fprint.freedesktop.org/libfprint-dev/writing-a-driver.html)
- [Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)
- [FPC/GROW fingerprint sensor protocol (R30X series)](https://www.waveshare.com/wiki/UART_Fingerprint_Sensor_(C))
- [WinBio WBDI sensor adapter interface (MSDN)](https://learn.microsoft.com/en-us/windows/win32/secbiomet/winbio-framework-overview)
- [Fixing my fingerprint reader on Linux](https://infinytum.co/fixing-my-fingerprint-reader-on-linux-by-writing-a-driver-for-it/)
