# microarray.c — libfprint driver for MicroarrayTechnology MAFP (3274:8012)

## Status: **WORKING** ✓

Enrollment and verify confirmed working on real hardware (2026-03-10).

## Hardware

[TNP Nano USB Fingerprint Reader](https://www.amazon.com/dp/B07DW62XS7) (Amazon)

<img src="docs/tnp-nano-usb-fingerprint-reader.jpg" width="200" alt="TNP Nano USB Fingerprint Reader">

Protocol fully reverse-engineered from `MicroarrayFingerprintDevice.dll` v9.47.11.214
using [Ghidra](https://ghidra-sre.org) 12.0.4 headless analysis.
See [Reverse Engineering](docs/reverse-engineering.md) for how to reproduce.

## What Works

- Enrollment: 6-stage press/lift cycle, stores template to device flash
- Verify: correct finger matches, wrong finger rejects
- Finger-present detection via GET_IMAGE polling (CMD 0x01)
- Press/lift detection between captures via `waiting_for_lift` flag
- Per-enrollment handshake (CMD 0x23) to reset device session state
- Device flash clear (CMD 0x0D) at enrollment start to free FID slots
- FID bitmap parsing (CMD 0x1F) to find first free slot
- Template storage (CMD 0x06) and retrieval for verify (CMD 0x66)

## Known Limitations / TODOs

1. **CMD 0x0D (Empty) clears ALL templates** at the start of each enrollment. This is necessary because failed enrollments leave stale templates in device flash. The proper fix is to track which FID slot we're writing to and only clear that slot, or to not clear at all if the device has free slots.

2. **Interrupt endpoint (EP 0x82)** not used. Currently polling CMD 0x01 for finger detection. The interrupt endpoint would be more efficient and allow proper finger-on/off events without extra USB traffic.

3. **"Hold to complete" quirk**: if the user holds their finger without lifting between captures, the `waiting_for_lift` flag will wait for a lift before accepting the next sample. This works correctly in practice.

4. **Handshake response** is accepted if header bytes EF 01 are present. The Windows driver validates 35 bytes via `FUN_180006fc0` which was not fully decompiled.

5. **Identify (1:N search)** not implemented. CMD 0x66 may support searching all slots with FID=0xFFFF (unconfirmed).

## Key Protocol Discoveries (from debugging)

- The Windows driver calls `mfm_handshake` (CMD 0x23) at the **start of every enrollment**, not just at device open. Without this, failed enrollments leave the device in a broken session state.
- The device supports exactly **30 FID slots** (0–29). StoreChar returns 0x18 if the slot is out of range.
- CMD 0x0D (Empty) returns success and clears all 30 slots.
- The required number of GenChar samples for RegModel is `DAT_180032020 / 3`clamped to \[3, 6\]. For this device the value is 6.
- Extra GET_IMAGE calls between GenChars corrupt the device's char buffer state. The `waiting_for_lift` approach must minimize GET_IMAGE polling between captures.

## Build

```bash
./build.sh
```

Copies `src/microarray.c` into the libfprint source tree (`$LIBFPRINT_SRC`, defaults to `~/libfprint`), builds with ninja, and installs the shared library.

## Testing

```bash
# Enroll right index finger (6 press/lift cycles)
fprintd-enroll -f right-index-finger

# Verify
fprintd-verify -f right-index-finger

# Debug logging
sudo G_MESSAGES_DEBUG=all /usr/libexec/fprintd -t 2>&1
```

## License

[MIT](LICENSE)

## Legal

This driver was created by reverse engineering the proprietary Windows driver
(`MicroarrayFingerprintDevice.dll`) for the sole purpose of hardware interoperability on Linux.
No proprietary code is included — the driver is an independent implementation of the USB protocol.

Reverse engineering for interoperability is protected under:

- **US:** DMCA §1201(f) — software interoperability exemption
- **EU:** Software Directive Article 6 — decompilation for interoperability

See [Reverse Engineering](docs/reverse-engineering.md) for full details on the analysis methodology.

## Protocol Reference

See [Protocol Documentation](docs/fingerprint-driver-re.md) for full protocol details.
