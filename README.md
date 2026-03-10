# microarray.c — libfprint driver for MicroarrayTechnology MAFP (3274:8012)

## Status: **SKELETON — NOT YET TESTED**

The protocol was fully reverse-engineered from `MicroarrayFingerprintDevice.dll`
using Ghidra 12.0.4 headless analysis. The command opcodes and packet framing
are confirmed. The code compiles but has not yet been run against real hardware.

## What Works (on paper)

- Packet framing (`ma_build_cmd`) — confirmed from `Sensor::fsm_sendcmd`
- Response parsing (`ma_parse_response`) — confirmed from checksum/response logic
- Handshake packet bytes — confirmed from `Sensor::mfm_handshake`
- All USB command opcodes — confirmed from `Sensor::fsm_sensor_control` and callers
- Enrollment and verify state machine structure

## What Still Needs Work

1. **GetImage retry loop**: CMD 0x01 needs to be polled until resp[0]==0 (finger
   present). Currently jumps straight past if not ready.

2. **FID bitmap parsing**: `ENROLL_RECV_READ_INDEX` needs to scan the 32-byte
   bitmap returned by CMD 0x1F to find the first free slot.

3. **Response buffer handling**: The `ma_recv_cb` functions need to parse the
   response and check `resp[0]` before advancing the SSM.

4. **Handshake response validation**: `mfm_handshake` in the DLL calls
   `FUN_180006fc0(response, 0x23)` to validate 35 bytes — this function was not
   decompiled. The handshake receive currently just discards the data.

5. **Identify (1:N search)**: Not yet implemented. CMD 0x66 can search all slots
   if FID is passed as 0xFFFF (unconfirmed — needs testing).

6. **Interrupt endpoint (EP 0x82)**: Finger-detect events on the interrupt
   endpoint are not yet wired up. Currently using polling CMD 0x01.

7. **Checksum formula verification**: The checksum bytes in the handshake packet
   (0xA2) don't match the formula in fsm_sendcmd. May need adjustment.

## Integration into libfprint

```bash
# Clone libfprint
git clone https://gitlab.freedesktop.org/libfprint/libfprint
cd libfprint

# Copy driver
cp /home/jason/tmp/libfprint-driver/microarray.c libfprint/drivers/

# Edit libfprint/drivers/meson.build — add to drivers list:
#   'microarray',

# Edit libfprint/libfprint/fpi-device-private.h — add extern declaration

# Edit libfprint/libfprint/drivers.h — add to driver list

# Build
mkdir build && cd build
meson .. -Ddrivers=microarray,...
ninja
```

## Testing

```bash
# Check device is visible
lsusb | grep 3274

# Test with fprintd
fprintd-enroll
fprintd-verify
```

## Protocol Reference

See `/home/jason/tmp/fingerprint-driver-re.md` for full protocol documentation.
