# USB Fingerprint Reader Setup — Fedora 43 / KDE

## Hardware

**Device:** TNP Nano USB Fingerprint Reader
**Amazon:** [B07DW62XS7](https://www.amazon.com/TNP-Fingerprint-Reader-Windows-Hello/dp/B07DW62XS7)
**Chip:** Elan Microelectronics (`04f3:0c26`)
**Form factor:** Nano dongle — sits flush in USB-A port

### Why This Device

- `04f3:0c26` is confirmed in libfprint 1.94.10 udev hwdb (already installed on this system)
- No extra drivers or hacks needed — plug and play with fprintd
- Smallest confirmed Linux-compatible fingerprint reader found

---

## Setup After Device Arrives

### 1. Install fprintd

```bash
sudo dnf install -y fprintd fprintd-pam
```

### 2. Enroll a Fingerprint

Plug in the TNP Nano, then:

```bash
fprintd-enroll
```

Follow the prompts — swipe your finger several times. To enroll additional fingers:

```bash
fprintd-enroll -f right-index-finger
```

Valid finger names: `left-thumb`, `left-index-finger`, `left-middle-finger`,
`left-ring-finger`, `left-little-finger` (and same for `right-*`).

### 3. Verify Enrollment

```bash
fprintd-verify
```

### 4. Enable in KDE

**System Settings → Users → configure Fingerprint Authentication**

KDE has built-in fingerprint support — no manual PAM editing needed for the
lock screen and login.

### 5. Enable for sudo (optional)

To use fingerprint for `sudo` in the terminal, add to `/etc/pam.d/sudo`:

```bash
sudo tee /etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth        sufficient    pam_fprintd.so
auth        include       system-auth
account     include       system-auth
password    include       system-auth
session     include       system-auth
EOF
```

> **Note:** With `sufficient`, if the fingerprint read fails or times out,
> it falls back to password automatically.

---

## Verify Device is Recognized

After plugging in:

```bash
# Should show the Elan device
lsusb | grep 04f3

# Should list the fingerprint device
fprintd-list $(whoami)
```

---

## Troubleshooting

**Device not recognized:**
```bash
lsusb | grep 04f3
# If missing, try a different USB port
# Check dmesg for errors:
sudo dmesg | tail -20
```

**fprintd not finding device:**
```bash
systemctl status fprintd
sudo systemctl restart fprintd
```

**Re-enroll a finger:**
```bash
fprintd-delete $(whoami)
fprintd-enroll
```

---

## System Info

| Item | Detail |
|---|---|
| OS | Fedora 43 |
| libfprint version | 1.94.10-1.fc43 |
| Device USB ID | 04f3:0c26 |
| hwdb entry | `/usr/lib/udev/hwdb.d/60-autosuspend-libfprint-2.hwdb` |
| Desktop | KDE Plasma (Wayland) |
