#!/usr/bin/env bash
# Build and install the microarray driver into the system libfprint.
# Run from anywhere; finds the libfprint source tree automatically.
set -euo pipefail

DRIVER_SRC="$(dirname "$(realpath "$0")")/microarray.c"
LIBFPRINT_SRC="${LIBFPRINT_SRC:-$HOME/libfprint}"
DEST="$LIBFPRINT_SRC/libfprint/drivers/microarray/microarray.c"
BUILD="$LIBFPRINT_SRC/build"

echo "==> Copying driver source..."
cp "$DRIVER_SRC" "$DEST"

echo "==> Building..."
ninja -C "$BUILD" libfprint/libfprint-2.so.2.0.0

echo "==> Saving build output..."
REPO_DIR="$(dirname "$(realpath "$0")")"
cp "$BUILD/libfprint/libfprint-2.so.2.0.0" "$REPO_DIR/build/libfprint-2.so.2.0.0"

echo "==> Installing (requires sudo)..."
sudo systemctl stop fprintd
sudo cp "$BUILD/libfprint/libfprint-2.so.2.0.0" /usr/lib64/libfprint-2.so.2.0.0
echo "==> Done. Run: fprintd-enroll -f right-index-finger"
