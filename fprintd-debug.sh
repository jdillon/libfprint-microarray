#!/usr/bin/env bash
# Run fprintd in the foreground with full debug logging and capture output.
# Usage: ./fprintd-debug.sh [logfile]
#   logfile defaults to docs/fprintd-$(date +%Y%m%d-%H%M%S).log
set -euo pipefail

REPO_DIR="$(dirname "$(realpath "$0")")"
LOGDIR="$REPO_DIR/docs"
LOGFILE="${1:-$LOGDIR/fprintd-$(date +%Y%m%d-%H%M%S).log}"

echo "==> Stopping fprintd service..."
sudo systemctl stop fprintd 2>/dev/null || true

echo "==> Starting fprintd with debug logging (Ctrl-C to stop)"
echo "==> Log: $LOGFILE"
echo ""

sudo G_MESSAGES_DEBUG=all /usr/libexec/fprintd -t 2>&1 | tee "$LOGFILE"
