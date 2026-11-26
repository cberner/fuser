#!/usr/bin/env bash
# Times a few workloads (tests/macos_bench.py) on a mount of the simple example, through the
# backend that FUSER_FEATURES or FUSER_MOUNT_OPTION picks: e.g. FUSER_FEATURES=macos-nfs, or
# FUSER_MOUNT_OPTION=backend=fskit for macFUSE's FSKit backend

set -euo pipefail

FEATURES=${FUSER_FEATURES:+--features $FUSER_FEATURES}
LABEL=${FUSER_FEATURES:-${FUSER_MOUNT_OPTION:-macFUSE}}
DATA_DIR=$(mktemp -d)
# Canonical, as the mount table lists it (/var is a symlink to /private/var)
DIR=$(cd "$(mktemp -d)" && pwd -P)

cargo build --release $FEATURES --example simple
./target/release/examples/simple ${FUSER_MOUNT_OPTION:+-o "$FUSER_MOUNT_OPTION"} \
  --data-dir "$DATA_DIR" --mount-point "$DIR" > /tmp/bench-mount.log 2>&1 &
PID=$!

cleanup() {
  # Unmounted first: killing the server under an NFS or SMB mount would leave it hanging
  umount "$DIR" 2>/dev/null || true
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  mount | grep -q " on $DIR (" && break
  sleep 0.1
done
mount | grep " on $DIR ("

python3 "$(dirname "$0")/macos_bench.py" "$DIR" "$LABEL"
