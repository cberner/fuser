#!/usr/bin/env bash
# Times a few workloads (tests/macos_bench.py) on a mount of the simple example, through the
# backend that FUSER_FEATURES or FUSER_MOUNT_OPTION picks: e.g. FUSER_FEATURES=macos-nfs, or
# FUSER_MOUNT_OPTION=backend=fskit for macFUSE's FSKit backend

set -euo pipefail

FEATURES=${FUSER_FEATURES:+--features $FUSER_FEATURES}
LABEL="${FUSER_FEATURES:-macFUSE}${FUSER_MOUNT_OPTION:+ $FUSER_MOUNT_OPTION}"
DATA_DIR=$(mktemp -d)
# Canonical, as the mount table lists it (/var is a symlink to /private/var)
DIR=$(cd "$(mktemp -d)" && pwd -P)

cargo build --release $FEATURES --example simple
# Warnings, such as of calls the server took long over, unless BENCH_LOG_LEVEL says otherwise
./target/release/examples/simple "${BENCH_LOG_LEVEL:--v}" ${FUSER_MOUNT_OPTION:+-o "$FUSER_MOUNT_OPTION"} \
  --data-dir "$DATA_DIR" --mount-point "$DIR" > /tmp/bench-mount.log 2>&1 &
PID=$!

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- mount log: warnings, errors and the last COMPOUNDs"
    grep -E "WARN|ERROR|COMPOUND|NFS call" /tmp/bench-mount.log | tail -n 80 || true
    echo "--- mount log, last 30 lines"
    tail -n 30 /tmp/bench-mount.log || true
  fi
  # Unmounted first: killing the server under an NFS or SMB mount would leave it hanging
  umount "$DIR" 2>/dev/null || true
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  rm -rf "$DATA_DIR"
  exit "$status"
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  mount | grep -q " on $DIR (" && break
  sleep 0.1
done
mount | grep " on $DIR ("

python3 "$(dirname "$0")/macos_bench.py" "$DIR" "$LABEL"
