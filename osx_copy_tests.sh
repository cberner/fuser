#!/usr/bin/env bash

set -euo pipefail

TEST_EXIT_STATUS=1
FUSE_PID=""
MOUNT_DIR=""
DATA_DIR=""
WORK_DIR=""

cleanup() {
  set +e
  if [[ -n "$FUSE_PID" ]]; then
    if kill -0 "$FUSE_PID" 2>/dev/null; then
      kill "$FUSE_PID" 2>/dev/null || true
      wait "$FUSE_PID" 2>/dev/null || true
    fi
  fi

  if [[ -n "$MOUNT_DIR" && -d "$MOUNT_DIR" ]]; then
    # macOS sometimes requires diskutil to unmount FUSE mounts.
    umount "$MOUNT_DIR" 2>/dev/null || diskutil unmount "$MOUNT_DIR" 2>/dev/null || true
    rmdir "$MOUNT_DIR" 2>/dev/null || true
  fi

  if [[ -n "$DATA_DIR" && -d "$DATA_DIR" ]]; then
    rm -rf "$DATA_DIR"
  fi

  if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi

  exit "$TEST_EXIT_STATUS"
}
trap cleanup EXIT INT TERM

export RUST_BACKTRACE=1

cargo build --example simple > /dev/null

DATA_DIR=$(mktemp -d)
MOUNT_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)

cargo run --example simple -- \
  --data-dir "$DATA_DIR" \
  --mount-point "$MOUNT_DIR" \
  -v &
FUSE_PID=$!

# Wait up to 15s for the mount to appear.
for _ in $(seq 30); do
  if mount | grep -q "$MOUNT_DIR"; then
    break
  fi
  sleep 0.5
done

if ! mount | grep -q "$MOUNT_DIR"; then
  echo "Failed to mount simple filesystem at $MOUNT_DIR" >&2
  exit 1
fi

# --- Copy from host into the FUSE mount ---
HOST_SOURCE="$WORK_DIR/host_source.txt"
FUSE_TARGET="$MOUNT_DIR/host_to_fuse.txt"
PAYLOAD="macos copy test $(date +%s)"
printf '%s' "$PAYLOAD" > "$HOST_SOURCE"

if ! cp "$HOST_SOURCE" "$FUSE_TARGET"; then
  echo "Copy from host into FUSE mount failed" >&2
  exit 1
fi

if [[ "$(cat "$FUSE_TARGET")" != "$PAYLOAD" ]]; then
  echo "Data mismatch after copying host file into FUSE mount" >&2
  exit 1
fi

# --- Copy from the FUSE mount back to the host ---
FUSE_TO_HOST="$WORK_DIR/fuse_to_host.txt"
if ! cp "$FUSE_TARGET" "$FUSE_TO_HOST"; then
  echo "Copy from FUSE mount back to host failed" >&2
  exit 1
fi

if ! cmp -s "$HOST_SOURCE" "$FUSE_TO_HOST"; then
  echo "Round-trip copy mismatch between host and FUSE" >&2
  exit 1
fi

# --- Copy within the FUSE mount ---
FUSE_INTERNAL_COPY="$MOUNT_DIR/fuse_internal.txt"
if ! cp "$FUSE_TARGET" "$FUSE_INTERNAL_COPY"; then
  echo "Copy inside the FUSE mount failed" >&2
  exit 1
fi

if [[ "$(cat "$FUSE_INTERNAL_COPY")" != "$PAYLOAD" ]]; then
  echo "Data mismatch after copying file within FUSE mount" >&2
  exit 1
fi

# Simulate Finder metadata probing that happens during GUI copies.
JOINED_IMAGE="$MOUNT_DIR/joined_image_25.png"
if ! cp "$FUSE_TARGET" "$JOINED_IMAGE"; then
  echo "Failed to create Finder-style payload inside FUSE mount" >&2
  exit 1
fi

export MOUNT_DIR
export JOINED_IMAGE
python3 - <<'PY'
import os
import subprocess
import sys
import time

mount = os.environ["MOUNT_DIR"]
joined = os.environ["JOINED_IMAGE"]

for _ in range(3):
    os.statvfs(mount)
    time.sleep(0.05)

def probe_xattr(path: str) -> None:
    result = subprocess.run(
        ["xattr", "-p", "com.apple.FinderInfo", path],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return

    stderr = (result.stderr or "").lower()
    if "no such xattr" in stderr or "attribute not found" in stderr:
        return
    if "permission" in stderr:
        return

    result.check_returncode()

probe_xattr(mount)

os.stat(mount)

with os.scandir(mount) as it:
    entries = {entry.name for entry in it}
if "joined_image_25.png" not in entries:
    sys.exit("Finder-style test file missing after scandir")

fd = os.open(joined, os.O_RDONLY)
os.close(fd)

probe_xattr(joined)
PY

# --- Ensure FUSE process is still responding ---
if ! kill -0 "$FUSE_PID" 2>/dev/null; then
  echo "FUSE process exited unexpectedly during copy tests" >&2
  exit 1
fi

# Access the files again to confirm the mount is still healthy.
if [[ "$(cat "$FUSE_INTERNAL_COPY")" != "$PAYLOAD" ]]; then
  echo "Unable to read file inside FUSE mount after copy operations" >&2
  exit 1
fi

TEST_EXIT_STATUS=0
