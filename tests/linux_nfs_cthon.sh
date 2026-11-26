#!/usr/bin/env bash
# Tests the NFS backend's server with another client than macOS's: Linux's. The simple example
# serves over NFS without mounting (built with FUSER_NFS_SERVE_ONLY), the kernel mounts it, and
# the Connectathon suite (cthon04) runs on the mount. Mounting needs sudo.

set -euo pipefail

PORT=${FUSER_NFS_PORT:-20490}
CTHON=${CTHON_DIR:-/tmp/cthon04}
LOG=/tmp/nfs-serve.log
DATA_DIR=$(mktemp -d)
MNT=$(mktemp -d)
PID=""

cleanup() {
  status=$?
  sudo umount -f "$MNT" 2>/dev/null || true
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ]; then
    echo "--- server log, last 100 lines"
    tail -n 100 "$LOG" || true
  fi
  exit "$status"
}
trap cleanup EXIT

if [ ! -d "$CTHON" ]; then
  git clone --depth 1 git://git.linux-nfs.org/projects/steved/cthon04.git "$CTHON" ||
    git clone --depth 1 https://git.linux-nfs.org/projects/steved/cthon04.git "$CTHON"
fi
make -C "$CTHON" > /dev/null

FUSER_NFS_SERVE_ONLY=1 cargo build --release --features macos-nfs --example simple
FUSER_NFS_PORT=$PORT ./target/release/examples/simple -v --data-dir "$DATA_DIR" \
  --mount-point "$MNT" > "$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 100); do
  (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
  sleep 0.1
done

# Both ports given, and no NLM (locks stay on the client): the kernel needs neither rpcbind
# nor statd. The export is the simple example's filesystem name
sudo mount -t nfs -o "vers=3,proto=tcp,port=$PORT,mountport=$PORT,mountproto=tcp,nolock" \
  127.0.0.1:/fuser "$MNT"
mount | grep " $MNT "

cd "$CTHON"
# Basic, general, special and lock tests, in full
NFSTESTDIR="$MNT/cthon" ./runtests -a -t "$MNT/cthon"
