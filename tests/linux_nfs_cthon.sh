#!/usr/bin/env bash
# Tests the NFS backend's server with another client than macOS's: Linux's. The simple example
# serves over NFS without mounting (built with FUSER_NFS_SERVE_ONLY), the kernel mounts it, and
# the Connectathon suite (cthon04) runs on the mount. NFS_VERS picks NFSv3 (the default) or
# NFSv4.1. Mounting needs sudo.

set -euo pipefail

PORT=${FUSER_NFS_PORT:-20490}
VERS=${NFS_VERS:-3}
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
    echo "--- server log: the last NFSv4 COMPOUNDs, warnings and errors"
    grep -E "COMPOUND|WARN|ERROR" "$LOG" | tail -n 100 || true
    echo "--- server log, last 30 lines"
    tail -n 30 "$LOG" || true
  fi
  exit "$status"
}
trap cleanup EXIT

if [ ! -d "$CTHON" ]; then
  git clone --depth 1 git://git.linux-nfs.org/projects/steved/cthon04.git "$CTHON" ||
    git clone --depth 1 https://git.linux-nfs.org/projects/steved/cthon04.git "$CTHON"
fi
make -C "$CTHON" > /dev/null

# Requests carry their caller's ids, and the kernel makes the mount's own as root, which
# mounts it here: simple admits other users, as /etc/fuse.conf allows
echo user_allow_other | sudo tee /etc/fuse.conf > /dev/null
FUSER_NFS_SERVE_ONLY=1 cargo build --release --features macos-nfs --example simple
OPTIONS=()
if [ "$VERS" != 3 ]; then
  OPTIONS=(-o "vers=$VERS")
fi
FUSER_NFS_PORT=$PORT ./target/release/examples/simple -vvv "${OPTIONS[@]}" --data-dir "$DATA_DIR" \
  --mount-point "$MNT" > "$LOG" 2>&1 &
PID=$!
for _ in $(seq 1 100); do
  (echo > "/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
  sleep 0.1
done

# The export, which the server names once it serves
for _ in $(seq 1 100); do
  EXPORT=$(sed -n 's/.*Serving NFS on .*, export \([^,]*\),.*/\1/p' "$LOG")
  [ -n "$EXPORT" ] && break
  sleep 0.1
done
if [ "$VERS" = 3 ]; then
  # Both ports given, and no NLM (locks stay on the client): the kernel needs neither rpcbind
  # nor statd
  sudo mount -t nfs -o "vers=3,proto=tcp,port=$PORT,mountport=$PORT,mountproto=tcp,nolock" \
    "127.0.0.1:$EXPORT" "$MNT"
else
  # Locks are NFSv4's own, which the server passes on to the filesystem
  sudo mount -t nfs -o "vers=$VERS,proto=tcp,port=$PORT" "127.0.0.1:$EXPORT" "$MNT"
fi
mount | grep " $MNT "

cd "$CTHON"
# Basic, general, special and lock tests, in full
NFSTESTDIR="$MNT/cthon" ./runtests -a -t "$MNT/cthon"
