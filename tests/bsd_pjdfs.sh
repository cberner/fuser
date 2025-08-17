#!/usr/bin/env bash

set -ex

exit_handler() {
    if [ "${PJDFS_EXIT_STATUS}" -ne 0 ]; then
        echo "fuser simple mount logs:"
        tail -n 100 /tmp/mount.log
    fi
    exit "$PJDFS_EXIT_STATUS"
}
trap exit_handler TERM
trap "kill 0" INT EXIT

export PJDFS_EXIT_STATUS=1
export RUST_BACKTRACE=1

DATA_DIR=$(mktemp --directory)
DIR=$(mktemp --directory)

cargo build --release --example simple --features=libfuse
cargo run --release --example simple --features=libfuse -- -vvv --suid --data-dir $DATA_DIR --mount-point $DIR > /tmp/mount.log 2>&1 &
FUSE_PID=$!
sleep 0.5

echo "mounting at $DIR"
# Make sure FUSE was successfully mounted
mount
mount | grep fuser

set +e
cd ${DIR}
prove -rf /tmp/pjdfstest/tests | tee /tmp/pjdfs.log
export PJDFS_EXIT_STATUS=${PIPESTATUS[0]}
echo "Total failed:"
cat /tmp/pjdfs.log | egrep -o 'Failed: [0-9]+' | egrep -o '[0-9]+' | paste -s -d+ | bc

rm -rf ${DATA_DIR}

kill $FUSE_PID
wait $FUSE_PID
