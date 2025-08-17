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

# TODO: fix these tests on BSD
export HARNESS_SKIPTEST='/tmp/pjdfstest/tests/chmod/00.t \
/tmp/pjdfstest/tests/chmod/05.t \
/tmp/pjdfstest/tests/chmod/07.t \
/tmp/pjdfstest/tests/chmod/11.t \
/tmp/pjdfstest/tests/chmod/12.t \
/tmp/pjdfstest/tests/chown/00.t \
/tmp/pjdfstest/tests/chown/05.t \
/tmp/pjdfstest/tests/chown/07.t \
/tmp/pjdfstest/tests/ftruncate/00.t \
/tmp/pjdfstest/tests/ftruncate/05.t \
/tmp/pjdfstest/tests/ftruncate/06.t \
/tmp/pjdfstest/tests/link/00.t \
/tmp/pjdfstest/tests/link/06.t \
/tmp/pjdfstest/tests/link/07.t \
/tmp/pjdfstest/tests/link/11.t \
/tmp/pjdfstest/tests/mkdir/00.t \
/tmp/pjdfstest/tests/mkdir/05.t \
/tmp/pjdfstest/tests/mkdir/06.t \
/tmp/pjdfstest/tests/open/00.t \
/tmp/pjdfstest/tests/open/05.t \
/tmp/pjdfstest/tests/open/06.t \
/tmp/pjdfstest/tests/open/07.t \
/tmp/pjdfstest/tests/open/08.t \
/tmp/pjdfstest/tests/posix_fallocate/00.t \
/tmp/pjdfstest/tests/rename/00.t \
/tmp/pjdfstest/tests/rename/04.t \
/tmp/pjdfstest/tests/rename/05.t \
/tmp/pjdfstest/tests/rename/09.t \
/tmp/pjdfstest/tests/rename/10.t \
/tmp/pjdfstest/tests/rename/15.t \
/tmp/pjdfstest/tests/rename/18.t \
/tmp/pjdfstest/tests/rename/21.t \
/tmp/pjdfstest/tests/rmdir/07.t \
/tmp/pjdfstest/tests/rmdir/08.t \
/tmp/pjdfstest/tests/rmdir/11.t \
/tmp/pjdfstest/tests/symlink/05.t \
/tmp/pjdfstest/tests/symlink/06.t \
/tmp/pjdfstest/tests/truncate/00.t \
/tmp/pjdfstest/tests/truncate/05.t \
/tmp/pjdfstest/tests/truncate/06.t \
/tmp/pjdfstest/tests/unlink/00.t \
/tmp/pjdfstest/tests/unlink/05.t \
/tmp/pjdfstest/tests/unlink/06.t \
/tmp/pjdfstest/tests/unlink/11.t \
/tmp/pjdfstest/tests/utimensat/03.t \
/tmp/pjdfstest/tests/utimensat/06.t \
/tmp/pjdfstest/tests/utimensat/07.t \
/tmp/pjdfstest/tests/utimensat/08.t'

set +e
cd ${DIR}
prove -rf /tmp/pjdfstest/tests | tee /tmp/pjdfs.log
export PJDFS_EXIT_STATUS=${PIPESTATUS[0]}
echo "Total failed:"
cat /tmp/pjdfs.log | egrep -o 'Failed: [0-9]+' | egrep -o '[0-9]+' | paste -s -d+ | bc

rm -rf ${DATA_DIR}

kill $FUSE_PID
wait $FUSE_PID
