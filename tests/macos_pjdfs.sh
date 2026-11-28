#!/usr/bin/env bash

set -ex

# PJDFS setup
# /etc/fuse.conf isn't used on FreeBSD, but simple.rs uses it
PROJ_DIR=$(pwd)
PJDFS_TMP_DIR=$(mktemp --directory)
cd $PJDFS_TMP_DIR
git clone https://github.com/fleetfs/pjdfstest
cd pjdfstest
git checkout d3beed6f5f15c204a8af3df2f518241931a42e94
autoreconf -ifs
./configure
make pjdfstest
cd $PROJ_DIR

exit_handler() {
    if [ "${PJDFS_EXIT_STATUS}" -ne 0 ]; then
        echo "fuser simple mount logs:"
        tail -n 100 /tmp/mount.log
    fi
    exit "$PJDFS_EXIT_STATUS"
}
trap exit_handler TERM INT EXIT

export PJDFS_EXIT_STATUS=1
export RUST_BACKTRACE=1

# PJDFS_EXCLUDED=1 runs only the tests excluded below, as root, as pjdfstest is meant to run:
# most switch to other users. simple then admits them, as /etc/fuse.conf allows other users
EXCLUDED_RUN=${PJDFS_EXCLUDED:-}
if [ -n "$EXCLUDED_RUN" ]; then
  echo user_allow_other | sudo tee /etc/fuse.conf > /dev/null
fi

DATA_DIR=$(mktemp --directory)
# Canonical, as the mount table lists it (/var is a symlink to /private/var)
DIR=$(cd "$(mktemp --directory)" && pwd -P)

# e.g. FUSER_FEATURES=macos-nfs to test the NFS backend
FEATURES=${FUSER_FEATURES:+--features $FUSER_FEATURES}
cargo build --release $FEATURES --example simple
cargo run --release $FEATURES --example simple -- -vvv --suid ${FUSER_MOUNT_OPTION:+-o "$FUSER_MOUNT_OPTION"} --data-dir $DATA_DIR --mount-point $DIR > /tmp/mount.log 2>&1 &
FUSE_PID=$!

echo "mounting at $DIR"
# Make sure FUSE was successfully mounted. With the FSKit backend the mount table shows
# macfuse://<uuid> rather than the fsname, so match the mount point
for _ in $(seq 1 100); do
  mount | grep -q " on $DIR (" && break
  sleep 0.1
done
mount
mount | grep " on $DIR ("

# macFUSE's FSKit backend reports a NAME_MAX of 256, one more than the filesystem allows, and no
# PATH_MAX, so the tests that probe those limits cannot pass there. macOS's NFSv3 client reports
# no PATH_MAX either, which NFSv3 has no way to carry
LIMIT_TESTS='/(chmod|ftruncate|link|mkdir|open|rmdir|symlink|truncate|unlink)'
LIMIT_SKIP='^$'
if [ "${FUSER_MOUNT_OPTION:-}" = "backend=fskit" ]; then
  LIMIT_SKIP="$LIMIT_TESTS/0[23]\.t$"
elif [ "${FUSER_FEATURES:-}" = "macos-nfs" ]; then
  LIMIT_SKIP="$LIMIT_TESTS/03\.t$"
fi

set +e
cd ${DIR}
# So that the status is prove's, not that of the find at the head of the pipeline
set -o pipefail
# Excluded from the usual run, as most switch to other users, which needs root: see
# PJDFS_EXCLUDED above
EXCLUDED=(
  symlink/05.t
  symlink/06.t
  truncate/00.t
  truncate/05.t
  truncate/06.t
  unlink/00.t
  unlink/05.t
  unlink/06.t
  unlink/11.t
  ftruncate/00.t
  ftruncate/05.t
  ftruncate/06.t
  link/00.t
  link/06.t
  link/07.t
  link/11.t
  mkdir/00.t
  mkdir/05.t
  mkdir/06.t
  rmdir/07.t
  rmdir/08.t
  rmdir/11.t
  utimensat/08.t
  utimensat/03.t
  rename/00.t
  rename/01.t
  rename/02.t
  rename/04.t
  rename/05.t
  rename/09.t
  rename/10.t
  rename/15.t
  rename/18.t
  rename/20.t
  rename/21.t
  posix_fallocate/00.t
  chown/00.t
  chown/02.t
  chown/03.t
  chown/05.t
  chown/07.t
  chmod/00.t
  chmod/05.t
  chmod/07.t
  chmod/11.t
  chmod/12.t
  open/00.t
  open/05.t
  open/06.t
  open/07.t
  open/08.t
)
# Matched at the end of the path, as the names were before: link/00.t also names
# symlink/00.t and unlink/00.t
EXCLUDED_RE="($(IFS='|'; echo "${EXCLUDED[*]}" | sed 's/\./\\./g'))$"
if [ -n "$EXCLUDED_RUN" ]; then
  find $PJDFS_TMP_DIR/pjdfstest/tests -name '*.t' | grep -E "$EXCLUDED_RE" \
  | grep -v -E "$LIMIT_SKIP" | sort | xargs sudo prove -f | tee /tmp/pjdfs.log
else
  find $PJDFS_TMP_DIR/pjdfstest/tests -name '*.t' | grep -v -E "$EXCLUDED_RE" \
  | grep -v -E "$LIMIT_SKIP" | xargs prove -f | tee /tmp/pjdfs.log
fi
export PJDFS_EXIT_STATUS=$?
echo "Total failed:"
cat /tmp/pjdfs.log | egrep -o 'Failed: [0-9]+' | egrep -o '[0-9]+' | paste -s -d+ - | bc
TOTAL=$(egrep -o 'Tests=[0-9]+' /tmp/pjdfs.log | egrep -o '[0-9]+' | tail -n 1)
FAILED=$(egrep -o 'Failed: [0-9]+' /tmp/pjdfs.log | egrep -o '[0-9]+' | awk '{ s += $1 } END { print s + 0 }')
echo "pjdfs: $((${TOTAL:-0} - FAILED)) of ${TOTAL:-0} tests passed, $FAILED failed"
if [ -n "$EXCLUDED_RUN" ]; then
  # Which of the excluded test files now pass, for the job summary
  {
    echo "### pjdfs excluded tests, as root: ${FUSER_FEATURES:-macFUSE} ${FUSER_MOUNT_OPTION:-}"
    echo
    echo "$((${TOTAL:-0} - FAILED)) of ${TOTAL:-0} tests passed"
    echo
    echo "| test | result |"
    echo "|---|---|"
    grep -E '^/.*\.t \.\.' /tmp/pjdfs.log | sed -E 's#^.*/tests/##; s# \.+ *# | #' \
      | sed -E 's#\| *$#| failed#; s#^#| #; s#$# |#'
  } >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
  # Informational: the usual run is what gates
  PJDFS_EXIT_STATUS=0
fi

rm -rf ${DATA_DIR}

# Killing the server would leave an NFS mount behind, unanswered: unmount it first, which
# ends the session
if [ -n "${FUSER_FEATURES:-}" ]; then
  cd "$PROJ_DIR"
  umount "$DIR"
fi
kill $FUSE_PID
wait $FUSE_PID
