#!/usr/bin/env bash

set -ex

exit_handler() {
    exit "$XFSTESTS_EXIT_STATUS"
}
trap exit_handler TERM
trap "kill 0" INT EXIT

export RUST_BACKTRACE=1

TEST_DATA_DIR=$(mktemp --directory)
SCRATCH_DATA_DIR=$(mktemp --directory)
TEST_DIR=$(mktemp --directory)
SCRATCH_DIR=$(mktemp --directory)

set +e
# Clear mount log file, since the tests append to it
echo "" > /code/logs/xfstests_mount.log
DIR=/var/tmp/fuse-xfstests/check-fuser
mkdir -p $DIR
cd /code/fuse-xfstests

# requires OFD & POSIX locks. OFD locks are not supported by fuse
echo "generic/478" >> xfs_excludes.txt

# TODO: requires supporting orphaned files, that have an open file handle, but no links
echo "generic/484" >> xfs_excludes.txt

# Writes directly to scratch block dev
echo "generic/062" >> xfs_excludes.txt

# TODO: takes > 10min
echo "generic/069" >> xfs_excludes.txt

# TODO: needs fallocate which is missing from Linux FUSE driver (https://github.com/libfuse/libfuse/issues/395)
echo "generic/263" >> xfs_excludes.txt

# TODO: Passes, but takes ~30min
echo "generic/127" >> xfs_excludes.txt

# TODO: requires more complete falloc support. Also fills up the entire hard disk...
echo "generic/103" >> xfs_excludes.txt

# TODO: requires ulimit support for limiting file size
echo "generic/394" >> xfs_excludes.txt

# requires BSD lock support, and checks /proc/locks. fuse locks don't seem to show up in /proc/locks
echo "generic/504" >> xfs_excludes.txt

# TODO: requires support for system.posix_acl_access xattr sync'ing to file permissions
# Some information about it linked from here: https://stackoverflow.com/questions/29569408/documentation-of-posix-acl-access-and-friends
echo "generic/099" >> xfs_excludes.txt
echo "generic/105" >> xfs_excludes.txt
echo "generic/375" >> xfs_excludes.txt

# TODO: requires support for remounting read-only. 306 and 452 additionally need a change in
# fuse-xfstests, whose _scratch_remount answers "fuse.fuser does not support any options"
# without attempting the remount; 294 goes through _try_scratch_mount and does attempt it
echo "generic/294" >> xfs_excludes.txt
echo "generic/306" >> xfs_excludes.txt
echo "generic/452" >> xfs_excludes.txt

# TODO: exercises the noatime, relatime and strictatime mount options, and a read-only
# mount. fuse-xfstests cannot ask for any of them: _fuser_mount reads $4 for suid and drops
# the rest, so "_scratch_mount -o relatime" and "_scratch_cycle_mount noatime" both arrive as
# a plain mount. The example implements the kernel default, relatime, which is what the first
# phase wants; the noatime and strictatime phases need the option to reach the filesystem
echo "generic/003" >> xfs_excludes.txt

# TODO: Passes, but takes ~10min and writes > 20GB. Needs support for writing files with large holes,
# for this test to be fast
echo "generic/130" >> xfs_excludes.txt

# TODO: uses namespaces and inodes don't seem to get mapped properly
# this test ends up trying to chmod "/" (the root inode)
echo "generic/317" >> xfs_excludes.txt

# TODO: requires more complete ACL support
echo "generic/319" >> xfs_excludes.txt
echo "generic/444" >> xfs_excludes.txt

# TODO: Seems to cause a host OOM (even from inside Docker), when run with 84, 87, 88, 100, and 109
echo "generic/089" >> xfs_excludes.txt

# TODO: very slow. Passes, but takes > 30min
echo "generic/074" >> xfs_excludes.txt

# TODO: very slow. Ran for > 3hrs without completing
echo "generic/339" >> xfs_excludes.txt

# TODO: Passes, but takes ~60min on CI
echo "generic/006" >> xfs_excludes.txt
echo "generic/011" >> xfs_excludes.txt
echo "generic/070" >> xfs_excludes.txt

# TODO: very slow. Passes, but takes 20min
echo "generic/438" >> xfs_excludes.txt

# TODO: seems to crash host
echo "generic/476" >> xfs_excludes.txt

# TODO: writing to /proc/sys/vm/drop_caches is not allowed inside Docker
echo "generic/086" >> xfs_excludes.txt
echo "generic/391" >> xfs_excludes.txt
echo "generic/426" >> xfs_excludes.txt
echo "generic/467" >> xfs_excludes.txt
echo "generic/477" >> xfs_excludes.txt
# These two check that a file handle goes stale once the cache is dropped, so the failed
# drop leaves every handle resolvable and every check reports the opposite of what it wants
echo "generic/756" >> xfs_excludes.txt
echo "generic/777" >> xfs_excludes.txt

# Triggering memory compaction is not allowed inside Docker: /proc/sys/vm/compact_memory is
# read-only. Also very slow, running for > 11min before failing
echo "generic/750" >> xfs_excludes.txt

# Clearing the kernel ring buffer is not allowed inside Docker. The test itself passes; only
# dmesg's complaint about it shows up in the output
echo "generic/310" >> xfs_excludes.txt

# Setting sysctls is not allowed inside Docker: /proc/sys is mounted read-only. Both tests
# toggle fs.protected_symlinks / fs.protected_regular, and sysctl's refusal to do so lands in
# the output. Making /proc/sys writable would let them through, but those knobs are global, so
# the container would be reaching out and changing the host's
echo "generic/597" >> xfs_excludes.txt
echo "generic/598" >> xfs_excludes.txt

# fsx against hugepage-backed buffers, which cannot be set up here: MADV_COLLAPSE is refused
# and init_hugepages_buf fails before any filesystem operation runs
echo "generic/759" >> xfs_excludes.txt
echo "generic/760" >> xfs_excludes.txt

# Toggling CPUs offline is not allowed inside Docker: /sys/devices/system/cpu/*/online is
# read-only
echo "generic/650" >> xfs_excludes.txt

# Mounts overlayfs on top of the filesystem under test, which is refused here
echo "generic/631" >> xfs_excludes.txt

# Mounts the same device twice and assumes the two mounts share a superblock, as the test's own
# _exclude_fs list for nfs, overlay and tmpfs concedes. Each fuser mount is a separate process
# with its own state, so a file created through one mount is not visible through the other
echo "generic/732" >> xfs_excludes.txt

# TODO: requires support for shutting the filesystem down
echo "generic/766" >> xfs_excludes.txt

# Requires atomic writes, which xfs_io in this image cannot request (pwrite -A)
echo "generic/775" >> xfs_excludes.txt
echo "generic/778" >> xfs_excludes.txt

# Requires fio, which is not installed in the test image
echo "generic/774" >> xfs_excludes.txt

# TODO: permission failure invoking FIBMAP
echo "generic/519" >> xfs_excludes.txt

# TODO: Tries to create 50k+ files, which OOMs
echo "generic/531" >> xfs_excludes.txt

# Test requires mounting a loopback device
echo "generic/564" >> xfs_excludes.txt

# Very slow
echo "generic/117" >> xfs_excludes.txt
echo "generic/471" >> xfs_excludes.txt
echo "generic/642" >> xfs_excludes.txt
echo "generic/676" >> xfs_excludes.txt
echo "generic/707" >> xfs_excludes.txt
echo "generic/736" >> xfs_excludes.txt

# Too slow (>2min each)
echo "generic/007" >> xfs_excludes.txt
echo "generic/109" >> xfs_excludes.txt
echo "generic/120" >> xfs_excludes.txt
echo "generic/208" >> xfs_excludes.txt
echo "generic/323" >> xfs_excludes.txt


FUSER_EXTRA_MOUNT_OPTIONS="--auto-unmount --dev" TEST_DEV="$TEST_DATA_DIR" TEST_DIR="$TEST_DIR" SCRATCH_DEV="$SCRATCH_DATA_DIR" SCRATCH_MNT="$SCRATCH_DIR" \
./check-fuser -E xfs_excludes.txt "$@" \
| tee /code/logs/xfstests.log

export XFSTESTS_EXIT_STATUS=${PIPESTATUS[0]}

if [ $XFSTESTS_EXIT_STATUS ]
then
  cat /code/fuse-xfstests/results/generic/*.bad
  cp /code/fuse-xfstests/results/generic/*.bad /code/logs/
fi

rm -rf ${TEST_DATA_DIR}
rm -rf ${TEST_DIR}
rm -rf ${SCRATCH_DATA_DIR}
rm -rf ${SCRATCH_DIR}
