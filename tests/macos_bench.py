"""Times a few workloads on a mounted filesystem: python3 macos_bench.py <dir> <label>

Large sequential writes and reads, and many small files: create, stat, read, list, delete.
Reads use F_NOCACHE, so that they reach the filesystem rather than the page cache.
"""

import fcntl
import os
import sys
import time

MB = 1 << 20
BIG = 256 * MB
SMALL_FILES = 1000
SMALL = 4096
# macOS: no data caching for this descriptor
F_NOCACHE = 48

root, label = sys.argv[1], sys.argv[2]
results = []


def no_cache(fd):
    # Elsewhere, where this only checks the script, the page cache serves reads
    if sys.platform == "darwin":
        fcntl.fcntl(fd, F_NOCACHE, 1)


def timed(name, amount, unit, run):
    start = time.perf_counter()
    run()
    seconds = time.perf_counter() - start
    results.append((name, amount / seconds, unit, seconds))


big = os.path.join(root, "big")
block = os.urandom(MB)


def write_big():
    with open(big, "wb") as f:
        for _ in range(BIG // MB):
            f.write(block)
        f.flush()
        os.fsync(f.fileno())


def read_big():
    fd = os.open(big, os.O_RDONLY)
    try:
        no_cache(fd)
        while os.read(fd, MB):
            pass
    finally:
        os.close(fd)


small_dir = os.path.join(root, "small")
os.mkdir(small_dir)
names = [os.path.join(small_dir, f"f{i:05}") for i in range(SMALL_FILES)]
small = os.urandom(SMALL)


def create_small():
    for name in names:
        with open(name, "wb") as f:
            f.write(small)


def stat_small():
    for name in names:
        os.stat(name)


def read_small():
    for name in names:
        fd = os.open(name, os.O_RDONLY)
        try:
            no_cache(fd)
            os.read(fd, SMALL)
        finally:
            os.close(fd)


def list_small():
    for entry in os.scandir(small_dir):
        entry.stat(follow_symlinks=False)


def delete_small():
    for name in names:
        os.unlink(name)


timed("write 256 MiB", BIG / MB, "MiB/s", write_big)
timed("read 256 MiB", BIG / MB, "MiB/s", read_big)
os.unlink(big)
timed("create 1000 x 4 KiB", SMALL_FILES, "files/s", create_small)
timed("stat 1000", SMALL_FILES, "files/s", stat_small)
timed("read 1000 x 4 KiB", SMALL_FILES, "files/s", read_small)
timed("list 1000, with stat", SMALL_FILES, "entries/s", list_small)
timed("delete 1000", SMALL_FILES, "files/s", delete_small)
os.rmdir(small_dir)

lines = [f"### Benchmark: {label}", "", "| workload | rate | time |", "|---|---|---|"]
for name, rate, unit, seconds in results:
    lines.append(f"| {name} | {rate:.1f} {unit} | {seconds:.2f} s |")
report = "\n".join(lines) + "\n"
print(report)
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a") as f:
        f.write(report + "\n")
