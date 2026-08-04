FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# libcap2-bin (setcap/getcap/capsh), fio, acct (accton) and the gdbm headers that build
# src/dbtest are each what stands between some tests and running at all.
#
# liburing-dev is deliberately absent. It would build src/feature with io_uring support and
# let four more tests run, but only alongside seccomp=unconfined, since Docker's default
# profile blocks io_uring outright - and turning that off also unblocks swapon, which is
# global rather than per-container. Without liburing those tests skip, which is what we want:
# with it and seccomp left on, _require_io_uring reads the EPERM as an error and fails
RUN apt update && apt install -y git build-essential autoconf curl cmake libfuse-dev pkg-config fuse bc libtool \
  uuid-dev xfslibs-dev libattr1-dev libacl1-dev libaio-dev attr acl quota bsdmainutils dbench psmisc \
  libcap2-bin fio acct libgdbm-dev libgdbm-compat-dev

# Tests that check permissions across two unrelated unprivileged users need both
RUN adduser --disabled-password --gecos '' fsgqa && adduser --disabled-password --gecos '' fsgqa2

RUN echo 'user_allow_other' >> /etc/fuse.conf

ADD rust-toolchain /code/fuser/rust-toolchain

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain=$(cat /code/fuser/rust-toolchain)

ENV PATH=/root/.cargo/bin:$PATH

RUN mkdir -p /code && cd /code && git clone https://github.com/fleetfs/fuse-xfstests && cd fuse-xfstests \
  && git checkout fleetfs-xfs-v2026.03.20 && make

ADD . /code/fuser/

RUN cd /code/fuser && cargo build --release --examples && cp target/release/examples/simple /bin/fuser
