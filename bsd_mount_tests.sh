#!/usr/bin/env bash

set -x

exit_handler() {
    exit "${TEST_EXIT_STATUS:-1}"
}
trap exit_handler TERM
trap 'kill $(jobs -p); exit $TEST_EXIT_STATUS' INT EXIT

export RUST_BACKTRACE=1

NC="\e[39m"
GREEN="\e[32m"
RED="\e[31m"

function run_test {
  DIR=$(mktemp -d)
  cargo build --example hello > /dev/null 2>&1
  cargo run --example hello -- $DIR $2 &
  FUSE_PID=$!
  sleep 2

  echo "mounting at $DIR"
  # Make sure FUSE was successfully mounted
  mount | grep hello || exit 1

  if [[ $(cat ${DIR}/hello.txt) = "Hello World!" ]]; then
      echo -e "$GREEN OK $1 $2 $NC"
  else
      echo -e "$RED FAILED $1 $2 $NC"
      export TEST_EXIT_STATUS=1
      exit 1
  fi

  kill $FUSE_PID
  wait $FUSE_PID
}

run_test 'with libfuse'

# TODO: auto unmount doesn't seem to be supported on FreeBSD
# run_test 'with libfuse' --auto_unmount

export TEST_EXIT_STATUS=0
