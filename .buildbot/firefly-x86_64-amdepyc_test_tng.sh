#!/bin/bash

# echo "Skipped"

pushd src/transport
make check TESTS='test_communicator_basic-tcp test_communicator_rekey-tcp test_communicator_basic-unix test_communicator_basic-udp test_communicator_backchannel-udp'
pkill --signal 9 -U buildbot gnunet
popd