#!/bin/bash
set -exuo pipefail

make clean
./bootstrap
./configure CFLAGS="-ggdb -O0" \
	    --enable-logging=verbose \
	    --disable-doc

make -j $(nproc)
make install
