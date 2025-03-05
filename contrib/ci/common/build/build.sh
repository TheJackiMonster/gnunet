#!/bin/bash
set -exuo pipefail

MESON_BUILD_DIR=./build

rm -rf ${MESON_BUILD_DIR}
./bootstrap meson
meson setup -Dlogging=verbose \
	    ${MESON_BUILD_DIR}

meson compile -C ${MESON_BUILD_DIR}
meson install -C ${MESON_BUILD_DIR}
