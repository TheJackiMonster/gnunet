#!/bin/bash
set -exuo pipefail

./bootstrap meson
meson setup --wipe -Dlogging=verbose \
	    build

meson compile -C build
meson install -C build
