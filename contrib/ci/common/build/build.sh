#!/bin/bash
set -exuo pipefail

./bootstrap meson
meson setup -Dlogging=verbose \
	    build

meson compile -C build
meson install -C build
