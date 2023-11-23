#!/bin/sh
set -ex

git fetch origin $(git rev-parse --abbrev-ref HEAD) --depth=1000 --tags
RECENT_VERSION_TAG=$(git describe --tags --match 'v*.*.*' --always --abbrev=0 HEAD)

commits="$(git rev-list ${RECENT_VERSION_TAG}..HEAD --count)"
if [ "${commits}" = "0" ]; then
    git describe --tag HEAD
else
    echo $(echo ${RECENT_VERSION_TAG} | cut -d'v' -f2)-${commits}-$(git rev-parse --short=8 HEAD)
fi
