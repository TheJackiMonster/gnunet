#!/bin/bash
set -exuo pipefail
# This file is in the public domain.
# Helper script to build the latest DEB packages in the container.


unset LD_LIBRARY_PATH

# Install build-time dependencies.
# Update apt cache first
apt-get update
mk-build-deps --install --tool='apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends --yes' debian/control

export VERSION="$(./contrib/ci/jobs/2-deb-package/version.sh)"
echo "Building gnunet packages version ${VERSION}"
EMAIL=none gbp dch --ignore-branch --debian-tag="%(version)s" --git-author --new-version="${VERSION}"
./bootstrap
dpkg-buildpackage -rfakeroot -b -uc -us

ls -alh ../*.deb
mkdir -p /artifacts/gnunet/${CI_COMMIT_REF} # Variable comes from CI environment
mv ../*.deb /artifacts/gnunet/${CI_COMMIT_REF}/
