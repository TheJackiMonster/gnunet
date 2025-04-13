#!/bin/sh

# This is more portable than `which' but comes with
# the caveat of not(?) properly working on busybox's ash:
existence()
{
    type "$1" >/dev/null 2>&1
}

if ! existence doxygen; then
  echo "Doxygen not found"
  exit 1
fi
cd "${MESON_SOURCE_ROOT}/doc/doxygen"
echo "PROJECT_NUMBER = ${PACKAGE_VERSION}" > version.doxy
doxygen gnunet.doxy || exit 1

echo "Doxygen files generated into ${MESON_SOURCE_ROOT}/doc/doxygen!"
