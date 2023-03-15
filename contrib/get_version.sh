#!/bin/sh
# Gets the version number from git, or from the contents of .version
VERSION=
if test -f ".version"; then
  VERSION=$(cat .version)
fi
if [ -e ./.git ]; then
  # With sparse checkouts, we have a .git dir but possibly no tags
  gitver=$(git describe --tags 2>/dev/null || echo no-git-version)
  if test "$gitver" != "no-git-version"; then
    VERSION=${gitver#v}
    echo "$VERSION" > .version
  fi
fi
if test "x$VERSION" = "x"; then
  VERSION="unknown"
fi
case $1 in
"--major")
  echo "$VERSION" | sed 's/\(^[0-9]*\)\.\([0-9]*\)\.\([0-9]*\).*/\1/g'
  ;;
"--minor")
  echo "$VERSION" | sed 's/\(^[0-9]*\)\.\([0-9]*\)\.\([0-9]*\).*/\2/g'
  ;;
"--micro")
  echo "$VERSION" | sed 's/\(^[0-9]*\)\.\([0-9]*\)\.\([0-9]*\).*/\3/g'
  ;;
"--git")
  echo "$VERSION" | sed 's/\(^[0-9]*\)\.\([0-9]*\)\.\([0-9]*\)\(.*\)/\4/g'
  ;;
*)
  echo "$VERSION"
esac
