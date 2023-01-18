#!/bin/bash
NEW_VERSION=$1
if [ -z $NEW_VERSION ]; then
    NEW_VERSION="Unreleased"
fi
DELTA_SH="contrib/scripts/changelog_delta.sh"
LASTHASH=$(head -n1 NEWS | cut -d " " -f 2 | tr -d \( | tr -d \) | tr -d :)

echo "$NEW_VERSION ($(git rev-parse --short HEAD)):" > NEWS.delta || exit 1
$DELTA_SH $LASTHASH >> NEWS.delta || exit 1
cp NEWS NEWS.bak || exit 1
cat NEWS.delta > NEWS || exit 1
cat NEWS.bak >> NEWS || exit 1
rm NEWS.bak NEWS.delta

