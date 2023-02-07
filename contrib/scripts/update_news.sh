#!/bin/bash
NEW_VERSION=$1
if [ -z $NEW_VERSION ]; then
    NEW_VERSION="Unreleased"
fi
DELTA_SH="contrib/scripts/news_delta.sh"
LASTVER=$(head -n1 NEWS | tr -d :)

echo "$NEW_VERSION:" > NEWS.delta || exit 1
$DELTA_SH $LASTVER >> NEWS.delta || exit 1
cp NEWS NEWS.bak || exit 1
cat NEWS.delta > NEWS || exit 1
cat NEWS.bak >> NEWS || exit 1
rm NEWS.bak NEWS.delta

