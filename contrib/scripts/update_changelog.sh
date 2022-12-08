#!/bin/bash
DELTA_SH="contrib/scripts/changelog_delta.sh"
LASTHASH=$(head -n1 ChangeLog | cut -d " " -f 7 | tr -d \( | tr -d \))

$DELTA_SH $LASTHASH changelog > ChangeLog.delta || exit 1
cp ChangeLog ChangeLog.bak || exit 1
cat ChangeLog.delta > ChangeLog || exit 1
cat ChangeLog.bak >> ChangeLog || exit 1
rm ChangeLog.bak ChangeLog.delta

