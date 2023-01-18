#!/bin/bash

OLDVERSION=$1

git --no-pager log --grep="^NEWS: " -i --no-merges --no-color --format="%s%n%b" $1..HEAD | grep -i "^NEWS:\s[a-zA-Z][a-zA-Z]*" | sed 's/NEWS:/  -/i'
echo ""
