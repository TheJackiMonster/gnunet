#!/bin/bash
LASTHASH=$(head -n1 ChangeLog | cut -d " " -f 7 | tr -d \( | tr -d \))
git log --grep="^[a-zA-Z]*: " --no-merges --no-color --format="%aD (%h)%n%s%n%b%nby: %cN%n" $LASTHASH..HEAD
