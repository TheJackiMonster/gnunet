#!/bin/bash
if [ $2 == "plain" ]; then
  FORMAT="  - %s%n%b"
  echo "Changes since $1:"
elif [ $2 == "html" ]; then
  FORMAT="  <li>%s<br>%b</li>"
  echo "<ul>"
elif [ $2 == "changelog" ]; then
  FORMAT="%aD (%h)%n%s%n%b%nby: %cN%n"
fi

git --no-pager log --grep="^[a-zA-Z]*: " --no-merges --no-color --format="$FORMAT" $1..HEAD

if [ $2 == "html" ]; then
  echo "</ul>"
fi


