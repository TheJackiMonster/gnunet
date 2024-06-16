#!/bin/bash
set -exuo pipefail

job_dir=$(dirname "${BASH_SOURCE[0]}")

skip=$(cat <<EOF
ABOUT-NLS
*/debian/tmp/**
*.bbl
*.bib
*build-aux*
*.bst
*.cache/*
ChangeLog
*.cls
configure*
config.status
config.guess
depcomp
*/contrib/*
*/contrib/hellos/**
*.dat
*.deflate
*.doc
*/doc/*
**/doc/flows/main.de.tex
*/doc/texinfo.tex
*.docx
*.ecc
*.eot
*.epgz
*.eps
*.epub
*.fee
*.fees
*.file
**/fonts/**
*.gif
*/.git/**
*.gz
*/i18n/strings.ts
*.info
*.jpeg
*.jpg
*.??.json
*.json
*.json-*
*/keys/*
*key
*.latexmkrc
*libtool*
ltmain.sh
*.log
*/m4/*
*.m4
**/*.map
*.min.js
*.mp4
*.odg
*.ods
*.odt
*.pack.js
*.pdf
*.png
*.PNG
*.po
*.pptx
*.priv
**/rfc.bib
*.rpath
**/signing-key.asc
*.sqlite
**/*.svg
*.svg
*.tag
*/templating/test?/**
*.tgz
*.ttf
*.ttf
**/valgrind.h
*/vpn/tests/**
*.wav
*.woff
*.woff2
*.xcf
*.xlsx
*.zkey
EOF
);

echo Current directory: `pwd`

codespell -I "${job_dir}"/dictionary.txt -S ${skip//$'\n'/,} $@
