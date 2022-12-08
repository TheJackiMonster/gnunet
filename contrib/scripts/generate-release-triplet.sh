#!/bin/bash

PACKAGE=$1
VERSION=$2

cat << EOF >> $PACKAGE-$VERSION.directive
version: 1.2
directory: gnunet
filename: $PACKAGE-$VERSION.tar.gz
symlink: $PACKAGE-$VERSION.tar.gz $PACKAGE-latest.tar.gz
EOF

gpg --clearsign $PACKAGE-$VERSION.directive
gpg -b $PACKAGE-$VERSION.tar.gz
exit
ftp -inv ftp-upload.gnu.org <<EOF
user anonymous
cd incoming/ftp
mput $PACKAGE-$VERSION.tar.gz $PACKAGE-$VERSION.tar.gz.sig $PACKAGE-$VERSION.tar.gz.directive.asc
bye
EOF
