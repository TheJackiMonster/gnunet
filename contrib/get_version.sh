#!/bin/bash
VERSION=$(git describe --tags | tr -d '\n')
VERSION=${VERSION:1:${#VERSION}}
echo $VERSION > .version
echo  $VERSION
