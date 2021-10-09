#!/bin/bash
VERSION=$(git describe --tags)
VERSION=${VERSION:1:${#VERSION}}
echo $VERSION > .version
echo  -n $VERSION
