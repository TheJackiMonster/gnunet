#!/usr/bin/env bash

cat ./crypto-test-vectors.json | ./gnunet-crypto-tvg --verify
