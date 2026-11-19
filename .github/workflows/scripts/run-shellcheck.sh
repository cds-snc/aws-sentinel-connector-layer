#!/bin/bash

docker run --rm -v "$PWD:/mnt:ro" koalaman/shellcheck:v0.7.1@sha256:bc09eaa591263367f2531eaabafcbeaaf56f6f87aa4c0f736c40bbbbf6f33ff7 -P ./bin/ -x ./.github/workflows/scripts/*.sh
