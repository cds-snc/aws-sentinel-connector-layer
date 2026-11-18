#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

BANDIT_IMAGE="cytopia/bandit:latest@sha256:72371c0ddaee0343a3ea9ec30dda0e242e38eeae4fc44fe962edad3ca99d849f"
docker pull "$BANDIT_IMAGE"

# Scan source code and only report on high severity issues
docker run --rm -v "$(pwd):/data:ro" "$BANDIT_IMAGE" -r /data -ll