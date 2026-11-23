#!/usr/bin/env bash
# Build CAVR's sandbox image asent-cavr-sandbox:local and record its image ID (docs/cavr-m2-plan.md PR 3).
# Every CAVR sandbox run checks the image against this record first; an image built any other way is UNRESOLVED.
#   bash docker/cavr-sandbox/build.sh        (from the repository root; uses .venv/bin/python when present)
set -euo pipefail
cd "$(dirname "$0")/../.."
PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python
exec "$PY" -m backend.cavr.sandbox_image build
