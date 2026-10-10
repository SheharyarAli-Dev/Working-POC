#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Building asent-sandbox:local and asent-sandbox-app..."
docker build \
    -t asent-sandbox:local \
    -t asent-sandbox-app:latest \
    -f "${ROOT_DIR}/docker/sandbox.Dockerfile" \
    "${ROOT_DIR}"

echo "Validating built images..."
docker images | grep -E "asent-sandbox"

echo "Running probe test in asent-sandbox:local..."
docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 512m \
    --cpus 1 \
    --pids-limit 64 \
    --tmpfs /tmp:rw,nosuid,size=64m \
    asent-sandbox:local python -c "import pytest, pydantic, fastapi; print('Sandbox container verification SUCCESS')"

echo "Phase 6 Docker sandbox image built and verified."
