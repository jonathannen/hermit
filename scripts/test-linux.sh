#!/bin/bash

# This is a convenience script for running ARM/Linux locally when developing
# on Mac/etc. It uses docker with seccomp disabled.
set -e

IMAGE="hermit-test"
PLATFORM="linux/aarch64"

echo "=== Building test image (x86_64) ==="
docker build --platform "$PLATFORM" -f Dockerfile.test -t "$IMAGE" .

echo ""
echo "=== Running tests (jitless mode - default) ==="
docker run --rm --platform "$PLATFORM" --security-opt seccomp=unconfined "$IMAGE"

echo ""
echo "=== Running tests (JIT mode) ==="
docker run --rm --platform "$PLATFORM" --security-opt seccomp=unconfined -e HERMIT_JIT=1 "$IMAGE"

echo ""
echo "=== All tests passed ==="
