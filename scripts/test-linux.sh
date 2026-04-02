#!/bin/bash

# This is a convenience script for running ARM/Linux locally when developing
# on Mac/etc. It uses docker with seccomp disabled.
set -e

IMAGE="hermit-test"
PLATFORM="linux/aarch64"

echo "=== Building test image ($PLATFORM) ==="
docker build --platform "$PLATFORM" -f Dockerfile.test -t "$IMAGE" .

echo ""
echo "=== Running tests (jitless mode - default) ==="
docker run --rm --platform "$PLATFORM" --security-opt seccomp=unconfined "$IMAGE"

echo ""
echo "=== Running tests (JIT mode) ==="
docker run --rm --platform "$PLATFORM" --security-opt seccomp=unconfined -e HERMIT_JIT=1 "$IMAGE"

echo ""
echo "=== Stress test: 100 sequential evals (jitless) ==="
STRESS_SCRIPT='
INPUT=""
for i in $(seq 1 100); do
  INPUT="${INPUT}console.log(\"eval ${i}\")
"
done
# Final blank line to flush last block
echo "$INPUT" | /build/target/release/hermit | tail -1
'
RESULT=$(docker run --rm --platform "$PLATFORM" --security-opt seccomp=unconfined "$IMAGE" bash -c "$STRESS_SCRIPT")
if [ "$RESULT" = "eval 100" ]; then
  echo "Stress test passed (100 evals)"
else
  echo "Stress test FAILED: expected 'eval 100', got '$RESULT'"
  exit 1
fi

echo ""
echo "=== Stress test: 100 sequential evals (JIT) ==="
RESULT=$(docker run --rm --platform "$PLATFORM" --security-opt seccomp=unconfined "$IMAGE" bash -c "$(cat <<'JITEOF'
INPUT=""
for i in $(seq 1 100); do
  INPUT="${INPUT}console.log(\"eval ${i}\")
"
done
echo "$INPUT" | /build/target/release/hermit --jit | tail -1
JITEOF
)")
if [ "$RESULT" = "eval 100" ]; then
  echo "Stress test passed (100 evals, JIT)"
else
  echo "Stress test FAILED: expected 'eval 100', got '$RESULT'"
  exit 1
fi

echo ""
echo "=== All tests passed ==="
