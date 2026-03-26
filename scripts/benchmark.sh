#!/bin/bash
# Benchmark hermit cold start performance

set -e

BINARY="${HERMIT_BIN:-./target/release/hermit}"
ITERATIONS="${1:-500}"

if [ ! -x "$BINARY" ]; then
    echo "Building release binary..."
    cargo build --release
fi

echo "Binary: $BINARY"
echo "Size: $(ls -lh "$BINARY" | awk '{print $5}')"
echo "Iterations: $ITERATIONS"
echo ""

echo "=== Cold start (serial) ==="
START=$(perl -MTime::HiRes=time -e 'print time')
for i in $(seq 1 "$ITERATIONS"); do
    echo 'console.log(1+1)' | "$BINARY" >/dev/null 2>&1
done
END=$(perl -MTime::HiRes=time -e 'print time')
DURATION=$(echo "$END - $START" | bc)
echo "Rate: $(echo "scale=2; $ITERATIONS / $DURATION" | bc) isolates/sec"
echo "Latency: $(echo "scale=3; $DURATION / $ITERATIONS * 1000" | bc)ms"
echo ""

echo "=== Cold start (8 parallel) ==="
START=$(perl -MTime::HiRes=time -e 'print time')
for i in $(seq 1 "$ITERATIONS"); do
    echo 'console.log(1+1)' | "$BINARY" >/dev/null 2>&1 &
    if [ $((i % 8)) -eq 0 ]; then wait; fi
done
wait
END=$(perl -MTime::HiRes=time -e 'print time')
DURATION=$(echo "$END - $START" | bc)
echo "Rate: $(echo "scale=2; $ITERATIONS / $DURATION" | bc) isolates/sec"
echo ""

echo "=== Warm evals (1000 evals, single process) ==="
{
    for i in $(seq 1 1000); do
        echo "console.log($i)"
    done
} > /tmp/hermit-bench-evals.txt

START=$(perl -MTime::HiRes=time -e 'print time')
cat /tmp/hermit-bench-evals.txt | "$BINARY" 2>/dev/null | wc -l | tr -d ' '
END=$(perl -MTime::HiRes=time -e 'print time')
DURATION=$(echo "$END - $START" | bc)
echo "Rate: $(echo "scale=2; 1000 / $DURATION" | bc) evals/sec"

rm -f /tmp/hermit-bench-evals.txt
