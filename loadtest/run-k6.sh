#!/bin/sh
# Runs loadtest/load-test.js in the pinned k6 image against the stack backend/tests/test_load.py started
# (LOAD_TEST_EXTERNAL_K6=1). $1: the LOAD_TEST_OUT directory, where the test wrote k6.env.
set -u
out=$1
export MSYS_NO_PATHCONV=1  # Git Bash: keep /scripts and /out as container paths
until [ -f "$out/k6.env" ]; do sleep 1; done
docker run --rm -v "$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd):/scripts:ro" -v "$out:/out" \
  --env-file "$out/k6.env" grafana/k6:1.0.0 run --quiet --summary-export /out/summary.json /scripts/load-test.js \
  > "$out/k6.txt" 2>&1
echo $? > "$out/k6.exit"
