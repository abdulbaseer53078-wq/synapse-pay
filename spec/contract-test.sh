#!/usr/bin/env bash
# Contract tests (Task 1.8): validate examples, then run Schemathesis against a Prism mock of the spec.
# Needs Node and Python with: pip install -r spec/requirements.txt
#
# These tests verify spec internal consistency. Prism returns the first example, so response
# assertions are tautological. Behavioral tests (idempotency replay, registry lookup, state
# transitions) require the real backend and belong to the Stage 1 integration test suite,
# to be built alongside the Host Connector (Step 4).
set -euo pipefail
cd "$(dirname "$0")/.."

python spec/check_spec.py spec/openapi.yaml

npx -y @stoplight/prism-cli@5.14.2 mock spec/openapi.yaml -p 4010 >/dev/null 2>&1 &
PRISM=$!
trap 'kill $PRISM' EXIT
for _ in $(seq 1 60); do curl -sf -H 'Authorization: Bearer test' http://127.0.0.1:4010/v1/capabilities/UPI >/dev/null && break; sleep 1; done

# Prism serves paths without the /api server prefix. The mock only checks that a token is present.
schemathesis run spec/openapi.yaml --url http://127.0.0.1:4010 --mode positive -H 'Authorization: Bearer test' \
  --checks not_a_server_error,status_code_conformance,content_type_conformance,response_schema_conformance
