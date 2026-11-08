#!/bin/sh
# Fetches the terminal CA's CRL before Envoy starts. AWS Private CA publishes it to S3 in DER; Envoy wants PEM.
# Every region fetches the same CRL, so a terminal revoked anywhere is refused everywhere.
# shortcut: fetched once at startup (Envoy reads the CRL only then). Tasks must be recycled more often than the
# CRL's validity, or Envoy refuses every terminal; serve it over SDS to reload in place.
set -eu
if [ -n "${GATEWAY_CRL_URL:-}" ]; then
  der=$(mktemp)
  curl -fsS --retry 5 --max-time 10 "$GATEWAY_CRL_URL" -o "$der"
  { echo "-----BEGIN X509 CRL-----"; base64 -w 64 "$der"; echo "-----END X509 CRL-----"; } > /run/app-secrets/GATEWAY_CRL
  rm -f "$der"
fi
[ -s /run/app-secrets/GATEWAY_CRL ] || { echo "gateway: no CRL (set GATEWAY_CRL_URL or FILE_GATEWAY_CRL)" >&2; exit 1; }
exec "$@"
