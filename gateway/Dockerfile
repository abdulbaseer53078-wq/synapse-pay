# Terminal mTLS gateway (gateway/envoy.yaml), run in the API task so the backend is 127.0.0.1:8000.
# Build from the repo root:  docker build -f gateway/Dockerfile -t synapsepay-gateway .
FROM envoyproxy/envoy:v1.31.2

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* && mkdir /run/app-secrets && chown envoy /run/app-secrets
COPY gateway/envoy.yaml /etc/envoy/envoy.yaml
# Same config as local development, with the backend in the same task and certificates from secrets.
RUN sed -i -e 's|address: host.docker.internal|address: 127.0.0.1|' \
           -e 's|/etc/synapse/ca.pem|/run/app-secrets/GATEWAY_CA|' \
           -e 's|/etc/synapse/crl.pem|/run/app-secrets/GATEWAY_CRL|' \
           -e 's|/etc/synapse/server.pem|/run/app-secrets/GATEWAY_SERVER_CERT|' \
           -e 's|/etc/synapse/server-key.pem|/run/app-secrets/GATEWAY_SERVER_KEY|' /etc/envoy/envoy.yaml \
    && ! grep -q 'filename: /etc/synapse\|address: host.docker.internal' /etc/envoy/envoy.yaml
COPY --chmod=755 docker/write-secrets.sh /usr/local/bin/write-secrets
COPY --chmod=755 gateway/entrypoint.sh /usr/local/bin/gateway-entrypoint

USER envoy
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/write-secrets", "/usr/local/bin/gateway-entrypoint"]
CMD ["envoy", "-c", "/etc/envoy/envoy.yaml", "--log-level", "warn"]
