# card-service, run as a sidecar of the API task (it listens on loopback only). Build from the repo root:
#   docker build -f card-service/Dockerfile -t synapsepay-card-service .
FROM rust:1.88.0-bookworm AS build
WORKDIR /src
COPY iso8583 iso8583
COPY host-connector host-connector
COPY card-service card-service
RUN cargo build --release --locked --manifest-path card-service/Cargo.toml --bin card_service

FROM debian:bookworm-slim
RUN useradd --uid 10001 --no-create-home app && mkdir /run/app-secrets && chown app /run/app-secrets
COPY --from=build /src/card-service/target/release/card_service /usr/local/bin/card_service
COPY iso8583/dialects /opt/dialects
COPY --chmod=755 docker/write-secrets.sh /usr/local/bin/write-secrets

USER app
ENV CARD_SERVICE_ADDR=127.0.0.1:7070
ENTRYPOINT ["/usr/local/bin/write-secrets"]
CMD ["/usr/local/bin/card_service"]
