FROM golang:1.24-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tap ./cmd/tap \
    && mkdir -p /out/data \
    && chmod 0700 /out/data \
    && install -m 0644 mitm-ca.pem /out/data/mitm-ca.pem \
    && install -m 0600 mitm-ca-key.pem /out/data/mitm-ca-key.pem

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/tap /tap
COPY --from=build --chown=65532:65532 /out/data /data
COPY signing-rules.json /etc/tap/signing-rules.json

LABEL "tee.launch_policy.allow_env_override"="TAP_PG_DSN_SECRET_VERSION,TRUSTED_PROXY_PG_DSN_SECRET_VERSION"
LABEL "tee.launch_policy.log_redirect"="always"

WORKDIR /data
EXPOSE 8080/tcp
# Confidential Space exposes its on-demand attestation API through a
# root-owned Unix socket at /run/container_launcher/teeserver.sock. The
# workload must run as root to request customer-bound attestation tokens.
USER root:root
ENTRYPOINT ["/tap"]
CMD ["-listen", ":8080", "-ca-cert", "/data/mitm-ca.pem", "-ca-key", "/data/mitm-ca-key.pem", "-attestation-audience", "tap/customer/v1"]
