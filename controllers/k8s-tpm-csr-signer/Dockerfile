FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY controllers ./controllers
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/k8s-tpm-csr-signer ./controllers/k8s-tpm-csr-signer/cmd/k8s-tpm-csr-signer

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libtpm2-pkcs11-1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/k8s-tpm-csr-signer /usr/local/bin/k8s-tpm-csr-signer
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/k8s-tpm-csr-signer"]
