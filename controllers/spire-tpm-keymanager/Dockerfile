FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY controllers ./controllers
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/spire-tpm-keymanager ./controllers/spire-tpm-keymanager/cmd/spire-tpm-keymanager

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libtpm2-pkcs11-1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/spire-tpm-keymanager /spire-tpm-keymanager
USER 65532:65532
ENTRYPOINT ["/spire-tpm-keymanager"]
