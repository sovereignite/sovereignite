FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY controllers ./controllers
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/spire-tpm-keymanager-controller ./controllers/spire-tpm-keymanager-controller/cmd/spire-tpm-keymanager-controller

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/spire-tpm-keymanager-controller /usr/local/bin/spire-tpm-keymanager-controller
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/spire-tpm-keymanager-controller"]
