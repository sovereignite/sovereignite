FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY controllers ./controllers
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/tpm-cluster-issuer ./controllers/tpm-cluster-issuer/cmd/tpm-cluster-issuer

FROM fedora:44
RUN dnf -y install ca-certificates tpm2-pkcs11 \
    && dnf clean all
COPY --from=build /out/tpm-cluster-issuer /usr/local/bin/tpm-cluster-issuer
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tpm-cluster-issuer"]
