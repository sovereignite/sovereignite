FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY controllers ./controllers
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/spire-tpm-keymanager ./controllers/spire-tpm-keymanager/cmd/spire-tpm-keymanager

FROM fedora:44
RUN dnf -y install ca-certificates tpm2-pkcs11 \
    && dnf clean all
COPY --from=build /out/spire-tpm-keymanager /spire-tpm-keymanager
USER 65532:65532
ENTRYPOINT ["/spire-tpm-keymanager"]
