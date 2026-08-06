# Copyright 2026 SovereignIT Foundation
# SPDX-License-Identifier: GPL-2.0-only

# Build stage
FROM golang:1.26.5-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o /kpt-fn-provenance .

# Runtime stage
FROM alpine:3.21

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy the binary from builder
COPY --from=builder /kpt-fn-provenance /usr/local/bin/kpt-fn-provenance

# Set the entrypoint
ENTRYPOINT ["kpt-fn-provenance"]
