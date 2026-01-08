# =============================================================================
# OA-VERIFIER DOCKERFILE - REPRODUCIBLE BUILD
# =============================================================================
# IMPORTANT: Base images are pinned by digest for reproducibility.
# Users verifying the build must use these exact digests.
#
# To update digests (when upgrading versions):
#   docker pull golang:1.22-alpine && docker inspect golang:1.22-alpine --format='{{index .RepoDigests 0}}'
#   docker pull alpine:3.19 && docker inspect alpine:3.19 --format='{{index .RepoDigests 0}}'
# =============================================================================

# Pinned base image digests (for reproducibility)
ARG GOLANG_DIGEST=sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052
ARG ALPINE_DIGEST=sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

# Build stage
FROM golang@${GOLANG_DIGEST} AS builder

WORKDIR /app

# Install git for fetching dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build with reproducible settings
# - CGO_ENABLED=0: Static binary
# - -trimpath: Remove local paths from binary
# - -buildid=: Remove build ID for reproducibility
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid=" \
    -o verifier ./cmd/verifier

# Runtime stage - minimal image
FROM alpine@${ALPINE_DIGEST}

WORKDIR /app

# Install ca-certificates for HTTPS calls
# Note: Using --no-cache to avoid varying package versions
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user with fixed UID
RUN adduser -D -u 1000 appuser

# Copy binary from builder
COPY --from=builder /app/verifier /app/verifier

# Set ownership
RUN chown -R appuser:appuser /app

USER appuser

# Expose ports: 8000 (HTTP dev), 443 (HTTPS), 80 (ACME challenge)
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8000/broadcast || exit 1

# Run the verifier
ENTRYPOINT ["/app/verifier"]

