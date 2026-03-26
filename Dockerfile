# Build stage
FROM rust:1.91.1-slim-trixie AS builder

WORKDIR /build

# Install build dependencies (V8 requires clang and other tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    clang \
    lld \
    curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock* ./
RUN cargo build --release || true

# Copy source
COPY src ./src

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:trixie-slim

# Install runtime dependencies (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/target/release/hermit /usr/local/bin/hermit

# Run as non-root user
RUN useradd -r -s /bin/false hermit
USER hermit

ENTRYPOINT ["hermit"]
