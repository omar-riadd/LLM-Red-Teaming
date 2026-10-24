# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Stage 1: Build release binary
# -----------------------------------------------------------------------------
FROM rust:bookworm AS builder

WORKDIR /usr/src/llm-redteamer

# Install required build tools and libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace source files
COPY . .

# Build release binary for llm-redteamer CLI
RUN cargo build --release -p redteamer-cli

# -----------------------------------------------------------------------------
# Stage 2: Minimal, secure runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Install TLS root certificates and runtime dynamic libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user and group
RUN groupadd -g 10001 redteamer && \
    useradd -u 10001 -g redteamer -m -s /bin/sh redteamer

# Copy compiled binary from builder stage
COPY --from=builder /usr/src/llm-redteamer/target/release/llm-redteamer /usr/local/bin/llm-redteamer

# Copy bundled models and helpers with non-root ownership
COPY --from=builder --chown=redteamer:redteamer /usr/src/llm-redteamer/models /home/redteamer/models

# Set working directory and non-root execution user
WORKDIR /home/redteamer
USER redteamer

ENTRYPOINT ["llm-redteamer"]
CMD ["--help"]
