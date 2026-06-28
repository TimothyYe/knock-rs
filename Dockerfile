# Use the Rust official image for the build stage
FROM rust:1.88 AS builder

# Add target for musl
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

# Copy the workspace manifests and the committed lockfile so the build resolves
# pinned dependency versions (enforced below with `cargo --locked`).
COPY Cargo.toml Cargo.lock ./
COPY knockd ./knockd
COPY knock-cli ./knock-cli

# Version string reported by the binary; supplied by the release workflow.
ARG VERSION

# Build the knockd binary on the musl target with locked dependencies.
# This creates a statically linked executable.
RUN VERSION="$VERSION" cargo build --release --locked -p knockd --target=x86_64-unknown-linux-musl

FROM alpine:3.21

# Install iptables
RUN apk add --no-cache iptables

# Ensure iptables is reachable at /usr/sbin/iptables (used by the config command).
# On Alpine 3.21+ the /usr merge means it is already there, so only create the
# compatibility symlink on older layouts where it would otherwise be missing.
RUN [ -e /usr/sbin/iptables ] || ln -s /sbin/iptables /usr/sbin/iptables

# Copy the binary from the builder stage
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/knockd /

# Command to run
CMD ["/knockd"]