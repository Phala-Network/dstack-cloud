# Build context: workspace root (docker build -f kms/Dockerfile .)
# bookworm-based to match the debian:bookworm-slim runtime glibc (2.36).
FROM rust:1.92-slim-bookworm AS builder
RUN apt-get update && apt-get install -y \
    build-essential libssl-dev protobuf-compiler libprotobuf-dev \
    clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p dstack-kms

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/dstack-kms /usr/local/bin/dstack-kms
CMD ["dstack-kms"]
