# Build stage
FROM rust:1.75-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release --bin edge-api

# Runtime stage - distroless
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/target/release/edge-api /edge-api

USER nonroot:nonroot

EXPOSE 3000

ENTRYPOINT ["/edge-api"]
