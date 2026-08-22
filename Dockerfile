FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p cerberus

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/cerberus /usr/local/bin/cerberus
EXPOSE 8787
ENTRYPOINT ["cerberus"]
CMD ["start", "--port", "8787"]