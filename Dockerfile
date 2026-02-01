FROM rust:1.93 AS builder

# Make use of cache for dependencies.
RUN USER=root cargo new --bin traefik_crowdsec_bouncer
WORKDIR /traefik_crowdsec_bouncer
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./benches ./benches
RUN touch src/lib.rs && cargo build --release --bins --lib && \
    rm src/*.rs

# Build the app.
COPY . ./
RUN rm ./target/release/deps/traefik_crowdsec_bouncer*
RUN cargo build --release


# Use distroless as minimal base image to package the app.
FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder --chown=nonroot:nonroot /traefik_crowdsec_bouncer/target/release/traefik_crowdsec_bouncer /app/traefik_crowdsec_bouncer
COPY --from=samuelba/healthcheck:v0.2.0 --chown=nonroot:nonroot /app/healthcheck /app/healthcheck
USER nonroot
WORKDIR /app

ENV API_PATH=api/v1/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/app/healthcheck"]

CMD ["./traefik_crowdsec_bouncer"]
