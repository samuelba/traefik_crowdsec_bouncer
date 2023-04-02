FROM rust:1.68 as builder

# Make use of cache for dependencies.
RUN USER=root cargo new --bin traefik_crowdsec_bouncer
WORKDIR ./traefik_crowdsec_bouncer
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
RUN cargo build --release && \
    rm src/*.rs

# Build the app.
COPY . ./
RUN rm ./target/release/deps/traefik_crowdsec_bouncer*
RUN cargo build --release


# Use distroless as minimal base image to package the app.
FROM gcr.io/distroless/cc-debian11:nonroot

COPY --from=builder --chown=nonroot:nonroot /traefik_crowdsec_bouncer/target/release/traefik_crowdsec_bouncer /app/traefik_crowdsec_bouncer
COPY --from=samuelba/healthcheck:latest --chown=nonroot:nonroot /app/healthcheck /app/healthcheck
USER nonroot
WORKDIR /app
EXPOSE 9090

ENV PORT=9090
ENV API_PATH=api/v1/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/app/healthcheck"]

CMD ["./traefik_crowdsec_bouncer"]
