# Development

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- [Docker](https://docs.docker.com/get-docker/) (optional, for building the container)

## Build

To build the project in debug mode:

```bash
cargo build
```

To build for release:

```bash
cargo build --release
```

## Running

To run the bouncer locally:

```bash
cargo run
```

Configuration can be provided via environment variables as per the `README.md`.

## Testing

To run the unit and integration tests:

```bash
cargo test
```

## Formatting

Ensure your code is formatted correctly:

```bash
cargo fmt
```

To check formatting without modifying files (useful for CI):

```bash
cargo fmt -- --check
```

## Linting

Run Clippy to catch common mistakes and improve your code:

```bash
cargo clippy
```

## Update Dependencies

```bash
cargo update
```

## Docker

To build the Docker image:

```bash
docker build -t traefik-crowdsec-bouncer .
```
