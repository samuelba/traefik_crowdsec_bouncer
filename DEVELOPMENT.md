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

## Code Coverage

This project uses `cargo-llvm-cov` for generating code coverage reports.

### Install cargo-llvm-cov

```bash
cargo install cargo-llvm-cov --locked
```

### Generate coverage report

To run tests and generate a coverage report in terminal:

```bash
cargo llvm-cov
```

To generate an HTML report and open it in your browser:

```bash
cargo llvm-cov --open
```

To generate an lcov report for VS Code integration:

```bash
cargo llvm-cov --lcov --output-path lcov.info
```

### VS Code Coverage Visualization

Install the [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters) extension, then:

1. Generate the lcov report: `cargo llvm-cov --lcov --output-path lcov.info`
2. Click the "Watch" button in the VS Code status bar to display coverage

To automatically regenerate coverage on file changes (requires `cargo-watch`):

```bash
cargo install cargo-watch
cargo watch -x 'llvm-cov --lcov --output-path lcov.info' -w src
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
