# Benchmarking Guide

This document describes how to run performance benchmarks for the Traefik CrowdSec Bouncer.

## Overview

We provide two types of benchmarking tools:

1. **Criterion Benchmarks** - Microbenchmarks for core authentication functions
2. **Load Testing Tool** - End-to-end HTTP testing with realistic scenarios

## Criterion Benchmarks

Criterion provides statistical analysis and regression detection for microbenchmarks.

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench -- stream_mode

# Save baseline for comparison
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

### Current Benchmarks

- **Stream Mode IPv4** - Tests in-memory lookup performance for IPv4
  - Blocked IPs (cache hit)
  - Allowed IPs (cache miss)
  - Various cache sizes: 100, 1,000, 10,000 entries

- **Stream Mode IPv6** - Tests in-memory lookup performance for IPv6
  - Blocked IPs (cache hit)
  - Allowed IPs (cache miss)
  - Various cache sizes: 100, 1,000, 10,000 entries

### Results Location

Results are stored in `target/criterion/` and include:
- HTML reports with graphs
- Statistical analysis
- Comparison with previous runs

## Load Testing Tool

The load testing tool provides end-to-end HTTP testing with realistic scenarios.

### Running Load Tests

```bash
# Run the load test
cargo run --example load_test --release

# With logging
RUST_LOG=info cargo run --example load_test --release
```

### Test Scenarios

The load test covers:

1. **Stream Mode**
   - Warm cache (all hits)
   - Cold cache (all misses)
   - IPv4 and IPv6
   - 10,000 requests per test

2. **Live Mode** (requires mock API - currently commented out)
   - Cold cache (API calls)
   - Warm cache (cache hits)
   - Mixed cache (80% hits, 20% misses)

3. **None Mode** (requires mock API - currently commented out)
   - Direct API calls without caching

### Metrics Collected

- Total requests processed
- Total duration
- Requests per second (throughput)
- Average latency
- P50, P95, P99 latency percentiles

### Example Output

```
============================================================================
                    LOAD TEST RESULTS
============================================================================

Mode: Stream | Scenario: WarmCache | IP Version: IPv4
  Total Requests:      10000
  Duration:            1.23s
  Requests/sec:        8130.08
  Avg Latency:         122.45 µs
  P50 Latency:         115 µs
  P95 Latency:         189 µs
  P99 Latency:         234 µs
```

## Adding Mock API Support

To enable Live and None mode testing, implement a mock CrowdSec API server:

```rust
// Example using mockito or wiremock
#[tokio::test]
async fn test_with_mock_api() {
    let mock_server = mockito::Server::new();
    let mock = mock_server.mock("GET", "/api/v1/decisions")
        .with_status(200)
        .with_body(r#"[]"#)
        .create();
    
    // Run tests against mock_server.url()
}
```

## Performance Tracking

### Establishing Baselines

1. Run benchmarks on main branch:
   ```bash
   cargo bench -- --save-baseline main
   ```

2. Make changes in feature branch

3. Compare:
   ```bash
   cargo bench -- --baseline main
   ```

### What to Look For

- **Regressions**: >5% slowdown warrants investigation
- **Improvements**: Document what changed and why
- **Cache Hit Rate**: Should be >95% in production
- **Latency**: P99 should be <10ms for stream mode

## Continuous Integration

Consider adding benchmarks to CI:

```yaml
# Example GitHub Actions
- name: Run benchmarks
  run: cargo bench -- --save-baseline ${{ github.sha }}
  
- name: Compare to main
  if: github.event_name == 'pull_request'
  run: cargo bench -- --baseline main
```

## Tips

1. **Run in release mode**: Always use `--release` for accurate results
2. **Consistent environment**: Run on same hardware, low system load
3. **Multiple runs**: Criterion does this automatically, but repeat full load tests
4. **Document changes**: Keep a log of performance changes and their causes
5. **Profile hot paths**: Use `cargo flamegraph` or `perf` for deep analysis

## Future Enhancements

- [ ] Add concurrent request benchmarks
- [ ] Implement mock CrowdSec API for Live/None mode testing
- [ ] Add memory usage profiling
- [ ] Test with different network latencies
- [ ] Benchmark cache expiration handling
- [ ] Test with realistic IP distribution (some IPs more frequent)
