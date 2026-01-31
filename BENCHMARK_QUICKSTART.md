# Quick Start

Run the benchmarks and load tests to compare performance across modes.

## Quick Commands

```bash
# Run microbenchmarks
cargo bench

# Run load test (Stream mode only - requires no external dependencies)
cargo run --example load_test --release

# Run specific benchmark suite
cargo bench -- stream_mode_ipv4
```

## What Gets Tested

### Criterion Benchmarks (`cargo bench`)
- Stream mode IPv4/IPv6 lookups
- Various cache sizes (100, 1K, 10K entries)
- Cache hits vs misses

### Load Test (`cargo run --example load_test`)
- 10,000 requests per scenario
- Warm and cold cache tests
- Both IPv4 and IPv6
- Real HTTP stack overhead

## Expected Performance (ballpark)

Based on typical hardware:

**Stream Mode:**
- Warm cache: 50-100 µs per request
- Cold cache: 80-150 µs per request  
- Throughput: 8,000-15,000 req/s

**Live Mode (with cache):**
- Warm cache: 100-200 µs per request
- Cold cache: 10-50 ms per request (API latency)

**None Mode:**
- Every request: 10-50 ms (API latency)

## Tracking Changes

```bash
# Before making changes
cargo bench -- --save-baseline before

# After making changes
cargo bench -- --baseline before

# View the comparison
```

See [BENCHMARKING.md](BENCHMARKING.md) for full details.
