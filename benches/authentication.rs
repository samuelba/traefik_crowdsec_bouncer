use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use actix_web::web::Data;
use ip_network_table_deps_treebitmap::IpLookupTable;

use traefik_crowdsec_bouncer::bouncer::{TraefikHeaders, authenticate_stream_mode};
use traefik_crowdsec_bouncer::config::{Config, CrowdSecMode};
use traefik_crowdsec_bouncer::types::CacheAttributes;

// Helper function to create test configuration
fn create_test_config(mode: CrowdSecMode) -> Config {
    Config {
        crowdsec_live_url: "http://localhost:8080".to_string(),
        crowdsec_stream_url: "http://localhost:8080".to_string(),
        crowdsec_api_key: "test-key".to_string(),
        crowdsec_mode: mode,
        crowdsec_cache_ttl: 60000,
        stream_interval: 10,
        port: 8080,
        trusted_proxies: Vec::new(),
        log_level: String::from("warn"),
    }
}

// Helper to populate IPv4 cache with test data
fn populate_ipv4_cache(
    table: &mut IpLookupTable<Ipv4Addr, CacheAttributes>,
    count: usize,
    allowed: bool,
) {
    let expiration = chrono::Utc::now().timestamp_millis() + 60000;
    for i in 0..count {
        let ip = Ipv4Addr::new(
            ((i >> 24) & 0xFF) as u8,
            ((i >> 16) & 0xFF) as u8,
            ((i >> 8) & 0xFF) as u8,
            (i & 0xFF) as u8,
        );
        table.insert(
            ip,
            32,
            CacheAttributes {
                allowed,
                expiration_time: expiration,
            },
        );
    }
}

// Helper to populate IPv6 cache with test data
fn populate_ipv6_cache(
    table: &mut IpLookupTable<Ipv6Addr, CacheAttributes>,
    count: usize,
    allowed: bool,
) {
    let expiration = chrono::Utc::now().timestamp_millis() + 60000;
    for i in 0..count {
        let ip = Ipv6Addr::new(
            0x2001,
            0x0db8,
            ((i >> 16) & 0xFFFF) as u16,
            (i & 0xFFFF) as u16,
            0,
            0,
            0,
            1,
        );
        table.insert(
            ip,
            128,
            CacheAttributes {
                allowed,
                expiration_time: expiration,
            },
        );
    }
}

fn bench_stream_mode_ipv4_blocked(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_mode_ipv4");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("blocked", size), size, |b, &size| {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            b.to_async(&runtime).iter(|| async {
                // Setup - create lookup tables with blocked IPs
                let mut ipv4_table = IpLookupTable::new();
                populate_ipv4_cache(&mut ipv4_table, size, false);
                let ipv4_data = Data::new(Arc::new(Mutex::new(ipv4_table)));

                let ipv6_table = IpLookupTable::new();
                let ipv6_data = Data::new(Arc::new(Mutex::new(ipv6_table)));

                // Test with a blocked IP
                let headers = TraefikHeaders {
                    ip: "10.0.0.1".to_string(),
                };

                black_box(
                    authenticate_stream_mode(headers, ipv4_data.clone(), ipv6_data.clone()).await,
                )
            });
        });
    }

    group.finish();
}

fn bench_stream_mode_ipv4_allowed(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_mode_ipv4");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("allowed", size), size, |b, &size| {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            b.to_async(&runtime).iter(|| async {
                // Setup - create lookup tables with some blocked IPs
                let mut ipv4_table = IpLookupTable::new();
                populate_ipv4_cache(&mut ipv4_table, size, false);
                let ipv4_data = Data::new(Arc::new(Mutex::new(ipv4_table)));

                let ipv6_table = IpLookupTable::new();
                let ipv6_data = Data::new(Arc::new(Mutex::new(ipv6_table)));

                // Test with an allowed IP (not in block list)
                let headers = TraefikHeaders {
                    ip: "192.168.1.1".to_string(),
                };

                black_box(
                    authenticate_stream_mode(headers, ipv4_data.clone(), ipv6_data.clone()).await,
                )
            });
        });
    }

    group.finish();
}

fn bench_stream_mode_ipv6_blocked(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_mode_ipv6");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("blocked", size), size, |b, &size| {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            b.to_async(&runtime).iter(|| async {
                // Setup - create lookup tables with blocked IPs
                let ipv4_table = IpLookupTable::new();
                let ipv4_data = Data::new(Arc::new(Mutex::new(ipv4_table)));

                let mut ipv6_table = IpLookupTable::new();
                populate_ipv6_cache(&mut ipv6_table, size, false);
                let ipv6_data = Data::new(Arc::new(Mutex::new(ipv6_table)));

                // Test with a blocked IP
                let headers = TraefikHeaders {
                    ip: "2001:db8::1".to_string(),
                };

                black_box(
                    authenticate_stream_mode(headers, ipv4_data.clone(), ipv6_data.clone()).await,
                )
            });
        });
    }

    group.finish();
}

fn bench_stream_mode_ipv6_allowed(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_mode_ipv6");

    for size in [100, 1000, 10000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("allowed", size), size, |b, &size| {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            b.to_async(&runtime).iter(|| async {
                // Setup - create lookup tables with blocked IPs
                let ipv4_table = IpLookupTable::new();
                let ipv4_data = Data::new(Arc::new(Mutex::new(ipv4_table)));

                let mut ipv6_table = IpLookupTable::new();
                populate_ipv6_cache(&mut ipv6_table, size, false);
                let ipv6_data = Data::new(Arc::new(Mutex::new(ipv6_table)));

                // Test with an allowed IP (not in block list)
                let headers = TraefikHeaders {
                    ip: "2001:db8:1::1".to_string(),
                };

                black_box(
                    authenticate_stream_mode(headers, ipv4_data.clone(), ipv6_data.clone()).await,
                )
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_stream_mode_ipv4_blocked,
    bench_stream_mode_ipv4_allowed,
    bench_stream_mode_ipv6_blocked,
    bench_stream_mode_ipv6_allowed,
);
criterion_main!(benches);
