use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::{web, App, HttpServer};
use ip_network_table_deps_treebitmap::IpLookupTable;

use traefik_crowdsec_bouncer::bouncer::{authenticate, block_list, health};
use traefik_crowdsec_bouncer::config::{Config, CrowdSecMode};
use traefik_crowdsec_bouncer::types::{CacheAttributes, HealthStatus};

#[derive(Clone)]
struct BenchmarkConfig {
    mode: CrowdSecMode,
    num_requests: usize,
    cache_scenario: CacheScenario,
    ip_version: IpVersion,
    concurrent_workers: usize,
}

#[derive(Debug, Clone)]
enum CacheScenario {
    ColdCache,      // No cache entries, all misses
    WarmCache,      // All requests hit cache
    MixedCache,     // 80% hits, 20% misses
}

#[derive(Debug, Clone)]
enum IpVersion {
    IPv4,
    IPv6,
    Mixed,
}

#[derive(Debug)]
struct BenchmarkResult {
    mode: String,
    scenario: String,
    ip_version: String,
    total_requests: usize,
    duration: Duration,
    requests_per_second: f64,
    avg_latency_micros: f64,
    p50_latency_micros: u128,
    p95_latency_micros: u128,
    p99_latency_micros: u128,
}

fn create_test_config(mode: CrowdSecMode) -> Config {
    Config {
        crowdsec_live_url: "http://localhost:9999/api/v1/decisions".to_string(),
        crowdsec_stream_url: "http://localhost:9999/api/v1/decisions/stream".to_string(),
        crowdsec_api_key: "test-key".to_string(),
        crowdsec_mode: mode,
        crowdsec_cache_ttl: 60000,
        stream_interval: 10,
        port: 0,  // Let OS assign a free port
        trusted_proxies: Vec::new(),
    }
}

fn populate_ipv4_cache(
    table: &mut IpLookupTable<Ipv4Addr, CacheAttributes>,
    count: usize,
    blocked: bool,
) {
    let expiration = chrono::Utc::now().timestamp_millis() + 60000;
    for i in 0..count {
        let ip = Ipv4Addr::new(
            10,
            ((i >> 16) & 0xFF) as u8,
            ((i >> 8) & 0xFF) as u8,
            (i & 0xFF) as u8,
        );
        table.insert(
            ip,
            32,
            CacheAttributes {
                allowed: !blocked,
                expiration_time: expiration,
            },
        );
    }
}

fn populate_ipv6_cache(
    table: &mut IpLookupTable<Ipv6Addr, CacheAttributes>,
    count: usize,
    blocked: bool,
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
                allowed: !blocked,
                expiration_time: expiration,
            },
        );
    }
}

async fn setup_test_server(
    config: Config,
    ipv4_data: web::Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    ipv6_data: web::Data<Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>>,
) -> std::io::Result<(actix_web::dev::Server, u16)> {
    let health_status = web::Data::new(Arc::new(Mutex::new(HealthStatus::new())));
    let config_data = web::Data::new(config.clone());

    let server = HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .app_data(health_status.clone())
            .app_data(ipv4_data.clone())
            .app_data(ipv6_data.clone())
            .service(authenticate)
            .service(block_list)
            .service(health)
    })
    .bind(("127.0.0.1", config.port))?;
    
    let port = server.addrs()[0].port();
    let server = server.run();

    Ok((server, port))
}

async fn run_benchmark(bench_config: BenchmarkConfig) -> BenchmarkResult {
    // Setup data structures
    let mut ipv4_table = IpLookupTable::new();
    let mut ipv6_table = IpLookupTable::new();

    // Populate cache based on scenario
    match bench_config.cache_scenario {
        CacheScenario::WarmCache => {
            // Pre-populate with the IPs we'll be testing
            let count = bench_config.num_requests;
            populate_ipv4_cache(&mut ipv4_table, count, true);
            populate_ipv6_cache(&mut ipv6_table, count, true);
        }
        CacheScenario::MixedCache => {
            // Pre-populate with 80% of the IPs
            let count = (bench_config.num_requests as f64 * 0.8) as usize;
            populate_ipv4_cache(&mut ipv4_table, count, true);
            populate_ipv6_cache(&mut ipv6_table, count, true);
        }
        CacheScenario::ColdCache => {
            // Leave cache empty
        }
    }

    let ipv4_data = web::Data::new(Arc::new(Mutex::new(ipv4_table)));
    let ipv6_data = web::Data::new(Arc::new(Mutex::new(ipv6_table)));

    let config = create_test_config(bench_config.mode.clone());

    // Start test server
    let (server, port) = setup_test_server(config, ipv4_data.clone(), ipv6_data.clone())
        .await
        .expect("Failed to start server");
    
    let server_handle = tokio::spawn(server);

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run requests
    let mut latencies = Vec::with_capacity(bench_config.num_requests);
    let start = Instant::now();

    let client = reqwest::Client::new();
    
    for i in 0..bench_config.num_requests {
        let ip = match bench_config.ip_version {
            IpVersion::IPv4 => format!(
                "10.{}.{}.{}",
                (i >> 16) & 0xFF,
                (i >> 8) & 0xFF,
                i & 0xFF
            ),
            IpVersion::IPv6 => format!(
                "2001:db8:{}:{}::1",
                (i >> 16) & 0xFFFF,
                i & 0xFFFF
            ),
            IpVersion::Mixed => {
                if i % 2 == 0 {
                    format!(
                        "10.{}.{}.{}",
                        (i >> 16) & 0xFF,
                        (i >> 8) & 0xFF,
                        i & 0xFF
                    )
                } else {
                    format!(
                        "2001:db8:{}:{}::1",
                        (i >> 16) & 0xFFFF,
                        i & 0xFFFF
                    )
                }
            }
        };

        let request_start = Instant::now();
        
        let response = client
            .get(format!("http://127.0.0.1:{}/api/v1/forwardAuth", port))
            .header("X-Forwarded-For", &ip)
            .send()
            .await;

        let request_duration = request_start.elapsed();
        latencies.push(request_duration.as_micros());

        if response.is_err() {
            eprintln!("Request {} failed: {:?}", i, response.err());
        }
    }

    let total_duration = start.elapsed();

    // Stop server
    server_handle.abort();

    // Calculate statistics
    latencies.sort_unstable();
    let avg_latency = latencies.iter().sum::<u128>() as f64 / latencies.len() as f64;
    let p50_idx = (latencies.len() as f64 * 0.50) as usize;
    let p95_idx = (latencies.len() as f64 * 0.95) as usize;
    let p99_idx = (latencies.len() as f64 * 0.99) as usize;

    BenchmarkResult {
        mode: match bench_config.mode {
            CrowdSecMode::Stream => "Stream".to_string(),
            CrowdSecMode::Live => "Live".to_string(),
            CrowdSecMode::None => "None".to_string(),
        },
        scenario: format!("{:?}", bench_config.cache_scenario),
        ip_version: format!("{:?}", bench_config.ip_version),
        total_requests: bench_config.num_requests,
        duration: total_duration,
        requests_per_second: bench_config.num_requests as f64 / total_duration.as_secs_f64(),
        avg_latency_micros: avg_latency,
        p50_latency_micros: latencies[p50_idx],
        p95_latency_micros: latencies[p95_idx],
        p99_latency_micros: latencies[p99_idx],
    }
}

fn print_results(results: &[BenchmarkResult]) {
    println!("\n============================================================================");
    println!("                    LOAD TEST RESULTS");
    println!("============================================================================\n");

    for result in results {
        println!("Mode: {} | Scenario: {} | IP Version: {}", 
                 result.mode, result.scenario, result.ip_version);
        println!("  Total Requests:      {}", result.total_requests);
        println!("  Duration:            {:.2?}", result.duration);
        println!("  Requests/sec:        {:.2}", result.requests_per_second);
        println!("  Avg Latency:         {:.2} µs", result.avg_latency_micros);
        println!("  P50 Latency:         {} µs", result.p50_latency_micros);
        println!("  P95 Latency:         {} µs", result.p95_latency_micros);
        println!("  P99 Latency:         {} µs", result.p99_latency_micros);
        println!();
    }

    println!("============================================================================\n");
}

#[tokio::main]
async fn main() {
    env_logger::init();

    println!("Starting load tests...\n");
    println!("Note: Live and None modes will fail API calls since no mock server is running.");
    println!("      This is expected and simulates API failures.\n");

    let mut results = Vec::new();

    // Test configurations
    let test_configs = vec![
        // Stream mode tests (in-memory, should be fastest)
        BenchmarkConfig {
            mode: CrowdSecMode::Stream,
            num_requests: 10000,
            cache_scenario: CacheScenario::WarmCache,
            ip_version: IpVersion::IPv4,
            concurrent_workers: 1,
        },
        BenchmarkConfig {
            mode: CrowdSecMode::Stream,
            num_requests: 10000,
            cache_scenario: CacheScenario::WarmCache,
            ip_version: IpVersion::IPv6,
            concurrent_workers: 1,
        },
        BenchmarkConfig {
            mode: CrowdSecMode::Stream,
            num_requests: 10000,
            cache_scenario: CacheScenario::ColdCache,
            ip_version: IpVersion::IPv4,
            concurrent_workers: 1,
        },
        // Note: Live mode would require a mock CrowdSec API server
        // For now, these are commented out but can be enabled with proper mocking
        /*
        BenchmarkConfig {
            mode: CrowdSecMode::Live,
            num_requests: 1000,
            cache_scenario: CacheScenario::ColdCache,
            ip_version: IpVersion::IPv4,
            concurrent_workers: 1,
        },
        BenchmarkConfig {
            mode: CrowdSecMode::Live,
            num_requests: 1000,
            cache_scenario: CacheScenario::WarmCache,
            ip_version: IpVersion::IPv4,
            concurrent_workers: 1,
        },
        BenchmarkConfig {
            mode: CrowdSecMode::Live,
            num_requests: 1000,
            cache_scenario: CacheScenario::MixedCache,
            ip_version: IpVersion::IPv4,
            concurrent_workers: 1,
        },
        */
    ];

    for (idx, config) in test_configs.iter().enumerate() {
        println!("Running test {}/{}...", idx + 1, test_configs.len());
        let result = run_benchmark(config.clone()).await;
        results.push(result);
        
        // Small delay between tests
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    print_results(&results);
}
