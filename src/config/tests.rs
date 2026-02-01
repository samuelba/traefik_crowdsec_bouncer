//! Tests for the configuration module.
//!
//! Note: These tests modify global environment variables and are marked with
//! #[serial] to ensure they run one at a time.

use super::*;
use serial_test::serial;
use std::env;

fn setup_base_env() {
    unsafe {
        env::set_var("CROWDSEC_MODE", "stream");
        env::set_var("CROWDSEC_HTTPS", "false");
        env::set_var("CROWDSEC_HOST", "localhost:8080");
        env::set_var("CROWDSEC_API_KEY", "test_api_key");
        env::set_var("STREAM_UPDATE_INTERVAL", "10");
    }
}

fn cleanup_env() {
    unsafe {
        env::remove_var("CROWDSEC_MODE");
        env::remove_var("CROWDSEC_HTTPS");
        env::remove_var("CROWDSEC_HOST");
        env::remove_var("CROWDSEC_API_KEY");
        env::remove_var("STREAM_UPDATE_INTERVAL");
        env::remove_var("LIVE_CACHE_EXPIRATION");
        env::remove_var("PORT");
        env::remove_var("CROWDSEC_TRUSTED_PROXIES");
        env::remove_var("LOG_LEVEL");
    }
}

#[test]
#[serial]
async fn test_read_config_stream_mode() {
    cleanup_env();
    setup_base_env();

    let config = read_config();

    assert!(matches!(config.crowdsec_mode, CrowdSecMode::Stream));
    assert_eq!(config.crowdsec_api_key, "test_api_key");
    assert_eq!(config.stream_interval, 10);
    assert_eq!(config.crowdsec_cache_ttl, 0);
    assert_eq!(config.port, 8080);
    assert_eq!(config.log_level, "warning");
    assert!(config.crowdsec_live_url.contains("http://localhost:8080"));
    assert!(config.crowdsec_stream_url.contains("http://localhost:8080"));

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_live_mode() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "live");
        env::set_var("LIVE_CACHE_EXPIRATION", "60");
    }

    let config = read_config();

    assert!(matches!(config.crowdsec_mode, CrowdSecMode::Live));
    assert_eq!(config.crowdsec_cache_ttl, 60000); // 60 * 1000
    assert_eq!(config.stream_interval, 0);

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_none_mode() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "none");
    }

    let config = read_config();

    assert!(matches!(config.crowdsec_mode, CrowdSecMode::None));
    assert_eq!(config.crowdsec_cache_ttl, 0);
    assert_eq!(config.stream_interval, 0);

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_with_https() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_HTTPS", "true");
    }

    let config = read_config();

    assert!(config.crowdsec_live_url.starts_with("https://"));
    assert!(config.crowdsec_stream_url.starts_with("https://"));

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_with_custom_port() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("PORT", "9090");
    }

    let config = read_config();

    assert_eq!(config.port, 9090);

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_with_trusted_proxies() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_TRUSTED_PROXIES", "192.168.1.0/24, 10.0.0.0/8");
    }

    let config = read_config();

    assert_eq!(config.trusted_proxies.len(), 2);

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_with_log_levels() {
    let log_levels = vec!["debug", "info", "warning", "error"];

    for level in log_levels {
        cleanup_env();
        setup_base_env();
        unsafe {
            env::set_var("LOG_LEVEL", level);
        }

        let config = read_config();

        assert_eq!(config.log_level, level);
    }

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_with_invalid_log_level() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("LOG_LEVEL", "invalid");
    }

    let config = read_config();

    assert_eq!(config.log_level, "warning");

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "$CROWDSEC_MODE is not set")]
async fn test_read_config_missing_mode() {
    cleanup_env();
    unsafe {
        env::set_var("CROWDSEC_HTTPS", "false");
        env::set_var("CROWDSEC_HOST", "localhost:8080");
        env::set_var("CROWDSEC_API_KEY", "test_api_key");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "$CROWDSEC_MODE must be either 'stream', 'live' or 'none'")]
async fn test_read_config_invalid_mode() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "invalid_mode");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "$CROWDSEC_HTTPS is not set")]
async fn test_read_config_missing_https() {
    cleanup_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "stream");
        env::set_var("CROWDSEC_HOST", "localhost:8080");
        env::set_var("CROWDSEC_API_KEY", "test_api_key");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "Failed to parse CROWDSEC_HTTPS value as boolean")]
async fn test_read_config_invalid_https() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_HTTPS", "not_a_boolean");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "$CROWDSEC_HOST is not set")]
async fn test_read_config_missing_host() {
    cleanup_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "stream");
        env::set_var("CROWDSEC_HTTPS", "false");
        env::set_var("CROWDSEC_API_KEY", "test_api_key");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "$CROWDSEC_API_KEY is not set")]
async fn test_read_config_missing_api_key() {
    cleanup_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "stream");
        env::set_var("CROWDSEC_HTTPS", "false");
        env::set_var("CROWDSEC_HOST", "localhost:8080");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "$STREAM_UPDATE_INTERVAL is not set")]
async fn test_read_config_stream_mode_missing_interval() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::remove_var("STREAM_UPDATE_INTERVAL");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "Failed to parse STREAM_UPDATE_INTERVAL value as integer")]
async fn test_read_config_stream_mode_invalid_interval() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("STREAM_UPDATE_INTERVAL", "not_a_number");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "$LIVE_CACHE_EXPIRATION is not set")]
async fn test_read_config_live_mode_missing_cache_expiration() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "live");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "Failed to parse LIVE_CACHE_EXPIRATION value as integer")]
async fn test_read_config_live_mode_invalid_cache_expiration() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_MODE", "live");
        env::set_var("LIVE_CACHE_EXPIRATION", "not_a_number");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
#[should_panic(expected = "Invalid CIDR in CROWDSEC_TRUSTED_PROXIES")]
async fn test_read_config_invalid_trusted_proxy() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_TRUSTED_PROXIES", "invalid_cidr");
    }

    read_config();

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_empty_trusted_proxies() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("CROWDSEC_TRUSTED_PROXIES", "");
    }

    let config = read_config();

    assert_eq!(config.trusted_proxies.len(), 0);

    cleanup_env();
}

#[test]
#[serial]
async fn test_read_config_invalid_port_uses_default() {
    cleanup_env();
    setup_base_env();
    unsafe {
        env::set_var("PORT", "not_a_number");
    }

    let config = read_config();

    assert_eq!(config.port, 8080);

    cleanup_env();
}
