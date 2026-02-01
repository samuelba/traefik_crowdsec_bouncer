use std::env;

use crate::constants::{CROWDSEC_LIVE_ROUTE, CROWDSEC_STREAM_ROUTE};

#[derive(Clone)]
pub enum CrowdSecMode {
    Live,
    None,
    Stream,
}

#[derive(Clone)]
pub struct Config {
    /// The CrowdSec live url.
    pub crowdsec_live_url: String,
    /// The CrowdSec stream url.
    pub crowdsec_stream_url: String,
    /// The CrowdSec API key.
    pub crowdsec_api_key: String,
    /// The CrowdSec mode.
    pub crowdsec_mode: CrowdSecMode,
    /// The cache expiration time in milliseconds.
    pub crowdsec_cache_ttl: i64,
    /// The CrowdSec stream update interval in seconds.
    pub stream_interval: u64,
    /// The listening port.
    pub port: u16,
    /// The trusted proxies.
    pub trusted_proxies: Vec<ipnetwork::IpNetwork>,
    /// The log level.
    pub log_level: String,
}

/// Read the configuration from the environment variables.
/// # Returns
/// The configuration.
pub fn read_config() -> Config {
    let mut config = Config {
        crowdsec_live_url: String::new(),
        crowdsec_stream_url: String::new(),
        crowdsec_api_key: String::new(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 8080,
        trusted_proxies: Vec::new(),
        log_level: String::from("warn"),
    };

    // Get the CrowdSec mode.
    let crowdsec_mode_str =
        env::var("CROWDSEC_MODE").unwrap_or_else(|_| panic!("$CROWDSEC_MODE is not set."));
    config.crowdsec_mode = match crowdsec_mode_str.as_str() {
        "live" => CrowdSecMode::Live,
        "none" => CrowdSecMode::None,
        "stream" => CrowdSecMode::Stream,
        _ => panic!("$CROWDSEC_MODE must be either 'stream', 'live' or 'none'."),
    };

    // Get the urls.
    let use_https = match env::var("CROWDSEC_HTTPS") {
        Ok(val) => match val.parse::<bool>() {
            Ok(result) => result,
            Err(_) => panic!("Failed to parse CROWDSEC_HTTPS value as boolean."),
        },
        Err(_) => panic!("$CROWDSEC_HTTPS is not set."),
    };
    let url = env::var("CROWDSEC_HOST").unwrap_or_else(|_| panic!("$CROWDSEC_HOST is not set."));
    if !url.starts_with("http://") && !url.starts_with("https://") {
        config.crowdsec_live_url = (if use_https { "https://" } else { "http://" }).to_owned()
            + &url
            + CROWDSEC_LIVE_ROUTE;
        config.crowdsec_stream_url = (if use_https { "https://" } else { "http://" }).to_owned()
            + &url
            + CROWDSEC_STREAM_ROUTE;
    }

    // Get the API key.
    config.crowdsec_api_key =
        env::var("CROWDSEC_API_KEY").unwrap_or_else(|_| panic!("$CROWDSEC_API_KEY is not set."));

    // Get the stream interval and cache ttl.
    match config.crowdsec_mode {
        CrowdSecMode::None => {
            config.stream_interval = 0;
            config.crowdsec_cache_ttl = 0;
        }
        CrowdSecMode::Live => {
            config.stream_interval = 0;
            config.crowdsec_cache_ttl = match env::var("LIVE_CACHE_EXPIRATION") {
                Ok(val) => match val.parse::<i64>() {
                    Ok(result) => 1000 * result,
                    Err(_) => panic!("Failed to parse LIVE_CACHE_EXPIRATION value as integer."),
                },
                Err(_) => panic!("$LIVE_CACHE_EXPIRATION is not set."),
            };
        }
        CrowdSecMode::Stream => {
            config.stream_interval = match env::var("STREAM_UPDATE_INTERVAL") {
                Ok(val) => match val.parse::<u64>() {
                    Ok(result) => result,
                    Err(_) => panic!("Failed to parse STREAM_UPDATE_INTERVAL value as integer."),
                },
                Err(_) => panic!("$STREAM_UPDATE_INTERVAL is not set."),
            };
            config.crowdsec_cache_ttl = 0;
        }
    }

    // Get the listening port.
    config.port = match env::var("PORT") {
        Ok(val) => val.parse::<u16>().unwrap_or(config.port),
        Err(_) => config.port,
    };

    // Get the trusted proxies.
    let trusted_proxies_str =
        env::var("CROWDSEC_TRUSTED_PROXIES").unwrap_or_else(|_| String::new());
    config.trusted_proxies = trusted_proxies_str
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            s.trim()
                .parse()
                .expect("Invalid CIDR in CROWDSEC_TRUSTED_PROXIES")
        })
        .collect();
    // Get the log level.
    config.log_level = match env::var("LOG_LEVEL") {
        Ok(val) => {
            let level = val.to_lowercase();
            match level.as_str() {
                "debug" | "info" | "warn" | "error" => level,
                _ => {
                    eprintln!(
                        "Invalid LOG_LEVEL '{}'. Using default 'warn'. Valid values: debug, info, warn, error",
                        val
                    );
                    String::from("warn")
                }
            }
        }
        Err(_) => String::from("warn"),
    };
    config
}

#[cfg(test)]
mod tests;
