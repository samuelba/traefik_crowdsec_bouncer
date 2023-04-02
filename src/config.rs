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
        crowdsec_cache_ttl: 5000,
        stream_interval: 0,
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

    config
}
