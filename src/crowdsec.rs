use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{error, info, warn};

use actix_web::rt::time;

use ip_network_table_deps_treebitmap::IpLookupTable;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::errors::CrowdSecApiError;
use crate::types::{CacheAttributes, HealthStatus};
use crate::utils::get_ip_and_subnet;

#[cfg(test)]
mod tests;

/// The CrowdSec decision.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Decision {
    /// The unique ID of the decision.
    pub id: u32,
    /// The origin of the decision (CAPI, LAPI, etc.).
    pub origin: String,
    /// The type of the decision (ban, etc.).
    #[serde(rename = "type")]
    pub _type: String,
    /// The scope of the value (Ip, Range, etc.).
    pub scope: String,
    /// The IP Address or range to ban.
    pub value: String,
    /// The duration of the decision.
    pub duration: String,
    /// The reason for the decision.
    pub scenario: String,
}

/// The CrowdSec decision stream response.
#[derive(Debug, Deserialize, Serialize)]
pub struct Stream {
    pub deleted: Option<Vec<Decision>>,
    pub new: Option<Vec<Decision>>,
}

fn set_health_status(health_status: Arc<Mutex<HealthStatus>>, healthy: bool) {
    if let Ok(mut health_status) = health_status.lock() {
        health_status.stream_status = healthy;
    }
}

/// Call the CrowdSec API.
/// # Arguments
/// * `url` - The URL of the CrowdSec API.
/// * `api_key` - The API key to use to authenticate to the CrowdSec API.
/// # Returns
/// * The response of the CrowdSec API.
async fn get_request(
    url: reqwest::Url,
    api_key: &str,
) -> Result<reqwest::Response, reqwest::Error> {
    let client = reqwest::Client::new();
    client
        .get(url)
        .header("X-Api-Key", api_key)
        .timeout(Duration::from_secs(10))
        .send()
        .await
}

/// Call the CrowdSec decisions API to know if the ip is banned or not.
/// # Arguments
/// * `url` - The URL of the CrowdSec decisions API.
/// * `api_key` - The API key to use to authenticate to the CrowdSec decisions API.
/// * `ip` - The IP address to check.
/// # Returns
/// * `Some(Decision)` if the IP address is banned, `None` otherwise.
/// * `CrowdSecApiError` if the request failed.
pub async fn get_decision(
    url: &str,
    api_key: &str,
    ip: &str,
) -> Result<Option<Decision>, CrowdSecApiError> {
    let params = [("ip", ip), ("type", "ban")];
    let url = reqwest::Url::parse_with_params(url, &params)
        .map_err(|err| CrowdSecApiError::UrlParsingFailed { error: err })?;
    let res = get_request(url, api_key)
        .await
        .map_err(|err| CrowdSecApiError::RequestFailed { error: err })?;
    if !res.status().is_success() {
        return Err(CrowdSecApiError::ResponseBad {
            status_code: res.status(),
        });
    }
    if let Ok(text) = res.text().await {
        if text == "null" {
            return Ok(None);
        }
        if let Ok(decision) = serde_json::from_str::<Vec<Decision>>(&text) {
            if !decision.is_empty() {
                return Ok(Some(decision[0].clone()));
            }
        }
    }
    Err(CrowdSecApiError::ResponseParsingFailed {
        error: String::from("Could not parse decision in response."),
    })
}

/// Call the CrowdSec decisions stream API to get the new and deleted decisions.
/// # Arguments
/// * `url` - The URL of the CrowdSec decisions stream API.
/// * `api_key` - The API key to use to authenticate to the CrowdSec decisions stream API.
/// * `startup` - If `true`, the API will return all the decisions, otherwise it will only return the new decisions.
/// # Returns
/// * The new and deleted decisions.
/// * `CrowdSecApiError` if the request failed.
async fn get_decisions_stream(
    url: &str,
    api_key: &str,
    startup: bool,
) -> Result<Stream, CrowdSecApiError> {
    let params = [
        ("startup", if startup { "true" } else { "false" }),
        ("scope", "Ip,Range"),
    ];
    let url = reqwest::Url::parse_with_params(url, &params)
        .map_err(|err| CrowdSecApiError::UrlParsingFailed { error: err })?;
    let res = get_request(url, api_key)
        .await
        .map_err(|err| CrowdSecApiError::RequestFailed { error: err })?;
    if !res.status().is_success() {
        return Err(CrowdSecApiError::ResponseBad {
            status_code: res.status(),
        });
    }
    if let Ok(stream) = res.json::<Stream>().await {
        return Ok(stream);
    }
    Err(CrowdSecApiError::ResponseParsingFailed {
        error: String::from("Could not parse new/deleted decisions in response."),
    })
}

/// Call the CrowdSec decisions stream API to get the new and deleted decisions.
/// # Arguments
/// * `config` - The configuration.
/// * `health_status` - The health status.
/// * `ipv4_table` - The IPv4 table.
/// * `ipv6_table` - The IPv6 table.
/// * `startup` - If `true`, the API will return all the decisions, otherwise it will only return the new decisions.
async fn update_decisions(
    config: Config,
    health_status: Arc<Mutex<HealthStatus>>,
    ipv4_table: Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>,
    ipv6_table: Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>,
    startup: &mut bool,
) {
    match get_decisions_stream(
        &config.crowdsec_stream_url,
        &config.crowdsec_api_key,
        *startup,
    )
    .await
    {
        Ok(stream) => {
            set_health_status(health_status.clone(), true);
            if stream.new.is_none() && stream.deleted.is_none() {
                return;
            }
            info!("Decisions stream: {:?}", stream);

            if let Some(ref new) = stream.new {
                for decision in new {
                    let range = get_ip_and_subnet(&decision.value);
                    match range {
                        Some(range) => match range.ipv4 {
                            Some(ipv4) => {
                                if let Ok(mut table) = ipv4_table.lock() {
                                    table.insert(
                                        ipv4,
                                        range.subnet.unwrap_or(32),
                                        CacheAttributes::new(false, 0),
                                    );
                                }
                            }
                            None => match range.ipv6 {
                                Some(ipv6) => {
                                    if let Ok(mut table) = ipv6_table.lock() {
                                        table.insert(
                                            ipv6,
                                            range.subnet.unwrap_or(128),
                                            CacheAttributes::new(false, 0),
                                        );
                                    }
                                }
                                None => warn!("Invalid IP (in new): {:?}", decision.value),
                            },
                        },
                        None => warn!("Invalid IP (in new): {:?}", decision.value),
                    }
                }
            }
            if let Some(ref deleted) = stream.deleted {
                for decision in deleted {
                    let range = get_ip_and_subnet(&decision.value);
                    match range {
                        Some(range) => match range.ipv4 {
                            Some(ipv4) => {
                                if let Ok(mut table) = ipv4_table.lock() {
                                    table.remove(ipv4, range.subnet.unwrap_or(32));
                                }
                            }
                            None => match range.ipv6 {
                                Some(ipv6) => {
                                    if let Ok(mut table) = ipv6_table.lock() {
                                        table.remove(ipv6, range.subnet.unwrap_or(128));
                                    }
                                }
                                None => warn!("Invalid IP (in deleted): {:?}", decision.value),
                            },
                        },
                        None => warn!("Invalid IP (in deleted): {:?}", decision.value),
                    }
                }
            }
            *startup = false;
        }
        Err(err) => {
            error!("Could not call API. Error: {}", err);
            set_health_status(health_status.clone(), false);
        }
    }
}

/// The main function.
/// Updates the IP lookup tables with the new and deleted decisions at a regular interval.
/// # Arguments
/// * `config` - The configuration.
/// * `health_status` - The health status.
/// * `ipv4_table` - The IPv4 lookup table.
/// * `ipv6_table` - The IPv6 lookup table.
pub async fn stream_loop_thread(
    config: Config,
    health_status: Arc<Mutex<HealthStatus>>,
    ipv4_table: Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>,
    ipv6_table: Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>,
) {
    let mut startup: bool = true;
    let mut interval = time::interval(Duration::from_secs(config.stream_interval));
    loop {
        interval.tick().await;

        update_decisions(
            config.clone(),
            health_status.clone(),
            ipv4_table.clone(),
            ipv6_table.clone(),
            &mut startup,
        )
        .await;
    }
}
