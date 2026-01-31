use std::cmp::min;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use log::{info, warn};

use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};

use ip_network_table_deps_treebitmap::{IpLookupTable, address::Address};

use parse_duration::parse;

use crate::config::{Config, CrowdSecMode};
use crate::constants::{APPLICATION_JSON, TEXT_PLAIN};
use crate::crowdsec::get_decision;
use crate::errors::TraefikError;
use crate::types::{CacheAttributes, HealthStatus};

#[cfg(test)]
mod tests;

pub struct TraefikHeaders {
    ip: String,
}

/// Trait for abstracting over IPv4 and IPv6 address handling
trait IpVersion: Copy + Display + Sized {
    fn default_mask() -> u32;
    fn extract_from_address(addr: &crate::utils::Address) -> Option<(Self, u32)>;
    fn is_wrong_version(addr: &crate::utils::Address) -> bool;
    fn version_name() -> &'static str;
}

impl IpVersion for Ipv4Addr {
    fn default_mask() -> u32 {
        32
    }

    fn extract_from_address(addr: &crate::utils::Address) -> Option<(Self, u32)> {
        addr.ipv4.map(|ip| (ip, addr.subnet.unwrap_or(32)))
    }

    fn is_wrong_version(addr: &crate::utils::Address) -> bool {
        addr.ipv6.is_some()
    }

    fn version_name() -> &'static str {
        "IPv4"
    }
}

impl IpVersion for Ipv6Addr {
    fn default_mask() -> u32 {
        128
    }

    fn extract_from_address(addr: &crate::utils::Address) -> Option<(Self, u32)> {
        addr.ipv6.map(|ip| (ip, addr.subnet.unwrap_or(128)))
    }

    fn is_wrong_version(addr: &crate::utils::Address) -> bool {
        addr.ipv4.is_some()
    }

    fn version_name() -> &'static str {
        "IPv6"
    }
}

fn forbidden_response(ip: Option<String>) -> HttpResponse {
    if let Some(ip) = ip {
        info!("IP: {} is not allowed", ip);
    }
    HttpResponse::Forbidden()
        .content_type(TEXT_PLAIN)
        .body("Forbidden")
}

fn allowed_response(ip: Option<String>) -> HttpResponse {
    if let Some(ip) = ip {
        info!("IP: {} is allowed", ip);
    }
    HttpResponse::Ok().finish()
}

fn set_health_status(health_status: Arc<Mutex<HealthStatus>>, healthy: bool) {
    if let Ok(mut health_status) = health_status.lock() {
        health_status.live_status = healthy;
    }
}

fn extract_headers(request: &HttpRequest, config: &Config) -> Result<TraefikHeaders, TraefikError> {
    let ip = if let Some(ip) = request.headers().get("X-Forwarded-For") {
        if let Ok(ip) = ip.to_str() {
            let ips: Vec<&str> = ip.split(',').map(|s| s.trim()).collect();
            let mut client_ip = ips.first().unwrap_or(&"");

            for ip_str in ips.iter().rev() {
                match ip_str.parse::<std::net::IpAddr>() {
                    Ok(addr) => {
                        let is_trusted = config
                            .trusted_proxies
                            .iter()
                            .any(|cidr| cidr.contains(addr));
                        if !is_trusted {
                            client_ip = ip_str;
                            break;
                        }
                    }
                    Err(_) => {
                        // Unparseable IP: cannot verify trust, so treat as untrusted client IP and stop scanning.
                        // This prevents malformed entries from being skipped in favor of potentially spoofed IPs further left.
                        client_ip = ip_str;
                        break;
                    }
                }
            }
            client_ip.to_string()
        } else {
            return Err(TraefikError::BadHeaders);
        }
    } else {
        return Err(TraefikError::BadHeaders);
    };

    Ok(TraefikHeaders { ip })
}

/// Generic helper for checking cache and calling CrowdSec API
async fn check_ip_with_cache<T>(
    ip: T,
    ip_str: &str,
    lookup_table: Data<Arc<Mutex<IpLookupTable<T, CacheAttributes>>>>,
    config: &Config,
    health_status: Arc<Mutex<HealthStatus>>,
) -> HttpResponse
where
    T: IpVersion + Address,
{
    // Check if IP is in cache (including ranges).
    // If yes, check if it is expired.
    // If not, return the cached value.
    if let Ok(table) = lookup_table.lock()
        && let Some((_addr, _mask, cache_attributes)) = table.longest_match(ip)
        && cache_attributes.expiration_time > chrono::Utc::now().timestamp_millis()
    {
        return if cache_attributes.allowed {
            allowed_response(Some(ip_str.to_string()))
        } else {
            forbidden_response(Some(ip_str.to_string()))
        };
    }

    // IP not in cache or expired.
    // Call CrowdSec API.
    // Update cache.
    match get_decision(&config.crowdsec_live_url, &config.crowdsec_api_key, ip_str).await {
        Ok(decision) => {
            set_health_status(health_status.clone(), true);
            match decision {
                Some(decision) => {
                    // If the decisions duration is smaller than the cache TTL, use it instead.
                    let ttl = if let Ok(duration) = parse(&decision.duration) {
                        min(duration.as_millis() as i64, config.crowdsec_cache_ttl)
                    } else {
                        config.crowdsec_cache_ttl
                    };

                    // Update cache.
                    if let Ok(mut table) = lookup_table.lock() {
                        let (cache_ip, cache_mask) = match crate::utils::get_ip_and_subnet(
                            &decision.value,
                        ) {
                            Some(ref addr) if T::is_wrong_version(addr) => {
                                let wrong_version = if T::version_name() == "IPv4" {
                                    "IPv6"
                                } else {
                                    "IPv4"
                                };
                                warn!(
                                    "CrowdSec returned {} decision '{}' for {} request {}. Caching request IP instead.",
                                    wrong_version,
                                    decision.value,
                                    T::version_name(),
                                    ip_str
                                );
                                (ip, T::default_mask())
                            }
                            Some(ref addr) => {
                                if let Some((extracted_ip, mask)) = T::extract_from_address(addr) {
                                    (extracted_ip, mask)
                                } else {
                                    warn!(
                                        "Could not parse CrowdSec decision value '{}'. Caching request IP {} instead.",
                                        decision.value, ip_str
                                    );
                                    (ip, T::default_mask())
                                }
                            }
                            None => {
                                warn!(
                                    "Could not parse CrowdSec decision value '{}'. Caching request IP {} instead.",
                                    decision.value, ip_str
                                );
                                (ip, T::default_mask())
                            }
                        };
                        table.insert(
                            cache_ip,
                            cache_mask,
                            CacheAttributes {
                                allowed: false,
                                expiration_time: chrono::Utc::now().timestamp_millis() + ttl,
                            },
                        );
                    }
                    forbidden_response(Some(ip_str.to_string()))
                }
                None => {
                    // Update cache.
                    // No decision means no ban, so cache the request IP as allowed.
                    if let Ok(mut table) = lookup_table.lock() {
                        table.insert(
                            ip,
                            T::default_mask(),
                            CacheAttributes {
                                allowed: true,
                                expiration_time: chrono::Utc::now().timestamp_millis()
                                    + config.crowdsec_cache_ttl,
                            },
                        );
                    }
                    allowed_response(Some(ip_str.to_string()))
                }
            }
        }
        Err(err) => {
            info!(
                "Could not call API. IP: {} is not allowed. Error {}",
                ip_str, err
            );
            set_health_status(health_status, false);
            forbidden_response(None)
        }
    }
}

pub async fn authenticate_stream_mode(
    headers: TraefikHeaders,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    ipv6_data: Data<Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>>,
) -> HttpResponse {
    // Parse IP to determine version
    match headers.ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => {
            if let Ok(ipv4_table) = ipv4_data.lock() {
                if ipv4_table.longest_match(ipv4).is_some() {
                    forbidden_response(Some(headers.ip))
                } else {
                    allowed_response(Some(headers.ip))
                }
            } else {
                warn!("Could not lock the IPv4 lookup table. Block request.");
                forbidden_response(Some(headers.ip))
            }
        }
        Ok(IpAddr::V6(ipv6)) => {
            if let Ok(ipv6_table) = ipv6_data.lock() {
                if ipv6_table.longest_match(ipv6).is_some() {
                    forbidden_response(Some(headers.ip))
                } else {
                    allowed_response(Some(headers.ip))
                }
            } else {
                warn!("Could not lock the IPv6 lookup table. Block request.");
                forbidden_response(Some(headers.ip))
            }
        }
        Err(_) => forbidden_response(Some(headers.ip)),
    }
}

pub async fn authenticate_live_mode(
    headers: TraefikHeaders,
    config: Data<Config>,
    health_status: Data<Arc<Mutex<HealthStatus>>>,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    ipv6_data: Data<Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>>,
) -> HttpResponse {
    // Parse IP to determine version
    match headers.ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            check_ip_with_cache(
                ip,
                &headers.ip,
                ipv4_data,
                &config,
                health_status.get_ref().clone(),
            )
            .await
        }
        Ok(IpAddr::V6(ip)) => {
            check_ip_with_cache(
                ip,
                &headers.ip,
                ipv6_data,
                &config,
                health_status.get_ref().clone(),
            )
            .await
        }
        Err(_) => forbidden_response(Some(headers.ip)),
    }
}

pub async fn authenticate_none_mode(
    headers: TraefikHeaders,
    config: Data<Config>,
    health_status: Data<Arc<Mutex<HealthStatus>>>,
) -> HttpResponse {
    match get_decision(
        &config.crowdsec_live_url,
        &config.crowdsec_api_key,
        &headers.ip,
    )
    .await
    {
        Ok(decision) => {
            set_health_status(health_status.get_ref().clone(), true);
            match decision {
                Some(_) => forbidden_response(Some(headers.ip)),
                None => allowed_response(Some(headers.ip)),
            }
        }
        Err(err) => {
            info!(
                "Could not call API. IP: {} is not allowed. Error {}",
                headers.ip, err
            );
            set_health_status(health_status.get_ref().clone(), false);
            forbidden_response(None)
        }
    }
}

/// Authenticate an IP address.
/// # Arguments
/// * `config` - The configuration.
/// * `health_status` - The health status.
/// * `ipv4_data` - The IPv4 lookup table.
/// * `ipv6_data` - The IPv6 lookup table.
/// * `request` - The HTTP request.
/// # Returns
/// * `HttpResponse` - The HTTP response. Either `Ok` or `Forbidden`.
#[get("/api/v1/forwardAuth")]
pub async fn authenticate(
    config: Data<Config>,
    health_status: Data<Arc<Mutex<HealthStatus>>>,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    ipv6_data: Data<Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>>,
    request: HttpRequest,
) -> HttpResponse {
    let headers = match extract_headers(&request, &config) {
        Ok(header) => header,
        Err(err) => {
            warn!(
                "Could not get headers from request. Block request. Error: {}",
                err
            );
            return forbidden_response(None);
        }
    };

    match config.crowdsec_mode {
        CrowdSecMode::Stream => authenticate_stream_mode(headers, ipv4_data, ipv6_data).await,
        CrowdSecMode::Live => {
            authenticate_live_mode(headers, config, health_status, ipv4_data, ipv6_data).await
        }
        CrowdSecMode::None => authenticate_none_mode(headers, config, health_status).await,
    }
}

/// Get the list of blocked IP addresses. This is only available in stream mode.
/// # Arguments
/// * `config` - The configuration.
/// * `ipv4_data` - The IPv4 lookup table.
/// * `ipv6_data` - The IPv6 lookup table.
/// # Returns
/// * `HttpResponse` - The HTTP response.
pub async fn get_block_list(
    config: &Config,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    ipv6_data: Data<Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>>,
) -> HttpResponse {
    match config.crowdsec_mode {
        CrowdSecMode::Stream => {
            let mut list: Vec<String> = Vec::new();

            // Add IPv4 addresses
            let ipv4_table = match ipv4_data.lock() {
                Ok(table) => table,
                Err(_) => {
                    warn!("Could not lock the IPv4 lookup table for block list.");
                    return HttpResponse::InternalServerError()
                        .content_type(TEXT_PLAIN)
                        .body("Failed to acquire lock");
                }
            };

            for (ip, _, _) in ipv4_table.iter() {
                list.push(format!("{}", ip));
            }
            drop(ipv4_table);

            // Add IPv6 addresses
            let ipv6_table = match ipv6_data.lock() {
                Ok(table) => table,
                Err(_) => {
                    warn!("Could not lock the IPv6 lookup table for block list.");
                    return HttpResponse::InternalServerError()
                        .content_type(TEXT_PLAIN)
                        .body("Failed to acquire lock");
                }
            };

            for (ip, _, _) in ipv6_table.iter() {
                list.push(format!("{}", ip));
            }

            HttpResponse::Ok()
                .content_type(APPLICATION_JSON)
                .json(&list)
        }
        CrowdSecMode::Live => HttpResponse::Ok()
            .content_type(TEXT_PLAIN)
            .body("Only available in stream mode."),
        CrowdSecMode::None => HttpResponse::Ok()
            .content_type(TEXT_PLAIN)
            .body("Only available in stream mode."),
    }
}

/// Get the list of blocked IP addresses. This is only available in stream mode.
/// # Arguments
/// * `config` - The configuration.
/// * `ipv4_data` - The IPv4 lookup table.
/// * `ipv6_data` - The IPv6 lookup table.
/// # Returns
/// * `HttpResponse` - The HTTP response.
#[get("/api/v1/blockList")]
pub async fn block_list(
    config: Data<Config>,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    ipv6_data: Data<Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>>,
) -> HttpResponse {
    get_block_list(&config, ipv4_data, ipv6_data).await
}

/// Get the health status of the service.
/// # Arguments
/// * `health_status` - The health status.
/// # Returns
/// * `HttpResponse` - The HTTP response.
pub async fn get_health(health_status: &Arc<Mutex<HealthStatus>>) -> HttpResponse {
    if let Ok(health_status) = health_status.lock()
        && health_status.healthy()
    {
        return HttpResponse::Ok().content_type(TEXT_PLAIN).body("OK");
    }
    HttpResponse::ServiceUnavailable()
        .content_type(TEXT_PLAIN)
        .body("NOT OK")
}

/// Get the health status of the service.
/// # Arguments
/// * `health_status` - The health status.
/// # Returns
/// * `HttpResponse` - The HTTP response.
#[get("/api/v1/health")]
pub async fn health(health_status: Data<Arc<Mutex<HealthStatus>>>) -> HttpResponse {
    get_health(&health_status).await
}
