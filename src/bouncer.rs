use std::cmp::min;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use log::{info, warn};

use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};

use ip_network_table_deps_treebitmap::IpLookupTable;

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
            // Check if IP is in cache (including ranges).
            // If yes, check if it is expired.
            // If not, return the cached value.
            if let Ok(ipv4_table) = ipv4_data.lock()
                && let Some((_addr, _mask, cache_attributes)) = ipv4_table.longest_match(ip)
                && cache_attributes.expiration_time > chrono::Utc::now().timestamp_millis()
            {
                return if cache_attributes.allowed {
                    allowed_response(Some(headers.ip))
                } else {
                    forbidden_response(Some(headers.ip))
                };
            }

            // IP not in cache or expired.
            // Call CrowdSec API.
            // Update cache.
            return match get_decision(
                &config.crowdsec_live_url,
                &config.crowdsec_api_key,
                &headers.ip,
            )
            .await
            {
                Ok(decision) => {
                    set_health_status(health_status.get_ref().clone(), true);
                    match decision {
                        Some(decision) => {
                            // If the decisions duration is smaller than the cache TTL, use it instead.
                            let ttl = if let Ok(duration) = parse(&decision.duration) {
                                min(duration.as_millis() as i64, config.crowdsec_cache_ttl)
                            } else {
                                config.crowdsec_cache_ttl
                            };

                            // Update cache.
                            if let Ok(mut ipv4_table) = ipv4_data.lock() {
                                let (cache_ip, cache_mask) = match crate::utils::get_ip_and_subnet(
                                    &decision.value,
                                ) {
                                    Some(crate::utils::Address {
                                        ipv4: Some(addr),
                                        subnet,
                                        ..
                                    }) => (addr, subnet.unwrap_or(32)),
                                    Some(crate::utils::Address { ipv6: Some(_), .. }) => {
                                        warn!(
                                            "CrowdSec returned IPv6 decision '{}' but only IPv4 is supported. Caching request IP {} instead.",
                                            decision.value, headers.ip
                                        );
                                        (ip, 32)
                                    }
                                    None | Some(_) => {
                                        warn!(
                                            "Could not parse CrowdSec decision value '{}'. Caching request IP {} instead.",
                                            decision.value, headers.ip
                                        );
                                        (ip, 32)
                                    }
                                };
                                ipv4_table.insert(
                                    cache_ip,
                                    cache_mask,
                                    CacheAttributes {
                                        allowed: false,
                                        expiration_time: chrono::Utc::now().timestamp_millis()
                                            + ttl,
                                    },
                                );
                            }
                            forbidden_response(Some(headers.ip))
                        }
                        None => {
                            // Update cache.
                            // No decision means no ban, so cache the request IP as allowed.
                            if let Ok(mut ipv4_table) = ipv4_data.lock() {
                                ipv4_table.insert(
                                    ip,
                                    32,
                                    CacheAttributes {
                                        allowed: true,
                                        expiration_time: chrono::Utc::now().timestamp_millis()
                                            + config.crowdsec_cache_ttl,
                                    },
                                );
                            }
                            allowed_response(Some(headers.ip))
                        }
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
            };
        }
        Ok(IpAddr::V6(ip)) => {
            // Check if IP is in cache.
            // If yes, check if it is expired.
            // If not, return the cached value.
            if let Ok(ipv6_table) = ipv6_data.lock()
                && let Some(cache_attributes) = ipv6_table.exact_match(ip, 128)
                && cache_attributes.expiration_time > chrono::Utc::now().timestamp_millis()
            {
                return if cache_attributes.allowed {
                    allowed_response(Some(headers.ip))
                } else {
                    forbidden_response(Some(headers.ip))
                };
            }

            // IP not in cache or expired.
            // Call CrowdSec API.
            // Update cache.
            return match get_decision(
                &config.crowdsec_live_url,
                &config.crowdsec_api_key,
                &headers.ip,
            )
            .await
            {
                Ok(decision) => {
                    set_health_status(health_status.get_ref().clone(), true);
                    match decision {
                        Some(decision) => {
                            // If the decisions duration is smaller than the cache TTL, use it instead.
                            let ttl = if let Ok(duration) = parse(&decision.duration) {
                                min(duration.as_millis() as i64, config.crowdsec_cache_ttl)
                            } else {
                                config.crowdsec_cache_ttl
                            };

                            // Update cache.
                            if let Ok(mut ipv6_table) = ipv6_data.lock() {
                                let (cache_ip, cache_mask) =
                                    match crate::utils::get_ip_and_subnet(&decision.value) {
                                        Some(crate::utils::Address {
                                            ipv6: Some(addr),
                                            subnet,
                                            ..
                                        }) => (addr, subnet.unwrap_or(128)),
                                        _ => (ip, 128),
                                    };
                                ipv6_table.insert(
                                    cache_ip,
                                    cache_mask,
                                    CacheAttributes {
                                        allowed: false,
                                        expiration_time: chrono::Utc::now().timestamp_millis()
                                            + ttl,
                                    },
                                );
                            }
                            forbidden_response(Some(headers.ip))
                        }
                        None => {
                            // Update cache.
                            // No decision means no ban, so cache the request IP as allowed.
                            if let Ok(mut ipv6_table) = ipv6_data.lock() {
                                ipv6_table.insert(
                                    ip,
                                    128,
                                    CacheAttributes {
                                        allowed: true,
                                        expiration_time: chrono::Utc::now().timestamp_millis()
                                            + config.crowdsec_cache_ttl,
                                    },
                                );
                            }
                            allowed_response(Some(headers.ip))
                        }
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
            };
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
#[get("/api/v1/blockList")]
pub async fn block_list(
    config: Data<Config>,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    ipv6_data: Data<Arc<Mutex<IpLookupTable<Ipv6Addr, CacheAttributes>>>>,
) -> HttpResponse {
    match config.crowdsec_mode {
        CrowdSecMode::Stream => {
            let mut list: Vec<String> = Vec::new();

            // Add IPv4 addresses
            if let Ok(ipv4_table) = ipv4_data.lock() {
                let iter = ipv4_table.iter();
                for (ip, _, _) in iter {
                    list.push(format!("{}", ip));
                }
            }

            // Add IPv6 addresses
            if let Ok(ipv6_table) = ipv6_data.lock() {
                let iter = ipv6_table.iter();
                for (ip, _, _) in iter {
                    list.push(format!("{}", ip));
                }
            }

            if !list.is_empty() || ipv4_data.lock().is_ok() || ipv6_data.lock().is_ok() {
                return HttpResponse::Ok()
                    .content_type(APPLICATION_JSON)
                    .json(&list);
            }

            HttpResponse::InternalServerError()
                .content_type(TEXT_PLAIN)
                .body("Could not generate the block list.")
        }
        CrowdSecMode::Live => HttpResponse::Ok()
            .content_type(TEXT_PLAIN)
            .body("Only available in stream mode."),
        CrowdSecMode::None => HttpResponse::Ok()
            .content_type(TEXT_PLAIN)
            .body("Only available in stream mode."),
    }
}

/// Get the health status of the service.
/// # Arguments
/// * `health_status` - The health status.
/// # Returns
/// * `HttpResponse` - The HTTP response.
#[get("/api/v1/health")]
pub async fn health(health_status: Data<Arc<Mutex<HealthStatus>>>) -> HttpResponse {
    if let Ok(health_status) = health_status.lock()
        && health_status.healthy()
    {
        return HttpResponse::Ok().content_type(TEXT_PLAIN).body("OK");
    }
    HttpResponse::ServiceUnavailable()
        .content_type(TEXT_PLAIN)
        .body("NOT OK")
}
