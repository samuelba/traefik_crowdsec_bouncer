use std::cmp::min;
use std::net::Ipv4Addr;
use std::str::FromStr;
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

fn extract_headers(request: &HttpRequest) -> Result<TraefikHeaders, TraefikError> {
    let ip = if let Some(ip) = request.headers().get("X-Forwarded-For") {
        if let Ok(ip) = ip.to_str() {
            ip.to_string()
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
) -> HttpResponse {
    if let Ok(ipv4_table) = ipv4_data.lock() {
        let req_ip = Ipv4Addr::from_str(&headers.ip);
        match req_ip {
            Ok(ip) => {
                if ipv4_table.longest_match(ip).is_some() {
                    forbidden_response(Some(headers.ip))
                } else {
                    allowed_response(Some(headers.ip))
                }
            }
            Err(_) => forbidden_response(Some(headers.ip)),
        }
    } else {
        warn!("Could not lock the IPv4 lookup table. Block request.");
        forbidden_response(Some(headers.ip))
    }
}

pub async fn authenticate_live_mode(
    headers: TraefikHeaders,
    config: Data<Config>,
    health_status: Data<Arc<Mutex<HealthStatus>>>,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
) -> HttpResponse {
    let req_ip = Ipv4Addr::from_str(&headers.ip);
    match req_ip {
        Ok(ip) => {
            // Check if IP is in cache.
            // If yes, check if it is expired.
            // If not, return the cached value.
            if let Ok(ipv4_table) = ipv4_data.lock()
                && let Some(cache_attributes) = ipv4_table.exact_match(ip, 32)
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
                                ipv4_table.insert(
                                    ip,
                                    32,
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
/// * `request` - The HTTP request.
/// # Returns
/// * `HttpResponse` - The HTTP response. Either `Ok` or `Forbidden`.
#[get("/api/v1/forwardAuth")]
pub async fn authenticate(
    config: Data<Config>,
    health_status: Data<Arc<Mutex<HealthStatus>>>,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
    request: HttpRequest,
) -> HttpResponse {
    let headers = match extract_headers(&request) {
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
        CrowdSecMode::Stream => authenticate_stream_mode(headers, ipv4_data).await,
        CrowdSecMode::Live => {
            authenticate_live_mode(headers, config, health_status, ipv4_data).await
        }
        CrowdSecMode::None => authenticate_none_mode(headers, config, health_status).await,
    }
}

/// Get the list of blocked IP addresses. This is only available in stream mode.
/// # Arguments
/// * `config` - The configuration.
/// * `ipv4_data` - The IPv4 lookup table.
/// # Returns
/// * `HttpResponse` - The HTTP response.
#[get("/api/v1/blockList")]
pub async fn block_list(
    config: Data<Config>,
    ipv4_data: Data<Arc<Mutex<IpLookupTable<Ipv4Addr, CacheAttributes>>>>,
) -> HttpResponse {
    match config.crowdsec_mode {
        CrowdSecMode::Stream => {
            if let Ok(ipv4_table) = ipv4_data.lock() {
                let mut list: Vec<String> = Vec::new();
                let iter = ipv4_table.iter();
                for (ip, _, _) in iter {
                    list.push(format!("{}", ip));
                }
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
