use super::*;
use actix_web::{http::header, test};

#[test]
async fn test_extract_headers() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header(("X-Forwarded-For", "192.168.0.1"))
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    };

    let headers = extract_headers(&req, &config).unwrap();
    assert_eq!("192.168.0.1", headers.ip);
}

#[test]
async fn test_extract_headers_missing_headers() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    };

    assert!(extract_headers(&req, &config).is_err());
}

#[test]
async fn test_extract_headers_invalid_headers() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header((
            "X-Forwarded-For",
            header::HeaderValue::from_bytes(b"\xFF").unwrap(),
        ))
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    };

    assert!(extract_headers(&req, &config).is_err());
}

#[test]
async fn test_extract_headers_multiple_ips() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header(("X-Forwarded-For", "1.2.3.4, 5.6.7.8"))
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    };

    // No trusted proxies, so we take the "untrusted" one from the right, which is the last one (5.6.7.8)
    // Wait, if no trusted proxies, the logic says:
    // Iterate rev: 5.6.7.8. Trusted? No. Break. client_ip = 5.6.7.8.
    let headers = extract_headers(&req, &config).unwrap();
    assert_eq!("5.6.7.8", headers.ip);
}

#[test]
async fn test_extract_headers_multiple_ips_with_spaces() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header(("X-Forwarded-For", "1.2.3.4,  5.6.7.8"))
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    };

    let headers = extract_headers(&req, &config).unwrap();
    assert_eq!("5.6.7.8", headers.ip);
}

#[test]
async fn test_extract_headers_trusted_proxy() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header(("X-Forwarded-For", "1.2.3.4, 10.0.0.1"))
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec!["10.0.0.1/32".parse().unwrap()],
    };

    // 10.0.0.1 is trusted. Logic:
    // 1. 10.0.0.1 -> Trusted? Yes. Continue.
    // 2. 1.2.3.4 -> Trusted? No. Break. client_ip = 1.2.3.4.
    let headers = extract_headers(&req, &config).unwrap();
    assert_eq!("1.2.3.4", headers.ip);
}

#[test]
async fn test_extract_headers_garbage_in_chain() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header(("X-Forwarded-For", "1.2.3.4, not_an_ip, 10.0.0.1"))
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec!["10.0.0.1/32".parse().unwrap()],
    };

    // 10.0.0.1 is trusted.
    // not_an_ip is NOT trusted (invalid). Stop.
    // Result: not_an_ip.
    // This will cause the bouncer to forbid the request (fail closed).
    let headers = extract_headers(&req, &config).unwrap();
    assert_eq!("not_an_ip", headers.ip);
}

#[test]
async fn test_extract_headers_all_trusted_proxies() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header(("X-Forwarded-For", "203.0.113.1, 192.168.1.1, 10.0.0.1"))
        .to_http_request();
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![
            "203.0.113.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            "10.0.0.0/24".parse().unwrap(),
        ],
    };

    // All IPs are trusted proxies.
    // Logic should iterate right-to-left:
    // 1. 10.0.0.1 -> Trusted? Yes. Continue.
    // 2. 192.168.1.1 -> Trusted? Yes. Continue.
    // 3. 203.0.113.1 -> Trusted? Yes. Continue.
    // Loop completes without finding untrusted IP.
    // Result: client_ip should be the leftmost IP (203.0.113.1), the original client.
    let headers = extract_headers(&req, &config).unwrap();
    assert_eq!("203.0.113.1", headers.ip);
}

#[test]
async fn test_authenticate_stream_mode() {
    let mut ipv4_table = IpLookupTable::new();
    ipv4_table.insert(
        Ipv4Addr::from_str("172.16.0.0").unwrap(),
        16,
        CacheAttributes::new(false, 0),
    );
    ipv4_table.insert(
        Ipv4Addr::from_str("192.168.0.1").unwrap(),
        32,
        CacheAttributes::new(false, 0),
    );
    let ipv4_data = Data::new(Arc::new(Mutex::new(ipv4_table)));

    assert_eq!(
        200,
        authenticate_stream_mode(
            TraefikHeaders {
                ip: "1.1.1.1".to_string(),
            },
            ipv4_data.clone(),
        )
        .await
        .status()
    );
    assert_eq!(
        403,
        authenticate_stream_mode(
            TraefikHeaders {
                ip: "172.16.5.5".to_string(),
            },
            ipv4_data.clone(),
        )
        .await
        .status()
    );
    assert_eq!(
        403,
        authenticate_stream_mode(
            TraefikHeaders {
                ip: "192.168.0.1".to_string(),
            },
            ipv4_data.clone(),
        )
        .await
        .status()
    );
}

#[test]
async fn test_authenticate_live_mode_from_cache() {
    // Set up test data.
    let config = Data::new(Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: "".to_string(),
        crowdsec_mode: CrowdSecMode::Live,
        crowdsec_cache_ttl: 60000,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    });
    let health_status = Data::new(Arc::new(Mutex::new(HealthStatus {
        live_status: true,
        stream_status: true,
    })));
    let ipv4_data = Data::new(Arc::new(Mutex::new(IpLookupTable::<
        Ipv4Addr,
        CacheAttributes,
    >::new())));
    if let Ok(mut ipv4_table) = ipv4_data.lock() {
        ipv4_table.insert(
            Ipv4Addr::from_str("172.16.0.1").unwrap(),
            32,
            CacheAttributes {
                allowed: true,
                expiration_time: chrono::Utc::now().timestamp_millis() + 60000,
            },
        );
        ipv4_table.insert(
            Ipv4Addr::from_str("172.16.0.2").unwrap(),
            32,
            CacheAttributes {
                allowed: false,
                expiration_time: chrono::Utc::now().timestamp_millis() + 60000,
            },
        );
    }

    // Allowed IP.
    let response = authenticate_live_mode(
        TraefikHeaders {
            ip: "172.16.0.1".to_string(),
        },
        config.clone(),
        health_status.clone(),
        ipv4_data.clone(),
    )
    .await;
    assert_eq!(200, response.status());

    // Forbidden IP.
    let response = authenticate_live_mode(
        TraefikHeaders {
            ip: "172.16.0.2".to_string(),
        },
        config.clone(),
        health_status.clone(),
        ipv4_data.clone(),
    )
    .await;
    assert_eq!(403, response.status());
}

#[test]
async fn test_authenticate_live_mode_from_api_allowed() {
    // Set up test data.
    let health_status = Data::new(Arc::new(Mutex::new(HealthStatus {
        live_status: true,
        stream_status: true,
    })));
    let ipv4_data = Data::new(Arc::new(Mutex::new(IpLookupTable::<
        Ipv4Addr,
        CacheAttributes,
    >::new())));
    // Add an expired (blocked) entry to the cache.
    if let Ok(mut ipv4_table) = ipv4_data.lock() {
        ipv4_table.insert(
            Ipv4Addr::from_str("172.16.0.1").unwrap(),
            32,
            CacheAttributes {
                allowed: false,
                expiration_time: chrono::Utc::now().timestamp_millis() - 10000,
            },
        );
    }

    let api_key = "my_api_key";
    let ip = "172.16.0.1";

    // Simulate an allowed IP address.
    let mock_response = "null";
    let mut server = mockito::Server::new_async().await;
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response)
        .create_async()
        .await;

    let config = Data::new(Config {
        crowdsec_live_url: server.url() + "/v1/decisions",
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: api_key.to_string(),
        crowdsec_mode: CrowdSecMode::Live,
        crowdsec_cache_ttl: 60000,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    });

    // Allowed IP.
    let response = authenticate_live_mode(
        TraefikHeaders { ip: ip.to_string() },
        config.clone(),
        health_status.clone(),
        ipv4_data.clone(),
    )
    .await;
    assert_eq!(200, response.status());
    if let Ok(ipv4_table) = ipv4_data.lock() {
        let res = ipv4_table.exact_match(Ipv4Addr::from_str("172.16.0.1").unwrap(), 32);
        assert!(res.is_some());
        assert!(res.unwrap().allowed);
    }

    // Clean up the mock server.
    mock_server.assert();

    // Add an expired (allowed) entry to the cache.
    if let Ok(mut ipv4_table) = ipv4_data.lock() {
        ipv4_table.insert(
            Ipv4Addr::from_str("172.16.0.2").unwrap(),
            32,
            CacheAttributes {
                allowed: true,
                expiration_time: chrono::Utc::now().timestamp_millis() - 10000,
            },
        );
    }

    let ip = "172.16.0.2";

    // Simulate a forbidden IP address.
    let mock_response = serde_json::json!([
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Ip",
            "type": "ban",
            "value": ip
        }
    ]);
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create_async()
        .await;

    let config = Data::new(Config {
        crowdsec_live_url: server.url() + "/v1/decisions",
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: api_key.to_string(),
        crowdsec_mode: CrowdSecMode::Live,
        crowdsec_cache_ttl: 60000,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    });

    // Blocked IP.
    let response = authenticate_live_mode(
        TraefikHeaders { ip: ip.to_string() },
        config.clone(),
        health_status.clone(),
        ipv4_data.clone(),
    )
    .await;
    assert_eq!(403, response.status());
    if let Ok(ipv4_table) = ipv4_data.lock() {
        let res = ipv4_table.exact_match(Ipv4Addr::from_str("172.16.0.2").unwrap(), 32);
        assert!(res.is_some());
        assert!(!res.unwrap().allowed);
    }

    // Clean up the mock server.
    mock_server.assert();
}

#[test]
async fn test_authenticate_none_mode() {
    // Set up test data.
    let health_status = Data::new(Arc::new(Mutex::new(HealthStatus {
        live_status: true,
        stream_status: true,
    })));
    let api_key = "my_api_key";
    let ip = "172.16.0.1";

    // Simulate an allowed IP address.
    let mock_response = "null";
    let mut server = mockito::Server::new_async().await;
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response)
        .create_async()
        .await;

    let config = Data::new(Config {
        crowdsec_live_url: server.url() + "/v1/decisions",
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: api_key.to_string(),
        crowdsec_mode: CrowdSecMode::Live,
        crowdsec_cache_ttl: 60000,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    });

    // Allowed IP.
    let response = authenticate_none_mode(
        TraefikHeaders { ip: ip.to_string() },
        config.clone(),
        health_status.clone(),
    )
    .await;
    assert_eq!(200, response.status());

    // Clean up the mock server.
    mock_server.assert();

    // Simulate a forbidden IP address.
    let mock_response = serde_json::json!([
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Ip",
            "type": "ban",
            "value": ip
        }
    ]);
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create_async()
        .await;

    let config = Data::new(Config {
        crowdsec_live_url: server.url() + "/v1/decisions",
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: api_key.to_string(),
        crowdsec_mode: CrowdSecMode::Live,
        crowdsec_cache_ttl: 60000,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    });

    // Blocked IP.
    let response = authenticate_none_mode(
        TraefikHeaders { ip: ip.to_string() },
        config.clone(),
        health_status.clone(),
    )
    .await;
    assert_eq!(403, response.status());

    // Clean up the mock server.
    mock_server.assert();
}

#[test]
async fn test_authenticate_live_mode_caches_range() {
    // Set up test data.
    let health_status = Data::new(Arc::new(Mutex::new(HealthStatus {
        live_status: true,
        stream_status: true,
    })));
    let ipv4_data = Data::new(Arc::new(Mutex::new(IpLookupTable::<
        Ipv4Addr,
        CacheAttributes,
    >::new())));

    let api_key = "my_api_key";
    let ip_check = "10.0.0.1";
    let ip_range = "10.0.0.0/24";

    // Simulate a forbidden IP address range.
    let mock_response = serde_json::json!([
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Range",
            "type": "ban",
            "value": ip_range
        }
    ]);

    let mut server = mockito::Server::new_async().await;
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip_check).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .expect(1) // Should only be called once; second request should use cache
        .create_async()
        .await;

    let config = Data::new(Config {
        crowdsec_live_url: server.url() + "/v1/decisions",
        crowdsec_stream_url: "".to_string(),
        crowdsec_api_key: api_key.to_string(),
        crowdsec_mode: CrowdSecMode::Live,
        crowdsec_cache_ttl: 60000,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    });

    // Request for 10.0.0.1, should trigger API call and cache 10.0.0.0/24
    let response = authenticate_live_mode(
        TraefikHeaders {
            ip: ip_check.to_string(),
        },
        config.clone(),
        health_status.clone(),
        ipv4_data.clone(),
    )
    .await;
    assert_eq!(403, response.status());

    mock_server.assert();

    // Verify Cache contains the range
    if let Ok(ipv4_table) = ipv4_data.lock() {
        let res = ipv4_table.longest_match(Ipv4Addr::from_str("10.0.0.2").unwrap());
        assert!(res.is_some(), "Should find a match for 10.0.0.2");
        let (addr, mask, attr) = res.unwrap();
        assert_eq!(addr, Ipv4Addr::from_str("10.0.0.0").unwrap());
        assert_eq!(mask, 24);
        assert_eq!(attr.allowed, false);
    }

    // Test that a second request for a different IP in the cached range uses the cache
    // (no new mock is set up, so if it makes an API call, the test will fail)
    let response = authenticate_live_mode(
        TraefikHeaders {
            ip: "10.0.0.2".to_string(),
        },
        config.clone(),
        health_status.clone(),
        ipv4_data.clone(),
    )
    .await;
    assert_eq!(403, response.status());

    // Verify health status is still true (would be false if API call failed)
    if let Ok(health_data) = health_status.lock() {
        assert!(
            health_data.live_status,
            "Health status should remain true since cache was used"
        );
    }

    // Verify the mock was only called once
    mock_server.assert();
}
