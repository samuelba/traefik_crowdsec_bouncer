use super::*;
use actix_web::{http::header, test};

#[test]
async fn test_extract_headers() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .insert_header(("X-Forwarded-For", "192.168.0.1"))
        .to_http_request();

    let headers = extract_headers(&req).unwrap();
    assert_eq!("192.168.0.1", headers.ip);
}

#[test]
async fn test_extract_headers_missing_headers() {
    let req = test::TestRequest::default()
        .insert_header(header::ContentType::plaintext())
        .to_http_request();

    assert!(extract_headers(&req).is_err());
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

    assert!(extract_headers(&req).is_err());
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
