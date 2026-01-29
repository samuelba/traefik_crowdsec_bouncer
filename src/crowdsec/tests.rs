use super::*;

use crate::config::CrowdSecMode;

const MOCK_RESPONSE_1: &str = r#"{
    "new": [
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Ip",
            "type": "ban",
            "value": "1.2.3.4"
        },
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Range",
            "type": "ban",
            "value": "1.1.0.0/22"
        }
    ],
    "deleted": [
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Ip",
            "type": "ban",
            "value": "3.3.3.3"
        },
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Ip",
            "type": "ban",
            "value": "4.4.4.4"
        }
]
}"#;

const MOCK_RESPONSE_2: &str = r#"{
    "new": [
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Range",
            "type": "ban",
            "value": "2.2.0.0/16"
        }
    ],
    "deleted": [
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Range",
            "type": "ban",
            "value": "1.1.0.0/22"
        }
]
}"#;

#[test]
async fn test_get_decision_banned_ip() {
    let api_key = "my_api_key";
    let ip = "1.2.3.4";

    // Simulate a banned IP address.
    let mock_response = serde_json::json!([
        {
            "duration": "33h6m18.03174611s",
            "id": 1,
            "origin": "CAPI",
            "scenario": "abc",
            "scope": "Ip",
            "type": "ban",
            "value": "1.2.3.4"
        }
    ]);
    let mut server = mockito::Server::new_async().await;
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create_async()
        .await;

    // Get the decision.
    let url = server.url() + "/v1/decisions";
    let result = get_decision(&url, api_key, ip).await.unwrap();

    // Verify that the function returns the expected result.
    assert!(result.is_some());
    assert_eq!(result.unwrap().value, ip);

    // Clean up the mock server.
    mock_server.assert();
}

#[test]
async fn test_get_decision_unbanned_ip() {
    let api_key = "my_api_key";
    let ip = "1.2.3.4";

    // Simulate an unbanned IP address.
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

    let url = server.url() + "/v1/decisions";
    let result = get_decision(&url, api_key, ip).await.unwrap();

    // Verify that the function returns the expected result.
    assert!(result.is_none());

    // Clean up the mock server.
    mock_server.assert();
}

#[test]
async fn test_get_decision_bad_response() {
    let api_key = "my_api_key";
    let ip = "1.2.3.4";

    // Simulate a bad response from the API.
    let mut server = mockito::Server::new_async().await;
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(400)
        .create_async()
        .await;

    // Get the decision.
    let url = server.url() + "/v1/decisions";
    let result = get_decision(&url, api_key, ip).await;

    // Verify that the function returns an error.
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CrowdSecApiError::ResponseBad { .. }
    ));

    // Clean up the mock server.
    mock_server.assert();
}

#[test]
async fn test_get_decisions_stream_startup() {
    let api_key = "my_api_key";
    let startup = true;

    // Simulate a stream of decisions.
    let mut server = mockito::Server::new_async().await;
    let mock_server = server
        .mock("GET", "/v1/decisions/stream")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("startup=true&scope=Ip%2CRange").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(MOCK_RESPONSE_1)
        .create_async()
        .await;

    // Get the decision stream.
    let url = server.url() + "/v1/decisions/stream";
    let result = get_decisions_stream(&url, api_key, startup).await;

    assert!(result.is_ok());
    let stream = result.unwrap();
    let new = stream.new.unwrap();
    assert_eq!(2, new.len());
    assert_eq!("1.2.3.4", new[0].value);
    assert_eq!("1.1.0.0/22", new[1].value);
    let deleted = stream.deleted.unwrap();
    assert_eq!(2, deleted.len());
    assert_eq!("3.3.3.3", deleted[0].value);
    assert_eq!("4.4.4.4", deleted[1].value);

    // Clean up the mock server.
    mock_server.assert();
}

#[test]
async fn test_update_decisions() {
    let api_key = "my_api_key";

    // Simulate a stream of decisions.
    let mut server = mockito::Server::new_async().await;
    let mock_server = server
        .mock("GET", "/v1/decisions/stream")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("startup=true&scope=Ip%2CRange").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(MOCK_RESPONSE_1)
        .create_async()
        .await;

    // Set up test data
    let config = Config {
        crowdsec_live_url: "".to_string(),
        crowdsec_stream_url: server.url() + "/v1/decisions/stream",
        crowdsec_api_key: api_key.to_string(),
        crowdsec_mode: CrowdSecMode::Stream,
        crowdsec_cache_ttl: 0,
        stream_interval: 0,
        port: 0,
        trusted_proxies: vec![],
    };
    let health_status = Arc::new(Mutex::new(HealthStatus::new()));
    let ipv4_table = Arc::new(Mutex::new(IpLookupTable::new()));
    let ipv6_table = Arc::new(Mutex::new(IpLookupTable::new()));
    let mut startup = true;

    update_decisions(
        config.clone(),
        health_status.clone(),
        ipv4_table.clone(),
        ipv6_table.clone(),
        &mut startup,
    )
    .await;

    // Check the result.
    if let Ok(ipv4_table) = ipv4_table.lock() {
        assert_eq!(2, ipv4_table.len());
        assert!(
            ipv4_table
                .exact_match(Ipv4Addr::new(1, 2, 3, 4), 32)
                .is_some()
        );
        assert!(
            ipv4_table
                .exact_match(Ipv4Addr::new(1, 1, 0, 0), 22)
                .is_some()
        );
    } else {
        panic!("Expected an IPv4 table.");
    }

    // Clean up the mock server.
    mock_server.assert();

    let mock_server = server
        .mock("GET", "/v1/decisions/stream")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("startup=false&scope=Ip%2CRange").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(MOCK_RESPONSE_2)
        .create_async()
        .await;

    update_decisions(
        config.clone(),
        health_status.clone(),
        ipv4_table.clone(),
        ipv6_table.clone(),
        &mut startup,
    )
    .await;

    // Check the result.
    if let Ok(ipv4_table) = ipv4_table.lock() {
        assert_eq!(2, ipv4_table.len());
        assert!(
            ipv4_table
                .exact_match(Ipv4Addr::new(1, 2, 3, 4), 32)
                .is_some()
        );
        assert!(
            ipv4_table
                .exact_match(Ipv4Addr::new(1, 1, 0, 0), 22)
                .is_none()
        );
        assert!(
            ipv4_table
                .exact_match(Ipv4Addr::new(2, 2, 0, 0), 16)
                .is_some()
        );
    } else {
        panic!("Expected an IPv4 table.");
    }

    // Clean up the mock server.
    mock_server.assert();
}
