use super::*;

#[tokio::test]
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
    let mut server = mockito::Server::new();
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

#[tokio::test]
async fn test_get_decision_unbanned_ip() {
    let api_key = "my_api_key";
    let ip = "1.2.3.4";

    // Simulate an unbanned IP address.
    let mock_response = "null";
    let mut server = mockito::Server::new();
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response)
        .create();

    let url = server.url() + "/v1/decisions";
    let result = get_decision(&url, api_key, ip).await.unwrap();

    // Verify that the function returns the expected result.
    assert!(result.is_none());

    // Clean up the mock server.
    mock_server.assert();
}

#[tokio::test]
async fn test_get_decision_bad_response() {
    let api_key = "my_api_key";
    let ip = "1.2.3.4";

    // Simulate a bad response from the API.
    let mut server = mockito::Server::new();
    let mock_server = server
        .mock("GET", "/v1/decisions")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("ip={}&type=ban", ip).as_str())
        .with_status(400)
        .create();

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

#[tokio::test]
async fn test_get_decisions_stream_startup() {
    let api_key = "my_api_key";
    let startup = true;

    // Simulate a stream of decisions.
    let mock_response = serde_json::json!({
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
                "scope": "Ip",
                "type": "ban",
                "value": "1.2.3.5"
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
                "value": "1.1.1.1"
            },
            {
                "duration": "33h6m18.03174611s",
                "id": 1,
                "origin": "CAPI",
                "scenario": "abc",
                "scope": "Ip",
                "type": "ban",
                "value": "1.1.1.2"
            }
    ]
    });
    let mut server = mockito::Server::new();
    let mock_server = server
        .mock("GET", "/v1/decisions/stream")
        .match_header("X-Api-Key", api_key)
        .match_query(format!("startup=true&scope=Ip%2CRange").as_str())
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create();

    // Get the decision stream.
    let url = server.url() + "/v1/decisions/stream";
    let result = get_decisions_stream(&url, api_key, startup).await;

    assert!(result.is_ok());
    let stream = result.unwrap();
    let new = stream.new.unwrap();
    assert_eq!(2, new.len());
    assert_eq!("1.2.3.4", new[0].value);
    assert_eq!("1.2.3.5", new[1].value);
    let deleted = stream.deleted.unwrap();
    assert_eq!(2, deleted.len());
    assert_eq!("1.1.1.1", deleted[0].value);
    assert_eq!("1.1.1.2", deleted[1].value);

    // Clean up the mock server.
    mock_server.assert();
}
