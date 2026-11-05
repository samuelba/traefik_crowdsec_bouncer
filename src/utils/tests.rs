use std::time::Duration;

use super::*;

#[test]
async fn test_get_ip_and_subnet() {
    let ip = "1.1.1.1";
    let range = get_ip_and_subnet(ip);
    assert!(range.is_some());
    let range = range.unwrap();
    assert!(range.ipv4.is_some());
    assert!(range.ipv6.is_none());
    assert!(range.subnet.is_none());

    let ip = "1.1.1.1/24";
    let range = get_ip_and_subnet(ip);
    assert!(range.is_some());
    let range = range.unwrap();
    assert!(range.ipv4.is_some());
    assert!(range.ipv6.is_none());
    assert!(range.subnet.is_some());
    assert_eq!(range.subnet.unwrap(), 24);

    let ip = "1.1.1"; // invalid IP
    let range = get_ip_and_subnet(ip);
    assert!(range.is_none());

    let ip = "1.1.1.1/42"; // invalid subnet
    let range = get_ip_and_subnet(ip);
    assert!(range.is_none());

    let ip = "2001:db8::8a2e:370:7334"; // IPv6
    let range = get_ip_and_subnet(ip);
    assert!(range.is_some());
    let range = range.unwrap();
    assert!(range.ipv4.is_none());
    assert!(range.ipv6.is_some());
    assert!(range.subnet.is_none());

    let ip = "2001:db8::8a2e:370:7334/24"; // IPv6
    let range = get_ip_and_subnet(ip);
    assert!(range.is_some());
    let range = range.unwrap();
    assert!(range.ipv4.is_none());
    assert!(range.ipv6.is_some());
    assert!(range.subnet.is_some());
    assert_eq!(range.subnet.unwrap(), 24);

    let ip = "2001:db8::8a2e:370:7334/129"; // invalid subnet
    let range = get_ip_and_subnet(ip);
    assert!(range.is_none());
}

#[test]
async fn test_parse_crowdsec_duration() {
    assert_eq!(
        parse_crowdsec_duration("24h"),
        Some(Duration::from_secs(24 * 60 * 60))
    );
    assert_eq!(
        parse_crowdsec_duration("33h6m18.03174611s").map(|duration| duration.as_nanos()),
        Some(119_178_031_746_110)
    );
    assert_eq!(
        parse_crowdsec_duration("1h30m"),
        Some(Duration::from_secs(90 * 60))
    );
    assert_eq!(
        parse_crowdsec_duration("300ms"),
        Some(Duration::from_millis(300))
    );
    assert_eq!(
        parse_crowdsec_duration("1.5s"),
        Some(Duration::from_millis(1500))
    );
    assert_eq!(parse_crowdsec_duration("0"), Some(Duration::ZERO));
    assert_eq!(
        parse_crowdsec_duration("1us"),
        Some(Duration::from_micros(1))
    );
    assert_eq!(
        parse_crowdsec_duration("1µs"),
        Some(Duration::from_micros(1))
    );
    assert_eq!(
        parse_crowdsec_duration("1μs"),
        Some(Duration::from_micros(1))
    );

    assert!(parse_crowdsec_duration("").is_none());
    assert!(parse_crowdsec_duration("-1h").is_none());
    assert!(parse_crowdsec_duration("1").is_none());
    assert!(parse_crowdsec_duration("1x").is_none());
    assert!(parse_crowdsec_duration(&"1h".repeat(40)).is_none());
    assert!(parse_crowdsec_duration("999999999999999999999h").is_none());
}
