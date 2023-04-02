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
