use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(test)]
mod tests;

/// The IP address and optional subnet.
pub struct Address {
    /// The IPv4 address.
    pub ipv4: Option<Ipv4Addr>,
    /// The IPv6 address.
    pub ipv6: Option<Ipv6Addr>,
    /// The subnet.
    pub subnet: Option<u32>,
}

/// Get the IP address (IPv4 or IPv6) and optional subnet from a string.
/// # Arguments
/// * `ip` - The IP address and optional subnet.
/// # Returns
/// * The IP address (IPv4 or IPv6) and optional subnet or `None` if the IP address is invalid.
pub fn get_ip_and_subnet(ip: &str) -> Option<Address> {
    fn try_to_convert_to_ipv4(ip: &str, subnet: Option<u32>) -> Option<Address> {
        let addr = ip.parse::<Ipv4Addr>().ok()?;
        if let Some(subnet) = subnet {
            if subnet > 32 {
                return None;
            }
        }
        Some(Address {
            ipv4: Some(addr),
            ipv6: None,
            subnet,
        })
    }

    fn try_to_convert_to_ipv6(ip: &str, subnet: Option<u32>) -> Option<Address> {
        let addr = ip.parse::<Ipv6Addr>().ok()?;
        if let Some(subnet) = subnet {
            if subnet > 128 {
                return None;
            }
        }
        Some(Address {
            ipv4: None,
            ipv6: Some(addr),
            subnet,
        })
    }

    if !ip.contains('/') {
        if ip.contains(':') {
            return try_to_convert_to_ipv6(ip, None);
        }
        return try_to_convert_to_ipv4(ip, None);
    }
    let parts: Vec<&str> = ip.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_address = parts[0];
    let parsed_subnet = parts[1].parse::<u32>().ok()?;
    if ip_address.contains(':') {
        return try_to_convert_to_ipv6(ip_address, Some(parsed_subnet));
    }
    try_to_convert_to_ipv4(ip_address, Some(parsed_subnet))
}
