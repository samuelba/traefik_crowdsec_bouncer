use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// CrowdSec durations are short Go `time.Duration` strings. Cap the input so a
/// hostile value cannot force unbounded work (GHSA-qpgv-g792-wh6x).
const MAX_DURATION_LEN: usize = 64;

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
        if let Some(subnet) = subnet
            && subnet > 32
        {
            return None;
        }
        Some(Address {
            ipv4: Some(addr),
            ipv6: None,
            subnet,
        })
    }

    fn try_to_convert_to_ipv6(ip: &str, subnet: Option<u32>) -> Option<Address> {
        let addr = ip.parse::<Ipv6Addr>().ok()?;
        if let Some(subnet) = subnet
            && subnet > 128
        {
            return None;
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

/// Parse a CrowdSec decision duration.
///
/// CrowdSec uses Go's `time.ParseDuration` format (`24h`, `1h30m`, `300ms`,
/// `18.03174611s`, `0`). Returns `None` when the string is not that format or
/// the value does not fit in a [`Duration`].
pub fn parse_crowdsec_duration(input: &str) -> Option<Duration> {
    if input.is_empty() || input.len() > MAX_DURATION_LEN {
        return None;
    }
    if input == "0" {
        return Some(Duration::ZERO);
    }

    let mut rest = input;
    if let Some(stripped) = rest.strip_prefix('+') {
        rest = stripped;
    } else if rest.starts_with('-') {
        return None;
    }
    if rest.is_empty() {
        return None;
    }

    let mut total: u128 = 0;
    while !rest.is_empty() {
        let (component, next) = parse_duration_component(rest)?;
        total = total.checked_add(component)?;
        rest = next;
    }
    let nanos = u64::try_from(total).ok()?;
    Some(Duration::from_nanos(nanos))
}

fn parse_duration_component(input: &str) -> Option<(u128, &str)> {
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    let int_end = index;
    let (frac_start, frac_end) = if index < bytes.len() && bytes[index] == b'.' {
        index += 1;
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        (start, index)
    } else {
        (index, index)
    };
    if int_end == 0 && frac_start == frac_end {
        return None;
    }

    let (unit, rest) = split_duration_unit(&input[index..])?;
    let unit_nanos = duration_unit_nanos(unit)?;
    let nanos =
        scale_duration_component(&input[..int_end], &input[frac_start..frac_end], unit_nanos)?;
    Some((nanos, rest))
}

fn split_duration_unit(input: &str) -> Option<(&str, &str)> {
    if let Some(rest) = input
        .strip_prefix("µs")
        .or_else(|| input.strip_prefix("μs"))
    {
        return Some(("us", rest));
    }
    let end = input
        .find(|c: char| c.is_ascii_digit() || c == '.')
        .unwrap_or(input.len());
    if end == 0 || !input.as_bytes()[..end].iter().all(u8::is_ascii_alphabetic) {
        return None;
    }
    Some((&input[..end], &input[end..]))
}

fn duration_unit_nanos(unit: &str) -> Option<u128> {
    match unit {
        "ns" => Some(1),
        "us" => Some(1_000),
        "ms" => Some(1_000_000),
        "s" => Some(1_000_000_000),
        "m" => Some(60_000_000_000),
        "h" => Some(3_600_000_000_000),
        _ => None,
    }
}

fn scale_duration_component(int_part: &str, frac_part: &str, unit_nanos: u128) -> Option<u128> {
    let whole: u128 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().ok()?
    };
    let mut nanos = whole.checked_mul(unit_nanos)?;
    if !frac_part.is_empty() {
        // Hours are 3.6e12 ns. Fifteen fractional digits stay inside u128.
        let frac = if frac_part.len() > 15 {
            &frac_part[..15]
        } else {
            frac_part
        };
        let frac_val: u128 = frac.parse().ok()?;
        let scale = 10u128.checked_pow(u32::try_from(frac.len()).ok()?)?;
        nanos = nanos.checked_add(frac_val.checked_mul(unit_nanos)? / scale)?;
    }
    Some(nanos)
}
