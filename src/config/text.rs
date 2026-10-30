//! Parsers for the textual values: addresses with zones, host names,
//! interface names, hardware addresses, cookies (spec C7, C8, C16, K32).
//! Errors are messages; the caller names the field.

use std::net::{IpAddr, Ipv4Addr};

use super::{Cookie, Dhcpv6Identity, Family, HwAddr, L2tpIfName, Method, NameServer, RemoteAddr};

/// An interface name the kernel takes as given (K32): `L2tpIfName`'s
/// rules, and no `%`, which the kernel would expand as a pattern.
pub(crate) fn ifname(name: &[u8]) -> Result<L2tpIfName, String> {
    if name.contains(&b'%') {
        return Err(format!(
            "invalid interface name \"{}\": contains `%`",
            name.escape_ascii()
        ));
    }
    L2tpIfName::new(name).map_err(|e| e.to_string())
}

/// `None` when `text` is no IPv4 or IPv6 literal, else the address
/// (IPv4-mapped as IPv4) and the raw zone after `%` (C7).
pub(crate) fn ip_literal(text: &str) -> Option<(IpAddr, Option<&str>)> {
    let (addr, zone) = match text.split_once('%') {
        Some((addr, zone)) => (addr, Some(zone)),
        None => (text, None),
    };
    let addr: IpAddr = addr.parse().ok()?;
    Some((addr.to_canonical(), zone))
}

pub(crate) fn link_local(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V6(v6) if v6.is_unicast_link_local())
}

/// A zone is an interface name, valid only on a link-local address (C7).
pub(crate) fn zone(addr: IpAddr, zone: &[u8]) -> Result<L2tpIfName, String> {
    if !link_local(addr) {
        return Err(format!("{addr} is not link-local and takes no zone"));
    }
    ifname(zone)
}

/// Not unspecified, not multicast, not the IPv4 broadcast address;
/// loopback is allowed (C7).
pub(crate) fn unicast(addr: IpAddr) -> Result<(), String> {
    if addr.is_unspecified() || addr.is_multicast() || addr == Ipv4Addr::BROADCAST {
        return Err(format!("{addr} is not a unicast address"));
    }
    Ok(())
}

/// The host name of C7 without its trailing dot: at most 253 bytes of
/// dot-separated labels of 1 to 63 ASCII letters, digits and hyphens, no
/// label beginning or ending with a hyphen.
pub(crate) fn host_name(text: &str) -> Option<&str> {
    let name = text.strip_suffix('.').unwrap_or(text);
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    (name.len() <= 253
        && name.split('.').all(label)
        && name
            .rsplit('.')
            .next()
            .is_some_and(|last| !last.bytes().all(|b| b.is_ascii_digit())))
    .then_some(name)
}

/// `remote_addr` (C7). On error, the family of the literal when the
/// address part parsed, for C10's choice of family.
pub(crate) fn remote(text: &str) -> Result<RemoteAddr, (String, Option<Family>)> {
    if let Some((addr, zone)) = ip_literal(text) {
        let zone = zone
            .map(|z| ifname(z.as_bytes()))
            .transpose()
            .map_err(|e| (e, Some(Family::of(addr))))?;
        return Ok(RemoteAddr::Ip { addr, zone });
    }
    match host_name(text) {
        Some(name) => Ok(RemoteAddr::Host(name.to_owned())),
        None => Err((
            format!("{text:?} is neither an address nor a host name"),
            None,
        )),
    }
}

/// `"V4"` or `"V6"`, either case (C7).
pub(crate) fn family(text: &str) -> Option<Family> {
    match text.to_ascii_uppercase().as_str() {
        "V4" => Some(Family::V4),
        "V6" => Some(Family::V6),
        _ => None,
    }
}

/// Bytes from an even number of hexadecimal digits.
fn hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Only ASCII digits remain, so every pair is a `str` boundary.
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Six octets of two hexadecimal digits, all separated by `:` or all by
/// `-`, either case; unicast and not all zero (C8).
pub(crate) fn hwaddr(text: &str) -> Result<HwAddr, String> {
    let separator = if text.contains('-') { '-' } else { ':' };
    let octets: Vec<u8> = text
        .split(separator)
        .map(|octet| if octet.len() == 2 { hex(octet) } else { None })
        .collect::<Option<Vec<_>>>()
        .map(|parts| parts.concat())
        .unwrap_or_default();
    let octets = <[u8; 6]>::try_from(octets)
        .map_err(|_| format!("{text:?} is not six hexadecimal octets"))?;
    HwAddr::new(octets).map_err(|e| e.to_string())
}

/// 8 or 16 hexadecimal digits, either case (C8). The message never
/// repeats the value (O5).
pub(crate) fn cookie(text: &str) -> Result<Cookie, String> {
    match hex(text) {
        Some(bytes) if bytes.len() == 4 || bytes.len() == 8 => {
            Cookie::new(&bytes).map_err(|e| e.to_string())
        }
        _ => Err(format!(
            "a cookie is 8 or 16 hexadecimal digits; this one has {} characters",
            text.chars().count()
        )),
    }
}

/// An element of `addresses` (C16): a literal as for `remote_addr`, with
/// an optional port, `192.0.2.53:5353` or `[2001:db8::53]:5353`.
pub(crate) fn name_server(text: &str) -> Result<NameServer, String> {
    let invalid = || format!("{text:?} is not an address with an optional port");
    let (literal, port) = if let Some(rest) = text.strip_prefix('[') {
        let (literal, after) = rest.split_once(']').ok_or_else(invalid)?;
        match after {
            "" => (literal, None),
            _ => (literal, Some(after.strip_prefix(':').ok_or_else(invalid)?)),
        }
    } else if let Some((literal, port)) = text
        .split_once(':')
        .filter(|_| text.matches(':').count() == 1)
    {
        (literal, Some(port))
    } else {
        (text, None)
    };
    let (addr, zone) = ip_literal(literal).ok_or_else(invalid)?;
    let port = match port {
        // `u16::from_str` would also take a sign.
        Some(port) if port.bytes().all(|b| b.is_ascii_digit()) => {
            port.parse().map_err(|_| invalid())?
        }
        Some(_) => return Err(invalid()),
        None => 53,
    };
    let zone = zone.map(|z| ifname(z.as_bytes())).transpose()?;
    NameServer::new(addr, zone, port).map_err(|e| e.to_string())
}

/// `"ra"`, `"dhcpv6"` or `"ipv6"`, either case (C16).
pub(crate) fn method(text: &str) -> Result<Method, String> {
    match text.to_ascii_lowercase().as_str() {
        "ra" => Ok(Method::Ra),
        "dhcpv6" => Ok(Method::Dhcpv6),
        "ipv6" => Ok(Method::Ipv6),
        _ => Err(format!("{text:?} is not \"ra\", \"dhcpv6\" or \"ipv6\"")),
    }
}

/// `"link-layer"`, `"anonymous"` or `"random"`, either case (C16).
pub(crate) fn identity(text: &str) -> Result<Dhcpv6Identity, String> {
    match text.to_ascii_lowercase().as_str() {
        "link-layer" => Ok(Dhcpv6Identity::LinkLayer),
        "anonymous" => Ok(Dhcpv6Identity::Anonymous),
        "random" => Ok(Dhcpv6Identity::Random),
        _ => Err(format!(
            "{text:?} is not \"link-layer\", \"anonymous\" or \"random\""
        )),
    }
}

/// `dhcpv6_duid`: hexadecimal digits; the length is checked with the
/// entry (C16).
pub(crate) fn duid(text: &str) -> Result<Dhcpv6Identity, String> {
    hex(text)
        .map(Dhcpv6Identity::Duid)
        .ok_or_else(|| format!("{text:?} is not an even number of hexadecimal digits"))
}

/// Hexadecimal digits of `bytes`, for rendering (O8).
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
