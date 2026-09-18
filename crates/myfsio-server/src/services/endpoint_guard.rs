pub(crate) async fn guard_external_endpoint_async(endpoint: &str) -> Result<(), String> {
    if let Err(reason) = guard_external_endpoint(endpoint) {
        return Err(reason.to_string());
    }
    let (host, port) = match parse_endpoint_authority(endpoint) {
        Some(v) => v,
        None => return Err("could not parse endpoint authority".to_string()),
    };
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let lookup = format!("{}:{}", host, port);
    let resolved = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host(lookup),
    )
    .await
    {
        Ok(Ok(it)) => it.collect::<Vec<_>>(),
        Ok(Err(e)) => {
            return Err(format!("DNS resolution failed for '{}': {}", host, e));
        }
        Err(_) => {
            return Err(format!("DNS resolution timed out for '{}'", host));
        }
    };
    if resolved.is_empty() {
        return Err(format!("hostname '{}' resolved to no addresses", host));
    }
    for sa in &resolved {
        if let Err(reason) = reject_internal_ip(sa.ip()) {
            return Err(format!(
                "hostname '{}' resolves to internal address {} ({})",
                host,
                sa.ip(),
                reason
            ));
        }
    }
    Ok(())
}

fn parse_endpoint_authority(endpoint: &str) -> Option<(String, u16)> {
    let trimmed = endpoint.trim();
    let scheme_idx = trimmed.find("://")?;
    let scheme = &trimmed[..scheme_idx];
    let after_scheme = &trimmed[scheme_idx + 3..];
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let default_port = if scheme.eq_ignore_ascii_case("https") {
        443
    } else {
        80
    };
    if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']')?;
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        let port = if let Some(p) = rest.strip_prefix(':') {
            p.parse::<u16>().ok().unwrap_or(default_port)
        } else {
            default_port
        };
        return Some((host.to_string(), port));
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = p.parse::<u16>() {
                return Some((h.to_string(), port));
            }
        }
    }
    Some((authority.to_string(), default_port))
}

pub(crate) fn guard_external_endpoint(endpoint: &str) -> Result<(), &'static str> {
    use std::net::IpAddr;
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err("empty endpoint");
    }
    let scheme_idx = trimmed
        .find("://")
        .ok_or("missing scheme (use http:// or https://)")?;
    let scheme = &trimmed[..scheme_idx];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err("only http and https schemes are allowed");
    }
    let after_scheme = &trimmed[scheme_idx + 3..];
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_part = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']').ok_or("malformed IPv6 host")?;
        &stripped[..end]
    } else {
        authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority)
            .split(':')
            .next()
            .unwrap_or(authority)
    };
    if host_part.is_empty() {
        return Err("missing host");
    }
    let lowered = host_part.to_ascii_lowercase();
    if matches!(
        lowered.as_str(),
        "localhost" | "ip6-localhost" | "ip6-loopback"
    ) {
        return Err("loopback hostnames are not allowed");
    }
    if lowered.ends_with(".localhost") || lowered.ends_with(".local") {
        return Err("loopback or mDNS hostnames are not allowed");
    }
    if let Ok(ip) = host_part.parse::<IpAddr>() {
        return reject_internal_ip(ip);
    }
    Ok(())
}

pub(crate) fn reject_internal_ip(ip: std::net::IpAddr) -> Result<(), &'static str> {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return Err("loopback addresses are not allowed");
            }
            if v4.is_link_local() {
                return Err("link-local addresses are not allowed");
            }
            if v4.is_unspecified() {
                return Err("unspecified addresses are not allowed");
            }
            if v4.is_broadcast() || v4.is_multicast() {
                return Err("broadcast/multicast addresses are not allowed");
            }
            if v4.is_private() {
                return Err("RFC1918 private addresses are not allowed");
            }
            let octets = v4.octets();
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return Err("CGNAT (100.64.0.0/10) addresses are not allowed");
            }
            if octets[0] == 0 {
                return Err("0.0.0.0/8 addresses are not allowed");
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Err("loopback addresses are not allowed");
            }
            if v6.is_unspecified() {
                return Err("unspecified addresses are not allowed");
            }
            if v6.is_multicast() {
                return Err("multicast addresses are not allowed");
            }
            let segs = v6.segments();
            if segs[0] & 0xffc0 == 0xfe80 {
                return Err("link-local addresses are not allowed");
            }
            if (segs[0] & 0xfe00) == 0xfc00 {
                return Err("unique-local (fc00::/7) addresses are not allowed");
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return reject_internal_ip(IpAddr::V4(v4));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::guard_external_endpoint;

    #[test]
    fn rejects_loopback() {
        assert!(guard_external_endpoint("http://127.0.0.1:9000").is_err());
        assert!(guard_external_endpoint("http://localhost:9000").is_err());
        assert!(guard_external_endpoint("http://[::1]:9000").is_err());
    }

    #[test]
    fn rejects_link_local_and_metadata() {
        assert!(guard_external_endpoint("http://169.254.169.254/").is_err());
        assert!(guard_external_endpoint("http://[fe80::1]/").is_err());
    }

    #[test]
    fn rejects_rfc1918() {
        assert!(guard_external_endpoint("http://10.0.0.5").is_err());
        assert!(guard_external_endpoint("http://10.255.255.255:9000").is_err());
        assert!(guard_external_endpoint("http://172.16.0.1").is_err());
        assert!(guard_external_endpoint("http://172.31.255.255:9000").is_err());
        assert!(guard_external_endpoint("http://192.168.1.10").is_err());
        assert!(guard_external_endpoint("http://192.168.255.1:9000").is_err());
    }

    #[test]
    fn rejects_cgnat() {
        assert!(guard_external_endpoint("http://100.64.0.1").is_err());
        assert!(guard_external_endpoint("http://100.127.255.255").is_err());
    }

    #[test]
    fn rejects_unique_local_v6() {
        assert!(guard_external_endpoint("http://[fc00::1]").is_err());
        assert!(guard_external_endpoint("http://[fdff::1]").is_err());
    }

    #[test]
    fn rejects_v4_mapped_internal_v6() {
        assert!(guard_external_endpoint("http://[::ffff:127.0.0.1]").is_err());
        assert!(guard_external_endpoint("http://[::ffff:10.0.0.1]").is_err());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        assert!(guard_external_endpoint("file:///etc/passwd").is_err());
        assert!(guard_external_endpoint("gopher://x").is_err());
    }

    #[test]
    fn allows_normal_remote() {
        assert!(guard_external_endpoint("https://s3.example.com").is_ok());
        assert!(guard_external_endpoint("http://192.0.2.10:9000").is_ok());
        assert!(guard_external_endpoint("http://172.32.0.1").is_ok());
        assert!(guard_external_endpoint("http://100.63.255.255").is_ok());
        assert!(guard_external_endpoint("http://100.128.0.1").is_ok());
    }
}
