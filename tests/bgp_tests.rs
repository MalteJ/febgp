use febgp::febgp::*;

#[test]
fn test_ipv4_prefix() {
    let prefix: Prefix = "192.168.1.0/24".parse().unwrap();
    assert_eq!(prefix, Prefix::V4("192.168.1.0".parse().unwrap(), 24));
    assert_eq!(prefix.to_string(), "192.168.1.0/24");
}

#[test]
fn test_ipv6_prefix() {
    let prefix: Prefix = "2001:db8::/32".parse().unwrap();
    assert_eq!(prefix, Prefix::V6("2001:db8::".parse().unwrap(), 32));
    assert_eq!(prefix.to_string(), "2001:db8::/32");
}

#[test]
fn test_invalid_prefix_format() {
    let result: Result<Prefix, _> = "invalid_prefix".parse();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Invalid prefix format. Expected <IP>/<prefix_length>");
}

#[test]
fn test_invalid_prefix_length_ipv4() {
    let result: Result<Prefix, _> = "192.168.1.0/33".parse();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "IPv4 prefix length cannot exceed 32");
}

#[test]
fn test_invalid_prefix_length_ipv6() {
    let result: Result<Prefix, _> = "2001:db8::/129".parse();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "IPv6 prefix length cannot exceed 128");
}
