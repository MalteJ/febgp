# FeBGP

A BGP-4 daemon written in Rust.

## Structure

- `bgp/` - Protocol library for BGP message encoding/decoding and session management
- `febgpd/` - The BGP daemon binary
- `tests-integration/` - Integration tests using GoBGP

## Features

- BGP-4 protocol (RFC 4271)
- IPv6 link-local peering support
- 4-octet ASN capability (RFC 6793)
- Multiprotocol extensions (RFC 4760)

## Building

```sh
cargo build --release
```

## Running

```sh
./target/release/febgpd
```

## Testing

```sh
cargo test
```

Integration tests require GoBGP and root privileges for network namespace setup:

```sh
sudo make test-integration
```

## License

Licensed under [Apache-2.0](LICENSE).
