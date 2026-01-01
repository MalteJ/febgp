# FeBGP

A BGP daemon written in Rust, designed for BGP unnumbered deployments.

## Features

- BGP-4 protocol (RFC 4271)
- BGP unnumbered with IPv6 link-local peering
- Auto-detection of remote ASN from peer's OPEN message
- 4-octet ASN capability (RFC 6793)
- Multiprotocol extensions for IPv6 (RFC 4760)
- FIB installation via netlink
- gRPC API for status and route queries
- TOML configuration

## Building

```sh
cargo build --release
```

## Usage

### Run the daemon

```sh
# Uses defaults: /etc/febgp/config.toml and /var/lib/febgp/grpc.sock
febgp daemon

# Or with custom paths
febgp daemon --config /path/to/config.toml --socket /path/to/grpc.sock

# Install received routes into Linux routing table
febgp daemon --install-routes
```

### Query status

```sh
febgp status
```

### Query routes

```sh
febgp routes
```

## Configuration

Create a `config.toml`:

```toml
asn = 65001
router_id = "1.1.1.1"
prefixes = ["2001:db8::/32"]

# Optional: customize timers
hold_time = 9           # default: 9s (keepalive = 3s)
connect_retry_time = 30 # default: 30s

# BGP unnumbered - just specify the interface
[[peer]]
interface = "eth0"

# Or with explicit peer address
[[peer]]
interface = "eth1"
address = "fe80::1"
```

See [docs/configuration.md](docs/configuration.md) for full configuration reference.

## Testing

Integration tests use GoBGP and require root privileges for network namespace setup:

```sh
make test
```

See [docs/testing.md](docs/testing.md) for details.

## Project Structure

```
src/
  main.rs         # CLI (daemon, status, routes subcommands)
  lib.rs          # Library exports
  config.rs       # TOML configuration parsing
  api/            # gRPC server and client
  bgp/            # BGP protocol implementation
proto/
  febgp.proto     # gRPC API definition
tests-integration/
  src/            # Integration tests against GoBGP
```

## License

Licensed under [Apache-2.0](LICENSE).
