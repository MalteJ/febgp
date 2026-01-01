# Configuration Reference

FeBGP uses TOML for configuration.

## Example

```toml
asn = 65001
router_id = "1.1.1.1"
prefixes = ["2001:db8::/32", "2001:db8:1::/48"]

[[peer]]
interface = "eth0"

[[peer]]
interface = "eth1"
remote_asn = 65002
address = "fe80::1"
```

## Global Settings

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `asn` | integer | yes | Local Autonomous System Number (1-4294967295) |
| `router_id` | string | yes | BGP Router ID in IPv4 address format |
| `prefixes` | array | no | IPv6 prefixes to announce |

## Peer Configuration

Each `[[peer]]` section defines a BGP neighbor.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `interface` | string | yes | Network interface for the peering session |
| `remote_asn` | integer | no | Remote AS number. If omitted, learned from peer's OPEN message (BGP unnumbered) |
| `address` | string | no | Peer's IPv6 link-local address. If omitted, uses neighbor discovery |

### BGP Unnumbered

For BGP unnumbered deployments, you only need to specify the interface:

```toml
[[peer]]
interface = "eth0"
```

FeBGP will:
1. Listen for incoming BGP connections on the interface
2. Accept connections from any peer
3. Learn the remote ASN from the peer's OPEN message

### Explicit Peering

For traditional BGP peering with known peer address:

```toml
[[peer]]
interface = "eth0"
remote_asn = 65002
address = "fe80::1"
```

## CLI Options

### Daemon

```sh
febgp daemon --config <path> [--grpc-port <port>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | required | Path to configuration file |
| `--grpc-port` | 50051 | gRPC API listen port |

### Status

```sh
febgp status [--address <addr>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--address`, `-a` | 127.0.0.1:50051 | gRPC server address |

### Routes

```sh
febgp routes [--address <addr>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--address`, `-a` | 127.0.0.1:50051 | gRPC server address |
