# Configuration Reference

FeBGP uses TOML for configuration.

## Example

```toml
asn = 65001
router_id = "1.1.1.1"
prefixes = ["2001:db8::/32", "2001:db8:1::/48"]

# Optional: customize timers (defaults shown)
hold_time = 9              # hold time in seconds
connect_retry_time = 30    # connect retry in seconds

# Optional: install routes into Linux routing table
install_routes = false

[[peer]]
interface = "eth0"

[[peer]]
interface = "eth1"
remote_asn = 65002
address = "fe80::1"
```

## Global Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `asn` | integer | yes | - | Local Autonomous System Number (1-4294967295) |
| `router_id` | string | yes | - | BGP Router ID in IPv4 address format |
| `prefixes` | array | no | `[]` | IPv6 prefixes to announce |
| `hold_time` | integer | no | `9` | BGP hold time in seconds (keepalive = hold_time / 3) |
| `connect_retry_time` | integer | no | `30` | Connect retry timer in seconds |
| `install_routes` | boolean | no | `false` | Install received routes into Linux routing table via netlink |
| `ipv4_unicast` | boolean | no | `false` | Enable IPv4 unicast address family |
| `ipv6_unicast` | boolean | no | `true` | Enable IPv6 unicast address family |

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
febgp daemon [--config <path>] [--socket <path>] [--install-routes]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | /etc/febgp/config.toml | Path to configuration file |
| `--socket` | /var/lib/febgp/grpc.sock | Unix socket path for gRPC API |
| `--install-routes` | disabled | Install received routes into Linux routing table via netlink (can also be set via `install_routes` in config) |

### Status

```sh
febgp status [--socket <path>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--socket`, `-s` | /var/lib/febgp/grpc.sock | Unix socket path |

### Routes

```sh
febgp routes [--socket <path>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--socket`, `-s` | /var/lib/febgp/grpc.sock | Unix socket path |
