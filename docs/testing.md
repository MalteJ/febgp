# Testing

FeBGP uses integration tests with GoBGP to verify BGP protocol compliance.

## Prerequisites

- Linux (for network namespace support)
- Root privileges (for creating network namespaces)
- GoBGP binaries (automatically downloaded by Makefile)

## Running Tests

```sh
make test
```

This will:
1. Download GoBGP binaries if not present
2. Build the project
3. Run integration tests with sudo
4. Clean up network namespaces

## Test Structure

### `gobgp_to_gobgp`

Baseline test that verifies two GoBGP instances can:
- Establish a BGP session using IPv6 link-local addresses
- Exchange IPv6 prefixes

This confirms the test infrastructure works correctly.

### `febgp_to_gobgp`

Tests FeBGP against GoBGP:
- FeBGP connects to GoBGP using IPv6 link-local address
- Verifies session reaches ESTABLISHED state
- Confirms the session is held for the expected duration

## Test Infrastructure

Tests use Linux network namespaces to create isolated network environments:

```
┌─────────────────┐     veth pair      ┌─────────────────┐
│  febgp_test_r1  │◄──────────────────►│  febgp_test_r2  │
│                 │    eth0 <-> eth0   │                 │
│  FeBGP / GoBGP  │                    │     GoBGP       │
└─────────────────┘                    └─────────────────┘
```

### Network Namespace Utilities

Located in `tests-integration/src/common/`:

- `netns.rs` - Create/delete namespaces, create veth pairs
- `gobgp.rs` - Start GoBGP instances, query state via CLI

## Manual Testing

### Clean up namespaces

```sh
make clean
```

### Download GoBGP only

```sh
make tools
```

### Run specific test

```sh
sudo cargo test -p tests-integration --test febgp_to_gobgp -- --nocapture
```

## Adding New Tests

1. Create a new test file in `tests-integration/src/`
2. Add it to `tests-integration/Cargo.toml`:

```toml
[[test]]
name = "my_new_test"
path = "src/my_new_test.rs"
harness = true
```

3. Use the common utilities:

```rust
mod common;

use common::netns::{NetNs, create_veth_pair};
use common::gobgp::{GobgpConfig, GobgpInstance};

#[test]
fn test_something() {
    // Check for root
    if unsafe { libc::geteuid() != 0 } {
        eprintln!("Skipping: requires root");
        return;
    }

    // Create namespaces
    let ns1 = NetNs::new("test_ns1").unwrap();
    let ns2 = NetNs::new("test_ns2").unwrap();

    // Create veth pair
    create_veth_pair(&ns1, "eth0", &ns2, "eth0").unwrap();

    // ... test logic ...

    // Namespaces are cleaned up automatically on drop
}
```

## Troubleshooting

### Tests fail with permission errors

Run with sudo:
```sh
sudo cargo test -p tests-integration
```

Or use the Makefile which handles sudo:
```sh
make test
```

### Leftover namespaces

If tests are interrupted, namespaces may remain:
```sh
sudo ip netns del febgp_test_r1
sudo ip netns del febgp_test_r2
```

Or use:
```sh
make clean
```

### GoBGP not found

Ensure GoBGP is downloaded:
```sh
make tools
ls tools/
# Should show: gobgp  gobgpd  ...
```
