//! Neighbor Discovery for BGP Unnumbered
//!
//! Implements ICMPv6 Router Advertisement sending and receiving for automatic
//! peer discovery on point-to-point links.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};

use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// ICMPv6 type for Router Advertisement
const ICMPV6_TYPE_RA: u8 = 134;

/// All-nodes multicast address (ff02::1)
const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// RA sending interval in seconds
const RA_INTERVAL_SECS: u64 = 5;

/// Router lifetime in seconds (included in RA)
const ROUTER_LIFETIME: u16 = 1800;

/// Events emitted by neighbor discovery
#[derive(Debug, Clone)]
pub enum NeighborEvent {
    /// A new neighbor was discovered on an interface
    Discovered {
        interface: String,
        interface_index: u32,
        address: Ipv6Addr,
    },
}

/// Neighbor discovery actor for a single interface
pub struct NeighborDiscovery {
    interface: String,
    interface_index: u32,
    link_local: Ipv6Addr,
    mac_addr: [u8; 6],
    socket: Socket,
    event_tx: mpsc::Sender<NeighborEvent>,
    discovered: HashSet<Ipv6Addr>,
}

impl NeighborDiscovery {
    /// Create a new neighbor discovery instance for an interface.
    pub fn new(interface: &str, event_tx: mpsc::Sender<NeighborEvent>) -> io::Result<Self> {
        let interface_index = if_nametoindex(interface)
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?;

        let link_local = get_interface_link_local(interface)?;
        let mac_addr = get_interface_mac(interface)?;

        info!(
            interface = interface,
            link_local = %link_local,
            mac = ?mac_addr,
            "Neighbor discovery initialized"
        );

        // Create ICMPv6 raw socket
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;

        // Bind to interface
        socket.bind_device(Some(interface.as_bytes()))?;

        // Set hop limit to 255 (required by RFC 4861 for NDP)
        socket.set_unicast_hops_v6(255)?;
        socket.set_multicast_hops_v6(255)?;

        // Set non-blocking for async
        socket.set_nonblocking(true)?;

        Ok(Self {
            interface: interface.to_string(),
            interface_index,
            link_local,
            mac_addr,
            socket,
            event_tx,
            discovered: HashSet::new(),
        })
    }

    /// Run the neighbor discovery loop.
    ///
    /// Sends periodic Router Advertisements and listens for RAs from peers.
    /// Exits after discovering a neighbor (point-to-point model).
    pub async fn run(mut self) {
        info!(
            interface = self.interface,
            "Starting neighbor discovery on {}",
            self.interface
        );

        let mut ra_interval = interval(Duration::from_secs(RA_INTERVAL_SECS));
        let mut recv_buf = [0u8; 1500];

        loop {
            tokio::select! {
                _ = ra_interval.tick() => {
                    if let Err(e) = self.send_router_advertisement() {
                        error!(
                            interface = self.interface,
                            error = %e,
                            "Failed to send RA: {}",
                            e
                        );
                    }
                }
                result = Self::receive_packet_static(&self.socket, &mut recv_buf) => {
                    match result {
                        Ok(Some((src_addr, len))) => {
                            if let Some(neighbor_addr) = self.process_received_ra(src_addr, &recv_buf[..len]) {
                                // Neighbor discovered - emit event
                                info!(
                                    interface = self.interface,
                                    neighbor = %neighbor_addr,
                                    "Discovered neighbor {} on {}",
                                    neighbor_addr,
                                    self.interface
                                );

                                let event = NeighborEvent::Discovered {
                                    interface: self.interface.clone(),
                                    interface_index: self.interface_index,
                                    address: neighbor_addr,
                                };

                                if let Err(e) = self.event_tx.send(event).await {
                                    error!(
                                        interface = self.interface,
                                        error = %e,
                                        "Failed to send neighbor event: {}",
                                        e
                                    );
                                }

                                // Continue sending RAs so peer can also discover us
                                // but don't exit - keep running to maintain presence
                            }
                        }
                        Ok(None) => {
                            // No packet available (EAGAIN/EWOULDBLOCK)
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Err(e) => {
                            warn!(
                                interface = self.interface,
                                error = %e,
                                "Error receiving packet: {}",
                                e
                            );
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }

    /// Send a Router Advertisement.
    fn send_router_advertisement(&self) -> io::Result<()> {
        let ra_packet = build_router_advertisement(&self.link_local, &self.mac_addr);

        let dest = SocketAddrV6::new(ALL_NODES_MULTICAST, 0, 0, self.interface_index);
        let dest_addr = socket2::SockAddr::from(dest);

        self.socket.send_to(&ra_packet, &dest_addr)?;

        debug!(
            interface = self.interface,
            dest = %ALL_NODES_MULTICAST,
            "Sent Router Advertisement"
        );

        Ok(())
    }

    /// Receive a packet from the socket.
    ///
    /// Returns Ok(Some((src_addr, len))) if a packet was received,
    /// Ok(None) if no packet is available (non-blocking),
    /// or Err on error.
    async fn receive_packet_static(socket: &Socket, buf: &mut [u8]) -> io::Result<Option<(Ipv6Addr, usize)>> {
        // Use std recv_from since socket2 doesn't have async
        match socket.recv_from(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>, buf.len())
        }) {
            Ok((len, src_addr)) => {
                // Extract IPv6 address from sockaddr
                if let Some(addr) = src_addr.as_socket_ipv6() {
                    Ok(Some((*addr.ip(), len)))
                } else {
                    Ok(None)
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Process a received packet and check if it's an RA from a peer.
    ///
    /// Returns Some(address) if a new neighbor was discovered.
    fn process_received_ra(&mut self, src_addr: Ipv6Addr, data: &[u8]) -> Option<Ipv6Addr> {
        // Check minimum RA size (type + code + checksum + fields = 16 bytes)
        if data.len() < 16 {
            return None;
        }

        // Check ICMPv6 type
        let icmp_type = data[0];
        if icmp_type != ICMPV6_TYPE_RA {
            return None;
        }

        // Ignore our own RAs
        if src_addr == self.link_local {
            return None;
        }

        // Must be a link-local address
        if !is_link_local(&src_addr) {
            debug!(
                interface = self.interface,
                src = %src_addr,
                "Ignoring RA from non-link-local address"
            );
            return None;
        }

        // Check if already discovered
        if self.discovered.contains(&src_addr) {
            return None;
        }

        // New neighbor discovered
        self.discovered.insert(src_addr);
        Some(src_addr)
    }
}

/// Get the link-local IPv6 address for an interface.
pub fn get_interface_link_local(interface: &str) -> io::Result<Ipv6Addr> {
    let addrs = getifaddrs().map_err(io::Error::other)?;

    for addr in addrs {
        if addr.interface_name != interface {
            continue;
        }

        if let Some(sockaddr) = addr.address {
            if let Some(sin6) = sockaddr.as_sockaddr_in6() {
                let ip = sin6.ip();
                if is_link_local(&ip) {
                    return Ok(ip);
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("No link-local address found for interface {}", interface),
    ))
}

/// Get the MAC address for an interface.
fn get_interface_mac(interface: &str) -> io::Result<[u8; 6]> {
    let addrs = getifaddrs().map_err(io::Error::other)?;

    for addr in addrs {
        if addr.interface_name != interface {
            continue;
        }

        if let Some(sockaddr) = addr.address {
            if let Some(link_addr) = sockaddr.as_link_addr() {
                if let Some(mac) = link_addr.addr() {
                    if mac.len() == 6 {
                        let mut result = [0u8; 6];
                        result.copy_from_slice(&mac);
                        return Ok(result);
                    }
                }
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("No MAC address found for interface {}", interface),
    ))
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_link_local(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// Build a Router Advertisement packet.
///
/// Format (RFC 4861):
/// - Type: 134
/// - Code: 0
/// - Checksum: computed
/// - Cur Hop Limit: 64
/// - Flags: 0
/// - Router Lifetime: 1800
/// - Reachable Time: 0
/// - Retrans Timer: 0
/// - Options: Source Link-Layer Address
fn build_router_advertisement(src_addr: &Ipv6Addr, src_mac: &[u8; 6]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(24);

    // ICMPv6 header
    packet.push(ICMPV6_TYPE_RA); // Type: Router Advertisement
    packet.push(0); // Code: 0
    packet.push(0); // Checksum (placeholder)
    packet.push(0); // Checksum (placeholder)

    // RA fields
    packet.push(64); // Cur Hop Limit
    packet.push(0); // Flags (M=0, O=0)
    packet.extend_from_slice(&ROUTER_LIFETIME.to_be_bytes()); // Router Lifetime
    packet.extend_from_slice(&0u32.to_be_bytes()); // Reachable Time
    packet.extend_from_slice(&0u32.to_be_bytes()); // Retrans Timer

    // Source Link-Layer Address option
    packet.push(1); // Type: Source Link-Layer Address
    packet.push(1); // Length: 1 (in units of 8 bytes)
    packet.extend_from_slice(src_mac);

    // Compute checksum
    let checksum = compute_icmpv6_checksum(src_addr, &ALL_NODES_MULTICAST, &packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    packet
}

/// Compute ICMPv6 checksum.
///
/// The checksum is computed over a pseudo-header plus the ICMPv6 data.
fn compute_icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header: source address (16 bytes)
    for segment in src.segments() {
        sum += segment as u32;
    }

    // Pseudo-header: destination address (16 bytes)
    for segment in dst.segments() {
        sum += segment as u32;
    }

    // Pseudo-header: ICMPv6 length (4 bytes, upper layer length)
    sum += icmp_data.len() as u32;

    // Pseudo-header: next header (1 byte, padded to 4 bytes)
    sum += 58u32; // ICMPv6 = 58

    // ICMPv6 data (with checksum field zeroed - it's already 0 in our data)
    let mut i = 0;
    while i < icmp_data.len() {
        let word = if i + 1 < icmp_data.len() {
            ((icmp_data[i] as u16) << 8) | (icmp_data[i + 1] as u16)
        } else {
            (icmp_data[i] as u16) << 8
        };
        sum += word as u32;
        i += 2;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // One's complement
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_link_local() {
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_link_local(&"fe80::dead:beef:1234:5678".parse().unwrap()));
        assert!(is_link_local(&"fe80:1::1".parse().unwrap()));
        assert!(is_link_local(&"febf::1".parse().unwrap())); // fe80::/10 includes up to febf::
        assert!(!is_link_local(&"fec0::1".parse().unwrap())); // Outside fe80::/10
        assert!(!is_link_local(&"2001:db8::1".parse().unwrap()));
        assert!(!is_link_local(&"::1".parse().unwrap()));
        assert!(!is_link_local(&"ff02::1".parse().unwrap())); // Multicast
    }

    #[test]
    fn test_build_router_advertisement() {
        let src = "fe80::1".parse().unwrap();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ra = build_router_advertisement(&src, &mac);

        // Check basic structure
        assert_eq!(ra[0], ICMPV6_TYPE_RA); // Type
        assert_eq!(ra[1], 0); // Code
        assert_eq!(ra[4], 64); // Cur Hop Limit
        assert_eq!(ra[5], 0); // Flags

        // Check router lifetime (bytes 6-7)
        let lifetime = u16::from_be_bytes([ra[6], ra[7]]);
        assert_eq!(lifetime, ROUTER_LIFETIME);

        // Check reachable time (bytes 8-11) is 0
        let reachable = u32::from_be_bytes([ra[8], ra[9], ra[10], ra[11]]);
        assert_eq!(reachable, 0);

        // Check retrans timer (bytes 12-15) is 0
        let retrans = u32::from_be_bytes([ra[12], ra[13], ra[14], ra[15]]);
        assert_eq!(retrans, 0);

        // Check Source Link-Layer Address option
        assert_eq!(ra[16], 1); // Type
        assert_eq!(ra[17], 1); // Length
        assert_eq!(&ra[18..24], &mac);

        // Total length should be 24 bytes
        assert_eq!(ra.len(), 24);
    }

    #[test]
    fn test_build_router_advertisement_checksum_nonzero() {
        let src = "fe80::1".parse().unwrap();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ra = build_router_advertisement(&src, &mac);

        // Checksum should be non-zero (bytes 2-3)
        let checksum = u16::from_be_bytes([ra[2], ra[3]]);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_compute_icmpv6_checksum_verifiable() {
        // Build an RA and verify the checksum is valid by recomputing
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ra = build_router_advertisement(&src, &mac);

        // To verify: compute checksum over the packet (including the checksum field)
        // Result should be 0xffff (or fold to 0) if checksum is correct
        let mut verify_sum: u32 = 0;

        // Pseudo-header
        for segment in src.segments() {
            verify_sum += segment as u32;
        }
        for segment in ALL_NODES_MULTICAST.segments() {
            verify_sum += segment as u32;
        }
        verify_sum += ra.len() as u32;
        verify_sum += 58u32;

        // ICMPv6 data including checksum
        let mut i = 0;
        while i < ra.len() {
            let word = if i + 1 < ra.len() {
                ((ra[i] as u16) << 8) | (ra[i + 1] as u16)
            } else {
                (ra[i] as u16) << 8
            };
            verify_sum += word as u32;
            i += 2;
        }

        // Fold
        while verify_sum >> 16 != 0 {
            verify_sum = (verify_sum & 0xffff) + (verify_sum >> 16);
        }

        // Valid checksum should result in 0xffff
        assert_eq!(verify_sum as u16, 0xffff);
    }

    #[test]
    fn test_process_received_ra_valid() {
        let own_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut discovered = HashSet::new();

        // Build a valid RA from a different address
        let peer_addr: Ipv6Addr = "fe80::2".parse().unwrap();
        let peer_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ra = build_router_advertisement(&peer_addr, &peer_mac);

        // Process should return the peer address
        let result = process_ra_packet(peer_addr, &ra, own_addr, &mut discovered);
        assert_eq!(result, Some(peer_addr));
    }

    #[test]
    fn test_process_received_ra_ignores_own_address() {
        let own_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let own_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut discovered = HashSet::new();

        // Build an RA from our own address
        let ra = build_router_advertisement(&own_addr, &own_mac);

        // Should be ignored
        let result = process_ra_packet(own_addr, &ra, own_addr, &mut discovered);
        assert_eq!(result, None);
    }

    #[test]
    fn test_process_received_ra_ignores_non_link_local() {
        let own_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut discovered = HashSet::new();

        // Build an RA from a global address
        let global_addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ra = build_router_advertisement(&global_addr, &mac);

        // Should be ignored
        let result = process_ra_packet(global_addr, &ra, own_addr, &mut discovered);
        assert_eq!(result, None);
    }

    #[test]
    fn test_process_received_ra_ignores_duplicates() {
        let own_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut discovered = HashSet::new();

        let peer_addr: Ipv6Addr = "fe80::2".parse().unwrap();
        let peer_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ra = build_router_advertisement(&peer_addr, &peer_mac);

        // First time should succeed
        let result1 = process_ra_packet(peer_addr, &ra, own_addr, &mut discovered);
        assert_eq!(result1, Some(peer_addr));

        // Second time should be ignored (duplicate)
        let result2 = process_ra_packet(peer_addr, &ra, own_addr, &mut discovered);
        assert_eq!(result2, None);
    }

    #[test]
    fn test_process_received_ra_ignores_non_ra() {
        let own_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut discovered = HashSet::new();

        let peer_addr: Ipv6Addr = "fe80::2".parse().unwrap();

        // Build a packet that's not an RA (e.g., Router Solicitation = type 133)
        let rs = vec![133u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let result = process_ra_packet(peer_addr, &rs, own_addr, &mut discovered);
        assert_eq!(result, None);
    }

    #[test]
    fn test_process_received_ra_ignores_too_short() {
        let own_addr: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut discovered = HashSet::new();

        let peer_addr: Ipv6Addr = "fe80::2".parse().unwrap();

        // Packet too short (less than 16 bytes)
        let short_packet = vec![ICMPV6_TYPE_RA, 0, 0, 0, 0, 0, 0, 0];

        let result = process_ra_packet(peer_addr, &short_packet, own_addr, &mut discovered);
        assert_eq!(result, None);
    }

    /// Test helper that mimics process_received_ra logic without needing NeighborDiscovery
    fn process_ra_packet(
        src_addr: Ipv6Addr,
        data: &[u8],
        own_addr: Ipv6Addr,
        discovered: &mut HashSet<Ipv6Addr>,
    ) -> Option<Ipv6Addr> {
        // Check minimum RA size
        if data.len() < 16 {
            return None;
        }

        // Check ICMPv6 type
        let icmp_type = data[0];
        if icmp_type != ICMPV6_TYPE_RA {
            return None;
        }

        // Ignore our own RAs
        if src_addr == own_addr {
            return None;
        }

        // Must be a link-local address
        if !is_link_local(&src_addr) {
            return None;
        }

        // Check if already discovered
        if discovered.contains(&src_addr) {
            return None;
        }

        // New neighbor discovered
        discovered.insert(src_addr);
        Some(src_addr)
    }
}
