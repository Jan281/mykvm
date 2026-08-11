//! The UDP heartbeat peers use to find each other, and the description of a
//! peer that rides along with it.
//!
//! Discovery is deliberately separate from the transport: it is a broadcast
//! that says "I exist, here is my certificate and my screens", after which all
//! real traffic goes over QUIC (see [`crate::transport`]).

use std::net::{Ipv4Addr, UdpSocket};

use serde::{Deserialize, Serialize};

/// Default UDP port for the discovery heartbeat.
///
/// A peer that finds it taken drifts upward, which is why senders aim at a span
/// of consecutive ports rather than this one alone.
pub const DISCOVERY_PORT: u16 = 47833;

/// Marker in every discovery datagram. A packet without it is not ours.
pub const DISCOVERY_PROTOCOL: &str = "mykvm.discovery.v1";

/// A peer that wanted the discovery port but found it taken drifts upward. We
/// aim discovery traffic at this many consecutive ports starting from the
/// configured base, so two peers that landed on different ports still reach
/// each other.
pub const DISCOVERY_PORT_SPAN: u16 = 8;

pub const TRANSPORT_PORT_MIN: u16 = 1024;
pub const TRANSPORT_PORT_MAX: u16 = 65_535;

pub fn normalize_transport_port(port: u16) -> u16 {
    port.clamp(TRANSPORT_PORT_MIN, TRANSPORT_PORT_MAX)
}

pub fn preferred_quic_port(discovery_port: u16) -> u16 {
    discovery_port
        .saturating_add(1)
        .clamp(TRANSPORT_PORT_MIN, TRANSPORT_PORT_MAX)
}

pub fn normalize_quic_port(discovery_port: u16, quic_port: u16) -> u16 {
    if quic_port == 0 {
        preferred_quic_port(discovery_port)
    } else {
        normalize_transport_port(quic_port)
    }
}

/// The consecutive discovery ports we aim traffic at, starting from `base`.
pub fn discovery_target_ports(base: u16) -> Vec<u16> {
    let base = normalize_transport_port(base);
    let mut ports = Vec::new();
    for offset in 0..DISCOVERY_PORT_SPAN {
        let Some(port) = base.checked_add(offset) else {
            break;
        };
        if port > TRANSPORT_PORT_MAX {
            break;
        }
        ports.push(port);
    }
    ports
}

pub fn usable_discovery_ipv4(address: Ipv4Addr) -> bool {
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_link_local()
}

/// Asking the routing table which source address would reach the internet. No
/// packet is sent — connecting a UDP socket only picks a route.
fn default_route_ipv4_address() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let address = socket.local_addr().ok()?;
    match address.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(_) => None,
    }
}

/// Orders candidates so that addresses on a real subnet come before
/// point-to-point ones, and puts the default route first *within* that.
///
/// A VPN hands out a /32 on a tunnel interface and takes over the default
/// route, so asking the routing table alone yields an address that no peer on
/// the LAN can reach and a broadcast that vanishes into the tunnel. Since the
/// first address is what a peer announces as its own, that address has to be
/// one others can actually send to.
fn prefer_lan_addresses(
    candidates: &[(Ipv4Addr, bool)],
    default_route: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let collect = |wanted: bool| {
        let mut list: Vec<Ipv4Addr> = candidates
            .iter()
            .filter(|(_, has_subnet)| *has_subnet == wanted)
            .map(|(address, _)| *address)
            .collect();
        list.sort_by_key(Ipv4Addr::octets);
        list.dedup();
        list
    };

    let mut ordered: Vec<Ipv4Addr> = collect(true).into_iter().chain(collect(false)).collect();

    // The default route only earns the front spot if it is itself on a subnet;
    // a tunnel address stays wherever it landed.
    if let Some(default_ip) = default_route.filter(|ip| usable_discovery_ipv4(*ip)) {
        let on_subnet = candidates
            .iter()
            .any(|(address, has_subnet)| *address == default_ip && *has_subnet);
        if on_subnet {
            ordered.retain(|address| *address != default_ip);
            ordered.insert(0, default_ip);
        } else if !ordered.contains(&default_ip) {
            ordered.push(default_ip);
        }
    }

    ordered
}

/// Every usable local IPv4 address, the one peers should reach us on first.
pub fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    let mut candidates = Vec::new();

    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            if interface.is_loopback() {
                continue;
            }

            let if_addrs::IfAddr::V4(address) = interface.addr else {
                continue;
            };
            if usable_discovery_ipv4(address.ip) {
                // A /32 is a tunnel endpoint, not a subnet we can broadcast on.
                let has_subnet = address.netmask != Ipv4Addr::new(255, 255, 255, 255);
                candidates.push((address.ip, has_subnet));
            }
        }
    }

    prefer_lan_addresses(&candidates, default_route_ipv4_address())
}

/// Broadcast destinations for discovery, fanned out across the discovery port
/// span. Sending to the whole span — rather than a single port — lets us reach
/// peers that drifted onto a neighbouring port when their preferred port was
/// momentarily taken.
pub fn broadcast_addrs(base_port: u16) -> Vec<String> {
    broadcast_addrs_for_ips(base_port, &local_ipv4_addresses())
}

fn broadcast_addrs_for_ips(base_port: u16, local_ips: &[Ipv4Addr]) -> Vec<String> {
    let mut addresses = Vec::new();
    for port in discovery_target_ports(base_port) {
        addresses.push(format!("255.255.255.255:{port}"));
        for ip in local_ips {
            let [a, b, c, _] = ip.octets();
            addresses.push(format!("{a}.{b}.{c}.255:{port}"));
        }
    }

    addresses.sort();
    addresses.dedup();
    addresses
}

/// Every other host address in our local /24, used as a fallback when a network
/// drops broadcast traffic (common with Wi-Fi "AP/client isolation" and some
/// managed switches) but still forwards unicast between clients.
pub fn unicast_sweep_targets(port: u16) -> Vec<String> {
    unicast_sweep_targets_for_ips(port, &local_ipv4_addresses())
}

fn unicast_sweep_targets_for_ips(port: u16, local_ips: &[Ipv4Addr]) -> Vec<String> {
    let ports = discovery_target_ports(port);
    let mut targets = Vec::new();

    for ip in local_ips {
        let [a, b, c, self_host] = ip.octets();
        let subnet_prefix = format!("{a}.{b}.{c}");
        targets.extend(
            (1..=254u8)
                .filter(|host| *host != self_host)
                .flat_map(|host| {
                    let subnet_prefix = subnet_prefix.clone();
                    ports
                        .iter()
                        .map(move |port| format!("{subnet_prefix}.{host}:{port}"))
                }),
        );
    }

    targets.sort();
    targets.dedup();
    targets
}

/// How long a displayed pairing code stays valid.
pub const PAIRING_CODE_TTL_MS: u64 = 60_000;
/// Wrong codes tolerated before the challenge is thrown away.
pub const PAIRING_MAX_ATTEMPTS: u8 = 5;

/// A six-digit pairing code.
///
/// Shared so that every client shows a code of the same shape — the server
/// compares the typed string verbatim, so "0042" and "000042" are not the same
/// thing.
pub fn random_pairing_code() -> String {
    use ring::rand::SecureRandom;

    let mut bytes = [0_u8; 4];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        let fallback = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0);
        bytes = fallback.to_le_bytes()[..4].try_into().unwrap_or([0; 4]);
    }
    format!("{:06}", u32::from_le_bytes(bytes) % 1_000_000)
}

/// Folds any label into the id alphabet: lowercase ASCII alphanumerics, every
/// other character becoming a separator.
pub fn sanitize_id(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

/// The id a peer announces itself under, derived from its hostname and address.
///
/// Every client must build this the same way down to the character: the
/// receiving side addresses input packets by this exact string, and a packet
/// whose `targetDeviceId` does not match is dropped without a word.
pub fn local_peer_id(host: &str, ip: &str) -> String {
    let normalized = sanitize_id(&format!("{host}-{ip}"));

    if normalized.is_empty() {
        "peer-local".into()
    } else {
        format!("peer-{normalized}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vpn_tunnel_never_becomes_the_address_we_advertise() {
        // Exactly the observed setup: ProtonVPN hands out 10.2.0.2/32 and owns
        // the default route, while the reachable address is on Wi-Fi. Announcing
        // the tunnel made the phone unreachable for the desktop.
        let lan = Ipv4Addr::new(192, 168, 1, 124);
        let tunnel = Ipv4Addr::new(10, 2, 0, 2);
        let ordered = prefer_lan_addresses(&[(tunnel, false), (lan, true)], Some(tunnel));

        assert_eq!(ordered.first(), Some(&lan));
        // The tunnel is still worth announcing on, just never first.
        assert!(ordered.contains(&tunnel));
    }

    #[test]
    fn the_default_route_still_wins_when_it_is_a_normal_interface() {
        let wired = Ipv4Addr::new(192, 168, 0, 10);
        let wireless = Ipv4Addr::new(192, 168, 1, 124);
        let ordered =
            prefer_lan_addresses(&[(wireless, true), (wired, true)], Some(wireless));

        assert_eq!(ordered, vec![wireless, wired]);
    }

    #[test]
    fn peer_id_matches_the_shape_every_client_must_produce() {
        assert_eq!(
            local_peer_id("LDE-C1177D3", "192.168.0.117"),
            "peer-lde-c1177d3-192-168-0-117"
        );
        // Nothing usable in either part must still yield a legal id.
        assert_eq!(local_peer_id("", ""), "peer-local");
    }

    #[test]
    fn discovery_target_ports_spans_neighbouring_ports() {
        let ports = discovery_target_ports(DISCOVERY_PORT);
        assert_eq!(ports.len(), DISCOVERY_PORT_SPAN as usize);
        assert_eq!(ports[0], DISCOVERY_PORT);
        // A peer that drifted from 47833 to 47834 must still be a target.
        assert!(ports.contains(&(DISCOVERY_PORT + 1)));
        assert_eq!(
            *ports.last().unwrap(),
            DISCOVERY_PORT + DISCOVERY_PORT_SPAN - 1
        );
    }

    #[test]
    fn discovery_target_ports_clamp_near_max() {
        let ports = discovery_target_ports(TRANSPORT_PORT_MAX - 1);
        assert_eq!(ports, vec![TRANSPORT_PORT_MAX - 1, TRANSPORT_PORT_MAX]);
    }

    #[test]
    fn broadcast_addrs_reach_a_drifted_peer_port() {
        // The exact failure we are fixing: one peer on 47833 must still address a
        // peer that landed on 47834, via the global broadcast target.
        let addrs = broadcast_addrs(DISCOVERY_PORT);
        assert!(addrs.contains(&format!("255.255.255.255:{DISCOVERY_PORT}")));
        assert!(addrs.contains(&format!("255.255.255.255:{}", DISCOVERY_PORT + 1)));
    }

    #[test]
    fn broadcast_addrs_include_every_local_ipv4_subnet() {
        let addrs = broadcast_addrs_for_ips(
            DISCOVERY_PORT,
            &[Ipv4Addr::new(192, 168, 66, 106), Ipv4Addr::new(10, 0, 0, 4)],
        );

        assert!(addrs.contains(&format!("255.255.255.255:{DISCOVERY_PORT}")));
        assert!(addrs.contains(&format!("192.168.66.255:{DISCOVERY_PORT}")));
        assert!(addrs.contains(&format!("10.0.0.255:{DISCOVERY_PORT}")));
        assert!(addrs.contains(&format!("192.168.66.255:{}", DISCOVERY_PORT + 1)));
    }

    #[test]
    fn unicast_sweep_targets_cover_every_local_ipv4_subnet() {
        let targets = unicast_sweep_targets_for_ips(
            DISCOVERY_PORT,
            &[Ipv4Addr::new(192, 168, 66, 106), Ipv4Addr::new(10, 0, 0, 4)],
        );

        assert!(targets.contains(&format!("192.168.66.92:{DISCOVERY_PORT}")));
        assert!(targets.contains(&format!("10.0.0.1:{DISCOVERY_PORT}")));
        assert!(!targets.contains(&format!("192.168.66.106:{DISCOVERY_PORT}")));
        assert!(!targets.contains(&format!("10.0.0.4:{DISCOVERY_PORT}")));
    }
}

pub fn default_transport_port() -> u16 {
    DISCOVERY_PORT
}

pub fn default_protocol_version() -> u16 {
    crate::transport::PROTOCOL_VERSION
}

/// One peer as it describes itself on the network.
///
/// Every field is `pub` because this type crosses crate boundaries: the desktop
/// app builds it, the Android client builds it, and both read the other's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LanPeer {
    pub id: String,
    pub name: String,
    pub platform: String,
    #[serde(default)]
    pub machine_role: String,
    #[serde(default)]
    pub cluster_id: String,
    #[serde(default)]
    pub pairing_required: bool,
    pub host: String,
    pub ip: String,
    #[serde(default = "default_transport_port")]
    pub transport_port: u16,
    #[serde(default)]
    pub quic_port: u16,
    #[serde(default)]
    pub transport_public_key: String,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,
    pub screen_count: usize,
    #[serde(default)]
    pub input_ready: bool,
    #[serde(default)]
    pub upgrading: bool,
    #[serde(default)]
    pub screens: Vec<LanPeerScreen>,
    pub app_version: String,
    pub last_seen_ms: u64,
}

/// One screen of a peer, in that peer's own layout coordinates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LanPeerScreen {
    pub id: String,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub scale: f64,
    pub is_primary: bool,
}

/// A discovery datagram. `kind` is `"announce"`, `"probe"` or one of the
/// pairing exchanges; the pairing fields are absent unless that exchange is
/// under way.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryPacket {
    pub protocol: String,
    pub kind: String,
    pub peer: LanPeer,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_cluster_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_error: Option<String>,
}
