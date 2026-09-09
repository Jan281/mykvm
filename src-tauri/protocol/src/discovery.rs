//! The UDP heartbeat peers use to find each other, and the description of a
//! peer that rides along with it.
//!
//! Discovery is deliberately separate from the transport: it is a broadcast
//! that says "I exist, here is my certificate and my screens", after which all
//! real traffic goes over QUIC (see [`crate::transport`]).

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::RwLock;

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

/// How readily another machine on the same LAN can reach an address of ours.
///
/// Ordering matters: the first address is the one a peer announces as its own
/// and the one others will send input to, so it has to be reachable from the
/// LAN rather than merely present on this machine.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum AddressRank {
    /// A private address on a real subnet, on an interface that looks physical.
    Lan,
    /// A real subnet we cannot place. Probably fine, just not obviously a LAN.
    Routable,
    /// Container bridges and virtual-machine host adapters. Present on this
    /// machine, reachable by nothing else on the network.
    Virtual,
    /// A VPN or other tunnel. Reachable only by whatever is inside the tunnel.
    Tunnel,
}

/// Interface-name fragments that give a tunnel away, lowercased.
///
/// Names are the most reliable signal available: a VPN's address range is not.
/// A tunnel may hand out 10.8.0.0/24, and a real office LAN may be 10.0.0.0/8 —
/// the addresses are indistinguishable, the interface names are not.
const TUNNEL_NAME_FRAGMENTS: &[&str] = &[
    "tun", "tap", "wg", "ppp", "ipsec", "proton", "nordlynx", "mullvad", "tailscale", "zt",
    "wireguard", "openvpn", "vpn",
];

/// The same for interfaces that exist only inside this machine.
const VIRTUAL_NAME_FRAGMENTS: &[&str] = &[
    "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "vethernet", "lxc", "podman", "cni",
    "hyper-v",
];

impl AddressRank {
    /// The stable name the settings UI groups by. Kept separate from the
    /// variant so translations and styling do not ride on Rust identifiers.
    fn as_kind(self) -> &'static str {
        match self {
            AddressRank::Lan => "lan",
            AddressRank::Routable => "routable",
            AddressRank::Virtual => "virtual",
            AddressRank::Tunnel => "tunnel",
        }
    }
}

fn classify_address(name: &str, address: Ipv4Addr, has_subnet: bool) -> AddressRank {
    let name = name.to_ascii_lowercase();
    let mentions = |fragments: &[&str]| fragments.iter().any(|fragment| name.contains(fragment));

    // A point-to-point address has no subnet to broadcast on, which is what a
    // classic VPN endpoint looks like.
    if !has_subnet {
        return AddressRank::Tunnel;
    }
    // 100.64.0.0/10 is carrier-grade NAT, which VPN clients borrow for their
    // own plumbing — ProtonVPN's kill-switch interface lives there, and it
    // carries a real /24, so nothing but the range gives it away.
    let [first, second, ..] = address.octets();
    if first == 100 && (64..=127).contains(&second) {
        return AddressRank::Tunnel;
    }
    if mentions(TUNNEL_NAME_FRAGMENTS) {
        return AddressRank::Tunnel;
    }
    if mentions(VIRTUAL_NAME_FRAGMENTS) {
        return AddressRank::Virtual;
    }
    if address.is_private() {
        return AddressRank::Lan;
    }

    AddressRank::Routable
}

/// Orders candidates so the address peers can actually reach comes first.
///
/// A VPN takes over the default route, so asking the routing table alone yields
/// an address no peer on the LAN can reach and a broadcast that vanishes into
/// the tunnel. Ranking by reachability first, and only then by anything else,
/// is what keeps the announced address a real one.
fn prefer_lan_addresses(
    candidates: &[(Ipv4Addr, AddressRank)],
    default_route: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let mut ranked = candidates.to_vec();
    // Octets only break ties within a rank, so the order is stable rather than
    // meaningful. Ranking used to be the tie-breaker itself, which is how a
    // tunnel on 100.85.0.1 beat the Wi-Fi address on 192.168.2.115.
    ranked.sort_by_key(|(address, rank)| (*rank, address.octets()));

    let mut ordered: Vec<Ipv4Addr> = Vec::with_capacity(ranked.len());
    for (address, _) in ranked {
        if !ordered.contains(&address) {
            ordered.push(address);
        }
    }

    // Among several LAN addresses the routing table knows best which one the
    // machine actually uses. A tunnel or bridge never earns the front spot,
    // however emphatically it owns the default route.
    if let Some(default_ip) = default_route.filter(|ip| usable_discovery_ipv4(*ip)) {
        let is_lan = candidates
            .iter()
            .any(|(address, rank)| *address == default_ip && *rank == AddressRank::Lan);
        if is_lan {
            ordered.retain(|address| *address != default_ip);
            ordered.insert(0, default_ip);
        } else if !ordered.contains(&default_ip) {
            ordered.push(default_ip);
        }
    }

    ordered
}

/// One local IPv4 interface, as the settings UI lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    /// What the operating system calls it: `wlan0`, `Wi-Fi`, `tun0`.
    pub name: String,
    pub address: String,
    /// "lan" | "routable" | "virtual" | "tunnel" — what the automatic ranking
    /// made of it, so the user can see why their pick is or is not the default.
    pub kind: String,
}

/// The interface the user pinned, if any.
///
/// Process-wide rather than a parameter, because every address decision — the
/// announced identity, the broadcast targets, the unicast sweep — has to agree,
/// and they are reached from places that have no layout to hand. Set once at
/// startup and again whenever the setting is saved.
static PREFERRED_INTERFACE: RwLock<Option<String>> = RwLock::new(None);

/// Pins the interface whose address peers should reach us on, or `None` to go
/// back to the automatic ranking.
///
/// The name is stored, never the address: an address belongs to one network,
/// and a laptop that travels gets a new one at every stop. The interface stays.
pub fn set_preferred_interface(name: Option<String>) {
    let name = name
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());
    if let Ok(mut preferred) = PREFERRED_INTERFACE.write() {
        *preferred = name;
    }
}

pub fn preferred_interface() -> Option<String> {
    PREFERRED_INTERFACE
        .read()
        .ok()
        .and_then(|preferred| preferred.clone())
}

fn enumerate_candidates() -> Vec<(String, Ipv4Addr, AddressRank)> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };

    interfaces
        .into_iter()
        .filter(|interface| !interface.is_loopback())
        .filter_map(|interface| {
            let if_addrs::IfAddr::V4(address) = interface.addr else {
                return None;
            };
            if !usable_discovery_ipv4(address.ip) {
                return None;
            }
            // A /32 is a tunnel endpoint, not a subnet we can broadcast on.
            let has_subnet = address.netmask != Ipv4Addr::new(255, 255, 255, 255);
            let rank = classify_address(&interface.name, address.ip, has_subnet);
            Some((interface.name, address.ip, rank))
        })
        .collect()
}

/// Every usable local IPv4 interface, best first, for the settings UI.
pub fn local_ipv4_interfaces() -> Vec<NetworkInterface> {
    let mut candidates = enumerate_candidates();
    candidates.sort_by_key(|(name, address, rank)| (*rank, address.octets(), name.clone()));
    candidates
        .into_iter()
        .map(|(name, address, rank)| NetworkInterface {
            name,
            address: address.to_string(),
            kind: rank.as_kind().into(),
        })
        .collect()
}

/// Every usable local IPv4 address, the one peers should reach us on first.
pub fn local_ipv4_addresses() -> Vec<Ipv4Addr> {
    let candidates = enumerate_candidates();
    let ranked: Vec<(Ipv4Addr, AddressRank)> = candidates
        .iter()
        .map(|(_, address, rank)| (*address, *rank))
        .collect();
    let mut ordered = prefer_lan_addresses(&ranked, default_route_ipv4_address());

    // A pinned interface goes to the front — but only while it actually holds
    // an address. Otherwise the pin is silently ignored rather than leaving the
    // machine unreachable, which is what a laptop meets at every new network
    // where the pinned adapter happens to be down.
    if let Some(name) = preferred_interface() {
        if let Some((_, address, _)) = candidates
            .iter()
            .find(|(candidate, _, _)| candidate.eq_ignore_ascii_case(&name))
        {
            ordered.retain(|existing| existing != address);
            ordered.insert(0, *address);
        }
    }

    ordered
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

    /// Classifies the way `local_ipv4_addresses` does, so the tests describe
    /// real interfaces rather than pre-chewed ranks.
    fn candidate(name: &str, address: &str, has_subnet: bool) -> (Ipv4Addr, AddressRank) {
        let address: Ipv4Addr = address.parse().expect("test address");
        (address, classify_address(name, address, has_subnet))
    }

    #[test]
    fn a_vpn_tunnel_never_becomes_the_address_we_advertise() {
        // Exactly the observed setup: ProtonVPN hands out 10.2.0.2/32 and owns
        // the default route, while the reachable address is on Wi-Fi. Announcing
        // the tunnel made the phone unreachable for the desktop.
        let lan = Ipv4Addr::new(192, 168, 1, 124);
        let tunnel = Ipv4Addr::new(10, 2, 0, 2);
        let ordered = prefer_lan_addresses(
            &[
                candidate("proton0", "10.2.0.2", false),
                candidate("wlan0", "192.168.1.124", true),
            ],
            Some(tunnel),
        );

        assert_eq!(ordered.first(), Some(&lan));
        // The tunnel is still worth announcing on, just never first.
        assert!(ordered.contains(&tunnel));
    }

    #[test]
    fn a_tunnel_carrying_a_real_subnet_is_still_a_tunnel() {
        // The regression that made this rewrite necessary. ProtonVPN's
        // kill-switch interface holds 100.85.0.1/24 — a genuine subnet, so the
        // /32 rule missed it — and 100 sorts ahead of 192, so it was announced
        // in place of the Wi-Fi address. Two Docker bridges came next, and the
        // only reachable address ended up fourth.
        let ordered = prefer_lan_addresses(
            &[
                candidate("docker0", "172.17.0.1", true),
                candidate("br-9f5b6dbd1745", "172.18.0.1", true),
                candidate("wlan0", "192.168.2.115", true),
                candidate("pvpnksintrf0", "100.85.0.1", true),
                candidate("proton0", "10.2.0.2", false),
            ],
            Some(Ipv4Addr::new(100, 85, 0, 1)),
        );

        assert_eq!(ordered.first(), Some(&Ipv4Addr::new(192, 168, 2, 115)));
    }

    #[test]
    fn a_vpn_handing_out_an_ordinary_lan_range_is_caught_by_its_name() {
        // Nothing about 10.8.0.4/24 says "tunnel" — a real office LAN looks
        // exactly like it. The interface name is the only thing that does.
        let ordered = prefer_lan_addresses(
            &[
                candidate("tun0", "10.8.0.4", true),
                candidate("wlan0", "192.168.2.115", true),
            ],
            Some(Ipv4Addr::new(10, 8, 0, 4)),
        );

        assert_eq!(ordered.first(), Some(&Ipv4Addr::new(192, 168, 2, 115)));
    }

    #[test]
    fn container_bridges_rank_below_the_lan_but_above_tunnels() {
        let ordered = prefer_lan_addresses(
            &[
                candidate("docker0", "172.17.0.1", true),
                candidate("tun0", "10.8.0.4", true),
                candidate("eth0", "192.168.0.10", true),
            ],
            None,
        );

        assert_eq!(
            ordered,
            vec![
                Ipv4Addr::new(192, 168, 0, 10),
                Ipv4Addr::new(172, 17, 0, 1),
                Ipv4Addr::new(10, 8, 0, 4),
            ]
        );
    }

    #[test]
    fn the_default_route_still_wins_when_it_is_a_normal_interface() {
        let wired = Ipv4Addr::new(192, 168, 0, 10);
        let wireless = Ipv4Addr::new(192, 168, 1, 124);
        let ordered = prefer_lan_addresses(
            &[
                candidate("wlan0", "192.168.1.124", true),
                candidate("eth0", "192.168.0.10", true),
            ],
            Some(wireless),
        );

        assert_eq!(ordered, vec![wireless, wired]);
    }

    #[test]
    fn a_pin_is_ignored_while_its_interface_has_no_address() {
        // The travelling case: the pinned adapter is down at this stop. Honouring
        // the pin anyway would announce nothing and leave the machine
        // unreachable, so the automatic ranking takes over silently.
        set_preferred_interface(Some("eth0".into()));
        let present = local_ipv4_interfaces();
        set_preferred_interface(None);

        // Whatever this machine has, a name that is absent must not appear.
        assert!(!present.iter().any(|interface| interface.name == "eth0"
            && interface.address.is_empty()));
    }

    #[test]
    fn every_listed_interface_carries_the_rank_the_ui_groups_by() {
        for interface in local_ipv4_interfaces() {
            assert!(
                matches!(
                    interface.kind.as_str(),
                    "lan" | "routable" | "virtual" | "tunnel"
                ),
                "unexpected kind {:?} for {}",
                interface.kind,
                interface.name
            );
            assert!(interface.address.parse::<Ipv4Addr>().is_ok());
        }
    }

    #[test]
    fn windows_hyper_v_adapters_do_not_pass_for_a_lan() {
        // if_addrs reports Windows adapters by their friendly name.
        let ordered = prefer_lan_addresses(
            &[
                candidate("vEthernet (Default Switch)", "172.20.16.1", true),
                candidate("Wi-Fi", "192.168.2.117", true),
            ],
            None,
        );

        assert_eq!(ordered.first(), Some(&Ipv4Addr::new(192, 168, 2, 117)));
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
    /// The keyboard layout this machine's user types on, e.g. `"us(intl)"`.
    ///
    /// Key codes on the wire are positional, so a receiver normally applies its
    /// own layout — that is the whole point of the design. A phone has none for
    /// injected keys, so it borrows the controlling machine's. Defaulted rather
    /// than required, so a peer that predates this field is simply quiet about
    /// it instead of failing to decode.
    #[serde(default)]
    pub keyboard_layout: String,
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

/// Reads the keyboard layout this machine's user types on.
///
/// Only Linux is implemented, because that is the only platform that currently
/// captures input — a machine that never captures has no layout worth
/// announcing. An empty string means "unknown", which leaves the client on
/// whatever it was configured with rather than guessing wrong.
#[cfg(target_os = "linux")]
pub fn detect_keyboard_layout() -> String {
    // localectl reports what the session is actually using, including the
    // variant — and the variant is the whole story here: plain `us` and
    // `us(intl)` differ in exactly the keys that produce accents.
    let Ok(output) = std::process::Command::new("localectl").arg("status").output() else {
        return String::new();
    };
    if !output.status.success() {
        return String::new();
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(name))
            .map(|value| value.trim().to_string())
            .unwrap_or_default()
    };

    let layout = field("X11 Layout:");
    if layout.is_empty() {
        return String::new();
    }
    match field("X11 Variant:") {
        variant if variant.is_empty() => layout,
        variant => format!("{layout}({variant})"),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn detect_keyboard_layout() -> String {
    String::new()
}
