//! The UDP heartbeat peers use to find each other, and the description of a
//! peer that rides along with it.
//!
//! Discovery is deliberately separate from the transport: it is a broadcast
//! that says "I exist, here is my certificate and my screens", after which all
//! real traffic goes over QUIC (see [`crate::transport`]).

use serde::{Deserialize, Serialize};

/// Default UDP port for the discovery heartbeat.
///
/// A peer that finds it taken drifts upward, which is why senders aim at a span
/// of consecutive ports rather than this one alone.
pub const DISCOVERY_PORT: u16 = 47833;

/// Marker in every discovery datagram. A packet without it is not ours.
pub const DISCOVERY_PROTOCOL: &str = "mykvm.discovery.v1";

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
