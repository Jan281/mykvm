//! The envelope every input event travels in.
//!
//! Sent as a QUIC datagram, one per mouse move, so its size matters: the
//! credential fields are omitted once a peer is known, which drops roughly half
//! a kilobyte of static pairing block — mostly the base64 transport
//! certificate — off every packet.

use serde::{Deserialize, Serialize};

use crate::discovery::default_protocol_version;
use crate::input::InputEvent;

/// Marker in every input datagram; a packet without it is not input.
pub const INPUT_PROTOCOL: &str = "mykvm.input.v1";

fn str_ref_is_empty(value: &&str) -> bool {
    value.is_empty()
}

/// Borrowing serialization mirror of [`InputPacket`]: identical named
/// MessagePack bytes when every field is populated (guarded by a test), but
/// building one clones none of the ~0.8KB of credential strings.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputPacketRef<'a> {
    pub protocol: &'a str,
    pub target_device_id: &'a str,
    #[serde(skip_serializing_if = "str_ref_is_empty")]
    pub origin_device_id: &'a str,
    pub origin_port: u16,
    #[serde(skip_serializing_if = "str_ref_is_empty")]
    pub origin_transport_public_key: &'a str,
    pub origin_protocol_version: u16,
    #[serde(skip_serializing_if = "str_ref_is_empty")]
    pub cluster_id: &'a str,
    #[serde(skip_serializing_if = "str_ref_is_empty")]
    pub pair_secret: &'a str,
    pub event: &'a InputEvent,
}

/// The owning counterpart, used on the receiving side.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputPacket {
    pub protocol: String,
    #[serde(default)]
    pub target_device_id: String,
    #[serde(default)]
    pub origin_device_id: String,
    #[serde(default)]
    pub origin_port: u16,
    #[serde(default)]
    pub origin_transport_public_key: String,
    #[serde(default = "default_protocol_version")]
    pub origin_protocol_version: u16,
    #[serde(default)]
    pub cluster_id: String,
    #[serde(default)]
    pub pair_secret: String,
    pub event: InputEvent,
}
