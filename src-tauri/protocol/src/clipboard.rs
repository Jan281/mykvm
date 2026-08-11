//! What a copy looks like on the wire.
//!
//! Sent over a QUIC stream rather than a datagram: clipboard content has no
//! useful size limit, and unlike a mouse move it must not be dropped.

use serde::{Deserialize, Serialize};

/// Marker in every clipboard packet.
pub const CLIPBOARD_PROTOCOL: &str = "mykvm.clipboard.v1";

/// An image copy, RGBA bytes in base64. Kept here so text-only clients still
/// decode a packet carrying one, rather than rejecting it as malformed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardImage {
    pub width: u32,
    pub height: u32,
    pub rgba_base64: String,
}

/// One representation of the copied content. Receivers pick what they can use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardFormat {
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ClipboardImage>,
}

/// A copy travelling between peers.
///
/// `signature` is a fingerprint of the content, not a cryptographic one: it is
/// how a receiver recognises its own copy coming back and declines to apply it
/// again. Authorisation rides on `cluster_id` and `pair_secret`, with
/// `origin_transport_public_key` as the stable identity — a peer id is derived
/// from the LAN address and drifts when that changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClipboardPacket {
    pub protocol: String,
    pub origin_id: String,
    #[serde(default)]
    pub origin_transport_public_key: String,
    #[serde(default)]
    pub target_id: String,
    #[serde(default)]
    pub cluster_id: String,
    #[serde(default)]
    pub pair_secret: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub formats: Vec<ClipboardFormat>,
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ClipboardImage>,
    pub sequence: u64,
}

impl ClipboardPacket {
    /// Builds a text copy. The signature matches what the desktop computes for
    /// the same content, so an echo is recognised on either side.
    pub fn text(
        text: String,
        origin_id: String,
        origin_transport_public_key: String,
        cluster_id: String,
        pair_secret: String,
        sequence: u64,
    ) -> Self {
        Self {
            protocol: CLIPBOARD_PROTOCOL.into(),
            origin_id,
            origin_transport_public_key,
            target_id: String::new(),
            cluster_id,
            pair_secret,
            signature: format!("text:{text}"),
            formats: vec![ClipboardFormat {
                kind: "plainText".into(),
                text: text.clone(),
                image: None,
            }],
            text,
            image: None,
            sequence,
        }
    }

    /// The text in this packet, preferring the explicit field and falling back
    /// to a plain-text format entry.
    pub fn plain_text(&self) -> Option<&str> {
        if !self.text.is_empty() {
            return Some(&self.text);
        }
        self.formats
            .iter()
            .find(|format| format.kind == "plainText" && !format.text.is_empty())
            .map(|format| format.text.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_readable_from_either_field() {
        let packet = ClipboardPacket::text(
            "hello".into(),
            "peer-a".into(),
            "key".into(),
            "cluster".into(),
            "secret".into(),
            1,
        );
        assert_eq!(packet.plain_text(), Some("hello"));
        assert_eq!(packet.signature, "text:hello");

        // A peer that only filled the formats list must still be understood.
        let mut older = packet.clone();
        older.text = String::new();
        assert_eq!(older.plain_text(), Some("hello"));
    }
}
