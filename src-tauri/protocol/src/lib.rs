//! Everything MyKVM peers agree on: the events they exchange and the transport
//! that carries them.
//!
//! Split out of the desktop app so that a second client — the Android one —
//! speaks the exact same wire format instead of a hand-copied imitation of it.
//! `PROTOCOL_VERSION` lives in [`transport`] and is the single thing that
//! decides whether two peers will talk to each other.

pub mod discovery;
pub mod input;
pub mod packet;
pub mod transport;
