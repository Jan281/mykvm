//! The client side of MyKVM, reduced to what a phone needs.
//!
//! A phone is only ever controlled, never controlling: it announces itself, it
//! accepts input packets, and that is all. So this is deliberately not a port
//! of the desktop runtime — no capture, no layout, no edge logic. What it does
//! share, through `mykvm-protocol`, is every byte that goes on the wire.

use std::{
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use mykvm_protocol::{
    discovery::{
        broadcast_addrs, discovery_target_ports, local_ipv4_addresses, local_peer_id,
        preferred_quic_port, DiscoveryPacket, LanPeer, LanPeerScreen, DISCOVERY_PROTOCOL,
    },
    input::InputEvent,
    packet::{InputPacket, INPUT_PROTOCOL},
    transport::{self, TransportHandle, PROTOCOL_VERSION},
};

/// How often we shout into the network that we exist. Matches the desktop, and
/// the desktop's peer timeout is thirty times this — missing one is harmless.
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(3);
/// Read timeout on the discovery socket. Also the granularity at which the
/// thread notices it has been told to stop.
const DISCOVERY_POLL: Duration = Duration::from_millis(500);
/// Dropped rather than queued once the consumer falls this far behind. A phone
/// that cannot keep up should lag, not accumulate minutes of stale motion.
const MAX_QUEUED_EVENTS: usize = 512;

pub struct Config {
    /// What the user sees in the desktop's device list. Also feeds the peer id.
    pub device_name: String,
    pub discovery_port: u16,
    pub screen_width: i32,
    pub screen_height: i32,
    /// Where the QUIC identity is persisted. A new key every launch would break
    /// the desktop's certificate pinning and force a re-pair, so this must be
    /// somewhere durable — the app's files directory.
    pub identity_dir: PathBuf,
}

/// A running client. Dropping it does not stop the threads; call [`Client::stop`].
pub struct Client {
    transport: TransportHandle,
    events: Mutex<Receiver<InputEvent>>,
    running: Arc<AtomicBool>,
    device_id: String,
    quic_port: u16,
    peers_seen: Arc<Mutex<Vec<String>>>,
}

impl Client {
    /// Blocks until an input event arrives or the timeout expires.
    ///
    /// Kotlin drives this from one dedicated thread, which keeps the JNI
    /// surface free of callbacks into the JVM and the attach/detach dance they
    /// would require on every mouse move.
    pub fn poll(&self, timeout: Duration) -> Option<InputEvent> {
        let events = self.events.lock().ok()?;
        match events.recv_timeout(timeout) {
            Ok(event) => Some(event),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => None,
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        self.transport.shutdown();
    }

    /// A one-line summary for the setup screen and for the smoke test.
    pub fn status(&self) -> String {
        let peers = self
            .peers_seen
            .lock()
            .map(|peers| peers.join(", "))
            .unwrap_or_default();
        format!(
            "id={} quic={} peers=[{}]",
            self.device_id, self.quic_port, peers
        )
    }
}

pub fn start(config: Config) -> Result<Client, String> {
    let ip = local_ipv4_addresses()
        .first()
        .map(|address| address.to_string())
        .ok_or_else(|| "no usable IPv4 address; is Wi-Fi connected?".to_string())?;
    let device_id = local_peer_id(&config.device_name, &ip);

    let (event_tx, event_rx) = mpsc::channel();
    let queued = Arc::new(Mutex::new(0usize));

    let transport = start_transport(&config, &device_id, event_tx, Arc::clone(&queued))?;

    let running = Arc::new(AtomicBool::new(true));
    let peers_seen = Arc::new(Mutex::new(Vec::new()));

    spawn_discovery(
        &config,
        device_id.clone(),
        ip,
        transport.clone(),
        Arc::clone(&running),
        Arc::clone(&peers_seen),
    )?;

    let quic_port = transport.port();
    log::info!("[core] client up: id={device_id} quic={quic_port}");

    Ok(Client {
        transport,
        events: Mutex::new(event_rx),
        running,
        device_id,
        quic_port,
        peers_seen,
    })
}

/// Wires the QUIC transport so that every arriving datagram becomes an
/// [`InputEvent`] on the queue — or is dropped, loudly enough to debug.
fn start_transport(
    config: &Config,
    device_id: &str,
    events: Sender<InputEvent>,
    queued: Arc<Mutex<usize>>,
) -> Result<TransportHandle, String> {
    let expected_target = device_id.to_string();

    let on_datagram = Arc::new(move |payload: Vec<u8>, from: SocketAddr| {
        // The desktop warms a peer by sending an empty datagram; nothing to do.
        if payload.is_empty() {
            return;
        }

        let packet: InputPacket = match rmp_serde::from_slice(&payload) {
            Ok(packet) => packet,
            Err(error) => {
                log::debug!("[core] undecodable datagram from {from}: {error}");
                return;
            }
        };

        if packet.protocol != INPUT_PROTOCOL {
            log::debug!("[core] datagram from {from} is not input: {}", packet.protocol);
            return;
        }

        // An empty target means "whoever you are"; the desktop omits it only
        // before it has learned our id.
        if !packet.target_device_id.is_empty() && packet.target_device_id != expected_target {
            log::debug!(
                "[core] datagram addressed to {}, we are {expected_target}",
                packet.target_device_id
            );
            return;
        }

        if let Ok(mut depth) = queued.lock() {
            if *depth >= MAX_QUEUED_EVENTS {
                log::warn!("[core] event queue full; dropping input");
                return;
            }
            *depth += 1;
        }

        if events.send(packet.event).is_err() {
            log::debug!("[core] nobody is listening for input any more");
        }
    });

    // A phone neither sends nor answers clipboard and file streams yet.
    let on_stream = Arc::new(|_payload: Vec<u8>, from: SocketAddr| {
        log::debug!("[core] ignoring stream from {from}");
        false
    });

    transport::start(
        preferred_quic_port(config.discovery_port),
        config.identity_dir.clone(),
        on_datagram,
        on_stream,
    )
}

/// Binds the discovery socket, announcing on a timer and replying to anyone who
/// announces or probes.
///
/// The reply matters as much as the announce: a desktop that started first has
/// already sent its heartbeat into the void, and without an answer it would
/// wait a full cycle to notice us.
fn spawn_discovery(
    config: &Config,
    device_id: String,
    ip: String,
    transport: TransportHandle,
    running: Arc<AtomicBool>,
    peers_seen: Arc<Mutex<Vec<String>>>,
) -> Result<(), String> {
    let socket = bind_discovery_socket(config.discovery_port)?;
    socket
        .set_broadcast(true)
        .map_err(|error| format!("could not enable broadcast: {error}"))?;
    socket
        .set_read_timeout(Some(DISCOVERY_POLL))
        .map_err(|error| format!("could not set discovery timeout: {error}"))?;

    let base_port = config.discovery_port;
    let name = config.device_name.clone();
    let width = config.screen_width;
    let height = config.screen_height;

    thread::Builder::new()
        .name("mykvm-discovery".into())
        .spawn(move || {
            let mut buffer = vec![0u8; 64 * 1024];
            let mut last_announce = Instant::now() - ANNOUNCE_INTERVAL;

            while running.load(Ordering::Relaxed) {
                if last_announce.elapsed() >= ANNOUNCE_INTERVAL {
                    let peer = build_peer(
                        &device_id, &name, &ip, base_port, &transport, width, height,
                    );
                    broadcast(&socket, &peer, base_port);
                    last_announce = Instant::now();
                }

                let (size, from) = match socket.recv_from(&mut buffer) {
                    Ok(received) => received,
                    // A timeout is the normal case, not a problem.
                    Err(_) => continue,
                };

                let Ok(incoming) = rmp_serde::from_slice::<DiscoveryPacket>(&buffer[..size]) else {
                    continue;
                };
                if incoming.protocol != DISCOVERY_PROTOCOL {
                    continue;
                }

                // Our own broadcast comes straight back to us; without this we
                // would list ourselves as a peer and answer our own announce.
                if incoming.peer.id == device_id {
                    continue;
                }

                remember_peer(&peers_seen, &incoming.peer);

                if matches!(incoming.kind.as_str(), "announce" | "probe") {
                    let peer = build_peer(
                        &device_id, &name, &ip, base_port, &transport, width, height,
                    );
                    reply(&socket, &peer, from, &incoming.peer.ip, base_port);
                }
            }

            log::info!("[core] discovery stopped");
        })
        .map_err(|error| format!("could not start discovery thread: {error}"))?;

    Ok(())
}

/// Takes the configured port, or the first free one above it.
///
/// Drifting rather than failing is what lets two peers on one machine coexist,
/// and the whole port span is swept by senders for exactly this reason.
fn bind_discovery_socket(preferred: u16) -> Result<UdpSocket, String> {
    let mut last_error = String::new();
    for port in discovery_target_ports(preferred) {
        match UdpSocket::bind(("0.0.0.0", port)) {
            Ok(socket) => {
                log::info!("[core] discovery listening on {port}");
                return Ok(socket);
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    Err(format!(
        "no free discovery port near {preferred}: {last_error}"
    ))
}

fn build_peer(
    device_id: &str,
    name: &str,
    ip: &str,
    base_port: u16,
    transport: &TransportHandle,
    width: i32,
    height: i32,
) -> LanPeer {
    LanPeer {
        id: device_id.to_string(),
        name: name.to_string(),
        platform: "android".into(),
        machine_role: "client".into(),
        cluster_id: String::new(),
        pairing_required: false,
        host: name.to_string(),
        ip: ip.to_string(),
        transport_port: base_port,
        quic_port: transport.port(),
        transport_public_key: transport.public_key().to_string(),
        protocol_version: PROTOCOL_VERSION,
        screen_count: 1,
        input_ready: true,
        upgrading: false,
        screens: vec![LanPeerScreen {
            id: "local-display-1".into(),
            name: name.to_string(),
            x: 0,
            y: 0,
            width,
            height,
            scale: 1.0,
            is_primary: true,
        }],
        app_version: env!("CARGO_PKG_VERSION").into(),
        last_seen_ms: now_ms(),
    }
}

fn packet_for(peer: &LanPeer, kind: &str) -> DiscoveryPacket {
    DiscoveryPacket {
        protocol: DISCOVERY_PROTOCOL.into(),
        kind: kind.into(),
        peer: peer.clone(),
        pairing_code: None,
        pair_cluster_id: None,
        pair_secret: None,
        pairing_error: None,
    }
}

fn broadcast(socket: &UdpSocket, peer: &LanPeer, base_port: u16) {
    let Ok(payload) = rmp_serde::to_vec_named(&packet_for(peer, "announce")) else {
        return;
    };

    let targets = broadcast_addrs(base_port);
    let mut sent = 0usize;
    let mut first_error: Option<(String, String)> = None;

    for address in &targets {
        match socket.send_to(&payload, address) {
            Ok(_) => sent += 1,
            Err(error) => {
                first_error.get_or_insert_with(|| (address.clone(), error.to_string()));
            }
        }
    }

    // Announcing into a void looks identical to working, from the inside. Say
    // so once per state change instead of letting a VPN or a firewall silently
    // eat everything.
    report_broadcast_health(sent, targets.len(), first_error);
}

/// Logs only when the picture changes, so a healthy loop stays quiet.
fn report_broadcast_health(sent: usize, total: usize, error: Option<(String, String)>) {
    use std::sync::atomic::AtomicUsize;
    static LAST_SENT: AtomicUsize = AtomicUsize::new(usize::MAX);

    if LAST_SENT.swap(sent, Ordering::Relaxed) == sent {
        return;
    }

    match error {
        Some((address, reason)) if sent == 0 => {
            log::warn!("[core] every announce failed ({total} targets), e.g. {address}: {reason}")
        }
        Some((address, reason)) => {
            log::warn!("[core] announced to {sent}/{total} targets; {address} failed: {reason}")
        }
        None => log::info!("[core] announcing to {sent} targets"),
    }
}

/// Answers a peer both at the address its packet came from and at the address
/// it advertises, across the whole discovery port span.
///
/// The advertised path is what makes this work at all on Jan's network: the
/// access point forwards broadcasts from wired to wireless but not back, so the
/// phone hears the desktop while everything it broadcasts disappears. Unicast
/// crosses fine — proven by ping — so answering directly is the way in. The
/// source address alone is not enough, because the desktop scans from an
/// ephemeral socket that nobody reads replies on.
fn reply(socket: &UdpSocket, peer: &LanPeer, from: SocketAddr, advertised_ip: &str, base_port: u16) {
    let Ok(payload) = rmp_serde::to_vec_named(&packet_for(peer, "announce")) else {
        return;
    };

    let _ = socket.send_to(&payload, from);

    // The source address is the one we know is routable — the packet just came
    // from it. The advertised one may be on an interface we cannot reach at
    // all: a desktop with several VLANs announces whichever address its default
    // route picked, which here is a different subnet than the phone's Wi-Fi.
    let mut destinations = vec![from.ip().to_string()];
    let advertised_ip = advertised_ip.trim();
    if !advertised_ip.is_empty() && advertised_ip != destinations[0] {
        destinations.push(advertised_ip.to_string());
    }

    for address in destinations {
        for port in discovery_target_ports(base_port) {
            let _ = socket.send_to(&payload, (address.as_str(), port));
        }
    }
}

fn remember_peer(peers: &Arc<Mutex<Vec<String>>>, peer: &LanPeer) {
    let Ok(mut peers) = peers.lock() else {
        return;
    };
    let label = format!("{} ({})", peer.name, peer.ip);
    if !peers.contains(&label) {
        log::info!("[core] discovered {label}");
        peers.push(label);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Flattens an event into the three integers the JNI layer hands to Kotlin.
///
/// A phone has exactly one screen, so `MouseMove`'s screen id carries no
/// information and is dropped here rather than crossing the boundary.
pub fn flatten(event: &InputEvent) -> [i32; 3] {
    use mykvm_protocol::input::MouseButton;

    let button_ordinal = |button: MouseButton| match button {
        MouseButton::Left => 0,
        MouseButton::Right => 1,
        MouseButton::Middle => 2,
        MouseButton::Back => 3,
        MouseButton::Forward => 4,
    };

    match event {
        InputEvent::MouseMove { x, y, .. } => [KIND_MOUSE_MOVE, *x, *y],
        InputEvent::MouseButton { button, down } => [
            KIND_MOUSE_BUTTON,
            button_ordinal(*button),
            i32::from(*down),
        ],
        InputEvent::Scroll { delta_x, delta_y } => [KIND_SCROLL, *delta_x, *delta_y],
        InputEvent::Key { key_code, down } => {
            [KIND_KEY, i32::from(*key_code), i32::from(*down)]
        }
    }
}

pub const KIND_MOUSE_MOVE: i32 = 1;
pub const KIND_MOUSE_BUTTON: i32 = 2;
pub const KIND_SCROLL: i32 = 3;
pub const KIND_KEY: i32 = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use mykvm_protocol::input::MouseButton;

    #[test]
    fn events_flatten_into_the_shape_kotlin_expects() {
        assert_eq!(
            flatten(&InputEvent::MouseMove {
                screen_id: "local-display-1".into(),
                x: 640,
                y: 480
            }),
            [KIND_MOUSE_MOVE, 640, 480]
        );
        assert_eq!(
            flatten(&InputEvent::MouseButton {
                button: MouseButton::Right,
                down: true
            }),
            [KIND_MOUSE_BUTTON, 1, 1]
        );
        assert_eq!(
            flatten(&InputEvent::Scroll {
                delta_x: 0,
                delta_y: -2
            }),
            [KIND_SCROLL, 0, -2]
        );
        assert_eq!(
            flatten(&InputEvent::Key {
                key_code: 0x41,
                down: false
            }),
            [KIND_KEY, 0x41, 0]
        );
    }
}
