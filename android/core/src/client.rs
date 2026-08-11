//! The client side of MyKVM, reduced to what a phone needs.
//!
//! A phone is only ever controlled, never controlling: it announces itself, it
//! accepts input packets, and that is all. So this is deliberately not a port
//! of the desktop runtime — no capture, no layout, no edge logic. What it does
//! share, through `mykvm-protocol`, is every byte that goes on the wire.

use std::{
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
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
        preferred_quic_port, random_pairing_code, DiscoveryPacket, LanPeer, LanPeerScreen,
        DISCOVERY_PROTOCOL, PAIRING_CODE_TTL_MS, PAIRING_MAX_ATTEMPTS,
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

/// What a completed pairing leaves behind: the cluster we joined and the shared
/// secret that authorises input packets. Persisted, because losing it would
/// force the user through pairing again after every restart.
#[derive(Clone, Default)]
struct Membership {
    cluster_id: String,
    pair_secret: String,
}

impl Membership {
    fn is_paired(&self) -> bool {
        !self.cluster_id.trim().is_empty() && !self.pair_secret.trim().is_empty()
    }

    /// Two lines of text rather than a serialised struct: this file has to be
    /// readable when something goes wrong at three in the morning.
    fn load(dir: &Path) -> Self {
        let Ok(contents) = std::fs::read_to_string(dir.join(MEMBERSHIP_FILE)) else {
            return Self::default();
        };
        let mut lines = contents.lines();
        Self {
            cluster_id: lines.next().unwrap_or_default().trim().to_string(),
            pair_secret: lines.next().unwrap_or_default().trim().to_string(),
        }
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::write(
            dir.join(MEMBERSHIP_FILE),
            format!("{}\n{}\n", self.cluster_id, self.pair_secret),
        )
        .map_err(|error| format!("could not persist pairing: {error}"))
    }
}

const MEMBERSHIP_FILE: &str = "pairing.txt";

/// Just enough of any stream to tell what it is.
///
/// The kinds differ in shape — a discovery packet carries a whole peer, a
/// clipboard packet does not — so identifying one before decoding it keeps
/// valid traffic from being written off as corrupt.
#[derive(serde::Deserialize)]
struct StreamProbe {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    kind: String,
}

/// Names an unsupported stream kind once, rather than on every arrival.
fn log_unsupported_stream(protocol: &str) {
    use std::sync::Mutex as StdMutex;
    static SEEN: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

    let Ok(mut seen) = SEEN.lock() else {
        return;
    };
    if seen.iter().any(|known| known == protocol) {
        return;
    }
    log::info!("[core] acknowledging {protocol} streams, but nothing acts on them yet");
    seen.push(protocol.to_string());
}

/// An in-flight pairing: the code we are showing and who may answer it.
struct Challenge {
    code: String,
    expires_at: Instant,
    attempts: u8,
    requester_id: String,
    requester_public_key: String,
}

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
    challenge: Arc<Mutex<Option<Challenge>>>,
    membership: Arc<Mutex<Membership>>,
    /// How many events are enqueued but not yet polled.
    queued: Arc<Mutex<usize>>,
    /// The keyboard layout the controlling machine announced.
    layout: Arc<Mutex<String>>,
    /// Current screen size. Changes when the phone is rotated.
    screen: Arc<Mutex<(i32, i32)>>,
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
            Ok(event) => {
                // Releasing the slot is what makes the depth counter a measure
                // of backlog rather than of everything ever received.
                release_slot(&self.queued);
                Some(event)
            }
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
        let paired = self
            .membership
            .lock()
            .map(|membership| membership.is_paired())
            .unwrap_or(false);
        format!(
            "id={} quic={} paired={} peers=[{}]",
            self.device_id, self.quic_port, paired, peers
        )
    }

    /// Reports a new screen size, which on a phone means it was rotated.
    ///
    /// Width and height swap, and the desktop's layout has to learn that or
    /// every crossing lands somewhere the screen no longer reaches. Returns
    /// whether anything actually changed.
    pub fn set_screen(&self, width: i32, height: i32) -> bool {
        if width <= 0 || height <= 0 {
            return false;
        }
        let Ok(mut screen) = self.screen.lock() else {
            return false;
        };
        if *screen == (width, height) {
            return false;
        }
        log::info!("[core] screen is now {width}x{height}");
        *screen = (width, height);
        true
    }

    /// The keyboard layout the controlling machine last announced, or empty if
    /// it has not said — an older desktop simply omits the field.
    pub fn keyboard_layout(&self) -> String {
        self.layout.lock().map(|layout| layout.clone()).unwrap_or_default()
    }

    /// The code the user has to type on the desktop, while it is valid.
    pub fn pairing_code(&self) -> Option<String> {
        let challenge = self.challenge.lock().ok()?;
        let challenge = challenge.as_ref()?;
        (challenge.expires_at > Instant::now()).then(|| challenge.code.clone())
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

    let membership = Arc::new(Mutex::new(Membership::load(&config.identity_dir)));
    let layout = Arc::new(Mutex::new(String::new()));
    let screen = Arc::new(Mutex::new((config.screen_width, config.screen_height)));
    let challenge = Arc::new(Mutex::new(None));

    let transport = start_transport(
        &config,
        &device_id,
        event_tx,
        Arc::clone(&queued),
        Arc::clone(&challenge),
        Arc::clone(&membership),
    )?;

    let running = Arc::new(AtomicBool::new(true));
    let peers_seen = Arc::new(Mutex::new(Vec::new()));

    spawn_discovery(
        &config,
        device_id.clone(),
        ip,
        transport.clone(),
        Arc::clone(&running),
        Arc::clone(&peers_seen),
        Arc::clone(&challenge),
        Arc::clone(&membership),
        Arc::clone(&layout),
        Arc::clone(&screen),
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
        challenge,
        membership,
        queued,
        layout,
        screen,
    })
}

/// Wires the QUIC transport so that every arriving datagram becomes an
/// [`InputEvent`] on the queue — or is dropped, loudly enough to debug.
fn start_transport(
    config: &Config,
    device_id: &str,
    events: Sender<InputEvent>,
    queued: Arc<Mutex<usize>>,
    challenge: Arc<Mutex<Option<Challenge>>>,
    membership: Arc<Mutex<Membership>>,
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

        if !reserve_slot(&queued) {
            log::warn!("[core] event queue full; dropping input");
            return;
        }

        if events.send(packet.event).is_err() {
            log::debug!("[core] nobody is listening for input any more");
        }
    });

    // Streams carry clipboard and files, neither of which a phone does yet —
    // but also the pairing confirmation, which is why this is not a stub. The
    // returned bool is the acknowledgement the server waits for.
    let identity_dir = config.identity_dir.clone();
    let on_stream = Arc::new(move |payload: Vec<u8>, from: SocketAddr| {
        // Peek at the protocol before committing to a shape: clipboard packets
        // carry no `peer`, so decoding everything as a DiscoveryPacket would
        // report perfectly good traffic as garbage.
        let Ok(probe) = rmp_serde::from_slice::<StreamProbe>(&payload) else {
            log::debug!("[core] undecodable stream from {from}");
            return false;
        };

        if probe.protocol == DISCOVERY_PROTOCOL && probe.kind == "pair-confirm" {
            let Ok(packet) = rmp_serde::from_slice::<DiscoveryPacket>(&payload) else {
                log::warn!("[core] malformed pairing confirmation from {from}");
                return false;
            };
            return match complete_pairing(&challenge, &membership, &identity_dir, &packet) {
                Ok(()) => true,
                Err(error) => {
                    log::warn!("[core] pairing rejected: {error}");
                    false
                }
            };
        }

        // Everything else is acknowledged rather than refused. A refused stream
        // makes the sender drop the QUIC connection, and the next input
        // datagram then pays for re-establishing it — a clipboard we do not
        // support yet would show up as the cursor stuttering on arrival.
        log_unsupported_stream(&probe.protocol);
        true
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
    challenge: Arc<Mutex<Option<Challenge>>>,
    membership: Arc<Mutex<Membership>>,
    layout: Arc<Mutex<String>>,
    screen: Arc<Mutex<(i32, i32)>>,
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

    thread::Builder::new()
        .name("mykvm-discovery".into())
        .spawn(move || {
            let mut buffer = vec![0u8; 64 * 1024];
            let mut last_announce = Instant::now() - ANNOUNCE_INTERVAL;

            // Rebuilt per use rather than cached: pairing changes what we
            // announce, and a stale peer would keep claiming to need pairing
            // long after it joined.
            let current_peer = |membership: &Arc<Mutex<Membership>>| {
                let joined = membership
                    .lock()
                    .map(|membership| membership.clone())
                    .unwrap_or_default();
                let (width, height) = screen
                    .lock()
                    .map(|screen| *screen)
                    .unwrap_or((0, 0));
                build_peer(
                    &device_id, &name, &ip, base_port, &transport, width, height, &joined,
                )
            };

            while running.load(Ordering::Relaxed) {
                if last_announce.elapsed() >= ANNOUNCE_INTERVAL {
                    broadcast(&socket, &current_peer(&membership), base_port);
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

                remember_peer(&peers_seen, &incoming.peer, from);
                remember_layout(&layout, &incoming.peer);

                if incoming.kind == "pair-request" {
                    let paired = membership
                        .lock()
                        .map(|membership| membership.is_paired())
                        .unwrap_or(false);
                    if begin_challenge(&challenge, &incoming.peer, paired) {
                        let peer = current_peer(&membership);
                        let packet = packet_for(&peer, "pair-challenge");
                        if let Ok(payload) = rmp_serde::to_vec_named(&packet) {
                            let _ = socket.send_to(&payload, from);
                        }
                    }
                    continue;
                }

                if matches!(incoming.kind.as_str(), "announce" | "probe") {
                    reply(
                        &socket,
                        &current_peer(&membership),
                        from,
                        &incoming.peer.ip,
                        base_port,
                    );
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
    membership: &Membership,
) -> LanPeer {
    LanPeer {
        id: device_id.to_string(),
        name: name.to_string(),
        platform: "android".into(),
        machine_role: "client".into(),
        cluster_id: membership.cluster_id.clone(),
        // Until we have joined a cluster we must announce ourselves as needing
        // to pair. A server accepts an unknown peer on exactly that condition
        // (`peer_visible_to_layout`); claiming to be configured while carrying
        // no cluster id makes it drop us without a word.
        pairing_required: !membership.is_paired(),
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
        // A phone has no layout of its own to offer; it borrows one.
        keyboard_layout: String::new(),
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

    let mut sent = 0usize;
    let mut failure: Option<String> = None;
    for address in &destinations {
        for port in discovery_target_ports(base_port) {
            match socket.send_to(&payload, (address.as_str(), port)) {
                Ok(_) => sent += 1,
                Err(error) => {
                    failure.get_or_insert_with(|| format!("{address}:{port}: {error}"));
                }
            }
        }
    }

    static REPORTED: std::sync::Once = std::sync::Once::new();
    REPORTED.call_once(|| match failure {
        Some(reason) => log::warn!("[core] answered {destinations:?}, {sent} sends ok, {reason}"),
        None => log::info!("[core] answering {destinations:?} on every discovery port ({sent} sends)"),
    });
}

/// Records a peer under both addresses that matter.
///
/// The advertised one is what the peer believes it is reachable at; the source
/// one is where its packet actually came from. On a machine with several VLANs
/// those differ, and only the source address is known to be routable from here
/// — so if the two disagree, that is worth seeing rather than guessing at.
fn remember_peer(peers: &Arc<Mutex<Vec<String>>>, peer: &LanPeer, from: SocketAddr) {
    let Ok(mut peers) = peers.lock() else {
        return;
    };
    let label = format!("{} ({})", peer.name, peer.ip);
    if !peers.contains(&label) {
        if peer.ip.trim() == from.ip().to_string() {
            log::info!("[core] discovered {label} from {from}");
        } else {
            log::info!(
                "[core] discovered {label} but its packet came from {from} — answering both"
            );
        }
        peers.push(label);
    }
}

/// Answers a `pair-request` by showing a code and replying with our peer.
///
/// The server drives pairing: it asks, we show a code, the user types it there,
/// and it comes back over an encrypted stream. Only a server may ask, and only
/// while we have not joined a cluster yet.
fn begin_challenge(challenge: &Arc<Mutex<Option<Challenge>>>, requester: &LanPeer, paired: bool) -> bool {
    if requester.machine_role != "server" || paired {
        return false;
    }

    let Ok(mut slot) = challenge.lock() else {
        return false;
    };

    // A repeated request from the same server keeps the code on screen, so the
    // user is not chasing a number that changes while they type it.
    if let Some(existing) = slot.as_mut() {
        if existing.expires_at > Instant::now()
            && existing.requester_id == requester.id
            && existing.attempts == 0
        {
            existing.requester_public_key = requester.transport_public_key.clone();
            return true;
        }
    }

    let code = random_pairing_code();
    log::info!("[core] pairing code {code} for {}", requester.name);
    *slot = Some(Challenge {
        code,
        expires_at: Instant::now() + Duration::from_millis(PAIRING_CODE_TTL_MS),
        attempts: 0,
        requester_id: requester.id.clone(),
        requester_public_key: requester.transport_public_key.clone(),
    });
    true
}

/// Verifies a `pair-confirm` and, if it holds up, joins the cluster.
///
/// Mirrors the server's own checks: the code must match, it must come from the
/// peer we issued it to, and a handful of wrong guesses throws the challenge
/// away rather than allowing an endless hunt for six digits.
fn complete_pairing(
    challenge: &Arc<Mutex<Option<Challenge>>>,
    membership: &Arc<Mutex<Membership>>,
    identity_dir: &Path,
    packet: &DiscoveryPacket,
) -> Result<(), String> {
    let code = packet.pairing_code.clone().unwrap_or_default();
    let cluster_id = packet.pair_cluster_id.clone().unwrap_or_default();
    let secret = packet.pair_secret.clone().unwrap_or_default();
    if code.trim().is_empty() || cluster_id.trim().is_empty() || secret.trim().is_empty() {
        return Err("confirmation is missing its code or cluster".into());
    }

    {
        let mut slot = challenge
            .lock()
            .map_err(|_| "pairing lock poisoned".to_string())?;
        let Some(existing) = slot.as_mut() else {
            return Err("no pairing is in progress".into());
        };
        if existing.expires_at <= Instant::now() {
            *slot = None;
            return Err("the code expired".into());
        }
        if existing.requester_id != packet.peer.id
            || (!existing.requester_public_key.trim().is_empty()
                && existing.requester_public_key != packet.peer.transport_public_key)
        {
            return Err("confirmation came from a different peer".into());
        }
        if existing.code != code.trim() {
            existing.attempts = existing.attempts.saturating_add(1);
            if existing.attempts >= PAIRING_MAX_ATTEMPTS {
                *slot = None;
            }
            return Err("wrong code".into());
        }
        *slot = None;
    }

    let joined = Membership {
        cluster_id: cluster_id.trim().into(),
        pair_secret: secret.trim().into(),
    };
    joined.save(identity_dir)?;
    *membership
        .lock()
        .map_err(|_| "membership lock poisoned".to_string())? = joined;

    log::info!("[core] paired with {} ({})", packet.peer.name, cluster_id.trim());
    Ok(())
}

/// Adopts the controlling machine's keyboard layout.
///
/// Only a server's word counts: another client's layout says nothing about the
/// keyboard whose keys are arriving here.
fn remember_layout(layout: &Arc<Mutex<String>>, peer: &LanPeer) {
    if peer.machine_role != "server" || peer.keyboard_layout.trim().is_empty() {
        return;
    }
    let Ok(mut current) = layout.lock() else {
        return;
    };
    if *current == peer.keyboard_layout {
        return;
    }
    log::info!("[core] controlling machine types on {}", peer.keyboard_layout);
    *current = peer.keyboard_layout.clone();
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Claims one place in the queue, refusing once the consumer is this far
/// behind. Paired with [`release_slot`] — an unreleased slot is a leak that
/// eventually wedges the queue shut for good.
fn reserve_slot(queued: &Mutex<usize>) -> bool {
    let Ok(mut depth) = queued.lock() else {
        return false;
    };
    if *depth >= MAX_QUEUED_EVENTS {
        return false;
    }
    *depth += 1;
    true
}

fn release_slot(queued: &Mutex<usize>) {
    if let Ok(mut depth) = queued.lock() {
        *depth = depth.saturating_sub(1);
    }
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
    fn a_polled_event_frees_its_place_in_the_queue() {
        // The first version only ever counted up, so after MAX_QUEUED_EVENTS
        // arrivals every further event was dropped forever — input worked for
        // exactly 512 mouse moves and then stopped dead.
        let queued = Mutex::new(0usize);
        for _ in 0..MAX_QUEUED_EVENTS {
            assert!(reserve_slot(&queued));
        }
        assert!(!reserve_slot(&queued), "queue should be full");

        release_slot(&queued);
        assert!(reserve_slot(&queued), "a polled event must free its slot");
    }

    #[test]
    fn releasing_more_than_was_reserved_does_not_wrap_around() {
        let queued = Mutex::new(0usize);
        release_slot(&queued);
        assert_eq!(*queued.lock().unwrap(), 0);
    }

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
