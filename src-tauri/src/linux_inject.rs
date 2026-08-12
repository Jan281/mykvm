//! Wayland input injection for Linux — the receiving side of a KVM link.
//!
//! `linux_input.rs` captures this machine's own input to send elsewhere.
//! This module is the mirror image: it takes input arriving from a remote
//! peer and puts it back into the local session, via
//! `org.freedesktop.portal.RemoteDesktop`. That portal's `start()` call is
//! what raises the compositor's "let this app control your input" prompt —
//! the popup a user expects to see once a peer starts sending it commands.
//!
//! Architecture mirrors `linux_input.rs`'s `CaptureService`: one session,
//! opened once for the app's lifetime on a dedicated thread with its own
//! current-thread runtime, fed through an unbounded channel so the hot
//! datagram-receive path — which runs on the app's shared tokio runtime and
//! must never block on D-Bus — can hand off work with a cheap, non-blocking
//! send.
//!
//! Pointer placement goes through **libei**, not through the portal's own
//! `notify_pointer_*` calls. The portal offers absolute placement only via
//! `notify_pointer_motion_absolute`, which needs a Screencast stream id, and
//! negotiating a Screencast just to move a cursor would cost the user a
//! sharing prompt and a permanent "screen is being shared" indicator for a
//! stream nobody watches. `RemoteDesktop.ConnectToEIS` avoids that: it hands
//! back a libei socket on which the compositor exposes an *absolute* pointer
//! whose regions are the screens themselves, so a wire coordinate can be
//! placed exactly.
//!
//! The relative path (`notify_pointer_motion` against a remembered position)
//! is kept only as a fallback for portal backends too old to implement
//! `ConnectToEIS`, and it is a genuinely worse one: dead reckoning has no
//! feedback, so pointer acceleration applied to injected motion and clamping
//! at a screen edge both push the real cursor away from where this side
//! believes it is, permanently and cumulatively. That drift is what made a
//! cursor cross to a neighbouring screen long before reaching the edge.

use std::{
    collections::HashMap,
    io::Write,
    os::unix::{fs::OpenOptionsExt, net::UnixStream},
    path::PathBuf,
    sync::{mpsc, OnceLock},
    time::{Duration, Instant},
};

use ashpd::desktop::{
    remote_desktop::{Axis, DeviceType, KeyState, RemoteDesktop},
    PersistMode, Session,
};
use futures_util::StreamExt;
use reis::{
    ei,
    event::{Connection, DeviceCapability, EiEvent},
};

use crate::{
    linux_input::{self, BTN_EXTRA, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE},
    shared_input::MouseButton,
};

/// One wheel notch, in the 120ths libei counts scrolling in — the same unit
/// Windows calls `WHEEL_DELTA`, which is why the wire carries plain notches
/// and each platform multiplies on its way out.
const EI_SCROLL_UNIT: i32 = 120;

/// Inverts `linux_input::evdev_to_windows_vk`, built once from that single
/// source of truth rather than duplicating its ~80-arm match by hand — the
/// two tables would only ever drift apart otherwise.
fn windows_vk_to_evdev(vk: u16) -> Option<u32> {
    static TABLE: OnceLock<HashMap<u16, u32>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            (0u32..=255)
                .filter_map(|code| linux_input::evdev_to_windows_vk(code).map(|vk| (vk, code)))
                .collect()
        })
        .get(&vk)
        .copied()
}

fn mouse_button_to_evdev(button: MouseButton) -> u32 {
    match button {
        MouseButton::Left => BTN_LEFT,
        MouseButton::Right => BTN_RIGHT,
        MouseButton::Middle => BTN_MIDDLE,
        MouseButton::Back => BTN_SIDE,
        MouseButton::Forward => BTN_EXTRA,
    }
}

enum Command {
    MouseMove {
        x: i32,
        y: i32,
    },
    MouseButton {
        evdev_button: u32,
        down: bool,
        x: i32,
        y: i32,
    },
    Scroll {
        delta_x: i32,
        delta_y: i32,
    },
    Key {
        evdev_code: u32,
        down: bool,
    },
    #[allow(dead_code)]
    Shutdown,
}

/// The one RemoteDesktop session for this process, opened at first use and
/// held for the app's lifetime — same reasoning as `linux_input`'s
/// `CaptureService`: creating it lazily per-connection would mean the
/// permission prompt lands at some arbitrary later moment instead of
/// predictably, close to when receive mode actually turns on.
static SERVICE: OnceLock<Result<InjectService, String>> = OnceLock::new();

/// Set once if the compositor/portal refuses the RemoteDesktop grant, so a
/// later status poll can surface it without re-prompting — the same
/// check-without-re-ask shape `input_receive_status` already uses for
/// macOS's Accessibility/Secure-Input checks.
static DENIED: OnceLock<String> = OnceLock::new();

/// Where the portal's restore token lives. Handed over at startup rather
/// than worked out here, because resolving the app's config directory is
/// Tauri's job and this module has no app handle.
static TOKEN_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Called once during setup. Without it, injection still works — the user is
/// simply asked again on every start.
pub fn set_restore_token_path(path: PathBuf) {
    let _ = TOKEN_PATH.set(path);
}

fn load_restore_token() -> Option<String> {
    let token = std::fs::read_to_string(TOKEN_PATH.get()?).ok()?;
    let token = token.trim().to_owned();
    (!token.is_empty()).then_some(token)
}

/// A restore token re-grants control of this machine's input, so it is
/// written owner-only. The portal issues a fresh one per session and treats
/// the previous as spent, which is why this runs on every successful start
/// and not just the first.
fn store_restore_token(token: Option<&str>) {
    let Some(path) = TOKEN_PATH.get() else {
        return;
    };
    let Some(token) = token else {
        // No new token means the old one is spent and nothing replaces it;
        // keeping it would only produce a failed restore next time.
        let _ = std::fs::remove_file(path);
        log::debug!("[wayland] portal returned no restore token; permission will be asked again");
        return;
    };

    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(token.as_bytes()));

    match written {
        Ok(()) => log::debug!("[wayland] stored a fresh remote-desktop restore token"),
        Err(error) => log::warn!("[wayland] could not store the restore token: {error}"),
    }
}

pub fn service() -> Result<&'static InjectService, String> {
    SERVICE
        .get_or_init(InjectService::start)
        .as_ref()
        .map_err(|error| error.clone())
}

pub fn denial_reason() -> Option<String> {
    DENIED.get().cloned()
}

pub struct InjectService {
    command_tx: tokio::sync::mpsc::UnboundedSender<Command>,
}

impl InjectService {
    fn start() -> Result<Self, String> {
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = mpsc::channel();

        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("failed to start inject runtime: {error}")));
                    return;
                }
            };

            runtime.block_on(service_loop(command_rx, ready_tx));
        });

        match ready_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(Self { command_tx }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("The RemoteDesktop portal did not respond. It needs xdg-desktop-portal with a backend that implements RemoteDesktop (KDE Plasma 6.1+ or GNOME 46+).".into()),
        }
    }

    fn send(&self, command: Command) {
        let _ = self.command_tx.send(command);
    }
}

pub fn inject_mouse_move(x: i32, y: i32, _drag_button: Option<MouseButton>) {
    if let Ok(service) = service() {
        service.send(Command::MouseMove { x, y });
    }
}

pub fn inject_mouse_button(button: MouseButton, down: bool, x: i32, y: i32) {
    if let Ok(service) = service() {
        service.send(Command::MouseButton {
            evdev_button: mouse_button_to_evdev(button),
            down,
            x,
            y,
        });
    }
}

pub fn inject_scroll(delta_x: i32, delta_y: i32) {
    if let Ok(service) = service() {
        service.send(Command::Scroll { delta_x, delta_y });
    }
}

pub fn inject_key(key_code: u16, down: bool) {
    let Some(evdev_code) = windows_vk_to_evdev(key_code) else {
        log::debug!("[wayland] no evdev key for windows vk {key_code:#04x}; dropping");
        return;
    };
    if let Ok(service) = service() {
        service.send(Command::Key { evdev_code, down });
    }
}

/// Turns a wire scroll, counted in whole notches with Windows' sign, into
/// libei's 120ths with Wayland's. Only the vertical axis flips: both sides
/// agree that positive horizontal means rightwards.
fn scroll_to_ei(delta_x: i32, delta_y: i32) -> (i32, i32) {
    (delta_x * EI_SCROLL_UNIT, -delta_y * EI_SCROLL_UNIT)
}

/// One libei device the compositor offered us, and whether it may be driven
/// right now. A device arrives paused and has to be resumed before anything
/// sent on it counts; emulating is a second, client-side bracket around the
/// events themselves.
struct EisDevice {
    device: reis::event::Device,
    resumed: bool,
    emulating: bool,
}

/// The libei sender connection — the whole reason this module exists in its
/// current form, since it is what makes absolute placement possible.
struct EisSink {
    connection: Connection,
    devices: Vec<EisDevice>,
    /// libei wants a monotonically rising sequence per emulation bracket.
    sequence: u32,
    /// Frame timestamps are microseconds on an arbitrary monotonic clock, so
    /// the process start is as good an epoch as any.
    started: Instant,
}

impl EisSink {
    /// Sends one event on the first resumed device offering interface `T`,
    /// wrapped in the emulation bracket and the frame libei requires.
    /// Returns false when no device can carry it — during the moment between
    /// the grant and the compositor resuming its devices, for instance.
    fn emit<T, F>(&mut self, apply: F) -> bool
    where
        T: ei::Interface,
        F: FnOnce(&T),
    {
        let Some(index) = self
            .devices
            .iter()
            .position(|entry| entry.resumed && entry.device.interface::<T>().is_some())
        else {
            return false;
        };
        let interface = self.devices[index]
            .device
            .interface::<T>()
            .expect("the position() above just matched on this interface");

        self.start_emulating(index);
        apply(&interface);

        // One frame per event: libei treats everything between two frames as
        // simultaneous, and explicitly forbids two scrolls in one frame.
        let serial = self.connection.serial();
        let timestamp = self.started.elapsed().as_micros() as u64;
        self.devices[index].device.device().frame(serial, timestamp);
        let _ = self.connection.flush();
        true
    }

    fn start_emulating(&mut self, index: usize) {
        if self.devices[index].emulating {
            return;
        }
        let serial = self.connection.serial();
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        let entry = &mut self.devices[index];
        entry.device.device().start_emulating(serial, sequence);
        entry.emulating = true;
    }

    /// Tracks the device lifecycle. A pause revokes the emulation bracket on
    /// the server's side, so the flag has to fall with it — otherwise the
    /// next event would be sent into a bracket that no longer exists.
    fn apply_lifecycle(&mut self, event: &EiEvent) {
        match event {
            EiEvent::DeviceAdded(added) => {
                let regions: Vec<String> = added
                    .device
                    .regions()
                    .iter()
                    .map(|region| {
                        format!(
                            "{}x{}+{}+{}@{}",
                            region.width, region.height, region.x, region.y, region.scale
                        )
                    })
                    .collect();
                // Worth a line: these regions are the coordinate space every
                // absolute position is interpreted in, so a layout that does
                // not match what the sender thinks it is addressing shows up
                // here rather than as a cursor in the wrong place.
                log::info!(
                    "[wayland] inject device {:?} regions [{}]",
                    added.device.name().unwrap_or("<unnamed>"),
                    regions.join(", ")
                );
                self.devices.push(EisDevice {
                    device: added.device.clone(),
                    resumed: false,
                    emulating: false,
                });
            }
            EiEvent::DeviceRemoved(removed) => {
                self.devices.retain(|entry| entry.device != removed.device);
            }
            EiEvent::DeviceResumed(resumed) => {
                if let Some(entry) = self
                    .devices
                    .iter_mut()
                    .find(|entry| entry.device == resumed.device)
                {
                    entry.resumed = true;
                    entry.emulating = false;
                }
            }
            EiEvent::DevicePaused(paused) => {
                if let Some(entry) = self
                    .devices
                    .iter_mut()
                    .find(|entry| entry.device == paused.device)
                {
                    entry.resumed = false;
                    entry.emulating = false;
                }
            }
            EiEvent::SeatAdded(seat) => {
                seat.seat.bind_capabilities(
                    DeviceCapability::PointerAbsolute
                        | DeviceCapability::Button
                        | DeviceCapability::Scroll
                        | DeviceCapability::Keyboard,
                );
                let _ = self.connection.flush();
            }
            _ => {}
        }
    }

    fn handle(&mut self, command: Command) {
        let delivered = match command {
            Command::Shutdown => true,
            Command::MouseMove { x, y } => self.emit::<ei::PointerAbsolute, _>(|pointer| {
                pointer.motion_absolute(x as f32, y as f32)
            }),
            Command::MouseButton {
                evdev_button,
                down,
                x,
                y,
            } => {
                // Place first, then click — a button lands wherever the
                // pointer currently is, so the two cannot be reordered.
                self.emit::<ei::PointerAbsolute, _>(|pointer| {
                    pointer.motion_absolute(x as f32, y as f32)
                });
                let state = if down {
                    ei::button::ButtonState::Press
                } else {
                    ei::button::ButtonState::Released
                };
                self.emit::<ei::Button, _>(|button| button.button(evdev_button, state))
            }
            Command::Scroll { delta_x, delta_y } => {
                // Both axes in a single request: libei calls a second
                // scroll_discrete within one frame a client bug and may drop
                // it or disconnect us. The vertical flip is the same one the
                // capture side applies going the other way, from Wayland's
                // positive-is-down to the wire's Windows convention.
                let (x, y) = scroll_to_ei(delta_x, delta_y);
                self.emit::<ei::Scroll, _>(|scroll| scroll.scroll_discrete(x, y))
            }
            Command::Key { evdev_code, down } => {
                let state = if down {
                    ei::keyboard::KeyState::Press
                } else {
                    ei::keyboard::KeyState::Released
                };
                self.emit::<ei::Keyboard, _>(|keyboard| keyboard.key(evdev_code, state))
            }
        };

        if !delivered {
            // Dropping beats falling back to the relative path here: mixing
            // the two would leave the fallback's remembered position stale,
            // and a stale position is exactly the drift this rewrite removes.
            log::debug!("[wayland] no resumed ei device for the event; dropping");
        }
    }
}

/// Opens the libei sender connection on an already-granted RemoteDesktop
/// session. Every failure is recoverable — the caller keeps the relative
/// portal path — so all of them come back as a reason to log, not a panic.
async fn connect_eis(
    remote_desktop: &RemoteDesktop<'_>,
    session: &Session<'_, RemoteDesktop<'_>>,
) -> Result<(EisSink, reis::tokio::EiConvertEventStream), String> {
    let fd = remote_desktop
        .connect_to_eis(session)
        .await
        .map_err(|error| format!("ConnectToEIS refused: {error}"))?;

    let stream = UnixStream::from(fd);
    stream
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure the EIS socket: {error}"))?;

    let context =
        ei::Context::new(stream).map_err(|error| format!("could not create ei context: {error}"))?;
    let _ = context.flush();

    let (connection, events) = context
        .handshake_tokio("mykvm", ei::handshake::ContextType::Sender)
        .await
        .map_err(|error| format!("ei handshake failed: {error}"))?;

    Ok((
        EisSink {
            connection,
            devices: Vec::new(),
            sequence: 0,
            started: Instant::now(),
        },
        events,
    ))
}

/// Awaits the next libei event, or never, when there is no connection. Lets
/// the one `select!` below carry an arm that only exists some of the time.
async fn next_eis_event(
    events: &mut Option<reis::tokio::EiConvertEventStream>,
) -> Option<Result<EiEvent, reis::Error>> {
    match events {
        Some(events) => events.next().await,
        None => std::future::pending().await,
    }
}

async fn service_loop(
    mut command_rx: tokio::sync::mpsc::UnboundedReceiver<Command>,
    ready: mpsc::Sender<Result<(), String>>,
) {
    let remote_desktop = match RemoteDesktop::new().await {
        Ok(remote_desktop) => remote_desktop,
        Err(error) => {
            let _ = ready.send(Err(format!("RemoteDesktop portal unavailable: {error}")));
            return;
        }
    };

    let session = match remote_desktop.create_session().await {
        Ok(session) => session,
        Err(error) => {
            let _ = ready.send(Err(format!("could not create remote-desktop session: {error}")));
            return;
        }
    };

    // `ExplicitlyRevoked` rather than `Application`: the latter forgets the
    // grant when the process ends, which is exactly the case that made the
    // dialog reappear on every launch. Handing back a token we were given
    // earlier is what lets the portal skip the prompt entirely.
    let restore_token = load_restore_token();
    if let Err(error) = remote_desktop
        .select_devices(
            &session,
            DeviceType::Keyboard | DeviceType::Pointer,
            restore_token.as_deref(),
            PersistMode::ExplicitlyRevoked,
        )
        .await
        .and_then(|request| request.response())
    {
        let _ = ready.send(Err(format!("could not select input devices: {error}")));
        return;
    }

    log::info!("[wayland] remote-desktop session negotiated; requesting injection permission");
    let _ = ready.send(Ok(()));

    let mut granted = false;
    // Only used on the relative fallback path. `None` until the first
    // move/click arrives — the first sample only establishes an origin,
    // exactly like `last_absolute` on the capture side; turning it into a
    // delta from zero would fling the cursor.
    let mut last_position: Option<(f64, f64)> = None;
    let mut eis: Option<EisSink> = None;
    let mut eis_events: Option<reis::tokio::EiConvertEventStream> = None;

    let start_request = remote_desktop.start(&session, None);
    let mut start_request = std::pin::pin!(start_request);

    loop {
        tokio::select! {
            command = command_rx.recv() => {
                let Some(command) = command else { break };
                if matches!(command, Command::Shutdown) {
                    break;
                }
                if !granted {
                    // Nothing was queued for this, so there is no backlog to
                    // replay once the user answers the prompt — and queuing
                    // would let a slow answer pile up unbounded motion.
                    log::debug!("[wayland] injection not yet permitted; dropping command");
                    continue;
                }
                match eis.as_mut() {
                    Some(eis) => eis.handle(command),
                    None => {
                        handle_command(&remote_desktop, &session, &mut last_position, command).await
                    }
                }
            }
            result = &mut start_request, if !granted && DENIED.get().is_none() => {
                match result.and_then(|request| request.response()) {
                    Ok(selected) => {
                        granted = true;
                        log::info!("[wayland] remote-desktop injection permitted");
                        store_restore_token(selected.restore_token());
                        // Only now: ConnectToEIS needs a started session.
                        match connect_eis(&remote_desktop, &session).await {
                            Ok((sink, events)) => {
                                log::info!("[wayland] injecting through libei with absolute positioning");
                                eis = Some(sink);
                                eis_events = Some(events);
                            }
                            Err(error) => {
                                // Not fatal, but it does mean the cursor will
                                // drift out of step over time, so say why.
                                log::warn!(
                                    "[wayland] no libei connection ({error}); falling back to relative portal motion, which accumulates positional drift"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        let _ = DENIED.set(format!("RemoteDesktop permission was not granted: {error}"));
                        log::warn!("[wayland] remote-desktop permission refused: {error}");
                    }
                }
            }
            event = next_eis_event(&mut eis_events) => {
                match event {
                    Some(Ok(event)) => {
                        if let Some(eis) = eis.as_mut() {
                            eis.apply_lifecycle(&event);
                        }
                    }
                    // The socket closing takes absolute positioning with it.
                    // Keep the session, drop back to the portal rather than
                    // going silent.
                    other => {
                        if let Some(Err(error)) = other {
                            log::warn!("[wayland] libei connection failed: {error}");
                        } else {
                            log::warn!("[wayland] libei connection closed");
                        }
                        eis = None;
                        eis_events = None;
                        last_position = None;
                    }
                }
            }
        }
    }

    let _ = session.close().await;
}

/// The relative fallback, used only when the portal backend has no
/// `ConnectToEIS`. See the module header for why it is second choice.
async fn handle_command(
    remote_desktop: &RemoteDesktop<'_>,
    session: &Session<'_, RemoteDesktop<'_>>,
    last_position: &mut Option<(f64, f64)>,
    command: Command,
) {
    match command {
        Command::Shutdown => {}
        Command::MouseMove { x, y } => {
            sync_position(remote_desktop, session, last_position, x, y).await;
        }
        Command::MouseButton { evdev_button, down, x, y } => {
            // A click also has to land the cursor where the sender reported
            // it first — same as `windows_input::inject_mouse_button`
            // moving before posting the click.
            sync_position(remote_desktop, session, last_position, x, y).await;
            let state = if down { KeyState::Pressed } else { KeyState::Released };
            let _ = remote_desktop
                .notify_pointer_button(session, evdev_button as i32, state)
                .await;
        }
        Command::Scroll { delta_x, delta_y } => {
            // The capture side negates the vertical axis going from Wayland
            // convention (positive = down) to the wire's Windows convention
            // (positive = up); injecting reverses that same flip.
            if delta_x != 0 {
                let _ = remote_desktop
                    .notify_pointer_axis_discrete(session, Axis::Horizontal, delta_x)
                    .await;
            }
            if delta_y != 0 {
                let _ = remote_desktop
                    .notify_pointer_axis_discrete(session, Axis::Vertical, -delta_y)
                    .await;
            }
        }
        Command::Key { evdev_code, down } => {
            let state = if down { KeyState::Pressed } else { KeyState::Released };
            let _ = remote_desktop
                .notify_keyboard_keycode(session, evdev_code as i32, state)
                .await;
        }
    }
}

async fn sync_position(
    remote_desktop: &RemoteDesktop<'_>,
    session: &Session<'_, RemoteDesktop<'_>>,
    last_position: &mut Option<(f64, f64)>,
    x: i32,
    y: i32,
) {
    let (x, y) = (x as f64, y as f64);
    if let Some((last_x, last_y)) = *last_position {
        let (dx, dy) = (x - last_x, y - last_y);
        if dx != 0.0 || dy != 0.0 {
            let _ = remote_desktop.notify_pointer_motion(session, dx, dy).await;
        }
    }
    *last_position = Some((x, y));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_vk_to_evdev_round_trips_through_the_forward_table() {
        // The forward table isn't injective — evdev ENTER (28) and KPENTER
        // (96) both send VK_RETURN, matching how Windows itself does not
        // distinguish them by VK code. So the reverse table can only
        // promise it picks *some* evdev code that maps back to the same VK,
        // not the specific one a given test happened to start from.
        for code in 0u32..=255 {
            if let Some(vk) = linux_input::evdev_to_windows_vk(code) {
                let picked = windows_vk_to_evdev(vk).expect("vk must invert to some evdev code");
                assert_eq!(linux_input::evdev_to_windows_vk(picked), Some(vk));
            }
        }
    }

    #[test]
    fn scrolling_up_on_the_wire_scrolls_up_in_libei() {
        // Wheel-up is positive on the wire and negative in libei, and one
        // notch is 120 there. Getting either wrong inverts or multiplies
        // every scroll, which is only ever noticed by hand.
        assert_eq!(scroll_to_ei(0, 1), (0, -120));
        assert_eq!(scroll_to_ei(0, -3), (0, 360));
        // Horizontal keeps its sign: right is positive on both sides.
        assert_eq!(scroll_to_ei(2, 0), (240, 0));
    }

    #[test]
    fn unmapped_vk_codes_are_dropped_rather_than_guessed() {
        // 0x07 has no evdev counterpart in the forward table.
        assert_eq!(windows_vk_to_evdev(0x07), None);
    }

    #[test]
    fn mouse_buttons_map_to_the_same_evdev_codes_capture_uses() {
        assert_eq!(mouse_button_to_evdev(MouseButton::Left), BTN_LEFT);
        assert_eq!(mouse_button_to_evdev(MouseButton::Right), BTN_RIGHT);
        assert_eq!(mouse_button_to_evdev(MouseButton::Middle), BTN_MIDDLE);
        assert_eq!(mouse_button_to_evdev(MouseButton::Back), BTN_SIDE);
        assert_eq!(mouse_button_to_evdev(MouseButton::Forward), BTN_EXTRA);
    }
}
