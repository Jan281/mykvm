//! Wayland input capture for Linux.
//!
//! Unlike macOS (CGEventTap) and Windows (low-level hooks), Wayland gives no
//! global input hook. Capture goes through `org.freedesktop.portal.InputCapture`:
//! we hand the compositor pointer barriers along the screen edges that face a
//! remote device, and it hands us back an EIS socket. When the pointer crosses a
//! barrier the portal *activates* — from that moment the compositor freezes the
//! local cursor and streams relative motion plus key events over libei, until we
//! call `release()`.
//!
//! That inverts the responsibility compared to the other platforms: we never
//! warp or hide the cursor ourselves, the compositor owns it. What we do own is
//! deciding when to hand it back.
//!
//! Requires a portal backend implementing InputCapture — KDE Plasma 6.1+ or
//! GNOME 46+. Everything here is self-contained so `input.rs` only sees a stream
//! of already-translated events.

use std::{
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use ashpd::desktop::input_capture::{
    ActivatedBarrier, Barrier, BarrierID, Capabilities, InputCapture,
};
use futures_util::StreamExt;
use reis::{
    ei,
    event::{DeviceCapability, EiEvent},
};

/// A pointer barrier along one screen edge, in compositor coordinates.
/// Start and end positions are inclusive, matching the portal's convention.
#[derive(Debug, Clone)]
pub struct BarrierSpec {
    pub id: u32,
    pub x1: i32,
    pub y1: i32,
    pub x2: i32,
    pub y2: i32,
}

/// Input arriving from the compositor while capture is active, already
/// translated out of evdev into the codes MyKVM puts on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureEvent {
    /// A barrier was crossed. `x`/`y` is the cursor position in compositor
    /// coordinates at the moment of capture.
    Activated {
        barrier_id: u32,
        x: f64,
        y: f64,
    },
    /// Relative pointer motion.
    Motion { dx: f64, dy: f64 },
    /// Mouse button, already mapped to MyKVM's button index.
    Button { button: LinuxButton, down: bool },
    /// Scroll in wheel notches (the unit the Windows receiver multiplies by 120).
    Scroll { delta_x: i32, delta_y: i32 },
    /// Key press/release as a Windows virtual key code.
    Key { vk: u16, down: bool },
    /// The compositor ended capture on its own (session suspended, layout
    /// change, another client grabbed input).
    Deactivated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

/// What the consumer wants to happen after an event.
pub enum Reaction {
    /// Keep capturing.
    Continue,
    /// Hand control back to this machine, placing the cursor at `x`/`y`
    /// in compositor coordinates.
    Release { x: f64, y: f64 },
}

/// Outcome of bringing the portal session up.
pub struct CaptureReady {
    pub accepted_barriers: usize,
    pub failed_barriers: Vec<u32>,
    /// Zone geometry the portal reported, for diagnosing rejected barriers.
    pub zones: Vec<(i32, i32, u32, u32)>,
}

/// evdev button codes (`input-event-codes.h`).
const BTN_LEFT: u32 = 0x110;
const BTN_RIGHT: u32 = 0x111;
const BTN_MIDDLE: u32 = 0x112;
const BTN_SIDE: u32 = 0x113;
const BTN_EXTRA: u32 = 0x114;

fn map_button(code: u32) -> Option<LinuxButton> {
    match code {
        BTN_LEFT => Some(LinuxButton::Left),
        BTN_RIGHT => Some(LinuxButton::Right),
        BTN_MIDDLE => Some(LinuxButton::Middle),
        BTN_SIDE => Some(LinuxButton::Back),
        BTN_EXTRA => Some(LinuxButton::Forward),
        _ => None,
    }
}

/// evdev keycode -> Windows virtual key code.
///
/// This mapping is deliberately *positional*, not character-based: evdev codes
/// name physical keys and so do VK codes, so the receiving machine applies its
/// own keyboard layout to whatever we send. That is what makes dead keys and
/// AltGr work — pressing the physical `'` key on a US-International layout
/// arrives as VK_OEM_7 and Windows turns it into an acute accent itself,
/// rather than us shipping an already-resolved character it cannot re-interpret.
///
/// Left/right modifier identity is preserved for the same reason: AltGr must
/// arrive as VK_RMENU, not as a generic VK_MENU, or international layouts on
/// the receiver lose their third level.
pub fn evdev_to_windows_vk(code: u32) -> Option<u16> {
    let vk: u16 = match code {
        1 => 0x1B,   // ESC
        2..=10 => (0x31 + (code - 2) as u16) as u16, // 1..9
        11 => 0x30,  // 0
        12 => 0xBD,  // MINUS -> VK_OEM_MINUS
        13 => 0xBB,  // EQUAL -> VK_OEM_PLUS
        14 => 0x08,  // BACKSPACE
        15 => 0x09,  // TAB
        16 => 0x51,  // Q
        17 => 0x57,  // W
        18 => 0x45,  // E
        19 => 0x52,  // R
        20 => 0x54,  // T
        21 => 0x59,  // Y
        22 => 0x55,  // U
        23 => 0x49,  // I
        24 => 0x4F,  // O
        25 => 0x50,  // P
        26 => 0xDB,  // LEFTBRACE -> VK_OEM_4
        27 => 0xDD,  // RIGHTBRACE -> VK_OEM_6
        28 => 0x0D,  // ENTER
        29 => 0xA2,  // LEFTCTRL
        30 => 0x41,  // A
        31 => 0x53,  // S
        32 => 0x44,  // D
        33 => 0x46,  // F
        34 => 0x47,  // G
        35 => 0x48,  // H
        36 => 0x4A,  // J
        37 => 0x4B,  // K
        38 => 0x4C,  // L
        39 => 0xBA,  // SEMICOLON -> VK_OEM_1
        40 => 0xDE,  // APOSTROPHE -> VK_OEM_7  (the dead-key that started all this)
        41 => 0xC0,  // GRAVE -> VK_OEM_3
        42 => 0xA0,  // LEFTSHIFT
        43 => 0xDC,  // BACKSLASH -> VK_OEM_5
        44 => 0x5A,  // Z
        45 => 0x58,  // X
        46 => 0x43,  // C
        47 => 0x56,  // V
        48 => 0x42,  // B
        49 => 0x4E,  // N
        50 => 0x4D,  // M
        51 => 0xBC,  // COMMA
        52 => 0xBE,  // DOT
        53 => 0xBF,  // SLASH -> VK_OEM_2
        54 => 0xA1,  // RIGHTSHIFT
        55 => 0x6A,  // KPASTERISK
        56 => 0xA4,  // LEFTALT
        57 => 0x20,  // SPACE
        58 => 0x14,  // CAPSLOCK
        59..=68 => (0x70 + (code - 59) as u16) as u16, // F1..F10
        69 => 0x90,  // NUMLOCK
        70 => 0x91,  // SCROLLLOCK
        71 => 0x67,  // KP7
        72 => 0x68,  // KP8
        73 => 0x69,  // KP9
        74 => 0x6D,  // KPMINUS
        75 => 0x64,  // KP4
        76 => 0x65,  // KP5
        77 => 0x66,  // KP6
        78 => 0x6B,  // KPPLUS
        79 => 0x61,  // KP1
        80 => 0x62,  // KP2
        81 => 0x63,  // KP3
        82 => 0x60,  // KP0
        83 => 0x6E,  // KPDOT
        86 => 0xE2,  // 102ND (the extra ISO key) -> VK_OEM_102
        87 => 0x7A,  // F11
        88 => 0x7B,  // F12
        96 => 0x0D,  // KPENTER
        97 => 0xA3,  // RIGHTCTRL
        98 => 0x6F,  // KPSLASH
        99 => 0x2C,  // SYSRQ -> VK_SNAPSHOT
        100 => 0xA5, // RIGHTALT -> VK_RMENU (AltGr)
        102 => 0x24, // HOME
        103 => 0x26, // UP
        104 => 0x21, // PAGEUP
        105 => 0x25, // LEFT
        106 => 0x27, // RIGHT
        107 => 0x23, // END
        108 => 0x28, // DOWN
        109 => 0x22, // PAGEDOWN
        110 => 0x2D, // INSERT
        111 => 0x2E, // DELETE
        113 => 0xAD, // MUTE
        114 => 0xAE, // VOLUMEDOWN
        115 => 0xAF, // VOLUMEUP
        119 => 0x13, // PAUSE
        125 => 0x5B, // LEFTMETA -> VK_LWIN
        126 => 0x5C, // RIGHTMETA -> VK_RWIN
        127 => 0x5D, // COMPOSE -> VK_APPS
        _ => return None,
    };
    Some(vk)
}

/// libei reports discrete scroll in units of 120 per notch, same as Windows'
/// WHEEL_DELTA. MyKVM's wire format carries notches (the receiver multiplies by
/// 120 again), so divide. The vertical axis is also negated: Wayland counts
/// positive as scrolling *down*, Windows as scrolling *up*.
fn discrete_to_notches(discrete: i32) -> i32 {
    discrete / 120
}

/// Logical pixels libinput reports per wheel notch. Also the step size a
/// touchpad's smooth scrolling gets quantised to, since the wire format only
/// carries whole notches.
const SCROLL_PIXELS_PER_NOTCH: f32 = 15.0;

/// Turns libei's two scroll axes into whole notches.
///
/// A wheel click arrives twice in the same frame: once as [`EiEvent::ScrollDelta`]
/// in pixels and once as [`EiEvent::ScrollDiscrete`] in 120ths. Emitting both
/// would scroll twice as far, so a delta is held back until the next event
/// proves no discrete counterpart is coming — frames share a timestamp, so an
/// equal `time` identifies the counterpart.
///
/// Touchpads send only deltas, which is why handling the discrete kind alone
/// left smooth scrolling dead on the remote machine.
#[derive(Default)]
struct ScrollState {
    pending: Option<(u64, f32, f32)>,
    residue_x: f32,
    residue_y: f32,
    residue_v120_x: i32,
    residue_v120_y: i32,
    logged_source: bool,
}

impl ScrollState {
    fn delta(&mut self, time: u64, dx: f32, dy: f32) -> Option<CaptureEvent> {
        self.log_source("smooth (pixel)");
        if let Some(slot) = self.pending.as_mut() {
            if slot.0 == time {
                // Same frame, so merge rather than flush.
                slot.1 += dx;
                slot.2 += dy;
                return None;
            }
        }
        let flushed = self.flush();
        self.pending = Some((time, dx, dy));
        flushed
    }

    /// `dx`/`dy` are in 120ths of a notch. A high-resolution wheel reports a
    /// single detent as several sub-120 steps, so these accumulate rather than
    /// divide-and-drop — plain `dx / 120` rounds every one of those steps to
    /// zero, which silently kills scrolling on such a mouse entirely.
    fn discrete(&mut self, time: u64, dx: i32, dy: i32) -> Option<CaptureEvent> {
        self.log_source("discrete");
        if matches!(self.pending, Some((pending_time, ..)) if pending_time == time) {
            self.pending = None;
        }
        self.residue_v120_x += dx;
        self.residue_v120_y += dy;
        let notches_x = discrete_to_notches(self.residue_v120_x);
        let notches_y = discrete_to_notches(self.residue_v120_y);
        self.residue_v120_x -= notches_x * 120;
        self.residue_v120_y -= notches_y * 120;
        let delta_x = notches_x;
        let delta_y = -notches_y;
        if delta_x == 0 && delta_y == 0 {
            return None;
        }
        Some(CaptureEvent::Scroll { delta_x, delta_y })
    }

    /// Says once which of the two scroll kinds the compositor actually feeds us.
    /// Logged on arrival rather than on send, so that "scrolling does nothing"
    /// can be told apart from "scrolling never arrived" even when the events
    /// arrive but add up to less than a whole notch.
    fn log_source(&mut self, source: &str) {
        if !self.logged_source {
            log::info!("[wayland] scroll arrives as {source} events");
            self.logged_source = true;
        }
    }

    /// Emits whatever whole notches the buffered pixels add up to, carrying the
    /// remainder so a slow touchpad drag still scrolls eventually.
    fn flush(&mut self) -> Option<CaptureEvent> {
        let (_, dx, dy) = self.pending.take()?;
        self.residue_x += dx;
        self.residue_y += dy;
        let notches_x = (self.residue_x / SCROLL_PIXELS_PER_NOTCH).trunc();
        let notches_y = (self.residue_y / SCROLL_PIXELS_PER_NOTCH).trunc();
        self.residue_x -= notches_x * SCROLL_PIXELS_PER_NOTCH;
        self.residue_y -= notches_y * SCROLL_PIXELS_PER_NOTCH;
        let delta_x = notches_x as i32;
        let delta_y = -(notches_y as i32);
        if delta_x == 0 && delta_y == 0 {
            return None;
        }
        Some(CaptureEvent::Scroll { delta_x, delta_y })
    }

    /// The gesture ended; nothing more will arrive to flush the tail.
    fn stop(&mut self) -> Option<CaptureEvent> {
        let flushed = self.flush();
        self.residue_x = 0.0;
        self.residue_y = 0.0;
        flushed
    }
}

/// The one portal session for this process.
///
/// Held for the lifetime of the app rather than per capture run: creating it is
/// what prompts the user for permission, and a second concurrent session stops
/// the compositor from arming barriers at all.
static SERVICE: OnceLock<Result<CaptureService, String>> = OnceLock::new();

/// Returns the process-wide capture service, opening the portal session on the
/// first call.
pub fn service() -> Result<&'static CaptureService, String> {
    SERVICE
        .get_or_init(CaptureService::start)
        .as_ref()
        .map_err(|error| error.clone())
}

/// Handles capture events while armed. Swapped out on every re-arm, because
/// the targets it closes over change with the layout.
pub type EventHandler = Box<dyn FnMut(CaptureEvent) -> Reaction + Send>;

enum Command {
    Arm {
        barriers: Vec<BarrierSpec>,
        reply: mpsc::Sender<Result<CaptureReady, String>>,
    },
    Disarm,
    Shutdown,
}

/// A portal session that outlives individual capture runs.
///
/// The session is created once, at startup, which is what makes the permission
/// dialog appear immediately instead of whenever a peer happens to come online.
/// Arming and disarming then reuse that same session.
///
/// One session, never two: an earlier attempt opened an idle session at startup
/// and a second one to actually capture with. KDE refused to arm barriers while
/// the idle session was still open, and the doomed setup blocked long enough to
/// hang the app. Everything here funnels through the single session owned by the
/// service thread.
pub struct CaptureService {
    command_tx: tokio::sync::mpsc::UnboundedSender<Command>,
    handler: Arc<Mutex<Option<EventHandler>>>,
    /// Bumped on every arming, so a capture that has been replaced can tell
    /// that the barriers now in force are no longer the ones it put there.
    generation: AtomicU64,
}

impl CaptureService {
    /// Opens the portal session — and so triggers the permission prompt — then
    /// keeps it on a dedicated thread until [`shutdown`](Self::shutdown).
    ///
    /// Returns once the session is usable, so a caller can report a meaningful
    /// status; it does not wait for the user to answer the prompt, since KDE
    /// grants the session first and asks on the first activation.
    pub fn start() -> Result<Self, String> {
        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let handler: Arc<Mutex<Option<EventHandler>>> = Arc::new(Mutex::new(None));
        let thread_handler = Arc::clone(&handler);

        std::thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("failed to start capture runtime: {error}")));
                    return;
                }
            };

            runtime.block_on(service_loop(command_rx, thread_handler, ready_tx));
        });

        match ready_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(())) => Ok(Self {
                command_tx,
                handler,
                generation: AtomicU64::new(0),
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("The InputCapture portal did not respond. It needs xdg-desktop-portal with a backend that implements InputCapture (KDE Plasma 6.1+ or GNOME 46+).".into()),
        }
    }

    /// Points the existing session at a new set of screen edges.
    ///
    /// Returns the generation this arming created, for `disarm_generation`.
    pub fn arm(&self, barriers: Vec<BarrierSpec>, handler: EventHandler) -> Result<CaptureReady, String> {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut slot) = self.handler.lock() {
            *slot = Some(handler);
        }

        let (reply_tx, reply_rx) = mpsc::channel();
        self.command_tx
            .send(Command::Arm {
                barriers,
                reply: reply_tx,
            })
            .map_err(|_| "capture service is gone".to_string())?;

        reply_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "the portal did not answer the barrier request".to_string())?
    }

    /// Drops the barriers but keeps the session, so sharing can be turned back
    /// on without asking the user for permission again.
    pub fn disarm(&self) {
        if let Ok(mut slot) = self.handler.lock() {
            *slot = None;
        }
        let _ = self.command_tx.send(Command::Disarm);
    }

    /// The generation currently armed. Capture hands this to its stop-watcher.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Disarms only if nothing has re-armed since `generation`.
    ///
    /// The session is process-wide, and a capture being replaced signals its
    /// stop-watcher rather than joining it, so that thread can wake up to 200 ms
    /// after its replacement has already armed. Disarming unconditionally there
    /// tore down the *new* barriers: the log said the edges were armed, the
    /// cursor still would not cross, and only a manual stop/start — slow enough
    /// for the old thread to have finished — appeared to help.
    pub fn disarm_generation(&self, generation: u64) {
        if self.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        self.disarm();
    }

    #[allow(dead_code)]
    pub fn shutdown(&self) {
        let _ = self.command_tx.send(Command::Shutdown);
    }
}

async fn service_loop(
    mut command_rx: tokio::sync::mpsc::UnboundedReceiver<Command>,
    handler: Arc<Mutex<Option<EventHandler>>>,
    ready: mpsc::Sender<Result<(), String>>,
) {
    let input_capture = match InputCapture::new().await {
        Ok(input_capture) => input_capture,
        Err(error) => {
            let _ = ready.send(Err(format!("InputCapture portal unavailable: {error}")));
            return;
        }
    };

    let session = match input_capture
        .create_session(None, Capabilities::Keyboard | Capabilities::Pointer)
        .await
    {
        Ok((session, _capabilities)) => session,
        Err(error) => {
            let _ = ready.send(Err(format!("could not create capture session: {error}")));
            return;
        }
    };

    let fd = match input_capture.connect_to_eis(&session).await {
        Ok(fd) => fd,
        Err(error) => {
            let _ = ready.send(Err(format!("could not connect to EIS: {error}")));
            return;
        }
    };

    let stream = UnixStream::from(fd);
    if let Err(error) = stream.set_nonblocking(true) {
        let _ = ready.send(Err(format!("could not configure EIS socket: {error}")));
        return;
    }

    let context = match ei::Context::new(stream) {
        Ok(context) => context,
        Err(error) => {
            let _ = ready.send(Err(format!("could not create ei context: {error}")));
            return;
        }
    };
    let _ = context.flush();

    let (_connection, mut event_stream) = match context
        .handshake_tokio("mykvm", ei::handshake::ContextType::Receiver)
        .await
    {
        Ok(pair) => pair,
        Err(error) => {
            let _ = ready.send(Err(format!("ei handshake failed: {error}")));
            return;
        }
    };

    let mut activated_stream = match input_capture.receive_activated().await {
        Ok(stream) => stream,
        Err(error) => {
            let _ = ready.send(Err(format!("could not listen for activation: {error}")));
            return;
        }
    };

    log::info!("[wayland] portal session open and held; barriers can now be armed");
    let _ = ready.send(Ok(()));

    let mut enabled = false;
    let mut activation_id: Option<u32> = None;
    // Origin for absolute pointer streams; reset per activation so a new
    // hand-over does not inherit the previous one's coordinates.
    let mut last_absolute: Option<(f64, f64)> = None;
    let mut scroll = ScrollState::default();
    let mut logged_motion_kind = false;

    loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(Command::Arm { barriers, reply }) => {
                        let result = arm_barriers(
                            &input_capture,
                            &session,
                            &barriers,
                            &mut enabled,
                        )
                        .await;
                        activation_id = None;
                        let _ = reply.send(result);
                    }
                    Some(Command::Disarm) => {
                        if enabled {
                            if let Err(error) = input_capture.disable(&session).await {
                                log::warn!("[wayland] could not disable capture: {error}");
                            }
                            enabled = false;
                        }
                        activation_id = None;
                    }
                    Some(Command::Shutdown) | None => break,
                }
            }

            activated = activated_stream.next() => {
                let Some(activated) = activated else { break };
                activation_id = activated.activation_id();
                last_absolute = None;
                let (x, y) = activated.cursor_position().unwrap_or((0.0, 0.0));
                let barrier_id = match activated.barrier_id() {
                    Some(ActivatedBarrier::Barrier(id)) => id.get(),
                    _ => 0,
                };

                let reaction = dispatch(&handler, CaptureEvent::Activated {
                    barrier_id,
                    x: x as f64,
                    y: y as f64,
                });

                if let Reaction::Release { x, y } = reaction {
                    let _ = input_capture.release(&session, activation_id, Some((x, y))).await;
                    activation_id = None;
                }
            }

            ei_event = event_stream.next() => {
                let Some(Ok(ei_event)) = ei_event else { break };

                if matches!(
                    ei_event,
                    EiEvent::SeatAdded(_)
                        | EiEvent::DeviceAdded(_)
                        | EiEvent::DeviceRemoved(_)
                        | EiEvent::Disconnected(_)
                ) {
                    log::info!("[wayland] ei lifecycle event: {ei_event:?}");
                } else if matches!(
                    ei_event,
                    EiEvent::DevicePaused(_) | EiEvent::DeviceResumed(_)
                ) {
                    // Pause/resume brackets every single crossing, so it only
                    // earns a line while debugging one.
                    log::debug!("[wayland] ei lifecycle event: {ei_event:?}");
                }

                if let EiEvent::DeviceAdded(added) = &ei_event {
                    // Which interfaces the compositor actually put on the device
                    // decides what it will ever send us. A pointer without
                    // ei_scroll can never produce a scroll event, no matter what
                    // we bound on the seat.
                    let mut capabilities: Vec<&str> = Vec::new();
                    if added.device.interface::<ei::Pointer>().is_some() {
                        capabilities.push("pointer");
                    }
                    if added.device.interface::<ei::PointerAbsolute>().is_some() {
                        capabilities.push("pointer-absolute");
                    }
                    if added.device.interface::<ei::Button>().is_some() {
                        capabilities.push("button");
                    }
                    if added.device.interface::<ei::Scroll>().is_some() {
                        capabilities.push("scroll");
                    }
                    if added.device.interface::<ei::Keyboard>().is_some() {
                        capabilities.push("keyboard");
                    }
                    log::info!(
                        "[wayland] device {:?} offers [{}]",
                        added.device.name().unwrap_or("<unnamed>"),
                        capabilities.join(", ")
                    );
                }

                if let EiEvent::SeatAdded(seat_event) = &ei_event {
                    seat_event.seat.bind_capabilities(
                        DeviceCapability::Pointer
                            | DeviceCapability::PointerAbsolute
                            | DeviceCapability::Keyboard
                            | DeviceCapability::Scroll
                            | DeviceCapability::Button,
                    );
                    let _ = context.flush();
                    continue;
                }

                if !logged_motion_kind {
                    match &ei_event {
                        EiEvent::PointerMotion(_) => {
                            log::info!("[wayland] compositor streams RELATIVE pointer motion");
                            logged_motion_kind = true;
                        }
                        EiEvent::PointerMotionAbsolute(_) => {
                            log::info!("[wayland] compositor streams ABSOLUTE pointer motion");
                            logged_motion_kind = true;
                        }
                        _ => {}
                    }
                }

                let Some(event) = translate_ei_event(ei_event, &mut last_absolute, &mut scroll) else { continue };
                let is_deactivation = matches!(event, CaptureEvent::Deactivated);
                let reaction = dispatch(&handler, event);

                if is_deactivation {
                    activation_id = None;
                    continue;
                }

                if let Reaction::Release { x, y } = reaction {
                    let _ = input_capture.release(&session, activation_id, Some((x, y))).await;
                    activation_id = None;
                }
            }
        }
    }

    if enabled {
        let _ = input_capture.disable(&session).await;
    }
    let _ = session.close().await;
}

/// Barriers can only be replaced on a suspended session, so an already-enabled
/// session is disabled first. The portal documentation flags re-enabling as the
/// fragile step (GNOME 46 cannot do it at all), so a failure here is logged
/// loudly rather than folded into a generic error.
async fn arm_barriers(
    input_capture: &InputCapture<'_>,
    session: &ashpd::desktop::Session<'_, InputCapture<'_>>,
    barriers: &[BarrierSpec],
    enabled: &mut bool,
) -> Result<CaptureReady, String> {
    if *enabled {
        if let Err(error) = input_capture.disable(session).await {
            log::warn!("[wayland] could not suspend session before re-arming: {error}");
        }
        *enabled = false;
    }

    let zones = input_capture
        .zones(session)
        .await
        .map_err(|error| format!("could not query zones: {error}"))?
        .response()
        .map_err(|error| format!("could not read zones: {error}"))?;

    let zone_geometry: Vec<(i32, i32, u32, u32)> = zones
        .regions()
        .iter()
        .map(|region| {
            (
                region.x_offset(),
                region.y_offset(),
                region.width(),
                region.height(),
            )
        })
        .collect();

    let portal_barriers: Vec<Barrier> = barriers
        .iter()
        .filter_map(|spec| {
            let id = BarrierID::new(spec.id)?;
            Some(Barrier::new(id, (spec.x1, spec.y1, spec.x2, spec.y2)))
        })
        .collect();

    let response = input_capture
        .set_pointer_barriers(session, &portal_barriers, zones.zone_set())
        .await
        .map_err(|error| format!("could not set pointer barriers: {error}"))?
        .response()
        .map_err(|error| format!("barrier request rejected: {error}"))?;

    let failed: Vec<u32> = response.failed_barriers().iter().map(|id| id.get()).collect();
    let accepted = portal_barriers.len().saturating_sub(failed.len());

    log::info!(
        "[wayland] portal zones={:?} requested_barriers={:?} failed={:?}",
        zone_geometry,
        barriers
            .iter()
            .map(|b| (b.id, b.x1, b.y1, b.x2, b.y2))
            .collect::<Vec<_>>(),
        failed
    );

    input_capture
        .enable(session)
        .await
        .map_err(|error| format!("could not enable capture after re-arming: {error}"))?;
    *enabled = true;

    Ok(CaptureReady {
        accepted_barriers: accepted,
        failed_barriers: failed,
        zones: zone_geometry,
    })
}

fn dispatch(handler: &Arc<Mutex<Option<EventHandler>>>, event: CaptureEvent) -> Reaction {
    let Ok(mut slot) = handler.lock() else {
        return Reaction::Continue;
    };
    match slot.as_mut() {
        Some(handler) => handler(event),
        // Disarmed mid-flight: nothing is listening, so hand the cursor back
        // rather than leaving it captured by a session with no consumer.
        None => match event {
            CaptureEvent::Activated { x, y, .. } => Reaction::Release { x, y },
            _ => Reaction::Continue,
        },
    }
}

/// Translates one libei event, tracking the last absolute pointer position.
///
/// The compositor decides whether to stream relative or absolute motion, and
/// KDE creates both a relative and an "absolute device" for a capture session.
/// Handling only the relative kind silently drops every mouse move on a setup
/// that sends absolute ones — which also strands the pointer, because the
/// return-to-local check never sees the cursor move back out.
fn translate_ei_event(
    event: EiEvent,
    last_absolute: &mut Option<(f64, f64)>,
    scroll: &mut ScrollState,
) -> Option<CaptureEvent> {
    match event {
        EiEvent::PointerMotion(motion) => Some(CaptureEvent::Motion {
            dx: motion.dx as f64,
            dy: motion.dy as f64,
        }),
        EiEvent::PointerMotionAbsolute(motion) => {
            let x = motion.dx_absolute as f64;
            let y = motion.dy_absolute as f64;
            let delta = last_absolute.map(|(px, py)| (x - px, y - py));
            *last_absolute = Some((x, y));
            // The first absolute sample only establishes the origin; treating
            // it as a delta from zero would fling the remote cursor across the
            // screen.
            delta.map(|(dx, dy)| CaptureEvent::Motion { dx, dy })
        }
        EiEvent::Button(button) => {
            let mapped = map_button(button.button)?;
            Some(CaptureEvent::Button {
                button: mapped,
                down: matches!(button.state, ei::button::ButtonState::Press),
            })
        }
        EiEvent::ScrollDiscrete(event) => {
            scroll.discrete(event.time, event.discrete_dx, event.discrete_dy)
        }
        EiEvent::ScrollDelta(event) => scroll.delta(event.time, event.dx, event.dy),
        // A frame closes the group a held-back delta was waiting on, and a
        // stop/cancel ends the gesture entirely.
        EiEvent::Frame(_) => scroll.flush(),
        EiEvent::ScrollStop(_) | EiEvent::ScrollCancel(_) => scroll.stop(),
        EiEvent::KeyboardKey(key) => {
            let vk = evdev_to_windows_vk(key.key)?;
            Some(CaptureEvent::Key {
                vk,
                down: matches!(key.state, ei::keyboard::KeyState::Press),
            })
        }
        EiEvent::DevicePaused(_) | EiEvent::Disconnected(_) => Some(CaptureEvent::Deactivated),
        other => {
            log::debug!("[wayland] unhandled ei event: {other:?}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apostrophe_maps_to_oem_7_so_dead_keys_survive() {
        // The whole point of the positional mapping: the receiver decides what
        // this key means, we only say which key it was.
        assert_eq!(evdev_to_windows_vk(40), Some(0xDE));
    }

    #[test]
    fn right_alt_stays_distinguishable_for_altgr() {
        assert_eq!(evdev_to_windows_vk(100), Some(0xA5));
        assert_eq!(evdev_to_windows_vk(56), Some(0xA4));
    }

    #[test]
    fn digit_and_letter_rows_land_on_the_right_vk_ranges() {
        assert_eq!(evdev_to_windows_vk(2), Some(0x31)); // 1
        assert_eq!(evdev_to_windows_vk(10), Some(0x39)); // 9
        assert_eq!(evdev_to_windows_vk(11), Some(0x30)); // 0
        assert_eq!(evdev_to_windows_vk(30), Some(0x41)); // A
        assert_eq!(evdev_to_windows_vk(59), Some(0x70)); // F1
        assert_eq!(evdev_to_windows_vk(68), Some(0x79)); // F10
    }

    #[test]
    fn unknown_codes_are_dropped_rather_than_guessed() {
        assert_eq!(evdev_to_windows_vk(0), None);
        assert_eq!(evdev_to_windows_vk(9999), None);
    }

    #[test]
    fn scroll_notches_are_divided_and_vertical_axis_is_inverted() {
        assert_eq!(discrete_to_notches(120), 1);
        assert_eq!(discrete_to_notches(-240), -2);
        assert_eq!(discrete_to_notches(60), 0);
    }

    #[test]
    fn a_wheel_click_scrolls_once_even_though_it_arrives_twice() {
        let mut scroll = ScrollState::default();
        // One frame: pixels first, then the discrete counterpart, then the frame.
        assert_eq!(scroll.delta(100, 0.0, 15.0), None);
        assert_eq!(
            scroll.discrete(100, 0, 120),
            Some(CaptureEvent::Scroll {
                delta_x: 0,
                delta_y: -1
            })
        );
        assert_eq!(scroll.flush(), None);
    }

    #[test]
    fn a_high_resolution_wheel_scrolls_instead_of_being_rounded_to_nothing() {
        let mut scroll = ScrollState::default();
        // A G502-class wheel splits one detent into four 30/120 steps.
        for frame in 0..3u64 {
            assert_eq!(scroll.discrete(frame, 0, 30), None);
        }
        assert_eq!(
            scroll.discrete(3, 0, 30),
            Some(CaptureEvent::Scroll {
                delta_x: 0,
                delta_y: -1
            })
        );
    }

    #[test]
    fn high_resolution_remainders_do_not_leak_across_a_reversal() {
        let mut scroll = ScrollState::default();
        assert_eq!(scroll.discrete(0, 0, 60), None);
        // Turning back the other way cancels the half notch rather than adding
        // to it, so the wheel does not drift.
        assert_eq!(scroll.discrete(1, 0, -60), None);
        assert_eq!(
            scroll.discrete(2, 0, -120),
            Some(CaptureEvent::Scroll {
                delta_x: 0,
                delta_y: 1
            })
        );
    }

    #[test]
    fn smooth_scroll_without_a_discrete_counterpart_still_gets_through() {
        let mut scroll = ScrollState::default();
        assert_eq!(scroll.delta(100, 0.0, -15.0), None);
        // The next frame flushes the one before it.
        assert_eq!(
            scroll.delta(200, 0.0, -15.0),
            Some(CaptureEvent::Scroll {
                delta_x: 0,
                delta_y: 1
            })
        );
        assert_eq!(
            scroll.stop(),
            Some(CaptureEvent::Scroll {
                delta_x: 0,
                delta_y: 1
            })
        );
    }

    #[test]
    fn slow_smooth_scrolling_accumulates_instead_of_being_rounded_away() {
        let mut scroll = ScrollState::default();
        // Five pixels per frame, and each frame flushes the one before it: the
        // first three carry too little to report, the fourth releases a notch.
        for frame in 0..3u64 {
            assert_eq!(scroll.delta(frame, 0.0, 5.0), None);
        }
        assert_eq!(
            scroll.delta(3, 0.0, 5.0),
            Some(CaptureEvent::Scroll {
                delta_x: 0,
                delta_y: -1
            })
        );
    }

    #[test]
    fn deltas_within_one_frame_are_merged_rather_than_sent_twice() {
        let mut scroll = ScrollState::default();
        assert_eq!(scroll.delta(100, 0.0, 8.0), None);
        assert_eq!(scroll.delta(100, 0.0, 8.0), None);
        assert_eq!(
            scroll.flush(),
            Some(CaptureEvent::Scroll {
                delta_x: 0,
                delta_y: -1
            })
        );
    }
}
