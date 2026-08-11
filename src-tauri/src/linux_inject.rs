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
//! Only relative pointer motion is available: absolute placement
//! (`notify_pointer_motion_absolute`) needs a Screencast stream id, and this
//! module deliberately never negotiates a Screencast (there is nothing to
//! show — only input is being injected). So an absolute `(x, y)` target from
//! the wire is turned into a delta against the last position we synced to,
//! the same "first sample only establishes the origin" rule
//! `linux_input.rs::translate_ei_event` already applies on the capture side.

use std::{
    collections::HashMap,
    sync::{mpsc, OnceLock},
    time::Duration,
};

use ashpd::desktop::{
    remote_desktop::{Axis, DeviceType, KeyState, RemoteDesktop},
    PersistMode, Session,
};

use crate::{
    linux_input::{self, BTN_EXTRA, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE},
    shared_input::MouseButton,
};

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

    if let Err(error) = remote_desktop
        .select_devices(
            &session,
            DeviceType::Keyboard | DeviceType::Pointer,
            None,
            PersistMode::DoNot,
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
    // `None` until the first move/click arrives — the first sample only
    // establishes an origin, exactly like `last_absolute` on the capture
    // side; turning it into a delta from zero would fling the cursor.
    let mut last_position: Option<(f64, f64)> = None;

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
                handle_command(&remote_desktop, &session, &mut last_position, command).await;
            }
            result = &mut start_request, if !granted && DENIED.get().is_none() => {
                match result.and_then(|request| request.response()) {
                    Ok(_selected) => {
                        granted = true;
                        log::info!("[wayland] remote-desktop injection permitted");
                    }
                    Err(error) => {
                        let _ = DENIED.set(format!("RemoteDesktop permission was not granted: {error}"));
                        log::warn!("[wayland] remote-desktop permission refused: {error}");
                    }
                }
            }
        }
    }

    let _ = session.close().await;
}

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
