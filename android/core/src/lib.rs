//! The JNI surface. Five functions, deliberately.
//!
//! Everything that could be decided in Rust is decided in Rust; Kotlin gets a
//! blocking poll and three integers per event. That keeps the boundary free of
//! callbacks into the JVM, which would otherwise need an attach and a global
//! reference on every mouse move.

mod client;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use jni::{
    objects::{JClass, JString},
    sys::{jboolean, jint, jintArray, jstring},
    JNIEnv,
};

use client::Client;

/// The one client per process. Android may recreate the service around it, so
/// starting twice has to be harmless rather than fatal.
///
/// Behind an `Arc` so that polling can let go of this lock before it blocks.
/// Holding it across a blocking wait starved every other call — and since the
/// setup screen asks for status once a second, that showed up as a UI frozen
/// on its splash.
static CLIENT: Mutex<Option<Arc<Client>>> = Mutex::new(None);

/// The running client, if any, without keeping the lock.
fn current() -> Option<Arc<Client>> {
    CLIENT.lock().ok()?.as_ref().map(Arc::clone)
}

fn take_string(env: &mut JNIEnv, value: &JString) -> String {
    env.get_string(value)
        .map(|java| java.into())
        .unwrap_or_default()
}

fn to_java_string(env: &JNIEnv, value: &str) -> jstring {
    env.new_string(value)
        .map(|string| string.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Starts discovery and the QUIC transport. Returns an empty string on success,
/// otherwise the reason — Kotlin shows it in the setup screen rather than
/// leaving the user with a service that silently does nothing.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    device_name: JString,
    discovery_port: jint,
    screen_width: jint,
    screen_height: jint,
    identity_dir: JString,
    verbose: jboolean,
) -> jstring {
    // Matches the desktop's log level setting: info is enough to follow what
    // happens, debug is what tracking something down needs.
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(if verbose != 0 {
                log::LevelFilter::Debug
            } else {
                log::LevelFilter::Info
            })
            .with_tag("mykvm"),
    );

    let config = client::Config {
        device_name: take_string(&mut env, &device_name),
        discovery_port: discovery_port as u16,
        screen_width,
        screen_height,
        identity_dir: PathBuf::from(take_string(&mut env, &identity_dir)),
    };

    let Ok(mut slot) = CLIENT.lock() else {
        return to_java_string(&env, "client lock poisoned");
    };
    if let Some(existing) = slot.as_ref() {
        log::info!("[jni] already running: {}", existing.status());
        return to_java_string(&env, "");
    }

    match client::start(config) {
        Ok(started) => {
            *slot = Some(Arc::new(started));
            to_java_string(&env, "")
        }
        Err(error) => {
            log::error!("[jni] start failed: {error}");
            to_java_string(&env, &error)
        }
    }
}

/// Blocks for up to `timeout_ms` and returns `[kind, p1, p2]`, or null on
/// timeout. See `client::KIND_*` for the kinds.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativePoll(
    env: JNIEnv,
    _class: JClass,
    timeout_ms: jint,
) -> jintArray {
    // The clone is the point: the lock is released before the wait begins.
    let Some(running) = current() else {
        return std::ptr::null_mut();
    };
    let event = running.poll(Duration::from_millis(timeout_ms.max(0) as u64));

    let Some(event) = event else {
        return std::ptr::null_mut();
    };

    let flat = client::flatten(&event);
    match env.new_int_array(3) {
        Ok(array) => {
            if env.set_int_array_region(&array, 0, &flat).is_err() {
                return std::ptr::null_mut();
            }
            array.into_raw()
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    let Ok(mut slot) = CLIENT.lock() else {
        return;
    };
    if let Some(running) = slot.take() {
        running.stop();
        log::info!("[jni] stopped");
    }
}

/// The pairing code to type on the desktop, or an empty string when none is
/// pending. Polled by the UI rather than pushed, so the code appearing needs no
/// callback into the JVM.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativePairingCode(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let code = current()
        .and_then(|running| running.pairing_code())
        .unwrap_or_default();
    to_java_string(&env, &code)
}

/// Text that arrived from a peer, or empty. Kotlin puts it on the system
/// clipboard — which only the active keyboard is allowed to do.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativeTakeClipboard(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let text = current()
        .and_then(|running| running.take_clipboard())
        .unwrap_or_default();
    to_java_string(&env, &text)
}

/// Sends a copy made on this phone. Returns false when there was nothing to do
/// — not paired, no peers yet, or the same content we just applied from
/// elsewhere, which is what stops a copy bouncing between machines.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativeSendClipboard(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) -> jboolean {
    let text = take_string(&mut env, &text);
    let Ok(slot) = CLIENT.lock() else {
        return 0;
    };
    match slot.as_ref() {
        Some(running) if running.send_clipboard(&text) => 1,
        _ => 0,
    }
}

/// Reports a new screen size after a rotation. Announcing is on a timer, so
/// nothing has to be pushed — the next announce simply carries the new size.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativeSetScreen(
    _env: JNIEnv,
    _class: JClass,
    width: jint,
    height: jint,
) {
    let Ok(slot) = CLIENT.lock() else {
        return;
    };
    if let Some(running) = slot.as_ref() {
        running.set_screen(width, height);
    }
}

/// The keyboard layout the controlling machine announced, or empty. The client
/// applies it rather than guessing, since a phone has no layout of its own for
/// injected keys.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativeKeyboardLayout(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let layout = current()
        .map(|running| running.keyboard_layout())
        .unwrap_or_default();
    to_java_string(&env, &layout)
}

/// A one-line summary for the setup screen: our id, our QUIC port and which
/// peers we have heard from.
#[no_mangle]
pub extern "system" fn Java_de_mykvm_client_NativeCore_nativeStatus(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let text = current()
        .map(|running| running.status())
        .unwrap_or_else(|| "stopped".into());
    to_java_string(&env, &text)
}
