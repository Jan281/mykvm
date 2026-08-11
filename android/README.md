# MyKVM for Android

A phone joins the cluster as a client: it announces itself, pairs with a code,
and receives mouse, clicks, scrolling, typing and clipboard over the same QUIC
transport the desktop peers use. No root and no ADB — three system switches the
user grants once, after which it comes back by itself on reboot.

## How it is put together

| | |
|---|---|
| `core/` | The client runtime in Rust, built as `libmykvm_core.so`. Depends on `../../src-tauri/protocol`, so the wire format is shared with the desktop rather than reimplemented. |
| `app/` | The Android app: a foreground service that owns the core, an accessibility service, an input method, and the setup screen. |

The JNI boundary is deliberately narrow and has **no callbacks into the JVM**:
Kotlin blocks in `nativePoll` on one thread and gets three integers per event. A
callback would need an attach and a global reference on every mouse move.

Why each Android component exists:

- **Foreground service** — Android destroys activities freely, and a client that
  stops receiving when its screen is backgrounded is useless.
- **Accessibility service** — nothing may inject a pointer event without root, so
  a click becomes a gesture dispatched where the drawn cursor sits. It also
  provides the global actions behind the Windows key and Escape.
- **Input method** — the one thing a normal app may be that types into other
  apps. It also carries clipboard sync, because since Android 10 only the
  foreground app and the *active keyboard* may read the clipboard.
- **Overlay window** — Android grants no real cursor without root, so the pointer
  is drawn. It follows the absolute coordinates the desktop sends, which is why
  a crossing lands exactly where `edge_entry_point` computed it.

## Building

The toolchain is installed per user; nothing is placed system-wide, and the
desktop build keeps using the system's own Rust.

```
~/Android/Sdk               SDK platform 36, build-tools 36.0.0, NDK 29.0.14206865
~/.cargo                    rustup, target aarch64-linux-android, cargo-ndk
~/.local/opt/gradle-8.14.3  Gradle
~/.local/opt/jdk-21.0.12+8  JDK 21
```

JDK 21 is installed separately because the system default here is a JRE with no
`javac`, and the only JDK is 26 — which Gradle 8.14 does not support. The path is
pinned in `gradle.properties` via `org.gradle.java.home`.

```sh
cd android
~/.local/opt/gradle-8.14.3/bin/gradle :app:assembleDebug --no-daemon
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`preBuild` runs `cargo-ndk`, so the APK can never carry a stale `.so`: that
mismatch would surface as an `UnsatisfiedLinkError` at runtime, far from its
cause. Only `arm64-v8a` is built.

To build the Rust core alone:

```sh
cd android/core
ANDROID_NDK_HOME=~/Android/Sdk/ndk/29.0.14206865 \
  PATH="$HOME/.cargo/bin:$PATH" cargo ndk -t arm64-v8a build --release
```

## After every install, during development

**Android revokes the accessibility grant and the keyboard selection whenever the
app is reinstalled.** This is deliberate on the system's part — an update must not
inherit rights that powerful — and it means clicks, scrolling and typing quietly
stop working after each build until they are set again:

```sh
adb shell settings put secure enabled_accessibility_services \
  de.mykvm.client/de.mykvm.client.MyKvmAccessibilityService
adb shell settings put secure accessibility_enabled 1
adb shell ime enable de.mykvm.client/.MyKvmInputMethod
adb shell ime set de.mykvm.client/.MyKvmInputMethod
```

The setup screen states which grants are missing and opens the right settings
page for each, so an ordinary user never needs these.

## Things that look like bugs and are not

- **A VPN silently breaks discovery in one direction.** A VPN that declares itself
  non-bypassable covers every UID, and the system refuses to let an app route
  around it — `bindProcessToNetwork` still succeeds and changes nothing. Inbound
  broadcasts keep arriving over Wi-Fi while everything sent vanishes into the
  tunnel. The fix is in the VPN's own settings (Proton: Connection → Advanced →
  LAN connections). The app warns when one is active.
- **A firewall on the desktop is the first thing to check** when the phone sees the
  desktop but not the other way round. `ufw` dropping inbound UDP from the
  phone's subnet looked exactly like a routing problem, and ping went through the
  whole time.
- **No pointer on the lock screen or over the notification shade.** The keyguard and
  the system bars sit above `TYPE_APPLICATION_OVERLAY`; an app that could draw
  there could overlay a PIN prompt. Clicks *do* work on the shade — only the
  drawing is forbidden — but on the lock screen nothing works at all.
- **A device must be unlocked** with an ordinary app in front for input to land.

## Deliberate gaps

- The input method has no keyboard of its own, only a placeholder. Selecting
  MyKVM as the keyboard therefore means switching back to type with a finger.
- Dragging transmits the start and end points, not the real path. Chaining a
  continued stroke per motion event would be hundreds per second, and apps treat
  a drag by where it began and ended.
- Clipboard images are decoded and acknowledged, but not applied. Text only.
- No file transfer.
