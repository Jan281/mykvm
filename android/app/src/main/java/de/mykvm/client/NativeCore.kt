package de.mykvm.client

/**
 * The whole Rust boundary. Five functions, no callbacks into the JVM.
 *
 * [nativePoll] blocks, so it must never be called from the main thread — see
 * [CoreEvents] for the thread that drives it.
 */
object NativeCore {
    init {
        System.loadLibrary("mykvm_core")
    }

    /** Empty string on success, otherwise the reason to show the user. */
    external fun nativeStart(
        deviceName: String,
        discoveryPort: Int,
        screenWidth: Int,
        screenHeight: Int,
        identityDir: String,
    ): String

    /** `[kind, p1, p2]`, or null if nothing arrived within the timeout. */
    external fun nativePoll(timeoutMs: Int): IntArray?

    external fun nativeStop()

    /** One line: our id, our QUIC port, and the peers we have heard from. */
    external fun nativeStatus(): String

    const val KIND_MOUSE_MOVE = 1
    const val KIND_MOUSE_BUTTON = 2
    const val KIND_SCROLL = 3
    const val KIND_KEY = 4
}
