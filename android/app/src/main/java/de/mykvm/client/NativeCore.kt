package de.mykvm.client

/**
 * The whole Rust boundary. No callbacks into the JVM.
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
        preferredInterface: String,
        verbose: Boolean,
    ): String

    /**
     * The interfaces this phone can be reached on, one per line as
     * `name\taddress\tkind`. Safe to call before the core is started, which is
     * the point: the user picks an interface and only then connects.
     */
    external fun nativeListInterfaces(): String

    /** `[kind, p1, p2]`, or null if nothing arrived within the timeout. */
    external fun nativePoll(timeoutMs: Int): IntArray?

    external fun nativeStop()

    /** One line: our id, our QUIC port, and the peers we have heard from. */
    external fun nativeStatus(): String

    /** The code to type on the desktop, or empty while none is pending. */
    external fun nativePairingCode(): String

    /** The layout the controlling machine types on, e.g. "us(intl)". */
    external fun nativeKeyboardLayout(): String

    /** Reports a new screen size, which on a phone means it was rotated. */
    external fun nativeSetScreen(width: Int, height: Int)

    /** Text a peer copied, or empty. */
    external fun nativeTakeClipboard(): String

    /** Sends a copy made here. False when there was nothing to do. */
    external fun nativeSendClipboard(text: String): Boolean

    /** One interface this phone can be reached on. */
    data class NetworkInterface(val name: String, val address: String, val kind: String)

    /** [nativeListInterfaces], parsed. Empty when the list cannot be read. */
    fun listInterfaces(): List<NetworkInterface> =
        nativeListInterfaces()
            .lineSequence()
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val parts = line.split('\t')
                if (parts.size < 3) null
                else NetworkInterface(parts[0], parts[1], parts[2])
            }
            .toList()

    const val KIND_MOUSE_MOVE = 1
    const val KIND_MOUSE_BUTTON = 2
    const val KIND_SCROLL = 3
    const val KIND_KEY = 4
}
