package de.mykvm.client

import android.content.Context
import android.os.Build

/**
 * The subset of the desktop's settings that means anything on a phone.
 *
 * Left out on purpose: the capture-side ones (edge hotkeys, modifier remapping)
 * because a phone never captures; start-minimised and the performance monitor,
 * which have no counterpart; and file transfer and clipboard sync, which are
 * not implemented here yet — offering a switch that does nothing is worse than
 * offering none.
 */
class Settings(context: Context) {
    private val store = context.getSharedPreferences("mykvm", Context.MODE_PRIVATE)

    enum class Theme { SYSTEM, DARK, LIGHT }

    /** What the desktop calls the device. Feeds the peer id, so changing it re-pairs. */
    var deviceName: String
        get() = store.getString(KEY_NAME, null) ?: (Build.MODEL ?: "Android")
        set(value) = store.edit().putString(KEY_NAME, value.trim()).apply()

    /** Fixed port, or 0 for the canonical one. Mirrors the desktop's auto/fixed mode. */
    var discoveryPort: Int
        get() = store.getInt(KEY_PORT, 0).let { if (it in 1024..65535) it else DEFAULT_PORT }
        set(value) = store.edit().putInt(KEY_PORT, value).apply()

    var theme: Theme
        get() = runCatching { Theme.valueOf(store.getString(KEY_THEME, null) ?: "") }
            .getOrDefault(Theme.SYSTEM)
        set(value) = store.edit().putString(KEY_THEME, value.name).apply()

    /** Drawing the pointer can be turned off for a phone used only for typing. */
    var showCursor: Boolean
        get() = store.getBoolean(KEY_CURSOR, true)
        set(value) = store.edit().putBoolean(KEY_CURSOR, value).apply()

    /**
     * Empty means "use whatever the controlling machine announces", which is
     * almost always right. An override exists for the case where the desktop
     * cannot detect its own layout — on Windows and macOS it does not try.
     */
    var keyboardLayoutOverride: String
        get() = store.getString(KEY_LAYOUT, "") ?: ""
        set(value) = store.edit().putString(KEY_LAYOUT, value).apply()

    /** Matches the desktop's log level setting; debug is what a bug report needs. */
    var verboseLogging: Boolean
        get() = store.getBoolean(KEY_VERBOSE, false)
        set(value) = store.edit().putBoolean(KEY_VERBOSE, value).apply()

    private companion object {
        const val KEY_NAME = "device_name"
        const val KEY_PORT = "discovery_port"
        const val KEY_THEME = "theme"
        const val KEY_CURSOR = "show_cursor"
        const val KEY_LAYOUT = "keyboard_layout"
        const val KEY_VERBOSE = "verbose"
        const val DEFAULT_PORT = 47833
    }
}
