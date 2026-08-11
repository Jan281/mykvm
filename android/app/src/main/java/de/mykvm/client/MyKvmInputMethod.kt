package de.mykvm.client

import android.inputmethodservice.InputMethodService
import android.util.Log
import android.view.KeyEvent
import android.view.View
import android.widget.TextView

/**
 * The keyboard.
 *
 * An input method is the one thing a normal app may be that types into other
 * apps, so this is how remote keys reach a text field without root. It has to
 * serve two masters: while the desktop is typing it should take up no room at
 * all, and while a finger is typing it has to be a keyboard like any other —
 * because selecting it replaces whatever the user had before.
 */
class MyKvmInputMethod : InputMethodService() {

    override fun onCreate() {
        super.onCreate()
        instance = this
        Log.i(MyKvmService.TAG, "input method created")
    }

    override fun onDestroy() {
        instance = null
        super.onDestroy()
    }

    /**
     * A placeholder rather than a real keyboard, for now.
     *
     * This is the honest state of it: selecting MyKVM as the keyboard means
     * losing the on-screen one, so a full layout has to follow before anyone
     * uses this as their only input method. Saying so on screen beats leaving
     * the user staring at a blank strip.
     */
    override fun onCreateInputView(): View = TextView(this).apply {
        text = getString(R.string.ime_placeholder)
        setPadding(48, 48, 48, 48)
    }

    /**
     * Types one key that arrived from the desktop.
     *
     * Characters go in as text, which is what makes an umlaut possible at all —
     * there is no key code for ä. Anything with Ctrl or Alt held goes in as a
     * key event instead, so that Ctrl+C stays a shortcut rather than becoming
     * the letter c.
     */
    fun onRemoteKey(vk: Int, down: Boolean, modifiers: Modifiers) {
        val connection = currentInputConnection ?: run {
            // No focused text field. Normal, and not worth a line every keypress.
            return
        }

        KeyMap.keyCodeFor(vk)?.let { keyCode ->
            connection.sendKeyEvent(
                KeyEvent(
                    0,
                    0,
                    if (down) KeyEvent.ACTION_DOWN else KeyEvent.ACTION_UP,
                    keyCode,
                    0,
                    modifiers.metaState(),
                ),
            )
            return
        }

        // Only act once per keystroke; a release would double every character.
        if (!down) return

        if (modifiers.ctrl || modifiers.alt) {
            sendAsShortcut(vk, modifiers)
            return
        }

        val character = KeyMap.characterFor(vk, modifiers.shift, modifiers.altGr, layout)
        if (character == null) {
            Log.d(MyKvmService.TAG, "no mapping for vk 0x${vk.toString(16)}")
            return
        }
        connection.commitText(character.toString(), 1)
    }

    /**
     * Ctrl and Alt combinations have to arrive as key codes, because that is
     * the only form an app recognises as a shortcut. Mapping is positional
     * here: Ctrl+C is the C key wherever the layout puts it.
     */
    private fun sendAsShortcut(vk: Int, modifiers: Modifiers) {
        val connection = currentInputConnection ?: return
        val keyCode = when (vk) {
            in 0x41..0x5A -> KeyEvent.KEYCODE_A + (vk - 0x41)
            in 0x30..0x39 -> KeyEvent.KEYCODE_0 + (vk - 0x30)
            else -> return
        }
        val meta = modifiers.metaState()
        for (action in intArrayOf(KeyEvent.ACTION_DOWN, KeyEvent.ACTION_UP)) {
            connection.sendKeyEvent(KeyEvent(0, 0, action, keyCode, 0, meta))
        }
    }

    /** Which modifiers the desktop currently holds down. */
    data class Modifiers(
        val shift: Boolean = false,
        val ctrl: Boolean = false,
        val alt: Boolean = false,
        val altGr: Boolean = false,
    ) {
        fun metaState(): Int {
            var meta = 0
            if (shift) meta = meta or KeyEvent.META_SHIFT_ON
            if (ctrl) meta = meta or KeyEvent.META_CTRL_ON
            if (alt || altGr) meta = meta or KeyEvent.META_ALT_ON
            return meta
        }
    }

    companion object {
        @Volatile
        var instance: MyKvmInputMethod? = null
            private set

        /**
         * The layout the controlling machine uses. German for now because that
         * is what this was built against; it belongs in settings once there is
         * a second user.
         */
        var layout: KeyMap.Layout = KeyMap.Layout.GERMAN
    }
}
