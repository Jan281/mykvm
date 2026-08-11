package de.mykvm.client

import android.view.KeyEvent

/**
 * Turns the wire's Windows virtual key codes into something Android can use.
 *
 * The codes are positional by design — evdev 21 becomes VK_Y whatever is
 * printed on the key — because Windows then applies its own layout. Android has
 * no equivalent for injected keys: it would read them through a US character
 * map, which swaps y and z for a German keyboard and puts umlauts out of reach
 * entirely. So the layout that Windows would have applied is applied here.
 *
 * Keys that carry no character — arrows, Enter, function keys — are
 * layout-independent and go through as key codes.
 */
object KeyMap {

    enum class Layout {
        GERMAN,
        US,
        /**
         * US keys, but the quote and tilde positions are dead keys that
         * compose accents onto the next character. This is what makes umlauts
         * reachable on a US board, and it is what the machine this was built
         * against actually uses.
         */
        US_INTERNATIONAL,
        ;

        companion object {
            /** Parses what the controlling machine announces, e.g. "us(intl)". */
            fun parse(announced: String): Layout? {
                val text = announced.lowercase()
                return when {
                    text.isBlank() -> null
                    text.startsWith("de") -> GERMAN
                    text.contains("intl") || text.contains("altgr-intl") -> US_INTERNATIONAL
                    text.startsWith("us") -> US
                    else -> null
                }
            }
        }
    }

    /** A key that waits for the next one and combines with it. */
    private val DEAD_KEYS = mapOf(
        0xDE to Pair('\'', '"'),   // ' and " on a US board
        0xC0 to Pair('`', '~'),
    )

    /**
     * Whether this key, on this layout, waits for the next one.
     *
     * Returns the accent it carries, or null if the key stands alone.
     */
    fun deadKeyFor(vk: Int, shift: Boolean, layout: Layout): Char? {
        if (layout != Layout.US_INTERNATIONAL) return null
        val (base, shifted) = DEAD_KEYS[vk] ?: return null
        return if (shift) shifted else base
    }

    /**
     * Combines a pending accent with the key that followed.
     *
     * Returns null when the pair has no accented form — US-International then
     * emits the accent followed by the character, which is how a stray quote
     * gets typed at all.
     */
    fun compose(accent: Char, character: Char): Char? = COMPOSED["$accent$character"]

    private val COMPOSED: Map<String, Char> = buildMap {
        fun pair(accent: Char, plain: String, accented: String) {
            plain.forEachIndexed { index, character ->
                put("$accent$character", accented[index])
            }
        }
        pair('"', "aeiouyAEIOUY", "äëïöüÿÄËÏÖÜŸ")
        pair('\'', "aeiouycAEIOUYC", "áéíóúýçÁÉÍÓÚÝÇ")
        pair('`', "aeiouAEIOU", "àèìòùÀÈÌÒÙ")
        pair('^', "aeiouAEIOU", "âêîôûÂÊÎÔÛ")
        pair('~', "anoANO", "ãñõÃÑÕ")
    }

    /** What a printable key produces, unshifted / shifted / with AltGr. */
    private data class Printable(val base: Char, val shift: Char, val altGr: Char? = null)

    fun keyCodeFor(vk: Int): Int? = CONTROL_KEYS[vk]

    fun characterFor(vk: Int, shift: Boolean, altGr: Boolean, layout: Layout): Char? {
        val table = when (layout) {
            Layout.GERMAN -> GERMAN
            // US-International shares the US table; only the dead keys and
            // AltGr combinations differ, and those are handled apart.
            else -> US
        }
        val entry = table[vk] ?: return null
        return when {
            altGr -> entry.altGr
            shift -> entry.shift
            else -> entry.base
        }
    }

    fun isModifier(vk: Int): Boolean = vk in MODIFIERS

    /** Keys with no character of their own; identical on every layout. */
    private val CONTROL_KEYS = mapOf(
        0x08 to KeyEvent.KEYCODE_DEL,          // Backspace
        0x09 to KeyEvent.KEYCODE_TAB,
        0x0D to KeyEvent.KEYCODE_ENTER,
        0x1B to KeyEvent.KEYCODE_ESCAPE,
        0x20 to KeyEvent.KEYCODE_SPACE,
        0x21 to KeyEvent.KEYCODE_PAGE_UP,
        0x22 to KeyEvent.KEYCODE_PAGE_DOWN,
        0x23 to KeyEvent.KEYCODE_MOVE_END,
        0x24 to KeyEvent.KEYCODE_MOVE_HOME,
        0x25 to KeyEvent.KEYCODE_DPAD_LEFT,
        0x26 to KeyEvent.KEYCODE_DPAD_UP,
        0x27 to KeyEvent.KEYCODE_DPAD_RIGHT,
        0x28 to KeyEvent.KEYCODE_DPAD_DOWN,
        0x2D to KeyEvent.KEYCODE_INSERT,
        0x2E to KeyEvent.KEYCODE_FORWARD_DEL,
        0x70 to KeyEvent.KEYCODE_F1,
        0x71 to KeyEvent.KEYCODE_F2,
        0x72 to KeyEvent.KEYCODE_F3,
        0x73 to KeyEvent.KEYCODE_F4,
        0x74 to KeyEvent.KEYCODE_F5,
        0x75 to KeyEvent.KEYCODE_F6,
        0x76 to KeyEvent.KEYCODE_F7,
        0x77 to KeyEvent.KEYCODE_F8,
        0x78 to KeyEvent.KEYCODE_F9,
        0x79 to KeyEvent.KEYCODE_F10,
        0x7A to KeyEvent.KEYCODE_F11,
        0x7B to KeyEvent.KEYCODE_F12,
        0xAD to KeyEvent.KEYCODE_VOLUME_MUTE,
        0xAE to KeyEvent.KEYCODE_VOLUME_DOWN,
        0xAF to KeyEvent.KEYCODE_VOLUME_UP,
    )

    private val MODIFIERS = setOf(
        0x10, 0x11, 0x12,              // Shift, Control, Alt (unsided)
        0xA0, 0xA1,                    // Left/right Shift
        0xA2, 0xA3,                    // Left/right Control
        0xA4, 0xA5,                    // Left Alt, right Alt (AltGr)
        0x5B, 0x5C,                    // Windows keys
        0x14,                          // Caps Lock
    )

    private fun letters(swapYZ: Boolean): Map<Int, Printable> = buildMap {
        for (vk in 0x41..0x5A) {
            var upper = vk.toChar()
            if (swapYZ) {
                // A German keyboard has z where a US one has y. The wire
                // carries the position, so the swap happens here.
                upper = when (upper) {
                    'Y' -> 'Z'
                    'Z' -> 'Y'
                    else -> upper
                }
            }
            put(vk, Printable(upper.lowercaseChar(), upper))
        }
    }

    private val GERMAN: Map<Int, Printable> = buildMap {
        putAll(letters(swapYZ = true))
        put(0x51, Printable('q', 'Q', '@'))
        put(0x45, Printable('e', 'E', '€'))
        put(0x4D, Printable('m', 'M', 'µ'))

        put(0x30, Printable('0', '=', '}'))
        put(0x31, Printable('1', '!'))
        put(0x32, Printable('2', '"', '²'))
        put(0x33, Printable('3', '§', '³'))
        put(0x34, Printable('4', '$'))
        put(0x35, Printable('5', '%'))
        put(0x36, Printable('6', '&'))
        put(0x37, Printable('7', '/', '{'))
        put(0x38, Printable('8', '(', '['))
        put(0x39, Printable('9', ')', ']'))

        // The OEM keys are where a layout really shows: these positions carry
        // the umlauts and ß on a German keyboard.
        put(0xBA, Printable('ü', 'Ü'))
        put(0xDE, Printable('ä', 'Ä'))
        put(0xC0, Printable('ö', 'Ö'))
        put(0xDB, Printable('ß', '?', '\\'))
        put(0xBB, Printable('+', '*', '~'))
        put(0xBD, Printable('-', '_'))
        put(0xBC, Printable(',', ';'))
        put(0xBE, Printable('.', ':'))
        put(0xBF, Printable('#', '\''))
        put(0xDC, Printable('^', '°'))
        put(0xDD, Printable('´', '`'))
        put(0xE2, Printable('<', '>', '|'))
    }

    private val US: Map<Int, Printable> = buildMap {
        putAll(letters(swapYZ = false))
        put(0x30, Printable('0', ')'))
        put(0x31, Printable('1', '!'))
        put(0x32, Printable('2', '@'))
        put(0x33, Printable('3', '#'))
        put(0x34, Printable('4', '$'))
        put(0x35, Printable('5', '%'))
        put(0x36, Printable('6', '^'))
        put(0x37, Printable('7', '&'))
        put(0x38, Printable('8', '*'))
        put(0x39, Printable('9', '('))
        put(0xBA, Printable(';', ':'))
        put(0xBB, Printable('=', '+'))
        put(0xBC, Printable(',', '<'))
        put(0xBD, Printable('-', '_'))
        put(0xBE, Printable('.', '>'))
        put(0xBF, Printable('/', '?'))
        put(0xC0, Printable('`', '~'))
        put(0xDB, Printable('[', '{'))
        put(0xDC, Printable('\\', '|'))
        put(0xDD, Printable(']', '}'))
        put(0xDE, Printable('\'', '"'))
    }
}
