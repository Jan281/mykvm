package de.mykvm.client

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * Keeps the phone's clipboard and the cluster's in step.
 *
 * Android 10 restricted reading the clipboard to the app in the foreground and
 * to the active input method. A background service may not — which is why this
 * has to run inside the keyboard. Choosing to build an input method for typing
 * is what makes clipboard sync possible at all here; without it, copying in
 * another app could not be seen.
 */
class ClipboardBridge(private val context: Context) {
    private val clipboard =
        context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val handler = Handler(Looper.getMainLooper())

    /**
     * What we last put on the clipboard ourselves.
     *
     * Applying received text fires the change listener, and without this that
     * would be sent straight back out as a fresh local copy — the two machines
     * would then hand the same text back and forth.
     */
    private var applied: String? = null
    private var listening = false

    private val onChange = ClipboardManager.OnPrimaryClipChangedListener {
        val text = readText() ?: return@OnPrimaryClipChangedListener
        if (text == applied) return@OnPrimaryClipChangedListener
        if (NativeCore.nativeSendClipboard(text)) {
            Log.i(MyKvmService.TAG, "clipboard sent, ${text.length} characters")
        }
    }

    fun start() {
        if (listening) return
        clipboard.addPrimaryClipChangedListener(onChange)
        listening = true
        poll()
    }

    fun stop() {
        if (!listening) return
        clipboard.removePrimaryClipChangedListener(onChange)
        handler.removeCallbacks(pollTask)
        listening = false
    }

    /**
     * Picks up text the core received.
     *
     * Polled rather than pushed: applying a clip has to happen on the main
     * thread, and polling keeps the JNI boundary free of callbacks into the JVM
     * — the same reason input is polled.
     */
    private val pollTask = object : Runnable {
        override fun run() {
            NativeCore.nativeTakeClipboard().takeIf { it.isNotEmpty() }?.let { apply(it) }
            if (listening) handler.postDelayed(this, POLL_MS)
        }
    }

    private fun poll() = handler.post(pollTask)

    private fun apply(text: String) {
        applied = text
        runCatching {
            clipboard.setPrimaryClip(ClipData.newPlainText("MyKVM", text))
            Log.i(MyKvmService.TAG, "clipboard applied, ${text.length} characters")
        }.onFailure {
            // Writing is restricted the same way reading is; if the keyboard is
            // not the active one this is where it shows.
            Log.w(MyKvmService.TAG, "could not apply the clipboard", it)
        }
    }

    private fun readText(): String? {
        val clip = runCatching { clipboard.primaryClip }.getOrNull() ?: return null
        if (clip.itemCount == 0) return null
        return clip.getItemAt(0).coerceToText(context).toString().takeIf { it.isNotEmpty() }
    }

    private companion object {
        const val POLL_MS = 400L
    }
}
