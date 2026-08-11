package de.mykvm.client

import android.util.Log
import kotlin.concurrent.thread

/**
 * The one thread that drains the Rust event queue.
 *
 * [NativeCore.nativePoll] blocks on a channel, so it wakes the instant an event
 * arrives — the timeout is only how often the loop gets a chance to notice it
 * should stop, not a polling interval.
 */
class CoreEvents(private val onEvent: (kind: Int, p1: Int, p2: Int) -> Unit) {
    @Volatile
    private var running = false
    private var worker: Thread? = null

    fun start() {
        if (running) return
        running = true
        worker = thread(name = "mykvm-events") {
            Log.i(TAG, "event loop started")
            while (running) {
                val event = try {
                    NativeCore.nativePoll(POLL_TIMEOUT_MS)
                } catch (error: Throwable) {
                    Log.e(TAG, "poll failed", error)
                    null
                } ?: continue

                try {
                    onEvent(event[0], event[1], event[2])
                } catch (error: Throwable) {
                    // One bad event must not take the loop down with it.
                    Log.e(TAG, "handler threw", error)
                }
            }
            Log.i(TAG, "event loop stopped")
        }
    }

    fun stop() {
        running = false
        worker?.join(2 * POLL_TIMEOUT_MS.toLong())
        worker = null
    }

    private companion object {
        const val TAG = "mykvm"
        const val POLL_TIMEOUT_MS = 250
    }
}
