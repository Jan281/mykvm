package de.mykvm.client

import android.accessibilityservice.AccessibilityService
import android.util.Log
import android.view.accessibility.AccessibilityEvent

/**
 * The hands of the client.
 *
 * The core cannot reach this directly — Android owns the lifecycle of an
 * accessibility service and hands out no reference — so it publishes itself
 * here while connected. A null [instance] simply means the user has not
 * enabled it yet, which is a state the rest of the app has to tolerate rather
 * than crash on.
 */
class MyKvmAccessibilityService : AccessibilityService() {
    private var actions: PointerActions? = null

    override fun onServiceConnected() {
        super.onServiceConnected()
        actions = PointerActions(this)
        instance = this
        Log.i(MyKvmService.TAG, "accessibility service connected")
    }

    override fun onDestroy() {
        instance = null
        actions = null
        Log.i(MyKvmService.TAG, "accessibility service gone")
        super.onDestroy()
    }

    // Nothing is observed; this service exists to act. The event types the
    // config subscribes to are what keeps the window content queryable for
    // scrolling.
    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit

    override fun onInterrupt() = Unit

    fun press(x: Int, y: Int) = actions?.press(x, y)

    fun release(x: Int, y: Int, longPress: Boolean) = actions?.release(x, y, longPress)

    fun scroll(x: Int, y: Int, notches: Int) = actions?.scroll(x, y, notches)

    companion object {
        @Volatile
        var instance: MyKvmAccessibilityService? = null
            private set
    }
}
