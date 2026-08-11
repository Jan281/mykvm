package de.mykvm.client

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.graphics.Rect
import android.util.Log
import android.view.accessibility.AccessibilityNodeInfo
import kotlin.math.abs
import kotlin.math.hypot

/**
 * Turns remote mouse actions into things Android will actually do.
 *
 * Without root there is no way to inject a pointer event, so a click becomes a
 * dispatched tap at the coordinates our drawn cursor sits at, and a wheel
 * notch becomes a scroll action on whatever view is under it. On a phone that
 * is less of a compromise than it sounds: these apps are built for fingers, so
 * a tap *is* the native gesture. What genuinely does not exist is hovering.
 */
class PointerActions(private val service: AccessibilityService) {

    /** Where the button went down, so a release can tell a drag from a click. */
    private var pressedAt: Pair<Int, Int>? = null

    fun press(x: Int, y: Int) {
        pressedAt = x to y
    }

    /**
     * Completes a press. A pointer that barely moved is a click; one that
     * travelled is a drag, dispatched as a single stroke from origin to
     * release.
     *
     * The intermediate path is deliberately dropped. Following it faithfully
     * would mean chaining a continued stroke per motion event — hundreds per
     * second — and every app that matters treats a drag by where it started
     * and where it ended.
     */
    fun release(x: Int, y: Int, longPress: Boolean) {
        val (startX, startY) = pressedAt ?: (x to y)
        pressedAt = null

        val distance = hypot((x - startX).toFloat(), (y - startY).toFloat())
        if (distance > DRAG_THRESHOLD) {
            dispatch(strokeBetween(startX, startY, x, y, DRAG_MS), "drag")
            return
        }

        val duration = if (longPress) LONG_PRESS_MS else TAP_MS
        dispatch(strokeBetween(startX, startY, startX, startY, duration), "tap")
    }

    /**
     * Scrolls whatever sits under the pointer.
     *
     * Asking the view to scroll beats faking a swipe: it lands on the right
     * container even when the pointer is over a small list inside a page, and
     * it does not fling. The swipe is kept as a fallback for views that expose
     * no scroll action.
     */
    fun scroll(x: Int, y: Int, notches: Int) {
        if (notches == 0) return

        val action = if (notches > 0) {
            AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
        } else {
            AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
        }

        val target = scrollableUnder(x, y)
        if (target != null) {
            repeat(abs(notches).coerceAtMost(MAX_NOTCHES_PER_EVENT)) {
                target.performAction(action)
            }
            return
        }

        // Nothing claimed to be scrollable; swipe instead. Positive notches
        // mean scrolling up, so the content follows the finger downwards.
        val travel = (SWIPE_PER_NOTCH * notches).coerceIn(-SWIPE_MAX, SWIPE_MAX)
        dispatch(strokeBetween(x, y, x, y + travel, SWIPE_MS), "swipe")
    }

    /** The nearest scrollable ancestor of whatever is drawn at this point. */
    private fun scrollableUnder(x: Int, y: Int): AccessibilityNodeInfo? {
        val root = service.rootInActiveWindow ?: return null
        var node = deepestNodeAt(root, x, y) ?: return null
        while (!node.isScrollable) {
            node = node.parent ?: return null
        }
        return node
    }

    private fun deepestNodeAt(node: AccessibilityNodeInfo, x: Int, y: Int): AccessibilityNodeInfo? {
        val bounds = Rect()
        node.getBoundsInScreen(bounds)
        if (!bounds.contains(x, y)) return null

        for (index in 0 until node.childCount) {
            val child = node.getChild(index) ?: continue
            deepestNodeAt(child, x, y)?.let { return it }
        }
        return node
    }

    private fun strokeBetween(
        fromX: Int,
        fromY: Int,
        toX: Int,
        toY: Int,
        durationMs: Long,
    ): GestureDescription {
        val path = Path().apply {
            moveTo(fromX.toFloat(), fromY.toFloat())
            lineTo(toX.toFloat(), toY.toFloat())
        }
        return GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, durationMs))
            .build()
    }

    private fun dispatch(gesture: GestureDescription, what: String) {
        // A gesture is refused rather than queued while another is in flight,
        // and on protected surfaces it never starts at all — worth a line,
        // because from the desktop it looks like the click simply vanished.
        val accepted = service.dispatchGesture(gesture, null, null)
        if (!accepted) Log.w(MyKvmService.TAG, "$what was refused")
    }

    private companion object {
        const val TAP_MS = 60L
        const val LONG_PRESS_MS = 600L
        const val DRAG_MS = 250L
        const val SWIPE_MS = 120L
        /** Below this, a release is a click rather than a drag. */
        const val DRAG_THRESHOLD = 12f
        const val SWIPE_PER_NOTCH = 220
        const val SWIPE_MAX = 1200
        const val MAX_NOTCHES_PER_EVENT = 5
    }
}
