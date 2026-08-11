package de.mykvm.client

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.WindowManager

/**
 * The pointer, drawn by us.
 *
 * Android will not give an app a real system cursor without root, so this is a
 * window that follows the absolute coordinates the desktop sends. That turns
 * out to be an advantage: the pointer sits exactly where `edge_entry_point`
 * computed it, with no acceleration or rounding in between, which is what makes
 * a crossing land where the layout says it should.
 */
class CursorOverlay(private val context: Context) {
    private val windowManager =
        context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private val view = ArrowView(context)

    private var attached = false
    private var pendingX = 0
    private var pendingY = 0
    private var moveScheduled = false

    private val params = WindowManager.LayoutParams(
        WindowManager.LayoutParams.WRAP_CONTENT,
        WindowManager.LayoutParams.WRAP_CONTENT,
        WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
        // NOT_TOUCHABLE is the important one: without it the drawn pointer would
        // swallow real finger taps wherever it happens to sit. NOT_FOCUSABLE
        // keeps it from stealing key input from whatever is actually on screen,
        // and NO_LIMITS lets it reach the very edges, including under the
        // status bar where a crossing often arrives.
        WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
            WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
        PixelFormat.TRANSLUCENT,
    ).apply { gravity = Gravity.TOP or Gravity.START }

    /** Whether the user has granted "display over other apps". */
    fun canShow(): Boolean = Settings.canDrawOverlays(context)

    /**
     * Moves the pointer to an absolute position on this screen.
     *
     * Called from the event thread at the rate the desktop sends motion —
     * thousands per crossing — so the position is only stored here and applied
     * once per frame. Handing every single event to the window manager would
     * spend more time laying out than drawing.
     */
    fun moveTo(x: Int, y: Int) {
        pendingX = x
        pendingY = y
        if (moveScheduled) return
        moveScheduled = true
        handler.post {
            moveScheduled = false
            apply(pendingX, pendingY)
        }
    }

    private fun apply(x: Int, y: Int) {
        if (!canShow()) return

        params.x = x
        params.y = y
        if (!attached) {
            try {
                windowManager.addView(view, params)
                attached = true
            } catch (error: Throwable) {
                Log.e(MyKvmService.TAG, "could not show the pointer", error)
                return
            }
        } else {
            windowManager.updateViewLayout(view, params)
        }
    }

    /** Takes the pointer off screen — the cursor has gone back to the desktop. */
    fun hide() {
        handler.post {
            if (!attached) return@post
            runCatching { windowManager.removeView(view) }
            attached = false
        }
    }

    /**
     * An arrow with an outline, so it stays visible on light and dark content
     * alike — this floats over other apps and cannot assume a background.
     */
    private class ArrowView(context: Context) : View(context) {
        private val scale = context.resources.displayMetrics.density
        private val fill = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            style = Paint.Style.FILL
        }
        private val outline = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.BLACK
            style = Paint.Style.STROKE
            strokeWidth = 1.5f * scale
        }
        private val arrow = Path()

        override fun onMeasure(widthSpec: Int, heightSpec: Int) {
            val size = (24 * scale).toInt()
            setMeasuredDimension(size, size)
        }

        override fun onDraw(canvas: Canvas) {
            if (arrow.isEmpty) {
                // The classic pointer, its tip at (0,0) so the hotspot is the
                // window position itself — no offset to keep in sync.
                arrow.moveTo(0f, 0f)
                arrow.lineTo(0f, 17f * scale)
                arrow.lineTo(4.2f * scale, 13f * scale)
                arrow.lineTo(7f * scale, 19f * scale)
                arrow.lineTo(9.5f * scale, 18f * scale)
                arrow.lineTo(6.8f * scale, 12f * scale)
                arrow.lineTo(12f * scale, 11.5f * scale)
                arrow.close()
            }
            canvas.drawPath(arrow, fill)
            canvas.drawPath(arrow, outline)
        }
    }
}
