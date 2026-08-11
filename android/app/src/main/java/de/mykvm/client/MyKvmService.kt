package de.mykvm.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.hardware.display.DisplayManager
import android.view.Display
import android.view.WindowManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import java.io.File

/**
 * Owns the running core.
 *
 * The activity is only a window onto this: Android is free to destroy it at any
 * time, and a KVM client that stops receiving the moment its screen is
 * backgrounded would be useless. The notification is not a courtesy — the
 * system requires one for a service that keeps running.
 */
class MyKvmService : Service() {
    private var events: CoreEvents? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private var cursor: CursorOverlay? = null
    /** Where the drawn pointer sits — clicks are dispatched here. */
    private var pointerX = 0
    private var pointerY = 0

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.service_starting)))

        if (events != null) {
            updateNotification()
            return START_STICKY
        }

        acquireMulticastLock()
        bindToWifi()
        cursor = CursorOverlay(this).also {
            if (!it.canShow()) {
                Log.w(TAG, "no overlay permission; the pointer will stay invisible")
            }
        }

        val (width, height) = screenSize()
        val error = NativeCore.nativeStart(
            Build.MODEL ?: "Android",
            DISCOVERY_PORT,
            width,
            height,
            filesDir.absolutePath,
        )

        if (error.isNotEmpty()) {
            Log.e(TAG, "core failed to start: $error")
            // Say why in the one place the user can still see, then stop rather
            // than sit there with a notification claiming to work.
            updateNotification(getString(R.string.service_failed, error))
            return START_NOT_STICKY
        }

        events = CoreEvents { kind, p1, p2 -> onInput(kind, p1, p2) }.also { it.start() }
        getSystemService(DisplayManager::class.java)?.registerDisplayListener(displays, null)
        updateNotification()
        // START_STICKY: if Android reclaims us under memory pressure, come back.
        return START_STICKY
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        reportScreenSize()
    }

    /**
     * Watches for rotation.
     *
     * A service is not a UI context, so its configuration callback is not a
     * dependable signal for this — the display listener is. Rotating swaps
     * width and height, and the desktop's layout has to learn that or a
     * crossing keeps aiming at an edge that no longer exists.
     */
    private val displays = object : DisplayManager.DisplayListener {
        override fun onDisplayChanged(displayId: Int) = reportScreenSize()
        override fun onDisplayAdded(displayId: Int) = Unit
        override fun onDisplayRemoved(displayId: Int) = Unit
    }

    /**
     * The real size of the screen right now.
     *
     * Deliberately not `resources.displayMetrics`: a service holds an
     * application context, whose metrics do not follow rotation, so that would
     * report the startup size forever.
     */
    private fun screenSize(): Pair<Int, Int> {
        val display = getSystemService(DisplayManager::class.java)
            ?.getDisplay(Display.DEFAULT_DISPLAY)
            ?: return resources.displayMetrics.let { it.widthPixels to it.heightPixels }

        // A *window* context, not merely a display context: metrics from a
        // non-UI context are documented as unreliable, and that is exactly the
        // trap here — it would keep reporting the size at startup.
        val bounds = createDisplayContext(display)
            .createWindowContext(WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY, null)
            .getSystemService(WindowManager::class.java)
            .currentWindowMetrics
            .bounds
        return bounds.width() to bounds.height()
    }

    private fun reportScreenSize() {
        val (width, height) = screenSize()
        // Logged on arrival rather than on change: a callback that never fires
        // and a size that never changes look identical from the core's log.
        Log.d(TAG, "display reports ${width}x$height")
        NativeCore.nativeSetScreen(width, height)
    }

    override fun onDestroy() {
        getSystemService(DisplayManager::class.java)?.unregisterDisplayListener(displays)
        idle.removeCallbacks(hideCursor)
        cursor?.hide()
        cursor = null
        events?.stop()
        events = null
        NativeCore.nativeStop()
        multicastLock?.let { if (it.isHeld) it.release() }
        multicastLock = null
        Log.i(TAG, "service stopped")
        super.onDestroy()
    }

    private fun onInput(kind: Int, p1: Int, p2: Int) {
        when (kind) {
            NativeCore.KIND_MOUSE_MOVE -> {
                pointerX = p1
                pointerY = p2
                cursor?.moveTo(p1, p2)
                keepCursorVisible()
            }

            NativeCore.KIND_MOUSE_BUTTON -> onButton(button = p1, down = p2 != 0)

            // A wheel notch is positive upwards on the wire, the same
            // convention the Windows receiver uses.
            NativeCore.KIND_SCROLL -> reachOrWarn()?.scroll(pointerX, pointerY, p2)

            NativeCore.KIND_KEY -> onKey(vk = p1, down = p2 != 0)

            else -> Log.i(TAG, "input kind=$kind p1=$p1 p2=$p2")
        }
    }

    /**
     * Modifiers are tracked here rather than in the input method, because they
     * have to survive the input method being torn down and rebuilt — Android
     * recreates it freely, and a Shift that went down before that would
     * otherwise stay stuck.
     */
    private var modifiers = MyKvmInputMethod.Modifiers()

    private fun onKey(vk: Int, down: Boolean) {
        if (KeyMap.isModifier(vk)) {
            modifiers = when (vk) {
                0x10, 0xA0, 0xA1 -> modifiers.copy(shift = down)
                0x11, 0xA2, 0xA3 -> modifiers.copy(ctrl = down)
                0x12, 0xA4 -> modifiers.copy(alt = down)
                // Right Alt is AltGr on a German keyboard, and that is a
                // different thing from Alt: it produces characters.
                0xA5 -> modifiers.copy(altGr = down)
                else -> modifiers
            }
            return
        }

        adoptAnnouncedLayout()

        val keyboard = MyKvmInputMethod.instance
        if (keyboard == null) {
            warnNoKeyboard()
            return
        }
        keyboard.onRemoteKey(vk, down, modifiers)
    }

    private var lastAnnouncedLayout = ""

    /**
     * Takes the keyboard layout from the machine doing the typing.
     *
     * Key codes on the wire are positional so that each receiver applies its
     * own layout — but a phone has none for injected keys, so it borrows the
     * controlling machine's rather than guessing. Read per keystroke because
     * that is rare enough for the cost not to matter, and it means a layout
     * change on the desktop takes effect without restarting anything.
     */
    private fun adoptAnnouncedLayout() {
        val announced = NativeCore.nativeKeyboardLayout()
        if (announced == lastAnnouncedLayout) return
        lastAnnouncedLayout = announced

        val layout = KeyMap.Layout.parse(announced)
        if (layout == null) {
            if (announced.isNotEmpty()) Log.w(TAG, "unknown keyboard layout '$announced'")
            return
        }
        Log.i(TAG, "typing as $layout, announced as '$announced'")
        MyKvmInputMethod.layout = layout
    }

    private var warnedAboutKeyboard = false

    private fun warnNoKeyboard() {
        if (warnedAboutKeyboard) return
        warnedAboutKeyboard = true
        Log.w(TAG, "MyKVM is not the selected keyboard; typing does nothing")
        updateNotification(getString(R.string.needs_keyboard))
    }

    /**
     * A press only records where it began; the release decides whether that was
     * a click, a long press or a drag. Middle and side buttons have no meaning
     * on a touch screen and are dropped rather than mapped to something
     * arbitrary.
     */
    private fun onButton(button: Int, down: Boolean) {
        val hands = reachOrWarn() ?: return
        when (button) {
            BUTTON_LEFT -> if (down) hands.press(pointerX, pointerY)
                else hands.release(pointerX, pointerY, longPress = false)
            // Right-click is long-press on Android; that is what opens a
            // context menu here, so it is a translation rather than a guess.
            BUTTON_RIGHT -> if (down) hands.press(pointerX, pointerY)
                else hands.release(pointerX, pointerY, longPress = true)
            else -> Log.d(TAG, "ignoring button $button")
        }
    }

    /**
     * The accessibility service, or a warning naming why nothing happened —
     * a click that silently does nothing is the worst possible feedback.
     */
    private fun reachOrWarn(): MyKvmAccessibilityService? {
        val hands = MyKvmAccessibilityService.instance
        if (hands == null) warnOnce()
        return hands
    }

    private var warnedAboutAccessibility = false

    private fun warnOnce() {
        if (warnedAboutAccessibility) return
        warnedAboutAccessibility = true
        Log.w(TAG, "accessibility service is off; clicks and scrolling do nothing")
        updateNotification(getString(R.string.needs_accessibility))
    }

    /**
     * Hides the pointer once input stops arriving.
     *
     * The desktop does not announce that the cursor left — it simply stops
     * sending — so silence is the only signal we get. Anything shorter than
     * this would blink the pointer away during a pause in movement.
     */
    private fun keepCursorVisible() {
        idle.removeCallbacks(hideCursor)
        idle.postDelayed(hideCursor, CURSOR_IDLE_MS)
    }

    private val idle = Handler(Looper.getMainLooper())
    private val hideCursor = Runnable { cursor?.hide() }

    private fun buildNotification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.channel_name),
                    // Low: this notification exists because the system demands
                    // one, not because it has anything to announce.
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { setShowBadge(false) },
            )
        }

        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, MyKvmService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentIntent(open)
            .addAction(
                Notification.Action.Builder(null, getString(R.string.action_stop), stop).build(),
            )
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String = NativeCore.nativeStatus()) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }

    /**
     * Without this, Android's Wi-Fi stack filters inbound broadcast before it
     * reaches any socket, and discovery is deaf while looking healthy.
     */
    private fun acquireMulticastLock() {
        if (multicastLock?.isHeld == true) return
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifi.createMulticastLock("mykvm-discovery").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    /**
     * Keeps a LAN protocol off mobile data. Not a way around a VPN — see
     * [MainActivity.warnIfTunnelled] for why that cannot work.
     */
    private fun bindToWifi() {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        @Suppress("DEPRECATION")
        val wifi = manager.allNetworks.firstOrNull { network ->
            manager.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
        if (wifi == null) {
            Log.w(TAG, "no Wi-Fi network to bind to; leaving routing alone")
            return
        }
        manager.bindProcessToNetwork(wifi)
    }

    companion object {
        const val TAG = "mykvm"
        const val ACTION_STOP = "de.mykvm.client.STOP"
        private const val CHANNEL_ID = "mykvm"
        private const val NOTIFICATION_ID = 1
        private const val DISCOVERY_PORT = 47833
        private const val CURSOR_IDLE_MS = 2000L
        // Ordinals from the core's flatten(): Left, Right, Middle, Back, Forward.
        private const val BUTTON_LEFT = 0
        private const val BUTTON_RIGHT = 1

        fun start(context: Context) {
            context.startForegroundService(Intent(context, MyKvmService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, MyKvmService::class.java))
        }

        /**
         * Whether pairing has already happened, read from the file the core
         * writes. Used to decide whether starting on boot makes any sense: an
         * unpaired client would only put a permanent notification on screen
         * with nothing to receive.
         */
        fun isPaired(context: Context): Boolean {
            val file = File(context.filesDir, "pairing.txt")
            return file.isFile && file.readText().lines().let { lines ->
                lines.size >= 2 && lines[0].isNotBlank() && lines[1].isNotBlank()
            }
        }
    }
}
