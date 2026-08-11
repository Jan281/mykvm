package de.mykvm.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
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

        val metrics = resources.displayMetrics
        val error = NativeCore.nativeStart(
            Build.MODEL ?: "Android",
            DISCOVERY_PORT,
            metrics.widthPixels,
            metrics.heightPixels,
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
        updateNotification()
        // START_STICKY: if Android reclaims us under memory pressure, come back.
        return START_STICKY
    }

    override fun onDestroy() {
        events?.stop()
        events = null
        NativeCore.nativeStop()
        multicastLock?.let { if (it.isHeld) it.release() }
        multicastLock = null
        Log.i(TAG, "service stopped")
        super.onDestroy()
    }

    private fun onInput(kind: Int, p1: Int, p2: Int) {
        // Nothing acts on input yet — the cursor and the accessibility service
        // come next. Until then this proves the pipeline is alive.
        if (kind != NativeCore.KIND_MOUSE_MOVE) {
            Log.i(TAG, "input kind=$kind p1=$p1 p2=$p2")
        }
    }

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
