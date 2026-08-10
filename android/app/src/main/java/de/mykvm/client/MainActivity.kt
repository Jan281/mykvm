package de.mykvm.client

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/**
 * The smoke-test screen: start the core, show what it sees, log every event.
 *
 * Deliberately not a service yet. This exists to answer one question — do
 * discovery and QUIC work on a phone at all — before three Android components
 * are built on top of that assumption.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var status: TextView
    private lateinit var log: TextView
    private var events: CoreEvents? = null
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = TextView(this).apply { setPadding(0, 0, 0, 24) }
        log = TextView(this)
        val start = Button(this).apply {
            text = "Start"
            setOnClickListener { startCore() }
        }
        val stop = Button(this).apply {
            text = "Stop"
            setOnClickListener { stopCore() }
        }
        val refresh = Button(this).apply {
            text = "Status"
            setOnClickListener { showStatus() }
        }

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
            addView(status)
            addView(start)
            addView(stop)
            addView(refresh)
            addView(log)
        }
        setContentView(ScrollView(this).apply { addView(column) })

        status.text = "idle"
    }

    private fun startCore() {
        if (events != null) {
            showStatus()
            return
        }

        // Without this, Android's Wi-Fi stack filters broadcast packets before
        // they ever reach the socket — discovery would be deaf while looking
        // perfectly healthy from the inside.
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
            status.text = "start failed: $error"
            Log.e(TAG, "start failed: $error")
            return
        }

        events = CoreEvents { kind, p1, p2 -> onInput(kind, p1, p2) }.also { it.start() }
        showStatus()
    }

    private fun stopCore() {
        events?.stop()
        events = null
        NativeCore.nativeStop()
        multicastLock?.let { if (it.isHeld) it.release() }
        multicastLock = null
        status.text = "stopped"
    }

    private fun showStatus() {
        status.text = NativeCore.nativeStatus()
    }

    private fun onInput(kind: Int, p1: Int, p2: Int) {
        val line = when (kind) {
            NativeCore.KIND_MOUSE_MOVE -> "move $p1,$p2"
            NativeCore.KIND_MOUSE_BUTTON -> "button $p1 down=$p2"
            NativeCore.KIND_SCROLL -> "scroll $p1,$p2"
            NativeCore.KIND_KEY -> "key 0x${p1.toString(16)} down=$p2"
            else -> "unknown $kind"
        }
        Log.i(TAG, line)
        // Only moves are frequent enough to flood the view; the rest is rare.
        if (kind != NativeCore.KIND_MOUSE_MOVE) {
            runOnUiThread { log.append("$line\n") }
        }
    }

    /**
     * Pins this process's sockets to Wi-Fi.
     *
     * A VPN takes over the default route and swallows everything the app sends,
     * which shows up as a maddening asymmetry: the phone hears the desktop's
     * broadcasts on Wi-Fi, but nothing it sends ever leaves the tunnel. Binding
     * has to happen before the core opens any socket, since existing ones are
     * not moved.
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
        Log.i(TAG, "bound process to Wi-Fi")
    }

    private fun acquireMulticastLock() {
        if (multicastLock?.isHeld == true) return
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifi.createMulticastLock("mykvm-discovery").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    override fun onDestroy() {
        stopCore()
        super.onDestroy()
    }

    private companion object {
        const val TAG = "mykvm"
        const val DISCOVERY_PORT = 47833
    }
}
