package de.mykvm.client

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

/**
 * The setup screen.
 *
 * It starts and stops the service and walks the user through the system
 * switches Android will not grant an app on its own. Everything it shows is
 * read from the core, which lives in the service's process — so this window can
 * be destroyed and reopened without disturbing anything.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = TextView(this).apply { setPadding(0, 0, 0, 32) }

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
            addView(status)
            addView(button("Start") { MyKvmService.start(this@MainActivity) })
            addView(button("Stop") { MyKvmService.stop(this@MainActivity) })
            addView(button("Allow notifications") { requestNotifications() })
            addView(button("Ignore battery optimisation") { requestBatteryExemption() })
            addView(button("Allow drawing over other apps") { requestOverlay() })
            addView(button("Enable accessibility service") { openAccessibilitySettings() })
            addView(button("Choose MyKVM as keyboard") { openKeyboardSettings() })
        }
        setContentView(ScrollView(this).apply { addView(column) })
    }

    override fun onResume() {
        super.onResume()
        status.post(refresh)
    }

    override fun onPause() {
        status.removeCallbacks(refresh)
        super.onPause()
    }

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        setOnClickListener { onClick() }
    }

    /**
     * Redraws once a second while the window is open.
     *
     * The pairing code appears when the desktop asks for it and expires on its
     * own, so it has to show up without the user tapping anything — at that
     * moment they are looking at the desktop, not at the phone.
     */
    private val refresh = object : Runnable {
        override fun run() {
            showStatus()
            status.postDelayed(this, 1000)
        }
    }

    private fun showStatus() {
        val code = NativeCore.nativePairingCode()
        status.text = listOfNotNull(
            if (code.isEmpty()) null else "Pairing code: $code",
            NativeCore.nativeStatus(),
            batteryHint(),
            overlayHint(),
            accessibilityHint(),
            keyboardHint(),
            warnIfTunnelled(),
        ).joinToString("\n\n")
    }

    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            == PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }

    /**
     * Android will otherwise put the service to sleep after a while of screen-
     * off, and the phone silently drops out of the cluster.
     */
    private fun requestBatteryExemption() {
        if (isBatteryExempt()) return
        startActivity(
            Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:$packageName"),
            ),
        )
    }

    /**
     * The pointer lives in a window over other apps, which Android only grants
     * from its own settings screen — there is no in-app dialog for it.
     */
    private fun requestOverlay() {
        if (Settings.canDrawOverlays(this)) return
        startActivity(
            Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName"),
            ),
        )
    }

    /**
     * Android revokes the accessibility grant on every reinstall — an update
     * must not inherit rights that powerful — so this is not a one-time step
     * during development, and the hint has to stay visible.
     */
    private fun openAccessibilitySettings() {
        startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
    }

    private fun openKeyboardSettings() {
        startActivity(Intent(Settings.ACTION_INPUT_METHOD_SETTINGS))
    }

    private fun accessibilityHint(): String? {
        val enabled = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ).orEmpty().contains(packageName)
        return if (enabled) null
        else "Accessibility is off; clicks and scrolling do nothing. It is revoked by every reinstall."
    }

    private fun keyboardHint(): String? {
        val current = Settings.Secure.getString(
            contentResolver,
            Settings.Secure.DEFAULT_INPUT_METHOD,
        ).orEmpty()
        return if (current.contains(packageName)) null
        else "MyKVM is not the selected keyboard; typing does nothing."
    }

    private fun overlayHint(): String? =
        if (Settings.canDrawOverlays(this)) null
        else "Drawing over other apps is off; the pointer stays invisible."

    private fun isBatteryExempt(): Boolean =
        getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)

    private fun batteryHint(): String? =
        if (isBatteryExempt()) null else "Battery optimisation is on; the client may be stopped in the background."

    /**
     * Names the one condition that makes MyKVM look broken for no visible
     * reason, rather than letting the user hunt for it.
     *
     * A VPN that declares itself non-bypassable covers every UID, and the
     * system refuses to let an app route around it — binding to Wi-Fi succeeds
     * and changes nothing. The symptom is a one-way network: broadcasts from
     * the LAN still arrive, while everything sent disappears into the tunnel.
     * The fix lives in the VPN's settings (Proton: Connection, Advanced, LAN
     * connections), not in this app.
     */
    private fun warnIfTunnelled(): String? {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        val tunnelled = manager.allNetworks.any { network ->
            val capabilities = manager.getNetworkCapabilities(network) ?: return@any false
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }

        if (!tunnelled) return null
        Log.w(MyKvmService.TAG, "a non-bypassable VPN is active")
        return "A VPN is active. If no peer appears, allow LAN connections in its settings."
    }
}
