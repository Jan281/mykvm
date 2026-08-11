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
import android.provider.Settings as AndroidSettings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import de.mykvm.client.ui.MyKvmTheme
import de.mykvm.client.ui.Section
import de.mykvm.client.ui.StatusRow
import de.mykvm.client.ui.SwitchRow
import kotlinx.coroutines.delay

/**
 * The window onto the client: what it is doing, what it still needs, and the
 * handful of settings that mean anything on a phone.
 *
 * Everything shown is read from the core in the service's process, so this can
 * be destroyed and reopened without disturbing the connection.
 */
class MainActivity : ComponentActivity() {
    private lateinit var settings: Settings

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        settings = Settings(this)

        setContent {
            var theme by remember { mutableStateOf(settings.theme) }
            val dark = when (theme) {
                Settings.Theme.DARK -> true
                Settings.Theme.LIGHT -> false
                Settings.Theme.SYSTEM -> isSystemInDarkTheme()
            }

            MyKvmTheme(dark = dark) {
                Surface(
                    color = MaterialTheme.colorScheme.background,
                    modifier = Modifier.fillMaxSize(),
                ) {
                    Screen(theme = theme, onTheme = {
                        settings.theme = it
                        theme = it
                    })
                }
            }
        }
    }

    @Composable
    private fun Screen(theme: Settings.Theme, onTheme: (Settings.Theme) -> Unit) {
        // The pairing code appears when the desktop asks and expires on its
        // own, so the screen keeps itself current — at that moment the user is
        // looking at the desktop, not here.
        var tick by remember { mutableStateOf(0) }
        LaunchedEffect(Unit) {
            while (true) {
                delay(1000)
                tick++
            }
        }

        val status = remember(tick) { NativeCore.nativeStatus() }
        val code = remember(tick) { NativeCore.nativePairingCode() }
        val announced = remember(tick) { NativeCore.nativeKeyboardLayout() }
        val running = status != "stopped"

        Column(
            modifier = Modifier
                .fillMaxSize()
                // Without this the title sits under the status bar and the last
                // card under the navigation bar.
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Text(
                "MyKVM",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.SemiBold,
            )

            if (code.isNotEmpty()) {
                Section("Pairing") {
                    StatusRow("Type this on the desktop", code)
                }
            }

            Section("Connection") {
                StatusRow("Client", if (running) status else "stopped", ok = running)
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(onClick = { MyKvmService.start(this@MainActivity) }) { Text("Start") }
                    OutlinedButton(onClick = { MyKvmService.stop(this@MainActivity) }) {
                        Text("Stop")
                    }
                }
                warnIfTunnelled()?.let { StatusRow("Network", it, ok = false) }
            }

            PermissionsSection()
            SettingsSection(theme, onTheme, announced)
        }
    }

    @Composable
    private fun PermissionsSection() = Section("Permissions") {
        val notifications = hasNotificationPermission()
        StatusRow(
            "Notifications",
            if (notifications) "granted" else "needed for the running client",
            ok = notifications,
            actionLabel = if (notifications) null else "Grant",
            onAction = { requestNotifications() },
        )

        val overlay = AndroidSettings.canDrawOverlays(this@MainActivity)
        StatusRow(
            "Draw over other apps",
            if (overlay) "granted" else "the pointer stays invisible without it",
            ok = overlay,
            actionLabel = if (overlay) null else "Grant",
            onAction = { openOverlaySettings() },
        )

        val accessibility = hasAccessibility()
        StatusRow(
            "Accessibility",
            if (accessibility) "granted"
            else "clicks and scrolling do nothing — revoked by every reinstall",
            ok = accessibility,
            actionLabel = if (accessibility) null else "Open settings",
            onAction = {
                startActivity(Intent(AndroidSettings.ACTION_ACCESSIBILITY_SETTINGS))
            },
        )

        val keyboard = isSelectedKeyboard()
        StatusRow(
            "Keyboard",
            if (keyboard) "MyKVM is selected" else "typing does nothing until MyKVM is picked",
            ok = keyboard,
            actionLabel = if (keyboard) null else "Open settings",
            onAction = {
                startActivity(Intent(AndroidSettings.ACTION_INPUT_METHOD_SETTINGS))
            },
        )

        val battery = isBatteryExempt()
        StatusRow(
            "Battery optimisation",
            if (battery) "exempt" else "the client may be stopped in the background",
            ok = battery,
            actionLabel = if (battery) null else "Exempt",
            onAction = { requestBatteryExemption() },
        )
    }

    @Composable
    private fun SettingsSection(
        theme: Settings.Theme,
        onTheme: (Settings.Theme) -> Unit,
        announced: String,
    ) {
        var name by remember { mutableStateOf(settings.deviceName) }
        var port by remember { mutableStateOf(settings.discoveryPort.toString()) }
        var cursor by remember { mutableStateOf(settings.showCursor) }
        var wake by remember { mutableStateOf(settings.wakeOnInput) }
        var verbose by remember { mutableStateOf(settings.verboseLogging) }
        var paired by remember { mutableStateOf(MyKvmService.isPaired(this)) }

        Section("Settings") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Settings.Theme.entries.forEach { option ->
                    FilterChip(
                        selected = theme == option,
                        onClick = { onTheme(option) },
                        label = {
                            Text(option.name.lowercase().replaceFirstChar { it.uppercase() })
                        },
                    )
                }
            }

            OutlinedTextField(
                value = name,
                onValueChange = {
                    name = it
                    settings.deviceName = it
                },
                label = { Text("Device name") },
                supportingText = {
                    Text("Shown on the desktop. It feeds the peer id, so changing it means pairing again.")
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = port,
                onValueChange = { typed ->
                    port = typed.filter(Char::isDigit).take(5)
                    port.toIntOrNull()?.let { settings.discoveryPort = it }
                },
                label = { Text("Discovery port") },
                supportingText = { Text("Must match the desktop. 47833 unless you changed it there.") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            SwitchRow(
                label = "Show pointer",
                hint = "Turn off for a phone you only type on",
                checked = cursor,
                onChange = {
                    cursor = it
                    settings.showCursor = it
                },
            )

            SwitchRow(
                label = "Wake on arrival",
                hint = "Turn the screen on when the pointer comes over",
                checked = wake,
                onChange = {
                    wake = it
                    settings.wakeOnInput = it
                },
            )

            SwitchRow(
                label = "Verbose logging",
                hint = "Debug detail in logcat, for tracking something down",
                checked = verbose,
                onChange = {
                    verbose = it
                    settings.verboseLogging = it
                },
            )

            StatusRow(
                "Keyboard layout",
                if (announced.isEmpty()) "not announced yet — using the built-in default"
                else "$announced, from the controlling machine",
            )

            StatusRow(
                "Pairing",
                if (paired) "paired" else "not paired",
                ok = paired,
                actionLabel = if (paired) "Forget" else null,
                onAction = {
                    MyKvmService.forgetPairing(this@MainActivity)
                    MyKvmService.stop(this@MainActivity)
                    paired = false
                },
            )

            Text(
                "The name and port take effect when the client is restarted.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    private fun hasNotificationPermission(): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED

    private fun requestNotifications() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }

    private fun openOverlaySettings() {
        startActivity(
            Intent(
                AndroidSettings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:$packageName"),
            ),
        )
    }

    private fun hasAccessibility(): Boolean =
        AndroidSettings.Secure.getString(
            contentResolver,
            AndroidSettings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ).orEmpty().contains(packageName)

    private fun isSelectedKeyboard(): Boolean =
        AndroidSettings.Secure.getString(
            contentResolver,
            AndroidSettings.Secure.DEFAULT_INPUT_METHOD,
        ).orEmpty().contains(packageName)

    private fun isBatteryExempt(): Boolean =
        getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)

    private fun requestBatteryExemption() {
        startActivity(
            Intent(
                AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:$packageName"),
            ),
        )
    }

    /**
     * A VPN that declares itself non-bypassable covers every UID, and the
     * system refuses to let an app route around it — binding to Wi-Fi succeeds
     * and changes nothing. The symptom is a one-way network: broadcasts from
     * the LAN still arrive, while everything sent vanishes into the tunnel.
     */
    private fun warnIfTunnelled(): String? {
        val manager = getSystemService(ConnectivityManager::class.java) ?: return null
        @Suppress("DEPRECATION")
        val tunnelled = manager.allNetworks.any { network ->
            val capabilities = manager.getNetworkCapabilities(network) ?: return@any false
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        return if (tunnelled) {
            "A VPN is active. Allow LAN connections in its settings, or no peer will appear."
        } else {
            null
        }
    }
}
