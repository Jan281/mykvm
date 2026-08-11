package de.mykvm.client

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Brings the client back after a reboot.
 *
 * This is the whole reason the accessibility route was chosen over Shizuku:
 * once set up, the phone rejoins by itself and the user never has to think
 * about it again.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        if (!MyKvmService.isPaired(context)) {
            // Nothing to receive yet, and a permanent notification for an
            // unconfigured app is just noise.
            Log.i(MyKvmService.TAG, "not paired yet; staying off after boot")
            return
        }

        Log.i(MyKvmService.TAG, "starting after boot")
        MyKvmService.start(context)
    }
}
