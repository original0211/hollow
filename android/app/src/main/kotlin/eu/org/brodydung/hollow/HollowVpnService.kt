package eu.org.brodydung.hollow

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build

/**
 * M3-0 skeleton: consent target + foreground form only.
 *
 * Deliberately does NOT call Builder().establish() — without the data
 * plane (M3-2) an established TUN would blackhole all traffic. This
 * class proves the manifest declaration, the specialUse foreground
 * promotion (NP-1114-30 FGS record), and the revoke/stop teardown.
 */
class HollowVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            teardown()
            return START_NOT_STICKY
        }
        promoteToForeground()
        // M3-2: Builder().addAddress(...).addRoute(...).addDnsServer(...)
        //        .establish() and hand the fd to the Go pump.
        return START_NOT_STICKY
    }

    private fun promoteToForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.vpn_notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock) // placeholder icon; real asset in M3-4
            .build()
        // API 34 form: the three-arg startForeground with the declared
        // type constant; below 34 the two-arg form is the only one.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun teardown() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        // User revoked the VPN consent in system Settings: the system
        // has already torn the session down; just leave cleanly.
        teardown()
        super.onRevoke()
    }

    companion object {
        const val ACTION_STOP = "eu.org.brodydung.hollow.STOP"
        private const val CHANNEL_ID = "hollow-vpn"
        private const val NOTIFICATION_ID = 1
    }
}
