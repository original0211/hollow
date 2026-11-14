package eu.org.brodydung.hollow

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import hollowcore.Hollowcore
import org.json.JSONObject
import session.Protector
import java.io.File

/**
 * Hollow VpnService: consent target, foreground form (specialUse, per
 * the NP-1114-30 FGS record), and — since M3-2 — the data plane.
 *
 * Restart policy (plan §2, NP-1114-33, verbatim discipline): when the
 * system restarts this service with a null intent after process death,
 * a session is rebuilt from stored config ONLY IF the user_enabled
 * state bit is on disk AND the stored config is complete with a valid
 * PSK. A user-stopped service, or broken config/key material, never
 * self-starts: the whole start fails closed.
 *
 * State bit lifecycle (this file is the only writer):
 *  - set:     on an explicit user ACTION_START, before starting.
 *  - cleared: on an explicit user ACTION_STOP, before tearing down.
 *  - kept:    on onRevoke (system-side revoke is not a user stop; the
 *             system will not resurrect a revoked VPN anyway, and the
 *             next explicit start re-runs the full flow regardless).
 *  - config validity is re-checked at every (re)start, never cached.
 */
class HollowVpnService : VpnService() {

    private var sessionRunning = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // Explicit user stop: clear the state bit FIRST, then
                // tear down. After this, a system restart must not
                // resurrect the session.
                prefs().edit().putBoolean(KEY_USER_ENABLED, false).apply()
                stopSession()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            ACTION_START -> {
                prefs().edit().putBoolean(KEY_USER_ENABLED, true).apply()
                if (!startSession()) {
                    // Explicit start with unusable config: fail closed
                    // and visible (no foreground ghost, no retry loop).
                    stopSelf()
                }
            }
            else -> {
                // Null intent (system restart after process death) or
                // any other system-driven start: the restart gate.
                val userEnabled = prefs().getBoolean(KEY_USER_ENABLED, false)
                if (!userEnabled || !startSession()) {
                    stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }

    /**
     * Brings the data plane up. Returns false — with nothing left
     * half-started — when the config is unusable, establish() fails,
     * or the Go session refuses to start.
     */
    private fun startSession(): Boolean {
        if (sessionRunning) return true
        val cfg = readConfig() ?: return false
        promoteToForeground()
        val pfd = try {
            Builder()
                .setSession("Hollow")
                .addAddress("10.99.0.1", 24)
                .addAddress("fd00::1", 64) // v6 must enter the TUN to be dropped, never bypass (plan §2)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("10.99.0.1")
                .setMtu(1280)
                .establish()
        } catch (e: Exception) {
            null
        } ?: return false
        // detachFd transfers fd ownership to the Go session (it closes
        // the fd on Stop); our own handle closes right after.
        val fd = pfd.detachFd()
        pfd.close()
        return try {
            Hollowcore.startVPN(cfg, fd, ProtectorBridge())
            sessionRunning = true
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun stopSession() {
        if (sessionRunning) {
            try { Hollowcore.stopVPN() } catch (_: Exception) {}
            sessionRunning = false
        }
    }

    /**
     * Stored config is complete iff the pairing-written file exists,
     * parses, and carries a non-empty wsUrl and pskHex. (M3-3 writes
     * this file from the hollow:// payload; until then a config placed
     * by hand is honored the same way.)
     */
    private fun readConfig(): String? {
        val f = File(filesDir, CONFIG_FILE)
        if (!f.exists()) return null
        val text = try { f.readText() } catch (e: Exception) { return null }
        val obj = try { JSONObject(text) } catch (e: Exception) { return null }
        if (obj.optString("wsUrl").isEmpty() || obj.optString("pskHex").isEmpty()) return null
        return text
    }

    private fun prefs() = getSharedPreferences(PREFS, MODE_PRIVATE)

    override fun onRevoke() {
        // The user revoked the VPN in system Settings: tear the whole
        // session down (pump stopped, core closed). The state bit is
        // KEPT per the restart policy above.
        stopSession()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopSession()
        super.onDestroy()
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

    /** gomobile bridge: VpnService.protect for every egress socket. */
    inner class ProtectorBridge : Protector {
        override fun protect(fd: Long): Boolean = this@HollowVpnService.protect(fd.toInt())
    }

    companion object {
        const val ACTION_START = "eu.org.brodydung.hollow.START"
        const val ACTION_STOP = "eu.org.brodydung.hollow.STOP"
        private const val CHANNEL_ID = "hollow-vpn"
        private const val NOTIFICATION_ID = 1
        private const val PREFS = "hollow-vpn"
        private const val KEY_USER_ENABLED = "user_enabled"
        private const val CONFIG_FILE = "hollow-config.json"
    }
}
