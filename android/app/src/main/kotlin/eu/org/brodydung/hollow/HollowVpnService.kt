package eu.org.brodydung.hollow

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import hollowcore.Hollowcore
import hollowcore.Protector

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
 *  - persistence is SYNCHRONOUS (commit(), NP-1114-37): apply() is
 *    async, and a hard kill between the user's stop and the flush
 *    would leave a stale "enabled" bit that resurrects a session the
 *    user stopped — the exact failure this bit exists to prevent.
 *    Failure semantics are fail-closed both ways:
 *      set fails   -> the session is NOT started (start evidence must
 *                     be durable before a session may exist);
 *      clear fails -> the live session is still torn down (the user's
 *                     stop always wins in-process), the failure is
 *                     logged, and the stale bit is left as-is for the
 *                     next start to re-read — residue is visible in
 *                     the log, never silently "assumed stopped".
 */
class HollowVpnService : VpnService() {

    private var sessionRunning = false
    private var notifThread: Thread? = null

    /** Notification text from the facade state (M3-4): state label,
     *  elapsed time, and the two counters a glance should carry. */
    private fun notifText(): String {
        return try {
            val st = org.json.JSONObject(Hollowcore.vpnStateJSON())
            val label = when (st.optString("state")) {
                "connected" -> "已连接"
                "connecting" -> "连接中"
                "error" -> "连接失败"
                else -> "未连接"
            }
            val stats = st.optJSONObject("stats")
            val dns = stats?.optLong("dnsQueries") ?: 0
            val drops = (stats?.optLong("droppedUdp") ?: 0) + (stats?.optLong("droppedV6") ?: 0)
            "Hollow $label · DNS 查询 $dns · 丢弃 $drops"
        } catch (e: Exception) {
            "Hollow 隧道运行中"
        }
    }

    private fun startNotifTicker() {
        stopNotifTicker()
        notifThread = Thread {
            while (!Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(2000)
                } catch (e: InterruptedException) {
                    break
                }
                if (!sessionRunning) break
                try {
                    val nm = getSystemService(NotificationManager::class.java)
                    nm.notify(NOTIFICATION_ID, buildNotification(notifText()))
                } catch (_: Exception) {
                }
            }
        }.apply { isDaemon = true; start() }
    }

    private fun stopNotifTicker() {
        notifThread?.interrupt()
        notifThread = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                // Explicit user stop: clear the state bit FIRST
                // (synchronously, NP-1114-37), then tear down. After
                // this, a system restart must not resurrect the
                // session. A failed commit does not hold the stop
                // hostage — see the class-doc failure semantics.
                val cleared = prefs().edit().putBoolean(KEY_USER_ENABLED, false).commit()
                if (!cleared) {
                    android.util.Log.e("HollowVpnService", "user_enabled clear failed to persist; stopping the live session anyway")
                }
                stopSession()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            ACTION_START -> {
                // Fail-closed: without a durably recorded start, no
                // session (NP-1114-37 failure semantics).
                val recorded = prefs().edit().putBoolean(KEY_USER_ENABLED, true).commit()
                if (!recorded) {
                    android.util.Log.e("HollowVpnService", "user_enabled set failed to persist; not starting (fail-closed)")
                    stopSelf()
                } else if (!startSession()) {
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
            Hollowcore.startVPN(cfg, fd.toLong(), ProtectorBridge())
            sessionRunning = true
            startNotifTicker()
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun stopSession() {
        stopNotifTicker()
        if (sessionRunning) {
            try { Hollowcore.stopVPN() } catch (_: Exception) {}
            sessionRunning = false
        }
    }

    /**
     * Stored config is complete iff the Go facade can produce the
     * runtime config: stored file present, PSK unwrap succeeds
     * (Keystore), PSK present. Any failure — including a lost
     * keystore key — is "incomplete": the restart gate fails closed
     * and the session never self-starts (M3-3 read side).
     */
    private fun readConfig(): String? {
        HollowInit.ensure(this)
        return try { Hollowcore.storedRuntimeConfigJSON() } catch (e: Exception) { null }
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

    private fun buildNotification(text: String): Notification {
        // Tapping the notification returns to the main screen (M3-4).
        val tap = android.app.PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(tap)
            .setSmallIcon(android.R.drawable.ic_lock_lock) // placeholder icon; real asset in M3-5
            .build()
    }

    private fun promoteToForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val notification: Notification = buildNotification(getString(R.string.vpn_notification_text))
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
    }
}
