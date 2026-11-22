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
    private var lastUp = -1L
    private var lastDown = -1L
    private var lastSampleAt = 0L

    /** Notification text from the facade state (NP-1118-03): the
     *  persistent notification carries the connection state and the
     *  live rates (from the core's wire counters), not a placeholder. */
    private fun notifText(): String {
        return try {
            val st = org.json.JSONObject(Hollowcore.vpnStateJSON())
            val label = when (st.optString("state")) {
                "connected" -> "已连接"
                "connecting" -> "连接中"
                "error" -> "连接失败"
                else -> "未连接"
            }
            if (st.optString("state") != "connected") return "Hollow $label"
            val up = st.optLong("trafficUp")
            val down = st.optLong("trafficDown")
            val now = System.currentTimeMillis()
            var rateUp = 0L
            var rateDown = 0L
            if (lastSampleAt > 0 && now > lastSampleAt) {
                val dt = (now - lastSampleAt) / 1000.0
                rateUp = ((up - lastUp) / dt).toLong()
                rateDown = ((down - lastDown) / dt).toLong()
            }
            lastUp = up; lastDown = down; lastSampleAt = now
            "Hollow $label · ↓ ${fmtBytes(rateDown)}/s · ↑ ${fmtBytes(rateUp)}/s · 本次 ↓ ${fmtBytes(down)} · ↑ ${fmtBytes(up)}"
        } catch (e: Exception) {
            "Hollow 隧道运行中"
        }
    }

    private fun fmtBytes(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024 * 1024 -> String.format("%.1f KB", n / 1024.0)
        n < 1024 * 1024 * 1024 -> String.format("%.1f MB", n / 1024.0 / 1024.0)
        else -> String.format("%.2f GB", n / 1024.0 / 1024.0 / 1024.0)
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
                try {
                    prefs().edit().putBoolean(KEY_TAKEN_OVER, false).commit()
                } catch (_: Exception) {}
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
                // NP-1118-17 role split: the DEVICE's interface
                // address is .2; .1 is the virtual gateway that
                // lives only inside the tunnel (the pump's NIC)
                // and is declared as the DNS server. Declaring a
                // DNS server that is also one of the device's own
                // interface addresses (the pre-fix .1/.1 pairing)
                // makes the kernel deliver netd's queries locally
                // — they never reach the TUN fd, the pump never
                // sees them, and system resolution dies at the
                // configuration level (Chrome BAD_CONFIG) while
                // direct app queries to remote resolvers work.
                .addAddress("10.99.0.2", 24)
                .addAddress("fd00::1", 64) // v6 must enter the TUN to be dropped, never bypass (plan §2). fd00::1 is interface-only: no v6 DNS server is declared, so the NP-1118-17 role collision does not arise here; if one is ever declared it must NOT be this address.
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
            // NP-1118-62: while the service runs, the deployment
            // wizard's direct dialer protects its sockets through
            // the same bridge — wizard traffic never enters the
            // tunnel it may be (re)deploying.
            try { Hollowcore.wizardSetProtector(ProtectorBridge()) } catch (_: Exception) {}
            sessionRunning = true
            startNotifTicker()
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun stopSession() {
        try { Hollowcore.wizardClearProtector() } catch (_: Exception) {}
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
        // The VPN slot was taken from us (another app established
        // its VPN, or the user switched VPN off in Settings): tear
        // the whole session down (pump stopped, core closed) and
        // RECORD the takeover, so the shell can say "VPN 已被其他
        // 应用接管" instead of presenting the core's carrier state
        // (NP-1118-16). The user_enabled bit is KEPT per the
        // restart policy above; the taken-over flag separately
        // stops the shell's auto-connect from stealing the slot
        // straight back — retaking it is a human decision.
        try {
            prefs().edit().putBoolean(KEY_TAKEN_OVER, true).commit()
        } catch (_: Exception) {}
        try { Hollowcore.noteVpnRevoked() } catch (_: Exception) {}
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
        const val KEY_TAKEN_OVER = "vpn_taken_over"
        private const val KEY_USER_ENABLED = "user_enabled"
    }
}
