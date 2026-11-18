package eu.org.brodydung.hollow

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import java.net.InetAddress
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import hollowcore.Hollowcore
import org.json.JSONObject

/**
 * Main screen (NP-1118-03, the Windows v0.3.0 structure carried over):
 * a status hero fed by a 1-second poll of the Go facade's state JSON
 * (the service owns the session; this screen only presents), layered
 * settings with the protocol internals in an advanced fold, a
 * first-run single-step import when nothing is configured, humanized
 * error cards, and a collapsible diagnostics drawer. The mode
 * presentation stays honest — Android has no system-proxy mode, only
 * VPN on/off.
 */
class MainActivity : Activity() {

    private lateinit var stateView: TextView
    private lateinit var detailView: TextView
    private lateinit var readingsView: TextView
    private lateinit var noticesView: TextView
    private lateinit var mainButton: Button
    private lateinit var retryButton: Button
    private lateinit var errorCard: LinearLayout
    private lateinit var errorBody: TextView
    private lateinit var errorDetail: TextView
    private lateinit var firstRunSection: LinearLayout
    private lateinit var settingsSection: LinearLayout
    private lateinit var ioSection: LinearLayout
    private lateinit var pairingSummary: TextView
    private lateinit var advancedBody: LinearLayout
    private lateinit var advancedText: TextView
    private lateinit var autoConnectSwitch: Switch
    private lateinit var autoConnectNote: TextView
    private lateinit var diagBody: LinearLayout
    private lateinit var log: TextView

    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() {
            renderState()
            // The advanced panel used to render only at expand time,
            // so its counters froze at whatever the session looked
            // like in its first seconds — field readings quoted
            // stale zeros as live values (NP-1118-11 evidence note).
            if (advancedBody.visibility == View.VISIBLE) renderAdvanced()
            handler.postDelayed(this, 1000)
        }
    }

    // Rate sampling from the facade's cumulative wire counters.
    private var prevUp = -1L
    private var prevDown = -1L
    private var prevAt = 0L
    private var rateUp = 0L
    private var rateDown = 0L
    // Landing identification, cached per connection (sinceMs).
    private var landingForSince = 0L
    private var landingText = ""
    // /meta retry state (NP-1118-07 F2): within one connection the
    // landing fetch retries with backoff instead of latching shut
    // after a single transient failure; every failure is logged.
    private var landingNextRetryAtMs = 0L
    private var landingRetryDelaySec = 5
    @Volatile private var landingInFlight = false

    // System-DNS hint card (NP-1118-16): the pump path and the
    // netd path are disjoint — when the tunnel's own resolver is
    // provably healthy while system resolution (netd, the path
    // Chrome uses) fails sampling repeatedly, the standing cause
    // is Private DNS (strict DoT/DoH3) failing closed over the
    // tunnel. The card says so and deep-links to network settings.
    private lateinit var dnsHintCard: LinearLayout
    @Volatile private var sysDnsSampling = false
    private var sysDnsFailRounds = 0
    private var sysDnsLastSampleAt = 0L
    private var sysDnsCardShown = false
    private var autoConnectTried = false
    private var lastState = "disconnected"
    private var lastConfigured = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        HollowInit.ensure(this)

        stateView = TextView(this).apply { textSize = 24f; text = "未连接" }
        detailView = TextView(this)
        readingsView = TextView(this).apply { textSize = 15f }
        noticesView = TextView(this)

        fun btn(label: String, onClick: () -> Unit) = Button(this).apply {
            text = label
            setOnClickListener { onClick() }
        }
        mainButton = btn("连接") { onMainButton() }
        retryButton = btn("一键重试") { retryConnection() }
        retryButton.visibility = View.GONE

        errorBody = TextView(this)
        errorDetail = TextView(this).apply { textSize = 12f; visibility = View.GONE }
        errorCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            addView(TextView(this@MainActivity).apply { text = "连接失败"; textSize = 17f })
            addView(errorBody)
            addView(btn("查看原始详情") {
                errorDetail.visibility = if (errorDetail.visibility == View.GONE) View.VISIBLE else View.GONE
            })
            addView(errorDetail)
            addView(btn("立即重试") { retryConnection() })
        }

        dnsHintCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            addView(TextView(this@MainActivity).apply { text = "\n浏览器打不开网页？"; textSize = 17f })
            addView(TextView(this@MainActivity).apply {
                text = "系统私人 DNS 拦截了浏览器解析——到 设置→网络和互联网→私人 DNS 改为『关闭』后重试"
            })
            addView(btn("打开网络设置") { openNetworkSettings() })
        }

        // (j) First run: one import action, nothing else.
        firstRunSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            addView(TextView(this@MainActivity).apply { text = "\n— 开始使用 —"; textSize = 17f })
            addView(TextView(this@MainActivity).apply {
                text = "还没有配置。导入一份配置（hollow:// 链接、.hollow.json 文件或二维码）即可连接，不需要先填任何设置。"
            })
            addView(btn("粘贴导入（链接或 JSON 文本）") { showPasteImport() })
            addView(btn("从文件导入（.hollow.json）") { openDocument("*/*", REQ_OPEN_FILE) })
            addView(btn("从二维码图片导入") { openDocument("image/*", REQ_OPEN_IMAGE) })
            addView(btn("从剪贴板读二维码图导入") { importFromClipboardImage() })
            addView(btn("相机扫码导入") {
                startActivityForResult(Intent(this@MainActivity, ScanActivity::class.java), REQ_SCAN)
            })
        }

        autoConnectSwitch = Switch(this).apply { text = "启动时自动连接（仅限上次成功连接过的配置）" }
        autoConnectNote = TextView(this).apply { textSize = 12f }
        pairingSummary = TextView(this)
        advancedText = TextView(this).apply { textSize = 13f }
        advancedBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            addView(advancedText)
        }
        settingsSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(TextView(this@MainActivity).apply { text = "\n— 设置 —"; textSize = 17f })
            addView(autoConnectSwitch)
            addView(autoConnectNote)
            addView(pairingSummary)
            addView(btn("高级设置（协议内部）") {
                advancedBody.visibility = if (advancedBody.visibility == View.GONE) View.VISIBLE else View.GONE
                if (advancedBody.visibility == View.VISIBLE) renderAdvanced()
            })
            addView(advancedBody)
        }
        autoConnectSwitch.setOnCheckedChangeListener { _, checked ->
            // Apply-on-change: the preference is the whole mechanism.
            // (Programmatic syncs from renderPairingSummary carry the
            // already-stored value and are not user changes.)
            val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
            if (prefs.getBoolean(KEY_AUTO_CONNECT, true) == checked) return@setOnCheckedChangeListener
            val ok = prefs.edit().putBoolean(KEY_AUTO_CONNECT, checked).commit()
            autoConnectNote.text = if (ok) "已生效" else "保存失败"
        }

        ioSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(TextView(this@MainActivity).apply { text = "\n— 导入 / 导出 —"; textSize = 17f })
            addView(btn("粘贴导入（链接或 JSON 文本）") { showPasteImport() })
            addView(btn("从文件导入（.hollow.json）") { openDocument("*/*", REQ_OPEN_FILE) })
            addView(btn("从二维码图片导入") { openDocument("image/*", REQ_OPEN_IMAGE) })
            addView(btn("从剪贴板读二维码图导入") { importFromClipboardImage() })
            addView(btn("相机扫码导入") {
                startActivityForResult(Intent(this@MainActivity, ScanActivity::class.java), REQ_SCAN)
            })
            addView(btn("导出 hollow:// 链接") { pendingExportIsLink = true; askExportPsk { link -> showLinkDialog(link) } })
            addView(btn("导出 .hollow.json 文件") {
                pendingExportIsLink = false
                askExportPsk { json ->
                    pendingExportJson = json
                    startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "application/json"
                        putExtra(Intent.EXTRA_TITLE, "hollow-config.json")
                    }, REQ_CREATE_FILE)
                }
            })
        }

        log = TextView(this).apply { textSize = 13f }
        diagBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            addView(btn("复制日志") {
                getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("hollow log", log.text.toString()))
                log.append("\n日志已复制到剪贴板")
            })
            addView(log)
        }

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(stateView)
            addView(detailView)
            addView(readingsView)
            addView(noticesView)
            addView(mainButton)
            addView(retryButton)
            addView(errorCard)
            addView(dnsHintCard)
            addView(firstRunSection)
            addView(settingsSection)
            addView(ioSection)
            addView(TextView(this@MainActivity).apply { text = "\n— 诊断日志 —"; textSize = 17f })
            addView(btn("展开 / 收起诊断日志") {
                diagBody.visibility = if (diagBody.visibility == View.GONE) View.VISIBLE else View.GONE
            })
            addView(diagBody)
        }
        setContentView(ScrollView(this).apply { addView(layout) })
        // Crash surfacing (M3-5): a marker from a previous run's
        // uncaught exception is shown once, then cleared.
        try {
            val marker = java.io.File(filesDir, HollowApplication.CRASH_MARKER)
            if (marker.exists()) {
                val text = marker.readText()
                marker.delete()
                log.append("\n上次运行异常退出（$text）——如反复出现请反馈此行")
            }
        } catch (_: Exception) {
        }
        renderState()
        maybeAutoConnect()
        handleDeepLink(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    override fun onResume() {
        super.onResume()
        handler.post(poll)
    }

    override fun onPause() {
        handler.removeCallbacks(poll)
        super.onPause()
    }

    private fun openDocument(type: String, req: Int) {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            this.type = type
        }, req)
    }

    /** (j) hollow:// deep links land in the same import funnel. */
    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.dataString ?: return
        if (data.startsWith("hollow://")) funnel(data)
    }

    // ---- (h) startup auto-connect ----
    private fun maybeAutoConnect() {
        if (autoConnectTried) return
        autoConnectTried = true
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_AUTO_CONNECT, true)) return
        if (!prefs.getBoolean(KEY_USER_ENABLED, false)) return
        if (!lastConfigured || lastState != "disconnected") return
        // Consent already granted -> start directly; not granted ->
        // the system consent flow decides (never bypassed).
        if (VpnService.prepare(this) == null) {
            log.append("\n启动自动连接：恢复上次配置")
            startVpnService()
        }
    }

    private fun onMainButton() {
        if (lastState == "connected" || lastState == "connecting") {
            startService(Intent(this, HollowVpnService::class.java).setAction(HollowVpnService.ACTION_STOP))
            log.append("\n已停止（状态位已清除，不会被系统拉活）")
        } else {
            requestConsentOrStart()
        }
    }

    /** (i) one-click retry from any failure / degraded state. */
    private fun retryConnection() {
        startService(Intent(this, HollowVpnService::class.java).setAction(HollowVpnService.ACTION_STOP))
        handler.postDelayed({ requestConsentOrStart() }, 400)
    }

    /** Renders the facade state into the hero + sections. */
    private fun renderState() {
        val st = try {
            JSONObject(Hollowcore.vpnStateJSON())
        } catch (e: Exception) {
            stateView.text = "状态读取失败"
            detailView.text = e.message ?: ""
            return
        }
        val state = st.optString("state")
        val configured = st.optBoolean("configured")
        lastState = state
        lastConfigured = configured
        maybeSampleSystemDns(state)
        val firstRun = !configured

        stateView.text = when (state) {
            "connected" -> "● 已连接"
            "connecting" -> "● 连接中…"
            "error" -> "● 连接失败"
            else -> "● 未连接"
        }
        val rawDetail = st.optString("detail")
        detailView.text = when {
            firstRun && state == "disconnected" -> "还没有配置——导入一份配置即可开始。"
            state == "connecting" && rawDetail.isNotEmpty() -> rawDetail
            else -> ""
        }

        // Rates from cumulative wire counters (display only).
        val up = st.optLong("trafficUp")
        val down = st.optLong("trafficDown")
        val now = System.currentTimeMillis()
        if (prevAt > 0 && now > prevAt) {
            val dt = (now - prevAt) / 1000.0
            rateUp = ((up - prevUp) / dt).toLong()
            rateDown = ((down - prevDown) / dt).toLong()
        }
        prevUp = up; prevDown = down; prevAt = now

        if (state == "connected") {
            val since = st.optLong("sinceMs")
            if (since > 0 && landingForSince != since && !landingInFlight &&
                System.currentTimeMillis() >= landingNextRetryAtMs
            ) {
                landingInFlight = true
                Thread {
                    try {
                        val m = JSONObject(Hollowcore.fetchMetaJSON())
                        landingText = "${m.optString("colo")} / ${m.optString("country")}"
                        landingForSince = since
                        landingRetryDelaySec = 5
                    } catch (e: Exception) {
                        val delay = landingRetryDelaySec
                        landingNextRetryAtMs = System.currentTimeMillis() + delay * 1000L
                        landingRetryDelaySec = minOf(delay * 3, 60)
                        runOnUiThread {
                            log.append("\n落地信息（/meta）拉取失败：${e.message ?: "未知错误"}；${delay} 秒后重试")
                        }
                    } finally {
                        landingInFlight = false
                    }
                }.start()
            }
            val secs = if (since > 0) (now - since) / 1000 else 0
            val host = try {
                android.net.Uri.parse(st.optString("wsUrl")).host ?: st.optString("wsUrl")
            } catch (_: Exception) {
                st.optString("wsUrl")
            }
            readingsView.text =
                "下载速率 ${fmtBytes(rateDown)}/s · 上传速率 ${fmtBytes(rateUp)}/s\n" +
                "承载健康 ${st.optInt("liveCarriers")}/${st.optInt("poolSize")} · 入口 $host · RTT ${st.optLong("carrierRttMs")} ms\n" +
                "落地（经 /meta 实测）${if (landingForSince == since && landingText.isNotEmpty()) landingText else "—"}\n" +
                "本次流量 ↓ ${fmtBytes(down)} · ↑ ${fmtBytes(up)} · 已连接 ${fmtDuration(secs)}"
        } else {
            readingsView.text = ""
            if (state == "disconnected") {
                landingText = ""; landingForSince = 0
                landingNextRetryAtMs = 0; landingRetryDelaySec = 5
            }
        }
        // The two fixed notices, verbatim (plan §6).
        noticesView.text = if (state == "connected") "IPv6 已阻断 · UDP 流量不经过 Hollow 加密通道" else ""

        // Error card with a humanized reason; raw text in the fold.
        if (state == "error") {
            val (title, advice) = humanizeError(rawDetail)
            errorBody.text = "$title\n$advice"
            errorDetail.text = rawDetail
            errorCard.visibility = View.VISIBLE
        } else {
            errorCard.visibility = View.GONE
        }
        val degraded = state == "error" || (state == "connecting" && rawDetail.isNotEmpty())
        retryButton.visibility = if (degraded && !firstRun) View.VISIBLE else View.GONE

        mainButton.visibility = if (firstRun) View.GONE else View.VISIBLE
        mainButton.text = when (state) {
            "connected", "connecting" -> "断开"
            else -> "连接"
        }
        firstRunSection.visibility = if (firstRun) View.VISIBLE else View.GONE
        settingsSection.visibility = if (firstRun) View.GONE else View.VISIBLE
        ioSection.visibility = if (firstRun) View.GONE else View.VISIBLE
        if (!firstRun) renderPairingSummary(st)
    }

    private fun renderPairingSummary(st: JSONObject) {
        if (autoConnectSwitch.isChecked != getSharedPreferences(PREFS, MODE_PRIVATE)
                .getBoolean(KEY_AUTO_CONNECT, true)
        ) {
            autoConnectSwitch.isChecked = getSharedPreferences(PREFS, MODE_PRIVATE)
                .getBoolean(KEY_AUTO_CONNECT, true)
        }
        pairingSummary.text = "目标：${st.optString("wsUrl")} · keyId ${st.optInt("keyId")}"
    }

    // --- System-DNS sampling & hint card (NP-1118-16) ---

    private fun maybeSampleSystemDns(state: String) {
        if (state != "connected") {
            sysDnsFailRounds = 0
            if (sysDnsCardShown) {
                sysDnsCardShown = false
                dnsHintCard.visibility = View.GONE
            }
            return
        }
        val now = System.currentTimeMillis()
        if (sysDnsSampling || now - sysDnsLastSampleAt < 10_000) return
        sysDnsSampling = true
        sysDnsLastSampleAt = now
        Thread {
            // Several well-known names; the round succeeds if ANY
            // resolves. This process's lookups go through netd on
            // the VPN network — the same path Chrome uses — while
            // the pump resolver is a separate, tunnel-internal path.
            val names = listOf("www.google.com", "gmail.com", "www.cloudflare.com")
            var ok = false
            for (name in names) {
                try {
                    if (InetAddress.getByName(name) != null) {
                        ok = true
                        break
                    }
                } catch (e: Exception) {
                    // try the next name
                }
            }
            runOnUiThread {
                sysDnsSampling = false
                onSysDnsSample(ok)
            }
        }.start()
    }

    private fun onSysDnsSample(ok: Boolean) {
        if (ok) {
            sysDnsFailRounds = 0
            if (sysDnsCardShown) {
                sysDnsCardShown = false
                dnsHintCard.visibility = View.GONE
                log.append("\n系统解析抽样恢复，私人 DNS 提示卡已撤下")
            }
            return
        }
        sysDnsFailRounds++
        if (sysDnsFailRounds < 2 || sysDnsCardShown) return
        // Require the tunnel side to be provably healthy at the
        // same moment: carriers live and the pump resolver has
        // resolved successfully. Otherwise the failure is ours,
        // not the system resolver's, and the card must not blame
        // Private DNS.
        val st = try {
            JSONObject(Hollowcore.vpnStateJSON())
        } catch (e: Exception) {
            return
        }
        if (st.optString("state") != "connected") return
        val stats = st.optJSONObject("stats")
        val pumpResolved = stats?.optLong("dnsResolved") ?: 0
        if (st.optInt("liveCarriers") < 1 || pumpResolved < 1) return
        sysDnsCardShown = true
        dnsHintCard.visibility = View.VISIBLE
        log.append("\n系统解析抽样连续 $sysDnsFailRounds 轮失败而泵解析健康（已解析 $pumpResolved）——疑似私人 DNS 拦截，已出提示卡")
    }

    private fun openNetworkSettings() {
        val intents = listOf(
            Intent(Settings.ACTION_WIRELESS_SETTINGS),
            Intent(Settings.ACTION_SETTINGS)
        )
        for (intent in intents) {
            try {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
                return
            } catch (e: Exception) {
                // try the next one
            }
        }
    }

    private fun renderAdvanced() {
        val p = try { JSONObject(Hollowcore.storedPairingJSON()) } catch (_: Exception) { JSONObject() }
        val st = try { JSONObject(Hollowcore.vpnStateJSON()) } catch (_: Exception) { JSONObject() }
        val stats = st.optJSONObject("stats")
        val sb = StringBuilder()
        sb.append("配对 V：${p.optString("pskVerifier")}\n")
        sb.append("metaPath：${p.optString("metaPath")}\nedgesPath：${p.optString("edgesPath")}\n")
        sb.append("核心版本：${Hollowcore.version()}\n")
        if (stats != null) {
            sb.append(
                "载体 ${st.optInt("carriers")} · 流 ${st.optInt("streams")}（活跃 ${stats.optLong("activeFlows")}）\n" +
                    "DNS 查询 ${stats.optLong("dnsQueries")} · 解析 ${stats.optLong("dnsResolved")} · SERVFAIL ${stats.optLong("dnsServfail")}\n" +
                    "UDP 丢弃 ${stats.optLong("droppedUdp")} · IPv6 丢弃 ${stats.optLong("droppedV6")}"
            )
        }
        // Entry dispersion (NP-1118-09): per-carrier pinned entry IPs
        // and the ranked candidate list, when a measurement exists.
        val slotEdges = st.optJSONArray("slotEdges")
        val candidates = st.optJSONArray("edgeCandidates")
        if (slotEdges != null && slotEdges.length() > 0) {
            val pins = (0 until slotEdges.length()).joinToString(" · ") { i ->
                val ip = slotEdges.optString(i)
                "#${i + 1} ${if (ip.isEmpty()) "域名" else ip}"
            }
            sb.append("\n入口钉位：$pins")
        }
        if (candidates != null && candidates.length() > 0) {
            val ranked = (0 until candidates.length()).joinToString(" · ") { i ->
                val c = candidates.optJSONObject(i)
                "${c?.optString("ip")} ${c?.optLong("rttMs")}ms"
            }
            sb.append("\n候选入口（按 RTT)：$ranked")
        }
        advancedText.text = sb.toString()
    }

    /** Known failure surfaces in plain Chinese + the next step. */
    private fun humanizeError(raw: String): Pair<String, String> {
        val s = raw.lowercase()
        return when {
            s.contains("psk") || s.contains("unwrap") || s.contains("keystore") || s.contains("decrypt") ->
                "密钥材料不可用" to "本机密钥损坏或与服务端不匹配。下一步：重新导入一份完整配置。"
            s.contains("handshake") || s.contains("finished") || s.contains("verifier") ->
                "握手失败，密钥不匹配" to "本机密钥与 Worker 端不一致。下一步：核对配对 V，或重新导入配置。"
            s.contains("protect") ->
                "系统拒绝了套接字保护" to "VPN 授权可能已被系统撤销。下一步：点「立即重试」，在系统弹窗中允许。"
            s.contains("timeout") || s.contains("timed out") || s.contains("deadline") ->
                "连接超时" to "网络迟迟没有回应。下一步：换个网络环境后重试。"
            s.contains("refused") || s.contains("unreachable") || s.contains("unknown host") || s.contains("dns") || s.contains("no route") ->
                "无法连通 Worker" to "地址不可达或域名解析失败。下一步：检查网络，或核对配置中的地址。"
            s.contains("not configured") || s.contains("incomplete") ->
                "配置不完整" to "缺少地址或密钥。下一步：重新导入一份完整配置。"
            else -> "连接失败" to "下一步：点「立即重试」；反复失败请展开诊断日志查看原始详情。"
        }
    }

    private fun fmtDuration(totalSecs: Long): String {
        val s = maxOf(0, totalSecs)
        return String.format("%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
    }

    private fun fmtBytes(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024 * 1024 -> String.format("%.1f KB", n / 1024.0)
        n < 1024 * 1024 * 1024 -> String.format("%.1f MB", n / 1024.0 / 1024.0)
        else -> String.format("%.2f GB", n / 1024.0 / 1024.0 / 1024.0)
    }

    // ---- the one import funnel (M3-3, unchanged semantics) ----
    private fun funnel(text: String) {
        val wasFirstRun = !lastConfigured
        val previewJson = try {
            Hollowcore.stageImport(text)
        } catch (e: Exception) {
            log.append("\n导入被拒绝：${e.message}")
            return
        }
        val pv = JSONObject(previewJson)
        val msg = StringBuilder("目标 Worker：${pv.optString("workerUrl")}\nkeyId：${pv.optInt("keyId")}")
        if (pv.optBoolean("hasPsk")) {
            msg.append("\n含 PSK（配对 V：${pv.optString("pskVerifier").take(12)}…）")
            if (pv.optBoolean("overwritesPsk")) {
                msg.append("\n⚠ 本机已有 PSK，确认后将被覆盖，现配对随即失效。")
            }
        } else {
            msg.append("\n不含 PSK（只改地址）")
        }
        if (pv.optBoolean("hasEndpointPaths")) msg.append("\n含部署端点路径（一并应用）")
        AlertDialog.Builder(this)
            .setTitle("确认导入")
            .setMessage(msg.toString())
            .setPositiveButton("确认导入并覆盖") { _, _ ->
                try {
                    Hollowcore.confirmImport()
                    log.append("\n导入已应用。")
                    renderState()
                    // (j) after a first-run import, the first
                    // connection starts itself.
                    if (wasFirstRun) {
                        log.append("\n首次配置完成，自动发起连接")
                        requestConsentOrStart()
                    }
                } catch (e: Exception) {
                    log.append("\n导入失败：${e.message}")
                }
            }
            .setNegativeButton("取消") { _, _ ->
                Hollowcore.cancelImport()
                log.append("\n已取消导入。")
            }
            .setOnCancelListener { Hollowcore.cancelImport() }
            .show()
    }

    private fun showPasteImport() {
        val input = EditText(this).apply { hint = "粘贴 hollow:// 链接或 .hollow.json 内容" }
        AlertDialog.Builder(this)
            .setTitle("粘贴导入")
            .setView(input)
            .setPositiveButton("预览") { _, _ -> funnel(input.text.toString()) }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun importFromClipboardImage() {
        try {
            val cm = getSystemService(ClipboardManager::class.java)
            val uri = cm.primaryClip?.getItemAt(0)?.uri
                ?: throw IllegalStateException("剪贴板里没有图片")
            val bmp = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it) }
                ?: throw IllegalStateException("剪贴板图片读取失败")
            funnel(QrDecode.decodeBitmap(bmp))
        } catch (e: Exception) {
            log.append("\n剪贴板导入失败：${e.message}")
        }
    }

    // ---- export (M3-3, unchanged semantics) ----
    private var pendingExportJson: String? = null
    private var pendingExportIsLink = true

    private fun askExportPsk(build: (String) -> Unit) {
        AlertDialog.Builder(this)
            .setTitle("导出范围")
            .setMessage("是否在导出中包含 PSK 本体？")
            .setPositiveButton("不含 PSK") { _, _ -> runExport(false, build) }
            .setNeutralButton("含 PSK") { _, _ ->
                AlertDialog.Builder(this)
                    .setTitle("⚠ 含 PSK 导出")
                    .setMessage("任何拿到导出内容的人都能冒充本机配对。只给自己的设备，确认？")
                    .setPositiveButton("确认含 PSK 导出") { _, _ -> runExport(true, build) }
                    .setNegativeButton("取消", null)
                    .show()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun runExport(includePsk: Boolean, build: (String) -> Unit) {
        try {
            build(if (pendingExportIsLink) Hollowcore.exportLink(includePsk) else Hollowcore.exportConfigJSON(includePsk))
        } catch (e: Exception) {
            log.append("\n导出失败：${e.message}")
        }
    }

    private fun showLinkDialog(link: String) {
        AlertDialog.Builder(this)
            .setTitle("hollow:// 链接")
            .setMessage(link)
            .setPositiveButton("复制") { _, _ ->
                getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("hollow link", link))
                log.append("\n链接已复制到剪贴板")
            }
            .setNegativeButton("关闭", null)
            .show()
    }

    // ---- VPN consent / start ----
    private fun requestConsentOrStart() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN_CONSENT)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        startForegroundService(
            Intent(this, HollowVpnService::class.java).setAction(HollowVpnService.ACTION_START)
        )
        handler.postDelayed({ renderState() }, 600)
    }

    @Deprecated("Skeleton-era result flow; kept simple")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_VPN_CONSENT -> {
                if (resultCode == RESULT_OK) startVpnService()
                else log.append("\nVPN 授权被拒绝——不启动")
            }
            REQ_OPEN_FILE -> {
                if (resultCode != RESULT_OK) return
                val uri = data?.data ?: return
                try {
                    val text = contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
                        ?: throw IllegalStateException("文件读取失败")
                    funnel(text)
                } catch (e: Exception) {
                    log.append("\n文件导入失败：${e.message}")
                }
            }
            REQ_OPEN_IMAGE -> {
                if (resultCode != RESULT_OK) return
                val uri = data?.data ?: return
                try {
                    val bmp = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it) }
                        ?: throw IllegalStateException("图片读取失败")
                    funnel(QrDecode.decodeBitmap(bmp))
                } catch (e: Exception) {
                    log.append("\n图片扫码失败：${e.message}")
                }
            }
            REQ_SCAN -> {
                if (resultCode == RESULT_OK) {
                    data?.getStringExtra(ScanActivity.EXTRA_QR_TEXT)?.let { funnel(it) }
                }
            }
            REQ_CREATE_FILE -> {
                val json = pendingExportJson
                pendingExportJson = null
                if (resultCode != RESULT_OK || json == null) return
                val uri = data?.data ?: return
                try {
                    contentResolver.openOutputStream(uri)?.use { it.write(json.toByteArray(Charsets.UTF_8)) }
                    log.append("\n已导出 .hollow.json")
                } catch (e: Exception) {
                    log.append("\n导出写入失败：${e.message}")
                }
            }
        }
    }

    companion object {
        private const val REQUEST_VPN_CONSENT = 1
        private const val REQ_OPEN_FILE = 2
        private const val REQ_OPEN_IMAGE = 3
        private const val REQ_SCAN = 4
        private const val REQ_CREATE_FILE = 5
        // Shared with HollowVpnService's restart gate (same file).
        private const val PREFS = "hollow-vpn"
        private const val KEY_USER_ENABLED = "user_enabled"
        private const val KEY_AUTO_CONNECT = "auto_connect"
    }
}
