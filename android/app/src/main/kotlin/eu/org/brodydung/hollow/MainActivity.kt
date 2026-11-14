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
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import hollowcore.Hollowcore
import org.json.JSONObject

/**
 * Main screen (M3-4 formalized minimal surface): a status card fed by
 * a 1-second poll of the Go facade's state JSON (the service owns the
 * session; this screen only presents), connection controls, and the
 * M3-3 pairing panel. Copy follows the Windows fixed wording where
 * the plan pins it; the mode presentation is honest — Android has no
 * system-proxy mode, only VPN on/off.
 */
class MainActivity : Activity() {

    private lateinit var stateView: TextView
    private lateinit var detailView: TextView
    private lateinit var statsView: TextView
    private lateinit var noticesView: TextView
    private lateinit var configView: TextView
    private lateinit var pairingHeader: TextView
    private lateinit var connectButton: Button
    private lateinit var log: TextView

    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() {
            renderState()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        HollowInit.ensure(this)

        stateView = TextView(this).apply { textSize = 20f; text = "未连接" }
        detailView = TextView(this)
        statsView = TextView(this)
        noticesView = TextView(this)
        configView = TextView(this)
        log = TextView(this).apply { textSize = 13f }

        fun btn(label: String, onClick: () -> Unit) = Button(this).apply {
            text = label
            setOnClickListener { onClick() }
        }
        connectButton = btn("开启 VPN") { requestConsentOrStart() }
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(stateView)
            addView(detailView)
            addView(statsView)
            addView(noticesView)
            addView(configView)
            addView(connectButton)
            addView(btn("停止") {
                startService(Intent(this@MainActivity, HollowVpnService::class.java).setAction(HollowVpnService.ACTION_STOP))
                log.append("\n已停止（状态位已清除，不会被系统拉活）")
            })
            pairingHeader = TextView(this@MainActivity).apply { text = "\n— 配对导入 —" }
            addView(pairingHeader)
            addView(btn("粘贴导入（链接或 JSON 文本）") { showPasteImport() })
            addView(btn("从剪贴板读二维码图导入") { importFromClipboardImage() })
            addView(btn("从文件导入（.hollow.json）") {
                startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                }, REQ_OPEN_FILE)
            })
            addView(btn("从图片扫码导入") {
                startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "image/*"
                }, REQ_OPEN_IMAGE)
            })
            addView(btn("相机扫码导入") {
                startActivityForResult(Intent(this@MainActivity, ScanActivity::class.java), REQ_SCAN)
            })
            addView(TextView(this@MainActivity).apply { text = "\n— 导出（给另一台设备） —" })
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
            addView(TextView(this@MainActivity).apply { text = "\n— 记录 —" })
            addView(log)
        }
        setContentView(ScrollView(this).apply { addView(layout) })
        renderState()
    }

    override fun onResume() {
        super.onResume()
        handler.post(poll)
    }

    override fun onPause() {
        handler.removeCallbacks(poll)
        super.onPause()
    }

    /** Renders the facade state into the status card. Error states
     *  always carry their reason — never a silent blank. */
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
        stateView.text = when (state) {
            "connected" -> "已连接"
            "connecting" -> "连接中…"
            "error" -> "连接失败"
            else -> "未连接"
        }
        val detail = StringBuilder(st.optString("detail"))
        if (state == "connected" && st.optLong("sinceMs") > 0) {
            val secs = (System.currentTimeMillis() - st.optLong("sinceMs")) / 1000
            detail.append("已连接 " + fmtDuration(secs))
        }
        detailView.text = detail.toString()
        val stats = st.optJSONObject("stats")
        statsView.text = if (stats != null && state != "disconnected") {
            "载体 ${st.optInt("carriers")} · 流 ${st.optInt("streams")}（活跃 ${stats.optLong("activeFlows")}）\n" +
                "DNS 查询 ${stats.optLong("dnsQueries")} · 解析 ${stats.optLong("dnsResolved")} · SERVFAIL ${stats.optLong("dnsServfail")}\n" +
                "UDP 丢弃 ${stats.optLong("droppedUdp")} · IPv6 丢弃 ${stats.optLong("droppedV6")}"
        } else {
            ""
        }
        // The two fixed notices, verbatim (plan §6): they describe
        // what the data plane DOES with v6 / UDP while connected.
        noticesView.text = if (state == "connected") "IPv6 已阻断 · UDP 流量不经过 Hollow 加密通道" else ""
        configView.text = if (configured) {
            "目标：${st.optString("wsUrl")} · keyId ${st.optInt("keyId")}"
        } else {
            "未配对：请先完成下方配对导入"
        }
        pairingHeader.text = if (configured) "\n— 配对导入 —" else "\n— 配对导入（先完成这一步） —"
        connectButton.isEnabled = configured
        connectButton.text = if (configured) "开启 VPN" else "开启 VPN（未配对）"
    }

    private fun fmtDuration(totalSecs: Long): String {
        val s = maxOf(0, totalSecs)
        return String.format("%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
    }

    // ---- the one import funnel (M3-3, unchanged semantics) ----
    private fun funnel(text: String) {
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
        log.append("\n服务已启动（无配置/启动失败时状态卡会明示原因）")
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
    }
}
