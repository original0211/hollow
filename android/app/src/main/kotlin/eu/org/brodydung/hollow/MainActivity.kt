package eu.org.brodydung.hollow

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import hollowcore.Hollowcore
import org.json.JSONObject

/**
 * Shell screen: core seam status, VPN consent + start/stop, and —
 * since M3-3 — the pairing import/export panel. Every import surface
 * (paste, file, QR image, camera, clipboard) feeds ONE funnel:
 * Hollowcore.stageImport -> in-app preview confirmation ->
 * Hollowcore.confirmImport. Nothing is applied without the explicit
 * confirmation click, mirroring Windows M2-3.
 */
class MainActivity : Activity() {

    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        HollowInit.ensure(this)

        status = TextView(this).apply {
            textSize = 15f
            text = "核心通路：${Hollowcore.version()}\n状态：未连接"
        }
        fun btn(label: String, onClick: () -> Unit) = Button(this).apply {
            text = label
            setOnClickListener { onClick() }
        }
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(status)
            addView(btn("开启 VPN") { requestConsentOrStart() })
            addView(btn("停止") {
                startService(Intent(this@MainActivity, HollowVpnService::class.java).setAction(HollowVpnService.ACTION_STOP))
                status.append("\n已停止（状态位已清除，不会被系统拉活）")
            })
            addView(TextView(this@MainActivity).apply { text = "\n— 配对导入 —" })
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
        }
        setContentView(ScrollView(this).apply { addView(layout) })
        refreshConfiguredLine()
    }

    private var pendingExportJson: String? = null

    private fun refreshConfiguredLine() {
        val configured = try {
            JSONObject(Hollowcore.storedRuntimeConfigJSON()).optString("wsUrl")
        } catch (e: Exception) {
            null
        }
        status.text = "核心通路：${Hollowcore.version()}\n状态：未连接\n" +
            (if (configured != null) "已配对：$configured" else "未配对：请先导入配置")
    }

    // ---- the one import funnel ----
    private fun funnel(text: String) {
        val previewJson = try {
            Hollowcore.stageImport(text)
        } catch (e: Exception) {
            status.append("\n导入被拒绝：${e.message}")
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
                    status.append("\n导入已应用。")
                    refreshConfiguredLine()
                } catch (e: Exception) {
                    status.append("\n导入失败：${e.message}")
                }
            }
            .setNegativeButton("取消") { _, _ ->
                Hollowcore.cancelImport()
                status.append("\n已取消导入。")
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
            status.append("\n剪贴板导入失败：${e.message}")
        }
    }

    // ---- export ----
    private fun askExportPsk(build: (String) -> Unit) {
        // First ask whether the PSK rides along; a second, explicit
        // danger confirmation gates the with-PSK variant (Windows
        // export semantics).
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
            status.append("\n导出失败：${e.message}")
        }
    }

    private var pendingExportIsLink = true

    private fun showLinkDialog(link: String) {
        AlertDialog.Builder(this)
            .setTitle("hollow:// 链接")
            .setMessage(link)
            .setPositiveButton("复制") { _, _ ->
                getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("hollow link", link))
                status.append("\n链接已复制到剪贴板")
            }
            .setNegativeButton("关闭", null)
            .show()
    }

    // ---- VPN consent / start (unchanged semantics) ----
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
        status.append("\n服务已启动（前台通知应出现；无配置时服务会 fail-closed 自停）")
    }

    @Deprecated("Skeleton-era result flow; kept simple")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQUEST_VPN_CONSENT -> {
                if (resultCode == RESULT_OK) startVpnService()
                else status.append("\nVPN 授权被拒绝——不启动")
            }
            REQ_OPEN_FILE -> {
                if (resultCode != RESULT_OK) return
                val uri = data?.data ?: return
                try {
                    val text = contentResolver.openInputStream(uri)?.bufferedReader()?.readText()
                        ?: throw IllegalStateException("文件读取失败")
                    funnel(text)
                } catch (e: Exception) {
                    status.append("\n文件导入失败：${e.message}")
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
                    status.append("\n图片扫码失败：${e.message}")
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
                    status.append("\n已导出 .hollow.json")
                } catch (e: Exception) {
                    status.append("\n导出写入失败：${e.message}")
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
