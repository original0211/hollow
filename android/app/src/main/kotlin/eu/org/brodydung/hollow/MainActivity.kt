package eu.org.brodydung.hollow

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import hollowcore.Hollowcore

/**
 * M3-0 shell: one screen, three jobs —
 * 1) display the Go core's version string (proves the gomobile seam),
 * 2) run the VPN consent flow (VpnService.prepare -> system dialog),
 * 3) start/stop the skeleton foreground service.
 * Real connection UI is M3-4.
 */
class MainActivity : Activity() {

    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        status = TextView(this).apply {
            textSize = 16f
            // If this line renders the core string, bind -> AAR -> JNI
            // all work on this device.
            text = "核心通路：${Hollowcore.version()}\n回声自检：${Hollowcore.echo("m3-0")}\n状态：未连接（骨架）"
        }
        val startButton = Button(this).apply {
            text = "开启 VPN（骨架）"
            setOnClickListener { requestConsentOrStart() }
        }
        val stopButton = Button(this).apply {
            text = "停止"
            setOnClickListener {
                startService(Intent(this@MainActivity, HollowVpnService::class.java).setAction(HollowVpnService.ACTION_STOP))
                status.append("\n已发送停止（服务自拆）")
            }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(status)
            addView(startButton)
            addView(stopButton)
        })
    }

    private fun requestConsentOrStart() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            // Not yet consented: the system shows the VPN permission
            // dialog; the result returns to onActivityResult.
            @Suppress("DEPRECATION")
            startActivityForResult(consent, REQUEST_VPN_CONSENT)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        startForegroundService(Intent(this, HollowVpnService::class.java)) // direct call: minSdk 26 has it
        status.append("\n服务已启动（前台通知应出现）")
    }

    @Deprecated("Consent flow predates the Activity Result API; kept simple for the skeleton")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN_CONSENT) {
            if (resultCode == RESULT_OK) startVpnService()
            else status.append("\nVPN 授权被拒绝——不启动（骨架口径：不静默重试）")
        }
    }

    companion object {
        private const val REQUEST_VPN_CONSENT = 1
    }
}
