package eu.org.brodydung.hollow

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.hardware.Camera
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.SurfaceHolder
import android.view.SurfaceView
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer

/**
 * Minimal camera scanner (legacy Camera API — no AndroidX in this
 * shell): preview frames are fed to ZXing until a QR decodes; the
 * decoded TEXT returns to MainActivity, which routes it through the
 * Go pairing funnel like every other import surface.
 */
@Suppress("DEPRECATION")
class ScanActivity : Activity(), SurfaceHolder.Callback {

    private var camera: Camera? = null
    private var scanning = false
    private val handler = Handler(Looper.getMainLooper())
    private val reader = MultiFormatReader()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val view = SurfaceView(this)
        view.holder.addCallback(this)
        setContentView(view)
        if (checkSelfPermission(android.Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.CAMERA), REQ_CAMERA)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_CAMERA && grantResults.firstOrNull() != PackageManager.PERMISSION_GRANTED) {
            setResult(RESULT_CANCELED)
            finish()
        }
    }

    override fun surfaceCreated(holder: SurfaceHolder) {
        try {
            camera = Camera.open()
            camera?.setPreviewDisplay(holder)
            camera?.startPreview()
            scanning = true
            requestFrame()
        } catch (e: Exception) {
            setResult(RESULT_CANCELED)
            finish()
        }
    }

    private fun requestFrame() {
        if (!scanning) return
        camera?.setOneShotPreviewCallback { data, cam ->
            if (!scanning) return@setOneShotPreviewCallback
            val size = cam.parameters.previewSize
            val text = try {
                val src = PlanarYUVLuminanceSource(data, size.width, size.height, 0, 0, size.width, size.height, false)
                reader.decode(BinaryBitmap(HybridBinarizer(src))).text
            } catch (e: Exception) {
                null
            } finally {
                reader.reset()
            }
            if (text != null) {
                scanning = false
                setResult(RESULT_OK, Intent().putExtra(EXTRA_QR_TEXT, text))
                finish()
            } else {
                handler.postDelayed({ requestFrame() }, 250)
            }
        }
    }

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        scanning = false
        try {
            camera?.stopPreview()
            camera?.release()
        } catch (_: Exception) {
        }
        camera = null
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {}

    companion object {
        const val EXTRA_QR_TEXT = "qr_text"
        private const val REQ_CAMERA = 7
    }
}
