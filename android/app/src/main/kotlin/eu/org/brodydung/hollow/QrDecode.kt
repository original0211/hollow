package eu.org.brodydung.hollow

import android.graphics.Bitmap
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

/** QR-from-image decoding (shell side only; the decoded TEXT still
 *  goes through the Go pairing funnel — never parsed here). */
object QrDecode {
    fun decodeBitmap(bmp: Bitmap): String {
        val w = bmp.width
        val h = bmp.height
        val pixels = IntArray(w * h)
        bmp.getPixels(pixels, 0, w, 0, 0, w, h)
        val source = RGBLuminanceSource(w, h, pixels)
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        return MultiFormatReader().decode(bitmap).text
            ?: throw IllegalStateException("no QR code found in image")
    }
}
