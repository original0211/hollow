package eu.org.brodydung.hollow

import android.content.Context
import hollowcore.Hollowcore

/** One-time Go facade wiring (storage dir + Keystore box). */
object HollowInit {
    @Volatile private var done = false
    fun ensure(ctx: Context) {
        if (done) return
        synchronized(this) {
            if (done) return
            Hollowcore.initPairing(ctx.filesDir.absolutePath, KeystoreBox())
            done = true
        }
    }
}
