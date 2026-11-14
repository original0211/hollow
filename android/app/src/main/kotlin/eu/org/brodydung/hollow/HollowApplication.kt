package eu.org.brodydung.hollow

import android.app.Application
import java.io.File

/**
 * Process entry (M3-5): installs the crash-marker handler. A shell
 * (Java/Kotlin-layer) uncaught exception writes a small marker —
 * time + exception class + a truncated message, NEVER payloads or
 * key material — and the next MainActivity launch surfaces it on the
 * status card instead of the crash vanishing silently. Go-core
 * panics abort the process below this layer; that boundary is
 * recorded in the release runbook (§3), not papered over here.
 */
class HollowApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            try {
                val msg = (error.message ?: "").take(120).replace('\n', ' ')
                File(filesDir, CRASH_MARKER).writeText(
                    "${System.currentTimeMillis()} ${error.javaClass.name}: $msg"
                )
            } catch (_: Exception) {
                // Marker writing must never mask the original crash.
            }
            if (previous != null) previous.uncaughtException(thread, error)
            else throw RuntimeException(error)
        }
    }

    companion object {
        const val CRASH_MARKER = "crash-marker.txt"
    }
}
