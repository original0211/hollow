package eu.org.brodydung.hollow

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import hollowcore.SecretBox
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The Go facade's SecretBox, backed by the Android Keystore (D7):
 * the stored PSK is AES-256-GCM wrapped under a keystore key that
 * never leaves the TEE/StrongBox-backed store. Token form:
 * "v1:<b64 iv>.<b64 ct+tag>". Any failure to unwrap throws — the Go
 * side turns that into a hard "unwrap failed" error; nothing here or
 * there ever regenerates key material silently.
 */
class KeystoreBox : SecretBox {

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    override fun seal(plain: ByteArray?): String {
        requireNotNull(plain)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val ct = cipher.doFinal(plain)
        return "v1:" + Base64.encodeToString(cipher.iv, Base64.NO_WRAP) +
            "." + Base64.encodeToString(ct, Base64.NO_WRAP)
    }

    override fun `open`(token: String?): ByteArray {
        requireNotNull(token)
        val parts = token.removePrefix("v1:").split(".")
        require(parts.size == 2) { "bad token" }
        val iv = Base64.decode(parts[0], Base64.DEFAULT)
        val ct = Base64.decode(parts[1], Base64.DEFAULT)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        return cipher.doFinal(ct) // AEADBadTagException on tamper — intended
    }

    companion object {
        private const val ALIAS = "hollow-psk-wrap"
    }
}
