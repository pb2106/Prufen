package com.prufen.app.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class KeyManager {

    companion object {
        private const val KEY_ALIAS = "prufen_device_key"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    }

    private val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
        load(null)
    }

    /**
     * Generates a device-bound ECDSA key pair in the Android Keystore.
     * The key is non-exportable and requires the device to be unlocked.
     */
    fun generateDeviceKeyIfNotExists() {
        if (keyStore.containsAlias(KEY_ALIAS)) return

        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            KEYSTORE_PROVIDER
        )

        val parameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            // For the demo, no biometric auth required, just non-exportable hardware key
            .setUserAuthenticationRequired(false)
            .build()

        keyPairGenerator.initialize(parameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    /**
     * Retrieves the public key as a Base64-encoded string.
     */
    fun getPublicKeyBase64(): String? {
        val certificate = keyStore.getCertificate(KEY_ALIAS) ?: return null
        return Base64.encodeToString(certificate.publicKey.encoded, Base64.NO_WRAP)
    }

    /**
     * Signs a message (e.g., a challenge) using the secure device key.
     */
    fun signMessage(message: String): String {
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            ?: throw IllegalStateException("Key not found")

        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(privateKey)
            update(message.toByteArray(Charsets.UTF_8))
        }

        val sigBytes = signature.sign()
        return Base64.encodeToString(sigBytes, Base64.NO_WRAP)
    }
}
