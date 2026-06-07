package com.prufen.app

import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.prufen.app.crypto.KeyManager
import com.prufen.app.zk.ZkProver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var keyManager: KeyManager
    private lateinit var zkProver: ZkProver

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Simple programmatic UI for the demo
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }
        
        val statusText = TextView(this).apply {
            text = "Prüfen ZK Android Demo\nInitializing..."
            textSize = 16f
            layoutParams = android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 32) }
        }

        val btnGenerateProof = Button(this).apply {
            text = "Generate ZK Proof & Sign"
            isEnabled = false
        }

        layout.addView(statusText)
        layout.addView(btnGenerateProof)
        setContentView(layout)

        // Initialize Crypto and ZK Bridge
        keyManager = KeyManager()
        keyManager.generateDeviceKeyIfNotExists()
        
        zkProver = ZkProver(this)
        zkProver.initialize()

        statusText.text = "Device Key generated. WebView Prover ready."
        btnGenerateProof.isEnabled = true

        btnGenerateProof.setOnClickListener {
            btnGenerateProof.isEnabled = false
            statusText.text = "Generating Zero-Knowledge Proof..."

            CoroutineScope(Dispatchers.IO).launch {
                try {
                    // 1. ZK Proof Generation (MOCK DATA for demo)
                    val proofJson = zkProver.generateProof(
                        birthYear = 1990,
                        birthMonth = 1,
                        birthDay = 1,
                        salt = "123456789",
                        commitment = "7853200119776494731579049073919007882630784258459895508699754940308154824592", // Must match the hash
                        currentYear = 2024,
                        currentMonth = 1,
                        currentDay = 1,
                        minAge = 18
                    )

                    // 2. Keystore Signing to bind the proof to the device
                    val challenge = "challenge_123" // In production, this comes from the backend
                    val signature = keyManager.signMessage(proofJson + challenge)
                    val pubKey = keyManager.getPublicKeyBase64()

                    withContext(Dispatchers.Main) {
                        statusText.text = "✅ Proof Generated & Signed Successfully!\n\n" +
                                "PubKey: ${pubKey?.take(20)}...\n\n" +
                                "Signature: ${signature.take(20)}...\n\n" +
                                "Proof JSON snippet:\n${proofJson.take(100)}..."
                        
                        Log.d("PrufenAndroid", "Proof: $proofJson")
                        Log.d("PrufenAndroid", "Signature: $signature")
                        btnGenerateProof.isEnabled = true
                    }

                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        statusText.text = "❌ Error: ${e.message}"
                        btnGenerateProof.isEnabled = true
                    }
                }
            }
        }
    }
}
