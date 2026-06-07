package com.prufen.app.zk

import android.annotation.SuppressLint
import android.content.Context
import android.webkit.JavascriptInterface
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONObject
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class ZkProver(private val context: Context) {

    private var webView: WebView? = null
    private var proofContinuation: kotlin.coroutines.Continuation<String>? = null

    /**
     * Initializes the hidden WebView and loads the local snarkjs environment.
     */
    @SuppressLint("SetJavaScriptEnabled")
    fun initialize() {
        webView = WebView(context).apply {
            settings.javaScriptEnabled = true
            settings.allowFileAccess = true
            settings.allowFileAccessFromFileURLs = true
            settings.allowUniversalAccessFromFileURLs = true
            settings.cacheMode = WebSettings.LOAD_NO_CACHE

            addJavascriptInterface(ProofInterface(), "AndroidJS")
            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                }
            }
            // Load the local HTML file bundled in assets
            loadUrl("file:///android_asset/zk_prover.html")
        }
    }

    /**
     * Generates a Groth16 proof using the hidden WebView.
     */
    suspend fun generateProof(
        birthYear: Int,
        birthMonth: Int,
        birthDay: Int,
        salt: String,
        commitment: String,
        currentYear: Int,
        currentMonth: Int,
        currentDay: Int,
        minAge: Int
    ): String = suspendCancellableCoroutine { continuation ->
        proofContinuation = continuation

        val jsonInput = JSONObject().apply {
            put("birthYear", birthYear)
            put("birthMonth", birthMonth)
            put("birthDay", birthDay)
            put("salt", salt)
            put("commitment", commitment)
            put("currentYear", currentYear)
            put("currentMonth", currentMonth)
            put("currentDay", currentDay)
            put("minAge", minAge)
        }

        // Send input to the WebView
        webView?.post {
            webView?.evaluateJavascript("generateProof('${jsonInput}')", null)
        }
    }

    inner class ProofInterface {
        @JavascriptInterface
        fun onProofGenerated(proofJson: String) {
            proofContinuation?.resume(proofJson)
            proofContinuation = null
        }

        @JavascriptInterface
        fun onError(error: String) {
            proofContinuation?.resumeWithException(RuntimeException(error))
            proofContinuation = null
        }
    }
}
