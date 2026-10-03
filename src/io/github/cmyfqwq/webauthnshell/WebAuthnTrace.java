package io.github.cmyfqwq.webauthnshell;

import android.os.Looper;
import android.util.Log;
import android.webkit.WebView;

import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;

import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.WeakHashMap;

import de.robv.android.xposed.XposedBridge;

/**
 * Temporary outcome-only WebAuthn observer for Outlook/Swift Backup at rea.okta.com.
 * Does not change validation, credential requests, credentials, or returned promises.
 * Logs only predefined labels, booleans, counts and known DOM exception names.
 * Never logs URLs with paths/query parameters, credential IDs, user IDs, challenges,
 * signatures, authenticatorData, or raw clientDataJSON. No remote debugging enabled.
 * AndroidX API reference: https://developer.android.com/reference/androidx/webkit/WebViewCompat
 */
public final class WebAuthnTrace {
    private static final String TAG = "WA-TRACE";
    private static final String ORIGIN = "https://rea.okta.com";
    private static final String BRIDGE = "__waTraceDiagnostics";
    private static final Set<WebView> INSTALLED = Collections.newSetFromMap(
            new WeakHashMap<WebView, Boolean>());
    private static final String SCRIPT =
            "(() => {\n" +
            "  'use strict';\n" +
            "  const expected = 'https://rea.okta.com';\n" +
            "  if (location.origin !== expected) return;\n" +
            "  const bridge = window.__waTraceDiagnostics;\n" +
            "  if (!bridge || typeof bridge.postMessage !== 'function') return;\n" +
            "  const emit = (event) => { try { bridge.postMessage(JSON.stringify(event)); } catch (_) {} };\n" +
            "  const credentials = navigator.credentials;\n" +
            "  if (!credentials || typeof credentials.get !== 'function') {\n" +
            "    emit({stage: 'unsupported'}); return;\n" +
            "  }\n" +
            "  const marker = '__waTraceInstalled';\n" +
            "  if (credentials[marker]) return;\n" +
            "  const original = credentials.get;\n" +
            "  let sequence = 0;\n" +
            "  const choice = (value, permitted) => value == null ? 'unspecified' :\n" +
            "    (permitted.includes(value) ? value : 'other');\n" +
            "  const errorName = (error) => {\n" +
            "    const permitted = ['NotAllowedError','SecurityError','NotSupportedError',\n" +
            "      'AbortError','InvalidStateError','UnknownError','NotReadableError',\n" +
            "      'DataError','OperationError','ConstraintError','TypeError'];\n" +
            "    return error && permitted.includes(error.name) ? error.name : 'other';\n" +
            "  };\n" +
            "  function tracedGet(options) {\n" +
            "    // Trace only this RP, while leaving other credential operations untouched.\n" +
            "    const pk = options && options.publicKey;\n" +
            "    if (!pk || (pk.rpId != null && pk.rpId !== 'rea.okta.com')) {\n" +
            "      return Reflect.apply(original, this, arguments);\n" +
            "    }\n" +
            "    const id = ++sequence;\n" +
            "    emit({stage: 'start', id,\n" +
            "      uv: choice(pk.userVerification, ['required','preferred','discouraged']),\n" +
            "      mediation: choice(options.mediation, ['conditional','required','optional','silent']),\n" +
            "      allowedCount: Array.isArray(pk.allowCredentials) ? pk.allowCredentials.length : -1});\n" +
            "    let result;\n" +
            "    try { result = Reflect.apply(original, this, arguments); }\n" +
            "    catch (error) { emit({stage: 'syncThrow', id, errorName: errorName(error)}); throw error; }\n" +
            "    try {\n" +
            "      // Observe but return the ORIGINAL Promise, original credential and original errors.\n" +
            "      Promise.prototype.then.call(result, (credential) => {\n" +
            "        try {\n" +
            "          const response = credential && credential.response;\n" +
            "          const event = {stage: 'resolved', id,\n" +
            "            publicKey: !!credential && credential.type === 'public-key',\n" +
            "            hasClientData: !!(response && response.clientDataJSON),\n" +
            "            hasSignature: !!(response && response.signature)};\n" +
            "          if (response && response.clientDataJSON) {\n" +
            "            try {\n" +
            "              const data = JSON.parse(new TextDecoder().decode(response.clientDataJSON));\n" +
            "              event.originKind = typeof data.origin !== 'string' ? 'unknown' :\n" +
            "                (data.origin.startsWith('https://') ? 'web' :\n" +
            "                 data.origin.startsWith('android:apk-key-hash:') ? 'android' : 'other');\n" +
            "              event.originMatchesRp = data.origin === expected;\n" +
            "              event.typeMatches = data.type === 'webauthn.get';\n" +
            "              if (typeof data.crossOrigin === 'boolean') event.crossOrigin = data.crossOrigin;\n" +
            "            } catch (_) { event.metadataError = true; }\n" +
            "          }\n" +
            "          emit(event);\n" +
            "        } catch (_) { emit({stage: 'metadataError', id}); }\n" +
            "      }, (error) => { emit({stage: 'rejected', id, errorName: errorName(error)}); });\n" +
            "    } catch (_) { emit({stage: 'observeFailed', id}); }\n" +
            "    return result;\n" +
            "  }\n" +
            "  try {\n" +
            "    Object.defineProperty(credentials, 'get', {value: tracedGet, configurable: true, writable: true});\n" +
            "    Object.defineProperty(credentials, marker, {value: true, configurable: true});\n" +
            "    emit({stage: 'ready'});\n" +
            "  } catch (error) { emit({stage: 'installFailed', errorName: errorName(error)}); }\n" +
            "})();";

    private WebAuthnTrace() {}

    public static void install(WebView view) {
        boolean listenerAdded = false;
        try {
            String caller = view.getContext().getPackageName();
            if (!"com.microsoft.office.outlook".equals(caller)
                    && !"org.swiftapps.swiftbackup".equals(caller)) return;
            synchronized (INSTALLED) { if (INSTALLED.contains(view)) return; }
            if (Looper.myLooper() != Looper.getMainLooper()) {
                info("install skipped: WebView constructed off main thread");
                return;
            }
            boolean scripts = WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT);
            boolean messages = WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER);
            if (!scripts || !messages) {
                info("unsupported: documentStart=" + scripts + " messages=" + messages);
                return;
            }
            final int[] count = {0};
            WebViewCompat.addWebMessageListener(view, BRIDGE, Collections.singleton(ORIGIN),
                    (webView, message, sourceOrigin, isMainFrame, replyProxy) -> {
                        if (!ORIGIN.equals(sourceOrigin.toString())
                                && !(ORIGIN + "/").equals(sourceOrigin.toString())) return;
                        if (++count[0] > 80) return;
                        try {
                            String text = message.getData();
                            if (text == null || text.length() > 1200) return;
                            JSONObject data = new JSONObject(text);
                            String stage = data.optString("stage");
                            if (!Arrays.asList("ready", "start", "resolved", "rejected", "syncThrow",
                                    "unsupported", "metadataError", "observeFailed", "installFailed")
                                    .contains(stage)) return;
                            StringBuilder safe = new StringBuilder("caller=").append(caller)
                                    .append(" mainFrame=").append(isMainFrame)
                                    .append(" stage=").append(stage);
                            int id = data.optInt("id", -1);
                            if (id >= 0 && id <= 1000000) safe.append(" id=").append(id);
                            int allowed = data.optInt("allowedCount", -2);
                            if (allowed >= -1 && allowed <= 10000) safe.append(" allowedCount=").append(allowed);
                            for (String key : Arrays.asList("publicKey", "hasClientData", "hasSignature",
                                    "originMatchesRp", "typeMatches", "crossOrigin", "metadataError")) {
                                if (data.opt(key) instanceof Boolean) {
                                    safe.append(" ").append(key).append("=").append(data.optBoolean(key));
                                }
                            }
                            appendChoice(safe, data, "originKind", "web", "android", "unknown", "other");
                            appendChoice(safe, data, "uv", "required", "preferred", "discouraged", "unspecified", "other");
                            appendChoice(safe, data, "mediation", "conditional", "required", "optional", "silent", "unspecified", "other");
                            appendChoice(safe, data, "errorName", "NotAllowedError", "SecurityError",
                                    "NotSupportedError", "AbortError", "InvalidStateError", "UnknownError",
                                    "NotReadableError", "DataError", "OperationError", "ConstraintError", "TypeError", "other");
                            info(safe.toString());
                        } catch (Throwable ignored) {
                            info("message could not be parsed; contents suppressed");
                        }
                    });
            listenerAdded = true;
            WebViewCompat.addDocumentStartJavaScript(view, SCRIPT, Collections.singleton(ORIGIN));
            synchronized (INSTALLED) { INSTALLED.add(view); }
            info("trace-v1 registered for " + caller + "; awaiting rea.okta.com document");
        } catch (Throwable error) {
            if (listenerAdded) {
                try { WebViewCompat.removeWebMessageListener(view, BRIDGE); }
                catch (Throwable ignored) { }
            }
            info("INSTALL FAILED type=" + error.getClass().getName());
        }
    }

    private static void appendChoice(StringBuilder safe, JSONObject data, String key, String... permitted) {
        String value = data.optString(key, "");
        if (Arrays.asList(permitted).contains(value)) safe.append(" ").append(key).append("=").append(value);
    }

    private static void info(String message) {
        Log.i(TAG, message);
        XposedBridge.log("[" + TAG + "] " + message);
    }
}
