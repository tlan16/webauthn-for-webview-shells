package io.github.cmyfqwq.webauthnshell;

import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;

import androidx.webkit.WebSettingsCompat;
import androidx.webkit.WebViewFeature;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.WeakHashMap;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Temporary diagnostic replacement for MainHook.java.
 * Logs to both LSPosed and Android logcat (tag WAShell).
 * Does not log URLs, credentials, cookies, or authentication requests.
 * Uses FOR_APP only: does not bypass origin or app-domain association checks.
 * Adapted from https://github.com/cmyfqwq/webauthn-for-webview-shells
 */
public class MainHook implements IXposedHookLoadPackage {
    private static final String TAG = "WAShell";
    private static final List<String> TARGETS = Arrays.asList(
            "mark.via.gp",
            "mark.via",
            "com.microsoft.office.outlook",
            "org.swiftapps.swiftbackup"
    );

    private static final Set<WebSettings> SEEN = Collections.newSetFromMap(
            new WeakHashMap<WebSettings, Boolean>());
    private static final ThreadLocal<Boolean> APPLYING = new ThreadLocal<>();
    private static boolean installed;

    private static void info(String message) {
        Log.i(TAG, "diag-v2 " + message);
        XposedBridge.log("[WAShell] diag-v2 " + message);
    }

    private static void failure(String stage, Throwable error) {
        Log.e(TAG, "diag-v2 " + stage, error);
        XposedBridge.log("[WAShell] diag-v2 " + stage + "\n"
                + Log.getStackTraceString(error));
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpp) {
        // TEMPORARY diagnostic. Also select Bitwarden in LSPosed scope to activate.
        // Remove Bitwarden from scope after testing; keep Outlook/Swift Backup selected.
        if ("com.x8bit.bitwarden".equals(lpp.packageName)) {
            BitwardenDalTest.install(lpp.classLoader);
            return;
        }
        if (!TARGETS.contains(lpp.packageName)) return;
        synchronized (MainHook.class) {
            if (installed) return;
            installed = true;
        }
        info("S1 loaded package=" + lpp.packageName + " process=" + lpp.processName);

        // Deliberately do not call AndroidX/WebView feature detection here.
        // Package-load callbacks may run before application initialization.
        try {
            Set<?> hooks = XposedBridge.hookAllConstructors(WebView.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (param.getThrowable() != null) return;
                            try {
                                WebView view = (WebView) param.thisObject;
                                WebSettings settings = view.getSettings();
                                apply(settings);
                                WebAuthnTrace.install(view);
                            } catch (Throwable error) {
                                failure("WebView constructor callback failed", error);
                            }
                        }
                    });
            info("S2 WebView constructor hooks=" + hooks.size());
        } catch (Throwable error) {
            failure("Installing WebView constructor hooks failed", error);
        }

        // Re-check when the host obtains settings, including existing WebViews.
        // This is a concrete WebView method rather than an abstract WebSettings setter.
        try {
            Set<?> hooks = XposedBridge.hookAllMethods(WebView.class, "getSettings",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (param.getThrowable() != null) return;
                            Object result = param.getResult();
                            if (result instanceof WebSettings) apply((WebSettings) result);
                        }
                    });
            info("S2 getSettings hooks=" + hooks.size());
        } catch (Throwable error) {
            failure("Installing getSettings hooks failed", error);
        }
        info("S2 installation complete; waiting for a WebView");
    }

    private static void apply(WebSettings settings) {
        if (settings == null || Boolean.TRUE.equals(APPLYING.get())) return;
        APPLYING.set(Boolean.TRUE);
        try {
            boolean first;
            synchronized (SEEN) {
                first = SEEN.add(settings);
            }
            if (first) info("S3 WebView settings reached; checking feature support");

            boolean supported = WebViewFeature.isFeatureSupported(
                    WebViewFeature.WEB_AUTHENTICATION);
            if (first) info("S4 WEB_AUTHENTICATION supported=" + supported);
            if (!supported) return;

            int before = WebSettingsCompat.getWebAuthenticationSupport(settings);
            if (first) info("S5 support before=" + before);
            if (before != WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_FOR_APP) {
                WebSettingsCompat.setWebAuthenticationSupport(settings,
                        WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_FOR_APP);
            }
            int after = WebSettingsCompat.getWebAuthenticationSupport(settings);
            if (first || before != after) {
                info("S6 support after=" + after + " (FOR_APP=1)");
            }
        } catch (Throwable error) {
            failure("Applying WebAuthn support failed", error);
        } finally {
            APPLYING.remove();
        }
    }
}
