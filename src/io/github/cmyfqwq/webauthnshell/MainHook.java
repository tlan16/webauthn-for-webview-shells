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
 * Browser-mode experiment for Outlook and Swift Backup.
 * Logs to both LSPosed and Android logcat (tag WAShell).
 * Uses FOR_BROWSER for those two hosts; preserves Via's original FOR_APP mode.
 * Does not hook Bitwarden, bypass DAL checks, grant Android permissions,
 * alter privileged-app lists, or rewrite/sign credential contents.
 * Bitwarden's native trust flow must approve any unrecognized privileged caller.
 * The existing WebAuthnTrace observes rea.okta.com without changing responses.
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

    private static final List<String> BROWSER_TARGETS = Arrays.asList(
            "com.microsoft.office.outlook",
            "org.swiftapps.swiftbackup"
    );
    private static int requestedMode = WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_FOR_APP;
    private static String modeLabel = "FOR_APP";

    private static final Set<WebSettings> SEEN = Collections.newSetFromMap(
            new WeakHashMap<WebSettings, Boolean>());
    private static final ThreadLocal<Boolean> APPLYING = new ThreadLocal<>();
    private static boolean installed;

    private static void info(String message) {
        Log.i(TAG, "browser-v1 " + message);
        XposedBridge.log("[WAShell] browser-v1 " + message);
    }

    private static void failure(String stage, Throwable error) {
        Log.e(TAG, "browser-v1 " + stage, error);
        XposedBridge.log("[WAShell] browser-v1 " + stage + "\n"
                + Log.getStackTraceString(error));
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpp) {
        // Host apps only. In particular, DO NOT install anything inside Bitwarden.
        if (!TARGETS.contains(lpp.packageName)) return;
        synchronized (MainHook.class) {
            if (installed) return;
            if (BROWSER_TARGETS.contains(lpp.packageName)) {
                requestedMode = WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_FOR_BROWSER;
                modeLabel = "FOR_BROWSER";
            }
            installed = true;
        }
        info("S1 loaded package=" + lpp.packageName + " process=" + lpp.processName
                + " requestedMode=" + modeLabel);
        if (BROWSER_TARGETS.contains(lpp.packageName)) {
            info("Native Android/provider authorization remains enforced; no DAL bypass installed.");
        }

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
            if (before != requestedMode) {
                WebSettingsCompat.setWebAuthenticationSupport(settings, requestedMode);
            }
            int after = WebSettingsCompat.getWebAuthenticationSupport(settings);
            if (first || before != after || after != requestedMode) {
                info("S6 support after=" + after + " requested=" + modeLabel
                        + " applied=" + (after == requestedMode));
            }
        } catch (Throwable error) {
            failure("Applying WebAuthn support failed", error);
        } finally {
            APPLYING.remove();
        }
    }
}
