package io.github.cmyfqwq.webauthnshell;

import android.os.SystemClock;
import android.util.Log;

import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;

/**
 * TEMPORARY SECURITY-REDUCING DIAGNOSTIC. Remove Bitwarden from LSPosed scope
 * immediately after testing. Restarting Bitwarden RE-ARMS the ten-minute window.
 *
 * Matches Bitwarden Android v2026.9.0-bwpm (published build 21909) source:
 * network/.../service/DigitalAssetLinkServiceImpl.kt
 * network/.../model/DigitalAssetLinkCheckResponseJson.kt
 *
 * Only changes a successfully fetched DAL response from linked=false to true
 * for Outlook or Swift Backup and the handle_all_urls relation. Other callers,
 * network failures, privileged-browser checks and credential data are untouched.
 * Pinned to RP rea.okta.com. DOES NOT pin caller certificates: diagnosis only.
 * Does not invent a web origin, bypass unlock/biometrics, or change TLS checks.
 *
 * The com.bitwarden.** classes used here are kept by the release ProGuard rules.
 * Result/Continuation handling is reflective and fails closed on mismatch.
 * Handles a single-payload serializable wrapper even if R8 renamed kotlin.Result.
 * Logs an override only after the complete outgoing result is reconstructed.
 * Not device-tested. No credentials, challenges or response payloads are logged.
 */
public final class BitwardenDalTest {
    private static final String TAG = "BW-DAL-TEST";
    private static final String ALLOWED_RP = "rea.okta.com";
    private static final String SERVICE =
            "com.bitwarden.network.service.DigitalAssetLinkServiceImpl";
    private static final String MODEL =
            "com.bitwarden.network.model.DigitalAssetLinkCheckResponseJson";
    private static final String RELATION = "delegate_permission/common.handle_all_urls";
    private static final Set<String> PACKAGES = new HashSet<>(Arrays.asList(
            "com.microsoft.office.outlook", "org.swiftapps.swiftbackup"));
    private static final long WINDOW_MS = 10 * 60 * 1000L;
    private static final int MAX_OVERRIDES = 8;
    private static long startedAt;
    private static int overrides;
    private static boolean installed;

    private BitwardenDalTest() {}

    public static synchronized void install(ClassLoader loader) {
        if (installed) return;
        installed = true;
        startedAt = SystemClock.elapsedRealtime();
        info("diag-v3 Installing TEMPORARY DAL test for build 21909; RP="
                + ALLOWED_RP + "; ten minutes per process start.");
        try {
            Class<?> service = Class.forName(SERVICE, false, loader);
            Set<String> names = new HashSet<>();
            int hooks = 0;
            for (Method method : service.getDeclaredMethods()) {
                Class<?>[] types = method.getParameterTypes();
                if (!method.getName().startsWith("checkDigitalAssetLinksRelations")
                        || types.length != 5
                        || types[0] != String.class || types[1] != String.class
                        || types[2] != String.class
                        || !List.class.isAssignableFrom(types[3])
                        || !types[4].isInterface()
                        || !names.add(method.getName())) continue;
                final Class<?> continuationType = types[4];
                info("diag-v3 service method=" + method.getName()
                        + " continuation=" + continuationType.getName());
                hooks += XposedBridge.hookAllMethods(service, method.getName(),
                        new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) {
                                final Request request = requestFor(param.args);
                                if (request == null || !windowOpen()) return;
                                info("DAL requested: " + request.label());
                                final Object original = param.args[4];
                                if (original == null) return;
                                try {
                                    param.args[4] = Proxy.newProxyInstance(
                                            continuationType.getClassLoader(),
                                            new Class<?>[]{continuationType},
                                            (proxy, invoked, args) -> {
                                                if (invoked.getDeclaringClass() != Object.class) {
                                                    info("diag-v3 continuation method=" + invoked.getName()
                                                            + " params=" + invoked.getParameterCount()
                                                            + " return=" + invoked.getReturnType().getName());
                                                }
                                                // Identify Continuation.resumeWith(Object):void
                                                // structurally, so its name need not be stable.
                                                Object[] forwarded = args;
                                                if (invoked.getReturnType() == void.class
                                                        && invoked.getParameterCount() == 1
                                                        && invoked.getParameterTypes()[0] == Object.class
                                                        && args != null && args.length == 1) {
                                                    forwarded = args.clone();
                                                    forwarded[0] = transform(args[0], request, "continuation");
                                                }
                                                try {
                                                    return invoked.invoke(original, forwarded);
                                                } catch (InvocationTargetException error) {
                                                    throw error.getCause();
                                                }
                                            });
                                } catch (Throwable error) {
                                    failure("Could not wrap continuation; leaving request unchanged", error);
                                }
                            }

                            @Override
                            protected void afterHookedMethod(MethodHookParam param) {
                                Request request = requestFor(param.args);
                                if (request == null) return;
                                if (param.getThrowable() != null) {
                                    // Only log the exception class, never its payload/message.
                                    info("diag-v3 service threw=" + param.getThrowable().getClass().getName());
                                    return;
                                }
                                Object before = param.getResult();
                                Object after = transform(before, request, "immediate return");
                                if (after != before) param.setResult(after);
                            }
                        }).size();
            }
            if (hooks == 0) throw new IllegalStateException("No matching service method found");
            info("Installed " + hooks + " hook(s). No override occurs until a matching DAL result arrives.");
        } catch (Throwable error) {
            failure("INSTALL FAILED; do not interpret this run as a bypass test", error);
        }
    }

    private static Request requestFor(Object[] args) {
        if (args == null || args.length != 5
                || !(args[0] instanceof String) || !(args[1] instanceof String)
                || !(args[2] instanceof String) || ((String) args[2]).isEmpty()
                || !PACKAGES.contains(args[1])
                || !Collections.singletonList(RELATION).equals(args[3])) return null;
        try {
            URI site = URI.create((String) args[0]);
            if (!"https".equalsIgnoreCase(site.getScheme())
                    || !ALLOWED_RP.equalsIgnoreCase(site.getHost())
                    || (site.getPort() != -1 && site.getPort() != 443)
                    || (site.getPath() != null && !site.getPath().isEmpty()
                        && !"/".equals(site.getPath()))
                    || site.getUserInfo() != null || site.getQuery() != null
                    || site.getFragment() != null) return null;
            return new Request((String) args[1], site.getHost());
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static Object transform(Object value, Request request, String stage) {
        info("diag-v3 " + stage + " resultType="
                + (value == null ? "null" : value.getClass().getName())
                + ": " + request.label());
        if (!windowOpen()) {
            info("diag-v3 test window/count exhausted; returning unchanged");
            return value;
        }
        Object changed = rewrite(value, request, 0);
        if (changed == value) {
            info("diag-v3 " + stage + " unchanged");
            return value;
        }
        synchronized (BitwardenDalTest.class) {
            if (!windowOpen()) return value;
            overrides++;
        }
        // Only log/count a completed replacement, not an inner object that failed to rebox.
        info("OVERRIDE linked=false -> true: " + request.label()
                + " via=" + stage + "; remove Bitwarden scope after testing");
        return changed;
    }

    private static Object rewrite(Object value, Request request, int depth) {
        if (value == null || depth > 2) return value;
        try {
            Class<?> type = value.getClass();
            if (MODEL.equals(type.getName())) {
                boolean linked = (Boolean) type.getMethod("getLinked").invoke(value);
                info("Original DAL linked=" + linked + ": " + request.label());
                if (linked) return value;
                Constructor<?> ctor = type.getDeclaredConstructor(
                        boolean.class, String.class, String.class);
                ctor.setAccessible(true);
                return ctor.newInstance(true,
                        type.getMethod("getMaxAge").invoke(value),
                        type.getMethod("getDebugString").invoke(value));
            }

            // Preserve the known Kotlin wrapper when these literal API names survive R8.
            if ("kotlin.Result".equals(type.getName())) {
                try {
                    Method unbox = type.getDeclaredMethod("unbox-impl");
                    Method box = type.getDeclaredMethod("box-impl", Object.class);
                    unbox.setAccessible(true);
                    box.setAccessible(true);
                    Object inner = unbox.invoke(value);
                    info("diag-v3 Kotlin Result payloadType=" + typeName(inner));
                    Object changed = rewrite(inner, request, depth + 1);
                    return changed == inner ? value : box.invoke(null, changed);
                } catch (NoSuchMethodException renamedMethods) {
                    info("diag-v3 Kotlin wrapper method names changed; inspecting shape");
                }
            }

            // R8 can rename kotlin.Result. Do not guess its new name or bypass failures.
            // Accept only a final Serializable class directly extending Object, with
            // exactly ONE nonstatic Object field containing the exact known DAL model.
            if (type.getSuperclass() == Object.class
                    && Modifier.isFinal(type.getModifiers())
                    && Serializable.class.isAssignableFrom(type)) {
                Field payload = null;
                int count = 0;
                for (Field field : type.getDeclaredFields()) {
                    if (!Modifier.isStatic(field.getModifiers())) {
                        count++;
                        payload = field;
                    }
                }
                if (count == 1 && payload != null && payload.getType() == Object.class) {
                    payload.setAccessible(true);
                    Object inner = payload.get(value);
                    info("diag-v3 single-payload wrapper=" + type.getName()
                            + " payloadType=" + typeName(inner));
                    if (inner == null || !MODEL.equals(inner.getClass().getName())) return value;
                    Object changed = rewrite(inner, request, depth + 1);
                    if (changed == inner) return value;

                    Method factory = null;
                    int factories = 0;
                    for (Method candidate : type.getDeclaredMethods()) {
                        if (Modifier.isStatic(candidate.getModifiers())
                                && candidate.getReturnType() == type
                                && candidate.getParameterCount() == 1
                                && candidate.getParameterTypes()[0] == Object.class) {
                            factory = candidate;
                            factories++;
                        }
                    }
                    Object rebuilt;
                    if (factories == 1) {
                        factory.setAccessible(true);
                        rebuilt = factory.invoke(null, changed);
                    } else {
                        Constructor<?> ctor = type.getDeclaredConstructor(Object.class);
                        ctor.setAccessible(true);
                        rebuilt = ctor.newInstance(changed);
                    }
                    // Ensure the outgoing wrapper really contains our replacement.
                    if (rebuilt != null && rebuilt.getClass() == type
                            && payload.get(rebuilt) == changed) return rebuilt;
                    info("diag-v3 wrapper reconstruction could not be verified; unchanged");
                    return value;
                }
            }
            // COROUTINE_SUSPENDED, failures and unexpected shapes stay untouched.
            info("diag-v3 no supported DAL payload in type=" + type.getName());
            return value;
        } catch (Throwable error) {
            failure("Result transformation failed; keeping original validation result", error);
            return value;
        }
    }

    private static String typeName(Object value) {
        return value == null ? "null" : value.getClass().getName();
    }

    private static synchronized boolean windowOpen() {
        return overrides < MAX_OVERRIDES
                && SystemClock.elapsedRealtime() - startedAt < WINDOW_MS;
    }

    private static void info(String message) {
        Log.i(TAG, message);
        XposedBridge.log("[" + TAG + "] " + message);
    }

    private static void failure(String message, Throwable error) {
        Log.e(TAG, message, error);
        XposedBridge.log("[" + TAG + "] " + message + "\n" + Log.getStackTraceString(error));
    }

    private static final class Request {
        final String packageName;
        final String host;
        Request(String packageName, String host) {
            this.packageName = packageName;
            this.host = host;
        }
        String label() { return "caller=" + packageName + " RP=" + host; }
    }
}
