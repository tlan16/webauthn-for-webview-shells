package de.robv.android.xposed;

import java.util.Set;

/**
 * Compile-only stubs for the XposedBridge methods used by this module.
 * Never package these stubs into the APK. The original build.ps1 packages
 * only the io/ module classes; LSPosed supplies the real implementations.
 * Set<?> erases to java.util.Set, matching the real hook methods' return type.
 * Reference: https://api.xposed.info/reference/de/robv/android/xposed/XposedBridge.html
 */
public final class XposedBridge {
    private XposedBridge() {}

    public static Set<?> hookAllConstructors(Class<?> clazz, XC_MethodHook callback) {
        throw new IllegalStateException("compile-only stub");
    }

    public static Set<?> hookAllMethods(Class<?> clazz, String methodName,
                                        XC_MethodHook callback) {
        throw new IllegalStateException("compile-only stub");
    }

    public static void log(String text) {
        throw new IllegalStateException("compile-only stub");
    }
}
