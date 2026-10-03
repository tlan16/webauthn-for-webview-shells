package io.github.cmyfqwq.webauthnshell;

/**
 * RETIRED: inert compatibility stub replacing the temporary DAL bypass.
 * Keeping this class lets older source references compile without re-enabling
 * any bypass. The new MainHook does not call it. This file may also be deleted
 * once the new MainHook has replaced the previous version.
 */
public final class BitwardenDalTest {
    private BitwardenDalTest() {}

    public static void install(ClassLoader ignored) {
        android.util.Log.i("BW-DAL-TEST", "DISABLED: DAL bypass retired; no hooks installed.");
    }
}
