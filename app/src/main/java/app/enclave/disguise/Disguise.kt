package app.enclave.disguise

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import app.enclave.R
import app.enclave.vault.PlainPrefs

/**
 * Disguises are activity-aliases declared in the manifest: exactly one is enabled at a time,
 * and that one decides the name and icon shown in the app drawer.
 */
object Disguise {
    data class Preset(val id: String, val label: String, val icon: Int, val fg: Int, val bg: Int) {
        val alias get() = "app.enclave.alias.$id"
        /** The entry other apps see when choosing a file, under this disguise's name and icon. */
        val pickAlias get() = "app.enclave.pick.$id"
    }

    val presets = listOf(
        Preset("Default", "Enclave", R.mipmap.ic_enclave, R.drawable.fg_enclave, R.color.icon_bg_enclave),
        Preset("Calculator", "Calculator", R.mipmap.ic_calculator, R.drawable.fg_calculator, R.color.icon_bg_calculator),
        Preset("Notes", "Notes", R.mipmap.ic_notes, R.drawable.fg_notes, R.color.icon_bg_notes),
        Preset("Weather", "Weather", R.mipmap.ic_weather, R.drawable.fg_weather, R.color.icon_bg_weather),
        Preset("Clock", "Clock", R.mipmap.ic_clock, R.drawable.fg_clock, R.color.icon_bg_clock),
        Preset("Compass", "Compass", R.mipmap.ic_compass, R.drawable.fg_compass, R.color.icon_bg_compass),
        Preset("Tools", "System Tools", R.mipmap.ic_tools, R.drawable.fg_tools, R.color.icon_bg_tools),
    )

    fun current(): Preset = presets.firstOrNull { it.id == PlainPrefs.disguise } ?: presets.first()

    fun apply(c: Context, preset: Preset) {
        val pm = c.packageManager
        // Enable the new one first so the app is never left without a launcher entry.
        pm.setComponentEnabledSetting(ComponentName(c.packageName, preset.alias),
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
        presets.filter { it != preset }.forEach {
            pm.setComponentEnabledSetting(ComponentName(c.packageName, it.alias),
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED, PackageManager.DONT_KILL_APP)
        }
        PlainPrefs.disguise = preset.id
        // The entry other apps pick files from wears the same disguise.
        if (pickerEnabled(c)) setPickerEnabled(c, true)
    }

    private fun enabled(c: Context, name: String) =
        c.packageManager.getComponentEnabledSetting(ComponentName(c.packageName, name)) == PackageManager.COMPONENT_ENABLED_STATE_ENABLED

    private fun setEnabled(c: Context, name: String, on: Boolean) = c.packageManager.setComponentEnabledSetting(
        ComponentName(c.packageName, name),
        if (on) PackageManager.COMPONENT_ENABLED_STATE_ENABLED else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
        PackageManager.DONT_KILL_APP,
    )

    /** Whether other apps can pick files from Enclave (Settings → Other apps). */
    fun pickerEnabled(c: Context) = presets.any { enabled(c, it.pickAlias) }

    /** Turns picking on under the current disguise's name and icon, or off altogether. */
    fun setPickerEnabled(c: Context, on: Boolean) {
        val now = current()
        if (on) setEnabled(c, now.pickAlias, true)
        presets.filter { !on || it != now }.forEach { if (enabled(c, it.pickAlias)) setEnabled(c, it.pickAlias, false) }
    }

    /**
     * Earlier versions turned the picker itself on and off, and it always appeared as "Enclave".
     * If it was on, it's now on under the current disguise.
     */
    fun moveOldPicker(c: Context) {
        val old = ComponentName(c, app.enclave.ui.PickActivity::class.java)
        val state = c.packageManager.getComponentEnabledSetting(old)
        if (state == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT) return
        if (state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED) setPickerEnabled(c, true)
        // Back to the manifest's setting (on), or one switched off earlier would stay unreachable.
        c.packageManager.setComponentEnabledSetting(old, PackageManager.COMPONENT_ENABLED_STATE_DEFAULT, PackageManager.DONT_KILL_APP)
    }

    fun canPinShortcut(c: Context) = ShortcutManagerCompat.isRequestPinShortcutSupported(c)

    /**
     * A home-screen icon with any name and any picture. The launcher asks the user to confirm.
     * It opens Enclave through the current disguise's entry, not the bare activity (which has no
     * name or icon of its own, so the system would fill in "Enclave" on the start-up screen). It
     * stops working if the disguise is changed later, and has to be added again.
     */
    fun pinCustom(c: Context, name: String, icon: Bitmap): Boolean {
        val info = ShortcutInfoCompat.Builder(c, "custom_${System.currentTimeMillis()}")
            .setShortLabel(name)
            .setLongLabel(name)
            .setIcon(IconCompat.createWithAdaptiveBitmap(icon))
            .setIntent(Intent(Intent.ACTION_MAIN).setComponent(ComponentName(c.packageName, current().alias)))
            .build()
        return ShortcutManagerCompat.requestPinShortcut(c, info, null)
    }
}
