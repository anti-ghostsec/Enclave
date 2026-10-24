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
import app.enclave.ui.MainActivity
import app.enclave.vault.PlainPrefs

/**
 * Disguises are activity-aliases declared in the manifest: exactly one is enabled at a time,
 * and that one decides the name and icon shown in the app drawer.
 */
object Disguise {
    data class Preset(val id: String, val label: String, val icon: Int, val fg: Int, val bg: Int) {
        val alias get() = "app.enclave.alias.$id"
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
    }

    fun canPinShortcut(c: Context) = ShortcutManagerCompat.isRequestPinShortcutSupported(c)

    /** A home-screen icon with any name and any picture. The launcher asks the user to confirm. */
    fun pinCustom(c: Context, name: String, icon: Bitmap): Boolean {
        val info = ShortcutInfoCompat.Builder(c, "custom_${System.currentTimeMillis()}")
            .setShortLabel(name)
            .setLongLabel(name)
            .setIcon(IconCompat.createWithAdaptiveBitmap(icon))
            .setIntent(Intent(c, MainActivity::class.java).setAction(Intent.ACTION_MAIN))
            .build()
        return ShortcutManagerCompat.requestPinShortcut(c, info, null)
    }
}
