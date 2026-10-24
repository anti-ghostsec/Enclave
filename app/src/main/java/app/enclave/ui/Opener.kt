package app.enclave.ui

import android.content.Context
import android.content.Intent
import android.content.ComponentName
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import app.enclave.vault.Entry
import app.enclave.vault.Media
import app.enclave.vault.Shares
import app.enclave.vault.VaultSettings
import app.enclave.vault.VaultStore
import kotlinx.coroutines.flow.MutableStateFlow

/** Hands vault files to other apps: "Open with", default apps, and the share sheet. */
object Opener {
    const val IN_ENCLAVE = "enclave"
    const val ASK = "ask"

    /** The setting that decides how this kind of file opens. */
    fun preferenceFor(s: VaultSettings, e: Entry) = when {
        Media.isVideo(e) -> s.openVideos
        Media.isAudio(e) -> s.openAudio
        Media.isImage(e) || Media.isText(e) -> IN_ENCLAVE
        else -> s.openOther
    }

    /** Apps on this phone (or in this Secure Folder) that can open [mime]. */
    fun appsFor(ctx: Context, mime: String): List<Pair<String, String>> {
        val pm = ctx.packageManager
        val probe = Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse("content://${ctx.packageName}.files/x"), mime)
        return pm.queryIntentActivities(probe, PackageManager.MATCH_DEFAULT_ONLY)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .distinctBy { it.first }
            .filter { it.first != ctx.packageName }
            .sortedBy { it.second.lowercase() }
    }

    fun appLabel(ctx: Context, pkg: String): String? = runCatching {
        ctx.packageManager.getApplicationInfo(pkg, 0).loadLabel(ctx.packageManager).toString()
    }.getOrNull()

    /** Opens [e] in another app: the default app from Settings if one is set, otherwise asks. */
    fun openExternally(ctx: Context, store: VaultStore, e: Entry, alwaysAsk: Boolean = false) {
        val uri = Shares.create(ctx, store, e)
        val view = Intent(Intent.ACTION_VIEW).setDataAndType(uri, Media.mimeOf(e)).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        val pref = preferenceFor(store.settings.value, e)
        val target = if (!alwaysAsk && pref != ASK && pref != IN_ENCLAVE && appLabel(ctx, pref) != null) view.setPackage(pref)
        else Intent.createChooser(view, "Open with")
        ctx.openExternally(target)
    }

    /**
     * Files waiting for the user to choose where to send them. Enclave shows its own list of apps
     * (see ShareDialog) instead of Android's share sheet, which mixes in contacts and recent chats
     * that are far too easy to tap by mistake.
     */
    val pendingShare = MutableStateFlow<List<Entry>?>(null)

    fun share(ctx: Context, store: VaultStore, entries: List<Entry>) {
        val files = entries.filter { !it.folder }
        if (files.isEmpty()) return ctx.toast("Choose files, not folders, to share")
        pendingShare.value = files
    }

    /** The intent apps receive, without a target yet. Used both to list apps and to send. */
    fun sendIntent(files: List<Entry>, uris: List<Uri>? = null): Intent {
        val types = files.map { Media.mimeOf(it) }.distinct()
        val type = types.singleOrNull() ?: types.map { it.substringBefore('/') }.distinct().singleOrNull()?.let { "$it/*" } ?: "*/*"
        val send = if (files.size == 1) Intent(Intent.ACTION_SEND) else Intent(Intent.ACTION_SEND_MULTIPLE)
        send.type = type
        if (uris != null) {
            if (files.size == 1) send.putExtra(Intent.EXTRA_STREAM, uris[0])
            else send.putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris))
            send.clipData = android.content.ClipData.newRawUri(files[0].name, uris[0]).apply {
                uris.drop(1).forEach { addItem(android.content.ClipData.Item(it)) }
            }
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return send
    }

    /** Apps (never individual contacts) that can receive these files. */
    fun shareTargets(ctx: Context, files: List<Entry>): List<ResolveInfo> {
        val pm = ctx.packageManager
        return pm.queryIntentActivities(sendIntent(files), PackageManager.MATCH_DEFAULT_ONLY)
            .filter { it.activityInfo.packageName != ctx.packageName }
            .sortedBy { it.loadLabel(pm).toString().lowercase() }
    }

    /** Every app that can receive files of any kind, for the Settings list. */
    fun allShareTargets(ctx: Context): List<ResolveInfo> {
        val pm = ctx.packageManager
        return listOf(Intent.ACTION_SEND, Intent.ACTION_SEND_MULTIPLE)
            .flatMap { pm.queryIntentActivities(Intent(it).setType("*/*"), PackageManager.MATCH_DEFAULT_ONLY) }
            .distinctBy { componentOf(it).flattenToString() }
            .filter { it.activityInfo.packageName != ctx.packageName }
            .sortedBy { it.loadLabel(pm).toString().lowercase() }
    }

    fun componentOf(r: ResolveInfo) = ComponentName(r.activityInfo.packageName, r.activityInfo.name)

    /** Sends straight to one chosen app; the files are only made readable at this moment. */
    fun sendTo(ctx: Context, store: VaultStore, files: List<Entry>, target: ComponentName) {
        val uris = files.map { Shares.create(ctx, store, it) }
        ctx.openExternally(sendIntent(files, uris).setComponent(target))
    }
}
