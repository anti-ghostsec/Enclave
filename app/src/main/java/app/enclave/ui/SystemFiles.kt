package app.enclave.ui

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import androidx.documentfile.provider.DocumentFile
import app.enclave.vault.ExportFolder
import java.io.File
import java.io.IOException
import java.io.OutputStream

/**
 * A name that's safe as one file name: no folder separators, no "." or "..", no control
 * characters. Vault names can come from other apps, so they're never trusted as paths.
 */
fun safeFileName(name: String): String {
    val last = name.replace('\\', '/').substringAfterLast('/')
    val clean = last.filter { it >= ' ' && it != '\u007f' }.trim()
    return if (clean.isEmpty() || clean == "." || clean == "..") "file" else clean
}

/** Picks a safe name like "photo (2).jpg" that [taken] says isn't used yet. */
fun freeName(rawName: String, taken: (String) -> Boolean): String {
    val name = safeFileName(rawName)
    if (!taken(name)) return name
    val base = name.substringBeforeLast('.', name)
    val ext = if ('.' in name) "." + name.substringAfterLast('.') else ""
    var n = 1
    while (true) {
        val candidate = "$base (${n++})$ext"
        if (!taken(candidate)) return candidate
    }
}

/**
 * Picks a name like "photo (2).jpg" that doesn't exist yet in [dir]. The result is always
 * directly inside [dir].
 */
fun freeName(dir: File, rawName: String): File = File(dir, freeName(rawName) { File(dir, it).exists() })

/** A folder on disk to export into. Nothing is ever written outside [root]. */
class DirExportFolder(private val dir: File, private val root: File = dir.canonicalFile) : ExportFolder {
    private fun inside(f: File) = f.canonicalFile.toPath().startsWith(root.toPath())

    override fun folder(name: String): ExportFolder {
        val d = freeName(dir, name)
        check(inside(d)) { "refused to write outside the chosen folder" }
        d.mkdirs()
        return DirExportFolder(d, root)
    }

    override fun file(name: String): OutputStream {
        val f = freeName(dir, name)
        check(inside(f)) { "refused to write outside the chosen folder" }
        return f.outputStream()
    }
}

/**
 * A folder picked with Android's file picker. Enclave only gets the folder the user chose and
 * what it creates inside it, so it can't write anywhere else even if a name tried to.
 */
class TreeExportFolder(private val cr: ContentResolver, private val dir: DocumentFile) : ExportFolder {
    // The names already here, read once: asking the provider about each new name is slow.
    // Compared without case, since phone storage treats "A.jpg" and "a.jpg" as one file.
    private val taken: MutableSet<String> = dir.listFiles().mapNotNullTo(HashSet()) { it.name?.lowercase() }

    private fun pick(raw: String) = freeName(raw) { it.lowercase() in taken }.also { taken += it.lowercase() }

    override fun folder(name: String): ExportFolder =
        TreeExportFolder(cr, dir.createDirectory(pick(name)) ?: throw IOException("couldn't create a folder there"))

    override fun file(name: String): OutputStream {
        // A generic type, so the provider keeps the name as it is instead of adding an extension.
        val f = dir.createFile("application/octet-stream", pick(name)) ?: throw IOException("couldn't create a file there")
        return cr.openOutputStream(f.uri, "w") ?: throw IOException("couldn't write a file there")
    }
}

/** Whether the app that holds a picked document lets Enclave delete it. */
fun canDelete(cr: ContentResolver, uri: Uri): Boolean = runCatching {
    cr.query(uri, arrayOf(DocumentsContract.Document.COLUMN_FLAGS), null, null, null)?.use {
        it.moveToFirst() && (it.getInt(0) and DocumentsContract.Document.FLAG_SUPPORTS_DELETE) != 0
    } ?: false
}.getOrDefault(false)

/** Deletes a picked document. False if it couldn't be deleted. */
fun deleteDocument(cr: ContentResolver, uri: Uri): Boolean =
    runCatching { DocumentsContract.deleteDocument(cr, uri) }.getOrDefault(false)
