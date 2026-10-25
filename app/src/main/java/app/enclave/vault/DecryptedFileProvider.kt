package app.enclave.vault

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.provider.OpenableColumns
import android.system.ErrnoException
import android.system.OsConstants
import app.enclave.crypto.ChunkedCipher
import java.io.FileNotFoundException

/**
 * Lets another app open a vault file without Enclave ever writing the plaintext to disk. The
 * other app gets a virtual, seekable file whose bytes are decrypted on demand. See [Shares] for
 * how long a link stays valid.
 */
class DecryptedFileProvider : ContentProvider() {
    private val thread by lazy { HandlerThread("enclave-share").apply { start() } }

    override fun onCreate() = true

    private fun share(uri: Uri) = Shares.get(uri) ?: throw FileNotFoundException("expired")

    override fun getType(uri: Uri): String? = Shares.get(uri)?.mime

    override fun query(uri: Uri, projection: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor {
        val sh = share(uri)
        val cols = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(cols, 1).apply {
            addRow(cols.map { if (it == OpenableColumns.SIZE) sh.size else if (it == OpenableColumns.DISPLAY_NAME) sh.name else null })
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw SecurityException("read only")
        val sh = share(uri)
        val reader = ChunkedCipher.Reader(sh.open(), sh.key, sh.size)
        val sm = context!!.getSystemService(StorageManager::class.java)
        return sm.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY, object : ProxyFileDescriptorCallback() {
            override fun onGetSize() = reader.size
            override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
                if (!Shares.isLive(uri)) throw ErrnoException("read", OsConstants.EACCES)
                return reader.read(offset, data, 0, size).coerceAtLeast(0)
            }
            override fun onRelease() = reader.close()
        }, Handler(thread.looper))
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, s: String?, a: Array<out String>?) = 0
    override fun update(uri: Uri, v: ContentValues?, s: String?, a: Array<out String>?) = 0
}
