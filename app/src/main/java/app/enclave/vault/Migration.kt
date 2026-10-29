package app.enclave.vault

import java.io.IOException
import java.security.MessageDigest

/**
 * Moves a vault from the original one-directory format into deniable containers.
 *
 * Everything is copied byte for byte: the sealed index and settings, every encrypted file and
 * preview. Nothing is decrypted or re-encrypted, so the vault itself (its keys, names, files) is
 * exactly the same afterwards; only where the bytes live changes. Each copy is checked against
 * the original with SHA-256 before the move is marked complete, and only then is the old
 * directory removed. If anything goes wrong, or the vault locks, the old directory is untouched
 * and the next unlock carries on from where it stopped.
 */
object Migration {
    class Cancelled : IOException("stopped")

    data class Progress(val stage: Stage, val done: Long, val total: Long)

    enum class Stage { Copying, Checking }

    fun run(
        old: DirStorage,
        target: ContainerStorage,
        progress: (Progress) -> Unit,
        cancelled: () -> Boolean,
    ) {
        val names = old.names().sorted()
        val total = names.sumOf { old.size(it).coerceAtLeast(0) }
        val buf = ByteArray(256 * 1024)

        fun stopIfAsked() {
            if (cancelled()) throw Cancelled()
        }

        try {
            copyAndCheck(old, target, names, total, buf, progress, ::stopIfAsked)
        } finally {
            buf.fill(0)
        }
    }

    private fun copyAndCheck(
        old: DirStorage,
        target: ContainerStorage,
        names: List<String>,
        total: Long,
        buf: ByteArray,
        progress: (Progress) -> Unit,
        stopIfAsked: () -> Unit,
    ) {
        var done = 0L
        var sinceCommit = 0L
        // 1. Copy every blob that isn't already there (from an earlier, interrupted move).
        progress(Progress(Stage.Copying, 0, total))
        for (name in names) {
            stopIfAsked()
            val size = old.size(name)
            if (target.size(name) != size || !same(old, target, name, buf)) {
                target.put(name) { out ->
                    old.open(name).use { src ->
                        var pos = 0L
                        while (pos < size) {
                            stopIfAsked()
                            val n = src.read(pos, buf, 0, minOf(buf.size.toLong(), size - pos).toInt())
                            if (n <= 0) throw IOException("$name ended early")
                            out.write(buf, 0, n)
                            pos += n
                        }
                    }
                }
                sinceCommit += size
                // Save progress now and then, so an interruption doesn't lose much copying.
                if (sinceCommit > COMMIT_EVERY) {
                    target.commit()
                    sinceCommit = 0
                }
            }
            done += size
            progress(Progress(Stage.Copying, done, total))
        }
        old.loadSettings()?.let(target::saveSettings)
        val index = old.loadIndex() ?: throw IOException("the old vault has no index")
        target.saveIndex(index)

        // 2. Check every byte against the original before anything old is removed.
        done = 0
        progress(Progress(Stage.Checking, 0, total))
        for (name in names) {
            stopIfAsked()
            if (!same(old, target, name, buf)) throw IOException("a copy didn't match its original ($name)")
            done += old.size(name)
            progress(Progress(Stage.Checking, done, total))
        }
        if (!target.loadIndex().contentEquals(index)) throw IOException("the index didn't copy correctly")
        if (!target.loadSettings().contentEquals(old.loadSettings())) throw IOException("the settings didn't copy correctly")
        if (target.names() != old.names()) throw IOException("the file lists don't match")

        // 3. Only now does the container become the vault.
        target.finishMigration()
    }

    private fun same(a: Storage, b: Storage, name: String, buf: ByteArray): Boolean {
        val size = a.size(name)
        if (b.size(name) != size) return false
        return digest(a, name, size, buf).contentEquals(digest(b, name, size, buf))
    }

    private fun digest(s: Storage, name: String, size: Long, buf: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        s.open(name).use { src ->
            var pos = 0L
            while (pos < size) {
                val n = src.read(pos, buf, 0, minOf(buf.size.toLong(), size - pos).toInt())
                if (n <= 0) throw IOException("$name ended early")
                md.update(buf, 0, n)
                pos += n
            }
        }
        return md.digest()
    }

    private const val COMMIT_EVERY = 256L * 1024 * 1024
}
