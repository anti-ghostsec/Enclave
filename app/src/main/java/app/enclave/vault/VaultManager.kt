package app.enclave.vault

import android.content.Context
import app.enclave.crypto.Aead
import app.enclave.crypto.HardwareKey
import app.enclave.crypto.Kdf
import java.io.File
import java.nio.ByteBuffer

enum class Role(val code: Byte) {
    MAIN(1), DECOY(2), WIPE(3);

    companion object {
        fun of(code: Byte) = entries.firstOrNull { it.code == code }
    }
}

data class UnlockResult(val role: Role, val slot: Int, val master: ByteArray)

/**
 * The vault header holds [SLOT_COUNT] key slots. Each slot is the vault's master key wrapped
 * with a key derived from one password (+ optional keyfile). Unused slots are filled with
 * random bytes, so nobody can tell how many passwords exist or which one is a duress password:
 * the role (main / decoy / wipe) is stored inside the encrypted slot.
 *
 * The whole header is additionally wrapped by [HardwareKey], so it can't be attacked off-device.
 */
class Header(val params: Kdf.Params, val salt: ByteArray, val slots: Array<ByteArray>) {
    fun prefix(): ByteArray = ByteBuffer.allocate(PREFIX_BYTES)
        .put(MAGIC).put(VERSION)
        .putInt(params.memoryKiB).putInt(params.iterations).putInt(params.parallelism)
        .put(salt).array()

    fun slotAad(i: Int) = prefix() + byteArrayOf(i.toByte())

    fun serialize(): ByteArray = slots.fold(prefix()) { acc, s -> acc + s }

    companion object {
        const val SLOT_COUNT = 4
        const val SLOT_PLAIN = 1 + Aead.KEY_BYTES
        const val SLOT_SEALED = Aead.NONCE_BYTES + SLOT_PLAIN + Aead.TAG_BYTES
        private val MAGIC = "ENCV".toByteArray()
        private const val VERSION: Byte = 1
        private const val PREFIX_BYTES = 4 + 1 + 12 + 32

        fun parse(b: ByteArray): Header {
            val buf = ByteBuffer.wrap(b)
            val magic = ByteArray(4).also { buf.get(it) }
            require(magic.contentEquals(MAGIC) && buf.get() == VERSION) { "bad header" }
            val params = Kdf.Params(buf.int, buf.int, buf.int)
            val salt = ByteArray(32).also { buf.get(it) }
            val slots = Array(SLOT_COUNT) { ByteArray(SLOT_SEALED).also { s -> buf.get(s) } }
            return Header(params, salt, slots)
        }

        fun randomSlot() = Aead.random(SLOT_SEALED)
    }
}

object VaultManager {
    private lateinit var app: Context

    fun init(context: Context) {
        app = context.applicationContext
        // Left behind if Enclave was killed while a decoy was open. The folder itself is always
        // there, empty, so its presence says nothing about which vault is or was open.
        scratchDir.listFiles()?.forEach { it.deleteRecursively() }
        scratchDir.mkdirs()
        scratchDir.setLastModified(VaultStore.FIXED_TIME)
    }

    private val headerFile get() = File(app.noBackupFilesDir, "header.bin")
    /** Vaults in the original format, one directory each. */
    val vaultsRoot get() = File(app.noBackupFilesDir, "vaults")

    /** The deniable containers. */
    val containersDir get() = File(app.noBackupFilesDir, "store")

    /**
     * Where a decoy opened on its own keeps what's added to it, until it locks. Only ever holds
     * encrypted blobs whose keys are in memory, so whatever is left of it is unreadable.
     */
    val scratchDir get() = File(app.noBackupFilesDir, "scratch")

    fun exists() = headerFile.exists()

    fun dirFor(master: ByteArray): File =
        File(vaultsRoot, Aead.hex(Aead.sha256(master, "dir".toByteArray())).take(24))

    private fun read(): Header = Header.parse(HardwareKey.open(headerFile.readBytes()))

    private fun write(h: Header) {
        val tmp = File(headerFile.path + ".tmp")
        // On the disk before it replaces the old header: it holds the only copy of the keys.
        java.io.FileOutputStream(tmp).use { it.write(HardwareKey.seal(h.serialize())); it.fd.sync() }
        if (!tmp.renameTo(headerFile)) {
            headerFile.delete()
            tmp.renameTo(headerFile)
        }
        headerFile.setLastModified(VaultStore.FIXED_TIME)
    }

    private fun sealSlot(h: Header, i: Int, kek: ByteArray, role: Role, master: ByteArray) {
        h.slots[i] = Aead.seal(kek, byteArrayOf(role.code) + master, h.slotAad(i))
    }

    /** Creates a brand new vault and returns it unlocked. */
    fun create(password: CharArray, keyfileSecret: ByteArray?): UnlockResult {
        val h = Header(Kdf.DEFAULT, Aead.random(32), Array(Header.SLOT_COUNT) { Header.randomSlot() })
        val slot = (0 until Header.SLOT_COUNT).random()
        val master = Aead.random(Aead.KEY_BYTES)
        val kek = Kdf.derive(password, keyfileSecret, h.salt, h.params)
        sealSlot(h, slot, kek, Role.MAIN, master)
        Aead.wipe(kek)
        write(h)
        return UnlockResult(Role.MAIN, slot, master)
    }

    /**
     * A header that no password opens: what's left after a wipe for too many wrong passwords, so
     * the lock screen stays exactly as it was instead of showing that something was destroyed.
     */
    fun createUnopenable() {
        write(Header(Kdf.DEFAULT, Aead.random(32), Array(Header.SLOT_COUNT) { Header.randomSlot() }))
    }

    /**
     * Runs Argon2id once, then tries every slot. Returns null for a wrong password/keyfile.
     *
     * Every slot is always tried. Should one password ever open two slots, the real vault wins:
     * a decoy made by an earlier version could be given any password from inside it, and that
     * must never put the real vault out of reach.
     */
    fun unlock(password: CharArray, keyfileSecret: ByteArray?): UnlockResult? {
        val h = read()
        val kek = Kdf.derive(password, keyfileSecret, h.salt, h.params)
        try {
            var best: UnlockResult? = null
            for (i in 0 until Header.SLOT_COUNT) {
                val plain = runCatching { Aead.open(kek, h.slots[i], h.slotAad(i)) }.getOrNull() ?: continue
                val role = Role.of(plain[0])
                val master = plain.copyOfRange(1, plain.size)
                plain.fill(0)
                if (role != null && (best == null || (role == Role.MAIN && best.role != Role.MAIN))) {
                    best?.master?.let(Aead::wipe)
                    best = UnlockResult(role, i, master)
                } else Aead.wipe(master)
            }
            return best
        } finally {
            Aead.wipe(kek)
        }
    }

    /** What [probe] found: which of the slots asked about the password opens, and a tag for it. */
    class Probe(val opens: Set<Int>, val tag: ByteArray)

    /**
     * Checks a password against [slots] only, and against no others. A session may only ask about
     * slots it already knows: asking about the rest would let whoever holds a decoy password test
     * guesses at the real one, with no lock-out, and learn that it exists.
     *
     * The tag recognises the same password again later without keeping it.
     */
    fun probe(password: CharArray, keyfileSecret: ByteArray?, slots: Collection<Int>): Probe {
        val h = read()
        val kek = Kdf.derive(password, keyfileSecret, h.salt, h.params)
        try {
            val opens = slots.filter { i ->
                runCatching { Aead.open(kek, h.slots[i], h.slotAad(i)) }.getOrNull()?.also { it.fill(0) } != null
            }
            return Probe(opens.toSet(), Aead.sha256(kek, "password tag".toByteArray()))
        } finally {
            Aead.wipe(kek)
        }
    }

    /** (Re)writes one slot, e.g. for a password change or a new duress password. */
    fun setSlot(slot: Int, password: CharArray, keyfileSecret: ByteArray?, role: Role, master: ByteArray) {
        val h = read()
        val kek = Kdf.derive(password, keyfileSecret, h.salt, h.params)
        sealSlot(h, slot, kek, role, master)
        Aead.wipe(kek)
        write(h)
    }

    /**
     * What a decoy session does instead of [setSlot]: the same work, and the header is written
     * again, sealed afresh, so the file changes as it would. No slot is touched.
     */
    fun pretendToSetSlot(password: CharArray, keyfileSecret: ByteArray?) {
        val h = read()
        Aead.wipe(Kdf.derive(password, keyfileSecret, h.salt, h.params))
        write(h)
    }

    fun clearSlot(slot: Int) {
        val h = read()
        h.slots[slot] = Header.randomSlot()
        write(h)
    }

    fun freeSlot(used: Set<Int>): Int? = (0 until Header.SLOT_COUNT).filter { it !in used }.randomOrNull()

    /**
     * Crypto-shreds everything: the hardware key and the header are destroyed first, which makes
     * every encrypted file permanently unreadable, then old-format files are deleted.
     *
     * The containers are kept: every key that opened anything in them came from the destroyed
     * header, so they're now nothing but random bytes. A new vault reuses them straight away
     * instead of spending a minute writing fresh random bytes, which matters most under duress.
     */
    fun wipeAll() {
        HardwareKey.destroy()
        headerFile.delete()
        vaultsRoot.deleteRecursively()
    }
}
