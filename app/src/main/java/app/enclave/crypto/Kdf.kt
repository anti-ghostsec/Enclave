package app.enclave.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.io.InputStream
import java.security.MessageDigest

/**
 * Turns a password (plus an optional keyfile) into a 256-bit key with Argon2id.
 * The keyfile is hashed with SHA-512 and fed in as Argon2's secret input, so
 * the right password alone is useless without the right keyfile.
 */
object Kdf {
    const val DEFAULT_MEMORY_KIB = 64 * 1024
    const val DEFAULT_ITERATIONS = 3
    const val DEFAULT_PARALLELISM = 1

    data class Params(val memoryKiB: Int, val iterations: Int, val parallelism: Int)

    val DEFAULT = Params(DEFAULT_MEMORY_KIB, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM)

    fun derive(password: CharArray, keyfileSecret: ByteArray?, salt: ByteArray, params: Params): ByteArray {
        val pw = Charsets.UTF_8.encode(java.nio.CharBuffer.wrap(password)).let { buf ->
            ByteArray(buf.remaining()).also { buf.get(it); buf.array().fill(0) }
        }
        try {
            val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(params.memoryKiB)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
            if (keyfileSecret != null) builder.withSecret(keyfileSecret)
            val gen = Argon2BytesGenerator()
            gen.init(builder.build())
            val out = ByteArray(Aead.KEY_BYTES)
            gen.generateBytes(pw, out)
            return out
        } finally {
            pw.fill(0)
        }
    }

    /** SHA-512 of a keyfile's full contents. */
    fun keyfileSecret(input: InputStream): ByteArray {
        val md = MessageDigest.getInstance("SHA-512")
        val buf = ByteArray(64 * 1024)
        input.use {
            while (true) {
                val n = it.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest()
    }
}
