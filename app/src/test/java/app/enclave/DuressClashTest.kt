package app.enclave

import app.enclave.vault.VaultActions
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A duress password must never be the same as the vault's own, keyfile or not: duress passwords
 * are set without a keyfile and the lock screen tries every password without it too, so the
 * real password typed with the keyfile forgotten would set the duress password off.
 */
class DuressClashTest {
    private val real = byteArrayOf(1, 1, 1)      // the real password with its keyfile
    private val realAlone = byteArrayOf(2, 2, 2) // the real password, no keyfile
    private val other = byteArrayOf(3, 3, 3)

    private fun clash(
        opens: Set<Int> = emptySet(), bareOpens: Set<Int> = opens, tag: ByteArray = other, bareTag: ByteArray = tag,
        sessionPassword: ByteArray? = null, passwordAlone: ByteArray? = null, sessionDuress: List<ByteArray> = emptyList(),
    ) = VaultActions.clash(0, opens, bareOpens, tag, bareTag, sessionPassword, passwordAlone, sessionDuress)

    @Test
    fun aDuressPasswordCantBeTheRealOneWhenItHasAKeyfile() {
        // The real password alone opens no slot (its slot needs the keyfile), which is all that
        // was checked before.
        val t = clash(tag = realAlone, passwordAlone = realAlone)
        assertTrue(t.own)
        assertFalse(t.other)
    }

    @Test
    fun aDifferentDuressPasswordIsFree() {
        val t = clash(tag = other, passwordAlone = realAlone)
        assertFalse(t.own || t.other)
    }

    @Test
    fun withoutAKeyfileTheRealPasswordIsFoundByItsSlot() {
        assertTrue(clash(opens = setOf(0)).own)
        assertFalse(clash(opens = setOf(0)).other)
    }

    @Test
    fun aNewPasswordWithAKeyfileCantBeADuressPassword() {
        // With the keyfile it opens nothing; alone, it opens the duress password's slot.
        assertTrue(clash(opens = emptySet(), bareOpens = setOf(2), tag = real, bareTag = realAlone).other)
        // The same for a duress password a decoy session only pretends to have.
        assertTrue(clash(opens = emptySet(), bareOpens = emptySet(), tag = real, bareTag = realAlone, sessionDuress = listOf(realAlone)).other)
    }

    @Test
    fun keepingThePasswordAndAddingAKeyfileIsAllowed() {
        // Alone it opens this vault's own slot, and nothing else.
        val t = clash(opens = emptySet(), bareOpens = setOf(0), tag = real, bareTag = realAlone)
        assertFalse(t.other)
    }

    @Test
    fun aDecoysSessionPasswordStillCounts() {
        assertTrue(clash(tag = other, sessionPassword = other).own)
        assertFalse(clash(opens = setOf(0), tag = other, sessionPassword = real).own)
        assertTrue(clash(tag = realAlone, sessionPassword = real, passwordAlone = realAlone).own)
    }
}
