package app.enclave

import app.enclave.crypto.StateKey
import app.enclave.vault.StateTrust
import app.enclave.vault.StateTrust.Action
import app.enclave.vault.StateTrust.Found
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.AEADBadTagException

/** What Enclave makes of its lock-out state file at start (see StateTrust and PlainPrefs). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class StateTrustTest {
    private fun decide(
        found: Found,
        vault: Boolean = true,
        stateKeys: Boolean? = true,
        oldPreferences: Boolean = false,
        suspectedBefore: Boolean = false,
        suspectedForMs: Long = -1,
    ) = StateTrust.decide(found, vault, stateKeys, oldPreferences, suspectedBefore, suspectedForMs)

    @Test
    fun aReadableFileIsUsed() {
        assertEquals(Action.USE, decide(Found.OPENED))
        assertEquals(Action.USE, decide(Found.OPENED, vault = false))
    }

    @Test
    fun aFaultThatMayPassIsNeverTakenForTampering() {
        // However long it lasts, and even if it was suspected before.
        assertEquals(Action.RETRY, decide(Found.ERROR))
        assertEquals(Action.RETRY, decide(Found.ERROR, suspectedBefore = true, suspectedForMs = 3_600_000))
        // A missing file when the keystore can't say whether any state key exists.
        assertEquals(Action.RETRY, decide(Found.MISSING, stateKeys = null))
    }

    @Test
    fun withNoVaultThereIsNothingToProtect() {
        for (f in listOf(Found.MISSING, Found.REJECTED)) {
            assertEquals(Action.START_EMPTY, decide(f, vault = false))
            assertEquals(Action.START_EMPTY, decide(f, vault = false, suspectedBefore = true))
        }
    }

    @Test
    fun evidenceIsActedOnOnlyOnceSeenAgain() {
        for (f in listOf(Found.MISSING, Found.REJECTED)) {
            // First seen: no password can be tried, nothing is replaced yet.
            assertEquals(Action.SUSPECT, decide(f))
            assertEquals(Action.SUSPECT, decide(f, suspectedForMs = 0))
            assertEquals(Action.SUSPECT, decide(f, suspectedForMs = StateTrust.CONFIRM_MS - 1))
            // Seen again on a later start, or still there a while later.
            assertEquals(Action.DISTRUST, decide(f, suspectedBefore = true))
            assertEquals(Action.DISTRUST, decide(f, suspectedForMs = StateTrust.CONFIRM_MS))
        }
    }

    @Test
    fun settingsFromBefore040MoveOnlyWithNoStateKey() {
        assertEquals(Action.MOVE_OLD, decide(Found.MISSING, stateKeys = false, oldPreferences = true))
        // With a state key there, a missing file was deleted, preferences or not.
        assertEquals(Action.SUSPECT, decide(Found.MISSING, stateKeys = true, oldPreferences = true))
        // No key and nothing to move: a state file that's gone.
        assertEquals(Action.SUSPECT, decide(Found.MISSING, stateKeys = false, oldPreferences = false))
        // A file that's there but opens with no key is never an upgrade.
        assertEquals(Action.SUSPECT, decide(Found.REJECTED, stateKeys = false, oldPreferences = true))
    }

    @Test
    fun onlyPreferencesAVersionBefore040WroteLookOld() {
        assertTrue(StateTrust.looksOld(setOf("disguise", "failed", "wipe_after", "calc_hash", "calc_salt")))
        assertFalse(StateTrust.looksOld(emptySet()))
        // Anything a later version keeps (a record of a wipe, the containers' mark) is planted.
        assertFalse(StateTrust.looksOld(setOf("failed", "wiped_ms")))
        assertFalse(StateTrust.looksOld(setOf("disguise", "main_in_containers")))
        assertFalse(StateTrust.looksOld(setOf("calc_kdf")))
    }

    @Test
    fun theFirstReplacementLeavesAMarginAndLaterOnesDont() {
        // First time: the third wrong password wipes.
        assertEquals(17, StateTrust.distrustCount(20, distrustedBefore = false))
        // Again before the real password was typed: the next one does.
        assertEquals(19, StateTrust.distrustCount(20, distrustedBefore = true))
    }

    @Test
    fun onlyABadTagIsARejection() {
        assertTrue(StateKey.isRejection(AEADBadTagException()))
        // The keystore wraps it at times.
        assertTrue(StateKey.isRejection(ProviderException(KeyStoreException(AEADBadTagException()))))
        assertFalse(StateKey.isRejection(KeyStoreException("busy")))
        assertFalse(StateKey.isRejection(ProviderException("StrongBox didn't answer")))
        assertFalse(StateKey.isRejection(java.io.IOException("read")))
        assertFalse(StateKey.isRejection(IllegalStateException()))
    }

    @Test
    fun aFileTooShortToBeSealedIsRejectedWithoutTheKeystore() {
        // Rejected before any key is asked (the keystore isn't there on the PC at all).
        assertNull(StateKey.open(ByteArray(27)))
    }
}
