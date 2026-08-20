package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class SyncStateTest {

    @Test
    fun terminalSyncState_noError_isSynced() {
        assertEquals(SyncState.Synced, terminalSyncState(error = null, cancelRequested = false))
    }

    @Test
    fun terminalSyncState_errorAfterCancelRequest_isStopped() {
        val error = ZcashException("Sync canceled")

        assertEquals(SyncState.Stopped, terminalSyncState(error, cancelRequested = true))
    }

    @Test
    fun terminalSyncState_errorWithoutCancelRequest_isFailed() {
        val error = ZcashException("Server unreachable")

        assertEquals(SyncState.Failed(error), terminalSyncState(error, cancelRequested = false))
    }

    /** A cancel that lost the race leaves the flag set, but an empty error slot still means success. */
    @Test
    fun terminalSyncState_cancelRequestedButNoError_isSynced() {
        assertEquals(SyncState.Synced, terminalSyncState(error = null, cancelRequested = true))
    }

    @Test
    fun syncProgressOf_packedWord_splitsHeightAndTime() {
        val packed = (2_500_000L shl 32) or 1_700_000_000L

        assertEquals(SyncProgress(height = 2_500_000, time = 1_700_000_000L), syncProgressOf(packed))
    }

    @Test
    fun syncProgressOf_timestampBeyondIntRange_staysPositive() {
        val packed = (2_500_000L shl 32) or 4_000_000_000L

        assertEquals(4_000_000_000L, syncProgressOf(packed)?.time)
    }

    @Test
    fun syncProgressOf_beforeFirstBlock_isNull() {
        assertNull(syncProgressOf(0L))
    }
}
