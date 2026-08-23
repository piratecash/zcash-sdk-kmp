package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.runTest

private const val ACCOUNT_ID = 7
private const val LOCAL_HEIGHT = 2_500_000
private const val TARGET_HEIGHT = 2_500_100

class ZcashSyncFlowTest {

    @Test
    fun syncFlow_nativeFails_emitsFailedWithoutSynced() = runTest {
        val failure = ZcashException("compact block stream failed")
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(syncFailure = failure),
        ).toList()

        assertEquals(SyncState.Connecting, states.first())
        val failed = assertIs<SyncState.Failed>(states.last())
        assertEquals(failure.message, failed.error.message)
        assertTrue(SyncState.Synced !in states)
    }

    @Test
    fun syncFlow_nativeReturnsBeforeTarget_reportsFailureInsteadOfSynced() = runTest {
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(localHeight = LOCAL_HEIGHT),
        ).toList()

        assertEquals(SyncState.Syncing(LOCAL_HEIGHT, TARGET_HEIGHT), states[1])
        val failure = assertIs<SyncState.Failed>(states.last())
        assertTrue(failure.error.message.orEmpty().contains("before target"))
        assertTrue(SyncState.Synced !in states)
    }

    @Test
    fun syncFlow_requestedAccountIsMissing_reportsFailureInsteadOfSynced() = runTest {
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(localHeight = null),
        ).toList()

        val failure = assertIs<SyncState.Failed>(states.last())
        assertTrue(failure.error.message.orEmpty().contains("requested accounts"))
        assertTrue(SyncState.Synced !in states)
    }

    @Test
    fun syncFlow_finalHeightReadFails_reportsTheReadFailureInsteadOfSynced() = runTest {
        val readFailure = ZcashException("account height read failed")
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(heightFailure = readFailure),
        ).toList()

        val failure = assertIs<SyncState.Failed>(states.last())
        assertEquals(readFailure.message, failure.error.message)
        assertTrue(SyncState.Synced !in states)
    }

    @Test
    fun syncFlow_nativeReachesTarget_emitsSyncedAfterTheFinalHeight() = runTest {
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(localHeight = TARGET_HEIGHT),
        ).toList()

        assertEquals(
            listOf(
                SyncState.Connecting,
                SyncState.Syncing(TARGET_HEIGHT, TARGET_HEIGHT),
                SyncState.Synced,
            ),
            states,
        )
    }

    @Test
    fun syncFlow_cancelledNativeRun_emitsStopped() = runTest {
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(
                syncFailure = ZcashException("Sync canceled"),
                cancelRequested = true,
            ),
        ).toList()

        assertEquals(SyncState.Stopped, states.last())
        assertTrue(SyncState.Synced !in states)
    }
}

private class FakeSyncBackend(
    private val localHeight: Int? = TARGET_HEIGHT,
    private val syncFailure: ZcashException? = null,
    private val heightFailure: ZcashException? = null,
    override val cancelRequested: Boolean = false,
) : SyncBackend {

    override suspend fun latestHeight(): Int = TARGET_HEIGHT

    override suspend fun synchronize(
        accountIds: List<Int>,
        target: Int,
        actionsPerSync: Int,
        transparentLimit: Int,
        checkpointAge: Int,
    ) {
        syncFailure?.let { throw it }
    }

    override suspend fun progress(): SyncProgress? = null

    override suspend fun syncedHeight(accountIds: List<Int>): Int? {
        heightFailure?.let { throw it }
        return localHeight
    }

    override fun onStart() = Unit

    override fun onFinish() = Unit
}
