package cash.p.zcash

import co.touchlab.kermit.LogWriter
import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
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

    @Test
    fun syncFlow_repeatedProgressAndFinalHeight_emitsEachStateOnce() = runTest {
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(
                localHeight = TARGET_HEIGHT,
                progress = SyncProgress(TARGET_HEIGHT, 0),
                syncDelayMs = 1_000,
            ),
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
    fun syncFlow_progressAndFinalHeightExceedTarget_clampsAndDeduplicatesStates() = runTest {
        val states = syncFlow(
            accountIds = listOf(ACCOUNT_ID),
            actionsPerSync = 1,
            transparentLimit = 1,
            checkpointAge = 1,
            mutex = Mutex(),
            backend = FakeSyncBackend(
                localHeight = TARGET_HEIGHT + 100,
                progress = SyncProgress(TARGET_HEIGHT + 200, 0),
                syncDelayMs = 1_000,
            ),
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
    fun sync_actionsPerSyncOmitted_passesPublicDefaultToBackend() = runTest {
        val backend = FakeSyncBackend()

        ZcashWallet.forSyncTest(backend).sync(accountIds = listOf(ACCOUNT_ID)).toList()

        assertEquals(10_000, backend.receivedActionsPerSync)
    }

    @Test
    fun sync_successfulNoOp_writesNoLogs() = runTest {
        val records = captureLogs {
            ZcashWallet.forSyncTest(FakeSyncBackend()).sync(listOf(ACCOUNT_ID)).toList()
        }

        assertTrue(records.isEmpty())
    }

    @Test
    fun sync_progressingPass_writesOnlyFirstProgressAndTerminalLogs() = runTest {
        val records = captureLogs {
            ZcashWallet.forSyncTest(
                FakeSyncBackend(
                    progress = SyncProgress(LOCAL_HEIGHT, 0),
                    syncDelayMs = 1_000,
                )
            ).sync(listOf(ACCOUNT_ID)).toList()
        }

        assertEquals(2, records.size)
    }

    @Test
    fun sync_failure_writesOneSanitizedTerminalLog() = runTest {
        val secret = "seed abandon abandon private-key"
        val records = captureLogs {
            ZcashWallet.forSyncTest(
                FakeSyncBackend(syncFailure = ZcashException("TLS failure $secret"))
            ).sync(listOf(ACCOUNT_ID)).toList()
        }

        assertEquals(1, records.size)
        assertTrue(records.none { it.message.contains(secret) || it.throwable?.message.orEmpty().contains(secret) })
    }

    @Test
    fun sync_cancelled_writesOneSanitizedTerminalLog() = runTest {
        val secret = "viewing-key-secret"
        val records = captureLogs {
            ZcashWallet.forSyncTest(
                FakeSyncBackend(
                    syncFailure = ZcashException("Sync canceled $secret"),
                    cancelRequested = true,
                )
            ).sync(listOf(ACCOUNT_ID)).toList()
        }

        assertEquals(1, records.size)
        assertTrue(records.none { it.message.contains(secret) || it.throwable?.message.orEmpty().contains(secret) })
    }

    private suspend fun captureLogs(block: suspend () -> Unit): List<LogRecord> {
        val previousWriters = Logger.config.logWriterList
        val previousSeverity = Logger.config.minSeverity
        val writer = CapturingLogWriter()
        Logger.setLogWriters(writer)
        Logger.setMinSeverity(Severity.Debug)
        return try {
            block()
            writer.records
        } finally {
            Logger.setLogWriters(previousWriters)
            Logger.setMinSeverity(previousSeverity)
        }
    }
}

private class FakeSyncBackend(
    private val localHeight: Int? = TARGET_HEIGHT,
    private val syncFailure: ZcashException? = null,
    private val heightFailure: ZcashException? = null,
    private val progress: SyncProgress? = null,
    private val syncDelayMs: Long = 0,
    override val cancelRequested: Boolean = false,
) : SyncBackend {

    var receivedActionsPerSync: Int? = null
        private set

    override suspend fun latestHeight(): Int = TARGET_HEIGHT

    override suspend fun synchronize(
        accountIds: List<Int>,
        target: Int,
        actionsPerSync: Int,
        transparentLimit: Int,
        checkpointAge: Int,
    ) {
        receivedActionsPerSync = actionsPerSync
        delay(syncDelayMs)
        syncFailure?.let { throw it }
    }

    override suspend fun progress(): SyncProgress? = progress

    override suspend fun syncedHeight(accountIds: List<Int>): Int? {
        heightFailure?.let { throw it }
        return localHeight
    }

    override fun onStart() = Unit

    override fun onFinish() = Unit
}

private data class LogRecord(val message: String, val throwable: Throwable?)

private class CapturingLogWriter : LogWriter() {
    val records = mutableListOf<LogRecord>()

    override fun log(
        severity: Severity,
        message: String,
        tag: String,
        throwable: Throwable?,
    ) {
        records += LogRecord(message, throwable)
    }
}
