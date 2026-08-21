package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class MigrationDtoTest {

    @Test
    fun parseMigrationStatus_migratingPhase_mapsEveryField() {
        val status = parseMigrationStatus(
            """{"phase":"migrating","sdNotesCount":4,"nonSdNotesCount":1,"ironwoodSdCount":2}"""
        )

        assertEquals(
            MigrationStatus(
                phase = MigrationPhase.MIGRATING,
                standardNotes = 4,
                nonStandardNotes = 1,
                migratedNotes = 2,
            ),
            status,
        )
    }

    @Test
    fun parseMigrationStatus_unknownPhase_throws() {
        assertFailsWith<ZcashException> {
            parseMigrationStatus(
                """{"phase":"whatever","sdNotesCount":0,"nonSdNotesCount":0,"ironwoodSdCount":0}"""
            )
        }
    }

    @Test
    fun parseMigrationStep_splitComplete_mapsEventFeeAndStatus() {
        val step = parseMigrationStep(
            """
            {"event":"splitComplete","fee":25000,
             "status":{"phase":"splitting","sdNotesCount":1,"nonSdNotesCount":3,"ironwoodSdCount":0}}
            """
        )

        assertEquals(MigrationEvent.SPLIT_COMPLETE, step.event)
        assertEquals(25_000L, step.fee)
        assertEquals(MigrationPhase.SPLITTING, step.status.phase)
        assertEquals(3, step.status.nonStandardNotes)
    }

    @Test
    fun parseMigrationStep_nothingToDo_mapsToWaitingEvent() {
        val step = parseMigrationStep(
            """
            {"event":"nothingToDo","fee":0,
             "status":{"phase":"migrating","sdNotesCount":2,"nonSdNotesCount":0,"ironwoodSdCount":1}}
            """
        )

        assertEquals(MigrationEvent.NOTHING_TO_DO, step.event)
        assertEquals(0L, step.fee)
    }

    @Test
    fun parseMigrationStep_broadcastEvent_carriesTxid() {
        val step = parseMigrationStep(
            """
            {"event":"migrateComplete","fee":20000,"txid":"9f3c",
             "status":{"phase":"migrating","sdNotesCount":1,"nonSdNotesCount":0,"ironwoodSdCount":2}}
            """
        )

        assertEquals("9f3c", step.txid)
    }

    @Test
    fun parseMigrationStep_eventWithoutBroadcast_hasNoTxid() {
        val step = parseMigrationStep(
            """
            {"event":"complete","fee":0,
             "status":{"phase":"complete","sdNotesCount":0,"nonSdNotesCount":0,"ironwoodSdCount":3}}
            """
        )

        assertNull(step.txid)
    }

    @Test
    fun parseMigrationStep_errorEvent_throws() {
        assertFailsWith<ZcashException> {
            parseMigrationStep(
                """
                {"event":"error","fee":0,
                 "status":{"phase":"splitting","sdNotesCount":0,"nonSdNotesCount":1,"ironwoodSdCount":0}}
                """
            )
        }
    }
}
