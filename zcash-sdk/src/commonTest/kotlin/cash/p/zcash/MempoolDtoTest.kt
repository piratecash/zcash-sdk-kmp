package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class MempoolDtoTest {

    @Test
    fun parseMempoolEvent_epoch_mapsHeight() {
        assertEquals(
            MempoolEvent.Epoch(2_500_000),
            parseMempoolEvent("""{"kind":"epoch","height":2500000}"""),
        )
    }

    @Test
    fun parseMempoolEvent_unconfirmed_mapsEveryField() {
        val event = parseMempoolEvent(
            """
            {"kind":"unconfirmed","txid":"ab0201","size":512,
             "amounts":[{"account":3,"value":900}],
             "notes":[{"account":3,"value":900,"pool":2,"memo":"for you"}]}
            """
        )

        assertEquals(
            MempoolEvent.Unconfirmed(
                txid = "ab0201",
                amounts = listOf(MempoolAmount(account = 3, value = 900)),
                notes = listOf(
                    MempoolNote(account = 3, value = 900, pool = Pool.ORCHARD, memo = "for you")
                ),
                size = 512,
            ),
            event,
        )
    }

    @Test
    fun parseMempoolEvent_spentNote_keepsTheNegativeValue() {
        val event = parseMempoolEvent(
            """
            {"kind":"unconfirmed","txid":"00","size":1,"amounts":[],
             "notes":[{"account":0,"value":-900,"pool":1,"memo":null}]}
            """
        )

        val note = (event as MempoolEvent.Unconfirmed).notes.single()
        assertEquals(-900, note.value)
        assertEquals(Pool.SAPLING, note.pool)
        assertNull(note.memo)
    }

    @Test
    fun parseMempoolEvent_endedWithoutError_returnsNull() {
        assertNull(parseMempoolEvent("""{"kind":"ended","error":null}"""))
    }

    @Test
    fun parseMempoolEvent_endedWithError_throws() {
        val failure = assertFailsWith<ZcashException> {
            parseMempoolEvent("""{"kind":"ended","error":"server unreachable"}""")
        }

        assertEquals("server unreachable", failure.message)
    }

    @Test
    fun parseMempoolEvent_unknownKind_throws() {
        assertFailsWith<ZcashException> { parseMempoolEvent("""{"kind":"reorg"}""") }
    }

    @Test
    fun parseMempoolEvent_unknownPoolBit_throws() {
        assertFailsWith<IllegalStateException> {
            parseMempoolEvent(
                """
                {"kind":"unconfirmed","txid":"00","size":1,"amounts":[],
                 "notes":[{"account":0,"value":1,"pool":9}]}
                """
            )
        }
    }
}
