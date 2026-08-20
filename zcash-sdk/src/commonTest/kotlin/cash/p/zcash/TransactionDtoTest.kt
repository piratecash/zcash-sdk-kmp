package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class TransactionDtoTest {

    @Test
    fun parseTransactions_fullRow_mapsEveryField() {
        val transactions = parseTransactions(
            """
            [{"id":3,"txid":"ab0201","height":2500000,"time":1700000000,
              "value":-5000,"memo":"lunch"}]
            """
        )

        assertEquals(
            listOf(
                Transaction(
                    id = 3,
                    txid = "ab0201",
                    height = 2_500_000,
                    time = 1_700_000_000,
                    value = -5_000,
                    memo = "lunch",
                )
            ),
            transactions,
        )
    }

    @Test
    fun parseTransactions_nullMemo_mapsToNull() {
        val transactions = parseTransactions(
            """[{"id":1,"txid":"00","height":1,"time":2,"value":10,"memo":null}]"""
        )

        assertNull(transactions.single().memo)
    }

    @Test
    fun parseTransactions_absentMemo_mapsToNull() {
        val transactions = parseTransactions(
            """[{"id":1,"txid":"00","height":1,"time":2,"value":10}]"""
        )

        assertNull(transactions.single().memo)
    }

    @Test
    fun parseTransactions_emptyList_returnsEmpty() {
        assertEquals(emptyList(), parseTransactions("[]"))
    }
}
