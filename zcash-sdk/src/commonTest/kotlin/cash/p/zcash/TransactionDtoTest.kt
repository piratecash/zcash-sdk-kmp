package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TransactionDtoTest {

    @Test
    fun parseTransactions_fullRow_mapsEveryField() {
        val transactions = parseTransactions(
            """
            [{"id":3,"txid":"ab0201","height":2500000,"time":1700000000,
              "value":-5000,"memo":"lunch","fee":15000,"totalReceived":1000,
              "isChange":false,"recipient":"u1recipient"}]
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
                    fee = 15_000,
                    totalReceived = 1_000,
                    isChange = false,
                    recipient = "u1recipient",
                )
            ),
            transactions,
        )
    }

    @Test
    fun parseTransactions_changeRow_keepsTheChangeFlag() {
        val transactions = parseTransactions(
            """
            [{"id":4,"txid":"00","height":1,"time":2,"value":-1000,
              "fee":10000,"totalReceived":9000,"isChange":true,"recipient":null}]
            """
        )

        val transaction = transactions.single()
        assertTrue(transaction.isChange)
        assertEquals(9_000, transaction.totalReceived)
        assertNull(transaction.recipient)
    }

    @Test
    fun parseTransactions_absentDetailFields_mapToNeutralDefaults() {
        val transaction = parseTransactions(
            """[{"id":1,"txid":"00","height":1,"time":2,"value":10}]"""
        ).single()

        assertEquals(0, transaction.fee)
        assertEquals(0, transaction.totalReceived)
        assertFalse(transaction.isChange)
        assertNull(transaction.recipient)
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
