package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PaymentDtoTest {

    @Test
    fun encodeRecipients_poolsNullAndMemoPresent_omitsPoolsButKeepsMemo() {
        val json = encodeRecipients(
            listOf(Recipient(address = "u1testaddress", amount = 100_000, pools = null, memo = "thanks")),
        )

        assertTrue(json.contains("\"address\":\"u1testaddress\""))
        assertTrue(json.contains("\"amount\":100000"))
        assertTrue(json.contains("\"memo\":\"thanks\""))
        assertFalse(json.contains("\"pools\""))
    }

    @Test
    fun encodeRecipients_poolsSet_encodesPoolSetMaskNotOrdinal() {
        val json = encodeRecipients(
            listOf(Recipient(address = "u1x", amount = 1, pools = PoolSet.of(Pool.SAPLING, Pool.ORCHARD))),
        )

        assertTrue(json.contains("\"pools\":6"))
    }

    @Test
    fun parseTransactionPlan_inputWithNullAmount_parsesAsNull() {
        val json = """
            {"height":2500000,
             "inputs":[{"pool":2,"amount":null,"assetName":"ZEC"}],
             "outputs":[{"pool":1,"amount":40000,"address":"u1out","assetName":"ZEC"}],
             "fee":10000,"canSign":true,"canBroadcast":false}
        """

        val plan = parseTransactionPlan(json)

        assertEquals(
            TransactionPlan(
                height = 2_500_000,
                inputs = listOf(PlanInput(Pool.ORCHARD, amount = null, assetName = "ZEC")),
                outputs = listOf(PlanOutput(Pool.SAPLING, amount = 40_000, address = "u1out", assetName = "ZEC")),
                fee = 10_000,
                canSign = true,
                canBroadcast = false,
            ),
            plan,
        )
    }

    @Test
    fun parseBroadcastResult_zeroErrorCode_isAcceptedAndCarriesTheTxid() {
        val result = parseBroadcastResult("""{"errorCode":0,"message":"a1b2c3"}""")

        assertTrue(result.accepted)
        assertEquals("a1b2c3", result.message)
    }

    @Test
    fun parseBroadcastResult_nonZeroErrorCode_keepsCodeAndReason() {
        val result = parseBroadcastResult(
            """{"errorCode":-25,"message":"tx already committed to best chain"}"""
        )

        assertFalse(result.accepted)
        assertEquals(-25, result.errorCode)
        assertEquals("tx already committed to best chain", result.message)
    }
}
