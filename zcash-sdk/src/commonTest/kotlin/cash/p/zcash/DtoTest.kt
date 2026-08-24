package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DtoTest {

    @Test
    fun parseAccounts_fullRow_mapsEveryField() {
        val accounts = parseAccounts(
            """
            [{"id":7,"name":"main","birth":419200,"aindex":1,"dindex":2,"position":3,
              "hidden":false,"enabled":true,"internal":false,"hw":0,
              "height":2500000,"time":1700000000,"balance":123456789}]
            """
        )

        assertEquals(
            AccountInfo(
                id = 7,
                name = "main",
                birthHeight = 419200,
                accountIndex = 1,
                diversifierIndex = 2,
                position = 3,
                height = 2500000,
                time = 1700000000L,
                balance = 123456789L,
                hidden = false,
                enabled = true,
                internal = false,
                hardwareWallet = false,
            ),
            accounts.single(),
        )
    }

    @Test
    fun parseAccounts_timestampBeyondIntRange_isParsed() {
        val accounts = parseAccounts(
            """
            [{"id":1,"name":"a","birth":0,"aindex":0,"dindex":0,"position":0,
              "hidden":false,"enabled":true,"internal":false,"hw":0,
              "height":0,"time":4000000000,"balance":0}]
            """
        )

        assertEquals(4_000_000_000L, accounts.single().time)
    }

    @Test
    fun parseAccounts_unknownNativeField_isIgnored() {
        val accounts = parseAccounts(
            """
            [{"id":1,"name":"a","birth":0,"aindex":0,"dindex":0,"position":0,
              "hidden":false,"enabled":true,"internal":false,"hw":2,
              "height":0,"time":0,"balance":0,"somethingAddedLater":"x"}]
            """
        )

        assertEquals(true, accounts.single().hardwareWallet)
    }

    @Test
    fun parseAccounts_emptyList_returnsNoAccounts() {
        assertEquals(emptyList(), parseAccounts("[]"))
    }

    @Test
    fun parseAddresses_missingReceivers_areNull() {
        val addresses = parseAddresses(
            """{"unified":"u1abc","sapling":null,"orchard":"o1abc","diversifierIndex":2}"""
        )

        assertEquals("u1abc", addresses.unified)
        assertEquals("o1abc", addresses.orchard)
        assertNull(addresses.sapling)
        assertNull(addresses.transparent)
        assertEquals(2, addresses.diversifierIndex)
    }

    @Test
    fun toPoolBalance_nativeOrdering_mapsEachPool() {
        val balance = longArrayOf(
            1L, 0L, 0L, 0L,
            2L, 0L, 0L, 0L,
            4L, 0L, 0L, 0L,
            8L, 0L, 0L, 0L,
        ).toPoolBalance()

        assertEquals(1L, balance[Pool.TRANSPARENT].total)
        assertEquals(2L, balance[Pool.SAPLING].total)
        assertEquals(4L, balance[Pool.ORCHARD].total)
        assertEquals(8L, balance[Pool.IRONWOOD].total)
        assertEquals(15L, balance.total)
        assertEquals(14L, balance.shielded)
    }

    @Test
    fun toPoolBalance_fourFieldsPerPool_areReadInOrder() {
        val balance = longArrayOf(0L, 0L, 0L, 0L, 10L, 2L, 3L, 7L).toPoolBalance()

        assertEquals(
            Balance(available = 10L, locked = 2L, changePending = 3L, valuePending = 7L),
            balance[Pool.SAPLING],
        )
        assertEquals(10L, balance.available)
        assertEquals(22L, balance.total)
    }

    @Test
    fun toPoolBalance_shortNativeArray_missingPoolsAreZero() {
        val balance = longArrayOf(1L, 2L).toPoolBalance()

        assertEquals(Balance(), balance[Pool.ORCHARD])
        assertEquals(3L, balance.total)
    }
}
