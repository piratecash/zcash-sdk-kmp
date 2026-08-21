package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PoolSetTest {

    @Test
    fun mask_matchesNativeBitOrder() {
        // rust/src/pay/pool.rs: 0 transparent, 1 sapling, 2 orchard, 3 ironwood
        assertEquals(0b0001, PoolSet.of(Pool.TRANSPARENT).mask)
        assertEquals(0b0010, PoolSet.of(Pool.SAPLING).mask)
        assertEquals(0b0100, PoolSet.of(Pool.ORCHARD).mask)
        assertEquals(0b1000, PoolSet.of(Pool.IRONWOOD).mask)
    }

    @Test
    fun constants_matchNativeAliases() {
        assertEquals(0b1111, PoolSet.ALL.mask)
        assertEquals(0b1110, PoolSet.SHIELDED.mask)
        assertTrue(PoolSet.NONE.isEmpty)
    }

    @Test
    fun shielded_excludesTransparent() {
        assertFalse(Pool.TRANSPARENT in PoolSet.SHIELDED)
        assertEquals(listOf(Pool.SAPLING, Pool.ORCHARD, Pool.IRONWOOD), PoolSet.SHIELDED.toList())
    }

    @Test
    fun plusMinus_areIdempotent() {
        val set = PoolSet.NONE + Pool.ORCHARD + Pool.ORCHARD
        assertEquals(PoolSet.of(Pool.ORCHARD), set)
        assertEquals(PoolSet.NONE, set - Pool.ORCHARD - Pool.ORCHARD)
    }

    @Test
    fun balance_pendingAndTotal_sumTheirParts() {
        val balance = Balance(available = 10L, changePending = 3L, valuePending = 7L)

        assertEquals(10L, balance.pending)
        assertEquals(20L, balance.total)
    }

    @Test
    fun poolBalance_sumsAndSeparatesTransparent() {
        val balance = PoolBalance(
            mapOf(
                Pool.TRANSPARENT to Balance(available = 100L),
                Pool.ORCHARD to Balance(available = 250L),
            )
        )
        assertEquals(350L, balance.total)
        assertEquals(250L, balance.shielded)
        assertEquals(Balance(), balance[Pool.SAPLING])
    }
}
