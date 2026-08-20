package cash.p.zcash.demo

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class ZecAmountTest {

    @Test
    fun parseZatoshi_wholeAndFraction_convertsToZatoshi() {
        assertEquals(100_000_000L, parseZatoshi("1"))
        assertEquals(150_000_000L, parseZatoshi("1.5"))
        assertEquals(1L, parseZatoshi("0.00000001"))
        assertEquals(12_345_678L, parseZatoshi(".12345678"))
        assertEquals(100_000_000L, parseZatoshi("  1  "))
    }

    @Test
    fun parseZatoshi_emptyOrNonNumeric_returnsNull() {
        assertNull(parseZatoshi(""))
        assertNull(parseZatoshi("   "))
        assertNull(parseZatoshi("."))
        assertNull(parseZatoshi("abc"))
        assertNull(parseZatoshi("1,5"))
        assertNull(parseZatoshi("1.2.3"))
        assertNull(parseZatoshi("1e8"))
    }

    @Test
    fun parseZatoshi_negative_returnsNull() {
        assertNull(parseZatoshi("-1"))
        assertNull(parseZatoshi("-0.5"))
    }

    @Test
    fun parseZatoshi_moreThanEightDecimals_returnsNull() {
        assertNull(parseZatoshi("0.123456789"))
    }

    @Test
    fun parseZatoshi_overflowsLong_returnsNull() {
        assertNull(parseZatoshi("92233720369"))
        assertEquals(Long.MAX_VALUE, parseZatoshi("92233720368.54775807"))
    }

    @Test
    fun formatZec_printsEightDecimals() {
        assertEquals("1.00000000", formatZec(ZATOSHI_PER_ZEC))
        assertEquals("0.00000001", formatZec(1))
        assertEquals("0.00000000", formatZec(0))
        assertEquals("-0.50000000", formatZec(-50_000_000))
    }
}
