package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

private const val TONIC_DNS_FAILURE =
    "transport error: dns error: dns error: failed to lookup address information: Name or service not known"

class ZcashExceptionTest {

    @Test
    fun category_tlsOrHandshakeMessage_isTls() {
        assertCategory(FailureCategory.TLS, "TLS failure", "handshake failed", "tls handshake eof")
    }

    @Test
    fun category_timeoutMessage_isTimeout() {
        assertCategory(
            FailureCategory.TIMEOUT,
            "request timeout",
            "operation timed out",
            "deadline has elapsed",
            "connect timed out after 60 s",
        )
    }

    @Test
    fun category_connectivityMessage_isNetwork() {
        assertCategory(
            FailureCategory.NETWORK,
            "unexpected eof",
            "connection reset by peer",
            "network is unreachable",
            "socket closed",
            "dns error",
            "lookup failed",
            "could not resolve host",
            "transport error",
            "failed to connect",
            TONIC_DNS_FAILURE,
        )
    }

    @Test
    fun category_databaseMessage_isDatabase() {
        assertCategory(FailureCategory.DATABASE, "sqlite error code 5", "database is locked")
    }

    @Test
    fun category_databaseErrorWithSqliteTailMentioningTimeout_isDatabase() {
        assertCategory(
            FailureCategory.DATABASE,
            "error returned from database: (code: 14) unable to open database file " +
                "[sqlite: 14: os_unix.c:44000: (110) open(*.sqlite3) - Connection timed out]",
        )
    }

    @Test
    fun category_unrecognisedMessage_isOther() {
        assertCategory(FailureCategory.OTHER, "Invalid Key", "Sync ended at block 1 before target 2")
    }

    @Test
    fun stage_twoArgumentConstructor_isNull() {
        assertNull(ZcashException("failure", RuntimeException("cause")).stage)
    }

    private fun assertCategory(expected: FailureCategory, vararg messages: String) {
        messages.forEach { message ->
            assertEquals(expected, ZcashException(message).category, message)
        }
    }
}
