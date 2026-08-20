package cash.p.zcash

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** Published BIP-39 test vector (all-zero entropy) — never holds funds. */
private const val TEST_PHRASE =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

private const val BIRTH_HEIGHT = 2_000_000

/** Pinned in the Rust tests too: both sides must derive the very same spending key. */
private const val TEST_PHRASE_USK_SHA256 =
    "3fabc1d61f40e5cb045261c10c1e0c559f48f7305d19c4200716424846fd1285"

/** Unified full viewing key of [TEST_PHRASE], account 0 — watch-only, holds no spending material. */
private const val TEST_UFVK =
    "uview1qggz6nejagvka9wtm9r7xf84kkwy4cc0cgchptr98w0cyz33cj4958q5ulkd32nz2u3s0sp9yhcw7tu2n3n" +
        "lw9x6ulghyd2zgc857tnzme2zpr3vn24zhtm2rjduv9a5zxlmzz404n7l0k69gmu4tfn2g3vpcn03rhz63e3l" +
        "92fn8gra37tyly7utvgveswl20vz23pu84rc2nyqess38wvlgr2xzyhgj232ne5qutpe6ql6ghzetdy7pfzcm" +
        "dzd5gd5dnwk25fwv7nnzmnty7u5ax3nzzgr6pdc905ckpd0s9v2cvn7e03qm7r46e5ngax536ywz7zxjptymm" +
        "90px0rhvmqtwvttuy6d7degly023lqvskclk6mezyt69dwu6c4tfzrjgq4uuh5xa9m5dclgatykgtrrw268qe" +
        "5pldfkx73f2kd5yyy2tjpjql92pa6tsk2nh2h88q23nee9z379het4akl6haqmuwf9d0nl0susg4tnxyk"

private val TEST_DB_KEY = ByteArray(32) { it.toByte() }

/** Header of every unencrypted SQLite file; SQLCipher stores random salt there instead. */
private val SQLITE_MAGIC = "SQLite format 3\u0000".toByteArray(Charsets.US_ASCII)

/**
 * End-to-end against the real native library, entirely offline: account creation, listing,
 * address derivation and balance all run on the local database.
 */
class ZcashWalletIntegrationTest {

    @Test
    fun restoreAccount_publishedTestVector_isListedWithItsBirthHeight() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        val accounts = wallet.accounts()
        assertEquals(1, accounts.size)
        assertEquals(id, accounts.single().id)
        assertEquals("vector", accounts.single().name)
        assertEquals(BIRTH_HEIGHT, accounts.single().birthHeight)
    }

    @Test
    fun addresses_restoredAccount_hasUnifiedAndItsReceivers() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        val addresses = wallet.addresses(id)
        assertTrue(assertNotNull(addresses.unified).startsWith("u1"))
        assertTrue(assertNotNull(addresses.sapling).startsWith("zs1"))
        assertTrue(assertNotNull(addresses.transparent).startsWith("t1"))
    }

    @Test
    fun balance_freshAccount_isZeroInEveryPool() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        val balance = wallet.balance(id)
        assertEquals(0L, balance.total)
        Pool.entries.forEach { assertEquals(0L, balance[it], "pool $it") }
    }

    @Test
    fun deleteAccount_afterRestore_leavesNoAccounts() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        wallet.deleteAccount(id)

        assertTrue(wallet.accounts().isEmpty())
    }

    @Test
    fun restoreAccount_blankKey_isRejectedBeforeTheNativeCall() = withWallet { wallet ->
        assertFailsWith<IllegalArgumentException> { wallet.restoreAccount(name = "blank", key = " ") }

        assertTrue(wallet.accounts().isEmpty())
    }

    @Test
    fun restoreAccount_noPools_isRejectedBeforeTheNativeCall() = withWallet { wallet ->
        assertFailsWith<IllegalArgumentException> {
            wallet.restoreAccount(name = "poolless", key = TEST_PHRASE, pools = PoolSet.NONE)
        }

        assertTrue(wallet.accounts().isEmpty())
    }

    @Test
    fun restoreAccount_unifiedFullViewingKey_yieldsAddressesAndAZeroBalance() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "watch-only", key = TEST_UFVK, birthHeight = BIRTH_HEIGHT)

        assertTrue(assertNotNull(wallet.addresses(id).unified).startsWith("u1"))
        assertEquals(0L, wallet.balance(id).total)
    }

    @Test
    fun deriveSpendingKey_withoutOpeningAWallet_isDeterministicAndMatchesTheRustVector() =
        runBlocking {
            val key = ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN)

            assertEquals(TEST_PHRASE_USK_SHA256, sha256Hex(key))
            assertContentEquals(key, ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN))
        }

    @Test
    fun deriveSpendingKey_invalidPhrase_failsWithAZcashException() = runBlocking {
        assertFailsWith<ZcashException> {
            ZcashSdk.deriveSpendingKey("not a seed phrase", ZcashNetwork.MAIN)
        }
        Unit
    }

    @Test
    fun deriveSpendingKey_negativeAccountIndex_isRejectedBeforeTheNativeCall() = runBlocking {
        assertFailsWith<IllegalArgumentException> {
            ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN, accountIndex = -1)
        }

        listOf(0, Int.MAX_VALUE).forEach { index ->
            val key = ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN, index)
            assertTrue(key.isNotEmpty(), "account index $index")
        }
    }

    @Test
    fun generateSeedPhrase_freshPhrase_differsEachTimeAndRestoresAnAccount() = withWallet { wallet ->
        val phrase = ZcashSdk.generateSeedPhrase()
        assertNotEquals(phrase, ZcashSdk.generateSeedPhrase())

        val id = wallet.restoreAccount(name = "generated", key = phrase, birthHeight = BIRTH_HEIGHT)

        assertEquals(id, wallet.accounts().single().id)
    }

    @Test
    fun close_calledTwice_isIdempotent() = withWallet { wallet ->
        wallet.close()
        wallet.close()

        assertFailsWith<ZcashException> { wallet.accounts() }
    }

    @Test
    fun open_withDbKey_writesAFileWithoutThePlaintextSqliteHeader() = withTempDir { directory ->
        val dbFile = writeEncryptedDatabase(directory)

        val header = Files.newInputStream(dbFile).use { it.readNBytes(SQLITE_MAGIC.size) }

        assertFalse(header.contentEquals(SQLITE_MAGIC))
    }

    @Test
    fun open_encryptedDatabaseWithoutTheKey_fails() = withTempDir { directory ->
        val dbFile = writeEncryptedDatabase(directory)

        assertFailsWith<ZcashException> { openWallet(dbFile.absolutePathString()) }
    }

    private suspend fun writeEncryptedDatabase(directory: Path): Path {
        val dbFile = directory.resolve("wallet.db")
        val wallet = openWallet(dbFile.absolutePathString(), TEST_DB_KEY)
        try {
            wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
        } finally {
            wallet.close()
        }
        return dbFile
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun withWallet(block: suspend (ZcashWallet) -> Unit) = withTempDir { directory ->
        val wallet = openWallet(directory.resolve("wallet.db").absolutePathString())
        try {
            block(wallet)
        } finally {
            wallet.close()
        }
    }

    private fun withTempDir(block: suspend (Path) -> Unit) = runBlocking {
        val directory = Files.createTempDirectory("zcash-sdk-test")
        ZcashSdk.initialize(directory.absolutePathString())
        try {
            block(directory)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private suspend fun openWallet(dbPath: String, dbKey: ByteArray? = null) = ZcashWallet.open(
        dbPath = dbPath,
        network = ZcashNetwork.MAIN,
        server = ServerConfig(url = "http://127.0.0.1:1"),
        dbKey = dbKey,
    )
}
