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
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.runBlocking

/** Published BIP-39 test vector (all-zero entropy) — never holds funds. */
private const val TEST_PHRASE =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

private const val BIRTH_HEIGHT = 2_000_000

/**
 * A v6 transaction spending outpoint `01..01:0` — an input no wallet in this suite owns.
 * Byte-for-byte the vector the Rust `transparent_transaction()` test helper builds.
 */
private const val FOREIGN_TRANSACTION_HEX =
    "0600008098b684d85b16a537000000000000000001010101010101010101010101010101" +
        "01010101010101010101010101010101010000000000ffffffff0000000000"

private fun String.hexToBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** BIP-39 passphrase, the "25th word": a different wallet from the very same phrase. */
private const val TEST_PASSPHRASE = "pepper"

private const val TEST_PHRASE_PASSPHRASE_USK_SHA256 =
    "fe58e5f0215f80de0fd298d04c27192dd6ffc0c0848b7f6ddae6704588962163"

/** BIP-44 `m/44'/133'/0'/0/3` of the BIP-39 seed of [TEST_PHRASE] with [TEST_PASSPHRASE]. */
private const val TEST_PHRASE_PASSPHRASE_TRANSPARENT = "t1WaKiZ8GaKjV8seRko8T5j8s4UXTZcGBPi"

/**
 * Cross-vendor vector: the ECC SDK derives these receivers from [ECC_PHRASE] with an empty
 * passphrase (`app/src/androidTest/.../ZcashAddressDerivationTest.kt`). Holds no funds.
 */
private const val ECC_PHRASE =
    "deputy visa gentle among clean scout farm drive comfort patch skin salt ranch cool ramp " +
        "warrior drink narrow normal lunch behind salt deal person"
private const val ECC_TRANSPARENT_RECEIVER = "t1WksXp7ci6XkPNkEHNkFfzQXbRpBCQw7kW"
private const val ECC_SAPLING_RECEIVER =
    "zs1yc4sgtfwwzz6xfsy2xsradzr6m4aypgxhfw2vcn3hatrh5ryqsr08sgpemlg39vdh9kfupx20py"

/** ZIP-320 form of [ECC_TRANSPARENT_RECEIVER] — the one address kind nothing else here produces. */
private const val ECC_TEX_RECEIVER = "tex134f6aaltdxvueh5uwl65wwfr5n2jr4fmcakzpq"

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

/** Account-level (m/44'/133'/0') transparent extended private key of [TEST_PHRASE] — spends. */
private const val TEST_XPRV =
    "xprv9yMAh5zLARRVxiM7BXEzJ2t6WbW7dbm8G765ctzqhjYqW9GAtei2NjQyYmDsoVoWxTdfY5D1uDAm58bcTb35GH" +
        "TxKRCVzpv42SfuxTfPTCm"

/** Account-level transparent extended public key of [TEST_PHRASE] — watch-only. */
private const val TEST_XPUB =
    "xpub6DXuQW17LykdVpnmb4Vu3mocrZtUdokvLqTNZXDUDLvMVutc92kNKTJUpr7QzurmRGgdDfVSx6RgYCEi4C1M" +
        "NmZfwvXaVDn5R6noWao5gzw"

/** Account-level Sapling extended spending key of [TEST_PHRASE] — spends the shielded pool. */
private const val TEST_SAPLING_ESK =
    "secret-extended-key-main1q00pkhghqqqqpqpjr7aphsx37860r2y85wfgq66meql6jw69ls69aztxjhq8cmn" +
        "jdhc9v7jnk3utf4g66ddp6cll6fw0vqthr9vnczdjqkxyelkjxgtq2a5g5w6ngqj4rnewvnf3ehh7fzftv4jpkgz" +
        "rtv4jqjej6zdge4gr0se3lftqty8gvymk3097nzt4mdy34ftxea0yfwg84tgmyjckvpngs4zkwfleqwvd9n870zk" +
        "jgt5d5s4uxyqcwsh8t298lgl5vf95g9qdtz6vv"

/** Account-level Sapling extended full viewing key of [TEST_PHRASE] — watch-only. */
private const val TEST_SAPLING_EFVK =
    "zxviews1q00pkhghqqqqpqpjr7aphsx37860r2y85wfgq66meql6jw69ls69aztxjhq8cmnjd5k8kq2gx555yanx" +
        "7mv0hsgyw8nn4dmsl44afssw5whnkfqxrgcs343rpv59a97w4320fa3m6jderp4y8rhywd3edkvqetmt9wtde7yx" +
        "0se3lftqty8gvymk3097nzt4mdy34ftxea0yfwg84tgmyjckvpngs4zkwfleqwvd9n870zkjgt5d5s4uxyqcwsh8" +
        "t298lgl5vf95g9qw2wx7h"

/** A Sapling spending key of the wrong network: well-formed, only its HRP differs. */
private const val TEST_FOREIGN_SAPLING_ESK =
    "secret-extended-key-test1q00pkhghqqqqpqpjr7aphsx37860r2y85wfgq66meql6jw69ls69aztxjhq8cmn" +
        "jdhc9v7jnk3utf4g66ddp6cll6fw0vqthr9vnczdjqkxyelkjxgtq2a5g5w6ngqj4rnewvnf3ehh7fzftv4jpkgz" +
        "rtv4jqjej6zdge4gr0se3lftqty8gvymk3097nzt4mdy34ftxea0yfwg84tgmyjckvpngs4zkwfleqwvd9n870zk" +
        "jgt5d5s4uxyqcwsh8t298lgl5vf95g9qxhxc5v"

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

        val balance = wallet.balance(id, confirmations = 0)
        assertEquals(0L, balance.total)
        Pool.entries.forEach { assertEquals(Balance(), balance[it], "pool $it") }
    }

    @Test
    fun balance_unsyncedAccount_confirmationThresholdIsAcceptedByTheNativeLayer() =
        withWallet { wallet ->
            val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

            val balance = wallet.balance(id, confirmations = 10)

            assertEquals(0L, balance.total)
            assertEquals(0L, balance.available)
        }

    @Test
    fun balance_negativeConfirmations_isRejectedBeforeTheNativeCall() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        assertFailsWith<IllegalArgumentException> { wallet.balance(id, confirmations = -1) }
    }

    @Test
    fun maxSpendable_freshAccount_isZeroForEverySourcePool() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        val sourcePools = listOf(
            PoolSet.of(Pool.TRANSPARENT),
            PoolSet.of(Pool.SAPLING),
            PoolSet.of(Pool.ORCHARD, Pool.IRONWOOD),
            PoolSet.ALL,
        )

        sourcePools.forEach {
            assertEquals(0L, wallet.maxSpendable(id, it, confirmations = 0), "pools ${it.toList()}")
        }
    }

    @Test
    fun maxSpendable_negativeConfirmations_isRejectedBeforeTheNativeCall() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        assertFailsWith<IllegalArgumentException> {
            wallet.maxSpendable(id, PoolSet.ALL, confirmations = -1)
        }
    }

    @Test
    fun nextTransparentAddress_calledTwice_yieldsTwoUnusedAddresses() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
        val own = assertNotNull(wallet.addresses(id).transparent)

        val first = assertNotNull(wallet.nextTransparentAddress(id))
        val second = assertNotNull(wallet.nextTransparentAddress(id))

        assertTrue(first.startsWith("t1"))
        assertTrue(second.startsWith("t1"))
        assertNotEquals(first, second)
        assertNotEquals(own, first)
        assertNotEquals(own, second)
    }

    @Test
    fun nextTransparentAddress_calledConcurrently_neverHandsOutTheSameAddressTwice() =
        withWallet { wallet ->
            val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
            val callers = 8

            val addresses = coroutineScope {
                List(callers) { async { wallet.nextTransparentAddress(id) } }.awaitAll()
            }

            assertEquals(callers, addresses.filterNotNull().distinct().size)
        }

    @Test
    fun nextTransparentAddress_afterGenerating_theAccountKeepsItsOwnAddresses() =
        withWallet { wallet ->
            val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
            val before = wallet.addresses(id)

            wallet.nextTransparentAddress(id)

            assertEquals(before, wallet.addresses(id))
        }

    @Test
    fun transparentBalance_freshAccount_isZero() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
        val address = assertNotNull(wallet.nextTransparentAddress(id))

        assertEquals(0L, wallet.transparentBalance(id, address))
    }

    @Test
    fun transparentBalance_addressOfAnotherWallet_isZeroRatherThanAnError() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        assertEquals(0L, wallet.transparentBalance(id, ECC_TRANSPARENT_RECEIVER))
    }

    @Test
    fun transparentBalance_blankAddress_isRejectedBeforeTheNativeCall() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        assertFailsWith<IllegalArgumentException> { wallet.transparentBalance(id, " ") }
    }

    @Test
    fun migrationStatus_freshAccount_hasNothingToMigrate() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        assertEquals(
            MigrationStatus(
                phase = MigrationPhase.COMPLETE,
                standardNotes = 0,
                nonStandardNotes = 0,
                migratedNotes = 0,
            ),
            wallet.migrationStatus(id),
        )
    }

    @Test
    fun migrationStep_unreachableServer_failsWithAZcashException() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
        val key = ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN)

        assertFailsWith<ZcashException> { wallet.migrationStep(id, key) }
        Unit
    }

    @Test
    fun mempool_unreachableServer_endsTheFlowWithTheConnectionFailure() = withWallet { wallet ->
        wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        val failure = assertFailsWith<ZcashException> { wallet.mempool().collect { } }

        // The exact reason matters: a native panic would surface as a ZcashException too.
        // The OS wording of a refused connection is not portable, the tonic prefix is.
        assertTrue(failure.message.orEmpty().contains("tcp connect error"), failure.message)
    }

    @Test
    fun mempool_leavingTheFlow_releasesTheRunForTheNextCollection() = withWallet { wallet ->
        wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        val first = assertFailsWith<ZcashException> { wallet.mempool().collect { } }
        val second = assertFailsWith<ZcashException> { wallet.mempool().collect { } }

        // A leaked run would fail the second collection with "mempool is already running".
        assertEquals(first.message, second.message)
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
        assertEquals(0L, wallet.balance(id, confirmations = 0).total)
    }

    @Test
    fun viewingKey_accountRestoredFromThePhrase_isTheKnownUnifiedFullViewingKey() =
        withWallet { wallet ->
            val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

            assertEquals(TEST_UFVK, wallet.viewingKey(id))
        }

    @Test
    fun deriveSpendingKey_withoutOpeningAWallet_isDeterministicAndMatchesTheRustVector() =
        runBlocking {
            val key = ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN)

            assertEquals(TEST_PHRASE_USK_SHA256, sha256Hex(key))
            assertContentEquals(key, ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN))
        }

    @Test
    fun deriveTransparentAccountKey_withoutOpeningAWallet_isTheKnownAccountXprv() = runBlocking {
        assertEquals(TEST_XPRV, ZcashSdk.deriveTransparentAccountKey(TEST_PHRASE, ZcashNetwork.MAIN))
    }

    @Test
    fun deriveTransparentAccountKey_bip39Passphrase_yieldsADifferentKeyThanWithoutOne() =
        runBlocking {
            val peppered =
                ZcashSdk.deriveTransparentAccountKey(
                    TEST_PHRASE,
                    ZcashNetwork.MAIN,
                    passphrase = TEST_PASSPHRASE,
                )

            assertNotEquals(TEST_XPRV, peppered)
            assertTrue(ZcashSdk.isSpendingKey(peppered, ZcashNetwork.MAIN))
        }

    @Test
    fun deriveTransparentAccountKey_blankPhrase_failsBeforeTheNativeCall() = runBlocking {
        assertFailsWith<IllegalArgumentException> {
            ZcashSdk.deriveTransparentAccountKey("   ", ZcashNetwork.MAIN)
        }
        Unit
    }

    @Test
    fun deriveUfvk_withoutOpeningAWallet_matchesTheUfvkOfTheAccountRestoredFromTheSamePhrase() =
        withWallet { wallet ->
            val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

            assertEquals(wallet.viewingKey(id), ZcashSdk.deriveUfvk(TEST_PHRASE, ZcashNetwork.MAIN))
        }

    @Test
    fun deriveUfvk_bip39Passphrase_yieldsADifferentKeyThanWithoutOne() = runBlocking {
        val plain = ZcashSdk.deriveUfvk(TEST_PHRASE, ZcashNetwork.MAIN)

        assertNotEquals(
            plain,
            ZcashSdk.deriveUfvk(TEST_PHRASE, ZcashNetwork.MAIN, passphrase = TEST_PASSPHRASE),
        )
    }

    @Test
    fun deriveUfvk_blankPhrase_failsBeforeTheNativeCall() = runBlocking {
        assertFailsWith<IllegalArgumentException> { ZcashSdk.deriveUfvk("   ", ZcashNetwork.MAIN) }
        Unit
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
    fun deriveSpendingKey_bip39Passphrase_yieldsADifferentKeyThanWithoutOne() = runBlocking {
        val plain = ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN)
        val peppered =
            ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN, passphrase = TEST_PASSPHRASE)

        assertNotEquals(sha256Hex(plain), sha256Hex(peppered))
        assertEquals(TEST_PHRASE_PASSPHRASE_USK_SHA256, sha256Hex(peppered))
        assertContentEquals(
            peppered,
            ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN, passphrase = TEST_PASSPHRASE),
        )
    }

    @Test
    fun deriveSpendingKey_emptyPassphrase_matchesNoPassphraseAtAll() = runBlocking {
        assertContentEquals(
            ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN),
            ZcashSdk.deriveSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN, passphrase = ""),
        )
    }

    @Test
    fun deriveAddresses_withoutOpeningAWallet_matchTheRestoredAccount() = withWallet { wallet ->
        val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        assertEquals(
            wallet.addresses(id),
            ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN),
        )
    }

    @Test
    fun deriveAddressesFromViewingKey_withoutOpeningAWallet_matchTheWatchOnlyAccount() =
        withWallet { wallet ->
            val id = wallet.restoreAccount(name = "watch-only", key = TEST_UFVK, birthHeight = BIRTH_HEIGHT)

            assertEquals(
                wallet.addresses(id),
                ZcashSdk.deriveAddressesFromViewingKey(TEST_UFVK, ZcashNetwork.MAIN),
            )
        }

    @Test
    fun deriveAddresses_eccVectorPhrase_deriveTheSameReceiversAsTheEccSdk() = runBlocking {
        val addresses = ZcashSdk.deriveAddresses(ECC_PHRASE, ZcashNetwork.MAIN)

        assertEquals(ECC_TRANSPARENT_RECEIVER, addresses.transparent)
        assertEquals(ECC_SAPLING_RECEIVER, addresses.sapling)
    }

    @Test
    fun deriveAddresses_bip39Passphrase_yieldDifferentAddressesThanWithoutOne() = runBlocking {
        val plain = ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN)
        val peppered =
            ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN, passphrase = TEST_PASSPHRASE)

        assertNotEquals(plain.unified, peppered.unified)
        assertEquals(TEST_PHRASE_PASSPHRASE_TRANSPARENT, peppered.transparent)
    }

    @Test
    fun deriveAddresses_accountIndex_selectsADifferentAccountAndRejectsANegativeOne() = runBlocking {
        assertFailsWith<IllegalArgumentException> {
            ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN, accountIndex = -1)
        }

        assertNotEquals(
            ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN).unified,
            ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN, accountIndex = 1).unified,
        )
    }

    @Test
    fun deriveAddresses_invalidPhrase_failsWithAZcashException() = runBlocking {
        assertFailsWith<ZcashException> {
            ZcashSdk.deriveAddresses("not a seed phrase", ZcashNetwork.MAIN)
        }
        Unit
    }

    @Test
    fun deriveAddressesFromViewingKey_invalidKey_failsWithAZcashException() = runBlocking {
        assertFailsWith<ZcashException> {
            ZcashSdk.deriveAddressesFromViewingKey("not a viewing key", ZcashNetwork.MAIN)
        }
        Unit
    }

    @Test
    fun keyPools_phraseAndUnifiedFullViewingKey_encodeTransparentSaplingAndOrchard() {
        val expected = PoolSet.of(Pool.TRANSPARENT, Pool.SAPLING, Pool.ORCHARD)

        assertEquals(expected, ZcashSdk.keyPools(TEST_PHRASE, ZcashNetwork.MAIN))
        assertEquals(expected, ZcashSdk.keyPools(TEST_UFVK, ZcashNetwork.MAIN))
    }

    @Test
    fun keyPools_importedTransparentExtendedKey_encodesTransparentOnly() {
        val expected = PoolSet.of(Pool.TRANSPARENT)

        assertEquals(expected, ZcashSdk.keyPools(TEST_XPRV, ZcashNetwork.MAIN))
        assertEquals(expected, ZcashSdk.keyPools(TEST_XPUB, ZcashNetwork.MAIN))
    }

    @Test
    fun keyPools_importedSaplingKeys_encodeSaplingOnly() {
        val expected = PoolSet.of(Pool.SAPLING)

        assertEquals(expected, ZcashSdk.keyPools(TEST_SAPLING_ESK, ZcashNetwork.MAIN))
        assertEquals(expected, ZcashSdk.keyPools(TEST_SAPLING_EFVK, ZcashNetwork.MAIN))
    }

    @Test
    fun keyPools_receiverAddressAndGarbage_areEmpty() {
        assertEquals(PoolSet.NONE, ZcashSdk.keyPools(ECC_TRANSPARENT_RECEIVER, ZcashNetwork.MAIN))
        assertEquals(PoolSet.NONE, ZcashSdk.keyPools("not a key", ZcashNetwork.MAIN))
    }

    @Test
    fun isValidKey_phraseAndUnifiedFullViewingKey_areTrue() {
        assertTrue(ZcashSdk.isValidKey(TEST_PHRASE, ZcashNetwork.MAIN))
        assertTrue(ZcashSdk.isValidKey(TEST_UFVK, ZcashNetwork.MAIN))
    }

    @Test
    fun isValidKey_receiverAddressAndGarbage_areFalse() {
        assertFalse(ZcashSdk.isValidKey(ECC_TRANSPARENT_RECEIVER, ZcashNetwork.MAIN))
        assertFalse(ZcashSdk.isValidKey("not a key", ZcashNetwork.MAIN))
    }

    @Test
    fun isSpendingKey_importedTransparentExtendedKey_isTrue() {
        assertTrue(ZcashSdk.isSpendingKey(TEST_XPRV, ZcashNetwork.MAIN))
    }

    @Test
    fun isSpendingKey_importedSaplingExtendedSpendingKey_isTrue() {
        assertTrue(ZcashSdk.isSpendingKey(TEST_SAPLING_ESK, ZcashNetwork.MAIN))
    }

    @Test
    fun isSpendingKey_viewingKeys_areFalse() {
        assertFalse(ZcashSdk.isSpendingKey(TEST_XPUB, ZcashNetwork.MAIN))
        assertFalse(ZcashSdk.isSpendingKey(TEST_SAPLING_EFVK, ZcashNetwork.MAIN))
    }

    @Test
    fun isSpendingKey_phraseAndUnifiedFullViewingKey_areFalse() {
        // A phrase spends too, but through restoreAccount/deriveSpendingKey — not this predicate.
        assertFalse(ZcashSdk.isSpendingKey(TEST_PHRASE, ZcashNetwork.MAIN))
        assertFalse(ZcashSdk.isSpendingKey(TEST_UFVK, ZcashNetwork.MAIN))
    }

    @Test
    fun importSpendingKey_spendingKeys_areDeterministicAndDistinctPerPool() {
        val transparent = ZcashSdk.importSpendingKey(TEST_XPRV, ZcashNetwork.MAIN)
        val sapling = ZcashSdk.importSpendingKey(TEST_SAPLING_ESK, ZcashNetwork.MAIN)

        assertTrue(transparent.isNotEmpty())
        assertTrue(sapling.isNotEmpty())
        assertFalse(transparent.contentEquals(sapling))
        assertContentEquals(transparent, ZcashSdk.importSpendingKey(TEST_XPRV, ZcashNetwork.MAIN))
    }

    @Test
    fun importSpendingKey_everythingIsSpendingKeyRejects_failsNamingWhyItCannotSpend() {
        for ((key, reason) in listOf(
            TEST_XPUB to "viewing key",
            TEST_SAPLING_EFVK to "viewing key",
            TEST_UFVK to "viewing key",
            TEST_PHRASE to "restoreAccount",
            TEST_FOREIGN_SAPLING_ESK to "another network",
            "not a key" to "not a recognized",
        )) {
            assertFalse(ZcashSdk.isSpendingKey(key, ZcashNetwork.MAIN), key)
            val error = assertFailsWith<ZcashException>(key) {
                ZcashSdk.importSpendingKey(key, ZcashNetwork.MAIN)
            }
            assertTrue(error.message?.contains(reason) == true, "$key: ${error.message}")
        }
    }

    @Test
    fun deriveAddressesFromKey_phrase_withoutOpeningAWallet_matchesTheRestoredAccountUnifiedAddress() =
        withWallet { wallet ->
            val id = wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
            val expected = wallet.addresses(id)

            // A phrase carries all three pools, so each of them gets its own address.
            val actual = ZcashSdk.deriveAddressesFromKey(TEST_PHRASE, ZcashNetwork.MAIN)
            assertEquals(expected.unified, actual.unified)
            assertEquals(expected.transparent, actual.transparent)
            assertEquals(expected.sapling, actual.sapling)
            assertEquals(expected.orchard, actual.orchard)
        }

    @Test
    fun deriveAddressesFromKey_importedTransparentExtendedKey_matchesThePhraseAccountTransparentAddress() =
        withWallet { wallet ->
            // restoreAccount must accept the key; its own addresses() cannot be read back for a
            // transparent-only account (pre-existing gap, unrelated to this phase — see report).
            wallet.restoreAccount(name = "xprv", key = TEST_XPRV, birthHeight = BIRTH_HEIGHT)

            assertEquals(
                ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN).transparent,
                ZcashSdk.deriveAddressesFromKey(TEST_XPRV, ZcashNetwork.MAIN).transparent,
            )
        }

    @Test
    fun deriveAddressesFromKey_invalidKey_failsWithAZcashException() = runBlocking {
        assertFailsWith<ZcashException> {
            ZcashSdk.deriveAddressesFromKey("not a key", ZcashNetwork.MAIN)
        }
        Unit
    }

    @Test
    fun deriveSaplingViewingKey_publishedTestVector_derivesTheExpectedEfvk() = runBlocking {
        assertEquals(
            TEST_SAPLING_EFVK,
            ZcashSdk.deriveSaplingViewingKey(TEST_SAPLING_ESK, ZcashNetwork.MAIN),
        )
    }

    @Test
    fun deriveSaplingViewingKey_derivedKey_yieldsTheSameSaplingAddressAsTheSpendingKey() = runBlocking {
        val viewingKey = assertNotNull(ZcashSdk.deriveSaplingViewingKey(TEST_SAPLING_ESK, ZcashNetwork.MAIN))

        val fromSpendingKey = ZcashSdk.deriveAddressesFromKey(TEST_SAPLING_ESK, ZcashNetwork.MAIN)
        val fromViewingKey = ZcashSdk.deriveAddressesFromKey(viewingKey, ZcashNetwork.MAIN)

        assertEquals(fromSpendingKey.sapling, fromViewingKey.sapling)
    }

    @Test
    fun deriveSaplingViewingKey_blankOrViewingKeyInput_isNull() = runBlocking {
        assertNull(ZcashSdk.deriveSaplingViewingKey("", ZcashNetwork.MAIN))
        assertNull(ZcashSdk.deriveSaplingViewingKey(TEST_SAPLING_EFVK, ZcashNetwork.MAIN))
    }

    @Test
    fun addressKind_validAddresses_areClassifiedWithoutAWalletOrACoroutine() {
        assertEquals(
            ZcashAddressKind.TRANSPARENT,
            ZcashSdk.addressKind(ECC_TRANSPARENT_RECEIVER, ZcashNetwork.MAIN),
        )
        assertEquals(
            ZcashAddressKind.SAPLING,
            ZcashSdk.addressKind(ECC_SAPLING_RECEIVER, ZcashNetwork.MAIN),
        )
        assertEquals(ZcashAddressKind.TEX, ZcashSdk.addressKind(ECC_TEX_RECEIVER, ZcashNetwork.MAIN))
    }

    @Test
    fun addressKind_unifiedAddress_isUnifiedWhateverReceiversItHolds() = runBlocking {
        val unified = assertNotNull(ZcashSdk.deriveAddresses(TEST_PHRASE, ZcashNetwork.MAIN).unified)

        assertEquals(ZcashAddressKind.UNIFIED, ZcashSdk.addressKind(unified, ZcashNetwork.MAIN))
    }

    @Test
    fun addressKind_brokenChecksum_isNotAnAddress() {
        listOf(ECC_TRANSPARENT_RECEIVER, ECC_SAPLING_RECEIVER, ECC_TEX_RECEIVER).forEach { address ->
            val corrupted = address.dropLast(1) + if (address.last() == 'q') 'p' else 'q'

            assertNull(ZcashSdk.addressKind(corrupted, ZcashNetwork.MAIN), address)
        }
    }

    @Test
    fun addressKind_addressOfAnotherNetwork_isNotAnAddress() {
        assertNull(ZcashSdk.addressKind(ECC_TRANSPARENT_RECEIVER, ZcashNetwork.TEST))
        assertNull(ZcashSdk.addressKind(ECC_SAPLING_RECEIVER, ZcashNetwork.TEST))
    }

    @Test
    fun addressKind_textThatIsNotAnAddress_isNotAnAddress() {
        assertNull(ZcashSdk.addressKind("", ZcashNetwork.MAIN))
        assertNull(ZcashSdk.addressKind(TEST_PHRASE, ZcashNetwork.MAIN))
        assertNull(ZcashSdk.addressKind(TEST_UFVK, ZcashNetwork.MAIN))
    }

    @Test
    fun transactionId_bytesThatAreNotATransaction_failsWithAZcashException() = runBlocking {
        assertFailsWith<ZcashException> { ZcashSdk.transactionId(ByteArray(32)) }
        Unit
    }

    @Test
    fun restoreAccount_eccVectorPhrase_derivesTheSameReceiversAsTheEccSdk() = withWallet { wallet ->
        val account = wallet.restoreAccount(name = "ecc", key = ECC_PHRASE, birthHeight = BIRTH_HEIGHT)
        val addresses = wallet.addresses(account)

        assertEquals(ECC_TRANSPARENT_RECEIVER, addresses.transparent)
        assertEquals(ECC_SAPLING_RECEIVER, addresses.sapling)
    }

    @Test
    fun restoreAccount_bip39Passphrase_derivesDifferentAddressesThanWithoutOne() = withWallet { wallet ->
        val plain = wallet.restoreAccount(name = "plain", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)
        val peppered = wallet.restoreAccount(
            name = "peppered",
            key = TEST_PHRASE,
            birthHeight = BIRTH_HEIGHT,
            passphrase = TEST_PASSPHRASE,
        )

        assertNotEquals(wallet.addresses(plain).unified, wallet.addresses(peppered).unified)
        assertNotEquals(wallet.addresses(plain).sapling, wallet.addresses(peppered).sapling)
        assertEquals(TEST_PHRASE_PASSPHRASE_TRANSPARENT, wallet.addresses(peppered).transparent)
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

    @Test
    fun reserveForBroadcast_permissiveForeignTransaction_reservesNothingAndSucceeds() =
        withWallet { wallet ->
            val account =
                wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

            wallet.reserveForBroadcast(
                account,
                FOREIGN_TRANSACTION_HEX.hexToBytes(),
                requireOwnInputs = false,
            )
        }

    @Test
    fun reserveForBroadcast_foreignTransactionByDefault_isRejected() = withWallet { wallet ->
        val account =
            wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

        val failure = assertFailsWith<ZcashException> {
            wallet.reserveForBroadcast(account, FOREIGN_TRANSACTION_HEX.hexToBytes())
        }

        assertTrue(
            failure.message.orEmpty().contains("does not spend an input owned"),
            failure.message,
        )
    }

    /**
     * Zebra assembles its client without dialing, so the reservation is the first thing that
     * runs and the only thing that can stop the call before the network does.
     */
    @Test
    fun broadcast_permissiveForeignTransaction_reachesTheNetwork() =
        withWallet(ServerType.ZEBRA) { wallet ->
            val account =
                wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

            val failure = assertFailsWith<ZcashException> {
                wallet.broadcast(
                    account,
                    FOREIGN_TRANSACTION_HEX.hexToBytes(),
                    BIRTH_HEIGHT,
                    requireOwnInputs = false,
                )
            }

            // The wording of a refused connection is not portable; the refusal it must NOT be is.
            assertFalse(
                failure.message.orEmpty().contains("does not spend an input owned"),
                failure.message,
            )
        }

    @Test
    fun broadcast_foreignTransactionByDefault_neverReachesTheNetwork() =
        withWallet(ServerType.ZEBRA) { wallet ->
            val account =
                wallet.restoreAccount(name = "vector", key = TEST_PHRASE, birthHeight = BIRTH_HEIGHT)

            val failure = assertFailsWith<ZcashException> {
                wallet.broadcast(account, FOREIGN_TRANSACTION_HEX.hexToBytes(), BIRTH_HEIGHT)
            }

            assertTrue(
                failure.message.orEmpty().contains("does not spend an input owned"),
                failure.message,
            )
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

    private fun withWallet(
        serverType: ServerType = ServerType.LIGHTWALLETD,
        block: suspend (ZcashWallet) -> Unit,
    ) = withTempDir { directory ->
        val wallet =
            openWallet(directory.resolve("wallet.db").absolutePathString(), serverType = serverType)
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

    private suspend fun openWallet(
        dbPath: String,
        dbKey: ByteArray? = null,
        serverType: ServerType = ServerType.LIGHTWALLETD,
    ) = ZcashWallet.open(
        dbPath = dbPath,
        network = ZcashNetwork.MAIN,
        server = ServerConfig(url = "http://127.0.0.1:1", type = serverType),
        dbKey = dbKey,
    )
}
