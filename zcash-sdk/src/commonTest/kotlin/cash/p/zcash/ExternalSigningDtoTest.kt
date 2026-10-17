package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

private const val HARDENED = 0x8000_0000L

class ExternalSigningDtoTest {

    @Test
    fun parseExternalSigningView_orchardPayload_mapsEveryField() {
        val json = """
            {"tx_version":5,"version_group_id":648301322,"consensus_branch_id":1307094001,
             "fallback_lock_time":null,"expiry_height":3400040,"coin_type":133,"tx_modifiable":0,
             "transparent_inputs":[{"prevout_txid":"11","prevout_index":1,"sequence":null,"value":50000,
               "script_pubkey":"76a9","sighash_type":1,
               "derivation":{"pubkey":"02aa","seed_fingerprint":"00","path":[2147483692,2147483781,2147483648,0,0]}}],
             "transparent_outputs":[{"value":10000,"script_pubkey":"76a9","derivation":null}],
             "orchard":{"actions":[{"cv_net":"01","nullifier":"02","rk":"03","spend_recipient":"04",
               "spend_value":100000,"spend_rho":"05","spend_rseed":"06","alpha":"07","seed_fingerprint":"00",
               "path":[2147483680,2147483781,2147483648],"cmx":"08","ephemeral_key":"09","enc_ciphertext":"0a",
               "out_ciphertext":"0b","recipient":"0c","recipient_address":"u1x","value":60000,"rseed":"0d",
               "rcv":"0e"}],
               "flags":3,"value_balance":-25000,"anchor":"0f","note_plaintext_version":2,"sign_indices":[0]},
             "ironwood":null}
        """

        val view = parseExternalSigningView(json)

        assertEquals(
            ExternalSigningView(
                txVersion = 5,
                versionGroupId = 648_301_322L,
                consensusBranchId = 1_307_094_001L,
                fallbackLockTime = null,
                expiryHeight = 3_400_040,
                coinType = 133,
                txModifiable = 0,
                transparentInputs = listOf(
                    ExternalTransparentInput(
                        prevoutTxid = "11",
                        prevoutIndex = 1,
                        sequence = null,
                        value = 50_000L,
                        scriptPubkey = "76a9",
                        sighashType = 1,
                        derivation = ExternalKeyDerivation(
                            pubkey = "02aa",
                            seedFingerprint = "00",
                            path = listOf(44 + HARDENED, 133 + HARDENED, HARDENED, 0L, 0L),
                        ),
                    ),
                ),
                transparentOutputs = listOf(ExternalTransparentOutput(10_000L, "76a9", derivation = null)),
                orchard = ExternalActionBundle(
                    actions = listOf(
                        ExternalAction(
                            cvNet = "01",
                            nullifier = "02",
                            rk = "03",
                            spendRecipient = "04",
                            spendValue = 100_000L,
                            spendRho = "05",
                            spendRseed = "06",
                            alpha = "07",
                            seedFingerprint = "00",
                            path = listOf(32 + HARDENED, 133 + HARDENED, HARDENED),
                            cmx = "08",
                            ephemeralKey = "09",
                            encCiphertext = "0a",
                            outCiphertext = "0b",
                            recipient = "0c",
                            recipientAddress = "u1x",
                            value = 60_000L,
                            rseed = "0d",
                            rcv = "0e",
                        ),
                    ),
                    flags = 3,
                    valueBalance = -25_000L,
                    anchor = "0f",
                    notePlaintextVersion = 2,
                    signIndices = listOf(0),
                ),
                ironwood = null,
            ),
            view,
        )
    }

    @Test
    fun parseExternalSigningView_lockTimeAndSequence_areParsedBeyondIntRange() {
        val json = """
            {"tx_version":6,"version_group_id":3632571032,"consensus_branch_id":1,
             "fallback_lock_time":4294967295,"expiry_height":0,"coin_type":133,"tx_modifiable":0,
             "transparent_inputs":[{"prevout_txid":"","prevout_index":0,"sequence":4294967295,"value":1,
               "script_pubkey":"","sighash_type":1,
               "derivation":{"pubkey":"","seed_fingerprint":"","path":[]}}],
             "transparent_outputs":[],"orchard":null,"ironwood":null}
        """

        val view = parseExternalSigningView(json)

        assertEquals(3_632_571_032L, view.versionGroupId)
        assertEquals(4_294_967_295L, view.fallbackLockTime)
        assertEquals(4_294_967_295L, view.transparentInputs.single().sequence)
        assertNull(view.orchard)
    }
}
