package cash.p.zcash

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TransparentSigningDtoTest {

    @Test
    fun parseTransparentSigningRequest_fullPayload_mapsEveryField() {
        val json = """
            {"tx_version":5,"version_group_id":648301281,"consensus_branch_id":1173770069,
             "expiry_height":2500100,"lock_time":0,
             "shielded":{"sapling_spends":0,"sapling_outputs":1,"orchard_actions":2},
             "inputs":[{"index":0,"prev_txid":"ab12","prev_index":1,"value":50000,
                        "sequence":4294967295,"scope":0,"dindex":3,"script_pubkey":"76a914"}],
             "outputs":[{"index":0,"value":40000,"address":"t1out","is_change":false}]}
        """

        val request = parseTransparentSigningRequest(json)

        assertEquals(
            TransparentSigningRequest(
                txVersion = 5,
                versionGroupId = 648_301_281L,
                consensusBranchId = 1_173_770_069L,
                expiryHeight = 2_500_100,
                lockTime = 0L,
                shielded = ShieldedCounts(saplingSpends = 0, saplingOutputs = 1, orchardActions = 2),
                inputs = listOf(
                    TransparentSigningInput(
                        index = 0,
                        prevTxid = "ab12",
                        prevIndex = 1,
                        value = 50_000L,
                        sequence = 4_294_967_295L,
                        scope = 0,
                        dindex = 3,
                        scriptPubkey = "76a914",
                    ),
                ),
                outputs = listOf(
                    TransparentSigningOutput(
                        index = 0,
                        value = 40_000L,
                        address = "t1out",
                        isChange = false,
                        scope = null,
                        dindex = null,
                    ),
                ),
            ),
            request,
        )
    }

    @Test
    fun parseTransparentSigningRequest_sequenceSentinel_parsesBeyondIntMaxAsLong() {
        val json = """
            {"tx_version":5,"version_group_id":1,"consensus_branch_id":1,
             "expiry_height":0,"lock_time":0,
             "shielded":{"sapling_spends":0,"sapling_outputs":0,"orchard_actions":0},
             "inputs":[{"index":0,"prev_txid":"00","prev_index":0,"value":1,
                        "sequence":4294967295,"scope":0,"dindex":0,"script_pubkey":""}],
             "outputs":[]}
        """

        val request = parseTransparentSigningRequest(json)

        assertEquals(4_294_967_295L, request.inputs.single().sequence)
    }

    @Test
    fun parseTransparentSigningRequest_consensusBranchIdBeyondIntRange_isParsed() {
        // NU5/Orchard branch id 0xc2d6d0b4 and v4 Sapling version_group_id 0x892F2085 both
        // exceed Int.MAX_VALUE as unsigned decimal, exactly like a real mainnet transaction.
        val json = """
            {"tx_version":5,"version_group_id":2301567109,"consensus_branch_id":3268858548,
             "expiry_height":0,"lock_time":0,
             "shielded":{"sapling_spends":0,"sapling_outputs":0,"orchard_actions":0},
             "inputs":[],"outputs":[]}
        """

        val request = parseTransparentSigningRequest(json)

        assertEquals(2_301_567_109L, request.versionGroupId)
        assertEquals(3_268_858_548L, request.consensusBranchId)
    }

    @Test
    fun parseTransparentSigningRequest_changeOutput_carriesScopeAndDindex() {
        val json = """
            {"tx_version":5,"version_group_id":1,"consensus_branch_id":1,
             "expiry_height":0,"lock_time":0,
             "shielded":{"sapling_spends":0,"sapling_outputs":0,"orchard_actions":0},
             "inputs":[],
             "outputs":[{"index":0,"value":1000,"address":"t1change","is_change":true,
                         "scope":1,"dindex":7}]}
        """

        val output = parseTransparentSigningRequest(json).outputs.single()

        assertTrue(output.isChange)
        assertEquals(1, output.scope)
        assertEquals(7, output.dindex)
    }

    @Test
    fun parseTransparentSigningRequest_plainOutput_leavesScopeAndDindexNull() {
        val json = """
            {"tx_version":5,"version_group_id":1,"consensus_branch_id":1,
             "expiry_height":0,"lock_time":0,
             "shielded":{"sapling_spends":0,"sapling_outputs":0,"orchard_actions":0},
             "inputs":[],
             "outputs":[{"index":0,"value":1000,"address":"t1recipient","is_change":false}]}
        """

        val output = parseTransparentSigningRequest(json).outputs.single()

        assertFalse(output.isChange)
        assertNull(output.scope)
        assertNull(output.dindex)
    }

    @Test
    fun parseAddressReceivers_hasTransparentTrue_isParsed() {
        assertTrue(parseAddressReceivers("""{"has_transparent":true}""").hasTransparent)
    }

    @Test
    fun parseAddressReceivers_hasTransparentFalse_isParsed() {
        assertFalse(parseAddressReceivers("""{"has_transparent":false}""").hasTransparent)
    }
}
