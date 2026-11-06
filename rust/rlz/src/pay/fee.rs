use zcash_primitives::transaction::fees::zip317::{
    FeeRule, GRACE_ACTIONS, P2PKH_STANDARD_INPUT_SIZE, P2PKH_STANDARD_OUTPUT_SIZE,
};
use zcash_protocol::value::Zatoshis;

use crate::api::coin::Network;

pub const LEGACY_COST_PER_ACTION: u64 = 5000;
pub const REDUCED_COST_PER_ACTION: u64 = 1000;
pub const MAINNET_FEE_REDUCTION_HEIGHT: u32 = 3_590_000;
pub const TESTNET_FEE_REDUCTION_HEIGHT: u32 = 4_465_026;

/// The ZIP 2009 marginal fee for a transaction landing at `target_height`. The planner, the
/// builder's rule, the dust floors and the migration pad must all read one value of it.
pub fn cost_per_action(network: &Network, target_height: u32) -> u64 {
    let reduction_height = match network {
        Network::Main => MAINNET_FEE_REDUCTION_HEIGHT,
        Network::Test => TESTNET_FEE_REDUCTION_HEIGHT,
        Network::Regtest(_) => 0,
        // The ZSA node fork predates the reduction.
        Network::ZsaRegtest(_) => return LEGACY_COST_PER_ACTION,
    };
    if target_height >= reduction_height {
        REDUCED_COST_PER_ACTION
    } else {
        LEGACY_COST_PER_ACTION
    }
}

/// The builder requires a plan's fee to match this rule exactly.
pub fn fee_rule(cost_per_action: u64) -> FeeRule {
    FeeRule::non_standard(
        Zatoshis::const_from_u64(cost_per_action),
        GRACE_ACTIONS,
        P2PKH_STANDARD_INPUT_SIZE,
        P2PKH_STANDARD_OUTPUT_SIZE,
    )
    .expect("standard P2PKH sizes are non-zero")
}

/// ZIP-317 creation cost per new asset, in equivalent logical actions.
/// Zebra currently uses 0; this matches the upstream `FeeRule::standard()`
/// constant but may diverge on networks where zebra configures it differently.
pub const CREATION_COST: u64 = 0;

#[derive(Clone, Debug)]
pub struct FeeManager {
    pub cost_per_action: u64,
    pub num_inputs: [u8; 4],
    pub num_outputs: [u8; 4],
    /// Logical actions contributed by the issue bundle (ZIP-317).
    /// Equal to `total_issue_note_count + CREATION_COST * asset_creation_count`.
    pub issuance_actions: u64,
    /// In migration mode (O→O self-sends), the Orchard V3 bundle disables
    /// cross-address transfers, so actions are `spends + outputs` instead
    /// of `max(spends, outputs)`.
    pub migration: bool,
}

impl FeeManager {
    pub fn new(cost_per_action: u64) -> Self {
        Self {
            cost_per_action,
            num_inputs: [0; 4],
            num_outputs: [0; 4],
            issuance_actions: 0,
            migration: false,
        }
    }

    // Add an input
    pub fn add_input(&mut self, pool: u8) {
        self.num_inputs[pool as usize] += 1;
    }

    // Add an output
    pub fn add_output(&mut self, pool: u8) {
        self.num_outputs[pool as usize] += 1;
    }

    // Remove an output
    pub fn remove_output(&mut self, pool: u8) {
        self.num_outputs[pool as usize] -= 1;
    }

    /// Add logical actions from the issue bundle.
    /// `issue_note_count` — total number of issue notes across all issue actions.
    /// `asset_creation_count` — number of new assets being created (first issuance).
    pub fn add_issuance_actions(&mut self, issue_note_count: u64, asset_creation_count: u64) {
        self.issuance_actions += issue_note_count + CREATION_COST * asset_creation_count;
    }

    // Return the current amount of fees
    pub fn fee(&self) -> u64 {
        let t = self.num_inputs[0].max(self.num_outputs[0]);
        let s = if self.num_inputs[1] > 0 || self.num_outputs[1] > 0 {
            // if any sapling, # bundle outputs = max(2, # outputs)
            // if any input, # bundle inputs = max(1, # inputs)
            // # logical sapling = max(# bundle in, bundle out) =
            // max(2, # inputs, # outputs)
            // I O -> BI BO -> L
            // 0 0 -> 0  0  -> 0
            // 1 0 -> 1  2  -> 2
            // 0 1 -> 0  2  -> 2
            // 1 1 -> 1  2  -> 2
            // 2 1 -> 2  1  -> 2
            // etc.
            //
            // basically it is max(# inputs, # outputs, 2) unless there
            // is no input or output
            self.num_inputs[1].max(self.num_outputs[1]).max(2)
        } else {
            0
        };
        let o = if self.num_inputs[2] > 0 || self.num_outputs[2] > 0 {
            if self.migration {
                (self.num_inputs[2] as u64 + self.num_outputs[2] as u64).max(2)
            } else {
                self.num_inputs[2].max(self.num_outputs[2]).max(2) as u64
            }
        } else {
            0
        };
        let i = if self.num_inputs[3] > 0 || self.num_outputs[3] > 0 {
            // Ironwood has same padding as Orchard: min 2 actions
            self.num_inputs[3].max(self.num_outputs[3]).max(2)
        } else {
            0
        };
        let f = (t as u64 + s as u64 + o + i as u64).max(2); // minimum 2 logical actions
                                                             // Issuance actions are counted by the builder as orchard actions,
                                                             // so we don't add them separately here. The issuance counts are
                                                             // informational for logging only.
        f as u64 * self.cost_per_action
    }

    #[allow(dead_code)]
    fn min_actions_padding(a: u8) -> u8 {
        if a == 0 {
            0
        } else {
            a.max(2)
        }
    }
}

impl std::fmt::Display for FeeManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fee: {}:{} {}:{} {}:{} {}:{} issuance:{}",
            self.num_inputs[0],
            self.num_outputs[0],
            self.num_inputs[1],
            self.num_outputs[1],
            self.num_inputs[2],
            self.num_outputs[2],
            self.num_inputs[3],
            self.num_outputs[3],
            self.issuance_actions,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::coin::network_from_coin;
    use zcash_primitives::transaction::fees::{transparent::InputSize, FeeRule as _};
    use zcash_protocol::consensus::BlockHeight;

    #[test]
    fn cost_per_action_follows_zip_2009_at_the_target_height() {
        let regtest = network_from_coin(2);
        let zsa_regtest = network_from_coin(3);
        let cases = [
            (
                &Network::Main,
                MAINNET_FEE_REDUCTION_HEIGHT - 1,
                LEGACY_COST_PER_ACTION,
            ),
            (
                &Network::Main,
                MAINNET_FEE_REDUCTION_HEIGHT,
                REDUCED_COST_PER_ACTION,
            ),
            (
                &Network::Test,
                TESTNET_FEE_REDUCTION_HEIGHT - 1,
                LEGACY_COST_PER_ACTION,
            ),
            (
                &Network::Test,
                TESTNET_FEE_REDUCTION_HEIGHT,
                REDUCED_COST_PER_ACTION,
            ),
            (&regtest, 0, REDUCED_COST_PER_ACTION),
            (&zsa_regtest, u32::MAX, LEGACY_COST_PER_ACTION),
        ];
        for (network, height, expected) in cases {
            assert_eq!(
                cost_per_action(network, height),
                expected,
                "{network:?} @ {height}"
            );
        }
    }

    #[test]
    fn fee_rule_prices_a_plan_as_the_fee_manager_does_at_either_rate() {
        for cost in [LEGACY_COST_PER_ACTION, REDUCED_COST_PER_ACTION] {
            let required = fee_rule(cost)
                .fee_required(
                    &Network::Main,
                    BlockHeight::from_u32(1),
                    std::iter::empty::<InputSize>(),
                    std::iter::empty::<usize>(),
                    0,
                    0,
                    2,
                    0,
                )
                .expect("fee");
            let mut manager = FeeManager::new(cost);
            manager.add_input(2);
            manager.add_output(2);
            manager.add_output(2);
            assert_eq!(required.into_u64(), manager.fee());
        }
    }

    #[test]
    fn fee_manager_two_actions_at_the_reduced_rate_cost_two_thousand() {
        let mut manager = FeeManager::new(REDUCED_COST_PER_ACTION);
        manager.add_input(0);
        manager.add_output(0);
        assert_eq!(manager.fee(), 2_000);
    }
}
