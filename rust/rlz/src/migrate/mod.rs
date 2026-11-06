use anyhow::Result;
use sqlx::{Row, SqliteConnection};
use tracing::info;

use crate::{
    account::get_account_full_address,
    api::coin::Network,
    db::get_account_hw,
    net::BroadcastOutcome,
    pay::{
        fee::{cost_per_action, FeeManager},
        plan::{extract_transaction, plan_transaction, sign_transaction},
        pool::PoolMask,
        reserve::{reserve_and_send, OwnInputs},
        Recipient,
    },
    Client,
};

/// Minimum spendable chunk: 100 logical actions.
/// Below this threshold, non-SD notes are left alone — splitting them
/// would cost more in fees than the value recovered.
pub const fn min_sd(cost_per_action: u64) -> u64 {
    100 * cost_per_action
}

/// Maximum number of non-SD notes to split in a single transaction.
/// Caps transaction size to avoid oversized bundles that nodes reject.
const MAX_SPLIT_INPUTS: usize = 50;

/// Maximum migration anchor interval specified by the migration protocol.
pub const ANCHOR_BUCKET_SIZE: u32 = 144;

/// Zcash's target block spacing, used to scale the anchor interval to the
/// selected migration speed.
const TARGET_BLOCK_SPACING_MS: u64 = 75_000;

/// Fee padding embedded in each standard denomination.
/// Covers Orchard input + change (2 actions in sum mode) and Ironwood
/// output (2 actions, padded).
/// It follows the marginal fee, so a note padded before ZIP 2009 stops matching [`is_sd`]
/// after it and is split again at the new pad.
pub(crate) const fn sd_fee_pad(cost_per_action: u64) -> u64 {
    4 * cost_per_action
}

/// Decompose a total amount into standard denomination notes with embedded fees.
///
/// Each standard denomination is `10^k + p` for the fee pad `p`.
///
/// Greedy from largest to smallest. Returns sparse `(denom, count)` pairs
/// and any leftover below the smallest denomination.
pub fn decompose_to_sd(total: u64, p: u64) -> (Vec<(u64, u8)>, u64) {
    let d_min = 10u64.pow(5) + p;
    let k_min = 5u32;
    let k_max = 16u32; // 10^16 + P covers 100M ZEC
    let mut result = Vec::new();
    let mut remainder = total;

    for k in (k_min..k_max).rev() {
        if remainder < d_min {
            break;
        }
        let d = 10u64.pow(k) + p;
        let count = (remainder / d) as u8;
        remainder %= d;
        if count > 0 {
            result.push((d, count));
        }
    }

    (result, remainder)
}

/// Check whether `value` is a standard denomination: exactly `10^(i+5)`, i ≥ 0.
/// Ironwood notes are minted at the pure denomination; Orchard SD notes include
/// an additional fee pad, see [`is_sd`].
pub fn is_iw_sd(value: u64) -> bool {
    value >= 100_000 && value % 100_000 == 0 && {
        let mut x = value / 100_000;
        while x % 10 == 0 {
            x /= 10;
        }
        x == 1
    }
}

/// Check whether `value` is a fee-inclusive standard denomination, `10^(i+5) + p`.
pub fn is_sd(value: u64, p: u64) -> bool {
    value > p && is_iw_sd(value - p)
}

/// A split action's planned outputs. `total` is carried so `step` can log it without
/// re-summing the inputs the planner already summed.
struct SplitPlan {
    digits: Vec<(u64, u8)>,
    remainder: u64,
    total: u64,
}

/// The SD outputs a split action would actually produce for `values`, or `None` when it would
/// produce none. `step` and `has_split_transaction` must never disagree, so both go through here.
fn plan_split(values: &[u64], cost_per_action: u64) -> Option<SplitPlan> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.truncate(MAX_SPLIT_INPUTS);
    let num_inputs = sorted.len() as u64;
    let total: u64 = sorted.iter().sum();
    let min_sd = min_sd(cost_per_action);
    if total < min_sd {
        return None;
    }

    let pad = sd_fee_pad(cost_per_action);
    let (mut digits, mut remainder) = decompose_to_sd(total, pad);

    // If the natural remainder is too small to cover the transaction fee, carve out the minimum
    // chunk from the decomposable pool as a fee buffer.
    if remainder < min_sd / 2 {
        let (d, r) = decompose_to_sd(total.saturating_sub(min_sd), pad);
        if !d.is_empty() {
            digits = d;
            remainder = r + min_sd;
        }
    }
    let mut num_outputs: u64 = digits.iter().map(|&(_, c)| c as u64).sum();

    // Mirror what plan_transaction will construct, including the change output, so the fee
    // estimate is exact.
    let mut fm = FeeManager {
        migration: true,
        ..FeeManager::new(cost_per_action)
    };
    for _ in 0..num_inputs {
        fm.add_input(2);
    }
    for _ in 0..num_outputs {
        fm.add_output(2);
    }
    fm.add_output(2); // change output

    // Trim the lowest denomination until the fee fits, or until nothing is left to send. Strict:
    // the fee counts a change output, and a remainder equal to it would leave none to build.
    loop {
        if fm.fee() < remainder || num_outputs == 0 {
            break;
        }
        if let Some((denom, count)) = digits.last_mut() {
            *count -= 1;
            remainder += *denom;
            num_outputs -= 1;
            fm.remove_output(2);
            if *count == 0 {
                digits.pop();
            }
        }
    }

    if num_outputs > 0 {
        Some(SplitPlan {
            digits,
            remainder,
            total,
        })
    } else {
        None
    }
}

/// Whether the next migration action can split the currently known non-SD notes.
pub(crate) fn has_split_transaction(values: Vec<u64>, cost_per_action: u64) -> bool {
    plan_split(&values, cost_per_action).is_some()
}

/// Result of a migration step.
pub enum MigrationEvent {
    /// A split transaction was broadcast.
    SplitComplete { fee: u64, txid: String },
    /// A migration transaction was broadcast.
    MigrateComplete { fee: u64, txid: String },
    /// Migration is complete — no more Orchard notes to migrate.
    Complete,
    /// No action needed (e.g., all notes are already SD but no migration
    /// target yet, or waiting for confirmation).
    NothingToDo,
}

/// Current migration status for the UI.
pub struct MigrationStatus {
    pub phase: String,
    pub progress: f64,
    pub next_action: String,
    pub work_summary: String,
    pub sd_notes_count: u32,
    pub non_sd_notes_count: u32,
}

/// Notes grouped by pool and ZEC/ZSA.
struct OrchardZecNote {
    id: u32,
    height: u32,
    value: u64,
    cmx: Option<Vec<u8>>,
    has_checkpoint: bool,
}

/// Fetch unspent Orchard ZEC notes with their cmx values.
///
/// Like `fetch_unspent_notes_grouped_by_pool` but restricted to Orchard ZEC
/// (pool 2, no asset) and includes `cmx` so callers don't need a second
/// pass to fetch commitments.
async fn fetch_unspent_orchard_notes_with_cmx(
    connection: &mut SqliteConnection,
    account: u32,
    checkpoint_height: u32,
    confirmed_height: u32,
) -> Result<Vec<OrchardZecNote>> {
    sqlx::query(
        "SELECT a.id_note, a.height, a.value, a.cmx,
                EXISTS (
                    SELECT 1
                    FROM witnesses w
                    WHERE w.account = a.account
                    AND w.note = a.id_note
                    AND w.height = ?1
                )
         FROM notes a
         LEFT JOIN spends b ON a.id_note = b.id_note
         LEFT JOIN active_pending_spend_inputs p
            ON p.account = a.account
            AND p.nullifier = a.nullifier
         WHERE b.id_note IS NULL
         AND a.account = ?2
         AND a.height <= ?3
         AND a.pool = 2
         AND a.id_asset IS NULL
         AND a.locked = 0
         AND p.nullifier IS NULL",
    )
    .bind(checkpoint_height)
    .bind(account)
    .bind(confirmed_height)
    .map(|row| OrchardZecNote {
        id: row.get(0),
        height: row.get(1),
        value: row.get::<i64, _>(2) as u64,
        cmx: row.get(3),
        has_checkpoint: row.get(4),
    })
    .fetch_all(connection)
    .await
    .map_err(Into::into)
}

pub(crate) fn migration_anchor_bucket_size(mean_delay_ms: u64) -> u32 {
    let blocks =
        mean_delay_ms.saturating_add(TARGET_BLOCK_SPACING_MS - 1) / TARGET_BLOCK_SPACING_MS;
    u32::try_from(blocks)
        .unwrap_or(u32::MAX)
        .clamp(1, ANCHOR_BUCKET_SIZE)
}

/// Return the first migration anchor boundary at or above `height`.
pub(crate) fn next_anchor_bucket_height(height: u32, bucket_size: u32) -> u32 {
    let remainder = height % bucket_size;
    if remainder == 0 {
        height
    } else {
        height.saturating_add(bucket_size - remainder)
    }
}

/// The node reports a rejection in-band, so a step that did not land must fail
/// rather than report a txid that does not exist.
fn broadcast_txid(outcome: BroadcastOutcome) -> Result<String> {
    if outcome.error_code != 0 {
        anyhow::bail!(
            "Broadcast rejected ({}): {}",
            outcome.error_code,
            outcome.message
        );
    }
    Ok(outcome.message)
}

async fn broadcast(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    height: u32,
    tx: &[u8],
) -> Result<String> {
    broadcast_txid(
        reserve_and_send(
            network,
            connection,
            client,
            account,
            height,
            tx,
            OwnInputs::Required,
        )
        .await?,
    )
}

/// Run one migration step. Fully idempotent — re-scans notes on every call.
///
/// `usk_bytes` signs the transaction this step broadcasts; this fork keeps no
/// spending key in the database, so the host has to supply it.
pub async fn step(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    anchor_bucket_size: u32,
    usk_bytes: &[u8],
) -> Result<MigrationEvent> {
    let height = client.latest_height().await?;
    let cost = cost_per_action(network, height.saturating_add(1));
    let pad = sd_fee_pad(cost);
    let checkpoint_height = crate::sync::get_db_height(&mut *connection, account)
        .await?
        .height;
    let confirmed_height = crate::db::confirmed_height(
        &mut *connection,
        account,
        crate::api::pay::DEFAULT_CONFIRMATIONS,
    )
    .await?;

    // Get the wallet's own Orchard/Ironwood address
    let hw = get_account_hw(&mut *connection, account).await?;
    let own_address = get_account_full_address(network, &mut *connection, account, 0, hw).await?;

    // Fetch all unspent Orchard ZEC notes with cmx.
    let orchard_zec = fetch_unspent_orchard_notes_with_cmx(
        &mut *connection,
        account,
        checkpoint_height,
        confirmed_height,
    )
    .await?;

    info!(
        "Migration step: {} Orchard ZEC notes found",
        orchard_zec.len(),
    );
    if orchard_zec.is_empty() {
        return Ok(MigrationEvent::Complete);
    }

    // Separate SD vs non-SD
    let sd_notes: Vec<&OrchardZecNote> =
        orchard_zec.iter().filter(|n| is_sd(n.value, pad)).collect();
    let non_sd_notes: Vec<&OrchardZecNote> = orchard_zec
        .iter()
        .filter(|n| !is_sd(n.value, pad))
        .collect();
    info!(
        "SD notes: {:?}, non-SD notes: {:?}",
        sd_notes.iter().map(|n| n.value).collect::<Vec<_>>(),
        non_sd_notes.iter().map(|n| n.value).collect::<Vec<_>>(),
    );

    // ── Splitting phase ──

    // Cap inputs to keep transaction size manageable. Sort by value
    // descending so the largest notes are split first; remaining non-SD
    // notes will be handled in subsequent step() calls.
    let capped_non_sd: Vec<&OrchardZecNote> = {
        let mut sorted = non_sd_notes.clone();
        sorted.sort_by_key(|n| std::cmp::Reverse(n.value));
        sorted.truncate(MAX_SPLIT_INPUTS);
        sorted
    };

    let split_values: Vec<u64> = capped_non_sd.iter().map(|n| n.value).collect();
    if let Some(SplitPlan {
        digits,
        remainder,
        total,
    }) = plan_split(&split_values, cost)
    {
        // Build recipients from (denom, count) pairs.
        let mut recipients: Vec<Recipient> = Vec::new();
        for &(denom, count) in &digits {
            for _ in 0..count {
                recipients.push(Recipient {
                    address: own_address.clone(),
                    amount: denom,
                    pools: Some(PoolMask::from_pool(2).0), // Orchard only
                    ..Recipient::default()
                });
            }
        }

        info!(
            "Migration split: {} non-SD notes (total {}) → {} SD outputs (remainder {})",
            capped_non_sd.len(),
            total,
            recipients.len(),
            remainder,
        );

        let preselected: Vec<u32> = capped_non_sd.iter().map(|n| n.id).collect();

        let pczt = plan_transaction(
            network,
            &mut *connection,
            client,
            account,
            PoolMask::from_pool(2).0, // Orchard source
            &recipients,
            false,
            Some(crate::api::pay::DEFAULT_CONFIRMATIONS),
            false,
            None,
            None,
            true, // migration
            Some(&preselected),
            None,  // anchor_height
            false, // hardware_signing
            false, // external_pczt_signing
        )
        .await?;

        let fee = crate::pay::TxPlan::from_package(network, &pczt)
            .map(|p| p.fee)
            .unwrap_or(0);
        let pczt = sign_transaction(&mut *connection, account, network, &pczt, usk_bytes).await?;
        let tx_bytes = extract_transaction(&pczt).await?;
        let txid = broadcast(
            network,
            &mut *connection,
            client,
            account,
            height,
            &tx_bytes,
        )
        .await?;

        return Ok(MigrationEvent::SplitComplete { fee, txid });
    }
    // No outputs remained after the fee trim: fall through to the migration phase.

    if !sd_notes.is_empty() {
        /*
        # migrate one orchard SD note at a time
        - inputs:
            - select 1 SD note, it include 2 COST_ACTIONS
            - dummy input
        - outputs
            - ironwood SD - 2 COST_ACTIONS = "real" SD
            - dummy output
         */

        // ── Migrating phase ──
        anyhow::ensure!(
            checkpoint_height % anchor_bucket_size == 0,
            "Migration checkpoint {checkpoint_height} is not on a \
             {anchor_bucket_size}-block anchor boundary",
        );
        let anchor_height = checkpoint_height;

        // The selected note must exist at the current boundary checkpoint.
        // Migration never rewinds a witness to a historical anchor.
        let mut sorted_sd: Vec<&OrchardZecNote> = sd_notes
            .iter()
            .copied()
            .filter(|n| n.height <= anchor_height && n.has_checkpoint)
            .collect();
        if sorted_sd.is_empty() {
            info!(
                "Migration waiting: no SD note is available at checkpoint {}",
                checkpoint_height,
            );
            return Ok(MigrationEvent::NothingToDo);
        }

        // Sort by cmx for deterministic random order
        sorted_sd.sort_by(|a, b| {
            let a_cmx = a.cmx.as_deref().unwrap_or(&[]);
            let b_cmx = b.cmx.as_deref().unwrap_or(&[]);
            a_cmx.cmp(b_cmx)
        });

        // Pick one SD note (largest cmx). Its value embeds the fee pad
        // for Orchard fees; the Ironwood output is the "real" denomination.
        let note = sorted_sd.last().unwrap();
        let ironwood_amount = note.value - pad;

        // One Ironwood output (dummy output for padding is handled by the
        // builder, as is the dummy Orchard input).
        let recipients = vec![Recipient {
            address: own_address.clone(),
            amount: ironwood_amount,
            pools: Some(PoolMask::from_pool(3).0), // Ironwood
            ..Recipient::default()
        }];

        info!(
            "Migration: note id={} value={} → Ironwood amount={}, anchor={} (checkpoint={})",
            note.id, note.value, ironwood_amount, anchor_height, checkpoint_height,
        );

        let preselected: Vec<u32> = vec![note.id];

        let pczt = plan_transaction(
            network,
            &mut *connection,
            client,
            account,
            PoolMask::from_pool(2).0, // Orchard source
            &recipients,
            false,
            Some(crate::api::pay::DEFAULT_CONFIRMATIONS),
            false,
            None,
            None,
            true, // migration — O→I
            Some(&preselected),
            Some(anchor_height),
            false, // hardware_signing
            false, // external_pczt_signing
        )
        .await?;

        let fee = crate::pay::TxPlan::from_package(network, &pczt)
            .map(|p| p.fee)
            .unwrap_or(0);
        let pczt = sign_transaction(&mut *connection, account, network, &pczt, usk_bytes).await?;
        let tx_bytes = extract_transaction(&pczt).await?;
        let txid = broadcast(
            network,
            &mut *connection,
            client,
            account,
            height,
            &tx_bytes,
        )
        .await?;

        return Ok(MigrationEvent::MigrateComplete { fee, txid });
    }

    // No SD and no non-SD orchard notes
    Ok(MigrationEvent::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::{memory_db, ACCOUNT};
    use crate::pay::fee::{LEGACY_COST_PER_ACTION, REDUCED_COST_PER_ACTION};

    const COST: u64 = LEGACY_COST_PER_ACTION;
    const PAD: u64 = sd_fee_pad(COST);

    #[tokio::test]
    async fn fetch_unspent_orchard_notes_unconfirmed_note_excludes_value() {
        let mut connection = memory_db().await;
        for (height, nullifier) in [(90_u32, vec![1_u8]), (91, vec![2])] {
            sqlx::query(
                "INSERT INTO notes(height, account, pool, scope, nullifier, tx, value)
                VALUES (?1, ?2, 2, 0, ?3, 0, 50)",
            )
            .bind(height)
            .bind(ACCOUNT)
            .bind(nullifier)
            .execute(&mut connection)
            .await
            .expect("note");
        }

        let notes = fetch_unspent_orchard_notes_with_cmx(&mut connection, ACCOUNT, 100, 90)
            .await
            .expect("notes");

        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].height, 90);
    }

    #[test]
    fn test_is_sd() {
        // PAD = 20_000, so SD = 10^k + 20_000
        assert!(!is_sd(10_001, PAD)); // not a multiple of 10,000
        assert!(!is_sd(20_001, PAD)); // (20001-20000) % 100000 = 1 ≠ 0
        assert!(is_sd(120_000, PAD)); // 10^5 + 20_000
        assert!(is_sd(1_020_000, PAD)); // 10^6 + 20_000
        assert!(is_sd(10_020_000, PAD)); // 10^7 + 20_000
        assert!(!is_sd(1_000_000, PAD)); // missing +base
        assert!(!is_sd(120_001, PAD)); // (120001-20000) % 100000 = 1 ≠ 0
                                       // Old P=10_000 values are no longer SD
        assert!(!is_sd(110_000, PAD));
        assert!(!is_sd(1_010_000, PAD));
    }

    #[test]
    fn is_sd_legacy_pad_note_after_the_reduction_is_split_again() {
        let pad = sd_fee_pad(REDUCED_COST_PER_ACTION);

        assert_eq!(pad, 4_000);
        assert_eq!(min_sd(REDUCED_COST_PER_ACTION), 100_000);
        assert!(is_sd(104_000, pad));
        assert!(is_sd(1_004_000, pad));
        assert!(!is_sd(120_000, pad));
        assert!(!is_sd(1_020_000, pad));
        assert!(has_split_transaction(
            vec![1_020_000],
            REDUCED_COST_PER_ACTION
        ));
    }

    #[test]
    fn decompose_to_sd_reduced_pad_uses_the_reduced_denominations() {
        let (pairs, leftover) = decompose_to_sd(550_000, sd_fee_pad(REDUCED_COST_PER_ACTION));

        assert_eq!(pairs, vec![(104_000, 5)]);
        assert_eq!(leftover, 30_000);
    }

    #[test]
    fn plan_split_at_either_rate_emits_denominations_of_that_rate() {
        for cost in [LEGACY_COST_PER_ACTION, REDUCED_COST_PER_ACTION] {
            let plan = plan_split(&[5_000_000], cost).expect("a split");

            assert!(!plan.digits.is_empty());
            for (denom, _) in plan.digits {
                assert!(is_sd(denom, sd_fee_pad(cost)), "{denom} at {cost}");
            }
        }
    }

    #[test]
    fn plan_split_legacy_denomination_at_the_reduced_rate_is_split_again() {
        let plan = plan_split(&[120_000], REDUCED_COST_PER_ACTION).expect("a split");

        assert_eq!(plan.digits, vec![(104_000, 1)]);
        assert_eq!(plan.remainder, 16_000);
        assert!(has_split_transaction(
            vec![120_000],
            REDUCED_COST_PER_ACTION
        ));
    }

    #[test]
    fn plan_split_above_the_buffer_band_at_the_legacy_rate_still_carves_the_buffer() {
        let plan = plan_split(&[620_000], COST).expect("a split");

        assert_eq!(plan.digits, vec![(120_000, 1)]);
        assert_eq!(plan.remainder, 500_000);
    }

    #[test]
    fn test_next_anchor_bucket_height() {
        assert_eq!(next_anchor_bucket_height(0, 144), 0);
        assert_eq!(next_anchor_bucket_height(1, 144), 144);
        assert_eq!(next_anchor_bucket_height(143, 144), 144);
        assert_eq!(next_anchor_bucket_height(144, 144), 144);
        assert_eq!(next_anchor_bucket_height(145, 144), 288);
        assert_eq!(next_anchor_bucket_height(145, 4), 148);
    }

    #[test]
    fn test_migration_anchor_bucket_size() {
        assert_eq!(migration_anchor_bucket_size(60_000), 1);
        assert_eq!(migration_anchor_bucket_size(900_000), 12);
        assert_eq!(migration_anchor_bucket_size(3_600_000), 48);
        assert_eq!(migration_anchor_bucket_size(10_800_000), 144);
        assert_eq!(migration_anchor_bucket_size(u64::MAX), 144);
    }

    #[test]
    fn test_has_split_transaction_applies_input_cap() {
        assert!(!has_split_transaction(vec![min_sd(COST) - 1], COST));
        assert!(!has_split_transaction(vec![min_sd(COST) / 100; 100], COST));
    }

    #[test]
    fn test_plan_split_min_sd_trims_one_output_to_pay_the_fee() {
        let plan = plan_split(&[min_sd(COST)], COST).expect("a split");
        assert_eq!(plan.digits, vec![(120_000, 3)]);
        assert_eq!(plan.remainder, 140_000);
        assert_eq!(
            decompose_to_sd(min_sd(COST), PAD),
            (vec![(120_000, 4)], 20_000)
        );
        assert_eq!(decompose_to_sd(0, PAD), (vec![], 0));
    }

    #[test]
    fn test_has_split_transaction_boundary_is_min_sd() {
        assert!(!has_split_transaction(vec![499_999], COST));
        assert!(has_split_transaction(vec![500_000], COST));
        assert!(has_split_transaction(vec![619_999], COST));
        assert!(has_split_transaction(vec![620_000], COST));
    }

    // The fee estimate counts a change output: an exact remainder leaves none and the builder
    // refuses, so the output is trimmed instead.
    #[test]
    fn plan_split_remainder_equal_to_the_fee_is_trimmed() {
        assert!(plan_split(&[107_000], REDUCED_COST_PER_ACTION).is_none());
        assert_eq!(
            plan_split(&[107_001], REDUCED_COST_PER_ACTION)
                .expect("a split")
                .digits,
            vec![(104_000, 1)]
        );

        let plan = plan_split(&[510_000], COST).expect("a smaller split");
        assert_eq!(plan.digits, vec![(120_000, 3)]);
        assert_eq!(plan.remainder, 150_000);
    }

    #[test]
    fn test_has_split_transaction_still_true_above_band() {
        assert!(has_split_transaction(vec![1_000_000], COST));
    }

    #[test]
    fn test_decompose_below_min_denom() {
        // Below d_min (120_000).
        let (pairs, leftover) = decompose_to_sd(10_000, PAD);
        assert!(pairs.is_empty());
        assert_eq!(leftover, 10_000);
    }

    #[test]
    fn test_decompose_zero() {
        let (pairs, leftover) = decompose_to_sd(0, PAD);
        assert!(pairs.is_empty());
        assert_eq!(leftover, 0);
    }

    #[test]
    fn test_decompose_exact_sd() {
        // 120_000 = 10^5 + 20_000.
        let (pairs, leftover) = decompose_to_sd(120_000, PAD);
        assert_eq!(pairs, vec![(120_000, 1)]);
        assert_eq!(leftover, 0);
    }

    #[test]
    fn test_decompose_multiple() {
        // 4 × 120_000 = 480_000, leftover 20_000.
        let (pairs, leftover) = decompose_to_sd(500_000, PAD);
        assert_eq!(pairs, vec![(120_000, 4)]);
        assert_eq!(leftover, 20_000);
    }

    #[test]
    fn test_decompose_two_positions() {
        // 1_140_000 → 1×1_020_000 + 1×120_000.
        let (pairs, leftover) = decompose_to_sd(1_140_000, PAD);
        assert_eq!(pairs, vec![(1_020_000, 1), (120_000, 1)]);
        assert_eq!(leftover, 0);
    }

    #[test]
    fn test_decompose_with_remainder() {
        // 130_000 → 1×120_000, leftover 10_000 (below d_min).
        let (pairs, leftover) = decompose_to_sd(130_000, PAD);
        assert_eq!(pairs, vec![(120_000, 1)]);
        assert_eq!(leftover, 10_000);
    }

    /// Round-trip invariant: sum(denom × count) + leftover ≡ original total.
    #[test]
    fn test_decompose_round_trip() {
        let cases = &[0, 10_000, 120_000, 500_000, 1_140_000, 130_000, 5_000_000];
        for &total in cases {
            let (pairs, leftover) = decompose_to_sd(total, PAD);
            let represented: u64 = pairs.iter().map(|&(d, c)| d * c as u64).sum();
            assert_eq!(
                represented + leftover,
                total,
                "round-trip failed for total={total}"
            );
        }
    }

    #[test]
    fn broadcast_txid_returns_the_txid_when_the_node_accepted_the_transaction() {
        let outcome = BroadcastOutcome {
            error_code: 0,
            message: "9f3c".to_string(),
            inputs_released: false,
        };

        assert_eq!("9f3c", broadcast_txid(outcome).unwrap());
    }

    #[test]
    fn broadcast_txid_fails_when_the_node_rejected_the_transaction() {
        let outcome = BroadcastOutcome {
            error_code: -25,
            message: "missing inputs".to_string(),
            inputs_released: false,
        };

        let error = broadcast_txid(outcome).unwrap_err().to_string();
        assert!(error.contains("-25"), "{error}");
        assert!(error.contains("missing inputs"), "{error}");
    }
}
