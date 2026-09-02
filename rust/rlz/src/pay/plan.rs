use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    str::FromStr as _,
    sync::LazyLock,
};

use anyhow::{anyhow, Result};

use bip32::PrivateKey;
use itertools::Itertools;
use orchard::{
    circuit::ProvingKey,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::AssetBase,
    value::NoteValue,
    Address,
};
use pczt::{
    common::determine_lock_time,
    roles::{
        creator::Creator, io_finalizer::IoFinalizer, issuer::Issuer, prover::Prover,
        signer::Signer, spend_finalizer::SpendFinalizer, tx_extractor::TransactionExtractor,
        updater::Updater,
    },
    Pczt,
};
use rand_core::{OsRng, RngCore};
use ripemd::Ripemd160;
use sapling_crypto::PaymentAddress;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{sqlite::SqliteRow, Row, SqliteConnection};
use tracing::{event, info, span, Level};
use zcash_address::{unified::Receiver, ConversionError, TryFromAddress, ZcashAddress};
use zcash_keys::{
    address::UnifiedAddress, encoding::AddressCodec as _, keys::sapling::ExtendedSpendingKey,
};
use zcash_note_encryption::Domain;
use zcash_primitives::transaction::{
    builder::{BuildConfig, Builder, BundlePadding},
    fees::zip317::FeeRule,
    TxVersion,
};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};
use zcash_protocol::{PoolType, ShieldedPool, TxId};
use zcash_script::script;
use zcash_transparent::{
    address::TransparentAddress,
    builder::{SpendInfo, TransparentInputInfo},
    bundle::{OutPoint, TxOut},
    keys::AccountPrivKey,
    pczt::Bip32Derivation,
};
use zip321::{Payment, TransactionRequest};

use crate::{
    account::{
        derive_transparent_sk, generate_next_change_address, get_account_full_address,
        get_orchard_note, get_orchard_vk, get_sapling_note, get_sapling_vk,
    },
    api::{coin::Network, issuance::IssuanceInfo, pay::PcztPackage},
    db::{get_account_can_sign, get_account_dindex, get_account_hw, select_account_transparent},
    keys::{sapling_pgk_for_scope, sapling_ssk_for_scope, SaplingFullViewingKey},
    pay::{
        error::Error,
        fee::COST_PER_ACTION,
        pool::{PoolMask, NUM_POOLS},
        prepare::to_zec,
        signing_key::SigningKey,
        solve, DecomposedRecipient, InputNote, ReceiverOption, Recipient, RecipientState,
    },
    warp::hasher::{empty_roots, OrchardHasher, SaplingHasher},
    Client,
};

use zcash_primitives::transaction::zsa_builder::ZsaBuilder;

fn attach_orchard_asset_names<D: Domain>(
    mut updater: orchard::pczt::Updater<'_, D>,
    asset_names: &HashMap<[u8; 32], String>,
) -> Result<(), orchard::pczt::UpdaterError> {
    for index in 0..updater.bundle().actions().len() {
        let (spend_name, output_name) = {
            let action = &updater.bundle().actions()[index];
            (
                action
                    .spend()
                    .asset()
                    .and_then(|asset| asset_names.get(&asset.to_bytes()).cloned()),
                action
                    .output()
                    .asset()
                    .and_then(|asset| asset_names.get(&asset.to_bytes()).cloned()),
            )
        };

        updater.update_action_with(index, |mut action| {
            if let Some(name) = spend_name {
                action.set_spend_proprietary("asset_name".to_string(), name.into_bytes());
            }
            if let Some(name) = output_name {
                action.set_output_proprietary("asset_name".to_string(), name.into_bytes());
            }
            Ok(())
        })?;
    }
    Ok(())
}

pub fn is_tex(network: &Network, address: &str) -> Result<bool> {
    let zaddress = ZcashAddress::from_str(address)?;
    let zaddress: zcash_keys::address::Address =
        zaddress.convert_if_network(network.network_type()).unwrap();

    let is_tex = matches!(zaddress, zcash_keys::address::Address::Tex(_));
    Ok(is_tex)
}

pub async fn build_puri(recipients: &[Recipient]) -> Result<String> {
    // make a payment uri
    let payments = recipients
        .iter()
        .map(|r| {
            let address = ZcashAddress::from_str(&r.address)?;
            let amount = Zatoshis::const_from_u64(r.amount);
            let memo = encode_memo(r)?;
            Ok::<_, anyhow::Error>(
                Payment::new(address, Some(amount), memo, None, None, vec![]).expect("payment"),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let puri = TransactionRequest::new(payments)?;
    let puri = puri.to_uri();

    Ok(puri)
}

fn build_zsa_builder(info: &IssuanceInfo, oaddress: orchard::Address) -> Result<ZsaBuilder> {
    let mut zsa = ZsaBuilder::new(info.isk.clone());
    zsa.add_issue_output(
        info.desc_hash,
        oaddress,
        NoteValue::from_raw(info.amount),
        info.first_issuance,
        &mut OsRng,
    )
    .map_err(|e| anyhow!("Failed to add issue output: {e:?}"))?;
    if info.finalize {
        zsa.finalize_asset(&info.desc_hash)
            .map_err(|e| anyhow!("Failed to finalize asset: {e:?}"))?;
    }
    Ok(zsa)
}

/// Decompose a Zcash address into its individual shielded receivers.
/// - UA address → S/O/I receivers (transparent stripped)
/// - Pre-ironwood: Ironwood removed → max S/O
/// - Post-ironwood: Orchard removed → max S/I
/// - Single-pool address → 1 receiver as-is
/// Returns 1 or 2 ReceiverOptions (OR alternatives).
/// Prefer O/I over S, returning exactly 1 shielded receiver.
fn decompose_address(
    address: &str,
    network: &Network,
    ironwood_active: bool,
) -> Result<ReceiverOption> {
    // Decode as unified address (works for UAs and single-pool shielded)
    if let Ok(ua) = UnifiedAddress::decode(network, address) {
        // Prefer Orchard/Ironwood over Sapling
        if let Some(orchard) = ua.orchard() {
            return Ok(ReceiverOption {
                receiver: Receiver::Orchard(orchard.to_raw_address_bytes()),
                pool: if ironwood_active { 3 } else { 2 },
                remaining: 0,
            });
        }
        if let Some(sapling) = ua.sapling() {
            return Ok(ReceiverOption {
                receiver: Receiver::Sapling(sapling.to_bytes()),
                pool: 1,
                remaining: 0,
            });
        }
        anyhow::bail!("Address has no shielded receivers");
    }

    // Fallback: single-pool address (transparent, sapling, orchard).
    // UnifiedAddress::decode only handles Bech32m UA containers, so
    // regtest Sapling (Bech32) and transparent (Base58) addresses
    // must be decoded individually via the AddressCodec trait.
    let zaddr = ZcashAddress::try_from_encoded(address)?;

    if zaddr.can_receive_as(PoolType::Transparent) {
        let receiver = match zaddr.convert_if_network(network.network_type()) {
            Ok(zcash_keys::address::Address::Tex(data)) => Receiver::P2pkh(data),
            _ => {
                let taddr = TransparentAddress::decode(network, address)
                    .map_err(|e| anyhow!("Failed to decode transparent address: {e:?}"))?;
                match taddr {
                    TransparentAddress::PublicKeyHash(hash) => Receiver::P2pkh(hash),
                    TransparentAddress::ScriptHash(hash) => Receiver::P2sh(hash),
                }
            }
        };
        return Ok(ReceiverOption {
            receiver,
            pool: 0,
            remaining: 0,
        });
    }

    if zaddr.can_receive_as(PoolType::Shielded(ShieldedPool::Sapling)) {
        let sapling = PaymentAddress::decode(network, address)
            .map_err(|e| anyhow!("Failed to decode sapling address: {e}"))?;
        return Ok(ReceiverOption {
            receiver: Receiver::Sapling(sapling.to_bytes()),
            pool: 1,
            remaining: 0,
        });
    }

    if zaddr.can_receive_as(PoolType::Shielded(ShieldedPool::Orchard)) {
        // Orchard single-pool addresses — re-decode through UA
        let ua = UnifiedAddress::decode(network, address)
            .map_err(|e| anyhow!("Failed to decode orchard address: {e}"))?;
        let orchard = ua
            .orchard()
            .ok_or_else(|| anyhow!("Address has no orchard receiver"))?;
        return Ok(ReceiverOption {
            receiver: Receiver::Orchard(orchard.to_raw_address_bytes()),
            pool: if ironwood_active { 3 } else { 2 },
            remaining: 0,
        });
    }

    anyhow::bail!("Unrecognized address pool");
}

/// Whether the app can produce a spending key for this account: from a phrase it owns, or
/// from an imported xprv/ESK. A viewing-key-only or Ledger account cannot.
async fn account_can_sign(connection: &mut SqliteConnection, account: u32) -> Result<bool> {
    get_account_can_sign(connection, account).await
}

/// The candidate set a plan may spend from: only the pools in `src_pools`, and within
/// them only notes confirmed against `max_height`.
pub(crate) fn restrict_to_source_pools(
    input_pools: &mut [Vec<InputNote>],
    src_pools: u8,
    max_height: u32,
) {
    for pool in 0..NUM_POOLS {
        if src_pools & (1 << pool) == 0 {
            input_pools[pool].clear();
        } else {
            input_pools[pool].retain(|n| n.height <= max_height);
        }
    }
}

/// Drops ZEC notes too small to pay for a single logical action. ZSA amounts are
/// denominated in their own asset and cannot pay fees, so the threshold ignores them.
pub(crate) fn drop_zec_dust(input_pools: &mut [Vec<InputNote>]) {
    for pool in input_pools.iter_mut() {
        pool.retain(|n| {
            let is_zec = n.asset_base.is_empty() || n.asset_base.iter().all(|&byte| byte == 0);
            !is_zec || n.amount >= COST_PER_ACTION
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn plan_transaction(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    src_pools: u8,
    recipients: &[Recipient],
    recipient_pays_fee: bool,
    confirmations: Option<u32>,
    smart_transparent: bool,
    category: Option<u32>,
    issuance: Option<&IssuanceInfo>,
    migration: bool,
    preselected: Option<&[u32]>,
    anchor_height: Option<u32>,
    // Forces a v5 (ZIP-244) transaction, the only version an external hardware signer
    // (e.g. Trezor) currently understands, regardless of the account's own `hw` flag.
    hardware_signing: bool,
) -> Result<PcztPackage> {
    let mut input_pools = fetch_unspent_notes_by_pool(connection, account).await?;
    let height = client.latest_height().await?;
    let confirmations = confirmations.unwrap_or_default();
    let max_height = crate::db::confirmed_height(&mut *connection, account, confirmations).await?;
    restrict_to_source_pools(&mut input_pools, src_pools, max_height);

    // Preselected filter: restrict to specific note IDs (e.g. migration)
    if let Some(ids) = preselected {
        for pool in 0..NUM_POOLS {
            input_pools[pool].retain(|n| ids.contains(&n.id));
        }
    }

    let recipients = recipients.to_vec();
    let (mut input_pools, recipients, recipient_pays_fee) = if smart_transparent {
        let mut notes = std::mem::take(&mut input_pools[0]);
        // Group by taddress, pick one random address to shield
        notes.sort_by_key(|n| n.taddress);
        let groups: Vec<Vec<InputNote>> = notes
            .into_iter()
            .chunk_by(|n| n.taddress)
            .into_iter()
            .map(|(_, group)| group.collect())
            .collect();
        let notes = if groups.is_empty() {
            vec![]
        } else {
            let i = OsRng.next_u32() as usize % groups.len();
            groups[i].clone()
        };
        let max = notes.iter().map(|n| n.amount).sum::<u64>();
        let recipient = Recipient {
            amount: max,
            ..recipients.first().cloned().unwrap_or_default()
        };
        let mut pools = vec![vec![]; NUM_POOLS as usize];
        pools[0] = notes;
        (pools, vec![recipient], true)
    } else {
        (input_pools, recipients, recipient_pays_fee)
    };

    let ironwood_active =
        network.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(height));
    let orchard_note_version =
        if BranchId::for_height(network, BlockHeight::from_u32(height)) == BranchId::Nu7 {
            orchard::NoteVersion::V3ZSA
        } else {
            orchard::NoteVersion::V2
        };
    let decomposed: Vec<DecomposedRecipient> = recipients
        .iter()
        .map(|r| {
            let asset_base = if r.asset_base.is_empty() {
                [0u8; 32].to_vec()
            } else {
                r.asset_base.clone()
            };
            Ok(DecomposedRecipient {
                address: r.address.clone(),
                receiver: decompose_address(&r.address, network, ironwood_active)?,
                amount: r.amount,
                remaining: r.amount,
                memo: r.user_memo.clone(),
                memo_bytes: r.memo_bytes.clone(),
                asset_base,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // ZSA and Ironwood are mutually exclusive (different V6 version group IDs).
    let has_zsa = decomposed
        .iter()
        .any(|d| d.asset_base != [0u8; 32].to_vec())
        || issuance.is_some();
    if has_zsa && ironwood_active {
        anyhow::bail!("ZSA and Ironwood are incompatible");
    }

    // Build asset list for solver: index 0 = ZEC, indices 1+ = ZSA (sorted)
    let zec_key = [0u8; 32];
    let zsa_assets: Vec<[u8; 32]> = decomposed
        .iter()
        .filter(|d| d.asset_base != zec_key.to_vec())
        .map(|d| d.asset_base.clone())
        .sorted()
        .dedup()
        .filter_map(|b| b.try_into().ok())
        .collect();

    // ── Compute additional context ───────────────────────────────────────
    let dindex = get_account_dindex(connection, account).await?;
    let hw = get_account_hw(&mut *connection, account).await?;

    // Compute weighted average price from recipients that have a price set
    let mut total_amount = 0;
    let mut total_fiat = 0.0;
    for r in &recipients {
        if let Some(p) = r.price {
            total_fiat += p * r.amount as f64;
            total_amount += r.amount;
        }
    }
    let price = if total_amount != 0 {
        Some(total_fiat / total_amount as f64)
    } else {
        None
    };

    let (use_internal,): (bool,) =
        sqlx::query_as("SELECT use_internal FROM accounts WHERE id_account = ?")
            .bind(account)
            .fetch_one(&mut *connection)
            .await?;

    let before_dust: [usize; NUM_POOLS] = std::array::from_fn(|p| input_pools[p].len());
    drop_zec_dust(&mut input_pools);
    info!(
        "plan: after dust filter — t:{}→{}, s:{}→{}, o:{}→{}, iw:{}→{}",
        before_dust[0],
        input_pools[0].len(),
        before_dust[1],
        input_pools[1].len(),
        before_dust[2],
        input_pools[2].len(),
        before_dust[3],
        input_pools[3].len(),
    );

    // Build asset→index lookup: 0 = ZEC, 1+ = index into zsa_assets
    let zsa_index: HashMap<[u8; 32], u8> = zsa_assets
        .iter()
        .enumerate()
        .map(|(i, a)| (*a, (i + 1) as u8))
        .collect();

    // Clone for move-capture in closures below
    let zi = zsa_index.clone();

    fn resolve_asset_index(
        asset_base: &Vec<u8>,
        zec_key: [u8; 32],
        zsa_index: &HashMap<[u8; 32], u8>,
    ) -> u8 {
        let asset_bytes: [u8; 32] = asset_base.clone().try_into().unwrap_or(zec_key);
        if asset_bytes == zec_key {
            0
        } else {
            zsa_index.get(&asset_bytes).copied().unwrap_or(0)
        }
    }

    // ── Coin selection via solve::select_notes ─────────────────────────────
    // Stamp asset_index on notes: 0 = ZEC, 1+ = index into zsa_assets
    let select_notes_input: Vec<solve::Note> = input_pools
        .iter()
        .enumerate()
        .flat_map(|(pool, notes)| {
            let zi = zi.clone();
            notes.iter().enumerate().filter_map(move |(idx, n)| {
                // Classify by the note's real asset: ZEC → 0, a recipient ZSA
                // asset → its solver index. A ZSA note whose asset is NOT one of
                // the recipient assets can't fund this payment (it isn't ZEC and
                // has no matching output), so drop it from the candidate set.
                // Mapping it to index 0 (the old `unwrap_or(0)` behaviour) let the
                // solver treat it as spendable ZEC: it would then "pay" the fee
                // with phantom ZEC while the builder spent the note as its real
                // asset, leaving that asset over-spent and the ZEC change unbacked
                // (Orchard IO-finalize → ValueCommitMismatch).
                let asset_bytes: [u8; 32] = n.asset_base.clone().try_into().unwrap_or(zec_key);
                let asset_index = if asset_bytes == zec_key {
                    0
                } else {
                    match zi.get(&asset_bytes) {
                        Some(&i) => i,
                        None => return None,
                    }
                };
                Some(solve::Note {
                    pool: pool as u8,
                    amount: n.amount,
                    pool_index: idx,
                    asset_index,
                })
            })
        })
        .collect();

    // Compute pool preference per recipient once (explicit pool hint, or
    // fall back to the address-derived pool from decompose_address).
    let pool_prefs: Vec<u8> = recipients
        .iter()
        .zip(decomposed.iter())
        .map(|(r, dr)| {
            r.pools
                .and_then(|p| PoolMask(p).to_best_pool())
                .unwrap_or(dr.receiver.pool)
        })
        .collect();

    let select_outputs: Vec<solve::Output> = pool_prefs
        .iter()
        .zip(decomposed.iter())
        .map(|(&pool, dr)| {
            let asset_index = resolve_asset_index(&dr.asset_base, zec_key, &zsa_index);
            solve::Output {
                pool,
                amount: dr.amount,
                asset_index,
            }
        })
        .collect();

    info!(
        "plan: calling select_notes — {} input notes, {} outputs, migration={}, recipient_pays_fee={}, first_recipient={}",
        select_notes_input.len(), select_outputs.len(), migration, recipient_pays_fee,
        recipients.first().map(|r| r.amount).unwrap_or(0)
    );
    for o in &select_outputs {
        info!("plan: output pool={} amount={}", o.pool, o.amount);
    }

    let selection = solve::select_notes(
        &select_notes_input,
        &select_outputs,
        COST_PER_ACTION,
        migration,
        recipient_pays_fee,
        recipients.first().map(|r| r.amount).unwrap_or(0),
    )
    .ok_or_else(|| anyhow!("No feasible note selection found"))?;

    info!(
        "plan: select_notes succeeded — fee={}, change_pool={}, selected_inputs={}",
        selection.fee,
        selection.change_pool,
        selection.inputs.len()
    );

    // Mark selected notes as fully consumed (select_notes uses 0/1 knapsack)
    for pool in 0..NUM_POOLS {
        for &idx in &selection.per_pool_indices[pool] {
            input_pools[pool][idx].remaining = 0;
        }
    }

    // ZSA assets only exist in Orchard; force change to orchard if any ZSA.
    // The ZEC change output satisfies ZIP-226 (no dummy needed).
    let change_pool = if has_zsa { 2 } else { selection.change_pool };

    // ── Compute ZSA change amounts ───────────────────────────────────────
    // Per-asset: sum of selected ZSA notes minus required ZSA outputs.
    let mut zsa_changes: Vec<([u8; 32], u64)> = vec![];
    if has_zsa {
        let mut zsa_selected: HashMap<[u8; 32], u64> = HashMap::new();
        // Pool 2 (Orchard) is where ZSA notes live
        for &idx in &selection.per_pool_indices[2] {
            let note = &input_pools[2][idx];
            let asset_bytes: [u8; 32] = note.asset_base.clone().try_into().unwrap_or(zec_key);
            if asset_bytes != zec_key {
                *zsa_selected.entry(asset_bytes).or_default() += note.amount;
            }
        }
        for asset in &zsa_assets {
            let selected = *zsa_selected.get(asset).unwrap_or(&0);
            let needed: u64 = decomposed
                .iter()
                .filter(|d| d.asset_base == asset.to_vec())
                .map(|d| d.amount)
                .sum();
            if selected > needed {
                zsa_changes.push((*asset, selected - needed));
            }
        }
    }

    // ── Build RecipientStates ────────────────────────────────────────────
    let mut recipient_states: Vec<RecipientState> = pool_prefs
        .iter()
        .zip(decomposed.iter())
        .map(|(&pool, dr)| {
            RecipientState {
                recipient: Recipient {
                    address: dr.address.clone(),
                    amount: dr.amount,
                    asset_base: dr.asset_base.clone(),
                    memo_bytes: dr.memo_bytes.clone(),
                    user_memo: dr.memo.clone(),
                    ..Default::default()
                },
                remaining: 0, // fully funded by select_notes
                pool_mask: PoolMask::from_pool(pool),
                asset_base: dr.asset_base.clone(),
            }
        })
        .collect();

    // Append ZSA change outputs (ZIP-226: ZEC outputs before ZSA outputs)
    for (asset, change_amount) in &zsa_changes {
        recipient_states.push(RecipientState {
            recipient: Recipient {
                address: String::new(), // filled in below with change_address
                amount: *change_amount,
                asset_base: asset.to_vec(),
                ..Recipient::default()
            },
            remaining: 0,
            pool_mask: PoolMask::from_pool(2), // ZSA always Orchard
            asset_base: asset.to_vec(),
        });
    }

    // ── Fee, totals, and change (select_notes already validated feasibility) ─
    // Issuance actions add separate logical actions on top of regular pool
    // actions (ZIP-233). First issuance: 2 notes (reference + real), reissuance: 1.
    let issuance_fee = issuance
        .map(|info| if info.first_issuance { 2 } else { 1 } * COST_PER_ACTION)
        .unwrap_or(0);
    let fee = selection.fee + issuance_fee;
    info!("Fee (select_notes + issuance): {}", to_zec(fee));

    // When the recipient pays the fee, deduct it from the first recipient
    // so the sender only needs to cover (total_output - fee), matching the
    // solver's target of `output_sum` (without fee).
    if recipient_pays_fee {
        if let Some(first) = recipient_states.first_mut() {
            first.recipient.amount = first.recipient.amount.saturating_sub(fee);
        }
    }

    let total_output: u64 = recipient_states.iter().map(|r| r.recipient.amount).sum();
    let total_input: u64 = selection.inputs.iter().map(|n| n.amount).sum();
    let change = total_input.saturating_sub(total_output + fee);

    info!(
        "change: {}, pool: {change_pool}, fee: {}",
        to_zec(change),
        to_zec(fee)
    );

    // ── Log outputs ──────────────────────────────────────────────────────
    for r in &recipient_states {
        info!(
            "address: {}, pool: {}, amount: {}",
            r.recipient.address,
            r.pool_mask.to_best_pool().unwrap(),
            to_zec(r.recipient.amount)
        );
    }

    // ── Fetch tree states and anchors ────────────────────────────────────
    let h = crate::sync::get_db_height(connection, account).await?;
    let anchor_height = anchor_height.unwrap_or(h.height);
    anyhow::ensure!(
        anchor_height <= h.height,
        "Anchor height {anchor_height} is ahead of checkpoint {}",
        h.height,
    );
    anyhow::ensure!(
        !migration || anchor_height == h.height,
        "Migration anchor {anchor_height} no longer matches checkpoint {}",
        h.height,
    );
    let (ts, to, ti) = crate::sync::get_tree_state(network, client, anchor_height).await?;
    let es = ts.to_edge(&SaplingHasher::default());
    let eo = to.to_edge(&OrchardHasher::default());
    let ei = ti.to_edge(&OrchardHasher::default());
    let sapling_anchor = es.root(&SaplingHasher::default());
    let orchard_anchor = eo.root(&OrchardHasher::default());
    let ironwood_anchor = ei.root(&OrchardHasher::default());

    // Determine which pools are active in this transaction
    let mut has_pool = [false; NUM_POOLS as usize];
    for pool in 1..NUM_POOLS {
        let p = pool as u8;
        has_pool[pool] = input_pools[pool].iter().any(|inp| inp.is_used())
            || recipient_states
                .iter()
                .any(|r| r.pool_mask.to_best_pool() == Some(p))
            || change_pool == p;
    }
    has_pool[3] &= ironwood_active;
    // ZSA assets only exist in Orchard pool; ensure pool 2 is active
    // when ZSA is present (covers issuance-only case with no ZSA notes).
    has_pool[2] |= has_zsa;

    // ── Fetch change address ─────────────────────────────────────────────
    let change_scope = if use_internal { 1 } else { 0 };
    let mut change_address =
        get_account_full_address(network, connection, account, change_scope, hw).await?;
    let tkeys = select_account_transparent(connection, account, dindex).await?;
    if change_pool == 0 && tkeys.xvk.is_some() {
        change_address = generate_next_change_address(network, connection, account)
            .await?
            .unwrap();
    }

    // Fill in ZSA change output addresses
    for rs in &mut recipient_states {
        if rs.recipient.address.is_empty() && rs.asset_base != zec_key.to_vec() {
            rs.recipient.address = change_address.clone();
        }
    }

    // ── Fetch keys ───────────────────────────────────────────────────────
    let svk = get_sapling_vk(connection, account).await?;
    let ovk = get_orchard_vk(connection, account).await?;
    let can_sign = account_can_sign(connection, account).await?;

    // ── Build transaction ────────────────────────────────────────────────
    let current_height = client.latest_height().await?;
    let target_height = current_height;

    let build_config = BuildConfig::Standard {
        sapling_anchor: if has_pool[1] {
            sapling_crypto::Anchor::from_bytes(sapling_anchor).into_option()
        } else {
            None
        },
        orchard_anchor: if has_pool[2] {
            orchard::Anchor::from_bytes(orchard_anchor).into_option()
        } else {
            None
        },
        ironwood_anchor: if has_pool[3] {
            orchard::Anchor::from_bytes(ironwood_anchor).into_option()
        } else {
            None
        },
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    };
    let mut builder = Builder::new(network, BlockHeight::from_u32(target_height), build_config);

    // Hardware (Ledger) wallets only support v5 (ZIP-244) transaction signing.
    // The Zondax "Zcash Shielded" app predates NU6.3 and cannot sign v6/Ironwood
    // transactions, so force a v5 tx while keeping consensus_branch_id = Nu6_3
    // (V5 is valid in Nu6_3 per TxVersion::valid_in_branch). A v5 tx carrying the
    // current Nu6_3 branch id is valid on the network.
    if wants_hardware_v5(hw, hardware_signing) {
        builder
            .propose_version::<()>(TxVersion::V5)
            .map_err(|e| anyhow!("failed to force v5 for hardware signing: {e:?}"))?;
    }

    let es = es.to_auth_path(&SaplingHasher::default());
    let eo = eo.to_auth_path(&OrchardHasher::default());
    let ei = ei.to_auth_path(&OrchardHasher::default());
    let ers = empty_roots(&SaplingHasher::default());
    let ero = empty_roots(&OrchardHasher::default());

    let mut tsk_dindex = vec![];
    let mut s_scope = vec![];

    event!(Level::INFO, "Adding Inputs");

    let mut n_spends: [usize; NUM_POOLS as usize] = [0; NUM_POOLS as usize];

    for pool in input_pools.iter() {
        for inp in pool.iter() {
            if inp.is_used() {
                let InputNote {
                    id, amount, pool, ..
                } = inp;
                n_spends[*pool as usize] += 1;
                match pool {
                    0 => {
                        let row = sqlx::query(
                            "SELECT nullifier, t.pk, t.sk, t.scope, t.dindex, t.address, t.uncompressed FROM notes
                            JOIN transparent_address_accounts t ON notes.taddress = t.id_taddress
                            WHERE id_note = ?",
                        )
                        .bind(*id)
                        .fetch_one(&mut *connection)
                        .await?;

                        let _nf: Vec<u8> = row.get(0);
                        let pk: Vec<u8> = row.get(1);
                        let scope: u32 = row.get(3);
                        let dindex_t: u32 = row.get(4);
                        let taddress: String = row.get(5);
                        let uncompressed: bool = row.get(6);

                        let pubkey = PublicKey::from_slice(&pk).unwrap();
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&_nf[0..32]);
                        let n = u32::from_le_bytes(_nf[32..36].try_into().unwrap());
                        let utxo = OutPoint::new(hash, n);
                        let pk_bytes = if uncompressed {
                            pubkey.serialize_uncompressed().to_vec()
                        } else {
                            pubkey.serialize().to_vec()
                        };
                        let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(&pk_bytes)).into();
                        let addr = TransparentAddress::PublicKeyHash(pkh);
                        let coin =
                            TxOut::new(Zatoshis::from_u64(*amount).unwrap(), addr.script().into());

                        builder.add_transparent_input(
                            TransparentInputInfo::from_parts(
                                utxo,
                                coin,
                                SpendInfo::P2pkh { pubkey },
                            )
                            .map_err(|e: zcash_transparent::builder::Error| anyhow!(e))?,
                        );
                        tsk_dindex.push((pubkey, scope, dindex_t, taddress, uncompressed));
                    }
                    1 => {
                        let (note, scope, merkle_path) = get_sapling_note(
                            connection,
                            *id,
                            h.height,
                            svk.as_ref().unwrap(),
                            &es,
                            &ers,
                        )
                        .await?;

                        let dfvk = svk.as_ref().unwrap();
                        let fvk = dfvk.to_fvk(scope);
                        builder.add_sapling_spend::<Infallible>(fvk, note, merkle_path)?;
                        s_scope.push(scope);
                    }
                    2 => {
                        let (note, merkle_path) = get_orchard_note(
                            connection,
                            *id,
                            h.height,
                            ovk.as_ref().unwrap(),
                            &eo,
                            &ero,
                            orchard_note_version,
                            (!migration && anchor_height < h.height).then_some(eo.1),
                        )
                        .await?;

                        builder.add_orchard_spend::<Infallible>(
                            ovk.clone().unwrap(),
                            note,
                            merkle_path,
                        )?;
                    }
                    3 => {
                        let (note, merkle_path) = get_orchard_note(
                            connection,
                            *id,
                            h.height,
                            ovk.as_ref().unwrap(),
                            &ei,
                            &ero,
                            orchard::NoteVersion::V3,
                            (!migration && anchor_height < h.height).then_some(ei.1),
                        )
                        .await?;

                        builder.add_ironwood_spend::<Infallible>(
                            ovk.clone().unwrap(),
                            note,
                            merkle_path,
                        )?;
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    // ── Add outputs ──────────────────────────────────────────────────────
    event!(Level::INFO, "Adding Outputs");
    let mut n_outputs: [usize; NUM_POOLS as usize] = [0; NUM_POOLS as usize];
    // In transparent-bundle order: the address every transparent output actually pays,
    // for `label_transparent_outputs` to attach to the equivalent PCZT output.
    let mut transparent_output_addresses: Vec<String> = Vec::new();

    for r in &recipient_states {
        let pool = r.pool_mask.to_best_pool().unwrap();
        let value = Zatoshis::from_u64(r.recipient.amount)?;
        let memo = encode_memo(&r.recipient)?.unwrap_or(MemoBytes::empty());

        n_outputs[pool as usize] += 1;
        match pool {
            0 => {
                if value != Zatoshis::ZERO {
                    let to = get_transparent_address(network, &r.recipient.address)?;
                    builder
                        .add_transparent_output(&to, value)
                        .map_err(|e: zcash_transparent::builder::Error| anyhow!(e))?;
                    transparent_output_addresses.push(r.recipient.address.clone());
                }
            }
            1 => {
                let to = get_sapling_address(network, &r.recipient.address)?;
                builder.add_sapling_output::<Infallible>(
                    svk.as_ref().map(|svk| svk.to_ovk(Scope::External)),
                    to,
                    value,
                    memo,
                )?;
            }
            2 => {
                let to = get_orchard_address(network, &r.recipient.address)?;
                let asset_base = if r.asset_base == [0u8; 32].to_vec() {
                    AssetBase::zatoshi()
                } else {
                    let asset_bytes: [u8; 32] =
                        r.asset_base.clone().try_into().map_err(|v: Vec<u8>| {
                            anyhow!("Invalid asset_base length: expected 32, got {}", v.len())
                        })?;
                    Option::from(AssetBase::from_bytes(&asset_bytes)).ok_or_else(|| {
                        anyhow!("Invalid asset_base bytes: {}", hex::encode(&asset_bytes))
                    })?
                };
                if ironwood_active {
                    // O->O self-send: use change output to avoid dummy-spend
                    // fee inflation (Orchard V3 disables cross-address transfers).
                    if let Some(ref fvk) = ovk {
                        builder.add_orchard_change_output::<Infallible>(
                            fvk.clone(),
                            Some(fvk.to_ovk(Scope::External)),
                            to,
                            value,
                            asset_base,
                            MemoBytes::empty(),
                        )?;
                    } else {
                        anyhow::bail!("No orchard key for migration change output");
                    }
                } else {
                    builder.add_orchard_output::<Infallible>(
                        ovk.as_ref().map(|ovk| ovk.to_ovk(Scope::External)),
                        to,
                        value,
                        asset_base,
                        memo,
                    )?;
                }
            }
            3 => {
                let to = get_orchard_address(network, &r.recipient.address)?;
                builder.add_ironwood_output::<Infallible>(
                    ovk.as_ref().map(|ovk| ovk.to_ovk(Scope::External)),
                    to,
                    value,
                    memo,
                )?;
            }
            _ => {}
        }
    }

    // ── Add change output ────────────────────────────────────────────────
    let mut transparent_change_label: Option<TransparentChangeLabel> = None;
    if change > 0 {
        let change_addr = if change_pool == 0 && tkeys.xvk.is_some() {
            generate_next_change_address(network, connection, account)
                .await?
                .unwrap()
        } else {
            change_address.clone()
        };
        match change_pool {
            0 => {
                let to = get_transparent_address(network, &change_addr)?;
                builder
                    .add_transparent_output(&to, Zatoshis::const_from_u64(change))
                    .map_err(|e: zcash_transparent::builder::Error| anyhow!(e))?;
                transparent_change_label =
                    Some(load_transparent_change_label(connection, account, &change_addr).await?);
            }
            1 => {
                let to = get_sapling_address(network, &change_addr)?;
                builder.add_sapling_output::<Infallible>(
                    svk.as_ref().map(|svk| svk.to_ovk(Scope::External)),
                    to,
                    Zatoshis::const_from_u64(change),
                    MemoBytes::empty(),
                )?;
            }
            2 => {
                let to = get_orchard_address(network, &change_addr)?;
                if ironwood_active {
                    if let Some(ref fvk) = ovk {
                        builder.add_orchard_change_output::<Infallible>(
                            fvk.clone(),
                            Some(fvk.to_ovk(Scope::External)),
                            to,
                            Zatoshis::const_from_u64(change),
                            AssetBase::zatoshi(),
                            MemoBytes::empty(),
                        )?;
                    } else {
                        anyhow::bail!("No orchard key for change output");
                    }
                } else {
                    builder.add_orchard_output::<Infallible>(
                        ovk.as_ref().map(|ovk| ovk.to_ovk(Scope::External)),
                        to,
                        Zatoshis::const_from_u64(change),
                        AssetBase::zatoshi(),
                        MemoBytes::empty(),
                    )?;
                }
            }
            3 => {
                let to = get_orchard_address(network, &change_addr)?;
                if let Some(ref fvk) = ovk {
                    builder.add_ironwood_output::<Infallible>(
                        Some(fvk.to_ovk(Scope::External)),
                        to,
                        Zatoshis::const_from_u64(change),
                        MemoBytes::empty(),
                    )?;
                } else {
                    anyhow::bail!("No orchard key for ironwood change output");
                }
            }
            _ => {}
        }
    }

    // ── Build PCZT ───────────────────────────────────────────────────────
    info!("Building");
    event!(Level::INFO, "Preparing PCZT");

    // Attach ZsaBuilder before build_for_pczt for fee computation (ZIP-317)
    if let Some(info) = issuance {
        let oaddress = ovk
            .as_ref()
            .ok_or_else(|| anyhow!("No orchard key for issuance"))?
            .address_at(dindex, Scope::External);
        let zsa = build_zsa_builder(info, oaddress)?;
        builder.set_zsa_builder(zsa);
    }

    let r = builder.build_for_pczt(OsRng, &FeeRule::standard(), |_asset: &AssetBase| false)?;
    let sapling_meta = &r.sapling_meta;
    let ironwood_meta = &r.ironwood_meta;

    let pczt = Creator::build_from_parts(r.pczt_parts).unwrap();
    info!("Created");

    let mut asset_names = sqlx::query(
        "SELECT asset_base, asset_name FROM assets
         WHERE asset_name IS NOT NULL AND asset_name != ''",
    )
    .map(|row: SqliteRow| {
        let asset_base: Vec<u8> = row.get(0);
        let asset_name: String = row.get(1);
        (asset_base, asset_name)
    })
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .filter_map(|(asset_base, asset_name)| {
        asset_base
            .try_into()
            .ok()
            .map(|asset_base| (asset_base, asset_name))
    })
    .collect::<HashMap<[u8; 32], String>>();
    for recipient in &recipient_states {
        if let (Ok(asset_base), Some(asset_name)) = (
            recipient.asset_base.as_slice().try_into(),
            recipient.recipient.asset_name.as_ref(),
        ) {
            if !asset_name.is_empty() {
                asset_names.insert(asset_base, asset_name.clone());
            }
        }
    }

    let updater = Updater::new(pczt);
    let updater = updater
        .update_transparent_with(|mut u| {
            for (i, (pubkey, scope, dindex_t, taddress, uncompressed)) in
                tsk_dindex.into_iter().enumerate()
            {
                u.update_input_with(i, |mut u| {
                    let derivation_path = vec![scope, dindex_t];
                    let path = Bip32Derivation::parse([0u8; 32], derivation_path).unwrap();
                    u.set_bip32_derivation(pubkey.serialize(), path);
                    u.set_proprietary("scope".to_string(), scope.to_le_bytes().to_vec());
                    u.set_proprietary("dindex".to_string(), dindex_t.to_le_bytes().to_vec());
                    u.set_proprietary("address".to_string(), taddress.into_bytes());
                    u.set_proprietary("uncompressed".to_string(), vec![uncompressed as u8]);
                    let pk_bytes = if uncompressed {
                        pubkey.serialize_uncompressed().to_vec()
                    } else {
                        pubkey.serialize().to_vec()
                    };
                    u.set_hash160_preimage(pk_bytes);
                    Ok(())
                })?;
            }
            label_transparent_outputs(u, transparent_output_addresses, transparent_change_label)
        })
        .unwrap();

    let updater = updater
        .update_sapling_with(|mut u| {
            for (c_input, scope) in s_scope.iter().enumerate() {
                let bundle_index = sapling_meta.spend_index(c_input).unwrap();
                u.update_spend_with(bundle_index, |mut u| {
                    u.set_proprietary("scope".to_string(), scope.to_le_bytes().to_vec());
                    Ok(())
                })?;
            }
            Ok(())
        })
        .unwrap();

    let updater =
        if BranchId::for_height(network, BlockHeight::from_u32(target_height)) == BranchId::Nu7 {
            updater.update_orchard_zsa_with(|u| attach_orchard_asset_names(u, &asset_names))
        } else {
            updater.update_orchard_with(|u| attach_orchard_asset_names(u, &asset_names))
        }
        .map_err(|error| anyhow!("Failed to attach Orchard asset names: {error:?}"))?;

    let pczt = updater.finish();

    // Issuer phase 1: build the AwaitingSighash issue bundle
    let pczt = if let Some(info) = issuance {
        let oaddress = ovk
            .as_ref()
            .ok_or_else(|| anyhow!("No orchard key for issuance"))?
            .address_at(dindex, Scope::External);
        let zsa_builder = build_zsa_builder(info, oaddress)?;
        Issuer::new(pczt)
            .build_awaiting_sighash(zsa_builder, OsRng)
            .map_err(|e| anyhow!("Issuer (phase 1) failed: {e:?}"))?
    } else {
        pczt
    };

    let (pczt, shielded_sighash) = IoFinalizer::new(pczt).finalize_io().unwrap();
    info!("IO Finalized");

    // Issuer phase 2: sign the issue bundle
    let pczt = if let Some(info) = issuance {
        Issuer::new(pczt)
            .sign(&info.isk, shielded_sighash)
            .map_err(|e| anyhow!("Issuer (phase 2/sign) failed: {e:?}"))?
    } else {
        pczt
    };

    let orchard_indices = pczt
        .orchard()
        .actions()
        .iter()
        .enumerate()
        .filter_map(|(index, action)| action.spend().spend_auth_sig().is_none().then_some(index))
        .collect();
    let pczt_package = PcztPackage {
        pczt: pczt.serialize().unwrap(),
        n_spends: [n_spends[0], n_spends[1], n_spends[2], n_spends[3]],
        sapling_indices: (0..n_spends[1])
            .map(|n| sapling_meta.spend_index(n).unwrap())
            .collect(),
        orchard_indices,
        ironwood_indices: (0..n_spends[3])
            .map(|n| ironwood_meta.spend_action_index(n).unwrap())
            .collect(),
        can_sign,
        can_broadcast: false,
        price,
        category,
        is_issuance: issuance.is_some(),
    };

    Ok(pczt_package)
}
fn encode_memo(recipient: &Recipient) -> Result<Option<MemoBytes>> {
    let text_memo = recipient
        .user_memo
        .as_ref()
        .map(|s| Memo::from_str(s))
        .transpose()?
        .map(MemoBytes::from);
    let byte_memo = recipient
        .memo_bytes
        .as_ref()
        .map(|mb| MemoBytes::from_bytes(mb))
        .transpose()?;
    let memo = text_memo.or(byte_memo);
    Ok(memo)
}

/// zkool-only paths keep no spending key: this fork cannot sign there.
pub const NO_SPENDING_KEY: &[u8] = &[];

/// The transparent private key a [`SigningKey`] carries, or `None` if it has no transparent
/// component.
fn signing_key_transparent(key: &SigningKey) -> Option<&AccountPrivKey> {
    match key {
        SigningKey::Unified(usk) => Some(usk.transparent()),
        SigningKey::Transparent(tsk) => Some(tsk),
        SigningKey::Sapling(_) => None,
    }
}

/// The Sapling extended spending key a [`SigningKey`] carries, or `None` if it has no
/// Sapling component.
fn signing_key_sapling(key: &SigningKey) -> Option<&ExtendedSpendingKey> {
    match key {
        SigningKey::Unified(usk) => Some(usk.sapling()),
        SigningKey::Sapling(esk) => Some(esk),
        SigningKey::Transparent(_) => None,
    }
}

/// The Orchard spending key a [`SigningKey`] carries, or `None` if it has no Orchard
/// component. Only [`SigningKey::Unified`] does: there is no Orchard-only variant.
fn signing_key_orchard(key: &SigningKey) -> Option<&SpendingKey> {
    match key {
        SigningKey::Unified(usk) => Some(usk.orchard()),
        SigningKey::Transparent(_) | SigningKey::Sapling(_) => None,
    }
}

fn signing_key_transparent_pubkey(key: &SigningKey) -> Option<Vec<u8>> {
    signing_key_transparent(key).map(|tsk| tsk.to_account_pubkey().serialize().to_vec())
}

fn signing_key_sapling_dfvk(key: &SigningKey) -> Option<Vec<u8>> {
    signing_key_sapling(key).map(|esk| esk.to_diversifiable_full_viewing_key().to_bytes().to_vec())
}

fn signing_key_orchard_fvk(key: &SigningKey) -> Option<Vec<u8>> {
    signing_key_orchard(key).map(|osk| FullViewingKey::from(osk).to_bytes().to_vec())
}

/// [`signing_key_transparent`], failing with a message naming the missing pool.
fn require_transparent_key(key: &SigningKey) -> Result<&AccountPrivKey> {
    signing_key_transparent(key).ok_or_else(|| anyhow!("spending key has no transparent component"))
}

/// [`signing_key_sapling`], failing with a message naming the missing pool.
fn require_sapling_key(key: &SigningKey) -> Result<&ExtendedSpendingKey> {
    signing_key_sapling(key).ok_or_else(|| anyhow!("spending key has no sapling component"))
}

/// The Orchard spend-authorizing key a [`SigningKey`] can produce, failing with a message
/// naming `pool` (`orchard` or `ironwood`: both spend with the same key).
fn require_orchard_key(key: &SigningKey, pool: &str) -> Result<SpendAuthorizingKey> {
    signing_key_orchard(key)
        .map(SpendAuthorizingKey::from)
        .ok_or_else(|| anyhow!("spending key has no {pool} component"))
}

/// Reads a 4-byte little-endian `u32` from a PCZT `proprietary` map, naming `pool` and
/// `index` in the error if the field is missing or has the wrong length.
fn read_proprietary_u32(
    proprietary: &BTreeMap<String, Vec<u8>>,
    field: &str,
    pool: &str,
    index: usize,
) -> Result<u32> {
    let bytes = proprietary
        .get(field)
        .ok_or_else(|| anyhow!("{pool} spend {index} is missing the '{field}' field"))?;
    let bytes: [u8; 4] = bytes.clone().try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "{pool} spend {index} has a {}-byte '{field}' field, expected 4",
            bytes.len()
        )
    })?;
    Ok(u32::from_le_bytes(bytes))
}

/// The only guard against signing with a key that is not the account's own.
/// A provisioned pool whose `xvk` is NULL, differs, or has no matching component in `key`
/// is a mismatch, never a skipped pool.
async fn verify_spending_key(
    connection: &mut SqliteConnection,
    account: u32,
    key: &SigningKey,
) -> Result<()> {
    let derived = [
        ("transparent_accounts", signing_key_transparent_pubkey(key)),
        ("sapling_accounts", signing_key_sapling_dfvk(key)),
        ("orchard_accounts", signing_key_orchard_fvk(key)),
    ];

    let mut compared = 0;
    for (table, expected) in derived {
        let stored: Option<Option<Vec<u8>>> =
            sqlx::query_scalar(&format!("SELECT xvk FROM {table} WHERE account = ?"))
                .bind(account)
                .fetch_optional(&mut *connection)
                .await?;
        match stored {
            // the pool is not provisioned for this account
            None => continue,
            Some(Some(ref xvk)) if expected.as_deref() == Some(xvk.as_slice()) => compared += 1,
            _ => return Err(anyhow!("spending key does not match account {account}")),
        }
    }

    // Nothing compared means no viewing key to authenticate against: an unknown account, or
    // one whose pools were never provisioned.
    if compared == 0 {
        return Err(anyhow!(
            "account {account} has no viewing key to verify against"
        ));
    }

    Ok(())
}

pub async fn sign_transaction(
    connection: &mut SqliteConnection,
    account: u32,
    _network: &crate::api::coin::Network,
    pczt: &PcztPackage,
    usk_bytes: &[u8],
) -> Result<PcztPackage> {
    let span = span!(Level::INFO, "transaction");

    // Cheap check before the expensive PCZT parse.
    let key = SigningKey::decode(usk_bytes)
        .map_err(|error| anyhow!("failed to parse spending key: {error}"))?;
    verify_spending_key(connection, account, &key).await?;

    let PcztPackage {
        pczt,
        n_spends,
        sapling_indices,
        orchard_indices,
        ironwood_indices,
        price,
        category,
        is_issuance,
        ..
    } = pczt;
    let pczt = Pczt::parse(pczt)
        .map_err(|error| anyhow!("failed to parse PCZT for signing: {error:?}"))?;
    let orchard_pk = get_orchard_pk(*pczt.global().consensus_branch_id())?;

    // Bounds-check every sapling spend and read its scope before `pczt` is consumed by the
    // updater: `update_sapling_with`'s closure can only return the pczt crate's own error
    // type, not `anyhow::Error`, so out-of-range indices must be rejected here.
    let sapling_bundle_len = pczt.sapling().spends().len();
    let mut sapling_scopes = Vec::with_capacity(sapling_indices.len());
    for bundle_index in sapling_indices {
        let spend = pczt.sapling().spends().get(*bundle_index).ok_or_else(|| {
            anyhow!(
                "sapling spend index {bundle_index} is out of bounds for a bundle with {sapling_bundle_len} spends"
            )
        })?;
        let scope = read_proprietary_u32(spend.proprietary(), "scope", "sapling", *bundle_index)?;
        sapling_scopes.push((*bundle_index, scope));
    }

    let updater = Updater::new(pczt);
    let updater = if sapling_scopes.is_empty() {
        updater
    } else {
        let esk = require_sapling_key(&key)?;
        let pgk = esk.expsk.proof_generation_key();
        let internal_pgk = esk.derive_internal().expsk.proof_generation_key();
        updater
            .update_sapling_with(|mut u| {
                for (bundle_index, scope) in &sapling_scopes {
                    u.update_spend_with(*bundle_index, |mut u| {
                        u.set_proof_generation_key(sapling_pgk_for_scope(
                            *scope,
                            pgk.clone(),
                            internal_pgk.clone(),
                        ))
                    })?;
                }
                Ok(())
            })
            .map_err(|error| anyhow!("failed to update sapling bundle: {error:?}"))?
    };
    let pczt = updater.finish();
    info!("Updated");

    let mut signer = Signer::new(pczt.clone()).unwrap();
    let tbundle = pczt.transparent();

    let transparent_inputs_len = tbundle.inputs().len();
    if n_spends[0] > transparent_inputs_len {
        return Err(anyhow!(
            "transparent spend count {} exceeds the bundle's {transparent_inputs_len} inputs",
            n_spends[0]
        ));
    }
    for index in 0..n_spends[0] {
        info!("signing transparent {index}");
        let inp = &tbundle.inputs()[index];
        let scope = read_proprietary_u32(inp.proprietary(), "scope", "transparent", index)?;
        if scope > 1 {
            return Err(anyhow!(
                "transparent input {index} has an unknown scope {scope}, expected 0 or 1"
            ));
        }
        let dindex = read_proprietary_u32(inp.proprietary(), "dindex", "transparent", index)?;
        if dindex >= (1 << 31) {
            return Err(anyhow!(
                "transparent input {index} has a hardened dindex {dindex}, cannot derive a non-hardened key"
            ));
        }
        // Check if "uncompressed" flag exists in proprietary, default to false (compressed)
        let uncompressed_flag = if let Some(val) = inp.proprietary().get("uncompressed") {
            if !val.is_empty() {
                val[0] != 0
            } else {
                info!(
                    "Invalid uncompressed flag length: {}, defaulting to compressed",
                    val.len()
                );
                false
            }
        } else {
            info!("No 'uncompressed' proprietary field found, defaulting to compressed");
            false
        };
        info!(
            "Signing transparent input {}: scope={}, dindex={}, uncompressed={}",
            index, scope, dindex, uncompressed_flag
        );

        // Get the signing key from the derivation path
        let tsk = require_transparent_key(&key)?;
        let sk = derive_transparent_sk(tsk, scope, dindex)?;
        let sk: [u8; 32] = sk.try_into().map_err(|sk: Vec<u8>| {
            anyhow!(
                "transparent input {index} derived a {}-byte key, expected 32",
                sk.len()
            )
        })?;
        let sk = SecretKey::from_bytes(&sk).map_err(|_| Error::NoSigningKey)?;

        // Derive pubkey from secret key to check
        let secp = secp256k1::Secp256k1::new();
        let derived_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let derived_compressed = derived_pubkey.serialize();
        let derived_uncompressed = derived_pubkey.serialize_uncompressed();
        let hash_compressed = zcash_transparent::util::hash160::hash(&derived_compressed);
        let hash_uncompressed = zcash_transparent::util::hash160::hash(&derived_uncompressed);
        info!(
            "Derived pubkey (compressed): hash={}, len={}",
            hex::encode(hash_compressed),
            derived_compressed.len()
        );
        info!(
            "Derived pubkey (uncompressed): hash={}, len={}",
            hex::encode(hash_uncompressed),
            65
        );

        // Get the sighash and sign manually
        let sighash = signer.transparent_sighash(index).map_err(|e| {
            anyhow!("failed to compute sighash for transparent input {index}: {e:?}")
        })?;
        let msg = secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, &sk);

        // Append the signature - the pubkey will be retrieved from hash160_preimages
        info!("Appending signature for input {}", index);
        signer
            .append_transparent_signature(index, sig)
            .map_err(|e| {
                anyhow!("failed to append signature for transparent input {index}: {e:?}")
            })?;
    }
    for (index, (bundle_index, scope)) in sapling_scopes.iter().enumerate() {
        info!("signing sapling {index}");
        let esk = require_sapling_key(&key)?;
        let ssk = sapling_ssk_for_scope(*scope, esk);
        signer
            .sign_sapling(*bundle_index, &ssk.expsk.ask)
            .map_err(|e| {
                anyhow!(
                    "failed to sign sapling spend {bundle_index} (selected spend {index}): {e:?}"
                )
            })?;
    }
    for (index, bundle_index) in orchard_indices.iter().enumerate() {
        info!("signing orchard {index}");
        let osak = require_orchard_key(&key, "orchard")?;
        signer.sign_orchard(*bundle_index, &osak).map_err(|e| {
            anyhow!("failed to sign Orchard action {bundle_index} (selected spend {index}): {e:?}")
        })?;
    }
    for (index, bundle_index) in ironwood_indices.iter().enumerate() {
        info!("signing ironwood {index}");
        let osak = require_orchard_key(&key, "ironwood")?;
        signer.sign_ironwood(*bundle_index, &osak).map_err(|e| {
            anyhow!("failed to sign Ironwood action {bundle_index} (selected spend {index}): {e:?}")
        })?;
    }
    let pczt = signer.finish();

    span.in_scope(|| {
        info!("Adding Proofs to PCZT");
    });
    let prover = Prover::new(pczt);
    let prover = if prover.requires_sapling_proofs() {
        let sapling_prover = get_sapling_prover().await?;
        prover
            .create_sapling_proofs(sapling_prover, sapling_prover)
            .map_err(|error| anyhow!("failed to create Sapling proofs: {error:?}"))?
    } else {
        prover
    };

    let pczt = prover
        .create_orchard_proof(orchard_pk)
        .map_err(|error| anyhow!("failed to create Orchard proof: {error:?}"))?
        .create_ironwood_proof(&IRONWOOD_PK)
        .map_err(|error| anyhow!("failed to create Ironwood proof: {error:?}"))?
        .finish();
    info!("Proved");

    let pczt = SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(|error| anyhow!("failed to finalize PCZT spends: {error:?}"))?;
    info!("Spend Finalized");

    Ok(PcztPackage {
        pczt: pczt
            .serialize()
            .map_err(|error| anyhow!("failed to serialize signed PCZT: {error:?}"))?,
        n_spends: *n_spends,
        sapling_indices: sapling_indices.clone(),
        orchard_indices: orchard_indices.clone(),
        ironwood_indices: ironwood_indices.clone(),
        can_sign: true,
        can_broadcast: true,
        price: *price,
        category: *category,
        is_issuance: *is_issuance,
    })
}

pub async fn extract_transaction(package: &PcztPackage) -> Result<Vec<u8>> {
    let span = span!(Level::INFO, "transaction");
    span.in_scope(|| {
        info!("Extracting Tx");
    });

    let pczt =
        Pczt::parse(&package.pczt).map_err(|error| anyhow!("failed to parse PCZT: {error:?}"))?;

    let needs_sapling = !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty();
    let keys = if needs_sapling {
        Some(get_sapling_prover().await?.verifying_keys())
    } else {
        None
    };
    let mut tx_extractor = TransactionExtractor::new(pczt);
    if let Some((svk, ovk)) = &keys {
        tx_extractor = tx_extractor.with_sapling(svk, ovk);
    }
    match tx_extractor.extract() {
        Ok(tx) => {
            if let Some(bundle) = tx.sapling_bundle() {
                let vb: i64 = (*bundle.value_balance()).into();
                info!(
                    "Sapling verify OK: spends={} outputs={} valueBalance={}",
                    bundle.shielded_spends().len(),
                    bundle.shielded_outputs().len(),
                    vb
                );
            }
            let mut tx_bytes = vec![];
            tx.write(&mut tx_bytes).unwrap();
            info!("Tx Extracted");
            span.in_scope(|| {
                info!("TX HEX: {}", hex::encode(&tx_bytes));
                info!("Tx Ready - {} bytes", tx_bytes.len());
            });
            return Ok(tx_bytes);
        }
        Err(e) => {
            info!("Extraction failed: {:?}", e);
            return Err(anyhow!("Extraction failed: {:?}", e));
        }
    }
}

/// The txid of a fully signed transaction, in the display order explorers use.
///
/// A v5 transaction carries its own consensus branch id, so the one passed to the parser is
/// only a fallback for older versions - hence the walk from the newest branch down.
pub fn transaction_id(raw: &[u8]) -> Result<String> {
    let parsed = crate::pay::reserve::parse_transaction(raw)?;
    let mut display = parsed.txid;
    display.reverse();
    Ok(hex::encode(display))
}

struct MyTransparentAddress(TransparentAddress);
impl TryFromAddress for MyTransparentAddress {
    type Error = ();

    fn try_from_unified(
        _net: NetworkType,
        data: zcash_address::unified::Address,
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        let ua = UnifiedAddress::try_from(data).unwrap();
        ua.transparent()
            .map(|v| MyTransparentAddress(*v))
            .ok_or(ConversionError::User(()))
    }

    fn try_from_transparent_p2pkh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(MyTransparentAddress(TransparentAddress::PublicKeyHash(
            data,
        )))
    }

    fn try_from_tex(
        _net: NetworkType,
        data: [u8; 20],
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(MyTransparentAddress(TransparentAddress::PublicKeyHash(
            data,
        )))
    }

    fn try_from_transparent_p2sh(
        _net: NetworkType,
        data: [u8; 20],
    ) -> std::result::Result<Self, ConversionError<Self::Error>> {
        Ok(MyTransparentAddress(TransparentAddress::ScriptHash(data)))
    }
}

fn get_transparent_address(network: &Network, address: &str) -> Result<TransparentAddress> {
    let addr = ZcashAddress::try_from_encoded(address)?;
    if addr.can_receive_as(zcash_protocol::PoolType::Transparent) {
        let taddr: MyTransparentAddress = addr.convert_if_network(network.network_type()).unwrap();
        return Ok(taddr.0);
    }
    anyhow::bail!("Invalid transparent address: {address}");
}

fn get_sapling_address(network: &Network, address: &str) -> Result<PaymentAddress> {
    if let Ok(addr) = PaymentAddress::decode(network, address) {
        return Ok(addr);
    }
    if let Ok(addr) = UnifiedAddress::decode(network, address) {
        let addr = addr.sapling().unwrap();
        Ok(*addr)
    } else {
        anyhow::bail!("Invalid sapling address: {address}");
    }
}

fn get_orchard_address(network: &Network, address: &str) -> Result<Address> {
    if let Ok(addr) = UnifiedAddress::decode(network, address) {
        let addr = addr.orchard().unwrap();
        Ok(*addr)
    } else {
        anyhow::bail!("Invalid orchard address: {address}");
    }
}

pub async fn fetch_unspent_notes_grouped_by_pool(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Vec<InputNote>> {
    let mut unspent_notes = fetch_unspent_notes(connection, account).await?;
    unspent_notes.sort_by_key(|note| note.pool);
    Ok(unspent_notes)
}

async fn fetch_unspent_notes(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Vec<InputNote>> {
    sqlx::query(
        "SELECT a.id_note, a.height, a.pool, a.value, a.id_asset, a.taddress,
                COALESCE(ast.asset_base, X'0000000000000000000000000000000000000000000000000000000000000000') as asset_base
        FROM notes a
        LEFT JOIN spends b ON a.id_note = b.id_note
        LEFT JOIN assets ast ON a.id_asset = ast.id_asset
        LEFT JOIN active_pending_spend_inputs p
            ON p.account = a.account
            AND p.nullifier = a.nullifier
        WHERE b.id_note IS NULL AND a.account = ?1
        AND locked = 0
        AND p.nullifier IS NULL",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let id_note: u32 = row.get(0);
        let height: u32 = row.get(1);
        let pool: u8 = row.get(2);
        let value: i64 = row.get(3);
        let id_asset: Option<i64> = row.get(4);
        let taddress: Option<i64> = row.get(5);
        let asset_base: Vec<u8> = row.get(6);
        InputNote {
            id: id_note,
            height,
            amount: value as u64,
            remaining: value as u64,
            pool,
            id_asset: id_asset.map(|v| v as u32),
            asset_base,
            taddress: taddress.map(|v| v as u32),
        }
    })
    .fetch_all(connection)
    .await
    .map_err(Into::into)
}

pub async fn fetch_unspent_notes_by_pool(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Vec<Vec<InputNote>>> {
    let unspent_notes = fetch_unspent_notes(connection, account).await?;

    let mut result: Vec<Vec<InputNote>> = vec![vec![]; NUM_POOLS as usize];
    for note in unspent_notes {
        let pool = note.pool as usize;
        anyhow::ensure!(pool < NUM_POOLS, "unexpected pool {pool}");
        result[pool].push(note);
    }
    Ok(result)
}

pub async fn get_sapling_prover() -> Result<&'static LocalTxProver> {
    static PROVER: tokio::sync::OnceCell<LocalTxProver> = tokio::sync::OnceCell::const_new();
    PROVER
        .get_or_try_init(|| async {
            #[cfg(feature = "bundled-sapling-params")]
            {
                // Parameters compiled into the binary — never touch disk or network.
                return Ok(LocalTxProver::bundled());
            }
            #[cfg(not(feature = "bundled-sapling-params"))]
            {
                let (spend_path, output_path) =
                    crate::api::sapling::ensure_sapling_params().await?;
                Ok(LocalTxProver::new(&spend_path, &output_path))
            }
        })
        .await
}
pub static ORCHARD_VANILLA_PK: LazyLock<ProvingKey> =
    LazyLock::new(|| ProvingKey::build(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2));
pub static ORCHARD_ZSA_PK: LazyLock<ProvingKey> = LazyLock::new(|| ProvingKey::build_zsa());
pub static IRONWOOD_PK: LazyLock<ProvingKey> =
    LazyLock::new(|| ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrchardProvingKeyKind {
    Vanilla,
    Zsa,
    Ironwood,
}

fn orchard_proving_key_kind(branch_id: BranchId) -> OrchardProvingKeyKind {
    match branch_id {
        BranchId::Nu7 => OrchardProvingKeyKind::Zsa,
        BranchId::Nu6_3 => OrchardProvingKeyKind::Ironwood,
        _ => OrchardProvingKeyKind::Vanilla,
    }
}

/// Whether the transaction must be forced to v5 (ZIP-244): either the account is
/// itself hardware-bound (`hw != 0`), or this specific plan is being prepared for an
/// external hardware signer that only understands v5.
fn wants_hardware_v5(hw: u8, hardware_signing: bool) -> bool {
    hw != 0 || hardware_signing
}

/// The change output's own derivation path, so an external signer can recognise the
/// output as its own change rather than a payment to a third party.
struct TransparentChangeLabel {
    pubkey: PublicKey,
    scope: u32,
    dindex: u32,
    address: String,
}

async fn load_transparent_change_label(
    connection: &mut SqliteConnection,
    account: u32,
    address: &str,
) -> Result<TransparentChangeLabel> {
    let row = sqlx::query(
        "SELECT pk, scope, dindex FROM transparent_address_accounts WHERE account = ?1 AND address = ?2",
    )
    .bind(account)
    .bind(address)
    .fetch_one(&mut *connection)
    .await?;
    let pk: Vec<u8> = row.get(0);
    Ok(TransparentChangeLabel {
        pubkey: PublicKey::from_slice(&pk)
            .map_err(|e| anyhow!("invalid change address pubkey: {e}"))?,
        scope: row.get(1),
        dindex: row.get(2),
        address: address.to_string(),
    })
}

/// Labels a planned transparent bundle's outputs for an external signer: each recipient
/// output gets the user-facing address it pays, and the change output (if any) gets its
/// own BIP-32 derivation so the signer can recognise it as change rather than a payment.
fn label_transparent_outputs(
    mut u: zcash_transparent::pczt::Updater<'_>,
    recipient_addresses: Vec<String>,
    change: Option<TransparentChangeLabel>,
) -> std::result::Result<(), zcash_transparent::pczt::UpdaterError> {
    let change_index = recipient_addresses.len();
    for (index, address) in recipient_addresses.into_iter().enumerate() {
        u.update_output_with(index, |mut u| {
            u.set_user_address(address);
            Ok(())
        })?;
    }
    if let Some(TransparentChangeLabel {
        pubkey,
        scope,
        dindex,
        address,
    }) = change
    {
        u.update_output_with(change_index, |mut u| {
            let path = Bip32Derivation::parse([0u8; 32], vec![scope, dindex]).unwrap();
            u.set_bip32_derivation(pubkey.serialize(), path);
            u.set_proprietary("scope".to_string(), scope.to_le_bytes().to_vec());
            u.set_proprietary("dindex".to_string(), dindex.to_le_bytes().to_vec());
            u.set_proprietary("address".to_string(), address.into_bytes());
            Ok(())
        })?;
    }
    Ok(())
}

/// JSON payload describing everything an external signer (e.g. Trezor) needs to review
/// and sign a planned transparent bundle. Built from a planner PCZT before any signing.
#[derive(Serialize, Deserialize)]
pub struct TransparentSigningRequest {
    pub tx_version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    pub expiry_height: u32,
    pub lock_time: u32,
    pub shielded: ShieldedCounts,
    pub inputs: Vec<TransparentSigningInput>,
    pub outputs: Vec<TransparentSigningOutput>,
}

/// Counts of shielded components, so a caller can refuse a bundle the device cannot sign.
#[derive(Serialize, Deserialize)]
pub struct ShieldedCounts {
    pub sapling_spends: usize,
    pub sapling_outputs: usize,
    pub orchard_actions: usize,
}

#[derive(Serialize, Deserialize)]
pub struct TransparentSigningInput {
    pub index: usize,
    /// Hex in display (block-explorer) order — the reverse of the txid's internal bytes.
    pub prev_txid: String,
    pub prev_index: u32,
    pub value: u64,
    /// The effective sequence: the PCZT leaves this `None` for every planner-built input,
    /// which the extractor treats as `0xffff_ffff`, never as `0`.
    pub sequence: u32,
    pub scope: u32,
    pub dindex: u32,
    pub script_pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransparentSigningOutput {
    pub index: usize,
    pub value: u64,
    pub address: String,
    pub is_change: bool,
    pub scope: Option<u32>,
    pub dindex: Option<u32>,
}

/// Like [`read_proprietary_u32`], but the field is optional (e.g. an output's `scope`,
/// which is only present on a change output).
fn read_proprietary_u32_opt(
    proprietary: &BTreeMap<String, Vec<u8>>,
    field: &str,
    pool: &str,
    index: usize,
) -> Result<Option<u32>> {
    if proprietary.contains_key(field) {
        read_proprietary_u32(proprietary, field, pool, index).map(Some)
    } else {
        Ok(None)
    }
}

/// Resolves a transparent output's address: the label the planner wrote for a recipient,
/// or the address recovered from `script_pubkey` for a change output. The app never reads
/// a change output's address here (Phase 4 derives it on the device), so the fallback
/// exists for diagnostics and non-app callers, not as a correctness dependency.
fn transparent_output_address(
    network: &Network,
    output: &pczt::transparent::Output,
) -> Result<String> {
    if let Some(address) = output.user_address() {
        return Ok(address.clone());
    }
    let pubkey = script::PubKey::parse(&script::Code(output.script_pubkey().clone()))
        .map_err(|error| anyhow!("failed to parse output script_pubkey: {error:?}"))?;
    let address = TransparentAddress::from_script_pubkey(&pubkey)
        .ok_or_else(|| anyhow!("output script_pubkey is not a standard transparent address"))?;
    Ok(address.encode(network))
}

/// Builds the request an external signer reviews before producing transparent signatures.
/// `network` matters because a fallback output address is re-encoded from
/// `script_pubkey`, and the PCZT's consensus branch id does not distinguish networks.
pub fn transparent_signing_request(
    network: &Network,
    package: &PcztPackage,
) -> Result<TransparentSigningRequest> {
    let pczt =
        Pczt::parse(&package.pczt).map_err(|error| anyhow!("failed to parse PCZT: {error:?}"))?;
    let global = pczt.global();
    let tbundle = pczt.transparent();

    let lock_time = determine_lock_time(global, tbundle.inputs())
        .ok_or_else(|| anyhow!("transparent inputs do not agree on a lock time"))?;

    let inputs = tbundle
        .inputs()
        .iter()
        .enumerate()
        .map(|(index, input)| {
            Ok(TransparentSigningInput {
                index,
                prev_txid: TxId::from_bytes(*input.prevout_txid()).to_string(),
                prev_index: *input.prevout_index(),
                value: *input.value(),
                sequence: input.sequence().unwrap_or(0xffff_ffff),
                scope: read_proprietary_u32(input.proprietary(), "scope", "transparent", index)?,
                dindex: read_proprietary_u32(input.proprietary(), "dindex", "transparent", index)?,
                script_pubkey: hex::encode(input.script_pubkey()),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let outputs = tbundle
        .outputs()
        .iter()
        .enumerate()
        .map(|(index, output)| {
            let scope =
                read_proprietary_u32_opt(output.proprietary(), "scope", "transparent", index)?;
            let dindex =
                read_proprietary_u32_opt(output.proprietary(), "dindex", "transparent", index)?;
            Ok(TransparentSigningOutput {
                index,
                value: *output.value(),
                address: transparent_output_address(network, output)?,
                is_change: scope.is_some(),
                scope,
                dindex,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(TransparentSigningRequest {
        tx_version: *global.tx_version(),
        version_group_id: *global.version_group_id(),
        consensus_branch_id: *global.consensus_branch_id(),
        expiry_height: *global.expiry_height(),
        lock_time,
        shielded: ShieldedCounts {
            sapling_spends: pczt.sapling().spends().len(),
            sapling_outputs: pczt.sapling().outputs().len(),
            orchard_actions: pczt.orchard().actions().len(),
        },
        inputs,
        outputs,
    })
}

/// Applies device-produced ECDSA signatures to every transparent input of a planned PCZT
/// and finalizes it. `indices`/`sigs` are parallel arrays; on success the returned package
/// has `can_broadcast = true`, matching what local signing already produces.
pub fn apply_transparent_signatures(
    package: &PcztPackage,
    indices: &[u32],
    sigs: &[Vec<u8>],
) -> Result<PcztPackage> {
    if indices.len() != sigs.len() {
        return Err(anyhow!(
            "indices and signatures have different lengths: {} vs {}",
            indices.len(),
            sigs.len()
        ));
    }

    let expected = package.n_spends[0];
    let mut seen = vec![false; expected];
    for &index in indices {
        let index = index as usize;
        if index >= expected {
            return Err(anyhow!(
                "transparent input index {index} is out of range: only {expected} transparent input(s)"
            ));
        }
        if seen[index] {
            return Err(anyhow!("duplicate signature for transparent input {index}"));
        }
        seen[index] = true;
    }
    if let Some(index) = seen.iter().position(|signed| !signed) {
        return Err(anyhow!("missing a signature for transparent input {index}"));
    }

    let signatures = indices
        .iter()
        .zip(sigs.iter())
        .map(|(&index, sig)| {
            let signature = secp256k1::ecdsa::Signature::from_der(sig).map_err(|error| {
                anyhow!("signature for transparent input {index} is not valid DER: {error}")
            })?;
            Ok((index as usize, signature))
        })
        .collect::<Result<Vec<_>>>()?;

    let pczt =
        Pczt::parse(&package.pczt).map_err(|error| anyhow!("failed to parse PCZT: {error:?}"))?;
    let mut signer =
        Signer::new(pczt).map_err(|error| anyhow!("failed to start signing session: {error:?}"))?;
    for (index, signature) in signatures {
        signer
            .append_transparent_signature(index, signature)
            .map_err(|error| match error {
                pczt::roles::signer::Error::InvalidIndex => {
                    anyhow!("transparent input index {index} is out of range")
                }
                pczt::roles::signer::Error::TransparentSign(error) => anyhow!(
                    "signature for transparent input {index} failed sighash verification: {error:?}"
                ),
                other => {
                    anyhow!("failed to apply signature for transparent input {index}: {other:?}")
                }
            })?;
    }

    let pczt = signer.finish();
    let pczt = SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(|error| anyhow!("failed to finalize PCZT spends: {error:?}"))?;

    Ok(PcztPackage {
        pczt: pczt
            .serialize()
            .map_err(|error| anyhow!("failed to serialize signed PCZT: {error:?}"))?,
        n_spends: package.n_spends,
        sapling_indices: package.sapling_indices.clone(),
        orchard_indices: package.orchard_indices.clone(),
        ironwood_indices: package.ironwood_indices.clone(),
        can_sign: package.can_sign,
        can_broadcast: true,
        price: package.price,
        category: package.category,
        is_issuance: package.is_issuance,
    })
}

pub(crate) fn get_orchard_pk(consensus_branch_id: u32) -> Result<&'static ProvingKey> {
    // ZSA and Ironwood are mutually exclusive hard forks with different
    // V6 version group IDs and circuit versions.
    let branch_id = BranchId::try_from(consensus_branch_id)
        .map_err(|_| anyhow!("unsupported consensus branch ID: {consensus_branch_id:#x}"))?;
    Ok(match orchard_proving_key_kind(branch_id) {
        OrchardProvingKeyKind::Vanilla => &ORCHARD_VANILLA_PK,
        OrchardProvingKeyKind::Zsa => &ORCHARD_ZSA_PK,
        OrchardProvingKeyKind::Ironwood => &IRONWOOD_PK,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        account_can_sign, apply_transparent_signatures, determine_lock_time, extract_transaction,
        require_orchard_key, require_sapling_key, require_transparent_key, sign_transaction,
        transparent_signing_request, verify_spending_key, Pczt, PcztPackage, NO_SPENDING_KEY,
    };
    use super::{
        get_transparent_address, label_transparent_outputs, orchard_proving_key_kind,
        wants_hardware_v5, BranchId, Creator, OrchardProvingKeyKind, Signer,
        TransparentChangeLabel,
    };
    use super::{
        AssetBase, BlockHeight, BuildConfig, Builder, BundlePadding, FeeRule, IoFinalizer,
        OutPoint, SpendInfo, TransparentAddress, TransparentInputInfo, TxOut, TxVersion, Updater,
        Zatoshis,
    };
    use crate::account::tests::{restore, test_usk, watch_only_keys, TEST_PHRASE};
    use crate::account::{derive_spending_key, derive_transparent_sk};
    use crate::api::coin::Network;
    use crate::db::tests::memory_db;
    use crate::keys::SaplingFullViewingKey as _;
    use crate::pay::signing_key::{self, SigningKey};
    use bip32::{ExtendedPrivateKey, Prefix};
    use incrementalmerkletree::{Hashable, Level, Position};
    use pczt::roles::verifier::{TransparentError, Verifier};
    use ripemd::Ripemd160;
    use sapling_crypto::{
        value::NoteValue, Anchor, MerklePath, Node, Note, Rseed, NOTE_COMMITMENT_TREE_DEPTH,
    };
    use secp256k1::{PublicKey, SecretKey};
    use sha2::{Digest as _, Sha256};
    use std::convert::Infallible;
    use std::str::FromStr as _;
    use zcash_keys::encoding::encode_extended_spending_key;
    use zcash_keys::encoding::AddressCodec as _;
    use zcash_keys::keys::{sapling::ExtendedSpendingKey, Era, UnifiedSpendingKey};
    use zcash_protocol::consensus::NetworkConstants as _;
    use zcash_transparent::{keys::AccountPrivKey, pczt::Bip32Derivation};

    /// A second seed, built from entropy rather than a literal so it cannot rot.
    fn other_phrase() -> String {
        bip39::Mnemonic::from_entropy(&[1u8; 32])
            .expect("entropy")
            .to_string()
    }

    /// The encoded transparent-only envelope for `phrase`'s account 0 (as `sign_transaction`
    /// receives it: raw bytes, not a decoded [`SigningKey`]).
    fn transparent_key_bytes_of(phrase: &str) -> Vec<u8> {
        let seed = bip39::Mnemonic::from_str(phrase)
            .expect("phrase")
            .to_seed("");
        let xprv = ExtendedPrivateKey::<SecretKey>::new(seed)
            .expect("xprv")
            .to_string(Prefix::XPRV)
            .to_string();
        signing_key::encode_transparent(&xprv).expect("encode")
    }

    /// The account's transparent-only component, as a genuinely partial [`SigningKey`]
    /// (not a [`SigningKey::Unified`] wrapping every pool).
    fn transparent_key_of(phrase: &str) -> SigningKey {
        SigningKey::decode(&transparent_key_bytes_of(phrase)).expect("decode")
    }

    /// The encoded sapling-only envelope for `phrase`'s account `aindex`.
    fn sapling_key_bytes_of(phrase: &str, aindex: u32) -> Vec<u8> {
        let usk = usk_of(phrase, aindex);
        let esk = encode_extended_spending_key(
            Network::Main.hrp_sapling_extended_spending_key(),
            usk.sapling(),
        );
        signing_key::encode_sapling(&esk, &Network::Main).expect("encode")
    }

    /// The account's sapling-only component, as a genuinely partial [`SigningKey`].
    fn sapling_key_of(phrase: &str, aindex: u32) -> SigningKey {
        SigningKey::decode(&sapling_key_bytes_of(phrase, aindex)).expect("decode")
    }

    /// A structurally valid, empty PCZT (no spends, outputs, or actions in any pool) for
    /// `BranchId::Nu5`, built entirely offline via the `Creator` role.
    fn empty_pczt_bytes() -> Vec<u8> {
        Creator::new(u32::from(BranchId::Nu5), 100, 133, None, None)
            .expect("creator")
            .build()
            .expect("build")
            .serialize()
            .expect("serialize")
    }

    /// The account-level transparent key `sign_transaction` sees for `TEST_PHRASE`'s
    /// account when it is `restore`d from a raw `tprv`: `new_account` stores this exact
    /// `AccountPrivKey`'s pubkey as `transparent_accounts.xvk`, matching `watch_only_keys`'s
    /// own "tprv" fixture in `account.rs`.
    fn transparent_only_tprv() -> String {
        let seed = bip39::Mnemonic::from_str(TEST_PHRASE)
            .expect("phrase")
            .to_seed("");
        ExtendedPrivateKey::<SecretKey>::new(seed)
            .expect("xprv")
            .to_string(Prefix::XPRV)
            .to_string()
    }

    /// The bytes a well-formed `u32` proprietary field carries.
    fn le_bytes(value: u32) -> Option<Vec<u8>> {
        Some(value.to_le_bytes().to_vec())
    }

    /// A structurally valid PCZT with a single transparent input at `(scope, dindex)`,
    /// spendable by `tsk`, and no other pool activity. The input's value equals ZIP-317's
    /// grace-action fee, so the transaction balances with zero outputs.
    ///
    /// `scope_field` and `dindex_field` are the raw bytes written to those proprietary fields
    /// (`None` omits the field), kept separate from the `scope`/`dindex` the key is derived at
    /// so tests can plant values - wrong-valued or wrong-length - that derivation never
    /// produces. `set_hash160_preimage` controls that field.
    fn transparent_pczt_bytes_custom(
        tsk: &AccountPrivKey,
        scope: u32,
        dindex: u32,
        scope_field: Option<Vec<u8>>,
        dindex_field: Option<Vec<u8>>,
        set_hash160_preimage: bool,
    ) -> Vec<u8> {
        let sk_bytes = derive_transparent_sk(tsk, scope, dindex).expect("derive sk");
        let sk = SecretKey::from_slice(&sk_bytes).expect("secret key");
        let pubkey = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);

        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(
            &Network::Main,
            BlockHeight::from_u32(1_700_000),
            build_config,
        );

        let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(pubkey.serialize())).into();
        let addr = TransparentAddress::PublicKeyHash(pkh);
        // 20,000 in, 10,000 out, 10,000 ZIP-317 grace-action fee: balances to zero.
        let coin = TxOut::new(Zatoshis::const_from_u64(20_000), addr.script().into());
        let utxo = OutPoint::new([7u8; 32], 0);
        builder.add_transparent_input(
            TransparentInputInfo::from_parts(utxo, coin, SpendInfo::P2pkh { pubkey })
                .expect("input"),
        );
        builder
            .add_transparent_output(&addr, Zatoshis::const_from_u64(10_000))
            .expect("output");

        let r = builder
            .build_for_pczt(
                rand_core::OsRng,
                &FeeRule::standard(),
                |_asset: &AssetBase| false,
            )
            .expect("build_for_pczt");
        let pczt = Creator::build_from_parts(r.pczt_parts).expect("creator");

        let pczt = Updater::new(pczt)
            .update_transparent_with(|mut u| {
                u.update_input_with(0, |mut u| {
                    let path = Bip32Derivation::parse([0u8; 32], vec![scope, dindex])
                        .expect("derivation path");
                    u.set_bip32_derivation(pubkey.serialize(), path);
                    if let Some(bytes) = scope_field.clone() {
                        u.set_proprietary("scope".to_string(), bytes);
                    }
                    if let Some(bytes) = dindex_field.clone() {
                        u.set_proprietary("dindex".to_string(), bytes);
                    }
                    u.set_proprietary("address".to_string(), b"t1fixture".to_vec());
                    u.set_proprietary("uncompressed".to_string(), vec![0u8]);
                    if set_hash160_preimage {
                        u.set_hash160_preimage(pubkey.serialize().to_vec());
                    }
                    Ok(())
                })?;
                Ok(())
            })
            .expect("update transparent")
            .finish();

        let (pczt, _sighash) = IoFinalizer::new(pczt).finalize_io().expect("finalize_io");
        pczt.serialize().expect("serialize")
    }

    fn transparent_pczt_bytes(tsk: &AccountPrivKey, scope: u32, dindex: u32) -> Vec<u8> {
        transparent_pczt_bytes_custom(tsk, scope, dindex, le_bytes(scope), le_bytes(dindex), true)
    }

    /// Deliberately asymmetric: a palindromic txid would let a byte-order assertion pass
    /// under both internal and display order.
    const FIXTURE_PREVOUT_TXID: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    /// A structurally valid transparent-only PCZT with one input (spendable by `tsk` at
    /// `(scope, dindex)`), one recipient output paying `recipient_address`, and one change
    /// output back to `tsk` at `(change_scope, change_dindex)` — built and labeled through
    /// the exact same `Builder`/`label_transparent_outputs` pipeline `plan_transaction` uses.
    fn labeled_transparent_pczt_bytes(
        tsk: &AccountPrivKey,
        scope: u32,
        dindex: u32,
        recipient_address: &str,
        change_scope: u32,
        change_dindex: u32,
    ) -> Vec<u8> {
        let sk_bytes = derive_transparent_sk(tsk, scope, dindex).expect("derive sk");
        let sk = SecretKey::from_slice(&sk_bytes).expect("secret key");
        let pubkey = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);

        let change_sk_bytes =
            derive_transparent_sk(tsk, change_scope, change_dindex).expect("derive change sk");
        let change_sk = SecretKey::from_slice(&change_sk_bytes).expect("change secret key");
        let change_pubkey = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &change_sk);

        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(
            &Network::Main,
            BlockHeight::from_u32(1_700_000),
            build_config,
        );

        let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(pubkey.serialize())).into();
        let addr = TransparentAddress::PublicKeyHash(pkh);
        // 30,000 in, 10,000 to the recipient, 10,000 change, 10,000 ZIP-317 grace-action fee.
        let coin = TxOut::new(Zatoshis::const_from_u64(30_000), addr.script().into());
        let utxo = OutPoint::new(FIXTURE_PREVOUT_TXID, 0);
        builder.add_transparent_input(
            TransparentInputInfo::from_parts(utxo, coin, SpendInfo::P2pkh { pubkey })
                .expect("input"),
        );

        let recipient_addr =
            get_transparent_address(&Network::Main, recipient_address).expect("recipient address");
        builder
            .add_transparent_output(&recipient_addr, Zatoshis::const_from_u64(10_000))
            .expect("recipient output");

        let change_pkh: [u8; 20] =
            Ripemd160::digest(Sha256::digest(change_pubkey.serialize())).into();
        let change_addr = TransparentAddress::PublicKeyHash(change_pkh);
        builder
            .add_transparent_output(&change_addr, Zatoshis::const_from_u64(10_000))
            .expect("change output");

        let r = builder
            .build_for_pczt(
                rand_core::OsRng,
                &FeeRule::standard(),
                |_asset: &AssetBase| false,
            )
            .expect("build_for_pczt");
        let pczt = Creator::build_from_parts(r.pczt_parts).expect("creator");

        let pczt = Updater::new(pczt)
            .update_transparent_with(|mut u| {
                u.update_input_with(0, |mut u| {
                    let path = Bip32Derivation::parse([0u8; 32], vec![scope, dindex])
                        .expect("derivation path");
                    u.set_bip32_derivation(pubkey.serialize(), path);
                    u.set_hash160_preimage(pubkey.serialize().to_vec());
                    u.set_proprietary("scope".to_string(), scope.to_le_bytes().to_vec());
                    u.set_proprietary("dindex".to_string(), dindex.to_le_bytes().to_vec());
                    Ok(())
                })?;
                label_transparent_outputs(
                    u,
                    vec![recipient_address.to_string()],
                    Some(TransparentChangeLabel {
                        pubkey: change_pubkey,
                        scope: change_scope,
                        dindex: change_dindex,
                        address: change_addr.encode(&Network::Main),
                    }),
                )
            })
            .expect("update transparent")
            .finish();

        let (pczt, _sighash) = IoFinalizer::new(pczt).finalize_io().expect("finalize_io");
        pczt.serialize().expect("serialize")
    }

    #[test]
    fn label_transparent_outputs_labels_recipient_and_change() {
        let tprv = transparent_only_tprv();
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );
        let recipient_address = TransparentAddress::PublicKeyHash([9u8; 20]).encode(&Network::Main);

        let bytes = labeled_transparent_pczt_bytes(&tsk, 0, 0, &recipient_address, 1, 3);
        let pczt = Pczt::parse(&bytes).expect("parse pczt");
        let outputs = pczt.transparent().outputs();
        assert_eq!(
            outputs.len(),
            2,
            "expected one recipient and one change output"
        );

        assert_eq!(
            outputs[0].user_address().as_deref(),
            Some(recipient_address.as_str()),
            "recipient output must carry the original recipient address"
        );
        assert!(
            outputs[1].user_address().is_none(),
            "change output has no third-party recipient to label"
        );

        let change = &outputs[1];
        assert_eq!(
            change.proprietary().get("scope").cloned(),
            Some(1u32.to_le_bytes().to_vec())
        );
        assert_eq!(
            change.proprietary().get("dindex").cloned(),
            Some(3u32.to_le_bytes().to_vec())
        );
        assert!(
            change.proprietary().contains_key("address"),
            "change output must record its own address for recovery"
        );

        let change_sk_bytes = derive_transparent_sk(&tsk, 1, 3).expect("derive change sk");
        let change_sk = SecretKey::from_slice(&change_sk_bytes).expect("change secret key");
        let change_pubkey = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &change_sk);
        Verifier::new(pczt)
            .with_transparent(|bundle| {
                let derivations = bundle.outputs()[1].bip32_derivation();
                assert_eq!(
                    derivations.get(&change_pubkey.serialize()),
                    Some(&Bip32Derivation::parse([0u8; 32], vec![1, 3]).expect("derivation path")),
                    "change output must carry the BIP-32 derivation an external signer needs \
                     to recognise it as change"
                );
                assert_eq!(derivations.len(), 1);
                Ok::<(), TransparentError<Infallible>>(())
            })
            .expect("verify transparent");
    }

    /// A sapling spending key built directly from raw seed bytes, unrelated to any
    /// mnemonic-derived account: a genuinely "imported" ESK.
    fn sapling_only_esk() -> ExtendedSpendingKey {
        ExtendedSpendingKey::master(b"phase2b sapling fixture seed 32")
    }

    /// A structurally valid PCZT with a single sapling spend from `esk`'s default address
    /// and a single transparent output, balanced against the ZIP-317 fee. Neither the
    /// spend's note nor its Merkle path is chain-validated - they only need to be
    /// internally consistent, since the PCZT never leaves this offline fixture.
    ///
    /// `scope` builds the note against `esk`'s real (external/internal) key; `scope_field` is
    /// the raw bytes recorded in the spend's "scope" proprietary field (`None` omits it).
    /// Callers wanting a consistent fixture pass `le_bytes(scope)`; anything else simulates
    /// untrusted scope bookkeeping.
    fn sapling_pczt_bytes_custom(
        esk: &ExtendedSpendingKey,
        scope: u32,
        scope_field: Option<Vec<u8>>,
    ) -> Vec<u8> {
        let dfvk = esk.to_diversifiable_full_viewing_key();
        let fvk = dfvk.to_fvk(scope);
        let (_, recipient) = esk.default_address();
        // A lone sapling spend is padded to 2 outputs (1 real transparent + 1 dummy sapling),
        // so ZIP-317 charges 3 logical actions: 15,000 fee against a 10,000 transparent output.
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(25_000),
            Rseed::AfterZip212([7u8; 32]),
        );

        let path_elems: Vec<Node> = (0..NOTE_COMMITMENT_TREE_DEPTH)
            .map(|level| Node::empty_root(Level::from(level)))
            .collect();
        let merkle_path =
            MerklePath::from_parts(path_elems, Position::from(0u64)).expect("merkle path");
        let anchor = Anchor::from(merkle_path.root(Node::from_cmu(&note.cmu())));

        let build_config = BuildConfig::Standard {
            sapling_anchor: Some(anchor),
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(
            &Network::Main,
            BlockHeight::from_u32(1_700_000),
            build_config,
        );
        builder
            .add_sapling_spend::<Infallible>(fvk, note, merkle_path)
            .expect("spend");
        // 25,000 in via the sapling spend, 10,000 out, 15,000 fee (see the note above).
        builder
            .add_transparent_output(
                &TransparentAddress::PublicKeyHash([9u8; 20]),
                Zatoshis::const_from_u64(10_000),
            )
            .expect("output");

        let r = builder
            .build_for_pczt(
                rand_core::OsRng,
                &FeeRule::standard(),
                |_asset: &AssetBase| false,
            )
            .expect("build_for_pczt");
        let pczt = Creator::build_from_parts(r.pczt_parts).expect("creator");

        let pczt = Updater::new(pczt)
            .update_sapling_with(|mut u| {
                u.update_spend_with(0, |mut u| {
                    if let Some(bytes) = scope_field.clone() {
                        u.set_proprietary("scope".to_string(), bytes);
                    }
                    Ok(())
                })?;
                Ok(())
            })
            .expect("update sapling")
            .finish();

        let (pczt, _sighash) = IoFinalizer::new(pczt).finalize_io().expect("finalize_io");
        pczt.serialize().expect("serialize")
    }

    fn empty_package() -> PcztPackage {
        PcztPackage {
            pczt: Vec::new(),
            n_spends: [0; 4],
            sapling_indices: Vec::new(),
            orchard_indices: Vec::new(),
            ironwood_indices: Vec::new(),
            can_sign: false,
            can_broadcast: false,
            price: None,
            category: None,
            is_issuance: false,
        }
    }

    fn usk_of(phrase: &str, aindex: u32) -> UnifiedSpendingKey {
        let bytes = derive_spending_key(&Network::Main, phrase, None, aindex).expect("derive");
        UnifiedSpendingKey::from_bytes(Era::Orchard, &bytes).expect("usk")
    }

    #[tokio::test]
    async fn verify_spending_key_accepts_the_key_derived_for_the_same_account() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        verify_spending_key(
            &mut connection,
            account,
            &SigningKey::Unified(usk_of(TEST_PHRASE, 0)),
        )
        .await
        .expect("the account's own key must be accepted");
    }

    #[tokio::test]
    async fn verify_spending_key_rejects_another_account_index_and_another_seed() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        for (label, usk) in [
            ("other index", usk_of(TEST_PHRASE, 1)),
            ("other seed", usk_of(&other_phrase(), 0)),
        ] {
            assert!(
                verify_spending_key(&mut connection, account, &SigningKey::Unified(usk))
                    .await
                    .is_err(),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn verify_spending_key_rejects_a_provisioned_pool_without_a_viewing_key() {
        let mut connection = memory_db().await;
        let wif = watch_only_keys()
            .into_iter()
            .find(|key| key.label == "wif")
            .expect("wif vector");
        let account = restore(&mut connection, &wif.key, 0, None)
            .await
            .expect("restore");

        assert!(
            verify_spending_key(&mut connection, account, &SigningKey::Unified(test_usk(0)))
                .await
                .is_err(),
            "a NULL xvk in a provisioned pool must never count as a skipped pool"
        );
    }

    #[tokio::test]
    async fn verify_spending_key_rejects_an_account_that_has_no_pool_rows_at_all() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        assert!(
            verify_spending_key(
                &mut connection,
                account + 1,
                &SigningKey::Unified(test_usk(0))
            )
            .await
            .is_err(),
            "an unknown account must never be signable"
        );
    }

    #[tokio::test]
    async fn verify_spending_key_compares_only_the_provisioned_pools() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, Some(2))
            .await
            .expect("restore");

        // Old contract (pre-G2): compared only the intersection of pools present in
        // both the key and the account, so a full USK against this sapling-only
        // account only ever compared the sapling pool and always passed - the same
        // outcome as today, because a full key trivially covers a partial account.
        verify_spending_key(
            &mut connection,
            account,
            &SigningKey::Unified(usk_of(TEST_PHRASE, 0)),
        )
        .await
        .expect("a sapling-only account must accept its own USK");

        // New contract (G2): the key must cover every pool the account has a viewing
        // key for. A transparent-only key cannot be expressed as a partial
        // `UnifiedSpendingKey` at all, so this rejection only became reachable once
        // `verify_spending_key` started taking `&SigningKey`.
        match verify_spending_key(&mut connection, account, &transparent_key_of(TEST_PHRASE)).await
        {
            Err(_) => {}
            Ok(()) => panic!(
                "a transparent-only key must not satisfy an account whose only \
                 viewing key is sapling"
            ),
        }
    }

    #[tokio::test]
    async fn verify_spending_key_rejects_a_partial_key_for_an_account_with_three_viewing_keys() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        // The sapling component itself matches the account's own sapling viewing key -
        // only the missing transparent/orchard coverage must cause the rejection.
        match verify_spending_key(&mut connection, account, &sapling_key_of(TEST_PHRASE, 0)).await {
            Err(_) => {}
            Ok(()) => panic!(
                "a sapling-only key must not satisfy an account with transparent and \
                 orchard viewing keys too"
            ),
        }
    }

    #[tokio::test]
    async fn verify_spending_key_rejects_an_esk_from_a_different_seed_for_a_sapling_only_account() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, Some(2))
            .await
            .expect("restore");

        match verify_spending_key(
            &mut connection,
            account,
            &sapling_key_of(&other_phrase(), 0),
        )
        .await
        {
            Err(_) => {}
            Ok(()) => panic!("an ESK from a different seed must not be accepted"),
        }
    }

    #[tokio::test]
    async fn account_can_sign_is_true_for_mnemonic_and_imported_spending_keys() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        assert!(account_can_sign(&mut connection, account)
            .await
            .expect("can sign"));

        for label in ["tprv", "sapling xsk"] {
            let key = watch_only_keys()
                .into_iter()
                .find(|k| k.label == label)
                .unwrap_or_else(|| panic!("no fixture for {label}"));
            let mut connection = memory_db().await;
            let account = restore(&mut connection, &key.key, 0, None)
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", key.label));

            assert!(
                account_can_sign(&mut connection, account)
                    .await
                    .expect("can sign"),
                "{}",
                key.label
            );
        }

        for label in ["ufvk", "wif"] {
            let key = watch_only_keys()
                .into_iter()
                .find(|k| k.label == label)
                .unwrap_or_else(|| panic!("no fixture for {label}"));
            let mut connection = memory_db().await;
            let account = restore(&mut connection, &key.key, 0, None)
                .await
                .unwrap_or_else(|error| panic!("{}: {error}", key.label));

            assert!(
                !account_can_sign(&mut connection, account)
                    .await
                    .expect("can sign"),
                "{}",
                key.label
            );
        }
    }

    #[tokio::test]
    async fn sign_transaction_rejects_a_missing_spending_key_before_the_pczt() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &empty_package(),
            NO_SPENDING_KEY,
        )
        .await;
        let error = match signed {
            Ok(_) => panic!("an empty spending key must be rejected"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("spending key"), "{error}");
    }

    #[tokio::test]
    async fn sign_transaction_rejects_a_pczt_needing_orchard_with_a_sapling_only_key() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, Some(2))
            .await
            .expect("restore");

        let mut package = empty_package();
        package.pczt = empty_pczt_bytes();
        package.orchard_indices = vec![0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &sapling_key_bytes_of(TEST_PHRASE, 0),
        )
        .await;
        let error = match signed {
            Ok(_) => panic!("a sapling-only key must not sign an orchard spend"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("no orchard component"), "{error}");
    }

    #[tokio::test]
    async fn sign_transaction_signs_a_transparent_only_account_with_an_imported_xprv() {
        let mut connection = memory_db().await;
        let tprv = transparent_only_tprv();
        let account = restore(&mut connection, &tprv, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_transparent(&tprv).expect("encode");
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );

        let mut package = empty_package();
        package.pczt = transparent_pczt_bytes(&tsk, 0, 0);
        package.n_spends = [1, 0, 0, 0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        match signed {
            Ok(_) => {}
            Err(error) => panic!("a transparent-only key must sign its own input: {error}"),
        }
    }

    #[tokio::test]
    async fn sign_transaction_rejects_a_transparent_input_missing_its_scope_field() {
        let mut connection = memory_db().await;
        let tprv = transparent_only_tprv();
        let account = restore(&mut connection, &tprv, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_transparent(&tprv).expect("encode");
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );

        let mut package = empty_package();
        package.pczt = transparent_pczt_bytes_custom(&tsk, 0, 0, None, le_bytes(0), true);
        package.n_spends = [1, 0, 0, 0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        let error = match signed {
            Ok(_) => panic!("a transparent input missing its scope field must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("scope"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn sign_transaction_rejects_a_transparent_scope_outside_external_and_internal() {
        let mut connection = memory_db().await;
        let tprv = transparent_only_tprv();
        let account = restore(&mut connection, &tprv, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_transparent(&tprv).expect("encode");
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );

        let mut package = empty_package();
        // The key is derived at scope 0; only the PCZT's advertised scope is out of range,
        // which is exactly what an attacker-supplied PCZT can do.
        package.pczt = transparent_pczt_bytes_custom(&tsk, 0, 0, le_bytes(2), le_bytes(0), true);
        package.n_spends = [1, 0, 0, 0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        let error = match signed {
            Ok(_) => panic!("a transparent input with an unknown scope must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("scope"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn sign_transaction_rejects_transparent_metadata_that_is_absent_or_the_wrong_length() {
        let tprv = transparent_only_tprv();
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );

        for (label, scope_field, dindex_field) in [
            ("absent dindex", le_bytes(0), None),
            ("two-byte scope", Some(vec![0, 0]), le_bytes(0)),
            ("one-byte dindex", le_bytes(0), Some(vec![0])),
        ] {
            let mut connection = memory_db().await;
            let account = restore(&mut connection, &tprv, 0, None)
                .await
                .expect("restore");
            let usk_bytes = signing_key::encode_transparent(&tprv).expect("encode");

            let mut package = empty_package();
            package.pczt =
                transparent_pczt_bytes_custom(&tsk, 0, 0, scope_field, dindex_field, true);
            package.n_spends = [1, 0, 0, 0];

            let signed = sign_transaction(
                &mut connection,
                account,
                &Network::Main,
                &package,
                &usk_bytes,
            )
            .await;

            let error = match signed {
                Ok(_) => panic!("{label} must be rejected"),
                Err(error) => error.to_string(),
            };
            let field = if label.contains("scope") {
                "scope"
            } else {
                "dindex"
            };
            assert!(
                error.contains(field),
                "{label}: expected an error naming '{field}', got: {error}"
            );
        }
    }

    #[tokio::test]
    async fn sign_transaction_propagates_a_failed_transparent_signature_append_as_an_error() {
        let mut connection = memory_db().await;
        let tprv = transparent_only_tprv();
        let account = restore(&mut connection, &tprv, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_transparent(&tprv).expect("encode");
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );

        let mut package = empty_package();
        // No hash160 preimage recorded: the pczt signer cannot verify a signature against the
        // input's script, so `append_transparent_signature` fails and must not be swallowed.
        package.pczt = transparent_pczt_bytes_custom(&tsk, 0, 0, le_bytes(0), le_bytes(0), false);
        package.n_spends = [1, 0, 0, 0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        match signed {
            Ok(_) => panic!("an under-signed transparent input must not yield Ok"),
            Err(_) => {}
        }
    }

    #[tokio::test]
    async fn sign_transaction_rejects_an_out_of_bounds_sapling_spend_index() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let usk_bytes = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");

        let mut package = empty_package();
        package.pczt = empty_pczt_bytes();
        package.sapling_indices = vec![0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;
        let error = match signed {
            Ok(_) => panic!("an out-of-bounds sapling spend index must be rejected"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("out of bounds"), "{error}");
    }

    #[tokio::test]
    async fn sign_transaction_signs_a_sapling_only_account_with_an_imported_esk() {
        let mut connection = memory_db().await;
        let esk = sapling_only_esk();
        let key_str =
            encode_extended_spending_key(Network::Main.hrp_sapling_extended_spending_key(), &esk);
        let account = restore(&mut connection, &key_str, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_sapling(&key_str, &Network::Main).expect("encode");

        let mut package = empty_package();
        package.pczt = sapling_pczt_bytes_custom(&esk, 0, le_bytes(0));
        package.sapling_indices = vec![0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        match signed {
            Ok(_) => {}
            Err(error) => panic!("a sapling-only key must sign its own spend: {error}"),
        }
    }

    #[tokio::test]
    async fn sign_transaction_signs_a_phrase_account_with_its_full_unified_key() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let usk_bytes = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");
        let usk = usk_of(TEST_PHRASE, 0);

        let mut transparent = empty_package();
        transparent.pczt = transparent_pczt_bytes(usk.transparent(), 0, 0);
        transparent.n_spends = [1, 0, 0, 0];

        let mut sapling = empty_package();
        sapling.pczt = sapling_pczt_bytes_custom(usk.sapling(), 0, le_bytes(0));
        sapling.sapling_indices = vec![0];

        for (pool, package) in [("transparent", transparent), ("sapling", sapling)] {
            if let Err(error) = sign_transaction(
                &mut connection,
                account,
                &Network::Main,
                &package,
                &usk_bytes,
            )
            .await
            {
                panic!("a full unified key must sign its account's {pool} spend: {error}");
            }
        }
    }

    #[test]
    fn require_pool_keys_accept_a_unified_key_and_name_the_pool_a_partial_key_lacks() {
        let unified = SigningKey::Unified(usk_of(TEST_PHRASE, 0));
        assert!(require_transparent_key(&unified).is_ok());
        assert!(require_sapling_key(&unified).is_ok());
        assert!(require_orchard_key(&unified, "orchard").is_ok());
        assert!(require_orchard_key(&unified, "ironwood").is_ok());

        let transparent = transparent_key_of(TEST_PHRASE);
        assert!(require_transparent_key(&transparent).is_ok());
        for (pool, error) in [
            ("sapling", require_sapling_key(&transparent).unwrap_err()),
            (
                "orchard",
                require_orchard_key(&transparent, "orchard").unwrap_err(),
            ),
            (
                "ironwood",
                require_orchard_key(&transparent, "ironwood").unwrap_err(),
            ),
        ] {
            let error = error.to_string();
            assert!(error.contains(pool), "expected '{pool}' in: {error}");
        }

        let sapling = sapling_key_of(TEST_PHRASE, 0);
        assert!(require_sapling_key(&sapling).is_ok());
        assert!(require_transparent_key(&sapling)
            .unwrap_err()
            .to_string()
            .contains("transparent"));
        assert!(require_orchard_key(&sapling, "orchard")
            .unwrap_err()
            .to_string()
            .contains("orchard"));
    }

    #[tokio::test]
    async fn sign_transaction_rejects_a_sapling_spend_missing_its_scope_field() {
        let mut connection = memory_db().await;
        let esk = sapling_only_esk();
        let key_str =
            encode_extended_spending_key(Network::Main.hrp_sapling_extended_spending_key(), &esk);
        let account = restore(&mut connection, &key_str, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_sapling(&key_str, &Network::Main).expect("encode");

        let mut package = empty_package();
        package.pczt = sapling_pczt_bytes_custom(&esk, 0, None);
        package.sapling_indices = vec![0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;
        let error = match signed {
            Ok(_) => panic!("a sapling spend missing its scope field must be rejected"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("scope"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn sign_transaction_rejects_a_sapling_scope_field_of_the_wrong_length() {
        let mut connection = memory_db().await;
        let esk = sapling_only_esk();
        let key_str =
            encode_extended_spending_key(Network::Main.hrp_sapling_extended_spending_key(), &esk);
        let account = restore(&mut connection, &key_str, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_sapling(&key_str, &Network::Main).expect("encode");

        let mut package = empty_package();
        package.pczt = sapling_pczt_bytes_custom(&esk, 0, Some(vec![0, 0]));
        package.sapling_indices = vec![0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        let error = match signed {
            Ok(_) => panic!("a two-byte sapling scope field must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("scope"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn sign_transaction_propagates_a_failed_sapling_signature_as_an_error() {
        let mut connection = memory_db().await;
        let esk = sapling_only_esk();
        let key_str =
            encode_extended_spending_key(Network::Main.hrp_sapling_extended_spending_key(), &esk);
        let account = restore(&mut connection, &key_str, 0, None)
            .await
            .expect("restore");
        let usk_bytes = signing_key::encode_sapling(&key_str, &Network::Main).expect("encode");

        // The note is built and spent with the account's own external key (scope 0), but the
        // PCZT's "scope" field - untrusted bookkeeping the caller controls, not derived from
        // the key - falsely claims scope 1 (internal). Signing then derives the internal ask,
        // which does not match the note's real proof_generation_key: the pczt crate's own
        // nullifier check catches this inside `sign_sapling`, which must surface as an `Err`,
        // not a panic. The account's own key still passes `verify_spending_key`, so this
        // failure is reached only via `sign_sapling`, not the earlier key-coverage check.
        let mut package = empty_package();
        package.pczt = sapling_pczt_bytes_custom(&esk, 0, le_bytes(1));
        package.sapling_indices = vec![0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        match signed {
            Ok(_) => panic!("a spend signed under the wrong scope must be rejected"),
            Err(_) => {}
        }
    }

    #[tokio::test]
    async fn sign_transaction_propagates_an_out_of_bounds_orchard_action_index_as_an_error() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let usk_bytes = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");

        let mut package = empty_package();
        package.pczt = empty_pczt_bytes();
        package.orchard_indices = vec![0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        match signed {
            Ok(_) => panic!("an out-of-bounds orchard action index must be rejected"),
            Err(_) => {}
        }
    }

    #[tokio::test]
    async fn sign_transaction_propagates_an_out_of_bounds_ironwood_action_index_as_an_error() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let usk_bytes = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");

        let mut package = empty_package();
        package.pczt = empty_pczt_bytes();
        package.ironwood_indices = vec![99];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;

        match signed {
            Ok(_) => panic!("an out-of-bounds ironwood action index must be rejected"),
            Err(_) => {}
        }
    }

    #[tokio::test]
    async fn sign_transaction_rejects_a_transparent_spend_count_beyond_the_bundle() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let usk_bytes = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");

        let mut package = empty_package();
        package.pczt = empty_pczt_bytes();
        package.n_spends = [1, 0, 0, 0];

        let signed = sign_transaction(
            &mut connection,
            account,
            &Network::Main,
            &package,
            &usk_bytes,
        )
        .await;
        let error = match signed {
            Ok(_) => panic!("a transparent spend count beyond the bundle must be rejected"),
            Err(error) => error.to_string(),
        };

        assert!(error.contains("exceeds"), "{error}");
    }

    #[test]
    fn ironwood_activation_selects_ironwood_orchard_proving_key() {
        assert_eq!(
            orchard_proving_key_kind(BranchId::Nu6_3),
            OrchardProvingKeyKind::Ironwood,
        );
        assert_eq!(
            orchard_proving_key_kind(BranchId::Nu6_2),
            OrchardProvingKeyKind::Vanilla,
        );
    }

    #[test]
    fn zsa_selects_zsa_orchard_proving_key() {
        assert_eq!(
            orchard_proving_key_kind(BranchId::Nu7),
            OrchardProvingKeyKind::Zsa,
        );
    }

    #[test]
    fn wants_hardware_v5_when_account_is_hardware_bound() {
        assert!(wants_hardware_v5(1, false));
    }

    #[test]
    fn wants_hardware_v5_when_plan_targets_external_hardware_signer() {
        assert!(wants_hardware_v5(0, true));
    }

    #[test]
    fn wants_hardware_v5_false_for_a_plain_software_account() {
        assert!(!wants_hardware_v5(0, false));
    }

    /// A transparent-only PCZT built the same way `plan_transaction` builds one, at a
    /// height past Nu6_3's mainnet activation (3,428,143) so the branch's own suggested
    /// version is `V6` — only `hardware_signing` can force `V5` here. Returns
    /// `(tx_version, version_group_id)` from the built header.
    fn built_pczt_header(hardware_signing: bool) -> (u32, u32) {
        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(
            &Network::Main,
            BlockHeight::from_u32(3_500_000),
            build_config,
        );
        if wants_hardware_v5(0, hardware_signing) {
            builder
                .propose_version::<()>(TxVersion::V5)
                .expect("propose v5");
        }

        let sk = SecretKey::from_slice(&[7u8; 32]).expect("secret key");
        let pubkey = PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
        let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(pubkey.serialize())).into();
        let addr = TransparentAddress::PublicKeyHash(pkh);
        let coin = TxOut::new(Zatoshis::const_from_u64(20_000), addr.script().into());
        let utxo = OutPoint::new([9u8; 32], 0);
        builder.add_transparent_input(
            TransparentInputInfo::from_parts(utxo, coin, SpendInfo::P2pkh { pubkey })
                .expect("input"),
        );
        builder
            .add_transparent_output(&addr, Zatoshis::const_from_u64(10_000))
            .expect("output");

        let r = builder
            .build_for_pczt(
                rand_core::OsRng,
                &FeeRule::standard(),
                |_asset: &AssetBase| false,
            )
            .expect("build_for_pczt");
        let pczt = Creator::build_from_parts(r.pczt_parts).expect("creator");
        let global = pczt.global();
        (*global.tx_version(), *global.version_group_id())
    }

    #[test]
    fn wants_hardware_v5_true_forces_a_v5_header() {
        let (tx_version, version_group_id) = built_pczt_header(true);
        assert_eq!(tx_version, 5);
        assert_eq!(version_group_id, 0x26A7_270A);
    }

    #[test]
    fn wants_hardware_v5_false_leaves_the_branchs_suggested_version() {
        let (tx_version, _version_group_id) = built_pczt_header(false);
        assert_eq!(tx_version, 6);
    }

    #[test]
    fn transparent_signing_request_reports_header_inputs_and_outputs() {
        let tprv = transparent_only_tprv();
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );
        let recipient_address = TransparentAddress::PublicKeyHash([9u8; 20]).encode(&Network::Main);
        let bytes = labeled_transparent_pczt_bytes(&tsk, 0, 0, &recipient_address, 1, 3);

        let parsed = Pczt::parse(&bytes).expect("parse pczt");
        let global = parsed.global();
        let tbundle = parsed.transparent();
        let expected_lock_time = determine_lock_time(global, tbundle.inputs()).expect("lock time");

        let mut package = empty_package();
        package.pczt = bytes;
        package.n_spends = [1, 0, 0, 0];

        let request = transparent_signing_request(&Network::Main, &package).expect("request");

        assert_eq!(request.tx_version, *global.tx_version());
        assert_eq!(request.version_group_id, *global.version_group_id());
        assert_eq!(request.consensus_branch_id, *global.consensus_branch_id());
        assert_eq!(request.expiry_height, *global.expiry_height());
        assert_eq!(request.lock_time, expected_lock_time);
        assert_eq!(request.shielded.sapling_spends, 0);
        assert_eq!(request.shielded.sapling_outputs, 0);
        assert_eq!(request.shielded.orchard_actions, 0);

        assert_eq!(request.inputs.len(), 1);
        let input = &request.inputs[0];
        assert_eq!(input.index, 0);
        let mut display_order = FIXTURE_PREVOUT_TXID;
        display_order.reverse();
        assert_eq!(
            input.prev_txid,
            hex::encode(display_order),
            "hardware signers expect the txid in display order, not internal order"
        );
        assert_eq!(input.prev_index, 0);
        assert_eq!(input.value, 30_000);
        assert_eq!(
            input.sequence, 0xffff_ffff,
            "a planner-built input leaves no explicit sequence, which must read back as final"
        );
        assert_eq!(input.scope, 0);
        assert_eq!(input.dindex, 0);

        assert_eq!(request.outputs.len(), 2);
        let recipient = &request.outputs[0];
        assert_eq!(recipient.value, 10_000);
        assert_eq!(recipient.address, recipient_address);
        assert!(!recipient.is_change);
        assert_eq!(recipient.scope, None);
        assert_eq!(recipient.dindex, None);

        let change = &request.outputs[1];
        assert_eq!(change.value, 10_000);
        assert!(change.is_change);
        assert_eq!(change.scope, Some(1));
        assert_eq!(change.dindex, Some(3));
    }

    #[test]
    fn transparent_signing_request_reports_the_unified_address_for_a_ua_recipient() {
        let tprv = transparent_only_tprv();
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );
        let (ua, _) = crate::api::account::derive_unified_address(0, TEST_PHRASE, None, 0)
            .expect("derive ua");
        let bytes = labeled_transparent_pczt_bytes(&tsk, 0, 0, &ua, 1, 3);

        let mut package = empty_package();
        package.pczt = bytes;
        package.n_spends = [1, 0, 0, 0];

        let request = transparent_signing_request(&Network::Main, &package).expect("request");
        assert_eq!(
            request.outputs[0].address, ua,
            "a UA recipient's own address must survive, not a re-derived transparent encoding"
        );
    }

    #[tokio::test]
    async fn apply_transparent_signatures_accepts_a_valid_signature_and_can_broadcast() {
        let tprv = transparent_only_tprv();
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );
        let bytes = transparent_pczt_bytes(&tsk, 0, 0);

        let sk_bytes = derive_transparent_sk(&tsk, 0, 0).expect("derive sk");
        let sk = SecretKey::from_slice(&sk_bytes).expect("secret key");
        let pczt = Pczt::parse(&bytes).expect("parse pczt");
        let signer = Signer::new(pczt).expect("signer");
        let sighash = signer.transparent_sighash(0).expect("sighash");
        let signature =
            secp256k1::Secp256k1::new().sign_ecdsa(&secp256k1::Message::from_digest(sighash), &sk);

        let mut package = empty_package();
        package.pczt = bytes;
        package.n_spends = [1, 0, 0, 0];
        assert!(!package.can_broadcast);

        let signed =
            apply_transparent_signatures(&package, &[0], &[signature.serialize_der()[..].to_vec()])
                .expect("apply signatures");

        assert!(signed.can_broadcast);
        extract_transaction(&signed)
            .await
            .expect("signed transaction must extract");
    }

    #[test]
    fn apply_transparent_signatures_rejects_a_signature_that_does_not_verify() {
        let tprv = transparent_only_tprv();
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );
        let bytes = transparent_pczt_bytes(&tsk, 0, 0);

        let sk_bytes = derive_transparent_sk(&tsk, 0, 0).expect("derive sk");
        let sk = SecretKey::from_slice(&sk_bytes).expect("secret key");
        let pczt = Pczt::parse(&bytes).expect("parse pczt");
        let signer = Signer::new(pczt).expect("signer");
        let sighash = signer.transparent_sighash(0).expect("sighash");
        let signature =
            secp256k1::Secp256k1::new().sign_ecdsa(&secp256k1::Message::from_digest(sighash), &sk);
        let mut der = signature.serialize_der()[..].to_vec();
        let last = der.len() - 1;
        der[last] ^= 0xFF;

        let mut package = empty_package();
        package.pczt = bytes;
        package.n_spends = [1, 0, 0, 0];

        let error = apply_transparent_signatures(&package, &[0], &[der])
            .err()
            .expect("a corrupted signature must be rejected");
        assert!(
            error.to_string().contains("failed sighash verification"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn apply_transparent_signatures_rejects_a_non_der_blob() {
        let tprv = transparent_only_tprv();
        let tsk = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&tprv).expect("parse"),
        );
        let bytes = transparent_pczt_bytes(&tsk, 0, 0);

        let mut package = empty_package();
        package.pczt = bytes;
        package.n_spends = [1, 0, 0, 0];

        let error = apply_transparent_signatures(&package, &[0], &[vec![0xDE, 0xAD, 0xBE, 0xEF]])
            .err()
            .expect("a non-DER blob must be rejected");
        assert!(
            error.to_string().contains("is not valid DER"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn apply_transparent_signatures_rejects_mismatched_indices_and_signatures_lengths() {
        let mut package = empty_package();
        package.n_spends = [2, 0, 0, 0];

        let error = apply_transparent_signatures(&package, &[0, 1], &[Vec::new()])
            .err()
            .expect("a length mismatch must be rejected");
        assert!(
            error.to_string().contains("different lengths"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn apply_transparent_signatures_rejects_an_out_of_range_index() {
        let mut package = empty_package();
        package.n_spends = [2, 0, 0, 0];

        let error = apply_transparent_signatures(&package, &[5], &[Vec::new()])
            .err()
            .expect("an out-of-range index must be rejected");
        assert!(
            error.to_string().contains("out of range"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn apply_transparent_signatures_rejects_a_duplicate_index() {
        let mut package = empty_package();
        package.n_spends = [2, 0, 0, 0];

        let error = apply_transparent_signatures(&package, &[0, 0], &[Vec::new(), Vec::new()])
            .err()
            .expect("a duplicate index must be rejected");
        assert!(
            error.to_string().contains("duplicate"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn apply_transparent_signatures_rejects_a_missing_index() {
        let mut package = empty_package();
        package.n_spends = [2, 0, 0, 0];

        let error = apply_transparent_signatures(&package, &[0], &[Vec::new()])
            .err()
            .expect("a missing index must be rejected");
        assert!(
            error.to_string().contains("missing a signature"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn tex_addresses_are_detected() {
        use super::is_tex;
        use crate::api::coin::Network;
        // Test vectors from zcash_address encoding.rs (same hash as the
        // t1.../tm... P2PKH addresses on the same line).
        assert!(is_tex(&Network::Main, "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte").unwrap());
        assert!(!is_tex(&Network::Main, "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC").unwrap());
        assert!(is_tex(
            &Network::Test,
            "textest1qyqszqgpqyqszqgpqyqszqgpqyqszqgpfcjgfy"
        )
        .unwrap());
        assert!(!is_tex(&Network::Test, "tm9ofD7kHR7AF8MsJomEzLqGcrLCBkD9gDj").unwrap());
    }
}
