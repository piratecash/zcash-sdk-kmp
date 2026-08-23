use anyhow::{Context as _, Result};
use sqlx::SqliteConnection;
use sqlx::{sqlite::SqliteRow, Row};
use std::collections::HashMap;
use tokio::sync::broadcast;
use tokio::sync::mpsc::channel;
use tokio_stream::StreamExt;
use tracing::debug;
use zcash_transparent::address::TransparentAddress;

use crate::api::account::get_ledger;
use crate::api::coin::{Coin, Network};
use crate::api::sync::{CANCEL_SYNC, SYNCING};
use crate::budget::merge_pending_txs;

use crate::db::{store_block_header, transparent_addresses_to_scan};
use crate::io::SyncHeight;
use crate::{Client, Sink};
use std::{collections::HashSet, mem};

use crate::{
    account::{derive_transparent_address, derive_transparent_sk, get_birth_height, has_pool},
    api::sync::SyncProgress,
    db::{
        get_account_aindex, get_account_dindex, get_account_hw, select_account_transparent,
        store_account_transparent_addr,
    },
    lwd::CompactBlock,
    warp::{legacy::CommitmentTreeFrontier, sync::warp_sync},
};
use bincode::config;
use sqlx::pool::PoolConnection;
use sqlx::{Connection, Sqlite, SqlitePool};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

pub const DEFAULT_ACTIONS_PER_SYNC: u32 = 10000u32;
pub const DEFAULT_TRANSPARENT_LIMIT: u32 = 100u32;

pub use zcash_trees::types::SyncError;
pub use zcash_trees::types::{BlockHeader, Issuance, Note, Transaction, WarpSyncMessage, UTXO};

pub struct NoteExtended {
    pub id: u32,
    pub address: Vec<u8>,
    pub memo: Vec<u8>,
}

/// Pre-derived Sapling account keys — loaded once before sync.
pub struct SaplingAccountKeys {
    pub dfvk: sapling_crypto::zip32::DiversifiableFullViewingKey,
    pub external_ivk: sapling_crypto::keys::SaplingIvk,
    pub internal_ivk: sapling_crypto::keys::SaplingIvk,
    pub external_nk: sapling_crypto::keys::NullifierDerivingKey,
    pub internal_nk: sapling_crypto::keys::NullifierDerivingKey,
}

/// Pre-derived Orchard account keys — loaded once before sync.
pub struct OrchardAccountKeys {
    pub fvk: orchard::keys::FullViewingKey,
    pub external_ivk: orchard::keys::IncomingViewingKey,
    pub internal_ivk: orchard::keys::IncomingViewingKey,
    // Orchard NK = FullViewingKey (see warp/sync/shielded/orchard.rs line 27)
}

/// Cache of all per-account key material needed during shielded sync.
/// Preloaded once so key derivation stays out of the database writer's hot path.
pub struct AccountKeyCache {
    pub sapling: HashMap<u32, SaplingAccountKeys>,
    pub orchard: HashMap<u32, OrchardAccountKeys>,
}

#[allow(clippy::too_many_arguments)]
pub async fn synchronize_impl<S: Sink<SyncProgress> + Send + 'static>(
    progress: S,
    accounts: Vec<u32>,
    current_height: u32,
    actions_per_sync: u32,
    transparent_limit: u32,
    checkpoint_age: u32,
    noskip_details: bool,
    c: &Coin,
) -> Result<u32> {
    if accounts.is_empty() {
        return Ok(current_height);
    }

    let Ok(_guard) = SYNCING.try_lock() else {
        return Ok(current_height);
    };

    let (tx_cancel, _rx_cancel) = broadcast::channel::<()>(1);
    {
        let mut cancel = CANCEL_SYNC.lock().await;
        *cancel = Some(tx_cancel.clone());
    }

    let network = c.network();
    let mut connection = c.get_connection().await?;
    let progress2 = progress.clone();

    let checkpoint_cutoff = current_height.saturating_sub(checkpoint_age);
    for account in accounts.iter() {
        prune_old_checkpoints(&mut connection, *account, checkpoint_cutoff).await?;
    }

    let mut account_use_internal = HashMap::<u32, bool>::new();
    let res = async {
        recover_from_partial_sync(&mut connection, &accounts).await?;

        // Get account heights
        let mut account_heights = HashMap::new();
        debug!("Current network height: {}", current_height);
        for account in accounts.iter() {
            let r: (Option<u32>, Option<u32>) = sqlx::query_as(
                r#"SELECT account, MIN(height) FROM sync_heights
                JOIN accounts ON account = id_account
                WHERE account = ?"#,
            )
            .bind(account)
            .fetch_one(&mut *connection)
            .await?;
            if let (Some(account), Some(height)) = r {
                debug!(
                    "Account {} - current DB sync height: {}, next sync height: {}",
                    account,
                    height,
                    height + 1
                );
                account_heights.insert(account, height + 1);

                let (use_internal,): (bool,) =
                    sqlx::query_as("SELECT use_internal FROM accounts WHERE id_account = ?")
                        .bind(account)
                        .fetch_one(&mut *connection)
                        .await
                        .context("Fetch use_internal")?;
                account_use_internal.insert(account, use_internal);

                // Check which pools this account has
                let t_count: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM transparent_address_accounts WHERE account = ?",
                )
                .bind(account)
                .fetch_one(&mut *connection)
                .await?;
                debug!(
                    "Account {} - has {} transparent addresses, use_internal={}",
                    account, t_count.0, use_internal
                );
            } else {
                debug!(
                    "Account {} - NO sync_heights entry found, will be skipped",
                    account
                );
            }
        }

        // Create a sorted list of unique heights
        let mut unique_heights: Vec<u32> = account_heights.values().cloned().collect();
        unique_heights.sort_unstable();
        unique_heights.dedup();
        debug!(
            "Unique sync start heights for accounts: {:?}",
            unique_heights
        );

        let (tx_progress, mut rx_progress) = channel::<SyncProgress>(1);

        tokio::spawn(async move {
            while let Some(p) = rx_progress.recv().await {
                let _ = progress.send(p).await;
            }
        });

        // For each unique height, process accounts that need to be synced from that height
        for (i, &start_height) in unique_heights.iter().enumerate() {
            // Determine the end height (next height - 1 or current_height)
            let end_height = if i + 1 < unique_heights.len() {
                unique_heights[i + 1] - 1
            } else {
                current_height
            };

            // Find accounts that have a height <= this start_height
            let accounts_to_sync = account_heights
                .iter()
                .filter(|&(_, &height)| height <= start_height)
                .map(|(&account, _)| {
                    let use_internal = account_use_internal[&account];
                    (account, use_internal)
                })
                .collect::<Vec<_>>();

            // Skip if no accounts to sync
            if accounts_to_sync.is_empty() {
                debug!("No accounts to sync for start_height {}", start_height);
                continue;
            }

            debug!(
                "Syncing accounts {:?} from height {} to {}",
                accounts_to_sync.iter().map(|(a, _)| a).collect::<Vec<_>>(),
                start_height,
                end_height
            );

            let pool = c.get_pool()?;
            // Update the sync heights for these accounts
            let mut client = c.client().await?;

            debug!("Start height: {}", start_height);
            debug!("End height: {}", end_height);

            if start_height > end_height {
                debug!("Skipping sync: start_height ({}) > end_height ({}), wallet is ahead of network", start_height, end_height);
                return Ok(());
            }

            let account_ids = accounts_to_sync
                .iter()
                .map(|(account, _)| *account)
                .collect::<Vec<_>>();
            transparent_sync(
                &network,
                &mut connection,
                &mut client,
                &account_ids,
                start_height,
                end_height,
                transparent_limit,
                tx_cancel.subscribe(),
            )
            .await?;

            shielded_sync(
                &network,
                &pool,
                &mut client,
                &accounts_to_sync,
                start_height,
                end_height,
                actions_per_sync,
                tx_progress.clone(),
                tx_cancel.subscribe(),
            )
            .await?;

            debug!("heights_without_time");
            let heights_without_time =
                get_heights_without_time(&mut connection, start_height, end_height).await?;
            for h in heights_without_time {
                debug!("fetch block @{h}");
                let block = client.block(&network, h).await?;
                let time = block.time;
                sqlx::query("UPDATE transactions SET time = ? WHERE height = ? AND time = 0")
                    .bind(time)
                    .bind(h)
                    .execute(&mut *connection)
                    .await?;
                let block_header = BlockHeader {
                    height: h,
                    hash: block.hash,
                    time: block.time,
                };
                store_block_header(&mut connection, &block_header).await?;
            }

            // Update our local map as well for the next iteration
            for (account, _) in &accounts_to_sync {
                account_heights.insert(*account, end_height);
                if !noskip_details {
                    crate::memo::fetch_tx_details(&network, &mut connection, &mut client, *account)
                        .await?;
                }
            }

            debug!(
                "Sync completed for height range {}-{}",
                start_height, end_height
            );
        }

        for account in accounts.iter() {
            merge_pending_txs(&mut connection, *account, current_height).await?;
        }

        Ok::<_, anyhow::Error>(())
    };

    match res.await {
        Ok(_) => {}
        Err(e) => {
            debug!("Error during sync: {:?}", e);
            progress2.send_error(e).await;
        }
    }

    {
        let mut cancel = CANCEL_SYNC.lock().await;
        *cancel = None;
    }

    Ok(current_height)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn transparent_sync(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    accounts: &[u32],
    start_height: u32,
    end_height: u32,
    limit: u32,
    mut rx_cancel: broadcast::Receiver<()>,
) -> Result<()> {
    let mut addresses = vec![];
    let mut scanned_accounts = vec![];
    debug!(
        "transparent_sync: scanning accounts {:?} from height {} to {} with limit {}",
        accounts, start_height, end_height, limit
    );
    for account in accounts {
        let scanned = transparent_addresses_to_scan(&mut *connection, *account, limit).await?;
        for (id_taddress, address) in &scanned {
            debug!(
                "transparent_sync: account {} has taddress id={} addr={}",
                account, id_taddress, address
            );
        }
        debug!(
            "transparent_sync: account {} has {} transparent addresses to scan",
            account,
            scanned.len()
        );
        if !scanned.is_empty() {
            scanned_accounts.push(*account);
        }
        addresses.extend(scanned.into_iter().map(|address| (*account, address)));
    }
    debug!(
        "transparent_sync: total {} addresses to scan across all accounts",
        addresses.len()
    );
    for (account, address_row) in addresses.iter() {
        let my_address = TransparentAddress::decode(&network, &address_row.1)?;
        debug!(
            "transparent_sync: scanning account {} address {} (decoded: {:?})",
            account,
            address_row.1,
            my_address.encode(network)
        );
        let mut txs = client
            .taddress_txs(network, &address_row.1, start_height, end_height)
            .await?
            .into_inner();

        let mut db_tx = connection.begin().await?;
        loop {
            tokio::select! {
                _ = rx_cancel.recv() => {
                    debug!("Canceling sync");
                    anyhow::bail!("Sync canceled");
                }
                m = txs.recv() => {
                    if let Some(item) = m {
                        let (height, transaction, _) = item?;
                        let txid = transaction.txid().as_ref().to_vec();
                        debug!(
                            "transparent_sync: found tx {} at height {} for account {} version={:?} branch_id={:?}",
                            hex::encode(&txid),
                            height,
                            account,
                            transaction.version(),
                            transaction.consensus_branch_id(),
                        );
                        // tx time is available in the block (not here)
                        let tx_insert_result = sqlx::query("INSERT INTO transactions (account, txid, height, time) VALUES (?, ?, ?, 0) ON CONFLICT DO NOTHING")
                        .bind(account)
                        .bind(&txid)
                        .bind(height)
                        .execute(&mut *db_tx)
                        .await?;
                        debug!(
                            "transparent_sync: tx {} inserted into transactions (rows_affected={})",
                            hex::encode(&txid),
                            tx_insert_result.rows_affected()
                        );

                        // Access the transparent bundle part
                        if let Some(transparent_bundle) = transaction.transparent_bundle() {
                            debug!(
                                "transparent_sync: tx {} has transparent bundle: {} vins, {} vouts",
                                transaction.txid(),
                                transparent_bundle.vin.len(),
                                transparent_bundle.vout.len()
                            );

                            let vins = &transparent_bundle.vin;
                            for vin in vins.iter() {
                                // The "nullifier" of a transparent input is the outpoint
                                let mut nf = vec![];
                                vin.prevout().write(&mut nf)?;

                                let row: Option<(u32, i64)> = sqlx::query_as(
                                "SELECT id_note, value FROM notes WHERE account = ?1 AND nullifier = ?2",
                            )
                            .bind(account)
                            .bind(&nf)
                            .fetch_optional(&mut *db_tx)
                            .await?;

                                if let Some((id, amount)) = row {
                                    debug!(
                                        "transparent_sync: tx {} vin spends note {} amount {}",
                                        transaction.txid(),
                                        id,
                                        amount
                                    );
                                    // note was found
                                    // add a spent entry
                                    sqlx::query(
                                        "INSERT INTO spends (account, id_note, pool, tx, height, value)
                                SELECT ?, ?, 0, tx.id_tx, ?, ? FROM transactions tx WHERE tx.txid = ?
                                AND account = ? ON CONFLICT DO NOTHING",
                                    )
                                    .bind(account)
                                    .bind(id)
                                    .bind(height)
                                    .bind(-amount)
                                    .bind(&txid)
                                    .bind(account)
                                    .execute(&mut *db_tx)
                                    .await?;
                                }
                            }

                            let vouts = &transparent_bundle.vout;
                            for (i, vout) in vouts.iter().enumerate() {
                                let vout_value = vout.value().into_u64();
                                if let Some(vout_addr) = vout.recipient_address() {
                                    let vout_addr_encoded = vout_addr.encode(network);
                                    let my_addr_encoded = my_address.encode(network);
                                    let is_match = vout_addr == my_address;
                                    debug!(
                                        "transparent_sync: tx {} vout[{}] value={} recipient={} my_address={} match={}",
                                        transaction.txid(),
                                        i,
                                        vout_value,
                                        vout_addr_encoded,
                                        my_addr_encoded,
                                        is_match,
                                    );
                                    if is_match {
                                        // It is for me
                                        // add a new note entry
                                        let mut nf = transaction.txid().as_ref().to_vec();
                                        nf.extend_from_slice(&(i as u32).to_le_bytes());

                                        let note_result = sqlx::query("INSERT INTO notes (account, height, pool, tx, taddress, nullifier, value)
                                    SELECT ?, ?, 0, tx.id_tx, ?, ?, ? FROM transactions tx WHERE tx.txid = ?
                                    AND account = ? ON CONFLICT DO NOTHING")
                                        .bind(account)
                                        .bind(height)
                                        .bind(address_row.0)
                                        .bind(&nf)
                                        .bind(vout_value as i64)
                                        .bind(&txid)
                                        .bind(account)
                                        .execute(&mut *db_tx)
                                        .await?;
                                        debug!(
                                            "transparent_sync: tx {} vout[{}] NOTE CREATED value={} rows_affected={}",
                                            transaction.txid(),
                                            i,
                                            vout_value,
                                            note_result.rows_affected()
                                        );
                                    }
                                } else {
                                    debug!(
                                        "transparent_sync: tx {} vout[{}] value={} has NO recipient address (script cannot be decoded)",
                                        transaction.txid(),
                                        i,
                                        vout_value,
                                    );
                                }
                            }
                        } else {
                            debug!(
                                "transparent_sync: tx {} has NO transparent bundle (shielded-only tx) version={:?} branch_id={:?} height={}",
                                transaction.txid(),
                                transaction.version(),
                                transaction.consensus_branch_id(),
                                height,
                            );
                        }
                    } else {
                        // No more transactions
                        break;
                    }
                }
            }
        }

        db_tx.commit().await?;
    }

    // Only once every address of the range has been scanned: moving the height earlier strands
    // whatever a mid-account failure left unscanned, and that range is never requested again.
    let mut db_tx = connection.begin().await?;
    for account in scanned_accounts.iter() {
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ? AND pool = 0")
            .bind(end_height)
            .bind(account)
            .execute(&mut *db_tx)
            .await?;
    }
    db_tx.commit().await?;

    Ok(())
}

pub async fn get_compact_block_range(
    network: &Network,
    client: &mut Client,
    start: u32,
    end: u32,
) -> Result<ReceiverStream<Result<CompactBlock>>> {
    let blocks = client.block_range(network, start, end).await?;
    Ok(blocks)
}

pub async fn get_tree_state(
    network: &Network,
    client: &mut Client,
    height: u32,
) -> Result<(
    CommitmentTreeFrontier,
    CommitmentTreeFrontier,
    CommitmentTreeFrontier,
)> {
    let min_height: u32 = network
        .activation_height(zcash_protocol::consensus::NetworkUpgrade::Sapling)
        .unwrap()
        .into();

    if height < min_height {
        return Ok((
            CommitmentTreeFrontier::default(),
            CommitmentTreeFrontier::default(),
            CommitmentTreeFrontier::default(),
        ));
    }

    let (sapling_tree, orchard_tree, ironwood_tree) = client.tree_state(height).await?;

    fn decode_tree_state(tree: &[u8]) -> CommitmentTreeFrontier {
        if tree.is_empty() {
            CommitmentTreeFrontier::default()
        } else {
            CommitmentTreeFrontier::read(tree).unwrap()
        }
    }

    let sapling = decode_tree_state(&sapling_tree);
    let orchard = decode_tree_state(&orchard_tree);
    let ironwood = decode_tree_state(&ironwood_tree);

    Ok((sapling, orchard, ironwood))
}

/// Preload all Sapling and Orchard account keys from the database.
/// All key derivations happen exactly once, before any sync work starts.
pub async fn preload_account_key_cache(
    connection: &mut SqliteConnection,
) -> Result<AccountKeyCache> {
    let mut sapling = HashMap::new();
    let sapling_rows: Vec<(u32, Vec<u8>)> =
        sqlx::query_as("SELECT account, xvk FROM sapling_accounts")
            .fetch_all(&mut *connection)
            .await?;

    for (account, xvk) in sapling_rows {
        let dfvk = sapling_crypto::zip32::DiversifiableFullViewingKey::from_bytes(
            &xvk.try_into().unwrap(),
        )
        .unwrap();
        let external_ivk = dfvk.fvk().vk.ivk();
        let internal_ivk = dfvk.to_internal_fvk().vk.ivk();
        let external_nk = dfvk.fvk().vk.nk;
        let internal_nk = dfvk.to_internal_fvk().vk.nk;
        sapling.insert(
            account,
            SaplingAccountKeys {
                dfvk,
                external_ivk,
                internal_ivk,
                external_nk,
                internal_nk,
            },
        );
    }

    let mut orchard = HashMap::new();
    let orchard_rows: Vec<(u32, Vec<u8>)> =
        sqlx::query_as("SELECT account, xvk FROM orchard_accounts")
            .fetch_all(&mut *connection)
            .await?;

    for (account, xvk) in orchard_rows {
        let fvk = orchard::keys::FullViewingKey::from_bytes(&xvk.try_into().unwrap()).unwrap();
        let external_ivk = fvk.to_ivk(orchard::keys::Scope::External);
        let internal_ivk = fvk.to_ivk(orchard::keys::Scope::Internal);
        orchard.insert(
            account,
            OrchardAccountKeys {
                fvk,
                external_ivk,
                internal_ivk,
            },
        );
    }

    Ok(AccountKeyCache { sapling, orchard })
}

/// Resolve the diversifier index from a note's raw diversifier bytes.
/// Pure computation — no DB access, uses the preloaded key cache.
fn resolve_diversifier_index(
    cache: &AccountKeyCache,
    account: u32,
    pool: u8,
    scope: u8,
    diversifier: &[u8],
) -> Option<i64> {
    match pool {
        1 => cache.sapling.get(&account).and_then(|keys| {
            crate::db::resolve_sapling_diversifier_index(&keys.dfvk, scope, diversifier)
        }),
        2 => cache.orchard.get(&account).and_then(|keys| {
            crate::db::resolve_orchard_diversifier_index(&keys.fvk, scope, diversifier)
        }),
        _ => None,
    }
}

async fn commit_warp_messages(
    network: &Network,
    writer_connection: &mut SqliteConnection,
    messages: &mut Vec<WarpSyncMessage>,
    tx_progress: &Sender<SyncProgress>,
    key_cache: &AccountKeyCache,
) -> Result<()> {
    let mut db_tx = writer_connection.begin().await?;
    for message in mem::take(messages) {
        handle_message(network, &mut db_tx, message, tx_progress, key_cache).await?;
    }
    db_tx.commit().await?;
    debug!("Committing transaction");
    Ok(())
}

async fn write_warp_messages(
    network: &Network,
    writer_connection: &mut SqliteConnection,
    mut rx_messages: Receiver<WarpSyncMessage>,
    tx_progress: &Sender<SyncProgress>,
    key_cache: &AccountKeyCache,
) -> Result<()> {
    debug!("[db handler] starting");
    let mut messages = vec![];
    while let Some(message) = rx_messages.recv().await {
        if matches!(message, WarpSyncMessage::Commit) {
            commit_warp_messages(
                network,
                writer_connection,
                &mut messages,
                tx_progress,
                key_cache,
            )
            .await?;
        } else {
            messages.push(message);
        }
    }
    commit_warp_messages(
        network,
        writer_connection,
        &mut messages,
        tx_progress,
        key_cache,
    )
    .await?;

    debug!("[db handler] stopped");
    check_witness_consistency(writer_connection).await
}

#[allow(clippy::too_many_arguments)]
pub async fn shielded_sync(
    network: &Network,
    pool: &SqlitePool,
    client: &mut Client,
    accounts: &[(u32, bool)],
    start: u32,
    end: u32,
    actions_per_sync: u32,
    tx_progress: Sender<SyncProgress>,
    rx_cancel: broadcast::Receiver<()>,
) -> Result<()> {
    let activation_height: u32 = network
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap()
        .into();
    let start = start.max(activation_height);
    let end = end.max(activation_height);

    let accounts = accounts.to_vec();
    let (s, o, i) = get_tree_state(network, client, start - 1).await?;

    debug!("get compact block range");
    let blocks = get_compact_block_range(network, client, start, end).await?;
    debug!("got streaming blocks");
    let (tx_messages, rx_messages) = channel::<WarpSyncMessage>(100);

    let mut connection = pool.acquire().await?;
    // get the list of transaction heights for which the time is 0
    // because raw transactions do not have timestamp (it comes from the block header)
    let heights_without_time = get_heights_without_time(&mut connection, start, end).await?;

    let mut writer_connection = pool.acquire().await?;
    // Key derivations happen once upfront — no per-note DB queries in the hot path.
    let key_cache = preload_account_key_cache(&mut writer_connection).await?;
    let network = *network;
    let error_sender = tx_messages.clone();
    let sync = async move {
        debug!("Start sync");
        if let Err(error) = warp_sync(
            &network,
            &mut connection,
            start,
            end,
            &accounts,
            blocks,
            heights_without_time,
            actions_per_sync,
            &s,
            &o,
            &i,
            tx_messages,
            rx_cancel,
        )
        .await
        {
            tracing::error!("Error during warp sync: {:?}", error);
            error_sender
                .send(WarpSyncMessage::Error(error))
                .await
                .context("sending warp sync error")?;
        }
        debug!("Sync finished");
        Ok::<_, anyhow::Error>(())
    };
    let writer = write_warp_messages(
        &network,
        &mut writer_connection,
        rx_messages,
        &tx_progress,
        &key_cache,
    );

    let (sync_result, writer_result) = tokio::join!(sync, writer);
    writer_result?;
    sync_result
}

async fn handle_message(
    network: &Network,
    db_tx: &mut sqlx::Transaction<'_, Sqlite>,
    msg: WarpSyncMessage,
    tx_progress: &Sender<SyncProgress>,
    key_cache: &AccountKeyCache,
) -> Result<()> {
    tracing::debug!(target: "warp", "Warp Message: {msg:?}");
    match msg {
        WarpSyncMessage::Issuance(iss) => {
            sqlx::query(
                "INSERT OR IGNORE INTO assets(asset_desc_hash, ik, asset_base, finalized, first_seen_height)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&iss.asset_desc_hash)
            .bind(&iss.ik)
            .bind(&iss.asset_base)
            .bind(iss.finalized)
            .bind(iss.height)
            .execute(&mut **db_tx)
            .await?;
            tracing::debug!("asset base {}", hex::encode(&iss.asset_base));

            if iss.finalized {
                sqlx::query(
                    "UPDATE assets SET finalized = TRUE WHERE asset_desc_hash = ?1 AND ik = ?2",
                )
                .bind(&iss.asset_desc_hash)
                .bind(&iss.ik)
                .execute(&mut **db_tx)
                .await?;
            }
            debug!(
                "Processing Issuance: height={}, finalized={}",
                iss.height, iss.finalized
            );
        }
        WarpSyncMessage::Transaction(tx) => {
            // ignore duplicate transactions because they could have been created
            // by a previous type of scan (i.e transparent)
            sqlx::query(
                "INSERT INTO transactions (account, txid, height, time) VALUES (?, ?, ?, ?)
                ON CONFLICT DO NOTHING",
            )
            .bind(tx.account)
            .bind(&tx.txid)
            .bind(tx.height)
            .bind(tx.time)
            .execute(&mut **db_tx)
            .await?;
            debug!("Processing Transaction: id={}, height={}", tx.id, tx.height);
        }
        WarpSyncMessage::Note(note) => {
            // Resolve id_asset via LEFT JOIN on the assets table.
            // For ZSA notes (non-empty asset_base), the JOIN finds the
            // matching row inserted earlier by an Issuance message.
            // For vanilla ZEC notes, asset_base is empty and id_asset
            // resolves to NULL.
            tracing::debug!("note asset base {}", hex::encode(&note.asset_base));

            // Auto-register ZSA assets discovered through decryption.
            // Issuance messages insert with known desc_hash+ik; for encrypted
            // ZSA transfers we only know the asset_base. Use the asset_base
            // itself as a unique key so the LEFT JOIN below can resolve id_asset.
            if note.asset_base.len() == 32 && note.asset_base != [0u8; 32] {
                // Use asset_base as the desc_hash placeholder and a zero-prefixed
                // asset_base as the ik placeholder to get a unique (desc_hash, ik).
                let mut ik_placeholder = vec![0u8; 33];
                ik_placeholder[1..].copy_from_slice(&note.asset_base[..32]);
                sqlx::query(
                    "INSERT OR IGNORE INTO assets(asset_desc_hash, ik, asset_base, finalized, first_seen_height)
                     VALUES (?1, ?2, ?3, 0, ?4)",
                )
                .bind(&note.asset_base)
                .bind(&ik_placeholder)
                .bind(&note.asset_base)
                .bind(note.height)
                .execute(&mut **db_tx)
                .await?;
            }

            // Resolve diversifier_index from the preloaded key cache
            let diversifier_index = resolve_diversifier_index(
                key_cache,
                note.account,
                note.pool,
                note.scope,
                &note.diversifier,
            );

            let r = sqlx::query
                    ("INSERT INTO notes
                        (account, height, pool, scope, tx, nullifier, value, cmx, position, diversifier, rcm, rho, id_asset, diversifier_index)
                        SELECT t.account, ?, ?, ?, t.id_tx, ?, ?, ?, ?, ?, ?, ?, a.id_asset, ?
                        FROM transactions t
                        LEFT JOIN assets a ON a.asset_base = ?
                        WHERE t.account = ? AND t.txid = ?")
                    .bind(note.height)
                    .bind(note.pool)
                    .bind(note.scope)
                    .bind(&note.nf)
                    .bind(note.value as i64)
                    .bind(&note.cmx)
                    .bind(note.position)
                    .bind(&note.diversifier)
                    .bind(&note.rcm)
                    .bind(&note.rho)
                    .bind(diversifier_index)
                    .bind(&note.asset_base)
                    .bind(note.account)
                    .bind(&note.txid)
                    .execute(&mut **db_tx).await?;
            debug!(
                "Processing Note: id={}, account={}, height={}",
                note.id, note.account, note.height
            );
            debug!("{:?}", note);
            assert_eq!(r.rows_affected(), 1);
        }
        WarpSyncMessage::Witness(account, height, cmx, witness) => {
            let w = bincode::encode_to_vec(&witness, config::legacy())?;
            let r = sqlx::query(
                "INSERT INTO witnesses (account, note, height, witness)
                        SELECT ?, n.id_note, ?, ? FROM notes n
                        WHERE n.account = ? AND n.cmx = ?",
            )
            .bind(account)
            .bind(height)
            .bind(&w)
            .bind(account)
            .bind(&cmx)
            .execute(&mut **db_tx)
            .await?;
            assert_eq!(r.rows_affected(), 1);
        }
        WarpSyncMessage::Spend(utxo) => {
            // note does not belong to the tx because the tx is spending the note
            // and not creating it, do not join n with t!
            let r = sqlx::query(
                "INSERT INTO spends (id_note, account, height, pool, tx, value)
                    SELECT n.id_note, ?1, t.height, ?2, t.id_tx, ?3 FROM notes n, transactions t
                    WHERE n.account = ?1 AND n.cmx = ?4
                    AND t.txid = ?5 AND t.account = ?1",
            )
            .bind(utxo.account)
            .bind(utxo.pool)
            .bind(-(utxo.value as i64))
            .bind(&utxo.cmx)
            .bind(&utxo.txid)
            .execute(&mut **db_tx)
            .await?;
            debug!("Processing Spend: {:?}", &utxo);
            assert_eq!(r.rows_affected(), 1);
        }
        WarpSyncMessage::Checkpoint(accounts, pool, height) => {
            for a in accounts {
                if has_pool(db_tx, a, pool).await? {
                    sqlx::query(
                        "INSERT OR REPLACE INTO sync_heights(account, pool, height)
                        VALUES (?1, ?2, ?3)",
                    )
                    .bind(a)
                    .bind(pool)
                    .bind(height)
                    .execute(&mut **db_tx)
                    .await?;
                    debug!("Checkpoint for account: {}, height: {}", a, height);
                }
                let _ = tx_progress.send(SyncProgress { height, time: 0 }).await;
            }
        }
        WarpSyncMessage::BlockHeader(block_header) => {
            debug!("Processing BlockHeader: {:?}", block_header);
            // ignore dups because we could have already inserted the block header
            // if a transparent transaction needs it
            // to resolve the time of the transaction
            sqlx::query(
                "INSERT INTO headers (height, hash, time)
                    VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
            )
            .bind(block_header.height)
            .bind(&block_header.hash)
            .bind(block_header.time)
            .execute(&mut **db_tx)
            .await?;
            sqlx::query("UPDATE transactions SET time = ? WHERE height = ?")
                .bind(block_header.time)
                .bind(block_header.height)
                .execute(&mut **db_tx)
                .await?;
        }
        WarpSyncMessage::Commit => {
            // handled in the caller
        }
        WarpSyncMessage::Rewind(accounts, height) => {
            debug!("Discard height: {}", height);
            for account in accounts {
                rewind_sync(network, db_tx, account, height).await?;
            }
        }
        WarpSyncMessage::Error(e) => {
            return Err(e.into());
        }
    }

    Ok(())
}

pub async fn recover_from_partial_sync(
    connection: &mut SqliteConnection,
    accounts: &[u32],
) -> Result<()> {
    for account in accounts {
        let account_heights = sqlx::query(
            "SELECT account, MIN(height) FROM sync_heights
            WHERE account = ?",
        )
        .bind(account)
        .map(|row: SqliteRow| {
            let account: u32 = row.get(0);
            let height: u32 = row.get(1);
            (account, height)
        })
        .fetch_all(&mut *connection)
        .await?;

        for (account, height) in account_heights {
            trim_sync_data(&mut *connection, account, height).await?;
        }
    }

    Ok(())
}

// remove synchronization data (notes, spends, transactions, witnesses) after the given height
// keep the data at the given height
// do not remove headers because they are used by multiple accounts
pub async fn trim_sync_data(
    connection: &mut SqliteConnection,
    account: u32,
    height: u32,
) -> Result<()> {
    let mut db_tx = connection.begin().await?;
    sqlx::query("DELETE FROM notes WHERE height > ? AND account = ?")
        .bind(height)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;
    sqlx::query("DELETE FROM spends WHERE height > ? AND account = ?")
        .bind(height)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;
    sqlx::query("DELETE FROM transactions WHERE height > ? AND account = ?")
        .bind(height)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;
    sqlx::query("DELETE FROM witnesses WHERE height > ? AND account = ?")
        .bind(height)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;
    sqlx::query("DELETE FROM outputs WHERE height > ? AND account = ?")
        .bind(height)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;
    sqlx::query("DELETE FROM memos WHERE height > ? AND account = ?")
        .bind(height)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;
    sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
        .bind(height)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;

    db_tx.commit().await?;
    Ok(())
}

#[cfg(debug_assertions)]
pub async fn check_witness_consistency(connection: &mut SqliteConnection) -> Result<()> {
    let notes = sqlx::query(
    "WITH utxo AS (SELECT * FROM notes n LEFT JOIN spends s ON n.id_note = s.id_note WHERE s.id_note IS NULL),
    db_height AS (SELECT * FROM sync_heights)
    SELECT u.account, u.pool, u.height, u.value, d.height FROM utxo u
    JOIN db_height d ON d.account = u.account AND d.pool = u.pool
    LEFT JOIN witnesses w ON u.id_note = w.note AND w.account = u.account
    AND w.height = d.height
    WHERE w.id_witness IS NULL AND u.pool <> 0 AND u.id_asset IS NULL")
    .map(|r: SqliteRow| {
        let account: u32 = r.get(0);
        let pool: u8 = r.get(1);
        let height: u32 = r.get(2);
        let value: u64 = r.get(3);
        let db_height: u32 = r.get(4);
        (account, pool, height, value, db_height)
    })
    .fetch_all(connection).await?;

    for (account, pool, height, value, db_height) in notes.iter() {
        debug!("Missing witness for note {pool} {height} {value} of account {account} at height {db_height}");
    }
    if !notes.is_empty() {
        anyhow::bail!("Some notes have no witness data. Abort Sync");
    }
    debug!("Db check passed");
    Ok(())
}

#[cfg(not(debug_assertions))]
pub async fn check_witness_consistency(_connection: &mut SqliteConnection) -> Result<()> {
    Ok(())
}

// for each account, find the latest checkpoint before the given height
// and trim the synchronization data to that height
pub async fn rewind_sync(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    height: u32,
) -> Result<()> {
    let prev_height =
        sqlx::query("SELECT MAX(height) FROM witnesses WHERE height < ? AND account = ?")
            .bind(height)
            .bind(account)
            .map(|row: SqliteRow| {
                let height: Option<u32> = row.get(0);
                height
            })
            .fetch_one(&mut *connection)
            .await?;

    if let Some(prev_height) = prev_height {
        trim_sync_data(&mut *connection, account, prev_height).await?;
    } else {
        crate::account::reset_sync(network, &mut *connection, account).await?;
    }

    // then trim the headers because there are no accounts using them
    sqlx::query("DELETE FROM headers WHERE height > ?")
        .bind(height)
        .execute(connection)
        .await?;

    Ok(())
}

pub async fn prune_old_checkpoints(
    connection: &mut SqliteConnection,
    account: u32,
    height: u32,
) -> Result<()> {
    // find the latest checkpoint before the given height
    let checkpoint_height =
        sqlx::query("SELECT MAX(height) FROM witnesses WHERE account = ? AND height < ?")
            .bind(account)
            .bind(height)
            .map(|row: SqliteRow| {
                let height: Option<u32> = row.get(0);
                height
            })
            .fetch_one(&mut *connection)
            .await?;
    // delete all witnesses before the checkpoint height
    if let Some(checkpoint_height) = checkpoint_height {
        sqlx::query("DELETE FROM witnesses WHERE account = ? AND height < ?")
            .bind(account)
            .bind(checkpoint_height)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

pub async fn get_db_height(connection: &mut SqliteConnection, account: u32) -> Result<SyncHeight> {
    // Use an outer join because the time stamp may not be present if we didn't
    // have to scan the chain (i.e. the account is transparent only)
    let (height, time): (u32, u32) = sqlx::query_as(
        "WITH mh AS (SELECT MIN(height) AS min_height
            FROM sync_heights
            WHERE account = ?1)
            SELECT h.height, COALESCE(h.time, 0) FROM headers h
            JOIN mh ON h.height = mh.min_height",
    )
    .bind(account)
    .fetch_one(connection)
    .await?;
    Ok(SyncHeight {
        pool: 0,
        height,
        time,
    })
}

/// Rediscovers transparent addresses the wallet issued but has no rows for — the state a restore
/// leaves behind, where only the account's own address survives. Walks each scope forward, storing
/// an address as soon as the server reports a transaction for it, and gives up once `gap_limit`
/// consecutive unused addresses say the wallet never went further. Returns how many were added.
#[allow(clippy::too_many_arguments)]
pub async fn discover_transparent_addresses(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    end_height: u32,
    gap_limit: u32,
    progress_fn: impl Fn(String),
    cancellation_token: CancellationToken,
) -> Result<u32> {
    let hw = get_account_hw(connection, account).await?;
    let aindex = get_account_aindex(connection, account).await?;
    let account_dindex = get_account_dindex(connection, account).await?;
    let ledger = get_ledger(connection, account).await?;
    let tk = select_account_transparent(connection, account, account_dindex).await?;
    let xvk = tk.xvk;
    let start_height = get_birth_height(connection, account).await?;

    let mut n_added = 0;
    for scope in 0..2 {
        let mut dindex = 0;
        let mut gap = 0;
        while gap <= gap_limit {
            let (pk, taddr) = match xvk.as_ref() {
                Some(xvk) => derive_transparent_address(xvk, scope, dindex, false)?,
                None if hw != 0 => {
                    ledger
                        .get_hw_transparent_address(network, aindex, scope, dindex)
                        .await?
                }
                _ => anyhow::bail!("Sweep needs an xpub key"),
            };
            let taddr = taddr.encode(network);
            progress_fn(taddr.clone());

            tokio::select! {
                _ = cancellation_token.cancelled() => {
                    return Ok(n_added)
                }

                txids = client
                    .taddress_txs(network, &taddr, start_height, end_height)
                    => {
                    let mut txids = txids?;
                    if txids.next().await.transpose()?.is_some() {
                        // The wallet reached this far, so the window reopens from here.
                        gap = 0;
                        let sk = tk
                            .xsk
                            .as_ref()
                            .map(|tsk| derive_transparent_sk(tsk, scope, dindex))
                            .transpose()?;
                        if store_account_transparent_addr(
                            connection, account, scope, dindex, sk, &pk, &taddr, false,
                        )
                        .await?
                        {
                            n_added += 1;
                        }
                    } else {
                        gap += 1;
                    }
                    dindex += 1;
                }
            }
        }
    }
    Ok(n_added)
}

/// Fire-and-forget wrapper: the caller watches the scan through `progress_fn`.
#[allow(clippy::too_many_arguments)]
pub async fn transparent_sweep(
    network: &Network,
    mut connection: PoolConnection<Sqlite>,
    mut client: Client,
    account: u32,
    end_height: u32,
    gap_limit: u32,
    progress_fn: impl Fn(String) + 'static + Send,
    cancellation_token: CancellationToken,
) -> Result<()> {
    let network = *network;
    tokio::spawn(async move {
        discover_transparent_addresses(
            &network,
            &mut connection,
            &mut client,
            account,
            end_height,
            gap_limit,
            progress_fn,
            cancellation_token,
        )
        .await
    });
    Ok(())
}

pub async fn get_heights_without_time(
    connection: &mut SqliteConnection,
    start: u32,
    end: u32,
) -> Result<HashSet<u32>> {
    let mut tx_without_time: HashSet<u32> = sqlx::query(
        "SELECT DISTINCT height FROM transactions WHERE time = 0
        AND height >= ? AND height <= ?",
    )
    .bind(start)
    .bind(end)
    .map(|row: SqliteRow| {
        let height: u32 = row.get(0);
        height
    })
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .collect();

    let synced_heights_without_time = sqlx::query(
        "SELECT sh.height FROM sync_heights sh
        LEFT JOIN headers h ON sh.height = h.height
        WHERE h.time IS NULL AND sh.height > 0",
    )
    .map(|row: SqliteRow| {
        let height: u32 = row.get(0);
        height
    })
    .fetch_all(&mut *connection)
    .await?
    .into_iter();
    tx_without_time.extend(synced_heights_without_time);

    Ok(tx_without_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::{restore, TEST_PHRASE};
    use crate::db::tests::{
        insert_scoped_taddress, insert_scoped_taddress_for_account, memory_db,
        set_pool_sync_height, set_pool_sync_height_for_account, ACCOUNT,
    };
    use crate::net::{BroadcastOutcome, LwdServer};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::async_trait;
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    async fn sync_heights(connection: &mut SqliteConnection) -> Vec<u32> {
        sqlx::query_scalar("SELECT height FROM sync_heights ORDER BY pool")
            .fetch_all(connection)
            .await
            .expect("heights")
    }

    #[tokio::test]
    async fn write_warp_messages_reorg_commits_the_rewind_before_returning_the_error() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        for pool in 0..=2 {
            set_pool_sync_height_for_account(&mut connection, account, pool, 2_000_010).await;
        }
        sqlx::query(
            "INSERT INTO transactions (account, txid, height, time) VALUES (?1, ?2, ?3, 0)",
        )
        .bind(account)
        .bind([7_u8; 32].as_slice())
        .bind(2_000_008_u32)
        .execute(&mut connection)
        .await
        .expect("transaction");
        let key_cache = preload_account_key_cache(&mut connection)
            .await
            .expect("key cache");
        let (tx_progress, _rx_progress) = channel(1);
        let (sender, receiver) = channel(3);

        crate::warp::sync::send_reorg(&sender, vec![account], 2_000_004)
            .await
            .expect("queue reorg");
        sender
            .send(WarpSyncMessage::Error(SyncError::Reorg(2_000_004)))
            .await
            .expect("queue error");
        drop(sender);

        let result = write_warp_messages(
            &Network::Main,
            &mut connection,
            receiver,
            &tx_progress,
            &key_cache,
        )
        .await;

        assert!(result
            .expect_err("reorg")
            .to_string()
            .contains("Reorganization"));
        assert!(sync_heights(&mut connection)
            .await
            .into_iter()
            .all(|height| height < 2_000_010));
        let transactions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transactions")
            .fetch_one(&mut connection)
            .await
            .expect("transaction count");
        assert_eq!(0, transactions);
    }

    /// `transparent_sync` commits pool 0 for the whole range before the shielded pass runs, so a
    /// failure there leaves it ahead. The next pass must rewind it, not skip the missed range.
    #[tokio::test]
    async fn recover_from_partial_sync_rewinds_a_pool_that_ran_ahead() {
        let mut connection = memory_db().await;
        set_pool_sync_height(&mut connection, 0, 200).await;
        set_pool_sync_height(&mut connection, 1, 100).await;
        set_pool_sync_height(&mut connection, 2, 100).await;

        recover_from_partial_sync(&mut connection, &[ACCOUNT])
            .await
            .expect("recover");

        assert_eq!(sync_heights(&mut connection).await, vec![100, 100, 100]);
    }

    /// Without a shielded pool nothing holds the minimum back — the trace the review found.
    #[tokio::test]
    async fn recover_from_partial_sync_keeps_a_lone_transparent_pool_where_it_is() {
        let mut connection = memory_db().await;
        set_pool_sync_height(&mut connection, 0, 200).await;

        recover_from_partial_sync(&mut connection, &[ACCOUNT])
            .await
            .expect("recover");

        assert_eq!(sync_heights(&mut connection).await, vec![200]);
    }

    /// Answers every address with an empty stream, failing on call `fail_at_call` when set —
    /// the shape a mid-account network error takes.
    struct EmptyStreams {
        calls: u32,
        fail_at_call: Option<u32>,
        stream_failure: bool,
    }

    #[async_trait]
    impl LwdServer for EmptyStreams {
        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, _height: u32) -> Result<CompactBlock> {
            unimplemented!()
        }

        type CompactBlockStream = ReceiverStream<Result<CompactBlock>>;
        async fn block_range(
            &mut self,
            _network: &Network,
            _start: u32,
            _end: u32,
        ) -> Result<Self::CompactBlockStream> {
            unimplemented!()
        }

        async fn transaction(
            &mut self,
            _network: &Network,
            _txid: &[u8],
        ) -> Result<(u32, Transaction)> {
            unimplemented!()
        }

        async fn post_transaction(&mut self, _height: u32, _tx: &[u8]) -> Result<BroadcastOutcome> {
            unimplemented!()
        }

        type TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn taddress_txs(
            &mut self,
            _network: &Network,
            _taddress: &str,
            _start: u32,
            _end: u32,
        ) -> Result<Self::TransactionStream> {
            self.calls += 1;
            anyhow::ensure!(
                self.fail_at_call != Some(self.calls),
                "server failed on address {}",
                self.calls
            );
            let (sender, receiver) = channel(2);
            if self.stream_failure {
                sender
                    .send(Ok((101, any_transaction(), 0)))
                    .await
                    .expect("queue transaction");
                sender
                    .send(Err(anyhow::anyhow!("transaction stream failed")))
                    .await
                    .expect("queue error");
            }
            drop(sender);
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }
    }

    async fn two_addresses_at_height(connection: &mut SqliteConnection, height: u32) {
        insert_scoped_taddress(connection, 1, 0, 0, "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt").await;
        insert_scoped_taddress(connection, 2, 0, 1, "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC").await;
        set_pool_sync_height(connection, 0, height).await;
    }

    const OTHER_ACCOUNT: u32 = ACCOUNT + 1;

    /// One address per account, so call N of the fake server belongs to account N.
    async fn two_accounts_at_height(connection: &mut SqliteConnection, height: u32) {
        let accounts = [
            (ACCOUNT, "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt"),
            (OTHER_ACCOUNT, "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC"),
        ];
        for (index, (account, address)) in accounts.into_iter().enumerate() {
            let id_taddress = index as u32 + 1;
            insert_scoped_taddress_for_account(connection, account, id_taddress, 0, 0, address)
                .await;
            set_pool_sync_height_for_account(connection, account, 0, height).await;
        }
    }

    async fn transparent_heights(connection: &mut SqliteConnection) -> Vec<(u32, u32)> {
        sqlx::query_as("SELECT account, height FROM sync_heights WHERE pool = 0 ORDER BY account")
            .fetch_all(connection)
            .await
            .expect("heights")
    }

    async fn scan_to_200(
        connection: &mut SqliteConnection,
        accounts: &[u32],
        fail_at_call: Option<u32>,
    ) -> Result<()> {
        let mut client: Client = Box::new(EmptyStreams {
            calls: 0,
            fail_at_call,
            stream_failure: false,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);

        transparent_sync(
            &Network::Main,
            connection,
            &mut client,
            accounts,
            101,
            200,
            10,
            rx_cancel,
        )
        .await
    }

    /// A failure on a later address must not leave pool 0 at the end of a range the earlier
    /// addresses covered but the later ones never did — those payments are never requested again.
    #[tokio::test]
    async fn transparent_sync_keeps_the_pool_height_when_a_later_address_fails() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;

        let result = scan_to_200(&mut connection, &[ACCOUNT], Some(2)).await;

        assert!(result.is_err());
        assert_eq!(sync_heights(&mut connection).await, vec![100]);
    }

    #[tokio::test]
    async fn transparent_sync_stream_fails_rolls_back_the_transaction_and_height() {
        let mut connection = memory_db().await;
        insert_scoped_taddress(
            &mut connection,
            1,
            0,
            0,
            "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt",
        )
        .await;
        set_pool_sync_height(&mut connection, 0, 100).await;
        let mut client: Client = Box::new(EmptyStreams {
            calls: 0,
            fail_at_call: None,
            stream_failure: true,
        });
        let (_cancel, cancellation) = broadcast::channel(1);

        let result = transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[ACCOUNT],
            101,
            200,
            10,
            cancellation,
        )
        .await;

        assert!(result
            .expect_err("stream failure")
            .to_string()
            .contains("transaction stream failed"));
        let transactions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transactions")
            .fetch_one(&mut connection)
            .await
            .expect("transaction count");
        assert_eq!(0, transactions);
        assert_eq!(sync_heights(&mut connection).await, vec![100]);
    }

    #[tokio::test]
    async fn transparent_sync_advances_the_pool_height_once_every_address_is_scanned() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;

        scan_to_200(&mut connection, &[ACCOUNT], None)
            .await
            .expect("sync");

        assert_eq!(sync_heights(&mut connection).await, vec![200]);
    }

    /// Every scanned account is checkpointed, not just the first one — the rest would silently
    /// re-request the range they already covered, or never move at all.
    #[tokio::test]
    async fn transparent_sync_advances_every_scanned_account() {
        let mut connection = memory_db().await;
        two_accounts_at_height(&mut connection, 100).await;

        scan_to_200(&mut connection, &[ACCOUNT, OTHER_ACCOUNT], None)
            .await
            .expect("sync");

        assert_eq!(
            transparent_heights(&mut connection).await,
            vec![(ACCOUNT, 200), (OTHER_ACCOUNT, 200)]
        );
    }

    /// The whole range is one checkpoint: a failure on the second account also withdraws the
    /// first one's, because nothing proves the range is fully covered until every address is.
    #[tokio::test]
    async fn transparent_sync_keeps_every_account_height_when_a_later_account_fails() {
        let mut connection = memory_db().await;
        two_accounts_at_height(&mut connection, 100).await;

        let result = scan_to_200(&mut connection, &[ACCOUNT, OTHER_ACCOUNT], Some(2)).await;

        assert!(result.is_err());
        assert_eq!(
            transparent_heights(&mut connection).await,
            vec![(ACCOUNT, 100), (OTHER_ACCOUNT, 100)]
        );
    }

    /// An account with a pool row but no address has nothing to scan, so its height stays put —
    /// advancing it would checkpoint a range no address ever covered.
    #[tokio::test]
    async fn transparent_sync_leaves_an_account_without_addresses_where_it_is() {
        let mut connection = memory_db().await;
        set_pool_sync_height(&mut connection, 0, 100).await;

        scan_to_200(&mut connection, &[ACCOUNT], None)
            .await
            .expect("sync");

        assert_eq!(
            transparent_heights(&mut connection).await,
            vec![(ACCOUNT, 100)]
        );
    }

    /// Answers with a transaction on the calls listed in `used_at_calls` and with an empty stream
    /// otherwise — what a rediscovery scan sees when only some derived addresses were ever paid.
    struct UsedAtCalls {
        calls: Arc<AtomicU32>,
        used_at_calls: Vec<u32>,
        fail_at_call: Option<u32>,
    }

    /// The smallest transaction that parses: the scan only asks whether the stream has an item.
    fn any_transaction() -> Transaction {
        // v4 header and version group id, then zeroes: no inputs, outputs, spends or joinsplits.
        let raw =
            hex::decode("0400008085202f89000000000000000000000000000000000000000000").expect("hex");
        Transaction::read(&mut &raw[..], BranchId::Sapling).expect("transaction")
    }

    #[async_trait]
    impl LwdServer for UsedAtCalls {
        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, _height: u32) -> Result<CompactBlock> {
            unimplemented!()
        }

        type CompactBlockStream = ReceiverStream<Result<CompactBlock>>;
        async fn block_range(
            &mut self,
            _network: &Network,
            _start: u32,
            _end: u32,
        ) -> Result<Self::CompactBlockStream> {
            unimplemented!()
        }

        async fn transaction(
            &mut self,
            _network: &Network,
            _txid: &[u8],
        ) -> Result<(u32, Transaction)> {
            unimplemented!()
        }

        async fn post_transaction(&mut self, _height: u32, _tx: &[u8]) -> Result<BroadcastOutcome> {
            unimplemented!()
        }

        type TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn taddress_txs(
            &mut self,
            _network: &Network,
            _taddress: &str,
            _start: u32,
            _end: u32,
        ) -> Result<Self::TransactionStream> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            let (sender, receiver) = channel(2);
            if self.fail_at_call == Some(call) {
                sender
                    .send(Err(anyhow::anyhow!("discovery stream failed")))
                    .await
                    .expect("queue error");
            } else if self.used_at_calls.contains(&call) {
                sender
                    .send(Ok((1, any_transaction(), 0)))
                    .await
                    .expect("queue transaction");
            }
            drop(sender);
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }
    }

    async fn receive_dindexes(connection: &mut SqliteConnection, account: u32) -> Vec<u32> {
        sqlx::query_scalar(
            "SELECT dindex FROM transparent_address_accounts
            WHERE account = ? AND scope = 0 ORDER BY dindex",
        )
        .bind(account)
        .fetch_all(connection)
        .await
        .expect("addresses")
    }

    /// Runs a rediscovery scan over a freshly restored account, whose only transparent row is the
    /// account's own address. Returns how many addresses it added and how many calls it made.
    async fn discover(
        connection: &mut SqliteConnection,
        account: u32,
        gap_limit: u32,
        used_at_calls: Vec<u32>,
    ) -> (u32, u32) {
        let calls = Arc::new(AtomicU32::new(0));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: calls.clone(),
            used_at_calls,
            fail_at_call: None,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            connection,
            &mut client,
            account,
            2_000_100,
            gap_limit,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        (n_added, calls.load(Ordering::Relaxed))
    }

    /// After a restore the wallet has no row for a one-time address it once handed out, so the
    /// funds paid to it are invisible until the scan finds the address again.
    #[tokio::test]
    async fn discover_transparent_addresses_restores_an_address_that_received_funds() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0]);

        let (n_added, _) = discover(&mut connection, account, 2, vec![3]).await;

        assert_eq!(n_added, 1);
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0, 2]);
    }

    /// A used address reopens the window: stopping `gap_limit` addresses after the last hit is
    /// what keeps a wallet that spaced its addresses out from losing the later ones.
    #[tokio::test]
    async fn discover_transparent_addresses_keeps_scanning_past_a_used_address() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let (n_added, _) = discover(&mut connection, account, 1, vec![1, 3, 5]).await;

        assert_eq!(n_added, 2, "dindex 0 is the account's own address");
        assert_eq!(
            receive_dindexes(&mut connection, account).await,
            vec![0, 2, 4]
        );
    }

    /// Nothing bounds the derivation but the gap, so an unused account must stop after
    /// `gap_limit + 1` addresses in each of the two scopes rather than run forever.
    #[tokio::test]
    async fn discover_transparent_addresses_stops_after_the_gap_limit() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let (n_added, calls) = discover(&mut connection, account, 2, vec![]).await;

        assert_eq!(n_added, 0);
        assert_eq!(calls, 6, "three addresses in each scope");
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0]);
    }

    #[tokio::test]
    async fn discover_transparent_addresses_stream_fails_returns_error_without_storing_address() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_at_call: Some(1),
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result
            .expect_err("stream failure")
            .to_string()
            .contains("discovery stream failed"));
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0]);
    }
}
