use anyhow::{Context as _, Result};
use sqlx::SqliteConnection;
use sqlx::{sqlite::SqliteRow, Row};
use std::collections::HashMap;
use tokio::sync::broadcast;
use tokio::sync::mpsc::channel;
use tokio::sync::MutexGuard;
use tracing::debug;
use zcash_transparent::address::TransparentAddress;

use crate::api::account::get_ledger;
use crate::api::coin::{acquire_with_retry, Coin, Network, DB_STATS};
use crate::api::sync::{CANCEL_SYNC, SYNCING};
use crate::budget::merge_pending_txs;

use crate::db::{
    advance_backfilled_height, highest_stored_dindex, raise_catch_up_debt, store_block_header,
    taddress_scope_dindex, transparent_address_is_used, transparent_address_row,
    transparent_addresses_to_scan, transparent_backfilled_height, transparent_incarnation,
    transparent_trim_counter, write_transparent_coverage,
};
use crate::io::SyncHeight;
use crate::{Client, Sink};
use std::{collections::HashSet, mem, time::Duration};

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
use futures::future::join_all;
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

    let res = async {
        let (tx_progress, mut rx_progress) = channel::<SyncProgress>(1);
        tokio::spawn(async move {
            while let Some(p) = rx_progress.recv().await {
                let _ = progress.send(p).await;
            }
        });
        let pool = c.get_pool()?;
        let mut client = c.client().await?;
        sync_height_ranges(
            &network,
            &pool,
            &mut connection,
            &mut client,
            &accounts,
            current_height,
            actions_per_sync,
            transparent_limit,
            noskip_details,
            &tx_progress,
            &tx_cancel,
        )
        .await?;

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

/// One sync cycle: recovery, then every height range the accounts need, transparent pass before
/// shielded pass. Separate from `synchronize_impl` so the cycle can run against any `LwdServer`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_height_ranges(
    network: &Network,
    pool: &SqlitePool,
    connection: &mut SqliteConnection,
    client: &mut Client,
    accounts: &[u32],
    current_height: u32,
    actions_per_sync: u32,
    transparent_limit: u32,
    noskip_details: bool,
    tx_progress: &Sender<SyncProgress>,
    tx_cancel: &broadcast::Sender<()>,
) -> Result<()> {
    recover_from_partial_sync(&mut *connection, accounts).await?;

    let mut account_heights = HashMap::new();
    let mut account_use_internal = HashMap::<u32, bool>::new();
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
        } else {
            debug!(
                "Account {} - NO sync_heights entry found, will be skipped",
                account
            );
        }
    }

    let mut unique_heights: Vec<u32> = account_heights.values().cloned().collect();
    unique_heights.sort_unstable();
    unique_heights.dedup();
    debug!(
        "Unique sync start heights for accounts: {:?}",
        unique_heights
    );

    for (i, &start_height) in unique_heights.iter().enumerate() {
        let end_height = if i + 1 < unique_heights.len() {
            unique_heights[i + 1] - 1
        } else {
            current_height
        };

        let accounts_to_sync = account_heights
            .iter()
            .filter(|&(_, &height)| height <= start_height)
            .map(|(&account, _)| (account, account_use_internal[&account]))
            .collect::<Vec<_>>();
        if accounts_to_sync.is_empty() {
            continue;
        }
        debug!(
            "Syncing accounts {:?} from height {} to {}",
            accounts_to_sync.iter().map(|(a, _)| a).collect::<Vec<_>>(),
            start_height,
            end_height
        );
        if start_height > end_height {
            debug!(
                "Skipping sync: start_height ({}) > end_height ({}), wallet is ahead of network",
                start_height, end_height
            );
            return Ok(());
        }

        let account_ids = accounts_to_sync
            .iter()
            .map(|(account, _)| *account)
            .collect::<Vec<_>>();
        transparent_sync(
            network,
            &mut *connection,
            &mut *client,
            &account_ids,
            start_height,
            end_height,
            transparent_limit,
            tx_cancel.subscribe(),
        )
        .await?;

        shielded_sync(
            network,
            pool,
            &mut *client,
            &accounts_to_sync,
            start_height,
            end_height,
            actions_per_sync,
            tx_progress.clone(),
            tx_cancel.subscribe(),
        )
        .await?;

        let heights_without_time =
            get_heights_without_time(&mut *connection, start_height, end_height).await?;
        fill_missing_block_times(
            &mut *connection,
            &mut *client,
            network,
            heights_without_time,
        )
        .await?;

        for (account, _) in &accounts_to_sync {
            account_heights.insert(*account, end_height);
            if !noskip_details {
                crate::memo::fetch_tx_details(network, &mut *connection, &mut *client, *account)
                    .await?;
            }
        }
        debug!(
            "Sync completed for height range {}-{}",
            start_height, end_height
        );
    }

    Ok(())
}

/// One address's window, decoded and ready to write. Nothing is read from the server while the
/// ingest transaction is open, so a caller that drops the walk cannot take a report down with it.
#[derive(Default)]
struct WindowRows {
    transactions: Vec<(Vec<u8>, u32)>,
    /// Transaction, height, nullifier, value.
    notes: Vec<(Vec<u8>, u32, Vec<u8>, i64)>,
    /// Transaction, height, the outpoint a transparent input spends.
    vins: Vec<(Vec<u8>, u32, Vec<u8>)>,
}

impl WindowRows {
    fn at_or_below(mut self, height: u32) -> Self {
        self.transactions.retain(|(_, h)| *h <= height);
        self.notes.retain(|(_, h, _, _)| *h <= height);
        self.vins.retain(|(_, h, _)| *h <= height);
        self
    }
}

/// Takes one address's whole answer off the stream, owing every transaction it carries. A stream
/// item that is itself an error is the server's failure, not the database's, and stays
/// distinguishable so the caller can narrow the window instead of giving up. The ledger is
/// published at the one point the stream can park, because that is where a caller drops the walk:
/// a payment this window consumed but never wrote down would go with it, and a retry omitting it
/// would certify the range that carried it. A replayed `first` was already owed in `unsettled` by
/// `fetch_window`; only what this function pulls off the stream itself is recorded here.
#[allow(clippy::too_many_arguments)]
async fn drain_transparent_window(
    my_address: &TransparentAddress,
    first: Option<Result<(u32, zcash_primitives::transaction::Transaction, usize)>>,
    txs: &mut Receiver<Result<(u32, zcash_primitives::transaction::Transaction, usize)>>,
    lo: u32,
    hi: u32,
) -> Result<WindowRows, BackfillError> {
    let mut rows = WindowRows::default();
    let mut next = first;
    loop {
        let item = match next.take() {
            Some(item) => item,
            None => match txs.recv().await {
                Some(item) => item,
                None => break,
            },
        };
        let (height, transaction, _) = item.map_err(BackfillError::Fetch)?;
        // The height is the server's word: a note, a marker or a catch-up debt written from a
        // height nobody asked for would outlive the endpoint that lied about it.
        if !(lo..=hi).contains(&height) {
            return Err(BackfillError::Fetch(anyhow::anyhow!(
                "transaction height {height} outside the requested window [{lo}, {hi}]"
            )));
        }
        let txid = transaction.txid().as_ref().to_vec();
        rows.transactions.push((txid.clone(), height));
        if rows.transactions.len() > MAX_BUFFERED_TXS {
            return Err(BackfillError::WindowFull(anyhow::anyhow!(
                "the server streamed more transactions than one window can buffer"
            )));
        }

        let Some(transparent_bundle) = transaction.transparent_bundle() else {
            continue;
        };
        for vin in transparent_bundle.vin.iter() {
            // The "nullifier" of a transparent input is the outpoint it spends.
            let mut nf = vec![];
            vin.prevout().write(&mut nf).map_err(db_error)?;
            rows.vins.push((txid.clone(), height, nf));
            if rows.vins.len() > MAX_BUFFERED_VINS {
                return Err(BackfillError::WindowFull(anyhow::anyhow!(
                    "the server streamed more transparent inputs than one window can buffer"
                )));
            }
        }
        for (i, vout) in transparent_bundle.vout.iter().enumerate() {
            if vout.recipient_address().as_ref() != Some(my_address) {
                continue;
            }
            let mut nf = txid.clone();
            nf.extend_from_slice(&(i as u32).to_le_bytes());
            rows.notes
                .push((txid.clone(), height, nf, vout.value().into_u64() as i64));
            if rows.notes.len() > MAX_BUFFERED_NOTES {
                return Err(BackfillError::WindowFull(anyhow::anyhow!(
                    "the server streamed more transparent outputs than one window can buffer"
                )));
            }
        }
    }
    Ok(rows)
}

/// Writes what the drain decoded into `transactions`/`notes`/`spends`. Spends are resolved last,
/// so a spend the stream delivered before the note it spends is not silently dropped.
async fn write_transparent_window(
    connection: &mut SqliteConnection,
    account: u32,
    address_row: &(u32, String),
    rows: &WindowRows,
    used: bool,
) -> Result<(), BackfillError> {
    // Never cleared: a trim deletes notes, not this, so "used once" survives every fork and the
    // selector cannot hand the address out again.
    if used {
        sqlx::query(
            "UPDATE transparent_address_accounts SET seen_used = TRUE WHERE id_taddress = ?",
        )
        .bind(address_row.0)
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    }
    for (txid, height) in &rows.transactions {
        sqlx::query("INSERT INTO transactions (account, txid, height, time) VALUES (?, ?, ?, 0) ON CONFLICT DO NOTHING")
            .bind(account)
            .bind(txid)
            .bind(height)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
    }

    for (txid, height, nf, value) in &rows.notes {
        sqlx::query(
            "INSERT INTO notes (account, height, pool, tx, taddress, nullifier, value)
            SELECT ?, ?, 0, tx.id_tx, ?, ?, ? FROM transactions tx WHERE tx.txid = ?
            AND account = ? ON CONFLICT DO NOTHING",
        )
        .bind(account)
        .bind(height)
        .bind(address_row.0)
        .bind(nf)
        .bind(value)
        .bind(txid)
        .bind(account)
        .execute(&mut *connection)
        .await
        .map_err(db_error)?;
    }

    for (txid, height, nf) in &rows.vins {
        let row: Option<(u32, i64)> = sqlx::query_as(
            "SELECT id_note, value FROM notes WHERE account = ?1 AND nullifier = ?2",
        )
        .bind(account)
        .bind(nf)
        .fetch_optional(&mut *connection)
        .await
        .map_err(db_error)?;

        if let Some((id, amount)) = row {
            sqlx::query(
                "INSERT INTO spends (account, id_note, pool, tx, height, value)
                SELECT ?, ?, 0, tx.id_tx, ?, ? FROM transactions tx WHERE tx.txid = ?
                AND account = ? ON CONFLICT DO NOTHING",
            )
            .bind(account)
            .bind(id)
            .bind(height)
            .bind(-amount)
            .bind(txid)
            .bind(account)
            .execute(&mut *connection)
            .await
            .map_err(db_error)?;
        }
    }

    Ok(())
}

/// One address's window: everything that talks to the server, so a single deadline covers all of
/// it. The answer is taken off the stream first and written afterwards, in one database
/// transaction: a failure anywhere in the window leaves nothing behind.
#[allow(clippy::too_many_arguments)]
async fn sync_address_window(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    address_row: &(u32, String),
    my_address: &TransparentAddress,
    start_height: u32,
    end_height: u32,
    rx_cancel: &mut broadcast::Receiver<()>,
) -> Result<(), BackfillError> {
    let mut txs = client
        .taddress_txs(network, &address_row.1, start_height, end_height)
        .await
        .map_err(BackfillError::Fetch)?
        .into_inner();

    let rows = tokio::select! {
        _ = rx_cancel.recv() => {
            debug!("Canceling sync");
            return Err(BackfillError::Cancelled);
        }
        result = drain_transparent_window(my_address, None, &mut txs, start_height, end_height) => result?,
    };
    let mut db_tx = connection.begin().await.map_err(db_error)?;
    let used = !rows.transactions.is_empty();
    write_transparent_window(&mut db_tx, account, address_row, &rows, used).await?;
    db_tx.commit().await.map_err(db_error)?;

    // From the database, not from this stream: an earlier pass can have committed a transaction it
    // never managed to date, and this pass moves the marker past it.
    let heights =
        heights_of_transactions_without_time(connection, Some(account), start_height, end_height)
            .await
            .map_err(db_error)?;
    fill_missing_block_times(connection, client, network, heights).await?;

    Ok(())
}

/// Records that one window is now covered for one address.
async fn advance_address_marker(
    connection: &mut SqliteConnection,
    account: u32,
    birth_height: u32,
    id_taddress: u32,
    covered_from: u32,
    through: u32,
) -> Result<()> {
    let (scope, dindex) = taddress_scope_dindex(connection, id_taddress).await?;
    advance_backfilled_height(
        connection,
        account,
        birth_height,
        scope,
        dindex,
        covered_from,
        through,
    )
    .await
}

/// One address's whole range, in windows. The range spans the account's stored height to the tip,
/// which on an old wallet is millions of blocks, so a deadline over the whole of it would fail
/// every pass forever: a stalled or failed window is halved instead, exactly as a discovery window
/// is, and only a server that fails on the floor width fails the sync.
///
/// Above the seam every write is scratch: recovery trims it at the head of the next tick, so a
/// window may commit as it completes. Below the seam — the range a row that fell behind the pool
/// still owes — nothing cleans up, so that part lands in one transaction and commits only once a
/// fresh read of the tick's anchor confirms the chain it was fetched from.
#[allow(clippy::too_many_arguments)]
async fn sync_address_range(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    address_row: &(u32, String),
    my_address: &TransparentAddress,
    marker: Option<u32>,
    start_height: u32,
    end_height: u32,
    anchor: &[u8],
    rx_cancel: &mut broadcast::Receiver<()>,
) -> Result<()> {
    // A row that fell behind the pool owes `(marker, pool]` too; from the driver's height the
    // marker write would be non-contiguous and dropped, and the row could never catch up. History
    // cannot predate the account, so a marker clamped to 0 by `reset_sync` still starts at birth.
    let birth_height = get_birth_height(connection, account).await?;
    let lo = marker
        .map_or(start_height, |marker| start_height.min(marker + 1))
        .max(birth_height);
    let seam = account_seam(connection, account).await?;
    if lo <= seam {
        let mut tx = connection.begin().await?;
        walk_windows(
            network,
            &mut tx,
            client,
            account,
            birth_height,
            address_row,
            my_address,
            lo,
            seam,
            rx_cancel,
        )
        .await?;
        if chain_anchor(client, end_height, rx_cancel).await? != anchor {
            anyhow::bail!("chain reorganised during the transparent walk");
        }
        tx.commit().await?;
    }
    walk_windows(
        network,
        connection,
        client,
        account,
        birth_height,
        address_row,
        my_address,
        lo.max(seam + 1),
        end_height,
        rx_cancel,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn walk_windows(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    birth_height: u32,
    address_row: &(u32, String),
    my_address: &TransparentAddress,
    mut lo: u32,
    end_height: u32,
    rx_cancel: &mut broadcast::Receiver<()>,
) -> Result<()> {
    let mut window = end_height.saturating_sub(lo).saturating_add(1);
    let mut marker_lo = lo;
    while lo <= end_height {
        let hi = lo.saturating_add(window - 1).min(end_height);
        let failure = match tokio::time::timeout(
            WINDOW_TIMEOUT,
            sync_address_window(
                network,
                &mut *connection,
                &mut *client,
                account,
                address_row,
                my_address,
                lo,
                hi,
                rx_cancel,
            ),
        )
        .await
        {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e),
            Err(_elapsed) => Some(BackfillError::Timeout { lo, hi }),
        };
        match failure {
            None => {
                advance_address_marker(
                    connection,
                    account,
                    birth_height,
                    address_row.0,
                    marker_lo,
                    hi,
                )
                .await?;
                if hi == end_height {
                    break;
                }
                marker_lo = hi + 1;
                lo = hi + 1;
            }
            Some(
                BackfillError::Fetch(_)
                | BackfillError::Timeout { .. }
                | BackfillError::WindowFull(_),
            ) if window > MIN_BACKFILL_WINDOW => {
                window = (window / 2).max(MIN_BACKFILL_WINDOW);
            }
            Some(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// The backend's hash of `height`, bounded like a window: the read runs under `SYNCING`, and a
/// server that accepts the request and never answers would otherwise hold every locked API.
async fn chain_anchor(
    client: &mut Client,
    height: u32,
    rx_cancel: &mut broadcast::Receiver<()>,
) -> Result<Vec<u8>> {
    tokio::select! {
        _ = rx_cancel.recv() => anyhow::bail!("chain anchor read cancelled"),
        anchor = tokio::time::timeout(WINDOW_TIMEOUT, client.chain_anchor(height)) => {
            anchor.map_err(|_| anyhow::anyhow!("chain anchor read at {height} timed out after {WINDOW_TIMEOUT:?}"))?
        }
    }
}

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
    if addresses.is_empty() {
        return Ok(());
    }

    // Two reads of the backend's chain bracket the walk: a fork landing between two windows can
    // move a payment into a range already answered, and the pool must not pass it.
    let anchor = chain_anchor(client, end_height, &mut rx_cancel).await?;
    for (account, address_row) in addresses.iter() {
        let my_address = TransparentAddress::decode(network, &address_row.1)?;
        debug!(
            "transparent_sync: scanning account {} address {}",
            account, address_row.1
        );
        let marker = transparent_backfilled_height(connection, address_row.0).await?;
        sync_address_range(
            network,
            &mut *connection,
            &mut *client,
            *account,
            address_row,
            &my_address,
            marker,
            start_height,
            end_height,
            &anchor,
            &mut rx_cancel,
        )
        .await?;
    }
    if chain_anchor(client, end_height, &mut rx_cancel).await? != anchor {
        anyhow::bail!("chain reorganised during the transparent walk");
    }

    // Only once every address of the range has been scanned: moving the height earlier strands
    // whatever a mid-account failure left unscanned, and that range is never requested again.
    // A catch-up debt is paid by the row's own marker alone, never by any height the server named.
    let mut db_tx = connection.begin().await?;
    for account in scanned_accounts.iter() {
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ? AND pool = 0")
            .bind(end_height)
            .bind(account)
            .execute(&mut *db_tx)
            .await?;
        sqlx::query(
            "UPDATE transparent_address_accounts SET catch_up_owed_through = NULL
            WHERE account = ? AND catch_up_owed_through IS NOT NULL
            AND backfilled_height >= catch_up_owed_through",
        )
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

    let mut connection = acquire_with_retry(pool, &DB_STATS).await?;
    // get the list of transaction heights for which the time is 0
    // because raw transactions do not have timestamp (it comes from the block header)
    let heights_without_time = get_heights_without_time(&mut connection, start, end).await?;

    let mut writer_connection = acquire_with_retry(pool, &DB_STATS).await?;
    // Key derivations happen once upfront — no per-note DB queries in the hot path.
    let key_cache = preload_account_key_cache(&mut writer_connection).await?;
    let network = *network;
    let reopen_client = client.duplicate();
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
            reopen_client,
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
    // The notes deleted below are what paid their addresses' catch-up; deleting them re-owes it,
    // so the next tick's scan set carries exactly the addresses this trim empties.
    sqlx::query(
        "UPDATE transparent_address_accounts SET catch_up_owed_through = MAX(
            COALESCE(catch_up_owed_through, 0),
            (SELECT MAX(height) FROM notes WHERE taddress = id_taddress AND height > ?1 AND pool = 0))
        WHERE id_taddress IN
            (SELECT taddress FROM notes WHERE height > ?1 AND account = ?2 AND pool = 0)",
    )
    .bind(height)
    .bind(account)
    .execute(&mut *db_tx)
    .await?;
    let mut trimmed = false;
    for statement in [
        "DELETE FROM notes WHERE height > ? AND account = ?",
        "DELETE FROM spends WHERE height > ? AND account = ?",
        "DELETE FROM transactions WHERE height > ? AND account = ?",
        "DELETE FROM witnesses WHERE height > ? AND account = ?",
        "DELETE FROM outputs WHERE height > ? AND account = ?",
        "DELETE FROM memos WHERE height > ? AND account = ?",
    ] {
        let r = sqlx::query(statement)
            .bind(height)
            .bind(account)
            .execute(&mut *db_tx)
            .await?;
        trimmed |= r.rows_affected() > 0;
    }
    // A marker above the trim height would otherwise still satisfy discovery's `>= seam` skip
    // term, over history this trim just deleted.
    let clamp = sqlx::query(
        "UPDATE transparent_address_accounts SET backfilled_height = ?
        WHERE account = ? AND backfilled_height > ?",
    )
    .bind(height)
    .bind(account)
    .bind(height)
    .execute(&mut *db_tx)
    .await?;
    trimmed |= clamp.rows_affected() > 0;

    if trimmed {
        sqlx::query(
            "INSERT INTO props(key, value) VALUES ('tcov_trim:' || ?, '1')
            ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)",
        )
        .bind(account)
        .execute(&mut *db_tx)
        .await?;
    }

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
        // A walk already in flight was started against the chain this rewind discards.
        crate::db::retire_transparent_walks(&mut *connection, account).await?;
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

/// Failure of one backfill window's network request. `Fetch` is the initial `taddress_txs` call
/// itself failing (e.g. the server rejecting the window's width) and may be retried narrower;
/// `Db` covers everything after a successful request — a stream item, ingestion, or block-time
/// failure — and must propagate immediately without narrowing the window; `Timeout` is the whole
/// window outliving `WINDOW_TIMEOUT` while `SYNCING` was held and is retried narrower like
/// `Fetch`, because a wide window is exactly what a slow-but-honest server stalls on; `WindowFull`
/// is one answer carrying more transactions, inputs or outputs than a single window may buffer,
/// which narrowing is the only thing that fixes; `Cancelled` is the caller's cancellation token firing mid-ingest, which the
/// walk turns into a clean stop rather than an error.
enum BackfillError {
    Fetch(anyhow::Error),
    Db(anyhow::Error),
    Timeout { lo: u32, hi: u32 },
    WindowFull(anyhow::Error),
    Cancelled,
}

/// Stores the address and hands back the row it now has, so a caller needing the row does not
/// repeat the lookup.
async fn store_and_read_transparent_row(
    connection: &mut SqliteConnection,
    account: u32,
    scope: u32,
    dindex: u32,
    sk: Option<Vec<u8>>,
    pk: &[u8],
    taddr: &str,
) -> Result<Option<(u32, String)>> {
    store_account_transparent_addr(connection, account, scope, dindex, sk, pk, taddr, false)
        .await?;
    transparent_address_row(connection, account, scope, dindex).await
}

/// Everything that is not a network round-trip: the walk must propagate it as-is rather than
/// blame the server and narrow the window.
fn db_error<E: Into<anyhow::Error>>(error: E) -> BackfillError {
    BackfillError::Db(error.into())
}

impl From<BackfillError> for anyhow::Error {
    fn from(error: BackfillError) -> Self {
        match error {
            BackfillError::Fetch(e) => e,
            BackfillError::Db(e) => e,
            BackfillError::Timeout { lo, hi } => {
                anyhow::anyhow!("backfill window [{lo}, {hi}] timed out after {WINDOW_TIMEOUT:?}")
            }
            BackfillError::WindowFull(e) => e,
            BackfillError::Cancelled => anyhow::anyhow!("backfill cancelled"),
        }
    }
}

/// A window narrowed by repeated `Fetch` failures never shrinks past this floor; a floor request
/// that still fails propagates instead of narrowing further.
const MIN_BACKFILL_WINDOW: u32 = 1_000;

/// However many candidates the caller asks for at once, a discovery walk never has more than this
/// many requests in flight on its one connection.
const MAX_DISCOVERY_CONCURRENCY: u32 = 32;

/// The `Ok` half of `fetch_window`: a window's first item, the rest of its stream, and the seam
/// the request was made under: outside `SYNCING` a concurrent sync can move it onto another fork,
/// so the ingest compares seams and asks again instead of committing a reply from a chain it left.
struct Fetched {
    seam: u32,
    first: Option<(u32, zcash_primitives::transaction::Transaction, usize)>,
    rx: Receiver<Result<(u32, zcash_primitives::transaction::Transaction, usize)>>,
}

/// Caps how long one address's one window may hold `SYNCING` for, in a discovery walk and in the
/// regular sync alike. Held per window rather than for a whole run, so a stalled server cannot
/// starve `synchronize_impl`'s sync ticks or freeze address selection behind a run that may
/// otherwise never end.
const WINDOW_TIMEOUT: Duration = Duration::from_secs(120);

/// A window buffers every row it decodes until the stream drains, so a server that never stops
/// sending would grow those buffers until the process dies. Orders of magnitude above any real
/// address's history in one window: a stream that exceeds any of them is a misbehaving server, and
/// the window is narrowed or the sync fails rather than the wallet being killed.
#[cfg(not(test))]
const MAX_BUFFERED_TXS: usize = 50_000;
#[cfg(test)]
const MAX_BUFFERED_TXS: usize = 8;
#[cfg(not(test))]
const MAX_BUFFERED_VINS: usize = 200_000;
#[cfg(test)]
const MAX_BUFFERED_VINS: usize = 4;
#[cfg(not(test))]
const MAX_BUFFERED_NOTES: usize = 200_000;
/// Above `MAX_BUFFERED_TXS`, so a flood of one-output payments trips the transaction cap first.
#[cfg(test)]
const MAX_BUFFERED_NOTES: usize = 12;

/// Requests one window and consumes its first item as an existence probe. An item that is itself
/// an error proves nothing about the address, so it stays a fetch failure rather than an empty
/// window. The receiver still carries the rest of the stream, replayed through
/// `drain_transparent_window`'s `first` parameter. Both awaits are cancellable: a request the
/// server never answers would otherwise hold `SYNCING` for the whole window deadline after the
/// caller asked to stop.
async fn fetch_window(
    client: &mut Client,
    network: &Network,
    taddr: &str,
    lo: u32,
    hi: u32,
    seam: u32,
    cancellation_token: &CancellationToken,
) -> Result<Fetched, BackfillError> {
    tokio::select! {
        _ = cancellation_token.cancelled() => Err(BackfillError::Cancelled),
        result = async {
            let mut rx = client
                .taddress_txs(network, taddr, lo, hi)
                .await
                .map_err(BackfillError::Fetch)?
                .into_inner();
            let first = match rx.recv().await {
                Some(Ok(item)) => Some(item),
                Some(Err(e)) => return Err(BackfillError::Fetch(e)),
                None => None,
            };
            Ok(Fetched { seam, first, rx })
        } => result,
    }
}

/// `MIN(sync_heights)` — the seam. Everything above it is scratch that `recover_from_partial_sync`
/// deletes at the head of the next sync, so discovery writes nothing there.
async fn account_seam(connection: &mut SqliteConnection, account: u32) -> Result<u32> {
    let seam: Option<u32> =
        sqlx::query_scalar("SELECT MIN(height) FROM sync_heights WHERE account = ?")
            .bind(account)
            .fetch_one(&mut *connection)
            .await?;
    seam.context("account has no sync_heights row")
}

/// Ingests one window's stream up to the seam and, once ingestion and block-time enrichment both
/// succeed and `intact` says nothing trimmed the rows this walk already committed, advances the
/// address's backfill marker to `min(hi, seam)` and reports it certified. What the stream carried
/// above the seam is evidence only: it proves the address used and raises the row's catch-up
/// debt for `transparent_sync` to pay, and is otherwise dropped rather than written where the
/// next recovery would delete it. Block-time heights are re-derived from the database rather than
/// taken from the stream, so an earlier committed-but-undated transaction in the same range is
/// repaired too.
#[allow(clippy::too_many_arguments)]
async fn ingest_backfill_window(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    birth_height: u32,
    address_row: &(u32, String),
    my_address: &TransparentAddress,
    scope: u32,
    dindex: u32,
    marker_lo: u32,
    lo: u32,
    hi: u32,
    seam: u32,
    first: Option<Result<(u32, zcash_primitives::transaction::Transaction, usize)>>,
    rx: &mut Receiver<Result<(u32, zcash_primitives::transaction::Transaction, usize)>>,
    intact: bool,
    cancellation_token: &CancellationToken,
) -> Result<bool, BackfillError> {
    let rows = tokio::select! {
        _ = cancellation_token.cancelled() => Err(BackfillError::Cancelled),
        result = drain_transparent_window(my_address, first, rx, lo, hi) => result,
    }?;
    let used = !rows.transactions.is_empty();
    let owed_through = rows
        .transactions
        .iter()
        .map(|(_, height)| *height)
        .filter(|height| *height > seam)
        .max();
    let rows = rows.at_or_below(seam);

    let mut db_tx = connection.begin().await.map_err(db_error)?;
    write_transparent_window(&mut db_tx, account, address_row, &rows, used).await?;
    if let Some(through) = owed_through {
        raise_catch_up_debt(&mut db_tx, address_row.0, through)
            .await
            .map_err(db_error)?;
    }
    db_tx.commit().await.map_err(db_error)?;

    let through = hi.min(seam);
    let heights = heights_of_transactions_without_time(connection, Some(account), lo, through)
        .await
        .map_err(db_error)?;
    fill_missing_block_times(connection, client, network, heights).await?;

    if intact && through >= marker_lo {
        advance_backfilled_height(
            connection,
            account,
            birth_height,
            scope,
            dindex,
            marker_lo,
            through,
        )
        .await
        .map_err(db_error)?;
    }

    Ok(intact)
}

/// What makes an account the account a walk started on. `delete_account` frees the numeric id for
/// reuse, so a walk that outlives its account would otherwise commit the old wallet's history
/// against whatever account inherits the id.
#[derive(PartialEq)]
struct AccountIdentity {
    seed_fingerprint: Option<Vec<u8>>,
    aindex: u32,
    birth: u32,
    xvk: Option<Vec<u8>>,
    incarnation: u32,
}

async fn account_identity(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<AccountIdentity>> {
    let row: Option<(Option<Vec<u8>>, u32, u32, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT a.seed_fingerprint, a.aindex, a.birth, t.xvk FROM accounts a
        LEFT JOIN transparent_accounts t ON t.account = a.id_account
        WHERE a.id_account = ?",
    )
    .bind(account)
    .fetch_optional(&mut *connection)
    .await?;
    let Some((seed_fingerprint, aindex, birth, xvk)) = row else {
        return Ok(None);
    };

    Ok(Some(AccountIdentity {
        seed_fingerprint,
        aindex,
        birth,
        xvk,
        incarnation: transparent_incarnation(connection, account).await?,
    }))
}

async fn ensure_same_account(
    connection: &mut SqliteConnection,
    account: u32,
    identity: &AccountIdentity,
) -> Result<()> {
    if account_identity(connection, account).await?.as_ref() != Some(identity) {
        anyhow::bail!("account {account} was replaced while discovery was running");
    }
    Ok(())
}

/// Decides where one candidate's walk starts, or `None` when nothing has to be requested for it:
/// its marker reaches the seam and the address is already known used, so `transparent_sync`
/// keeps it current above the seam. A stored address not yet known used is probed over
/// `(marker, tip]` on every walk, so a payment made to it above the seam is seen before the
/// selector can hand it out. The seam, the row and its marker are read in one critical section,
/// so no sync can move the seam between reading it and acting on it.
async fn candidate_start(
    connection: &mut SqliteConnection,
    account: u32,
    identity: &AccountIdentity,
    scope: u32,
    dindex: u32,
    taddr: &str,
    birth_height: u32,
) -> Result<Option<(Option<(u32, String)>, u32)>> {
    let _guard = SYNCING.lock().await;
    ensure_same_account(connection, account, identity).await?;
    let seam = account_seam(connection, account).await?;

    let existing = transparent_address_row(connection, account, scope, dindex).await?;
    let lo = match &existing {
        Some(row) => {
            let backfilled = transparent_backfilled_height(connection, row.0).await?;
            if backfilled.is_some_and(|h| h >= seam)
                && transparent_address_is_used(connection, account, taddr).await?
            {
                return Ok(None);
            }
            backfilled.map(|h| h + 1).unwrap_or(0).max(birth_height)
        }
        None => birth_height,
    };
    Ok(Some((existing, lo)))
}

/// Walks `[lo, backfill_end]` in windows for one candidate. A candidate already stored (`row` is
/// `Some`) is ingested window by window unconditionally. A candidate with no row yet is only a
/// probe: an empty window proves nothing and the walk keeps going, but as soon as a window reports
/// a transaction the address is stored and that window (and every one after it) is ingested like
/// an existing candidate's. Returns the address row if one now exists and whether this run found
/// the candidate used — the caller needs both to decide storage/count and gap-reset separately.
#[allow(clippy::too_many_arguments)]
async fn walk_candidate(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    identity: &AccountIdentity,
    birth_height: u32,
    scope: u32,
    dindex: u32,
    mut row: Option<(u32, String)>,
    my_address: &TransparentAddress,
    sk: Option<Vec<u8>>,
    pk: &[u8],
    taddr: &str,
    mut lo: u32,
    backfill_end: u32,
    cancellation_token: &CancellationToken,
    mut first: Option<Fetched>,
) -> Result<(Option<(u32, String)>, bool), BackfillError> {
    let mut used = false;
    if lo > backfill_end {
        return Ok((row, used));
    }
    let mut window = backfill_end - lo + 1;
    // The trim counter this walk started against: recovery deletes rows an earlier window already
    // committed, and a marker written over them would certify history that is gone.
    let mut trim: Option<i64> = None;
    let mut marker_lo = lo;

    while lo <= backfill_end {
        let hi = lo.saturating_add(window - 1).min(backfill_end);

        // One candidate, one window per critical section: `SYNCING` is taken fresh for each
        // iteration (never for the whole walk) and released as soon as this window's ingest and
        // marker advance land, so a multi-minute discovery walk cannot starve a 30 s sync tick or
        // freeze address selection behind it.
        let outcome = {
            let _guard = SYNCING.lock().await;
            match tokio::time::timeout(WINDOW_TIMEOUT, async {
                ensure_same_account(connection, account, identity)
                    .await
                    .map_err(BackfillError::Db)?;
                let seen = transparent_trim_counter(connection, account)
                    .await
                    .map_err(BackfillError::Db)?;
                let intact = *trim.get_or_insert(seen) == seen;
                // Under the same guard as the write it bounds, so the cut is taken against the
                // height the write is consistent with.
                let seam = account_seam(connection, account)
                    .await
                    .map_err(BackfillError::Db)?;
                // Re-read rather than trust the id this walk started with: an account deleted and
                // restored from the same seed passes the identity check with brand-new address
                // rows, and a note bound to the id that is gone is invisible and unspendable.
                row = transparent_address_row(connection, account, scope, dindex)
                    .await
                    .map_err(BackfillError::Db)?;
                // A reply obtained under a different seam is unusable at any height: it may
                // describe a fork a concurrent sync has since left.
                let Fetched { first, mut rx, .. } = match first.take() {
                    Some(fetched) if fetched.seam == seam => fetched,
                    _ => {
                        fetch_window(client, network, taddr, lo, hi, seam, cancellation_token)
                            .await?
                    }
                };
                // Any window that yielded something proves the address used, even if this window
                // later fails and the walk has to narrow and retry it.
                let found = first.is_some();
                used = used || found;
                if row.is_none() && !found {
                    return Ok(None);
                }
                if row.is_none() {
                    row = Some(
                        store_and_read_transparent_row(
                            connection,
                            account,
                            scope,
                            dindex,
                            sk.clone(),
                            pk,
                            taddr,
                        )
                        .await
                        .and_then(|row| row.context("just-stored address row missing"))
                        .map_err(BackfillError::Db)?,
                    );
                }
                let address_row = row.as_ref().expect("row stored above");
                ingest_backfill_window(
                    network,
                    connection,
                    client,
                    account,
                    birth_height,
                    address_row,
                    my_address,
                    scope,
                    dindex,
                    marker_lo,
                    lo,
                    hi,
                    seam,
                    first.map(Ok),
                    &mut rx,
                    intact,
                    cancellation_token,
                )
                .await
                .map(Some)
            })
            .await
            {
                Ok(result) => result,
                Err(_elapsed) => Err(BackfillError::Timeout { lo, hi }),
            }
        };

        match outcome {
            Ok(None) => {
                lo = hi + 1;
            }
            Ok(Some(certified)) => {
                if certified {
                    marker_lo = hi + 1;
                }
                lo = hi + 1;
            }
            Err(
                e @ (BackfillError::Fetch(_)
                | BackfillError::Timeout { .. }
                | BackfillError::WindowFull(_)),
            ) => {
                if window > MIN_BACKFILL_WINDOW {
                    window = (window / 2).max(MIN_BACKFILL_WINDOW);
                } else {
                    return Err(e);
                }
            }
            Err(e @ (BackfillError::Db(_) | BackfillError::Cancelled)) => return Err(e),
        }
    }

    Ok((row, used))
}

/// One index planned into a batch. `candidate` is `None` when `candidate_start` said the index
/// needs no request at all.
struct BatchEntry {
    dindex: u32,
    candidate: Option<Candidate>,
}

/// Everything one batched candidate needs, derived once while the batch is planned.
struct Candidate {
    existing: Option<(u32, String)>,
    lo: u32,
    address: TransparentAddress,
    pk: Vec<u8>,
    taddr: String,
    sk: Option<Vec<u8>>,
}

/// Rediscovers transparent addresses the wallet issued but has no rows for, and backfills the
/// transaction history of every address in `[birth_height, seam]` — both the state a restore
/// leaves behind (only the account's own address survives) and the gaps an address that already
/// has a row can still carry (e.g. a rewind that trimmed its marker back). Every window is
/// requested up to `end_height`, because an address first used above the seam has its only
/// evidence there; what lies above the seam is `transparent_sync`'s to write. Walks each scope
/// forward, gives up once `gap_limit` consecutive addresses were never stored *and* every index
/// the scope already had a row for has been visited (existing rows always count as reached,
/// regardless of what this run finds for them), and fails instead of reporting success if any
/// address it touched still falls short of the seam afterward or a trim landed during the walk.
/// Returns how many new addresses were added.
#[allow(clippy::too_many_arguments)]
pub async fn discover_transparent_addresses(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    end_height: u32,
    gap_limit: u32,
    concurrency: u32,
    progress_fn: impl Fn(String),
    cancellation_token: CancellationToken,
) -> Result<u32> {
    // The identity every later check compares against and the key material the walk derives from
    // must come from one guarded read: a delete plus a restore between them would leave the walk
    // deriving addresses from the old account's key while every check passes against the new one.
    let (identity, hw, aindex, ledger, tk, birth_height, stored_through, trim_at_start) = {
        let _guard = SYNCING.lock().await;
        let identity = account_identity(connection, account)
            .await?
            .context("account not found")?;
        let hw = get_account_hw(connection, account).await?;
        let aindex = get_account_aindex(connection, account).await?;
        let account_dindex = get_account_dindex(connection, account).await?;
        let ledger = get_ledger(connection, account).await?;
        let tk = select_account_transparent(connection, account, account_dindex).await?;
        let birth_height = get_birth_height(connection, account).await?;
        let stored_through = [
            highest_stored_dindex(connection, account, 0).await?,
            highest_stored_dindex(connection, account, 1).await?,
        ];
        let trim_at_start = transparent_trim_counter(connection, account).await?;
        (
            identity,
            hw,
            aindex,
            ledger,
            tk,
            birth_height,
            stored_through,
            trim_at_start,
        )
    };
    let xvk = tk.xvk;
    let backfill_end = end_height;

    let mut n_added = 0;
    let mut covered: Vec<(u32, u32)> = vec![];

    // One adaptive width for the whole invocation: a server that refused a batch is not asked to
    // take a wider one again in the next scope.
    let mut width = concurrency.clamp(1, MAX_DISCOVERY_CONCURRENCY);

    for scope in 0..2 {
        // A wider earlier walk can have stored an address past where this gap would stop; leaving
        // it unvisited would let the run certify coverage for history it never checked.
        let stored_through = stored_through[scope as usize];
        let mut dindex = 0;
        let mut gap = 0;
        while gap <= gap_limit || stored_through.is_some_and(|last| dindex <= last) {
            if cancellation_token.is_cancelled() {
                anyhow::bail!("transparent discovery cancelled");
            }

            // Plan over the indexes the sequential walk is certain to reach from here, so a batch
            // never requests an address that walk would not have asked for.
            let certain = gap_limit.saturating_add(1).saturating_sub(gap).max(
                stored_through.map_or(0, |last| last.saturating_add(1).saturating_sub(dindex)),
            );
            let mut batch: Vec<BatchEntry> = vec![];
            let mut requests = 0;
            while (batch.len() as u32) < certain && requests < width {
                let (pk, address) = match xvk.as_ref() {
                    Some(xvk) => derive_transparent_address(xvk, scope, dindex, false)?,
                    None if hw != 0 => {
                        ledger
                            .get_hw_transparent_address(network, aindex, scope, dindex)
                            .await?
                    }
                    _ => anyhow::bail!("Sweep needs an xpub key"),
                };
                let taddr = address.encode(network);
                progress_fn(taddr.clone());

                let candidate = match candidate_start(
                    connection,
                    account,
                    &identity,
                    scope,
                    dindex,
                    &taddr,
                    birth_height,
                )
                .await?
                {
                    Some((existing, lo)) => {
                        // An address already backfilled past the tip costs an index but no
                        // request, so it never spends one of the batch's slots.
                        if lo <= backfill_end {
                            requests += 1;
                        }
                        let sk = tk
                            .xsk
                            .as_ref()
                            .map(|tsk| derive_transparent_sk(tsk, scope, dindex))
                            .transpose()?;
                        Some(Candidate {
                            existing,
                            lo,
                            address,
                            pk,
                            taddr,
                            sk,
                        })
                    }
                    None => None,
                };
                batch.push(BatchEntry { dindex, candidate });
                dindex += 1;
            }

            // Ask for every candidate's whole first window at once, outside `SYNCING`. A lone
            // request is left to `walk_candidate` under the guard, so width 1 is what it was.
            let mut prefetched: Vec<Option<Result<Fetched, BackfillError>>> =
                batch.iter().map(|_| None).collect();
            if requests >= 2 {
                // Read here rather than reused from planning: those guards are released between
                // candidates, so only a fresh one states what the batch is actually requested under.
                let batch_seam = {
                    let _guard = SYNCING.lock().await;
                    account_seam(connection, account).await?
                };
                let targets: Vec<(usize, &Candidate)> = batch
                    .iter()
                    .enumerate()
                    .filter_map(|(slot, entry)| entry.candidate.as_ref().map(|c| (slot, c)))
                    .filter(|(_, candidate)| candidate.lo <= backfill_end)
                    .collect();
                // Built before the join: a future borrowing `client` would not be `Send`, and the
                // walk is spawned.
                let mut duplicates: Vec<Client> =
                    targets.iter().map(|_| client.duplicate()).collect();
                let token = &cancellation_token;
                let results = join_all(duplicates.iter_mut().zip(&targets).map(
                    |(duplicate, (_, candidate))| async move {
                        match tokio::time::timeout(
                            WINDOW_TIMEOUT,
                            fetch_window(
                                duplicate,
                                network,
                                &candidate.taddr,
                                candidate.lo,
                                backfill_end,
                                batch_seam,
                                token,
                            ),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_elapsed) => Err(BackfillError::Timeout {
                                lo: candidate.lo,
                                hi: backfill_end,
                            }),
                        }
                    },
                ))
                .await;
                for ((slot, _), result) in targets.iter().zip(results) {
                    prefetched[*slot] = Some(result);
                }
            }

            // A cancellation anywhere in the batch ends the walk before anything of it is written.
            if prefetched
                .iter()
                .any(|slot| matches!(slot, Some(Err(BackfillError::Cancelled))))
            {
                anyhow::bail!("transparent discovery cancelled");
            }

            // Ingest strictly in index order.
            for (slot, entry) in batch.into_iter().enumerate() {
                // Per candidate, not per batch: a token cancelled while the batch waited for
                // `SYNCING` is never seen by an empty prefetch, which skips `fetch_window` too.
                if cancellation_token.is_cancelled() {
                    anyhow::bail!("transparent discovery cancelled");
                }
                let Some(candidate) = entry.candidate else {
                    gap = 0;
                    covered.push((scope, entry.dindex));
                    continue;
                };
                let first = match prefetched[slot].take() {
                    Some(Ok(fetched)) => Some(fetched),
                    // The first failed probe halves the width for the rest of the invocation and
                    // drops every sibling stream unread, so this candidate's retry and each of the
                    // later ones reaches the server alone, exactly as the sequential walk does.
                    Some(Err(_fetch_or_timeout)) => {
                        width = (width / 2).max(1);
                        prefetched.iter_mut().for_each(|sibling| *sibling = None);
                        None
                    }
                    None => None,
                };

                let (row, used) = walk_candidate(
                    network,
                    connection,
                    client,
                    account,
                    &identity,
                    birth_height,
                    scope,
                    entry.dindex,
                    candidate.existing.clone(),
                    &candidate.address,
                    candidate.sk,
                    &candidate.pk,
                    &candidate.taddr,
                    candidate.lo,
                    backfill_end,
                    &cancellation_token,
                    first,
                )
                .await?;

                if row.is_some() {
                    covered.push((scope, entry.dindex));
                    if candidate.existing.is_none() {
                        n_added += 1;
                    }
                }
                // The row re-read under the guard, not the one seen while planning: an address
                // allocated in between is an existing address, not a step toward the gap.
                if row.is_some() || used {
                    gap = 0;
                } else {
                    gap += 1;
                }
            }
        }
    }

    // One last critical section for the whole verification and the record it stamps: a trim
    // landing between "the walk finished" and "the walk is recorded" would leave the record
    // certifying history it no longer describes.
    let _guard = SYNCING.lock().await;
    ensure_same_account(connection, account, &identity).await?;
    let seam_now = account_seam(connection, account).await?;
    let total = covered.len();
    let mut incomplete = 0;
    for (scope, dindex) in covered {
        let row = transparent_address_row(connection, account, scope, dindex)
            .await?
            .context("covered address row missing")?;
        let backfilled = transparent_backfilled_height(connection, row.0).await?;
        if !backfilled.is_some_and(|h| h >= seam_now) {
            incomplete += 1;
        }
    }
    if incomplete > 0 {
        anyhow::bail!(
            "transparent coverage incomplete for {incomplete} of {total} covered addresses"
        );
    }
    // A skipped address was trusted on its marker and its notes; a trim between two candidates
    // may have deleted the notes and clamped the marker to exactly the seam read above.
    if transparent_trim_counter(connection, account).await? != trim_at_start {
        anyhow::bail!("coverage invalidated by a trim during the walk");
    }
    write_transparent_coverage(&mut *connection, account, gap_limit).await?;

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
    concurrency: u32,
    progress_fn: impl Fn(String) + 'static + Send,
    cancellation_token: CancellationToken,
    walk: MutexGuard<'static, ()>,
) -> Result<()> {
    let network = *network;
    tokio::spawn(async move {
        let _walk = walk; // held for the whole scan, released only when it ends
        discover_transparent_addresses(
            &network,
            &mut connection,
            &mut client,
            account,
            end_height,
            gap_limit,
            concurrency,
            progress_fn,
            cancellation_token,
        )
        .await
    });
    Ok(())
}

/// Heights of `account`'s undated transactions in `[start, end]` — `None` for every account.
async fn heights_of_transactions_without_time(
    connection: &mut SqliteConnection,
    account: Option<u32>,
    start: u32,
    end: u32,
) -> Result<HashSet<u32>> {
    Ok(sqlx::query(
        "SELECT DISTINCT height FROM transactions WHERE time = 0
        AND height >= ? AND height <= ? AND (? IS NULL OR account = ?)",
    )
    .bind(start)
    .bind(end)
    .bind(account)
    .bind(account)
    .map(|row: SqliteRow| {
        let height: u32 = row.get(0);
        height
    })
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .collect())
}

/// Fetches the block at each of `heights` and fills in its transactions' time and its header,
/// one DB transaction per height so a height is either fully enriched or left untouched — the
/// network fetch itself stays outside any transaction so this never holds a write lock across a
/// whole loop of round-trips.
async fn fill_missing_block_times(
    connection: &mut SqliteConnection,
    client: &mut Client,
    network: &Network,
    heights: HashSet<u32>,
) -> Result<(), BackfillError> {
    for h in heights {
        debug!("fetch block @{h}");
        let block = client
            .block(network, h)
            .await
            .map_err(BackfillError::Fetch)?;
        let time = block.time;
        let mut db_tx = connection.begin().await.map_err(db_error)?;
        sqlx::query("UPDATE transactions SET time = ? WHERE height = ? AND time = 0")
            .bind(time)
            .bind(h)
            .execute(&mut *db_tx)
            .await
            .map_err(db_error)?;
        let block_header = BlockHeader {
            height: h,
            hash: block.hash,
            time: block.time,
        };
        store_block_header(&mut db_tx, &block_header)
            .await
            .map_err(db_error)?;
        db_tx.commit().await.map_err(db_error)?;
    }
    Ok(())
}

pub async fn get_heights_without_time(
    connection: &mut SqliteConnection,
    start: u32,
    end: u32,
) -> Result<HashSet<u32>> {
    let mut tx_without_time =
        heights_of_transactions_without_time(connection, None, start, end).await?;

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
    use crate::account::tests::{account_xpub, restore, TEST_PHRASE};
    use crate::api::sync::{file_backed_coin, LOCK_TEST_SERIAL};
    use crate::db::catch_up_owed_through;
    use crate::db::tests::{
        insert_account_with_birth, insert_scoped_taddress, insert_scoped_taddress_for_account,
        memory_db, set_pool_sync_height, set_pool_sync_height_for_account, ACCOUNT,
    };
    use crate::net::{BroadcastOutcome, LwdServer};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;
    use tokio::sync::Notify;
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::async_trait;
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    /// Moves the seam. Discovery writes nothing above `MIN(sync_heights)` by design, so a fixture
    /// whose payments sit above the birth height needs the account's pools up there first.
    async fn synced_to(connection: &mut SqliteConnection, account: u32, height: u32) {
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(height)
            .bind(account)
            .execute(connection)
            .await
            .expect("move the seam");
    }

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

    async fn taddress_backfilled_height(
        connection: &mut SqliteConnection,
        id_taddress: u32,
    ) -> Option<i64> {
        sqlx::query_scalar(
            "SELECT backfilled_height FROM transparent_address_accounts WHERE id_taddress = ?",
        )
        .bind(id_taddress)
        .fetch_one(&mut *connection)
        .await
        .expect("row")
    }

    async fn tcov_trim(connection: &mut SqliteConnection, account: u32) -> Option<String> {
        crate::db::get_prop(connection, &format!("tcov_trim:{account}"))
            .await
            .expect("prop")
    }

    /// A marker above the trim height would otherwise satisfy discovery's `>= seam` skip term
    /// even though the history it certifies was just deleted.
    #[tokio::test]
    async fn trim_sync_data_clamps_a_backfill_marker_above_the_trim_height() {
        let mut connection = memory_db().await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, "t1a").await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 500 WHERE id_taddress = 1",
        )
        .execute(&mut connection)
        .await
        .expect("seed marker");

        trim_sync_data(&mut connection, ACCOUNT, 200)
            .await
            .expect("trim");

        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(200)
        );
        assert_eq!(
            tcov_trim(&mut connection, ACCOUNT).await,
            Some("1".to_string())
        );
    }

    /// No gratuitous re-backfill: a marker already at or below the trim height proves nothing
    /// that the trim removed, so it is left alone and the trim counter does not move.
    #[tokio::test]
    async fn trim_sync_data_leaves_a_marker_below_the_trim_height_alone() {
        let mut connection = memory_db().await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, "t1a").await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 100 WHERE id_taddress = 1",
        )
        .execute(&mut connection)
        .await
        .expect("seed marker");

        trim_sync_data(&mut connection, ACCOUNT, 200)
            .await
            .expect("trim");

        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(100)
        );
        assert_eq!(tcov_trim(&mut connection, ACCOUNT).await, None);
    }

    /// Shared `block()` behaviour for the fakes: `Some(time)` succeeds, `fail_block` errors,
    /// and neither set means the test never expected the call.
    /// A stable per-height anchor: every fake answers the same chain unless a test says otherwise.
    fn fake_anchor(height: u32) -> Vec<u8> {
        height.to_be_bytes().to_vec()
    }

    fn block_response(
        height: u32,
        block_time: Option<u32>,
        fail_block: bool,
    ) -> Result<CompactBlock> {
        if fail_block {
            anyhow::bail!("block fetch failed for height {}", height);
        }
        match block_time {
            Some(time) => Ok(CompactBlock {
                height: height as u64,
                time,
                ..Default::default()
            }),
            None => unimplemented!(),
        }
    }

    /// Answers every address with an empty stream, failing on call `fail_at_call` when set —
    /// the shape a mid-account network error takes. `stream_failures` is how many of the first
    /// streams announce a transaction and then break, so one fake can serve a failing call and
    /// the retry that follows it.
    #[derive(Clone)]
    struct EmptyStreams {
        calls: Arc<AtomicU32>,
        fail_at_call: Option<u32>,
        stream_failures: Arc<AtomicU32>,
        block_time: Option<u32>,
        fail_block: bool,
    }

    #[async_trait]
    impl LwdServer for EmptyStreams {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, self.block_time, self.fail_block)
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
            anyhow::ensure!(
                self.fail_at_call != Some(call),
                "server failed on address {}",
                call
            );
            let (sender, receiver) = channel(2);
            if self.stream_failures.load(Ordering::Relaxed) > 0 {
                self.stream_failures.fetch_sub(1, Ordering::Relaxed);
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

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    #[tokio::test]
    async fn fill_missing_block_times_rolls_back_the_time_update_when_the_header_write_fails() {
        let mut connection = memory_db().await;
        sqlx::query(
            "INSERT INTO transactions (account, txid, height, time) VALUES (?, x'00', ?, 0)",
        )
        .bind(ACCOUNT)
        .bind(100)
        .execute(&mut connection)
        .await
        .expect("transaction");
        sqlx::query("DROP TABLE headers")
            .execute(&mut connection)
            .await
            .expect("drop headers");

        let mut client: Client = Box::new(EmptyStreams {
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: Some(12345),
            fail_block: false,
        });

        let result = fill_missing_block_times(
            &mut connection,
            &mut client,
            &Network::Main,
            HashSet::from([100]),
        )
        .await;

        assert!(result.is_err());
        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE height = 100")
            .fetch_one(&mut connection)
            .await
            .expect("time");
        assert_eq!(time, 0);
    }

    async fn two_addresses_at_height(connection: &mut SqliteConnection, height: u32) {
        insert_account_with_birth(connection, ACCOUNT, 0, 0).await;
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
            insert_account_with_birth(connection, account, 0, 0).await;
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
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: None,
            fail_block: false,
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

    /// A transaction an earlier pass committed but could not date is no longer in this pass's
    /// stream, yet this pass advances the marker past it — so the undated heights have to come
    /// from the database, not from what the server just sent.
    #[tokio::test]
    async fn transparent_sync_dates_a_committed_transaction_its_stream_no_longer_carries() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        sqlx::query(
            "INSERT INTO transactions (account, txid, height, time) VALUES (?, x'01', ?, 0)",
        )
        .bind(ACCOUNT)
        .bind(150)
        .execute(&mut connection)
        .await
        .expect("undated transaction");
        let mut client: Client = Box::new(EmptyStreams {
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: Some(12345),
            fail_block: false,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);

        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[ACCOUNT],
            101,
            200,
            10,
            rx_cancel,
        )
        .await
        .expect("sync");

        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE height = 150")
            .fetch_one(&mut connection)
            .await
            .expect("time");
        assert_eq!(time, 12345, "the pass that advanced the marker dated it");
    }

    #[tokio::test]
    async fn transparent_sync_stream_fails_rolls_back_the_transaction_and_height() {
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
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
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(1)),
            block_time: None,
            fail_block: false,
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

    /// Accepts the request and then never answers it, the way a hung or hostile server does.
    /// `calls` lets a test wait until the stall is provably in flight before it moves the clock.
    /// `stall_wider_than` models the slow-but-honest server: it answers a narrow enough window.
    #[derive(Clone)]
    struct StalledStream {
        calls: Arc<AtomicU32>,
        call_ranges: Arc<Mutex<Vec<(u32, u32)>>>,
        stall_wider_than: Option<u32>,
    }

    /// Yields until the fake has been asked `target` times, bounded by real time so a regression
    /// that stops asking fails the test instead of hanging it. The bound cannot be a tokio timer:
    /// these tests run on a paused clock they move by hand.
    async fn wait_for_calls(calls: &Arc<AtomicU32>, target: u32) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while calls.load(Ordering::Relaxed) < target {
            assert!(
                std::time::Instant::now() < deadline,
                "the server was asked {} times, expected {target}",
                calls.load(Ordering::Relaxed)
            );
            tokio::task::yield_now().await;
        }
    }

    #[async_trait]
    impl LwdServer for StalledStream {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

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
            start: u32,
            end: u32,
        ) -> Result<Self::TransactionStream> {
            self.call_ranges.lock().expect("lock").push((start, end));
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.stall_wider_than {
                Some(width) if end - start <= width => {}
                _ => std::future::pending::<()>().await,
            }
            let (sender, receiver) = channel(1);
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

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// The regular sync holds `SYNCING` for its whole run, so an address whose fetch never
    /// answers would wedge receive-address selection and every other locked API for the life of
    /// the process. One address gets the same deadline one discovery window already has.
    ///
    /// Time is advanced explicitly, not by `start_paused`'s auto-advance: the sync's own database
    /// work runs on sqlx's background thread, leaving the runtime idle enough for auto-advance to
    /// race past both deadlines before the inner one is even armed.
    #[tokio::test]
    async fn transparent_sync_gives_up_on_a_server_that_never_answers() {
        tokio::time::pause();
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
        insert_scoped_taddress(
            &mut connection,
            1,
            0,
            0,
            "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt",
        )
        .await;
        set_pool_sync_height(&mut connection, 0, 100).await;
        let calls = Arc::new(AtomicU32::new(0));
        let mut client: Client = Box::new(StalledStream {
            calls: calls.clone(),
            call_ranges: Arc::new(Mutex::new(vec![])),
            stall_wider_than: None,
        });
        let (_cancel, cancellation) = broadcast::channel(1);

        let mut task = tokio::spawn(async move {
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
            (result, connection)
        });

        wait_for_calls(&calls, 1).await;
        tokio::time::advance(WINDOW_TIMEOUT + Duration::from_millis(1)).await;

        let (result, mut connection) = tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .expect("a stalled fetch must not hang the sync")
            .expect("sync task panicked");

        assert!(result
            .expect_err("a stalled fetch must fail the sync")
            .to_string()
            .contains("timed out"));
        assert_eq!(
            sync_heights(&mut connection).await,
            vec![100],
            "a timed-out address must not move the pool height"
        );
    }

    /// A slow but honest server must not be mistaken for a hung one. The regular sync covers the
    /// account's whole stored-height-to-tip range, which on an old wallet is millions of blocks:
    /// a single deadline over the whole of it would fail every pass forever and strand the pool
    /// height. It narrows the window instead, down to the same floor discovery uses.
    #[tokio::test]
    async fn transparent_sync_narrows_its_window_when_the_server_stalls() {
        tokio::time::pause();
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 2_000_000, 0).await;
        insert_scoped_taddress(
            &mut connection,
            1,
            0,
            0,
            "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt",
        )
        .await;
        set_pool_sync_height(&mut connection, 0, 1_999_999).await;
        let calls = Arc::new(AtomicU32::new(0));
        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut client: Client = Box::new(StalledStream {
            calls: calls.clone(),
            call_ranges: call_ranges.clone(),
            stall_wider_than: Some(MIN_BACKFILL_WINDOW),
        });
        let (_cancel, cancellation) = broadcast::channel(1);

        let mut task = tokio::spawn(async move {
            let result = transparent_sync(
                &Network::Main,
                &mut connection,
                &mut client,
                &[ACCOUNT],
                2_000_000,
                2_002_999,
                10,
                cancellation,
            )
            .await;
            (result, connection)
        });

        // 3000 blocks, then 1500, are both too wide for this server; the floor width is not, and
        // halving 1500 lands under the floor, so the floor is what has to stop it.
        for stall in 1..=2 {
            wait_for_calls(&calls, stall).await;
            tokio::time::advance(WINDOW_TIMEOUT + Duration::from_millis(1)).await;
        }
        // Once the server is answering, auto-advance would race the deadline of a window that is
        // merely waiting on sqlx's blocking thread, so the clock goes back to being real.
        wait_for_calls(&calls, 3).await;
        tokio::time::resume();

        let (result, mut connection) = tokio::time::timeout(Duration::from_secs(30), &mut task)
            .await
            .expect("a narrowed sync must finish")
            .expect("sync task panicked");
        result.expect("a server that answers a narrower window must not fail the sync");

        assert_eq!(
            sync_heights(&mut connection).await,
            vec![2_002_999],
            "a narrowed sync still covers the whole range"
        );
        let ranges = call_ranges.lock().expect("lock").clone();
        assert!(
            ranges
                .iter()
                .all(|(lo, hi)| hi - lo + 1 >= MIN_BACKFILL_WINDOW),
            "narrowed below the floor: {ranges:?}"
        );
        assert_eq!(
            ranges[2..],
            [
                (2_000_000, 2_000_999),
                (2_001_000, 2_001_999),
                (2_002_000, 2_002_999),
            ],
            "the narrowed windows must tile the range without a hole"
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(2_002_999),
            "every narrowed window must be recorded as covered"
        );
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
    /// `fail_from_call` fails that call and every later one, the shape a server that stays down
    /// has: a single failing call would be repaired by the very narrowing under test.
    /// `fail_mid_stream` turns the `fail_wider_than` rejection from a refused request into a
    /// stream that delivers one transaction and then dies.
    #[derive(Clone)]
    struct UsedAtCalls {
        calls: Arc<AtomicU32>,
        used_at_calls: Vec<u32>,
        fail_from_call: Option<u32>,
        block_time: Option<u32>,
        fail_block: bool,
        call_ranges: Arc<Mutex<Vec<(u32, u32)>>>,
        fail_wider_than: Option<u32>,
        fail_mid_stream: bool,
    }

    /// The smallest transaction that parses: the scan only asks whether the stream has an item.
    fn any_transaction() -> Transaction {
        // v4 header and version group id, then zeroes: no inputs, outputs, spends or joinsplits.
        let raw =
            hex::decode("0400008085202f89000000000000000000000000000000000000000000").expect("hex");
        Transaction::read(&mut &raw[..], BranchId::Sapling).expect("transaction")
    }

    /// V4 tail shared by every builder here: no lock time, no expiry, no shielded parts.
    fn write_v4_tail(raw: &mut Vec<u8>) {
        raw.extend_from_slice(&[0u8; 4]); // lock_time
        raw.extend_from_slice(&[0u8; 4]); // expiry_height
        raw.extend_from_slice(&[0u8; 8]); // valueBalanceSapling
        raw.push(0x00); // nShieldedSpend
        raw.push(0x00); // nShieldedOutput
        raw.push(0x00); // nJoinSplit
    }

    /// A v4 transaction with one P2PKH vout paying `address` — the smallest transaction the
    /// ingestion match (`vout.recipient_address() == my_address`) can actually recognize.
    fn transaction_paying(address: &str, value: u64) -> Transaction {
        transaction_paying_outputs(address, value, 1)
    }

    /// The same payment repeated `outputs` times in one transaction — a single answer carrying
    /// more notes than the window may hold.
    fn transaction_paying_outputs(address: &str, value: u64, outputs: u8) -> Transaction {
        let hash = match TransparentAddress::decode(&Network::Main, address).expect("address") {
            TransparentAddress::PublicKeyHash(hash) | TransparentAddress::ScriptHash(hash) => hash,
        };
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&hash);
        script.extend_from_slice(&[0x88, 0xac]);

        let mut raw = hex::decode("0400008085202f89").expect("hex");
        raw.push(0x00); // nIn
        raw.push(outputs); // nOut
        for _ in 0..outputs {
            raw.extend_from_slice(&value.to_le_bytes());
            raw.push(script.len() as u8);
            raw.extend_from_slice(&script);
        }
        write_v4_tail(&mut raw);
        Transaction::read(&mut &raw[..], BranchId::Sapling).expect("transaction")
    }

    /// A v4 transaction with one input spending `(txid, vout_index)` — what ingestion reads
    /// `vin.prevout` from to write the `spends` row.
    fn transaction_spending(txid: &[u8], vout_index: u32) -> Transaction {
        let mut raw = hex::decode("0400008085202f89").expect("hex");
        raw.push(0x01); // nIn
        raw.extend_from_slice(txid);
        raw.extend_from_slice(&vout_index.to_le_bytes());
        raw.push(0x00); // empty script_sig
        raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence
        raw.push(0x00); // nOut
        write_v4_tail(&mut raw);
        Transaction::read(&mut &raw[..], BranchId::Sapling).expect("transaction")
    }

    /// Yields a fixed sequence of transactions in the exact order given — used to prove ingestion
    /// is insensitive to delivery order (e.g. a spend arriving before the note it spends).
    #[derive(Clone)]
    struct FixedTxs {
        items: Vec<(u32, Transaction, usize)>,
        block_time: Option<u32>,
        fail_block: bool,
        /// `Some` counts the call and then never answers it, the way a hung server does.
        stall_block: Option<Arc<AtomicU32>>,
    }

    #[async_trait]
    impl LwdServer for FixedTxs {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            if let Some(calls) = &self.stall_block {
                calls.fetch_add(1, Ordering::Relaxed);
                std::future::pending::<()>().await;
            }
            block_response(height, self.block_time, self.fail_block)
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
            let (sender, receiver) = channel(self.items.len().max(1));
            for item in self.items.drain(..) {
                sender.send(Ok(item)).await.expect("queue item");
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// The spend arrives before the note it spends — the immediate per-item resolution used to
    /// drop it silently. Ingestion must resolve spends only after every vout has landed.
    #[tokio::test]
    async fn transparent_sync_records_a_spend_delivered_before_its_note() {
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
        let address = "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt";
        insert_scoped_taddress(&mut connection, 1, 0, 0, address).await;
        set_pool_sync_height(&mut connection, 0, 100).await;

        let funding = transaction_paying(address, 1_000);
        let funding_txid = funding.txid().as_ref().to_vec();
        let spending = transaction_spending(&funding_txid, 0);

        let mut client: Client = Box::new(FixedTxs {
            stall_block: None,
            items: vec![(150, spending, 0), (140, funding, 0)],
            block_time: Some(12345),
            fail_block: false,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);

        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[ACCOUNT],
            101,
            200,
            10,
            rx_cancel,
        )
        .await
        .expect("sync");

        let notes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes")
            .fetch_one(&mut connection)
            .await
            .expect("notes");
        let spends: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM spends")
            .fetch_one(&mut connection)
            .await
            .expect("spends");
        assert_eq!(notes, 1);
        assert_eq!(spends, 1);
    }

    /// Sends the first transaction immediately, then blocks on a `Notify` the test owns before
    /// sending a second — proves cancellation wins over a stream with a genuine remainder still
    /// pending, not one already exhausted.
    #[derive(Clone)]
    struct GatedStream {
        release_second: Arc<Notify>,
    }

    #[async_trait]
    impl LwdServer for GatedStream {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

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
            start: u32,
            _end: u32,
        ) -> Result<Self::TransactionStream> {
            let (sender, receiver) = channel(2);
            sender
                .send(Ok((start, any_transaction(), 0)))
                .await
                .expect("queue first transaction");
            let release_second = self.release_second.clone();
            tokio::spawn(async move {
                release_second.notified().await;
                let _ = sender.send(Ok((start, any_transaction(), 0))).await;
            });
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// Cancellation queued before the call still wins even though the stream has a genuine item
    /// still pending (gated behind a `Notify` this test never releases): the per-address ingest
    /// can never finish on its own, so only the cancellation branch can ever become ready, and
    /// its already-open db transaction must roll back rather than commit the first item alone.
    #[tokio::test]
    async fn transparent_sync_cancels_before_draining_the_rest_of_the_stream() {
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
        insert_scoped_taddress(
            &mut connection,
            1,
            0,
            0,
            "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt",
        )
        .await;
        set_pool_sync_height(&mut connection, 0, 100).await;

        let mut client: Client = Box::new(GatedStream {
            release_second: Arc::new(Notify::new()),
        });
        let (cancel, rx_cancel) = broadcast::channel(1);
        cancel.send(()).expect("queue cancel");

        let result = transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[ACCOUNT],
            101,
            200,
            10,
            rx_cancel,
        )
        .await;

        assert!(result.is_err());
        let transactions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transactions")
            .fetch_one(&mut connection)
            .await
            .expect("transaction count");
        assert_eq!(transactions, 0);
    }

    /// Behaviour-preserving pin: a plain payment is still recorded, and its address's marker
    /// still advances end to end, after the ingestion loop was extracted into its own function.
    #[tokio::test]
    async fn transparent_sync_still_records_a_note_after_the_extraction() {
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
        let address = "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt";
        insert_scoped_taddress(&mut connection, 1, 0, 0, address).await;
        set_pool_sync_height(&mut connection, 0, 100).await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 100 WHERE id_taddress = 1",
        )
        .execute(&mut connection)
        .await
        .expect("seed marker");

        let funding = transaction_paying(address, 1_000);
        let mut client: Client = Box::new(FixedTxs {
            stall_block: None,
            items: vec![(150, funding, 0)],
            block_time: Some(12345),
            fail_block: false,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);

        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[ACCOUNT],
            101,
            200,
            10,
            rx_cancel,
        )
        .await
        .expect("sync");

        let notes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes")
            .fetch_one(&mut connection)
            .await
            .expect("notes");
        assert_eq!(notes, 1);
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(200)
        );
    }

    /// F5 ordering: the block-time fill happens before the marker write, so a fill failure
    /// leaves the height outstanding rather than certifying a range still dated zero.
    #[tokio::test]
    async fn transparent_sync_fills_block_times_before_it_advances_a_marker() {
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
        let address = "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt";
        insert_scoped_taddress(&mut connection, 1, 0, 0, address).await;
        set_pool_sync_height(&mut connection, 0, 100).await;
        // Contiguous with the scan below, so a wrongly-ordered implementation would land the
        // marker at 200 despite the block-time failure — a NULL marker would stay NULL either way.
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 100 WHERE id_taddress = 1",
        )
        .execute(&mut connection)
        .await
        .expect("seed marker");

        let funding = transaction_paying(address, 1_000);
        let mut client: Client = Box::new(FixedTxs {
            stall_block: None,
            items: vec![(150, funding, 0)],
            block_time: None,
            fail_block: true,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);

        let result = transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[ACCOUNT],
            101,
            200,
            10,
            rx_cancel,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(100)
        );
    }

    /// Dating a block is a network call too. Left outside the deadline it holds `SYNCING` — and
    /// every locked API behind it — for the life of the process, however hard the fetch itself
    /// is bounded.
    #[tokio::test]
    async fn transparent_sync_gives_up_on_a_server_that_stalls_dating_a_block() {
        tokio::time::pause();
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
        let address = "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt";
        insert_scoped_taddress(&mut connection, 1, 0, 0, address).await;
        set_pool_sync_height(&mut connection, 0, 100).await;
        let block_calls = Arc::new(AtomicU32::new(0));
        let mut client: Client = Box::new(FixedTxs {
            stall_block: Some(block_calls.clone()),
            items: vec![(150, transaction_paying(address, 1_000), 0)],
            block_time: None,
            fail_block: false,
        });
        let (_cancel, cancellation) = broadcast::channel(1);

        // 100 blocks is already at the floor width, so the deadline fails the sync outright
        // instead of asking the same server for a narrower window.
        let mut task = tokio::spawn(async move {
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
            (result, connection)
        });

        wait_for_calls(&block_calls, 1).await;
        tokio::time::advance(WINDOW_TIMEOUT + Duration::from_millis(1)).await;
        // The deadline has moved; from here the join needs REAL time. Paused time auto-advances
        // whenever the runtime idles on the sqlite worker thread, which expires the guard below
        // before the sync has finished writing.
        tokio::time::resume();

        let (result, mut connection) = tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .expect("a stalled block lookup must not hang the sync")
            .expect("sync task panicked");

        assert!(result
            .expect_err("a stalled block lookup must fail the sync")
            .to_string()
            .contains("timed out"));
        assert_eq!(
            sync_heights(&mut connection).await,
            vec![100],
            "a timed-out address must not move the pool height"
        );
    }

    /// The marker's second writer: a marker at the seam and a scan of `[seam + 1, tip]` end at
    /// `tip`, contiguous with what the row already proved.
    #[tokio::test]
    async fn transparent_sync_advances_a_marker_contiguous_with_its_scan_range() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 100 WHERE id_taddress IN (1, 2)",
        )
        .execute(&mut connection)
        .await
        .expect("seed marker");

        scan_to_200(&mut connection, &[ACCOUNT], None)
            .await
            .expect("sync");

        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(200)
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, 2).await,
            Some(200)
        );
    }

    /// A stored row with `backfilled_height IS NULL` must still be `NULL` after a sync of
    /// `[seam + 1, tip]`: that delta proves nothing about `[birth, seam]`.
    #[tokio::test]
    async fn transparent_sync_does_not_mark_an_address_that_has_no_marker() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;

        scan_to_200(&mut connection, &[ACCOUNT], None)
            .await
            .expect("sync");

        assert_eq!(taddress_backfilled_height(&mut connection, 1).await, None);
        assert_eq!(taddress_backfilled_height(&mut connection, 2).await, None);
    }

    /// `MAX` semantics on a locally-ahead wallet: a marker already above the scan's `end_height`
    /// is left alone rather than lowered to it.
    #[tokio::test]
    async fn transparent_sync_does_not_lower_a_marker_above_its_end_height() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 300 WHERE id_taddress IN (1, 2)",
        )
        .execute(&mut connection)
        .await
        .expect("seed marker");

        scan_to_200(&mut connection, &[ACCOUNT], None)
            .await
            .expect("sync");

        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(300)
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, 2).await,
            Some(300)
        );
    }

    #[async_trait]
    impl LwdServer for UsedAtCalls {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, self.block_time, self.fail_block)
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
            start: u32,
            end: u32,
        ) -> Result<Self::TransactionStream> {
            let requests = {
                let mut ranges = self.call_ranges.lock().expect("lock");
                ranges.push((start, end));
                ranges.len()
            };
            if let Some(fail_wider_than) = self.fail_wider_than {
                if end - start > fail_wider_than {
                    // Only the first over-wide request dies after a transaction: one that did so
                    // on every candidate would make each of them read as used and the walk endless.
                    if !self.fail_mid_stream || requests > 1 {
                        anyhow::bail!("window wider than the server allows");
                    }
                    let (sender, receiver) = channel(2);
                    sender
                        .send(Ok((start, any_transaction(), 0)))
                        .await
                        .expect("queue transaction");
                    sender
                        .send(Err(anyhow::anyhow!("stream died mid-window")))
                        .await
                        .expect("queue error");
                    drop(sender);
                    return Ok(ReceiverStream::new(receiver));
                }
            }
            let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            let (sender, receiver) = channel(2);
            if self.fail_from_call.is_some_and(|first| call >= first) {
                sender
                    .send(Err(anyhow::anyhow!("discovery stream failed")))
                    .await
                    .expect("queue error");
            } else if self.used_at_calls.contains(&call) {
                sender
                    .send(Ok((start, any_transaction(), 0)))
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

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// On the *first* request, spawns a task that grabs `SYNCING` and immediately releases it,
    /// recording that it ran; on the *second*, asserts the flag is already set. Proves the walk
    /// let its own guard go between candidates: under a fair mutex the probe (queued while the
    /// walk still held the guard for the first candidate) is served before the walk can re-acquire
    /// it for the second, so the flag can only be set in time if the walk actually released it.
    #[derive(Clone)]
    struct GuardReleaseProbe {
        calls: Arc<AtomicU32>,
        probe_ran: Arc<AtomicBool>,
    }

    #[async_trait]
    impl LwdServer for GuardReleaseProbe {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(0), false)
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
            if call == 1 {
                let probe_ran = self.probe_ran.clone();
                let (queued_tx, queued_rx) = oneshot::channel();
                tokio::spawn(async move {
                    let mut acquire = Box::pin(SYNCING.lock());
                    let mut queued = Some(queued_tx);
                    let _guard = std::future::poll_fn(|cx| {
                        let polled = std::future::Future::poll(acquire.as_mut(), cx);
                        if polled.is_pending() {
                            if let Some(tx) = queued.take() {
                                let _ = tx.send(());
                            }
                        }
                        polled
                    })
                    .await;
                    probe_ran.store(true, Ordering::SeqCst);
                });
                // Spawning alone does not queue the probe: it must be parked on SYNCING before
                // this candidate's window ends, or the walk re-acquires first and fairness proves
                // nothing. A dropped sender means the first poll succeeded, i.e. the window was
                // running without the guard.
                queued_rx
                    .await
                    .expect("SYNCING must be held while a candidate's window runs");
            } else if call == 2 {
                assert!(
                    self.probe_ran.load(Ordering::SeqCst),
                    "SYNCING must be released between candidates"
                );
            }
            let (_sender, receiver) = channel(1);
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
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
        discover_with(connection, account, gap_limit, used_at_calls, 1).await
    }

    /// Width 1 is the sequential walk, so every test written before batching keeps running on the
    /// path it was written for.
    async fn discover_with(
        connection: &mut SqliteConnection,
        account: u32,
        gap_limit: u32,
        used_at_calls: Vec<u32>,
        concurrency: u32,
    ) -> (u32, u32) {
        let calls = Arc::new(AtomicU32::new(0));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: calls.clone(),
            used_at_calls,
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            connection,
            &mut client,
            account,
            2_000_100,
            gap_limit,
            concurrency,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        (n_added, calls.load(Ordering::Relaxed))
    }

    /// One request as the server saw it, with how many were open when it arrived.
    #[derive(Clone, Debug, PartialEq)]
    struct Request {
        taddr: String,
        lo: u32,
        hi: u32,
        in_flight: u32,
    }

    /// What `ScriptedServer` does with one request.
    #[derive(Clone, Default)]
    enum Reply {
        #[default]
        Empty,
        /// One payment at `height`, handed over `after` a delay.
        Funded {
            height: u32,
            after: Duration,
        },
        Fail,
        /// Accepts the request and never answers it.
        Stall,
        /// Cancels the walk, then never answers.
        CancelsThenStalls(CancellationToken),
        /// Cancels the walk as it answers empty, so only the ingest can see the cancellation.
        CancelsWhileReplying(CancellationToken),
        /// Stores another index's address row through its own connection first — what a concurrent
        /// `next_unused_transparent_address` does while a probe is in flight.
        StoresRow {
            coin: Coin,
            account: u32,
            scope: u32,
            dindex: u32,
        },
        /// Trims the account through its own connection first.
        Trims {
            coin: Coin,
            account: u32,
            height: u32,
        },
        /// Moves the seam through its own connection first — what a concurrent `synchronize` that
        /// scanned a replacement chain leaves behind while a probe is in flight.
        SyncsTo {
            coin: Coin,
            account: u32,
            height: u32,
        },
    }

    /// Replies to give for one address: `first` in order, then `then` forever.
    struct Script {
        first: VecDeque<Reply>,
        then: Reply,
    }

    /// Answers by address, never by call order — under concurrency call order is not a fixture.
    /// Records every request with the number in flight when it arrived. `hold` keeps a request
    /// open long enough for the rest of its batch to reach the server, and `reject_above` refuses
    /// one that found more than that many others already open.
    #[derive(Clone, Default)]
    struct ScriptedServer {
        script: Arc<Mutex<HashMap<String, Script>>>,
        default_reply: Reply,
        requests: Arc<Mutex<Vec<Request>>>,
        in_flight: Arc<AtomicU32>,
        peak: Arc<AtomicU32>,
        hold: Duration,
        reject_above: Option<u32>,
        /// Senders of stalled streams, kept alive so their receivers never see EOF.
        stalled: Arc<Mutex<Vec<Sender<Result<(u32, Transaction, usize)>>>>>,
    }

    impl ScriptedServer {
        /// Holds every request open for `hold`, so a whole batch is in flight at once.
        fn holding(hold: Duration) -> Self {
            Self {
                hold,
                ..Self::default()
            }
        }

        /// A server that admits only `limit` concurrent requests and refuses the rest.
        fn rejecting_above(limit: u32) -> Self {
            Self {
                hold: Duration::from_millis(20),
                reject_above: Some(limit),
                ..Self::default()
            }
        }

        fn failing_everything() -> Self {
            Self {
                default_reply: Reply::Fail,
                ..Self::default()
            }
        }

        fn always(&self, taddr: &str, then: Reply) {
            self.then_always(taddr, vec![], then);
        }

        fn then_always(&self, taddr: &str, first: Vec<Reply>, then: Reply) {
            self.script.lock().expect("lock").insert(
                taddr.to_string(),
                Script {
                    first: first.into(),
                    then,
                },
            );
        }

        fn next_reply(&self, taddr: &str) -> Reply {
            let mut script = self.script.lock().expect("lock");
            match script.get_mut(taddr) {
                Some(scripted) => scripted.first.pop_front().unwrap_or(scripted.then.clone()),
                None => self.default_reply.clone(),
            }
        }

        fn requests(&self) -> Vec<Request> {
            self.requests.lock().expect("lock").clone()
        }

        fn addresses(&self) -> Vec<String> {
            self.requests().into_iter().map(|r| r.taddr).collect()
        }

        fn ranges_for(&self, taddr: &str) -> Vec<(u32, u32)> {
            self.requests()
                .iter()
                .filter(|request| request.taddr == taddr)
                .map(|request| (request.lo, request.hi))
                .collect()
        }

        fn peak(&self) -> u32 {
            self.peak.load(Ordering::SeqCst)
        }

        fn stalling_stream(&self) -> ReceiverStream<Result<(u32, Transaction, usize)>> {
            let (sender, receiver) = channel(1);
            self.stalled.lock().expect("lock").push(sender);
            ReceiverStream::new(receiver)
        }
    }

    #[async_trait]
    impl LwdServer for ScriptedServer {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), false)
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
            taddress: &str,
            start: u32,
            end: u32,
        ) -> Result<Self::TransactionStream> {
            let arrived = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.requests.lock().expect("lock").push(Request {
                taddr: taddress.to_string(),
                lo: start,
                hi: end,
                in_flight: arrived,
            });
            let reply = self.next_reply(taddress);
            if !self.hold.is_zero() {
                tokio::time::sleep(self.hold).await;
            }
            self.peak
                .fetch_max(self.in_flight.load(Ordering::SeqCst), Ordering::SeqCst);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            anyhow::ensure!(
                !self.reject_above.is_some_and(|limit| arrived > limit),
                "server admits no more than {:?} concurrent requests",
                self.reject_above
            );

            match reply {
                Reply::Fail => anyhow::bail!("scripted failure for {taddress}"),
                Reply::Stall => Ok(self.stalling_stream()),
                Reply::CancelsThenStalls(token) => {
                    token.cancel();
                    Ok(self.stalling_stream())
                }
                Reply::CancelsWhileReplying(token) => {
                    token.cancel();
                    let (_sender, receiver) = channel(1);
                    Ok(ReceiverStream::new(receiver))
                }
                Reply::StoresRow {
                    coin,
                    account,
                    scope,
                    dindex,
                } => {
                    let mut connection = coin.get_connection().await.expect("own connection");
                    let tk = select_account_transparent(&mut connection, account, 0)
                        .await
                        .expect("transparent keys");
                    let (pk, address) = derive_transparent_address(
                        tk.xvk.as_ref().expect("xvk"),
                        scope,
                        dindex,
                        false,
                    )
                    .expect("derive");
                    store_account_transparent_addr(
                        &mut connection,
                        account,
                        scope,
                        dindex,
                        None,
                        &pk,
                        &address.encode(&Network::Main),
                        false,
                    )
                    .await
                    .expect("store the concurrently allocated row");
                    let (_sender, receiver) = channel(1);
                    Ok(ReceiverStream::new(receiver))
                }
                Reply::Trims {
                    coin,
                    account,
                    height,
                } => {
                    let mut connection = coin.get_connection().await.expect("own connection");
                    trim_sync_data(&mut connection, account, height)
                        .await
                        .expect("trim under the walk");
                    let (_sender, receiver) = channel(1);
                    Ok(ReceiverStream::new(receiver))
                }
                Reply::SyncsTo {
                    coin,
                    account,
                    height,
                } => {
                    let mut connection = coin.get_connection().await.expect("own connection");
                    synced_to(&mut connection, account, height).await;
                    let (_sender, receiver) = channel(1);
                    Ok(ReceiverStream::new(receiver))
                }
                Reply::Funded { height, after } => {
                    if !after.is_zero() {
                        tokio::time::sleep(after).await;
                    }
                    let (sender, receiver) = channel(1);
                    if (start..=end).contains(&height) {
                        sender
                            .send(Ok((height, transaction_paying(taddress, 10_000), 0)))
                            .await
                            .expect("queue payment");
                    }
                    drop(sender);
                    Ok(ReceiverStream::new(receiver))
                }
                Reply::Empty => {
                    let (_sender, receiver) = channel(1);
                    Ok(ReceiverStream::new(receiver))
                }
            }
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// The address the walk derives for `(scope, dindex)`. Address-keyed mocks must match on this.
    async fn taddress_at(
        connection: &mut SqliteConnection,
        account: u32,
        scope: u32,
        dindex: u32,
    ) -> String {
        let tk = select_account_transparent(connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, address) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), scope, dindex, false)
                .expect("derive");
        address.encode(&Network::Main)
    }

    /// Puts `(scope, dindex)` in the state that makes the walk skip it: stored, known used and
    /// backfilled past the seam — what a finished earlier walk leaves behind.
    async fn store_covered_address(
        connection: &mut SqliteConnection,
        account: u32,
        scope: u32,
        dindex: u32,
    ) {
        let tk = select_account_transparent(connection, account, 0)
            .await
            .expect("transparent keys");
        let (pk, address) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), scope, dindex, false)
                .expect("derive");
        store_account_transparent_addr(
            connection,
            account,
            scope,
            dindex,
            None,
            &pk,
            &address.encode(&Network::Main),
            false,
        )
        .await
        .expect("store");
        sqlx::query(
            "UPDATE transparent_address_accounts SET seen_used = 1, backfilled_height = 2000100
            WHERE account = ? AND scope = ? AND dindex = ?",
        )
        .bind(account)
        .bind(scope)
        .bind(dindex)
        .execute(connection)
        .await
        .expect("cover");
    }

    /// Runs a walk against `server` on a freshly restored account and returns how many addresses
    /// it added.
    async fn discover_against(
        connection: &mut SqliteConnection,
        account: u32,
        gap_limit: u32,
        concurrency: u32,
        server: impl LwdServer<
                CompactBlockStream = ReceiverStream<Result<CompactBlock>>,
                TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>,
                MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>,
            > + 'static,
    ) -> Result<u32> {
        discover_to(
            connection,
            account,
            2_000_100,
            gap_limit,
            concurrency,
            server,
        )
        .await
    }

    /// `discover_against` against a tip other than the fixture's.
    async fn discover_to(
        connection: &mut SqliteConnection,
        account: u32,
        end_height: u32,
        gap_limit: u32,
        concurrency: u32,
        server: impl LwdServer<
                CompactBlockStream = ReceiverStream<Result<CompactBlock>>,
                TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>,
                MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>,
            > + 'static,
    ) -> Result<u32> {
        let mut client: Client = Box::new(server);
        discover_transparent_addresses(
            &Network::Main,
            connection,
            &mut client,
            account,
            end_height,
            gap_limit,
            concurrency,
            |_| {},
            CancellationToken::new(),
        )
        .await
    }

    async fn restored_account(connection: &mut SqliteConnection) -> u32 {
        restore(connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore")
    }

    #[tokio::test]
    async fn discover_transparent_addresses_probes_a_batch_concurrently() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let server = ScriptedServer::holding(Duration::from_millis(20));

        discover_against(&mut connection, account, 8, 4, server.clone())
            .await
            .expect("discover");

        assert_eq!(4, server.peak());
    }

    /// Whatever the caller asks for, one connection never carries more than the cap.
    #[tokio::test]
    async fn discover_transparent_addresses_clamps_the_width_to_the_maximum() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let server = ScriptedServer::holding(Duration::from_millis(20));

        discover_against(&mut connection, account, 40, 64, server.clone())
            .await
            .expect("discover");

        assert_eq!(32, server.peak());
    }

    /// A caller that asks for no concurrency at all gets the sequential walk, not a stalled one.
    #[tokio::test]
    async fn discover_transparent_addresses_clamps_a_zero_concurrency_to_one() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let server = ScriptedServer::holding(Duration::from_millis(20));

        let n_added = discover_against(&mut connection, account, 2, 0, server.clone())
            .await
            .expect("discover");

        assert_eq!(n_added, 0);
        assert_eq!(
            server.requests().len(),
            7,
            "the same requests the width-1 walk makes"
        );
        assert_eq!(1, server.peak(), "one request on the wire at a time");
    }

    /// The request set a successful wide walk makes is the one the sequential walk makes — no
    /// address is probed that the narrow walk would not have reached.
    #[tokio::test]
    async fn discover_transparent_addresses_with_a_wide_batch_requests_exactly_what_the_sequential_walk_does(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;

        let (n_added, calls) = discover_with(&mut connection, account, 2, vec![], 16).await;

        assert_eq!(n_added, 0);
        assert_eq!(calls, 7, "four external candidates, three internal");
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0]);
    }

    /// A skipped index resets the gap where the sequential walk resets it — in index order, after
    /// the candidates before it were counted. Applying it while the batch is planned would cut the
    /// walk short of an address the narrow walk finds.
    #[tokio::test]
    async fn discover_transparent_addresses_counts_a_skipped_candidate_in_index_order() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        store_covered_address(&mut connection, account, 0, 5).await;
        let funded = taddress_at(&mut connection, account, 0, 25).await;
        let server = ScriptedServer::default();
        server.always(
            &funded,
            Reply::Funded {
                height: 2_000_050,
                after: Duration::ZERO,
            },
        );

        let n_added = discover_against(&mut connection, account, 20, 16, server)
            .await
            .expect("discover");

        assert_eq!(n_added, 1);
        assert_eq!(
            receive_dindexes(&mut connection, account).await,
            vec![0, 5, 25]
        );
    }

    /// A run of stored indexes the sync already covers costs the batch indexes, not requests: the
    /// next batch must still be free to probe the addresses beyond them.
    #[tokio::test]
    async fn discover_transparent_addresses_does_not_spend_a_stored_run_on_extra_probes() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        for dindex in 0..9 {
            store_covered_address(&mut connection, account, 0, dindex).await;
        }
        let server = ScriptedServer::default();

        discover_against(&mut connection, account, 2, 16, server.clone())
            .await
            .expect("discover");

        let mut expected = vec![];
        for dindex in 9..12 {
            expected.push(taddress_at(&mut connection, account, 0, dindex).await);
        }
        for dindex in 0..3 {
            expected.push(taddress_at(&mut connection, account, 1, dindex).await);
        }
        assert_eq!(expected, server.addresses());
    }

    /// The order rows were written in, which `receive_dindexes` cannot show.
    async fn receive_dindexes_by_rowid(
        connection: &mut SqliteConnection,
        account: u32,
    ) -> Vec<u32> {
        sqlx::query_scalar(
            "SELECT dindex FROM transparent_address_accounts
            WHERE account = ? AND scope = 0 ORDER BY rowid",
        )
        .bind(account)
        .fetch_all(connection)
        .await
        .expect("addresses")
    }

    /// A server that refuses concurrent requests must not be asked for a wide batch again and
    /// again: the first refusal halves the width for the rest of the walk.
    #[tokio::test]
    async fn discover_transparent_addresses_halves_the_batch_after_a_failed_probe() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let funded = taddress_at(&mut connection, account, 0, 5).await;
        let server = ScriptedServer::rejecting_above(2);
        server.always(
            &funded,
            Reply::Funded {
                height: 2_000_050,
                after: Duration::ZERO,
            },
        );

        let n_added = discover_against(&mut connection, account, 12, 4, server.clone())
            .await
            .expect("discover");

        assert_eq!(4, server.peak(), "the first batch is the wide one");
        assert_eq!(
            2,
            server
                .requests()
                .iter()
                .filter(|request| request.in_flight > 2)
                .count(),
            "only the first batch may exceed what the server admits"
        );
        assert_eq!(n_added, 1);
        assert!(receive_dindexes(&mut connection, account)
            .await
            .contains(&5));
    }

    /// At the window floor a failed probe is terminal for the candidate, so the retry is the only
    /// thing that can carry the walk past a server that refuses concurrency.
    #[tokio::test]
    async fn discover_transparent_addresses_recovers_at_the_window_floor_from_a_concurrency_rejection(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let funded = taddress_at(&mut connection, account, 0, 5).await;
        let server = ScriptedServer::rejecting_above(2);
        server.always(
            &funded,
            Reply::Funded {
                height: 2_000_050,
                after: Duration::ZERO,
            },
        );

        let n_added = discover_against(&mut connection, account, 8, 4, server)
            .await
            .expect("the retry recovers the walk");

        assert_eq!(n_added, 1);
        assert!(receive_dindexes(&mut connection, account)
            .await
            .contains(&5));
    }

    /// The halved width is one value for the whole invocation: the second scope must not start
    /// over at the width the server already refused.
    #[tokio::test]
    async fn discover_transparent_addresses_keeps_the_halved_width_across_scopes() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let server = ScriptedServer::rejecting_above(2);

        discover_against(&mut connection, account, 8, 4, server.clone())
            .await
            .expect("discover");

        let mut internal = HashSet::new();
        for dindex in 0..12 {
            internal.insert(taddress_at(&mut connection, account, 1, dindex).await);
        }
        for request in server.requests() {
            if internal.contains(&request.taddr) {
                assert!(
                    request.in_flight <= 2,
                    "the internal scope ran {} requests in flight",
                    request.in_flight
                );
            }
        }
    }

    /// `gap_limit` reaches the caller as `-1 as u32` when Kotlin asks for "no limit", so planning
    /// a batch from it must not overflow.
    #[tokio::test]
    async fn discover_transparent_addresses_with_the_maximum_gap_limit_fails_cleanly_instead_of_overflowing(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;

        let error = discover_against(
            &mut connection,
            account,
            u32::MAX,
            4,
            ScriptedServer::failing_everything(),
        )
        .await
        .expect_err("every request fails");

        assert!(
            error.to_string().contains("scripted failure"),
            "expected the server's failure, got {error}"
        );
    }

    /// The public store takes any `u32`, so the highest stored index can be `u32::MAX`.
    #[tokio::test]
    async fn discover_transparent_addresses_with_a_stored_index_at_u32_max_fails_cleanly_instead_of_overflowing(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        store_account_transparent_addr(
            &mut connection,
            account,
            0,
            u32::MAX,
            None,
            b"pk",
            "t1storedatthetop",
            false,
        )
        .await
        .expect("store the extreme index");

        let error = discover_against(
            &mut connection,
            account,
            2,
            4,
            ScriptedServer::failing_everything(),
        )
        .await
        .expect_err("every request fails");

        assert!(
            error.to_string().contains("scripted failure"),
            "expected the server's failure, got {error}"
        );
    }

    /// Answers come back in whatever order the server chooses; rows must still be written in index
    /// order, because that order is what the gap and the coverage record are built on.
    #[tokio::test]
    async fn discover_transparent_addresses_ingests_a_batch_in_index_order() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let slow = taddress_at(&mut connection, account, 0, 1).await;
        let quick = taddress_at(&mut connection, account, 0, 3).await;
        let server = ScriptedServer::default();
        server.always(
            &slow,
            Reply::Funded {
                height: 2_000_050,
                after: Duration::from_millis(30),
            },
        );
        server.always(
            &quick,
            Reply::Funded {
                height: 2_000_050,
                after: Duration::ZERO,
            },
        );

        let n_added = discover_against(&mut connection, account, 4, 4, server)
            .await
            .expect("discover");

        assert_eq!(n_added, 2);
        assert_eq!(
            receive_dindexes_by_rowid(&mut connection, account).await,
            vec![0, 1, 3]
        );
    }

    /// An address whose marker already sits at the tip needs no request at all, batched or not.
    #[tokio::test]
    async fn discover_transparent_addresses_skips_the_prefetch_for_an_address_backfilled_to_the_tip(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 2000100
            WHERE account = ? AND scope = 0 AND dindex = 0",
        )
        .bind(account)
        .execute(&mut connection)
        .await
        .expect("mark fully covered");

        let (n_added, calls) = discover_with(&mut connection, account, 2, vec![], 4).await;

        assert_eq!(n_added, 0);
        assert_eq!(calls, 6, "dindex 0 costs an index but no request");
    }

    /// A failed probe is retried once, as one whole-window request under the guard — the same
    /// request the sequential walk makes first, not a narrowed one.
    #[tokio::test]
    async fn discover_transparent_addresses_retries_a_failed_prefetch_once_as_one_sequential_request(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        synced_to(&mut connection, account, 2_005_000).await;
        let failing = taddress_at(&mut connection, account, 0, 1).await;
        let server = ScriptedServer::default();
        server.then_always(&failing, vec![Reply::Fail], Reply::Empty);

        discover_to(&mut connection, account, 2_005_000, 2, 4, server.clone())
            .await
            .expect("the retry carries the walk");

        let ranges = server.ranges_for(&failing);
        assert_eq!(2, ranges.len(), "one probe and one retry, got {ranges:?}");
        assert_eq!(
            ranges[0], ranges[1],
            "the retry asks for the same whole window"
        );
        assert_eq!(2_005_000, ranges[0].1, "and it reaches the tip");
        let retry = server
            .requests()
            .into_iter()
            .filter(|request| request.taddr == failing)
            .nth(1)
            .expect("the retry");
        assert_eq!(1, retry.in_flight, "the retry is a lone sequential request");
    }

    /// When the retry fails too, the candidate must narrow exactly as it does after the sequential
    /// walk's own first failure — the batched walk adds one request, nothing else.
    #[tokio::test]
    async fn discover_transparent_addresses_narrows_like_the_sequential_walk_when_the_retry_fails_too(
    ) {
        let mut sequential_db = memory_db().await;
        let sequential_account = restored_account(&mut sequential_db).await;
        synced_to(&mut sequential_db, sequential_account, 2_005_000).await;
        let taddr = taddress_at(&mut sequential_db, sequential_account, 0, 1).await;
        let sequential = ScriptedServer::default();
        sequential.then_always(&taddr, vec![Reply::Fail], Reply::Empty);
        discover_to(
            &mut sequential_db,
            sequential_account,
            2_005_000,
            2,
            1,
            sequential.clone(),
        )
        .await
        .expect("the sequential walk narrows and finishes");

        let mut batched_db = memory_db().await;
        let batched_account = restored_account(&mut batched_db).await;
        synced_to(&mut batched_db, batched_account, 2_005_000).await;
        let batched = ScriptedServer::default();
        batched.then_always(&taddr, vec![Reply::Fail, Reply::Fail], Reply::Empty);
        discover_to(
            &mut batched_db,
            batched_account,
            2_005_000,
            2,
            4,
            batched.clone(),
        )
        .await
        .expect("the batched walk narrows and finishes");

        let after_the_retry = sequential.ranges_for(&taddr);
        let mut expected = vec![after_the_retry[0]];
        expected.extend(after_the_retry);
        assert_eq!(expected, batched.ranges_for(&taddr));
    }

    /// A receive address allocated while a probe is in flight is an existing address by the time
    /// the walk ingests it, and the gap must be read from the row the walk re-reads under the
    /// guard — reading the one seen while planning would cut the walk short.
    #[tokio::test]
    async fn discover_transparent_addresses_counts_a_row_stored_by_a_concurrent_allocation_as_existing(
    ) {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let allocating = taddress_at(&mut connection, account, 0, 1).await;
        let funded = taddress_at(&mut connection, account, 0, 5).await;
        let server = ScriptedServer::default();
        server.always(
            &allocating,
            Reply::StoresRow {
                coin: coin.clone(),
                account,
                scope: 0,
                dindex: 2,
            },
        );
        server.always(
            &funded,
            Reply::Funded {
                height: 2_000_050,
                after: Duration::ZERO,
            },
        );

        let n_added = discover_against(&mut connection, account, 2, 4, server)
            .await
            .expect("discover");

        assert_eq!(
            receive_dindexes(&mut connection, account).await,
            vec![0, 2, 5]
        );
        assert_eq!(n_added, 2);
    }

    /// A cancellation seen anywhere in a batch ends the walk before any of that batch is written,
    /// so a row is never stored for a candidate whose window the walk then abandons.
    #[tokio::test]
    async fn discover_transparent_addresses_cancelled_during_a_batch_writes_nothing_from_that_batch(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        set_marker(&mut connection, id, Some(2_000_100)).await;
        let funded = taddress_at(&mut connection, account, 0, 1).await;
        let cancelling = taddress_at(&mut connection, account, 0, 2).await;
        let token = CancellationToken::new();
        let server = ScriptedServer::default();
        server.always(
            &funded,
            Reply::Funded {
                height: 2_000_050,
                after: Duration::ZERO,
            },
        );
        server.always(&cancelling, Reply::CancelsThenStalls(token.clone()));
        let mut client: Client = Box::new(server);

        let error = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            4,
            |_| {},
            token,
        )
        .await
        .expect_err("a cancelled batch must not report success");

        assert!(error.to_string().contains("cancel"), "{error}");
        assert!(
            transparent_address_row(&mut connection, account, 0, 1)
                .await
                .expect("row lookup")
                .is_none(),
            "nothing of the cancelled batch may be written"
        );
        assert!(
            !crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage")
                .certified
        );
    }

    /// The prefetch holds no guard, so a trim can land between a probe and its ingest. The walk
    /// must refuse to certify coverage it can no longer describe.
    #[tokio::test]
    async fn discover_transparent_addresses_refuses_to_certify_when_a_trim_lands_while_probes_are_in_flight(
    ) {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        set_marker(&mut connection, id, Some(2_000_100)).await;
        let trimming = taddress_at(&mut connection, account, 0, 1).await;
        let server = ScriptedServer::default();
        server.always(
            &trimming,
            Reply::Trims {
                coin: coin.clone(),
                account,
                height: 2_000_040,
            },
        );

        let error = discover_against(&mut connection, account, 2, 4, server)
            .await
            .expect_err("a trim during the walk invalidates the coverage");

        assert!(
            error.to_string().contains("invalidated by a trim"),
            "{error}"
        );
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_040)
        );
        assert!(
            !crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage")
                .certified
        );
    }

    /// A cancellation that arrives once a batch's probes have all succeeded is still a
    /// cancellation: every empty result is ingested without ever entering `fetch_window`'s select,
    /// so only a per-candidate check keeps the walk from certifying coverage it stopped short of.
    #[tokio::test]
    async fn discover_transparent_addresses_cancelled_after_a_successful_batch_does_not_certify() {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        synced_to(&mut connection, account, 2_000_100).await;
        let last = taddress_at(&mut connection, account, 1, 2).await;
        let token = CancellationToken::new();
        let server = ScriptedServer::default();
        server.always(&last, Reply::CancelsWhileReplying(token.clone()));
        let mut client: Client = Box::new(server);

        let error = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            4,
            |_| {},
            token,
        )
        .await
        .expect_err("a cancelled walk must not report success");

        assert!(error.to_string().contains("cancel"), "{error}");
        assert!(
            !crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage")
                .certified
        );
    }

    /// The prefetch holds no guard, so a concurrent synchronize can move the seam between a probe
    /// and its ingest — onto a chain that reply does not describe. The walk must ask again instead
    /// of committing the old answer against the new seam.
    #[tokio::test]
    async fn discover_transparent_addresses_refetches_a_prefetch_taken_before_the_seam_moved() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_040).await;
        let funded = taddress_at(&mut connection, account, 0, 1).await;
        let syncing = taddress_at(&mut connection, account, 0, 2).await;
        let server = ScriptedServer::default();
        server.then_always(
            &funded,
            vec![Reply::Funded {
                height: 2_000_050,
                after: Duration::ZERO,
            }],
            Reply::Empty,
        );
        server.always(
            &syncing,
            Reply::SyncsTo {
                coin: coin.clone(),
                account,
                height: 2_000_100,
            },
        );
        let observed = server.clone();

        let n_added = discover_against(&mut connection, account, 4, 4, server)
            .await
            .expect("discover");

        assert_eq!(
            2,
            observed.ranges_for(&funded).len(),
            "the reply obtained under the old seam must be asked for again"
        );
        assert_eq!(n_added, 0, "the stale payment must store no address row");
        assert_eq!(
            receive_dindexes(&mut connection, account).await,
            vec![0],
            "only the account's own address"
        );
    }

    /// A probe the server accepts and never answers must not park the walk: the prefetch carries
    /// its own deadline, and a timed-out probe is retried once like any other failed one.
    #[tokio::test]
    async fn discover_transparent_addresses_times_out_a_stalled_prefetch_and_retries_it_once() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        tokio::time::pause();
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        synced_to(&mut connection, account, 2_000_100).await;
        let stalling = taddress_at(&mut connection, account, 0, 1).await;
        let server = ScriptedServer::holding(Duration::from_millis(20));
        server.then_always(&stalling, vec![Reply::Stall], Reply::Empty);
        let observed = server.clone();
        let mut client: Client = Box::new(server);

        let mut task = tokio::spawn(async move {
            let result = discover_transparent_addresses(
                &Network::Main,
                &mut connection,
                &mut client,
                account,
                2_000_100,
                2,
                4,
                |_| {},
                CancellationToken::new(),
            )
            .await;
            (result, connection)
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            while observed.requests().len() < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the batch's requests never all started");

        tokio::time::advance(WINDOW_TIMEOUT + Duration::from_millis(1)).await;
        // The rest of the walk runs on the real clock: a paused one jumps to the next deadline at
        // every idle moment, which would expire windows the server answers at once.
        tokio::time::resume();

        let (result, _connection) = tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .expect("the walk did not finish once the prefetch deadline elapsed")
            .expect("walk task panicked");
        result.expect("the retry answers");

        let ranges = observed.ranges_for(&stalling);
        assert_eq!(
            2,
            ranges.len(),
            "one timed-out probe and one retry, got {ranges:?}"
        );
        assert_eq!(ranges[0], ranges[1], "the retry asks for the same window");
        assert_eq!(
            1,
            observed
                .requests()
                .iter()
                .filter(|request| request.in_flight > 2)
                .count(),
            "only the batch that timed out ran wider than the halved width"
        );
    }

    /// A server that serves one stream per connection: a request is refused while a stream it
    /// admitted is still open. `held`'s stream stays open until all three of its items have been
    /// handed over — the channel holds one, so the third `send` resolves only once the walk
    /// consumed the second during ingest — or until its receiver is dropped. `slow` checks
    /// admission after a delay, so it loses the race for the one slot.
    #[derive(Clone)]
    struct OneStreamAtATime {
        slow: String,
        held: String,
        open: Arc<AtomicU32>,
        /// How many streams were open at each admission check, in order.
        checks: Arc<Mutex<Vec<(String, u32)>>>,
    }

    #[async_trait]
    impl LwdServer for OneStreamAtATime {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), false)
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
            taddress: &str,
            _start: u32,
            _end: u32,
        ) -> Result<Self::TransactionStream> {
            if taddress == self.slow {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let open = self.open.load(Ordering::SeqCst);
            self.checks
                .lock()
                .expect("lock")
                .push((taddress.to_string(), open));
            anyhow::ensure!(open == 0, "the server serves one stream at a time");

            let (sender, receiver) = channel(1);
            if taddress == self.held {
                self.open.fetch_add(1, Ordering::SeqCst);
                let open = self.open.clone();
                let address = taddress.to_string();
                tokio::spawn(async move {
                    for value in 0..3u64 {
                        let item = (2_000_050, transaction_paying(&address, 10_000 + value), 0);
                        if sender.send(Ok(item)).await.is_err() {
                            break;
                        }
                    }
                    drop(sender);
                    open.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// The retry of a failed probe must reach the server alone: every sibling stream of the batch
    /// is dropped first, and the forwarder ends the request as soon as its receiver is gone.
    #[tokio::test]
    async fn discover_transparent_addresses_drops_its_siblings_prefetches_before_retrying_a_failed_probe(
    ) {
        let mut connection = memory_db().await;
        let account = restored_account(&mut connection).await;
        let refused = taddress_at(&mut connection, account, 0, 0).await;
        let held = taddress_at(&mut connection, account, 0, 1).await;
        let server = OneStreamAtATime {
            slow: refused.clone(),
            held,
            open: Arc::new(AtomicU32::new(0)),
            checks: Arc::new(Mutex::new(vec![])),
        };
        let checks = server.checks.clone();

        let n_added = discover_against(&mut connection, account, 2, 4, server)
            .await
            .expect("the retry reaches a server with nothing open");

        let for_refused: Vec<u32> = checks
            .lock()
            .expect("lock")
            .iter()
            .filter(|(taddr, _)| *taddr == refused)
            .map(|(_, open)| *open)
            .collect();
        assert_eq!(
            vec![1, 0],
            for_refused,
            "the probe was refused while a sibling was open, the retry found the server free"
        );
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0, 1]);
        assert_eq!(n_added, 1);
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
    /// `gap_limit + 1` never-stored addresses rather than run forever. The external scope makes
    /// one extra call: its dindex 0 is the account's own pre-existing address, which always
    /// resets the gap (an existing row counts as reached regardless of what backfill finds), so
    /// the walk needs one more never-stored address after it before the gap is exceeded.
    #[tokio::test]
    async fn discover_transparent_addresses_stops_after_the_gap_limit() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let (n_added, calls) = discover(&mut connection, account, 2, vec![]).await;

        assert_eq!(n_added, 0);
        assert_eq!(
            calls, 7,
            "four addresses in the external scope, three in the internal scope"
        );
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0]);
    }

    /// The per-window critical section lives inside the walk itself, so a discovery run must
    /// queue behind a sync that already holds `SYNCING` rather than running past it.
    #[tokio::test]
    async fn discover_transparent_addresses_waits_for_a_sync_holding_the_lock() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let guard = SYNCING.lock().await;

        let mut call = tokio::spawn(async move {
            let mut connection = memory_db().await;
            let account = restore(&mut connection, TEST_PHRASE, 0, None)
                .await
                .expect("restore");
            let (n_added, _) = discover(&mut connection, account, 2, vec![3]).await;
            (n_added, receive_dindexes(&mut connection, account).await)
        });

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        // 500ms, not 50ms: an unguarded walk still does real secp256k1 derivation and SQLite
        // writes for several candidates, which alone can take ~100ms in a debug build — a
        // shorter margin makes this assertion pass whether or not the guard is actually held.
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut call)
                .await
                .is_err(),
            "discovery must not complete while SYNCING is held"
        );

        drop(guard);
        let (n_added, dindexes) = tokio::time::timeout(Duration::from_secs(5), &mut call)
            .await
            .expect("discovery did not complete once SYNCING was released")
            .expect("discovery task panicked");

        assert_eq!(n_added, 1);
        assert_eq!(dindexes, vec![0, 2]);
    }

    /// Under a fair mutex the guard-release probe (see `GuardReleaseProbe`) can only observe
    /// itself running before the second candidate's request if the walk actually let `SYNCING` go
    /// between candidates, rather than holding it for the whole scan.
    #[tokio::test]
    async fn discover_transparent_addresses_releases_the_sync_guard_between_candidates() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let mut client: Client = Box::new(GuardReleaseProbe {
            calls: Arc::new(AtomicU32::new(0)),
            probe_ran: Arc::new(AtomicBool::new(false)),
        });

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            1,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");
    }

    /// The first call answers immediately with an empty stream so its window completes and
    /// advances normally; the second never sends and the sender is kept alive (not dropped), so
    /// `fetch_window`'s `rx.recv()` blocks until `WINDOW_TIMEOUT` trips instead of seeing a closed
    /// stream.
    #[derive(Clone)]
    struct HangsOnSecondCall {
        calls: Arc<AtomicU32>,
        hung_sender: Option<Sender<Result<(u32, Transaction, usize)>>>,
    }

    #[async_trait]
    impl LwdServer for HangsOnSecondCall {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), false)
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
            let (sender, receiver) = channel(1);
            if call == 1 {
                drop(sender);
            } else {
                self.hung_sender = Some(sender);
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// A stalled server must not be allowed to hold `SYNCING` past `WINDOW_TIMEOUT`: the deadline
    /// trips, the completed first window's marker is untouched, the stalled second window never
    /// wrote anything, and a later run against a healthy server re-requests the exact range the
    /// stall abandoned rather than resuming past it.
    ///
    /// Time is paused and advanced explicitly rather than relying on `start_paused`'s auto-advance:
    /// the first window still does real work through sqlx's background connection thread, and
    /// auto-advance cannot tell that stall apart from a task that is genuinely never going to make
    /// progress — it would race ahead and time out the healthy first window too. Spawning the walk
    /// and spinning on `yield_now` until the second call has started keeps the runtime's run queue
    /// non-empty (and auto-advance dormant) for as long as that real work is in flight; only once
    /// the second window is provably stuck behind a channel that will never resolve do we advance
    /// the clock ourselves, past a deadline whose timer is already armed.
    #[tokio::test]
    async fn discover_transparent_addresses_abandons_a_window_that_outlives_the_deadline() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        tokio::time::pause();
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;

        let calls = Arc::new(AtomicU32::new(0));
        let mut client: Client = Box::new(HangsOnSecondCall {
            calls: calls.clone(),
            hung_sender: None,
        });

        let mut task = tokio::spawn(async move {
            let result = discover_transparent_addresses(
                &Network::Main,
                &mut connection,
                &mut client,
                account,
                2_000_100,
                1,
                1,
                |_| {},
                CancellationToken::new(),
            )
            .await;
            (result, connection)
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            while calls.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the second window's call never started");

        tokio::time::advance(WINDOW_TIMEOUT + Duration::from_millis(1)).await;

        let (result, mut connection) = tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .expect("discover_transparent_addresses did not complete once the deadline elapsed")
            .expect("discover task panicked");

        assert!(
            result.is_err(),
            "a stalled window must fail once the deadline trips, not hang forever"
        );

        let row0 = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("query dindex 0")
            .expect("dindex 0 row exists");
        let marker0 = transparent_backfilled_height(&mut connection, row0.0)
            .await
            .expect("query dindex 0 marker");
        assert_eq!(
            marker0,
            Some(2_000_100),
            "the completed first window's marker must be intact"
        );

        let row1 = transparent_address_row(&mut connection, account, 0, 1)
            .await
            .expect("query dindex 1");
        assert!(
            row1.is_none(),
            "the stalled window must not have stored its own address row"
        );

        // Back to real time before the healthy retry: with the clock still paused, tokio
        // auto-advances to the next armed deadline whenever this task's sqlx work is briefly
        // pending, and times the healthy window out too.
        tokio::time::resume();

        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut healthy_client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: call_ranges.clone(),
            fail_wider_than: None,
            fail_mid_stream: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut healthy_client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover against a healthy server");

        let ranges = call_ranges.lock().expect("lock").clone();
        assert_eq!(
            ranges[0],
            (2_000_000, 2_000_100),
            "the retry must re-request exactly the range the stall abandoned, not resume past it"
        );
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
            fail_from_call: Some(1),
            block_time: None,
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
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

    /// A stream that errors on its first item says nothing about whether the address is used, so
    /// counting it as empty lets a funded address fall into the gap while the walk still certifies
    /// coverage it never established.
    #[tokio::test]
    async fn discover_transparent_addresses_fails_when_an_unstored_candidate_stream_errors() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: Some(2),
            block_time: None,
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result
            .expect_err("stream failure")
            .to_string()
            .contains("discovery stream failed"));
        assert!(
            !crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage")
                .certified,
            "a walk that never learned whether an address is used must not certify"
        );
    }

    /// Answers `taddress_txs` with a payment only when the requested address equals `target`,
    /// and an empty stream for every other address — the per-address targeting `UsedAtCalls`'s
    /// pure call-counter can't provide, needed once a test cares which specific derived address
    /// actually receives funds.
    #[derive(Clone)]
    struct FundedAddress {
        target: String,
        value: u64,
        height: u32,
        fail_block: bool,
    }

    #[async_trait]
    impl LwdServer for FundedAddress {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), self.fail_block)
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
            taddress: &str,
            start: u32,
            end: u32,
        ) -> Result<Self::TransactionStream> {
            let (sender, receiver) = channel(1);
            if taddress == self.target && (start..=end).contains(&self.height) {
                sender
                    .send(Ok((
                        self.height,
                        transaction_paying(&self.target, self.value),
                        0,
                    )))
                    .await
                    .expect("queue funding transaction");
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// A discovered address's actual funds must be ingested, not merely noticed — the fix's core
    /// promise: a one-time address the wallet never scanned now yields the note it always had.
    #[tokio::test]
    async fn discover_transparent_addresses_ingests_the_funds_of_a_discovered_address() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 1, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 5_000,
            height: 2_000_050,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 1);
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0, 1]);
        let value: i64 = sqlx::query_scalar("SELECT value FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("note");
        assert_eq!(value, 5_000);
    }

    /// An address that already has a row can still carry a gap in its own coverage (e.g. its
    /// history was never fetched) — the walk must backfill it exactly as it would a freshly
    /// discovered one, ingesting whatever funds it actually received.
    #[tokio::test]
    async fn discover_transparent_addresses_backfills_an_address_already_in_the_database() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 0, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target,
            value: 7_500,
            height: 2_000_050,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 0, "the address already had a row");
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100)
        );
        let value: i64 = sqlx::query_scalar("SELECT value FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("note");
        assert_eq!(value, 7_500);
    }

    /// A wide walk can leave a change address stored far past where a later narrow walk would
    /// stop. Trailing-gap termination must not certify coverage while such a row still owes a
    /// backfill: the walk has to reach the highest index already stored for the scope.
    #[tokio::test]
    async fn discover_transparent_addresses_walks_through_a_stored_index_beyond_the_gap_limit() {
        const GAP_LIMIT: u32 = 20;
        const STORED_DINDEX: u32 = 25;
        const TIP: u32 = 2_000_100;

        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let change = derived_taddress(&mut connection, account, 1, STORED_DINDEX).await;
        insert_scoped_taddress_for_account(
            &mut connection,
            account,
            900,
            1,
            STORED_DINDEX,
            &change,
        )
        .await;

        let mut client: Client = Box::new(FundedAddresses {
            targets: vec![change.clone()],
            value: 6_250,
            height: 2_000_050,
        });

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            TIP,
            GAP_LIMIT,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        let (id, _) = transparent_address_row(&mut connection, account, 1, STORED_DINDEX)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(TIP),
            "a stored index past the gap limit still owes a backfill"
        );
        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &change)
                .await
                .expect("balance"),
            6_250,
            "its funds must be ingested, not left invisible"
        );
    }

    /// `reset_sync` clamps a fully-backfilled marker to `0`, not `NULL`. The next backfill must
    /// still start at `birth_height` (via `discover_transparent_addresses`'s own `.max(birth_height)`)
    /// and — the part a `COALESCE`-only floor in `advance_backfilled_height` gets wrong — the marker
    /// update has to land against that floor too, or the walk keeps reporting incomplete coverage
    /// and failing forever even though the funds it re-ingested are already back.
    #[tokio::test]
    async fn reset_sync_restores_a_backfill_from_the_birth_height() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 0, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 7_500,
            height: 2_000_050,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("initial backfill");
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100),
            "sanity: fully backfilled before reset"
        );

        crate::account::reset_sync(&Network::Main, &mut connection, account)
            .await
            .expect("reset_sync");

        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(0),
            "reset_sync clamps the marker to 0, not NULL"
        );
        let notes_after_reset: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM notes WHERE account = ?")
                .bind(account)
                .fetch_one(&mut connection)
                .await
                .expect("note count");
        assert_eq!(notes_after_reset, 0, "sanity: reset_sync deleted the note");
        synced_to(&mut connection, account, 2_000_100).await;

        let mut client: Client = Box::new(FundedAddress {
            target,
            value: 7_500,
            height: 2_000_050,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("backfill after reset must land, not report incomplete coverage forever");

        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100),
            "the marker must reach backfill_end again, not stay stuck at 0"
        );
        let value: i64 = sqlx::query_scalar("SELECT value FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("note");
        assert_eq!(value, 7_500, "the note reset_sync deleted must be back");
    }

    /// An address already backfilled to at least the tip needs no network call at all — the
    /// whole point of the marker is to make a re-run of discovery a no-op for addresses it
    /// already fully covered.
    #[tokio::test]
    async fn discover_transparent_addresses_skips_an_address_backfilled_up_to_the_tip() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 2000100
            WHERE account = ? AND scope = 0 AND dindex = 0",
        )
        .bind(account)
        .execute(&mut connection)
        .await
        .expect("mark fully covered");

        let (n_added, calls) = discover(&mut connection, account, 2, vec![]).await;

        assert_eq!(n_added, 0);
        assert_eq!(
            calls, 6,
            "one fewer than the 7 in the unmarked baseline: dindex 0 is never called"
        );
    }

    /// A window request whose width the server rejects gets halved and retried, not abandoned —
    /// the same address is still walked, just in smaller pieces.
    #[tokio::test]
    async fn discover_transparent_addresses_halves_the_window_after_a_failed_request() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: call_ranges.clone(),
            fail_wider_than: Some(1_500),
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_003_000,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result.is_ok(), "{result:?}");
        let ranges = call_ranges.lock().expect("lock").clone();
        assert_eq!(
            ranges[0],
            (2_000_000, 2_003_000),
            "first attempt uses the full width"
        );
        assert!(
            ranges[1].1 - ranges[1].0 <= 1_500,
            "retry narrows below the server's limit: {:?}",
            ranges[1]
        );
    }

    /// A stream that dies partway through a window is a fetch-stage failure just like a rejected
    /// request: the window must narrow and be retried, not propagate as if the database broke.
    #[tokio::test]
    async fn discover_transparent_addresses_halves_the_window_when_the_stream_fails_mid_window() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: call_ranges.clone(),
            fail_wider_than: Some(1_500),
            fail_mid_stream: true,
        });

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_003_000,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("a stream that dies mid-window is retried narrower, not propagated");

        let ranges = call_ranges.lock().expect("lock").clone();
        assert_eq!(
            ranges[0],
            (2_000_000, 2_003_000),
            "first attempt uses the full width"
        );
        assert!(
            ranges[1].1 - ranges[1].0 <= 1_500,
            "retry narrows below the width the stream survives: {:?}",
            ranges[1]
        );
    }

    /// One payment to the address under test, served by every request whose range covers its
    /// height. `fail_wider_than` makes a wider request announce the payment and then die
    /// mid-stream; `serves_left` caps how many times the server ever hands it over, so a server
    /// that reports a transaction and then withholds it can be built. `fail_blocks` fails that
    /// many block lookups before the first one succeeds.
    #[derive(Clone)]
    struct FlakyPayment {
        taddress: String,
        value: u64,
        height: u32,
        fail_wider_than: Option<u32>,
        /// Accepts a wider window and then never answers it, the way a hung server does.
        stall_wider_than: Option<u32>,
        /// Reports the payment and then never ends the stream, the way a server that dies
        /// after answering does.
        stall_after_payment: bool,
        /// Set once a consumer has taken the reported payment off the stream. That is the point
        /// after which the window is provably parked on the next item, so a test can expire its
        /// deadline without racing the ingestion it is about to drop.
        consumed: Arc<AtomicBool>,
        calls: Arc<AtomicU32>,
        serves_left: Option<Arc<AtomicU32>>,
        fail_blocks: Arc<AtomicU32>,
        /// How many distinct payments a window containing `height` carries.
        payments: usize,
        /// Payments only the FIRST answer carries: a server that reports more than one window
        /// can hold and then omits the excess from every retry.
        withheld_after_first_call: usize,
    }

    #[async_trait]
    impl LwdServer for FlakyPayment {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            let fail = self.fail_blocks.load(Ordering::Relaxed) > 0;
            if fail {
                self.fail_blocks.fetch_sub(1, Ordering::Relaxed);
            }
            block_response(height, Some(12345), fail)
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
            start: u32,
            end: u32,
        ) -> Result<Self::TransactionStream> {
            let first_call = self.calls.fetch_add(1, Ordering::Relaxed) == 0;
            if self
                .stall_wider_than
                .is_some_and(|width| end - start > width)
            {
                std::future::pending::<()>().await;
            }
            let withheld = if first_call {
                self.withheld_after_first_call
            } else {
                0
            };
            let (sender, receiver) = channel(self.payments + withheld + 1);
            let mut served = false;
            let serves = self
                .serves_left
                .as_ref()
                .is_none_or(|left| left.load(Ordering::Relaxed) > 0);
            if (start..=end).contains(&self.height) && serves {
                if let Some(left) = self.serves_left.as_ref() {
                    left.fetch_sub(1, Ordering::Relaxed);
                }
                for i in 0..self.payments + withheld {
                    sender
                        .send(Ok((
                            self.height,
                            transaction_paying(&self.taddress, self.value + i as u64),
                            0,
                        )))
                        .await
                        .expect("queue payment");
                }
                served = true;
            }
            if self
                .fail_wider_than
                .is_some_and(|width| end - start > width)
            {
                sender
                    .send(Err(anyhow::anyhow!("stream died mid-window")))
                    .await
                    .expect("queue error");
            }
            if self.stall_after_payment && served {
                let consumed = self.consumed.clone();
                let queued = self.payments + withheld + 1;
                // The task owning `sender` is what keeps the stream open. Reserving the channel's
                // whole capacity can only be granted once the consumer has popped every payment,
                // which is the rendezvous.
                tokio::spawn(async move {
                    let _rendezvous = sender
                        .reserve_many(queued)
                        .await
                        .expect("reserve on consumption");
                    consumed.store(true, Ordering::Relaxed);
                    std::future::pending::<()>().await;
                });
            } else {
                drop(sender);
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    fn flaky_payment(taddress: &str) -> FlakyPayment {
        FlakyPayment {
            taddress: taddress.to_string(),
            value: 5_000,
            height: 2_000_050,
            fail_wider_than: None,
            stall_wider_than: None,
            stall_after_payment: false,
            consumed: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicU32::new(0)),
            serves_left: None,
            fail_blocks: Arc::new(AtomicU32::new(0)),
            payments: 1,
            withheld_after_first_call: 0,
        }
    }

    /// The one candidate every flaky-payment walk targets: receive index 1 of a restored account.
    async fn candidate_address(
        connection: &mut SqliteConnection,
        account: u32,
    ) -> (Vec<u8>, TransparentAddress, String) {
        let tk = select_account_transparent(connection, account, 0)
            .await
            .expect("transparent keys");
        let (pk, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 1, false).expect("derive");
        let taddr = addr.encode(&Network::Main);
        (pk, addr, taddr)
    }

    /// Walks that candidate over `[2_000_000, 2_003_000]` against a `FlakyPayment` the caller
    /// tunes — wide enough that a narrowed retry splits it into several tiles.
    async fn walk_flaky_candidate(
        connection: &mut SqliteConnection,
        account: u32,
        configure: impl FnOnce(&mut FlakyPayment),
    ) -> Result<(Option<(u32, String)>, bool), BackfillError> {
        walk_flaky_candidate_until(
            connection,
            account,
            None,
            &CancellationToken::new(),
            configure,
        )
        .await
    }

    async fn walk_flaky_candidate_until(
        connection: &mut SqliteConnection,
        account: u32,
        row: Option<(u32, String)>,
        cancellation_token: &CancellationToken,
        configure: impl FnOnce(&mut FlakyPayment),
    ) -> Result<(Option<(u32, String)>, bool), BackfillError> {
        let identity = account_identity(connection, account)
            .await
            .expect("identity")
            .expect("account exists");
        let (pk, addr, taddr) = candidate_address(connection, account).await;
        let mut payment = flaky_payment(&taddr);
        configure(&mut payment);
        let mut client: Client = Box::new(payment);

        walk_candidate(
            &Network::Main,
            connection,
            &mut client,
            account,
            &identity,
            2_000_000,
            0,
            1,
            row,
            &addr,
            None,
            &pk,
            &taddr,
            2_000_000,
            2_003_000,
            cancellation_token,
            None,
        )
        .await
    }

    async fn note_values_at(connection: &mut SqliteConnection, id_taddress: u32) -> Vec<i64> {
        sqlx::query_scalar("SELECT value FROM notes WHERE taddress = ?")
            .bind(id_taddress)
            .fetch_all(connection)
            .await
            .expect("notes")
    }

    /// The normal shape of a mid-stream failure: the narrowed retry re-delivers what the wide
    /// window only announced, so the payment is committed and the range is certified.
    #[tokio::test]
    async fn walk_candidate_ingests_a_payment_a_narrowed_retry_redelivers() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_003_000).await;

        let (row, used) = walk_flaky_candidate(&mut connection, account, |payment| {
            payment.fail_wider_than = Some(1_500);
        })
        .await
        .map_err(anyhow::Error::from)
        .expect("walk");

        let (id_taddress, _) = row.expect("the announced address must be stored");
        assert!(used, "the announced payment proves the address used");
        assert_eq!(
            note_values_at(&mut connection, id_taddress).await,
            vec![5_000]
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id_taddress).await,
            Some(2_003_000),
            "a re-delivered payment leaves the whole range certified"
        );
    }

    /// A user who leaves mid-request must not be held by the server: cancellation has to be
    /// polled while the window's first request is still in flight, not only once it answers.
    #[tokio::test]
    async fn walk_candidate_stops_when_cancelled_during_its_first_request() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let calls = Arc::new(AtomicU32::new(0));
        let cancellation_token = CancellationToken::new();

        let canceller = {
            let calls = calls.clone();
            let cancellation_token = cancellation_token.clone();
            async move {
                wait_for_calls(&calls, 1).await;
                cancellation_token.cancel();
            }
        };
        let walk = walk_flaky_candidate_until(
            &mut connection,
            account,
            None,
            &cancellation_token,
            |payment| {
                payment.stall_wider_than = Some(0);
                payment.calls = calls.clone();
            },
        );
        let (result, ()) = tokio::join!(walk, canceller);

        assert!(
            matches!(result, Err(BackfillError::Cancelled)),
            "a cancelled request must stop the walk"
        );
        assert!(
            transparent_address_row(&mut connection, account, 0, 1)
                .await
                .expect("row lookup")
                .is_none(),
            "a cancelled probe must store nothing"
        );
    }

    /// A stalled window is the same slow-server story as a rejected one, and a candidate's range
    /// spans the account's whole history: failing the walk on the first deadline would strand
    /// every wallet whose server needs longer than `WINDOW_TIMEOUT` for a wide window.
    #[tokio::test]
    async fn walk_candidate_narrows_its_window_when_the_server_stalls() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_003_000).await;
        let calls = Arc::new(AtomicU32::new(0));

        // Paused only now: the restore above is real work, and auto-advance would fire the
        // deadline of a window that is merely waiting on sqlx's blocking thread.
        tokio::time::pause();
        let stalls = calls.clone();
        let driver = async move {
            // 3001 blocks, then 1500, are both too wide for this server; halving 1500 lands under
            // the floor, so the floor width is what finally gets an answer.
            for stall in 1..=2 {
                wait_for_calls(&stalls, stall).await;
                tokio::time::advance(WINDOW_TIMEOUT + Duration::from_millis(1)).await;
            }
            wait_for_calls(&stalls, 3).await;
            tokio::time::resume();
        };
        let walk = walk_flaky_candidate(&mut connection, account, |payment| {
            payment.stall_wider_than = Some(MIN_BACKFILL_WINDOW);
            payment.calls = calls.clone();
        });
        let (result, ()) = tokio::join!(walk, driver);

        let (row, used) = result
            .map_err(anyhow::Error::from)
            .expect("a server that answers a narrower window must not fail the walk");
        let (id_taddress, _) = row.expect("the payment's address must be stored");
        assert!(used, "the payment proves the address used");
        assert_eq!(
            note_values_at(&mut connection, id_taddress).await,
            vec![5_000]
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id_taddress).await,
            Some(2_003_000),
            "the narrowed windows must tile the range without a hole"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            6,
            "two stalled windows, then four tiles at the floor width"
        );
    }

    /// The window buffers every transparent input the stream carries until it drains, so a server
    /// that never stops sending would grow that buffer until the process dies. The cap is what
    /// turns an endless stream into a failed window instead.
    #[tokio::test]
    async fn drain_transparent_window_fails_a_window_that_outgrows_the_input_buffer() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (_, addr, _) = candidate_address(&mut connection, account).await;

        let (sender, mut rx) = channel(MAX_BUFFERED_VINS + 2);
        for i in 0..=MAX_BUFFERED_VINS {
            sender
                .send(Ok((2_000_050, transaction_spending(&[i as u8; 32], 0), 0)))
                .await
                .expect("queue spend");
        }
        drop(sender);

        let error = drain_transparent_window(&addr, None, &mut rx, 2_000_000, 2_003_000)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
            .expect_err("a stream that outgrows the buffer must fail the window");

        assert!(
            error.to_string().contains("more transparent inputs"),
            "the window must fail on the input cap, not on something else: {error}"
        );
    }

    /// One transaction may pay the same address any number of times, so a single answer can carry
    /// more notes than the whole window is allowed to hold in memory.
    #[tokio::test]
    async fn drain_transparent_window_fails_a_window_that_outgrows_the_output_buffer() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (_, addr, taddr) = candidate_address(&mut connection, account).await;

        let (sender, mut rx) = channel(2);
        sender
            .send(Ok((
                2_000_050,
                transaction_paying_outputs(&taddr, 5_000, MAX_BUFFERED_NOTES as u8 + 1),
                0,
            )))
            .await
            .expect("queue payment");
        drop(sender);

        let error = drain_transparent_window(&addr, None, &mut rx, 2_000_000, 2_003_000)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
            .expect_err("a transaction that outgrows the buffer must fail the window");

        assert!(
            error.to_string().contains("more transparent outputs"),
            "the window must fail on the output cap, not on something else: {error}"
        );
    }

    /// A shielded-to-transparent payment carries no transparent input, so a stream of them never
    /// trips the input cap. What grows instead is the list of transactions the window buffers.
    #[tokio::test]
    async fn drain_transparent_window_fails_a_window_that_outgrows_the_transaction_buffer() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (_, addr, taddr) = candidate_address(&mut connection, account).await;

        let (sender, mut rx) = channel(MAX_BUFFERED_TXS + 2);
        for i in 0..=MAX_BUFFERED_TXS {
            sender
                .send(Ok((
                    2_000_050,
                    transaction_paying(&taddr, 1_000 + i as u64),
                    0,
                )))
                .await
                .expect("queue payment");
        }
        drop(sender);

        let error = drain_transparent_window(&addr, None, &mut rx, 2_000_000, 2_003_000)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
            .expect_err("a stream that outgrows the transaction buffer must fail the window");

        assert!(
            error
                .to_string()
                .contains("more transactions than one window"),
            "the window must fail on the transaction cap, not on something else: {error}"
        );
    }

    /// The candidate's row is read before the walk, and an account can be deleted and restored
    /// from the same seed in between — the identity check passes, but the row is a new one. A
    /// note bound to the id that is gone would be invisible and unspendable.
    #[tokio::test]
    async fn walk_candidate_ingests_into_the_row_the_database_has_now() {
        const STALE_ID: u32 = 4_000;
        const CURRENT_ID: u32 = 4_100;

        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_003_000).await;
        let (_, _, taddr) = candidate_address(&mut connection, account).await;
        insert_scoped_taddress_for_account(&mut connection, account, CURRENT_ID, 0, 1, &taddr)
            .await;

        let (row, _) = walk_flaky_candidate_until(
            &mut connection,
            account,
            Some((STALE_ID, taddr.clone())),
            &CancellationToken::new(),
            |_| {},
        )
        .await
        .map_err(anyhow::Error::from)
        .expect("walk");

        assert_eq!(row.expect("the walk keeps a row").0, CURRENT_ID);
        assert_eq!(
            note_values_at(&mut connection, STALE_ID).await,
            Vec::<i64>::new(),
            "the replaced row must not carry the note"
        );
        assert_eq!(
            note_values_at(&mut connection, CURRENT_ID).await,
            vec![5_000]
        );
    }

    /// Use is a property of the address, not of the window that happened to succeed: a payment
    /// that commits and then loses its block lookup is still use, even though every narrowed
    /// retry after it comes back empty. Losing it would let the gap counter close too early.
    #[tokio::test]
    async fn walk_candidate_keeps_the_use_evidence_across_a_block_fetch_retry() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_003_000).await;

        let (row, used) = walk_flaky_candidate(&mut connection, account, |payment| {
            payment.serves_left = Some(Arc::new(AtomicU32::new(1)));
            payment.fail_blocks = Arc::new(AtomicU32::new(1));
        })
        .await
        .map_err(anyhow::Error::from)
        .expect("walk");

        let (id_taddress, _) = row.expect("the funded address must be stored");
        assert_eq!(
            note_values_at(&mut connection, id_taddress).await,
            vec![5_000]
        );
        assert!(
            used,
            "a committed payment stays use evidence after its block lookup is retried"
        );
    }

    /// A re-delivered payment is settled by its commit, not by the block lookup that follows it:
    /// the note is already in the database, so losing the timestamp fetch must only cost a retry.
    /// Holding the announcement open past the commit would let a later empty tile conclude the
    /// server had withheld a payment it had in fact handed over, and fail a sound walk.
    #[tokio::test]
    async fn walk_candidate_settles_a_redelivery_whose_block_lookup_fails() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_003_000).await;

        let (row, _) = walk_flaky_candidate(&mut connection, account, |payment| {
            payment.fail_wider_than = Some(1_500);
            payment.serves_left = Some(Arc::new(AtomicU32::new(2)));
            payment.fail_blocks = Arc::new(AtomicU32::new(1));
        })
        .await
        .map_err(anyhow::Error::from)
        .expect("a committed re-delivery must not fail the walk");

        let (id_taddress, _) = row.expect("the funded address must be stored");
        assert_eq!(
            note_values_at(&mut connection, id_taddress).await,
            vec![5_000]
        );
        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("transaction time");
        assert_eq!(
            time, 12345,
            "the retried block lookup must date the payment"
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id_taddress).await,
            Some(2_003_000),
            "a settled re-delivery leaves the whole range certified"
        );
    }

    /// The keys, indices and birth height the walk derives from, and the identity every later
    /// check compares against, must come from one guarded read: a delete plus a restore between
    /// them would leave the walk deriving addresses from the old account's key while every
    /// identity check passes against the new one.
    #[tokio::test]
    async fn discover_transparent_addresses_snapshots_the_account_under_the_sync_guard() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let guard = SYNCING.lock().await;

        let mut call = tokio::spawn(async move {
            let mut client: Client = Box::new(EmptyStreams {
                calls: Arc::new(AtomicU32::new(0)),
                fail_at_call: None,
                stream_failures: Arc::new(AtomicU32::new(0)),
                block_time: None,
                fail_block: false,
            });
            // An account id nothing was ever stored under: every read of it fails at once, so a
            // slow run can only mean the snapshot is waiting for the guard.
            discover_transparent_addresses(
                &Network::Main,
                &mut connection,
                &mut client,
                account + 1,
                2_000_100,
                0,
                1,
                |_| {},
                CancellationToken::new(),
            )
            .await
        });

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut call)
                .await
                .is_err(),
            "the account snapshot must wait for the guard"
        );

        drop(guard);
        let result = tokio::time::timeout(Duration::from_secs(5), &mut call)
            .await
            .expect("discovery did not finish once SYNCING was released")
            .expect("discovery task panicked");
        assert!(
            result.is_err(),
            "an account that does not exist cannot be walked: {result:?}"
        );
    }

    /// The block lookup that dates a committed transaction is a network round-trip too, so a
    /// failure there narrows the window instead of aborting the walk at full width.
    #[tokio::test]
    async fn discover_transparent_addresses_narrows_the_window_when_a_block_fetch_fails() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_003_000).await;
        sqlx::query(
            "INSERT INTO transactions (account, txid, height, time) VALUES (?, x'01', ?, 0)",
        )
        .bind(account)
        .bind(2_000_500)
        .execute(&mut connection)
        .await
        .expect("undated transaction");
        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: None,
            fail_block: true,
            call_ranges: call_ranges.clone(),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_003_000,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result.is_err(), "a block that never arrives ends the walk");
        let ranges = call_ranges.lock().expect("lock").clone();
        assert_eq!(
            ranges[0],
            (2_000_000, 2_003_000),
            "first attempt uses the full width"
        );
        assert!(
            ranges[1].1 - ranges[1].0 < ranges[0].1 - ranges[0].0,
            "the block failure narrows the window: {:?}",
            ranges
        );
    }

    /// Once the window can no longer shrink, a further failure must surface instead of looping
    /// forever at the floor.
    #[tokio::test]
    async fn discover_transparent_addresses_propagates_a_failure_at_the_minimum_window() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: None,
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: Some(900),
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_003_000,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result
            .expect_err("floor request still fails")
            .to_string()
            .contains("window wider than the server allows"));
    }

    /// A restored account always gets sync_heights rows; if that invariant is ever violated the
    /// scan must fail loudly rather than silently skip the seam-based coverage check.
    #[tokio::test]
    async fn discover_transparent_addresses_without_sync_heights_fails_instead_of_reporting_success(
    ) {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        sqlx::query("DELETE FROM sync_heights WHERE account = ?")
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("clear sync_heights");
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: None,
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result
            .expect_err("no sync_heights row")
            .to_string()
            .contains("account has no sync_heights row"));
    }

    /// The tip handed to discovery can lag the account's own recorded progress; the walk can
    /// only cover up to that tip, so it must report incompleteness rather than certify coverage
    /// the account's own sync_heights already exceed.
    #[tokio::test]
    async fn discover_transparent_addresses_reports_incomplete_when_the_server_tip_is_below_the_seam(
    ) {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(3_000_000u32)
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("advance seam past the tip");
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result
            .expect_err("tip below the seam leaves coverage short")
            .to_string()
            .contains("transparent coverage incomplete"));
    }

    /// The record a completed walk leaves behind is the only thing that certifies coverage;
    /// without it the receive screen can never present an address as scanned.
    #[tokio::test]
    async fn discover_transparent_addresses_certifies_its_own_coverage() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        assert!(
            !crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage")
                .certified,
            "no walk has run yet"
        );

        discover(&mut connection, account, 2, vec![3]).await;

        let coverage = crate::db::read_transparent_coverage(&mut connection, account)
            .await
            .expect("coverage");
        assert!(coverage.certified);
        assert_eq!(coverage.gap, 2);
    }

    /// A walk that ends short must certify nothing: a record it did not earn would present an
    /// address from a range the wallet has never scanned as safe to hand out.
    #[tokio::test]
    async fn discover_transparent_addresses_does_not_certify_an_incomplete_walk() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(3_000_000u32)
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("advance seam past the tip");
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect_err("tip below the seam leaves coverage short");

        let coverage = crate::db::read_transparent_coverage(&mut connection, account)
            .await
            .expect("coverage");
        assert!(!coverage.certified);
        assert_eq!(coverage.gap, 0);
    }

    /// A stored row's own empty delta must not count as a gap: only an index the walk never
    /// stored contributes to the counter, or a wallet with widely spaced addresses would lose
    /// later ones even though every address in between is accounted for.
    #[tokio::test]
    async fn discover_transparent_addresses_counts_a_gap_only_for_addresses_it_never_stored() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        insert_scoped_taddress_for_account(
            &mut connection,
            account,
            50,
            0,
            1,
            "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC",
        )
        .await;

        let (n_added, calls) = discover(&mut connection, account, 2, vec![]).await;

        assert_eq!(n_added, 0, "dindex 0 and 1 both already had rows");
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0, 1]);
        assert_eq!(
            calls, 8,
            "external scope: dindex 0 and 1 reset the gap for free; 2, 3, 4 exhaust the limit \
             of 2 (5 calls); internal scope has no existing row: 0, 1, 2 exhaust it (3 calls)"
        );
    }

    /// The tip discovery was handed can lag the account's own recorded progress. The marker it
    /// writes must reflect what the walk actually covered, not be forged up to a seam it never
    /// reached.
    #[tokio::test]
    async fn discover_transparent_addresses_does_not_mark_when_the_tip_lags_local_sync() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(3_000_000u32)
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("advance seam past the tip");
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result.is_err(), "coverage is short of the seam");
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100),
            "the marker must land at end_height, not be forged up to the seam"
        );
    }

    /// A historical transaction recovered by a backfill window must carry the funding block's
    /// actual time, not the placeholder `0` the ingest insert writes before the enrichment pass
    /// runs.
    #[tokio::test]
    async fn discover_transparent_addresses_fills_the_time_of_a_recovered_transaction() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 1, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target,
            value: 5_000,
            height: 2_000_050,
            fail_block: false,
        });

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("transaction");
        assert_eq!(
            time, 12345,
            "the recovered transaction must carry the block's real time"
        );
    }

    /// A window whose ingest committed but whose block-time enrichment then fails must not
    /// still advance the marker: the address stays unmarked so the next run retries the same
    /// range instead of certifying coverage over a transaction dated zero forever.
    #[tokio::test]
    async fn discover_transparent_addresses_does_not_mark_when_the_block_time_lookup_fails() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 0, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target,
            value: 5_000,
            height: 2_000_050,
            fail_block: true,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result.is_err(), "a failed block-time lookup must surface");
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            None,
            "the address must stay unmarked when its block time could not be filled"
        );
    }

    /// Sends a funding transaction for `target` immediately, then blocks on a `Notify` this test
    /// never releases before sending a second — a genuine remainder stays pending so
    /// cancellation is the only branch of the walk's `select!` that can ever become ready.
    #[derive(Clone)]
    struct GatedFundedStream {
        target: String,
        value: u64,
        release_second: Arc<Notify>,
    }

    #[async_trait]
    impl LwdServer for GatedFundedStream {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

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
            let (sender, receiver) = channel(2);
            sender
                .send(Ok((
                    2_000_050,
                    transaction_paying(&self.target, self.value),
                    0,
                )))
                .await
                .expect("queue funding transaction");
            let release_second = self.release_second.clone();
            tokio::spawn(async move {
                release_second.notified().await;
                let _ = sender.send(Ok((2_000_051, any_transaction(), 0))).await;
            });
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// Cancellation fired only once the walk is already blocked on the gated second item — not
    /// pre-queued before the call — so the funded first item has genuinely been written into the
    /// still-open `db_tx` by the time cancellation wins the race. The whole window, that write
    /// included, must roll back, neither the marker nor a coverage record may advance past what
    /// was never actually covered, and the call must report the interruption: an `Ok` would let a
    /// caller memoize a half-finished walk as a completed one.
    #[tokio::test]
    async fn discover_transparent_addresses_cancels_before_draining_the_rest_of_the_stream() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 0, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(GatedFundedStream {
            target,
            value: 5_000,
            release_second: Arc::new(Notify::new()),
        });
        let cancellation_token = CancellationToken::new();
        let token_for_walk = cancellation_token.clone();

        let call = tokio::spawn(async move {
            let result = discover_transparent_addresses(
                &Network::Main,
                &mut connection,
                &mut client,
                account,
                2_000_100,
                0,
                1,
                |_| {},
                token_for_walk,
            )
            .await;
            (result, connection)
        });

        // Give the spawned walk enough turns to fetch the window, write the funded item's
        // transaction/note rows and block on the gated second item's `rx.recv()` before
        // cancellation is raised — cancelling any earlier could race a still-pending `first`.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        cancellation_token.cancel();

        let (result, mut connection) = tokio::time::timeout(Duration::from_secs(5), call)
            .await
            .expect("walk did not finish after cancellation")
            .expect("walk task panicked");

        let error = result.expect_err("a cancelled walk must not report success");
        assert!(
            error.to_string().contains("cancel"),
            "the failure must name cancellation, got: {error}"
        );

        let transactions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM transactions")
            .fetch_one(&mut connection)
            .await
            .expect("transaction count");
        assert_eq!(transactions, 0, "the funded window must roll back whole");
        let notes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes")
            .fetch_one(&mut connection)
            .await
            .expect("note count");
        assert_eq!(notes, 0, "the funded window must roll back whole");
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            None,
            "a cancelled window must not write a coverage record: the marker stays unset"
        );
    }

    /// A walk cancelled before its first candidate covers nothing at all, so reporting success
    /// would be the same lie as reporting it mid-window: the caller must be able to tell a walk
    /// that finished from one that never ran.
    #[tokio::test]
    async fn discover_transparent_addresses_reports_a_walk_cancelled_before_it_starts() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let mut client: Client = Box::new(EmptyStreams {
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: Some(12345),
            fail_block: false,
        });
        let cancellation_token = CancellationToken::new();
        cancellation_token.cancel();

        let error = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            cancellation_token,
        )
        .await
        .expect_err("a walk cancelled before its first candidate must not report success");

        assert!(
            error.to_string().contains("cancel"),
            "the failure must name cancellation, got: {error}"
        );
        assert!(
            !crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage read")
                .certified,
            "a walk that never ran must not leave a coverage record"
        );
    }

    /// The seam, the candidate's row and its marker decide the skip together, so they are read in
    /// one critical section: a sync holding `SYNCING` must block that decision, not race it.
    #[tokio::test]
    async fn candidate_start_waits_for_the_sync_guard() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let identity = account_identity(&mut connection, account)
            .await
            .expect("identity")
            .expect("account exists");

        let taddr = derived_taddress(&mut connection, account, 0, 0).await;

        let guard = SYNCING.lock().await;
        let blocked = tokio::time::timeout(
            Duration::from_millis(50),
            candidate_start(&mut connection, account, &identity, 0, 0, &taddr, 2_000_000),
        )
        .await;
        assert!(
            blocked.is_err(),
            "the skip decision must wait for the guard"
        );
        drop(guard);

        let start = candidate_start(&mut connection, account, &identity, 0, 0, &taddr, 2_000_000)
            .await
            .expect("decision");
        assert!(
            start.is_some(),
            "an address with no marker still has to be walked"
        );
    }

    /// `delete_account` frees the numeric id for reuse, so a walk that outlives the account it
    /// started on must refuse its next window instead of grafting the old wallet's history onto
    /// whatever account inherited the id.
    #[tokio::test]
    async fn walk_candidate_refuses_a_window_when_the_account_id_was_reused() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let identity = account_identity(&mut connection, account)
            .await
            .expect("identity")
            .expect("account exists");
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let xvk = tk.xvk.as_ref().expect("xvk");
        let (pk, addr) = derive_transparent_address(xvk, 0, 1, false).expect("derive");
        let target = addr.encode(&Network::Main);

        sqlx::query(
            "UPDATE accounts SET seed_fingerprint = x'00', birth = birth + 1
            WHERE id_account = ?",
        )
        .bind(account)
        .execute(&mut connection)
        .await
        .expect("another account inherits the id");

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 1_000,
            height: 2_000_050,
            fail_block: false,
        });
        let result = walk_candidate(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            &identity,
            2_000_000,
            0,
            1,
            None,
            &addr,
            None,
            &pk,
            &target,
            2_000_000,
            2_000_100,
            &CancellationToken::new(),
            None,
        )
        .await;

        assert!(
            result.is_err(),
            "the walk must not commit against a different account"
        );
        assert!(
            transparent_address_row(&mut connection, account, 0, 1)
                .await
                .expect("row lookup")
                .is_none(),
            "no address row may be stored for the account that inherited the id"
        );
    }

    /// `store_account_transparent_addr` returns only whether *this* call's own write landed, never
    /// the row's id, so `walk_candidate` must always re-read the row by (account, scope, dindex)
    /// afterwards and bind ingestion to whatever id is actually stored there — exercised once where
    /// this call's own insert wins, and once where a concurrent writer already claimed the same
    /// (scope, dindex) first, so this call's insert is the one `ON CONFLICT DO NOTHING` swallows.
    #[tokio::test]
    async fn discover_transparent_addresses_binds_the_stored_address_row_id() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let identity = account_identity(&mut connection, account)
            .await
            .expect("identity")
            .expect("account exists");
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let xvk = tk.xvk.as_ref().expect("xvk");

        let (pk1, addr1) = derive_transparent_address(xvk, 0, 1, false).expect("derive");
        let target1 = addr1.encode(&Network::Main);
        let mut client1: Client = Box::new(FundedAddress {
            target: target1.clone(),
            value: 1_000,
            height: 2_000_050,
            fail_block: false,
        });
        walk_candidate(
            &Network::Main,
            &mut connection,
            &mut client1,
            account,
            &identity,
            0,
            0,
            1,
            None,
            &addr1,
            None,
            &pk1,
            &target1,
            2_000_000,
            2_000_100,
            &CancellationToken::new(),
            None,
        )
        .await
        .map_err(anyhow::Error::from)
        .expect("walk candidate 1");

        let (id1, _) = transparent_address_row(&mut connection, account, 0, 1)
            .await
            .expect("row lookup")
            .expect("row exists");
        let bound1: i64 =
            sqlx::query_scalar("SELECT taddress FROM notes WHERE account = ? AND value = ?")
                .bind(account)
                .bind(1_000_i64)
                .fetch_one(&mut connection)
                .await
                .expect("note");
        assert_eq!(
            bound1 as u32, id1,
            "own insert must bind to the id it just stored"
        );

        let (pk2, addr2) = derive_transparent_address(xvk, 0, 2, false).expect("derive");
        let target2 = addr2.encode(&Network::Main);
        store_account_transparent_addr(
            &mut connection,
            account,
            0,
            2,
            None,
            b"someone_elses_pk",
            "t1someoneelse",
            false,
        )
        .await
        .expect("racing insert");

        let mut client2: Client = Box::new(FundedAddress {
            target: target2.clone(),
            value: 2_000,
            height: 2_000_050,
            fail_block: false,
        });
        walk_candidate(
            &Network::Main,
            &mut connection,
            &mut client2,
            account,
            &identity,
            0,
            0,
            2,
            None,
            &addr2,
            None,
            &pk2,
            &target2,
            2_000_000,
            2_000_100,
            &CancellationToken::new(),
            None,
        )
        .await
        .map_err(anyhow::Error::from)
        .expect("walk candidate 2");

        let (id2, address2) = transparent_address_row(&mut connection, account, 0, 2)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            address2, "t1someoneelse",
            "the racing insert must be the one that won"
        );
        let bound2: i64 =
            sqlx::query_scalar("SELECT taddress FROM notes WHERE account = ? AND value = ?")
                .bind(account)
                .bind(2_000_i64)
                .fetch_one(&mut connection)
                .await
                .expect("note");
        assert_eq!(
            bound2 as u32, id2,
            "a lost race must still bind ingestion to the row that actually won"
        );
    }

    /// A `gap_limit` of 20 stops the external scope after dindex 21 (20 never-stored indexes past
    /// the account's own dindex 0), so it never even queries dindex 22 — this is the missing edge
    /// `discover_transparent_addresses_stops_after_twenty_one_never_stored_indexes` pins. Running
    /// discovery again on the same wallet with a wider limit reaches past that bound and finds a
    /// funded dindex 22: recovery beyond a walk's own depth is a checked behaviour, not a claim.
    #[tokio::test]
    async fn discover_transparent_addresses_at_a_wider_gap_limit_finds_what_the_narrow_walk_missed()
    {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let (n_added_narrow, _) = discover(&mut connection, account, 20, vec![]).await;
        assert_eq!(
            n_added_narrow, 0,
            "the narrow walk never reaches dindex 22 to begin with"
        );
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0]);

        // dindex 0 is backfilled to the seam but was never seen used, so every walk probes it
        // again: dindex 0..21 are calls 1..22, and dindex 22 — the first index the narrow walk
        // could not reach — is call 23.
        let (n_added_wide, _) = discover(&mut connection, account, 21, vec![23]).await;

        assert_eq!(
            n_added_wide, 1,
            "the wider walk recovers the index the narrow one structurally could not reach"
        );
        assert_eq!(
            receive_dindexes(&mut connection, account).await,
            vec![0, 22]
        );
    }

    /// The account's default address has no backfill marker and its only payment sits below any
    /// window `transparent_sync` would ever request — `transparent_sync` only ever scans
    /// `[start_height, end_height]` forward from the caller, never back to `birth_height`. One
    /// ordinary sync pass over a window that excludes the payment must leave the marker `NULL`
    /// (`advance_backfilled_height`'s contiguity guard), so a later discovery run — which does
    /// look back to `birth_height` — still walks the address and finds the payment. A writer that
    /// forged the marker to `through` regardless of contiguity would make discovery's own
    /// short-circuit skip the address forever, and the payment would never be seen.
    #[tokio::test]
    async fn discover_transparent_addresses_backfills_an_address_the_sync_could_not_mark() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let (id_taddress, default_address) =
            transparent_address_row(&mut connection, account, 0, 0)
                .await
                .expect("row lookup")
                .expect("default address exists");

        let mut sync_client: Client = Box::new(EmptyStreams {
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: None,
            fail_block: false,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);
        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut sync_client,
            &[account],
            2_000_051,
            2_000_100,
            10,
            rx_cancel,
        )
        .await
        .expect("transparent sync");

        assert_eq!(
            transparent_backfilled_height(&mut connection, id_taddress)
                .await
                .expect("marker"),
            None,
            "a window that never reached the payment must not forge a complete marker"
        );

        let mut discover_client: Client = Box::new(FundedAddress {
            target: default_address,
            value: 55_000,
            height: 2_000_010,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut discover_client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        let bound: i64 =
            sqlx::query_scalar("SELECT taddress FROM notes WHERE account = ? AND value = ?")
                .bind(account)
                .bind(55_000_i64)
                .fetch_one(&mut connection)
                .await
                .expect("the below-window payment must be found by discovery");
        assert_eq!(bound as u32, id_taddress);
    }

    /// `ingest_backfill_window`'s first query, `heights_of_transactions_without_time`, must stay
    /// scoped to the account under discovery. Another account's still-undated transaction sitting
    /// inside this account's window must not be swept up: `fail_block: true` turns any call to
    /// `client.block()` into an error, so if the query leaked across accounts the walk over the
    /// restored account's own (already-stored) address would fail loudly instead of succeeding.
    #[tokio::test]
    async fn discover_transparent_addresses_does_not_fetch_blocks_of_another_account_in_its_range()
    {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let other_account = account + 1;
        sqlx::query(
            "INSERT INTO transactions (account, txid, height, time) VALUES (?, x'00', ?, 0)",
        )
        .bind(other_account)
        .bind(2_000_010u32)
        .execute(&mut connection)
        .await
        .expect("other account transaction");

        let mut client: Client = Box::new(EmptyStreams {
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: None,
            fail_block: true,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            1,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("another account's undated transaction must not trigger a block fetch");

        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE account = ?")
            .bind(other_account)
            .fetch_one(&mut connection)
            .await
            .expect("other account transaction");
        assert_eq!(
            time, 0,
            "the other account's transaction must be left untouched"
        );
    }

    /// `get_heights_without_time`'s second query is a union of every `sync_heights` row missing a
    /// header, with no account and no range predicate at all — correct for `synchronize_impl`,
    /// which syncs every account, but only because `discover_transparent_addresses` never calls
    /// it: `ingest_backfill_window` uses the windowed, account-scoped
    /// `heights_of_transactions_without_time` instead. Another account's `sync_heights` row, far
    /// outside this account's window and missing a header, must stay untouched by this discovery
    /// run — `fail_block: true` turns any `client.block()` call into an error.
    #[tokio::test]
    async fn discover_transparent_addresses_does_not_fetch_blocks_outside_its_window() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let other_account = account + 1;
        set_pool_sync_height_for_account(&mut connection, other_account, 0, 5_000_000).await;

        let mut client: Client = Box::new(EmptyStreams {
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: None,
            fail_block: true,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            1,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("another account's out-of-window sync_heights row must not trigger a block fetch");
    }

    /// `walk_candidate`'s match arm returns `BackfillError::Db` immediately instead of halving the
    /// window the way `BackfillError::Fetch` does. The window starts wide (10,001 heights) so a
    /// halving-and-retry bug would show up as several narrower re-requests before giving up, not
    /// just one — dropping the `headers` table makes `fill_missing_block_times`'s header write
    /// fail for a pre-existing undated transaction, which is exactly the database-stage failure
    /// `ingest_backfill_window` reports as `BackfillError::Db`.
    #[tokio::test]
    async fn discover_transparent_addresses_does_not_narrow_the_window_on_a_database_failure() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_010_000).await;
        sqlx::query(
            "INSERT INTO transactions (account, txid, height, time) VALUES (?, x'00', ?, 0)",
        )
        .bind(account)
        .bind(2_000_010u32)
        .execute(&mut connection)
        .await
        .expect("pre-existing undated transaction");
        sqlx::query("DROP TABLE headers")
            .execute(&mut connection)
            .await
            .expect("drop headers");

        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: call_ranges.clone(),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_010_000,
            1,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(
            result.is_err(),
            "a dropped headers table must surface as a database error"
        );
        assert_eq!(
            call_ranges.lock().expect("lock").len(),
            1,
            "a database-stage failure must not halve the window and retry"
        );
    }

    /// The inclusive edge of the gap bound: with `gap_limit` 20 a funded index preceded by
    /// exactly 20 never-stored ones is still reached. dindex 1 is the last used index `u`,
    /// dindex 2..=21 are empty, and dindex 22 — `u + 21` — is funded and must be stored.
    /// Regression pin: this bound must not move.
    #[tokio::test]
    async fn discover_transparent_addresses_finds_a_funded_index_twenty_one_past_the_last_used_one()
    {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        // dindex n is call n + 1: dindex 0 (the account's own address) is call 1.
        let (n_added, _) = discover(&mut connection, account, 20, vec![2, 23]).await;

        assert_eq!(n_added, 2, "the used dindex 1 and the funded dindex 22");
        assert_eq!(
            receive_dindexes(&mut connection, account).await,
            vec![0, 1, 22],
            "a funded index 21 past the last used one is still inside the bound"
        );
    }

    /// The scenario the whole ticket is about: an address whose *only* transaction lands above
    /// the local sync seam. A walk that capped its fetch at the seam would never see it, so the
    /// address would stay undiscovered; a walk that wrote what it saw there would have the note
    /// deleted by the next recovery. The request reaches the tip, the write stops at the seam, and
    /// the ordinary sync over `(seam, tip]` ingests the payment.
    #[tokio::test]
    async fn discover_transparent_addresses_finds_an_address_first_used_above_the_seam() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(2_000_050u32)
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("seam below the tip");
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 1, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 9_100,
            height: 2_000_080,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 1, "the address is first used above the seam");
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0, 1]);
        let (id, _) = transparent_address_row(&mut connection, account, 0, 1)
            .await
            .expect("row lookup")
            .expect("the address is stored on the run that saw it");
        assert!(
            transparent_address_is_used(&mut connection, account, &target)
                .await
                .expect("used"),
            "seen above the seam is still seen"
        );
        assert_eq!(
            highest_written_height(&mut connection, account).await,
            None,
            "nothing is written above the seam"
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(2_000_050),
            "the marker stops at the seam"
        );

        let (_cancel, rx_cancel) = broadcast::channel(1);
        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[account],
            2_000_051,
            2_000_100,
            100,
            rx_cancel,
        )
        .await
        .expect("sync over the range above the seam");
        let value: i64 = sqlx::query_scalar("SELECT value FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("note");
        assert_eq!(
            value, 9_100,
            "the sync, not the walk, ingests the payment above the seam"
        );
    }

    /// The highest height of any note, spend or transaction row of the account.
    async fn highest_written_height(
        connection: &mut SqliteConnection,
        account: u32,
    ) -> Option<u32> {
        sqlx::query_scalar(
            "SELECT MAX(h) FROM (
                SELECT MAX(height) AS h FROM notes WHERE account = ?1
                UNION ALL SELECT MAX(height) FROM spends WHERE account = ?1
                UNION ALL SELECT MAX(height) FROM transactions WHERE account = ?1)",
        )
        .bind(account)
        .fetch_one(connection)
        .await
        .expect("heights")
    }

    /// Change lives in the internal scope, and a restore leaves no row for any of it. The walk
    /// must cover scope 1 exactly as it covers scope 0, or every change output a wallet ever
    /// produced stays invisible.
    #[tokio::test]
    async fn discover_transparent_addresses_ingests_a_change_address() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) = derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 1, 0, false)
            .expect("derive change address");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 4_200,
            height: 2_000_050,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 1, "the change address is new to the database");
        let change_dindexes: Vec<u32> = sqlx::query_scalar(
            "SELECT dindex FROM transparent_address_accounts
            WHERE account = ? AND scope = 1 ORDER BY dindex",
        )
        .bind(account)
        .fetch_all(&mut connection)
        .await
        .expect("change addresses");
        assert_eq!(change_dindexes, vec![0]);
        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &target)
                .await
                .expect("balance"),
            4_200
        );
    }

    /// pcash's Trezor accounts restore from a bare account-level xpub, so the walk has a viewing
    /// key and no spending key at all. Discovery must still derive, store and ingest for them —
    /// this is the hardware-wallet path in the shipped build.
    #[tokio::test]
    async fn discover_transparent_addresses_ingests_for_an_xpub_only_account() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, &account_xpub(), 0, None)
            .await
            .expect("restore from xpub");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        assert!(tk.xsk.is_none(), "an xpub-only account has no spending key");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 1, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 6_300,
            height: 2_000_050,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 1);
        assert_eq!(receive_dindexes(&mut connection, account).await, vec![0, 1]);
        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &target)
                .await
                .expect("balance"),
            6_300
        );
    }

    /// A watch-only account imported from a UFVK carries the transparent viewing key inside the
    /// unified key and no spending key at all. Discovery must derive, store and ingest for it just
    /// as it does for a seed account, change chain included — otherwise an imported watch-only
    /// wallet keeps reporting only the single address its restore created.
    #[tokio::test]
    async fn discover_transparent_addresses_ingests_for_a_watch_only_ufvk_account() {
        let ufvk = crate::account::derive_ufvk(&Network::Main, TEST_PHRASE, None, 0).expect("ufvk");
        let mut connection = memory_db().await;
        let account = restore(&mut connection, &ufvk, 0, None)
            .await
            .expect("restore from ufvk");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        assert!(
            tk.xsk.is_none(),
            "a watch-only ufvk account has no spending key"
        );
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 1, 0, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 9_100,
            height: 2_000_050,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(
            n_added, 1,
            "the funded change address is new to the database"
        );
        let (id, _) = transparent_address_row(&mut connection, account, 1, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100)
        );
        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &target)
                .await
                .expect("balance"),
            9_100
        );
    }

    /// The window's stream carries exactly one transaction — the funding one — and the walk
    /// consumes it as its existence probe. A probe that swallows the item it peeked stores the
    /// address, passes every other test in this file, and loses precisely this money, so the
    /// peeked transaction has to be replayed into the ingest.
    #[tokio::test]
    async fn discover_transparent_addresses_ingests_the_first_transaction_of_the_stream() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 1, false).expect("derive");
        let target = addr.encode(&Network::Main);

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 3_300,
            height: 2_000_050,
            fail_block: false,
        });

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        let transactions: u32 =
            sqlx::query_scalar("SELECT COUNT(*) FROM transactions WHERE account = ?")
                .bind(account)
                .fetch_one(&mut connection)
                .await
                .expect("transaction count");
        assert_eq!(
            transactions, 1,
            "the stream carried exactly one transaction"
        );
        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &target)
                .await
                .expect("balance"),
            3_300,
            "the peeked first transaction must still reach the ingest"
        );
    }

    /// Twenty-one addresses that already have rows, each answering its own delta with nothing,
    /// must not consume the gap budget: only an index the walk never stored counts. Under
    /// incremental counting the 21 empty deltas exhaust a limit of 20 and the funded dindex 21 is
    /// never probed — the original bug, re-created by the fix for it.
    #[tokio::test]
    async fn discover_transparent_addresses_keeps_walking_past_stored_addresses_with_an_empty_delta(
    ) {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let xvk = tk.xvk.as_ref().expect("xvk");
        let derive = |dindex: u32| {
            derive_transparent_address(xvk, 0, dindex, false)
                .expect("derive")
                .1
                .encode(&Network::Main)
        };

        // dindex 0 already has the account's own row; back-fill dindex 0..=20 to height H.
        for dindex in 1..=20u32 {
            insert_scoped_taddress_for_account(
                &mut connection,
                account,
                100 + dindex,
                0,
                dindex,
                &derive(dindex),
            )
            .await;
        }
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 2000050
            WHERE account = ? AND scope = 0",
        )
        .bind(account)
        .execute(&mut connection)
        .await
        .expect("back-fill markers");
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(2_000_080u32)
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("advance the seam past H");

        let target = derive(21);
        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 8_800,
            height: 2_000_070,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_080,
            20,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 1, "the funded dindex 21 is new");
        assert!(
            receive_dindexes(&mut connection, account)
                .await
                .contains(&21),
            "21 stored addresses with empty deltas must not close the walk"
        );
        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &target)
                .await
                .expect("balance"),
            8_800
        );
    }

    /// Discovery back-fills history behind the seam; it never scans forward, so it must not
    /// touch a single pool's `sync_heights` row. Moving one would tell the scanner it had
    /// covered blocks nobody scanned. Regression pin: this must not change.
    #[tokio::test]
    async fn discover_transparent_addresses_leaves_the_sync_heights_alone() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let before = sync_heights(&mut connection).await;
        assert!(
            !before.is_empty(),
            "the account has pool heights to leave alone"
        );
        let tk = select_account_transparent(&mut connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), 0, 1, false).expect("derive");

        let mut client: Client = Box::new(FundedAddress {
            target: addr.encode(&Network::Main),
            value: 1_500,
            height: 2_000_050,
            fail_block: false,
        });

        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 1, "the walk did real work");
        assert_eq!(
            sync_heights(&mut connection).await,
            before,
            "every pool height must be exactly where the walk found it"
        );
    }

    /// Halving stops at the floor: a server that rejects anything wider than
    /// `MIN_BACKFILL_WINDOW` must be satisfied by exactly that width, and the walk must never
    /// issue a narrower request than the floor on its way there.
    #[tokio::test]
    async fn discover_transparent_addresses_never_narrows_below_the_minimum_window() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: call_ranges.clone(),
            fail_wider_than: Some(MIN_BACKFILL_WINDOW - 1),
            fail_mid_stream: false,
        });

        // 2_000_000..=2_002_999 is exactly three floor-width windows, so no request is narrowed
        // by the end-of-range clamp and every width below the floor would be the halving's own.
        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_002_999,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result.is_ok(), "{result:?}");
        let widths: Vec<u32> = call_ranges
            .lock()
            .expect("lock")
            .iter()
            .map(|(lo, hi)| hi - lo + 1)
            .collect();
        assert!(
            widths.iter().all(|w| *w >= MIN_BACKFILL_WINDOW),
            "no request may be narrower than the floor: {widths:?}"
        );
        assert_eq!(
            widths.iter().min().copied(),
            Some(MIN_BACKFILL_WINDOW),
            "the halving must reach the floor exactly: {widths:?}"
        );
    }

    /// A stored address marked at the seam and paid above it, with the tip above both: the skip
    /// rule's second conjunct makes the walk probe `(marker, tip]`, and what it finds there is
    /// evidence, not history — the address is flagged used and owed, nothing is written above the
    /// seam, and the selector must not hand the address out. The sync over the same range then
    /// ingests the payment and pays the debt.
    #[tokio::test]
    async fn discover_transparent_addresses_flags_a_stored_address_paid_above_its_marker() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_050).await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 2000050
            WHERE account = ? AND scope = 0 AND dindex = 0",
        )
        .bind(account)
        .execute(&mut connection)
        .await
        .expect("mark at the seam");
        let (id, target) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 2_600,
            height: 2_000_080,
            fail_block: false,
        });

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert!(
            transparent_address_is_used(&mut connection, account, &target)
                .await
                .expect("used"),
            "the payment above the marker proves the address used"
        );
        assert_eq!(
            highest_written_height(&mut connection, account).await,
            None,
            "nothing is written above the seam"
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(2_000_050),
            "the marker stays at the seam"
        );
        assert_eq!(
            catch_up_owed_through(&mut connection, id)
                .await
                .expect("debt"),
            Some(2_000_080),
            "the dropped payment is owed to the sync"
        );
        let next = crate::account::next_unused_receive_address(
            &Network::Main,
            &mut connection,
            account,
            &[],
        )
        .await
        .expect("selector")
        .expect("transparent account");
        assert_ne!(
            next.address, target,
            "an address paid above the seam must not be handed out again"
        );

        let (_cancel, rx_cancel) = broadcast::channel(1);
        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[account],
            2_000_051,
            2_000_100,
            100,
            rx_cancel,
        )
        .await
        .expect("the next sync tick");
        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &target)
                .await
                .expect("balance"),
            2_600,
            "the sync ingests the payment the walk only flagged"
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(2_000_100)
        );
        assert_eq!(
            catch_up_owed_through(&mut connection, id)
                .await
                .expect("debt"),
            None,
            "a marker at the debt's height pays it"
        );
    }

    /// A marker can sit just below the seam when the tip once lagged local sync. That address is
    /// not covered, so it must not be skipped — and the refetch has to resume at `marker + 1`
    /// rather than restart at the birth height or re-request the marked block.
    #[tokio::test]
    async fn discover_transparent_addresses_refetches_an_address_marked_below_the_seam() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(2_000_050u32)
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("seam");
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = 2000049
            WHERE account = ? AND scope = 0 AND dindex = 0",
        )
        .bind(account)
        .execute(&mut connection)
        .await
        .expect("mark one block below the seam");
        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: call_ranges.clone(),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            call_ranges.lock().expect("lock").first().copied(),
            Some((2_000_050, 2_000_100)),
            "the marked address is walked first, resuming at marker + 1"
        );
    }

    /// The positive half of the coverage postcondition: without it "always `Err`" would satisfy
    /// the two incompleteness tests. The walk's terminal probes are unstored by design and carry
    /// no marker, so only the addresses that actually got a row are held to the bar.
    #[tokio::test]
    async fn discover_transparent_addresses_reports_complete_for_a_walk_that_meets_the_bar() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;

        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![2],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        let n_added = match result {
            Ok(n) => n,
            Err(e) => panic!("a healthy walk must report complete coverage: {e:?}"),
        };
        assert_eq!(n_added, 1, "the used index at call 2 is the one new row");

        let seam: u32 =
            sqlx::query_scalar("SELECT MIN(height) FROM sync_heights WHERE account = ?")
                .bind(account)
                .fetch_one(&mut connection)
                .await
                .expect("seam");
        let bar = seam.max(2_000_100);
        let markers: Vec<(u32, u32, Option<u32>)> = sqlx::query(
            "SELECT scope, dindex, backfilled_height FROM transparent_address_accounts
            WHERE account = ? ORDER BY scope, dindex",
        )
        .bind(account)
        .map(|row: SqliteRow| (row.get(0), row.get(1), row.get(2)))
        .fetch_all(&mut connection)
        .await
        .expect("stored rows");

        assert!(!markers.is_empty(), "the walk must have stored something");
        for (scope, dindex, backfilled) in markers {
            assert!(
                backfilled.is_some_and(|h: u32| h >= bar),
                "stored ({scope}, {dindex}) carries {backfilled:?}, below the bar {bar}"
            );
        }
    }

    /// The cost claim, made testable. Discovery covers the address up to the seam, an ordinary
    /// `transparent_sync` pass carries that marker on to the tip, and the next walk therefore owes
    /// the address no request at all. Against a marker only discovery ever writes, every stored
    /// address costs one delta request per walk.
    #[tokio::test]
    async fn discover_transparent_addresses_skips_an_address_the_sync_already_covered() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let seam: u32 =
            sqlx::query_scalar("SELECT MIN(height) FROM sync_heights WHERE account = ?")
                .bind(account)
                .fetch_one(&mut connection)
                .await
                .expect("seam");

        let mut client: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            seam,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("first walk covers the address up to the seam");

        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(seam),
            "the walk must leave a marker contiguous with the sync's next range"
        );

        let mut sync_client: Client = Box::new(EmptyStreams {
            calls: Arc::new(AtomicU32::new(0)),
            fail_at_call: None,
            stream_failures: Arc::new(AtomicU32::new(0)),
            block_time: None,
            fail_block: false,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);
        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut sync_client,
            &[account],
            seam + 1,
            2_000_100,
            10,
            rx_cancel,
        )
        .await
        .expect("sync");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100),
            "the sync pass is the writer that carries the marker to the tip"
        );

        let calls = Arc::new(AtomicU32::new(0));
        let call_ranges = Arc::new(Mutex::new(vec![]));
        let mut second: Client = Box::new(UsedAtCalls {
            calls: calls.clone(),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: call_ranges.clone(),
            fail_wider_than: None,
            fail_mid_stream: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut second,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("second walk");

        assert!(
            !call_ranges
                .lock()
                .expect("lock")
                .contains(&(seam + 1, 2_000_100)),
            "the sync-covered address must not be re-fetched: {:?}",
            call_ranges.lock().expect("lock")
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            6,
            "one fewer than the 7-call unmarked baseline: dindex 0 is never called"
        );
    }

    /// Pays `target` and then fails the same stream, so the failure lands after rows were already
    /// staged — the shape a rollback has to survive, which a fake that fails before its first item
    /// never exercises.
    #[derive(Clone)]
    struct PaysThenFails {
        target: String,
        value: u64,
        height: u32,
    }

    #[async_trait]
    impl LwdServer for PaysThenFails {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), false)
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
            taddress: &str,
            _start: u32,
            _end: u32,
        ) -> Result<Self::TransactionStream> {
            let (sender, receiver) = channel(2);
            if taddress == self.target {
                sender
                    .send(Ok((
                        self.height,
                        transaction_paying(&self.target, self.value),
                        0,
                    )))
                    .await
                    .expect("queue funding transaction");
                sender
                    .send(Err(anyhow::anyhow!("discovery stream failed")))
                    .await
                    .expect("queue mid-stream failure");
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// A stream that dies halfway must leave nothing behind — no note and no marker — precisely so
    /// the next run fetches the same range again. A marker written before the stream finished would
    /// certify history the wallet never received.
    #[tokio::test]
    async fn discover_transparent_addresses_retries_an_address_whose_stream_failed() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let (id, target) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");

        let mut failing: Client = Box::new(PaysThenFails {
            target: target.clone(),
            value: 9_000,
            height: 2_000_050,
        });
        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut failing,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result
            .expect_err("mid-stream failure")
            .to_string()
            .contains("discovery stream failed"));
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            None,
            "a failed window must not be certified"
        );
        let notes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("count");
        assert_eq!(notes, 0, "the staged rows must have been rolled back");

        let mut healthy: Client = Box::new(FundedAddress {
            target,
            value: 9_000,
            height: 2_000_050,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut healthy,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("the retry must fetch the address again");

        let value: i64 = sqlx::query_scalar("SELECT value FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("note");
        assert_eq!(value, 9_000, "the retry recovers what the failure dropped");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100)
        );
    }

    /// A backfill that dies in its second window must not throw away the first. The committed
    /// window's marker is what makes the next run resume where the failure landed instead of
    /// re-fetching the whole history from the birth height.
    #[tokio::test]
    async fn discover_transparent_addresses_resumes_a_backfill_from_the_committed_window() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_004_000).await;
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");

        // The full range is rejected as too wide, so the walk halves to 2 000-block windows: the
        // first commits, the second fails mid-stream.
        let first_ranges = Arc::new(Mutex::new(vec![]));
        let mut failing: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: Some(2),
            block_time: Some(12345),
            fail_block: false,
            call_ranges: first_ranges.clone(),
            fail_wider_than: Some(2_000),
            fail_mid_stream: false,
        });
        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut failing,
            account,
            2_004_000,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert!(result.is_err(), "the second window failed");
        assert_eq!(
            first_ranges.lock().expect("lock").clone(),
            vec![
                (2_000_000, 2_004_000),
                (2_000_000, 2_001_999),
                (2_002_000, 2_003_999),
                (2_002_000, 2_002_999),
            ],
            "one rejected full range, one committed window, then a failing window narrowed once              to the floor before the walk gives up"
        );
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_001_999),
            "the committed window's marker survives the later failure"
        );

        let second_ranges = Arc::new(Mutex::new(vec![]));
        let mut healthy: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: second_ranges.clone(),
            fail_wider_than: None,
            fail_mid_stream: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut healthy,
            account,
            2_004_000,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("second run");

        assert_eq!(
            second_ranges.lock().expect("lock").first().copied(),
            Some((2_002_000, 2_004_000)),
            "the retry resumes at marker + 1, not at the birth height"
        );
    }

    /// Pays every address in `targets` — the two-funded-index shape the single-target
    /// `FundedAddress` cannot express, and which a call-number fake cannot express either once the
    /// second index sits past the scope's own last call.
    #[derive(Clone)]
    struct FundedAddresses {
        targets: Vec<String>,
        value: u64,
        height: u32,
    }

    #[async_trait]
    impl LwdServer for FundedAddresses {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), false)
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
            taddress: &str,
            _start: u32,
            _end: u32,
        ) -> Result<Self::TransactionStream> {
            let (sender, receiver) = channel(1);
            if self.targets.iter().any(|t| t == taddress) {
                sender
                    .send(Ok((
                        self.height,
                        transaction_paying(taddress, self.value),
                        0,
                    )))
                    .await
                    .expect("queue funding transaction");
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    async fn derived_taddress(
        connection: &mut SqliteConnection,
        account: u32,
        scope: u32,
        dindex: u32,
    ) -> String {
        let tk = select_account_transparent(connection, account, 0)
            .await
            .expect("transparent keys");
        let (_, addr) =
            derive_transparent_address(tk.xvk.as_ref().expect("xvk"), scope, dindex, false)
                .expect("derive");
        addr.encode(&Network::Main)
    }

    /// The exclusive edge of the same bound, asserted as the residual rather than as a probe
    /// count: last used at dindex 1, dindex 2..=22 (21 never-stored indexes) empty, and the funded
    /// dindex 23 — `u + 22` — is out of reach and stays unstored. Regression pin: this miss is the
    /// checked fact behind the `## Assumptions` qualification, and the bound must not move.
    #[tokio::test]
    async fn discover_transparent_addresses_stops_after_twenty_one_never_stored_indexes() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let last_used = derived_taddress(&mut connection, account, 0, 1).await;
        let out_of_reach = derived_taddress(&mut connection, account, 0, 23).await;

        let mut client: Client = Box::new(FundedAddresses {
            targets: vec![last_used, out_of_reach],
            value: 5_000,
            height: 2_000_050,
        });
        let n_added = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            20,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("discover");

        assert_eq!(n_added, 1, "only the reachable used index is added");
        assert_eq!(
            receive_dindexes(&mut connection, account).await,
            vec![0, 1],
            "a funded index behind 21 never-stored ones is beyond this walk's bound"
        );
    }

    /// Parks a task on `SYNCING` and returns once it is provably queued behind the guard the
    /// caller holds. Without the rendezvous the walk re-acquires first and the task lands after
    /// the postcondition instead of in the gap between two windows.
    async fn queue_behind_syncing<Fut>(work: Fut)
    where
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (queued_tx, queued_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut acquire = Box::pin(SYNCING.lock());
            let mut queued = Some(queued_tx);
            let _guard = std::future::poll_fn(|cx| {
                let polled = std::future::Future::poll(acquire.as_mut(), cx);
                if polled.is_pending() {
                    if let Some(tx) = queued.take() {
                        let _ = tx.send(());
                    }
                }
                polled
            })
            .await;
            work.await;
        });
        queued_rx
            .await
            .expect("SYNCING must be held while the walk's window runs");
    }

    /// The retry after a failed block-time lookup must repair the transaction it already
    /// committed, and it can only do so by re-deriving the height from the database:
    /// `heights_of_transactions_without_time` is the sole source, because the second run's stream
    /// is empty — the ingest already happened and nothing re-delivers it.
    #[tokio::test]
    async fn discover_transparent_addresses_repairs_a_time_after_a_committed_ingestion() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let (id, target) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");

        let mut failing: Client = Box::new(FundedAddress {
            target,
            value: 5_000,
            height: 2_000_050,
            fail_block: true,
        });
        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut failing,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;
        assert!(result.is_err(), "a failed block-time lookup must surface");
        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("transaction");
        assert_eq!(time, 0, "the ingest committed, dated with the placeholder");

        // An empty stream: the transaction is already in the database and is never re-delivered.
        let mut healthy: Client = Box::new(UsedAtCalls {
            calls: Arc::new(AtomicU32::new(0)),
            used_at_calls: vec![],
            fail_from_call: None,
            block_time: Some(12345),
            fail_block: false,
            call_ranges: Arc::new(Mutex::new(vec![])),
            fail_wider_than: None,
            fail_mid_stream: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut healthy,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("the retry must repair the time and complete");

        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("transaction");
        assert_eq!(
            time, 12345,
            "the retry found the height through the database, not through the stream"
        );
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100),
            "with the time repaired the window is finally certified"
        );
    }

    /// The checkpoint `UnderWalkChange::Rewind` rewinds to.
    const REWIND_CHECKPOINT: u32 = 2_000_100;

    /// What the queued task does to the wallet in the gap between two windows of one walk.
    #[derive(Clone)]
    enum UnderWalkChange {
        /// Clamps sync data back to this height.
        Trim(u32),
        /// Deletes the account and restores the same seed, so the replacement inherits the
        /// numeric id.
        ReplaceAccount,
        /// Resets the account. `dropped` names the payments the reorg it recovers from took with
        /// it: the server stops serving them once the reset has run.
        Reset { dropped: Vec<(u32, u64)> },
        /// Rewinds past `REWIND_CHECKPOINT`. `dropped` names the payments the reorg it recovers
        /// from took with it: the server stops serving them once the rewind has run.
        Rewind { dropped: Vec<(u32, u64)> },
    }

    /// A server that lets the wallet change under the walk. After the chosen call's stream is
    /// handed over — the walk still holding `SYNCING` — a task is queued behind that guard, so it
    /// changes the wallet in the gap before the next window.
    #[derive(Clone)]
    struct TrimUnderWalk {
        taddress: String,
        calls: Arc<AtomicU32>,
        coin: Coin,
        account: u32,
        change: UnderWalkChange,
        /// Which call's window the queued task follows.
        observe_after_call: u32,
        /// Height and value of every payment a window containing that height carries.
        payments: Vec<(u32, u64)>,
        /// How many outputs to this address each of those payments carries.
        outputs: u8,
        /// The call whose stream dies after its payments, forcing the walk to narrow.
        fail_call: Option<u32>,
    }

    impl TrimUnderWalk {
        fn still_served(&self, call: u32, payment: &(u32, u64)) -> bool {
            match &self.change {
                UnderWalkChange::Reset { dropped } | UnderWalkChange::Rewind { dropped } => {
                    call <= self.observe_after_call || !dropped.contains(payment)
                }
                _ => true,
            }
        }
    }

    #[async_trait]
    impl LwdServer for TrimUnderWalk {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), false)
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
            start: u32,
            end: u32,
        ) -> Result<Self::TransactionStream> {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            let (sender, receiver) = channel(self.payments.len() + 1);
            for payment in &self.payments {
                let (height, value) = *payment;
                if (start..=end).contains(&height) && self.still_served(call, payment) {
                    sender
                        .send(Ok((
                            height,
                            transaction_paying_outputs(&self.taddress, value, self.outputs),
                            0,
                        )))
                        .await
                        .expect("queue payment");
                }
            }
            if self.fail_call == Some(call) {
                sender
                    .send(Err(anyhow::anyhow!("stream died mid-window")))
                    .await
                    .expect("queue error");
            }
            if call == self.observe_after_call {
                let coin = self.coin.clone();
                let account = self.account;
                let change = self.change.clone();
                queue_behind_syncing(async move {
                    let mut connection = coin.get_connection().await.expect("trim connection");
                    match change {
                        UnderWalkChange::ReplaceAccount => {
                            crate::db::delete_account(&mut connection, account)
                                .await
                                .expect("delete");
                            let restored = restore(&mut connection, TEST_PHRASE, 0, None)
                                .await
                                .expect("restore the same seed");
                            assert_eq!(restored, account, "the numeric id is reused");
                        }
                        UnderWalkChange::Reset { .. } => {
                            crate::account::reset_sync(&Network::Main, &mut connection, account)
                                .await
                                .expect("reset");
                        }
                        UnderWalkChange::Rewind { .. } => {
                            sqlx::query(
                                "INSERT INTO witnesses(account, note, height, witness)
                                VALUES (?, 1, ?, ?)",
                            )
                            .bind(account)
                            .bind(REWIND_CHECKPOINT)
                            .bind(vec![0u8; 32])
                            .execute(&mut *connection)
                            .await
                            .expect("checkpoint");
                            rewind_sync(
                                &Network::Main,
                                &mut connection,
                                account,
                                REWIND_CHECKPOINT + 1,
                            )
                            .await
                            .expect("rewind");
                        }
                        UnderWalkChange::Trim(height) => {
                            trim_sync_data(&mut connection, account, height)
                                .await
                                .expect("trim");
                        }
                    }
                })
                .await;
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

        async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
            Ok(fake_anchor(height))
        }
    }

    /// The one shape both trim-under-walk tests need: a candidate walked over
    /// `[2_000_000, 2_003_000]` against a server the caller tunes.
    async fn walk_under_trim(
        connection: &mut SqliteConnection,
        coin: &Coin,
        account: u32,
        configure: impl FnOnce(&mut TrimUnderWalk),
    ) -> Result<(Option<u32>, Vec<i64>), BackfillError> {
        let identity = account_identity(connection, account)
            .await
            .expect("identity")
            .expect("account exists");
        let (pk, addr, taddr) = candidate_address(connection, account).await;
        let mut server = TrimUnderWalk {
            taddress: taddr.clone(),
            calls: Arc::new(AtomicU32::new(0)),
            coin: coin.clone(),
            account,
            change: UnderWalkChange::Trim(2_000_000),
            observe_after_call: 0,
            payments: vec![],
            outputs: 1,
            fail_call: None,
        };
        configure(&mut server);
        let mut client: Client = Box::new(server);

        let result = walk_candidate(
            &Network::Main,
            connection,
            &mut client,
            account,
            &identity,
            2_000_000,
            0,
            1,
            None,
            &addr,
            None,
            &pk,
            &taddr,
            2_000_000,
            2_003_000,
            &CancellationToken::new(),
            None,
        )
        .await;
        // A refused walk has nothing to inspect, and its candidate may not even exist any more.
        result?;

        let row = transparent_address_row(connection, account, 0, 1)
            .await
            .expect("row lookup")
            .expect("row exists");
        let marker = transparent_backfilled_height(connection, row.0)
            .await
            .expect("marker");
        let notes = note_values_at(connection, row.0).await;
        Ok((marker, notes))
    }

    /// A trim that clamps a marker the walk already wrote moves the seam down with it, so the
    /// marker still meets the bar; what gives the trim away is its counter, and the walk must say
    /// so. Returning a count instead is the false completion that lets a caller memoise an epoch
    /// over history the trim just deleted.
    #[tokio::test]
    async fn discover_transparent_addresses_reports_incomplete_when_a_trim_clamps_a_walked_marker()
    {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");

        let mut client: Client = Box::new(TrimUnderWalk {
            taddress: String::new(),
            calls: Arc::new(AtomicU32::new(0)),
            coin: coin.clone(),
            account,
            change: UnderWalkChange::Trim(2_000_040),
            observe_after_call: 0,
            payments: vec![],
            outputs: 1,
            fail_call: None,
        });

        let result = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            1,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;

        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_040),
            "the trim must have landed between candidates, clamping the walked marker"
        );
        assert!(result
            .expect_err("a clamped marker is incomplete coverage")
            .to_string()
            .contains("invalidated by a trim"),);
    }

    /// The end-to-end half of the clamp: a rewind deletes a backfilled note, and the next walk has
    /// to fetch that history again. Without `trim_sync_data`'s marker clamp the stale marker still
    /// satisfies the skip rule, the address is never re-probed and the balance stays wrong for
    /// good.
    #[tokio::test]
    async fn discover_transparent_addresses_refetches_history_deleted_by_a_rewind() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let (id, target) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");

        let mut client: Client = Box::new(FundedAddress {
            target: target.clone(),
            value: 6_250,
            height: 2_000_050,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("backfill");
        let value: i64 = sqlx::query_scalar("SELECT value FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("note");
        assert_eq!(value, 6_250);

        trim_sync_data(&mut connection, account, 2_000_040)
            .await
            .expect("rewind past the funding transaction");
        let notes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("count");
        assert_eq!(notes, 0, "the rewind deleted the note");
        // The pools sync back up to the tip before the next walk; below the seam the walk
        // writes, above it only the sync does.
        synced_to(&mut connection, account, 2_000_100).await;

        let mut again: Client = Box::new(FundedAddress {
            target,
            value: 6_250,
            height: 2_000_050,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut again,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("the walk after a rewind must re-fetch the deleted history");

        let value: i64 = sqlx::query_scalar("SELECT value FROM notes WHERE account = ?")
            .bind(account)
            .fetch_one(&mut connection)
            .await
            .expect("the note must come back");
        assert_eq!(value, 6_250, "the rewound history is recovered, not lost");
        assert_eq!(
            transparent_backfilled_height(&mut connection, id)
                .await
                .expect("marker"),
            Some(2_000_100)
        );
    }
    /// The state the trim/re-ingest pair leaves behind: a scope-1 change address that has fallen
    /// out of the newest-`limit` change window, whose only note was deleted by a trim and then
    /// re-ingested by a second walk. Returns the account and that address.
    async fn reingested_old_change_note(connection: &mut SqliteConnection) -> (u32, String) {
        const NOTE_HEIGHT: u32 = 2_000_050;
        const TRIM_HEIGHT: u32 = 2_000_040;
        const TIP: u32 = 2_000_100;

        let account = restore(connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let change = derived_taddress(connection, account, 1, 0).await;
        // A newer change address so the funded one sits outside the newest-1 window and can only
        // be returned through the `funded_change` branch.
        let newer = derived_taddress(connection, account, 1, 1).await;
        insert_scoped_taddress_for_account(connection, account, 900, 1, 1, &newer).await;

        let funded = || -> Client {
            Box::new(FundedAddresses {
                targets: vec![change.clone()],
                value: 6_250,
                height: NOTE_HEIGHT,
            })
        };
        let walk = async |connection: &mut SqliteConnection, client: &mut Client| {
            discover_transparent_addresses(
                &Network::Main,
                connection,
                client,
                account,
                TIP,
                0,
                1,
                |_| {},
                CancellationToken::new(),
            )
            .await
            .expect("walk");
        };

        synced_to(connection, account, TIP).await;
        let mut client = funded();
        walk(connection, &mut client).await;
        assert!(
            scanned_addresses(connection, account)
                .await
                .contains(&change),
            "the funded change address is scanned before the trim"
        );

        trim_sync_data(connection, account, TRIM_HEIGHT)
            .await
            .expect("trim below the note");
        assert!(
            scanned_addresses(connection, account)
                .await
                .contains(&change),
            "the trim owed the catch-up for the note it deleted, so the address stays in the set"
        );

        let mut client = funded();
        let (_cancel, rx_cancel) = broadcast::channel(1);
        transparent_sync(
            &Network::Main,
            connection,
            &mut client,
            &[account],
            TRIM_HEIGHT + 1,
            TIP,
            1,
            rx_cancel,
        )
        .await
        .expect("the next sync tick");
        assert_eq!(
            crate::db::transparent_address_balance(connection, account, &change)
                .await
                .expect("balance"),
            6_250,
            "the sync re-ingests the trimmed note from the owed address"
        );

        (account, change)
    }

    /// The newest-1 change window, so an older funded change address can only appear through the
    /// `funded_change` branch.
    async fn scanned_addresses(connection: &mut SqliteConnection, account: u32) -> Vec<String> {
        transparent_addresses_to_scan(connection, account, 1)
            .await
            .expect("scan set")
            .into_iter()
            .map(|(_, address)| address)
            .collect()
    }

    async fn min_sync_height(connection: &mut SqliteConnection, account: u32) -> u32 {
        sqlx::query_scalar("SELECT MIN(height) FROM sync_heights WHERE account = ?")
            .bind(account)
            .fetch_one(connection)
            .await
            .expect("seam")
    }

    /// The money property: on a wallet whose heights have caught up, the trim at the head of the
    /// next sync has nothing above `MIN(sync_heights)` to delete, so the repaired note — and the
    /// old change address it keeps in the scan set — survive into the next sync.
    #[tokio::test]
    async fn sync_after_a_reingested_old_change_note_keeps_it_once_the_heights_are_caught_up() {
        let mut connection = memory_db().await;
        let (account, change) = reingested_old_change_note(&mut connection).await;

        sqlx::query("UPDATE sync_heights SET height = ? WHERE account = ?")
            .bind(2_000_100_u32)
            .bind(account)
            .execute(&mut connection)
            .await
            .expect("catch every pool up to the tip");
        assert_eq!(min_sync_height(&mut connection, account).await, 2_000_100);

        recover_from_partial_sync(&mut connection, &[account])
            .await
            .expect("the head of the next sync");

        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &change)
                .await
                .expect("balance"),
            6_250,
            "a caught-up wallet has nothing above the seam, so the repair must survive"
        );
        assert!(
            scanned_addresses(&mut connection, account)
                .await
                .contains(&change),
            "the surviving note keeps the old change address in the scan set"
        );
    }

    /// The other half of the same rule, and the reason Phase 4 refuses to spend a walk until the
    /// trim counter stops moving: while the heights are still behind the note, the trim at the
    /// head of the next sync undoes the repair — and owes it again.
    #[tokio::test]
    async fn sync_while_the_heights_are_still_catching_up_trims_a_reingested_old_change_note_again()
    {
        let mut connection = memory_db().await;
        let (account, change) = reingested_old_change_note(&mut connection).await;

        assert_eq!(
            min_sync_height(&mut connection, account).await,
            2_000_040,
            "the walk left the heights where the trim put them, below the note"
        );

        recover_from_partial_sync(&mut connection, &[account])
            .await
            .expect("the head of the next sync");

        assert_eq!(
            crate::db::transparent_address_balance(&mut connection, account, &change)
                .await
                .expect("balance"),
            0,
            "a walk that ran during catch-up is undone by the very next sync"
        );
        assert!(
            scanned_addresses(&mut connection, account)
                .await
                .contains(&change),
            "and the trim owes the catch-up again, so the address stays in the scan set"
        );
    }
    /// A trim between two windows of ONE walk deletes rows an earlier window of that same walk
    /// committed. Nothing in the walk's own ledger records that — what it still owes is unchanged —
    /// so nothing stops it certifying the range whose payment recovery just removed.
    #[tokio::test]
    async fn walk_candidate_withholds_coverage_when_a_trim_lands_between_its_windows() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let (marker, notes) = walk_under_trim(&mut connection, &coin, account, |server| {
            server.payments = vec![(2_000_050, 7_000), (2_002_950, 5_000)];
            server.fail_call = Some(0);
            server.observe_after_call = 1;
            server.change = UnderWalkChange::Trim(2_000_000);
        })
        .await
        .map_err(anyhow::Error::from)
        .expect("the walk itself succeeds; only its coverage is withheld");

        assert!(
            !notes.contains(&7_000),
            "the trim must have deleted the payment an earlier window committed"
        );
        assert_ne!(
            marker,
            Some(2_003_000),
            "a range whose committed payment the trim deleted must not be certified"
        );
    }

    /// Restoring the same seed reproduces every other field of the identity, so a walk comparing
    /// only those keeps committing into an account whose earlier history the deletion took with
    /// it — and certifies the range it committed into.
    #[tokio::test]
    async fn walk_candidate_refuses_a_window_whose_account_a_restore_replaced() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let walked = walk_under_trim(&mut connection, &coin, account, |server| {
            server.change = UnderWalkChange::ReplaceAccount;
            server.observe_after_call = 1;
            server.payments = vec![(2_000_050, 7_000), (2_002_950, 5_000)];
            server.fail_call = Some(0);
        })
        .await
        .map_err(anyhow::Error::from)
        .expect_err("the account under the walk was replaced");

        assert!(
            walked.to_string().contains("was replaced"),
            "the walk must stop on the replacement rather than certify over it: {walked}"
        );
    }
    /// A reset between two windows retires the walk: the account's sync data is back at birth and
    /// the walk's next window would certify a marker over history a rescan has to redo.
    #[tokio::test]
    async fn walk_candidate_aborts_when_a_reset_lands_between_two_windows() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (_, _, taddr) = candidate_address(&mut connection, account).await;

        walk_under_trim(&mut connection, &coin, account, |server| {
            server.payments = vec![(2_000_050, 7_000), (2_002_950, 5_000)];
            server.fail_call = Some(0);
            server.observe_after_call = 0;
            server.change = UnderWalkChange::Reset {
                dropped: vec![(2_002_950, 5_000)],
            };
        })
        .await
        .map_err(anyhow::Error::from)
        .expect_err("the reset retired this walk");

        let mut canonical: Client = Box::new(FundedAddress {
            target: taddr,
            value: 7_000,
            height: 2_000_050,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut canonical,
            account,
            2_003_000,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("the canonical history is certifiable by the next walk");
    }

    /// A rewind between two windows retires the walk: the blocks above its checkpoint are gone and
    /// the walk's next window would certify a marker over history the chain no longer holds.
    #[tokio::test]
    async fn walk_candidate_aborts_when_a_rewind_lands_between_two_windows() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (_, _, taddr) = candidate_address(&mut connection, account).await;

        walk_under_trim(&mut connection, &coin, account, |server| {
            server.payments = vec![(2_000_050, 7_000), (2_002_950, 5_000)];
            server.fail_call = Some(0);
            server.observe_after_call = 0;
            server.change = UnderWalkChange::Rewind {
                dropped: vec![(2_002_950, 5_000)],
            };
        })
        .await
        .map_err(anyhow::Error::from)
        .expect_err("the rewind retired this walk");

        let mut canonical: Client = Box::new(FundedAddress {
            target: taddr,
            value: 7_000,
            height: 2_000_050,
            fail_block: false,
        });
        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut canonical,
            account,
            2_003_000,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("the history the rewind kept is certifiable by the next walk");
    }

    /// The periodic sync meets the same oversized history discovery does, and narrowing is what
    /// makes it scannable. Giving up instead leaves the address stuck: every pass re-requests the
    /// same range, overflows again, and the notes an earlier walk recovered are trimmed away.
    #[tokio::test]
    async fn transparent_sync_narrows_a_window_the_transaction_buffer_cannot_hold() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (id, taddr) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        let payments: Vec<(u32, u64)> = (0..=MAX_BUFFERED_TXS)
            .map(|i| (2_000_050 + 300 * i as u32, 5_000 + i as u64))
            .collect();
        let mut client: Client = Box::new(TrimUnderWalk {
            taddress: taddr,
            calls: Arc::new(AtomicU32::new(0)),
            coin: coin.clone(),
            account,
            change: UnderWalkChange::Trim(2_000_000),
            observe_after_call: u32::MAX,
            payments: payments.clone(),
            outputs: 1,
            fail_call: None,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);

        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[account],
            2_000_000,
            2_003_000,
            100,
            rx_cancel,
        )
        .await
        .expect("a history one window cannot hold is still scannable in narrower ones");

        assert_eq!(
            note_values_at(&mut connection, id).await,
            payments
                .iter()
                .map(|(_, value)| *value as i64)
                .collect::<Vec<_>>(),
            "every payment the oversized answer carried must be ingested"
        );
    }

    /// An answer can overflow the ingest buffer without overflowing the ledger: a few transactions
    /// each paying several outputs. Narrowing is the only thing that makes such a range scannable,
    /// and the periodic sync giving up instead leaves the address stuck — every later pass requests
    /// the very same range while the recovery keeps trimming what an earlier walk ingested.
    #[tokio::test]
    async fn transparent_sync_narrows_a_window_the_buffer_cannot_hold() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (id, taddr) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        let outputs = 3u8;
        let payments: Vec<(u32, u64)> = (0..5)
            .map(|i| (2_000_050 + 600 * i as u32, 5_000 + i as u64))
            .collect();
        assert!(
            payments.len() * outputs as usize > MAX_BUFFERED_NOTES
                && payments.len() <= MAX_BUFFERED_TXS,
            "the whole range must overflow the output buffer, not the transaction buffer"
        );
        let mut client: Client = Box::new(TrimUnderWalk {
            taddress: taddr,
            calls: Arc::new(AtomicU32::new(0)),
            coin: coin.clone(),
            account,
            change: UnderWalkChange::Trim(2_000_000),
            observe_after_call: u32::MAX,
            payments: payments.clone(),
            outputs,
            fail_call: None,
        });
        let (_cancel, rx_cancel) = broadcast::channel(1);

        transparent_sync(
            &Network::Main,
            &mut connection,
            &mut client,
            &[account],
            2_000_000,
            2_003_000,
            100,
            rx_cancel,
        )
        .await
        .expect("a window the buffer cannot hold is still scannable in narrower ones");

        assert_eq!(
            note_values_at(&mut connection, id).await.len(),
            payments.len() * outputs as usize,
            "every output the oversized answer carried must be ingested"
        );
    }

    // ---- Round-17 revision: discovery writes nothing above the seam; the sync pays the debt ----

    /// A valid transparent address that belongs to nobody, for fixtures that need many rows.
    fn fake_taddress(i: u32) -> String {
        let mut hash = [0u8; 20];
        hash[..4].copy_from_slice(&i.to_be_bytes());
        TransparentAddress::PublicKeyHash(hash).encode(&Network::Main)
    }

    /// Pays fixed addresses at fixed heights, records every request and answers `chain_anchor`
    /// from a script — one entry per read, the last one repeated — so a fork between the two
    /// reads of one tick is a single differing entry. `off_window` payments are served whatever
    /// the range, the way a lying server answers.
    #[derive(Clone)]
    struct AnchoredPayments {
        payments: Vec<(String, u32, u64)>,
        off_window: Vec<(String, u32, u64)>,
        anchors: Vec<Vec<u8>>,
        anchor_reads: Arc<AtomicU32>,
        stall_anchor: bool,
        fail_anchor_read: Option<usize>,
        fail_stream_wider_than: Option<u32>,
        requests: Arc<Mutex<Vec<(String, u32, u32)>>>,
    }

    impl AnchoredPayments {
        fn paying(payments: Vec<(&str, u32, u64)>) -> Self {
            AnchoredPayments {
                payments: payments
                    .into_iter()
                    .map(|(a, h, v)| (a.to_string(), h, v))
                    .collect(),
                off_window: vec![],
                anchors: vec![fake_anchor(0)],
                anchor_reads: Arc::new(AtomicU32::new(0)),
                stall_anchor: false,
                fail_anchor_read: None,
                fail_stream_wider_than: None,
                requests: Arc::new(Mutex::new(vec![])),
            }
        }
    }

    #[async_trait]
    impl LwdServer for AnchoredPayments {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
            block_response(height, Some(12345), false)
        }

        type CompactBlockStream = ReceiverStream<Result<CompactBlock>>;
        async fn block_range(
            &mut self,
            _network: &Network,
            _start: u32,
            _end: u32,
        ) -> Result<Self::CompactBlockStream> {
            let (sender, receiver) = channel(1);
            drop(sender);
            Ok(ReceiverStream::new(receiver))
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
            taddress: &str,
            start: u32,
            end: u32,
        ) -> Result<Self::TransactionStream> {
            self.requests
                .lock()
                .expect("lock")
                .push((taddress.to_string(), start, end));
            let served: Vec<_> = self
                .payments
                .iter()
                .filter(|(a, h, _)| a == taddress && (start..=end).contains(h))
                .chain(self.off_window.iter().filter(|(a, _, _)| a == taddress))
                .cloned()
                .collect();
            let (sender, receiver) = channel(served.len() + 1);
            if self
                .fail_stream_wider_than
                .is_some_and(|width| end - start > width)
            {
                sender
                    .send(Err(anyhow::anyhow!("stream died")))
                    .await
                    .expect("queue error");
                return Ok(ReceiverStream::new(receiver));
            }
            for (address, height, value) in served {
                sender
                    .send(Ok((height, transaction_paying(&address, value), 0)))
                    .await
                    .expect("queue payment");
            }
            Ok(ReceiverStream::new(receiver))
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        /// Empty trees: what a keyless account's shielded pass reads and then has no keys to use.
        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            Ok((vec![], vec![], vec![]))
        }

        async fn chain_anchor(&mut self, _height: u32) -> Result<Vec<u8>> {
            let read = self.anchor_reads.fetch_add(1, Ordering::Relaxed) as usize;
            if self.stall_anchor {
                std::future::pending::<()>().await;
            }
            if self.fail_anchor_read == Some(read) {
                anyhow::bail!("anchor read failed");
            }
            Ok(self.anchors[read.min(self.anchors.len() - 1)].clone())
        }
    }

    const DEFAULT_TADDR: &str = "t1h31WzbruQhnwHg4XDJ5anLM7CAtwjXmPt";

    async fn sync_range(
        connection: &mut SqliteConnection,
        client: &mut Client,
        accounts: &[u32],
        start: u32,
        end: u32,
    ) -> Result<()> {
        let (_cancel, rx_cancel) = broadcast::channel(1);
        transparent_sync(
            &Network::Main,
            connection,
            client,
            accounts,
            start,
            end,
            100,
            rx_cancel,
        )
        .await
    }

    /// The `(lo, hi)` ranges a fake server was asked for one address, in request order.
    fn asked_ranges(
        requests: &Arc<Mutex<Vec<(String, u32, u32)>>>,
        address: &str,
    ) -> Vec<(u32, u32)> {
        requests
            .lock()
            .expect("lock")
            .iter()
            .filter(|(a, _, _)| a == address)
            .map(|(_, lo, hi)| (*lo, *hi))
            .collect()
    }

    async fn set_marker(connection: &mut SqliteConnection, id_taddress: u32, marker: Option<u32>) {
        sqlx::query(
            "UPDATE transparent_address_accounts SET backfilled_height = ? WHERE id_taddress = ?",
        )
        .bind(marker)
        .bind(id_taddress)
        .execute(connection)
        .await
        .expect("marker");
    }

    async fn seen_used(connection: &mut SqliteConnection, id_taddress: u32) -> bool {
        sqlx::query_scalar(
            "SELECT seen_used FROM transparent_address_accounts WHERE id_taddress = ?",
        )
        .bind(id_taddress)
        .fetch_one(connection)
        .await
        .expect("seen_used")
    }

    async fn owed(connection: &mut SqliteConnection, id_taddress: u32) -> Option<u32> {
        catch_up_owed_through(connection, id_taddress)
            .await
            .expect("debt")
    }

    /// `count` change rows for `ACCOUNT`, ids `first_id..`, dindex `0..count`, so that with a
    /// limit of 100 the oldest of them sits outside the newest-hundred window.
    async fn change_rows(connection: &mut SqliteConnection, first_id: u32, count: u32) {
        for dindex in 0..count {
            insert_scoped_taddress(
                connection,
                first_id + dindex,
                1,
                dindex,
                &fake_taddress(first_id + dindex),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn drain_transparent_window_rejects_a_transaction_outside_the_requested_window() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (_, addr, taddr) = candidate_address(&mut connection, account).await;
        let (sender, mut rx) = channel(2);
        sender
            .send(Ok((2_000_101, transaction_paying(&taddr, 1_000), 0)))
            .await
            .expect("queue");
        sender
            .send(Ok((4_000_000_000, transaction_paying(&taddr, 2_000), 0)))
            .await
            .expect("queue");
        drop(sender);

        let error = drain_transparent_window(&addr, None, &mut rx, 2_000_000, 2_000_100)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
            .expect_err("a height outside the window must fail the window");

        assert!(
            error.to_string().contains("outside the requested window"),
            "{error}"
        );
    }

    /// The same lie through both callers: nothing of it lands — no note, no marker, no flag, no
    /// debt — and the next tick's scan set is what it was.
    #[tokio::test]
    async fn walk_and_sync_leave_nothing_behind_for_a_transaction_outside_the_window() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let (id, target) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        let scan_set_before = transparent_addresses_to_scan(&mut connection, account, 100)
            .await
            .expect("scan set");
        let mut server = AnchoredPayments::paying(vec![]);
        server.off_window = vec![(target.clone(), 2_000_101, 5_000)];
        let mut client: Client = Box::new(server);

        let walk = discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await;
        assert!(walk.is_err(), "the walk must refuse the lying answer");
        let sync = sync_range(
            &mut connection,
            &mut client,
            &[account],
            2_000_001,
            2_000_100,
        )
        .await;
        assert!(sync.is_err(), "the sync must refuse the lying answer");

        assert_eq!(note_values_at(&mut connection, id).await, Vec::<i64>::new());
        assert_eq!(taddress_backfilled_height(&mut connection, id).await, None);
        assert!(!seen_used(&mut connection, id).await);
        assert_eq!(owed(&mut connection, id).await, None);
        assert_eq!(
            transparent_addresses_to_scan(&mut connection, account, 100)
                .await
                .expect("scan set"),
            scan_set_before
        );
    }

    #[tokio::test]
    async fn discover_transparent_addresses_writes_nothing_above_the_seam() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_050).await;
        let (id, target) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        let mut client: Client = Box::new(AnchoredPayments::paying(vec![
            (&target, 2_000_020, 1_000),
            (&target, 2_000_080, 2_000),
        ]));

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("walk");

        assert_eq!(note_values_at(&mut connection, id).await, vec![1_000]);
        assert_eq!(
            highest_written_height(&mut connection, account).await,
            Some(2_000_020)
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(2_000_050)
        );
        let trim_before = tcov_trim(&mut connection, account).await;
        recover_from_partial_sync(&mut connection, &[account])
            .await
            .expect("recovery");
        assert_eq!(
            tcov_trim(&mut connection, account).await,
            trim_before,
            "the recovery found nothing above the seam to delete"
        );
        assert_eq!(note_values_at(&mut connection, id).await, vec![1_000]);
    }

    #[tokio::test]
    async fn discover_transparent_addresses_owes_a_catch_up_for_history_it_dropped_above_the_seam()
    {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_050).await;
        let target = derived_taddress(&mut connection, account, 0, 1).await;
        let mut client: Client = Box::new(AnchoredPayments::paying(vec![
            (&target, 2_000_020, 1_000),
            (&target, 2_000_080, 2_000),
        ]));

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            2,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("walk");

        let (id, _) = transparent_address_row(&mut connection, account, 0, 1)
            .await
            .expect("row lookup")
            .expect("stored");
        assert!(seen_used(&mut connection, id).await);
        assert_eq!(owed(&mut connection, id).await, Some(2_000_080));
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(2_000_050)
        );
        assert_eq!(note_values_at(&mut connection, id).await, vec![1_000]);

        sync_range(
            &mut connection,
            &mut client,
            &[account],
            2_000_051,
            2_000_100,
        )
        .await
        .expect("the next tick");
        assert_eq!(
            note_values_at(&mut connection, id).await,
            vec![1_000, 2_000]
        );
        assert_eq!(owed(&mut connection, id).await, None);
    }

    #[tokio::test]
    async fn discover_transparent_addresses_dates_no_transaction_above_the_seam() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_050).await;
        sqlx::query(
            "INSERT INTO transactions (account, txid, height, time) VALUES (?, x'01', ?, 0)",
        )
        .bind(account)
        .bind(2_000_051)
        .execute(&mut connection)
        .await
        .expect("undated transaction a failed sync left above the seam");
        let (_, target) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        let mut client: Client =
            Box::new(AnchoredPayments::paying(vec![(&target, 2_000_020, 1_000)]));

        discover_transparent_addresses(
            &Network::Main,
            &mut connection,
            &mut client,
            account,
            2_000_100,
            0,
            1,
            |_| {},
            CancellationToken::new(),
        )
        .await
        .expect("walk");

        let time: i64 = sqlx::query_scalar("SELECT time FROM transactions WHERE height = 2000051")
            .fetch_one(&mut connection)
            .await
            .expect("transaction");
        assert_eq!(time, 0, "dating it would write a header above the seam");
        let headers_above: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM headers WHERE height > 2000050")
                .fetch_one(&mut connection)
                .await
                .expect("headers");
        assert_eq!(headers_above, 0);
    }

    /// A skipped row is trusted on its marker and its notes; a trim between two candidates may
    /// have deleted those notes and clamped that marker to the very seam the postcondition reads.
    #[tokio::test]
    async fn discover_transparent_addresses_reports_incomplete_when_a_trim_landed_during_the_walk()
    {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        synced_to(&mut connection, account, 2_000_100).await;
        let (id, _) = transparent_address_row(&mut connection, account, 0, 0)
            .await
            .expect("row lookup")
            .expect("row exists");
        set_marker(&mut connection, id, Some(2_000_100)).await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET seen_used = TRUE WHERE id_taddress = ?",
        )
        .bind(id)
        .execute(&mut *connection)
        .await
        .expect("used");

        let walk = async |connection: &mut SqliteConnection, observe_after_call: u32| {
            let mut client: Client = Box::new(TrimUnderWalk {
                taddress: String::new(),
                calls: Arc::new(AtomicU32::new(0)),
                coin: coin.clone(),
                account,
                change: UnderWalkChange::Trim(2_000_040),
                observe_after_call,
                payments: vec![],
                outputs: 1,
                fail_call: None,
            });
            discover_transparent_addresses(
                &Network::Main,
                connection,
                &mut client,
                account,
                2_000_100,
                1,
                1,
                |_| {},
                CancellationToken::new(),
            )
            .await
        };

        let error = walk(&mut connection, 0)
            .await
            .expect_err("a trim during the walk invalidates the skipped row's evidence");
        assert!(
            error.to_string().contains("invalidated by a trim"),
            "{error}"
        );
        assert!(
            !crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage")
                .certified,
            "no coverage stamp after a trimmed walk"
        );

        synced_to(&mut connection, account, 2_000_100).await;
        set_marker(&mut connection, id, Some(2_000_100)).await;
        walk(&mut connection, u32::MAX)
            .await
            .expect("the same walk without the trim certifies");
        assert!(
            crate::db::read_transparent_coverage(&mut connection, account)
                .await
                .expect("coverage")
                .certified
        );
    }

    /// `reset_sync` clamps every marker to 0; history cannot predate the account, so the walk
    /// resumes at the birth height, not at block 1.
    #[tokio::test]
    async fn sync_address_range_starts_no_lower_than_the_birth_height() {
        let mut connection = memory_db().await;
        insert_account_with_birth(&mut connection, ACCOUNT, 100, 0).await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, DEFAULT_TADDR).await;
        set_pool_sync_height(&mut connection, 0, 100).await;
        set_marker(&mut connection, 1, Some(0)).await;
        let server = AnchoredPayments::paying(vec![]);
        let requests = server.requests.clone();
        let mut client: Client = Box::new(server);

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 150)
            .await
            .expect("sync");

        assert_eq!(
            asked_ranges(&requests, DEFAULT_TADDR),
            vec![(100, 100), (101, 150)],
            "the part below the seam is asked on its own"
        );
    }

    #[tokio::test]
    async fn sync_address_range_starts_at_the_marker_of_an_address_behind_the_pool() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        set_marker(&mut connection, 1, Some(50)).await;
        let server = AnchoredPayments::paying(vec![(DEFAULT_TADDR, 80, 1_000)]);
        let requests = server.requests.clone();
        let mut client: Client = Box::new(server);

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 200)
            .await
            .expect("sync");

        let asked = asked_ranges(&requests, DEFAULT_TADDR);
        assert_eq!(
            asked,
            vec![(51, 100), (101, 200)],
            "the row is caught up from its own marker, the part below the seam on its own"
        );
        assert_eq!(note_values_at(&mut connection, 1).await, vec![1_000]);
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(200)
        );
    }

    #[tokio::test]
    async fn sync_address_window_marks_the_address_seen_used_when_it_ingests_a_note() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        let mut client: Client =
            Box::new(AnchoredPayments::paying(vec![(DEFAULT_TADDR, 150, 1_000)]));

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 200)
            .await
            .expect("sync");

        assert!(seen_used(&mut connection, 1).await);
        assert!(!seen_used(&mut connection, 2).await);
        trim_sync_data(&mut connection, ACCOUNT, 100)
            .await
            .expect("trim");
        assert!(
            transparent_address_is_used(&mut connection, ACCOUNT, DEFAULT_TADDR)
                .await
                .expect("used"),
            "the trim deleted the note, not the evidence"
        );
    }

    #[tokio::test]
    async fn transparent_sync_narrows_a_window_whose_stream_failed() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        let mut server = AnchoredPayments::paying(vec![(DEFAULT_TADDR, 2_500, 1_000)]);
        server.fail_stream_wider_than = Some(1_500);
        let requests = server.requests.clone();
        let mut client: Client = Box::new(server);

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 3_100)
            .await
            .expect("halved windows succeed where the wide one failed");

        assert_eq!(sync_heights(&mut connection).await, vec![3_100]);
        assert_eq!(note_values_at(&mut connection, 1).await, vec![1_000]);
        let widths: Vec<u32> = requests
            .lock()
            .expect("lock")
            .iter()
            .map(|(_, lo, hi)| hi - lo)
            .collect();
        assert_eq!(
            widths.iter().filter(|w| **w > 1_500).count(),
            2,
            "one wide attempt per address: {widths:?}"
        );
        assert!(widths.len() > 2, "{widths:?}");
    }

    #[tokio::test]
    async fn transparent_sync_fails_the_tick_after_a_reorg_during_the_walk() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        let mut server = AnchoredPayments::paying(vec![(DEFAULT_TADDR, 150, 1_000)]);
        server.anchors = vec![fake_anchor(1), fake_anchor(2)];
        let mut client: Client = Box::new(server);

        let error = sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 200)
            .await
            .expect_err("a fork between the two anchor reads fails the tick");
        assert!(error.to_string().contains("reorganised"), "{error}");
        assert_eq!(sync_heights(&mut connection).await, vec![100]);

        // The head of the next tick deletes what the failed one committed above the pool height.
        recover_from_partial_sync(&mut connection, &[ACCOUNT])
            .await
            .expect("recovery");
        let mut settled: Client =
            Box::new(AnchoredPayments::paying(vec![(DEFAULT_TADDR, 149, 1_001)]));
        sync_range(&mut connection, &mut settled, &[ACCOUNT], 101, 200)
            .await
            .expect("the next tick against the settled chain");
        assert_eq!(sync_heights(&mut connection).await, vec![200]);
        let heights: Vec<u32> =
            sqlx::query_scalar("SELECT height FROM notes WHERE taddress = 1 ORDER BY height")
                .fetch_all(&mut connection)
                .await
                .expect("notes");
        assert_eq!(heights, vec![149], "only the re-mined payment survives");
    }

    #[tokio::test]
    async fn transparent_sync_fails_the_tick_when_the_anchor_read_stalls() {
        tokio::time::pause();
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        let mut server = AnchoredPayments::paying(vec![]);
        server.stall_anchor = true;
        let reads = server.anchor_reads.clone();
        let mut client: Client = Box::new(server);
        let (_cancel, rx_cancel) = broadcast::channel(1);

        let mut task = tokio::spawn(async move {
            let result = transparent_sync(
                &Network::Main,
                &mut connection,
                &mut client,
                &[ACCOUNT],
                101,
                200,
                10,
                rx_cancel,
            )
            .await;
            (result, connection)
        });
        wait_for_calls(&reads, 1).await;
        tokio::time::advance(WINDOW_TIMEOUT + Duration::from_millis(1)).await;
        let (result, mut connection) = tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .expect("a stalled anchor read must not hold the sync for ever")
            .expect("sync task panicked");
        let error = result.expect_err("a stalled anchor read fails the tick");
        assert!(error.to_string().contains("timed out"), "{error}");
        assert_eq!(sync_heights(&mut connection).await, vec![100]);

        // And a cancellation ends the wait before the deadline.
        let mut server = AnchoredPayments::paying(vec![]);
        server.stall_anchor = true;
        let reads = server.anchor_reads.clone();
        let mut client: Client = Box::new(server);
        let (cancel, rx_cancel) = broadcast::channel(1);
        let mut task = tokio::spawn(async move {
            transparent_sync(
                &Network::Main,
                &mut connection,
                &mut client,
                &[ACCOUNT],
                101,
                200,
                10,
                rx_cancel,
            )
            .await
        });
        wait_for_calls(&reads, 1).await;
        cancel.send(()).expect("cancel");
        let result = tokio::time::timeout(Duration::from_secs(5), &mut task)
            .await
            .expect("cancellation must end the anchor wait")
            .expect("sync task panicked");
        assert!(result
            .expect_err("a cancelled tick fails")
            .to_string()
            .contains("cancelled"));
    }

    /// An owed change row outside the newest hundred: `first_id` is its id, `marker` its marker,
    /// `through` what it owes.
    async fn owed_change_row_outside_the_window(
        connection: &mut SqliteConnection,
        marker: u32,
        through: u32,
    ) -> (u32, String) {
        two_addresses_at_height(connection, 100).await;
        change_rows(connection, 10, 101).await;
        set_marker(connection, 10, Some(marker)).await;
        crate::db::raise_catch_up_debt(connection, 10, through)
            .await
            .expect("debt");
        (10, fake_taddress(10))
    }

    #[tokio::test]
    async fn transparent_sync_clears_a_debt_only_after_the_anchor_confirms_a_marker_that_reaches_it(
    ) {
        let mut connection = memory_db().await;
        let (id, _) = owed_change_row_outside_the_window(&mut connection, 100, 150).await;
        let mut client: Client = Box::new(AnchoredPayments::paying(vec![]));

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 200)
            .await
            .expect("sync");
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(200)
        );
        assert_eq!(owed(&mut connection, id).await, None);

        // The same walk for a row whose marker write the contiguity rule drops: with no marker
        // and a birth of 0 the window `[201, 300]` is not contiguous, so the debt stands.
        set_marker(&mut connection, id, None).await;
        crate::db::raise_catch_up_debt(&mut connection, id, 250)
            .await
            .expect("debt");
        sync_range(&mut connection, &mut client, &[ACCOUNT], 201, 300)
            .await
            .expect("sync");
        assert_eq!(taddress_backfilled_height(&mut connection, id).await, None);
        assert_eq!(owed(&mut connection, id).await, Some(250));
        assert!(
            transparent_addresses_to_scan(&mut connection, ACCOUNT, 100)
                .await
                .expect("scan set")
                .iter()
                .any(|(row, _)| *row == id),
            "an unpaid debt keeps the row in the next tick's set"
        );
    }

    #[tokio::test]
    async fn transparent_sync_keeps_a_debt_after_an_anchor_mismatch() {
        let mut connection = memory_db().await;
        let (id, address) = owed_change_row_outside_the_window(&mut connection, 100, 150).await;
        let mut server = AnchoredPayments::paying(vec![(&address, 150, 1_000)]);
        server.anchors = vec![fake_anchor(1), fake_anchor(2)];
        let mut client: Client = Box::new(server);

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 200)
            .await
            .expect_err("fork");
        assert_eq!(owed(&mut connection, id).await, Some(150));

        let server = AnchoredPayments::paying(vec![(&address, 150, 1_000)]);
        let requests = server.requests.clone();
        let mut client: Client = Box::new(server);
        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 200)
            .await
            .expect("the next tick");
        let asked = asked_ranges(&requests, &address);
        assert!(!asked.is_empty(), "the owed row is in the next tick's set");
        assert_eq!(note_values_at(&mut connection, id).await, vec![1_000]);
        assert_eq!(owed(&mut connection, id).await, None);
    }

    /// A fork proves the walk answered against a chain that no longer exists, so the markers it
    /// advanced prove nothing: the next tick asks again from where each row stood before.
    #[tokio::test]
    async fn transparent_sync_rewalks_the_range_a_forked_tick_answered_behind_the_pool() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 200).await;
        set_marker(&mut connection, 1, Some(100)).await;
        let mut server = AnchoredPayments::paying(vec![]);
        server.anchors = vec![fake_anchor(1), fake_anchor(2)];
        let mut client: Client = Box::new(server);

        sync_range(&mut connection, &mut client, &[ACCOUNT], 201, 250)
            .await
            .expect_err("fork");
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(100)
        );

        recover_from_partial_sync(&mut connection, &[ACCOUNT])
            .await
            .expect("recovery");
        // The fork re-mined a payment into the range the failed tick had already answered.
        let settled = AnchoredPayments::paying(vec![(DEFAULT_TADDR, 150, 1_000)]);
        let requests = settled.requests.clone();
        let mut client: Client = Box::new(settled);
        sync_range(&mut connection, &mut client, &[ACCOUNT], 201, 250)
            .await
            .expect("the next tick");

        assert_eq!(
            asked_ranges(&requests, DEFAULT_TADDR),
            vec![(101, 200), (201, 250)]
        );
        assert_eq!(note_values_at(&mut connection, 1).await, vec![1_000]);
    }

    async fn straggler_paid_below_the_seam(connection: &mut SqliteConnection) -> AnchoredPayments {
        two_addresses_at_height(connection, 200).await;
        set_marker(connection, 1, Some(100)).await;
        AnchoredPayments::paying(vec![(DEFAULT_TADDR, 150, 1_000)])
    }

    /// Recovery trims only above the seam, so a catch-up below it is durable: nothing of it may
    /// land while the chain it was read from is unconfirmed.
    #[tokio::test]
    async fn transparent_sync_writes_nothing_below_the_seam_when_the_anchor_read_fails() {
        let mut connection = memory_db().await;
        let mut server = straggler_paid_below_the_seam(&mut connection).await;
        server.fail_anchor_read = Some(1);
        let mut client: Client = Box::new(server);

        let error = sync_range(&mut connection, &mut client, &[ACCOUNT], 201, 250)
            .await
            .expect_err("the confirming read failed");

        assert!(error.to_string().contains("anchor read failed"), "{error}");
        assert_eq!(note_values_at(&mut connection, 1).await, Vec::<i64>::new());
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(100)
        );
    }

    #[tokio::test]
    async fn transparent_sync_discards_a_below_seam_catch_up_the_fork_invalidated() {
        let mut connection = memory_db().await;
        let mut server = straggler_paid_below_the_seam(&mut connection).await;
        server.anchors = vec![fake_anchor(1), fake_anchor(2)];
        let mut client: Client = Box::new(server);

        sync_range(&mut connection, &mut client, &[ACCOUNT], 201, 250)
            .await
            .expect_err("fork");
        assert_eq!(note_values_at(&mut connection, 1).await, Vec::<i64>::new());
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(100)
        );

        recover_from_partial_sync(&mut connection, &[ACCOUNT])
            .await
            .expect("recovery");
        // The fork removed the payment outright; the settled chain never had it.
        let settled = AnchoredPayments::paying(vec![]);
        let requests = settled.requests.clone();
        let mut client: Client = Box::new(settled);
        sync_range(&mut connection, &mut client, &[ACCOUNT], 201, 250)
            .await
            .expect("the next tick");

        assert_eq!(
            asked_ranges(&requests, DEFAULT_TADDR),
            vec![(101, 200), (201, 250)]
        );
        assert_eq!(note_values_at(&mut connection, 1).await, Vec::<i64>::new());
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(250)
        );
        assert_eq!(sync_heights(&mut connection).await, vec![250]);
    }

    /// The confirming read sits between the two parts of the range: a fork above the seam fails the
    /// tick but does not take the confirmed catch-up below it with it.
    #[tokio::test]
    async fn transparent_sync_keeps_a_confirmed_below_seam_catch_up_when_the_walk_above_it_forks() {
        let mut connection = memory_db().await;
        let mut server = straggler_paid_below_the_seam(&mut connection).await;
        server.anchors = vec![fake_anchor(1), fake_anchor(1), fake_anchor(2)];
        let mut client: Client = Box::new(server);

        sync_range(&mut connection, &mut client, &[ACCOUNT], 201, 250)
            .await
            .expect_err("fork above the seam");
        recover_from_partial_sync(&mut connection, &[ACCOUNT])
            .await
            .expect("recovery");

        assert_eq!(note_values_at(&mut connection, 1).await, vec![1_000]);
        assert_eq!(
            taddress_backfilled_height(&mut connection, 1).await,
            Some(200)
        );
        assert_eq!(sync_heights(&mut connection).await, vec![200]);
    }

    #[tokio::test]
    async fn transparent_sync_keeps_a_debt_whose_height_lies_above_the_invocation_target() {
        let mut connection = memory_db().await;
        let (id, address) = owed_change_row_outside_the_window(&mut connection, 100, 200).await;
        let mut client: Client = Box::new(AnchoredPayments::paying(vec![(&address, 200, 1_000)]));

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 199)
            .await
            .expect("a target sampled before the walk owed the debt");
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(199)
        );
        assert_eq!(owed(&mut connection, id).await, Some(200));
        assert!(transparent_addresses_to_scan(&mut connection, ACCOUNT, 100)
            .await
            .expect("scan set")
            .iter()
            .any(|(row, _)| *row == id));

        sync_range(&mut connection, &mut client, &[ACCOUNT], 200, 200)
            .await
            .expect("the tick that reaches the debt");
        assert_eq!(note_values_at(&mut connection, id).await, vec![1_000]);
        assert_eq!(owed(&mut connection, id).await, None);
    }

    #[tokio::test]
    async fn transparent_sync_keeps_a_debt_a_lagging_server_cannot_reach() {
        let mut connection = memory_db().await;
        let (id, address) =
            owed_change_row_outside_the_window(&mut connection, 100, 3_000_101).await;
        let mut client: Client =
            Box::new(AnchoredPayments::paying(vec![(&address, 3_000_101, 1_000)]));

        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 3_000_000)
            .await
            .expect("an endpoint behind the debt completes its tick");
        assert_eq!(owed(&mut connection, id).await, Some(3_000_101));

        sync_range(
            &mut connection,
            &mut client,
            &[ACCOUNT],
            3_000_001,
            3_000_101,
        )
        .await
        .expect("an endpoint at the debt");
        assert_eq!(note_values_at(&mut connection, id).await, vec![1_000]);
        assert_eq!(owed(&mut connection, id).await, None);
    }

    /// Round 3's 100/301 oscillation as a pin: an owed row joins the newest hundred exactly until
    /// one tick has paid it.
    #[tokio::test]
    async fn transparent_addresses_to_scan_includes_an_owed_change_address_until_it_is_scanned_once(
    ) {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        change_rows(&mut connection, 10, 301).await;
        set_marker(&mut connection, 10, Some(100)).await;
        crate::db::raise_catch_up_debt(&mut connection, 10, 200)
            .await
            .expect("debt");
        let mut client: Client = Box::new(AnchoredPayments::paying(vec![]));
        let scan_set_size = async |connection: &mut SqliteConnection| {
            transparent_addresses_to_scan(connection, ACCOUNT, 100)
                .await
                .expect("scan set")
                .len()
        };

        assert_eq!(scan_set_size(&mut connection).await, 2 + 100 + 1);
        sync_range(&mut connection, &mut client, &[ACCOUNT], 101, 200)
            .await
            .expect("tick");
        assert_eq!(scan_set_size(&mut connection).await, 2 + 100);
        for tick in 1..=6u32 {
            let start = 200 + (tick - 1) * 10 + 1;
            sync_range(&mut connection, &mut client, &[ACCOUNT], start, start + 9)
                .await
                .expect("tick");
            assert_eq!(scan_set_size(&mut connection).await, 2 + 100);
        }
        assert_eq!(sync_heights(&mut connection).await, vec![260]);
    }

    #[tokio::test]
    async fn trim_sync_data_re_owes_a_catch_up_for_an_address_whose_notes_it_deletes() {
        let mut connection = memory_db().await;
        two_addresses_at_height(&mut connection, 100).await;
        change_rows(&mut connection, 10, 2).await;
        for (id_note, height, taddress) in [(1, 150, 10), (2, 50, 11)] {
            crate::db::tests::insert_note(
                &mut connection,
                id_note,
                id_note,
                0,
                height,
                1_000,
                None,
            )
            .await;
            sqlx::query("UPDATE notes SET taddress = ? WHERE id_note = ?")
                .bind(taddress)
                .bind(id_note)
                .execute(&mut connection)
                .await
                .expect("taddress");
        }

        trim_sync_data(&mut connection, ACCOUNT, 100)
            .await
            .expect("trim");

        assert_eq!(note_values_at(&mut connection, 10).await, Vec::<i64>::new());
        assert_eq!(owed(&mut connection, 10).await, Some(150));
        assert_eq!(note_values_at(&mut connection, 11).await, vec![1_000]);
        assert_eq!(owed(&mut connection, 11).await, None);
    }

    #[tokio::test]
    async fn reset_sync_clears_every_catch_up_debt() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        for (id, dindex, through) in [
            (900, 0, 2_000_050),
            (901, 1, 2_000_060),
            (902, 2, 1_000_000_000),
        ] {
            let address = derived_taddress(&mut connection, account, 1, dindex).await;
            insert_scoped_taddress_for_account(&mut connection, account, id, 1, dindex, &address)
                .await;
            set_marker(&mut connection, id, Some(2_000_100)).await;
            crate::db::raise_catch_up_debt(&mut connection, id, through)
                .await
                .expect("debt");
        }

        crate::account::reset_sync(&Network::Main, &mut connection, account)
            .await
            .expect("reset");

        for id in [900, 901, 902] {
            assert_eq!(owed(&mut connection, id).await, None);
            assert_eq!(
                taddress_backfilled_height(&mut connection, id).await,
                Some(0)
            );
        }
    }

    #[tokio::test]
    async fn transparent_sync_reingests_an_old_change_note_the_trim_deleted() {
        let mut connection = memory_db().await;
        let (account, change) = reingested_old_change_note(&mut connection).await;

        let (id, _): (u32, String) = sqlx::query_as(
            "SELECT id_taddress, address FROM transparent_address_accounts WHERE address = ?",
        )
        .bind(&change)
        .fetch_one(&mut connection)
        .await
        .expect("row");
        assert_eq!(
            owed(&mut connection, id).await,
            None,
            "the tick paid the debt"
        );
        assert_eq!(
            taddress_backfilled_height(&mut connection, id).await,
            Some(2_000_100)
        );
        assert_eq!(
            transparent_heights(&mut connection).await,
            vec![(account, 2_000_100)]
        );
    }

    // ---- The driver: transparent before shielded, one anchor pair per range ----

    async fn sync_cycle(
        coin: &Coin,
        connection: &mut SqliteConnection,
        client: &mut Client,
        accounts: &[u32],
        tip: u32,
    ) -> Result<()> {
        let pool = coin.get_pool().expect("pool");
        let (tx_progress, mut rx_progress) = channel::<SyncProgress>(1);
        tokio::spawn(async move { while rx_progress.recv().await.is_some() {} });
        let (tx_cancel, _rx_cancel) = broadcast::channel(1);
        sync_height_ranges(
            &Network::Main,
            &pool,
            connection,
            client,
            accounts,
            tip,
            1_000,
            100,
            true,
            &tx_progress,
            &tx_cancel,
        )
        .await
    }

    /// Two keyless accounts at different heights, so the driver builds two ranges and the
    /// shielded pass has nothing to decrypt.
    async fn two_accounts_two_ranges(connection: &mut SqliteConnection) {
        two_accounts_at_height(connection, 100).await;
        set_pool_sync_height_for_account(connection, OTHER_ACCOUNT, 0, 150).await;
    }

    #[tokio::test]
    async fn synchronize_impl_keeps_a_debt_across_an_intermediate_height_range() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        two_accounts_two_ranges(&mut connection).await;
        change_rows(&mut connection, 10, 301).await;
        for id in 10..311 {
            set_marker(&mut connection, id, Some(100)).await;
            crate::db::raise_catch_up_debt(&mut connection, id, 200)
                .await
                .expect("debt");
        }
        let server = AnchoredPayments::paying(vec![]);
        let requests = server.requests.clone();
        let mut client: Client = Box::new(server);

        sync_cycle(
            &coin,
            &mut connection,
            &mut client,
            &[ACCOUNT, OTHER_ACCOUNT],
            200,
        )
        .await
        .expect("cycle");

        let change: std::collections::HashSet<String> = (10..311).map(fake_taddress).collect();
        let second_range: Vec<(u32, u32)> = requests
            .lock()
            .expect("lock")
            .iter()
            .filter(|(a, lo, _)| change.contains(a) && *lo > 150)
            .map(|(_, lo, hi)| (*lo, *hi))
            .collect();
        assert_eq!(
            second_range.len(),
            301,
            "every owed row is still in the second range's set"
        );
        assert!(
            second_range.iter().all(|r| *r == (151, 200)),
            "each row was carried to 150 by the first range: {second_range:?}"
        );
        for id in 10..311 {
            assert_eq!(
                taddress_backfilled_height(&mut connection, id).await,
                Some(200)
            );
            assert_eq!(owed(&mut connection, id).await, None);
        }
    }

    #[tokio::test]
    async fn synchronize_impl_stops_at_an_anchor_mismatch_before_the_next_height_range() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        two_accounts_two_ranges(&mut connection).await;
        let mut server = AnchoredPayments::paying(vec![(DEFAULT_TADDR, 120, 1_000)]);
        server.anchors = vec![fake_anchor(1), fake_anchor(2), fake_anchor(3)];
        let requests = server.requests.clone();
        let mut client: Client = Box::new(server);

        sync_cycle(
            &coin,
            &mut connection,
            &mut client,
            &[ACCOUNT, OTHER_ACCOUNT],
            200,
        )
        .await
        .expect_err("the fork in the first range fails the cycle");

        assert!(
            requests
                .lock()
                .expect("lock")
                .iter()
                .all(|(_, lo, _)| *lo == 101),
            "the second range is never requested"
        );
        assert_eq!(
            transparent_heights(&mut connection).await,
            vec![(ACCOUNT, 100), (OTHER_ACCOUNT, 150)]
        );

        let mut settled: Client =
            Box::new(AnchoredPayments::paying(vec![(DEFAULT_TADDR, 120, 1_000)]));
        sync_cycle(
            &coin,
            &mut connection,
            &mut settled,
            &[ACCOUNT, OTHER_ACCOUNT],
            200,
        )
        .await
        .expect("the next cycle against the settled chain");
        assert_eq!(note_values_at(&mut connection, 1).await, vec![1_000]);
        assert_eq!(
            transparent_heights(&mut connection).await,
            vec![(ACCOUNT, 200), (OTHER_ACCOUNT, 200)]
        );
    }

    /// Round 17's reproduction: the pools at 2 000 100, discovery flagged a change address paid
    /// at 2 000 106 and owed the catch-up, a fork above the seam removed the payment. Under the
    /// ledger the same sequence wedged every pool; here each cycle advances and the debt is paid
    /// by the marker alone.
    #[tokio::test]
    async fn final_review_fork_above_the_seam_no_longer_blocks_sync() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        insert_account_with_birth(&mut connection, ACCOUNT, 0, 0).await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, DEFAULT_TADDR).await;
        set_pool_sync_height(&mut connection, 0, 2_000_100).await;
        change_rows(&mut connection, 10, 101).await;
        set_marker(&mut connection, 10, Some(2_000_100)).await;
        sqlx::query(
            "UPDATE transparent_address_accounts SET seen_used = TRUE WHERE id_taddress = 10",
        )
        .execute(&mut *connection)
        .await
        .expect("what discovery left");
        crate::db::raise_catch_up_debt(&mut connection, 10, 2_000_106)
            .await
            .expect("what discovery left");
        let mut client: Client = Box::new(AnchoredPayments::paying(vec![]));

        for cycle in 1..=3u32 {
            let tip = 2_000_100 + cycle * 10;
            sync_cycle(&coin, &mut connection, &mut client, &[ACCOUNT], tip)
                .await
                .unwrap_or_else(|e| panic!("cycle {cycle} failed: {e}"));
            assert_eq!(sync_heights(&mut connection).await, vec![tip]);
        }
        assert_eq!(owed(&mut connection, 10).await, None);
    }
}
