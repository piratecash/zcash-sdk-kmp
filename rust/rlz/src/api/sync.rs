use anyhow::Result;
use std::sync::LazyLock;
use tokio::sync::{broadcast, Mutex};

use crate::api::coin::Coin;

use crate::db::{
    calculate_balance, calculate_balance_breakdown,
    max_spendable_from_pools as db_max_spendable_from_pools,
};
use crate::io::SyncHeight;
use crate::pay::pool::PoolMask;
use crate::sync::BlockHeader;

#[cfg(feature = "flutter")]
use crate::frb_generated::StreamSink;
#[cfg(feature = "flutter")]
use flutter_rust_bridge::frb;

#[cfg(feature = "flutter")]
#[allow(clippy::too_many_arguments)]
#[cfg_attr(feature = "flutter", frb)]
pub async fn synchronize(
    progress: StreamSink<SyncProgress>,
    accounts: Vec<u32>,
    current_height: u32,
    actions_per_sync: u32,
    transparent_limit: u32,
    checkpoint_age: u32,
    fast: bool,
    c: &Coin,
) -> Result<u32> {
    crate::sync::synchronize_impl(
        progress,
        accounts,
        current_height,
        actions_per_sync,
        transparent_limit,
        checkpoint_age,
        fast,
        c,
    )
    .await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn balance(c: &Coin) -> Result<PoolBalance> {
    let mut connection = c.get_connection().await?;
    let account = c.account;

    calculate_balance(&mut *connection, account, None).await
}

/// Splits the balance into spendable and pending, per pool.
///
/// `confirmations` is the caller's threshold; the cutoff height is the locally scanned
/// one, so the result never depends on the network being reachable.
#[cfg_attr(feature = "flutter", frb)]
pub async fn balance_breakdown(confirmations: u32, c: &Coin) -> Result<PoolBalanceBreakdown> {
    let mut connection = c.get_connection().await?;
    let account = c.account;

    calculate_balance_breakdown(&mut connection, account, confirmations).await
}

/// A conservative lower bound on what is spendable from `pool_mask` alone, fundable
/// for any single recipient pool. A same-pool send can afford more.
pub async fn max_spendable_from_pools(confirmations: u32, pool_mask: u8, c: &Coin) -> Result<u64> {
    let mut connection = c.get_connection().await?;
    let account = c.account;

    db_max_spendable_from_pools(&mut connection, account, PoolMask(pool_mask), confirmations).await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn cancel_sync() -> Result<()> {
    let tx = CANCEL_SYNC.lock().await;
    if let Some(tx) = tx.as_ref() {
        tx.send(())?;
    }
    Ok(())
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn rewind_sync(height: u32, account: u32, c: &Coin) -> Result<()> {
    let mut connection = c.get_connection().await?;
    crate::sync::rewind_sync(&c.network(), &mut *connection, account, height).await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn get_db_height(c: &Coin) -> Result<SyncHeight> {
    let mut connection = c.get_connection().await?;
    crate::sync::get_db_height(&mut *connection, c.account).await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn fetch_tx_details(account: u32, c: &Coin) -> Result<()> {
    let mut connection = c.get_connection().await?;
    let mut client = c.client().await?;
    crate::memo::fetch_tx_details(&c.network(), &mut *connection, &mut client, account).await?;
    Ok(())
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn cache_block_time(height: u32, c: &Coin) -> Result<()> {
    let mut connection = c.get_connection().await?;
    let mut client = c.client().await?;
    let block = client.block(&c.network(), height).await?;
    let bh = BlockHeader {
        height,
        hash: block.hash,
        time: block.time,
    };
    crate::db::store_block_header(&mut connection, &bh).await?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SyncProgress {
    pub height: u32,
    pub time: u32,
}

pub struct PoolBalance(pub Vec<u64>);

/// One pool's unspent value, split by how many confirmations its notes still need.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    pub available: u64,
    pub locked: u64,
    pub change_pending: u64,
    pub value_pending: u64,
}

pub struct PoolBalanceBreakdown(pub Vec<Balance>);

pub static SYNCING: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
pub static CANCEL_SYNC: LazyLock<Mutex<Option<broadcast::Sender<()>>>> =
    LazyLock::new(|| Mutex::new(None));
