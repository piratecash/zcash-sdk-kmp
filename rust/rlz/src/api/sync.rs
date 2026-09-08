use anyhow::Result;
use sqlx::pool::PoolConnection;
use sqlx::Sqlite;
use std::sync::LazyLock;
use tokio::sync::{broadcast, Mutex, MutexGuard};

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

/// Takes the SDK-wide sync guard before its pooled connection, always in that order, so a
/// caller queued here can never end up holding a connection while it waits for `SYNCING`.
pub(crate) async fn locked_connection(
    c: &Coin,
) -> Result<(MutexGuard<'static, ()>, PoolConnection<Sqlite>)> {
    let guard = SYNCING.lock().await;
    let connection = c.get_connection().await?;
    Ok((guard, connection))
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn rewind_sync(height: u32, account: u32, c: &Coin) -> Result<()> {
    let (_guard, mut connection) = locked_connection(c).await?;
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

/// A real, file-backed `Coin` with a fully opened (5-connection) pool, for tests that need to
/// exhaust the pool to observe lock-vs-connection acquisition order. Shared across `api` test
/// modules since the pool internals it exercises (`api/coin.rs`) are not test-owned here.
#[cfg(test)]
pub(crate) async fn file_backed_coin() -> Coin {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "rlz-locked-connection-test-{}-{nanos}-{n}.sqlite",
        std::process::id(),
    ));
    Coin::new(None)
        .open_database(path.to_string_lossy().into_owned(), None)
        .await
        .expect("open file-backed test database")
}

/// Serializes tests that exercise the process-wide `SYNCING`/`DISCOVERING` guards. Cargo runs
/// tests in parallel by default; without this, an unrelated test contending for the same
/// global lock produces a false pass or a false failure depending on timing.
#[cfg(test)]
pub(crate) static LOCK_TEST_SERIAL: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Asserts one entry point queues behind `SYNCING` rather than interleaving with a walk: a
/// discovery window checks the account's identity once and then writes under that same guard
/// until it commits, so anything that can free or reuse an account id has to wait its turn.
#[cfg(test)]
pub(crate) async fn assert_queues_behind_syncing<F>(what: &str, call: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let guard = SYNCING.lock().await;
    let mut task = tokio::spawn(call);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut task)
            .await
            .is_err(),
        "{what} must not complete while SYNCING is held"
    );

    drop(guard);
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut task)
        .await
        .unwrap_or_else(|_| panic!("{what} did not complete once SYNCING was released"))
        .expect("task panicked")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::{restore, TEST_PHRASE};
    use std::time::Duration;

    #[tokio::test]
    async fn locked_connection_takes_the_guard_before_the_connection() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(
                coin.get_connection()
                    .await
                    .expect("acquire pooled connection"),
            );
        }

        let mut call = tokio::spawn({
            let coin = coin.clone();
            async move { locked_connection(&coin).await.map(|(_guard, _conn)| ()) }
        });

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            SYNCING.try_lock().is_err(),
            "a lock-first locked_connection must already hold SYNCING while the pool is exhausted"
        );

        held.pop();
        let joined = tokio::time::timeout(Duration::from_secs(5), &mut call)
            .await
            .expect("locked_connection did not complete once a connection was freed");
        joined
            .expect("task panicked")
            .expect("locked_connection failed");
    }

    #[tokio::test]
    async fn locked_connection_waits_for_a_sync_holding_the_lock() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;

        assert_queues_behind_syncing("locked_connection", async move {
            locked_connection(&coin).await.map(|(_guard, _conn)| ())
        })
        .await
        .expect("locked_connection failed");
    }

    /// `rewind_sync` reaches `locked_connection` like any other wrapper, so a discovery walk
    /// mid-window (holding `SYNCING`) must make it wait rather than let it interleave with the
    /// walk's own writes.
    #[tokio::test]
    async fn rewind_sync_waits_for_a_discovery_holding_the_lock() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = restored_coin().await;
        let account = coin.account;

        assert_queues_behind_syncing("rewind_sync", async move {
            rewind_sync(0, account, &coin).await
        })
        .await
        .expect("rewind_sync failed");
    }

    /// `delete_account` frees the account id a walk mid-window is writing under.
    #[tokio::test]
    async fn delete_account_waits_for_a_discovery_holding_the_lock() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = restored_coin().await;
        let account = coin.account;

        assert_queues_behind_syncing("delete_account", async move {
            crate::api::account::delete_account(account, &coin).await
        })
        .await
        .expect("delete_account failed");
    }

    async fn restored_coin() -> Coin {
        let coin = file_backed_coin().await;
        let mut connection = coin
            .get_connection()
            .await
            .expect("acquire pooled connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore test account");
        drop(connection);
        Coin { account, ..coin }
    }

    /// Cancelling a DKG deletes accounts, so it frees ids the same way `delete_account` does.
    #[tokio::test]
    async fn cancel_dkg_waits_for_a_discovery_holding_the_lock() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = restored_coin().await;

        // No DKG was ever started here, so the call fails once it gets its turn — what this pins
        // is that it does not get that turn while a walk holds the lock.
        let _ = assert_queues_behind_syncing("cancel_dkg", async move {
            crate::api::frost::cancel_dkg(&coin).await
        })
        .await;
    }

    #[tokio::test]
    async fn reset_sign_waits_for_a_discovery_holding_the_lock() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = restored_coin().await;

        assert_queues_behind_syncing("reset_sign", async move {
            crate::api::frost::reset_sign(&coin).await
        })
        .await
        .expect("reset_sign failed");
    }
}
