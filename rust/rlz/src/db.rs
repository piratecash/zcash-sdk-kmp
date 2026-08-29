use std::fs::File;

use crate::keys::{SaplingDiversifiedAddress, ScopeExt};
use anyhow::{anyhow, Result};
use csv_async::AsyncWriter;
use futures::TryStreamExt;
use orchard::keys::{FullViewingKey, SpendingKey};
use sapling_crypto::PaymentAddress;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteRow},
    Column, Connection, Row, SqliteConnection, TypeInfo,
};
use tracing::debug;
use zcash_keys::{
    encoding::AddressCodec,
    keys::sapling::{DiversifiableFullViewingKey, ExtendedSpendingKey},
};
use zcash_protocol::consensus::NetworkUpgrade;
use zcash_protocol::consensus::Parameters;
use zcash_transparent::keys::{AccountPrivKey, AccountPubKey};

use crate::api::account::Folder;
use crate::api::account::TAddressTxCount;
use crate::api::account::{Account, Memo, Tx};
use crate::api::coin::Network;
use crate::api::sync::{Balance, PoolBalance, PoolBalanceBreakdown};
use crate::pay::fee::COST_PER_ACTION;
use crate::pay::pool::{PoolMask, NUM_POOLS};
use crate::sync::BlockHeader;
use crate::{api::account::TxNote, tiu};

/// Schema version. Bump only when the export format changes (IOAccount or any
/// embedded struct gains/removes/changes a field). Do NOT bump for runtime-only
/// changes (queries, PoolBalance, solve mode, etc.).
pub const DB_VERSION: u16 = 10;

pub async fn create_schema(connection: &mut SqliteConnection) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS props(
        key TEXT PRIMARY KEY,
        VALUE TEXT NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS accounts(
        id_account INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        seed TEXT,
        passphrase TEXT NOT NULL DEFAULT '',
        seed_fingerprint BLOB,
        aindex INTEGER NOT NULL,
        dindex INTEGER NOT NULL,
        def_dindex INTEGER NOT NULL,
        icon BLOB,
        birth INTEGER NOT NULL,
        position INTEGER NOT NULL,
        use_internal BOOL NOT NULL,
        hidden BOOL NOT NULL,
        saved BOOL NOT NULL,
        enabled BOOL NOT NULL DEFAULT TRUE,
        internal BOOL NOT NULL DEFAULT FALSE,
        can_sign INTEGER NOT NULL DEFAULT(0)
        )",
    )
    .execute(&mut *connection)
    .await?;

    // `create_schema` runs on every open (api/coin.rs), so a swallowed error here would
    // silently leave existing databases without the column and `can_sign` permanently false.
    if !has_can_sign_column(&mut *connection).await? {
        migrate_can_sign(connection).await?;
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS transparent_accounts(
        account INTEGER PRIMARY KEY,
        xsk BLOB,
        xvk BLOB)",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS transparent_address_accounts(
        id_taddress INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        scope INTEGER NOT NULL,
        dindex INTEGER NOT NULL,
        sk BLOB,
        pk BLOB NOT NULL,
        address TEXT NOT NULL,
        UNIQUE (account, scope, dindex))",
    )
    .execute(&mut *connection)
    .await?;

    let _ =
        sqlx::query("ALTER TABLE transparent_address_accounts ADD COLUMN uncompressed BOOL NOT NULL DEFAULT FALSE")
            .execute(&mut *connection)
            .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sapling_accounts(
        account INTEGER PRIMARY KEY,
        xsk BLOB,
        xvk BLOB NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;

    let _ =
        sqlx::query("ALTER TABLE sapling_accounts ADD COLUMN address BLOB NOT NULL DEFAULT('')")
            .execute(&mut *connection)
            .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS orchard_accounts(
        account INTEGER PRIMARY KEY,
        xsk BLOB,
        xvk BLOB NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sync_heights(
        account INTEGER,
        pool INTEGER NOT NULL,
        height INTEGER NOT NULL,
        PRIMARY KEY (account, pool))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS headers(
        height INTEGER PRIMARY KEY,
        hash BLOB NOT NULL,
        time INTEGER NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS notes(
        id_note INTEGER PRIMARY KEY,
        height INTEGER NOT NULL,
        account INTEGER NOT NULL,
        pool INTEGER NOT NULL,
        scope INTEGER,
        nullifier BLOB NOT NULL,
        tx INTEGER NOT NULL,
        value INTEGER NOT NULL,
        cmx BLOB,
        taddress INTEGER,
        position INTEGER,
        diversifier BLOB,
        rcm BLOB,
        rho BLOB,
        locked BOOL NOT NULL DEFAULT FALSE,
        id_asset INTEGER,
        diversifier_index INTEGER,
        UNIQUE(account, nullifier))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS spends(
        id_note INTEGER PRIMARY KEY,
        height INTEGER NOT NULL,
        account INTEGER NOT NULL,
        pool INTEGER NOT NULL,
        tx INTEGER NOT NULL,
        value INTEGER NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS transactions(
        id_tx INTEGER PRIMARY KEY,
        txid BLOB NOT NULL,
        height INTEGER NOT NULL,
        account INTEGER NOT NULL,
        time INTEGER,
        details BOOL NOT NULL DEFAULT FALSE,
        tpe INTEGER,
        value INTEGER NOT NULL DEFAULT 0,
        fee INTEGER NOT NULL DEFAULT 0,
        UNIQUE (account, txid))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS witnesses(
        id_witness INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        note INTEGER NOT NULL,
        height INTEGER NOT NULL,
        witness BLOB NOT NULL,
        UNIQUE (note, height))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS outputs (
        id_output INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        height INTEGER NOT NULL,
        tx INTEGER NOT NULL,
        pool INTEGER NOT NULL,
        vout INTEGER NOT NULL,
        value INTEGER NOT NULL,
        address TEXT NOT NULL,
        UNIQUE (tx, pool, vout))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS memos(
        id_memo INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        height INTEGER NOT NULL,
        tx INTEGER NOT NULL,
        pool INTEGER NOT NULL,
        vout INTEGER NOT NULL,
        note INTEGER,
        output INTEGER,
        memo_text TEXT,
        memo_bytes BLOB NOT NULL,
        UNIQUE (tx, pool, vout))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_memos(
        account INTEGER NOT NULL,
        id_tx INTEGER NOT NULL,
        user_memo TEXT NOT NULL,
        UNIQUE(account, id_tx))",
    )
    .execute(&mut *connection)
    .await?;
    tracing::debug!("create_schema: user_memos table ready");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS assets(
        id_asset INTEGER PRIMARY KEY,
        asset_desc_hash BLOB NOT NULL,
        ik BLOB NOT NULL,
        asset_base BLOB NOT NULL,
        finalized BOOL NOT NULL DEFAULT FALSE,
        first_seen_height INTEGER NOT NULL,
        UNIQUE (asset_desc_hash, ik),
        UNIQUE (asset_base))",
    )
    .execute(&mut *connection)
    .await?;

    // Migration: add id_asset to notes for ZSA note→asset linking
    let _ =
        sqlx::query("ALTER TABLE notes ADD COLUMN id_asset INTEGER REFERENCES assets(id_asset)")
            .execute(&mut *connection)
            .await;

    // Migration: add diversifier_index to notes for per-address shielded tx counts
    let _ = sqlx::query("ALTER TABLE notes ADD COLUMN diversifier_index INTEGER")
        .execute(&mut *connection)
        .await;

    // Migration: add asset_name to assets for human-readable naming
    let _ = sqlx::query("ALTER TABLE assets ADD COLUMN asset_name TEXT")
        .execute(&mut *connection)
        .await;

    // Migration: ensure asset_base is unique to prevent duplicate note inserts
    // caused by duplicate issuances with the same asset_base.
    let _ = sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_asset_base ON assets(asset_base)",
    )
    .execute(&mut *connection)
    .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dkg_params (
        account INTEGER PRIMARY KEY,
        id INTEGER NOT NULL,
        n INTEGER NOT NULL,
        t INTEGER NOT NULL,
        seed TEXT NOT NULL,
        birth_height INTEGER NOT NULL,
        name TEXT NOT NULL DEFAULT('')
    )",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dkg_packages (
        id_dkg_package INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        public BOOL NOT NULL,
        round INTEGER NOT NULL,
        from_id INTEGER NOT NULL,
        data BLOB NOT NULL,
        UNIQUE (account, public, round, from_id)
    )",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dkg_addresses (
        account INTEGER NOT NULL,
        from_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        PRIMARY KEY (account, from_id)
    )",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dkg_state (
        account INTEGER PRIMARY KEY,
        spkg1 BLOB,
        spkg2 BLOB,
        key_pkg BLOB
    )",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dkg_peers (
        account INTEGER NOT NULL,
        round INTEGER NOT NULL,
        from_id INTEGER NOT NULL,
        data BLOB NOT NULL,
        PRIMARY KEY (account, round, from_id)
    )",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS frost_signatures (
        id_signature INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        sighash BLOB NOT NULL,
        idx INTEGER NOT NULL,
        nonce BLOB NOT NULL,
        sigpackage BLOB,
        randomizer BLOB,
        sigshare BLOB,
        signature BLOB,
        UNIQUE (account, sighash, idx))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS frost_commitments (
        id_nonce INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        sighash BLOB NOT NULL,
        idx INTEGER NOT NULL,
        from_id INTEGER NOT NULL,
        commitment BLOB NOT NULL,
        sigshare BLOB,
        UNIQUE (account, sighash, idx, from_id))",
    )
    .execute(&mut *connection)
    .await?;

    // V5
    let _ = sqlx::query("ALTER TABLE accounts ADD COLUMN folder INTEGER")
        .execute(&mut *connection)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS folders (
        id_folder INTEGER PRIMARY KEY,
        name TEXT NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;

    let _ = sqlx::query("ALTER TABLE transactions ADD COLUMN category INTEGER")
        .execute(&mut *connection)
        .await;
    let _ = sqlx::query("ALTER TABLE transactions ADD COLUMN price REAL")
        .execute(&mut *connection)
        .await;
    let _ = sqlx::query("ALTER TABLE transactions ADD COLUMN zsa_value INTEGER NOT NULL DEFAULT 0")
        .execute(&mut *connection)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE transactions ADD COLUMN asset_id INTEGER REFERENCES assets(id_asset)",
    )
    .execute(&mut *connection)
    .await;
    if sqlx::query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='categories'")
        .fetch_optional(&mut *connection)
        .await?
        .is_none()
    {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS categories (
                id_category INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                income BOOL NOT NULL,
                UNIQUE (name))",
        )
        .execute(&mut *connection)
        .await?;

        for (c, i) in vec![
            ("Salary", true),
            ("Investment Income/Mining", true),
            ("Rental/Property Income", true),
            ("Other Income", true),
            ("Housing & Utilities", false),
            ("Food & Groceries", false),
            ("Restaurants & Coffee", false),
            ("Transportation & Hotels", false),
            ("Health & Insurance", false),
            ("Debt & Financial Obligations", false),
            ("Education & Training", false),
            ("Entertainment & Lifestyle", false),
            ("Personal & Family Care", false),
            ("Savings & Investments", false),
            ("Other Expenses", false),
        ] {
            sqlx::query(
                "INSERT OR REPLACE INTO categories(name, income)
            VALUES (?, ?)",
            )
            .bind(c)
            .bind(i)
            .execute(&mut *connection)
            .await?;
        }
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_txs (
        id_pending_tx INTEGER PRIMARY KEY,
        account INTEGER NOT NULL,
        txid BLOB NOT NULL,
        height INTEGER NOT NULL,
        price REAL,
        category INTEGER,
        expiry_height INTEGER,
        UNIQUE (account, txid))",
    )
    .execute(&mut *connection)
    .await?;

    let _ = sqlx::query("ALTER TABLE pending_txs ADD COLUMN expiry_height INTEGER")
        .execute(&mut *connection)
        .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_spend_inputs (
        account INTEGER NOT NULL,
        nullifier BLOB NOT NULL,
        owner_txid BLOB NOT NULL,
        expiry_height INTEGER NOT NULL,
        PRIMARY KEY (account, nullifier))",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE VIEW IF NOT EXISTS active_pending_spend_inputs AS
        SELECT p.account, p.nullifier, p.owner_txid, p.expiry_height
        FROM pending_spend_inputs p
        WHERE p.expiry_height = 0
            OR p.expiry_height > COALESCE((
                SELECT MIN(s.height)
                FROM sync_heights s
                WHERE s.account = p.account
            ), 0)",
    )
    .execute(&mut *connection)
    .await?;

    // V9 — contacts
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS contacts (
        id_contact INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        notes TEXT NOT NULL DEFAULT '')",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS contact_addresses (
        id_address INTEGER PRIMARY KEY,
        contact_id INTEGER NOT NULL REFERENCES contacts(id_contact) ON DELETE CASCADE,
        address TEXT NOT NULL,
        receiver TEXT NOT NULL,
        pool INTEGER NOT NULL,
        ordinal INTEGER NOT NULL DEFAULT 0)",
    )
    .execute(&mut *connection)
    .await?;

    let _ = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_contact_receiver ON contact_addresses(receiver, pool)",
    )
    .execute(&mut *connection)
    .await;

    // Plugins
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS plugins(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            author TEXT,
            description TEXT,
            min_app_version TEXT NOT NULL,
            types TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            install_dir TEXT NOT NULL,
            script TEXT NOT NULL,
            manifest_json TEXT NOT NULL)",
    )
    .execute(&mut *connection)
    .await?;

    // V7
    let _ = sqlx::query("ALTER TABLE accounts ADD COLUMN hw INTEGER NOT NULL DEFAULT(0)")
        .execute(&mut *connection)
        .await;
    let _ = sqlx::query("ALTER TABLE dkg_params ADD COLUMN name TEXT NOT NULL DEFAULT('')")
        .execute(&mut *connection)
        .await;

    // V8 — signing key for FROST message authentication
    let _ = sqlx::query("ALTER TABLE dkg_state ADD COLUMN signing_keypair BLOB")
        .execute(&mut *connection)
        .await;

    // V9 — migrate dkg_packages into dkg_addresses / dkg_state / dkg_peers
    // dkg_packages round=0, public=1  → dkg_addresses
    sqlx::query(
        "INSERT OR IGNORE INTO dkg_addresses (account, from_id, address)
        SELECT account, from_id, CAST(data AS TEXT)
        FROM dkg_packages WHERE round = 0 AND public = 1",
    )
    .execute(&mut *connection)
    .await?;

    // dkg_packages round=1/2/3, public=0 → dkg_state columns
    // Insert a stub row for any account that has secrets, then fill each column.
    sqlx::query(
        "INSERT OR IGNORE INTO dkg_state (account)
        SELECT DISTINCT account FROM dkg_packages WHERE public = 0 AND round IN (1, 2, 3)",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "UPDATE dkg_state SET spkg1 = (
            SELECT data FROM dkg_packages
            WHERE dkg_packages.account = dkg_state.account AND round = 1 AND public = 0
        ) WHERE spkg1 IS NULL",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "UPDATE dkg_state SET spkg2 = (
            SELECT data FROM dkg_packages
            WHERE dkg_packages.account = dkg_state.account AND round = 2 AND public = 0
        ) WHERE spkg2 IS NULL",
    )
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "UPDATE dkg_state SET key_pkg = (
            SELECT data FROM dkg_packages
            WHERE dkg_packages.account = dkg_state.account AND round = 3 AND public = 0
        ) WHERE key_pkg IS NULL",
    )
    .execute(&mut *connection)
    .await?;

    // dkg_packages round=1/2/3, public=1 → dkg_peers
    sqlx::query(
        "INSERT OR IGNORE INTO dkg_peers (account, round, from_id, data)
        SELECT account, round, from_id, data
        FROM dkg_packages WHERE public = 1 AND round IN (1, 2, 3)",
    )
    .execute(&mut *connection)
    .await?;

    let version = get_prop(connection, "version").await?;
    match version {
        Some(version) if version.parse::<u16>()? > DB_VERSION => {
            anyhow::bail!("This app version only supports up to db version {DB_VERSION}");
        }
        _ => {
            put_prop(connection, "version", &DB_VERSION.to_string()).await?;
        }
    }

    // V10 — the bridge now always scans and spends on the Internal scope. Runs after the version
    // check so a database rejected as too new is left untouched.
    sqlx::query("UPDATE accounts SET use_internal = 1 WHERE use_internal <> 1")
        .execute(&mut *connection)
        .await?;

    Ok(())
}

async fn has_can_sign_column(connection: &mut SqliteConnection) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name = 'can_sign'",
    )
    .fetch_one(&mut *connection)
    .await?;

    Ok(count > 0)
}

/// One transaction: a column added without its backfill would leave every phrase account unable
/// to spend, and the existence check in [`create_schema`] would never retry it.
async fn migrate_can_sign(connection: &mut SqliteConnection) -> Result<()> {
    // `BEGIN IMMEDIATE` serializes concurrent openers; the loser then sees the winner's column
    // and skips an `ALTER TABLE` that would fail an otherwise valid wallet open.
    let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;
    if has_can_sign_column(&mut tx).await? {
        return Ok(());
    }
    sqlx::query("ALTER TABLE accounts ADD COLUMN can_sign INTEGER NOT NULL DEFAULT(0)")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE accounts SET can_sign = 1 WHERE seed_fingerprint IS NOT NULL")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(())
}

pub async fn migrate_sapling_addresses(
    network: &Network,
    connection: &mut SqliteConnection,
) -> Result<()> {
    let accounts: Vec<(u32, u32, Vec<u8>)> = sqlx::query_as(
        "SELECT id_account, dindex, xvk FROM accounts a
            JOIN sapling_accounts s ON a.id_account = s.account
            WHERE address = ''",
    )
    .fetch_all(&mut *connection)
    .await?;

    for (account, dindex, xvk) in accounts {
        let fvk: [u8; 128] = tiu!(xvk);
        let fvk = DiversifiableFullViewingKey::from_bytes(&fvk).unwrap();
        let address = fvk.address((dindex as u64).into()).unwrap();
        let address = address.encode(network);
        sqlx::query("UPDATE sapling_accounts SET address = ?2 WHERE account = ?1")
            .bind(account)
            .bind(&address)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

/// Resolve a Sapling diversifier index from raw diversifier bytes and the DFVK.
/// Returns None if the diversifier was not derived from this viewing key.
pub fn resolve_sapling_diversifier_index(
    dfvk: &DiversifiableFullViewingKey,
    scope: u8,
    diversifier: &[u8],
) -> Option<i64> {
    let d = sapling_crypto::keys::Diversifier(diversifier.try_into().ok()?);
    let address = dfvk.diversified_address_for_scope(scope, d)?;
    dfvk.decrypt_diversifier(&address)
        .and_then(|(di, _)| di.try_into().ok())
        .map(|d: u64| d as i64)
}

/// Resolve an Orchard diversifier index from raw diversifier bytes and the FVK.
/// Returns None if the diversifier was not derived from this viewing key.
pub fn resolve_orchard_diversifier_index(
    fvk: &FullViewingKey,
    scope: u8,
    diversifier: &[u8],
) -> Option<i64> {
    let d = orchard::keys::Diversifier::from_bytes(diversifier.try_into().ok()?);
    let scope = scope.orchard_scope();
    let address = fvk.address(d, scope);
    fvk.to_ivk(scope)
        .diversifier_index(&address)
        .and_then(|di| di.try_into().ok())
        .map(|d: u64| d as i64)
}

/// Pre-ECC databases stored spending keys; only viewing keys survive. Runs on every open.
pub async fn scrub_spending_keys(connection: &mut SqliteConnection) -> Result<()> {
    for statement in [
        "UPDATE transparent_accounts SET xsk = NULL",
        "UPDATE sapling_accounts SET xsk = NULL",
        "UPDATE orchard_accounts SET xsk = NULL",
        "UPDATE transparent_address_accounts SET sk = NULL",
    ] {
        sqlx::query(statement).execute(&mut *connection).await?;
    }

    Ok(())
}

pub async fn backfill_diversifier_index(connection: &mut SqliteConnection) -> Result<()> {
    // Skip if backfill was already completed
    if get_prop(connection, "backfilled_diversifier_index")
        .await?
        .is_some()
    {
        return Ok(());
    }

    // Check if any notes need backfilling
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM notes WHERE pool IN (1, 2) AND diversifier IS NOT NULL AND diversifier_index IS NULL",
    )
    .fetch_one(&mut *connection)
    .await?;

    if count.0 == 0 {
        // Nothing to backfill, mark as done
        put_prop(connection, "backfilled_diversifier_index", "1").await?;
        return Ok(());
    }

    debug!("Backfilling diversifier_index for {} notes", count.0);

    // Fetch distinct accounts with unbackfilled notes
    let accounts: Vec<(u32,)> = sqlx::query_as(
        "SELECT DISTINCT account FROM notes WHERE pool IN (1, 2) AND diversifier IS NOT NULL AND diversifier_index IS NULL",
    )
    .fetch_all(&mut *connection)
    .await?;

    for (account,) in accounts {
        // Load Sapling DFVK for this account
        let sapling_dfvk: Option<DiversifiableFullViewingKey> =
            sqlx::query_as("SELECT xvk FROM sapling_accounts WHERE account = ?")
                .bind(account)
                .fetch_optional(&mut *connection)
                .await?
                .map(|(xvk,): (Vec<u8>,)| {
                    DiversifiableFullViewingKey::from_bytes(&xvk.try_into().unwrap()).unwrap()
                });

        // Load Orchard FVK for this account
        let orchard_fvk: Option<FullViewingKey> =
            sqlx::query_as("SELECT xvk FROM orchard_accounts WHERE account = ?")
                .bind(account)
                .fetch_optional(&mut *connection)
                .await?
                .map(|(xvk,): (Vec<u8>,)| {
                    FullViewingKey::from_bytes(&xvk.try_into().unwrap()).unwrap()
                });

        // Fetch unbackfilled notes for this account
        let notes: Vec<(u32, u8, u8, Vec<u8>)> = sqlx::query_as(
            "SELECT id_note, pool, scope, diversifier FROM notes WHERE account = ? AND pool IN (1, 2) AND diversifier IS NOT NULL AND diversifier_index IS NULL",
        )
        .bind(account)
        .fetch_all(&mut *connection)
        .await?;

        for (id_note, pool, scope, diversifier) in notes {
            let di: Option<i64> = match pool {
                1 => sapling_dfvk
                    .as_ref()
                    .and_then(|dfvk| resolve_sapling_diversifier_index(dfvk, scope, &diversifier)),
                2 => orchard_fvk
                    .as_ref()
                    .and_then(|fvk| resolve_orchard_diversifier_index(fvk, scope, &diversifier)),
                _ => None,
            };

            if let Some(di) = di {
                sqlx::query("UPDATE notes SET diversifier_index = ? WHERE id_note = ?")
                    .bind(di)
                    .bind(id_note)
                    .execute(&mut *connection)
                    .await?;
            }
        }
    }

    debug!("Backfill diversifier_index complete");
    put_prop(connection, "backfilled_diversifier_index", "1").await?;
    Ok(())
}

pub async fn put_prop(connection: &mut SqliteConnection, key: &str, value: &str) -> Result<()> {
    sqlx::query("INSERT OR REPLACE INTO props(key, value) VALUES (?, ?)")
        .bind(key)
        .bind(value)
        .execute(&mut *connection)
        .await?;

    Ok(())
}

pub async fn get_prop(connection: &mut SqliteConnection, key: &str) -> Result<Option<String>> {
    let value: Option<(String,)> = sqlx::query_as("SELECT value FROM props WHERE key = ?")
        .bind(key)
        .fetch_optional(&mut *connection)
        .await?;

    Ok(value.map(|v| v.0))
}

pub async fn delete_prop_prefix(connection: &mut SqliteConnection, prefix: &str) -> Result<()> {
    sqlx::query("DELETE FROM props WHERE key LIKE ?")
        .bind(format!("{prefix}%"))
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub async fn store_account_metadata(
    connection: &mut SqliteConnection,
    name: &str,
    icon: &Option<Vec<u8>>,
    fingerprint: &Option<Vec<u8>>,
    birth: u32,
    use_internal: bool,
    internal: bool,
    can_sign: bool,
) -> Result<u32> {
    let (last_position,): (u32,) = sqlx::query_as("SELECT MAX(position) FROM accounts")
        .fetch_optional(&mut *connection)
        .await?
        .unwrap_or_default();

    let (id,): (u32,) = sqlx::query_as(
        "INSERT INTO accounts(name, icon, seed_fingerprint, birth,
        aindex, dindex, def_dindex, position, use_internal, saved, hidden, internal, can_sign)
        VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?, FALSE, FALSE, ?, ?)
        ON CONFLICT(id_account) DO UPDATE SET
            name = excluded.name
        RETURNING id_account",
    )
    .bind(name)
    .bind(icon)
    .bind(fingerprint)
    .bind(birth)
    .bind(last_position + 1)
    .bind(use_internal)
    .bind(internal)
    .bind(can_sign)
    .fetch_one(&mut *connection)
    .await?;

    Ok(id)
}

pub async fn store_block_header(
    connection: &mut SqliteConnection,
    block_header: &BlockHeader,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO headers (height, hash, time)
                    VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(block_header.height)
    .bind(&block_header.hash)
    .bind(block_header.time)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

pub async fn store_synced_height(
    connection: &mut SqliteConnection,
    account: u32,
    pool: u8,
    height: u32,
) -> Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO sync_heights(account, pool, height)
        VALUES (?, ?, ?)",
    )
    .bind(account)
    .bind(pool)
    .bind(height)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

pub async fn store_account_seed_fingerprint(
    connection: &mut SqliteConnection,
    account: u32,
    fingerprint: &[u8],
    aindex: u32,
) -> Result<()> {
    sqlx::query(
        "UPDATE accounts
         SET seed_fingerprint = ?,
             aindex = ?
         WHERE id_account = ?",
    )
    .bind(fingerprint)
    .bind(aindex)
    .bind(account)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

pub async fn init_account_transparent(
    connection: &mut SqliteConnection,
    account: u32,
    birth: u32,
) -> Result<()> {
    sqlx::query("INSERT INTO transparent_accounts(account) VALUES (?)")
        .bind(account)
        .execute(&mut *connection)
        .await?;
    store_synced_height(connection, account, 0, birth).await?;

    Ok(())
}

pub const LEDGER_CODE: u32 = 1;

pub async fn store_account_hw(
    connection: &mut SqliteConnection,
    account: u32,
    hw_code: u32,
    aindex: u32,
) -> Result<()> {
    sqlx::query("UPDATE accounts SET hw = ?2, aindex = ?3 WHERE id_account = ?1")
        .bind(account)
        .bind(hw_code)
        .bind(aindex)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn store_account_transparent_vk(
    connection: &mut SqliteConnection,
    account: u32,
    xvk: &AccountPubKey,
) -> Result<()> {
    sqlx::query(
        "UPDATE transparent_accounts
        SET xvk = ? WHERE account = ?",
    )
    .bind(xvk.serialize())
    .bind(account)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

pub async fn store_account_transparent_addr(
    connection: &mut SqliteConnection,
    account: u32,
    scope: u32,
    dindex: u32,
    sk: Option<Vec<u8>>,
    pk: &[u8],
    address: &str,
    uncompressed: bool,
) -> Result<bool> {
    let r = sqlx::query(
        "INSERT INTO transparent_address_accounts(account, scope, dindex, sk, pk, address, uncompressed)
        VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(account)
    .bind(scope)
    .bind(dindex)
    .bind(sk)
    .bind(pk)
    .bind(address)
    .bind(uncompressed)
    .execute(&mut *connection)
    .await?;

    Ok(r.rows_affected() > 0)
}

pub async fn init_account_sapling(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    birth: u32,
) -> Result<()> {
    sqlx::query("INSERT INTO sapling_accounts(account, xvk) VALUES (?, '')")
        .bind(account)
        .execute(&mut *connection)
        .await?;
    let activation_height: u32 = network
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap()
        .into();
    store_synced_height(connection, account, 1, birth.max(activation_height)).await?;

    Ok(())
}

pub async fn store_account_sapling_vk(
    connection: &mut SqliteConnection,
    account: u32,
    xvk: &DiversifiableFullViewingKey,
    address: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE sapling_accounts
        SET xvk = ?2, address = ?3 WHERE account = ?1",
    )
    .bind(account)
    .bind(xvk.to_bytes().as_slice())
    .bind(address)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

pub async fn init_account_orchard(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    birth: u32,
) -> Result<()> {
    sqlx::query("INSERT INTO orchard_accounts(account, xvk) VALUES (?, '')")
        .bind(account)
        .execute(&mut *connection)
        .await?;
    let activation_height = network
        .activation_height(NetworkUpgrade::Nu5)
        .unwrap()
        .into();
    store_synced_height(connection, account, 2, birth.max(activation_height)).await?;

    Ok(())
}

pub async fn store_account_orchard_vk(
    connection: &mut SqliteConnection,
    account: u32,
    xvk: &orchard::keys::FullViewingKey,
) -> Result<()> {
    sqlx::query(
        "UPDATE orchard_accounts
        SET xvk = ? WHERE account = ?",
    )
    .bind(xvk.to_bytes().as_slice())
    .bind(account)
    .execute(&mut *connection)
    .await?;

    Ok(())
}

pub async fn update_dindex(
    connection: &mut SqliteConnection,
    account: u32,
    dindex: u32,
    update_default: bool,
) -> Result<()> {
    sqlx::query("UPDATE accounts SET dindex = ? WHERE id_account = ?")
        .bind(dindex)
        .bind(account)
        .execute(&mut *connection)
        .await?;
    if update_default {
        sqlx::query("UPDATE accounts SET def_dindex = ? WHERE id_account = ?")
            .bind(dindex)
            .bind(account)
            .execute(&mut *connection)
            .await?;
    }

    Ok(())
}

pub async fn select_account_transparent(
    connection: &mut SqliteConnection,
    account: u32,
    dindex: u32,
) -> Result<TransparentKeys> {
    #[allow(clippy::type_complexity)]
    let r: Option<(Option<Vec<u8>>, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT xsk, xvk FROM transparent_accounts WHERE account = ?")
            .bind(account)
            .fetch_optional(&mut *connection)
            .await?;

    let (xsk, xvk, taddress) = match r {
        Some((None, None)) => {
            // no xprv, no xpub => get the address imported as bip38
            let taddress =
                sqlx::query("SELECT address FROM transparent_address_accounts WHERE account = ?1 AND dindex = ?2 AND scope = 0")
                    .bind(account)
                    .bind(dindex)
                    .map(|row: SqliteRow| row.get::<String, _>(0))
                    .fetch_optional(&mut *connection)
                    .await?;
            (None, None, taddress)
        }
        Some((xsk, xvk)) => (xsk, xvk, None),
        None => (None, None, None),
    };

    let keys = TransparentKeys {
        xsk: xsk.map(|xsk| AccountPrivKey::from_bytes(&xsk).unwrap()),
        xvk: xvk.map(|xvk| AccountPubKey::deserialize(&xvk.try_into().unwrap()).unwrap()),
        address: taddress,
    };

    Ok(keys)
}

pub async fn select_account_sapling(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<SaplingKeys> {
    let r: Option<(Option<Vec<u8>>, Vec<u8>, String)> =
        sqlx::query_as("SELECT xsk, xvk, address FROM sapling_accounts WHERE account = ?")
            .bind(account)
            .fetch_optional(&mut *connection)
            .await?;

    let (xsk, xvk, address) = match r {
        Some((xsk, xvk, address)) => (xsk, Some(xvk), Some(address)),
        None => (None, None, None),
    };

    let keys = SaplingKeys {
        xsk: xsk.map(|xsk| {
            ExtendedSpendingKey::from_bytes(&xsk)
                .map_err(|_| anyhow!("Invalid sdk"))
                .unwrap()
        }),
        xvk: xvk
            .map(|xvk| DiversifiableFullViewingKey::from_bytes(&xvk.try_into().unwrap()).unwrap()),
        address: address.map(|a| PaymentAddress::decode(network, &a).unwrap()),
    };

    Ok(keys)
}

pub async fn select_account_orchard(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<OrchardKeys> {
    let r: Option<(Option<Vec<u8>>, Vec<u8>)> =
        sqlx::query_as("SELECT xsk, xvk FROM orchard_accounts WHERE account = ?")
            .bind(account)
            .fetch_optional(&mut *connection)
            .await?;

    let (xsk, xvk) = match r {
        Some((xsk, xvk)) => (xsk, Some(xvk)),
        None => (None, None),
    };

    let keys = OrchardKeys {
        xsk: xsk.map(|xsk| SpendingKey::from_bytes(xsk.try_into().unwrap()).unwrap()),
        xvk: xvk.map(|xvk| FullViewingKey::from_bytes(&xvk.try_into().unwrap()).unwrap()),
    };

    Ok(keys)
}

pub struct TransparentKeys {
    pub xsk: Option<AccountPrivKey>,
    pub xvk: Option<AccountPubKey>,
    pub address: Option<String>,
}

pub struct SaplingKeys {
    pub xsk: Option<ExtendedSpendingKey>,
    pub xvk: Option<DiversifiableFullViewingKey>,
    pub address: Option<PaymentAddress>,
}

pub struct OrchardKeys {
    pub xsk: Option<SpendingKey>,
    pub xvk: Option<FullViewingKey>,
}

pub async fn list_accounts(connection: &mut SqliteConnection, coin: u8) -> Result<Vec<Account>> {
    let mut rows = sqlx::query(
        "WITH sh AS (SELECT account, MIN(height) AS height FROM sync_heights GROUP BY account),
        unspent AS (SELECT a.*
                FROM notes a
                LEFT JOIN spends b ON a.id_note = b.id_note
                WHERE b.id_note IS NULL AND a.id_asset IS NULL)
        SELECT id_account, a.name, seed, passphrase, aindex, dindex,
        icon, birth, use_internal, a.position, hidden, saved, enabled, internal,
        sh.height, COALESCE(hdr.time, 0), COALESCE(SUM(unspent.value), 0) AS balance,
        COALESCE(f.id_folder, 0), COALESCE(f.name, '') AS folder_name,
        hw
        FROM accounts a
        JOIN sh ON a.id_account = sh.account
        LEFT JOIN headers hdr ON sh.height = hdr.height
        LEFT JOIN unspent ON a.id_account = unspent.account
        LEFT JOIN folders f ON a.folder = f.id_folder
        GROUP BY id_account
        ORDER by a.position",
    )
    .map(|row: SqliteRow| {
        let folder = Folder {
            id: row.get(17),
            name: row.get(18),
        };
        Account {
            coin,
            id: row.get(0),
            name: row.get(1),
            seed: row.get(2),
            passphrase: row.get(3),
            aindex: row.get(4),
            dindex: row.get(5),
            icon: row.get(6),
            birth: row.get(7),
            use_internal: row.get(8),
            position: row.get(9),
            hidden: row.get(10),
            saved: row.get(11),
            enabled: row.get(12),
            internal: row.get(13),
            height: row.get(14),
            time: row.get(15),
            balance: row.get::<i64, _>(16) as u64,
            folder,
            hw: row.get::<u8, _>(19),
        }
    })
    .fetch(&mut *connection);

    let mut accounts = vec![];
    while let Some(row) = rows.try_next().await? {
        accounts.push(row);
    }

    Ok(accounts)
}

pub async fn get_account_fingerprint(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<Vec<u8>>> {
    let (fingerprint,): (Option<Vec<u8>>,) =
        sqlx::query_as("SELECT seed_fingerprint FROM accounts WHERE id_account = ?")
            .bind(account)
            .fetch_one(&mut *connection)
            .await?;

    Ok(fingerprint)
}

pub async fn get_account_can_sign(connection: &mut SqliteConnection, account: u32) -> Result<bool> {
    let (can_sign,): (bool,) = sqlx::query_as("SELECT can_sign FROM accounts WHERE id_account = ?")
        .bind(account)
        .fetch_one(&mut *connection)
        .await?;

    Ok(can_sign)
}

pub async fn delete_account(connection: &mut SqliteConnection, account: u32) -> Result<()> {
    let mut tx = connection.begin().await?;

    sqlx::query("DELETE FROM pending_spend_inputs WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM pending_txs WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM dkg_params WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM dkg_packages WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM dkg_addresses WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM dkg_state WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM dkg_peers WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM frost_signatures WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM frost_commitments WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM outputs WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM memos WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM witnesses WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM notes WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM spends WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM transactions WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sync_heights WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM transparent_accounts WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM transparent_address_accounts WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sapling_accounts WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM orchard_accounts WHERE account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM accounts WHERE id_account = ?")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(())
}

pub async fn reorder_account(
    connection: &mut SqliteConnection,
    old_position: u32,
    new_position: u32,
) -> Result<()> {
    debug!(
        "Reordering account from {} to {}",
        old_position, new_position
    );
    let mut tx = connection.begin().await?;
    let (id,): (u32,) = sqlx::query_as("SELECT id_account FROM accounts WHERE position = ?")
        .bind(old_position)
        .fetch_one(&mut *tx)
        .await?;
    if old_position < new_position {
        sqlx::query(
            "UPDATE accounts
            SET position = position - 1
            WHERE position > ? AND position <= ?",
        )
        .bind(old_position)
        .bind(new_position)
        .execute(&mut *tx)
        .await?;
    }
    if old_position > new_position {
        sqlx::query(
            "UPDATE accounts
            SET position = position + 1
            WHERE position >= ? AND position < ?",
        )
        .bind(new_position)
        .bind(old_position)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE accounts
        SET position = ?
        WHERE id_account = ?",
    )
    .bind(new_position)
    .bind(id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

pub async fn get_sync_height(conn: &mut SqliteConnection, account: u32) -> Result<Option<u32>> {
    let (h,): (Option<u32>,) = sqlx::query_as(
        "SELECT MIN(height) FROM sync_heights
    WHERE account = ?1",
    )
    .bind(account)
    .fetch_one(conn)
    .await?;
    Ok(h)
}

/// Every unspent ZEC note the account owns, joined to its pending-spend reservation.
/// `?1` is the account.
const OWNED_UNSPENT_ZEC_NOTES: &str = "FROM notes n
        LEFT JOIN spends s ON s.id_note = n.id_note
        LEFT JOIN active_pending_spend_inputs p
            ON p.account = n.account
            AND p.nullifier = n.nullifier
        WHERE n.account = ?1 AND n.id_asset IS NULL AND s.id_note IS NULL";

/// A note counts as available only when confirmed against `?2`, unlocked and unreserved.
const AVAILABLE_NOTE: &str = "n.height <= ?2 AND NOT n.locked AND p.nullifier IS NULL";

pub async fn confirmed_height(
    connection: &mut SqliteConnection,
    account: u32,
    confirmations: u32,
) -> Result<u32> {
    Ok(get_sync_height(connection, account)
        .await?
        .unwrap_or_default()
        .saturating_sub(confirmations))
}

pub async fn calculate_balance(
    pool: &mut SqliteConnection,
    account: u32,
    height: Option<u32>,
) -> Result<PoolBalance> {
    let mut balance = PoolBalance(vec![0, 0, 0, 0]);
    let height = height.unwrap_or(u32::MAX);

    let mut rows = sqlx::query("
    WITH N AS (SELECT value, pool, height FROM notes WHERE account = ?1 AND id_asset IS NULL UNION ALL SELECT s.value, s.pool, s.height FROM spends s JOIN notes n ON s.id_note = n.id_note WHERE s.account = ?1 AND n.id_asset IS NULL)
    SELECT pool, SUM(value) FROM N WHERE height <= ?2 GROUP BY pool")
        .bind(account)
        .bind(height)
        .map(|row: SqliteRow| (row.get::<u8, _>(0), row.get::<i64, _>(1)))
        .fetch(pool);
    while let Some((pool, value)) = rows.try_next().await? {
        balance.0[pool as usize] += value as u64;
    }

    Ok(balance)
}

/// Splits each pool's unspent notes into spendable and still-maturing value.
///
/// The cutoff is the locally scanned height minus `confirmations`, matching what
/// `plan_transaction` will accept as an input. Pending value is split by note scope:
/// internal notes are change coming back, external ones are incoming payments.
pub async fn calculate_balance_breakdown(
    connection: &mut SqliteConnection,
    account: u32,
    confirmations: u32,
) -> Result<PoolBalanceBreakdown> {
    let confirmed_height = confirmed_height(&mut *connection, account, confirmations).await?;

    let mut balance = PoolBalanceBreakdown(vec![Balance::default(); NUM_POOLS]);
    let query = format!(
        "SELECT n.pool,
            SUM(CASE WHEN {AVAILABLE_NOTE} THEN n.value ELSE 0 END),
            SUM(CASE WHEN n.height <= ?2 AND (n.locked OR p.nullifier IS NOT NULL) THEN n.value ELSE 0 END),
            SUM(CASE WHEN n.height > ?2 AND n.scope = 1 THEN n.value ELSE 0 END),
            SUM(CASE WHEN n.height > ?2 AND (n.scope IS NULL OR n.scope <> 1) THEN n.value ELSE 0 END)
        {OWNED_UNSPENT_ZEC_NOTES}
        GROUP BY n.pool"
    );
    let mut rows = sqlx::query(&query)
        .bind(account)
        .bind(confirmed_height)
        .map(|row: SqliteRow| {
            (
                row.get::<u8, _>(0),
                row.get::<i64, _>(1),
                row.get::<i64, _>(2),
                row.get::<i64, _>(3),
                row.get::<i64, _>(4),
            )
        })
        .fetch(connection);
    while let Some((pool, available, locked, change_pending, value_pending)) =
        rows.try_next().await?
    {
        balance.0[pool as usize] = Balance {
            available: available as u64,
            locked: locked as u64,
            change_pending: change_pending as u64,
            value_pending: value_pending as u64,
        };
    }

    Ok(balance)
}

pub async fn fetch_txs(connection: &mut SqliteConnection, account: u32) -> Result<Vec<Tx>> {
    // union notes and spends, then sum value by tx into v to get tx value
    // join transactions with v by id_tx and filter by account
    // order by height desc to get latest transactions first
    tracing::debug!("fetch_txs: starting for account {}", account);
    let transactions = sqlx::query(
        "SELECT t.id_tx, t.txid, t.height, t.time, t.value, t.tpe, c.name, t.zsa_value, t.price, t.asset_id,
            a.asset_name, a.asset_desc_hash,
            COALESCE(NULLIF(um.user_memo, ''), (SELECT m.memo_text FROM memos m
                WHERE m.account = t.account AND m.tx = t.id_tx AND m.memo_text IS NOT NULL
                ORDER BY m.pool, m.vout LIMIT 1)) as memo,
            (um.user_memo IS NOT NULL AND um.user_memo != '') as is_user_memo,
            oc.contact_name,
            t.fee,
            (SELECT COALESCE(SUM(n.value), 0) FROM notes n
                WHERE n.account = t.account AND n.tx = t.id_tx AND n.id_asset IS NULL) as total_received,
            (SELECT COUNT(*) FROM notes n
                WHERE n.account = t.account AND n.tx = t.id_tx AND n.id_asset IS NULL) as received_count,
            (SELECT COUNT(*) FROM notes n
                WHERE n.account = t.account AND n.tx = t.id_tx AND n.id_asset IS NULL AND n.scope = 1) as change_count,
            (SELECT o.address FROM outputs o
                WHERE o.account = t.account AND o.tx = t.id_tx AND NOT EXISTS (
                    SELECT 1 FROM notes n
                    WHERE n.account = o.account AND n.tx = o.tx AND n.pool = o.pool AND n.value = o.value)
                ORDER BY o.value DESC LIMIT 1) as recipient
            FROM transactions t
            LEFT JOIN categories c ON c.id_category = t.category
            LEFT JOIN assets a ON t.asset_id = a.id_asset
            LEFT JOIN user_memos um ON um.id_tx = t.id_tx AND um.account = t.account
            LEFT JOIN (
                SELECT DISTINCT o.tx, ct.name as contact_name
                FROM outputs o
                JOIN contact_addresses ca ON o.address = ca.receiver AND o.pool = ca.pool
                JOIN contacts ct ON ca.contact_id = ct.id_contact
            ) oc ON oc.tx = t.id_tx
            WHERE t.account = ?
            ORDER BY t.height DESC",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let id: u32 = row.get(0);
        let txid: Vec<u8> = row.get(1);
        let height: u32 = row.get(2);
        let time: u32 = row.get(3);
        let value: i64 = row.get(4);
        let tpe: Option<u8> = row.get(5);
        let category: Option<String> = row.get(6);
        let zsa_value: i64 = row.get(7);
        let price: Option<f64> = row.get(8);
        let asset_id: Option<i32> = row.get(9);
        let asset_name: Option<String> = row.get(10);
        let asset_desc_hash: Option<Vec<u8>> = row.get(11);
        let memo: Option<String> = row.get(12);
        let is_user_memo: bool = row.get(13);
        let contact_name: Option<String> = row.get(14);
        let fee: i64 = row.get(15);
        let total_received: i64 = row.get(16);
        let received_count: i64 = row.get(17);
        let change_count: i64 = row.get(18);
        let recipient: Option<String> = row.get(19);
        Tx {
            id,
            txid,
            height,
            time,
            value,
            tpe,
            category,
            zsa_value,
            asset_id,
            asset_display: crate::account::asset_display(
                asset_id,
                asset_name,
                asset_desc_hash,
            ),
            price,
            memo,
            is_user_memo,
            contact_name,
            fee: fee as u64,
            total_received: total_received as u64,
            is_change: received_count > 0 && received_count == change_count,
            recipient,
        }
    })
    .fetch_all(&mut *connection)
    .await?;
    tracing::debug!("fetch_txs: completed with {} txs", transactions.len());
    Ok(transactions)
}

pub async fn get_memos(pool: &mut SqliteConnection, account: u32) -> Result<Vec<Memo>> {
    let memos = sqlx::query(
        "SELECT COALESCE(m.id_memo, 0) as id_memo,
            t.height,
            t.id_tx as tx,
            COALESCE(m.pool, 0) as pool,
            COALESCE(m.vout, 0) as vout,
            COALESCE(m.note, CASE WHEN t.value + t.fee >= 0 THEN 0 ELSE NULL END) as note,
            t.time,
            COALESCE(NULLIF(um.user_memo, ''), m.memo_text) as memo_text,
            COALESCE(m.memo_bytes, X'') as memo_bytes,
            (um.user_memo IS NOT NULL AND um.user_memo != '') as is_user_memo
        FROM transactions t
        LEFT JOIN memos m ON m.tx = t.id_tx AND m.account = t.account
        LEFT JOIN user_memos um ON um.id_tx = t.id_tx AND um.account = t.account
        WHERE t.account = ?
          AND (m.id_memo IS NOT NULL OR (um.user_memo IS NOT NULL AND um.user_memo != ''))
        ORDER BY t.height DESC",
    )
    .bind(account)
    .map(row_to_memo)
    .fetch_all(pool)
    .await?;

    Ok(memos)
}

pub async fn get_memos_txid(
    pool: &mut SqliteConnection,
    account: u32,
    txid: &[u8],
) -> Result<Vec<Memo>> {
    let memos = sqlx::query(
        "SELECT COALESCE(m.id_memo, 0) as id_memo,
            t.height,
            t.id_tx as tx,
            COALESCE(m.pool, 0) as pool,
            COALESCE(m.vout, 0) as vout,
            COALESCE(m.note, CASE WHEN t.value + t.fee >= 0 THEN 0 ELSE NULL END) as note,
            t.time,
            COALESCE(NULLIF(um.user_memo, ''), m.memo_text) as memo_text,
            COALESCE(m.memo_bytes, X'') as memo_bytes,
            (um.user_memo IS NOT NULL AND um.user_memo != '') as is_user_memo
        FROM transactions t
        LEFT JOIN memos m ON m.tx = t.id_tx AND m.account = t.account
        LEFT JOIN user_memos um ON um.id_tx = t.id_tx AND um.account = t.account
        WHERE t.account = ?1 AND t.txid = ?2",
    )
    .bind(account)
    .bind(txid)
    .map(row_to_memo)
    .fetch_all(pool)
    .await?;

    Ok(memos)
}

fn row_to_memo(row: SqliteRow) -> Memo {
    let id: u32 = row.get(0);
    let height: u32 = row.get(1);
    let tx: u32 = row.get(2);
    let pool: u8 = row.get(3);
    let vout: u32 = row.get(4);
    let note: Option<u32> = row.get(5);
    let time: u32 = row.get(6);
    let memo_text: Option<String> = row.get(7);
    let memo_bytes: Vec<u8> = row.get(8);
    let is_user_memo: bool = row.get(9);
    Memo {
        id,
        id_tx: tx,
        id_note: note,
        height,
        pool,
        vout,
        time,
        memo: memo_text,
        memo_bytes,
        is_user_memo,
    }
}

pub async fn get_account_aindex(connection: &mut SqliteConnection, account: u32) -> Result<u32> {
    let (dindex,): (u32,) = sqlx::query_as("SELECT aindex FROM accounts WHERE id_account = ?")
        .bind(account)
        .fetch_one(&mut *connection)
        .await?;
    Ok(dindex)
}

pub async fn get_account_dindex(connection: &mut SqliteConnection, account: u32) -> Result<u32> {
    let (dindex,): (u32,) = sqlx::query_as("SELECT dindex FROM accounts WHERE id_account = ?")
        .bind(account)
        .fetch_one(&mut *connection)
        .await?;
    Ok(dindex)
}

pub async fn get_account_hw(connection: &mut SqliteConnection, account: u32) -> Result<u8> {
    let (hw,): (u8,) = sqlx::query_as("SELECT hw FROM accounts WHERE id_account = ?")
        .bind(account)
        .fetch_one(&mut *connection)
        .await?;
    Ok(hw)
}

pub async fn get_notes(connection: &mut SqliteConnection, account: u32) -> Result<Vec<TxNote>> {
    let notes = sqlx::query(
        "SELECT n.id_note, n.height, n.pool, n.tx, n.scope, n.diversifier, n.diversifier_index, n.value, n.locked,
        m.memo_text, n.id_asset, a.asset_name, a.asset_desc_hash
        FROM notes n LEFT JOIN spends s
	    ON n.id_note = s.id_note
        LEFT JOIN memos m ON n.id_note = m.note
        LEFT JOIN assets a ON n.id_asset = a.id_asset
	    WHERE n.account = ? AND s.id_note IS NULL ORDER BY n.height DESC",
    )
    .bind(account)
    .map(row_to_note)
    .fetch_all(&mut *connection)
    .await?;

    Ok(notes)
}

pub async fn get_notes_txid(
    connection: &mut SqliteConnection,
    account: u32,
    txid: &[u8],
) -> Result<Vec<TxNote>> {
    // Return all notes for a given transaction
    // including the ones that may be spent
    let notes = sqlx::query(
        "SELECT n.id_note, n.height, n.pool, n.tx, n.scope, n.diversifier, n.diversifier_index, n.value, n.locked,
        m.memo_text, n.id_asset, a.asset_name, a.asset_desc_hash
       FROM notes n
       JOIN transactions t ON n.tx = t.id_tx
       LEFT JOIN memos m ON n.id_note = m.note
       LEFT JOIN assets a ON n.id_asset = a.id_asset
	   WHERE n.account = ?1
       AND t.txid = ?2",
    )
    .bind(account)
    .bind(txid)
    .map(row_to_note)
    .fetch_all(&mut *connection)
    .await?;

    Ok(notes)
}

fn row_to_note(row: SqliteRow) -> TxNote {
    let id_note: u32 = row.get(0);
    let height: u32 = row.get(1);
    let pool: u8 = row.get(2);
    let tx: u32 = row.get(3);
    let scope: u8 = row.get(4);
    let diversifier: Option<Vec<u8>> = row.get(5);
    let diversifier_index: Option<i64> = row.get(6);
    let value: u64 = row.get(7);
    let locked: bool = row.get(8);
    let memo: Option<String> = row.get(9);
    let id_asset: Option<i64> = row.get(10);
    let asset_name: Option<String> = row.get(11);
    let asset_desc_hash: Option<Vec<u8>> = row.get(12);

    TxNote {
        id: id_note,
        height,
        pool,
        tx,
        scope,
        diversifier,
        diversifier_index,
        value,
        locked,
        id_asset: id_asset.map(|v| v as u32),
        memo,
        asset_display: crate::account::asset_display(
            id_asset.map(|v| v as i32),
            asset_name,
            asset_desc_hash,
        ),
    }
}

pub async fn lock_note(
    connection: &mut SqliteConnection,
    account: u32,
    id: u32,
    locked: bool,
) -> Result<()> {
    sqlx::query("UPDATE notes SET locked = ? WHERE account = ? AND id_note = ?")
        .bind(locked)
        .bind(account)
        .bind(id)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// Raw row from the assets table joined with unspent note balances.
#[derive(Clone, Debug)]
pub struct ZsaAssetRow {
    pub id_asset: i64,
    pub asset_desc_hash: Vec<u8>,
    pub asset_name: Option<String>,
    pub ik: Vec<u8>,
    pub asset_base: Vec<u8>,
    pub finalized: bool,
    pub first_seen_height: i32,
    pub balance: i64,
}

pub async fn get_zsa_holdings(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Vec<ZsaAssetRow>> {
    let holdings = sqlx::query(
        "SELECT a.id_asset, a.asset_desc_hash, a.asset_name, a.ik, a.asset_base,
                a.finalized, a.first_seen_height,
                COALESCE(SUM(n.value), 0) AS balance
         FROM assets a
         LEFT JOIN notes n ON n.id_asset = a.id_asset
           AND n.account = ?1
           AND n.id_note NOT IN (SELECT id_note FROM spends)
           AND n.locked = 0
         GROUP BY a.id_asset
         HAVING balance > 0
         ORDER BY a.asset_name, a.asset_desc_hash",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let id_asset: i64 = row.get(0);
        let asset_desc_hash: Vec<u8> = row.get(1);
        let asset_name: Option<String> = row.get(2);
        let ik: Vec<u8> = row.get(3);
        let asset_base: Vec<u8> = row.get(4);
        let finalized: bool = row.get(5);
        let first_seen_height: i32 = row.get(6);
        let balance: i64 = row.get(7);
        ZsaAssetRow {
            id_asset,
            asset_desc_hash,
            asset_name,
            ik,
            asset_base,
            finalized,
            first_seen_height,
            balance,
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    Ok(holdings)
}

/// Unspent value at one transparent address of `account`, in zatoshi.
///
/// Reads only the local database, so it is exactly as fresh as the last sync.
pub async fn transparent_address_balance(
    connection: &mut SqliteConnection,
    account: u32,
    address: &str,
) -> Result<u64> {
    let balance: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(n.value), 0) FROM notes n
        JOIN transparent_address_accounts ta ON ta.id_taddress = n.taddress
        LEFT JOIN spends s ON s.id_note = n.id_note
        WHERE n.account = ?1 AND n.pool = 0 AND n.id_asset IS NULL
            AND s.id_note IS NULL AND ta.address = ?2",
    )
    .bind(account)
    .bind(address)
    .fetch_one(&mut *connection)
    .await?;

    Ok(balance.max(0) as u64)
}

/// The account's own default address first, then every other receive address, then the newest
/// `limit` change addresses. Receive addresses are handed to payers and can be paid at any later
/// time, so none of them may fall out of the scan set; change addresses only appear on a spend.
/// The final `ORDER BY` is what fixes the scan order — a bare `UNION ALL` promises none.
pub async fn transparent_addresses_to_scan(
    connection: &mut SqliteConnection,
    account: u32,
    limit: u32,
) -> Result<Vec<(u32, String)>> {
    let addresses = sqlx::query(
        "WITH change AS
        (SELECT * FROM transparent_address_accounts WHERE account = ?1 AND scope = 1 ORDER BY dindex DESC LIMIT ?2)
        SELECT ta.id_taddress, ta.address,
            CASE WHEN ta.dindex = a.dindex THEN 0 ELSE 1 END AS scan_order, ta.dindex
        FROM transparent_address_accounts ta
            LEFT JOIN accounts a ON a.id_account = ta.account
        WHERE ta.account = ?1 AND ta.scope = 0
        UNION ALL SELECT id_taddress, address, 2, dindex FROM change
        ORDER BY scan_order, dindex DESC",
    )
    .bind(account)
    .bind(limit)
    .map(|row: SqliteRow| {
        let id_taddress: u32 = row.get(0);
        let address: String = row.get(1);
        (id_taddress, address)
    })
    .fetch_all(&mut *connection)
    .await?;

    Ok(addresses)
}

pub async fn fetch_transparent_address_tx_count(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Vec<TAddressTxCount>> {
    let rows = sqlx::query(
        "WITH n AS (
        SELECT account, tx, value, taddress FROM notes n WHERE n.pool = 0 UNION ALL
        SELECT n.account, s.tx, s.value, n.taddress FROM spends s JOIN notes n ON s.id_note = n.id_note AND s.account = n.account WHERE s.pool = 0)
        SELECT address, scope, dindex, SUM(n.value), COUNT(tx), MAX(t.time) FROM n
        JOIN transparent_address_accounts ta ON ta.id_taddress = taddress
        JOIN transactions t ON t.id_tx = n.tx
        WHERE n.account = ?
        GROUP BY taddress
        ORDER BY ta.scope, ta.dindex",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let address: String = row.get(0);
        let scope: u8 = row.get(1);
        let dindex: u32 = row.get(2);
        let amount: u64 = row.get(3);
        let tx_count: u32 = row.get(4);
        let time: u32 = row.get(5);
        TAddressTxCount {
            pool: 0,
            address,
            scope,
            dindex,
            amount,
            tx_count,
            time,
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    Ok(rows)
}

/// Raw tx stats for a transparent address slot, keyed by (scope, dindex).
pub struct TransparentSlotStats {
    pub scope: u8,
    pub dindex: u32,
    pub amount: u64,
    pub tx_count: u32,
    pub time: u32,
}

/// Batch query: tx stats for ALL transparent address slots for an account.
/// Returns rows keyed by (scope, dindex), including zero-tx slots (LEFT JOIN).
pub async fn fetch_transparent_slot_stats(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Vec<TransparentSlotStats>> {
    let rows = sqlx::query(
        "WITH n AS (
        SELECT tx, value, taddress FROM notes WHERE pool = 0 AND account = ?1
        UNION ALL
        SELECT s.tx, s.value, n2.taddress FROM spends s
        JOIN notes n2 ON s.id_note = n2.id_note AND s.account = n2.account
        WHERE s.pool = 0 AND n2.account = ?1)
        SELECT ta.scope, ta.dindex,
               COALESCE(SUM(n.value), 0), COUNT(n.tx), COALESCE(MAX(t.time), 0)
        FROM transparent_address_accounts ta
        LEFT JOIN n ON ta.id_taddress = n.taddress
        LEFT JOIN transactions t ON t.id_tx = n.tx AND t.account = ?1
        WHERE ta.account = ?1
        GROUP BY ta.scope, ta.dindex
        ORDER BY ta.scope, ta.dindex",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let scope: u8 = row.get::<i64, _>(0) as u8;
        let dindex: u32 = row.get::<i64, _>(1) as u32;
        let amount: u64 = row.get::<i64, _>(2) as u64;
        let tx_count: u32 = row.get(3);
        let time: u32 = row.get::<Option<u32>, _>(4).unwrap_or(0);
        TransparentSlotStats {
            scope,
            dindex,
            amount,
            tx_count,
            time,
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    Ok(rows)
}

/// Raw tx stats for a shielded address slot, keyed by (pool, scope, dindex).
pub struct ShieldedSlotStats {
    pub pool: u8,
    pub scope: u8,
    pub dindex: u32,
    pub amount: u64,
    pub tx_count: u32,
    pub time: u32,
}

/// Batch query: tx stats for ALL shielded address slots (Sapling + Orchard).
/// Groups notes+spends by (pool, scope, diversifier_index).
pub async fn fetch_shielded_slot_stats(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Vec<ShieldedSlotStats>> {
    let rows = sqlx::query(
        "SELECT sub.pool, sub.scope, sub.diversifier_index,
                SUM(sub.value), COUNT(sub.tx), COALESCE(MAX(t.time), 0)
        FROM (
            SELECT pool, scope, diversifier_index, tx, value
            FROM notes WHERE account = ?1 AND pool IN (1, 2) AND id_asset IS NULL
            UNION ALL
            SELECT n.pool, n.scope, n.diversifier_index, s.tx, s.value
            FROM spends s
            JOIN notes n ON s.id_note = n.id_note AND s.account = n.account
            WHERE s.pool IN (1, 2) AND n.account = ?1 AND n.id_asset IS NULL
        ) sub
        JOIN transactions t ON t.id_tx = sub.tx AND t.account = ?1
        GROUP BY sub.pool, sub.scope, sub.diversifier_index
        ORDER BY sub.pool, sub.scope, sub.diversifier_index",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let pool: u8 = row.get::<i64, _>(0) as u8;
        let scope: u8 = row.get::<i64, _>(1) as u8;
        let dindex: u32 = row.get::<i64, _>(2) as u32;
        let amount: u64 = row.get::<i64, _>(3) as u64;
        let tx_count: u32 = row.get(4);
        let time: u32 = row.get::<Option<u32>, _>(5).unwrap_or(0);
        ShieldedSlotStats {
            pool,
            scope,
            dindex,
            amount,
            tx_count,
            time,
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    Ok(rows)
}

pub async fn change_db_password(
    db_filepath: &str,
    tmp_dir: &str,
    old_password: &str,
    new_password: &str,
) -> Result<()> {
    let mut options = SqliteConnectOptions::new().filename(db_filepath);
    if !old_password.is_empty() {
        let escaped_old_password = old_password.replace('\'', "''");
        options = options.pragma("key", format!("'{escaped_old_password}'"));
    }

    let tmp_db_filepath = format!("{tmp_dir}/__tmp.db");
    File::create(&tmp_db_filepath)?;

    let mut connection = SqliteConnection::connect_with(&options).await?;
    let escaped_password = new_password.replace('\'', "''");
    sqlx::query(&format!(
        "ATTACH DATABASE '{}' AS new_db KEY '{}'",
        tmp_db_filepath, escaped_password
    ))
    .execute(&mut connection)
    .await?;
    sqlx::query("SELECT sqlcipher_export('new_db')")
        .execute(&mut connection)
        .await?;
    sqlx::query("DETACH DATABASE new_db")
        .execute(&mut connection)
        .await?;

    // Explicitly close the connection before file operations to ensure Windows
    // file handles are fully released. Relying on Drop (sqlite3_close_v2) may not
    // be synchronous enough on Windows, causing remove_file/rename to fail.
    connection.close().await?;

    std::fs::remove_file(db_filepath)?;
    std::fs::rename(tmp_db_filepath, db_filepath)?;

    Ok(())
}

pub async fn store_pending_tx(
    connection: &mut SqliteConnection,
    account: u32,
    height: u32,
    txid: &[u8],
    price: Option<f64>,
    category: Option<u32>,
) -> Result<()> {
    let mut txid = txid.to_vec();
    txid.reverse();
    sqlx::query(
        "INSERT INTO pending_txs(account, height, txid, price, category)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(account, txid) DO UPDATE SET
            height = excluded.height,
            price = excluded.price,
            category = excluded.category",
    )
    .bind(account)
    .bind(height)
    .bind(&txid)
    .bind(price)
    .bind(category)
    .execute(connection)
    .await?;
    Ok(())
}

pub async fn set_user_memo(
    connection: &mut SqliteConnection,
    account: u32,
    id_tx: u32,
    memo: Option<String>,
) -> Result<()> {
    match memo {
        Some(memo) if !memo.is_empty() => {
            sqlx::query(
                "INSERT INTO user_memos(account, id_tx, user_memo) VALUES (?1, ?2, ?3)
                ON CONFLICT(account, id_tx) DO UPDATE SET user_memo = excluded.user_memo",
            )
            .bind(account)
            .bind(id_tx)
            .bind(&memo)
            .execute(&mut *connection)
            .await?;
        }
        _ => {
            sqlx::query("DELETE FROM user_memos WHERE account = ?1 AND id_tx = ?2")
                .bind(account)
                .bind(id_tx)
                .execute(&mut *connection)
                .await?;
        }
    }
    Ok(())
}

pub async fn set_tx_category(
    connection: &mut SqliteConnection,
    id: u32,
    category: Option<u32>,
) -> Result<()> {
    sqlx::query("UPDATE transactions SET category = ?2 WHERE id_tx = ?1")
        .bind(id)
        .bind(category)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub async fn set_tx_price(
    connection: &mut SqliteConnection,
    id: u32,
    price: Option<f64>,
) -> Result<()> {
    sqlx::query("UPDATE transactions SET price = ?2 WHERE id_tx = ?1")
        .bind(id)
        .bind(price)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

pub async fn export_data(
    connection: &mut SqliteConnection,
    account: u32,
    tpe: u8,
    writer: &mut AsyncWriter<Vec<u8>>,
) -> Result<()> {
    let sql = match tpe {
        0 => "SELECT t.*, c.name FROM transactions t LEFT JOIN categories c ON c.id_category = t.category WHERE account = ?1 ORDER BY height",
        1 => "SELECT * FROM memos WHERE account = ?1 ORDER BY height",
        2 => "SELECT n.* FROM notes n LEFT JOIN spends s ON n.id_note = s.id_note WHERE n.account = ?1 AND s.id_note IS NULL ORDER BY height",
        3 => "WITH N AS (SELECT id_asset, value FROM notes WHERE account = ?1 AND id_asset IS NOT NULL UNION ALL SELECT n.id_asset, s.value FROM spends s JOIN notes n ON s.id_note = n.id_note WHERE s.account = ?1 AND n.id_asset IS NOT NULL) SELECT a.id_asset, hex(a.asset_desc_hash), a.asset_name, a.finalized, a.first_seen_height, COALESCE(SUM(N.value), 0) AS balance FROM assets a LEFT JOIN N ON N.id_asset = a.id_asset GROUP BY a.id_asset HAVING balance > 0 ORDER BY a.asset_name, a.asset_desc_hash",
        _ => anyhow::bail!("Invalid exported data type")
    };

    let mut rows = sqlx::query(sql)
        .bind(account)
        .map(|r: SqliteRow| {
            r.columns()
                .iter()
                .enumerate()
                .map(|(i, _)| get_sqlite_column_value(&r, i))
                .collect::<Result<Vec<_>>>()
        })
        .fetch(connection);

    while let Some(Ok(row)) = rows.try_next().await? {
        writer.write_record(row).await?;
    }
    Ok(())
}

fn get_sqlite_column_value(row: &SqliteRow, index: usize) -> Result<String> {
    let c = row.column(index);
    let t = c.type_info();
    let v = if let Ok(v) = row.try_get::<i64, _>(index) {
        v.to_string()
    } else if let Ok(v) = row.try_get::<f64, _>(index) {
        v.to_string()
    } else if let Ok(v) = row.try_get::<String, _>(index) {
        v
    } else if let Ok(mut v) = row.try_get::<Vec<u8>, _>(index) {
        if c.name() == "txid" {
            v.reverse();
        }
        hex::encode(&v)
    } else {
        unreachable!("{}", t.name())
    };

    Ok(v)
}

pub async fn lock_recent_notes(
    connection: &mut SqliteConnection,
    account: u32,
    height: u32,
    threshold: u32,
) -> Result<()> {
    let max_height = height.saturating_sub(threshold);
    sqlx::query("UPDATE notes SET locked = TRUE WHERE account = ?1 AND height > ?2")
        .bind(account)
        .bind(max_height)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn toggle_all_notes(connection: &mut SqliteConnection, account: u32) -> Result<()> {
    sqlx::query("UPDATE notes SET locked = NOT locked WHERE account = ?1")
        .bind(account)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn unlock_all_notes(connection: &mut SqliteConnection, account: u32) -> Result<()> {
    sqlx::query("UPDATE notes SET locked = FALSE WHERE account = ?1")
        .bind(account)
        .execute(connection)
        .await?;
    Ok(())
}

// TODO: Include pool filter
// Unfortunately, the current UI flow asks for the amount before
// the source pool selection. Therefore we don't know what the user
// wants to use yet
pub async fn max_spendable(connection: &mut SqliteConnection, account: u32) -> Result<u64> {
    let confirmed_height = confirmed_height(
        &mut *connection,
        account,
        crate::api::pay::DEFAULT_CONFIRMATIONS,
    )
    .await?;
    let query = format!("SELECT SUM(n.value) {OWNED_UNSPENT_ZEC_NOTES} AND {AVAILABLE_NOTE}");
    let (amount,): (Option<u64>,) = sqlx::query_as(&query)
        .bind(account)
        .bind(confirmed_height)
        .fetch_one(connection)
        .await?;
    Ok(amount.unwrap_or_default())
}

/// A conservative lower bound on what is spendable from `pools`, fundable for ANY
/// single recipient pool. Not the exact maximum: a same-pool send can afford more.
pub async fn max_spendable_from_pools(
    connection: &mut SqliteConnection,
    account: u32,
    pools: PoolMask,
    confirmations: u32,
) -> Result<u64> {
    let confirmed_height = confirmed_height(&mut *connection, account, confirmations).await?;
    let query = format!(
        "SELECT n.pool, SUM(n.value), COUNT(*)
        {OWNED_UNSPENT_ZEC_NOTES} AND {AVAILABLE_NOTE} AND n.value >= ?3
        GROUP BY n.pool"
    );
    let mut rows = sqlx::query(&query)
        .bind(account)
        .bind(confirmed_height)
        .bind(COST_PER_ACTION as i64)
        .map(|row: SqliteRow| {
            (
                row.get::<u8, _>(0),
                row.get::<i64, _>(1),
                row.get::<i64, _>(2),
            )
        })
        .fetch(connection);

    let mut available = 0u64;
    let mut actions = 0u64;
    while let Some((pool, value, count)) = rows.try_next().await? {
        if !pools.has_pool(pool) {
            continue;
        }
        available += value as u64;
        // A shielded bundle is padded to two logical actions (ZIP-317);
        // transparent inputs are counted one by one.
        actions += if pool == 0 {
            count as u64
        } else {
            (count as u64).max(2)
        };
    }

    // At most two outputs (recipient and change) can land in pools outside the mask,
    // and each such bundle costs at most two more actions.
    let fee_bound = (actions + 4).max(2) * COST_PER_ACTION;
    Ok(available.saturating_sub(fee_bound))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Every column a pre-ECC database used for spending secrets.
    pub(crate) const SECRET_COLUMNS: [(&str, &str); 4] = [
        ("transparent_accounts", "xsk"),
        ("sapling_accounts", "xsk"),
        ("orchard_accounts", "xsk"),
        ("transparent_address_accounts", "sk"),
    ];

    /// The viewing material that must survive every write path and the scrub.
    pub(crate) const VIEWING_COLUMNS: [(&str, &str); 4] = [
        ("transparent_accounts", "xvk"),
        ("sapling_accounts", "xvk"),
        ("orchard_accounts", "xvk"),
        ("transparent_address_accounts", "pk"),
    ];

    pub(crate) async fn memory_db() -> SqliteConnection {
        let mut connection = SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        create_schema(&mut connection).await.expect("schema");

        connection
    }

    /// The single row's `column`, or `None` when it is NULL or the table is empty.
    pub(crate) async fn blob(
        connection: &mut SqliteConnection,
        table: &str,
        column: &str,
    ) -> Option<Vec<u8>> {
        sqlx::query_scalar(&format!("SELECT {column} FROM {table}"))
            .fetch_optional(&mut *connection)
            .await
            .expect("query")
            .flatten()
    }

    /// Rows still holding a value in `column` — a whole-column check [`blob`] cannot make.
    pub(crate) async fn non_null_rows(
        connection: &mut SqliteConnection,
        table: &str,
        column: &str,
    ) -> i64 {
        sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE {column} IS NOT NULL"
        ))
        .fetch_one(&mut *connection)
        .await
        .expect("query")
    }

    async fn seed_pre_ecc_database(connection: &mut SqliteConnection) {
        for statement in [
            "INSERT INTO transparent_accounts(account, xsk, xvk) VALUES (1, x'aa', x'11')",
            "INSERT INTO sapling_accounts(account, xsk, xvk) VALUES (1, x'bb', x'22')",
            "INSERT INTO orchard_accounts(account, xsk, xvk) VALUES (1, x'cc', x'33')",
            "INSERT INTO transparent_address_accounts(account, scope, dindex, sk, pk, address)
             VALUES (1, 0, 0, x'dd', x'44', 't1example')",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .expect("seed");
        }
    }

    pub(crate) const ACCOUNT: u32 = 1;

    /// `scope`: 0 external (incoming), 1 internal (change), NULL for transparent notes.
    pub(crate) async fn insert_note(
        connection: &mut SqliteConnection,
        id_note: u32,
        tx: u32,
        pool: u8,
        height: u32,
        value: u64,
        scope: Option<u8>,
    ) {
        sqlx::query(
            "INSERT INTO notes(id_note, height, account, pool, scope, nullifier, tx, value)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(id_note)
        .bind(height)
        .bind(ACCOUNT)
        .bind(pool)
        .bind(scope)
        .bind(id_note.to_le_bytes().to_vec())
        .bind(tx)
        .bind(value as i64)
        .execute(connection)
        .await
        .expect("note");
    }

    async fn spend_note(connection: &mut SqliteConnection, id_note: u32, pool: u8, height: u32) {
        sqlx::query(
            "INSERT INTO spends(id_note, height, account, pool, tx, value)
             SELECT id_note, ?2, account, ?3, 0, -value FROM notes WHERE id_note = ?1",
        )
        .bind(id_note)
        .bind(height)
        .bind(pool)
        .execute(connection)
        .await
        .expect("spend");
    }

    pub(crate) async fn set_sync_height(connection: &mut SqliteConnection, height: u32) {
        for pool in 0..NUM_POOLS as u8 {
            set_pool_sync_height(&mut *connection, pool, height).await;
        }
    }

    pub(crate) async fn set_pool_sync_height(
        connection: &mut SqliteConnection,
        pool: u8,
        height: u32,
    ) {
        set_pool_sync_height_for_account(connection, ACCOUNT, pool, height).await;
    }

    pub(crate) async fn set_pool_sync_height_for_account(
        connection: &mut SqliteConnection,
        account: u32,
        pool: u8,
        height: u32,
    ) {
        sqlx::query(
            "INSERT OR REPLACE INTO sync_heights(account, pool, height) VALUES (?1, ?2, ?3)",
        )
        .bind(account)
        .bind(pool)
        .bind(height)
        .execute(&mut *connection)
        .await
        .expect("sync height");
    }

    #[tokio::test]
    async fn create_schema_legacy_pending_table_preserves_rows_and_adds_reservations() {
        let mut connection = SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("database");
        sqlx::query(
            "CREATE TABLE pending_txs (
                id_pending_tx INTEGER PRIMARY KEY,
                account INTEGER NOT NULL,
                txid BLOB NOT NULL,
                height INTEGER NOT NULL,
                price REAL,
                category INTEGER,
                UNIQUE (account, txid))",
        )
        .execute(&mut connection)
        .await
        .expect("legacy table");
        sqlx::query(
            "INSERT INTO pending_txs(account, txid, height, price, category)
            VALUES (1, x'0102', 100, 2.5, 7)",
        )
        .execute(&mut connection)
        .await
        .expect("legacy row");

        create_schema(&mut connection).await.expect("upgrade");

        let row: (Vec<u8>, u32, f64, u32, Option<u32>) =
            sqlx::query_as("SELECT txid, height, price, category, expiry_height FROM pending_txs")
                .fetch_one(&mut connection)
                .await
                .expect("preserved row");
        assert_eq!(row, (vec![1, 2], 100, 2.5, 7, None));
        let columns: u32 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_table_info('pending_spend_inputs')")
                .fetch_one(&mut connection)
                .await
                .expect("reservation table");
        assert_eq!(columns, 4);
    }

    /// An `accounts` table as it existed before the `can_sign` column, so migration tests
    /// exercise the real `ALTER TABLE` path instead of the fresh-database `CREATE TABLE`.
    pub(crate) async fn pre_can_sign_migration_db() -> SqliteConnection {
        let mut connection = SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("database");
        sqlx::query(
            "CREATE TABLE accounts(
                id_account INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                seed TEXT,
                passphrase TEXT NOT NULL DEFAULT '',
                seed_fingerprint BLOB,
                aindex INTEGER NOT NULL,
                dindex INTEGER NOT NULL,
                def_dindex INTEGER NOT NULL,
                icon BLOB,
                birth INTEGER NOT NULL,
                position INTEGER NOT NULL,
                use_internal BOOL NOT NULL,
                hidden BOOL NOT NULL,
                saved BOOL NOT NULL,
                enabled BOOL NOT NULL DEFAULT TRUE,
                internal BOOL NOT NULL DEFAULT FALSE
            )",
        )
        .execute(&mut connection)
        .await
        .expect("legacy accounts table (pre can_sign)");

        connection
    }

    #[tokio::test]
    async fn create_schema_migrates_existing_accounts_can_sign_from_seed_fingerprint() {
        let mut connection = pre_can_sign_migration_db().await;

        sqlx::query(
            "INSERT INTO accounts(id_account, name, seed_fingerprint, aindex, dindex, def_dindex, birth, position, use_internal, hidden, saved)
            VALUES (1, 'phrase', x'0102', 0, 0, 0, 100, 0, TRUE, FALSE, TRUE)",
        )
        .execute(&mut connection)
        .await
        .expect("phrase account");

        sqlx::query(
            "INSERT INTO accounts(id_account, name, seed_fingerprint, aindex, dindex, def_dindex, birth, position, use_internal, hidden, saved)
            VALUES (2, 'ufvk', NULL, 0, 0, 0, 100, 1, TRUE, FALSE, TRUE)",
        )
        .execute(&mut connection)
        .await
        .expect("ufvk account");

        create_schema(&mut connection).await.expect("migration");

        assert!(get_account_can_sign(&mut connection, 1)
            .await
            .expect("phrase can_sign"));
        assert!(!get_account_can_sign(&mut connection, 2)
            .await
            .expect("ufvk can_sign"));
    }

    #[tokio::test]
    async fn create_schema_can_sign_backfill_failure_leaves_no_half_migrated_column() {
        let mut connection = pre_can_sign_migration_db().await;
        sqlx::query(
            "INSERT INTO accounts(id_account, name, seed_fingerprint, aindex, dindex, def_dindex, birth, position, use_internal, hidden, saved)
            VALUES (1, 'phrase', x'0102', 0, 0, 0, 100, 0, TRUE, FALSE, TRUE)",
        )
        .execute(&mut connection)
        .await
        .expect("phrase account");
        // Stands in for losing the process between the ALTER TABLE and the backfill.
        sqlx::query(
            "CREATE TRIGGER fail_backfill BEFORE UPDATE ON accounts
            BEGIN SELECT RAISE(ABORT, 'interrupted'); END",
        )
        .execute(&mut connection)
        .await
        .expect("trigger");

        assert!(create_schema(&mut connection).await.is_err());

        let has_can_sign: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name = 'can_sign'",
        )
        .fetch_one(&mut connection)
        .await
        .expect("column count");
        assert_eq!(
            0, has_can_sign,
            "the column must not outlive the backfill that fills it"
        );
    }

    #[tokio::test]
    async fn migrate_can_sign_after_a_concurrent_opener_migrated_succeeds() {
        let mut connection = pre_can_sign_migration_db().await;
        create_schema(&mut connection)
            .await
            .expect("winning opener");

        // The losing opener read the schema before the winner committed, so it still believes
        // the column is missing; its migration must find the column and give up quietly.
        migrate_can_sign(&mut connection)
            .await
            .expect("a losing opener must not fail the wallet open");
    }

    #[tokio::test]
    async fn create_schema_migration_is_idempotent() {
        let mut connection = pre_can_sign_migration_db().await;
        create_schema(&mut connection).await.expect("first open");
        // Re-opening an already-migrated database must not error (duplicate ALTER TABLE).
        create_schema(&mut connection).await.expect("second open");
    }

    #[tokio::test]
    async fn store_account_metadata_records_can_sign_false_for_dkg_accounts() {
        // Mirrors frost/dkg.rs's call shape (no fingerprint, no hw, can_sign: false) — a DKG
        // account cannot sign outside the multi-party ceremony that created it.
        let mut connection = memory_db().await;

        let account = store_account_metadata(
            &mut connection,
            "dkg",
            &None,
            &None,
            100,
            false,
            false,
            false,
        )
        .await
        .expect("dkg account");

        assert!(!get_account_can_sign(&mut connection, account)
            .await
            .expect("can sign"));
    }

    #[tokio::test]
    async fn calculate_balance_breakdown_splits_pending_by_note_scope() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 1, 80, 100, Some(0)).await;
        insert_note(&mut connection, 2, 0, 1, 95, 30, Some(0)).await;
        insert_note(&mut connection, 3, 0, 1, 96, 7, Some(1)).await;
        insert_note(&mut connection, 4, 0, 2, 80, 5, Some(0)).await;

        let breakdown = calculate_balance_breakdown(&mut connection, ACCOUNT, 10)
            .await
            .expect("breakdown");

        assert_eq!(
            breakdown.0[1],
            Balance {
                available: 100,
                locked: 0,
                change_pending: 7,
                value_pending: 30,
            }
        );
        assert_eq!(
            breakdown.0[2],
            Balance {
                available: 5,
                ..Balance::default()
            }
        );
    }

    #[tokio::test]
    async fn calculate_balance_breakdown_spent_note_is_excluded_everywhere() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 1, 80, 100, Some(0)).await;
        insert_note(&mut connection, 2, 0, 1, 95, 30, Some(0)).await;
        spend_note(&mut connection, 1, 1, 99).await;

        let breakdown = calculate_balance_breakdown(&mut connection, ACCOUNT, 10)
            .await
            .expect("breakdown");

        assert_eq!(
            breakdown.0[1],
            Balance {
                available: 0,
                locked: 0,
                change_pending: 0,
                value_pending: 30,
            }
        );
    }

    #[tokio::test]
    async fn calculate_balance_breakdown_zero_confirmations_totals_match_calculate_balance() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 1, 80, 100, Some(0)).await;
        insert_note(&mut connection, 2, 0, 1, 100, 30, Some(1)).await;
        insert_note(&mut connection, 3, 0, 2, 90, 5, Some(0)).await;
        spend_note(&mut connection, 1, 1, 99).await;

        let breakdown = calculate_balance_breakdown(&mut connection, ACCOUNT, 0)
            .await
            .expect("breakdown");
        let total = calculate_balance(&mut connection, ACCOUNT, None)
            .await
            .expect("balance");

        for pool in 0..NUM_POOLS {
            let b = breakdown.0[pool];
            assert_eq!(b.change_pending, 0, "pool {pool}");
            assert_eq!(b.value_pending, 0, "pool {pool}");
            assert_eq!(b.available, total.0[pool], "pool {pool}");
        }
    }

    #[tokio::test]
    async fn calculate_balance_breakdown_unsynced_account_reports_everything_pending() {
        let mut connection = memory_db().await;
        insert_note(&mut connection, 1, 0, 1, 80, 100, Some(0)).await;

        let breakdown = calculate_balance_breakdown(&mut connection, ACCOUNT, 10)
            .await
            .expect("breakdown");

        assert_eq!(
            breakdown.0[1],
            Balance {
                available: 0,
                locked: 0,
                change_pending: 0,
                value_pending: 100,
            }
        );
    }

    #[tokio::test]
    async fn calculate_balance_breakdown_transparent_note_without_scope_counts_as_incoming() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 0, 95, 42, None).await;

        let breakdown = calculate_balance_breakdown(&mut connection, ACCOUNT, 10)
            .await
            .expect("breakdown");

        assert_eq!(
            breakdown.0[0],
            Balance {
                available: 0,
                locked: 0,
                change_pending: 0,
                value_pending: 42,
            }
        );
    }

    #[tokio::test]
    async fn calculate_balance_breakdown_confirmation_boundary_matches_spend_cutoff() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 1, 91, 42, Some(0)).await;

        let nine = calculate_balance_breakdown(&mut connection, ACCOUNT, 9)
            .await
            .expect("nine confirmations");
        let ten = calculate_balance_breakdown(&mut connection, ACCOUNT, 10)
            .await
            .expect("ten confirmations");

        assert_eq!(nine.0[1].available, 42);
        assert_eq!(ten.0[1].available, 0);
        assert_eq!(ten.0[1].value_pending, 42);
    }

    const TX: u32 = 7;

    async fn insert_tx(connection: &mut SqliteConnection, id_tx: u32, value: i64, fee: u64) {
        sqlx::query(
            "INSERT INTO transactions(id_tx, txid, height, account, time, value, fee)
             VALUES (?1, ?2, 100, ?3, 1700000000, ?4, ?5)",
        )
        .bind(id_tx)
        .bind(id_tx.to_le_bytes().to_vec())
        .bind(ACCOUNT)
        .bind(value)
        .bind(fee as i64)
        .execute(connection)
        .await
        .expect("transaction");
    }

    async fn insert_output(
        connection: &mut SqliteConnection,
        tx: u32,
        pool: u8,
        vout: u32,
        value: u64,
        address: &str,
    ) {
        sqlx::query(
            "INSERT INTO outputs(account, height, tx, pool, vout, value, address)
             VALUES (?1, 100, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(ACCOUNT)
        .bind(tx)
        .bind(pool)
        .bind(vout)
        .bind(value as i64)
        .bind(address)
        .execute(connection)
        .await
        .expect("output");
    }

    async fn insert_memo(
        connection: &mut SqliteConnection,
        tx: u32,
        pool: u8,
        vout: u32,
        text: &str,
    ) {
        sqlx::query(
            "INSERT INTO memos(account, height, tx, pool, vout, memo_text, memo_bytes)
             VALUES (?1, 100, ?2, ?3, ?4, ?5, x'00')",
        )
        .bind(ACCOUNT)
        .bind(tx)
        .bind(pool)
        .bind(vout)
        .bind(text)
        .execute(connection)
        .await
        .expect("memo");
    }

    async fn insert_user_memo(connection: &mut SqliteConnection, tx: u32, text: &str) {
        sqlx::query("INSERT INTO user_memos(account, id_tx, user_memo) VALUES (?1, ?2, ?3)")
            .bind(ACCOUNT)
            .bind(tx)
            .bind(text)
            .execute(connection)
            .await
            .expect("user memo");
    }

    async fn single_tx(connection: &mut SqliteConnection) -> Tx {
        fetch_txs(connection, ACCOUNT)
            .await
            .expect("transactions")
            .pop()
            .expect("one transaction")
    }

    #[tokio::test]
    async fn fetch_txs_on_chain_memo_is_reported_when_the_user_wrote_none() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, -3_000, 1_000).await;
        insert_memo(&mut connection, TX, 3, 1, "second output").await;
        insert_memo(&mut connection, TX, 2, 0, "first output").await;

        let tx = single_tx(&mut connection).await;

        assert_eq!(Some("first output".to_string()), tx.memo);
        assert!(!tx.is_user_memo);
    }

    #[tokio::test]
    async fn fetch_txs_user_memo_overrides_the_on_chain_one() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, -3_000, 1_000).await;
        insert_memo(&mut connection, TX, 2, 0, "on chain").await;
        insert_user_memo(&mut connection, TX, "my note").await;

        let tx = single_tx(&mut connection).await;

        assert_eq!(Some("my note".to_string()), tx.memo);
        assert!(tx.is_user_memo);
    }

    #[tokio::test]
    async fn fetch_txs_total_received_counts_only_notes_of_that_transaction() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, -3_000, 1_000).await;
        insert_note(&mut connection, 1, TX, 2, 100, 600, Some(0)).await;
        insert_note(&mut connection, 2, TX, 3, 100, 400, Some(1)).await;
        insert_note(&mut connection, 3, TX + 1, 2, 100, 999, Some(0)).await;

        let tx = single_tx(&mut connection).await;

        assert_eq!(1_000, tx.total_received);
    }

    #[tokio::test]
    async fn fetch_txs_only_internal_notes_mark_the_transaction_as_change() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, -1_000, 1_000).await;
        insert_note(&mut connection, 1, TX, 2, 100, 600, Some(1)).await;
        insert_note(&mut connection, 2, TX, 3, 100, 400, Some(1)).await;

        assert!(single_tx(&mut connection).await.is_change);
    }

    #[tokio::test]
    async fn fetch_txs_one_external_note_keeps_the_transaction_out_of_change() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, -1_000, 1_000).await;
        insert_note(&mut connection, 1, TX, 2, 100, 600, Some(1)).await;
        insert_note(&mut connection, 2, TX, 3, 100, 400, Some(0)).await;

        assert!(!single_tx(&mut connection).await.is_change);
    }

    #[tokio::test]
    async fn fetch_txs_transaction_without_notes_is_not_change() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, -1_000, 1_000).await;

        assert!(!single_tx(&mut connection).await.is_change);
    }

    #[tokio::test]
    async fn fetch_txs_recipient_skips_the_output_that_came_back_to_us() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, -3_000, 1_000).await;
        insert_note(&mut connection, 1, TX, 2, 100, 6_000, Some(1)).await;
        insert_output(&mut connection, TX, 2, 0, 6_000, "own-change").await;
        insert_output(&mut connection, TX, 2, 1, 3_000, "recipient").await;

        let tx = single_tx(&mut connection).await;

        assert_eq!(Some("recipient".to_string()), tx.recipient);
        assert_eq!(1_000, tx.fee);
    }

    #[tokio::test]
    async fn fetch_txs_transaction_without_details_has_no_recipient_and_no_fee() {
        let mut connection = memory_db().await;
        insert_tx(&mut connection, TX, 5_000, 0).await;
        insert_note(&mut connection, 1, TX, 2, 100, 5_000, Some(0)).await;

        let tx = single_tx(&mut connection).await;

        assert_eq!(None, tx.recipient);
        assert_eq!(0, tx.fee);
        assert_eq!(5_000, tx.total_received);
    }

    #[tokio::test]
    async fn scrub_spending_keys_clears_secrets_and_keeps_viewing_keys() {
        let mut connection = memory_db().await;
        seed_pre_ecc_database(&mut connection).await;

        scrub_spending_keys(&mut connection).await.expect("scrub");

        for (table, column) in SECRET_COLUMNS {
            assert_eq!(
                non_null_rows(&mut connection, table, column).await,
                0,
                "{table}"
            );
        }
        for (table, column) in VIEWING_COLUMNS {
            assert!(
                blob(&mut connection, table, column).await.is_some(),
                "{table}.{column}"
            );
        }
        let address: String =
            sqlx::query_scalar("SELECT address FROM transparent_address_accounts")
                .fetch_one(&mut connection)
                .await
                .expect("address");
        assert_eq!(address, "t1example");
    }

    #[tokio::test]
    async fn scrub_spending_keys_runs_twice_without_error() {
        let mut connection = memory_db().await;
        seed_pre_ecc_database(&mut connection).await;

        scrub_spending_keys(&mut connection).await.expect("scrub");
        scrub_spending_keys(&mut connection)
            .await
            .expect("second scrub");
    }

    async fn insert_taddress(connection: &mut SqliteConnection, id_taddress: u32, address: &str) {
        insert_scoped_taddress(connection, id_taddress, 0, id_taddress, address).await;
    }

    pub(crate) async fn insert_scoped_taddress(
        connection: &mut SqliteConnection,
        id_taddress: u32,
        scope: u32,
        dindex: u32,
        address: &str,
    ) {
        insert_scoped_taddress_for_account(
            connection,
            ACCOUNT,
            id_taddress,
            scope,
            dindex,
            address,
        )
        .await;
    }

    pub(crate) async fn insert_scoped_taddress_for_account(
        connection: &mut SqliteConnection,
        account: u32,
        id_taddress: u32,
        scope: u32,
        dindex: u32,
        address: &str,
    ) {
        sqlx::query(
            "INSERT INTO transparent_address_accounts(id_taddress, account, scope, dindex, pk, address)
             VALUES (?1, ?2, ?3, ?4, x'00', ?5)",
        )
        .bind(id_taddress)
        .bind(account)
        .bind(scope)
        .bind(dindex)
        .bind(address)
        .execute(&mut *connection)
        .await
        .expect("taddress");
    }

    async fn insert_account(connection: &mut SqliteConnection, dindex: u32) {
        sqlx::query(
            "INSERT INTO accounts(id_account, name, aindex, dindex, def_dindex, birth, position,
             use_internal, hidden, saved)
             VALUES (?1, 'test', 0, ?2, ?2, 0, 0, FALSE, FALSE, TRUE)",
        )
        .bind(ACCOUNT)
        .bind(dindex)
        .execute(&mut *connection)
        .await
        .expect("account");
    }

    async fn insert_transparent_note(
        connection: &mut SqliteConnection,
        id_note: u32,
        value: u64,
        id_taddress: u32,
    ) {
        insert_note(&mut *connection, id_note, 0, 0, 100, value, None).await;
        sqlx::query("UPDATE notes SET taddress = ?2 WHERE id_note = ?1")
            .bind(id_note)
            .bind(id_taddress)
            .execute(&mut *connection)
            .await
            .expect("taddress of note");
    }

    #[tokio::test]
    async fn transparent_address_balance_counts_unspent_notes_of_that_address_only() {
        let mut connection = memory_db().await;
        insert_taddress(&mut connection, 1, "t1first").await;
        insert_taddress(&mut connection, 2, "t1second").await;
        insert_transparent_note(&mut connection, 1, 100, 1).await;
        insert_transparent_note(&mut connection, 2, 30, 1).await;
        insert_transparent_note(&mut connection, 3, 7, 2).await;
        spend_note(&mut connection, 2, 0, 110).await;

        let first = transparent_address_balance(&mut connection, ACCOUNT, "t1first")
            .await
            .expect("balance");
        let second = transparent_address_balance(&mut connection, ACCOUNT, "t1second")
            .await
            .expect("balance");

        assert_eq!(first, 100);
        assert_eq!(second, 7);
    }

    #[tokio::test]
    async fn transparent_address_balance_unknown_address_is_zero() {
        let mut connection = memory_db().await;
        insert_taddress(&mut connection, 1, "t1first").await;
        insert_transparent_note(&mut connection, 1, 100, 1).await;

        let balance = transparent_address_balance(&mut connection, ACCOUNT, "t1other")
            .await
            .expect("balance");

        assert_eq!(balance, 0);
    }

    #[tokio::test]
    async fn transparent_address_balance_ignores_notes_of_another_account() {
        let mut connection = memory_db().await;
        insert_taddress(&mut connection, 1, "t1first").await;
        insert_transparent_note(&mut connection, 1, 100, 1).await;

        let balance = transparent_address_balance(&mut connection, ACCOUNT + 1, "t1first")
            .await
            .expect("balance");

        assert_eq!(balance, 0);
    }

    /// The signal `generate_next_transparent_address` retries on.
    #[tokio::test]
    async fn store_account_transparent_addr_reports_an_index_taken_by_someone_else() {
        let mut connection = memory_db().await;

        let first = store_account_transparent_addr(
            &mut connection,
            ACCOUNT,
            0,
            7,
            None,
            b"pk",
            "t1a",
            false,
        )
        .await
        .expect("first insert");
        let second = store_account_transparent_addr(
            &mut connection,
            ACCOUNT,
            0,
            7,
            None,
            b"pk",
            "t1b",
            false,
        )
        .await
        .expect("second insert");

        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn transparent_addresses_to_scan_takes_the_newest_of_each_scope() {
        let mut connection = memory_db().await;
        insert_account(&mut connection, 0).await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, "t1default").await;
        insert_scoped_taddress(&mut connection, 2, 0, 1, "t1receive").await;
        insert_scoped_taddress(&mut connection, 3, 1, 0, "t1change").await;

        let scanned = transparent_addresses_to_scan(&mut connection, ACCOUNT, 100)
            .await
            .expect("addresses");

        let addresses: Vec<&str> = scanned.iter().map(|(_, a)| a.as_str()).collect();
        assert_eq!(addresses, vec!["t1default", "t1receive", "t1change"]);
    }

    /// The account's own address is the one that must never be dropped from a short window.
    #[tokio::test]
    async fn transparent_addresses_to_scan_scans_the_default_address_first() {
        let mut connection = memory_db().await;
        insert_account(&mut connection, 0).await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, "t1default").await;
        insert_scoped_taddress(&mut connection, 2, 0, 1, "t1one").await;
        insert_scoped_taddress(&mut connection, 3, 1, 0, "t1change").await;

        let scanned = transparent_addresses_to_scan(&mut connection, ACCOUNT, 100)
            .await
            .expect("addresses");

        assert_eq!(scanned.first().map(|(_, a)| a.as_str()), Some("t1default"));
    }

    /// A receive address is handed to a payer, who can pay it at any later time, so no number of
    /// newer addresses may push it out of the scan set.
    #[tokio::test]
    async fn transparent_addresses_to_scan_keeps_every_issued_receive_address() {
        let mut connection = memory_db().await;
        insert_account(&mut connection, 0).await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, "t1default").await;
        for dindex in 1..=3 {
            insert_scoped_taddress(
                &mut connection,
                dindex + 1,
                0,
                dindex,
                &format!("t1one{dindex}"),
            )
            .await;
        }

        let scanned = transparent_addresses_to_scan(&mut connection, ACCOUNT, 2)
            .await
            .expect("addresses");

        let addresses: Vec<&str> = scanned.iter().map(|(_, a)| a.as_str()).collect();
        assert_eq!(
            addresses,
            vec!["t1default", "t1one3", "t1one2", "t1one1"],
            "no receive address may be dropped, whatever the limit"
        );
    }

    #[tokio::test]
    async fn transparent_addresses_to_scan_scans_the_default_before_older_receive_addresses() {
        let mut connection = memory_db().await;
        insert_account(&mut connection, 1).await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, "t1old").await;
        insert_scoped_taddress(&mut connection, 2, 0, 1, "t1default").await;
        insert_scoped_taddress(&mut connection, 3, 0, 2, "t1one").await;

        let scanned = transparent_addresses_to_scan(&mut connection, ACCOUNT, 2)
            .await
            .expect("addresses");

        let addresses: Vec<&str> = scanned.iter().map(|(_, a)| a.as_str()).collect();
        assert_eq!(addresses, vec!["t1default", "t1one", "t1old"]);
    }

    /// Change addresses stay bounded: they are internal, and only a spend can create one.
    #[tokio::test]
    async fn transparent_addresses_to_scan_bounds_the_change_window() {
        let mut connection = memory_db().await;
        insert_account(&mut connection, 0).await;
        insert_scoped_taddress(&mut connection, 1, 0, 0, "t1default").await;
        for dindex in 0..=2 {
            insert_scoped_taddress(
                &mut connection,
                dindex + 2,
                1,
                dindex,
                &format!("t1change{dindex}"),
            )
            .await;
        }

        let scanned = transparent_addresses_to_scan(&mut connection, ACCOUNT, 2)
            .await
            .expect("addresses");

        let addresses: Vec<&str> = scanned.iter().map(|(_, a)| a.as_str()).collect();
        assert_eq!(addresses, vec!["t1default", "t1change2", "t1change1"]);
    }

    async fn use_internal_of(connection: &mut SqliteConnection, account: u32) -> bool {
        sqlx::query_scalar("SELECT use_internal FROM accounts WHERE id_account = ?1")
            .bind(account)
            .fetch_one(connection)
            .await
            .expect("use_internal")
    }

    #[tokio::test]
    async fn create_schema_migrates_legacy_accounts_to_internal_scope() {
        let mut connection = memory_db().await;
        insert_account(&mut connection, 0).await;
        assert!(!use_internal_of(&mut connection, ACCOUNT).await);

        create_schema(&mut connection).await.expect("re-open");
        assert!(use_internal_of(&mut connection, ACCOUNT).await);

        create_schema(&mut connection).await.expect("re-open again");
        assert!(use_internal_of(&mut connection, ACCOUNT).await);
    }

    pub(crate) async fn delete_note(connection: &mut SqliteConnection, id_note: u32) {
        sqlx::query("DELETE FROM notes WHERE id_note = ?1")
            .bind(id_note)
            .execute(connection)
            .await
            .expect("delete note");
    }

    /// The reservation a prepared-but-not-yet-broadcast transaction holds on a note.
    async fn reserve_note(connection: &mut SqliteConnection, id_note: u32) {
        sqlx::query(
            "INSERT INTO pending_spend_inputs(account, nullifier, owner_txid, expiry_height)
             VALUES (?1, ?2, ?3, 0)",
        )
        .bind(ACCOUNT)
        .bind(id_note.to_le_bytes().to_vec())
        .bind(vec![0u8; 32])
        .execute(connection)
        .await
        .expect("reservation");
    }

    async fn lock_note(connection: &mut SqliteConnection, id_note: u32) {
        sqlx::query("UPDATE notes SET locked = TRUE WHERE id_note = ?1")
            .bind(id_note)
            .execute(connection)
            .await
            .expect("lock");
    }

    const T: PoolMask = PoolMask(0b0001);
    const S: PoolMask = PoolMask(0b0010);
    const OI: PoolMask = PoolMask(0b1100);

    #[tokio::test]
    async fn max_spendable_from_pools_mask_excludes_notes_of_other_pools() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 0, 80, 100_000, None).await;
        insert_note(&mut connection, 2, 0, 1, 80, 900_000, Some(0)).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, T, 10)
            .await
            .expect("max");

        assert_eq!(max, 100_000 - 25_000);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_transparent_pool_charges_one_action_per_note() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        for id in 1..=3u32 {
            insert_note(&mut connection, id, 0, 0, 80, 100_000, None).await;
        }

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, T, 10)
            .await
            .expect("max");

        assert_eq!(max, 300_000 - 35_000);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_shielded_pool_pads_to_two_actions() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 1, 80, 100_000, Some(0)).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, S, 10)
            .await
            .expect("max");

        assert_eq!(max, 100_000 - 30_000);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_two_shielded_pools_pad_independently() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 2, 80, 100_000, Some(0)).await;
        insert_note(&mut connection, 2, 0, 3, 80, 200_000, Some(0)).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, OI, 10)
            .await
            .expect("max");

        assert_eq!(max, 300_000 - 40_000);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_dust_notes_add_neither_value_nor_action() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 1, 80, 100_000, Some(0)).await;
        insert_note(&mut connection, 2, 0, 1, 80, COST_PER_ACTION - 1, Some(0)).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, S, 10)
            .await
            .expect("max");

        assert_eq!(max, 100_000 - 30_000);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_note_worth_exactly_one_action_is_not_dust() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 1, 80, 100_000, Some(0)).await;
        insert_note(&mut connection, 2, 0, 1, 80, COST_PER_ACTION, Some(0)).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, S, 10)
            .await
            .expect("max");

        assert_eq!(max, 105_000 - 30_000);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_fee_bound_above_available_returns_zero() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 0, 80, COST_PER_ACTION, None).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, T, 10)
            .await
            .expect("max");

        assert_eq!(max, 0);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_empty_account_returns_zero() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, S, 10)
            .await
            .expect("max");

        assert_eq!(max, 0);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_note_reserved_by_a_pending_spend_is_ignored() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 0, 80, 100_000, None).await;
        insert_note(&mut connection, 2, 0, 0, 80, 500_000, None).await;
        reserve_note(&mut connection, 2).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, T, 10)
            .await
            .expect("max");

        assert_eq!(max, 100_000 - 25_000);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_wallet_of_only_dust_returns_zero() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        for id in 1..=4u32 {
            insert_note(&mut connection, id, 0, 1, 80, COST_PER_ACTION - 1, Some(0)).await;
        }

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, S, 10)
            .await
            .expect("max");

        assert_eq!(max, 0);
    }

    #[tokio::test]
    async fn max_spendable_from_pools_unconfirmed_locked_and_spent_notes_are_ignored() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, 100).await;
        insert_note(&mut connection, 1, 0, 0, 80, 100_000, None).await;
        insert_note(&mut connection, 2, 0, 0, 95, 500_000, None).await;
        insert_note(&mut connection, 3, 0, 0, 80, 500_000, None).await;
        insert_note(&mut connection, 4, 0, 0, 80, 500_000, None).await;
        lock_note(&mut connection, 3).await;
        spend_note(&mut connection, 4, 0, 99).await;

        let max = max_spendable_from_pools(&mut connection, ACCOUNT, T, 10)
            .await
            .expect("max");

        assert_eq!(max, 75_000);
    }
}
