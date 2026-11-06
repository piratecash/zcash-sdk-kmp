use anyhow::{ensure, Context as _, Result};
use sqlx::{Connection as _, Row, Sqlite, SqliteConnection, Transaction as SqliteTransaction};
use zcash_primitives::transaction::{
    Authorized, OrchardBundle, Transaction, TransactionData, TxVersion,
};
use zcash_protocol::consensus::BranchId;

use crate::api::{coin::Network, pay::DEFAULT_CONFIRMATIONS};
use crate::db::get_sync_height;
use crate::{net::BroadcastOutcome, Client};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedTransaction {
    pub txid: Vec<u8>,
    pub expiry_height: u32,
    pub inputs: Vec<Vec<u8>>,
    /// `None` before v5: an older format does not carry its branch.
    pub branch: Option<BranchId>,
}

pub(crate) fn parse_transaction(raw: &[u8]) -> Result<ParsedTransaction> {
    for branch in [
        BranchId::Zsa,
        BranchId::Nu7,
        BranchId::Nu6_3,
        BranchId::Nu6_2,
        BranchId::Nu6,
        BranchId::Nu5,
    ] {
        let mut remaining = raw;
        if let Ok(tx) = Transaction::read(&mut remaining, branch) {
            if remaining.is_empty() {
                return Ok(parsed_transaction(tx));
            }
        }
    }
    anyhow::bail!("Not a valid transaction")
}

fn parsed_transaction(tx: Transaction) -> ParsedTransaction {
    let txid = tx.txid().as_ref().to_vec();
    let expiry_height = u32::from(tx.expiry_height());
    let branch =
        matches!(tx.version(), TxVersion::V5 | TxVersion::V6).then(|| tx.consensus_branch_id());
    let inputs = transaction_inputs(&tx.into_data());
    ParsedTransaction {
        txid,
        expiry_height,
        inputs,
        branch,
    }
}

pub(crate) fn transaction_inputs(tx: &TransactionData<Authorized>) -> Vec<Vec<u8>> {
    let mut inputs = Vec::new();
    if let Some(bundle) = tx.transparent_bundle() {
        for input in &bundle.vin {
            let mut prevout = Vec::new();
            input
                .prevout()
                .write(&mut prevout)
                .expect("writing an outpoint to memory cannot fail");
            inputs.push(prevout);
        }
    }
    if let Some(bundle) = tx.sapling_bundle() {
        inputs.extend(
            bundle
                .shielded_spends()
                .iter()
                .map(|spend| spend.nullifier().to_vec()),
        );
    }
    if let Some(bundle) = tx.orchard_bundle() {
        match bundle {
            OrchardBundle::OrchardVanilla(bundle) => inputs.extend(
                bundle
                    .actions()
                    .iter()
                    .map(|action| action.nullifier().to_bytes().to_vec()),
            ),
            OrchardBundle::OrchardZSA(bundle) => inputs.extend(
                bundle
                    .actions()
                    .iter()
                    .map(|action| action.nullifier().to_bytes().to_vec()),
            ),
        }
    }
    if let Some(bundle) = tx.ironwood_bundle() {
        inputs.extend(
            bundle
                .actions()
                .iter()
                .map(|action| action.nullifier().to_bytes().to_vec()),
        );
    }
    inputs
}

/// Whether the caller guarantees the transaction spends this account's notes.
/// `Optional` is for a transaction of unknown origin — a foreign one reserves nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnInputs {
    Required,
    Optional,
}

pub async fn reserve_transaction(
    connection: &mut SqliteConnection,
    account: u32,
    raw: &[u8],
    own_inputs: OwnInputs,
) -> Result<()> {
    let parsed = parse_transaction(raw)?;
    reserve_parsed_transaction(connection, account, &parsed, own_inputs).await
}

pub async fn reserve_and_send(
    network: &Network,
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    height: u32,
    raw: &[u8],
    own_inputs: OwnInputs,
) -> Result<BroadcastOutcome> {
    let parsed = parse_transaction(raw)?;
    reserve_parsed_transaction(connection, account, &parsed, own_inputs).await?;
    // An `Err` here is not a verdict: the bytes may have reached the node, so the inputs stay held.
    let mut outcome = crate::pay::send(client, height, raw).await?;
    if outcome.error_code != 0 && cannot_be_mined(network, client, &parsed, &outcome.message).await
    {
        outcome.inputs_released = release_reservation(connection, account, &parsed.txid).await;
    }
    Ok(outcome)
}

async fn release_reservation(connection: &mut SqliteConnection, account: u32, txid: &[u8]) -> bool {
    delete_reservation(connection, account, txid)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(account, "Reserved inputs not released: {error:#}");
            false
        })
}

async fn delete_reservation(
    connection: &mut SqliteConnection,
    account: u32,
    txid: &[u8],
) -> Result<bool> {
    let mut transaction = connection.begin().await?;
    let released =
        sqlx::query("DELETE FROM pending_spend_inputs WHERE account = ?1 AND owner_txid = ?2")
            .bind(account)
            .bind(txid)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
    sqlx::query("DELETE FROM pending_txs WHERE account = ?1 AND txid = ?2")
        .bind(account)
        .bind(txid)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(released > 0)
}

/// A fork from before the branch ended could still mine the transaction, and a deleted reservation
/// cannot come back: wait out the depth the wallet already trusts for confirmations.
const REORG_MARGIN: u32 = DEFAULT_CONFIRMATIONS;

/// Zebra retries what it refused, so a wrong-branch answer proves nothing until that branch is well
/// over for the next block. The tip is read here: the caller's `height` may be the expiry height.
async fn cannot_be_mined(
    network: &Network,
    client: &mut Client,
    parsed: &ParsedTransaction,
    message: &str,
) -> bool {
    if !message
        .to_lowercase()
        .contains("incorrect consensus branch id")
    {
        return false;
    }
    let Some((_, Some(end))) = parsed
        .branch
        .and_then(|branch| branch.height_bounds(network))
    else {
        return false;
    };
    let Ok(tip) = client.latest_height().await else {
        return false;
    };
    u32::from(end).saturating_add(REORG_MARGIN) <= tip.saturating_add(1)
}

async fn reserve_parsed_transaction(
    connection: &mut SqliteConnection,
    account: u32,
    parsed: &ParsedTransaction,
    own_inputs: OwnInputs,
) -> Result<()> {
    let scanned_height = get_sync_height(&mut *connection, account).await?;
    if let Some(height) = scanned_height {
        ensure!(
            parsed.expiry_height == 0 || parsed.expiry_height > height,
            "Transaction expired at height {}",
            parsed.expiry_height
        );
    }

    let mut transaction = connection.begin().await?;
    let owned_inputs = validate_owned_inputs(&mut transaction, account, parsed).await?;
    if owned_inputs.is_empty() {
        ensure!(
            own_inputs == OwnInputs::Optional,
            "Transaction does not spend an input owned by account {account}"
        );
        ensure!(
            !reserved_by_another_transaction(&mut transaction, account, parsed).await?,
            "Transaction input is reserved by another pending transaction"
        );
        return Ok(());
    }
    claim_inputs(&mut transaction, account, parsed, owned_inputs).await?;
    record_pending_tx(&mut transaction, account, parsed, scanned_height).await?;
    transaction.commit().await?;
    tracing::debug!(
        account,
        txid = %hex::encode(&parsed.txid),
        expiry_height = parsed.expiry_height,
        inputs = parsed.inputs.len(),
        "Reserved transaction inputs"
    );
    Ok(())
}

async fn validate_owned_inputs(
    transaction: &mut SqliteTransaction<'_, Sqlite>,
    account: u32,
    parsed: &ParsedTransaction,
) -> Result<Vec<Vec<u8>>> {
    let mut owned_inputs = Vec::new();
    for input in &parsed.inputs {
        let rows = sqlx::query(
            "SELECT n.account, n.locked, s.id_note IS NOT NULL, t.txid
            FROM notes n
            LEFT JOIN spends s ON s.id_note = n.id_note
            LEFT JOIN transactions t ON t.id_tx = s.tx AND t.account = s.account
            WHERE n.nullifier = ?1",
        )
        .bind(input)
        .fetch_all(&mut **transaction)
        .await?;

        for row in rows {
            let owner: u32 = row.get(0);
            ensure!(
                owner == account,
                "Transaction spends an input from another account"
            );
            ensure!(
                !row.get::<bool, _>(1),
                "Transaction input is manually locked"
            );
            let is_spent: bool = row.get(2);
            let spend_txid: Option<Vec<u8>> = row.get(3);
            ensure!(
                !is_spent || spend_txid.as_deref() == Some(parsed.txid.as_slice()),
                "Transaction input is already spent by another transaction"
            );
            if !owned_inputs.contains(input) {
                owned_inputs.push(input.clone());
            }
        }
    }
    Ok(owned_inputs)
}

/// A rewind can delete a note row while its reservation survives, leaving an input that
/// [`validate_owned_inputs`] no longer recognizes yet another pending transaction still holds.
async fn reserved_by_another_transaction(
    transaction: &mut SqliteTransaction<'_, Sqlite>,
    account: u32,
    parsed: &ParsedTransaction,
) -> Result<bool> {
    for input in &parsed.inputs {
        let owner: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT owner_txid FROM active_pending_spend_inputs
            WHERE account = ?1 AND nullifier = ?2",
        )
        .bind(account)
        .bind(input)
        .fetch_optional(&mut **transaction)
        .await?;
        if owner.is_some_and(|txid| txid != parsed.txid) {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn claim_inputs(
    transaction: &mut SqliteTransaction<'_, Sqlite>,
    account: u32,
    parsed: &ParsedTransaction,
    owned_inputs: Vec<Vec<u8>>,
) -> Result<()> {
    for input in owned_inputs {
        let result = sqlx::query(
            "INSERT INTO pending_spend_inputs(account, nullifier, owner_txid, expiry_height)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(account, nullifier) DO UPDATE SET
                owner_txid = excluded.owner_txid,
                expiry_height = excluded.expiry_height
            WHERE pending_spend_inputs.owner_txid = excluded.owner_txid
                OR NOT EXISTS (
                    SELECT 1 FROM active_pending_spend_inputs active
                    WHERE active.account = pending_spend_inputs.account
                        AND active.nullifier = pending_spend_inputs.nullifier
                )",
        )
        .bind(account)
        .bind(input)
        .bind(&parsed.txid)
        .bind(parsed.expiry_height)
        .execute(&mut **transaction)
        .await?;
        ensure!(
            result.rows_affected() == 1,
            "Transaction input is reserved by another pending transaction"
        );
    }
    Ok(())
}

async fn record_pending_tx(
    transaction: &mut SqliteTransaction<'_, Sqlite>,
    account: u32,
    parsed: &ParsedTransaction,
    scanned_height: Option<u32>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO pending_txs(account, txid, height, expiry_height)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(account, txid) DO UPDATE SET
            height = excluded.height,
            expiry_height = excluded.expiry_height",
    )
    .bind(account)
    .bind(&parsed.txid)
    .bind(scanned_height.unwrap_or_default())
    .bind(parsed.expiry_height)
    .execute(&mut **transaction)
    .await
    .context("record pending transaction")?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        api::sync::Balance,
        budget::merge_pending_txs,
        db::{
            calculate_balance_breakdown, max_spendable, store_pending_tx,
            tests::{memory_db, set_pool_sync_height_for_account, ACCOUNT},
        },
        pay::{
            plan::fetch_unspent_notes_by_pool,
            plan_tests::{BroadcastReply, ScriptedServer, NU7_ACTIVATION},
            pool::NUM_POOLS,
        },
    };
    use proptest::{
        strategy::{Strategy, ValueTree},
        test_runner::TestRunner,
    };
    use zcash_primitives::transaction::{
        components::{orchard::testing as orchard_testing, sapling::testing as sapling_testing},
        TxVersion,
    };
    use zcash_protocol::value::Zatoshis;
    use zcash_transparent::{
        address::Script,
        bundle::{Authorized as TransparentAuthorized, Bundle, OutPoint, TxIn},
    };

    const NOTE: [u8; 4] = [1, 2, 3, 4];

    async fn set_sync_height(connection: &mut SqliteConnection, account: u32, height: u32) {
        for pool in 0..NUM_POOLS as u8 {
            set_pool_sync_height_for_account(connection, account, pool, height).await;
        }
    }

    async fn insert_note(
        connection: &mut SqliteConnection,
        account: u32,
        nullifier: &[u8],
        value: u64,
        height: u32,
    ) {
        sqlx::query(
            "INSERT INTO notes(height, account, pool, scope, nullifier, tx, value)
            VALUES (?1, ?2, 1, 0, ?3, 0, ?4)",
        )
        .bind(height)
        .bind(account)
        .bind(nullifier)
        .bind(value as i64)
        .execute(connection)
        .await
        .expect("note");
    }

    /// What a rewind does to a reserved input: the note row goes, the reservation stays.
    async fn rewind_notes(connection: &mut SqliteConnection, account: u32) {
        sqlx::query("DELETE FROM notes WHERE account = ?1")
            .bind(account)
            .execute(connection)
            .await
            .expect("rewind");
    }

    async fn pending_row_counts(connection: &mut SqliteConnection, account: u32) -> (i64, i64) {
        let inputs =
            sqlx::query_scalar("SELECT COUNT(*) FROM pending_spend_inputs WHERE account = ?1")
                .bind(account)
                .fetch_one(&mut *connection)
                .await
                .expect("pending_spend_inputs");
        let txs = sqlx::query_scalar("SELECT COUNT(*) FROM pending_txs WHERE account = ?1")
            .bind(account)
            .fetch_one(&mut *connection)
            .await
            .expect("pending_txs");
        (inputs, txs)
    }

    fn parsed(txid: u8, expiry_height: u32) -> ParsedTransaction {
        ParsedTransaction {
            txid: vec![txid; 32],
            expiry_height,
            inputs: vec![NOTE.to_vec()],
            branch: Some(BranchId::Nu6_3),
        }
    }

    fn draw<S: Strategy>(strategy: &S, runner: &mut TestRunner) -> S::Value {
        strategy.new_tree(runner).expect("strategy value").current()
    }

    fn serialize(tx_data: TransactionData<Authorized>) -> Vec<u8> {
        let tx = tx_data.freeze().expect("freeze transaction");
        let mut bytes = Vec::new();
        tx.write(&mut bytes).expect("serialize transaction");
        bytes
    }

    fn transparent_spend() -> (Bundle<TransparentAuthorized>, Vec<u8>) {
        let bundle = Bundle {
            vin: vec![TxIn::from_parts(
                OutPoint::new([1; 32], 0),
                Script::default(),
                u32::MAX,
            )],
            vout: vec![],
            authorization: TransparentAuthorized,
        };
        let mut input = Vec::new();
        bundle.vin[0]
            .prevout()
            .write(&mut input)
            .expect("serialize outpoint");
        (bundle, input)
    }

    fn transparent_v6_transaction(branch: BranchId) -> (Vec<u8>, Vec<u8>) {
        let (bundle, input) = transparent_spend();
        let raw = serialize(TransactionData::<Authorized>::from_parts_v6(
            branch,
            0,
            0u32.into(),
            Zatoshis::ZERO,
            Some(bundle),
            None,
            None,
            None,
        ));
        (raw, input)
    }

    pub(crate) fn transparent_transaction() -> (Vec<u8>, Vec<u8>) {
        transparent_v6_transaction(BranchId::Nu6_3)
    }

    #[test]
    fn parse_transaction_invalid_bytes_returns_error() {
        assert!(parse_transaction(&[0; 32]).is_err());
    }

    #[test]
    fn parse_transaction_transparent_spend_returns_serialized_outpoint() {
        let (raw, expected) = transparent_transaction();

        assert!(parse_transaction(&raw)
            .expect("parse")
            .inputs
            .contains(&expected));
    }

    #[tokio::test]
    async fn reserve_transaction_internal_txid_joins_mined_metadata() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        let (raw, input) = transparent_transaction();
        let parsed = parse_transaction(&raw).expect("parse");
        insert_note(&mut connection, ACCOUNT, &input, 50, 80).await;
        reserve_transaction(&mut connection, ACCOUNT, &raw, OwnInputs::Required)
            .await
            .expect("reserve");
        let mut display_txid = parsed.txid.clone();
        display_txid.reverse();
        store_pending_tx(
            &mut connection,
            ACCOUNT,
            100,
            &display_txid,
            Some(2.5),
            Some(7),
        )
        .await
        .expect("metadata");
        sqlx::query(
            "INSERT INTO transactions(id_tx, txid, height, account, time, value, fee)
            VALUES (1, ?1, 101, ?2, 1, -1, 1)",
        )
        .bind(&parsed.txid)
        .bind(ACCOUNT)
        .execute(&mut connection)
        .await
        .expect("mined transaction");

        merge_pending_txs(&mut connection, ACCOUNT, 101)
            .await
            .expect("merge metadata");

        let metadata: (f64, u32) =
            sqlx::query_as("SELECT price, category FROM transactions WHERE id_tx = 1")
                .fetch_one(&mut connection)
                .await
                .expect("merged metadata");
        assert_eq!(metadata, (2.5, 7));
    }

    #[test]
    fn parse_transaction_nu7_transparent_spend_returns_serialized_outpoint() {
        let (raw, expected) = transparent_v6_transaction(BranchId::Nu7);

        assert!(parse_transaction(&raw)
            .expect("parse")
            .inputs
            .contains(&expected));
    }

    #[test]
    fn parse_transaction_zsa_transparent_spend_returns_serialized_outpoint() {
        let (bundle, expected) = transparent_spend();
        let raw = serialize(TransactionData::<Authorized>::from_parts_zsa(
            BranchId::Zsa,
            0,
            0u32.into(),
            Zatoshis::ZERO,
            Some(bundle),
            None,
            None,
            None,
        ));

        assert!(parse_transaction(&raw)
            .expect("parse")
            .inputs
            .contains(&expected));
    }

    #[test]
    fn parse_transaction_sapling_spend_returns_nullifier() {
        let mut runner = TestRunner::deterministic();
        let strategy = sapling_testing::arb_bundle_for_version(TxVersion::V6);
        let bundle = loop {
            if let Some(bundle) = draw(&strategy, &mut runner) {
                if !bundle.shielded_spends().is_empty() {
                    break bundle;
                }
            }
        };
        let expected = bundle.shielded_spends()[0].nullifier().to_vec();
        let raw = serialize(TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            0,
            0u32.into(),
            Zatoshis::ZERO,
            None,
            Some(bundle),
            None,
            None,
        ));

        assert!(parse_transaction(&raw)
            .expect("parse")
            .inputs
            .contains(&expected));
    }

    #[test]
    fn parse_transaction_orchard_spend_returns_nullifier() {
        let mut runner = TestRunner::deterministic();
        let strategy = orchard_testing::arb_bundle_for_branch(TxVersion::V6, BranchId::Nu6_3);
        let bundle = loop {
            match draw(&strategy, &mut runner) {
                Some(OrchardBundle::OrchardVanilla(bundle)) if bundle.flags().spends_enabled() => {
                    break bundle;
                }
                _ => {}
            }
        };
        let expected = bundle.actions()[0].nullifier().to_bytes().to_vec();
        let raw = serialize(TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            0,
            0u32.into(),
            Zatoshis::ZERO,
            None,
            None,
            Some(bundle),
            None,
        ));

        assert!(parse_transaction(&raw)
            .expect("parse")
            .inputs
            .contains(&expected));
    }

    #[test]
    fn parse_transaction_ironwood_spend_returns_nullifier() {
        let mut runner = TestRunner::deterministic();
        let strategy =
            orchard_testing::arb_ironwood_bundle_for_branch(TxVersion::V6, BranchId::Nu6_3);
        let bundle = loop {
            if let Some(bundle) = draw(&strategy, &mut runner) {
                if bundle.flags().spends_enabled() {
                    break bundle;
                }
            }
        };
        let expected = bundle.actions()[0].nullifier().to_bytes().to_vec();
        let raw = serialize(TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
            0,
            0u32.into(),
            Zatoshis::ZERO,
            None,
            None,
            None,
            Some(bundle),
        ));

        assert!(parse_transaction(&raw)
            .expect("parse")
            .inputs
            .contains(&expected));
    }

    #[tokio::test]
    async fn reserve_transaction_owned_note_moves_available_to_locked() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;

        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Required,
        )
        .await
        .expect("reserve");
        let balance = calculate_balance_breakdown(&mut connection, ACCOUNT, 10)
            .await
            .expect("balance");

        assert_eq!(
            balance.0[1],
            Balance {
                available: 0,
                locked: 50,
                change_pending: 0,
                value_pending: 0,
            }
        );
        assert_eq!(balance.0[1].available + balance.0[1].locked, 50);
        assert_eq!(
            max_spendable(&mut connection, ACCOUNT).await.expect("max"),
            0
        );
        assert!(fetch_unspent_notes_by_pool(&mut connection, ACCOUNT)
            .await
            .expect("notes")[1]
            .is_empty());
    }

    #[tokio::test]
    async fn max_spendable_unconfirmed_note_excludes_value() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 91).await;

        assert_eq!(
            max_spendable(&mut connection, ACCOUNT).await.expect("max"),
            0
        );
    }

    #[tokio::test]
    async fn reserve_transaction_same_owner_is_idempotent_foreign_owner_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;

        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Required,
        )
        .await
        .expect("first reserve");
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Required,
        )
        .await
        .expect("idempotent reserve");
        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(2, 120),
            OwnInputs::Required,
        )
        .await
        .expect_err("foreign owner must fail");

        assert!(error.to_string().contains("reserved by another"));
        let owner: Vec<u8> = sqlx::query_scalar(
            "SELECT owner_txid FROM pending_spend_inputs WHERE account = ?1 AND nullifier = ?2",
        )
        .bind(ACCOUNT)
        .bind(&NOTE[..])
        .fetch_one(&mut connection)
        .await
        .expect("owner");
        assert_eq!(owner, vec![1; 32]);
    }

    #[tokio::test]
    async fn reserve_transaction_expiry_and_rewind_toggle_spendability() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 101),
            OwnInputs::Required,
        )
        .await
        .expect("reserve");

        let before_expiry = calculate_balance_breakdown(&mut connection, ACCOUNT, 0)
            .await
            .expect("before expiry");
        set_sync_height(&mut connection, ACCOUNT, 101).await;
        let at_expiry = calculate_balance_breakdown(&mut connection, ACCOUNT, 0)
            .await
            .expect("at expiry");
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        let after_rewind = calculate_balance_breakdown(&mut connection, ACCOUNT, 0)
            .await
            .expect("after rewind");

        assert_eq!(before_expiry.0[1].locked, 50);
        assert_eq!(at_expiry.0[1].available, 50);
        assert_eq!(after_rewind.0[1].locked, 50);
    }

    #[tokio::test]
    async fn reserve_transaction_rescan_same_nullifier_restores_lock() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Required,
        )
        .await
        .expect("reserve");
        sqlx::query("DELETE FROM notes WHERE account = ?1")
            .bind(ACCOUNT)
            .execute(&mut connection)
            .await
            .expect("reset notes");
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;

        let balance = calculate_balance_breakdown(&mut connection, ACCOUNT, 0)
            .await
            .expect("balance after rescan");

        assert_eq!(balance.0[1].locked, 50);
        assert_eq!(balance.0[1].available, 0);
    }

    #[tokio::test]
    async fn reserve_transaction_zero_expiry_never_unlocks_by_height() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 0), OwnInputs::Required)
            .await
            .expect("reserve");
        set_sync_height(&mut connection, ACCOUNT, u32::MAX).await;

        let balance = calculate_balance_breakdown(&mut connection, ACCOUNT, 0)
            .await
            .expect("balance");

        assert_eq!(balance.0[1].locked, 50);
    }

    #[tokio::test]
    async fn reserve_transaction_wrong_account_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT + 1, &NOTE, 50, 80).await;

        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Required,
        )
        .await
        .expect_err("wrong account must fail");

        assert!(error.to_string().contains("another account"));
    }

    #[tokio::test]
    async fn reserve_transaction_no_owned_inputs_reserves_nothing_and_succeeds() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        let (raw, _) = transparent_transaction();

        reserve_transaction(&mut connection, ACCOUNT, &raw, OwnInputs::Optional)
            .await
            .expect("a transaction of unknown origin reserves nothing and succeeds");

        assert_eq!(pending_row_counts(&mut connection, ACCOUNT).await, (0, 0));
    }

    #[tokio::test]
    async fn reserve_transaction_no_owned_inputs_required_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        let (raw, _) = transparent_transaction();

        let error = reserve_transaction(&mut connection, ACCOUNT, &raw, OwnInputs::Required)
            .await
            .expect_err("an own send must still spend an owned input");

        assert!(error.to_string().contains("does not spend an input owned"));
    }

    #[tokio::test]
    async fn reserve_transaction_optional_other_account_input_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT + 1, &NOTE, 50, 80).await;

        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect_err("another account's input must still fail");

        assert!(error.to_string().contains("another account"));
    }

    #[tokio::test]
    async fn reserve_transaction_optional_locked_input_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        sqlx::query("UPDATE notes SET locked = TRUE WHERE account = ?1")
            .bind(ACCOUNT)
            .execute(&mut connection)
            .await
            .expect("lock note");

        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect_err("a locked input must still fail");

        assert!(error.to_string().contains("manually locked"));
    }

    #[tokio::test]
    async fn reserve_transaction_optional_input_spent_by_another_transaction_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        sqlx::query(
            "INSERT INTO transactions(id_tx, txid, height, account) VALUES (1, ?1, 90, ?2)",
        )
        .bind(vec![9u8; 32])
        .bind(ACCOUNT)
        .execute(&mut connection)
        .await
        .expect("mined transaction");
        sqlx::query(
            "INSERT INTO spends(id_note, height, account, pool, tx, value)
            SELECT id_note, 90, account, pool, 1, value FROM notes WHERE account = ?1",
        )
        .bind(ACCOUNT)
        .execute(&mut connection)
        .await
        .expect("spend");

        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect_err("an input spent by another transaction must still fail");

        assert!(error.to_string().contains("already spent"));
    }

    #[tokio::test]
    async fn reserve_transaction_optional_input_reserved_by_another_pending_tx_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect("first reserve");

        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(2, 120),
            OwnInputs::Optional,
        )
        .await
        .expect_err("an input held by another pending transaction must still fail");

        assert!(error.to_string().contains("reserved by another"));
    }

    /// `trim_sync_data` drops the note row on a rewind but keeps its reservation, so the
    /// still-reserved input now looks unknown.
    #[tokio::test]
    async fn reserve_transaction_optional_orphaned_reservation_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect("first reserve");
        rewind_notes(&mut connection, ACCOUNT).await;

        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(2, 120),
            OwnInputs::Optional,
        )
        .await
        .expect_err("a reservation must outlive the note row a rewind removed");

        assert!(error.to_string().contains("reserved by another"));
    }

    #[tokio::test]
    async fn reserve_transaction_optional_orphaned_own_reservation_is_idempotent() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect("first reserve");
        rewind_notes(&mut connection, ACCOUNT).await;

        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect("rebroadcasting the very same transaction must stay idempotent");
    }

    /// The reservation expires at 90 while the account syncs past it, so it no longer holds
    /// the input and must not refuse an unrelated transaction.
    #[tokio::test]
    async fn reserve_transaction_optional_expired_orphaned_reservation_does_not_block() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 50).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 40).await;
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 90),
            OwnInputs::Optional,
        )
        .await
        .expect("first reserve");
        rewind_notes(&mut connection, ACCOUNT).await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;

        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(2, 120),
            OwnInputs::Optional,
        )
        .await
        .expect("an expired reservation must not block a transaction of unknown origin");
    }

    /// No note is inserted: the expiry check sits above the ownership branch, so even a
    /// transaction whose inputs are unknown is refused once it has expired.
    #[tokio::test]
    async fn reserve_transaction_optional_expired_transaction_is_rejected() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;

        let error = reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 100),
            OwnInputs::Optional,
        )
        .await
        .expect_err("an expired transaction must still fail");

        assert!(error.to_string().contains("expired"));
    }

    /// `raw` spends this account's note, is reserved and sent with the chain at `tips`.
    async fn send_at_tips(
        connection: &mut SqliteConnection,
        (raw, input): (Vec<u8>, Vec<u8>),
        tips: &[u32],
        reply: BroadcastReply,
    ) -> Result<BroadcastOutcome> {
        set_sync_height(connection, ACCOUNT, 100).await;
        insert_note(connection, ACCOUNT, &input, 50_000, 80).await;
        let mut client = ScriptedServer::new(tips, reply).client();
        reserve_and_send(
            &Network::Main,
            connection,
            &mut client,
            ACCOUNT,
            100,
            &raw,
            OwnInputs::Required,
        )
        .await
    }

    /// The first tip at which NU6.3 is over by the whole reorg margin for the next block.
    const BRANCH_OVER_TIP: u32 = NU7_ACTIVATION + REORG_MARGIN - 1;

    /// An NU6.3 transaction with that branch over.
    async fn send_own_transaction(
        connection: &mut SqliteConnection,
        reply: BroadcastReply,
    ) -> Result<BroadcastOutcome> {
        send_at_tips(
            connection,
            transparent_transaction(),
            &[BRANCH_OVER_TIP],
            reply,
        )
        .await
    }

    async fn assert_branch_id_rejection_keeps_the_reservation(
        transaction: (Vec<u8>, Vec<u8>),
        tips: &[u32],
    ) {
        let mut connection = memory_db().await;

        let outcome = send_at_tips(
            &mut connection,
            transaction,
            tips,
            BroadcastReply::Verdict(-25, BRANCH_ID_REJECTION),
        )
        .await
        .expect("a verdict");

        assert!(!outcome.inputs_released, "tips {tips:?}");
        assert_eq!(
            pending_row_counts(&mut connection, ACCOUNT).await,
            (1, 1),
            "tips {tips:?}"
        );
    }

    #[tokio::test]
    async fn reserve_and_send_branch_still_current_keeps_the_reservation() {
        assert_branch_id_rejection_keeps_the_reservation(
            transparent_transaction(),
            &[NU7_ACTIVATION - 2],
        )
        .await;
        assert_branch_id_rejection_keeps_the_reservation(
            transparent_v6_transaction(BranchId::Nu7),
            &[NU7_ACTIVATION + 10],
        )
        .await;
    }

    // Reproduced on regtest: built ahead of the node, refused, then mined from Zebra's retry queue.
    #[tokio::test]
    async fn reserve_and_send_branch_ahead_of_the_node_keeps_the_reservation() {
        assert_branch_id_rejection_keeps_the_reservation(
            transparent_v6_transaction(BranchId::Nu7),
            &[NU7_ACTIVATION - 2],
        )
        .await;
    }

    #[tokio::test]
    async fn reserve_and_send_branch_ended_within_the_reorg_margin_keeps_the_reservation() {
        assert_branch_id_rejection_keeps_the_reservation(
            transparent_transaction(),
            &[BRANCH_OVER_TIP - 1],
        )
        .await;
    }

    #[tokio::test]
    async fn reserve_and_send_tip_unreadable_keeps_the_reservation() {
        assert_branch_id_rejection_keeps_the_reservation(transparent_transaction(), &[]).await;
    }

    #[test]
    fn parse_transaction_records_the_branch_of_v5_and_v6_only() {
        let older_format = |version, branch| {
            let (bundle, _) = transparent_spend();
            serialize(TransactionData::<Authorized>::from_parts(
                version,
                branch,
                0,
                0u32.into(),
                Zatoshis::ZERO,
                Some(bundle),
                None,
                None,
                None,
            ))
        };
        let branch_of = |raw: &[u8]| parse_transaction(raw).expect("parse").branch;

        assert_eq!(
            branch_of(&older_format(TxVersion::V4, BranchId::Canopy)),
            None
        );
        assert_eq!(
            branch_of(&older_format(TxVersion::V5, BranchId::Nu6)),
            Some(BranchId::Nu6)
        );
        assert_eq!(
            branch_of(&transparent_v6_transaction(BranchId::Nu7).0),
            Some(BranchId::Nu7)
        );
    }

    const BRANCH_ID_REJECTION: &str = "failed to validate tx: WtxId(\"private\"), error: \
        transaction did not pass consensus validation: \
        transaction uses an incorrect consensus branch id";

    #[tokio::test]
    async fn reserve_and_send_incorrect_branch_id_releases_the_inputs_for_the_next_plan() {
        for message in [BRANCH_ID_REJECTION, "INCORRECT CONSENSUS BRANCH ID"] {
            let mut connection = memory_db().await;

            let outcome =
                send_own_transaction(&mut connection, BroadcastReply::Verdict(-25, message))
                    .await
                    .expect("a verdict");

            assert!(outcome.inputs_released, "{message}");
            assert_eq!(outcome.error_code, -25);
            assert_eq!(pending_row_counts(&mut connection, ACCOUNT).await, (0, 0));
            assert_eq!(
                fetch_unspent_notes_by_pool(&mut connection, ACCOUNT)
                    .await
                    .expect("notes")[1]
                    .len(),
                1
            );
        }
    }

    async fn assert_nonzero_verdict_keeps_the_reservation(message: &'static str) {
        let mut connection = memory_db().await;

        let outcome = send_own_transaction(&mut connection, BroadcastReply::Verdict(-25, message))
            .await
            .expect("a verdict");

        assert!(!outcome.inputs_released, "{message}");
        assert_eq!(
            pending_row_counts(&mut connection, ACCOUNT).await,
            (1, 1),
            "{message}"
        );
    }

    #[tokio::test]
    async fn reserve_and_send_unknown_rejection_text_keeps_the_reservation() {
        for message in [
            "something this wallet has never seen",
            "failed to validate tx: bad anchor",
        ] {
            assert_nonzero_verdict_keeps_the_reservation(message).await;
        }
    }

    #[tokio::test]
    async fn reserve_and_send_mempool_disabled_keeps_the_reservation() {
        assert_nonzero_verdict_keeps_the_reservation(
            "mempool is disabled since synchronization is behind the chain tip",
        )
        .await;
    }

    #[tokio::test]
    async fn reserve_and_send_transaction_already_known_keeps_the_reservation() {
        for message in [
            "transaction dropped because it is already in the mempool",
            "18: txn-already-in-mempool",
            "transaction was committed to the best chain",
        ] {
            assert_nonzero_verdict_keeps_the_reservation(message).await;
        }
    }

    #[tokio::test]
    async fn reserve_and_send_transport_failure_keeps_the_reservation() {
        let mut connection = memory_db().await;

        send_own_transaction(&mut connection, BroadcastReply::TransportFailure)
            .await
            .expect_err("the bytes may have left");

        assert_eq!(pending_row_counts(&mut connection, ACCOUNT).await, (1, 1));
    }

    #[tokio::test]
    async fn reserve_and_send_accepted_keeps_the_reservation() {
        let mut connection = memory_db().await;

        let outcome = send_own_transaction(&mut connection, BroadcastReply::Verdict(0, "ok"))
            .await
            .expect("a verdict");

        assert!(!outcome.inputs_released);
        assert_eq!(pending_row_counts(&mut connection, ACCOUNT).await, (1, 1));
    }

    #[tokio::test]
    async fn reserve_and_send_optional_without_own_inputs_rejected_deletes_nothing() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;
        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Required,
        )
        .await
        .expect("another transaction's reservation");
        let (raw, _) = transparent_transaction();
        let mut client = ScriptedServer::new(
            &[BRANCH_OVER_TIP],
            BroadcastReply::Verdict(-25, BRANCH_ID_REJECTION),
        )
        .client();

        let outcome = reserve_and_send(
            &Network::Main,
            &mut connection,
            &mut client,
            ACCOUNT,
            100,
            &raw,
            OwnInputs::Optional,
        )
        .await
        .expect("a verdict");

        assert!(!outcome.inputs_released);
        assert_eq!(pending_row_counts(&mut connection, ACCOUNT).await, (1, 1));
    }

    #[tokio::test]
    async fn reserve_transaction_optional_owned_input_reserves_and_records() {
        let mut connection = memory_db().await;
        set_sync_height(&mut connection, ACCOUNT, 100).await;
        insert_note(&mut connection, ACCOUNT, &NOTE, 50, 80).await;

        reserve_parsed_transaction(
            &mut connection,
            ACCOUNT,
            &parsed(1, 120),
            OwnInputs::Optional,
        )
        .await
        .expect("an owned input reserves as usual");

        assert_eq!(pending_row_counts(&mut connection, ACCOUNT).await, (1, 1));
    }
}
