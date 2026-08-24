use anyhow::{ensure, Context as _, Result};
use sqlx::{Connection as _, Row, Sqlite, SqliteConnection, Transaction as SqliteTransaction};
use zcash_primitives::transaction::{Authorized, OrchardBundle, Transaction, TransactionData};
use zcash_protocol::consensus::BranchId;

use crate::db::get_sync_height;
use crate::{net::BroadcastOutcome, Client};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedTransaction {
    pub txid: Vec<u8>,
    pub expiry_height: u32,
    pub inputs: Vec<Vec<u8>>,
}

pub(crate) fn parse_transaction(raw: &[u8]) -> Result<ParsedTransaction> {
    for branch in [
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
    let inputs = transaction_inputs(&tx.into_data());
    ParsedTransaction {
        txid,
        expiry_height,
        inputs,
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

pub async fn reserve_transaction(
    connection: &mut SqliteConnection,
    account: u32,
    raw: &[u8],
) -> Result<()> {
    let parsed = parse_transaction(raw)?;
    reserve_parsed_transaction(connection, account, &parsed).await
}

pub async fn reserve_and_send(
    connection: &mut SqliteConnection,
    client: &mut Client,
    account: u32,
    height: u32,
    raw: &[u8],
) -> Result<BroadcastOutcome> {
    reserve_transaction(connection, account, raw).await?;
    crate::pay::send(client, height, raw).await
}

async fn reserve_parsed_transaction(
    connection: &mut SqliteConnection,
    account: u32,
    parsed: &ParsedTransaction,
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
    ensure!(
        !owned_inputs.is_empty(),
        "Transaction does not spend an input owned by account {account}"
    );
    Ok(owned_inputs)
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
mod tests {
    use super::*;
    use crate::{
        api::sync::Balance,
        budget::merge_pending_txs,
        db::{
            calculate_balance_breakdown, max_spendable, store_pending_tx,
            tests::{memory_db, set_pool_sync_height_for_account, ACCOUNT},
        },
        pay::{plan::fetch_unspent_notes_by_pool, pool::NUM_POOLS},
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

    fn parsed(txid: u8, expiry_height: u32) -> ParsedTransaction {
        ParsedTransaction {
            txid: vec![txid; 32],
            expiry_height,
            inputs: vec![NOTE.to_vec()],
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

    fn transparent_transaction() -> (Vec<u8>, Vec<u8>) {
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
        let raw = serialize(TransactionData::<Authorized>::from_parts_v6(
            BranchId::Nu6_3,
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
        reserve_transaction(&mut connection, ACCOUNT, &raw)
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

        reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 120))
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

        reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 120))
            .await
            .expect("first reserve");
        reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 120))
            .await
            .expect("idempotent reserve");
        let error = reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(2, 120))
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
        reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 101))
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
        reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 120))
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
        reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 0))
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

        let error = reserve_parsed_transaction(&mut connection, ACCOUNT, &parsed(1, 120))
            .await
            .expect_err("wrong account must fail");

        assert!(error.to_string().contains("another account"));
    }
}
