//! `plan_transaction` end to end: a real database and builder, a scripted server.
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use anyhow::Result;
use pczt::Pczt;
use sqlx::SqliteConnection;
use tokio_stream::wrappers::ReceiverStream;
use tonic::async_trait;
use zcash_primitives::transaction::Transaction;

use crate::account::{
    get_account_full_address,
    tests::{restore, TEST_PHRASE},
};
use crate::api::coin::Network;
use crate::api::pay::{MaxSendable, PaymentOptions, PcztPackage};
use crate::db::tests::{memory_db, set_pool_sync_height_for_account};
use crate::lwd::CompactBlock;
use crate::net::{BroadcastOutcome, LwdServer};
use crate::pay::plan::{max_sendable, plan_transaction};
use crate::pay::pool::{ALL_POOLS, NUM_POOLS};
use crate::pay::{Recipient, TxPlan};
use crate::Client;

pub(crate) const NU7_ACTIVATION: u32 = 3_543_405;
const NU6_3_ACTIVATION: u32 = 3_428_143;
const NU6_3_BRANCH: u32 = 0x37a5_165b;
const NU7_BRANCH: u32 = 0x77190ad9;
const NU7_EXPIRY_DELTA: u32 = 120;
const LAST_LEGACY_TARGET: u32 = 3_589_999;
const FIRST_REDUCED_TARGET: u32 = 3_590_000;

#[derive(Clone)]
pub(crate) enum BroadcastReply {
    Verdict(i32, &'static str),
    TransportFailure,
}

/// Reports heights from a script, its last entry repeating, and answers a broadcast as told.
#[derive(Clone)]
pub(crate) struct ScriptedServer {
    heights: Arc<Mutex<VecDeque<u32>>>,
    height_reads: Arc<AtomicUsize>,
    reply: BroadcastReply,
}

impl ScriptedServer {
    pub(crate) fn new(heights: &[u32], reply: BroadcastReply) -> Self {
        Self {
            heights: Arc::new(Mutex::new(heights.iter().copied().collect())),
            height_reads: Arc::new(AtomicUsize::new(0)),
            reply,
        }
    }

    pub(crate) fn client(&self) -> Client {
        Box::new(self.clone())
    }

    fn height_reads(&self) -> usize {
        self.height_reads.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl LwdServer for ScriptedServer {
    fn duplicate(&self) -> Client {
        self.client()
    }

    async fn latest_height(&mut self) -> Result<u32> {
        self.height_reads.fetch_add(1, Ordering::SeqCst);
        let mut heights = self.heights.lock().unwrap();
        if heights.len() > 1 {
            return Ok(heights.pop_front().expect("scripted height"));
        }
        heights
            .front()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("height unavailable"))
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
        match &self.reply {
            BroadcastReply::Verdict(code, message) => Ok(BroadcastOutcome {
                error_code: *code,
                message: message.to_string(),
                inputs_released: false,
            }),
            BroadcastReply::TransportFailure => anyhow::bail!("connection reset"),
        }
    }

    type TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
    async fn taddress_txs(
        &mut self,
        _network: &Network,
        _taddress: &str,
        _start: u32,
        _end: u32,
    ) -> Result<Self::TransactionStream> {
        unimplemented!()
    }

    type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
    async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
        unimplemented!()
    }

    async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        Ok((vec![], vec![], vec![]))
    }

    async fn chain_anchor(&mut self, _height: u32) -> Result<Vec<u8>> {
        unimplemented!()
    }
}

/// A restored mainnet account synced to `height`, holding one transparent note per value.
async fn funded_account(connection: &mut SqliteConnection, height: u32, values: &[u64]) -> u32 {
    let account = restore(connection, TEST_PHRASE, 0, None)
        .await
        .expect("restore");
    for pool in 0..NUM_POOLS as u8 {
        set_pool_sync_height_for_account(connection, account, pool, height).await;
    }
    sqlx::query("INSERT OR REPLACE INTO headers(height, hash, time) VALUES (?1, ?2, 0)")
        .bind(height)
        .bind(vec![0u8; 32])
        .execute(&mut *connection)
        .await
        .expect("header");
    let taddress: u32 = sqlx::query_scalar(
        "SELECT id_taddress FROM transparent_address_accounts
        WHERE account = ?1 AND scope = 0 AND dindex = 0",
    )
    .bind(account)
    .fetch_one(&mut *connection)
    .await
    .expect("transparent address");
    for (index, value) in values.iter().enumerate() {
        let mut outpoint = vec![index as u8 + 1; 32];
        outpoint.extend_from_slice(&0u32.to_le_bytes());
        sqlx::query(
            "INSERT INTO notes(height, account, pool, nullifier, tx, value, taddress)
            VALUES (?1, ?2, 0, ?3, 0, ?4, ?5)",
        )
        .bind(height)
        .bind(account)
        .bind(outpoint)
        .bind(*value as i64)
        .bind(taddress)
        .execute(&mut *connection)
        .await
        .expect("note");
    }
    account
}

async fn transparent_recipient(connection: &mut SqliteConnection, account: u32) -> String {
    sqlx::query_scalar(
        "SELECT address FROM transparent_address_accounts
        WHERE account = ?1 AND scope = 0 AND dindex = 0",
    )
    .bind(account)
    .fetch_one(connection)
    .await
    .expect("address")
}

async fn shielded_recipient(connection: &mut SqliteConnection, account: u32) -> String {
    get_account_full_address(&Network::Main, connection, account, 0, 0)
        .await
        .expect("unified address")
}

struct Payment {
    address: String,
    amount: u64,
    recipient_pays_fee: bool,
    hardware_signing: bool,
}

impl Payment {
    fn to(address: String, amount: u64) -> Self {
        Self {
            address,
            amount,
            recipient_pays_fee: false,
            hardware_signing: false,
        }
    }
}

async fn plan(
    connection: &mut SqliteConnection,
    server: &ScriptedServer,
    account: u32,
    payment: Payment,
) -> Result<PcztPackage> {
    let recipient = Recipient {
        address: payment.address,
        amount: payment.amount,
        ..Recipient::default()
    };
    plan_transaction(
        &Network::Main,
        connection,
        &mut server.client(),
        account,
        ALL_POOLS,
        &[recipient],
        payment.recipient_pays_fee,
        Some(0),
        false,
        None,
        None,
        false,
        None,
        None,
        payment.hardware_signing,
        false,
    )
    .await
}

fn silent_server(heights: &[u32]) -> ScriptedServer {
    ScriptedServer::new(heights, BroadcastReply::Verdict(0, "accepted"))
}

fn fee_of(package: &PcztPackage) -> u64 {
    TxPlan::from_package(&Network::Main, package)
        .expect("plan")
        .fee
}

fn header_of(package: &PcztPackage) -> (u32, u32, u32) {
    let pczt = Pczt::parse(&package.pczt).expect("pczt");
    let global = pczt.global();
    (
        *global.consensus_branch_id(),
        *global.tx_version(),
        *global.expiry_height(),
    )
}

#[tokio::test]
async fn plan_transaction_tip_is_last_block_before_nu7_builds_for_nu7() {
    let tip = NU7_ACTIVATION - 1;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[50_000]).await;
    let address = transparent_recipient(&mut connection, account).await;

    let package = plan(
        &mut connection,
        &silent_server(&[tip]),
        account,
        Payment::to(address, 10_000),
    )
    .await
    .expect("plan");

    assert_eq!(
        header_of(&package),
        (NU7_BRANCH, 6, NU7_ACTIVATION + NU7_EXPIRY_DELTA)
    );
}

#[tokio::test]
async fn plan_transaction_tip_is_last_block_before_nu6_3_pays_the_ua_on_ironwood() {
    let tip = NU6_3_ACTIVATION - 1;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[50_000]).await;
    let address = shielded_recipient(&mut connection, account).await;

    let package = plan(
        &mut connection,
        &silent_server(&[tip]),
        account,
        Payment::to(address, 10_000),
    )
    .await
    .expect("plan");

    assert_eq!(header_of(&package).0, NU6_3_BRANCH);
    let plan = TxPlan::from_package(&Network::Main, &package).expect("plan");
    assert!(plan
        .outputs
        .iter()
        .any(|output| output.pool == 3 && output.amount == 10_000));
}

#[tokio::test]
async fn plan_transaction_hardware_signing_tip_is_last_block_before_nu7_builds_v5_for_nu7() {
    let tip = NU7_ACTIVATION - 1;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[50_000]).await;
    let address = transparent_recipient(&mut connection, account).await;

    let package = plan(
        &mut connection,
        &silent_server(&[tip]),
        account,
        Payment {
            hardware_signing: true,
            ..Payment::to(address, 10_000)
        },
    )
    .await
    .expect("plan");

    assert_eq!(
        header_of(&package),
        (NU7_BRANCH, 5, NU7_ACTIVATION + NU7_EXPIRY_DELTA)
    );
}

#[tokio::test]
async fn plan_transaction_height_grows_past_the_fee_boundary_reads_it_once() {
    // (scripted reads, expected fee, expected target)
    let cases: [(&[u32], u64, u32); 2] = [
        (
            &[LAST_LEGACY_TARGET - 1, LAST_LEGACY_TARGET],
            10_000,
            LAST_LEGACY_TARGET,
        ),
        (
            &[FIRST_REDUCED_TARGET - 1, FIRST_REDUCED_TARGET],
            2_000,
            FIRST_REDUCED_TARGET,
        ),
    ];
    for (heights, expected_fee, target) in cases {
        let mut connection = memory_db().await;
        let account = funded_account(&mut connection, heights[0], &[50_000]).await;
        let address = transparent_recipient(&mut connection, account).await;
        let server = silent_server(heights);

        let package = plan(
            &mut connection,
            &server,
            account,
            Payment::to(address, 10_000),
        )
        .await
        .expect("plan");

        assert_eq!(server.height_reads(), 1, "{heights:?}");
        assert_eq!(fee_of(&package), expected_fee, "{heights:?}");
        assert_eq!(
            header_of(&package).2,
            target + NU7_EXPIRY_DELTA,
            "{heights:?}"
        );
    }
}

#[tokio::test]
async fn plan_transaction_hardware_signing_with_ironwood_recipient_explains_the_refusal() {
    let tip = NU7_ACTIVATION + 10;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[50_000]).await;
    let address = shielded_recipient(&mut connection, account).await;

    let Err(error) = plan(
        &mut connection,
        &silent_server(&[tip]),
        account,
        Payment {
            hardware_signing: true,
            ..Payment::to(address, 10_000)
        },
    )
    .await
    else {
        panic!("a v5 transaction cannot carry Ironwood");
    };

    assert_eq!(
        error.to_string(),
        "Hardware signing cannot spend or receive Ironwood funds"
    );
}

#[tokio::test]
async fn plan_transaction_software_account_with_ironwood_recipient_still_builds() {
    let tip = NU7_ACTIVATION + 10;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[50_000]).await;
    let address = shielded_recipient(&mut connection, account).await;

    plan(
        &mut connection,
        &silent_server(&[tip]),
        account,
        Payment::to(address, 10_000),
    )
    .await
    .expect("the refusal is only for v5");
}

async fn quote_max(
    connection: &mut SqliteConnection,
    server: &ScriptedServer,
    account: u32,
    address: String,
) -> MaxSendable {
    let recipient = Recipient {
        address,
        ..Recipient::default()
    };
    let options = PaymentOptions {
        src_pools: ALL_POOLS,
        recipient_pays_fee: false,
        smart_transparent: false,
        confirmations: 0,
        category: None,
        hardware_signing: false,
        external_pczt_signing: false,
    };
    max_sendable(
        &Network::Main,
        connection,
        &mut server.client(),
        account,
        &recipient,
        &options,
    )
    .await
    .expect("max")
}

/// Output and input values, without the zero-value padding of a shielded bundle.
fn paid_outputs_and_inputs(package: &PcztPackage) -> (Vec<u64>, Vec<u64>) {
    let plan = TxPlan::from_package(&Network::Main, package).expect("plan");
    let outputs = plan.outputs.iter().map(|output| output.amount);
    let inputs = plan.inputs.iter().filter_map(|input| input.amount);
    (
        outputs.filter(|&amount| amount > 0).collect(),
        inputs.filter(|&amount| amount > 0).collect(),
    )
}

async fn send_everything(
    connection: &mut SqliteConnection,
    server: &ScriptedServer,
    account: u32,
    address: String,
    max: &MaxSendable,
) -> PcztPackage {
    plan(
        connection,
        server,
        account,
        Payment {
            recipient_pays_fee: true,
            ..Payment::to(address, max.amount + max.fee)
        },
    )
    .await
    .expect("plan")
}

// This is why a max send goes through recipient_pays_fee, not a plain plan for the amount.
#[tokio::test]
async fn plan_transaction_plain_plan_for_the_max_amount_strands_a_note_at_another_fee() {
    let tip = LAST_LEGACY_TARGET - 1;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[100_000, 5_000]).await;
    let address = shielded_recipient(&mut connection, account).await;
    let server = silent_server(&[tip]);

    let max = quote_max(&mut connection, &server, account, address.clone()).await;
    let package = plan(
        &mut connection,
        &server,
        account,
        Payment::to(address, max.amount),
    )
    .await
    .expect("plan");

    assert_eq!(
        max,
        MaxSendable {
            amount: 85_000,
            fee: 20_000
        }
    );
    assert_eq!(fee_of(&package), 15_000);
    assert_eq!(
        paid_outputs_and_inputs(&package),
        (vec![85_000], vec![100_000])
    );
}

#[tokio::test]
async fn max_sendable_shielded_recipient_send_spends_every_note_without_change() {
    let tip = LAST_LEGACY_TARGET - 1;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[100_000, 5_000]).await;
    let address = shielded_recipient(&mut connection, account).await;
    let server = silent_server(&[tip]);

    let max = quote_max(&mut connection, &server, account, address.clone()).await;
    let package = send_everything(&mut connection, &server, account, address, &max).await;

    assert_eq!(fee_of(&package), max.fee);
    let (outputs, mut inputs) = paid_outputs_and_inputs(&package);
    inputs.sort_unstable();
    assert_eq!((outputs, inputs), (vec![max.amount], vec![5_000, 100_000]));
}

#[tokio::test]
async fn max_sendable_transparent_recipient_send_spends_every_note_without_change() {
    let tip = LAST_LEGACY_TARGET - 1;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[100_000, 20_000, 7_000]).await;
    let address = transparent_recipient(&mut connection, account).await;
    let server = silent_server(&[tip]);

    let max = quote_max(&mut connection, &server, account, address.clone()).await;
    let package = send_everything(&mut connection, &server, account, address, &max).await;

    assert_eq!(
        max,
        MaxSendable {
            amount: 112_000,
            fee: 15_000
        }
    );
    assert_eq!(fee_of(&package), max.fee);
    let (outputs, mut inputs) = paid_outputs_and_inputs(&package);
    inputs.sort_unstable();
    assert_eq!(
        (outputs, inputs),
        (vec![112_000], vec![7_000, 20_000, 100_000])
    );
}

#[tokio::test]
async fn max_sendable_dust_floor_follows_the_target_height() {
    // (tip, notes, expected)
    let cases: [(u32, &[u64], MaxSendable); 2] = [
        (
            LAST_LEGACY_TARGET - 1,
            &[50_000, 4_999, 5_000],
            MaxSendable {
                amount: 45_000,
                fee: 10_000,
            },
        ),
        (
            FIRST_REDUCED_TARGET - 1,
            &[50_000, 999, 1_000],
            MaxSendable {
                amount: 49_000,
                fee: 2_000,
            },
        ),
    ];
    for (tip, notes, expected) in cases {
        let mut connection = memory_db().await;
        let account = funded_account(&mut connection, tip, notes).await;
        let address = transparent_recipient(&mut connection, account).await;
        let server = silent_server(&[tip]);

        let max = quote_max(&mut connection, &server, account, address).await;

        assert_eq!(max, expected, "tip {tip}");
    }
}

#[tokio::test]
async fn max_sendable_balance_below_the_fee_quotes_zero() {
    let tip = LAST_LEGACY_TARGET - 1;
    for notes in [&[][..], &[6_000][..]] {
        let mut connection = memory_db().await;
        let account = funded_account(&mut connection, tip, notes).await;
        let address = transparent_recipient(&mut connection, account).await;
        let server = silent_server(&[tip]);

        let max = quote_max(&mut connection, &server, account, address).await;

        assert_eq!(max, MaxSendable { amount: 0, fee: 0 }, "{notes:?}");
    }
}

async fn change_indices(connection: &mut SqliteConnection, account: u32) -> Vec<u32> {
    sqlx::query_scalar(
        "SELECT dindex FROM transparent_address_accounts
        WHERE account = ?1 AND scope = 1 ORDER BY dindex",
    )
    .bind(account)
    .fetch_all(connection)
    .await
    .expect("change indices")
}

#[tokio::test]
async fn max_sendable_repeated_quotes_do_not_grow_the_change_indices() {
    let tip = LAST_LEGACY_TARGET - 1;
    let mut connection = memory_db().await;
    let account = funded_account(&mut connection, tip, &[100_000]).await;
    let address = transparent_recipient(&mut connection, account).await;
    let server = silent_server(&[tip]);
    quote_max(&mut connection, &server, account, address.clone()).await;
    let after_first = change_indices(&mut connection, account).await;

    for _ in 0..25 {
        quote_max(&mut connection, &server, account, address.clone()).await;
    }
    plan(
        &mut connection,
        &server,
        account,
        Payment::to(address, 10_000),
    )
    .await
    .expect("a partial send pays change");

    assert_eq!(change_indices(&mut connection, account).await, after_first);
}
