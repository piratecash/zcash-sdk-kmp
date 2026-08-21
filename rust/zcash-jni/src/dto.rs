//! What crosses the bridge as JSON.
//!
//! Defined here rather than derived on rlz's own types: those carry `seed`, `passphrase` and the
//! account icon, none of which the Kotlin API needs and the first two of which must never leave
//! the native side at all.

use rlz::api::account::{Account, Receivers, Tx};
use rlz::api::mempool::{MempoolAmount, MempoolMsg, MempoolNote};
use rlz::api::migrate::{MigrationEvent, MigrationStatus};
use rlz::net::BroadcastOutcome;
use rlz::pay::{Recipient, TxPlan, TxPlanIn, TxPlanOut};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDto {
    pub id: u32,
    pub name: String,
    pub birth: u32,
    pub aindex: u32,
    pub dindex: u32,
    pub position: u8,
    pub hidden: bool,
    pub enabled: bool,
    pub internal: bool,
    pub hw: u8,
    pub height: u32,
    pub time: u32,
    pub balance: u64,
}

impl From<&Account> for AccountDto {
    fn from(a: &Account) -> Self {
        AccountDto {
            id: a.id,
            name: a.name.clone(),
            birth: a.birth,
            aindex: a.aindex,
            dindex: a.dindex,
            position: a.position,
            hidden: a.hidden,
            enabled: a.enabled,
            internal: a.internal,
            hw: a.hw,
            height: a.height,
            time: a.time,
            balance: a.balance,
        }
    }
}

/// Every field is optional: an account without a given pool is a normal result, not an error.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressesDto {
    pub unified: Option<String>,
    pub sapling: Option<String>,
    pub orchard: Option<String>,
    pub transparent: Option<String>,
    pub diversifier_index: u32,
}

impl AddressesDto {
    pub fn new(unified: String, receivers: Receivers, diversifier_index: u32) -> Self {
        AddressesDto {
            unified: Some(unified),
            sapling: receivers.saddr,
            orchard: receivers.oaddr,
            transparent: receivers.taddr,
            diversifier_index,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientDto {
    pub address: String,
    pub amount: u64,
    pub pools: Option<u8>,
    pub memo: Option<String>,
}

/// ZSA fields (`asset_base`, `asset_name`, `price`, `memo_bytes`) are not exposed to Kotlin
/// yet, so `Recipient::default()` fills them.
impl From<RecipientDto> for Recipient {
    fn from(dto: RecipientDto) -> Self {
        Recipient {
            address: dto.address,
            amount: dto.amount,
            pools: dto.pools,
            user_memo: dto.memo,
            ..Recipient::default()
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxPlanDto {
    pub height: u32,
    pub inputs: Vec<TxPlanInDto>,
    pub outputs: Vec<TxPlanOutDto>,
    pub fee: u64,
    pub can_sign: bool,
    pub can_broadcast: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxPlanInDto {
    pub pool: u8,
    pub amount: Option<u64>,
    pub asset_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxPlanOutDto {
    pub pool: u8,
    pub amount: u64,
    pub address: String,
    pub asset_name: String,
}

impl From<TxPlan> for TxPlanDto {
    fn from(plan: TxPlan) -> Self {
        TxPlanDto {
            height: plan.height,
            inputs: plan.inputs.into_iter().map(TxPlanInDto::from).collect(),
            outputs: plan.outputs.into_iter().map(TxPlanOutDto::from).collect(),
            fee: plan.fee,
            can_sign: plan.can_sign,
            can_broadcast: plan.can_broadcast,
        }
    }
}

impl From<TxPlanIn> for TxPlanInDto {
    fn from(input: TxPlanIn) -> Self {
        TxPlanInDto {
            pool: input.pool,
            amount: input.amount,
            asset_name: input.asset_name,
        }
    }
}

impl From<TxPlanOut> for TxPlanOutDto {
    fn from(output: TxPlanOut) -> Self {
        TxPlanOutDto {
            pool: output.pool,
            amount: output.amount,
            address: output.address,
            asset_name: output.asset_name,
        }
    }
}

/// `txid` is hex of the byte-reversed hash — the order block explorers and users expect.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxDto {
    pub id: u32,
    pub txid: String,
    pub height: u32,
    pub time: u32,
    pub value: i64,
    pub memo: Option<String>,
    pub fee: u64,
    pub total_received: u64,
    pub is_change: bool,
    pub recipient: Option<String>,
}

impl From<&Tx> for TxDto {
    fn from(t: &Tx) -> Self {
        TxDto {
            id: t.id,
            txid: t
                .txid
                .iter()
                .rev()
                .fold(String::with_capacity(t.txid.len() * 2), |mut acc, b| {
                    acc.push_str(&format!("{:02x}", b));
                    acc
                }),
            height: t.height,
            time: t.time,
            value: t.value,
            memo: t.memo.clone(),
            fee: t.fee,
            total_received: t.total_received,
            is_change: t.is_change,
            recipient: t.recipient.clone(),
        }
    }
}

/// The node's verdict on a broadcast. `errorCode` 0 means accepted and `message` is the txid.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BroadcastResultDto {
    pub error_code: i32,
    pub message: String,
}

impl From<BroadcastOutcome> for BroadcastResultDto {
    fn from(outcome: BroadcastOutcome) -> Self {
        BroadcastResultDto {
            error_code: outcome.error_code,
            message: outcome.message,
        }
    }
}

/// The net value an unconfirmed transaction moves for one account, in zatoshi.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MempoolAmountDto {
    pub account: u32,
    pub value: i64,
}

impl From<&MempoolAmount> for MempoolAmountDto {
    fn from(a: &MempoolAmount) -> Self {
        MempoolAmountDto {
            account: a.account,
            value: a.value,
        }
    }
}

/// What an ephemeral history row is built from; rlz's remaining note fields stay native detail.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MempoolNoteDto {
    pub account: u32,
    pub value: i64,
    pub pool: u8,
    pub memo: Option<String>,
}

impl From<&MempoolNote> for MempoolNoteDto {
    fn from(n: &MempoolNote) -> Self {
        MempoolNoteDto {
            account: n.account,
            value: n.value,
            pool: n.pool,
            memo: n.memo.clone(),
        }
    }
}

/// One event of the mempool subscription, tagged so Kotlin branches on `kind`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum MempoolEventDto {
    /// A new observation epoch opened at this height — not a claim that anything was mined.
    Epoch { height: u32 },
    Unconfirmed {
        txid: String,
        amounts: Vec<MempoolAmountDto>,
        notes: Vec<MempoolNoteDto>,
        size: u32,
    },
    /// The run stopped for good; `error` is absent when it was cancelled.
    Ended { error: Option<String> },
}

impl From<MempoolMsg> for MempoolEventDto {
    fn from(msg: MempoolMsg) -> Self {
        match msg {
            MempoolMsg::BlockHeight(height) => MempoolEventDto::Epoch { height },
            MempoolMsg::TxId(tx) => MempoolEventDto::Unconfirmed {
                txid: tx.txid,
                amounts: tx.amounts.iter().map(MempoolAmountDto::from).collect(),
                notes: tx.notes.iter().map(MempoolNoteDto::from).collect(),
                size: tx.size,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlz::api::account::Folder;
    use rlz::api::mempool::MempoolTx;

    fn account() -> Account {
        Account {
            coin: 0,
            id: 7,
            name: "main".to_string(),
            seed: Some("dial thunder pledge fabric attitude".to_string()),
            passphrase: Some("hunter2".to_string()),
            aindex: 1,
            dindex: 2,
            icon: Some(vec![1, 2, 3]),
            use_internal: false,
            birth: 419_200,
            folder: Folder { id: 0, name: String::new() },
            position: 3,
            hidden: false,
            saved: true,
            enabled: true,
            internal: false,
            hw: 0,
            height: 2_500_000,
            time: 1_700_000_000,
            balance: 123_456_789,
        }
    }

    fn migration_status() -> MigrationStatus {
        MigrationStatus {
            phase: "migrating".to_string(),
            split_fees: 10_000,
            migrate_fees: 20_000,
            total_fees: 30_000,
            sd_notes_count: 4,
            non_sd_notes_count: 1,
            ironwood_sd_count: 2,
            progress: 0.5,
            next_action: "Preparing migration transaction...".to_string(),
            work_summary: "4 notes left".to_string(),
        }
    }

    #[test]
    fn broadcast_result_dto_round_trips_a_rejection() {
        let dto = BroadcastResultDto::from(BroadcastOutcome {
            error_code: -25,
            message: "missing inputs".to_string(),
        });
        let json = serde_json::to_string(&dto).unwrap();

        assert!(json.contains("errorCode"));
        assert_eq!(
            dto,
            serde_json::from_str::<BroadcastResultDto>(&json).unwrap()
        );
    }

    #[test]
    fn migration_status_dto_round_trips() {
        let dto = MigrationStatusDto::from(migration_status());
        let json = serde_json::to_string(&dto).unwrap();
        assert_eq!(
            dto,
            serde_json::from_str::<MigrationStatusDto>(&json).unwrap()
        );
    }

    #[test]
    fn migration_step_dto_carries_event_and_fee() {
        let dto = MigrationStepDto::new(
            MigrationEvent::MigrateComplete { fee: 20_000 },
            migration_status(),
        );

        assert_eq!("migrateComplete", dto.event);
        assert_eq!(20_000, dto.fee);
        assert_eq!(4, dto.status.sd_notes_count);
    }

    #[test]
    fn migration_step_dto_reports_a_failed_step_as_error() {
        let dto = MigrationStepDto::new(
            MigrationEvent::Error {
                message: "broadcast rejected".to_string(),
            },
            migration_status(),
        );

        assert_eq!("error", dto.event);
        assert_eq!(0, dto.fee);
    }

    #[test]
    fn account_dto_round_trips() {
        let dto = AccountDto::from(&account());
        let json = serde_json::to_string(&dto).unwrap();
        assert_eq!(dto, serde_json::from_str::<AccountDto>(&json).unwrap());
    }

    #[test]
    fn account_dto_never_carries_key_material() {
        let json = serde_json::to_string(&AccountDto::from(&account())).unwrap();
        assert!(!json.contains("seed"));
        assert!(!json.contains("passphrase"));
        assert!(!json.contains("icon"));
        assert!(!json.contains("dial thunder"));
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn addresses_dto_round_trips_with_missing_receivers() {
        let receivers = Receivers {
            taddr: None,
            saddr: Some("zs1sapling".to_string()),
            oaddr: None,
        };
        let dto = AddressesDto::new("u1unified".to_string(), receivers, 2);
        let json = serde_json::to_string(&dto).unwrap();

        assert!(json.contains("\"diversifierIndex\":2"));
        assert_eq!(dto, serde_json::from_str::<AddressesDto>(&json).unwrap());
    }

    #[test]
    fn recipient_dto_round_trips() {
        let dto = RecipientDto {
            address: "u1testaddress".to_string(),
            amount: 100_000,
            pools: Some(6),
            memo: Some("thanks".to_string()),
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert_eq!(dto, serde_json::from_str::<RecipientDto>(&json).unwrap());
    }

    #[test]
    fn recipient_dto_leaves_zsa_fields_empty() {
        let recipient = Recipient::from(RecipientDto {
            address: "u1testaddress".to_string(),
            amount: 100_000,
            pools: None,
            memo: None,
        });
        assert!(recipient.asset_base.is_empty());
        assert_eq!(recipient.asset_name, None);
        assert_eq!(recipient.price, None);
        assert_eq!(recipient.memo_bytes, None);
    }

    #[test]
    fn tx_plan_dto_serializes_with_camel_case_fields() {
        let dto = TxPlanDto {
            height: 2_500_000,
            inputs: vec![TxPlanInDto {
                pool: 2,
                amount: Some(50_000),
                asset_name: "ZEC".to_string(),
            }],
            outputs: vec![TxPlanOutDto {
                pool: 2,
                amount: 40_000,
                address: "u1out".to_string(),
                asset_name: "ZEC".to_string(),
            }],
            fee: 10_000,
            can_sign: true,
            can_broadcast: false,
        };
        let json = serde_json::to_string(&dto).unwrap();

        assert!(json.contains("\"canSign\":true"));
        assert!(json.contains("\"canBroadcast\":false"));
        assert!(json.contains("\"assetName\":\"ZEC\""));
    }

    /// Kotlin omits `pools`/`memo` entirely when they are null, so serde must accept them absent.
    #[test]
    fn recipient_dto_parses_with_optional_fields_absent() {
        let dto: RecipientDto =
            serde_json::from_str(r#"{"address":"u1recipient","amount":50000}"#).unwrap();

        assert_eq!(dto.pools, None);
        assert_eq!(dto.memo, None);
    }

    #[test]
    fn tx_dto_txid_is_reversed_hex() {
        let tx = Tx {
            id: 3,
            txid: vec![0x01, 0x02, 0xab],
            height: 2_500_000,
            time: 1_700_000_000,
            value: -5_000,
            tpe: None,
            category: None,
            zsa_value: 0,
            asset_id: None,
            asset_display: String::new(),
            price: None,
            memo: Some("hi".to_string()),
            is_user_memo: true,
            contact_name: None,
            fee: 15_000,
            total_received: 1_000,
            is_change: false,
            recipient: Some("u1recipient".to_string()),
        };

        let dto = TxDto::from(&tx);

        assert_eq!("ab0201", dto.txid);
        assert_eq!(-5_000, dto.value);
        assert_eq!(Some("hi".to_string()), dto.memo);
        assert_eq!(15_000, dto.fee);
        assert_eq!(1_000, dto.total_received);
        assert!(!dto.is_change);
        assert_eq!(Some("u1recipient".to_string()), dto.recipient);
    }

    #[test]
    fn tx_dto_serializes_the_new_fields_in_camel_case() {
        let tx = Tx {
            id: 4,
            txid: vec![0x01],
            height: 2_500_000,
            time: 1_700_000_000,
            value: 1_000,
            tpe: None,
            category: None,
            zsa_value: 0,
            asset_id: None,
            asset_display: String::new(),
            price: None,
            memo: None,
            is_user_memo: false,
            contact_name: None,
            fee: 0,
            total_received: 1_000,
            is_change: true,
            recipient: None,
        };

        let json = serde_json::to_string(&TxDto::from(&tx)).unwrap();

        assert!(json.contains("\"totalReceived\":1000"));
        assert!(json.contains("\"isChange\":true"));
        assert!(json.contains("\"recipient\":null"));
    }

    fn mempool_note(value: i64) -> MempoolNote {
        MempoolNote {
            account: 3,
            name: "main".to_string(),
            value,
            pool: 2,
            scope: 0,
            diversifier: None,
            diversifier_index: None,
            address: Some("u1self".to_string()),
            memo: Some("for you".to_string()),
        }
    }

    #[test]
    fn mempool_msg_block_height_becomes_an_epoch_event() {
        let event = MempoolEventDto::from(MempoolMsg::BlockHeight(2_500_000));

        assert_eq!(MempoolEventDto::Epoch { height: 2_500_000 }, event);
        assert_eq!(
            r#"{"kind":"epoch","height":2500000}"#,
            serde_json::to_string(&event).unwrap()
        );
    }

    #[test]
    fn mempool_msg_tx_keeps_only_the_fields_kotlin_needs() {
        let event = MempoolEventDto::from(MempoolMsg::TxId(MempoolTx {
            txid: "ab01".to_string(),
            amounts: vec![MempoolAmount {
                account: 3,
                name: "main".to_string(),
                value: 900,
            }],
            notes: vec![mempool_note(900)],
            size: 512,
        }));

        assert_eq!(
            MempoolEventDto::Unconfirmed {
                txid: "ab01".to_string(),
                amounts: vec![MempoolAmountDto {
                    account: 3,
                    value: 900
                }],
                notes: vec![MempoolNoteDto {
                    account: 3,
                    value: 900,
                    pool: 2,
                    memo: Some("for you".to_string()),
                }],
                size: 512,
            },
            event
        );
    }

    /// A spend keeps its negative value, which is how Kotlin tells its own outgoing apart.
    #[test]
    fn mempool_note_dto_keeps_the_sign_of_a_spend() {
        assert_eq!(-900, MempoolNoteDto::from(&mempool_note(-900)).value);
    }

    #[test]
    fn mempool_event_dto_ended_reports_the_error_that_stopped_the_run() {
        let json = serde_json::to_string(&MempoolEventDto::Ended {
            error: Some("server unreachable".to_string()),
        })
        .unwrap();

        assert_eq!(r#"{"kind":"ended","error":"server unreachable"}"#, json);
    }

    #[test]
    fn mempool_event_dto_ended_without_an_error_means_it_was_cancelled() {
        let json = serde_json::to_string(&MempoolEventDto::Ended { error: None }).unwrap();

        assert_eq!(r#"{"kind":"ended","error":null}"#, json);
    }
}

/// Where the Orchard → Ironwood migration currently stands.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationStatusDto {
    pub phase: String,
    pub sd_notes_count: u32,
    pub non_sd_notes_count: u32,
    pub ironwood_sd_count: u32,
}

impl From<MigrationStatus> for MigrationStatusDto {
    fn from(s: MigrationStatus) -> Self {
        MigrationStatusDto {
            phase: s.phase,
            sd_notes_count: s.sd_notes_count,
            non_sd_notes_count: s.non_sd_notes_count,
            ironwood_sd_count: s.ironwood_sd_count,
        }
    }
}

/// Outcome of one migration step. `fee` is zero for the events that broadcast nothing.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationStepDto {
    pub event: String,
    pub fee: u64,
    pub status: MigrationStatusDto,
}

impl MigrationStepDto {
    pub fn new(event: MigrationEvent, status: MigrationStatus) -> Self {
        let (event, fee) = match event {
            MigrationEvent::SplitComplete { fee } => ("splitComplete", fee),
            MigrationEvent::MigrateComplete { fee } => ("migrateComplete", fee),
            MigrationEvent::Complete => ("complete", 0),
            MigrationEvent::NothingToDo => ("nothingToDo", 0),
            MigrationEvent::Error { .. } => ("error", 0),
        };
        MigrationStepDto {
            event: event.to_string(),
            fee,
            status: status.into(),
        }
    }
}
