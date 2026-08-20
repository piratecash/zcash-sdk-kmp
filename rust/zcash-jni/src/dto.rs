//! What crosses the bridge as JSON.
//!
//! Defined here rather than derived on rlz's own types: those carry `seed`, `passphrase` and the
//! account icon, none of which the Kotlin API needs and the first two of which must never leave
//! the native side at all.

use rlz::api::account::{Account, Receivers, Tx};
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlz::api::account::Folder;

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
        };

        let dto = TxDto::from(&tx);

        assert_eq!("ab0201", dto.txid);
        assert_eq!(-5_000, dto.value);
        assert_eq!(Some("hi".to_string()), dto.memo);
    }
}
