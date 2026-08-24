use anyhow::Result;
use bincode::{config::legacy, Decode, Encode};

use crate::{
    api::coin::Coin,
    pay::{
        plan::{plan_transaction, NO_SPENDING_KEY},
        Recipient, TxPlan,
    },
};
#[cfg(feature = "flutter")]
use flutter_rust_bridge::frb;

pub const DEFAULT_CONFIRMATIONS: u32 = 10;

pub struct PaymentOptions {
    pub src_pools: u8,
    pub recipient_pays_fee: bool,
    pub smart_transparent: bool,
    pub confirmations: u32,
    pub category: Option<u32>,
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn build_puri(recipients: &[Recipient]) -> Result<String> {
    crate::pay::plan::build_puri(recipients).await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn prepare(
    recipients: &[Recipient],
    options: PaymentOptions,
    c: &Coin,
) -> Result<PcztPackage> {
    let account = c.account;
    let network = &c.network();
    let mut connection = c.get_connection().await?;
    let mut client = c.client().await?;

    plan_transaction(
        network,
        &mut *connection,
        &mut client,
        account,
        options.src_pools,
        recipients,
        options.recipient_pays_fee,
        Some(options.confirmations),
        options.smart_transparent,
        options.category,
        None,  // issuance — normal sends have no issuance
        false, // migration — only used by note migration
        None,  // preselected
        None,  // anchor_height
    )
    .await
}

/// Prepare a migration transaction (splitting or migrating).
/// Uses `migration=true` to allow Orchard outputs when Ironwood is active.
#[cfg_attr(feature = "flutter", frb)]
pub async fn prepare_migration(
    recipients: &[Recipient],
    src_pools: u8,
    c: &Coin,
) -> Result<PcztPackage> {
    let account = c.account;
    let network = &c.network();
    let mut connection = c.get_connection().await?;
    let mut client = c.client().await?;

    plan_transaction(
        network,
        &mut *connection,
        &mut client,
        account,
        src_pools,
        recipients,
        false, // recipient_pays_fee
        Some(DEFAULT_CONFIRMATIONS),
        false, // smart_transparent
        None,  // category
        None,  // issuance
        true,  // migration
        None,  // preselected
        None,  // anchor_height
    )
    .await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn sign_transaction(pczt: &PcztPackage, c: &Coin) -> Result<PcztPackage> {
    sign_transaction_with_key(pczt, c, NO_SPENDING_KEY).await
}

/// Entry point for hosts that hold the spending key outside the SDK.
pub async fn sign_transaction_with_key(
    pczt: &PcztPackage,
    c: &Coin,
    usk_bytes: &[u8],
) -> Result<PcztPackage> {
    let account = c.account;
    let mut connection = c.get_connection().await?;
    let network = c.network();

    let tx =
        crate::pay::plan::sign_transaction(&mut *connection, account, &network, pczt, usk_bytes)
            .await?;

    Ok(tx)
}

#[cfg_attr(feature = "flutter", frb)]
pub enum SigningEvent {
    Progress(String),
    Result(PcztPackage),
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn extract_transaction(package: &PcztPackage) -> Result<Vec<u8>> {
    crate::pay::plan::extract_transaction(package).await
}

/// The txid of a fully signed transaction, in the display order explorers use.
#[cfg_attr(feature = "flutter", frb)]
pub fn transaction_id(raw: &[u8]) -> Result<String> {
    crate::pay::plan::transaction_id(raw)
}

#[cfg_attr(feature = "flutter", frb(dart_metadata = ("freezed")))]
#[derive(Encode, Decode)]
pub struct PcztPackage {
    pub pczt: Vec<u8>,
    pub n_spends: [usize; 4],
    pub sapling_indices: Vec<usize>,
    pub orchard_indices: Vec<usize>,
    pub ironwood_indices: Vec<usize>,
    pub can_sign: bool,
    pub can_broadcast: bool,
    pub price: Option<f64>,
    pub category: Option<u32>,
    pub is_issuance: bool,
}

#[cfg_attr(feature = "flutter", frb)]
pub fn pack_transaction(pczt: &PcztPackage) -> Result<Vec<u8>> {
    let pkg = bincode::encode_to_vec(pczt, legacy())?;
    Ok(pkg)
}

#[cfg_attr(feature = "flutter", frb)]
pub fn unpack_transaction(bytes: &[u8]) -> Result<PcztPackage> {
    let (pkg, _) = bincode::decode_from_slice(bytes, legacy())?;
    Ok(pkg)
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn broadcast_transaction(height: u32, tx_bytes: &[u8], c: &Coin) -> Result<String> {
    Ok(broadcast(height, tx_bytes, c).await?.message)
}

/// Broadcast keeping the node's verdict: a host that must tell "already in the chain"
/// from a real rejection needs the error code, not just the message.
pub async fn broadcast(
    height: u32,
    tx_bytes: &[u8],
    c: &Coin,
) -> Result<crate::net::BroadcastOutcome> {
    let mut connection = c.get_connection().await?;
    let mut client = c.client().await?;
    crate::pay::reserve::reserve_and_send(
        &mut connection,
        &mut client,
        c.account,
        height,
        tx_bytes,
    )
    .await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn reserve_for_broadcast(tx_bytes: &[u8], c: &Coin) -> Result<()> {
    let mut connection = c.get_connection().await?;
    crate::pay::reserve::reserve_transaction(&mut connection, c.account, tx_bytes).await
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn to_plan(package: &PcztPackage, c: &Coin) -> Result<TxPlan> {
    TxPlan::from_package(&c.network(), package)
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn send(height: u32, data: &[u8], c: &Coin) -> Result<String> {
    Ok(broadcast(height, data, c).await?.message)
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn store_pending_tx(
    height: u32,
    txid: &[u8],
    price: Option<f64>,
    category: Option<u32>,
    c: &Coin,
) -> Result<()> {
    let mut connection = c.get_connection().await?;
    crate::db::store_pending_tx(&mut connection, c.account, height, txid, price, category).await?;

    Ok(())
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn parse_payment_uri(uri: &str) -> Option<Vec<Recipient>> {
    crate::pay::prepare::parse_payment_uri(uri).ok()
}
