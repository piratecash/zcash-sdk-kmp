//! JNI bridge for `cash.p.zcash.ZcashJni`.
//!
//! Kept as a separate crate so `rlz` carries no bridge code of its own and can be re-vendored
//! by replacing the directory rather than merging a diff.

mod dto;
mod mempool;
mod progress;
mod registry;

use dto::{
    AccountDto, AddressesDto, BroadcastResultDto, MigrationStatusDto, MigrationStepDto,
    RecipientDto, TxDto, TxPlanDto,
};
use jni::errors::ErrorPolicy;
use jni::objects::{JByteArray, JIntArray, JLongArray, JObject, JString};
use jni::refs::Reference;
use jni::sys::{jboolean, jbyte, jint, jlong};
use jni::{Env, EnvUnowned};
use rlz::api::account::{
    address_kind, delete_account, derive_unified_address, generate_next_receive_address,
    get_account_pools, get_account_ufvk, list_accounts, list_tx_history, new_account,
    receivers_from_ua, receivers_of, transparent_address_balance, ua_from_ufvk, unified_address,
    AddressKind, NewAccount,
};
use rlz::api::coin::{init_datadir, Coin};
use rlz::api::key::{derive_spending_key, generate_seed};
use rlz::api::migrate::{migration_status, migration_step};
use rlz::api::network::get_current_height;
use rlz::api::pay::{
    broadcast, extract_transaction, pack_transaction, prepare, reserve_for_broadcast,
    sign_transaction_with_key, to_plan, transaction_id, unpack_transaction, PaymentOptions,
    PcztPackage,
};
use rlz::api::sapling::set_legacy_params_dir;
use rlz::api::sweep::discover_transparent_addresses;
use rlz::api::sync::{balance_breakdown, cancel_sync, max_spendable_from_pools};
use rlz::pay::pool::ALL_POOLS;
use rlz::pay::reserve::OwnInputs;
use rlz::pay::Recipient;
use rlz::sync::synchronize_impl;
use serde::Serialize;
use std::any::Any;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// jni's error policy requires `std::error::Error`, which `anyhow::Error` does not implement.
#[derive(Debug)]
struct BridgeError(String);

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BridgeError {}

impl From<anyhow::Error> for BridgeError {
    fn from(e: anyhow::Error) -> Self {
        BridgeError(format!("{e:#}"))
    }
}

impl From<jni::errors::Error> for BridgeError {
    fn from(e: jni::errors::Error) -> Self {
        BridgeError(e.to_string())
    }
}

impl From<serde_json::Error> for BridgeError {
    fn from(e: serde_json::Error) -> Self {
        BridgeError(e.to_string())
    }
}

/// `with_env` already turns a panic into an outcome instead of unwinding into the JVM; this policy
/// decides what reaches Java. jni's own `ThrowRuntimeExAndDefault` reports a `String` payload as
/// "non-string panic payload", and every `expect`/`unwrap` in rlz produces exactly that — so the
/// one thing that would explain the crash is the one thing it drops.
struct ThrowNativeError;

impl<T: Default, E: std::error::Error> ErrorPolicy<T, E> for ThrowNativeError {
    type Captures<'unowned_env_local: 'native_method, 'native_method> = ();

    fn on_error<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        err: E,
    ) -> jni::errors::Result<T> {
        throw(env, err.to_string());
        Ok(T::default())
    }

    fn on_panic<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _captures: &mut Self::Captures<'unowned_env_local, 'native_method>,
        payload: Box<dyn Any + Send + 'static>,
    ) -> jni::errors::Result<T> {
        throw(env, format!("native panic: {}", panic_message(&payload)));
        Ok(T::default())
    }
}

fn throw(env: &mut Env<'_>, message: String) {
    if !env.exception_check() {
        let _ = env.throw(message);
    }
}

fn panic_message(payload: &Box<dyn Any + Send + 'static>) -> String {
    payload
        .downcast_ref::<&'static str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".to_string())
}

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("tokio runtime"))
}

fn wallet(handle: jlong) -> Result<Coin, BridgeError> {
    registry::get(handle).ok_or_else(|| BridgeError("wallet is closed".to_string()))
}

/// A wallet's own account is per call, so the registry entry is never mutated to read a balance.
fn wallet_account(handle: jlong, account: jint) -> Result<Coin, BridgeError> {
    Ok(Coin {
        account: account as u32,
        ..wallet(handle)?
    })
}

/// The account's unified full viewing key, over every pool it holds keys for.
async fn account_ufvk(account: u32, coin: &Coin) -> anyhow::Result<String> {
    let pools = get_account_pools(account, coin).await?;
    get_account_ufvk(account, pools, coin).await
}

fn to_json<'local, T: Serialize>(
    env: &mut Env<'local>,
    value: &T,
) -> Result<JString<'local>, BridgeError> {
    Ok(env.new_string(serde_json::to_string(value)?)?)
}

fn account_ids(accounts: &JIntArray<'_>, env: &Env<'_>) -> Result<Vec<u32>, BridgeError> {
    let mut ids = vec![0i32; accounts.len(env)?];
    accounts.get_region(env, 0, &mut ids)?;
    Ok(ids.into_iter().map(|id| id as u32).collect())
}

fn optional_bytes(value: &JByteArray<'_>, env: &Env<'_>) -> Result<Option<Vec<u8>>, BridgeError> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(env.convert_byte_array(value)?))
    }
}

fn optional_string(value: &JString<'_>, env: &Env<'_>) -> Result<Option<String>, BridgeError> {
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(value.try_to_string(env)?))
    }
}

fn build_new_account(
    name: String,
    key: String,
    passphrase: Option<String>,
    birth_height: jint,
    pools: jint,
    aindex: jint,
) -> NewAccount {
    NewAccount {
        icon: None,
        name,
        // rlz never reads this flag: a non-empty key restores, an empty one generates.
        restore: !key.is_empty(),
        key,
        passphrase,
        fingerprint: None,
        aindex: aindex as u32,
        birth: (birth_height > 0).then_some(birth_height as u32),
        folder: String::new(),
        pools: Some(pools as u8),
        // Standard ZIP-32 wallets keep change on the Internal scope; scanning it is what makes
        // a seed restored from one of them show its change.
        use_internal: true,
        internal: false,
        ledger: false,
    }
}

fn parse_recipients(json: &str) -> Result<Vec<Recipient>, BridgeError> {
    let recipients: Vec<RecipientDto> = serde_json::from_str(json)?;
    Ok(recipients.into_iter().map(Recipient::from).collect())
}

fn unpack_package(env: &Env<'_>, pkg: &JByteArray<'_>) -> Result<PcztPackage, BridgeError> {
    let bytes = env.convert_byte_array(pkg)?;
    Ok(unpack_transaction(&bytes)?)
}

fn pack_package<'local>(
    env: &mut Env<'local>,
    package: &PcztPackage,
) -> Result<JByteArray<'local>, BridgeError> {
    let bytes = pack_transaction(package)?;
    Ok(env.byte_array_from_slice(&bytes)?)
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_initDataDir<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    directory: JString<'local>,
) {
    unowned_env
        .with_env(|env| -> Result<(), BridgeError> {
            let directory = directory.try_to_string(env)?;

            // rustls picks no provider by itself; without this any TLS call to lightwalletd panics.
            let _ = rustls::crypto::ring::default_provider().install_default();

            runtime().block_on(init_datadir(&directory))?;
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_open<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    db_path: JString<'local>,
    db_key: JByteArray<'local>,
    coin: jbyte,
    url: JString<'local>,
    server_type: jbyte,
    transport: jbyte,
    proxy: JString<'local>,
) -> jlong {
    unowned_env
        .with_env(|env| -> Result<jlong, BridgeError> {
            let db_path = db_path.try_to_string(env)?;
            let db_key = optional_bytes(&db_key, env)?;
            let url = url.try_to_string(env)?;
            let proxy = proxy.try_to_string(env)?;

            let opened = runtime().block_on(async {
                Coin::new(Some(coin as u8))
                    .open_database_with_key(db_path, db_key)
                    .await?
                    .set_lwd(server_type as u8, url)?
                    .set_transport(transport as u8)?
                    .set_proxy(proxy)
            })?;
            Ok(registry::insert(opened))
        })
        .resolve::<ThrowNativeError>()
}

/// Idempotent, and deliberately does not call `close_pool`: rlz `expect`s the pool on 36 paths, so
/// dropping it under an in-flight call would abort the process instead of failing the call.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_close<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|_env| -> Result<(), BridgeError> {
            registry::remove(handle);
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_generateSeedPhrase<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            Ok(env.new_string(generate_seed()?)?)
        })
        .resolve::<ThrowNativeError>()
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_newAccount<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    name: JString<'local>,
    key: JString<'local>,
    passphrase: JString<'local>,
    birth_height: jint,
    pools: jint,
    aindex: jint,
) -> jint {
    unowned_env
        .with_env(|env| -> Result<jint, BridgeError> {
            let account = build_new_account(
                name.try_to_string(env)?,
                key.try_to_string(env)?,
                optional_string(&passphrase, env)?,
                birth_height,
                pools,
                aindex,
            );
            let id = runtime().block_on(new_account(&account, &wallet(handle)?))?;
            Ok(id as jint)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_listAccounts<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let accounts = runtime().block_on(list_accounts(&wallet(handle)?))?;
            let accounts = accounts.iter().map(AccountDto::from).collect::<Vec<_>>();
            to_json(env, &accounts)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_deleteAccount<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
) {
    unowned_env
        .with_env(|_env| -> Result<(), BridgeError> {
            runtime().block_on(delete_account(account as u32, &wallet(handle)?))?;
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

/// Persists the wallet's current account, so the choice survives a reopen.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_setAccount<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
) {
    unowned_env
        .with_env(|_env| -> Result<(), BridgeError> {
            let coin = runtime().block_on(wallet(handle)?.set_account(account as u32))?;
            registry::replace(handle, coin);
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_accountAddresses<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = wallet(handle)?;
            let account = account as u32;

            let (ufvk, dindex) = runtime().block_on(async {
                let ufvk = account_ufvk(account, &coin).await?;
                let dindex = list_accounts(&coin)
                    .await?
                    .into_iter()
                    .find(|a| a.id == account)
                    .map(|a| a.dindex);
                anyhow::Ok((ufvk, dindex))
            })?;

            let unified = ua_from_ufvk(&ufvk, dindex, &coin)?;
            let receivers = receivers_from_ua(&unified, &coin)?;
            to_json(
                env,
                &AddressesDto::new(unified, receivers, dindex.unwrap_or(0)),
            )
        })
        .resolve::<ThrowNativeError>()
}

/// The account's unified full viewing key, over every pool the account holds keys for.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_accountUfvk<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = wallet(handle)?;
            let account = account as u32;

            let ufvk = runtime().block_on(account_ufvk(account, &coin))?;

            Ok(env.new_string(ufvk)?)
        })
        .resolve::<ThrowNativeError>()
}

/// A fresh receive-scope transparent address, or `null` when the account has no transparent key.
///
/// The account's own address stays where it is, so the receive screen is unaffected.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_nextTransparentAddress<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = wallet_account(handle, account)?;
            match runtime().block_on(generate_next_receive_address(&coin))? {
                Some(address) => Ok(env.new_string(&address)?),
                None => Ok(JString::default()),
            }
        })
        .resolve::<ThrowNativeError>()
}

/// Unspent value at `address` in zatoshi, as of the last sync.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_transparentBalance<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    address: JString<'local>,
) -> jlong {
    unowned_env
        .with_env(|env| -> Result<jlong, BridgeError> {
            let coin = wallet_account(handle, account)?;
            let address = address.try_to_string(env)?;
            let balance = runtime().block_on(transparent_address_balance(&coin, &address))?;
            Ok(balance as jlong)
        })
        .resolve::<ThrowNativeError>()
}

/// Re-derives transparent addresses this account handed out before it was restored, storing the
/// ones the server knows a transaction for. Returns how many were added.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_discoverTransparentAddresses<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    end_height: jint,
    gap_limit: jint,
) -> jint {
    unowned_env
        .with_env(|_env| -> Result<jint, BridgeError> {
            let coin = wallet_account(handle, account)?;
            let added = runtime().block_on(discover_transparent_addresses(
                end_height as u32,
                gap_limit as u32,
                &coin,
            ))?;
            Ok(added as jint)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_deriveAddresses<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    coin: jbyte,
    phrase: JString<'local>,
    passphrase: JString<'local>,
    account_index: jint,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = coin as u8;
            let phrase = phrase.try_to_string(env)?;
            let passphrase = optional_string(&passphrase, env)?;
            let (unified, dindex) =
                derive_unified_address(coin, &phrase, passphrase.as_deref(), account_index as u32)?;
            let receivers = receivers_of(coin, &unified)?;
            to_json(env, &AddressesDto::new(unified, receivers, dindex))
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_addressKind<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    coin: jbyte,
    address: JString<'local>,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let address = address.try_to_string(env)?;
            let kind = match address_kind(coin as u8, &address) {
                Some(AddressKind::Transparent) => "transparent",
                Some(AddressKind::Sapling) => "sapling",
                Some(AddressKind::Unified) => "unified",
                Some(AddressKind::Tex) => "tex",
                None => "invalid",
            };
            Ok(env.new_string(kind)?)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_addressesFromViewingKey<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    coin: jbyte,
    viewing_key: JString<'local>,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = coin as u8;
            let viewing_key = viewing_key.try_to_string(env)?;
            let (unified, dindex) = unified_address(coin, &viewing_key, None)?;
            let receivers = receivers_of(coin, &unified)?;
            to_json(env, &AddressesDto::new(unified, receivers, dindex))
        })
        .resolve::<ThrowNativeError>()
}

/// Four longs per pool — available, locked, change pending, value pending — from a single snapshot,
/// so the split can never be read across two different sync states.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_balance<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    confirmations: jint,
) -> JLongArray<'local> {
    unowned_env
        .with_env(|env| -> Result<JLongArray<'local>, BridgeError> {
            let coin = wallet_account(handle, account)?;
            let confirmations = confirmations.max(0) as u32;
            let pools = runtime().block_on(balance_breakdown(confirmations, &coin))?;
            let pools: Vec<i64> = pools
                .0
                .into_iter()
                .flat_map(|b| {
                    [
                        b.available as i64,
                        b.locked as i64,
                        b.change_pending as i64,
                        b.value_pending as i64,
                    ]
                })
                .collect();

            let array = env.new_long_array(pools.len())?;
            array.set_region(env, 0, &pools)?;
            Ok(array)
        })
        .resolve::<ThrowNativeError>()
}

/// A conservative lower bound on what is spendable using only the pools in `pool_mask`,
/// fundable for any single recipient pool. A same-pool send can afford more.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_maxSpendable<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    confirmations: jint,
    pool_mask: jint,
) -> jlong {
    unowned_env
        .with_env(|_env| -> Result<jlong, BridgeError> {
            let coin = wallet_account(handle, account)?;
            let confirmations = confirmations.max(0) as u32;
            let pool_mask = (pool_mask.max(0) as u32 & ALL_POOLS as u32) as u8;
            let max =
                runtime().block_on(max_spendable_from_pools(confirmations, pool_mask, &coin))?;
            Ok(max as jlong)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_listTransactions<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = wallet_account(handle, account)?;
            let txs = runtime().block_on(list_tx_history(&coin))?;
            let txs = txs.iter().map(TxDto::from).collect::<Vec<_>>();
            to_json(env, &txs)
        })
        .resolve::<ThrowNativeError>()
}

/// Blocks until the sync finishes. Failures — cancellation included — arrive through the sink, so
/// the error slot, not the return value, decides whether this throws.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_synchronize<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    accounts: JIntArray<'local>,
    current_height: jint,
    actions_per_sync: jint,
    transparent_limit: jint,
    checkpoint_age: jint,
    noskip_details: jboolean,
) {
    unowned_env
        .with_env(|env| -> Result<(), BridgeError> {
            let coin = wallet(handle)?;
            let accounts = account_ids(&accounts, env)?;
            let sink = progress::sink();
            sink.reset();

            runtime().block_on(synchronize_impl(
                sink.clone(),
                accounts,
                current_height as u32,
                actions_per_sync as u32,
                transparent_limit as u32,
                checkpoint_age as u32,
                noskip_details,
                &coin,
            ))?;

            sink.outcome().map_err(BridgeError)
        })
        .resolve::<ThrowNativeError>()
}

/// Cancels whatever is syncing: rlz keeps a single process-wide cancellation channel.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_cancelSync<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
) {
    unowned_env
        .with_env(|_env| -> Result<(), BridgeError> {
            // rlz fails the send when no sync is listening; a cancel nobody hears is a no-op.
            let _ = runtime().block_on(cancel_sync());
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

/// Packed `(height, time)` of the last reported block, `0` before the first one.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_syncProgress<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
) -> jlong {
    unowned_env
        .with_env(|_env| -> Result<jlong, BridgeError> { Ok(progress::sink().packed() as jlong) })
        .resolve::<ThrowNativeError>()
}

/// Starts the process-wide mempool subscription. It writes nothing to the database.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_mempoolStart<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|_env| -> Result<(), BridgeError> {
            mempool::start(wallet(handle)?).map_err(BridgeError)
        })
        .resolve::<ThrowNativeError>()
}

/// The next mempool event as JSON, or `null` when none arrived within `timeout_ms`.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_mempoolNext<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    timeout_ms: jlong,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let timeout = Duration::from_millis(timeout_ms.max(0) as u64);
            match mempool::next(timeout) {
                Some(event) => to_json(env, &event),
                None => Ok(JString::default()),
            }
        })
        .resolve::<ThrowNativeError>()
}

/// Cancels the subscription and returns once the native reader has actually stopped.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_mempoolStop<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
) {
    unowned_env
        .with_env(|_env| -> Result<(), BridgeError> {
            mempool::stop();
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_latestHeight<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
) -> jint {
    unowned_env
        .with_env(|_env| -> Result<jint, BridgeError> {
            let height = runtime().block_on(get_current_height(&wallet(handle)?))?;
            Ok(height as jint)
        })
        .resolve::<ThrowNativeError>()
}

/// Registers a read-only fallback directory (e.g. a legacy ECC SDK install) that Sapling
/// param lookup checks before downloading.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_setLegacyParamsDir<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    directory: JString<'local>,
) {
    unowned_env
        .with_env(|env| -> Result<(), BridgeError> {
            set_legacy_params_dir(PathBuf::from(directory.try_to_string(env)?));
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_prepare<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    recipients_json: JString<'local>,
    src_pools: jbyte,
    recipient_pays_fee: jboolean,
    smart_transparent: jboolean,
    confirmations: jint,
) -> JByteArray<'local> {
    unowned_env
        .with_env(|env| -> Result<JByteArray<'local>, BridgeError> {
            let recipients = parse_recipients(&recipients_json.try_to_string(env)?)?;
            if confirmations < 0 {
                return Err(BridgeError(
                    "Confirmations must not be negative".to_string(),
                ));
            }
            let coin = wallet_account(handle, account)?;
            let options = PaymentOptions {
                src_pools: src_pools as u8,
                recipient_pays_fee,
                smart_transparent,
                confirmations: confirmations as u32,
                category: None,
            };
            let package = runtime().block_on(prepare(&recipients, options, &coin))?;
            pack_package(env, &package)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_transactionPlan<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    pkg: JByteArray<'local>,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let package = unpack_package(env, &pkg)?;
            let plan = to_plan(&package, &wallet(handle)?)?;
            to_json(env, &TxPlanDto::from(plan))
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_signTransaction<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    pkg: JByteArray<'local>,
    spending_key: JByteArray<'local>,
) -> JByteArray<'local> {
    unowned_env
        .with_env(|env| -> Result<JByteArray<'local>, BridgeError> {
            let package = unpack_package(env, &pkg)?;
            let coin = wallet_account(handle, account)?;
            let mut usk = env.convert_byte_array(&spending_key)?;
            let signed = runtime().block_on(sign_transaction_with_key(&package, &coin, &usk));
            usk.fill(0);
            pack_package(env, &signed?)
        })
        .resolve::<ThrowNativeError>()
}

/// Stateless: no database is opened, nothing is stored. The caller owns the key.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_deriveSpendingKey<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    coin: jbyte,
    phrase: JString<'local>,
    passphrase: JString<'local>,
    account_index: jint,
) -> JByteArray<'local> {
    unowned_env
        .with_env(|env| -> Result<JByteArray<'local>, BridgeError> {
            let phrase = phrase.try_to_string(env)?;
            let passphrase = optional_string(&passphrase, env)?;
            let mut key = derive_spending_key(
                coin as u8,
                &phrase,
                passphrase.as_deref(),
                account_index as u32,
            )?;
            let array = env.byte_array_from_slice(&key);
            key.fill(0);
            Ok(array?)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_extractTransaction<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    pkg: JByteArray<'local>,
) -> JByteArray<'local> {
    unowned_env
        .with_env(|env| -> Result<JByteArray<'local>, BridgeError> {
            let package = unpack_package(env, &pkg)?;
            let raw = runtime().block_on(extract_transaction(&package))?;
            Ok(env.byte_array_from_slice(&raw)?)
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_transactionId<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    tx: JByteArray<'local>,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let raw = env.convert_byte_array(&tx)?;
            let txid = transaction_id(&raw)?;
            Ok(env.new_string(txid)?)
        })
        .resolve::<ThrowNativeError>()
}

/// `false` means the caller cannot vouch for the transaction's origin, so unowned inputs are fine.
fn own_inputs(require_own_inputs: jboolean) -> OwnInputs {
    if require_own_inputs {
        OwnInputs::Required
    } else {
        OwnInputs::Optional
    }
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_broadcastTransaction<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    height: jint,
    tx: JByteArray<'local>,
    require_own_inputs: jboolean,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let raw = env.convert_byte_array(&tx)?;
            let coin = wallet_account(handle, account)?;
            let outcome = runtime().block_on(broadcast(
                height as u32,
                &raw,
                &coin,
                own_inputs(require_own_inputs),
            ))?;
            to_json(env, &BroadcastResultDto::from(outcome))
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_reserveForBroadcast<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    tx: JByteArray<'local>,
    require_own_inputs: jboolean,
) {
    unowned_env
        .with_env(|env| -> Result<(), BridgeError> {
            let raw = env.convert_byte_array(&tx)?;
            let coin = wallet_account(handle, account)?;
            runtime().block_on(reserve_for_broadcast(
                &raw,
                &coin,
                own_inputs(require_own_inputs),
            ))?;
            Ok(())
        })
        .resolve::<ThrowNativeError>()
}

#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_migrationStatus<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = wallet_account(handle, account)?;
            let status = runtime().block_on(migration_status(&coin))?;
            to_json(env, &MigrationStatusDto::from(status))
        })
        .resolve::<ThrowNativeError>()
}

/// One step of the Orchard → Ironwood migration. The step signs and broadcasts on its own, so
/// the caller repeats it until the reported phase is `complete`.
#[no_mangle]
pub extern "system" fn Java_cash_p_zcash_ZcashJni_migrationStep<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _this: JObject<'local>,
    handle: jlong,
    account: jint,
    spending_key: JByteArray<'local>,
) -> JString<'local> {
    unowned_env
        .with_env(|env| -> Result<JString<'local>, BridgeError> {
            let coin = wallet_account(handle, account)?;
            let mut usk = env.convert_byte_array(&spending_key)?;
            let stepped = runtime().block_on(migration_step(&coin, &usk));
            usk.fill(0);
            let (event, status) = stepped?;
            to_json(env, &MigrationStepDto::new(event, status))
        })
        .resolve::<ThrowNativeError>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(key: &str, birth_height: jint) -> NewAccount {
        build_new_account(
            "wallet".into(),
            key.into(),
            Some("pp".into()),
            birth_height,
            3,
            2,
        )
    }

    #[test]
    fn own_inputs_maps_the_bridge_flag() {
        assert_eq!(OwnInputs::Required, own_inputs(true));
        assert_eq!(OwnInputs::Optional, own_inputs(false));
    }

    #[test]
    fn build_new_account_uses_the_internal_scope() {
        assert!(account("key", 100).use_internal);
    }

    #[test]
    fn build_new_account_maps_the_bridge_arguments() {
        let account = account("key", 100);

        assert_eq!("wallet", account.name);
        assert_eq!("key", account.key);
        assert_eq!(Some("pp".to_string()), account.passphrase);
        assert_eq!(Some(100), account.birth);
        assert_eq!(Some(3), account.pools);
        assert_eq!(2, account.aindex);
    }

    #[test]
    fn build_new_account_restores_only_when_a_key_is_given() {
        assert!(account("key", 100).restore);
        assert!(!account("", 100).restore);
    }

    #[test]
    fn build_new_account_without_a_positive_birth_height_has_no_birth() {
        assert_eq!(None, account("key", 0).birth);
    }
}
