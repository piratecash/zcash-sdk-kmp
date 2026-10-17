//! Signing a planned PCZT on a device that takes it field by field (e.g. Ledger's Zcash app).
//!
//! The field extraction in [`external_signing_view`] is adapted from LedgerHQ
//! `ledger-zcash-utils` (Apache-2.0, see NOTICE).

use anyhow::{anyhow, Result};
use group::ff::PrimeField as _;
use orchard::note::NoteVersion;
use pczt::{
    roles::{
        signer::Signer,
        verifier::{OrchardError, TransparentError, Verifier},
    },
    Pczt,
};
use serde::{Deserialize, Serialize};
use zcash_keys::address::UnifiedAddress;
use zcash_script::script::Evaluable as _;

use crate::api::{coin::Network, pay::PcztPackage};
use crate::pay::plan::{
    append_transparent_signature, check_signature_cover, finalize_signed, get_orchard_pk,
    parse_transparent_signature, prove, repackage,
};
use crate::pay::pool::ALL_POOLS;

/// Every pool but Sapling, which the device can neither spend nor pay.
pub const USABLE_POOLS: u8 = ALL_POOLS & !(1 << 1);

const MAX_TRANSPARENT_INPUTS: usize = 32;
const MAX_TRANSPARENT_OUTPUTS: usize = 10;
const MAX_ACTIONS: usize = 32;
/// Shielded outputs the device shows for review; change and dummies are not shown.
const MAX_SHIELDED_RECIPIENTS: usize = 4;

const HARDENED: u32 = 0x8000_0000;
const SIGHASH_ALL: u8 = 0x01;

/// Why a payment cannot be signed by the external device. The bracketed code in the message is
/// the stable part a host maps to its own error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExternalSigningRefusal {
    #[error("[external-signing:sapling] the signing device does not support the Sapling pool")]
    Sapling,
    #[error("[external-signing:shielded-recipients] the signing device reviews at most {MAX_SHIELDED_RECIPIENTS} shielded recipients")]
    ShieldedRecipients,
    #[error("[external-signing:transparent-inputs] the signing device accepts at most {MAX_TRANSPARENT_INPUTS} transparent inputs")]
    TransparentInputs,
    #[error("[external-signing:transparent-outputs] the signing device accepts at most {MAX_TRANSPARENT_OUTPUTS} transparent outputs")]
    TransparentOutputs,
    #[error("[external-signing:orchard-actions] the signing device accepts at most {MAX_ACTIONS} Orchard actions")]
    OrchardActions,
    #[error("[external-signing:ironwood-actions] the signing device accepts at most {MAX_ACTIONS} Ironwood actions")]
    IronwoodActions,
}

/// `recipient_pools` holds the pool each recipient is paid from (0 = transparent, 1 = Sapling).
pub(super) fn check_recipient_pools(
    recipient_pools: &[u8],
) -> std::result::Result<(), ExternalSigningRefusal> {
    if recipient_pools.contains(&1) {
        return Err(ExternalSigningRefusal::Sapling);
    }
    if recipient_pools.iter().filter(|&&pool| pool >= 2).count() > MAX_SHIELDED_RECIPIENTS {
        return Err(ExternalSigningRefusal::ShieldedRecipients);
    }
    Ok(())
}

pub(super) fn check_device_limits(pczt: &Pczt) -> std::result::Result<(), ExternalSigningRefusal> {
    use ExternalSigningRefusal::*;
    let refusal = if !pczt.sapling().spends().is_empty() || !pczt.sapling().outputs().is_empty() {
        Some(Sapling)
    } else if pczt.transparent().inputs().len() > MAX_TRANSPARENT_INPUTS {
        Some(TransparentInputs)
    } else if pczt.transparent().outputs().len() > MAX_TRANSPARENT_OUTPUTS {
        Some(TransparentOutputs)
    } else if pczt.orchard().actions().len() > MAX_ACTIONS {
        Some(OrchardActions)
    } else if pczt.ironwood().actions().len() > MAX_ACTIONS {
        Some(IronwoodActions)
    } else {
        None
    };
    refusal.map_or(Ok(()), Err)
}

/// Adds the proofs a device-signed PCZT needs; no spending key is involved.
pub async fn prove_transaction(package: &PcztPackage) -> Result<PcztPackage> {
    let pczt = parse(package)?;
    let orchard_pk = get_orchard_pk(*pczt.global().consensus_branch_id())?;
    let pczt = prove(pczt, orchard_pk).await?;
    repackage(package, pczt, false)
}

/// Everything the device needs, in the device's terms: global fields, full derivation paths, and
/// for each shielded bundle the actions it must sign (dummy spends are already signed by the host).
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalSigningView {
    pub tx_version: u32,
    pub version_group_id: u32,
    pub consensus_branch_id: u32,
    pub fallback_lock_time: Option<u32>,
    pub expiry_height: u32,
    pub coin_type: u32,
    pub tx_modifiable: u8,
    pub transparent_inputs: Vec<ExternalTransparentInput>,
    pub transparent_outputs: Vec<ExternalTransparentOutput>,
    pub orchard: Option<ExternalActionBundle>,
    /// Always `None` below transaction version 6.
    pub ironwood: Option<ExternalActionBundle>,
}

/// Byte fields are hex; paths are raw BIP-32/ZIP-32 indices with the hardened bit set.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalKeyDerivation {
    pub pubkey: String,
    pub seed_fingerprint: String,
    pub path: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalTransparentInput {
    pub prevout_txid: String,
    pub prevout_index: u32,
    pub sequence: Option<u32>,
    pub value: u64,
    pub script_pubkey: String,
    pub sighash_type: u8,
    pub derivation: ExternalKeyDerivation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalTransparentOutput {
    pub value: u64,
    pub script_pubkey: String,
    /// Present only on the wallet's own change output.
    pub derivation: Option<ExternalKeyDerivation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalActionBundle {
    pub actions: Vec<ExternalAction>,
    pub flags: u8,
    /// Spends minus outputs, in zatoshis.
    pub value_balance: i64,
    pub anchor: String,
    pub note_plaintext_version: u8,
    /// Actions the device signs; the rest are dummies the host signed already.
    pub sign_indices: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExternalAction {
    pub cv_net: String,
    pub nullifier: String,
    pub rk: String,
    pub spend_recipient: String,
    pub spend_value: u64,
    pub spend_rho: String,
    pub spend_rseed: String,
    pub alpha: String,
    pub seed_fingerprint: String,
    pub path: Vec<u32>,
    pub cmx: String,
    pub ephemeral_key: String,
    pub enc_ciphertext: String,
    pub out_ciphertext: String,
    pub recipient: String,
    /// The Orchard-only unified address the device shows for this output.
    pub recipient_address: String,
    pub value: u64,
    pub rseed: String,
    pub rcv: String,
}

/// Builds the device's view of `package`. `account_index` is the ZIP-32/BIP-44 account the device
/// derives the keys at; the PCZT carries only paths relative to it.
pub fn external_signing_view(
    network: &Network,
    package: &PcztPackage,
    account_index: u32,
) -> Result<ExternalSigningView> {
    if account_index >= HARDENED {
        return Err(anyhow!("account index {account_index} is out of range"));
    }
    let pczt = parse(package)?;
    check_device_limits(&pczt)?;
    let global = GlobalFields::read(&pczt)?;
    let account = Account {
        coin_type: global.coin_type,
        index: account_index,
    };

    let mut transparent_inputs = Vec::new();
    let mut transparent_outputs = Vec::new();
    let verifier = Verifier::new(pczt)
        .with_transparent::<anyhow::Error, _>(|bundle| {
            transparent_inputs = bundle
                .inputs()
                .iter()
                .map(|input| view_transparent_input(input, &account))
                .collect::<Result<_>>()
                .map_err(TransparentError::Custom)?;
            transparent_outputs = bundle
                .outputs()
                .iter()
                .map(|output| view_transparent_output(output, &account))
                .collect::<Result<_>>()
                .map_err(TransparentError::Custom)?;
            Ok(())
        })
        .map_err(|error| match error {
            TransparentError::Custom(error) => error,
            other => anyhow!("failed to read the transparent bundle: {other:?}"),
        })?;

    let mut orchard = None;
    let verifier = verifier
        .with_orchard::<anyhow::Error, _>(|bundle| {
            orchard =
                view_action_bundle(network, bundle, &account).map_err(OrchardError::Custom)?;
            Ok(())
        })
        .map_err(|error| orchard_error("Orchard", error))?;

    let mut ironwood = None;
    if global.tx_version >= 6 {
        verifier
            .with_ironwood::<anyhow::Error, _>(|bundle| {
                ironwood =
                    view_action_bundle(network, bundle, &account).map_err(OrchardError::Custom)?;
                Ok(())
            })
            .map_err(|error| orchard_error("Ironwood", error))?;
    }

    Ok(ExternalSigningView {
        tx_version: global.tx_version,
        version_group_id: global.version_group_id,
        consensus_branch_id: global.consensus_branch_id,
        fallback_lock_time: global.fallback_lock_time,
        expiry_height: global.expiry_height,
        coin_type: global.coin_type,
        tx_modifiable: global.tx_modifiable,
        transparent_inputs,
        transparent_outputs,
        orchard,
        ironwood,
    })
}

/// Applies the device's signatures and finalizes the spends. Each signature is verified against
/// the PCZT's own sighash and key before it is accepted; transparent ones arrive as DER ‖ sighash
/// type, as the device returns them.
pub fn apply_external_signatures(
    package: &PcztPackage,
    orchard: &[(u32, [u8; 64])],
    ironwood: &[(u32, [u8; 64])],
    transparent: &[(u32, Vec<u8>)],
) -> Result<PcztPackage> {
    let pczt = parse(package)?;
    check_signature_cover(
        &indices_of(orchard),
        &unsigned_actions(pczt.orchard().actions()),
        "Orchard action",
    )?;
    check_signature_cover(
        &indices_of(ironwood),
        &unsigned_actions(pczt.ironwood().actions()),
        "Ironwood action",
    )?;
    let inputs: Vec<usize> = (0..pczt.transparent().inputs().len()).collect();
    check_signature_cover(&indices_of(transparent), &inputs, "transparent input")?;

    let mut signer =
        Signer::new(pczt).map_err(|error| anyhow!("failed to start signing session: {error:?}"))?;
    for (index, signature) in orchard {
        signer
            .apply_orchard_signature(*index as usize, (*signature).into())
            .map_err(|error| {
                anyhow!("signature for Orchard action {index} was rejected: {error:?}")
            })?;
    }
    for (index, signature) in ironwood {
        signer
            .apply_ironwood_signature(*index as usize, (*signature).into())
            .map_err(|error| {
                anyhow!("signature for Ironwood action {index} was rejected: {error:?}")
            })?;
    }
    for (index, signature) in transparent {
        let der = strip_sighash_all(*index, signature)?;
        let signature = parse_transparent_signature(*index, der)?;
        append_transparent_signature(&mut signer, *index as usize, signature)?;
    }
    finalize_signed(package, signer)
}

fn parse(package: &PcztPackage) -> Result<Pczt> {
    Pczt::parse(&package.pczt).map_err(|error| anyhow!("failed to parse PCZT: {error:?}"))
}

fn indices_of<T>(signatures: &[(u32, T)]) -> Vec<u32> {
    signatures.iter().map(|(index, _)| *index).collect()
}

/// After the IO Finalizer only real spends are still unsigned: it signs the dummies itself.
fn unsigned_actions(actions: &[pczt::orchard::Action]) -> Vec<usize> {
    actions
        .iter()
        .enumerate()
        .filter_map(|(index, action)| action.spend().spend_auth_sig().is_none().then_some(index))
        .collect()
}

fn strip_sighash_all(index: u32, signature: &[u8]) -> Result<&[u8]> {
    match signature.split_last() {
        Some((&SIGHASH_ALL, der)) => Ok(der),
        _ => Err(anyhow!(
            "signature for transparent input {index} does not end with the SIGHASH_ALL type"
        )),
    }
}

fn orchard_error(pool: &str, error: OrchardError<anyhow::Error>) -> anyhow::Error {
    match error {
        OrchardError::Custom(error) => error,
        other => anyhow!("failed to read the {pool} bundle: {other:?}"),
    }
}

/// The global fields the device header needs. Three of them have no getter on `Global`, so they
/// are read through its serde form.
struct GlobalFields {
    tx_version: u32,
    version_group_id: u32,
    consensus_branch_id: u32,
    fallback_lock_time: Option<u32>,
    expiry_height: u32,
    coin_type: u32,
    tx_modifiable: u8,
}

impl GlobalFields {
    fn read(pczt: &Pczt) -> Result<Self> {
        let global = pczt.global();
        let json = serde_json::to_value(global)?;
        let field = |name: &str| -> Result<u32> {
            json.get(name)
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| anyhow!("PCZT global field {name} is missing"))
        };
        let fallback_lock_time = match json.get("fallback_lock_time") {
            None | Some(serde_json::Value::Null) => None,
            Some(_) => Some(field("fallback_lock_time")?),
        };
        Ok(Self {
            tx_version: *global.tx_version(),
            version_group_id: *global.version_group_id(),
            consensus_branch_id: *global.consensus_branch_id(),
            fallback_lock_time,
            expiry_height: *global.expiry_height(),
            coin_type: field("coin_type")?,
            tx_modifiable: u8::try_from(field("tx_modifiable")?)?,
        })
    }
}

struct Account {
    coin_type: u32,
    index: u32,
}

impl Account {
    /// ZIP-32 `m/32'/coin'/account'`, the same for every Orchard and Ironwood action.
    fn zip32_path(&self) -> Vec<u32> {
        vec![
            32 | HARDENED,
            self.coin_type | HARDENED,
            self.index | HARDENED,
        ]
    }

    /// BIP-44 `m/44'/coin'/account'/scope/index` from the `[scope, index]` the planner records.
    fn bip44_path(&self, relative: &[u32]) -> Result<Vec<u32>> {
        match relative {
            [scope @ (0 | 1), index] if *index < HARDENED => Ok(vec![
                44 | HARDENED,
                self.coin_type | HARDENED,
                self.index | HARDENED,
                *scope,
                *index,
            ]),
            _ => Err(anyhow!(
                "transparent derivation {relative:?} is not a [scope, index] pair"
            )),
        }
    }
}

fn key_derivation(
    derivations: &std::collections::BTreeMap<[u8; 33], zcash_transparent::pczt::Bip32Derivation>,
    account: &Account,
) -> Result<Option<ExternalKeyDerivation>> {
    let mut entries = derivations.iter();
    let Some((pubkey, derivation)) = entries.next() else {
        return Ok(None);
    };
    if entries.next().is_some() {
        return Err(anyhow!(
            "a transparent entry carries more than one key derivation"
        ));
    }
    let relative: Vec<u32> = derivation
        .derivation_path()
        .iter()
        .copied()
        .map(u32::from)
        .collect();
    Ok(Some(ExternalKeyDerivation {
        pubkey: hex::encode(pubkey),
        seed_fingerprint: hex::encode(derivation.seed_fingerprint()),
        path: account.bip44_path(&relative)?,
    }))
}

fn view_transparent_input(
    input: &zcash_transparent::pczt::Input,
    account: &Account,
) -> Result<ExternalTransparentInput> {
    let derivation = key_derivation(input.bip32_derivation(), account)?
        .ok_or_else(|| anyhow!("a transparent input has no key derivation"))?;
    Ok(ExternalTransparentInput {
        prevout_txid: hex::encode(input.prevout_txid().as_ref()),
        prevout_index: *input.prevout_index(),
        sequence: *input.sequence(),
        value: input.value().into_u64(),
        script_pubkey: hex::encode(input.script_pubkey().to_bytes()),
        sighash_type: input.sighash_type().encode(),
        derivation,
    })
}

fn view_transparent_output(
    output: &zcash_transparent::pczt::Output,
    account: &Account,
) -> Result<ExternalTransparentOutput> {
    Ok(ExternalTransparentOutput {
        value: output.value().into_u64(),
        script_pubkey: hex::encode(output.script_pubkey().to_bytes()),
        derivation: key_derivation(output.bip32_derivation(), account)?,
    })
}

fn view_action_bundle(
    network: &Network,
    bundle: &orchard::pczt::Bundle,
    account: &Account,
) -> Result<Option<ExternalActionBundle>> {
    if bundle.actions().is_empty() {
        return Ok(None);
    }
    let actions = bundle
        .actions()
        .iter()
        .map(|action| view_action(network, action, account))
        .collect::<Result<Vec<_>>>()?;
    let sign_indices = bundle
        .actions()
        .iter()
        .enumerate()
        .filter(|(_, action)| action.spend().spend_auth_sig().is_none())
        .map(|(index, _)| u32::try_from(index))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (magnitude, sign) = bundle.value_sum().magnitude_sign();
    let magnitude = i64::try_from(magnitude)?;
    Ok(Some(ExternalActionBundle {
        actions,
        flags: bundle.flag_byte(),
        value_balance: match sign {
            orchard::value::Sign::Negative => -magnitude,
            orchard::value::Sign::Positive => magnitude,
        },
        anchor: hex::encode(bundle.anchor().to_bytes()),
        note_plaintext_version: lead_byte(bundle.bundle_version().note_version())?,
        sign_indices,
    }))
}

fn lead_byte(version: NoteVersion) -> Result<u8> {
    match version {
        NoteVersion::V2 => Ok(0x02),
        NoteVersion::V3 => Ok(0x03),
        other => Err(anyhow!(
            "note version {other:?} cannot be signed externally"
        )),
    }
}

fn view_action(
    network: &Network,
    action: &orchard::pczt::Action,
    account: &Account,
) -> Result<ExternalAction> {
    let spend = action.spend();
    let output = action.output();
    let missing = |field: &str| anyhow!("an action is missing its {field}");
    let recipient = output
        .recipient()
        .ok_or_else(|| missing("output recipient"))?;
    let note = output.encrypted_note();
    Ok(ExternalAction {
        cv_net: hex::encode(action.cv_net().to_bytes()),
        nullifier: hex::encode(spend.nullifier().to_bytes()),
        rk: hex::encode(<[u8; 32]>::from(spend.rk())),
        spend_recipient: hex::encode(
            spend
                .recipient()
                .ok_or_else(|| missing("spend recipient"))?
                .to_raw_address_bytes(),
        ),
        spend_value: spend.value().ok_or_else(|| missing("spend value"))?.inner(),
        spend_rho: hex::encode(spend.rho().ok_or_else(|| missing("spend rho"))?.to_bytes()),
        spend_rseed: hex::encode(
            spend
                .rseed()
                .as_ref()
                .ok_or_else(|| missing("spend rseed"))?
                .as_bytes(),
        ),
        alpha: hex::encode(spend.alpha().ok_or_else(|| missing("alpha"))?.to_repr()),
        seed_fingerprint: hex::encode([0u8; 32]),
        path: account.zip32_path(),
        cmx: hex::encode(output.cmx().to_bytes()),
        ephemeral_key: hex::encode(note.epk_bytes),
        enc_ciphertext: hex::encode(note.enc_ciphertext.as_ref()),
        out_ciphertext: hex::encode(note.out_ciphertext),
        recipient: hex::encode(recipient.to_raw_address_bytes()),
        recipient_address: UnifiedAddress::from_receivers(Some(recipient), None, None)
            .ok_or_else(|| anyhow!("an Orchard receiver does not form a unified address"))?
            .encode(network),
        value: output
            .value()
            .ok_or_else(|| missing("output value"))?
            .inner(),
        rseed: hex::encode(
            output
                .rseed()
                .as_ref()
                .ok_or_else(|| missing("output rseed"))?
                .as_bytes(),
        ),
        rcv: hex::encode(
            action
                .rcv()
                .as_ref()
                .ok_or_else(|| missing("rcv"))?
                .to_bytes(),
        ),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::account::derive_transparent_sk;
    use crate::account::tests::restore;
    use crate::api::pay::{pack_transaction, unpack_transaction};
    use crate::db::tests::memory_db;
    use crate::pay::plan::{
        extract_transaction, label_transparent_outputs, TransparentChangeLabel,
    };
    use incrementalmerkletree::{Hashable as _, Level};
    use orchard::{
        keys::{FullViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
        note::{AssetBase, RandomSeed, Rho},
        tree::{MerkleHashOrchard, MerklePath},
        value::NoteValue,
        Note,
    };
    use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, updater::Updater};
    use ripemd::Ripemd160;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use sha2::{Digest as _, Sha256};
    use std::convert::Infallible;
    use zcash_keys::encoding::AddressCodec as _;
    use zcash_keys::keys::{Era, UnifiedSpendingKey};
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, BundlePadding},
        fees::zip317::FeeRule,
    };
    use zcash_protocol::{consensus::BlockHeight, memo::MemoBytes, value::Zatoshis};
    use zcash_transparent::{
        address::TransparentAddress,
        builder::{SpendInfo, TransparentInputInfo},
        bundle::{OutPoint, TxOut},
        keys::AccountPrivKey,
        pczt::Bip32Derivation,
    };

    /// Speculos' default seed: the device under test in the emulator holds exactly this one.
    pub(crate) const SPECULOS_PHRASE: &str = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin";

    /// app-zcash `tests/standalone/test_pubkey_cmd.py`: what the device answers for account 0/1.
    const DEVICE_UFVK_ACCOUNT_0: &str = "uview1zkk7f8hp2m5v09kq7h29vkgngwhhvgy2ey32cy5j0kp69g7ju2vqjvnue03u99z382rtkgvj3f8vtqdtxfxvgjytezgt39dqc0lyt2sj084jdq4md69snc3wxdcl8uah8sxw3rrt9pnxnfl3r4xnczapts7gr4l0cuell7dcjv36gkdcsl4axps827xt6fgmfl78zlhddec72tn2p0eqnpkuy7a08puhj97v0ahxuqlyzmyqtldqnc0p3696d9ww8x6mpd56mz6w32twryevru2rx34lf8dtqsp50gar";
    const DEVICE_UFVK_ACCOUNT_1: &str = "uview15lcx60j8zufp6qe5xveppqjjw3ukg5n90ln8uhgdxukp60tejk626763gffftfw4a2mjkxy4s9mpjdd6ckfkecz846jdvth57djchnpq7699v09g7eu9xnyyfeqtvm5jxhvpn6dxkzqq3726xwhxmn458a8hd2agvl30r2kz9cde8d8nd3e7akdkufuzp3hyule9v0w3a6qx5p5fx8qa3wvjcj9qg9ypnr56m672rsv9y8fqn20usqzhxmrnmm2jf7gnh8kdk68dyvej9jlsm522w24jvce0lcqpn3mf";
    const DEVICE_ORCHARD_ADDRESS_ACCOUNT_0: &str = "u1u2h4ce7e2cn3z4nzur95muq2dl4da9x8h8kdp2l80gm9nl9raj8zzpx79ycjnfvar4v5exea5pqr5y9qsnlp0cdunwf9yjjx5c4q7ar9";

    const TRANSPARENT_AND_ORCHARD: u8 = 0b101;
    // NU6.2: the last branch whose transactions are v5 by default.
    const V5_HEIGHT: u32 = 3_400_000;
    const V6_HEIGHT: u32 = 3_500_000;
    const H: u32 = HARDENED;

    #[derive(Clone, Copy, PartialEq, Debug)]
    pub(crate) enum ShieldedPool {
        Orchard,
        Ironwood,
    }

    /// A planned payment: which pool funds it, which pool it pays into, and at which height.
    #[derive(Clone, Copy, PartialEq, Debug)]
    pub(crate) enum Fixture {
        V5Orchard,
        V6Ironwood,
        /// An old Orchard note spent after NU6.3: both bundles in one v6 transaction.
        V6OrchardToIronwood,
    }

    impl Fixture {
        fn height(self) -> u32 {
            match self {
                Fixture::V5Orchard => V5_HEIGHT,
                Fixture::V6Ironwood | Fixture::V6OrchardToIronwood => V6_HEIGHT,
            }
        }

        fn spend_pool(self) -> ShieldedPool {
            match self {
                Fixture::V5Orchard | Fixture::V6OrchardToIronwood => ShieldedPool::Orchard,
                Fixture::V6Ironwood => ShieldedPool::Ironwood,
            }
        }

        /// ZIP-317: one transparent action plus two per shielded bundle (the spend and the
        /// outputs share actions, padded to two).
        fn fee(self) -> u64 {
            match self {
                Fixture::V5Orchard | Fixture::V6Ironwood => 15_000,
                Fixture::V6OrchardToIronwood => 25_000,
            }
        }

        /// The planner pays change to a single pool, and the device refuses a second change.
        fn transparent_change(self) -> bool {
            matches!(self, Fixture::V5Orchard)
        }

        fn output_pool(self) -> ShieldedPool {
            match self {
                Fixture::V5Orchard => ShieldedPool::Orchard,
                Fixture::V6Ironwood | Fixture::V6OrchardToIronwood => ShieldedPool::Ironwood,
            }
        }
    }

    pub(crate) struct DeviceKeys {
        fvk: FullViewingKey,
        ask: SpendAuthorizingKey,
        tsk: AccountPrivKey,
    }

    pub(crate) fn speculos_keys() -> DeviceKeys {
        let bytes = crate::account::derive_spending_key(&Network::Main, SPECULOS_PHRASE, None, 0)
            .expect("derive");
        let usk = UnifiedSpendingKey::from_bytes(Era::Orchard, &bytes).expect("usk");
        DeviceKeys {
            fvk: FullViewingKey::from(usk.orchard()),
            ask: SpendAuthorizingKey::from(usk.orchard()),
            tsk: usk.transparent().clone(),
        }
    }

    fn transparent_key(keys: &DeviceKeys, scope: u32, dindex: u32) -> (SecretKey, PublicKey) {
        let sk = derive_transparent_sk(&keys.tsk, scope, dindex).expect("derive sk");
        let sk = SecretKey::from_slice(&sk).expect("secret key");
        (sk, PublicKey::from_secret_key(&Secp256k1::new(), &sk))
    }

    fn p2pkh(pubkey: &PublicKey) -> TransparentAddress {
        TransparentAddress::PublicKeyHash(
            Ripemd160::digest(Sha256::digest(pubkey.serialize())).into(),
        )
    }

    /// A spendable note of `value` at the account's own address, alone in an otherwise empty tree.
    fn own_note(
        keys: &DeviceKeys,
        pool: ShieldedPool,
        value: u64,
    ) -> (Note, MerklePath, orchard::Anchor) {
        let rho = Rho::from_bytes(&[0u8; 32]).expect("rho");
        let rseed = RandomSeed::from_bytes([7u8; 32], &rho).expect("rseed");
        let version = match pool {
            ShieldedPool::Orchard => NoteVersion::V2,
            ShieldedPool::Ironwood => NoteVersion::V3,
        };
        let note = Note::from_parts(
            keys.fvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(value),
            AssetBase::zatoshi(),
            rho,
            rseed,
            version,
        )
        .expect("note");
        let auth_path =
            std::array::from_fn(|level| MerkleHashOrchard::empty_root(Level::from(level as u8)));
        let path = MerklePath::from_parts(0, auth_path);
        let anchor = path.root(note.commitment().into());
        (note, path, anchor)
    }

    fn third_party_address() -> orchard::Address {
        let sk = SpendingKey::from_bytes([9u8; 32]).expect("sk");
        FullViewingKey::from(&sk).address_at(0u32, Scope::External)
    }

    /// What the planner produces for a device account: one shielded spend plus one transparent
    /// input, a payment to a third party and the change, after the IO Finalizer.
    pub(crate) fn planned_package(keys: &DeviceKeys, fixture: Fixture) -> PcztPackage {
        let (note, merkle_path, anchor) = own_note(keys, fixture.spend_pool(), 100_000);
        let height = fixture.height();
        let anchor_of = |pool: ShieldedPool| {
            let used = fixture.spend_pool() == pool || fixture.output_pool() == pool;
            used.then_some(anchor)
        };
        let build_config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: anchor_of(ShieldedPool::Orchard),
            ironwood_anchor: anchor_of(ShieldedPool::Ironwood),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(&Network::Main, BlockHeight::from_u32(height), build_config);

        let (_, input_pubkey) = transparent_key(keys, 0, 0);
        let coin = TxOut::new(
            Zatoshis::const_from_u64(50_000),
            p2pkh(&input_pubkey).script().into(),
        );
        builder.add_transparent_input(
            TransparentInputInfo::from_parts(
                OutPoint::new([0x11; 32], 1),
                coin,
                SpendInfo::P2pkh {
                    pubkey: input_pubkey,
                },
            )
            .expect("input"),
        );
        let change_value = 100_000 + 50_000 - 60_000 - fixture.fee();
        let (_, change_pubkey) = transparent_key(keys, 1, 0);
        if fixture.transparent_change() {
            builder
                .add_transparent_output(
                    &p2pkh(&change_pubkey),
                    Zatoshis::const_from_u64(change_value),
                )
                .expect("transparent change");
        }

        let ovk = Some(keys.fvk.to_ovk(Scope::External));
        let change = keys.fvk.address_at(0u32, Scope::Internal);
        match fixture.spend_pool() {
            ShieldedPool::Orchard => {
                builder.add_orchard_spend::<Infallible>(keys.fvk.clone(), note, merkle_path)
            }
            ShieldedPool::Ironwood => {
                builder.add_ironwood_spend::<Infallible>(keys.fvk.clone(), note, merkle_path)
            }
        }
        .expect("spend");
        let mut outputs = vec![(third_party_address(), 60_000)];
        if !fixture.transparent_change() {
            outputs.push((change, change_value));
        }
        for (to, value) in outputs {
            let value = Zatoshis::const_from_u64(value);
            match fixture.output_pool() {
                ShieldedPool::Orchard => builder.add_orchard_output::<Infallible>(
                    ovk.clone(),
                    to,
                    value,
                    AssetBase::zatoshi(),
                    MemoBytes::empty(),
                ),
                ShieldedPool::Ironwood => builder.add_ironwood_output::<Infallible>(
                    ovk.clone(),
                    to,
                    value,
                    MemoBytes::empty(),
                ),
            }
            .expect("output");
        }

        let built = builder
            .build_for_pczt(
                rand_core::OsRng,
                &FeeRule::standard(),
                |_asset: &AssetBase| false,
            )
            .expect("build_for_pczt");
        let ironwood_spend = built.ironwood_meta.spend_action_index(0);
        let pczt = Creator::build_from_parts(built.pczt_parts).expect("creator");
        let pczt = Updater::new(pczt)
            .update_transparent_with(|mut u| {
                u.update_input_with(0, |mut u| {
                    let path = Bip32Derivation::parse([0u8; 32], vec![0, 0]).expect("path");
                    u.set_bip32_derivation(input_pubkey.serialize(), path);
                    u.set_proprietary("scope".to_string(), 0u32.to_le_bytes().to_vec());
                    u.set_proprietary("dindex".to_string(), 0u32.to_le_bytes().to_vec());
                    u.set_hash160_preimage(input_pubkey.serialize().to_vec());
                    Ok(())
                })?;
                label_transparent_outputs(
                    u,
                    vec![],
                    fixture
                        .transparent_change()
                        .then(|| TransparentChangeLabel {
                            pubkey: change_pubkey,
                            scope: 1,
                            dindex: 0,
                            address: p2pkh(&change_pubkey).encode(&Network::Main),
                        }),
                )
            })
            .expect("update")
            .finish();
        let (pczt, _) = IoFinalizer::new(pczt).finalize_io().expect("finalize_io");

        PcztPackage {
            n_spends: match fixture.spend_pool() {
                ShieldedPool::Orchard => [1, 0, 1, 0],
                ShieldedPool::Ironwood => [1, 0, 0, 1],
            },
            sapling_indices: vec![],
            orchard_indices: unsigned_actions(pczt.orchard().actions()),
            ironwood_indices: ironwood_spend.into_iter().collect(),
            can_sign: false,
            can_broadcast: false,
            price: None,
            category: None,
            is_issuance: false,
            pczt: pczt.serialize().expect("serialize"),
        }
    }

    pub(crate) struct DeviceSignatures {
        orchard: Vec<(u32, [u8; 64])>,
        ironwood: Vec<(u32, [u8; 64])>,
        transparent: Vec<(u32, Vec<u8>)>,
    }

    /// What the device answers, produced with the same keys on the host.
    pub(crate) fn device_signatures(keys: &DeviceKeys, package: &PcztPackage) -> DeviceSignatures {
        let view = external_signing_view(&Network::Main, package, 0).expect("view");
        let pczt = parse(package).expect("parse");
        let mut signer = Signer::new(pczt).expect("signer");
        let transparent = view
            .transparent_inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                let path = &input.derivation.path;
                let (sk, _) = transparent_key(keys, path[3], path[4]);
                let sighash = signer.transparent_sighash(index).expect("sighash");
                let signature =
                    Secp256k1::new().sign_ecdsa(&secp256k1::Message::from_digest(sighash), &sk);
                let mut der = signature.serialize_der().to_vec();
                der.push(SIGHASH_ALL);
                (index as u32, der)
            })
            .collect();
        let sign_indices = |bundle: &Option<ExternalActionBundle>| -> Vec<u32> {
            bundle
                .as_ref()
                .map(|b| b.sign_indices.clone())
                .unwrap_or_default()
        };
        for &index in &sign_indices(&view.orchard) {
            signer
                .sign_orchard(index as usize, &keys.ask)
                .expect("sign orchard");
        }
        for &index in &sign_indices(&view.ironwood) {
            signer
                .sign_ironwood(index as usize, &keys.ask)
                .expect("sign ironwood");
        }
        let signed = signer.finish();
        let read = |actions: &[pczt::orchard::Action], indices: Vec<u32>| -> Vec<(u32, [u8; 64])> {
            indices
                .into_iter()
                .map(|index| {
                    (
                        index,
                        actions[index as usize]
                            .spend()
                            .spend_auth_sig()
                            .expect("signed"),
                    )
                })
                .collect()
        };
        DeviceSignatures {
            orchard: read(signed.orchard().actions(), sign_indices(&view.orchard)),
            ironwood: read(signed.ironwood().actions(), sign_indices(&view.ironwood)),
            transparent,
        }
    }

    fn apply(package: &PcztPackage, signatures: &DeviceSignatures) -> Result<PcztPackage> {
        apply_external_signatures(
            package,
            &signatures.orchard,
            &signatures.ironwood,
            &signatures.transparent,
        )
    }

    fn assert_refused(result: Result<impl std::fmt::Debug>, code: &str) {
        let error = result.expect_err("must be refused").to_string();
        assert!(
            error.contains(&format!("[external-signing:{code}]")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn external_signing_view_v5_has_full_paths_zip32_on_every_action_and_no_dummy_to_sign() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);

        let view = external_signing_view(&Network::Main, &package, 0).expect("view");

        assert_eq!(
            (view.tx_version, view.version_group_id, view.coin_type),
            (5, 0x26A7_270A, 133)
        );
        assert_eq!(
            view.transparent_inputs[0].derivation.path,
            vec![44 | H, 133 | H, H, 0, 0]
        );
        assert_eq!(view.transparent_inputs[0].sighash_type, SIGHASH_ALL);
        let change = view.transparent_outputs[0]
            .derivation
            .as_ref()
            .expect("change derivation");
        assert_eq!(change.path, vec![44 | H, 133 | H, H, 1, 0]);
        let orchard = view.orchard.expect("orchard bundle");
        assert_eq!(orchard.actions.len(), 2);
        assert!(orchard
            .actions
            .iter()
            .all(|action| action.path == vec![32 | H, 133 | H, H]));
        assert_eq!(orchard.sign_indices.len(), 1);
        let real = orchard.sign_indices[0] as usize;
        assert_eq!(orchard.actions[real].spend_value, 100_000);
        assert_eq!(orchard.actions[1 - real].spend_value, 0);
        assert_eq!(orchard.note_plaintext_version, 0x02);
        assert_eq!(orchard.value_balance, 100_000 - 60_000);
        assert!(view.ironwood.is_none());
    }

    #[test]
    fn external_signing_view_v6_reports_the_ironwood_bundle_with_v3_notes() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V6Ironwood);

        let view = external_signing_view(&Network::Main, &package, 0).expect("view");

        assert_eq!((view.tx_version, view.version_group_id), (6, 0xD884_B698));
        assert!(view.orchard.is_none());
        let ironwood = view.ironwood.expect("ironwood bundle");
        assert!(ironwood
            .actions
            .iter()
            .all(|action| action.path == vec![32 | H, 133 | H, H]));
        assert_eq!(
            ironwood.sign_indices,
            vec![package.ironwood_indices[0] as u32]
        );
        assert_eq!(ironwood.note_plaintext_version, 0x03);
    }

    #[test]
    fn external_signing_view_shows_the_third_party_as_an_orchard_only_address() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);
        let expected = UnifiedAddress::from_receivers(Some(third_party_address()), None, None)
            .expect("ua")
            .encode(&Network::Main);

        let view = external_signing_view(&Network::Main, &package, 0).expect("view");

        let orchard = view.orchard.expect("orchard bundle");
        assert!(orchard
            .actions
            .iter()
            .any(|action| action.recipient_address == expected && action.value == 60_000));
    }

    #[test]
    fn external_signing_view_paths_follow_the_requested_account() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);

        let view = external_signing_view(&Network::Main, &package, 7).expect("view");

        assert_eq!(view.transparent_inputs[0].derivation.path[2], 7 | H);
        assert_eq!(
            view.orchard.expect("orchard").actions[0].path,
            vec![32 | H, 133 | H, 7 | H]
        );
        assert!(external_signing_view(&Network::Main, &package, H).is_err());
    }

    #[test]
    fn apply_external_signatures_rejects_a_dummy_action_index() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);
        let mut signatures = device_signatures(&keys, &package);
        let real = signatures.orchard[0].0;
        signatures.orchard[0].0 = 1 - real;

        let error = apply(&package, &signatures)
            .err()
            .expect("a dummy must not be signed")
            .to_string();
        assert!(error.contains("out of range"), "unexpected error: {error}");
    }

    #[test]
    fn apply_external_signatures_rejects_a_missing_transparent_signature() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);
        let mut signatures = device_signatures(&keys, &package);
        signatures.transparent.clear();

        let error = apply(&package, &signatures)
            .err()
            .expect("must be rejected")
            .to_string();
        assert!(
            error.contains("missing a signature for transparent input 0"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn apply_external_signatures_rejects_a_transparent_signature_without_sighash_all() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);
        let mut signatures = device_signatures(&keys, &package);
        // Not `pop()`: the DER body's own last byte is 0x01 once in 256 runs.
        *signatures.transparent[0]
            .1
            .last_mut()
            .expect("sighash type byte") = 0x02;

        let error = apply(&package, &signatures)
            .err()
            .expect("must be rejected")
            .to_string();
        assert!(error.contains("SIGHASH_ALL"), "unexpected error: {error}");
    }

    #[test]
    fn apply_external_signatures_rejects_an_orchard_signature_that_does_not_verify() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);
        let mut signatures = device_signatures(&keys, &package);
        signatures.orchard[0].1[0] ^= 0x01;

        let error = apply(&package, &signatures)
            .err()
            .expect("must be rejected")
            .to_string();
        assert!(
            error.contains("Orchard action"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn apply_external_signatures_rejects_a_transparent_signature_that_does_not_verify() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);
        let other = planned_package(&keys, Fixture::V5Orchard);
        let mut signatures = device_signatures(&keys, &package);
        signatures.transparent = device_signatures(&keys, &other).transparent;

        let error = apply(&package, &signatures)
            .err()
            .expect("must be rejected")
            .to_string();
        assert!(
            error.contains("failed sighash verification"),
            "unexpected error: {error}"
        );
    }

    async fn prove_sign_extract(fixture: Fixture) -> Vec<u8> {
        let keys = speculos_keys();
        let package = planned_package(&keys, fixture);
        let proved = prove_transaction(&package).await.expect("prove");
        assert!(!proved.can_broadcast);
        let signatures = device_signatures(&keys, &proved);

        let signed = apply(&proved, &signatures).expect("apply");

        assert!(signed.can_broadcast);
        extract_transaction(&signed)
            .await
            .expect("extract verifies proofs and signatures")
    }

    #[tokio::test]
    async fn apply_external_signatures_v5_orchard_and_transparent_extracts() {
        let tx = prove_sign_extract(Fixture::V5Orchard).await;
        assert_eq!(&tx[..4], &[0x05, 0x00, 0x00, 0x80]);
    }

    #[tokio::test]
    async fn apply_external_signatures_v6_ironwood_and_transparent_extracts() {
        let tx = prove_sign_extract(Fixture::V6Ironwood).await;
        assert_eq!(&tx[..4], &[0x06, 0x00, 0x00, 0x80]);
    }

    #[tokio::test]
    async fn apply_external_signatures_v6_with_both_bundles_extracts() {
        let tx = prove_sign_extract(Fixture::V6OrchardToIronwood).await;
        assert_eq!(&tx[..4], &[0x06, 0x00, 0x00, 0x80]);
    }

    #[test]
    fn external_signing_view_v6_lists_both_bundles_and_signs_only_the_orchard_spend() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V6OrchardToIronwood);

        let view = external_signing_view(&Network::Main, &package, 0).expect("view");

        assert_eq!(view.tx_version, 6);
        let orchard = view.orchard.expect("orchard bundle");
        assert_eq!(orchard.sign_indices.len(), 1);
        assert_eq!(orchard.note_plaintext_version, 0x02);
        let ironwood = view.ironwood.expect("ironwood bundle");
        assert!(ironwood.sign_indices.is_empty());
        assert_eq!(ironwood.note_plaintext_version, 0x03);
    }

    #[tokio::test]
    async fn apply_external_signatures_without_proofs_does_not_extract() {
        let keys = speculos_keys();
        let package = planned_package(&keys, Fixture::V5Orchard);
        let signed = apply(&package, &device_signatures(&keys, &package)).expect("apply");

        assert!(extract_transaction(&signed).await.is_err());
    }

    #[test]
    fn check_recipient_pools_refuses_a_sapling_recipient() {
        assert_refused(
            check_recipient_pools(&[0, 1]).map_err(anyhow::Error::from),
            "sapling",
        );
    }

    #[test]
    fn check_recipient_pools_refuses_a_fifth_shielded_recipient() {
        assert!(check_recipient_pools(&[2, 3, 2, 3, 0, 0]).is_ok());
        assert_refused(
            check_recipient_pools(&[2, 3, 2, 3, 2]).map_err(anyhow::Error::from),
            "shielded-recipients",
        );
    }

    #[test]
    fn usable_pools_exclude_only_sapling() {
        assert_eq!(USABLE_POOLS, 0b1101);
    }

    fn transparent_only_pczt(inputs: usize, outputs: usize) -> Pczt {
        let keys = speculos_keys();
        let (_, pubkey) = transparent_key(&keys, 0, 0);
        let config = BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let mut builder = Builder::new(&Network::Main, BlockHeight::from_u32(V5_HEIGHT), config);
        for n in 0..inputs {
            let coin = TxOut::new(
                Zatoshis::const_from_u64(100_000),
                p2pkh(&pubkey).script().into(),
            );
            builder.add_transparent_input(
                TransparentInputInfo::from_parts(
                    OutPoint::new([0x22; 32], n as u32),
                    coin,
                    SpendInfo::P2pkh { pubkey },
                )
                .expect("input"),
            );
        }
        let fee = 5_000 * inputs.max(outputs).max(2) as u64;
        let paid = (100_000 * inputs as u64 - fee) / outputs as u64;
        let remainder = 100_000 * inputs as u64 - fee - paid * outputs as u64;
        for n in 0..outputs {
            let value = paid + if n == 0 { remainder } else { 0 };
            builder
                .add_transparent_output(&p2pkh(&pubkey), Zatoshis::const_from_u64(value))
                .expect("output");
        }
        let built = builder
            .build_for_pczt(
                rand_core::OsRng,
                &FeeRule::standard(),
                |_asset: &AssetBase| false,
            )
            .expect("build_for_pczt");
        Creator::build_from_parts(built.pczt_parts).expect("creator")
    }

    #[test]
    fn check_device_limits_refuses_a_33rd_transparent_input() {
        assert!(check_device_limits(&transparent_only_pczt(32, 1)).is_ok());
        assert_eq!(
            check_device_limits(&transparent_only_pczt(33, 1)),
            Err(ExternalSigningRefusal::TransparentInputs)
        );
    }

    #[test]
    fn check_device_limits_refuses_an_11th_transparent_output() {
        assert!(check_device_limits(&transparent_only_pczt(1, 10)).is_ok());
        assert_eq!(
            check_device_limits(&transparent_only_pczt(1, 11)),
            Err(ExternalSigningRefusal::TransparentOutputs)
        );
    }

    #[test]
    fn external_signing_view_refuses_a_sapling_bundle() {
        let config = BuildConfig::Standard {
            sapling_anchor: Some(sapling_crypto::Anchor::empty_tree()),
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        };
        let keys = speculos_keys();
        let (_, pubkey) = transparent_key(&keys, 0, 0);
        let mut builder = Builder::new(&Network::Main, BlockHeight::from_u32(V5_HEIGHT), config);
        let coin = TxOut::new(
            Zatoshis::const_from_u64(100_000),
            p2pkh(&pubkey).script().into(),
        );
        builder.add_transparent_input(
            TransparentInputInfo::from_parts(
                OutPoint::new([0x33; 32], 0),
                coin,
                SpendInfo::P2pkh { pubkey },
            )
            .expect("input"),
        );
        let sapling_to = sapling_crypto::zip32::ExtendedSpendingKey::master(&[1u8; 32])
            .default_address()
            .1;
        builder
            .add_sapling_output::<Infallible>(
                None,
                sapling_to,
                Zatoshis::const_from_u64(85_000),
                MemoBytes::empty(),
            )
            .expect("sapling output");
        let built = builder
            .build_for_pczt(
                rand_core::OsRng,
                &FeeRule::standard(),
                |_asset: &AssetBase| false,
            )
            .expect("build_for_pczt");
        let pczt = Creator::build_from_parts(built.pczt_parts).expect("creator");
        let mut package = planned_package(&keys, Fixture::V5Orchard);
        package.pczt = pczt.serialize().expect("serialize");

        assert_refused(
            external_signing_view(&Network::Main, &package, 0),
            "sapling",
        );
    }

    #[tokio::test]
    async fn device_ufvk_matches_the_sdk_derivation_restricted_to_transparent_and_orchard() {
        let mut connection = memory_db().await;
        for (aindex, device_ufvk) in [(0, DEVICE_UFVK_ACCOUNT_0), (1, DEVICE_UFVK_ACCOUNT_1)] {
            let account = restore(&mut connection, SPECULOS_PHRASE, aindex, None)
                .await
                .expect("restore");
            let ufvk = crate::key::get_account_ufvk(
                &Network::Main,
                &mut connection,
                account,
                TRANSPARENT_AND_ORCHARD,
            )
            .await
            .expect("ufvk");
            assert_eq!(ufvk, device_ufvk, "account {aindex}");
        }
    }

    #[test]
    fn orchard_only_address_of_the_device_account_ua_is_the_address_the_device_reports() {
        let (full, _) =
            crate::api::account::unified_address(0, DEVICE_UFVK_ACCOUNT_0, Some(0)).expect("ua");

        assert_eq!(
            crate::api::account::orchard_only_address(0, &full).as_deref(),
            Some(DEVICE_ORCHARD_ADDRESS_ACCOUNT_0)
        );
    }

    #[test]
    fn orchard_only_address_is_the_recipient_the_device_shows_for_orchard_and_ironwood_outputs() {
        use zcash_address::unified::{Address, Encoding as _, Receiver};
        let full = Address::try_from_items(vec![
            Receiver::P2pkh([7u8; 20]),
            Receiver::Orchard(third_party_address().to_raw_address_bytes()),
        ])
        .expect("ua")
        .encode(&zcash_protocol::consensus::NetworkType::Main);

        // Read off the speculos review screens of the v5-orchard and v6-ironwood fixtures.
        assert_eq!(
            crate::api::account::orchard_only_address(0, &full).as_deref(),
            Some("u1evdt2sqv0hgjvmg9uhl50q7xlawxaehlvk7eldmwspz58w374kylvy0fm8mncqggldputmy5uztk384s6k7k9kkr9al5559n6cpfnkc5")
        );
    }

    #[tokio::test]
    async fn device_ufvk_imports_as_a_watch_account_whose_orchard_address_is_the_devices() {
        let mut connection = memory_db().await;
        let account = restore(
            &mut connection,
            DEVICE_UFVK_ACCOUNT_0,
            0,
            Some(TRANSPARENT_AND_ORCHARD),
        )
        .await
        .expect("restore");

        let ufvk = crate::key::get_account_ufvk(
            &Network::Main,
            &mut connection,
            account,
            TRANSPARENT_AND_ORCHARD,
        )
        .await
        .expect("ufvk");
        assert_eq!(ufvk, DEVICE_UFVK_ACCOUNT_0);
        let orchard_only =
            crate::key::get_account_ufvk(&Network::Main, &mut connection, account, 0b100)
                .await
                .expect("orchard ufvk");
        let decoded =
            zcash_keys::keys::UnifiedFullViewingKey::decode(&Network::Main, &orchard_only)
                .expect("decode");
        let (address, index) = decoded
            .default_address(zcash_keys::keys::UnifiedAddressRequest::AllAvailableKeys)
            .expect("address");
        assert_eq!(u32::try_from(index).expect("index"), 0);
        assert_eq!(
            address.encode(&Network::Main),
            DEVICE_ORCHARD_ADDRESS_ACCOUNT_0
        );
    }

    /// Writes V5 and V6 planned packages for the speculos end-to-end run (not part of CI).
    #[test]
    #[ignore]
    fn write_speculos_fixtures() {
        let dir =
            std::env::var("EXTERNAL_SIGNING_FIXTURE_DIR").expect("EXTERNAL_SIGNING_FIXTURE_DIR");
        let keys = speculos_keys();
        for (name, fixture) in [
            ("v5-orchard.pkg", Fixture::V5Orchard),
            ("v6-ironwood.pkg", Fixture::V6Ironwood),
            ("v6-orchard-to-ironwood.pkg", Fixture::V6OrchardToIronwood),
        ] {
            let packed = pack_transaction(&planned_package(&keys, fixture)).expect("pack");
            unpack_transaction(&packed).expect("round trip");
            std::fs::write(std::path::Path::new(&dir).join(name), packed).expect("write");
        }
    }
}
