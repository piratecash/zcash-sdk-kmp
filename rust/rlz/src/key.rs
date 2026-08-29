use std::str::FromStr as _;

use crate::{api::coin::Network, db::get_account_dindex};
use anyhow::Result;
use bech32::Hrp;
use bip32::{
    ChildNumber, ExtendedKey, ExtendedKeyAttrs, ExtendedPrivateKey, ExtendedPublicKey, Prefix,
};
use bip39::Mnemonic;
use secp256k1::{PublicKey, SecretKey};
use sqlx::SqliteConnection;
use zcash_address::unified::{Encoding as _, Fvk, Ufvk};
use zcash_keys::{
    encoding::{decode_extended_full_viewing_key, decode_extended_spending_key, AddressCodec as _},
    keys::UnifiedFullViewingKey,
};
use zcash_protocol::consensus::NetworkConstants as _;
use zcash_transparent::address::TransparentAddress;

use crate::{
    bip38,
    db::{select_account_orchard, select_account_sapling, select_account_transparent},
};

pub async fn get_account_ufvk(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    pools: u8,
) -> Result<String> {
    let dindex = get_account_dindex(connection, account).await?;
    let tkeys = select_account_transparent(connection, account, dindex).await?;
    let skeys = select_account_sapling(network, connection, account).await?;
    let okeys = select_account_orchard(connection, account).await?;

    let items = vec![
        tkeys.xvk.clone().and_then(|vk| {
            if pools & 1 != 0 {
                Some(Fvk::P2pkh(vk.serialize().try_into().unwrap()))
            } else {
                None
            }
        }),
        skeys.xvk.and_then(|vk| {
            if pools & 2 != 0 {
                Some(Fvk::Sapling(vk.to_bytes()))
            } else {
                None
            }
        }),
        okeys.xvk.and_then(|vk| {
            if pools & 4 != 0 {
                Some(Fvk::Orchard(vk.to_bytes()))
            } else {
                None
            }
        }),
    ];
    let items = items.into_iter().flatten().collect::<Vec<Fvk>>();

    if items.is_empty() {
        return Err(anyhow::anyhow!("Viewing key has no receivers"));
    }
    if items.len() == 1 {
        if let Some(Fvk::P2pkh(data)) = items.first() {
            // special case for transparent keys since UFVK do not support them
            let chain_code = data[..32].try_into().unwrap(); // first 32 bytes is the chain code
            let public_key = PublicKey::from_slice(&data[32..])?; // next 33 bytes is the public key
            let xpub = ExtendedPublicKey::new(
                public_key,
                ExtendedKeyAttrs {
                    depth: 3,
                    // dummy values for parent fingerprint and child number
                    parent_fingerprint: [0xff, 0xff, 0xff, 0xff],
                    child_number: ChildNumber::new(0, true).unwrap(),
                    chain_code,
                },
            );
            let xpub = xpub.to_extended_key(Prefix::XPUB);
            return Ok(xpub.to_string());
        }
    }

    let ufvk = Ufvk::try_from_items(items)?;
    let ufvk = UnifiedFullViewingKey::parse(&ufvk)?;

    Ok(ufvk.encode(network))
}

pub fn is_valid_phrase(phrase: &str) -> bool {
    let mnemonic = Mnemonic::parse(phrase);
    mnemonic.is_ok()
}

/// The BIP-32 versions a Zcash transparent extended key carries on `network`: private, public.
fn transparent_prefixes(network: &Network) -> (Prefix, Prefix) {
    match network {
        Network::Main => (Prefix::XPRV, Prefix::XPUB),
        _ => (Prefix::TPRV, Prefix::TPUB),
    }
}

/// `bip32` validates only that a prefix is four ASCII letters, never the version bytes, so
/// without this another coin's account key (`Ltpv`, `yprv`, `dgpv`) parses as ours.
fn has_prefix(key: &str, expected: Prefix) -> bool {
    ExtendedKey::from_str(key).is_ok_and(|k| k.prefix.version() == expected.version())
}

/// A transparent extended private key (`xprv` on mainnet, `tprv` elsewhere). Any depth parses;
/// callers treat it as the account node, so rejecting a root key is the embedding application's
/// job. A Bitcoin `xprv` stays indistinguishable: Zcash reuses its version bytes.
pub fn is_account_xprv(network: &Network, key: &str) -> bool {
    has_prefix(key, transparent_prefixes(network).0)
        && ExtendedPrivateKey::<SecretKey>::from_str(key).is_ok()
}

/// A transparent extended public key, with the same caveats as [`is_account_xprv`].
pub fn is_account_xpub(network: &Network, key: &str) -> bool {
    has_prefix(key, transparent_prefixes(network).1)
        && ExtendedPublicKey::<PublicKey>::from_str(key).is_ok()
}

/// A Sapling extended spending key (`secret-extended-key-main` on mainnet).
pub fn is_sapling_esk(network: &Network, key: &str) -> bool {
    decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), key).is_ok()
}

/// A Sapling extended full viewing key.
pub fn is_sapling_efvk(network: &Network, key: &str) -> bool {
    decode_extended_full_viewing_key(network.hrp_sapling_extended_full_viewing_key(), key).is_ok()
}

pub fn is_valid_transparent_key(network: &Network, key: &str) -> bool {
    if bip38::import_tsk(key).is_ok() {
        return true;
    }

    if is_account_xprv(network, key) {
        return true;
    }

    if is_account_xpub(network, key) {
        return true;
    }

    if let Ok((hrp, pk)) = bech32::decode(key) {
        if hrp == Hrp::parse_unchecked("zpk") && PublicKey::from_slice(&pk).is_ok() {
            return true;
        }
    }

    false
}

pub fn is_valid_sapling_key(network: &Network, key: &str) -> bool {
    is_sapling_esk(network, key) || is_sapling_efvk(network, key)
}

pub fn is_valid_ufvk(network: &Network, key: &str) -> bool {
    UnifiedFullViewingKey::decode(network, key).is_ok()
}

pub fn is_valid_transparent_address(network: &Network, address: &str) -> bool {
    TransparentAddress::decode(network, address).is_ok()
}
