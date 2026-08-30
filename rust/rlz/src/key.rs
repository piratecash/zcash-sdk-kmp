use std::str::FromStr as _;

use crate::{api::coin::Network, db::get_account_dindex};
use anyhow::Result;
use bech32::Hrp;
use bip32::{
    ChildNumber, ExtendedKey, ExtendedKeyAttrs, ExtendedPrivateKey, ExtendedPublicKey, Prefix,
};
use bip39::{Language, Mnemonic};
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

/// Auto-detection rejects a phrase whose every word exists in two wordlists
/// (EN/FR share 100 words, the two Chinese lists 1275), so try each language in
/// turn, English first, instead of `Mnemonic::parse`.
/// Never call `to_entropy()` on the result: it panics on an ambiguous phrase.
pub(crate) fn parse_mnemonic(phrase: &str) -> Result<Mnemonic, bip39::Error> {
    match Mnemonic::parse_in(Language::English, phrase) {
        Ok(mnemonic) => Ok(mnemonic),
        Err(english_error) => Language::ALL
            .iter()
            .find_map(|&language| Mnemonic::parse_in(language, phrase).ok())
            .ok_or(english_error),
    }
}

pub fn is_valid_phrase(phrase: &str) -> bool {
    parse_mnemonic(phrase).is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Identical word sequence in both Chinese lists: the 1275 shared words sit at
    /// identical indices, so the derived key cannot depend on which list won.
    const CHINESE_ZERO_ENTROPY: &str = "的 的 的 的 的 的 的 的 的 的 的 在";

    /// The canonical all-zero-entropy 12-word phrase of every enabled wordlist,
    /// generated once from the vendored lists.
    const ZERO_ENTROPY_PHRASES: [(&str, &str); 10] = [
        ("english", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        ("chinese_simplified", CHINESE_ZERO_ENTROPY),
        ("chinese_traditional", CHINESE_ZERO_ENTROPY),
        ("czech", "abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace agrese"),
        ("french", "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille"),
        ("italian", "abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abete"),
        ("japanese", "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら"),
        ("korean", "가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가능"),
        ("portuguese", "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abater"),
        ("spanish", "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abierto"),
    ];

    const ENGLISH_ZERO_ENTROPY: &str = ZERO_ENTROPY_PHRASES[0].1;

    /// Every word lies in the 100-word English ∩ French intersection and the English
    /// checksum closes, so auto-detection cannot resolve it.
    const SHARED_WITH_FRENCH: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon angle";

    #[test]
    fn parse_mnemonic_every_enabled_language_is_accepted() {
        for (language, phrase) in ZERO_ENTROPY_PHRASES {
            assert!(
                parse_mnemonic(phrase).is_ok(),
                "{language}: {:?}",
                parse_mnemonic(phrase).unwrap_err()
            );
        }
    }

    #[test]
    fn is_valid_phrase_every_enabled_language_is_true() {
        for (language, phrase) in ZERO_ENTROPY_PHRASES {
            assert!(is_valid_phrase(phrase), "{language}");
        }
    }

    #[test]
    fn parse_mnemonic_chinese_shared_words_phrase_derives_the_canonical_seed() {
        let mnemonic = parse_mnemonic(CHINESE_ZERO_ENTROPY).expect("chinese phrase");

        assert_eq!(
            mnemonic.words().collect::<Vec<_>>(),
            CHINESE_ZERO_ENTROPY.split(' ').collect::<Vec<_>>()
        );
        assert_eq!(
            hex::encode(mnemonic.to_seed("")),
            "c015b86e4b208402bb0bdd0febb746708b869bb6e433cb227fd66d444f3ccdc3\
             60fee9ca9271014c2a684df380fcc40bd80a37eaa41a8061a52a18d319cdd899"
        );
    }

    #[test]
    fn parse_mnemonic_words_shared_with_french_resolves_as_english() {
        let mnemonic = parse_mnemonic(SHARED_WITH_FRENCH).expect("shared phrase");

        assert_eq!(
            hex::encode(mnemonic.to_seed("")),
            "363fa97e18a32da4b42d81131f4c82eda56a7bd484df6a5f004a35decc52d6c6\
             d21a45e377a7e698959bf48d73107ae389aeda70273dbfb15a04968c50093862"
        );
    }

    #[test]
    fn is_valid_phrase_english_phrase_is_true() {
        assert!(is_valid_phrase(ENGLISH_ZERO_ENTROPY));
    }

    #[test]
    fn is_valid_phrase_garbage_is_false() {
        assert!(!is_valid_phrase("not a mnemonic at all"));
    }
}
