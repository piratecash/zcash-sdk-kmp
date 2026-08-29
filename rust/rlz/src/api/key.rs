use anyhow::{anyhow, Result};
#[cfg(feature = "flutter")]
use flutter_rust_bridge::frb;
use rand_core::{OsRng, RngCore as _};
use zcash_keys::keys::UnifiedFullViewingKey;

use crate::{
    account,
    api::coin::{network_from_coin, Coin, Network},
    key::{is_valid_sapling_key, is_valid_transparent_key},
    pay::signing_key::{encode_sapling, encode_transparent},
};

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn generate_seed() -> Result<String> {
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let m = bip39::Mnemonic::from_entropy(&entropy)?;
    Ok(m.to_string())
}

/// Hosts that keep the spending key outside the SDK derive it here.
pub fn derive_spending_key(
    coin: u8,
    phrase: &str,
    passphrase: Option<&str>,
    aindex: u32,
) -> Result<Vec<u8>> {
    account::derive_spending_key(&network_from_coin(coin), phrase, passphrase, aindex)
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_valid_phrase(phrase: &str) -> bool {
    crate::key::is_valid_phrase(phrase)
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_valid_fvk(fvk: &str, c: &Coin) -> bool {
    crate::key::is_valid_ufvk(&c.network(), fvk)
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_valid_key(key: &str, c: &Coin) -> bool {
    let network = &c.network();

    if crate::key::is_valid_phrase(key) {
        return true;
    }

    if is_valid_transparent_key(network, key) {
        return true;
    }

    if is_valid_sapling_key(network, key) {
        return true;
    }

    if crate::key::is_valid_ufvk(network, key) {
        return true;
    }

    if crate::key::is_valid_transparent_address(network, key) {
        return true;
    }

    false
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_valid_address(address: &str) -> bool {
    let r = zcash_address::ZcashAddress::try_from_encoded(address);
    r.is_ok()
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_valid_transparent_address(address: &str, c: &Coin) -> bool {
    crate::key::is_valid_transparent_address(&c.network(), address)
}

#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_tex_address(address: &str, c: &Coin) -> bool {
    let Some(address) = zcash_keys::address::Address::decode(&c.network(), address) else {
        return false;
    };
    let is_tex = match address {
        zcash_keys::address::Address::Tex(_) => true,
        _ => false,
    };
    is_tex
}

/// The single classification shared by [`get_key_pools`] and [`is_spending_key`], so the two
/// never diverge on what a key string is.
enum KeyKind {
    Phrase,
    TransparentSpending,
    TransparentViewing,
    SaplingSpending,
    SaplingViewing,
    Ufvk(u8),
    ForeignNetwork,
    Unrecognized,
}

/// Sound only after the same checks failed on the wallet's own network: a match here therefore
/// means another one.
fn is_key_of_another_network(key: &str) -> bool {
    [Network::Main, Network::Test].iter().any(|n| {
        crate::key::is_account_xprv(n, key)
            || crate::key::is_account_xpub(n, key)
            || crate::key::is_sapling_esk(n, key)
            || crate::key::is_sapling_efvk(n, key)
            || crate::key::is_valid_ufvk(n, key)
    })
}

fn classify_key(key: &str, network: &Network) -> Result<KeyKind> {
    if crate::key::is_valid_phrase(key) {
        return Ok(KeyKind::Phrase);
    }
    if crate::key::is_account_xprv(network, key) {
        return Ok(KeyKind::TransparentSpending);
    }
    if crate::key::is_account_xpub(network, key) {
        return Ok(KeyKind::TransparentViewing);
    }
    if crate::key::is_sapling_esk(network, key) {
        return Ok(KeyKind::SaplingSpending);
    }
    if crate::key::is_sapling_efvk(network, key) {
        return Ok(KeyKind::SaplingViewing);
    }
    if crate::key::is_valid_ufvk(network, key) {
        let ufvk = UnifiedFullViewingKey::decode(network, key)
            .map_err(|_| anyhow::anyhow!("Invalid UFVK"))?;
        let mut pools = 0;
        if ufvk.transparent().is_some() {
            pools |= 1;
        }
        if ufvk.sapling().is_some() {
            pools |= 2;
        }
        if ufvk.orchard().is_some() {
            pools |= 4;
        }
        return Ok(KeyKind::Ufvk(pools));
    }
    if is_key_of_another_network(key) {
        return Ok(KeyKind::ForeignNetwork);
    }
    Ok(KeyKind::Unrecognized)
}

/// Mask of the components *encoded in the key string* (t/s/o), not the pools it can spend from —
/// Ironwood has no bit of its own, its spending authority follows Orchard's. `0` means `key` is
/// not a key at all (see [`is_valid_key`] for the broader, address-inclusive check).
#[cfg_attr(feature = "flutter", frb(sync))]
pub fn get_key_pools(key: &str, c: &Coin) -> Result<u8> {
    let network = &c.network();

    Ok(match classify_key(key, network)? {
        KeyKind::Phrase => 7,
        KeyKind::TransparentSpending | KeyKind::TransparentViewing => 1,
        KeyKind::SaplingSpending | KeyKind::SaplingViewing => 2,
        KeyKind::Ufvk(pools) => pools,
        KeyKind::ForeignNetwork | KeyKind::Unrecognized => 0,
    })
}

/// Whether `importSpendingKey` accepts `key`. Only `xprv` and a Sapling extended spending key
/// encode a spending authority this SDK can import this way — a mnemonic phrase also spends, but
/// through `restoreAccount`, not this predicate.
#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_spending_key(key: &str, c: &Coin) -> Result<bool> {
    let network = &c.network();

    Ok(matches!(
        classify_key(key, network)?,
        KeyKind::TransparentSpending | KeyKind::SaplingSpending
    ))
}

/// The spending-key envelope `signTransaction` takes, built from a standalone key string.
///
/// Accepts exactly what [`is_spending_key`] reports. Stateless: nothing is stored and the caller
/// owns the returned bytes.
#[cfg_attr(feature = "flutter", frb(sync))]
pub fn import_spending_key(key: &str, c: &Coin) -> Result<Vec<u8>> {
    let network = &c.network();

    match classify_key(key, network)? {
        KeyKind::TransparentSpending => Ok(encode_transparent(key)?),
        KeyKind::SaplingSpending => Ok(encode_sapling(key, network)?),
        KeyKind::Phrase => Err(anyhow!(
            "this is a seed phrase: it spends, but the account is restored with restoreAccount"
        )),
        KeyKind::TransparentViewing | KeyKind::SaplingViewing | KeyKind::Ufvk(_) => Err(anyhow!(
            "this is a viewing key: it can watch the account but not spend from it"
        )),
        KeyKind::ForeignNetwork => Err(anyhow!(
            "this key belongs to another network than the wallet"
        )),
        KeyKind::Unrecognized => Err(anyhow!("not a recognized Zcash key for this network")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::{
        account_efvk, account_xpub, foreign_extended_keys, test_usk, watch_only_keys, TEST_PHRASE,
    };
    use crate::api::account::{derive_unified_address, receivers_of};
    use crate::api::coin::Network;
    use crate::pay::signing_key::SigningKey;
    use bech32::{Bech32m, Hrp};
    use secp256k1::PublicKey;
    use zcash_keys::encoding::encode_extended_spending_key;
    use zcash_protocol::consensus::NetworkConstants as _;

    const MAIN: u8 = 0;

    fn coin() -> Coin {
        Coin::new(Some(MAIN))
    }

    fn key(label: &str) -> String {
        watch_only_keys()
            .into_iter()
            .find(|k| k.label == label)
            .unwrap_or_else(|| panic!("no fixture for {label}"))
            .key
    }

    fn taddress() -> String {
        let (ua, _) = derive_unified_address(MAIN, TEST_PHRASE, None, 0).expect("ua");
        receivers_of(MAIN, &ua)
            .expect("receivers")
            .taddr
            .expect("taddr")
    }

    fn account_zpk() -> String {
        let usk = test_usk(0);
        let data = usk.transparent().to_account_pubkey().serialize();
        let public_key = PublicKey::from_slice(&data[32..]).expect("pubkey");
        bech32::encode::<Bech32m>(Hrp::parse_unchecked("zpk"), &public_key.serialize())
            .expect("bech32")
    }

    fn foreign_network_esk() -> String {
        let usk = test_usk(0);
        encode_extended_spending_key(
            Network::Test.hrp_sapling_extended_spending_key(),
            usk.sapling(),
        )
    }

    #[test]
    fn get_key_pools_returns_the_component_mask_per_key_class() {
        let coin = coin();

        assert_eq!(get_key_pools(TEST_PHRASE, &coin).expect("phrase"), 7);
        assert_eq!(get_key_pools(&key("tprv"), &coin).expect("xprv"), 1);
        assert_eq!(get_key_pools(&account_xpub(), &coin).expect("xpub"), 1);
        assert_eq!(get_key_pools(&key("sapling xsk"), &coin).expect("esk"), 2);
        assert_eq!(get_key_pools(&account_efvk(), &coin).expect("efvk"), 2);
        assert_eq!(get_key_pools(&key("ufvk"), &coin).expect("ufvk"), 7);
        assert_eq!(get_key_pools(&taddress(), &coin).expect("t-address"), 0);
        assert_eq!(get_key_pools("not a key", &coin).expect("garbage"), 0);
        assert_eq!(
            get_key_pools(&foreign_network_esk(), &coin).expect("foreign esk"),
            0
        );
    }

    /// `bip32` validates only that a prefix is four ASCII letters, never the version bytes, so
    /// without an explicit check another coin's account key classifies as ours and restores an
    /// empty wallet.
    #[test]
    fn get_key_pools_rejects_extended_keys_of_other_coins_and_networks() {
        let coin = coin();

        for (label, key) in foreign_extended_keys() {
            assert_eq!(get_key_pools(&key, &coin).expect(label), 0, "{label}");
            assert!(!is_spending_key(&key, &coin).expect(label), "{label}");
            assert!(!is_valid_key(&key, &coin), "{label}");
        }
    }

    #[test]
    fn get_key_pools_no_longer_recognizes_single_address_transparent_keys() {
        let coin = coin();

        assert_eq!(get_key_pools(&key("wif"), &coin).expect("wif"), 0);
        assert_eq!(get_key_pools(&account_zpk(), &coin).expect("zpk"), 0);
    }

    #[test]
    fn is_spending_key_matches_the_set_import_spending_key_actually_accepts() {
        let coin = coin();

        for (label, expected) in [
            ("tprv", true),
            ("sapling xsk", true),
            ("ufvk", false),
            ("wif", false),
        ] {
            assert_eq!(
                is_spending_key(&key(label), &coin).expect(label),
                expected,
                "{label}"
            );
            assert_eq!(
                import_spending_key(&key(label), &coin).is_ok(),
                expected,
                "{label} import"
            );
        }

        for (label, key) in [
            ("phrase", TEST_PHRASE.to_string()),
            ("xpub", account_xpub()),
            ("efvk", account_efvk()),
            ("zpk", account_zpk()),
            ("t-address", taddress()),
            ("garbage", "not a key".to_string()),
            ("foreign esk", foreign_network_esk()),
        ] {
            assert!(!is_spending_key(&key, &coin).expect(label), "{label}");
            assert!(import_spending_key(&key, &coin).is_err(), "{label} import");
        }
    }

    #[test]
    fn import_spending_key_names_why_each_rejected_key_cannot_spend() {
        let coin = coin();

        for (label, key, expected) in [
            ("phrase", TEST_PHRASE.to_string(), "restoreAccount"),
            ("xpub", account_xpub(), "viewing key"),
            ("efvk", account_efvk(), "viewing key"),
            ("ufvk", key("ufvk"), "viewing key"),
            ("garbage", "not a key".to_string(), "not a recognized"),
            ("foreign esk", foreign_network_esk(), "another network"),
        ] {
            let error = import_spending_key(&key, &coin)
                .expect_err(label)
                .to_string();
            assert!(
                error.contains(expected),
                "{label}: expected an error naming '{expected}', got: {error}"
            );
        }
    }

    #[test]
    fn import_spending_key_produces_an_envelope_the_signer_decodes() {
        let coin = coin();

        let transparent = import_spending_key(&key("tprv"), &coin).expect("xprv");
        let sapling = import_spending_key(&key("sapling xsk"), &coin).expect("esk");

        assert!(matches!(
            SigningKey::decode(&transparent).ok(),
            Some(SigningKey::Transparent(_))
        ));
        assert!(matches!(
            SigningKey::decode(&sapling).ok(),
            Some(SigningKey::Sapling(_))
        ));
    }
}
