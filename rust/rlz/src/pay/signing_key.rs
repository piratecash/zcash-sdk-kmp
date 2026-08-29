//! Permissive decoder/encoder for the `UnifiedSpendingKey` envelope format
//! (era header + typecode/length/value records, see `zcash_keys::keys::UnifiedSpendingKey`).
//!
//! Unlike `UnifiedSpendingKey::from_bytes`, [`SigningKey::decode`] also accepts an envelope
//! carrying a single transparent-only or sapling-only component, and rejects trailing bytes
//! and duplicate components instead of silently ignoring/overwriting them.

use std::str::FromStr as _;

use bip32::ExtendedPrivateKey;
use secp256k1::SecretKey;
use thiserror::Error;
use zcash_encoding::CompactSize;
use zcash_keys::{
    encoding::decode_extended_spending_key,
    keys::{sapling::ExtendedSpendingKey, Era, UnifiedSpendingKey},
};
use zcash_protocol::consensus::{BranchId, NetworkConstants as _};
use zcash_transparent::keys::AccountPrivKey;

use crate::api::coin::Network;

const TYPECODE_P2PKH: u32 = 0x00;
const TYPECODE_SAPLING: u32 = 0x02;
const TYPECODE_ORCHARD: u32 = 0x03;

const LEN_P2PKH: usize = 74;
const LEN_SAPLING: usize = 169;
const LEN_ORCHARD: usize = 32;

/// A signing key decoded from a `UnifiedSpendingKey`-style envelope, which may carry
/// authority for all pools or, unlike the upstream type, a single pool only.
pub enum SigningKey {
    Unified(UnifiedSpendingKey),
    Transparent(AccountPrivKey),
    Sapling(ExtendedSpendingKey),
}

#[derive(Error, Debug)]
pub enum InvalidSpendingKey {
    #[error("Truncated: {0}")]
    Truncated(String),
    #[error("Unknown era id {0}")]
    UnknownEra(u32),
    #[error("Unknown typecode {0}")]
    UnknownTypecode(u32),
    #[error("Typecode {typecode} declares length {length}, expected {expected}")]
    BadLength {
        typecode: u32,
        length: usize,
        expected: usize,
    },
    #[error("{0} trailing byte(s) after the last component")]
    TrailingBytes(usize),
    #[error("Duplicate component for typecode {0}")]
    DuplicateComponent(u32),
    #[error("Component for typecode {typecode} does not decode to a valid key")]
    MalformedComponent { typecode: u32 },
    #[error("Unsupported component combination: {0}")]
    UnsupportedCombination(String),
    #[error("No components present")]
    NoComponents,
}

impl SigningKey {
    /// Decodes a `UnifiedSpendingKey`-style envelope, accepting either a full set of
    /// components (transparent + sapling + orchard) or a single transparent/sapling
    /// component. Orchard alone, any other subset, trailing bytes, and duplicate
    /// components are all rejected explicitly rather than silently tolerated.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidSpendingKey> {
        if bytes.len() < 4 {
            return Err(InvalidSpendingKey::Truncated(
                "missing 4-byte era header".to_string(),
            ));
        }
        let era_id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if era_id != u32::from(BranchId::Nu5) {
            return Err(InvalidSpendingKey::UnknownEra(era_id));
        }

        let mut remaining: &[u8] = &bytes[4..];
        let mut p2pkh: Option<AccountPrivKey> = None;
        let mut sapling: Option<ExtendedSpendingKey> = None;
        let mut orchard_present = false;

        while !remaining.is_empty() {
            let typecode = CompactSize::read_t::<_, u32>(&mut remaining)
                .map_err(|_| InvalidSpendingKey::Truncated("incomplete typecode".to_string()))?;
            let length = CompactSize::read_t::<_, u32>(&mut remaining).map_err(|_| {
                InvalidSpendingKey::Truncated(format!("incomplete length for typecode {typecode}"))
            })? as usize;

            let expected = match typecode {
                TYPECODE_P2PKH => LEN_P2PKH,
                TYPECODE_SAPLING => LEN_SAPLING,
                TYPECODE_ORCHARD => LEN_ORCHARD,
                _ => return Err(InvalidSpendingKey::UnknownTypecode(typecode)),
            };
            if length != expected {
                return Err(InvalidSpendingKey::BadLength {
                    typecode,
                    length,
                    expected,
                });
            }
            if remaining.len() < length {
                return Err(InvalidSpendingKey::Truncated(format!(
                    "typecode {typecode} declares {length} bytes but only {} remain",
                    remaining.len()
                )));
            }
            let (value, rest) = remaining.split_at(length);
            remaining = rest;

            match typecode {
                TYPECODE_P2PKH => {
                    if p2pkh.is_some() {
                        return Err(InvalidSpendingKey::DuplicateComponent(typecode));
                    }
                    p2pkh = Some(
                        AccountPrivKey::from_bytes(value)
                            .ok_or(InvalidSpendingKey::MalformedComponent { typecode })?,
                    );
                }
                TYPECODE_SAPLING => {
                    if sapling.is_some() {
                        return Err(InvalidSpendingKey::DuplicateComponent(typecode));
                    }
                    sapling = Some(
                        ExtendedSpendingKey::from_bytes(value)
                            .map_err(|_| InvalidSpendingKey::MalformedComponent { typecode })?,
                    );
                }
                TYPECODE_ORCHARD => {
                    if orchard_present {
                        return Err(InvalidSpendingKey::DuplicateComponent(typecode));
                    }
                    let key: [u8; LEN_ORCHARD] = value
                        .try_into()
                        .map_err(|_| InvalidSpendingKey::MalformedComponent { typecode })?;
                    Option::<orchard::keys::SpendingKey>::from(
                        orchard::keys::SpendingKey::from_bytes(key),
                    )
                    .ok_or(InvalidSpendingKey::MalformedComponent { typecode })?;
                    orchard_present = true;
                }
                _ => unreachable!("typecode already validated above"),
            }

            if p2pkh.is_some() && sapling.is_some() && orchard_present {
                if !remaining.is_empty() {
                    return Err(InvalidSpendingKey::TrailingBytes(remaining.len()));
                }
                // Re-validate from the original bytes so the Unified path stays byte-identical
                // to today's `UnifiedSpendingKey::from_bytes` behavior.
                let usk = UnifiedSpendingKey::from_bytes(Era::Orchard, bytes).map_err(|_| {
                    InvalidSpendingKey::MalformedComponent {
                        typecode: TYPECODE_P2PKH,
                    }
                })?;
                return Ok(SigningKey::Unified(usk));
            }
        }

        match (p2pkh, sapling, orchard_present) {
            (Some(key), None, false) => Ok(SigningKey::Transparent(key)),
            (None, Some(key), false) => Ok(SigningKey::Sapling(key)),
            (None, None, false) => Err(InvalidSpendingKey::NoComponents),
            (None, None, true) => Err(InvalidSpendingKey::UnsupportedCombination(
                "orchard alone".to_string(),
            )),
            (Some(_), Some(_), false) => Err(InvalidSpendingKey::UnsupportedCombination(
                "transparent+sapling".to_string(),
            )),
            (Some(_), None, true) => Err(InvalidSpendingKey::UnsupportedCombination(
                "transparent+orchard".to_string(),
            )),
            (None, Some(_), true) => Err(InvalidSpendingKey::UnsupportedCombination(
                "sapling+orchard".to_string(),
            )),
            (Some(_), Some(_), true) => {
                unreachable!("returned inside the loop once all three components are present")
            }
        }
    }
}

fn single_component_envelope(typecode: u32, value: &[u8]) -> Vec<u8> {
    let mut out = u32::from(BranchId::Nu5).to_le_bytes().to_vec();
    CompactSize::write(&mut out, typecode as usize).expect("typecode fits in a CompactSize");
    CompactSize::write(&mut out, value.len()).expect("component length fits in a CompactSize");
    out.extend_from_slice(value);
    out
}

/// Encodes a transparent extended private key (`xprv`) as a single-component envelope.
pub fn encode_transparent(xprv: &str) -> Result<Vec<u8>, InvalidSpendingKey> {
    let xprv = ExtendedPrivateKey::<SecretKey>::from_str(xprv).map_err(|_| {
        InvalidSpendingKey::MalformedComponent {
            typecode: TYPECODE_P2PKH,
        }
    })?;
    let key = AccountPrivKey::from_extended_privkey(xprv);
    Ok(single_component_envelope(TYPECODE_P2PKH, &key.to_bytes()))
}

/// Encodes a Sapling extended spending key as a single-component envelope.
pub fn encode_sapling(esk: &str, network: &Network) -> Result<Vec<u8>, InvalidSpendingKey> {
    let key = decode_extended_spending_key(network.hrp_sapling_extended_spending_key(), esk)
        .map_err(|_| InvalidSpendingKey::MalformedComponent {
            typecode: TYPECODE_SAPLING,
        })?;
    Ok(single_component_envelope(TYPECODE_SAPLING, &key.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::{test_usk, TEST_PHRASE};
    use bip32::Prefix;
    use zcash_keys::encoding::encode_extended_spending_key;

    fn era_header() -> Vec<u8> {
        u32::from(BranchId::Nu5).to_le_bytes().to_vec()
    }

    fn tlv(typecode: u32, value: &[u8]) -> Vec<u8> {
        let mut out = vec![];
        CompactSize::write(&mut out, typecode as usize).expect("typecode");
        CompactSize::write(&mut out, value.len()).expect("length");
        out.extend_from_slice(value);
        out
    }

    /// `SigningKey` deliberately has no `Debug` impl (it can hold key material), so
    /// `Result::unwrap_err` (which requires `T: Debug`) cannot be used directly.
    fn decode_err(bytes: &[u8]) -> InvalidSpendingKey {
        match SigningKey::decode(bytes) {
            Err(error) => error,
            Ok(_) => panic!("expected decode to fail"),
        }
    }

    fn test_transparent_xprv() -> String {
        let seed = bip39::Mnemonic::from_str(TEST_PHRASE)
            .expect("phrase")
            .to_seed("");
        ExtendedPrivateKey::<SecretKey>::new(seed)
            .expect("xprv")
            .to_string(Prefix::XPRV)
            .to_string()
    }

    #[test]
    fn decode_full_unified_envelope_round_trips_through_usk_to_bytes() {
        let usk = test_usk(0);
        let bytes = usk.to_bytes(Era::Orchard);

        let decoded = SigningKey::decode(&bytes).expect("valid unified envelope");

        assert!(matches!(decoded, SigningKey::Unified(_)));
    }

    #[test]
    fn encode_transparent_round_trips_through_decode() {
        let xprv = test_transparent_xprv();
        let expected = AccountPrivKey::from_extended_privkey(
            ExtendedPrivateKey::<SecretKey>::from_str(&xprv).expect("xprv"),
        )
        .to_bytes();

        let envelope = encode_transparent(&xprv).expect("encode");
        let decoded = SigningKey::decode(&envelope).expect("decode");

        match decoded {
            SigningKey::Transparent(key) => assert_eq!(key.to_bytes(), expected),
            _ => panic!("expected Transparent variant"),
        }
    }

    #[test]
    fn encode_sapling_round_trips_through_decode() {
        let network = Network::Main;
        let usk = test_usk(0);
        let esk = encode_extended_spending_key(
            network.hrp_sapling_extended_spending_key(),
            usk.sapling(),
        );
        let expected = usk.sapling().to_bytes();

        let envelope = encode_sapling(&esk, &network).expect("encode");
        let decoded = SigningKey::decode(&envelope).expect("decode");

        match decoded {
            SigningKey::Sapling(key) => assert_eq!(key.to_bytes(), expected),
            _ => panic!("expected Sapling variant"),
        }
    }

    #[test]
    fn decode_input_shorter_than_era_header_returns_truncated() {
        let empty = decode_err(&[]);
        let short = decode_err(&[0, 1, 2]);

        assert!(matches!(empty, InvalidSpendingKey::Truncated(_)));
        assert!(matches!(short, InvalidSpendingKey::Truncated(_)));
        assert!(short.to_string().contains("era header"));
    }

    #[test]
    fn decode_unknown_era_returns_unknown_era() {
        let bad_era = u32::from(BranchId::Nu5)
            .wrapping_add(1)
            .to_le_bytes()
            .to_vec();

        let error = decode_err(&bad_era);

        assert!(matches!(error, InvalidSpendingKey::UnknownEra(_)));
    }

    #[test]
    fn decode_unknown_typecode_returns_unknown_typecode() {
        let mut bytes = era_header();
        bytes.extend(tlv(0x01, &[])); // P2sh: not a USK component

        let error = decode_err(&bytes);

        assert!(matches!(error, InvalidSpendingKey::UnknownTypecode(1)));
    }

    #[test]
    fn decode_bad_component_length_returns_bad_length() {
        let mut bytes = era_header();
        bytes.extend(tlv(TYPECODE_ORCHARD, &[0u8; 31])); // wrong length for Orchard

        let error = decode_err(&bytes);

        assert!(matches!(
            error,
            InvalidSpendingKey::BadLength {
                typecode: TYPECODE_ORCHARD,
                length: 31,
                expected: LEN_ORCHARD,
            }
        ));
    }

    #[test]
    fn decode_trailing_bytes_after_full_envelope_returns_trailing_bytes() {
        let usk = test_usk(0);
        let mut bytes = usk.to_bytes(Era::Orchard);
        bytes.push(0);

        let error = decode_err(&bytes);

        assert!(matches!(error, InvalidSpendingKey::TrailingBytes(1)));
    }

    #[test]
    fn decode_duplicate_component_returns_duplicate_component() {
        let usk = test_usk(0);
        let orchard_bytes = usk.orchard().to_bytes();
        let mut bytes = era_header();
        bytes.extend(tlv(TYPECODE_ORCHARD, orchard_bytes));
        bytes.extend(tlv(TYPECODE_ORCHARD, orchard_bytes));

        let error = decode_err(&bytes);

        assert!(matches!(
            error,
            InvalidSpendingKey::DuplicateComponent(TYPECODE_ORCHARD)
        ));
    }

    #[test]
    fn decode_declared_length_exceeds_remaining_bytes_returns_truncated() {
        let mut bytes = era_header();
        CompactSize::write(&mut bytes, TYPECODE_ORCHARD as usize).expect("typecode");
        CompactSize::write(&mut bytes, LEN_ORCHARD).expect("length");
        bytes.extend_from_slice(&[0u8; 10]); // fewer than the declared 32 bytes

        let error = decode_err(&bytes);

        assert!(matches!(error, InvalidSpendingKey::Truncated(_)));
        assert!(error.to_string().contains("typecode"));
    }

    #[test]
    fn decode_malformed_component_bytes_returns_malformed_component() {
        // depth = 0 (byte 0) with a non-zero child index (bytes 5..9) is structurally
        // invalid: KeyIndex::new only accepts (depth==0, index==0) or (depth!=0, _).
        let mut sapling_bytes = [0u8; LEN_SAPLING];
        sapling_bytes[5] = 1;
        let mut bytes = era_header();
        bytes.extend(tlv(TYPECODE_SAPLING, &sapling_bytes));

        let error = decode_err(&bytes);

        assert!(matches!(
            error,
            InvalidSpendingKey::MalformedComponent {
                typecode: TYPECODE_SAPLING
            }
        ));
    }

    #[test]
    fn decode_orchard_alone_returns_unsupported_combination() {
        let usk = test_usk(0);
        let mut bytes = era_header();
        bytes.extend(tlv(TYPECODE_ORCHARD, usk.orchard().to_bytes()));

        let error = decode_err(&bytes);

        assert!(matches!(
            error,
            InvalidSpendingKey::UnsupportedCombination(_)
        ));
        assert!(error.to_string().contains("orchard"));
    }

    #[test]
    fn decode_exactly_two_components_returns_unsupported_combination() {
        let usk = test_usk(0);
        let p2pkh_bytes = usk.transparent().to_bytes();
        let sapling_bytes = usk.sapling().to_bytes();
        let orchard_bytes = usk.orchard().to_bytes();

        let cases = [
            (
                vec![
                    tlv(TYPECODE_P2PKH, &p2pkh_bytes),
                    tlv(TYPECODE_SAPLING, &sapling_bytes),
                ],
                ["transparent", "sapling"],
            ),
            (
                vec![
                    tlv(TYPECODE_P2PKH, &p2pkh_bytes),
                    tlv(TYPECODE_ORCHARD, orchard_bytes),
                ],
                ["transparent", "orchard"],
            ),
            (
                vec![
                    tlv(TYPECODE_SAPLING, &sapling_bytes),
                    tlv(TYPECODE_ORCHARD, orchard_bytes),
                ],
                ["sapling", "orchard"],
            ),
        ];

        for (tlvs, expected_names) in cases {
            let mut bytes = era_header();
            for record in tlvs {
                bytes.extend(record);
            }

            let error = decode_err(&bytes);
            let message = error.to_string();

            assert!(matches!(
                error,
                InvalidSpendingKey::UnsupportedCombination(_)
            ));
            for name in expected_names {
                assert!(message.contains(name), "expected '{name}' in '{message}'");
            }
        }
    }

    #[test]
    fn decode_header_only_returns_no_components() {
        let bytes = era_header();

        let error = decode_err(&bytes);

        assert!(matches!(error, InvalidSpendingKey::NoComponents));
    }
}
