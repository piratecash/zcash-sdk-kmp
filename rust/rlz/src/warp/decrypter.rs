use crate::lwd::{CompactOrchardAction, CompactSaplingOutput};
use zcash_protocol::consensus::ZIP212_GRACE_PERIOD;
use zcash_trees::network::Network;
use zcash_trees::types::Note;

use anyhow::Result;

use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha20,
};
use orchard::{
    keys::{IncomingViewingKey, PreparedIncomingViewingKey},
    note::{ExtractedNoteCommitment, Nullifier, Rho},
    note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
    zsa::OrchardZSADomain,
};
use sapling_crypto::{
    note_encryption::{plaintext_version_is_valid, SaplingDomain, Zip212Enforcement},
    SaplingIvk,
};
use zcash_note_encryption::note_bytes::{NoteBytes, NoteBytesData};
use zcash_note_encryption::{BatchDomain, EphemeralKeyBytes};

/// An output with its position: (height, ivtx, vout, output).
pub type OutputRef<'a, O> = (u32, u32, u32, &'a O);

const COMPACT_NOTE_SIZE: usize = 52;

fn zip212(network: &Network, height: u32) -> Zip212Enforcement {
    use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};
    let height = BlockHeight::from_u32(height);
    match network.activation_height(NetworkUpgrade::Canopy) {
        Some(h) => {
            if height >= h + ZIP212_GRACE_PERIOD {
                Zip212Enforcement::On
            } else if height >= h {
                Zip212Enforcement::GracePeriod
            } else {
                Zip212Enforcement::Off
            }
        }
        _ => Zip212Enforcement::On, // this doesn't apply for Zcash
    }
}

pub fn decrypt_sapling_batch(
    network: &Network,
    keys: &[(u32, u8, &SaplingIvk)],
    outputs: &[OutputRef<CompactSaplingOutput>],
) -> Vec<(usize, sapling_crypto::Note, Note)> {
    let pivks: Vec<_> = keys
        .iter()
        .map(|(_, _, ivk)| sapling_crypto::keys::PreparedIncomingViewingKey::new(ivk))
        .collect();
    let epks: Vec<&[u8]> = outputs.iter().map(|o| o.3.epk.as_slice()).collect();
    let symmetric = batch_keys::<SaplingDomain>(&pivks, &epks);
    matches(&symmetric, keys.len(), |i, k, key| {
        let (account, scope, _) = keys[k];
        decrypt_sapling_with_key(network, account, scope, &pivks[k], outputs[i], key)
    })
}

pub fn decrypt_orchard_batch(
    network: &Network,
    keys: &[(u32, u8, &IncomingViewingKey)],
    outputs: &[OutputRef<CompactOrchardAction>],
) -> Vec<(usize, orchard::note::Note, Note)> {
    let pivks: Vec<_> = keys
        .iter()
        .map(|(_, _, ivk)| PreparedIncomingViewingKey::new(ivk))
        .collect();
    let epks: Vec<&[u8]> = outputs
        .iter()
        .map(|o| o.3.ephemeral_key.as_slice())
        .collect();
    // Orchard, Ironwood and ZSA share the key agreement and the KDF.
    let symmetric = batch_keys::<OrchardDomain>(&pivks, &epks);
    matches(&symmetric, keys.len(), |i, k, key| {
        let (account, scope, _) = keys[k];
        decrypt_orchard_with_key(network, account, scope, &pivks[k], outputs[i], key)
    })
}

/// Symmetric keys of every (output, ivk) pair, output-major; `None` where the epk does not parse.
fn batch_keys<D: BatchDomain>(
    ivks: &[D::IncomingViewingKey],
    epks: &[&[u8]],
) -> Vec<Option<[u8; 32]>> {
    let epks: Vec<Option<EphemeralKeyBytes>> = epks
        .iter()
        .map(|epk| <[u8; 32]>::try_from(*epk).ok().map(EphemeralKeyBytes))
        .collect();
    let prepared = D::batch_epk(epks.iter().flatten().cloned());
    let per_ivk: Vec<Vec<Option<D::SymmetricKey>>> = ivks
        .iter()
        .map(|ivk| {
            let secrets = D::batch_ka_agree_dec(ivk, prepared.iter().map(|(epk, _)| epk.as_ref()));
            D::batch_kdf(
                secrets
                    .into_iter()
                    .zip(prepared.iter().map(|(_, bytes)| bytes)),
            )
        })
        .collect();
    let mut parsed = 0;
    let mut keys = Vec::with_capacity(epks.len() * ivks.len());
    for epk in &epks {
        for symmetric in &per_ivk {
            let key = epk
                .as_ref()
                .and(symmetric.get(parsed))
                .and_then(Option::as_ref);
            keys.push(key.and_then(|key| key.as_ref().try_into().ok()));
        }
        parsed += usize::from(epk.is_some());
    }
    keys
}

fn matches<N>(
    keys: &[Option<[u8; 32]>],
    n_ivks: usize,
    decrypt: impl Fn(usize, usize, &[u8; 32]) -> Result<Option<(N, Note)>>,
) -> Vec<(usize, N, Note)> {
    keys.iter()
        .enumerate()
        .filter_map(|(j, key)| {
            let (i, k) = (j / n_ivks, j % n_ivks);
            decrypt(i, k, key.as_ref()?)
                .unwrap_or_else(|e| {
                    tracing::warn!("decrypt error: {e}");
                    None
                })
                .map(|(n, dbn)| (k, n, dbn))
        })
        .collect()
}

fn decrypt_sapling_with_key(
    network: &Network,
    account: u32,
    scope: u8,
    pivk: &sapling_crypto::keys::PreparedIncomingViewingKey,
    (height, ivtx, vout, co): OutputRef<CompactSaplingOutput>,
    key: &[u8; 32],
) -> Result<Option<(sapling_crypto::Note, Note)>> {
    let enc = &co.ciphertext;
    let zip212_enforcement = zip212(network, height);
    let mut plaintext = [0; COMPACT_NOTE_SIZE];
    plaintext.copy_from_slice(enc);
    let mut keystream = ChaCha20::new(key.as_ref().into(), [0u8; 12][..].into());
    keystream.seek(64);
    keystream.apply_keystream(&mut plaintext);
    if (plaintext[0] == 0x01 || plaintext[0] == 0x02)
        && plaintext_version_is_valid(zip212_enforcement, plaintext[0])
    {
        use zcash_note_encryption::Domain;
        let d = SaplingDomain::new(zip212_enforcement);
        if let Some((note, recipient)) =
            d.parse_note_plaintext_without_memo_ivk(pivk, plaintext.as_ref())
        {
            let cmx = note.cmu();
            if cmx.to_bytes() == *co.cmu {
                let value = note.value().inner();
                let dbn = Note {
                    pool: 1,
                    account,
                    scope,
                    height,
                    value,
                    rcm: note.rcm().to_bytes().to_vec(),
                    vout,
                    diversifier: recipient.diversifier().0.to_vec(),
                    ivtx,
                    cmx: cmx.to_bytes().to_vec(),
                    ..Note::default()
                };
                return Ok(Some((note, dbn)));
            }
        }
    }
    Ok(None)
}

fn decrypt_orchard_with_key(
    network: &Network,
    account: u32,
    scope: u8,
    pivk: &PreparedIncomingViewingKey,
    (height, ivtx, vout, ca): OutputRef<CompactOrchardAction>,
    key: &[u8; 32],
) -> Result<Option<(orchard::note::Note, Note)>> {
    let zip212_enforcement = zip212(network, height);
    let ciphertext_len = ca.ciphertext.len();
    let mut keystream = ChaCha20::new(key.as_ref().into(), [0u8; 12][..].into());
    keystream.seek(64);

    // Handle ZSA (84-byte) and vanilla (52-byte) ciphertext sizes
    if ciphertext_len >= 84 {
        // 84-byte ZSA compact format with leadbyte 0x03.
        let mut plaintext = ca.ciphertext.clone();
        keystream.apply_keystream(&mut plaintext);

        // The ZSA protocol uses the asset-carrying V3ZSA note version for every Orchard
        // note, including native ZEC.
        if plaintext[0] == 0x03 {
            use zcash_note_encryption::Domain;
            let nullifier_bytes: [u8; 32] = ca
                .nullifier
                .clone()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid nullifier length"))?;
            let rho = Option::<Rho>::from(Rho::from_bytes(&nullifier_bytes))
                .ok_or_else(|| anyhow::anyhow!("Invalid Rho bytes"))?;

            let note_plaintext = NoteBytesData::<84>::from_slice(&plaintext[..84])
                .ok_or_else(|| anyhow::anyhow!("Invalid orchard note plaintext"))?;
            let parsed = OrchardZSADomain { rho }
                .parse_note_plaintext_without_memo_ivk(pivk, note_plaintext.as_ref());
            tracing::debug!(
                "ZSA parsed result: height={} vout={} is_some={}",
                height,
                vout,
                parsed.is_some()
            );
            if let Some((note, recipient)) = parsed {
                let cmx = ExtractedNoteCommitment::from(note.commitment());
                let value = note.value().inner();
                let matched = cmx.to_bytes() == *ca.cmx;
                if matched {
                    let is_zec = bool::from(note.asset().is_zatoshi());
                    let asset_base = if is_zec {
                        vec![]
                    } else {
                        note.asset().to_bytes().to_vec()
                    };
                    let dbn = Note {
                        pool: 2,
                        account,
                        scope,
                        height,
                        value,
                        rcm: note.rseed().as_bytes().to_vec(),
                        rho: rho.to_bytes().to_vec(),
                        vout,
                        diversifier: recipient.diversifier().as_array().to_vec(),
                        ivtx,
                        cmx: Vec::from(&*ca.cmx),
                        asset_base,
                        ..Note::default()
                    };
                    return Ok(Some((note, dbn)));
                }
            }
        }
        return Ok(None);
    }
    // Vanilla (52-byte) path
    let mut plaintext = [0u8; 52];
    plaintext.copy_from_slice(&ca.ciphertext);
    keystream.apply_keystream(&mut plaintext);

    let is_ironwood = plaintext[0] == 0x03;
    let is_orchard = matches!(plaintext[0], 0x01 | 0x02)
        && plaintext_version_is_valid(zip212_enforcement, plaintext[0]);
    if is_ironwood || is_orchard {
        use zcash_note_encryption::Domain;
        let nullifier_bytes: [u8; 32] = ca
            .nullifier
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid nullifier length"))?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&nullifier_bytes))
            .ok_or_else(|| anyhow::anyhow!("Invalid Rho bytes"))?;
        let note_ciphertext: [u8; 52] = ca.ciphertext[..52]
            .try_into()
            .map_err(|_| anyhow::anyhow!("ciphertext too short"))?;
        let cmx_bytes: [u8; 32] = ca
            .cmx
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid cmx length"))?;
        let ephemeral_key_bytes: [u8; 32] = ca
            .ephemeral_key
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid ephemeral key length"))?;
        let cca = CompactAction::from_parts(
            Option::<Nullifier>::from(Nullifier::from_bytes(&rho.to_bytes()))
                .ok_or_else(|| anyhow::anyhow!("Invalid nullifier"))?,
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                &cmx_bytes,
            ))
            .ok_or_else(|| anyhow::anyhow!("Invalid cmx"))?,
            EphemeralKeyBytes(ephemeral_key_bytes),
            note_ciphertext,
        );
        let parsed = if is_ironwood {
            IronwoodDomain::for_compact_action(&cca)
                .parse_note_plaintext_without_memo_ivk(pivk, plaintext.as_ref())
        } else {
            OrchardDomain::for_compact_action(&cca)
                .parse_note_plaintext_without_memo_ivk(pivk, plaintext.as_ref())
        };
        if let Some((note, recipient)) = parsed {
            let cmx = ExtractedNoteCommitment::from(note.commitment());
            let value = note.value().inner();
            if cmx.to_bytes() == *ca.cmx {
                // ZSA-patched orchard: AssetBase::zatoshi().to_bytes() is now
                // a non-zero Pallas point, not [0u8; 32]. Only store a non-empty
                // asset_base for actual ZSA assets so the auto-register check
                // (asset_base != [0u8; 32]) still works and ZEC notes get
                // id_asset = NULL for inclusion in calculate_balance.
                let is_zec = bool::from(note.asset().is_zatoshi());
                let dbn = Note {
                    pool: if is_ironwood { 3 } else { 2 },
                    account,
                    scope,
                    height,
                    value,
                    rcm: note.rseed().as_bytes().to_vec(),
                    rho: rho.to_bytes().to_vec(),
                    vout,
                    diversifier: recipient.diversifier().as_array().to_vec(),
                    ivtx,
                    cmx: cmx.to_bytes().to_vec(),
                    asset_base: if is_zec {
                        vec![]
                    } else {
                        note.asset().to_bytes().to_vec()
                    },
                    ..Note::default()
                };
                return Ok(Some((note, dbn)));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use blake2b_simd::Params;
    use halo2_proofs::pasta::{
        group::{ff::PrimeField as _, Curve as _, GroupEncoding as _},
        pallas, Fp, Fq,
    };
    use orchard::{
        keys::{FullViewingKey, Scope, SpendingKey},
        note::{AssetBase, NoteVersion, RandomSeed},
        note_encryption::{IronwoodNoteEncryption, OrchardNoteEncryption},
        value::NoteValue as OrchardValue,
    };
    use sapling_crypto::{
        note_encryption::{sapling_note_encryption, KDF_SAPLING_PERSONALIZATION},
        value::NoteValue as SaplingValue,
        zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
        Rseed,
    };
    use zcash_note_encryption::{Domain as _, NoteEncryption};

    pub(crate) const ORCHARD_HEIGHT: u32 = 3_000_000;

    /// Deterministic bytes: BLAKE2b of a counter.
    pub(crate) struct Bytes(u64);

    impl Bytes {
        pub(crate) fn new(seed: u64) -> Self {
            Bytes(seed << 32)
        }

        pub(crate) fn next(&mut self) -> [u8; 32] {
            self.0 += 1;
            Params::new()
                .hash_length(32)
                .hash(&self.0.to_le_bytes())
                .as_bytes()
                .try_into()
                .unwrap()
        }
    }

    // The scalar key derivation used before batching: the oracle the batch must match.
    fn orchard_key_scalar(ivk: &IncomingViewingKey, epk: &[u8]) -> Option<[u8; 32]> {
        let ivk_bytes: [u8; 32] = ivk.to_bytes()[32..64].try_into().ok()?;
        let ivk_fq = Option::<Fq>::from(Fq::from_repr(ivk_bytes))?;
        let epk_bytes: [u8; 32] = epk.try_into().ok()?;
        let epk = Option::<pallas::Point>::from(pallas::Point::from_bytes(&epk_bytes))?.to_affine();
        let ka = epk * ivk_fq;
        let key = Params::new()
            .hash_length(32)
            .personal(b"Zcash_OrchardKDF")
            .to_state()
            .update(&ka.to_bytes())
            .update(epk_bytes.as_ref())
            .finalize();
        key.as_bytes().try_into().ok()
    }

    fn sapling_key_scalar(ivk: &SaplingIvk, epkb: &[u8]) -> [u8; 32] {
        let epk = jubjub::AffinePoint::from_bytes(epkb.try_into().unwrap()).unwrap();
        let epk = epk.mul_by_cofactor().to_niels();
        let ka = epk.multiply_bits(&ivk.to_repr()).to_affine();
        let key = Params::new()
            .hash_length(32)
            .personal(KDF_SAPLING_PERSONALIZATION)
            .to_state()
            .update(&ka.to_bytes())
            .update(epkb)
            .finalize();
        key.as_bytes().try_into().unwrap()
    }

    pub(crate) fn orchard_scalar(
        network: &Network,
        keys: &[(u32, u8, &IncomingViewingKey)],
        outputs: &[OutputRef<CompactOrchardAction>],
    ) -> Vec<(usize, orchard::note::Note, Note)> {
        outputs
            .iter()
            .flat_map(|&o| {
                keys.iter()
                    .enumerate()
                    .filter_map(move |(k, &(account, scope, ivk))| {
                        let key = orchard_key_scalar(ivk, &o.3.ephemeral_key)?;
                        let pivk = PreparedIncomingViewingKey::new(ivk);
                        decrypt_orchard_with_key(network, account, scope, &pivk, o, &key)
                            .unwrap_or(None)
                            .map(|(n, dbn)| (k, n, dbn))
                    })
            })
            .collect()
    }

    pub(crate) fn sapling_scalar(
        network: &Network,
        keys: &[(u32, u8, &SaplingIvk)],
        outputs: &[OutputRef<CompactSaplingOutput>],
    ) -> Vec<(usize, sapling_crypto::Note, Note)> {
        outputs
            .iter()
            .flat_map(|&o| {
                keys.iter()
                    .enumerate()
                    .filter_map(move |(k, &(account, scope, ivk))| {
                        let key = sapling_key_scalar(ivk, &o.3.epk);
                        let pivk = sapling_crypto::keys::PreparedIncomingViewingKey::new(ivk);
                        decrypt_sapling_with_key(network, account, scope, &pivk, o, &key)
                            .unwrap_or(None)
                            .map(|(n, dbn)| (k, n, dbn))
                    })
            })
            .collect()
    }

    /// Every field of a stored note, so two results can be compared exactly.
    pub(crate) type NoteFields = (
        u32,
        u8,
        u32,
        u8,
        u32,
        u32,
        Vec<u8>,
        u64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );

    pub(crate) fn fields(n: &Note) -> NoteFields {
        (
            n.account,
            n.scope,
            n.height,
            n.pool,
            n.vout,
            n.ivtx,
            n.diversifier.clone(),
            n.value,
            n.rcm.clone(),
            n.rho.clone(),
            n.cmx.clone(),
            n.asset_base.clone(),
        )
    }

    fn summary<N>(matches: &[(usize, N, Note)]) -> Vec<(usize, NoteFields)> {
        matches
            .iter()
            .map(|(k, _, dbn)| (*k, fields(dbn)))
            .collect()
    }

    pub(crate) fn orchard_fvk(seed: u8) -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
    }

    fn orchard_scope(scope: u8) -> Scope {
        if scope == 0 {
            Scope::External
        } else {
            Scope::Internal
        }
    }

    pub(crate) fn orchard_ivk(fvk: &FullViewingKey, scope: u8) -> IncomingViewingKey {
        fvk.to_ivk(orchard_scope(scope))
    }

    #[derive(Clone, Copy)]
    pub(crate) enum OrchardKind {
        V2,
        Ironwood,
        Zsa,
    }

    pub(crate) fn orchard_action(
        fvk: &FullViewingKey,
        scope: u8,
        value: u64,
        kind: OrchardKind,
        bytes: &mut Bytes,
    ) -> CompactOrchardAction {
        let recipient = fvk.address_at(0u32, orchard_scope(scope));
        let rho = loop {
            let mut b = bytes.next();
            b[31] &= 0x3f;
            if let Some(rho) = Rho::from_bytes(&Fp::from_repr(b).unwrap().to_repr()).into_option() {
                break rho;
            }
        };
        let version = match kind {
            OrchardKind::V2 => NoteVersion::V2,
            OrchardKind::Ironwood => NoteVersion::V3,
            OrchardKind::Zsa => NoteVersion::V3ZSA,
        };
        let note = loop {
            let rseed = RandomSeed::from_bytes(bytes.next(), &rho).into_option();
            let note = rseed.and_then(|rseed| {
                orchard::note::Note::from_parts(
                    recipient,
                    OrchardValue::from_raw(value),
                    AssetBase::zatoshi(),
                    rho,
                    rseed,
                    version,
                )
                .into_option()
            });
            if let Some(note) = note {
                break note;
            }
        };
        let (epk, ciphertext) = match kind {
            OrchardKind::V2 => {
                let e = OrchardNoteEncryption::new(None, note, [0; 512]);
                (
                    OrchardDomain::epk_bytes(e.epk()),
                    e.encrypt_note_plaintext().as_ref()[..52].to_vec(),
                )
            }
            OrchardKind::Ironwood => {
                let e = IronwoodNoteEncryption::new(None, note, [0; 512]);
                (
                    IronwoodDomain::epk_bytes(e.epk()),
                    e.encrypt_note_plaintext().as_ref()[..52].to_vec(),
                )
            }
            OrchardKind::Zsa => {
                let e = NoteEncryption::<OrchardZSADomain>::new(None, note, [0; 512]);
                (
                    OrchardZSADomain::epk_bytes(e.epk()),
                    e.encrypt_note_plaintext().as_ref()[..84].to_vec(),
                )
            }
        };
        CompactOrchardAction {
            nullifier: rho.to_bytes().to_vec(),
            cmx: ExtractedNoteCommitment::from(note.commitment())
                .to_bytes()
                .to_vec(),
            ephemeral_key: epk.0.to_vec(),
            ciphertext,
        }
    }

    pub(crate) fn sapling_dfvk(seed: u8) -> DiversifiableFullViewingKey {
        ExtendedSpendingKey::master(&[seed; 32])
            .unwrap()
            .to_diversifiable_full_viewing_key()
    }

    /// `zip212`: lead byte 0x02 when true, 0x01 otherwise.
    pub(crate) fn sapling_output(
        dfvk: &DiversifiableFullViewingKey,
        scope: u8,
        value: u64,
        zip212: bool,
        bytes: &mut Bytes,
    ) -> CompactSaplingOutput {
        let address = if scope == 0 {
            dfvk.default_address().1
        } else {
            dfvk.change_address().1
        };
        let rseed = if zip212 {
            Rseed::AfterZip212(bytes.next())
        } else {
            let wide = [bytes.next(), bytes.next()].concat();
            Rseed::BeforeZip212(jubjub::Fr::from_bytes_wide(&wide.try_into().unwrap()))
        };
        let note = address.create_note(SaplingValue::from_raw(value), rseed);
        let e = sapling_note_encryption(None, note.clone(), [0; 512], &mut rand::rng());
        CompactSaplingOutput {
            cmu: note.cmu().to_bytes().to_vec(),
            epk: SaplingDomain::epk_bytes(e.epk()).0.to_vec(),
            ciphertext: e.encrypt_note_plaintext().as_ref()[..52].to_vec(),
        }
    }

    fn refs<O>(height: u32, outputs: &[O]) -> Vec<OutputRef<O>> {
        outputs
            .iter()
            .enumerate()
            .map(|(i, o)| (height, i as u32 / 3, i as u32 % 3, o))
            .collect()
    }

    fn pallas_epk(bytes: &mut Bytes) -> Vec<u8> {
        let fvk = orchard_fvk(200);
        orchard_action(&fvk, 0, 1, OrchardKind::V2, bytes).ephemeral_key
    }

    #[test]
    fn batch_keys_orchard_epks_match_scalar_kdf() {
        let mut bytes = Bytes::new(1);
        let ivks: Vec<_> = (1..=3).map(|s| orchard_ivk(&orchard_fvk(s), 0)).collect();
        let pivks: Vec<_> = ivks.iter().map(PreparedIncomingViewingKey::new).collect();
        // Rejected epks sit between valid ones, so the index bookkeeping after each is checked.
        let rejected = [vec![0; 32], vec![0xff; 32], vec![1; 31], vec![1; 33]];
        let mut epks = vec![];
        for bad in rejected {
            epks.push((pallas_epk(&mut bytes), true));
            epks.push((bad, false));
        }
        epks.push((pallas_epk(&mut bytes), true));
        let slices: Vec<&[u8]> = epks.iter().map(|(epk, _)| epk.as_slice()).collect();

        let keys = batch_keys::<OrchardDomain>(&pivks, &slices);

        assert_eq!(keys.len(), epks.len() * ivks.len());
        for (i, (epk, valid)) in epks.iter().enumerate() {
            for (k, ivk) in ivks.iter().enumerate() {
                let expected = valid.then(|| orchard_key_scalar(ivk, epk).unwrap());
                assert_eq!(keys[i * ivks.len() + k], expected, "epk {i} ivk {k}");
            }
        }
    }

    #[test]
    fn batch_keys_sapling_epks_match_scalar_kdf() {
        let mut bytes = Bytes::new(2);
        let ivks: Vec<_> = (1..=3)
            .map(|s| crate::keys::sapling_ivk_nk_for_scope(0u8, &sapling_dfvk(s)).0)
            .collect();
        let pivks: Vec<_> = ivks
            .iter()
            .map(sapling_crypto::keys::PreparedIncomingViewingKey::new)
            .collect();
        let dfvk = sapling_dfvk(200);
        let mut non_canonical = [0xff; 32];
        non_canonical[31] = 0x7f;
        let small_order = jubjub::AffinePoint::identity().to_bytes().to_vec();
        let mut epks = vec![];
        for (other, valid) in [
            (small_order, true),
            (non_canonical.to_vec(), false),
            (vec![1; 31], false),
        ] {
            epks.push((sapling_output(&dfvk, 0, 1, true, &mut bytes).epk, true));
            epks.push((other, valid));
        }
        epks.push((sapling_output(&dfvk, 0, 1, true, &mut bytes).epk, true));
        let slices: Vec<&[u8]> = epks.iter().map(|(epk, _)| epk.as_slice()).collect();

        let keys = batch_keys::<SaplingDomain>(&pivks, &slices);

        assert_eq!(keys.len(), epks.len() * ivks.len());
        for (i, (epk, valid)) in epks.iter().enumerate() {
            for (k, ivk) in ivks.iter().enumerate() {
                let expected = valid.then(|| sapling_key_scalar(ivk, epk));
                assert_eq!(keys[i * ivks.len() + k], expected, "epk {i} ivk {k}");
            }
        }
    }

    #[test]
    fn decrypt_orchard_batch_every_kind_matches_scalar_path() {
        let mut bytes = Bytes::new(3);
        let (a, b, foreign) = (orchard_fvk(1), orchard_fvk(2), orchard_fvk(9));
        let ivks = [
            orchard_ivk(&a, 0),
            orchard_ivk(&a, 1),
            orchard_ivk(&b, 0),
            orchard_ivk(&a, 0),
        ];
        // The last key repeats the first under another account: an output matches both.
        let keys: Vec<_> = [(1, 0), (1, 1), (2, 0), (3, 0)]
            .iter()
            .zip(&ivks)
            .map(|(&(account, scope), ivk)| (account, scope, ivk))
            .collect();
        let mut actions = vec![];
        for (i, kind) in [OrchardKind::V2, OrchardKind::Ironwood, OrchardKind::Zsa]
            .into_iter()
            .enumerate()
        {
            let value = 1000 * (i as u64 + 1);
            actions.push(orchard_action(&a, 0, value + 1, kind, &mut bytes));
            actions.push(orchard_action(&foreign, 0, value + 2, kind, &mut bytes));
            actions.push(orchard_action(&a, 1, value + 3, kind, &mut bytes));
            actions.push(orchard_action(&b, 0, value + 4, kind, &mut bytes));
        }
        let outputs = refs(ORCHARD_HEIGHT, &actions);

        let batch = decrypt_orchard_batch(&Network::Main, &keys, &outputs);
        let scalar = orchard_scalar(&Network::Main, &keys, &outputs);

        let pools: Vec<u8> = batch.iter().map(|(_, _, n)| n.pool).collect();
        assert_eq!(pools, [2, 2, 2, 2, 3, 3, 3, 3, 2, 2, 2, 2]);
        let accounts: Vec<u32> = batch.iter().map(|(_, _, n)| n.account).collect();
        assert_eq!(accounts, [1, 3, 1, 2, 1, 3, 1, 2, 1, 3, 1, 2]);
        assert_eq!(
            batch.iter().map(|(_, _, n)| n.value).sum::<u64>(),
            3 * (1 + 1 + 3 + 4) + 4 * 6000
        );
        assert_eq!(summary(&batch), summary(&scalar));
    }

    #[test]
    fn decrypt_sapling_batch_both_lead_bytes_match_scalar_path() {
        let mut bytes = Bytes::new(4);
        let (a, b, foreign) = (sapling_dfvk(1), sapling_dfvk(2), sapling_dfvk(9));
        let ivks = [
            crate::keys::sapling_ivk_nk_for_scope(0u8, &a).0,
            crate::keys::sapling_ivk_nk_for_scope(1u8, &a).0,
            crate::keys::sapling_ivk_nk_for_scope(0u8, &b).0,
        ];
        let keys: Vec<_> = [(1, 0), (1, 1), (2, 0)]
            .iter()
            .zip(&ivks)
            .map(|(&(account, scope), ivk)| (account, scope, ivk))
            .collect();
        let canopy = 1_046_400;
        for (height, leads) in [
            (canopy + 100, [false, true]),
            (canopy + ZIP212_GRACE_PERIOD + 1, [true, true]),
        ] {
            let mut outs = vec![];
            for zip212 in leads {
                outs.push(sapling_output(&a, 0, 11, zip212, &mut bytes));
                outs.push(sapling_output(&foreign, 0, 12, zip212, &mut bytes));
                outs.push(sapling_output(&a, 1, 13, zip212, &mut bytes));
                outs.push(sapling_output(&b, 0, 14, zip212, &mut bytes));
            }
            let outputs = refs(height, &outs);

            let batch = decrypt_sapling_batch(&Network::Main, &keys, &outputs);
            let scalar = sapling_scalar(&Network::Main, &keys, &outputs);

            let values: Vec<u64> = batch.iter().map(|(_, _, n)| n.value).collect();
            assert_eq!(values, [11, 13, 14, 11, 13, 14], "height {height}");
            assert_eq!(summary(&batch), summary(&scalar));
        }
    }
}
