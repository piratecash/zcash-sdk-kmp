use std::str::FromStr as _;

use crate::{
    api::{
        account::{get_ledger, Addresses},
        coin::Network,
    },
    bip38,
    db::{
        init_account_orchard, init_account_sapling, init_account_transparent,
        store_account_orchard_vk, store_account_sapling_vk, store_account_seed_fingerprint,
        store_account_transparent_addr, store_account_transparent_vk, update_dindex,
    },
    key::{is_valid_phrase, is_valid_sapling_key, is_valid_transparent_key, is_valid_ufvk},
    keys::{sapling_dfvk_to_fvk, ScopeExt},
    tiu,
};
use crate::{
    api::{
        account::{
            Category, Folder, NewAccount, Seed, TxAccount, TxMemo, TxNote, TxOutput, TxSpend,
        },
        key::generate_seed,
    },
    db::{get_account_hw, select_account_transparent, store_account_hw, store_account_metadata},
    pay::pool::ALL_POOLS,
};
use secp256k1::{PublicKey, SecretKey};
use zcash_keys::keys::{Era, UnifiedFullViewingKey, UnifiedSpendingKey};
use zcash_transparent::address::TransparentAddress;

use anyhow::{anyhow, Context, Result};
use bincode::config::legacy;
use bip32::{ExtendedPrivateKey, ExtendedPublicKey, PrivateKey};
use jubjub::Fr;
use orchard::{
    keys::FullViewingKey,
    note::{AssetBase, NoteVersion, RandomSeed, Rho},
    tree::MerkleHashOrchard,
    value::NoteValue,
    Note,
};
use ripemd::{Digest as _, Ripemd160};
use sapling_crypto::{zip32::DiversifiableFullViewingKey, PaymentAddress};
use sha2::Sha256;
use sqlx::{sqlite::SqliteRow, Connection, Row, SqliteConnection};
use zcash_keys::{
    address::UnifiedAddress, encoding::AddressCodec as _, keys::UnifiedAddressRequest,
};
use zcash_protocol::consensus::{NetworkConstants, NetworkUpgrade, Parameters};
use zcash_transparent::keys::{
    AccountPrivKey, AccountPubKey, NonHardenedChildIndex, TransparentKeyScope,
};
use zcash_trees::warp::FragmentAuthPath;
use zip32::{fingerprint::SeedFingerprint, AccountId};

use crate::{
    api::account::FrostParams,
    sync::trim_sync_data,
    warp::{AuthPath, Witness, MERKLE_DEPTH},
};

/// Mnemonic -> USK, plus the seed fingerprint `account_can_sign` keys on.
/// `aindex` is already range-checked by the caller.
fn usk_from_phrase(
    network: &Network,
    phrase: &str,
    passphrase: &str,
    aindex: AccountId,
) -> Result<(UnifiedSpendingKey, SeedFingerprint)> {
    let seed = bip39::Mnemonic::from_str(phrase)?.to_seed(passphrase);
    let usk = UnifiedSpendingKey::from_seed(network, &seed, aindex)?;
    let fingerprint =
        SeedFingerprint::from_seed(&seed).ok_or_else(|| anyhow!("invalid seed length"))?;

    Ok((usk, fingerprint))
}

/// Derives the spending key outside the database: the SDK never stores it.
pub(crate) fn derive_spending_key(
    network: &Network,
    phrase: &str,
    passphrase: Option<&str>,
    aindex: u32,
) -> Result<Vec<u8>> {
    let aindex = AccountId::try_from(aindex).map_err(|_| anyhow!("account index out of range"))?;
    let (usk, _) = usk_from_phrase(network, phrase, passphrase.unwrap_or_default(), aindex)?;

    Ok(usk.to_bytes(Era::Orchard))
}

/// Derives the account's unified full viewing key outside the database — the address it
/// yields is the one the account reports once it is restored from the same phrase.
pub(crate) fn derive_ufvk(
    network: &Network,
    phrase: &str,
    passphrase: Option<&str>,
    aindex: u32,
) -> Result<String> {
    let aindex = AccountId::try_from(aindex).map_err(|_| anyhow!("account index out of range"))?;
    let (usk, _) = usk_from_phrase(network, phrase, passphrase.unwrap_or_default(), aindex)?;

    Ok(usk.to_unified_full_viewing_key().encode(network))
}

pub async fn new_account(
    network: &Network,
    connection: &mut SqliteConnection,
    na: &NewAccount,
) -> Result<u32> {
    let mut db_tx = connection.begin().await?;

    let birth = na.birth.unwrap_or_else(|| {
        network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Sapling)
            .unwrap()
            .into()
    });

    let account = store_account_metadata(
        &mut db_tx,
        &na.name,
        &na.icon,
        &na.fingerprint,
        birth,
        na.use_internal,
        na.internal,
    )
    .await?;

    let mut key = na.key.clone();
    if key.is_empty() && !na.ledger {
        key = generate_seed()?;
    }

    let pools = na.pools.unwrap_or(ALL_POOLS);

    if na.ledger {
        let has_seed = !key.is_empty();
        if !has_seed {
            store_account_hw(&mut db_tx, account, 1, na.aindex).await?;
        }

        let ledger = get_ledger(&mut db_tx, account).await?;

        // we must do sapling derivation first to know a valid dindex
        // because in sapling some indices are invalid
        let mut dindex = 0;
        if pools & 2 != 0 {
            init_account_sapling(network, &mut db_tx, account, birth).await?;
            if has_seed {
                let sxsk = crate::recover::recover_ledger_seed(&key, na.aindex).await?;
                let sxvk = sxsk.to_diversifiable_full_viewing_key();
                let (di, _) = sxvk.default_address();
                let di: u128 = di.into();
                dindex = di as u32;
                let address = derive_sapling_address(network, &sxvk, dindex);
                store_account_sapling_vk(&mut db_tx, account, &sxvk, &address).await?;
            } else {
                let fvk = ledger.get_hw_fvk(network, na.aindex).await?;
                let mut dfvk = fvk.to_bytes().to_vec();
                dfvk.extend_from_slice(&[0u8; 32]); // add a dummy dk because we cannot get the one from the Ledger
                let xvk = DiversifiableFullViewingKey::from_bytes(&tiu!(dfvk)).unwrap();
                // We should get the default address dindex by using the get_div_list
                // api but it is currently not working
                // instead, we "assume" the dindex = 0 is the default sapling address
                // let (dindex, address) = get_hw_next_diversifier_address(&network, na.aindex, 0).await?;
                let address = ledger.get_hw_sapling_address(network, na.aindex).await?;
                store_account_sapling_vk(&mut db_tx, account, &xvk, &address).await?;
            }
        }
        if pools & 1 != 0 && !has_seed {
            init_account_transparent(&mut db_tx, account, birth).await?;
            let (pk, taddr) = ledger
                .get_hw_transparent_address(network, na.aindex, 0, dindex)
                .await?;
            store_account_transparent_addr(
                &mut db_tx,
                account,
                0,
                dindex,
                None,
                &pk,
                &taddr.encode(network),
                false,
            )
            .await?;
        }
        update_dindex(&mut db_tx, account, dindex, true).await?;
    } else if is_valid_phrase(&key) {
        let passphrase = na.passphrase.clone().unwrap_or_default();
        let (usk, seed_fingerprint) = usk_from_phrase(
            &network,
            &key,
            &passphrase,
            AccountId::try_from(na.aindex).unwrap(),
        )?;

        store_account_seed_fingerprint(
            &mut db_tx,
            account,
            &seed_fingerprint.to_bytes(),
            na.aindex,
        )
        .await?;
        let uvk = usk.to_unified_full_viewing_key();
        let (_, di) = uvk.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
        let dindex: u32 = di.try_into()?;

        if pools & 1 != 0 {
            init_account_transparent(&mut db_tx, account, birth).await?;
            let tsk = usk.transparent();
            let tvk = &tsk.to_account_pubkey();
            store_account_transparent_vk(&mut db_tx, account, tvk).await?;
            for di in &[0, dindex] {
                let (pk, taddr) = derive_transparent_address(tvk, 0, *di, false)?;
                store_account_transparent_addr(
                    &mut db_tx,
                    account,
                    0,
                    *di,
                    None,
                    &pk,
                    &taddr.encode(&network),
                    false,
                )
                .await?;
                // do not create two taddrs if dindex == 0
                if dindex == 0 {
                    break;
                }
            }
        }

        if pools & 2 != 0 {
            init_account_sapling(network, &mut db_tx, account, birth).await?;
            let sxsk = usk.sapling();
            let sxvk = sxsk.to_diversifiable_full_viewing_key();
            let address = derive_sapling_address(network, &sxvk, dindex);
            store_account_sapling_vk(&mut db_tx, account, &sxvk, &address).await?;
        }

        if pools & 4 != 0 {
            init_account_orchard(network, &mut db_tx, account, birth).await?;
            let oxsk = usk.orchard();
            let oxvk = FullViewingKey::from(oxsk);
            store_account_orchard_vk(&mut db_tx, account, &oxvk).await?;
        }

        update_dindex(&mut db_tx, account, dindex, true).await?;
    } else if is_valid_transparent_key(&key) {
        init_account_transparent(&mut db_tx, account, birth).await?;
        if let Ok(xsk) = ExtendedPrivateKey::<SecretKey>::from_str(&key) {
            let xsk = AccountPrivKey::from_extended_privkey(xsk);
            let xvk = xsk.to_account_pubkey();
            store_account_transparent_vk(&mut db_tx, account, &xvk).await?;
            let (pk, address) = derive_transparent_address(&xvk, 0, 0, false)?;
            store_account_transparent_addr(
                &mut db_tx,
                account,
                0,
                0,
                None,
                &pk,
                &address.encode(&network),
                false,
            )
            .await?;
        } else if let Ok(xvk) = ExtendedPublicKey::<PublicKey>::from_str(&key) {
            // No AccountPubKey::from_extended_pubkey, we need to use the bytes
            let mut buf = xvk.attrs().chain_code.to_vec();
            buf.extend_from_slice(&xvk.to_bytes());
            let xvk = AccountPubKey::deserialize(&buf.try_into().unwrap()).unwrap();
            store_account_transparent_vk(&mut db_tx, account, &xvk).await?;
            let (pk, address) = derive_transparent_address(&xvk, 0, 0, false)?;
            store_account_transparent_addr(
                &mut db_tx,
                account,
                0,
                0,
                None,
                &pk,
                &address.encode(&network),
                false,
            )
            .await?;
        } else if let Ok(sk) = bip38::import_tsk(&key) {
            let secp = secp256k1::Secp256k1::new();
            let pk = sk.0.public_key(&secp);
            let tpk = if sk.1 {
                pk.serialize_uncompressed().to_vec()
            } else {
                pk.serialize().to_vec()
            };
            let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(&tpk)).into();
            let addr = TransparentAddress::PublicKeyHash(pkh);
            let address_str = addr.encode(&network);
            store_account_transparent_addr(
                &mut db_tx,
                account,
                0,
                0,
                None,
                &tpk,
                &address_str,
                sk.1,
            )
            .await?;
        } else if let Ok((_hrp, tpk)) = bech32::decode(&key) {
            let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(&tpk)).into();
            let addr = TransparentAddress::PublicKeyHash(pkh);
            store_account_transparent_addr(
                &mut db_tx,
                account,
                0,
                0,
                None,
                &tpk,
                &addr.encode(&network),
                false,
            )
            .await?;
            let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(&tpk)).into();
            let addr = TransparentAddress::PublicKeyHash(pkh);
            store_account_transparent_addr(
                &mut db_tx,
                account,
                0,
                0,
                None,
                &tpk,
                &addr.encode(&network),
                false,
            )
            .await?;
        }
    } else if is_valid_sapling_key(network, &key) {
        init_account_sapling(network, &mut db_tx, account, birth).await?;
        let di = if let Ok(xsk) = zcash_keys::encoding::decode_extended_spending_key(
            network.hrp_sapling_extended_spending_key(),
            &key,
        ) {
            let xvk = xsk.to_diversifiable_full_viewing_key();
            let (di, address) = xvk.default_address();
            let address = address.encode(&network);
            store_account_sapling_vk(&mut db_tx, account, &xvk, &address).await?;
            di
        } else if let Ok(xvk) = zcash_keys::encoding::decode_extended_full_viewing_key(
            network.hrp_sapling_extended_full_viewing_key(),
            &key,
        ) {
            let (di, address) = xvk.default_address();
            let address = address.encode(&network);
            store_account_sapling_vk(
                &mut db_tx,
                account,
                &xvk.to_diversifiable_full_viewing_key(),
                &address,
            )
            .await?;
            di
        } else {
            return Err(anyhow!("Invalid Sapling Key"));
        };
        let dindex: u32 = di.try_into()?;
        update_dindex(&mut db_tx, account, dindex, true).await?;
    } else if is_valid_ufvk(network, &key) {
        let uvk =
            UnifiedFullViewingKey::decode(&network, &key).map_err(|_| anyhow!("Invalid Key"))?;
        let (ua, di) = uvk.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
        let dindex: u32 = di.try_into()?;

        match uvk.transparent() {
            Some(tvk) if pools & 1 != 0 => {
                init_account_transparent(&mut db_tx, account, birth).await?;
                store_account_transparent_vk(&mut db_tx, account, tvk).await?;
                let (pk, address) = derive_transparent_address(tvk, 0, dindex, false)?;
                store_account_transparent_addr(
                    &mut db_tx,
                    account,
                    0,
                    dindex,
                    None,
                    &pk,
                    &address.encode(&network),
                    false,
                )
                .await?;
            }
            _ => {}
        }
        match uvk.sapling() {
            Some(sxvk) if pools & 2 != 0 => {
                init_account_sapling(network, &mut db_tx, account, birth).await?;
                let address = ua.sapling().unwrap();
                let address = address.encode(&network);
                store_account_sapling_vk(&mut db_tx, account, sxvk, &address).await?;
            }
            _ => {}
        }
        match uvk.orchard() {
            Some(ovk) if pools & 4 != 0 => {
                init_account_orchard(network, &mut db_tx, account, birth).await?;
                store_account_orchard_vk(&mut db_tx, account, ovk).await?;
            }
            _ => {}
        }
        update_dindex(&mut db_tx, account, dindex, true).await?;
    } else {
        anyhow::bail!("Unsupported key");
    }
    db_tx.commit().await?;
    Ok(account)
}

pub fn derive_transparent_sk(tsk: &AccountPrivKey, scope: u32, dindex: u32) -> Result<Vec<u8>> {
    let scope = scope.transparent_scope();
    let tsk = tsk
        .derive_secret_key(scope, NonHardenedChildIndex::from_index(dindex).unwrap())
        .unwrap()
        .to_bytes();
    Ok(tsk.to_vec())
}

pub fn derive_transparent_address(
    tvk: &AccountPubKey,
    scope: u32,
    dindex: u32,
    uncompressed: bool,
) -> Result<(Vec<u8>, TransparentAddress)> {
    let sindex = TransparentKeyScope::custom(scope).unwrap();
    let pk = tvk
        .derive_address_pubkey(sindex, NonHardenedChildIndex::from_index(dindex).unwrap())
        .unwrap();
    let tpk = if uncompressed {
        pk.serialize_uncompressed().to_vec()
    } else {
        pk.serialize().to_vec()
    };
    let pkh: [u8; 20] = Ripemd160::digest(Sha256::digest(&tpk)).into();
    let addr = TransparentAddress::PublicKeyHash(pkh);
    Ok((tpk, addr))
}

pub async fn get_account_seed(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<Seed>> {
    let seed = sqlx::query("SELECT seed, passphrase, aindex FROM accounts WHERE id_account = ?")
        .bind(account)
        .map(|row: SqliteRow| {
            let mnemonic: Option<String> = row.get(0);
            let phrase: Option<String> = row.get(1);
            let aindex: u32 = row.get(2);
            let phrase = phrase.unwrap_or_default();
            mnemonic.map(|mnemonic| Seed {
                mnemonic,
                phrase,
                aindex,
            })
        })
        .fetch_one(&mut *connection)
        .await?;
    Ok(seed)
}

pub async fn get_sapling_vk(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<DiversifiableFullViewingKey>> {
    let vk = sqlx::query("SELECT xvk FROM sapling_accounts WHERE account = ?")
        .bind(account)
        .map(|row: SqliteRow| {
            let vk: Vec<u8> = row.get(0);
            DiversifiableFullViewingKey::from_bytes(&vk.try_into().unwrap()).unwrap()
        })
        .fetch_optional(&mut *connection)
        .await?;

    Ok(vk)
}

pub async fn get_sapling_address(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<PaymentAddress>> {
    let address = sqlx::query("SELECT address FROM sapling_accounts WHERE account = ?")
        .bind(account)
        .map(|row: SqliteRow| {
            let address: String = row.get(0);
            PaymentAddress::decode(network, &address).unwrap()
        })
        .fetch_optional(&mut *connection)
        .await?;

    Ok(address)
}

pub async fn get_sapling_note(
    connection: &mut SqliteConnection,
    id: u32,
    height: u32,
    dfvk: &DiversifiableFullViewingKey,
    edge: &FragmentAuthPath,
    empty_roots: &AuthPath,
) -> Result<(sapling_crypto::Note, u32, sapling_crypto::MerklePath)> {
    let r = sqlx::query(
        "SELECT position, diversifier, value, rcm, witness, scope FROM notes
        JOIN witnesses w ON notes.id_note = w.note
        WHERE id_note = ? AND w.height = ?",
    )
    .bind(id)
    .bind(height)
    .map(|row: SqliteRow| {
        let position: u32 = row.get(0);
        let diversifier: Vec<u8> = row.get(1);
        let value: u64 = row.get::<i64, _>(2) as u64;
        let rcm: Vec<u8> = row.get(3);
        let witness: Vec<u8> = row.get(4);
        let scope: u32 = row.get(5);

        let diversifier = sapling_crypto::Diversifier(diversifier.try_into().unwrap());
        let fvk = sapling_dfvk_to_fvk(scope, dfvk);
        let recipient = fvk.vk.to_payment_address(diversifier).unwrap();

        let value = sapling_crypto::value::NoteValue::from_raw(value);

        let rseed =
            sapling_crypto::Rseed::BeforeZip212(Fr::from_bytes(&rcm.try_into().unwrap()).unwrap());

        let note = sapling_crypto::Note::from_parts(recipient, value, rseed);

        let (witness, _) = bincode::decode_from_slice::<Witness, _>(&witness, legacy()).unwrap();

        let auth_path = witness.build_auth_path(edge, empty_roots).unwrap();
        let mut mp = vec![];
        for i in 0..MERKLE_DEPTH as usize {
            mp.push(sapling_crypto::Node::from_bytes(auth_path.0[i]).unwrap());
        }

        assert_eq!(position, witness.position);
        let merkle_path =
            sapling_crypto::MerklePath::from_parts(mp, (witness.position as u64).into()).unwrap();

        (note, scope, merkle_path)
    })
    .fetch_one(connection)
    .await
    .context("retrieve sinput")?;

    Ok(r)
}

pub async fn get_orchard_vk(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<orchard::keys::FullViewingKey>> {
    let vk = sqlx::query("SELECT xvk FROM orchard_accounts WHERE account = ?")
        .bind(account)
        .map(|row: SqliteRow| {
            let fvk: Vec<u8> = row.get(0);
            orchard::keys::FullViewingKey::read(&*fvk).unwrap()
        })
        .fetch_optional(&mut *connection)
        .await?;

    Ok(vk)
}

pub async fn get_orchard_note(
    connection: &mut SqliteConnection,
    id: u32,
    witness_height: u32,
    ovk: &orchard::keys::FullViewingKey,
    eo: &FragmentAuthPath,
    ero: &AuthPath,
    note_version: NoteVersion,
    rewind_to_position: Option<u32>,
) -> Result<(orchard::Note, orchard::tree::MerklePath)> {
    let (scope, position, diversifier, value, rcm, rho, witness, asset_base) = sqlx::query(
        "SELECT scope, position, diversifier, value, rcm, rho, witness,
                COALESCE(a.asset_base, X'0000000000000000000000000000000000000000000000000000000000000000') as asset_base
         FROM notes
         JOIN witnesses w ON notes.id_note = w.note
         LEFT JOIN assets a ON notes.id_asset = a.id_asset
         WHERE id_note = ? AND w.height = ?",
    )
    .bind(id)
    .bind(witness_height)
    .map(|row: SqliteRow| {
        let scope: Option<u8> = row.get(0);
        let position: u32 = row.get(1);
        let diversifier: Vec<u8> = row.get(2);
        let value: u64 = row.get::<i64, _>(3) as u64;
        let rcm: Vec<u8> = row.get(4);
        let rho: Vec<u8> = row.get(5);
        let witness: Vec<u8> = row.get(6);
        let asset_base: Vec<u8> = row.get(7);
        (scope, position, diversifier, value, rcm, rho, witness, asset_base)
    })
    .fetch_one(connection)
    .await
    .context("retrieve oinput")?;

    let scope = scope.unwrap_or(0);
    let scope = scope.orchard_scope();
    let (witness, _) = bincode::decode_from_slice::<Witness, _>(&witness, legacy()).unwrap();
    let witness = match rewind_to_position {
        Some(position) => {
            anyhow::ensure!(
                witness.position <= position,
                "Note position {} is after anchor edge position {position}",
                witness.position,
            );
            witness.rewind(position)
        }
        None => witness,
    };
    let rho = Rho::from_bytes(&rho.try_into().unwrap()).unwrap();

    let diversifer = orchard::keys::Diversifier::from_bytes(diversifier.try_into().unwrap());
    let recipient = ovk.address(diversifer, scope);
    let value = NoteValue::from_raw(value);
    let rseed = RandomSeed::from_bytes(rcm.try_into().unwrap(), &rho).unwrap();
    let zec_asset_base = [0u8; 32];
    let asset_base = if asset_base == zec_asset_base {
        AssetBase::zatoshi()
    } else {
        AssetBase::from_bytes(&asset_base.try_into().unwrap()).unwrap()
    };
    let note = Note::from_parts(recipient, value, asset_base, rho, rseed, note_version)
        .into_option()
        .unwrap();

    assert_eq!(witness.position, position);
    let auth_path = witness.build_auth_path(eo, ero).unwrap();
    let auth_path = auth_path
        .0
        .iter()
        .map(|a| MerkleHashOrchard::from_bytes(a).unwrap())
        .collect::<Vec<_>>();
    let auth_path: [MerkleHashOrchard; MERKLE_DEPTH as usize] = auth_path.try_into().unwrap();
    let merkle_path = orchard::tree::MerklePath::from_parts(witness.position, auth_path);

    Ok((note, merkle_path))
}

pub async fn get_birth_height(connection: &mut SqliteConnection, account: u32) -> Result<u32> {
    let (birth,): (u32,) = sqlx::query_as("SELECT birth FROM accounts WHERE id_account = ?")
        .bind(account)
        .fetch_one(connection)
        .await?;

    Ok(birth)
}

pub async fn get_account_full_address(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    scope: u8,
    hw: u8,
) -> Result<String> {
    let taddress = sqlx::query(
        "SELECT ta.address FROM transparent_address_accounts ta
        JOIN accounts a ON ta.account = a.id_account AND ta.dindex = a.dindex
        AND ta.scope = 0
        WHERE ta.account = ?",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let taddress: String = row.get(0);
        TransparentAddress::decode(network, &taddress).unwrap()
    })
    .fetch_optional(&mut *connection)
    .await?;

    let saddress = sqlx::query(
        "SELECT sa.xvk, sa.address FROM sapling_accounts sa
        JOIN accounts a ON sa.account = a.id_account AND sa.account = ?",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let xvk: Vec<u8> = row.get(0);
        let address: String = row.get(1);
        let fvk = DiversifiableFullViewingKey::from_bytes(&xvk.try_into().unwrap()).unwrap();
        if scope == 1 && hw == 0 {
            // we do not need to derive a diversified change address
            // since they are not exposed to the user
            let (_, pa) = fvk.change_address();
            pa
        } else {
            PaymentAddress::decode(network, &address).unwrap()
        }
    })
    .fetch_optional(&mut *connection)
    .await?;

    let oaddress = sqlx::query(
        "SELECT a.dindex, oa.xvk FROM orchard_accounts oa
        JOIN accounts a ON oa.account = a.id_account AND oa.account = ?",
    )
    .bind(account)
    .map(|row: SqliteRow| {
        let dindex: u32 = row.get(0);
        let xvk: Vec<u8> = row.get(1);
        let fvk = FullViewingKey::read(&*xvk).unwrap();
        let scope = scope.orchard_scope();
        fvk.address_at(dindex, scope)
    })
    .fetch_optional(connection)
    .await?;

    let address = match (taddress, saddress, oaddress) {
        (Some(taddress), None, None) => taddress.encode(network),
        _ => {
            let ua = UnifiedAddress::from_receivers(oaddress, saddress, taddress).unwrap();
            ua.encode(network)
        }
    };

    Ok(address)
}

pub async fn generate_next_dindex(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<u32> {
    let mut db_tx = connection.begin().await?;
    let ledger = get_ledger(&mut db_tx, account).await?;
    let (aindex, mut dindex): (u32, u32) =
        sqlx::query_as("SELECT aindex, dindex FROM accounts WHERE id_account = ?")
            .bind(account)
            .fetch_one(&mut *db_tx)
            .await?;
    let hw = get_account_hw(&mut db_tx, account).await?;
    // Next Sapling address. Some dindex must be skipped because they do not
    // correspond to a valid sapling address
    let svk = get_sapling_vk(&mut db_tx, account).await?;
    if let Some(svk) = svk.as_ref() {
        dindex += 1;
        let address = if hw != 0 {
            let (di, address) = ledger
                .get_hw_next_diversifier_address(network, aindex, dindex)
                .await?;
            dindex = di;
            address
        } else {
            let (di, address) = svk.find_address(dindex.into()).unwrap();
            dindex = di.try_into()?;
            address.encode(network)
        };
        sqlx::query("UPDATE sapling_accounts SET address = ?2 WHERE account = ?1")
            .bind(account)
            .bind(&address)
            .execute(&mut *db_tx)
            .await?;
    } else {
        // without sapling, any dindex is ok, just increment
        dindex += 1;
    }

    sqlx::query("UPDATE accounts SET dindex = ? WHERE id_account = ?")
        .bind(dindex)
        .bind(account)
        .execute(&mut *db_tx)
        .await?;

    let tkeys = select_account_transparent(&mut db_tx, account, dindex).await?;
    let (sk, pk, address) = match tkeys.xvk {
        Some(xvk) => {
            let sk = tkeys
                .xsk
                .as_ref()
                .map(|tsk| derive_transparent_sk(tsk, 0, dindex).unwrap());
            let (pk, address) = derive_transparent_address(&xvk, 0, dindex, false)?;
            (sk, pk, Some(address))
        }
        None if hw != 0 => {
            let (pk, address) = ledger
                .get_hw_transparent_address(network, aindex, 0, dindex)
                .await?;
            (None, pk, Some(address))
        }
        _ => (None, vec![], None),
    };

    if let Some(address) = address {
        store_account_transparent_addr(
            &mut db_tx,
            account,
            0,
            dindex,
            sk,
            &pk,
            &address.encode(network),
            false,
        )
        .await?;
    }
    db_tx.commit().await?;

    Ok(dindex)
}

pub async fn generate_next_change_address(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<String>> {
    generate_next_transparent_address(network, connection, account, 1).await
}

/// Retries of an index lost to a concurrent allocation before giving up.
const ADDRESS_ALLOCATION_ATTEMPTS: u32 = 8;

/// Next receive-scope transparent address, WITHOUT moving the account's default address the
/// way [`generate_next_dindex`] does — the receive screen has to keep showing the same one.
pub async fn generate_next_receive_address(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<String>> {
    generate_next_transparent_address(network, connection, account, 0).await
}

/// `None` when the account has no transparent key, so no such address exists.
async fn generate_next_transparent_address(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    scope: u32,
) -> Result<Option<String>> {
    let (xsk, xvk) = get_transparent_keys(connection, account).await?;

    if let Some(tvk) = xvk.as_ref() {
        // A concurrent allocation can claim the index between the SELECT and the INSERT; the
        // unique constraint rejects the loser, which then retries with a fresh index.
        for _ in 0..ADDRESS_ALLOCATION_ATTEMPTS {
            let dindex = sqlx::query(
                "SELECT MAX(dindex) FROM transparent_address_accounts WHERE account = ? AND scope = ?",
            )
            .bind(account)
            .bind(scope)
            .map(|row: SqliteRow| row.get::<Option<u32>, _>(0))
            .fetch_one(&mut *connection)
            .await?
            .map_or(0, |dindex| dindex + 1);

            let sk = xsk
                .as_ref()
                .map(|tsk| derive_transparent_sk(tsk, scope, dindex).unwrap());
            let (pk, address) = derive_transparent_address(tvk, scope, dindex, false)?;
            let address = address.encode(network);

            let stored = store_account_transparent_addr(
                &mut *connection,
                account,
                scope,
                dindex,
                sk,
                &pk,
                &address,
                false,
            )
            .await?;

            if stored {
                return Ok(Some(address));
            }
        }

        return Err(anyhow!(
            "Could not allocate a transparent address for account {account}, scope {scope}"
        ));
    }

    Ok(None)
}

async fn get_transparent_keys(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<(Option<AccountPrivKey>, Option<AccountPubKey>)> {
    let tkeys = sqlx::query("SELECT xsk, xvk FROM transparent_accounts WHERE account = ?")
        .bind(account)
        .map(|row: SqliteRow| {
            let xsk: Option<Vec<u8>> = row.get(0);
            let xvk: Option<Vec<u8>> = row.get(1);
            let xsk = xsk.map(|xsk| AccountPrivKey::from_bytes(&xsk).unwrap());
            let xvk = xvk.map(|xvk| AccountPubKey::deserialize(&xvk.try_into().unwrap()).unwrap());
            (xsk, xvk)
        })
        .fetch_optional(&mut *connection)
        .await?;
    let (xsk, xvk) = match tkeys {
        Some((xsk, xvk)) => (xsk, xvk),
        None => (None, None),
    };
    Ok((xsk, xvk))
}

pub async fn get_addresses(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    ua_pools: u8,
) -> Result<Addresses> {
    let dindex = crate::db::get_account_dindex(connection, account).await?;
    let diversifier_index = dindex;

    let tkeys = crate::db::select_account_transparent(connection, account, dindex).await?;
    let skeys = crate::db::select_account_sapling(network, connection, account).await?;
    let okeys = crate::db::select_account_orchard(connection, account).await?;

    let taddr = tkeys
        .xvk
        .as_ref()
        .map(|xvk| derive_transparent_address(xvk, 0, dindex, false).unwrap().1);

    let dindex = dindex as u64;
    let saddr = skeys.address;
    let oaddr = okeys
        .xvk
        .as_ref()
        .map(|xvk| xvk.address_at(dindex, orchard::keys::Scope::External));

    let ua_orchard = UnifiedAddress::from_receivers(oaddr, None, None);

    let ua = UnifiedAddress::from_receivers(
        if ua_pools & 4 != 0 { oaddr } else { None },
        if ua_pools & 2 != 0 { saddr } else { None },
        if ua_pools & 1 != 0 { taddr } else { None },
    );

    // final fallback if we have a transparent address from a BIP 38 secret key
    let taddr = taddr.map(|x| x.encode(&network)).or(tkeys.address);

    let addresses = Addresses {
        taddr,
        saddr: saddr.map(|x| x.encode(&network)),
        oaddr: ua_orchard.map(|x| x.encode(&network)),
        ua: ua.map(|x| x.encode(&network)),
        diversifier_index,
    };

    Ok(addresses)
}

pub async fn reset_sync(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<()> {
    let birth_height = sqlx::query("SELECT birth FROM accounts WHERE id_account = ?")
        .bind(account)
        .map(|row: SqliteRow| row.get::<u32, _>(0))
        .fetch_one(&mut *connection)
        .await?;
    trim_sync_data(&mut *connection, account, 0).await?;
    init_sync_heights(network, &mut *connection, account, birth_height).await?;
    Ok(())
}

pub async fn init_sync_heights(
    network: &Network,
    connection: &mut SqliteConnection,
    account: u32,
    birth_height: u32,
) -> Result<()> {
    let max_pool = if network.activation_height(NetworkUpgrade::Nu6_3).is_some() {
        4
    } else {
        3
    };
    for pool in 0..max_pool {
        let activation_height: u32 = match pool {
            0 => 0,
            1 => network
                .activation_height(NetworkUpgrade::Sapling)
                .unwrap()
                .into(),
            2 => network
                .activation_height(NetworkUpgrade::Nu5)
                .unwrap()
                .into(),
            3 => network
                .activation_height(NetworkUpgrade::Nu6_3)
                .unwrap()
                .into(),
            _ => unreachable!(),
        };
        sqlx::query("UPDATE sync_heights SET height = ?3 WHERE account = ?1 AND pool = ?2")
            .bind(account)
            .bind(pool)
            .bind(birth_height.max(activation_height))
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

pub(crate) fn asset_display(
    id_asset: Option<i32>,
    asset_name: Option<String>,
    asset_desc_hash: Option<Vec<u8>>,
) -> String {
    match id_asset {
        Some(_) => asset_name.filter(|n| !n.is_empty()).unwrap_or_else(|| {
            asset_desc_hash
                .map(|h| hex::encode(&h[..8.min(h.len())]))
                .unwrap_or_else(|| "ZSA".to_string())
        }),
        None => "ZEC".to_string(),
    }
}

pub async fn get_tx_details(
    connection: &mut SqliteConnection,
    account: u32,
    id_tx: u32,
) -> Result<TxAccount> {
    let mut tx = sqlx::query(
        "SELECT txid, height, time, price, category FROM transactions t
        WHERE account = ? AND id_tx = ?",
    )
    .bind(account)
    .bind(id_tx)
    .map(|row: SqliteRow| {
        let txid: Vec<u8> = row.get(0);
        let height: u32 = row.get(1);
        let time: u32 = row.get(2);
        let price: Option<f64> = row.get(3);
        let category: Option<u32> = row.get(4);
        TxAccount {
            id: id_tx,
            account,
            txid,
            height,
            time,
            price,
            category,
            notes: vec![],
            spends: vec![],
            outputs: vec![],
            memos: vec![],
            user_memo: None,
        }
    })
    .fetch_one(&mut *connection)
    .await?;

    let notes = sqlx::query(
        "SELECT n.id_note, n.pool, n.height, n.tx, n.scope,
        n.diversifier, n.value, n.locked, m.memo_text, n.id_asset,
        a.asset_name, a.asset_desc_hash
        FROM notes n
        LEFT JOIN memos m ON n.id_note = m.note
        LEFT JOIN assets a ON n.id_asset = a.id_asset
        WHERE n.account = ? AND n.tx = ?",
    )
    .bind(account)
    .bind(tx.id)
    .map(|row: SqliteRow| {
        let id_note: u32 = row.get(0);
        let pool: u8 = row.get(1);
        let height: u32 = row.get(2);
        let tx: u32 = row.get(3);
        let scope: u8 = row.get(4);
        let diversifier: Option<Vec<u8>> = row.get(5);
        let value: u64 = row.get(6);
        let locked: bool = row.get(7);
        let memo = row.get(8);
        let id_asset: Option<i32> = row.get(9);
        let asset_name: Option<String> = row.get(10);
        let asset_desc_hash: Option<Vec<u8>> = row.get(11);
        TxNote {
            id: id_note,
            pool,
            height,
            tx,
            scope,
            diversifier,
            diversifier_index: None,
            value,
            locked,
            memo,
            id_asset: id_asset.map(|v| v as u32),
            asset_display: asset_display(id_asset, asset_name, asset_desc_hash),
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    let outputs = sqlx::query(
        "SELECT o.id_output, o.pool, o.height, o.value, o.address,
                c.name as contact_name
         FROM outputs o
         LEFT JOIN contact_addresses ca ON o.address = ca.receiver AND o.pool = ca.pool
         LEFT JOIN contacts c ON ca.contact_id = c.id_contact
         WHERE o.account = ? AND o.tx = ?",
    )
    .bind(account)
    .bind(tx.id)
    .map(|row: SqliteRow| {
        let id_output: u32 = row.get(0);
        let pool: u8 = row.get(1);
        let height: u32 = row.get(2);
        let value: u64 = row.get(3);
        let address: String = row.get(4);
        let contact_name: Option<String> = row.get(5);
        TxOutput {
            id: id_output,
            pool,
            height,
            value,
            address,
            contact_name,
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    let spends = sqlx::query(
        "SELECT s.id_note, s.pool, s.height, s.value,
        n.id_asset, a.asset_name, a.asset_desc_hash
        FROM spends s
        JOIN notes n ON s.id_note = n.id_note
        LEFT JOIN assets a ON n.id_asset = a.id_asset
        WHERE s.account = ? AND s.tx = ?",
    )
    .bind(account)
    .bind(tx.id)
    .map(|row: SqliteRow| {
        let id: u32 = row.get(0);
        let pool: u8 = row.get(1);
        let height: u32 = row.get(2);
        let value: i64 = row.get(3);
        let id_asset: Option<i32> = row.get(4);
        let asset_name: Option<String> = row.get(5);
        let asset_desc_hash: Option<Vec<u8>> = row.get(6);
        TxSpend {
            id,
            pool,
            height,
            value: -value as u64,
            id_asset: id_asset.map(|v| v as u32),
            asset_display: asset_display(id_asset, asset_name, asset_desc_hash),
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    let memos = sqlx::query(
        "SELECT note, output, pool, memo_text, memo_bytes FROM memos
        WHERE account = ? AND tx = ?",
    )
    .bind(account)
    .bind(tx.id)
    .map(|row: SqliteRow| {
        let note: Option<u32> = row.get(0);
        let output: Option<u32> = row.get(1);
        let pool: u8 = row.get(2);
        let memo: Option<String> = row.get(3);
        let memo_bytes: Vec<u8> = row.get(4);
        TxMemo {
            note,
            output,
            pool,
            memo,
            memo_bytes,
        }
    })
    .fetch_all(&mut *connection)
    .await?;

    tx.notes = notes;
    tx.spends = spends;
    tx.memos = memos;
    tx.outputs = outputs;

    let user_memo: Option<String> =
        sqlx::query("SELECT user_memo FROM user_memos WHERE account = ?1 AND id_tx = ?2")
            .bind(account)
            .bind(id_tx)
            .map(|row: SqliteRow| row.get(0))
            .fetch_optional(&mut *connection)
            .await?
            .flatten();
    tx.user_memo = user_memo;

    Ok(tx)
}

pub async fn get_account_frost_params(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<Option<FrostParams>> {
    let frost = sqlx::query("SELECT id, n, t FROM dkg_params WHERE account = ?")
        .bind(account)
        .map(|row: SqliteRow| {
            let id: u8 = row.get(0);
            let n: u8 = row.get(1);
            let t: u8 = row.get(2);
            FrostParams { id, n, t }
        })
        .fetch_optional(connection)
        .await?;

    Ok(frost)
}

pub async fn list_folders(connection: &mut SqliteConnection) -> Result<Vec<Folder>> {
    let folders = sqlx::query("SELECT id_folder, name FROM folders ORDER BY name")
        .map(|r: SqliteRow| Folder {
            id: r.get(0),
            name: r.get(1),
        })
        .fetch_all(connection)
        .await?;
    Ok(folders)
}

pub async fn create_new_folder(connection: &mut SqliteConnection, name: &str) -> Result<Folder> {
    sqlx::query("INSERT OR IGNORE INTO folders(name) VALUES (?1)")
        .bind(name)
        .execute(&mut *connection)
        .await?;
    let id = sqlx::query("SELECT id_folder FROM folders WHERE name = ?1")
        .bind(name)
        .map(|r: SqliteRow| r.get::<u32, _>(0))
        .fetch_one(&mut *connection)
        .await?;

    Ok(Folder {
        id,
        name: name.to_string(),
    })
}

pub async fn rename_folder(connection: &mut SqliteConnection, id: u32, name: &str) -> Result<()> {
    if sqlx::query("SELECT 1 FROM folders WHERE name = ?1")
        .bind(name)
        .fetch_optional(&mut *connection)
        .await?
        .is_some()
    {
        anyhow::bail!("Folder name already exists");
    }

    sqlx::query("UPDATE folders SET name = ?2 WHERE id_folder = ?1")
        .bind(id)
        .bind(name)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn delete_folders(connection: &mut SqliteConnection, ids: &[u32]) -> Result<()> {
    for id in ids {
        sqlx::query("UPDATE accounts SET folder = NULL where folder = ?1")
            .bind(id)
            .execute(&mut *connection)
            .await?;

        sqlx::query("DELETE FROM folders WHERE id_folder = ?1")
            .bind(id)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

pub async fn list_categories(connection: &mut SqliteConnection) -> Result<Vec<Category>> {
    let folders =
        sqlx::query("SELECT id_category, name, income FROM categories ORDER BY income, name")
            .map(|r: SqliteRow| Category {
                id: r.get(0),
                name: r.get(1),
                is_income: r.get(2),
            })
            .fetch_all(connection)
            .await?;
    Ok(folders)
}

pub async fn create_new_category(
    connection: &mut SqliteConnection,
    category: &Category,
) -> Result<u32> {
    sqlx::query("INSERT OR IGNORE INTO categories(name, income) VALUES (?1, ?2)")
        .bind(&category.name)
        .bind(category.is_income)
        .execute(&mut *connection)
        .await?;
    let id = sqlx::query("SELECT id_category FROM categories WHERE name = ?1")
        .bind(&category.name)
        .map(|r: SqliteRow| r.get::<u32, _>(0))
        .fetch_one(&mut *connection)
        .await?;

    Ok(id)
}

pub async fn rename_category(connection: &mut SqliteConnection, category: &Category) -> Result<()> {
    if sqlx::query("SELECT 1 FROM categories WHERE name = ?1")
        .bind(&category.name)
        .fetch_optional(&mut *connection)
        .await?
        .is_some()
    {
        anyhow::bail!("Category name already exists");
    }

    sqlx::query("UPDATE categories SET name = ?2, income = ?3 WHERE id_category = ?1")
        .bind(category.id)
        .bind(&category.name)
        .bind(category.is_income)
        .execute(connection)
        .await?;
    Ok(())
}

pub async fn delete_categories(connection: &mut SqliteConnection, ids: &[u32]) -> Result<()> {
    for id in ids {
        sqlx::query("UPDATE transactions SET category = NULL where category = ?1")
            .bind(id)
            .execute(&mut *connection)
            .await?;

        sqlx::query("DELETE FROM categories WHERE id_category = ?1")
            .bind(id)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

pub async fn has_transparent_pub_key(
    connection: &mut SqliteConnection,
    account: u32,
) -> Result<bool> {
    let r = sqlx::query("SELECT xvk FROM transparent_accounts WHERE account = ?1")
        .bind(account)
        .map(|r: SqliteRow| r.get::<Option<Vec<u8>>, _>(0))
        .fetch_optional(connection)
        .await?
        .flatten();
    Ok(r.is_some())
}

pub async fn has_pool(connection: &mut SqliteConnection, account: u32, pool: u8) -> Result<bool> {
    let has_pool = match pool {
        0 => sqlx::query("SELECT 1 FROM transparent_accounts WHERE account = ?1")
            .bind(account)
            .fetch_optional(connection)
            .await?
            .is_some(),
        1 => sqlx::query("SELECT 1 FROM sapling_accounts WHERE account = ?1")
            .bind(account)
            .fetch_optional(connection)
            .await?
            .is_some(),
        2 => sqlx::query("SELECT 1 FROM orchard_accounts WHERE account = ?1")
            .bind(account)
            .fetch_optional(connection)
            .await?
            .is_some(),
        3 => sqlx::query("SELECT 1 FROM orchard_accounts WHERE account = ?1")
            .bind(account)
            .fetch_optional(connection)
            .await?
            .is_some(),
        _ => unreachable!(),
    };
    Ok(has_pool)
}

fn derive_sapling_address(
    network: &Network,
    sxvk: &DiversifiableFullViewingKey,
    dindex: u32,
) -> String {
    let address = sxvk.address(dindex.into()).unwrap();
    address.encode(network)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::db::tests::{blob, memory_db, non_null_rows, SECRET_COLUMNS, VIEWING_COLUMNS};
    use bip32::Prefix;
    use sha2::{Digest, Sha256};
    use zcash_keys::encoding::encode_extended_spending_key;

    /// Published BIP-39 vector (all-zero entropy) — never holds funds.
    pub(crate) const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    pub(crate) struct WatchOnlyKey {
        pub(crate) label: &'static str,
        pub(crate) key: String,
        /// Table and column carrying this form's viewing material after the restore.
        pub(crate) viewing: (&'static str, &'static str),
    }

    pub(crate) async fn restore(
        connection: &mut SqliteConnection,
        key: &str,
        aindex: u32,
        pools: Option<u8>,
    ) -> Result<u32> {
        let na = NewAccount {
            icon: None,
            name: "test".to_string(),
            restore: true,
            key: key.to_string(),
            passphrase: None,
            fingerprint: None,
            aindex,
            birth: Some(2_000_000),
            folder: String::new(),
            pools,
            use_internal: false,
            internal: false,
            ledger: false,
        };

        new_account(&Network::Main, connection, &na).await
    }

    pub(crate) fn test_usk(aindex: u32) -> UnifiedSpendingKey {
        let aindex = AccountId::try_from(aindex).expect("account index");
        usk_from_phrase(&Network::Main, TEST_PHRASE, "", aindex)
            .expect("usk")
            .0
    }

    /// The same seed in every non-mnemonic form `new_account` accepts.
    pub(crate) fn watch_only_keys() -> Vec<WatchOnlyKey> {
        let network = Network::Main;
        let usk = test_usk(0);
        let seed = bip39::Mnemonic::from_str(TEST_PHRASE)
            .expect("phrase")
            .to_seed("");

        let mut wif = vec![0x80u8];
        wif.extend_from_slice(&derive_transparent_sk(usk.transparent(), 0, 0).expect("tsk"));
        wif.push(0x01);

        vec![
            WatchOnlyKey {
                label: "ufvk",
                key: usk.to_unified_full_viewing_key().encode(&network),
                viewing: ("orchard_accounts", "xvk"),
            },
            WatchOnlyKey {
                label: "wif",
                key: bs58::encode(wif).with_check().into_string(),
                viewing: ("transparent_address_accounts", "pk"),
            },
            WatchOnlyKey {
                label: "tprv",
                key: ExtendedPrivateKey::<SecretKey>::new(seed)
                    .expect("xprv")
                    .to_string(Prefix::XPRV)
                    .to_string(),
                viewing: ("transparent_accounts", "xvk"),
            },
            WatchOnlyKey {
                label: "sapling xsk",
                key: encode_extended_spending_key(
                    network.hrp_sapling_extended_spending_key(),
                    usk.sapling(),
                ),
                viewing: ("sapling_accounts", "xvk"),
            },
        ]
    }

    #[tokio::test]
    async fn new_account_from_mnemonic_stores_viewing_keys_only() {
        let mut connection = memory_db().await;

        restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        for (table, column) in SECRET_COLUMNS {
            assert_eq!(
                non_null_rows(&mut connection, table, column).await,
                0,
                "{table}.{column}"
            );
        }
        for (table, column) in VIEWING_COLUMNS {
            assert!(
                blob(&mut connection, table, column).await.is_some(),
                "{table}.{column}"
            );
        }
    }

    #[tokio::test]
    async fn new_account_from_watch_only_key_stores_viewing_material_only() {
        for WatchOnlyKey {
            label,
            key,
            viewing: (table, column),
        } in watch_only_keys()
        {
            let mut connection = memory_db().await;

            restore(&mut connection, &key, 0, None)
                .await
                .unwrap_or_else(|error| panic!("{label}: {error}"));

            for (secret_table, secret_column) in SECRET_COLUMNS {
                assert_eq!(
                    non_null_rows(&mut connection, secret_table, secret_column).await,
                    0,
                    "{label}: {secret_table}.{secret_column}"
                );
            }
            assert!(
                blob(&mut connection, table, column).await.is_some(),
                "{label}: {table}.{column}"
            );
        }
    }

    #[tokio::test]
    async fn new_account_from_wif_stores_the_address() {
        let mut connection = memory_db().await;
        let wif = watch_only_keys()
            .into_iter()
            .find(|k| k.label == "wif")
            .expect("wif vector");

        restore(&mut connection, &wif.key, 0, None)
            .await
            .expect("restore");

        let address: String =
            sqlx::query_scalar("SELECT address FROM transparent_address_accounts")
                .fetch_one(&mut connection)
                .await
                .expect("address");
        assert!(address.starts_with("t1"), "{address}");
    }

    async fn sync_height_pools(connection: &mut SqliteConnection) -> Vec<u32> {
        sqlx::query_scalar("SELECT pool FROM sync_heights ORDER BY pool")
            .fetch_all(connection)
            .await
            .expect("sync heights")
    }

    /// A per-pool row is what keeps `MIN(height)` from following the transparent pool alone.
    #[tokio::test]
    async fn new_account_with_all_pools_tracks_a_sync_height_per_pool() {
        let mut connection = memory_db().await;

        restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        assert_eq!(sync_height_pools(&mut connection).await, vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn new_account_with_the_transparent_pool_only_tracks_that_pool_alone() {
        let mut connection = memory_db().await;

        restore(&mut connection, TEST_PHRASE, 0, Some(1))
            .await
            .expect("restore");

        assert_eq!(sync_height_pools(&mut connection).await, vec![0]);
    }

    /// Pinned in Kotlin too: the JNI boundary must derive the very same key.
    const TEST_PHRASE_USK_SHA256: &str =
        "3fabc1d61f40e5cb045261c10c1e0c559f48f7305d19c4200716424846fd1285";

    #[test]
    fn derive_spending_key_matches_the_cross_language_vector() {
        let key = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");

        assert_eq!(hex::encode(Sha256::digest(&key)), TEST_PHRASE_USK_SHA256);
    }

    #[test]
    fn derive_spending_key_is_deterministic() {
        let first = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");
        let second = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");

        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[test]
    fn derive_spending_key_differs_per_account_index_and_passphrase() {
        let base = derive_spending_key(&Network::Main, TEST_PHRASE, None, 0).expect("derive");
        let other_index =
            derive_spending_key(&Network::Main, TEST_PHRASE, None, 1).expect("derive");
        let peppered =
            derive_spending_key(&Network::Main, TEST_PHRASE, Some("pepper"), 0).expect("derive");

        assert_ne!(base, other_index);
        assert_ne!(base, peppered);
    }

    #[test]
    fn derive_spending_key_invalid_phrase_errors() {
        assert!(derive_spending_key(&Network::Main, "not a mnemonic", None, 0).is_err());
    }

    #[test]
    fn derive_spending_key_account_index_out_of_range_errors() {
        assert!(derive_spending_key(&Network::Main, TEST_PHRASE, None, 0x8000_0000).is_err());
    }

    #[tokio::test]
    async fn derive_ufvk_matches_the_account_restored_from_the_same_phrase() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let stored = crate::key::get_account_ufvk(&Network::Main, &mut connection, account, 7)
            .await
            .expect("stored ufvk");

        assert_eq!(
            stored,
            derive_ufvk(&Network::Main, TEST_PHRASE, None, 0).expect("derive")
        );
    }

    #[test]
    fn derive_ufvk_differs_per_account_index_and_passphrase() {
        let base = derive_ufvk(&Network::Main, TEST_PHRASE, None, 0).expect("derive");
        let other_index = derive_ufvk(&Network::Main, TEST_PHRASE, None, 1).expect("derive");
        let peppered = derive_ufvk(&Network::Main, TEST_PHRASE, Some("pepper"), 0).expect("derive");

        assert_ne!(base, other_index);
        assert_ne!(base, peppered);
    }

    #[test]
    fn derive_ufvk_invalid_phrase_errors() {
        assert!(derive_ufvk(&Network::Main, "not a mnemonic", None, 0).is_err());
    }

    async fn account_taddress(connection: &mut SqliteConnection, account: u32) -> Option<String> {
        sqlx::query_scalar(
            "SELECT ta.address FROM transparent_address_accounts ta
            JOIN accounts a ON ta.account = a.id_account AND ta.dindex = a.dindex AND ta.scope = 0
            WHERE ta.account = ?",
        )
        .bind(account)
        .fetch_optional(&mut *connection)
        .await
        .expect("account address")
    }

    async fn scope_of(connection: &mut SqliteConnection, address: &str) -> u32 {
        sqlx::query_scalar("SELECT scope FROM transparent_address_accounts WHERE address = ?")
            .bind(address)
            .fetch_one(&mut *connection)
            .await
            .expect("scope")
    }

    #[tokio::test]
    async fn generate_next_receive_address_returns_a_fresh_address_each_call() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let own = account_taddress(&mut connection, account)
            .await
            .expect("own address");

        let first = generate_next_receive_address(&Network::Main, &mut connection, account)
            .await
            .expect("first")
            .expect("some");
        let second = generate_next_receive_address(&Network::Main, &mut connection, account)
            .await
            .expect("second")
            .expect("some");

        assert_ne!(first, second);
        assert_ne!(first, own);
        assert_ne!(second, own);
        assert_eq!(scope_of(&mut connection, &first).await, 0);
        assert_eq!(scope_of(&mut connection, &second).await, 0);
    }

    #[tokio::test]
    async fn generate_next_receive_address_leaves_the_account_address_alone() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let before = get_account_full_address(&Network::Main, &mut connection, account, 0, 0)
            .await
            .expect("address before");

        generate_next_receive_address(&Network::Main, &mut connection, account)
            .await
            .expect("generate");

        let after = get_account_full_address(&Network::Main, &mut connection, account, 0, 0)
            .await
            .expect("address after");
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn generate_next_change_address_uses_the_change_scope() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");

        let change = generate_next_change_address(&Network::Main, &mut connection, account)
            .await
            .expect("generate")
            .expect("some");

        assert_eq!(scope_of(&mut connection, &change).await, 1);
    }

    #[tokio::test]
    async fn generate_next_receive_address_without_transparent_key_returns_none() {
        let mut connection = memory_db().await;
        let account = restore(&mut connection, TEST_PHRASE, 0, Some(2))
            .await
            .expect("restore");

        let address = generate_next_receive_address(&Network::Main, &mut connection, account)
            .await
            .expect("generate");

        assert!(address.is_none());
    }
}
