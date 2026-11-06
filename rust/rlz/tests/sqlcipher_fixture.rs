//! A wallet written by SQLCipher 4.5.7 must stay readable and writable after any SQLCipher bump,
//! otherwise an update locks users out of their wallets. The fixture holds only test data:
//! the public "abandon ... art" mnemonic, a made-up key and made-up notes.

use std::path::PathBuf;

use rlz::api::account::{get_addresses, list_tx_history};
use rlz::api::coin::Coin;
use rlz::api::db::{get_prop, put_prop};
use rlz::api::sync::balance;
use rlz::pay::pool::ALL_POOLS;

const FIXTURE: &[u8] = include_bytes!("fixtures/wallet_sqlcipher_4_5_7.db");
const TEST_KEY: [u8; 32] = [0x42; 32];

fn fixture_copy(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rlz-sqlcipher-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wallet.db");
    std::fs::write(&path, FIXTURE).unwrap();
    path
}

async fn open(path: &PathBuf, key: [u8; 32]) -> anyhow::Result<Coin> {
    Coin::new(None)
        .open_database_with_key(path.to_string_lossy().into_owned(), Some(key.to_vec()))
        .await
}

#[tokio::test]
async fn open_database_with_key_fixture_from_old_sqlcipher_reads_and_writes() {
    let path = fixture_copy("read-write");
    let coin = open(&path, TEST_KEY).await.unwrap();

    assert_eq!(coin.account, 1);
    assert_eq!(balance(&coin).await.unwrap().0, [1_000, 20_000, 295_000, 0]);
    let addresses = get_addresses(ALL_POOLS, &coin).await.unwrap();
    assert_eq!(
        addresses.taddr.as_deref(),
        Some("t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F")
    );
    assert_eq!(
        addresses.saddr.as_deref(),
        Some("zs16uhd4mux24se6wkm74vld0ec63d4dxt3d7m80l5xytreplkkllrrf9c7fj859mhp8tkcq9hxfvj")
    );
    let history: Vec<_> = list_tx_history(&coin)
        .await
        .unwrap()
        .iter()
        .map(|tx| (tx.height, tx.value))
        .collect();
    assert_eq!(history, [(2_000_100, -5_000), (2_000_000, 321_000)]);

    put_prop("fixture_write", "written", &coin).await.unwrap();

    // A fresh pool proves the written pages decrypt, not just that the old pool cached them.
    rlz::api::coin::close_pool(&path.to_string_lossy());
    let reopened = open(&path, TEST_KEY).await.unwrap();
    assert_eq!(
        get_prop("fixture_write", &reopened)
            .await
            .unwrap()
            .as_deref(),
        Some("written")
    );
}

#[tokio::test]
async fn open_database_with_key_fixture_with_wrong_key_fails() {
    let path = fixture_copy("wrong-key");
    assert!(open(&path, [0x24; 32]).await.is_err());
}
