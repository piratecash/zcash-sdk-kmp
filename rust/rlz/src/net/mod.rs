use anyhow::Result;
use futures::Stream;
use zcash_primitives::transaction::Transaction;

use tonic::async_trait;

use crate::{api::coin::Network, lwd::*};

pub mod lwd;
#[cfg(feature = "nym")]
pub mod nym;
#[cfg(feature = "nym")]
pub mod nym_service;
#[cfg(feature = "voting")]
pub mod votechain;
pub mod zebra;

pub const NYM_URL_SCHEME: &str = "nym://";

/// True when `url` names a mixnet-native server. Lives here, ungated, because the
/// classification must also exist with `nym` off — otherwise a `nym://` URL would
/// reach tonic and connect in the clear.
pub fn is_nym_url(url: &str) -> bool {
    url.trim_start()
        .as_bytes()
        .get(..NYM_URL_SCHEME.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(NYM_URL_SCHEME.as_bytes()))
}

#[async_trait]
pub trait LwdServer: Send {
    async fn latest_height(&mut self) -> Result<u32>;
    async fn block(&mut self, network: &Network, height: u32) -> Result<CompactBlock>;

    type CompactBlockStream: Stream<Item = CompactBlock>;
    async fn block_range(
        &mut self,
        network: &Network,
        start: u32,
        end: u32,
    ) -> Result<Self::CompactBlockStream>;

    async fn transaction(&mut self, network: &Network, txid: &[u8]) -> Result<(u32, Transaction)>;
    async fn post_transaction(&mut self, height: u32, tx: &[u8]) -> Result<String>;

    type TransactionStream: Stream<Item = (u32, Transaction, usize)>;
    async fn taddress_txs(
        &mut self,
        network: &Network,
        taddress: &str,
        start: u32,
        end: u32,
    ) -> Result<Self::TransactionStream>;

    async fn mempool_stream(&mut self, network: &Network) -> Result<Self::TransactionStream>;

    async fn tree_state(&mut self, height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_nym_url_accepts_the_scheme_in_any_case() {
        assert!(is_nym_url("nym://abc"));
        assert!(is_nym_url("NYM://abc"));
        assert!(is_nym_url("NyM://abc"));
        assert!(is_nym_url("   nym://abc"));
    }

    #[test]
    fn is_nym_url_rejects_everything_else() {
        assert!(!is_nym_url("https://zec.rocks"));
        assert!(!is_nym_url("nym:/abc"));
        assert!(!is_nym_url(""));
        assert!(!is_nym_url("日本語"));
    }
}
