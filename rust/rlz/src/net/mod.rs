use anyhow::Result;
use futures::{pin_mut, Stream, StreamExt};
use tokio::sync::mpsc::Sender;
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

pub(crate) async fn forward_stream<T>(
    source: impl Stream<Item = Result<T>>,
    sender: Sender<Result<T>>,
) {
    pin_mut!(source);
    while let Some(item) = source.next().await {
        let failed = item.is_err();
        if sender.send(item).await.is_err() {
            break;
        }
        if failed {
            break;
        }
    }
}

/// True when `url` names a mixnet-native server. Lives here, ungated, because the
/// classification must also exist with `nym` off — otherwise a `nym://` URL would
/// reach tonic and connect in the clear.
pub fn is_nym_url(url: &str) -> bool {
    url.trim_start()
        .as_bytes()
        .get(..NYM_URL_SCHEME.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(NYM_URL_SCHEME.as_bytes()))
}

/// Raw outcome of a broadcast. A non-zero `error_code` means the node rejected the
/// transaction and `message` carries its reason; on success `message` is the txid.
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcastOutcome {
    pub error_code: i32,
    pub message: String,
}

#[async_trait]
pub trait LwdServer: Send {
    async fn latest_height(&mut self) -> Result<u32>;
    async fn block(&mut self, network: &Network, height: u32) -> Result<CompactBlock>;

    type CompactBlockStream: Stream<Item = Result<CompactBlock>>;
    async fn block_range(
        &mut self,
        network: &Network,
        start: u32,
        end: u32,
    ) -> Result<Self::CompactBlockStream>;

    async fn transaction(&mut self, network: &Network, txid: &[u8]) -> Result<(u32, Transaction)>;
    async fn post_transaction(&mut self, height: u32, tx: &[u8]) -> Result<BroadcastOutcome>;

    type TransactionStream: Stream<Item = Result<(u32, Transaction, usize)>>;
    async fn taddress_txs(
        &mut self,
        network: &Network,
        taddress: &str,
        start: u32,
        end: u32,
    ) -> Result<Self::TransactionStream>;

    /// Items are fallible on purpose: the reader runs in its own task, so a mid-stream failure
    /// would otherwise be indistinguishable from the server ending the epoch.
    type MempoolStream: Stream<Item = Result<(u32, Transaction, usize)>>;
    async fn mempool_stream(&mut self, network: &Network) -> Result<Self::MempoolStream>;

    async fn tree_state(&mut self, height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::wrappers::ReceiverStream;

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

    #[tokio::test]
    async fn forward_stream_source_fails_forwards_the_error_before_closing() {
        let source = tokio_stream::iter([
            Ok(7),
            Err(anyhow::Error::new(tonic::Status::unavailable(
                "stream failed",
            ))),
        ]);
        let (sender, receiver) = tokio::sync::mpsc::channel(2);

        forward_stream(source, sender).await;

        let items = ReceiverStream::new(receiver).collect::<Vec<_>>().await;
        assert_eq!(
            2,
            items.len(),
            "the terminal source error must be observable"
        );
        assert_eq!(7, *items[0].as_ref().expect("first item"));
        assert!(items[1]
            .as_ref()
            .expect_err("source error")
            .to_string()
            .contains("stream failed"));
    }
}
