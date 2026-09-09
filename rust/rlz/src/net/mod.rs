use anyhow::Result;
use futures::{pin_mut, Stream, StreamExt};
use tokio::sync::mpsc::Sender;
use zcash_primitives::transaction::Transaction;

use tonic::async_trait;

use crate::{api::coin::Network, lwd::*, Client};

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
    loop {
        // A dropped receiver must end the upstream request now, not whenever the next item lands:
        // a stalled stream would otherwise stay open on the server after its reader is gone.
        // Biased so an item already in hand is still forwarded, exactly as before.
        let item = tokio::select! {
            biased;
            item = source.next() => item,
            _ = sender.closed() => break,
        };
        let Some(item) = item else { break };
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
    /// A second handle on the *same* connection, so concurrent requests multiplex over it
    /// instead of opening one connection each.
    fn duplicate(&self) -> Client;

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

    /// The backend's hash of the block at `height`. Taken from `GetTreeState`, which lightwalletd
    /// serves from the node rather than from its compact-block cache, so two equal answers bracket
    /// a transparent walk against one and the same chain.
    async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>>;
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

    #[tokio::test]
    async fn forward_stream_ends_when_the_receiver_is_dropped() {
        let source = futures::stream::pending::<Result<u32>>();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let forwarder = tokio::spawn(forward_stream(source, sender));

        drop(receiver);

        tokio::time::timeout(std::time::Duration::from_secs(1), forwarder)
            .await
            .expect("the forwarder must end as soon as its receiver is dropped")
            .expect("forwarder task");
    }
}
