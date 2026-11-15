use anyhow::Result;
use futures::{Stream, StreamExt};
use tracing::debug;
use zcash_primitives::transaction::Transaction;

use tokio_stream::wrappers::ReceiverStream;
use tonic::{async_trait, Request};
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::{
    api::{coin::Network, network::LWDInfo},
    lwd::*,
    net::{
        bounded, forward_stream_with_idle, BroadcastOutcome, CompletedSubtree, LwdServer,
        MAX_SUBTREE_ROOTS, STREAM_IDLE, UNARY_DEADLINE,
    },
    Client, GRPCClient,
};

#[async_trait]
impl LwdServer for GRPCClient {
    fn duplicate(&self) -> Client {
        Box::new(self.clone())
    }

    async fn latest_height(&mut self) -> Result<u32> {
        let block_id = bounded(
            "get_latest_block",
            UNARY_DEADLINE,
            self.get_latest_block(Request::new(ChainSpec {})),
        )
        .await?
        .into_inner();
        Ok(block_id.height as u32)
    }

    async fn block(&mut self, _network: &Network, height: u32) -> Result<CompactBlock> {
        let block = bounded(
            "get_block",
            UNARY_DEADLINE,
            self.get_block(Request::new(BlockId {
                height: height as u64,
                hash: vec![],
            })),
        )
        .await?
        .into_inner();
        Ok(block)
    }

    type CompactBlockStream = ReceiverStream<Result<CompactBlock>>;
    async fn block_range(
        &mut self,
        _network: &Network,
        start: u32,
        end: u32,
    ) -> Result<Self::CompactBlockStream> {
        debug!("Fetching block range from {} to {}", start, end);
        let blocks = bounded(
            "get_block_range open",
            UNARY_DEADLINE,
            self.get_block_range(Request::new(BlockRange {
                start: Some(BlockId {
                    height: start as u64,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: end as u64,
                    hash: vec![],
                }),
                spam_filter_threshold: 0,
            })),
        )
        .await?
        .into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<CompactBlock>>(10);
        tokio::spawn(forward_stream_with_idle(
            blocks.map(|block| block.map_err(anyhow::Error::new)),
            tx,
            Some(STREAM_IDLE),
        ));
        Ok(ReceiverStream::new(rx))
    }

    async fn transaction(&mut self, network: &Network, txid: &[u8]) -> Result<(u32, Transaction)> {
        let rtx = bounded(
            "get_transaction",
            UNARY_DEADLINE,
            self.get_transaction(Request::new(TxFilter {
                hash: txid.to_vec(),
                ..Default::default()
            })),
        )
        .await?
        .into_inner();
        let height = rtx.height as u32;
        let branch_id = BranchId::for_height(network, BlockHeight::from_u32(height));
        let tx = Transaction::read(&mut &rtx.data[..], branch_id)?;
        Ok((height, tx))
    }

    async fn post_transaction(&mut self, height: u32, tx: &[u8]) -> Result<BroadcastOutcome> {
        let rep = bounded(
            "send_transaction",
            UNARY_DEADLINE,
            self.send_transaction(Request::new(RawTransaction {
                data: tx.to_vec(),
                height: height as u64,
            })),
        )
        .await?
        .into_inner();
        let message = if rep.error_code == 0 {
            rep.error_message.trim_matches('"').to_string()
        } else {
            rep.error_message
        };
        Ok(BroadcastOutcome {
            error_code: rep.error_code,
            message,
            inputs_released: false,
        })
    }

    type TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
    async fn taddress_txs(
        &mut self,
        network: &Network,
        taddress: &str,
        start: u32,
        end: u32,
    ) -> Result<Self::TransactionStream> {
        let txs = bounded(
            "get_taddress_txids open",
            UNARY_DEADLINE,
            self.get_taddress_txids(Request::new(TransparentAddressBlockFilter {
                address: taddress.to_string(),
                range: Some(BlockRange {
                    start: Some(BlockId {
                        height: start as u64,
                        hash: vec![],
                    }),
                    end: Some(BlockId {
                        height: end as u64,
                        hash: vec![],
                    }),
                    spam_filter_threshold: 0,
                }),
            })),
        )
        .await?
        .into_inner();
        let network = *network;
        let (sender, rx) = tokio::sync::mpsc::channel::<Result<(u32, Transaction, usize)>>(10);
        tokio::spawn(forward_stream_with_idle(
            txs.map(move |rtx| {
                let rtx = rtx.map_err(anyhow::Error::new)?;
                let len = rtx.data.len();
                let branch_id =
                    BranchId::for_height(&network, BlockHeight::from_u32(rtx.height as u32));
                let tx = Transaction::read(&mut &rtx.data[..], branch_id)?;
                let txid = tx.txid();
                let has_tb = tx.transparent_bundle().is_some();
                let (n_vin, n_vout) = tx
                    .transparent_bundle()
                    .map(|tb| (tb.vin.len(), tb.vout.len()))
                    .unwrap_or((0, 0));
                debug!(
                    "LWD raw_tx: height={} branch_id={:?} txid={} size={} has_transparent={} n_vin={} n_vout={} raw_hex_first120={}",
                    rtx.height,
                    branch_id,
                    txid,
                    len,
                    has_tb,
                    n_vin,
                    n_vout,
                    hex::encode(&rtx.data[..rtx.data.len().min(120)]),
                );
                Ok((rtx.height as u32, tx, len))
            }),
            sender,
            Some(STREAM_IDLE),
        ));
        Ok(ReceiverStream::new(rx))
    }

    type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
    async fn mempool_stream(&mut self, network: &Network) -> Result<Self::MempoolStream> {
        let txs = self
            .get_mempool_stream(Request::new(Empty {}))
            .await?
            .into_inner();
        let network = *network;
        let (sender, rx) = tokio::sync::mpsc::channel::<Result<(u32, Transaction, usize)>>(10);
        tokio::spawn(forward_stream_with_idle(
            txs.map(move |rtx| {
                let rtx = rtx.map_err(anyhow::Error::new)?;
                let len = rtx.data.len();
                let branch_id =
                    BranchId::for_height(&network, BlockHeight::from_u32(rtx.height as u32));
                let tx = Transaction::read(&mut &rtx.data[..], branch_id)?;
                Ok((rtx.height as u32, tx, len))
            }),
            sender,
            // lightwalletd sends headers with the first tx, so a quiet, healthy mempool must time out
            // neither at the open nor here; the subscription ends through its cancel token instead.
            None,
        ));
        Ok(ReceiverStream::new(rx))
    }

    async fn tree_state(&mut self, height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let state = bounded(
            "get_tree_state",
            UNARY_DEADLINE,
            self.get_tree_state(Request::new(BlockId {
                height: height as u64,
                hash: vec![],
            })),
        )
        .await?
        .into_inner();
        let sapling_tree =
            hex::decode(&state.sapling_tree).expect("Failed to decode sapling tree hex");
        let orchard_tree =
            hex::decode(&state.orchard_tree).expect("Failed to decode sapling tree hex");
        let ironwood_tree = hex::decode(&state.ironwood_tree).unwrap_or_default();
        Ok((sapling_tree, orchard_tree, ironwood_tree))
    }

    async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
        let state = bounded(
            "get_tree_state",
            UNARY_DEADLINE,
            self.get_tree_state(Request::new(BlockId {
                height: height as u64,
                hash: vec![],
            })),
        )
        .await?
        .into_inner();
        anyhow::ensure!(
            !state.hash.is_empty(),
            "tree state at {height} carries no block hash"
        );
        Ok(hex::decode(&state.hash)?)
    }

    async fn subtree_roots(&mut self, protocol: i32, start: u32) -> Result<Vec<CompletedSubtree>> {
        let fetch = async {
            let stream = self
                .get_subtree_roots(Request::new(GetSubtreeRootsArg {
                    start_index: start,
                    shielded_protocol: protocol,
                    max_entries: MAX_SUBTREE_ROOTS,
                }))
                .await?
                .into_inner();
            read_subtree_roots(stream).await
        };
        bounded("get_subtree_roots", UNARY_DEADLINE, fetch).await
    }

    async fn lightd_info(&mut self) -> Result<LightdInfo> {
        let info = bounded(
            "get_lightd_info",
            UNARY_DEADLINE,
            self.get_lightd_info(Request::new(Empty {})),
        )
        .await?
        .into_inner();
        Ok(info)
    }
}

/// Each root is checked as it arrives and at most `MAX_SUBTREE_ROOTS` are read, whatever the server sends.
async fn read_subtree_roots(
    stream: impl Stream<Item = Result<SubtreeRoot, tonic::Status>>,
) -> Result<Vec<CompletedSubtree>> {
    let mut stream = std::pin::pin!(stream.take(MAX_SUBTREE_ROOTS as usize));
    let mut roots = vec![];
    while let Some(root) = stream.next().await {
        roots.push(completed_subtree(&root?)?);
    }
    Ok(roots)
}

fn completed_subtree(root: &SubtreeRoot) -> Result<CompletedSubtree> {
    let bytes = |field: &[u8], what: &str| {
        <[u8; 32]>::try_from(field)
            .map_err(|_| anyhow::anyhow!("a subtree {what} of {} bytes", field.len()))
    };
    Ok(CompletedSubtree {
        root: bytes(&root.root_hash, "root")?,
        height: u32::try_from(root.completing_block_height)?,
        hash: bytes(&root.completing_block_hash, "block hash")?,
    })
}

pub async fn query_lwd_list(coin: u8) -> Result<Vec<LWDInfo>> {
    // 0 = mainnet, 1 = testnet, 2 = regtest
    if coin == 2 {
        return Ok(Vec::new());
    }
    let chain = if coin == 1 { "test" } else { "main" };
    let url = format!("https://hosh.zec.rocks/api/v0/zec.json?chain={chain}");
    let rep = reqwest::get(&url)
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    // Parse the JSON response and convert it to Vec<LWDInfo>
    let servers = rep["servers"].as_array().cloned().unwrap_or_default();
    let mut lwd_list = Vec::new();
    for item in servers {
        let hostname = item["hostname"].as_str().unwrap_or_default();
        let port = item["port"].as_u64().unwrap_or(9067);
        let scheme = if hostname.ends_with(".onion") {
            "http"
        } else {
            "https"
        };
        let url = format!("{}://{}:{}", scheme, hostname, port);
        let is_tor = hostname.ends_with(".onion");
        let height = item["height"].as_u64().unwrap_or(0) as u32;
        let status = if item["online"].as_bool().unwrap_or(false) {
            "online"
        } else {
            "offline"
        };
        let uptime = (item["uptime_30d"].as_f64().unwrap_or(0.0) * 100.0) as u32;
        let ping = item["ping"].as_f64().unwrap_or(0.0) as u32;
        // These fields are not present in the API response, use defaults
        let version = item["node_version"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        let lwd_info = LWDInfo {
            url,
            is_tor,
            height,
            status: status.to_string(),
            uptime,
            version,
            ping,
        };
        lwd_list.push(lwd_info);
    }

    Ok(lwd_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::transport::{ClientTlsConfig, Endpoint};

    fn root(i: u8) -> SubtreeRoot {
        SubtreeRoot {
            root_hash: vec![i; 32],
            completing_block_hash: vec![i + 1; 32],
            completing_block_height: 1_000 + u64::from(i),
        }
    }

    async fn read(roots: Vec<SubtreeRoot>) -> Result<Vec<CompletedSubtree>> {
        read_subtree_roots(futures::stream::iter(roots.into_iter().map(Ok))).await
    }

    #[tokio::test]
    async fn read_subtree_roots_well_formed_keeps_order_and_fields() {
        let roots = read(vec![root(1), root(2)]).await.unwrap();
        let first = CompletedSubtree {
            root: [1; 32],
            height: 1_001,
            hash: [2; 32],
        };
        assert_eq!(
            roots,
            [
                first,
                CompletedSubtree {
                    root: [2; 32],
                    height: 1_002,
                    hash: [3; 32]
                }
            ]
        );
    }

    #[tokio::test]
    async fn read_subtree_roots_malformed_root_fails_the_call() {
        let short_root = SubtreeRoot {
            root_hash: vec![0; 31],
            ..root(1)
        };
        let long_hash = SubtreeRoot {
            completing_block_hash: vec![0; 33],
            ..root(1)
        };
        let high = SubtreeRoot {
            completing_block_height: u64::from(u32::MAX) + 1,
            ..root(1)
        };
        for bad in [short_root, long_hash, high] {
            assert!(read(vec![root(0), bad, root(2)]).await.is_err());
        }
    }

    #[tokio::test]
    async fn read_subtree_roots_server_ignores_the_limit_stops_at_it() {
        let many = vec![root(1); MAX_SUBTREE_ROOTS as usize + 5];
        assert_eq!(read(many).await.unwrap().len(), MAX_SUBTREE_ROOTS as usize);
    }

    #[tokio::test]
    async fn read_subtree_roots_stream_error_fails_the_call() {
        let stream = futures::stream::iter([Ok(root(1)), Err(tonic::Status::unimplemented("no"))]);
        assert!(read_subtree_roots(stream).await.is_err());
    }

    #[tokio::test]
    #[ignore = "live: needs mainnet lightwalletd servers"]
    async fn subtree_roots_live_servers_name_the_block_that_completed_each_subtree() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for url in ["https://zec.rocks:443", "https://ap.zec.rocks:443"] {
            let channel = Endpoint::from_static(url)
                .tls_config(ClientTlsConfig::new().with_enabled_roots())
                .unwrap()
                .connect()
                .await
                .unwrap();
            let mut client = GRPCClient::new(channel);
            for protocol in 0..3 {
                let roots = client.subtree_roots(protocol, 0).await.unwrap();
                let last = roots.last().expect("roots");
                let block = client.block(&Network::Main, last.height).await.unwrap();
                assert_eq!(block.hash, last.block_hash(), "{url} pool {protocol}");
            }
        }
    }
}
