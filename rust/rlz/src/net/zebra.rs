#![allow(unused_variables)]

//! Zebra JSON-RPC connector.
//!
//! Handles Sapling, Orchard, and Ironwood (NU6.3) bundle decoding.

use std::{
    future::Future,
    io::Read,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use futures::{Stream, StreamExt};
use httparse::Status;
use reqwest::Url;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;
use zcash_primitives::transaction::OrchardBundle;
use zcash_primitives::{block::BlockHeader, transaction::Transaction};

use byteorder::{ReadBytesExt, LE};
use tokio_stream::wrappers::ReceiverStream;
use tonic::async_trait;
use zcash_protocol::consensus::{BlockHeight, BranchId};

const COMPACT_NOTE_SIZE: usize = 52;

use crate::{
    api::coin::Network,
    lwd::*,
    net::{forward_stream, BroadcastOutcome, LwdServer},
    IntoAnyhow,
};

#[derive(Clone)]
pub struct ZebraClient {
    url: String,
    client: reqwest::Client,
    transport: u8,

    ssl: bool,
    host: String,
    port: u16,
    path: String,
    tls_config: Arc<ClientConfig>,
}

impl ZebraClient {
    pub fn new(network: &Network, url: &str, transport: u8, proxy: &str) -> Result<Self> {
        // Direct/proxy Zebra JSON-RPC uses reqwest; the proxy applies only
        // when the Proxy transport (3) is selected.
        // reqwest natively supports socks5/socks5h/http/https proxy URLs.
        let client = if transport == 3 && !proxy.is_empty() {
            reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(proxy).anyhow()?)
                .build()
                .anyhow()?
        } else {
            reqwest::Client::new()
        };

        let url = Url::parse(url).anyhow()?;
        let host = url.host_str().ok_or(anyhow::anyhow!("No host in URL"))?;
        let port = url
            .port_or_known_default()
            .ok_or(anyhow::anyhow!("No known port"))?;
        let path = url.path();
        let scheme = url.scheme();
        let ssl = match scheme {
            "http" => false,
            "https" => true,
            _ => anyhow::bail!("Unsupported URL scheme"),
        };
        // host: &str, port: u16, uri: &str
        let root_cert_store = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(); // We don't need client certificates for standard web browsing

        Ok(Self {
            url: url.to_string(),
            client,
            transport,
            ssl,
            host: host.to_string(),
            port,
            path: path.to_string(),
            tls_config: Arc::new(tls_config),
        })
    }
}

trait AsyncRW: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncRW for T {}

macro_rules! jsonrpc {
    ($client: ident, $method: literal, $params: tt, $ret: ty) => {
        {
            let id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let req = json!({
                "id": id.to_string(),
                "jsonrpc": "1.0",
                "method": $method,
                "params": $params,
            });
            $client.jsonrpc_impl::<$ret>(req).await
        }
    };
}

impl ZebraClient {
    pub async fn jsonrpc_impl<R>(&self, req: Value) -> Result<R>
    where
        R: for<'de> Deserialize<'de>,
    {
        let rep = match self.transport {
            // Tor and Nym hand a raw stream to post_stream; Direct and
            // Proxy keep the reqwest path.
            1 => {
                let tor_client = crate::api::coin::get_tor_client().await.lock().await;
                let stream = tor_client.connect((self.host.clone(), self.port)).await?;
                drop(tor_client);
                self.post_stream(Box::pin(stream), req).await?
            }
            #[cfg(feature = "nym")]
            2 => {
                let stream = crate::net::nym::nym_connect(&self.host, self.port).await?;
                self.post_stream(Box::pin(stream), req).await?
            }
            // Never remove: without this arm transport 2 falls into `_` and goes
            // out over plain reqwest.
            #[cfg(not(feature = "nym"))]
            2 => anyhow::bail!("nym feature disabled: transport 2 is unavailable"),
            _ => {
                let body: Value = self
                    .client
                    .post(&self.url)
                    .json(&req)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Value>()
                    .await?;
                if let Some(error) = body.pointer("/error") {
                    if !error.is_null() {
                        let msg = error
                            .pointer("/message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("unknown error");
                        anyhow::bail!("JSON RPC error: {}", msg);
                    }
                }
                body
            }
        };
        let result = rep
            .pointer("/result")
            .ok_or_else(|| anyhow::anyhow!("Missing result field in JSON-RPC response: {rep}"))?;
        let res: R = serde_json::from_value(result.clone())?;
        Ok(res)
    }

    async fn post_stream(&self, stream: Pin<Box<dyn AsyncRW + Send>>, req: Value) -> Result<Value> {
        let mut stream: Pin<Box<dyn AsyncRW + Send>> = if self.ssl {
            let connector = TlsConnector::from(self.tls_config.clone());
            let server_name: ServerName = self.host.clone().try_into().anyhow()?;
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .context("TLS handshake failed over transport stream")?;
            Box::pin(tls_stream)
        } else {
            stream
        };

        let request_json = req.to_string();

        stream
            .write_all(format!("POST /{} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{request_json}",
            self.path, self.host).as_bytes())
            .await?;

        stream.flush().await?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut rep = httparse::Response::new(&mut headers);
        let Status::Complete(offset) = rep.parse(&buf)? else {
            anyhow::bail!("Invalid HTTP response")
        };
        let body = String::from_utf8_lossy(&buf[offset..]);

        let body: Value = serde_json::from_str(&body)?;
        // Return the full body so caller can check /error and extract /result uniformly
        Ok(body)
    }
}

#[async_trait]
impl LwdServer for ZebraClient {
    async fn latest_height(&mut self) -> Result<u32> {
        let block_count = jsonrpc!(self, "getblockcount", [], u32)?;
        Ok(block_count as u32)
    }

    async fn block(&mut self, network: &Network, height: u32) -> Result<CompactBlock> {
        let block_hex = jsonrpc!(self, "getblock", [height.to_string(), 0], String)?;
        let block_bytes = hex::decode(block_hex)
            .map_err(|e| anyhow::anyhow!("Failed to decode block hex: {}", e))?;
        let branch_id = BranchId::for_height(network, BlockHeight::from_u32(height));
        let cb = parse_block(branch_id, height, &block_bytes)?;
        Ok(cb)
    }

    async fn post_transaction(&mut self, height: u32, tx: &[u8]) -> Result<BroadcastOutcome> {
        let tx_hex = hex::encode(tx);
        let rep = jsonrpc!(self, "sendrawtransaction", [tx_hex], String)?;
        // A rejection surfaces as a JSON-RPC error, so reaching here means the node accepted it.
        Ok(BroadcastOutcome {
            error_code: 0,
            message: rep,
        })
    }

    async fn transaction(&mut self, network: &Network, txid: &[u8]) -> Result<(u32, Transaction)> {
        let mut txid = txid.to_vec();
        txid.reverse();
        let tx_hex = hex::encode(txid);
        let rep = jsonrpc!(self, "getrawtransaction", [tx_hex, 1], Value)?;
        let data = rep["hex"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid response from node: No hex field"))?
            .to_string();
        let height = rep["height"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Invalid response from node: No height field"))?;
        let branch_id = BranchId::for_height(network, BlockHeight::from_u32(height as u32));
        let tx = Transaction::read(&mut hex::decode(data)?.as_slice(), branch_id)?;
        Ok((height as u32, tx))
    }

    type CompactBlockStream = ReceiverStream<Result<CompactBlock>>;
    async fn block_range(
        &mut self,
        network: &Network,
        start: u32,
        end: u32,
    ) -> Result<Self::CompactBlockStream> {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<CompactBlock>>(10);
        let client = self.clone();
        let network = *network;
        let blocks = fetch_stream(start..=end, move |height| {
            let mut client = client.clone();
            async move { client.block(&network, height).await }
        });
        tokio::spawn(forward_stream(blocks, tx));
        Ok(ReceiverStream::new(rx))
    }

    type TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
    async fn taddress_txs(
        &mut self,
        network: &Network,
        taddress: &str,
        start: u32,
        end: u32,
    ) -> Result<Self::TransactionStream> {
        let req = json!({
            "addresses": [taddress],
            "start": start,
            "end": end
        });
        let rep = jsonrpc!(self, "getaddresstxids", [req], Value)?;
        let txids = rep
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Invalid response from node: No result field"))?;
        let txids = txids
            .iter()
            .map(|txid| {
                let txid_str = txid
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid txid in response"))?
                    .to_string();
                Ok::<_, anyhow::Error>(txid_str)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let client = self.clone();
        let network = *network;
        let (txs, rx) = tokio::sync::mpsc::channel::<Result<(u32, Transaction, usize)>>(10);
        let transactions = fetch_stream(txids, move |txid| {
            let mut client = client.clone();
            async move {
                let mut txid_hex = hex::decode(txid)
                    .map_err(|e| anyhow::anyhow!("Invalid txid hex from node: {}", e))?;
                txid_hex.reverse();
                let (height, tx) = client.transaction(&network, &txid_hex).await?;
                Ok((height, tx, 0))
            }
        });
        tokio::spawn(forward_stream(transactions, txs));

        Ok(ReceiverStream::new(rx))
    }

    type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
    async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
        anyhow::bail!("zebra exposes no mempool stream")
    }

    async fn tree_state(&mut self, height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let res = jsonrpc!(self, "z_gettreestate", [height.to_string()], Value)?;
        let sapling_tree = res["sapling"]["commitments"]["finalState"]
            .as_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid response from node: No sapling commitments final state field"
                )
            })?
            .to_string();
        let orchard_tree = res["orchard"]["commitments"]["finalState"]
            .as_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid response from node: No orchard commitments final state field"
                )
            })?
            .to_string();
        let ironwood_tree = res["ironwood"]["commitments"]["finalState"]
            .as_str()
            .unwrap_or("")
            .to_string();
        Ok((
            hex::decode(sapling_tree)?,
            hex::decode(orchard_tree)?,
            hex::decode(&ironwood_tree).unwrap_or_default(),
        ))
    }
}

fn fetch_stream<I, T, F, Fut>(items: I, fetch: F) -> impl Stream<Item = Result<T>>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    futures::stream::iter(items).then(fetch)
}

pub fn parse_block(
    branch_id: BranchId,
    height: u32,
    mut block_bytes: &[u8],
) -> Result<CompactBlock> {
    let bh = BlockHeader::read(&mut block_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse block header: {}", e))?;
    let tx_count = read_compact_u32(&mut block_bytes)?;
    let mut vtx = vec![];
    for ivtx in 0..tx_count {
        let tx = Transaction::read(&mut block_bytes, branch_id)?;
        let txid = tx.txid().as_ref().to_vec();
        let tx_data = tx.into_data();
        // Skip fully transparent transactions
        if tx_data.sapling_bundle().is_none()
            && tx_data.orchard_bundle().is_none()
            && tx_data.ironwood_bundle().is_none()
        {
            continue;
        }
        let mut spends = vec![];
        let mut outputs = vec![];
        if let Some(sapling_bundle) = tx_data.sapling_bundle() {
            for spend in sapling_bundle.shielded_spends().iter() {
                spends.push(CompactSaplingSpend {
                    nf: spend.nullifier().0.to_vec(),
                });
            }
            for output in sapling_bundle.shielded_outputs().iter() {
                outputs.push(CompactSaplingOutput {
                    cmu: output.cmu().to_bytes().to_vec(),
                    epk: output.ephemeral_key().0.to_vec(),
                    ciphertext: output.enc_ciphertext().as_ref()[..COMPACT_NOTE_SIZE].to_vec(),
                });
            }
        }
        macro_rules! push_actions {
            ($bundle:expr, $actions:expr) => {{
                let bundle = $bundle;
                for action in bundle.actions().iter() {
                    let ciphertext = action.encrypted_note().enc_ciphertext.as_ref()
                        [..COMPACT_NOTE_SIZE]
                        .to_vec();
                    $actions.push(CompactOrchardAction {
                        nullifier: action.nullifier().to_bytes().to_vec(),
                        cmx: action.cmx().to_bytes().to_vec(),
                        ephemeral_key: action.encrypted_note().epk_bytes.to_vec(),
                        ciphertext,
                    });
                }
            }};
        }
        let mut actions = vec![];
        if let Some(orchard_bundle) = tx_data.orchard_bundle() {
            match orchard_bundle {
                OrchardBundle::OrchardVanilla(b) => push_actions!(b, actions),
                OrchardBundle::OrchardZSA(_b) => {
                    // TODO: ZSA compact action extraction
                }
            }
        }
        let mut ironwood_actions = vec![];
        if let Some(ironwood_bundle) = tx_data.ironwood_bundle() {
            push_actions!(ironwood_bundle, ironwood_actions);
        }

        // Extract ZSA issuance data from the issue bundle.
        let mut issuances = vec![];
        if let Some(ref issue_bundle) = tx_data.issue_bundle() {
            let ik = issue_bundle.ik().encode(); // 33 bytes: algorithm_byte + x-only pubkey
            for action in issue_bundle.actions().iter() {
                let issued_amount: u64 = action.notes().iter().map(|n| n.value().inner()).sum();
                let notes: Vec<CompactIssueNote> = action
                    .notes()
                    .iter()
                    .map(|note| CompactIssueNote {
                        recipient: note.recipient().to_raw_address_bytes().to_vec(),
                        value: note.value().inner(),
                        rho: note.rho().to_bytes().to_vec(),
                        rseed: note.rseed().as_bytes().to_vec(),
                    })
                    .collect();
                issuances.push(CompactIssuance {
                    asset_desc_hash: action.asset_desc_hash().to_vec(),
                    finalize: action.is_finalized(),
                    ik: ik.clone(),
                    issued_amount,
                    notes,
                });
            }
        }

        vtx.push(CompactTx {
            index: ivtx as u64,
            hash: txid,
            spends,
            outputs,
            actions,
            ironwood_actions,
            issuances,
            ..Default::default()
        });
    }

    Ok(CompactBlock {
        height: height as u64,
        hash: bh.hash().0.to_vec(),
        prev_hash: bh.prev_block.0.to_vec(),
        time: bh.time,
        vtx,
        ..Default::default()
    })
}

pub fn read_compact_u32<R: Read>(mut reader: R) -> Result<u32> {
    let tpe = reader
        .read_u8()
        .map_err(|e| anyhow::anyhow!("Failed to read compact u32 type: {}", e))?;
    if tpe < 0xFD {
        return Ok(tpe as u32);
    }
    if tpe == 0xFD {
        return Ok(reader
            .read_u16::<LE>()
            .map_err(|e| anyhow::anyhow!("Failed to read compact u16: {}", e))?
            as u32);
    }
    if tpe == 0xFE {
        return reader
            .read_u32::<LE>()
            .map_err(|e| anyhow::anyhow!("Failed to read compact u32: {}", e));
    }
    anyhow::bail!("Invalid compact u32 type: {tpe}");
}

#[cfg(all(test, not(feature = "nym")))]
mod tests {
    use super::*;
    use crate::api::coin::Network;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio_stream::wrappers::ReceiverStream;

    #[tokio::test]
    async fn jsonrpc_rejects_transport_2_when_nym_is_off() {
        // Building the TLS config needs a process-level provider; in production
        // library init installs it.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = ZebraClient::new(&Network::Main, "https://203.0.113.1:8232", 2, "")
            .expect("constructing the client must not need the network");
        let err = client
            .jsonrpc_impl::<serde_json::Value>(serde_json::json!({}))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("nym"), "{err}");
        assert!(err.contains("transport 2"), "{err}");
    }

    /// An empty stream would read as "the epoch ended", and the caller would loop forever.
    #[tokio::test]
    async fn mempool_stream_reports_that_zebra_has_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut client = ZebraClient::new(&Network::Main, "https://203.0.113.1:8232", 1, "")
            .expect("constructing the client must not need the network");
        let err = client
            .mempool_stream(&Network::Main)
            .await
            .expect_err("zebra has no mempool stream")
            .to_string();

        assert!(err.contains("mempool"), "{err}");
    }

    #[tokio::test]
    async fn block_producer_fetch_fails_forwards_the_error() {
        let source = fetch_stream(7..=8, |height| async move {
            anyhow::ensure!(height == 7, "block fetch failed");
            Ok(height)
        });
        let (sender, receiver) = tokio::sync::mpsc::channel(2);

        forward_stream(source, sender).await;

        let items = ReceiverStream::new(receiver).collect::<Vec<_>>().await;
        assert_eq!(7, *items[0].as_ref().expect("first block"));
        assert!(items[1]
            .as_ref()
            .expect_err("fetch error")
            .to_string()
            .contains("block fetch failed"));
    }

    #[tokio::test]
    async fn transaction_producer_fetch_fails_forwards_the_error() {
        let source = fetch_stream(["first", "second"], |txid| async move {
            anyhow::ensure!(txid == "first", "transaction fetch failed");
            Ok(txid)
        });
        let (sender, receiver) = tokio::sync::mpsc::channel(2);

        forward_stream(source, sender).await;

        let items = ReceiverStream::new(receiver).collect::<Vec<_>>().await;
        assert_eq!("first", *items[0].as_ref().expect("first transaction"));
        assert!(items[1]
            .as_ref()
            .expect_err("fetch error")
            .to_string()
            .contains("transaction fetch failed"));
    }

    #[tokio::test]
    async fn producer_receiver_closes_stops_fetching() {
        let calls = AtomicU32::new(0);
        let source = fetch_stream(1..=3, |_| async {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);

        forward_stream(source, sender).await;

        assert_eq!(1, calls.load(Ordering::Relaxed));
    }
}
