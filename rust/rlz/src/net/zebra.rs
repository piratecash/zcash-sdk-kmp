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
    Client, IntoAnyhow,
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
        // A redirect target is server-chosen text that would end up in connection errors.
        let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        if transport == 3 && !proxy.is_empty() {
            builder = builder.proxy(reqwest::Proxy::all(proxy).anyhow()?);
        }
        let client = builder.build().anyhow()?;

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
    /// Server text is untrusted and may echo the request's own credentials, so no part of a
    /// response reaches an error: a JSON-RPC error keeps only its code, a malformed result only the
    /// method name.
    pub async fn jsonrpc_impl<R>(&self, req: Value) -> Result<R>
    where
        R: for<'de> Deserialize<'de>,
    {
        let method = req["method"].as_str().unwrap_or("?").to_string();
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
                // The URL may carry credentials; keep it out of every error.
                let response = self
                    .client
                    .post(&self.url)
                    .json(&req)
                    .send()
                    .await
                    .map_err(reqwest::Error::without_url)?;
                // reqwest's own status error keeps the server's reason phrase; report the code only.
                let status = response.status();
                if !status.is_success() {
                    anyhow::bail!("HTTP status {} from {method}", status.as_u16());
                }
                let body: Value = response.json().await.map_err(reqwest::Error::without_url)?;
                if let Some(error) = body.pointer("/error") {
                    if !error.is_null() {
                        let code = error.pointer("/code").and_then(Value::as_i64);
                        anyhow::bail!("JSON RPC error, code {code:?}, method {method}");
                    }
                }
                body
            }
        };
        let result = rep
            .pointer("/result")
            .ok_or_else(|| anyhow::anyhow!("Missing result field in JSON-RPC response"))?;
        let res: R = serde_json::from_value(result.clone())
            .map_err(|_| anyhow::anyhow!("JSON RPC result of {method} has an unexpected shape"))?;
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
    fn duplicate(&self) -> Client {
        Box::new(self.clone())
    }

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

    async fn chain_anchor(&mut self, height: u32) -> Result<Vec<u8>> {
        let res = jsonrpc!(self, "z_gettreestate", [height.to_string()], Value)?;
        let hash = res["hash"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid response from node: No hash field"))?;
        Ok(hex::decode(hash)?)
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
    use zcash_primitives::transaction::TxId;

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

    /// The endpoint URL may carry credentials; reqwest puts it in every error, and those errors
    /// reach the native log and the JNI error slot.
    #[tokio::test]
    async fn jsonrpc_transport_error_omits_the_request_url() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = ZebraClient::new(&Network::Main, "http://127.0.0.1:1/?api_key=SECRET", 0, "")
            .expect("constructing the client must not need the network");
        let err = client
            .jsonrpc_impl::<serde_json::Value>(serde_json::json!({}))
            .await
            .expect_err("nothing listens on port 1");

        let shown = format!("{err:#}");
        assert!(!shown.contains("SECRET"), "{shown}");
    }

    /// One loopback HTTP server that answers its first request with `body` and closes.
    /// One HTTP/1.1 response on a loopback port; `status_line` may carry extra header lines.
    async fn one_shot_http_server(status_line: &str, body: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        let response = format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(response.as_bytes())
                .await
                .expect("respond");
        });
        port
    }

    /// A client pointed at a one-shot server, its URL carrying `credential_path`.
    async fn client_answering(body: &'static str, credential_path: &str) -> ZebraClient {
        let port = one_shot_http_server("200 OK", body).await;
        client_at(port, credential_path)
    }

    /// A client whose server answers only an HTTP status line; the URL carries a query credential.
    async fn client_refusing(status_line: &'static str) -> ZebraClient {
        let port = one_shot_http_server(status_line, "").await;
        client_at(port, "/?api_key=SECRET")
    }

    fn client_at(port: u16, credential_path: &str) -> ZebraClient {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let url = format!("http://127.0.0.1:{port}{credential_path}");
        ZebraClient::new(&Network::Main, &url, 0, "").expect("client")
    }

    fn shown(err: anyhow::Error) -> String {
        format!("{err:#}")
    }

    /// A server that reflects the request's credential in its error text must not get it into the
    /// native log or the JNI error slot.
    #[tokio::test]
    async fn jsonrpc_error_from_the_server_omits_the_endpoint_credentials() {
        let client = client_answering(
            r#"{"error":{"message":"Invalid API key: SECRET"}}"#,
            "/?api_key=SECRET",
        )
        .await;

        let text = shown(
            client
                .jsonrpc_impl::<serde_json::Value>(serde_json::json!({}))
                .await
                .expect_err("the server answered with an error"),
        );

        assert!(text.contains("JSON RPC error"), "{text}");
        assert!(!text.contains("SECRET"), "{text}");
    }

    #[tokio::test]
    async fn jsonrpc_error_from_the_server_omits_a_credential_carried_in_the_path() {
        let client = client_answering(
            r#"{"error":{"message":"Invalid API key: SECRET"}}"#,
            "/rpc/SECRET",
        )
        .await;

        let text = shown(
            client
                .jsonrpc_impl::<serde_json::Value>(serde_json::json!({}))
                .await
                .expect_err("the server answered with an error"),
        );

        assert!(!text.contains("SECRET"), "{text}");
    }

    #[tokio::test]
    async fn jsonrpc_response_without_a_result_omits_the_response_body() {
        let client = client_answering(
            r#"{"request_url":"http://127.0.0.1/?api_key=SECRET"}"#,
            "/?api_key=SECRET",
        )
        .await;

        let text = shown(
            client
                .jsonrpc_impl::<serde_json::Value>(serde_json::json!({}))
                .await
                .expect_err("no result field"),
        );

        assert!(!text.contains("SECRET"), "{text}");
    }

    /// reqwest keeps the server's custom reason phrase even after `without_url`.
    #[tokio::test]
    async fn jsonrpc_http_error_status_omits_the_reason_phrase() {
        let mut client = client_refusing("401 Invalid API key: SECRET").await;

        let text = shown(
            client
                .latest_height()
                .await
                .expect_err("the server refused"),
        );

        assert!(text.contains("401"), "{text}");
        assert!(!text.contains("SECRET"), "{text}");
    }

    /// A redirect target is server-chosen text that would end up in TLS and connection errors.
    #[tokio::test]
    async fn jsonrpc_does_not_follow_redirects() {
        let target = one_shot_http_server("200 OK", r#"{"result":100}"#).await;
        let redirect = format!("302 Found\r\nLocation: http://127.0.0.1:{target}/");
        let mut client = client_at(
            one_shot_http_server(&redirect, "").await,
            "/?api_key=SECRET",
        );

        let text = shown(
            client
                .latest_height()
                .await
                .expect_err("redirect not followed"),
        );

        assert!(text.contains("302"), "{text}");
    }

    /// The node's acknowledgement is not the txid: a well-formed 64-hex string (say a reflected
    /// credential) must not reach the caller either.
    #[tokio::test]
    async fn send_reports_the_locally_computed_txid_not_the_nodes_text() {
        let (raw, _) = crate::pay::reserve::tests::transparent_transaction();
        let local: [u8; 32] = crate::pay::reserve::parse_transaction(&raw)
            .expect("parse")
            .txid
            .try_into()
            .expect("32-byte txid");
        let mut client: crate::Client = Box::new(
            client_answering(r#"{"result":"abababababababababababababababababababababababababababababababab","error":null}"#, "/?api_key=abababababababababababababababababababababababababababababababab").await,
        );

        let outcome = crate::pay::send(&mut client, 0, &raw)
            .await
            .expect("accepted");

        assert_eq!(
            outcome,
            BroadcastOutcome {
                error_code: 0,
                message: TxId::from_bytes(local).to_string(),
            }
        );
    }

    /// serde quotes the offending value when a result has the wrong type.
    #[tokio::test]
    async fn jsonrpc_result_of_the_wrong_type_omits_the_value() {
        let mut client = client_answering(r#"{"result":"SECRET"}"#, "/?api_key=SECRET").await;

        let text = shown(
            client
                .latest_height()
                .await
                .expect_err("a string is not a height"),
        );

        assert!(text.contains("getblockcount"), "{text}");
        assert!(!text.contains("SECRET"), "{text}");
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
