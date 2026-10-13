use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

use crate::api::coin::{Coin, Network};
use crate::Client;
#[cfg(feature = "flutter")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "flutter", frb)]
pub async fn init_datadir(directory: &str) -> Result<()> {
    crate::api::coin::init_datadir(directory).await
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn is_ironwood_active(c: &Coin) -> Result<bool> {
    use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};
    let network = c.network();
    let mut client = c.client().await?;
    let height = client.latest_height().await?;
    Ok(network.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(height)))
}

pub async fn get_current_height(c: &Coin) -> Result<u32> {
    let mut client = c.client().await?;
    let height = client.latest_height().await?;
    Ok(height as u32)
}

fn coingecko_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("zkool/1.0")
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

pub async fn get_coingecko_price(api: &str, currency: &str) -> Result<f64> {
    let rep = coingecko_client()
        .get(&format!(
            "https://api.coingecko.com/api/v3/simple/price?ids=zcash&vs_currencies={currency}&x_cg_demo_api_key={api}"
        ))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    let price = rep["zcash"][currency]
        .as_f64()
        .ok_or(anyhow!("Price not found for currency: {currency}"))?;
    Ok(price)
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn get_supported_vs_currencies(api: &str) -> Result<Vec<String>> {
    let rep = coingecko_client()
        .get(&format!(
            "https://api.coingecko.com/api/v3/simple/supported_vs_currencies?x_cg_demo_api_key={api}"
        ))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<String>>()
        .await?;
    Ok(rep)
}

/// Returns the ZEC price in both `from_currency` and `to_currency`.
/// The exchange rate from `from_currency` to `to_currency` can be computed as
/// `to_price / from_price`.
#[cfg_attr(feature = "flutter", frb)]
pub async fn get_exchange_rate(
    api: &str,
    from_currency: &str,
    to_currency: &str,
) -> Result<ExchangeRate> {
    let rep = coingecko_client()
        .get(&format!(
            "https://api.coingecko.com/api/v3/simple/price?ids=zcash&vs_currencies={from_currency},{to_currency}&x_cg_demo_api_key={api}"
        ))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    let from_price = rep["zcash"][from_currency]
        .as_f64()
        .ok_or(anyhow!("Price not found for currency: {from_currency}"))?;
    let to_price = rep["zcash"][to_currency]
        .as_f64()
        .ok_or(anyhow!("Price not found for currency: {to_currency}"))?;
    Ok(ExchangeRate {
        from_price,
        to_price,
        from_currency: from_currency.to_string(),
        to_currency: to_currency.to_string(),
    })
}

const LIGHTWALLETD: u8 = 0;
const MAINNET: u8 = 0;

/// One measurement of a mainnet lightwalletd server.
#[derive(Debug)]
pub struct ServerProbe {
    pub chain_name: String,
    pub sapling_activation_height: u64,
    pub consensus_branch_id: String,
    pub block_height: u64,
    pub estimated_height: u64,
    /// The server's branch id is the one mainnet has at its `block_height`.
    pub branch_id_matches: bool,
    /// Fresh connect plus `GetLightdInfo`.
    pub info_ms: u64,
    pub range_ms: u64,
    pub range_blocks_received: u32,
}

/// Connects afresh and measures the server; the whole probe gives up after `timeout`.
pub async fn probe_server(
    url: &str,
    transport: u8,
    proxy: &str,
    range_blocks: u32,
    timeout: Duration,
) -> Result<ServerProbe> {
    let coin = Coin::new(Some(MAINNET))
        .set_lwd(LIGHTWALLETD, url.to_string())?
        .set_transport(transport)?
        .set_proxy(proxy.to_string())?;
    within(timeout, async {
        let started = Instant::now();
        let mut client = coin.client().await?;
        measure(&mut client, started, range_blocks).await
    })
    .await
}

async fn within<T>(timeout: Duration, probe: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(timeout, probe)
        .await
        .map_err(|_| anyhow!("probe timed out after {} ms", timeout.as_millis()))?
}

async fn measure(client: &mut Client, started: Instant, range_blocks: u32) -> Result<ServerProbe> {
    let info = client.lightd_info().await?;
    let info_ms = started.elapsed().as_millis() as u64;

    let range_started = Instant::now();
    let tip = info.block_height as u32;
    let first = tip.saturating_sub(range_blocks.saturating_sub(1));
    let mut blocks = client.block_range(&Network::Main, first, tip).await?;
    let mut range_blocks_received = 0;
    while let Some(block) = blocks.next().await {
        block?;
        range_blocks_received += 1;
    }
    let range_ms = range_started.elapsed().as_millis() as u64;

    Ok(ServerProbe {
        branch_id_matches: is_mainnet_branch_at(&info.consensus_branch_id, tip),
        chain_name: info.chain_name,
        sapling_activation_height: info.sapling_activation_height,
        consensus_branch_id: info.consensus_branch_id,
        block_height: info.block_height,
        estimated_height: info.estimated_height,
        info_ms,
        range_ms,
        range_blocks_received,
    })
}

fn is_mainnet_branch_at(branch_id_hex: &str, height: u32) -> bool {
    let expected = u32::from(BranchId::for_height(
        &MainNetwork,
        BlockHeight::from_u32(height),
    ));
    u32::from_str_radix(branch_id_hex, 16) == Ok(expected)
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn get_network_name(c: &Coin) -> String {
    c.get_name().to_string()
}

#[cfg_attr(feature = "flutter", frb)]
pub async fn query_lwd_list(coin: u8) -> Result<Vec<LWDInfo>> {
    crate::net::lwd::query_lwd_list(coin).await
}

/// True when `url` is a mixnet-native server address
/// (`nym://<identity>.<encryption>@<gateway>`).
#[cfg(feature = "nym")]
#[cfg_attr(feature = "flutter", frb(sync))]
pub fn is_valid_nym_url(url: String) -> bool {
    crate::net::nym_service::parse_nym_url(&url).is_some()
}

#[cfg_attr(feature = "flutter", frb(dart_metadata = ("freezed")))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRate {
    pub from_price: f64,
    pub to_price: f64,
    pub from_currency: String,
    pub to_currency: String,
}

#[cfg_attr(feature = "flutter", frb(dart_metadata = ("freezed")))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LWDInfo {
    pub url: String,
    pub is_tor: bool,
    pub height: u32,
    pub status: String,
    pub uptime: u32,
    pub version: String,
    pub ping: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lwd::{CompactBlock, LightdInfo};
    use crate::net::zebra::ZebraClient;
    use crate::net::{BroadcastOutcome, LwdServer};
    use std::sync::{Arc, Mutex};
    use tokio_stream::wrappers::ReceiverStream;
    use tonic::async_trait;
    use zcash_primitives::transaction::Transaction;

    const NU6_HEIGHT: u64 = 2_800_000;
    const NU6_BRANCH_ID: &str = "c8e71055";
    const NU5_BRANCH_ID: &str = "c2d6d0b4";

    /// Answers `GetLightdInfo` with `info` after `info_delay`, and a block range with at most
    /// `blocks_served` blocks after `range_delay`; `None` info never answers.
    #[derive(Clone)]
    struct FakeLightwalletd {
        info: Option<LightdInfo>,
        info_delay: Duration,
        blocks_served: u32,
        range_delay: Duration,
        ranges: Arc<Mutex<Vec<(u32, u32)>>>,
    }

    impl FakeLightwalletd {
        fn new(block_height: u64, branch_id: &str) -> Self {
            FakeLightwalletd {
                info: Some(LightdInfo {
                    chain_name: "main".to_string(),
                    sapling_activation_height: 419_200,
                    consensus_branch_id: branch_id.to_string(),
                    block_height,
                    estimated_height: block_height + 1,
                    ..Default::default()
                }),
                info_delay: Duration::from_millis(30),
                blocks_served: u32::MAX,
                range_delay: Duration::from_millis(20),
                ranges: Arc::new(Mutex::new(vec![])),
            }
        }
    }

    #[async_trait]
    impl LwdServer for FakeLightwalletd {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }

        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }

        async fn block(&mut self, _network: &Network, _height: u32) -> Result<CompactBlock> {
            unimplemented!()
        }

        type CompactBlockStream = ReceiverStream<Result<CompactBlock>>;
        async fn block_range(
            &mut self,
            _network: &Network,
            start: u32,
            end: u32,
        ) -> Result<Self::CompactBlockStream> {
            self.ranges.lock().expect("lock").push((start, end));
            tokio::time::sleep(self.range_delay).await;
            let count = (end - start + 1).min(self.blocks_served);
            let (sender, receiver) = tokio::sync::mpsc::channel(count.max(1) as usize);
            for height in start..start + count {
                let block = CompactBlock {
                    height: height as u64,
                    ..Default::default()
                };
                sender.send(Ok(block)).await.expect("queue block");
            }
            Ok(ReceiverStream::new(receiver))
        }

        async fn transaction(
            &mut self,
            _network: &Network,
            _txid: &[u8],
        ) -> Result<(u32, Transaction)> {
            unimplemented!()
        }

        async fn post_transaction(&mut self, _height: u32, _tx: &[u8]) -> Result<BroadcastOutcome> {
            unimplemented!()
        }

        type TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn taddress_txs(
            &mut self,
            _network: &Network,
            _taddress: &str,
            _start: u32,
            _end: u32,
        ) -> Result<Self::TransactionStream> {
            unimplemented!()
        }

        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _network: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }

        async fn tree_state(&mut self, _height: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            unimplemented!()
        }

        async fn chain_anchor(&mut self, _height: u32) -> Result<Vec<u8>> {
            unimplemented!()
        }

        async fn lightd_info(&mut self) -> Result<LightdInfo> {
            tokio::time::sleep(self.info_delay).await;
            match &self.info {
                Some(info) => Ok(info.clone()),
                None => std::future::pending().await,
            }
        }
    }

    async fn measure_fake(server: &FakeLightwalletd, range_blocks: u32) -> Result<ServerProbe> {
        let mut client: Client = Box::new(server.clone());
        measure(&mut client, Instant::now(), range_blocks).await
    }

    #[tokio::test(start_paused = true)]
    async fn measure_answering_server_maps_the_info_and_times_both_calls() {
        let server = FakeLightwalletd::new(NU6_HEIGHT, NU6_BRANCH_ID);

        let probe = measure_fake(&server, 10).await.expect("probe");

        assert_eq!(probe.chain_name, "main");
        assert_eq!(probe.sapling_activation_height, 419_200);
        assert_eq!(probe.consensus_branch_id, NU6_BRANCH_ID);
        assert_eq!(probe.block_height, NU6_HEIGHT);
        assert_eq!(probe.estimated_height, NU6_HEIGHT + 1);
        assert!(probe.branch_id_matches);
        assert_eq!(probe.info_ms, 30);
        assert_eq!(probe.range_ms, 20);
        assert_eq!(probe.range_blocks_received, 10);
        let tip = NU6_HEIGHT as u32;
        assert_eq!(*server.ranges.lock().unwrap(), vec![(tip - 9, tip)]);
    }

    #[tokio::test(start_paused = true)]
    async fn measure_branch_id_of_another_upgrade_does_not_match() {
        let server = FakeLightwalletd::new(NU6_HEIGHT, NU5_BRANCH_ID);

        let probe = measure_fake(&server, 10).await.expect("probe");

        assert!(!probe.branch_id_matches);
    }

    #[tokio::test(start_paused = true)]
    async fn measure_short_range_reports_the_blocks_received() {
        let server = FakeLightwalletd {
            blocks_served: 4,
            ..FakeLightwalletd::new(NU6_HEIGHT, NU6_BRANCH_ID)
        };

        let probe = measure_fake(&server, 10).await.expect("probe");

        assert_eq!(probe.range_blocks_received, 4);
    }

    #[tokio::test(start_paused = true)]
    async fn within_server_never_answers_fails_with_a_timeout_at_the_deadline() {
        let server = FakeLightwalletd {
            info: None,
            ..FakeLightwalletd::new(NU6_HEIGHT, NU6_BRANCH_ID)
        };
        let started = Instant::now();

        let error = within(Duration::from_millis(8_000), measure_fake(&server, 10))
            .await
            .expect_err("a silent server")
            .to_string();

        assert_eq!(error, "probe timed out after 8000 ms");
        assert_eq!(started.elapsed(), Duration::from_millis(8_000));
    }

    #[tokio::test]
    async fn lightd_info_zebra_server_is_not_available() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut zebra =
            ZebraClient::new(&Network::Main, "http://127.0.0.1:1", 0, "").expect("zebra client");

        let error = zebra.lightd_info().await.expect_err("zebra").to_string();

        assert!(error.contains("not available"), "{error}");
    }
}
