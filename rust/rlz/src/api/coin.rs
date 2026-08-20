use std::collections::HashMap;
use std::sync::{LazyLock, OnceLock};

use anyhow::Result;
use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
#[cfg(feature = "flutter")]
use flutter_rust_bridge::frb;
use hyper_util::rt::TokioIo;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{ConnectOptions, Sqlite, SqlitePool};
use tokio::sync::{Mutex, OnceCell};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tor_rtcompat::PreferredRuntime;
use tower::service_fn;
use zcash_protocol::consensus::{BlockHeight, OrchardMode};
use zcash_protocol::local_consensus::LocalNetwork;

use crate::db::{
    backfill_diversifier_index, create_schema, migrate_sapling_addresses, put_prop,
    scrub_spending_keys,
};
use crate::lwd::compact_tx_streamer_client::CompactTxStreamerClient;
use crate::net::zebra::ZebraClient;
use crate::{Client, IntoAnyhow};

#[cfg_attr(feature = "flutter", frb(dart_metadata = ("freezed")))]
#[derive(Clone)]
pub struct Coin {
    pub coin: u8,
    pub account: u32,
    pub db_filepath: String,
    pub url: String,
    pub server_type: u8,
    /// Transport: 0 = direct, 1 = Tor (arti), 3 = external proxy (uses `proxy`).
    /// 2 = Nym mixnet, only with the `nym` feature; rejected when it is off.
    pub transport: u8,
    /// Optional external proxy URL: socks5://, socks5h://, http://, https://.
    /// Empty string means a direct connection.
    pub proxy: String,
}

pub(crate) fn network_from_coin(coin: u8) -> Network {
    match coin {
        0 => Network::Main,
        1 => Network::Test,
        2 => Network::Regtest(LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(1)),
            blossom: Some(BlockHeight::from_u32(1)),
            heartwood: Some(BlockHeight::from_u32(1)),
            canopy: Some(BlockHeight::from_u32(1)),
            nu5: Some(BlockHeight::from_u32(1)),
            nu6: Some(BlockHeight::from_u32(1)),
            nu6_1: Some(BlockHeight::from_u32(1)),
            nu6_2: Some(BlockHeight::from_u32(1)),
            nu6_3: Some(BlockHeight::from_u32(250)),
            nu7: None,
            orchard_mode: OrchardMode::Normal,
        }),
        3 => {
            // ZSA regtest: NU7 active, no Ironwood (NU6.3 not active).
            // Orchard protocol V2 with cross-address transfers enabled.
            Network::ZsaRegtest(LocalNetwork {
                overwinter: Some(BlockHeight::from_u32(1)),
                sapling: Some(BlockHeight::from_u32(1)),
                blossom: Some(BlockHeight::from_u32(1)),
                heartwood: Some(BlockHeight::from_u32(1)),
                canopy: Some(BlockHeight::from_u32(1)),
                nu5: Some(BlockHeight::from_u32(1)),
                nu6: Some(BlockHeight::from_u32(1)),
                nu6_1: Some(BlockHeight::from_u32(1)),
                nu6_2: Some(BlockHeight::from_u32(1)),
                nu6_3: None,
                nu7: Some(BlockHeight::from_u32(1)),
                orchard_mode: OrchardMode::Zsa,
            })
        }
        _ => Network::Main,
    }
}

impl Coin {
    pub async fn open_database(
        self,
        db_filepath: String,
        password: Option<String>,
    ) -> Result<Coin> {
        let key_pragma = password.map(|p| format!("'{}'", p.replace('\'', "''")));
        self.open_with_key_pragma(db_filepath, key_pragma).await
    }

    /// SQLCipher raw key: exactly 32 bytes, taken verbatim with no KDF.
    /// Any other length would be silently treated as a passphrase instead.
    pub async fn open_database_with_key(
        self,
        db_filepath: String,
        db_key: Option<Vec<u8>>,
    ) -> Result<Coin> {
        if let Some(key) = db_key.as_ref() {
            anyhow::ensure!(key.len() == 32, "database key must be 32 bytes");
        }
        // The blob literal must be quoted: PRAGMA takes a name or string here, and SQLCipher
        // matches `x'<hex>'` only after the quotes are stripped. Hex needs no escaping.
        let key_pragma = db_key.map(|k| format!("\"x'{}'\"", hex::encode(k)));
        self.open_with_key_pragma(db_filepath, key_pragma).await
    }

    async fn open_with_key_pragma(
        self,
        db_filepath: String,
        key_pragma: Option<String>,
    ) -> Result<Coin> {
        let network = self.network();

        let hint_coin = if self.coin != 0 {
            Some(self.coin)
        } else {
            None
        };
        let pool = try_open(&db_filepath, &key_pragma, hint_coin).await?;
        {
            let mut pools = POOLS.lock().unwrap();
            pools.insert(db_filepath.clone(), pool.clone());
        }

        let mut connection = pool.acquire().await?;

        let mut default_coin = self.coin;
        if default_coin == 2 && self.db_filepath.to_lowercase().contains("zsa") {
            default_coin = 3;
        }
        let coin = crate::db::get_prop(&mut connection, "coin")
            .await?
            .unwrap_or(default_coin.to_string());
        let coin = coin.parse::<u8>()?;
        let account = crate::db::get_prop(&mut connection, "account")
            .await?
            .unwrap_or("0".to_string());
        let account = account.parse::<u32>()?;

        migrate_sapling_addresses(&network, &mut connection).await?;
        backfill_diversifier_index(&mut connection).await?;
        scrub_spending_keys(&mut connection).await?;

        Ok(Coin {
            coin,
            db_filepath,
            account,
            ..self
        })
    }

    pub fn get_name(&self) -> &'static str {
        match self.coin {
            0 => "mainnet",
            1 => "testnet",
            2 => "regnet",
            3 => "zsa",
            _ => unimplemented!(),
        }
    }

    pub(crate) fn network(&self) -> Network {
        network_from_coin(self.coin)
    }

    pub(crate) fn get_pool(&self) -> Result<SqlitePool> {
        let pools = POOLS.lock().unwrap();
        let pool = pools.get(&self.db_filepath).expect("Database not opened");
        Ok(pool.clone())
    }

    pub(crate) async fn get_connection(&self) -> Result<PoolConnection<Sqlite>> {
        let pool = self.get_pool()?;
        let start = std::time::Instant::now();
        let result = pool.acquire().await.anyhow();
        let elapsed = start.elapsed();
        if elapsed > std::time::Duration::from_secs(2) {
            tracing::warn!(
                "slow pool acquire took {:?} (size={}, idle={})",
                elapsed,
                pool.size(),
                pool.num_idle()
            );
        }
        result
    }

    #[cfg_attr(feature = "flutter", frb)]
    pub async fn set_account(self, account: u32) -> Result<Self> {
        let mut conn = self.get_connection().await?;
        put_prop(&mut *conn, "account", &account.to_string()).await?;
        Ok(Coin { account, ..self })
    }

    #[cfg_attr(feature = "flutter", frb(sync))]
    pub fn set_transport(self, transport: u8) -> Result<Coin> {
        #[cfg(not(feature = "nym"))]
        if transport == 2 {
            anyhow::bail!("nym feature disabled: transport 2 is unavailable");
        }
        Ok(Coin { transport, ..self })
    }

    #[cfg_attr(feature = "flutter", frb(sync))]
    pub fn set_lwd(self, server_type: u8, url: String) -> Result<Self> {
        Ok(Coin {
            url,
            server_type,
            ..self
        })
    }

    #[cfg_attr(feature = "flutter", frb(sync))]
    pub fn set_proxy(self, proxy: String) -> Result<Self> {
        Ok(Coin { proxy, ..self })
    }

    pub(crate) async fn client(&self) -> Result<Client> {
        // Mixnet-native endpoint (nym:// URL, a nym-rpc service): bypasses the
        // transport enum entirely — the mixnet IS the transport. Classified by
        // scheme before parsing, so a malformed recipient errors out instead of
        // reaching tonic, which would connect in the clear.
        if crate::net::is_nym_url(&self.url) {
            #[cfg(feature = "nym")]
            {
                if self.server_type != 0 {
                    anyhow::bail!("Nym service addresses only support lightwalletd (gRPC) servers");
                }
                let recipient = crate::net::nym_service::parse_nym_url(&self.url)
                    .ok_or_else(|| anyhow::anyhow!("invalid nym service address: {}", self.url))?;
                let channel = crate::net::nym_service::grpc_channel(recipient).await?;
                let client = CompactTxStreamerClient::new(channel);
                return Ok(Box::new(client) as Client);
            }
            #[cfg(not(feature = "nym"))]
            anyhow::bail!("nym feature disabled: refusing nym service address {}", self.url);
        }

        #[cfg(not(feature = "nym"))]
        if self.transport == 2 {
            anyhow::bail!("nym feature disabled: transport 2 is unavailable");
        }

        match self.server_type {
            // lightwalletd (gRPC): transport chosen explicitly by the enum.
            0 => {
                let channel = match self.transport {
                    1 => connect_over_tor(&self.url).await?,
                    #[cfg(feature = "nym")]
                    2 => connect_over_nym(&self.url).await?,
                    3 if !self.proxy.is_empty() => {
                        connect_over_proxy(&self.url, &self.proxy).await?
                    }
                    _ => {
                        let mut endpoint =
                            tonic::transport::Channel::from_shared(self.url.clone())?;
                        if self.url.starts_with("https") {
                            let tls = ClientTlsConfig::new().with_enabled_roots();
                            endpoint = endpoint.tls_config(tls)?;
                        }
                        endpoint.connect().await?
                    }
                };
                let client = CompactTxStreamerClient::new(channel);
                Ok(Box::new(client) as Client)
            }

            1 => {
                let client =
                    ZebraClient::new(&self.network(), &self.url, self.transport, &self.proxy)?;
                Ok(Box::new(client) as Client)
            }

            _ => unreachable!(),
        }
    }
}

async fn try_open(
    db_filepath: &str,
    key_pragma: &Option<String>,
    hint_coin: Option<u8>,
) -> Result<SqlitePool> {
    // Create a connection pool
    let options = get_connect_options(db_filepath, key_pragma);
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .idle_timeout(std::time::Duration::from_secs(30))
        .max_lifetime(std::time::Duration::from_secs(60 * 60))
        .connect_with(options)
        .await?;

    let mut connection = pool.acquire().await?;
    create_schema(&mut connection).await?;
    if sqlx::query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='props'")
        .fetch_optional(&mut *connection)
        .await?
        .is_some()
    {
        let coin_value = if let Some(coin) = hint_coin {
            coin.to_string()
        } else {
            let testnet = db_filepath.contains("testnet");
            let zsa = db_filepath.contains("zsa");
            let regtest = db_filepath.contains("regtest");
            if testnet {
                "1"
            } else if zsa {
                "3"
            } else if regtest {
                "2"
            } else {
                "0"
            }
            .to_string()
        };
        crate::db::put_prop(&mut connection, "coin", &coin_value).await?;
    }

    Ok(pool)
}

async fn build_tor(directory: &str) -> anyhow::Result<TorClient<PreferredRuntime>> {
    let config = TorClientConfigBuilder::from_directories(directory, directory).build()?;
    let tor_client = TorClient::create_bootstrapped(config).await?;
    Ok(tor_client)
}

async fn connect_over_tor(url: &str) -> anyhow::Result<Channel> {
    let uri = url.parse::<Uri>()?;

    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("no host"))?
        .to_string();
    let port = uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });

    let connector = service_fn(move |_dst| {
        let host = host.clone();
        async move {
            let tor_client = get_tor_client().await.lock().await;

            let stream = tor_client
                .connect((host.as_str(), port))
                .await
                .map_err(std::io::Error::other)?;
            // Convert to a type that implements hyper::rt::Read + Write
            let compat_stream = TokioIo::new(stream);
            Ok::<_, anyhow::Error>(compat_stream)
        }
    });

    let mut endpoint = Endpoint::from_shared(url.to_string())?;
    if url.starts_with("https") {
        let tls = ClientTlsConfig::new().with_enabled_roots();
        endpoint = endpoint.tls_config(tls)?;
    }

    Ok(endpoint.connect_with_connector(connector).await?)
}

#[cfg(feature = "nym")]
async fn connect_over_nym(url: &str) -> anyhow::Result<Channel> {
    let uri = url.parse::<Uri>()?;

    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("no host"))?
        .to_string();
    let port = uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });

    let connector = service_fn(move |_dst| {
        let host = host.clone();
        async move {
            // DNS + TCP both go through the mixnet; TLS (with SNI/cert
            // checks against the hostname) runs on top via the endpoint.
            let stream = crate::net::nym::nym_connect(&host, port).await?;
            Ok::<_, anyhow::Error>(TokioIo::new(stream))
        }
    });

    let mut endpoint = Endpoint::from_shared(url.to_string())?;
    if url.starts_with("https") {
        let tls = ClientTlsConfig::new().with_enabled_roots();
        endpoint = endpoint.tls_config(tls)?;
    }

    Ok(endpoint.connect_with_connector(connector).await?)
}

/// Build a tonic Channel to `url` whose TCP connection is established through an
/// external proxy. Supports socks5://, socks5h://, http:// and https:// proxies.
async fn connect_over_proxy(url: &str, proxy: &str) -> anyhow::Result<Channel> {
    let uri = url.parse::<Uri>()?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("no host"))?
        .to_string();
    let port = uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });

    let proxy = proxy.to_string();
    let connector = service_fn(move |_dst| {
        let host = host.clone();
        let proxy = proxy.clone();
        async move {
            let stream = open_proxied_stream(&proxy, &host, port).await?;
            let compat_stream = TokioIo::new(stream);
            Ok::<_, anyhow::Error>(compat_stream)
        }
    });

    let mut endpoint = Endpoint::from_shared(url.to_string())?;
    if url.starts_with("https") {
        let tls = ClientTlsConfig::new().with_enabled_roots();
        endpoint = endpoint.tls_config(tls)?;
    }

    Ok(endpoint.connect_with_connector(connector).await?)
}

/// Open a TCP stream to (`target_host`, `target_port`) through `proxy`.
/// Returns a tokio stream usable as the transport for a single connection.
pub(crate) async fn open_proxied_stream(
    proxy: &str,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<tokio::net::TcpStream> {
    let puri = proxy.parse::<Uri>()?;
    let scheme = puri.scheme_str().unwrap_or("").to_lowercase();
    let phost = puri
        .host()
        .ok_or_else(|| anyhow::anyhow!("proxy has no host"))?;
    let pport = puri.port_u16().unwrap_or(match scheme.as_str() {
        "socks5" | "socks5h" => 1080,
        "https" => 443,
        _ => 8080,
    });

    match scheme.as_str() {
        // socks5h => resolve the target hostname *at the proxy* (remote DNS).
        // This is what allows .onion addresses to work and prevents DNS leaks,
        // so it is the recommended scheme for Tor.
        "socks5h" => {
            let stream = tokio_socks::tcp::Socks5Stream::connect(
                (phost, pport),
                // Passing a &str target makes tokio-socks send the hostname to
                // the proxy as a SOCKS5 DOMAINNAME request (proxy-side DNS).
                (target_host, target_port),
            )
            .await?;
            Ok(stream.into_inner())
        }
        // socks5 => resolve the target hostname locally and send the IP to the
        // proxy. We resolve here explicitly so the distinction from socks5h is
        // honoured even though tokio-socks would otherwise defer to the proxy.
        "socks5" => {
            let mut addrs = tokio::net::lookup_host((target_host, target_port)).await?;
            let target_addr = addrs
                .next()
                .ok_or_else(|| anyhow::anyhow!("could not resolve {target_host}"))?;
            let stream =
                tokio_socks::tcp::Socks5Stream::connect((phost, pport), target_addr).await?;
            Ok(stream.into_inner())
        }
        "http" | "https" => http_connect_tunnel(phost, pport, target_host, target_port).await,
        other => anyhow::bail!("unsupported proxy scheme: {other}"),
    }
}

/// Establish an HTTP CONNECT tunnel through an http(s) proxy and return the
/// raw TCP stream (post-handshake) ready for TLS/HTTP2 to run over.
async fn http_connect_tunnel(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect((proxy_host, proxy_port)).await?;
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n",
        host = target_host,
        port = target_port
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read until we have the full status line + headers (terminated by \r\n\r\n).
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 256];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("proxy closed connection during CONNECT");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            anyhow::bail!("CONNECT response headers too large");
        }
    }

    let head = String::from_utf8_lossy(&buf);
    let status_line = head.lines().next().unwrap_or("");
    // Expect "HTTP/1.1 200 ..." (any 2xx is acceptable).
    let ok = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .map(|c| (200..300).contains(&c))
        .unwrap_or(false);
    if !ok {
        anyhow::bail!("proxy CONNECT failed: {status_line}");
    }
    Ok(stream)
}

impl Coin {
    #[cfg_attr(feature = "flutter", frb(sync))]
    pub fn new(default_coin: Option<u8>) -> Self {
        Coin {
            coin: default_coin.unwrap_or(0),
            account: 0,
            db_filepath: String::new(),
            server_type: 0,
            url: String::new(),
            transport: 0,
            proxy: String::new(),
        }
    }
}

fn get_connect_options(db_filepath: &str, key_pragma: &Option<String>) -> SqliteConnectOptions {
    let options = SqliteConnectOptions::new()
        .filename(db_filepath)
        .create_if_missing(true)
        .disable_statement_logging();
    match key_pragma {
        Some(key) => options.pragma("key", key.clone()),
        None => options,
    }
}

pub(crate) use zcash_trees::network::Network;

pub async fn init_datadir(directory: &str) -> Result<()> {
    let _ = DATADIR.set(directory.to_string());

    // Set the Sapling parameters directory relative to the data directory.
    // On mobile platforms (Android, iOS) the HOME env var is not set,
    // which breaks zcash_proofs::default_params_folder().  Doing it
    // unconditionally keeps the path consistent across all platforms.
    {
        let sapling_dir = std::path::PathBuf::from(directory).join(".zcash-params");
        crate::api::sapling::set_sapling_params_dir(sapling_dir);
    }

    Ok(())
}

pub async fn get_tor_client() -> &'static Mutex<TorClient<PreferredRuntime>> {
    let data_dir = {
        let data_dir = DATADIR.get().expect("Data dir should have been set");
        data_dir.clone()
    };
    let tor = TOR
        .get_or_init(|| async {
            let tor_client = build_tor(&data_dir).await.unwrap();
            Mutex::new(tor_client)
        })
        .await;
    tor
}

pub static TOR: OnceCell<Mutex<TorClient<PreferredRuntime>>> = OnceCell::const_new();
pub static DATADIR: OnceLock<String> = OnceLock::new();
pub static POOLS: LazyLock<std::sync::Mutex<HashMap<String, SqlitePool>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

pub fn close_pool(db_filepath: &str) {
    let mut pools = POOLS.lock().unwrap();
    pools.remove(db_filepath);
    // Dropping the SqlitePool closes all connections, releasing file handles
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TEST-NET-3: unroutable, so a regressed guard fails with a connection
    /// error whose text lacks the sentinel instead of quietly passing.
    #[cfg(not(feature = "nym"))]
    const UNROUTABLE: &str = "https://203.0.113.1:9067";

    fn coin_with(url: &str, transport: u8) -> Coin {
        Coin {
            coin: 0,
            account: 0,
            db_filepath: String::new(),
            url: url.to_string(),
            server_type: 0,
            transport,
            proxy: String::new(),
        }
    }

    #[tokio::test]
    async fn client_refuses_malformed_nym_url_instead_of_handing_it_to_tonic() {
        for url in [
            "nym://not-a-recipient",
            "NYM://not-a-recipient",
            "NyM://not-a-recipient",
        ] {
            let err = coin_with(url, 0)
                .client()
                .await
                .err()
                .expect("a malformed nym address must be rejected")
                .to_string();
            assert!(err.contains("nym"), "{url}: {err}");
            assert!(err.contains("not-a-recipient"), "{url}: {err}");
        }
    }

    #[cfg(not(feature = "nym"))]
    #[tokio::test]
    async fn client_rejects_transport_2_when_nym_is_off() {
        let err = coin_with(UNROUTABLE, 2)
            .client()
            .await
            .err()
            .expect("transport 2 must be rejected")
            .to_string();
        assert!(err.contains("nym"), "{err}");
        assert!(err.contains("transport 2"), "{err}");
    }

    #[cfg(not(feature = "nym"))]
    #[test]
    fn set_transport_rejects_2_when_nym_is_off() {
        let err = coin_with(UNROUTABLE, 0)
            .set_transport(2)
            .err()
            .expect("transport 2 must be rejected")
            .to_string();
        assert!(err.contains("nym"), "{err}");
        assert!(err.contains("transport 2"), "{err}");
    }
}
