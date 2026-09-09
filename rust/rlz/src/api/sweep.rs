use anyhow::Result;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[cfg(feature = "flutter")]
use crate::frb_generated::StreamSink;
use crate::{api::coin::Coin, sync::transparent_sweep, Client};

#[cfg(feature = "flutter")]
use flutter_rust_bridge::frb;

/// Serializes address-discovery walks against each other. Held for the whole walk (not per
/// window, unlike `SYNCING`), so a discovery call always occupies at most one pooled
/// connection no matter how many other discovery calls are queued behind it.
static DISCOVERING: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// How many candidates a discovery walk probes at once over its one connection when the caller
/// does not choose. The walk halves it on the first failed probe and clamps it to `1..=32`.
pub const DEFAULT_DISCOVERY_CONCURRENCY: u32 = 8;

#[cfg(not(test))]
const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
const CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// A server that accepts TCP but never finishes the handshake would otherwise pin `DISCOVERING`
/// and a pooled connection for the life of the process.
async fn connect_client(c: &Coin) -> Result<Client> {
    match tokio::time::timeout(CLIENT_CONNECT_TIMEOUT, c.client()).await {
        Ok(client) => client,
        Err(_elapsed) => anyhow::bail!("connecting to the light-wallet server timed out"),
    }
}

#[cfg_attr(feature = "flutter", frb(opaque))]
pub struct TransparentScanner {
    pub(crate) cancellation_token: CancellationToken,
}

impl TransparentScanner {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cancellation_token: CancellationToken::new(),
        })
    }

    #[cfg(feature = "flutter")]
    pub async fn run(
        &mut self,
        address_stream: StreamSink<String>,
        end_height: u32,
        gap_limit: u32,
        c: &Coin,
    ) -> Result<()> {
        let walk = DISCOVERING.lock().await;
        let connection = c.get_connection().await?;
        let client = connect_client(c).await?;
        transparent_sweep(
            &c.network(),
            connection,
            client,
            c.account,
            end_height,
            gap_limit,
            DEFAULT_DISCOVERY_CONCURRENCY,
            move |address| {
                let _ = address_stream.add(address);
            },
            self.cancellation_token.clone(),
            walk,
        )
        .await?;
        Ok(())
    }

    pub fn cancel(&self) -> Result<()> {
        self.cancellation_token.cancel();
        Ok(())
    }
}

/// Rediscovers transparent addresses the account handed out before it was restored: a restore
/// keeps the keys but not the address rows, so payments made to a one-time address stay invisible
/// until it is derived again. Returns how many addresses were added.
///
/// `concurrency` is how many candidates are probed at once over the one connection; the walk
/// clamps it into `1..=32`, so 0 means the sequential walk.
#[cfg_attr(feature = "flutter", frb)]
pub async fn discover_transparent_addresses(
    end_height: u32,
    gap_limit: u32,
    concurrency: u32,
    c: &Coin,
) -> Result<u32> {
    let _walk = DISCOVERING.lock().await;
    let mut connection = c.get_connection().await?;
    let mut client = connect_client(c).await?;
    crate::sync::discover_transparent_addresses(
        &c.network(),
        &mut connection,
        &mut client,
        c.account,
        end_height,
        gap_limit,
        concurrency,
        |_| {},
        CancellationToken::new(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::{restore, TEST_PHRASE};
    use crate::api::sync::{file_backed_coin, LOCK_TEST_SERIAL, SYNCING};

    #[tokio::test]
    async fn discover_transparent_addresses_takes_the_discovery_guard_before_the_connection() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let coin = file_backed_coin().await;
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(
                coin.get_connection()
                    .await
                    .expect("acquire pooled connection"),
            );
        }

        let mut call = tokio::spawn({
            let coin = coin.clone();
            async move {
                discover_transparent_addresses(0, 0, DEFAULT_DISCOVERY_CONCURRENCY, &coin).await
            }
        });

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            DISCOVERING.try_lock().is_err(),
            "a guard-first wrapper must already hold DISCOVERING while the pool is exhausted"
        );
        assert!(
            SYNCING.try_lock().is_ok(),
            "the connection was never asked for, so SYNCING must still be free"
        );

        held.clear();
        let joined = tokio::time::timeout(Duration::from_secs(5), &mut call)
            .await
            .expect("discover_transparent_addresses did not complete once a connection was freed");
        let _ = joined.expect("discover_transparent_addresses task panicked");
    }

    /// Accepts TCP and then answers nothing, each socket kept alive (dropping it right after
    /// accept would reset the connection and fail fast instead of stalling). Returns the coin
    /// pointed at it and the endpoint's authority, for tests that reach it through a proxy.
    async fn coin_at_a_stalling_endpoint() -> (Coin, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            let mut accepted = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                accepted.push(stream);
            }
        });

        let coin = file_backed_coin().await;
        let mut connection = coin
            .get_connection()
            .await
            .expect("acquire pooled connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore test account");
        drop(connection);
        let authority = format!("127.0.0.1:{port}");
        (
            Coin {
                account,
                url: format!("http://{authority}"),
                ..coin
            },
            authority,
        )
    }

    #[tokio::test]
    async fn discover_transparent_addresses_gives_up_on_an_endpoint_that_never_connects() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        // A SOCKS5 proxy that never answers the method-selection handshake: the client's
        // connect can then never finish, which is what has to be bounded.
        let (coin, authority) = coin_at_a_stalling_endpoint().await;
        let coin = Coin {
            transport: 3,
            proxy: format!("socks5://{authority}"),
            ..coin
        };

        let call = tokio::time::timeout(
            Duration::from_secs(5),
            discover_transparent_addresses(2_000_100, 0, DEFAULT_DISCOVERY_CONCURRENCY, &coin),
        )
        .await
        .expect("discovery must give up on its own, with nothing aborting it");

        assert!(
            call.is_err(),
            "an endpoint that never finishes connecting is a failed discovery"
        );
        assert!(
            DISCOVERING.try_lock().is_ok(),
            "the guard must be free for the next discovery call"
        );
    }

    #[tokio::test]
    async fn five_concurrent_discovery_calls_hold_at_most_one_connection() {
        let _serial = LOCK_TEST_SERIAL.lock().await;
        let (coin, _) = coin_at_a_stalling_endpoint().await;

        let handles: Vec<_> = (0..5)
            .map(|_| {
                let coin = coin.clone();
                tokio::spawn(async move {
                    discover_transparent_addresses(
                        2_000_100,
                        0,
                        DEFAULT_DISCOVERY_CONCURRENCY,
                        &coin,
                    )
                    .await
                })
            })
            .collect();

        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut spare = Vec::new();
        for _ in 0..4 {
            spare.push(
                tokio::time::timeout(Duration::from_secs(2), coin.get_connection())
                    .await
                    .expect(
                        "a spare connection must be available while 4 of 5 walks queue on DISCOVERING",
                    )
                    .expect("acquire pooled connection"),
            );
        }

        for handle in handles {
            handle.abort();
        }
    }
}
