use std::{collections::HashSet, time::Duration};

use anyhow::{Context as _, Result};
use shielded::Synchronizer;
use sqlx::{sqlite::SqliteRow, Row, SqliteConnection};
use tokio::sync::{broadcast, mpsc::Sender};
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tracing::debug;
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};
use zcash_trees::network::Network;

use orchard::issuance::auth::IssueValidatingKey;
use orchard::issuance::auth::ZSASchnorr;
use orchard::note::AssetBase;
use orchard::note::AssetId;

use crate::{
    lwd::CompactBlock,
    net::{StreamStats, STREAM_STATS},
    warp::hasher::{OrchardHasher, SaplingHasher},
    Client,
};
use zcash_trees::types::{BlockHeader, Issuance, WarpSyncMessage};

use super::legacy::CommitmentTreeFrontier;

pub use zcash_trees::types::SyncError;

mod shielded;

const MAX_BLOCKS_PER_CHUNK: usize = 1000;

/// Waits before each reopen of a broken compact-block stream; once they run out the scan fails.
const STREAM_RESUME_DELAYS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];

pub type SaplingSync = Synchronizer<shielded::sapling::SaplingProtocol>;
pub type OrchardSync = Synchronizer<shielded::orchard::OrchardProtocol>;
pub type IronwoodSync = Synchronizer<shielded::ironwood::IronwoodProtocol>;

pub enum BlockMessage {
    Chunk(Vec<CompactBlock>),
    SaveHeader(BlockHeader),
    Reorg(Vec<u32>, u32),
}

pub(crate) async fn send_reorg(
    tx_decrypted: &Sender<WarpSyncMessage>,
    accounts: Vec<u32>,
    height: u32,
) -> Result<(), SyncError> {
    tx_decrypted
        .send(WarpSyncMessage::Rewind(accounts, height))
        .await
        .context("sending reorg rewind")?;
    tx_decrypted
        .send(WarpSyncMessage::Commit)
        .await
        .context("committing reorg rewind")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn warp_sync(
    network: &Network,
    connection: &mut SqliteConnection,
    start_height: u32,
    end_height: u32,
    accounts: &[(u32, bool)],
    blocks: ReceiverStream<Result<CompactBlock>>,
    client: Client,
    heights_without_time: HashSet<u32>,
    actions_per_sync: u32,
    sapling_state: &CommitmentTreeFrontier,
    orchard_state: &CommitmentTreeFrontier,
    ironwood_state: &CommitmentTreeFrontier,
    tx_decrypted: Sender<WarpSyncMessage>,
    rx_cancel: broadcast::Receiver<()>,
) -> Result<(), SyncError> {
    let sap_hasher = SaplingHasher::default();

    let mut sap_dec = SaplingSync::new(
        *network,
        &mut *connection,
        1,
        start_height,
        accounts,
        tx_decrypted.clone(),
        sapling_state.size() as u32,
        sapling_state.to_edge(&sap_hasher),
    )
    .await?;

    let orch_hasher = OrchardHasher::default();
    let mut orch_dec = OrchardSync::new(
        *network,
        &mut *connection,
        2,
        start_height,
        accounts,
        tx_decrypted.clone(),
        orchard_state.size() as u32,
        orchard_state.to_edge(&orch_hasher),
    )
    .await?;

    let ironwood_active = network.activation_height(NetworkUpgrade::Nu6_3).is_some();
    let ironwood_hasher = OrchardHasher::default();
    let mut ironwood_dec = if ironwood_active {
        Some(
            IronwoodSync::new(
                *network,
                &mut *connection,
                3,
                start_height,
                accounts,
                tx_decrypted.clone(),
                ironwood_state.size() as u32,
                ironwood_state.to_edge(&ironwood_hasher),
            )
            .await?,
        )
    } else {
        None
    };

    let ironwood_has_keys = ironwood_dec.as_ref().map_or(false, |d| !d.has_no_keys());
    if sap_dec.has_no_keys() && orch_dec.has_no_keys() && !ironwood_has_keys {
        debug!("No keys to sync");
        return Ok(());
    }

    let prev_hash = sqlx::query("SELECT hash FROM headers WHERE height = ?")
        .bind(start_height - 1)
        .map(|row: SqliteRow| row.get::<Vec<u8>, _>(0))
        .fetch_optional(&mut *connection)
        .await
        .unwrap();

    let account_ids = accounts.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let (tx_blocks, mut rx_blocks) = tokio::sync::mpsc::channel::<BlockMessage>(2);
    let source = ResumableBlocks {
        blocks,
        client,
        network: *network,
        end_height,
        failures: 0,
        stats: &STREAM_STATS,
    };
    let block_reader = read_block_stream(
        source,
        start_height,
        prev_hash,
        account_ids,
        heights_without_time,
        actions_per_sync,
        tx_blocks,
        rx_cancel,
        Duration::from_secs(60),
    );

    let block_processor = async {
        while let Some(bm) = rx_blocks.recv().await {
            match bm {
                BlockMessage::Chunk(bs) => {
                    debug!("Processing {} blocks", bs.len());

                    // Send Issuance messages for asset storage before any Note
                    // messages (same transaction ordering guarantee).
                    for cb in &bs {
                        for vtx in &cb.vtx {
                            for iss in &vtx.issuances {
                                let desc_hash: [u8; 32] =
                                    iss.asset_desc_hash.as_slice().try_into().unwrap();
                                let ik = IssueValidatingKey::<ZSASchnorr>::decode(&iss.ik)
                                    .expect("invalid issuer key in issuance");
                                let asset_id = AssetId::new_v0(&ik, &desc_hash);
                                let asset_base = AssetBase::custom(&asset_id);
                                tx_decrypted
                                    .send(WarpSyncMessage::Issuance(Issuance {
                                        asset_desc_hash: iss.asset_desc_hash.clone(),
                                        ik: iss.ik.clone(),
                                        asset_base: asset_base.to_bytes().to_vec(),
                                        finalized: iss.finalize,
                                        height: cb.height as u32,
                                    }))
                                    .await
                                    .context("sending issuance")?;
                            }
                        }
                    }

                    sap_dec.add(&bs).await?;
                    orch_dec.add(&bs).await?;
                    if let Some(ref mut ironwood_dec) = ironwood_dec {
                        ironwood_dec.add(&bs).await?;
                    }

                    let lcb = bs.last().unwrap();
                    let bh = BlockHeader {
                        height: lcb.height as u32,
                        hash: lcb.hash.clone(),
                        time: lcb.time,
                    };
                    tx_decrypted
                        .send(WarpSyncMessage::BlockHeader(bh))
                        .await
                        .context("sending block header")?;
                    tx_decrypted
                        .send(WarpSyncMessage::Commit)
                        .await
                        .context("committing block chunk")?;
                }
                BlockMessage::Reorg(accounts, height) => {
                    send_reorg(&tx_decrypted, accounts, height).await?;
                    break;
                }
                BlockMessage::SaveHeader(bh) => {
                    tx_decrypted
                        .send(WarpSyncMessage::BlockHeader(bh))
                        .await
                        .context("sending saved block header")?;
                }
            }
        }
        Ok::<_, SyncError>(())
    };

    let (reader_result, processor_result) = tokio::join!(block_reader, block_processor);
    processor_result?;
    reader_result
}

/// The compact-block stream of one scan, reopened where it broke.
struct ResumableBlocks {
    blocks: ReceiverStream<Result<CompactBlock>>,
    client: Client,
    network: Network,
    end_height: u32,
    failures: usize,
    stats: &'static StreamStats,
}

impl ResumableBlocks {
    /// Replaces the broken stream with one starting at `from`, or fails once the delays run out.
    async fn resume(
        &mut self,
        mut error: anyhow::Error,
        from: u32,
        rx_cancel: &mut broadcast::Receiver<()>,
    ) -> Result<(), SyncError> {
        loop {
            self.stats.record_break();
            self.failures += 1;
            let Some(delay) = STREAM_RESUME_DELAYS.get(self.failures - 1) else {
                return Err(SyncError::Other(anyhow::anyhow!(
                    "network: compact block stream broke {} times: {error:#}",
                    self.failures
                )));
            };
            debug!("compact block stream broke ({error:#}), reopening at {from} in {delay:?}");
            let reopen = async {
                tokio::time::sleep(*delay).await;
                self.client
                    .block_range(&self.network, from, self.end_height)
                    .await
            };
            let reopened = tokio::select! {
                biased;
                _ = rx_cancel.recv() => return Err(SyncError::Cancelled),
                reopened = reopen => reopened,
            };
            match reopened {
                Ok(blocks) => {
                    self.blocks = blocks;
                    return Ok(());
                }
                Err(reopen_error) => error = reopen_error,
            }
        }
    }

    fn delivered_block(&mut self) {
        if self.failures > 0 {
            self.stats.record_resumed();
            self.failures = 0;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn read_block_stream(
    mut source: ResumableBlocks,
    start_height: u32,
    mut prev_hash: Option<Vec<u8>>,
    account_ids: Vec<u32>,
    mut heights_without_time: HashSet<u32>,
    actions_per_sync: u32,
    tx_blocks: Sender<BlockMessage>,
    mut rx_cancel: broadcast::Receiver<()>,
    stall_timeout: Duration,
) -> Result<(), SyncError> {
    let end_height = source.end_height as u64;
    let mut chunk = vec![];
    let mut interval = tokio::time::interval(stall_timeout);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut current_height = start_height;
    let mut previous_height = 0;
    let mut expected_height = start_height as u64;
    let mut actions = 0;

    loop {
        let error = tokio::select! {
            biased;
            _ = rx_cancel.recv() => {
                debug!("Sync cancelled");
                return Err(SyncError::Cancelled);
            }
            _ = interval.tick() => {
                debug!("Syncing at height {}", current_height);
                if previous_height != current_height {
                    previous_height = current_height;
                    continue;
                }
                anyhow::anyhow!("compact block stream stalled at height {current_height}")
            }
            message = source.blocks.next() => {
                match message {
                Some(Ok(block)) => {
                    if block.height != expected_height {
                        flush_chunk(&tx_blocks, &mut chunk).await?;
                        return Err(SyncError::Other(anyhow::anyhow!(
                            "expected compact block {expected_height}, received {}",
                            block.height
                        )));
                    }
                    let block_prev_hash = block.prev_hash.clone();
                    current_height = block.height as u32;
                    if let Some(previous_hash) = prev_hash {
                        if previous_hash != block_prev_hash {
                            flush_chunk(&tx_blocks, &mut chunk).await?;
                            tx_blocks
                                .send(BlockMessage::Reorg(account_ids, current_height - 1))
                                .await
                                .context("sending reorg")?;
                            debug!("Reorganization detected at block {}", block.height);
                            return Err(SyncError::Reorg(current_height - 1));
                        }
                    }
                    prev_hash = Some(block.hash.clone());
                    expected_height += 1;
                    source.delivered_block();

                    if heights_without_time.remove(&current_height) {
                        let header = BlockHeader {
                            height: current_height,
                            hash: block.hash.clone(),
                            time: block.time,
                        };
                        tx_blocks
                            .send(BlockMessage::SaveHeader(header))
                            .await
                            .context("sending block header")?;
                    }

                    for transaction in &block.vtx {
                        actions += transaction.outputs.len();
                        actions += transaction.actions.len();
                    }
                    chunk.push(block);

                    if actions >= actions_per_sync as usize || chunk.len() >= MAX_BLOCKS_PER_CHUNK {
                        flush_chunk(&tx_blocks, &mut chunk).await?;
                        actions = 0;
                    }
                    continue;
                }
                Some(Err(error)) => error,
                None if expected_height > end_height => break,
                None => anyhow::anyhow!(
                    "compact block stream ended before height {expected_height}"
                ),
                }
            }
        };
        flush_chunk(&tx_blocks, &mut chunk).await?;
        if expected_height > end_height {
            return Err(SyncError::Other(error));
        }
        source
            .resume(error, expected_height as u32, &mut rx_cancel)
            .await?;
        interval.reset();
    }

    debug!("no more blocks to process");
    flush_chunk(&tx_blocks, &mut chunk).await?;
    debug!("warp_sync completed");
    Ok(())
}

async fn flush_chunk(
    tx_blocks: &Sender<BlockMessage>,
    chunk: &mut Vec<CompactBlock>,
) -> Result<(), SyncError> {
    if chunk.is_empty() {
        return Ok(());
    }
    tx_blocks
        .send(BlockMessage::Chunk(std::mem::take(chunk)))
        .await
        .context("sending compact block chunk")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::tests::{restore, TEST_PHRASE};
    use crate::api::sync::file_backed_coin;
    use crate::net::{BroadcastOutcome, LwdServer, NetworkStats};
    use crate::sync::shielded_sync;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tonic::async_trait;
    use zcash_primitives::transaction::Transaction;

    fn block(height: u32, previous_hash: &[u8], hash: &[u8]) -> CompactBlock {
        CompactBlock {
            height: height as u64,
            prev_hash: previous_hash.to_vec(),
            hash: hash.to_vec(),
            ..Default::default()
        }
    }

    fn chained(height: u32) -> CompactBlock {
        block(height, &[height as u8 - 1], &[height as u8])
    }

    fn broken() -> Result<CompactBlock> {
        Err(anyhow::anyhow!("unexpected EOF"))
    }

    enum Reply {
        Refused,
        Ends(Vec<Result<CompactBlock>>),
        Stalls(Vec<Result<CompactBlock>>),
        Late(Duration, CompactBlock),
    }

    /// Answers each `block_range` with the next scripted reply; one more request than scripted panics.
    #[derive(Clone)]
    struct ScriptedRanges {
        replies: Arc<Mutex<VecDeque<Reply>>>,
        starts: Arc<Mutex<Vec<u32>>>,
        stalled: Arc<Mutex<Vec<Sender<Result<CompactBlock>>>>>,
    }

    impl ScriptedRanges {
        fn new(replies: Vec<Reply>) -> Self {
            ScriptedRanges {
                replies: Arc::new(Mutex::new(replies.into())),
                starts: Arc::new(Mutex::new(vec![])),
                stalled: Arc::new(Mutex::new(vec![])),
            }
        }

        fn starts(&self) -> Vec<u32> {
            self.starts.lock().expect("lock").clone()
        }
    }

    #[async_trait]
    impl LwdServer for ScriptedRanges {
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
            _end: u32,
        ) -> Result<Self::CompactBlockStream> {
            self.starts.lock().expect("lock").push(start);
            let reply = self.replies.lock().expect("lock").pop_front();
            let (items, stalls) = match reply.expect("an unscripted block range request") {
                Reply::Refused => anyhow::bail!("connection refused"),
                Reply::Ends(items) => (items, false),
                Reply::Stalls(items) => (items, true),
                Reply::Late(delay, block) => {
                    let (sender, receiver) = tokio::sync::mpsc::channel(1);
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = sender.send(Ok(block)).await;
                    });
                    return Ok(ReceiverStream::new(receiver));
                }
            };
            let (sender, receiver) = tokio::sync::mpsc::channel(items.len().max(1));
            for item in items {
                sender.send(item).await.expect("queue item");
            }
            if stalls {
                self.stalled.lock().expect("lock").push(sender);
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
            Ok((vec![], vec![], vec![]))
        }

        async fn chain_anchor(&mut self, _height: u32) -> Result<Vec<u8>> {
            unimplemented!()
        }
    }

    fn resumable(
        blocks: ReceiverStream<Result<CompactBlock>>,
        server: &ScriptedRanges,
        end_height: u32,
        stats: &'static StreamStats,
    ) -> ResumableBlocks {
        ResumableBlocks {
            blocks,
            client: Box::new(server.clone()),
            network: Network::Main,
            end_height,
            failures: 0,
            stats,
        }
    }

    struct Read {
        result: Result<(), SyncError>,
        messages: Vec<BlockMessage>,
        starts: Vec<u32>,
    }

    /// The first reply is the stream the scan opens; the rest answer its reopens.
    async fn read_scripted(
        replies: Vec<Reply>,
        start: u32,
        end: u32,
        previous_hash: Option<Vec<u8>>,
        stats: &'static StreamStats,
    ) -> Read {
        let server = ScriptedRanges::new(replies);
        let blocks = server
            .clone()
            .block_range(&Network::Main, start, end)
            .await
            .expect("first stream");
        let (messages, mut output) = tokio::sync::mpsc::channel(10);
        let (_cancel, cancellation) = broadcast::channel(1);

        let reader = read_block_stream(
            resumable(blocks, &server, end, stats),
            start,
            previous_hash,
            vec![7],
            HashSet::new(),
            usize::MAX as u32,
            messages,
            cancellation,
            Duration::from_secs(60),
        );
        let collector = async {
            let mut collected = vec![];
            while let Some(message) = output.recv().await {
                collected.push(message);
            }
            collected
        };
        let (result, messages) = tokio::join!(reader, collector);
        Read {
            result,
            messages,
            starts: server.starts(),
        }
    }

    async fn read(
        items: Vec<Result<CompactBlock>>,
        start: u32,
        end: u32,
        previous_hash: Option<Vec<u8>>,
    ) -> (Result<(), SyncError>, Vec<BlockMessage>) {
        static STATS: StreamStats = StreamStats::new();
        let read = read_scripted(vec![Reply::Ends(items)], start, end, previous_hash, &STATS).await;
        (read.result, read.messages)
    }

    fn chunked_heights(messages: &[BlockMessage]) -> Vec<u64> {
        messages
            .iter()
            .flat_map(|message| match message {
                BlockMessage::Chunk(blocks) => blocks.iter().map(|b| b.height).collect(),
                _ => vec![],
            })
            .collect()
    }

    fn stats(stream_breaks: u64, stream_resumed: u64) -> NetworkStats {
        NetworkStats {
            stream_breaks,
            stream_resumed,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_source_fails_returns_the_source_error() {
        static STATS: StreamStats = StreamStats::new();
        let fails = || Reply::Ends(vec![Err(anyhow::anyhow!("stream failed"))]);
        let read = read_scripted(
            vec![fails(), fails(), fails(), fails()],
            10,
            10,
            None,
            &STATS,
        )
        .await;

        let error = read.result.expect_err("source failure").to_string();
        assert!(error.contains("stream failed"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_ends_early_rejects_the_incomplete_range() {
        static STATS: StreamStats = StreamStats::new();
        let mut replies = vec![Reply::Ends(vec![Ok(block(10, &[], &[10]))])];
        replies.extend((0..3).map(|_| Reply::Ends(vec![])));
        let read = read_scripted(replies, 10, 11, None, &STATS).await;

        let error = read.result.expect_err("incomplete range").to_string();
        assert!(error.contains("11"), "{error}");
    }

    #[tokio::test]
    async fn read_block_stream_skips_a_height_rejects_the_gap() {
        let (result, _) = read(vec![Ok(block(11, &[], &[11]))], 10, 11, None).await;

        assert!(result.expect_err("height gap").to_string().contains("10"));
    }

    #[tokio::test]
    async fn read_block_stream_repeats_a_height_rejects_the_duplicate() {
        let (result, _) = read(
            vec![Ok(block(10, &[], &[10])), Ok(block(10, &[10], &[11]))],
            10,
            11,
            None,
        )
        .await;

        assert!(result
            .expect_err("duplicate height")
            .to_string()
            .contains("11"));
    }

    #[tokio::test]
    async fn read_block_stream_reads_the_exact_range_succeeds() {
        let (result, messages) = read(
            vec![Ok(block(10, &[], &[10])), Ok(block(11, &[10], &[11]))],
            10,
            11,
            None,
        )
        .await;

        result.expect("complete range");
        assert!(matches!(messages.as_slice(), [BlockMessage::Chunk(blocks)] if blocks.len() == 2));
    }

    #[tokio::test]
    async fn read_block_stream_sparse_range_chunks_at_one_thousand_blocks() {
        let mut previous_hash = vec![];
        let mut items = vec![];
        for height in 10u32..=1010 {
            let hash = height.to_le_bytes().to_vec();
            items.push(Ok(block(height, &previous_hash, &hash)));
            previous_hash = hash;
        }

        let (result, messages) = read(items, 10, 1010, None).await;

        result.expect("complete sparse range");
        assert!(matches!(
            messages.as_slice(),
            [BlockMessage::Chunk(first), BlockMessage::Chunk(second)]
                if first.len() == 1000 && second.len() == 1
        ));
    }

    #[tokio::test]
    async fn read_block_stream_is_cancelled_returns_cancelled() {
        static STATS: StreamStats = StreamStats::new();
        let (source, receiver) = tokio::sync::mpsc::channel(1);
        let (messages, _output) = tokio::sync::mpsc::channel(1);
        let (cancel, cancellation) = broadcast::channel(1);
        cancel.send(()).expect("cancel");

        let result = read_block_stream(
            resumable(
                ReceiverStream::new(receiver),
                &ScriptedRanges::new(vec![]),
                10,
                &STATS,
            ),
            10,
            None,
            vec![7],
            HashSet::new(),
            100,
            messages,
            cancellation,
            Duration::from_secs(60),
        )
        .await;
        drop(source);

        assert!(matches!(result, Err(SyncError::Cancelled)));
    }

    #[tokio::test]
    async fn read_block_stream_cancelled_with_pending_block_discards_the_block() {
        static STATS: StreamStats = StreamStats::new();
        let (source, receiver) = tokio::sync::mpsc::channel(1);
        source
            .send(Ok(block(10, &[], &[10])))
            .await
            .expect("source block");
        let (messages, mut output) = tokio::sync::mpsc::channel(1);
        let (cancel, cancellation) = broadcast::channel(1);
        let reader = tokio::spawn(read_block_stream(
            resumable(
                ReceiverStream::new(receiver),
                &ScriptedRanges::new(vec![]),
                11,
                &STATS,
            ),
            10,
            None,
            vec![7],
            HashSet::new(),
            100,
            messages,
            cancellation,
            Duration::from_secs(60),
        ));

        let permit = source
            .reserve()
            .await
            .expect("reader consumed pending block");
        cancel.send(()).expect("cancel");
        let result = reader.await.expect("reader task");
        drop(permit);
        drop(source);

        assert!(matches!(result, Err(SyncError::Cancelled)));
        assert!(output.try_recv().is_err());
    }

    #[tokio::test]
    async fn read_block_stream_block_and_cancel_ready_never_flushes_the_block() {
        static STATS: StreamStats = StreamStats::new();
        for _ in 0..32 {
            let (source, receiver) = tokio::sync::mpsc::channel(1);
            source
                .send(Ok(block(10, &[], &[10])))
                .await
                .expect("source block");
            let (messages, mut output) = tokio::sync::mpsc::channel(1);
            let (cancel, cancellation) = broadcast::channel(1);
            cancel.send(()).expect("cancel");

            let result = read_block_stream(
                resumable(
                    ReceiverStream::new(receiver),
                    &ScriptedRanges::new(vec![]),
                    10,
                    &STATS,
                ),
                10,
                None,
                vec![7],
                HashSet::new(),
                0,
                messages,
                cancellation,
                Duration::from_secs(60),
            )
            .await;

            assert!(matches!(result, Err(SyncError::Cancelled)));
            assert!(output.try_recv().is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_stalls_returns_an_error() {
        static STATS: StreamStats = StreamStats::new();
        let replies = (0..4).map(|_| Reply::Stalls(vec![])).collect();
        let read = read_scripted(replies, 10, 10, None, &STATS).await;

        assert!(read
            .result
            .expect_err("stall")
            .to_string()
            .contains("stalled"));
    }

    #[tokio::test]
    async fn read_block_stream_detects_a_reorg_returns_reorg() {
        let (result, messages) =
            read(vec![Ok(block(10, &[2], &[10]))], 10, 10, Some(vec![1])).await;

        assert!(matches!(result, Err(SyncError::Reorg(9))));
        assert!(
            matches!(messages.as_slice(), [BlockMessage::Reorg(accounts, 9)] if accounts == &[7])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_breaks_then_resumes_processes_every_block_once() {
        static STATS: StreamStats = StreamStats::new();
        let replies = vec![
            Reply::Ends(vec![Ok(chained(10)), Ok(chained(11)), broken()]),
            Reply::Ends(vec![Ok(chained(12)), Ok(chained(13))]),
        ];

        let read = read_scripted(replies, 10, 13, Some(vec![9]), &STATS).await;

        read.result.expect("resumed scan");
        assert_eq!(chunked_heights(&read.messages), vec![10, 11, 12, 13]);
        assert_eq!(read.starts, vec![10, 12]);
        assert_eq!(STATS.snapshot(), stats(1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_three_failed_reopens_fails_with_a_network_error() {
        static STATS: StreamStats = StreamStats::new();
        let replies = vec![
            Reply::Ends(vec![Ok(chained(10)), broken()]),
            Reply::Refused,
            Reply::Refused,
            Reply::Refused,
        ];

        let read = read_scripted(replies, 10, 12, Some(vec![9]), &STATS).await;

        let error = read.result.expect_err("retries run out").to_string();
        assert!(
            error.starts_with("network: compact block stream broke 4 times: connection refused"),
            "{error}"
        );
        assert_eq!(chunked_heights(&read.messages), vec![10]);
        assert_eq!(read.starts, vec![10, 11, 11, 11]);
        assert_eq!(STATS.snapshot(), stats(4, 0));
    }

    // Real time: the file-backed pool does I/O on other threads, which paused time would race.
    #[tokio::test]
    async fn shielded_sync_three_failed_reopens_keeps_the_blocks_read_before_the_break() {
        let coin = file_backed_coin().await;
        let mut connection = coin.get_connection().await.expect("connection");
        let account = restore(&mut connection, TEST_PHRASE, 0, None)
            .await
            .expect("restore");
        let mut client: Client = Box::new(ScriptedRanges::new(vec![
            Reply::Ends(vec![
                Ok(chained(2_000_001)),
                Ok(chained(2_000_002)),
                broken(),
            ]),
            Reply::Refused,
            Reply::Refused,
            Reply::Refused,
        ]));
        let (progress, _progress) = tokio::sync::mpsc::channel(100);
        let (_cancel, cancellation) = broadcast::channel(1);

        let error = shielded_sync(
            &Network::Main,
            &coin.get_pool().expect("pool"),
            &mut client,
            &[(account, false)],
            2_000_001,
            2_000_004,
            u32::MAX,
            progress,
            cancellation,
        )
        .await
        .expect_err("retries run out")
        .to_string();

        assert!(
            error.starts_with("network: compact block stream broke 4 times"),
            "{error}"
        );
        let header: Option<u32> = sqlx::query_scalar("SELECT MAX(height) FROM headers")
            .fetch_one(&mut *connection)
            .await
            .expect("headers");
        let shielded: Vec<u32> =
            sqlx::query_scalar("SELECT height FROM sync_heights WHERE pool IN (1, 2)")
                .fetch_all(&mut *connection)
                .await
                .expect("sync heights");
        assert_eq!(header, Some(2_000_002));
        assert_eq!(shielded, vec![2_000_002, 2_000_002]);
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_progress_after_each_break_resets_the_attempts() {
        static STATS: StreamStats = StreamStats::new();
        let mut replies: Vec<Reply> = (10..14)
            .map(|height| Reply::Ends(vec![Ok(chained(height)), broken()]))
            .collect();
        replies.push(Reply::Ends(vec![Ok(chained(14))]));

        let read = read_scripted(replies, 10, 14, Some(vec![9]), &STATS).await;

        read.result.expect("every break was followed by progress");
        assert_eq!(chunked_heights(&read.messages), vec![10, 11, 12, 13, 14]);
        assert_eq!(STATS.snapshot(), stats(4, 4));
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_stalled_stream_is_reopened_where_it_stalled() {
        static STATS: StreamStats = StreamStats::new();
        let replies = vec![
            Reply::Stalls(vec![Ok(chained(10))]),
            Reply::Ends(vec![Ok(chained(11))]),
        ];

        let read = read_scripted(replies, 10, 11, Some(vec![9]), &STATS).await;

        read.result.expect("resumed after the stall");
        assert_eq!(chunked_heights(&read.messages), vec![10, 11]);
        assert_eq!(read.starts, vec![10, 11]);
        assert_eq!(STATS.snapshot(), stats(1, 1));
    }

    /// The stall is seen by the tick at 60 s and the reopen lands at 60.5 s; the old tick schedule
    /// would fire at 120 s, before the reopened stream's block at 120.25 s.
    #[tokio::test(start_paused = true)]
    async fn read_block_stream_reopened_stream_gets_a_full_stall_window() {
        static STATS: StreamStats = StreamStats::new();
        let replies = vec![
            Reply::Stalls(vec![Ok(chained(10))]),
            Reply::Late(Duration::from_millis(59_750), chained(11)),
        ];

        let read = read_scripted(replies, 10, 11, Some(vec![9]), &STATS).await;

        read.result.expect("a slow reopened stream is not a stall");
        assert_eq!(read.starts, vec![10, 11]);
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_ends_early_is_reopened_where_it_ended() {
        static STATS: StreamStats = StreamStats::new();
        let replies = vec![
            Reply::Ends(vec![Ok(chained(10))]),
            Reply::Ends(vec![Ok(chained(11))]),
        ];

        let read = read_scripted(replies, 10, 11, Some(vec![9]), &STATS).await;

        read.result.expect("resumed after the early end");
        assert_eq!(chunked_heights(&read.messages), vec![10, 11]);
        assert_eq!(read.starts, vec![10, 11]);
        assert_eq!(STATS.snapshot(), stats(1, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_breaks_after_the_last_block_fails_without_reopening() {
        static STATS: StreamStats = StreamStats::new();
        let replies = vec![Reply::Ends(vec![Ok(chained(10)), broken()])];

        let read = read_scripted(replies, 10, 10, Some(vec![9]), &STATS).await;

        let error = read.result.expect_err("source failure").to_string();
        assert!(error.contains("unexpected EOF"), "{error}");
        assert_eq!(chunked_heights(&read.messages), vec![10]);
        assert_eq!(read.starts, vec![10]);
    }

    #[tokio::test(start_paused = true)]
    async fn read_block_stream_cancelled_during_the_backoff_returns_cancelled_without_reopening() {
        static STATS: StreamStats = StreamStats::new();
        let server = ScriptedRanges::new(vec![Reply::Ends(vec![broken()])]);
        let blocks = server
            .clone()
            .block_range(&Network::Main, 10, 10)
            .await
            .expect("first stream");
        let (messages, _output) = tokio::sync::mpsc::channel(1);
        let (cancel, cancellation) = broadcast::channel(1);
        let reader = tokio::spawn(read_block_stream(
            resumable(blocks, &server, 10, &STATS),
            10,
            None,
            vec![7],
            HashSet::new(),
            100,
            messages,
            cancellation,
            Duration::from_secs(60),
        ));

        // Busy-yielding keeps the paused clock from auto-advancing past the backoff.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while STATS.snapshot().stream_breaks == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the stream never broke"
            );
            tokio::task::yield_now().await;
        }
        let _ = cancel.send(());
        let result = reader.await.expect("reader task");

        assert!(matches!(result, Err(SyncError::Cancelled)));
        assert_eq!(server.starts(), vec![10]);
    }
}
