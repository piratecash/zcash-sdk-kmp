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
    warp::hasher::{OrchardHasher, SaplingHasher},
};
use zcash_trees::types::{BlockHeader, Issuance, WarpSyncMessage};

use super::legacy::CommitmentTreeFrontier;

pub use zcash_trees::types::SyncError;

mod shielded;

const MAX_BLOCKS_PER_CHUNK: usize = 1000;

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
    let block_reader = read_block_stream(
        blocks,
        start_height,
        end_height,
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

#[allow(clippy::too_many_arguments)]
async fn read_block_stream(
    mut blocks: ReceiverStream<Result<CompactBlock>>,
    start_height: u32,
    end_height: u32,
    mut prev_hash: Option<Vec<u8>>,
    account_ids: Vec<u32>,
    mut heights_without_time: HashSet<u32>,
    actions_per_sync: u32,
    tx_blocks: Sender<BlockMessage>,
    mut rx_cancel: broadcast::Receiver<()>,
    stall_timeout: Duration,
) -> Result<(), SyncError> {
    let mut chunk = vec![];
    let mut interval = tokio::time::interval(stall_timeout);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut current_height = start_height;
    let mut previous_height = 0;
    let mut expected_height = start_height as u64;
    let mut actions = 0;

    loop {
        tokio::select! {
            biased;
            _ = rx_cancel.recv() => {
                debug!("Sync cancelled");
                return Err(SyncError::Cancelled);
            }
            _ = interval.tick() => {
                debug!("Syncing at height {}", current_height);
                if previous_height == current_height {
                    debug!("Connection stalled. Aborting...");
                    flush_chunk(&tx_blocks, &mut chunk).await?;
                    return Err(SyncError::Other(anyhow::anyhow!(
                        "compact block stream stalled at height {current_height}"
                    )));
                }
                previous_height = current_height;
            }
            message = blocks.next() => {
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
                }
                Some(Err(error)) => {
                    flush_chunk(&tx_blocks, &mut chunk).await?;
                    return Err(SyncError::Other(error));
                }
                None => {
                    debug!("no more blocks to process");
                    flush_chunk(&tx_blocks, &mut chunk).await?;
                    if expected_height <= end_height as u64 {
                        return Err(SyncError::Other(anyhow::anyhow!(
                            "compact block stream ended before height {expected_height}"
                        )));
                    }
                    break;
                }
                }
            }
        }
    }

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

    fn block(height: u32, previous_hash: &[u8], hash: &[u8]) -> CompactBlock {
        CompactBlock {
            height: height as u64,
            prev_hash: previous_hash.to_vec(),
            hash: hash.to_vec(),
            ..Default::default()
        }
    }

    async fn read(
        items: Vec<Result<CompactBlock>>,
        start: u32,
        end: u32,
        previous_hash: Option<Vec<u8>>,
    ) -> (Result<(), SyncError>, Vec<BlockMessage>) {
        let (source, receiver) = tokio::sync::mpsc::channel(items.len().max(1));
        for item in items {
            source.send(item).await.expect("source item");
        }
        drop(source);
        let (messages, mut output) = tokio::sync::mpsc::channel(10);
        let (_cancel, cancellation) = broadcast::channel(1);

        let result = read_block_stream(
            ReceiverStream::new(receiver),
            start,
            end,
            previous_hash,
            vec![7],
            HashSet::new(),
            usize::MAX as u32,
            messages,
            cancellation,
            Duration::from_secs(60),
        )
        .await;
        let mut collected = vec![];
        while let Some(message) = output.recv().await {
            collected.push(message);
        }
        (result, collected)
    }

    #[tokio::test]
    async fn read_block_stream_source_fails_returns_the_source_error() {
        let (result, _) = read(vec![Err(anyhow::anyhow!("stream failed"))], 10, 10, None).await;

        let error = result.expect_err("source failure").to_string();
        assert!(error.contains("stream failed"), "{error}");
    }

    #[tokio::test]
    async fn read_block_stream_ends_early_rejects_the_incomplete_range() {
        let (result, _) = read(vec![Ok(block(10, &[], &[10]))], 10, 11, None).await;

        let error = result.expect_err("incomplete range").to_string();
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
        let (source, receiver) = tokio::sync::mpsc::channel(1);
        let (messages, _output) = tokio::sync::mpsc::channel(1);
        let (cancel, cancellation) = broadcast::channel(1);
        cancel.send(()).expect("cancel");

        let result = read_block_stream(
            ReceiverStream::new(receiver),
            10,
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
        let (source, receiver) = tokio::sync::mpsc::channel(1);
        source
            .send(Ok(block(10, &[], &[10])))
            .await
            .expect("source block");
        let (messages, mut output) = tokio::sync::mpsc::channel(1);
        let (cancel, cancellation) = broadcast::channel(1);
        let reader = tokio::spawn(read_block_stream(
            ReceiverStream::new(receiver),
            10,
            11,
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
                ReceiverStream::new(receiver),
                10,
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

    #[tokio::test]
    async fn read_block_stream_stalls_returns_an_error() {
        let (_source, receiver) = tokio::sync::mpsc::channel(1);
        let (messages, _output) = tokio::sync::mpsc::channel(1);
        let (_cancel, cancellation) = broadcast::channel(1);

        let result = read_block_stream(
            ReceiverStream::new(receiver),
            10,
            10,
            None,
            vec![7],
            HashSet::new(),
            100,
            messages,
            cancellation,
            Duration::from_millis(1),
        )
        .await;

        assert!(result.expect_err("stall").to_string().contains("stalled"));
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
}
