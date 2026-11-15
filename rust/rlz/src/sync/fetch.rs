//! Block download for the shielded scan: one ordered stream of compact
//! blocks, fetched over several connections when the range is long.
//!
//! The scan reads blocks strictly in height order, so only the blocks it
//! needs next are worth fetching in parallel. A long range is fetched as
//! consecutive slices from one shared cursor. Each stream claims the next
//! slice when it becomes free, sized to take about [`FetchConfig::piece`] at
//! that stream's own recent rate, and only while the bytes in flight and
//! buffered stay within a budget. Blocks are reordered and delivered in
//! height order, so the consumer sees the stream a single request would give.
//!
//! The number of streams is not tuned on throughput, which is too noisy to
//! compare over short periods. What the scanner and the buffer show decides:
//!
//! | Scanner | Buffered ahead           | Means            | Action                   |
//! |---------|--------------------------|------------------|--------------------------|
//! | waiting | large, a gap at the head | head-of-line     | move the head slice      |
//! | waiting | small, streams busy      | fetch-bound      | add a stream             |
//! | waiting | small, streams parked    | budget too tight | raise the budget         |
//! | busy    | any                      | healthy          | hold                     |
//! | any     | a stream failed          | server trouble   | fewer streams, stop adding |

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt as _;
use tracing::{debug, info};

use crate::api::coin::Network;
use crate::lwd::CompactBlock;
use crate::net::{BreakCounted, StreamStats};
use crate::warp::sync::ScanWait;
use crate::Client;

/// Opens one more connection to the block server.
pub type ClientFactory =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Client>> + Send>> + Send + Sync>;

type BlockStream = ReceiverStream<Result<CompactBlock>>;

/// Ranges shorter than this are one request on the caller's connection.
pub const PARALLEL_MIN_BLOCKS: u32 = 10_000;
/// A stream's first slice, before its rate is known, and the smallest slice.
/// Small enough to be safe where blocks are tens of kilobytes each.
const PROBE_BLOCKS: u32 = 64;
/// Scanner-wait fraction of a window above which the scanner counts as waiting.
const STARVED_FRACTION: f64 = 0.25;
/// A slice is aborted once it received this many times its planned bytes…
const OVERRUN_FACTOR: u64 = 2;
/// …or, while nothing is known to plan with, this many bytes…
const UNPLANNED_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// …or once it took this many times its planned time.
const BEHIND_FACTOR: f64 = 1.5;
/// A stream is slow when a slice ran below this share of the others' median.
const SLOW_RATIO: f64 = 0.5;
/// Consecutive slow slices before a stream is replaced.
const SLOW_SLICES: u32 = 3;
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct FetchConfig {
    /// How long one slice should take to download.
    pub piece: Duration,
    /// Ranges shorter than this start as one request on the caller's
    /// connection, with no stream opened unless that request is aborted.
    pub parallel_min_blocks: u32,
    /// Streams started at once.
    pub initial_streams: usize,
    /// Most streams, however long the scanner waits.
    pub max_streams: usize,
    /// Starting budget for bytes in flight plus buffered.
    pub budget: u64,
    /// The budget's ceiling, and the most bytes buffered before reading stops.
    pub mem_cap: u64,
    /// Length of one observation window.
    pub window: Duration,
    /// Longest a stream may go without a block while it has a slice.
    pub piece_stall: Duration,
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            piece: Duration::from_secs(3),
            parallel_min_blocks: PARALLEL_MIN_BLOCKS,
            initial_streams: 6,
            max_streams: 16,
            budget: 32 * MIB,
            mem_cap: 128 * MIB,
            window: Duration::from_secs(5),
            piece_stall: Duration::from_secs(30),
        }
    }
}

/// The caller's limits on one block download: streams open at once, the caller's
/// own included, and the bytes held ahead of the scan it aims for (not a hard cap).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BlockDownload {
    pub max_streams: u32,
    pub buffer_bytes: u64,
}

impl Default for BlockDownload {
    fn default() -> Self {
        let config = FetchConfig::default();
        Self {
            max_streams: config.max_streams as u32,
            buffer_bytes: config.mem_cap,
        }
    }
}

/// Out-of-range limits are clamped to one stream and 1 MiB, never rejected.
pub fn fetch_config(download: &BlockDownload) -> FetchConfig {
    let defaults = FetchConfig::default();
    let max_streams = download.max_streams.max(1) as usize;
    let mem_cap = download.buffer_bytes.max(MIB);
    FetchConfig {
        initial_streams: defaults.initial_streams.min(max_streams),
        max_streams,
        budget: defaults.budget.min(mem_cap),
        mem_cap,
        ..defaults
    }
}

/// More connections, and the limits a long range is downloaded over them with.
#[derive(Clone)]
pub struct FetchPlan {
    pub factory: ClientFactory,
    pub config: FetchConfig,
}

/// What a download did, for logs and tests.
#[derive(Default, Debug)]
pub struct FetchStats {
    /// Streams opened.
    pub connections: AtomicU64,
    /// Most streams alive at once, the caller's first one included.
    pub peak_connections: AtomicU64,
    /// Slices handed out.
    pub pieces: AtomicU64,
    /// Slices cut short for overrunning their byte estimate.
    pub cuts: AtomicU64,
    /// Slices given back by a failed stream.
    pub requeued: AtomicU64,
    /// Slices aborted for taking too long.
    pub timeouts: AtomicU64,
    /// Head slices moved off a stream that fell behind.
    pub steals: AtomicU64,
    /// Streams replaced for staying slow.
    pub replaced: AtomicU64,
    /// Times the budget was raised.
    pub budget_raises: AtomicU64,
    /// Most bytes held undelivered at once.
    pub max_buffered: AtomicU64,
}

/// The blocks of `start..=end` in height order. Without `fetch` this is one
/// request on `client`. With it, a long range is fetched over several
/// connections (see the module doc); a short one starts as one request on
/// `client` and moves to several only if that request is aborted. Every stream
/// failure is counted in `breaks`.
pub(crate) async fn block_stream(
    network: &Network,
    client: &mut Client,
    start: u32,
    end: u32,
    fetch: Option<&FetchPlan>,
    breaks: &'static StreamStats,
    scan_wait: Option<Arc<ScanWait>>,
) -> Result<BlockStream> {
    match fetch {
        Some(plan) if end >= start => {
            block_stream_with(
                network,
                client,
                start,
                end,
                plan.factory.clone(),
                plan.config.clone(),
                Arc::new(FetchStats::default()),
                breaks,
                scan_wait,
            )
            .await
        }
        _ => client.block_range(network, start, end).await,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn block_stream_with(
    network: &Network,
    client: &mut Client,
    start: u32,
    end: u32,
    factory: ClientFactory,
    cfg: FetchConfig,
    stats: Arc<FetchStats>,
    breaks: &'static StreamStats,
    scan_wait: Option<Arc<ScanWait>>,
) -> Result<BlockStream> {
    // The caller's connection fetches the first slice; the streams opened
    // here take everything after it. A short range is that one slice: like
    // any slice it is aborted if it takes too long, and streams take over.
    let short = end - start < cfg.parallel_min_blocks.saturating_sub(1);
    let first_end = if short {
        end
    } else {
        start.saturating_add(PROBE_BLOCKS - 1).min(end)
    };
    let first = client.block_range(network, start, first_end).await?;
    stats.peak_connections.fetch_max(1, Ordering::Relaxed);
    let (out, rx) = mpsc::channel(10);
    let (events_tx, events_rx) = mpsc::channel(64);
    let now = Instant::now();
    let fetch = Fetch {
        network: *network,
        end,
        budget: cfg.budget.min(cfg.mem_cap),
        target: if short { 0 } else { cfg.initial_streams.max(1) },
        ceiling: cfg.max_streams.max(1),
        cfg,
        stats,
        breaks,
        factory,
        out,
        first: Some(first),
        first_next: start,
        first_end,
        started: now,
        frontier: first_end.saturating_add(1),
        returned: BTreeMap::new(),
        buffer: BTreeMap::new(),
        buffered: 0,
        next: start,
        contig: start,
        avg_block: 0.0,
        workers: BTreeMap::new(),
        next_id: 0,
        events_tx,
        events_rx,
        last_error: None,
        starved_since: None,
        workers_unread: Hold::default(),
        first_unread: Hold::default(),
        starved_acc: Duration::ZERO,
        received_window: 0,
        buffered_sum: 0,
        buffered_samples: 0,
        parked_window: false,
        last_steal: now,
        avoid_head: None,
        replacements: 0,
        // A reopen reuses the scan's gauge: only waits from now on are this download's.
        scan_wait_seen: scan_wait
            .as_ref()
            .map(|wait| wait.total())
            .unwrap_or_default(),
        scan_wait,
    };
    tokio::spawn(fetch.run());
    Ok(ReceiverStream::new(rx))
}

enum Event {
    /// The connection is open.
    Ready(usize),
    Block {
        id: usize,
        block: CompactBlock,
        bytes: u64,
    },
    /// The slice is complete (or was stopped at its cut).
    Done(usize),
    /// The stream is gone; its slice is unfinished.
    Failed { id: usize, error: anyhow::Error },
}

struct Piece {
    start: u32,
    /// Next height expected.
    next: u32,
    /// Last height of the slice.
    end: u32,
    /// Blocks it had when handed out.
    blocks: u32,
    planned: u64,
    received: u64,
    /// When its time limit started: its first block, and until then its assignment.
    started: Instant,
    first_block: Option<Instant>,
}

/// A stream's task, ended with the stream's entry: a removed or abandoned
/// stream must not hold its connection open on the server.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Worker {
    assign: mpsc::Sender<(u32, u32)>,
    /// The worker stops its stream after a block at or above this height.
    stop: Arc<AtomicU32>,
    ready: bool,
    piece: Option<Piece>,
    /// Bytes per second over its recent slices.
    rate: Option<f64>,
    /// Slices finished.
    slices: u32,
    /// Consecutive slices well below the other streams' rate.
    slow_slices: u32,
    _task: AbortOnDrop,
}

struct Fetch {
    network: Network,
    end: u32,
    cfg: FetchConfig,
    stats: Arc<FetchStats>,
    breaks: &'static StreamStats,
    factory: ClientFactory,
    out: mpsc::Sender<Result<CompactBlock>>,

    /// The first slice, on the caller's connection.
    first: Option<BlockStream>,
    first_next: u32,
    first_end: u32,
    started: Instant,

    /// First height never assigned.
    frontier: u32,
    /// Unfinished ranges given back, `start -> end`, all below `frontier`.
    returned: BTreeMap<u32, u32>,

    /// Blocks received and not yet delivered.
    buffer: BTreeMap<u32, (CompactBlock, u64)>,
    buffered: u64,
    /// Next height to deliver.
    next: u32,
    /// First height at or above `next` that is not in `buffer`.
    contig: u32,
    /// Recent bytes per block.
    avg_block: f64,

    workers: BTreeMap<usize, Worker>,
    next_id: usize,
    /// Streams wanted.
    target: usize,
    /// Most streams `target` may grow to; lowered when a stream fails.
    ceiling: usize,
    /// Bytes in flight plus buffered that new slices must fit in.
    budget: u64,
    events_tx: mpsc::Sender<Event>,
    events_rx: mpsc::Receiver<Event>,
    last_error: Option<anyhow::Error>,

    starved_since: Option<Instant>,
    starved_acc: Duration,
    /// Slices age only while their blocks are being read.
    workers_unread: Hold,
    first_unread: Hold,
    received_window: u64,
    buffered_sum: u128,
    buffered_samples: u64,
    /// Whether a free stream was refused a slice by the budget this window.
    parked_window: bool,
    last_steal: Instant,
    /// The stream the head was just taken from: not given it straight back.
    avoid_head: Option<(usize, Instant)>,
    replacements: u32,
    /// The scan's own measure of its waiting, when it reports one.
    scan_wait: Option<Arc<ScanWait>>,
    scan_wait_seen: Duration,
}

/// How long a condition held, handed back once when it stops holding.
#[derive(Default)]
struct Hold(Option<Instant>);

impl Hold {
    fn update(&mut self, holds: bool) -> Option<Duration> {
        match (self.0, holds) {
            (None, true) => {
                self.0 = Some(Instant::now());
                None
            }
            (Some(since), false) => {
                self.0 = None;
                Some(since.elapsed())
            }
            _ => None,
        }
    }

    fn holds(&self) -> bool {
        self.0.is_some()
    }
}

/// A slice assigned during the hold only gets the part it lived through.
fn unexpected_block(height: u32, expected: u32) -> anyhow::Error {
    anyhow!("block {height} received, {expected} expected")
}

fn credit_unread(started: &mut Instant, unread_for: Duration) {
    *started += unread_for.min(started.elapsed());
}

async fn next_block(first: &mut Option<BlockStream>) -> Option<Result<CompactBlock>> {
    match first {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

impl Fetch {
    async fn run(mut self) {
        let mut window = tokio::time::interval(self.cfg.window);
        window.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        window.tick().await;
        // Wakes the loop so a stalled head is noticed without waiting for a block.
        let mut poll = tokio::time::interval(self.cfg.piece / 4);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut window_started = Instant::now();
        // A handle of its own, so a send permit does not borrow `self`.
        let out = self.out.clone();
        loop {
            if self.next > self.end {
                break;
            }
            self.expire();
            self.top_up();
            self.steal_head();
            self.assign();
            let deliverable = self.contig > self.next;
            if !deliverable && self.first.is_none() && self.workers.is_empty() {
                // Nothing left that could fetch the next block. What arrived
                // in order was delivered; the consumer sees where it stopped.
                if let Some(error) = self.last_error.take() {
                    let _ = out.send(Err(error.context(BreakCounted))).await;
                }
                break;
            }
            // Waiting: nothing to hand over while the consumer has (nearly)
            // emptied what it was given. A block just sent may still sit in
            // the channel, so "empty" would never be seen from here.
            let starved = !deliverable && out.capacity() * 2 >= out.max_capacity();
            self.note_starved(starved);
            self.buffered_sum += u128::from(self.buffered);
            self.buffered_samples += 1;
            // Past the cap only the blocks that fill the gap are still read.
            let poll_events =
                !self.workers.is_empty() && (self.buffered < self.cfg.mem_cap || !deliverable);
            let poll_first = self.first.is_some() && !deliverable;
            self.note_unread(
                !self.workers.is_empty() && !poll_events,
                self.first.is_some() && !poll_first,
            );
            tokio::select! {
                biased;
                permit = out.reserve(), if deliverable => {
                    let Ok(permit) = permit else { break };
                    if let Some((block, bytes)) = self.buffer.remove(&self.next) {
                        self.buffered -= bytes;
                        self.next += 1;
                        permit.send(Ok(block));
                    }
                }
                _ = out.closed(), if !deliverable => break,
                event = self.events_rx.recv(), if poll_events => {
                    if let Some(event) = event {
                        self.on_event(event);
                    }
                }
                item = next_block(&mut self.first), if poll_first => self.on_first(item),
                _ = window.tick() => {
                    self.on_window(window_started.elapsed());
                    window_started = Instant::now();
                }
                _ = poll.tick() => {}
            }
        }
        debug!(
            connections = self.stats.connections.load(Ordering::Relaxed),
            peak_connections = self.stats.peak_connections.load(Ordering::Relaxed),
            pieces = self.stats.pieces.load(Ordering::Relaxed),
            cuts = self.stats.cuts.load(Ordering::Relaxed),
            requeued = self.stats.requeued.load(Ordering::Relaxed),
            timeouts = self.stats.timeouts.load(Ordering::Relaxed),
            steals = self.stats.steals.load(Ordering::Relaxed),
            replaced = self.stats.replaced.load(Ordering::Relaxed),
            budget_raises = self.stats.budget_raises.load(Ordering::Relaxed),
            max_buffered_bytes = self.stats.max_buffered.load(Ordering::Relaxed),
            "block download done"
        );
    }

    fn note_starved(&mut self, starved: bool) {
        match (self.starved_since, starved) {
            (None, true) => self.starved_since = Some(Instant::now()),
            (Some(since), false) => {
                self.starved_acc += since.elapsed();
                self.starved_since = None;
            }
            _ => {}
        }
    }

    /// A slice cannot progress while its blocks go unread, so that time is not held against it.
    fn note_unread(&mut self, workers: bool, first: bool) {
        if let Some(unread_for) = self.workers_unread.update(workers) {
            for piece in self.workers.values_mut().filter_map(|w| w.piece.as_mut()) {
                credit_unread(&mut piece.started, unread_for);
            }
        }
        if let Some(unread_for) = self.first_unread.update(first) {
            credit_unread(&mut self.started, unread_for);
        }
    }

    fn insert(&mut self, height: u32, block: CompactBlock, bytes: u64) {
        if height < self.next || self.buffer.contains_key(&height) {
            return;
        }
        self.buffer.insert(height, (block, bytes));
        self.buffered += bytes;
        self.received_window += bytes;
        self.stats
            .max_buffered
            .fetch_max(self.buffered, Ordering::Relaxed);
        self.avg_block = if self.avg_block == 0.0 {
            bytes as f64
        } else {
            self.avg_block + (bytes as f64 - self.avg_block) / 64.0
        };
        if height == self.contig {
            self.contig += 1;
            while self.buffer.contains_key(&self.contig) {
                self.contig += 1;
            }
        }
    }

    fn on_first(&mut self, item: Option<Result<CompactBlock>>) {
        match item {
            Some(Ok(block)) => {
                let height = block.height as u32;
                if height != self.first_next {
                    self.fail_first(unexpected_block(height, self.first_next));
                    return;
                }
                let bytes = block.encoded_len() as u64;
                self.first_next = height.saturating_add(1);
                self.insert(height, block, bytes);
                if height >= self.first_end {
                    self.first = None;
                }
            }
            Some(Err(error)) => self.fail_first(error),
            None => self.fail_first(anyhow!(
                "the block stream ended at height {}, {} asked",
                self.first_next.saturating_sub(1),
                self.first_end
            )),
        }
    }

    fn fail_first(&mut self, error: anyhow::Error) {
        self.breaks.record_break();
        self.last_error = Some(error);
        self.drop_first();
    }

    /// Give up on the first slice: what it did not deliver is unassigned.
    fn drop_first(&mut self) {
        self.first = None;
        if self.first_next <= self.first_end {
            self.returned.insert(self.first_next, self.first_end);
            if self.target == 0 {
                self.target = self.cfg.initial_streams.max(1);
            }
        }
    }

    fn on_event(&mut self, event: Event) {
        match event {
            Event::Ready(id) => {
                if let Some(worker) = self.workers.get_mut(&id) {
                    worker.ready = true;
                }
            }
            Event::Block { id, block, bytes } => {
                let height = block.height as u32;
                let Some(piece) = self.workers.get_mut(&id).and_then(|w| w.piece.as_mut()) else {
                    return;
                };
                if height > piece.end {
                    return; // sent before the worker saw its slice was cut
                }
                if height != piece.next {
                    let error = unexpected_block(height, piece.next);
                    self.fail_worker(id, error);
                    return;
                }
                piece.next = height + 1;
                piece.received += bytes;
                if piece.first_block.is_none() {
                    // A slow reply is the server's latency, not a slow stream.
                    let now = Instant::now();
                    piece.first_block = Some(now);
                    piece.started = now;
                }
                let limit = if piece.planned > 0 {
                    OVERRUN_FACTOR * piece.planned
                } else {
                    UNPLANNED_MAX_BYTES
                };
                let overrun = piece.received > limit && piece.next <= piece.end;
                self.insert(height, block, bytes);
                if overrun {
                    self.abort(id);
                    self.stats.cuts.fetch_add(1, Ordering::Relaxed);
                }
            }
            Event::Done(id) => {
                let Some(worker) = self.workers.get_mut(&id) else {
                    return;
                };
                let Some(piece) = worker.piece.take() else {
                    return;
                };
                let rate = piece.first_block.and_then(|first| {
                    let secs = first.elapsed().as_secs_f64();
                    (secs > 0.001 && piece.received > 0).then(|| piece.received as f64 / secs)
                });
                if let Some(rate) = rate {
                    worker.rate = Some(worker.rate.map_or(rate, |old| (old + rate) / 2.0));
                }
                worker.slices += 1;
                let judged = worker.slices >= 2;
                if piece.next <= piece.end {
                    self.returned.insert(piece.next, piece.end);
                }
                if let (Some(rate), true) = (rate, judged) {
                    self.judge_slow(id, rate);
                }
            }
            Event::Failed { id, error } => self.fail_worker(id, error),
        }
    }

    /// Abort a slice that turned out bigger or slower than planned: what it
    /// delivered is kept, the rest goes back to the queue, and the stream's
    /// rate is set to what it managed, so its next slice is sized on that.
    fn abort(&mut self, id: usize) {
        if let Some(worker) = self.workers.get_mut(&id) {
            if let Some(piece) = worker.piece.as_ref() {
                let secs = piece.started.elapsed().as_secs_f64();
                if secs > 0.001 {
                    worker.rate = Some(piece.received as f64 / secs);
                }
            }
        }
        self.cut(id);
    }

    /// Abort every slice past its time limit, wherever it is in the range.
    fn expire(&mut self) {
        let limit = self.cfg.piece.mul_f64(BEHIND_FACTOR);
        if self.first.is_some() && !self.first_unread.holds() && self.started.elapsed() > limit {
            debug!(
                "block download: first slice timed out at {}",
                self.first_next
            );
            self.drop_first();
            self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        if self.workers_unread.holds() {
            return;
        }
        let late: Vec<usize> = self
            .workers
            .iter()
            .filter(|(_, w)| {
                w.piece.as_ref().is_some_and(|p| {
                    // A slice still waiting for its first block is left to `piece_stall`.
                    p.first_block.is_some() && p.next <= p.end && p.started.elapsed() > limit
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for id in late {
            debug!(stream = id, "block download: slice timed out");
            self.abort(id);
            self.stats.timeouts.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Stop a stream's slice at the last block it delivered; the rest goes
    /// back to the queue.
    fn cut(&mut self, id: usize) {
        let Some(worker) = self.workers.get_mut(&id) else {
            return;
        };
        let Some(piece) = worker.piece.as_mut() else {
            return;
        };
        if piece.next > piece.end {
            return;
        }
        self.returned.insert(piece.next, piece.end);
        piece.end = piece.next - 1;
        worker.stop.store(piece.end, Ordering::SeqCst);
    }

    /// Replace a stream that stays well below the others: a new connection
    /// may land on a better path.
    fn judge_slow(&mut self, id: usize, rate: f64) {
        let mut others: Vec<f64> = self
            .workers
            .iter()
            .filter(|(other, _)| **other != id)
            .filter_map(|(_, w)| w.rate)
            .collect();
        if others.len() < 2 {
            return;
        }
        others.sort_by(|a, b| a.total_cmp(b));
        let median = others[others.len() / 2];
        let Some(worker) = self.workers.get_mut(&id) else {
            return;
        };
        if rate < SLOW_RATIO * median {
            worker.slow_slices += 1;
        } else {
            worker.slow_slices = 0;
        }
        if worker.slow_slices >= SLOW_SLICES && (self.replacements as usize) < self.cfg.max_streams
        {
            info!(
                "block download: stream {id} stayed slow ({rate:.0} B/s, others {median:.0}): \
                 replacing it"
            );
            self.workers.remove(&id);
            self.replacements += 1;
            self.stats.replaced.fetch_add(1, Ordering::Relaxed);
            self.spawn_worker();
        }
    }

    /// Drop a stream; the rest of its slice goes back to the queue. A failed
    /// stream is the server's signal to ask for less.
    fn fail_worker(&mut self, id: usize, error: anyhow::Error) {
        let Some(worker) = self.workers.remove(&id) else {
            return;
        };
        self.breaks.record_break();
        if let Some(piece) = worker.piece {
            if piece.next <= piece.end {
                self.returned.insert(piece.next, piece.end);
                self.stats.requeued.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.target = self.target.saturating_sub(1);
        self.ceiling = self.ceiling.min(self.target.max(1));
        info!(
            "block download: stream {id} dropped ({} wanted now): {error:#}",
            self.target
        );
        self.last_error = Some(error);
    }

    /// Bytes per second all streams fetch together.
    fn total_rate(&self) -> f64 {
        self.workers.values().filter_map(|w| w.rate).sum()
    }

    /// The rate to plan with for a stream whose own is not known.
    fn mean_rate(&self) -> f64 {
        let known = self.workers.values().filter(|w| w.rate.is_some()).count();
        if known == 0 {
            1024.0 * 1024.0
        } else {
            self.total_rate() / known as f64
        }
    }

    /// Blocks in a stream's next slice: what it fetches in `piece` at its
    /// rate, or a probe while nothing is known of it.
    fn piece_blocks(&self, slices: u32, rate: Option<f64>) -> u32 {
        if slices == 0 || self.avg_block == 0.0 {
            return PROBE_BLOCKS;
        }
        let rate = rate.unwrap_or_else(|| self.mean_rate());
        let bytes = (rate * self.cfg.piece.as_secs_f64()).min(self.cfg.mem_cap as f64 / 4.0);
        let blocks = (bytes / self.avg_block.max(1.0)).ceil();
        (blocks.min(u32::MAX as f64) as u32).max(PROBE_BLOCKS)
    }

    fn has_unassigned(&self) -> bool {
        !self.returned.is_empty() || self.frontier <= self.end
    }

    /// Streams open now: the workers, and the caller's first one while it lasts.
    fn streams(&self) -> usize {
        self.workers.len() + usize::from(self.first.is_some())
    }

    fn spawn_worker(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        let (assign, assignments) = mpsc::channel(1);
        let stop = Arc::new(AtomicU32::new(u32::MAX));
        let task = tokio::spawn(worker(
            id,
            self.network,
            self.factory.clone(),
            assignments,
            stop.clone(),
            self.events_tx.clone(),
            self.cfg.piece_stall,
        ));
        self.workers.insert(
            id,
            Worker {
                assign,
                stop,
                ready: false,
                piece: None,
                rate: None,
                slices: 0,
                slow_slices: 0,
                _task: AbortOnDrop(task),
            },
        );
        self.stats.connections.fetch_add(1, Ordering::Relaxed);
        self.stats
            .peak_connections
            .fetch_max(self.streams() as u64, Ordering::Relaxed);
        id
    }

    /// Open streams up to the number wanted, the caller's first one counted.
    fn top_up(&mut self) {
        while self.streams() < self.target && self.has_unassigned() {
            self.spawn_worker();
        }
    }

    fn inflight_remaining(&self) -> u64 {
        self.workers
            .values()
            .filter_map(|w| w.piece.as_ref())
            .map(|p| p.planned.saturating_sub(p.received))
            .sum()
    }

    /// Hand the next slices to free streams, fastest first, while they fit
    /// the budget.
    fn assign(&mut self) {
        let mut free: Vec<(usize, u32, Option<f64>)> = self
            .workers
            .iter()
            .filter(|(_, w)| w.ready && w.piece.is_none())
            .map(|(id, w)| (*id, w.slices, w.rate))
            .collect();
        free.sort_by(|a, b| b.2.unwrap_or(0.0).total_cmp(&a.2.unwrap_or(0.0)));
        for (id, slices, rate) in free {
            let (start, limit) = match self.returned.first_key_value() {
                Some((&start, &end)) => (start, end),
                None if self.frontier <= self.end => (self.frontier, self.end),
                None => break,
            };
            // The slice holding the next block to deliver is always fetched,
            // whatever the budget says: a full buffer must not wait on a gap.
            let head = start == self.contig;
            if head && self.workers.len() > 1 {
                if let Some((avoided, since)) = self.avoid_head {
                    if avoided == id && since.elapsed() < self.cfg.piece {
                        continue;
                    }
                }
            }
            let blocks = self.piece_blocks(slices, rate);
            let end = start.saturating_add(blocks - 1).min(limit);
            let planned = (f64::from(end - start + 1) * self.avg_block) as u64;
            if !head && self.buffered + self.inflight_remaining() + planned > self.budget {
                self.parked_window = true;
                break;
            }
            if self.returned.remove(&start).is_some() {
                if end < limit {
                    self.returned.insert(end + 1, limit);
                }
            } else {
                self.frontier = end + 1;
            }
            let Some(worker) = self.workers.get_mut(&id) else {
                continue;
            };
            worker.stop.store(u32::MAX, Ordering::SeqCst);
            worker.piece = Some(Piece {
                start,
                next: start,
                end,
                blocks: end - start + 1,
                planned,
                received: 0,
                started: Instant::now(),
                first_block: None,
            });
            self.stats.pieces.fetch_add(1, Ordering::Relaxed);
            if worker.assign.try_send((start, end)).is_err() {
                self.fail_worker(id, anyhow!("stream task ended"));
            }
        }
    }

    /// Whether a slice is on course to take much longer than planned.
    fn behind(&self, piece: &Piece) -> bool {
        let planned = self.cfg.piece.as_secs_f64();
        let elapsed = piece.started.elapsed().as_secs_f64();
        if elapsed < planned / 4.0 {
            return false;
        }
        let done = piece.next - piece.start;
        if done == 0 {
            return false;
        }
        elapsed * f64::from(piece.blocks) / f64::from(done) > BEHIND_FACTOR * planned
    }

    /// Head-of-line: the consumer waits on a slice whose stream fell behind.
    /// Take the rest of that slice from it; a free stream fetches it, or the
    /// stream working furthest ahead is stopped to do so. A stream that is
    /// slow on a slice nobody waits for is left alone.
    fn steal_head(&mut self) {
        if self.starved_since.is_none() || self.last_steal.elapsed() < self.cfg.piece / 2 {
            return;
        }
        let head = self.contig;
        let holder = self.workers.iter().find_map(|(id, w)| {
            let piece = w.piece.as_ref()?;
            (piece.next == head && piece.next <= piece.end && self.behind(piece)).then_some(*id)
        });
        let Some(holder) = holder else {
            return;
        };
        let free = self
            .workers
            .iter()
            .any(|(id, w)| *id != holder && w.ready && w.piece.is_none());
        if !free {
            // Nobody is free. Stopping another stream only pays when blocks
            // past the gap are already here.
            if self.buffered == 0 {
                return;
            }
            let furthest = self
                .workers
                .iter()
                .filter(|(id, _)| **id != holder)
                .filter_map(|(id, w)| {
                    let piece = w.piece.as_ref()?;
                    (piece.next <= piece.end).then_some((piece.next, *id))
                })
                .max();
            let Some((_, furthest)) = furthest else {
                return;
            };
            self.cut(furthest);
        }
        debug!(
            holder,
            height = head,
            rate = self
                .workers
                .get(&holder)
                .and_then(|w| w.rate)
                .unwrap_or(0.0) as u64,
            buffered_bytes = self.buffered,
            "block download: head slice fell behind: moving it"
        );
        self.abort(holder);
        self.avoid_head = Some((holder, Instant::now()));
        self.stats.steals.fetch_add(1, Ordering::Relaxed);
        self.last_steal = Instant::now();
    }

    /// Whether enough of the range is left for another stream to help.
    fn worth_adding(&self) -> bool {
        let left = self.end.saturating_sub(self.frontier);
        left > self.piece_blocks(1, None).saturating_mul(2)
    }

    /// End of a window: read the scanner and the buffer (see the module doc).
    fn on_window(&mut self, elapsed: Duration) {
        if let Some(since) = self.starved_since {
            self.starved_acc += since.elapsed();
            self.starved_since = Some(Instant::now());
        }
        let secs = elapsed.as_secs_f64().max(0.001);
        // What the scan measured, if it reports; else what is seen from here,
        // which reads high when blocks are batched before the scan.
        let waiting = match &self.scan_wait {
            Some(gauge) => {
                let total = gauge.total();
                let waited = total.saturating_sub(self.scan_wait_seen);
                self.scan_wait_seen = total;
                (waited.as_secs_f64() / secs).min(1.0)
            }
            None => (self.starved_acc.as_secs_f64() / secs).min(1.0),
        };
        let rate = self.received_window as f64 / secs;
        let buffered = if self.buffered_samples == 0 {
            self.buffered
        } else {
            (self.buffered_sum / u128::from(self.buffered_samples)) as u64
        };
        let parked = self.parked_window;
        self.starved_acc = Duration::ZERO;
        self.received_window = 0;
        self.buffered_sum = 0;
        self.buffered_samples = 0;
        self.parked_window = false;
        // "Small": no more than the slices in flight would explain.
        let in_flight = (self.total_rate() * self.cfg.piece.as_secs_f64()) as u64;
        let small = buffered <= in_flight.max(1);
        debug!(
            rate_bps = rate as u64,
            waiting_pct = (waiting * 100.0) as u32,
            buffered_bytes = buffered,
            budget_bytes = self.budget,
            next = self.next,
            frontier = self.frontier,
            streams = self.workers.len(),
            busy = self.workers.values().filter(|w| w.piece.is_some()).count(),
            parked,
            "block download window"
        );
        if waiting <= STARVED_FRACTION || !small {
            return; // healthy, or head-of-line, which `steal_head` handles
        }
        if parked {
            if self.budget < self.cfg.mem_cap {
                self.budget = (self.budget + self.budget / 2).min(self.cfg.mem_cap);
                self.stats.budget_raises.fetch_add(1, Ordering::Relaxed);
                info!(
                    "block download: scanner waited {:.0}% with streams parked: budget now {} bytes",
                    waiting * 100.0,
                    self.budget
                );
            }
        } else if self.target < self.ceiling && self.worth_adding() {
            self.target += 1;
            info!(
                "block download: scanner waited {:.0}% with every stream busy: {} streams now",
                waiting * 100.0,
                self.target
            );
        }
    }
}

/// One stream: fetches the slices it is assigned, one at a time.
async fn worker(
    id: usize,
    network: Network,
    factory: ClientFactory,
    mut assignments: mpsc::Receiver<(u32, u32)>,
    stop: Arc<AtomicU32>,
    events: mpsc::Sender<Event>,
    stall: Duration,
) {
    let failed = |error: anyhow::Error| Event::Failed { id, error };
    let mut client = match tokio::time::timeout(stall, factory()).await {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => {
            let _ = events.send(failed(error)).await;
            return;
        }
        Err(_) => {
            let _ = events.send(failed(anyhow!("connecting timed out"))).await;
            return;
        }
    };
    if events.send(Event::Ready(id)).await.is_err() {
        return;
    }
    while let Some((start, end)) = assignments.recv().await {
        let mut stream = match client.block_range(&network, start, end).await {
            Ok(stream) => stream,
            Err(error) => {
                let _ = events.send(failed(error)).await;
                return;
            }
        };
        let mut last = start.saturating_sub(1);
        loop {
            let item = match tokio::time::timeout(stall, stream.next()).await {
                Ok(item) => item,
                Err(_) => {
                    let error = anyhow!("no block for {} s after height {last}", stall.as_secs());
                    let _ = events.send(failed(error)).await;
                    return;
                }
            };
            match item {
                Some(Ok(block)) => {
                    let height = block.height as u32;
                    let bytes = block.encoded_len() as u64;
                    last = height;
                    if events
                        .send(Event::Block { id, block, bytes })
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if height >= end || height >= stop.load(Ordering::SeqCst) {
                        break;
                    }
                }
                Some(Err(error)) => {
                    let _ = events.send(failed(error)).await;
                    return;
                }
                None => {
                    let error = anyhow!("the block stream ended at height {last}, {end} asked");
                    let _ = events.send(failed(error)).await;
                    return;
                }
            }
        }
        drop(stream);
        if events.send(Event::Done(id)).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use tonic::async_trait;
    use zcash_primitives::transaction::Transaction;

    use super::*;
    use crate::net::{BroadcastOutcome, LwdServer};

    pub(crate) type Sizes = Arc<dyn Fn(u32) -> usize + Send + Sync>;

    /// A block server that paces its blocks and can be told to break.
    #[derive(Clone)]
    pub(crate) struct Fake {
        pub(crate) delay: Duration,
        pub(crate) size: Sizes,
        /// The stream ends after this height.
        pub(crate) ends_after: Option<u32>,
        /// The stream fails after this height.
        pub(crate) fails_after: Option<u32>,
        /// The stream fails after this many blocks of a request.
        pub(crate) fails_after_blocks: Option<u32>,
        /// Leaves out this block of a request, as a server sending a wrong height would.
        pub(crate) skips_block: Option<u32>,
        /// Opens every stream and never sends on it.
        pub(crate) silent: bool,
        /// Wait before the first block of every request.
        pub(crate) latency: Duration,
        pub(crate) asked: Arc<Mutex<Vec<(u32, u32)>>>,
        /// Streams whose sending task is alive, and the most at once.
        pub(crate) open: Arc<AtomicU64>,
        pub(crate) peak_open: Arc<AtomicU64>,
        /// Blocks sent, over every request.
        pub(crate) sent: Arc<AtomicU64>,
    }

    impl Fake {
        pub(crate) fn new(delay_ms: u64, size: usize) -> Self {
            Self {
                delay: Duration::from_millis(delay_ms),
                size: Arc::new(move |_| size),
                ends_after: None,
                fails_after: None,
                fails_after_blocks: None,
                skips_block: None,
                silent: false,
                latency: Duration::ZERO,
                asked: Arc::new(Mutex::new(vec![])),
                open: Arc::new(AtomicU64::new(0)),
                peak_open: Arc::new(AtomicU64::new(0)),
                sent: Arc::new(AtomicU64::new(0)),
            }
        }

        /// Sends `start..=end` as asked, until a configured break.
        async fn serve(self, start: u32, end: u32, tx: mpsc::Sender<Result<CompactBlock>>) {
            if self.silent {
                tx.closed().await;
                return;
            }
            tokio::select! {
                _ = tx.closed() => return,
                _ = tokio::time::sleep(self.latency) => {}
            }
            for (sent, height) in (start..=end).enumerate() {
                let sent = sent as u32;
                if self.ends_after.is_some_and(|last| height > last) {
                    return;
                }
                if self.fails_after.is_some_and(|last| height > last)
                    || self.fails_after_blocks.is_some_and(|n| sent >= n)
                {
                    let _ = tx.send(Err(anyhow!("connection reset"))).await;
                    return;
                }
                if !self.delay.is_zero() {
                    tokio::select! {
                        _ = tx.closed() => return,
                        _ = tokio::time::sleep(self.delay) => {}
                    }
                }
                if self.skips_block == Some(sent) {
                    continue;
                }
                let block = CompactBlock {
                    height: u64::from(height),
                    header: vec![0u8; (self.size)(height)],
                    ..Default::default()
                };
                if tx.send(Ok(block)).await.is_err() {
                    return;
                }
                self.sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Counts a stream as open from its request until its sending task ends.
    struct OpenStream(Arc<AtomicU64>);

    impl OpenStream {
        fn new(open: &Arc<AtomicU64>, peak: &AtomicU64) -> Self {
            let now = open.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            Self(open.clone())
        }
    }

    impl Drop for OpenStream {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl LwdServer for Fake {
        fn duplicate(&self) -> Client {
            Box::new(self.clone())
        }
        async fn latest_height(&mut self) -> Result<u32> {
            unimplemented!()
        }
        async fn block(&mut self, _: &Network, _: u32) -> Result<CompactBlock> {
            unimplemented!()
        }
        type CompactBlockStream = ReceiverStream<Result<CompactBlock>>;
        async fn block_range(
            &mut self,
            _: &Network,
            start: u32,
            end: u32,
        ) -> Result<Self::CompactBlockStream> {
            self.asked.lock().unwrap().push((start, end));
            let open = OpenStream::new(&self.open, &self.peak_open);
            let fake = self.clone();
            let (tx, rx) = mpsc::channel(10);
            tokio::spawn(async move {
                let _open = open;
                fake.serve(start, end, tx).await;
            });
            Ok(ReceiverStream::new(rx))
        }
        async fn transaction(&mut self, _: &Network, _: &[u8]) -> Result<(u32, Transaction)> {
            unimplemented!()
        }
        async fn post_transaction(&mut self, _: u32, _: &[u8]) -> Result<BroadcastOutcome> {
            unimplemented!()
        }
        type TransactionStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn taddress_txs(
            &mut self,
            _: &Network,
            _: &str,
            _: u32,
            _: u32,
        ) -> Result<Self::TransactionStream> {
            unimplemented!()
        }
        type MempoolStream = ReceiverStream<Result<(u32, Transaction, usize)>>;
        async fn mempool_stream(&mut self, _: &Network) -> Result<Self::MempoolStream> {
            unimplemented!()
        }
        async fn tree_state(&mut self, _: u32) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
            Ok((vec![], vec![], vec![]))
        }
        async fn chain_anchor(&mut self, _: u32) -> Result<Vec<u8>> {
            unimplemented!()
        }
    }

    pub(crate) fn cfg(mem_cap: u64) -> FetchConfig {
        FetchConfig {
            piece: Duration::from_millis(100),
            parallel_min_blocks: 0,
            initial_streams: 3,
            max_streams: 6,
            budget: mem_cap,
            mem_cap,
            window: Duration::from_millis(50),
            piece_stall: Duration::from_secs(5),
        }
    }

    /// A factory handing out `first` once, then copies of `rest`, counting
    /// the connections it opened.
    pub(crate) fn factory(first: Option<Fake>, rest: Fake) -> (ClientFactory, Arc<AtomicU64>) {
        let first = Arc::new(Mutex::new(first));
        let opened = Arc::new(AtomicU64::new(0));
        let count = opened.clone();
        let factory: ClientFactory = Arc::new(move || {
            count.fetch_add(1, Ordering::Relaxed);
            let fake = first.lock().unwrap().take().unwrap_or_else(|| rest.clone());
            Box::pin(async move { Ok(Box::new(fake) as Client) })
        });
        (factory, opened)
    }

    pub(crate) fn new_breaks() -> &'static StreamStats {
        Box::leak(Box::new(StreamStats::new()))
    }

    async fn open(
        first: Fake,
        factory: ClientFactory,
        end: u32,
        cfg: FetchConfig,
    ) -> (BlockStream, Arc<FetchStats>) {
        open_counting(first, factory, end, cfg, new_breaks()).await
    }

    async fn open_counting(
        first: Fake,
        factory: ClientFactory,
        end: u32,
        cfg: FetchConfig,
        breaks: &'static StreamStats,
    ) -> (BlockStream, Arc<FetchStats>) {
        let stats = Arc::new(FetchStats::default());
        let mut client: Client = Box::new(first);
        let stream = block_stream_with(
            &Network::Main,
            &mut client,
            1,
            end,
            factory,
            cfg,
            stats.clone(),
            breaks,
            None,
        )
        .await
        .unwrap();
        (stream, stats)
    }

    /// Reads the stream to its end: the heights seen and the error, if any.
    async fn drain(stream: &mut BlockStream) -> (Vec<u32>, Option<String>) {
        let mut heights = vec![];
        while let Some(item) = stream.next().await {
            match item {
                Ok(block) => heights.push(block.height as u32),
                Err(error) => return (heights, Some(format!("{error:#}"))),
            }
        }
        (heights, None)
    }

    /// Whether `holds` turns true within `within`, checked in real time.
    pub(crate) async fn eventually(holds: impl Fn() -> bool, within: Duration) -> bool {
        let deadline = std::time::Instant::now() + within;
        while !holds() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        true
    }

    #[tokio::test]
    async fn blocks_arrive_in_order_across_streams() {
        let server = Fake::new(1, 100);
        let asked = server.asked.clone();
        let (more, opened) = factory(None, server.clone());
        let (mut stream, stats) = open(server, more, 3000, cfg(64 << 20)).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights, (1..=3000).collect::<Vec<_>>());
        assert!(
            opened.load(Ordering::Relaxed) >= 3,
            "the streams were not opened at the start"
        );
        assert!(stats.pieces.load(Ordering::Relaxed) > 3);
        // The first slice is a probe, not the whole range.
        assert_eq!(asked.lock().unwrap()[0], (1, PROBE_BLOCKS));
    }

    #[tokio::test]
    async fn a_short_range_is_one_request_on_the_callers_connection() {
        let server = Fake::new(0, 100);
        let asked = server.asked.clone();
        let (more, opened) = factory(None, server.clone());
        let mut client: Client = Box::new(server);
        let end = PARALLEL_MIN_BLOCKS - 1;
        let plan = FetchPlan {
            factory: more,
            config: FetchConfig::default(),
        };
        let mut stream = block_stream(
            &Network::Main,
            &mut client,
            1,
            end,
            Some(&plan),
            new_breaks(),
            None,
        )
        .await
        .unwrap();
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights.len() as u32, end);
        assert_eq!(*asked.lock().unwrap(), vec![(1, end)]);
        assert_eq!(opened.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn block_stream_with_short_range_counts_the_callers_stream_in_the_peak() {
        let server = Fake::new(0, 100);
        let (more, _) = factory(None, server.clone());
        let config = FetchConfig {
            parallel_min_blocks: 10_000,
            ..cfg(64 << 20)
        };
        let (mut stream, stats) = open(server, more, 100, config).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!((heights.len(), error), (100, None));
        assert_eq!(stats.peak_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_short_range_that_takes_too_long_is_aborted_and_split() {
        // 2000 blocks at a millisecond each, against a 150 ms limit.
        let server = Fake::new(1, 100);
        let asked = server.asked.clone();
        let (more, opened) = factory(None, server.clone());
        let mut config = cfg(64 << 20);
        config.parallel_min_blocks = 10_000;
        let (mut stream, stats) = open(server, more, 2000, config).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights, (1..=2000).collect::<Vec<_>>());
        assert_eq!(
            asked.lock().unwrap()[0],
            (1, 2000),
            "it starts as one request"
        );
        assert!(
            stats.timeouts.load(Ordering::Relaxed) >= 1,
            "the request was never aborted"
        );
        assert!(opened.load(Ordering::Relaxed) >= 1, "no stream took over");
    }

    #[tokio::test]
    async fn block_stream_slow_to_answer_server_delivers_every_block() {
        // Every request waits twice the 150 ms limit for its first block.
        let server = Fake {
            latency: Duration::from_millis(300),
            ..Fake::new(0, 100)
        };
        let (more, _) = factory(None, server.clone());
        let (mut stream, _) = open(server, more, 3000, cfg(64 << 20)).await;
        let (heights, error) = tokio::time::timeout(Duration::from_secs(20), drain(&mut stream))
            .await
            .expect("no progress against a slow server");
        assert_eq!(error, None);
        assert_eq!(heights, (1..=3000).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_slow_slice_nobody_waits_for_is_aborted_too() {
        let server = Fake::new(1, 100);
        let slow = Fake {
            delay: Duration::from_millis(40),
            ..server.clone()
        };
        let (more, _) = factory(Some(slow), server.clone());
        let (mut stream, stats) = open(server, more, 3000, cfg(64 << 20)).await;
        // The consumer is not reading, so nothing is "needed": only the
        // time limit can end the slow stream's slice.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            stats.timeouts.load(Ordering::Relaxed) >= 1,
            "the slow slice was left running"
        );
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights, (1..=3000).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_waiting_consumer_gets_more_streams() {
        let server = Fake::new(1, 100);
        let (more, _) = factory(None, server.clone());
        let (mut stream, stats) = open(server, more, 4000, cfg(64 << 20)).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights.len(), 4000);
        assert!(
            stats.peak_connections.load(Ordering::Relaxed) > 3,
            "no stream was added while the consumer waited"
        );
    }

    #[tokio::test]
    async fn block_stream_with_reused_gauge_ignores_the_waits_before_it() {
        let gauge = ScanWait::new();
        gauge
            .timed(tokio::time::sleep(Duration::from_millis(500)))
            .await;
        let server = Fake::new(0, 100);
        let (more, _) = factory(None, server.clone());
        let config = FetchConfig {
            initial_streams: 1,
            ..cfg(64 << 20)
        };
        let stats = Arc::new(FetchStats::default());
        let mut client: Client = Box::new(server);
        let mut stream = block_stream_with(
            &Network::Main,
            &mut client,
            1,
            100_000,
            more,
            config,
            stats.clone(),
            new_breaks(),
            Some(gauge),
        )
        .await
        .unwrap();
        let (heights, error) = drain(&mut stream).await;
        assert_eq!((heights.len(), error), (100_000, None));
        // The scan never waited during this download, so nothing asked for a second stream.
        assert_eq!(stats.peak_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn undelivered_bytes_stay_near_the_budget() {
        let cap = 200_000;
        let server = Fake::new(1, 1000);
        let (more, _) = factory(None, server.clone());
        let (mut stream, stats) = open(server, more, 3000, cfg(cap)).await;
        // Read for a while, then stop reading: the download must stop too.
        let mut heights = vec![];
        let reading = Instant::now();
        while reading.elapsed() < Duration::from_millis(400) {
            heights.push(stream.next().await.unwrap().unwrap().height as u32);
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
        let (rest, error) = drain(&mut stream).await;
        heights.extend(rest);
        assert_eq!(error, None);
        assert_eq!(heights, (1..=3000).collect::<Vec<_>>());
        let max = stats.max_buffered.load(Ordering::Relaxed);
        assert!(max <= cap * 2, "{max} bytes buffered, budget {cap}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_slice_is_credited_no_more_unread_time_than_it_lived() {
        let mut old = Instant::now();
        tokio::time::advance(Duration::from_secs(30)).await;
        let mut young = Instant::now();
        tokio::time::advance(Duration::from_secs(1)).await;
        credit_unread(&mut old, Duration::from_secs(20));
        credit_unread(&mut young, Duration::from_secs(20));
        assert_eq!(old.elapsed(), Duration::from_secs(11));
        assert_eq!(young, Instant::now());
    }

    #[tokio::test]
    async fn a_slow_scan_behind_a_full_buffer_times_out_no_slice() {
        let server = Fake::new(0, 1000);
        let (more, _) = factory(None, server.clone());
        let (mut stream, stats) = open(server, more, 1000, cfg(200_000)).await;
        let mut heights = vec![];
        while let Some(item) = stream.next().await {
            heights.push(item.unwrap().height as u32);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(heights, (1..=1000).collect::<Vec<_>>());
        assert_eq!(stats.timeouts.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn a_slice_denser_than_planned_is_cut_and_refetched() {
        // Blocks grow fifty-fold past height 800: slices planned on the
        // small ones overrun.
        let mut server = Fake::new(1, 100);
        server.size = Arc::new(|height| if height > 800 { 5000 } else { 100 });
        let (more, _) = factory(None, server.clone());
        let (mut stream, stats) = open(server, more, 2500, cfg(64 << 20)).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights, (1..=2500).collect::<Vec<_>>());
        assert!(stats.cuts.load(Ordering::Relaxed) >= 1, "no slice was cut");
    }

    #[tokio::test]
    async fn a_failed_stream_has_its_slice_refetched() {
        let server = Fake::new(1, 100);
        let mut breaks = server.clone();
        breaks.fails_after_blocks = Some(20);
        let (more, _) = factory(Some(breaks), server.clone());
        let (mut stream, stats) = open(server, more, 2000, cfg(64 << 20)).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights, (1..=2000).collect::<Vec<_>>());
        assert!(
            stats.requeued.load(Ordering::Relaxed) >= 1,
            "no slice was given back"
        );
    }

    #[tokio::test]
    async fn when_every_stream_fails_the_error_follows_what_arrived_in_order() {
        let mut server = Fake::new(1, 100);
        server.fails_after = Some(300);
        let (more, _) = factory(None, server.clone());
        let (mut stream, _) = open(server, more, 2000, cfg(64 << 20)).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(heights, (1..=300).collect::<Vec<_>>());
        assert!(error.unwrap().contains("connection reset"));
    }

    #[tokio::test]
    async fn a_stream_that_falls_behind_at_the_head_loses_its_slice() {
        // One stream takes 40 ms a block: its 64-block probe alone would
        // hold the head for 2.5 s.
        let server = Fake::new(1, 100);
        let slow = Fake {
            delay: Duration::from_millis(40),
            ..server.clone()
        };
        let (more, _) = factory(Some(slow), server.clone());
        let started = Instant::now();
        let (mut stream, stats) = open(server, more, 3000, cfg(64 << 20)).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights, (1..=3000).collect::<Vec<_>>());
        assert!(
            stats.steals.load(Ordering::Relaxed) >= 1,
            "the head slice was never moved"
        );
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "the slow stream held the scan back"
        );
    }

    #[tokio::test]
    async fn a_stream_that_stays_slow_is_replaced() {
        let server = Fake::new(1, 100);
        let slow = Fake {
            delay: Duration::from_millis(8),
            ..server.clone()
        };
        let (more, opened) = factory(Some(slow), server.clone());
        let mut config = cfg(64 << 20);
        config.initial_streams = 4;
        let (mut stream, stats) = open(server, more, 9000, config).await;
        let (heights, error) = drain(&mut stream).await;
        assert_eq!(error, None);
        assert_eq!(heights.len(), 9000);
        assert!(
            stats.replaced.load(Ordering::Relaxed) >= 1,
            "the slow stream was kept"
        );
        assert!(opened.load(Ordering::Relaxed) >= 5);
    }

    #[tokio::test]
    async fn fail_worker_stream_fails_records_a_stream_break() {
        let server = Fake::new(1, 100);
        let breaking = Fake {
            fails_after_blocks: Some(20),
            ..Fake::new(1, 100)
        };
        let (more, _) = factory(Some(breaking), server.clone());
        let breaks = new_breaks();
        let (mut stream, _) = open_counting(server, more, 2000, cfg(64 << 20), breaks).await;

        let (heights, error) = drain(&mut stream).await;

        assert_eq!(error, None);
        assert_eq!(heights, (1..=2000).collect::<Vec<_>>());
        assert_eq!(breaks.snapshot().stream_breaks, 1);
    }

    #[tokio::test]
    async fn on_first_first_stream_fails_records_a_stream_break() {
        let failing = Fake {
            fails_after_blocks: Some(10),
            ..Fake::new(1, 100)
        };
        let ending = Fake {
            ends_after: Some(10),
            ..Fake::new(1, 100)
        };
        for first in [failing, ending] {
            let (more, _) = factory(None, Fake::new(1, 100));
            let breaks = new_breaks();
            let (mut stream, _) = open_counting(first, more, 2000, cfg(64 << 20), breaks).await;

            let (heights, error) = drain(&mut stream).await;

            assert_eq!(error, None);
            assert_eq!(heights, (1..=2000).collect::<Vec<_>>());
            assert_eq!(breaks.snapshot().stream_breaks, 1);
        }
    }

    #[tokio::test]
    async fn block_stream_output_dropped_aborts_workers_and_their_streams() {
        let server = Fake {
            silent: true,
            ..Fake::new(0, 100)
        };
        let open_streams = server.open.clone();
        let (more, _) = factory(None, server.clone());
        let (stream, _) = open(server, more, 3000, cfg(64 << 20)).await;
        assert!(
            eventually(
                || open_streams.load(Ordering::SeqCst) >= 3,
                Duration::from_secs(2)
            )
            .await,
            "the parallel download never started"
        );

        drop(stream);

        // Well inside the 5 s `piece_stall` a lingering worker would wait out.
        assert!(
            eventually(
                || open_streams.load(Ordering::SeqCst) == 0,
                Duration::from_secs(1)
            )
            .await,
            "{} streams still open",
            open_streams.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn fail_worker_misbehaving_stream_is_aborted() {
        let server = Fake::new(1, 100);
        let misbehaving = Fake {
            skips_block: Some(5),
            ..Fake::new(5, 100)
        };
        let misbehaving_sent = misbehaving.sent.clone();
        let (more, _) = factory(Some(misbehaving), server.clone());
        let (mut stream, _) = open(server, more, 6000, cfg(64 << 20)).await;

        let (heights, error) = drain(&mut stream).await;

        assert_eq!(error, None);
        assert_eq!(heights, (1..=6000).collect::<Vec<_>>());
        // Left running, it would send the rest of its 64-block probe.
        let sent = misbehaving_sent.load(Ordering::Relaxed);
        assert!(sent < 20, "the dropped stream sent {sent} blocks");
    }

    #[tokio::test]
    async fn on_first_skipped_height_refetches_the_rest_of_the_slice() {
        let server = Fake::new(1, 100);
        let skipping = Fake {
            skips_block: Some(5),
            ..server.clone()
        };
        let (more, _) = factory(None, server);
        let (mut stream, _) = open(skipping, more, 3000, cfg(64 << 20)).await;

        let (heights, error) = tokio::time::timeout(Duration::from_secs(10), drain(&mut stream))
            .await
            .expect("the skipped height was never refetched");

        assert_eq!(error, None);
        assert_eq!(heights, (1..=3000).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn top_up_max_streams_bounds_concurrent_streams_including_the_first() {
        for max_streams in [1u32, 2, 6] {
            let server = Fake::new(1, 100);
            let peak_open = server.peak_open.clone();
            let (more, _) = factory(None, server.clone());
            let download = BlockDownload {
                max_streams,
                buffer_bytes: 64 << 20,
            };
            let limits = fetch_config(&download);
            let config = FetchConfig {
                initial_streams: limits.initial_streams,
                max_streams: limits.max_streams,
                ..cfg(64 << 20)
            };
            let (mut stream, stats) = open(server, more, 1000, config).await;

            let (heights, error) = drain(&mut stream).await;

            assert_eq!(error, None);
            assert_eq!(heights, (1..=1000).collect::<Vec<_>>());
            let peak = u64::from(max_streams);
            assert_eq!(stats.peak_connections.load(Ordering::Relaxed), peak);
            assert!(
                peak_open.load(Ordering::SeqCst) <= peak,
                "{} streams open at once, {max_streams} allowed",
                peak_open.load(Ordering::SeqCst)
            );
        }
    }

    #[test]
    fn fetch_config_out_of_range_values_are_clamped() {
        let config = fetch_config(&BlockDownload {
            max_streams: 0,
            buffer_bytes: 0,
        });

        assert_eq!(1, config.max_streams);
        assert_eq!(1, config.initial_streams);
        assert_eq!(MIB, config.mem_cap);
        assert_eq!(MIB, config.budget);
    }

    #[test]
    fn fetch_config_default_download_is_the_upstream_config() {
        let config = fetch_config(&BlockDownload::default());
        let upstream = FetchConfig::default();

        assert_eq!(upstream.max_streams, config.max_streams);
        assert_eq!(upstream.initial_streams, config.initial_streams);
        assert_eq!(upstream.mem_cap, config.mem_cap);
        assert_eq!(upstream.budget, config.budget);
    }
}
