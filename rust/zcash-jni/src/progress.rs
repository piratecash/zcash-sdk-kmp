//! Sync progress and the error channel behind it.
//!
//! `synchronize_impl` returns `Ok(current_height)` whatever happens inside and routes every failure
//! — including cancellation — through the sink, so the error slot is what decides the outcome.

use rlz::api::sync::SyncProgress;
use rlz::Sink;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

static SINK: LazyLock<ProgressSink> = LazyLock::new(ProgressSink::default);

pub fn sink() -> &'static ProgressSink {
    &SINK
}

/// Height in the high word, block time in the low one: Kotlin reads progress with one plain call.
fn pack(progress: &SyncProgress) -> u64 {
    ((progress.height as u64) << 32) | progress.time as u64
}

#[derive(Clone, Default)]
pub struct ProgressSink {
    packed: Arc<AtomicU64>,
    error: Arc<Mutex<Option<String>>>,
}

impl ProgressSink {
    pub fn reset(&self) {
        self.packed.store(0, Ordering::Relaxed);
        *self.slot() = None;
    }

    pub fn packed(&self) -> u64 {
        self.packed.load(Ordering::Relaxed)
    }

    /// An empty slot is the only success signal a completed sync gives.
    pub fn outcome(&self) -> Result<(), String> {
        self.slot().take().map_or(Ok(()), Err)
    }

    /// A panic must not poison the error channel and turn a reportable failure into a second one.
    fn slot(&self) -> MutexGuard<'_, Option<String>> {
        self.error.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Sink<SyncProgress> for ProgressSink {
    async fn send(&self, value: SyncProgress) {
        self.packed.store(pack(&value), Ordering::Relaxed);
    }

    async fn send_error(&self, e: anyhow::Error) {
        *self.slot() = Some(format!("{e:#}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    #[test]
    fn pack_keeps_height_and_time_in_separate_words() {
        let packed = pack(&SyncProgress {
            height: 2_500_000,
            time: 1_700_000_000,
        });

        assert_eq!(2_500_000, (packed >> 32) as u32);
        assert_eq!(1_700_000_000, packed as u32);
    }

    #[test]
    fn send_updates_the_progress_counter() {
        let sink = ProgressSink::default();

        block_on(sink.send(SyncProgress {
            height: 42,
            time: 7,
        }));

        assert_eq!((42u64 << 32) | 7, sink.packed());
        assert_eq!(Ok(()), sink.outcome());
    }

    #[test]
    fn send_error_populates_the_slot_and_fails_the_outcome() {
        let sink = ProgressSink::default();

        block_on(sink.send_error(anyhow::anyhow!("Sync canceled")));

        assert_eq!(Err("Sync canceled".to_string()), sink.outcome());
    }

    #[test]
    fn outcome_is_taken_once_so_a_later_sync_starts_clean() {
        let sink = ProgressSink::default();
        block_on(sink.send_error(anyhow::anyhow!("server unreachable")));

        assert!(sink.outcome().is_err());
        assert_eq!(Ok(()), sink.outcome());
    }

    #[test]
    fn reset_clears_progress_and_a_previous_error() {
        let sink = ProgressSink::default();
        block_on(sink.send(SyncProgress {
            height: 42,
            time: 7,
        }));
        block_on(sink.send_error(anyhow::anyhow!("server unreachable")));

        sink.reset();

        assert_eq!(0, sink.packed());
        assert_eq!(Ok(()), sink.outcome());
    }
}
