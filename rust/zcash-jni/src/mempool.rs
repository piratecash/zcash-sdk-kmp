//! The mempool subscription: one process-wide run, drained from Kotlin by polling.
//!
//! Events are queued rather than pushed at Kotlin, so the native reader never blocks on a slow
//! consumer and cancellation is always observed.

use crate::dto::MempoolEventDto;
use crate::runtime;
use rlz::api::coin::Coin;
use rlz::api::mempool::{observe_mempool, CancellationToken, MempoolMsg};
use rlz::Sink;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

static RUN: LazyLock<Mutex<Option<Run>>> = LazyLock::new(|| Mutex::new(None));

struct Run {
    events: UnboundedReceiver<MempoolEventDto>,
    cancel: CancellationToken,
    reader: JoinHandle<()>,
}

#[derive(Clone)]
struct EventSink(UnboundedSender<MempoolEventDto>);

impl Sink<MempoolMsg> for EventSink {
    async fn send(&self, value: MempoolMsg) {
        let _ = self.0.send(value.into());
    }

    async fn send_error(&self, e: anyhow::Error) {
        let _ = self.0.send(ended(Some(e)));
    }
}

/// Owns the right to report how the run finished, exactly once.
struct Verdict(Option<UnboundedSender<MempoolEventDto>>);

impl Verdict {
    fn send(mut self, event: MempoolEventDto) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(event);
        }
    }
}

/// The reader can only skip `send` by unwinding, and a closed queue alone is indistinguishable
/// from a clean end.
impl Drop for Verdict {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(ended(Some(anyhow::anyhow!("mempool reader panicked"))));
        }
    }
}

fn ended(error: Option<anyhow::Error>) -> MempoolEventDto {
    MempoolEventDto::Ended {
        error: error.map(|e| format!("{e:#}")),
    }
}

/// A panic must not poison the slot and strand a live native reader.
fn run() -> MutexGuard<'static, Option<Run>> {
    RUN.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Fails when a run is already active: two runs would share one queue and one cancellation.
pub fn start(coin: Coin) -> Result<(), String> {
    let mut slot = run();
    if slot.is_some() {
        return Err("mempool is already running".to_string());
    }
    let (sender, events) = unbounded_channel();
    let cancel = CancellationToken::new();
    let sink = EventSink(sender.clone());
    let token = cancel.clone();
    let reader = runtime().spawn(async move {
        let verdict = Verdict(Some(sender));
        let outcome = observe_mempool(sink, token, &coin).await;
        verdict.send(ended(outcome.err()));
    });
    *slot = Some(Run {
        events,
        cancel,
        reader,
    });
    Ok(())
}

/// The next event, or `None` when none arrived within `timeout`. A run removed by [stop]
/// ends the poll rather than failing it.
///
/// The wait happens under the lock, so a concurrent [stop] waits out at most one timeout.
pub fn next(timeout: Duration) -> Option<MempoolEventDto> {
    let mut slot = run();
    let Some(active) = slot.as_mut() else {
        return Some(ended(None));
    };
    recv_within(&mut active.events, timeout)
}

/// `None` on timeout. A closed queue means the reader is gone without a verdict — a panic,
/// nothing else — so it is reported as a plain end.
fn recv_within(
    events: &mut UnboundedReceiver<MempoolEventDto>,
    timeout: Duration,
) -> Option<MempoolEventDto> {
    // Built inside the runtime on purpose: the timeout registers its timer on construction.
    runtime()
        .block_on(async { tokio::time::timeout(timeout, events.recv()).await })
        .ok()
        .map(|event| event.unwrap_or_else(|| ended(None)))
}

/// Cancels the run and returns only once the native reader has actually stopped.
pub fn stop() {
    let active = run().take();
    let Some(active) = active else { return };
    active.cancel.cancel();
    let _ = runtime().block_on(active.reader);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rlz::api::mempool::{MempoolAmount, MempoolNote, MempoolTx};
    use std::future::Future;

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(future)
    }

    fn note(value: i64) -> MempoolNote {
        MempoolNote {
            account: 1,
            name: "main".to_string(),
            value,
            pool: 2,
            scope: 0,
            diversifier: None,
            diversifier_index: None,
            address: None,
            memo: Some("thanks".to_string()),
        }
    }

    #[test]
    fn send_queues_the_event_as_a_dto() {
        let (sender, mut events) = unbounded_channel();
        let sink = EventSink(sender);

        block_on(sink.send(MempoolMsg::TxId(MempoolTx {
            txid: "ab".to_string(),
            amounts: vec![MempoolAmount {
                account: 1,
                name: "main".to_string(),
                value: 500,
            }],
            notes: vec![note(500)],
            size: 42,
        })));

        let event = events.try_recv().expect("queued event");
        assert!(matches!(
            event,
            MempoolEventDto::Unconfirmed { size: 42, .. }
        ));
    }

    #[test]
    fn send_error_queues_a_terminal_event() {
        let (sender, mut events) = unbounded_channel();
        let sink = EventSink(sender);

        block_on(sink.send_error(anyhow::anyhow!("server unreachable")));

        assert_eq!(
            MempoolEventDto::Ended {
                error: Some("server unreachable".to_string())
            },
            events.try_recv().expect("queued event")
        );
    }

    #[test]
    fn send_on_a_dropped_queue_is_ignored() {
        let (sender, events) = unbounded_channel();
        let sink = EventSink(sender);
        drop(events);

        block_on(sink.send(MempoolMsg::BlockHeight(7)));
    }

    /// Guards the trap that `tokio::time::timeout` panics when built outside a runtime.
    #[test]
    fn recv_within_returns_a_queued_event() {
        let (sender, mut events) = unbounded_channel();
        sender.send(ended(None)).expect("queued");

        assert_eq!(
            Some(MempoolEventDto::Ended { error: None }),
            recv_within(&mut events, Duration::from_millis(50)),
        );
    }

    #[test]
    fn recv_within_an_empty_queue_times_out() {
        let (_sender, mut events) = unbounded_channel();

        assert_eq!(None, recv_within(&mut events, Duration::from_millis(50)));
    }

    #[test]
    fn recv_within_a_closed_queue_reports_a_plain_end() {
        let (sender, mut events) = unbounded_channel();
        drop(sender);

        assert_eq!(
            Some(MempoolEventDto::Ended { error: None }),
            recv_within(&mut events, Duration::from_millis(50)),
        );
    }

    /// A stopped run must end the poll loop, not fail it: `stop` removes the queue while the
    /// collector is between two polls.
    #[test]
    fn next_without_a_run_reports_a_plain_end() {
        assert_eq!(
            Some(MempoolEventDto::Ended { error: None }),
            next(Duration::from_millis(1))
        );
    }

    #[test]
    fn stop_without_a_run_is_a_no_op() {
        stop();
    }

    #[test]
    fn a_verdict_is_reported_once() {
        let (sender, mut events) = unbounded_channel();

        Verdict(Some(sender)).send(ended(None));

        assert_eq!(
            MempoolEventDto::Ended { error: None },
            events.try_recv().expect("queued event")
        );
        assert!(events.try_recv().is_err(), "the verdict must not repeat");
    }

    /// A panicking reader unwinds without reaching `send`; silence would read as a clean end.
    #[test]
    fn an_unreported_verdict_becomes_a_reader_failure() {
        let (sender, mut events) = unbounded_channel();

        drop(Verdict(Some(sender)));

        let MempoolEventDto::Ended { error } = events.try_recv().expect("queued event") else {
            panic!("expected a terminal event")
        };
        assert!(error.is_some(), "a lost verdict must carry the failure");
    }
}
