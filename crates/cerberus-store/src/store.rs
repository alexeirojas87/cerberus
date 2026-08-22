//! `SQLite` store for Cerberus audit events.
//!
//! `AuditStore` is `Send + Sync`: it owns only unbounded `std::sync::mpsc`
//! senders and thread handles. The `SQLite` writer/reader run on dedicated
//! **operating-system threads** (`std::thread`), never on the tokio runtime —
//! the async hot path just pushes into an unbounded channel (never blocks),
//! fixing review P1-10.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use rusqlite::Connection;

use crate::event::AuditEvent;

/// Minimum interval between retention purges (by time, not by count).
const PURGE_INTERVAL_SECS: u64 = 60;

/// Default capacity of the write channel (backpressure mitigated):
/// above this the hot path does not block, but events are dropped with WARN.
const DEFAULT_WRITE_CHANNEL_CAPACITY: usize = 16_384;

/// Default timeout for `flush`/`close`. Covers the COMPLETE operation:
/// enqueuing the barrier into the bounded channel PLUS waiting for the writer
/// ACK (fix review v6.1: before, `send` was blocking and unbounded, so a
/// stuck writer with a full channel hung the shutdown forever).
const DEFAULT_STORE_TIMEOUT: Duration = Duration::from_secs(5);

/// Wait between `try_send` retries while the channel is full during the
/// enqueue of a barrier (flush/close). Bounded by the global deadline.
const ENQUEUE_RETRY_BACKOFF: Duration = Duration::from_millis(2);

/// Store state (`AuditStore::state`, `AtomicU8`). Transitions are
/// monotonic and atomic: it never goes back to a previous state.
///
/// `ACCEPTING` → `CLOSING` → `SHUTDOWN_SENT` → `CLOSED`
///
/// * `ACCEPTING`: accepts events and barriers.
/// * `CLOSING`: does NOT accept new events (orderly drain in progress), but
///   the writer is still alive and `flush` is still valid.
/// * `SHUTDOWN_SENT`: the close barrier has already been emitted by a
///   `close()`; no other `close`/`flush` can emit barriers.
/// * `CLOSED`: the writer has terminated.
mod state {
    pub(super) const ACCEPTING: u8 = 0;
    pub(super) const CLOSING: u8 = 1;
    pub(super) const SHUTDOWN_SENT: u8 = 2;
    pub(super) const CLOSED: u8 = 3;

    pub(super) const fn name(v: u8) -> &'static str {
        match v {
            ACCEPTING => "accepting",
            CLOSING => "closing",
            SHUTDOWN_SENT => "shutdown-sent",
            _ => "closed",
        }
    }
}

/// Message sent to the writer thread.
enum WriteMsg {
    Event(Box<AuditEvent>),
    /// Durability barrier (fix review v4 #6): the writer replies `ack` only
    /// after persisting all previous `Event`s (the queue is FIFO). If some
    /// `INSERT` failed since the last flush, the ack is `Err` with the
    /// `SQLite` error message.
    Flush {
        ack: mpsc::SyncSender<Result<(), String>>,
    },
    /// Orderly writer shutdown (fix review v4 #6b). The ACK carries the
    /// last pending persistence error (fix review v5): if there was an
    /// unconsumed failed INSERT, it is delivered as `Err` — `close()` no
    /// longer confirms success when audit data was lost.
    Shutdown {
        ack: mpsc::SyncSender<Result<(), String>>,
    },
}

/// Message sent to the query thread.
enum QueryMsg {
    RecentEvents {
        limit: usize,
        tx: mpsc::SyncSender<QueryResult>,
    },
    EventCount {
        tx: mpsc::SyncSender<QueryResult>,
    },
}

/// Result of a `SQLite` query.
pub enum QueryResult {
    /// A list of events.
    Events(Vec<AuditEvent>),
    /// An integer count.
    Count(usize),
    /// SQL error.
    Error(String),
}

impl std::fmt::Debug for QueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Events(evts) => f.debug_tuple("Events").field(&evts.len()).finish(),
            Self::Count(c) => f.debug_tuple("Count").field(c).finish(),
            Self::Error(e) => f.debug_tuple("Error").field(e).finish(),
        }
    }
}

/// (Honest) result of a write attempt on the hot path.
/// Callers may ignore it; tests and metrics use it to distinguish loss due
/// to a slow disk from rejection due to shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Enqueued for the writer: will be persisted before `close()` returns.
    Queued,
    /// Dropped by backpressure (full channel, writer alive).
    DroppedBackpressure,
    /// Rejected because the store no longer accepts events (shutdown started).
    RejectedClosed,
}

/// `SQLite` store for audit events with non-blocking async writes.
#[derive(Debug)]
pub struct AuditStore {
    write_tx: mpsc::SyncSender<WriteMsg>,
    query_tx: mpsc::Sender<QueryMsg>,
    /// Events dropped by backpressure (full channel). The hot path never
    /// blocks: if the channel is full the event is dropped and counted here
    /// (fix review v5 #4 — bounded memory growth).
    dropped_events: std::sync::atomic::AtomicU64,
    /// Drops already reported and "consumed" by a previous `flush`/`close`.
    /// The next `flush` only reports new drops (total - acknowledged),
    /// so a successful flush does not fail again for already-notified drops
    /// (fix review v6 P1).
    dropped_acknowledged: std::sync::atomic::AtomicU64,
    /// Events REJECTED because the store had already started shutdown (or the
    /// writer terminated). Counted separately from `dropped_events`: these are
    /// not slow-disk backpressure, they are post-close writes — mixing them
    /// produced dishonest errors (fix review v6.1).
    rejected_after_close: std::sync::atomic::AtomicU64,
    /// Rejections already reported by a previous `flush`/`close`.
    rejected_acknowledged: std::sync::atomic::AtomicU64,
    /// Atomic state accepting/closing/closed (see [`state`] module).
    state: std::sync::atomic::AtomicU8,
    /// Hot-path writes that already passed the state gate but have not yet
    /// finished their `try_send`. `close()` waits for this to reach 0 before
    /// emitting the close barrier; combined with `SeqCst` ordering this makes
    /// it IMPOSSIBLE for an already-enqueued event to be lost on close
    /// (fix v6.1: before, there was a window between the state check and the
    /// send).
    inflight_writes: std::sync::atomic::AtomicUsize,
    timeout: Duration,
    #[allow(dead_code)]
    _write_thread: std::thread::JoinHandle<()>,
    #[allow(dead_code)]
    _query_thread: std::thread::JoinHandle<()>,
}

impl AuditStore {
    /// Open (or create) the `SQLite` database at `path` with the default
    /// retention of 90 days.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        Self::open_with(path, 90)
    }

    /// Events dropped by backpressure since creation (full channel, writer
    /// alive). Does NOT include events rejected after shutdown started —
    /// those are counted in [`Self::rejected_after_close`].
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Events rejected because the store no longer accepted writes (shutdown
    /// started or writer terminated).
    #[must_use]
    pub fn rejected_after_close(&self) -> u64 {
        self.rejected_after_close.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `true` while the store accepts new events (state `accepting`).
    #[must_use]
    pub fn is_accepting(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Acquire) == state::ACCEPTING
    }

    /// Name of the current state (`accepting` | `closing` | `shutdown-sent` |
    /// `closed`), for logs and diagnostics.
    #[must_use]
    pub fn state_name(&self) -> &'static str {
        state::name(self.state.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Override the global `flush`/`close` timeout (enqueue + ACK).
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Stop accepting new events WITHOUT closing the writer: first step of
    /// orderly shutdown. From here on the queue is finite (nothing new comes
    /// in), so the subsequent `flush` drains a bounded set and late events
    /// are reported as honest rejections instead of being silently lost.
    ///
    /// Returns `true` if this call performed the transition
    /// `accepting → closing`, `false` if shutdown had already started.
    pub fn begin_closing(&self) -> bool {
        self.state
            .compare_exchange(
                state::ACCEPTING,
                state::CLOSING,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    /// Open (or create) the `SQLite` database at `path` with a configurable
    /// retention period in days. Events with `ts_unix` older than
    /// `retention_days` are purged on open and periodically afterwards.
    pub fn open_with(path: impl AsRef<std::path::Path>, retention_days: u64) -> Result<Self, String> {
        Self::open_with_capacity(path, retention_days, DEFAULT_WRITE_CHANNEL_CAPACITY)
    }

    /// Open with a configurable retention period and write-channel capacity
    /// (fix review v5 #4). Events that arrive when the channel is full are
    /// dropped (counted in [`Self::dropped_events`]) so the hot path never
    /// blocks on a slow `SQLite` disk.
    pub fn open_with_capacity(
        path: impl AsRef<std::path::Path>,
        retention_days: u64,
        channel_capacity: usize,
    ) -> Result<Self, String> {
        let conn = Connection::open(path.as_ref()).map_err(|e| format!("cannot open SQLite: {e}"))?;
        Self::create_tables(&conn)?;
        // Retention purge on OPEN (once).
        let purged = purge_old(&conn, retention_days);
        if purged > 0 {
            tracing::info!("audit retention purge at open: removed {purged} events");
        }
        drop(conn);

        let writer_conn = Connection::open(path.as_ref()).map_err(|e| format!("cannot open SQLite for writer: {e}"))?;
        let reader_conn = Connection::open(path.as_ref()).map_err(|e| format!("cannot open SQLite for reader: {e}"))?;

        let (write_tx, write_rx) = mpsc::sync_channel::<WriteMsg>(channel_capacity);
        let (query_tx, query_rx) = mpsc::channel::<QueryMsg>();

        let write_thread = std::thread::Builder::new()
            .name("cerberus-store-writer".to_string())
            .spawn(move || Self::write_loop(write_rx, writer_conn, retention_days))
            .map_err(|e| format!("cannot spawn writer thread: {e}"))?;

        let query_thread = std::thread::Builder::new()
            .name("cerberus-store-reader".to_string())
            .spawn(move || Self::query_loop(query_rx, reader_conn))
            .map_err(|e| format!("cannot spawn reader thread: {e}"))?;

        Ok(Self {
            write_tx,
            query_tx,
            dropped_events: std::sync::atomic::AtomicU64::new(0),
            dropped_acknowledged: std::sync::atomic::AtomicU64::new(0),
            rejected_after_close: std::sync::atomic::AtomicU64::new(0),
            rejected_acknowledged: std::sync::atomic::AtomicU64::new(0),
            state: std::sync::atomic::AtomicU8::new(state::ACCEPTING),
            inflight_writes: std::sync::atomic::AtomicUsize::new(0),
            timeout: DEFAULT_STORE_TIMEOUT,
            _write_thread: write_thread,
            _query_thread: query_thread,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn write_loop(rx: mpsc::Receiver<WriteMsg>, conn: Connection, retention_days: u64) {
        let mut last_purge = Instant::now();
        // Last persistence error (fix review v4 #6): a failed INSERT is
        // retained and not lost; the next Flush propagates it to the caller
        // instead of ACKing as if everything were durable.
        let mut last_error: Option<String> = None;
        while let Ok(msg) = rx.recv() {
            match msg {
                WriteMsg::Event(event) => {
                    if let Err(e) = insert_event(&conn, &event) {
                        tracing::error!("audit write error: {e}");
                        last_error = Some(e);
                    }
                    // Periodic TIME-BASED retention: purge every ≥60s, not by count.
                    if last_purge.elapsed() >= Duration::from_secs(PURGE_INTERVAL_SECS) {
                        let purged = purge_old(&conn, retention_days);
                        if purged > 0 {
                            tracing::info!("audit retention purge: removed {purged} events");
                        }
                        last_purge = Instant::now();
                    }
                }
                WriteMsg::Flush { ack } => {
                    // Previous events already applied (FIFO queue, this thread
                    // processes them in order). The ack is the durability
                    // barrier: Ok(()) only if there was no failed insert since
                    // the last flush.
                    let res = last_error.take().map_or(Ok(()), Err);
                    let _ = ack.send(res);
                }
                WriteMsg::Shutdown { ack } => {
                    // ORDERLY drain before dying (fix review v6.1): a writer
                    // must not drop events that were already enqueued behind
                    // the close barrier. `close()` marks the store as
                    // `closing` BEFORE emitting this barrier, so the remaining
                    // queue is finite: it is drained in FIFO order and only
                    // then ACKed and terminated.
                    let drained = Self::drain_pending(&rx, &conn, &mut last_error);
                    if drained > 0 {
                        tracing::info!("audit writer drained {drained} pending message(s) at shutdown");
                    }
                    // The ACK carries the last pending persistence error
                    // (fix review v5 #4): close() will know if audit data was
                    // lost.
                    let res = last_error.take().map_or(Ok(()), Err);
                    let _ = ack.send(res);
                    return;
                }
            }
        }
    }

    /// Drains in FIFO order whatever remains in the channel (without blocking)
    /// and persists the pending `Event`s. Used by the `Shutdown` barrier to
    /// guarantee **orderly drain**: nothing already enqueued is lost just by
    /// closing. `Flush`/`Shutdown` messages left enqueued by concurrent calls
    /// receive their reply here, so no caller is left waiting for an ACK that
    /// never arrives.
    /// Returns how many messages were drained.
    fn drain_pending(rx: &mpsc::Receiver<WriteMsg>, conn: &Connection, last_error: &mut Option<String>) -> usize {
        let mut drained = 0usize;
        while let Ok(msg) = rx.try_recv() {
            drained += 1;
            match msg {
                WriteMsg::Event(event) => {
                    if let Err(e) = insert_event(conn, &event) {
                        tracing::error!("audit write error during shutdown drain: {e}");
                        *last_error = Some(e);
                    }
                }
                WriteMsg::Flush { ack } | WriteMsg::Shutdown { ack } => {
                    let res = last_error.take().map_or(Ok(()), Err);
                    let _ = ack.send(res);
                }
            }
        }
        drained
    }

    #[allow(clippy::needless_pass_by_value)]
    fn query_loop(rx: mpsc::Receiver<QueryMsg>, conn: Connection) {
        while let Ok(msg) = rx.recv() {
            match msg {
                QueryMsg::RecentEvents { limit, tx } => {
                    let _ = tx.send(query_recent_events(&conn, limit));
                }
                QueryMsg::EventCount { tx } => {
                    let _ = tx.send(query_count(&conn));
                }
            }
        }
    }

    /// Write an event asynchronously. **Never blocks**: pushes into a bounded
    /// channel (`DEFAULT_WRITE_CHANNEL_CAPACITY`). If the channel is full
    /// (a slow `SQLite` disk), the event is dropped and counted in
    /// [`Self::dropped_events`] — a slow disk cannot grow memory unbounded
    /// (fix review v5 #4). To guarantee durability (e.g. before shutdown),
    /// call [`Self::flush`] afterwards.
    #[allow(clippy::unused_async)]
    pub async fn write_event_async(&self, event: AuditEvent) -> WriteOutcome {
        // Register an in-flight write BEFORE looking at the state, with
        // `SeqCst` ordering on both sides: either this writer sees that the
        // store no longer accepts (and rejects), or `close()` sees
        // `inflight_writes > 0` and waits. Both never fail at once, so no
        // enqueued event is lost.
        self.inflight_writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let outcome = self.try_enqueue(event);
        self.inflight_writes.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        outcome
    }

    fn try_enqueue(&self, event: AuditEvent) -> WriteOutcome {
        // ATOMIC state gate (fix review v6.1): once shutdown has started, not
        // a single event more is accepted. Before, the `try_send` was still
        // attempted and the failure was counted as "backpressure", which
        // (a) made the queue potentially infinite during shutdown and
        // (b) produced a dishonest error ("slow disk") for what was really a
        // post-close write.
        if self.state.load(std::sync::atomic::Ordering::SeqCst) != state::ACCEPTING {
            let n = self
                .rejected_after_close
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            tracing::warn!(
                "audit store not accepting (state={}), event rejected (total rejected={n})",
                self.state_name(),
            );
            return WriteOutcome::RejectedClosed;
        }
        match self.write_tx.try_send(WriteMsg::Event(Box::new(event))) {
            Ok(()) => WriteOutcome::Queued,
            Err(mpsc::TrySendError::Full(_)) => {
                // Full channel (busy writer) → drop with counter.
                // Does not block the proxy hot path.
                let n = self.dropped_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                tracing::warn!("audit write channel full, event dropped (total dropped={n})");
                WriteOutcome::DroppedBackpressure
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                // The writer terminated (shutdown in progress or writer down):
                // this is NOT backpressure. Reported in its own category.
                let n = self
                    .rejected_after_close
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                tracing::warn!("audit writer gone, event rejected (total rejected={n})");
                WriteOutcome::RejectedClosed
            }
        }
    }

    /// Consumes the new drops (total - acknowledged) and marks them as
    /// reported. This way a successful flush after a previous flush Err due
    /// to PREVIOUS drops does not fail again (fix review v6 P1).
    #[must_use]
    fn consume_dropped(&self) -> u64 {
        let total = self.dropped_events.load(std::sync::atomic::Ordering::Relaxed);
        let acked = self
            .dropped_acknowledged
            .swap(total, std::sync::atomic::Ordering::Relaxed);
        total.saturating_sub(acked)
    }

    /// Same as [`Self::consume_dropped`] for events rejected after shutdown
    /// started.
    #[must_use]
    fn consume_rejected(&self) -> u64 {
        let total = self.rejected_after_close.load(std::sync::atomic::Ordering::Relaxed);
        let acked = self
            .rejected_acknowledged
            .swap(total, std::sync::atomic::Ordering::Relaxed);
        total.saturating_sub(acked)
    }

    /// Combines the writer result (durability) with the new drops consumed:
    /// if events were lost to backpressure OR the writer reported a
    /// persistence failure, the result is `Err` with all the reasons.
    fn finish_durability_ack(&self, ack: Result<(), String>, op: &str) -> Result<(), String> {
        let dropped = self.consume_dropped();
        let rejected = self.consume_rejected();
        let mut reason: Vec<String> = Vec::new();
        if dropped > 0 {
            reason.push(format!(
                "{dropped} audit event(s) lost to backpressure before {op} (bounded write channel)"
            ));
        }
        if rejected > 0 {
            reason.push(format!(
                "{rejected} audit event(s) rejected after close started before {op} (store state={})",
                self.state_name(),
            ));
        }
        if let Err(e) = ack {
            reason.push(e);
        }
        if reason.is_empty() {
            Ok(())
        } else {
            Err(reason.join("; "))
        }
    }

    /// Sends a barrier message to the writer (Flush/Shutdown) and waits for
    /// its ACK, the whole operation off the tokio executor
    /// (`spawn_blocking`): neither `send` (a bounded channel may be full) nor
    /// `recv_timeout` block an async worker.
    /// Returns the writer ack (Ok=previous persisted, Err=previous failure).
    async fn barrier_ack(&self, msg: WriteMsg, ack_rx: mpsc::Receiver<Result<(), String>>) -> Result<(), String> {
        self.barrier_ack_until(msg, ack_rx, Instant::now() + self.timeout).await
    }

    /// Waits (without blocking the executor) until no in-flight writes
    /// remain, or the deadline expires. Returns the ones left unfinished.
    async fn await_write_quiescence(&self, deadline: Instant) -> usize {
        loop {
            let inflight = self.inflight_writes.load(std::sync::atomic::Ordering::SeqCst);
            if inflight == 0 {
                return 0;
            }
            if Instant::now() >= deadline {
                tracing::warn!("store close: {inflight} write(s) still in flight at deadline");
                return inflight;
            }
            tokio::time::sleep(ENQUEUE_RETRY_BACKOFF).await;
        }
    }

    /// Same as [`Self::barrier_ack`] but with a deadline already in progress,
    /// so the `close()` timeout covers quiesce + enqueue + ACK.
    async fn barrier_ack_until(
        &self,
        msg: WriteMsg,
        ack_rx: mpsc::Receiver<Result<(), String>>,
        deadline: Instant,
    ) -> Result<(), String> {
        let tx = self.write_tx.clone();
        let op = match msg {
            WriteMsg::Shutdown { .. } => "close",
            _ => "flush",
        };
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            // A SINGLE deadline for the whole operation (fix review v6.1):
            // the blocking unbounded `send` could hang the shutdown forever
            // if the channel was full and the writer stalled. Now the enqueue
            // retries with `try_send` until the deadline, and the ACK only
            // has the remaining budget.
            let mut pending = msg;
            loop {
                match tx.try_send(pending) {
                    Ok(()) => break,
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        return Err("store channel closed (writer terminated)".to_string());
                    }
                    Err(mpsc::TrySendError::Full(msg)) => {
                        if Instant::now() >= deadline {
                            return Err(format!(
                                "store {op} timed out enqueueing the durability barrier (write channel full, writer stalled)"
                            ));
                        }
                        pending = msg;
                        std::thread::sleep(ENQUEUE_RETRY_BACKOFF);
                    }
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match ack_rx.recv_timeout(remaining) {
                Ok(res) => res,
                Err(mpsc::RecvTimeoutError::Disconnected) => Err("store channel closed (writer terminated)".to_string()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    Err(format!("store {op} timed out waiting for writer ACK"))
                }
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking failed: {e}"))?
    }

    /// Durability barrier: blocks until every event previously sent through
    /// [`Self::write_event_async`] has been persisted to `SQLite` by the writer
    /// thread. The hot path stays non-blocking; only this call awaits the ACK
    /// (with a timeout) off the tokio runtime.
    ///
    /// **Error propagation (fix review v4 #6):** if an `INSERT` failed while
    /// writing an event that is in the queue/being written BEFORE this flush,
    /// the ack is `Err` with the `SQLite` message — a flush no longer hides a
    /// previous persistence failure.
    ///
    /// **Drops by backpressure (fix review v6 P1):** after the barrier, if
    /// events were dropped due to a full channel since the last flush/close,
    /// returns `Err` indicating how many were lost — the hot path does not
    /// block but durability does NOT confirm success if there was loss.
    ///
    /// Returns `Err` if the writer channel is closed, the writer did not
    /// acknowledge within the timeout, a previous insert failed, or events
    /// were dropped to backpressure.
    pub async fn flush(&self) -> Result<(), String> {
        // `flush` is valid in `accepting` and in `closing` (writer alive).
        // Once the close barrier has been emitted, no more barriers are
        // emitted: the writer has already terminated or is terminating and a
        // `send` here would only produce an ACK that never arrives.
        let st = self.state.load(std::sync::atomic::Ordering::Acquire);
        if st >= state::SHUTDOWN_SENT {
            return self.finish_durability_ack(
                Err(format!(
                    "store already closed (state={}); flush cannot guarantee durability",
                    state::name(st)
                )),
                "flush",
            );
        }
        let (ack_tx, ack_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let ack = self.barrier_ack(WriteMsg::Flush { ack: ack_tx }, ack_rx).await;
        self.finish_durability_ack(ack, "flush")
    }

    /// Alias for [`Self::flush`] with explicit durability semantics +
    /// write-error propagation (fix review v4 #6). Used by the daemon during
    /// graceful shutdown.
    pub async fn flush_durable(&self) -> Result<(), String> {
        self.flush().await
    }

    /// Orderly shutdown of the writer thread. The ACK carries the last
    /// pending persistence error (fix review v5 #4): if the writer had to
    /// persist an event that failed, `close()` returns `Err` — it no longer
    /// confirms success when there is audit loss. Premature writer
    /// disconnection is also reported as `Err` (not as success).
    ///
    /// **Drops by backpressure (fix review v6 P1):** if events were dropped
    /// due to a full channel and not consumed by a previous flush, the close
    /// is NOT a clean success: returns `Err` with the number of lost events.
    ///
    /// Returns `Err` if the writer did not acknowledge within the timeout,
    /// there were pending persistence errors, or events were lost to
    /// backpressure.
    pub async fn close(&self) -> Result<(), String> {
        // Atomic transition to `shutdown-sent`: exactly ONE concurrent
        // `close` emits the close barrier; the rest fail honestly instead of
        // waiting for an ACK that another already consumed.
        // Before the barrier the store stops accepting events, so the queue
        // the writer must drain is finite.
        let deadline = Instant::now() + self.timeout;
        let mut cur = self.state.load(std::sync::atomic::Ordering::SeqCst);
        loop {
            if cur >= state::SHUTDOWN_SENT {
                return Err(format!("store close already invoked (state={})", state::name(cur)));
            }
            match self.state.compare_exchange_weak(
                cur,
                state::SHUTDOWN_SENT,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(observed) => cur = observed,
            }
        }

        // Quiesce: wait for writes that had already passed the gate to finish
        // their `try_send`. After this point no thread can enqueue anything
        // more, so the queue the writer will drain is final and the drain is
        // complete. The wait consumes from the SAME timeout budget (never
        // hangs).
        self.await_write_quiescence(deadline).await;

        let (ack_tx, ack_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let ack = self
            .barrier_ack_until(WriteMsg::Shutdown { ack: ack_tx }, ack_rx, deadline)
            .await;
        // The writer is gone (ACKed and exited, or the timeout expired and we
        // consider it lost): the final state is `closed` in both cases.
        self.state.store(state::CLOSED, std::sync::atomic::Ordering::Release);
        self.finish_durability_ack(ack, "store close")
    }

    /// Recent events (async). Note: reads what is already persisted; for a
    /// strict "write then read" guarantee call [`Self::flush`] first.
    pub async fn recent_events(&self, limit: usize) -> Vec<AuditEvent> {
        let (tx, rx) = mpsc::sync_channel(1);
        if self.query_tx.send(QueryMsg::RecentEvents { limit, tx }).is_err() {
            return Vec::new();
        }
        // Wait for the reply off the tokio runtime so this never blocks a worker.
        tokio::task::spawn_blocking(move || match rx.recv() {
            Ok(QueryResult::Events(e)) => e,
            Ok(QueryResult::Error(e)) => {
                tracing::error!("query error: {e}");
                Vec::new()
            }
            _ => Vec::new(),
        })
        .await
        .unwrap_or_default()
    }

    /// Total event count (async). Reads what is already persisted; combine
    /// with [`Self::flush`] for a durable barrier before asserting on counts.
    pub async fn event_count(&self) -> Result<usize, String> {
        let (tx, rx) = mpsc::sync_channel(1);
        if self.query_tx.send(QueryMsg::EventCount { tx }).is_err() {
            return Err("audit channel closed".to_string());
        }
        tokio::task::spawn_blocking(move || match rx.recv() {
            Ok(QueryResult::Count(c)) => Ok(c),
            Ok(QueryResult::Error(e)) => Err(e),
            _ => Err("count timeout".to_string()),
        })
        .await
        .map_err(|e| e.to_string())?
    }

    fn create_tables(conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_events (\
                id TEXT PRIMARY KEY, ts TEXT NOT NULL, mode TEXT NOT NULL, \
                tool TEXT NOT NULL, provider TEXT NOT NULL, \
                flags TEXT NOT NULL DEFAULT '[]', counts TEXT NOT NULL DEFAULT '{}', \
                action_taken TEXT NOT NULL, hashed_values TEXT NOT NULL DEFAULT '[]', \
                severity TEXT NOT NULL, ts_unix INTEGER NOT NULL); \
             CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts_unix); \
             CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action_taken); \
             CREATE INDEX IF NOT EXISTS idx_audit_provider ON audit_events(provider);",
        )
        .map_err(|e| format!("create tables error: {e}"))
    }
}

/// Persists an event. Returns the `SQLite` error message if the `INSERT`
/// fails (the writer retains it to propagate it in the next durability
/// barrier).
fn insert_event(conn: &Connection, event: &AuditEvent) -> Result<(), String> {
    let flags_json = serde_json::to_string(&event.flags).unwrap_or_default();
    let counts_json = serde_json::to_string(&event.counts).unwrap_or_default();
    let hashed_json = serde_json::to_string(&event.hashed_values).unwrap_or_default();

    conn.execute(
        "INSERT INTO audit_events (id,ts,mode,tool,provider,flags,counts,action_taken,hashed_values,severity,ts_unix) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        rusqlite::params![
            event.id,
            event.ts,
            event.mode,
            event.tool,
            event.provider,
            flags_json,
            counts_json,
            event.action_taken,
            hashed_json,
            event.severity,
            event.ts_unix,
        ],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[cfg(test)]
impl AuditStore {
    /// Test store whose writer is **stalled**: the channel receiver is
    /// parked on a thread that does not consume it until the returned
    /// `Sender` is released. Useful to verify that `flush`/`close` respect
    /// the timeout on the *enqueue* (full channel) and do not hang forever.
    fn with_stalled_writer(
        path: impl AsRef<std::path::Path>,
        channel_capacity: usize,
        timeout: Duration,
    ) -> Result<(Self, mpsc::Sender<()>), String> {
        let conn = Connection::open(path.as_ref()).map_err(|e| e.to_string())?;
        Self::create_tables(&conn)?;
        drop(conn);
        let reader_conn = Connection::open(path.as_ref()).map_err(|e| e.to_string())?;

        let (write_tx, write_rx) = mpsc::sync_channel::<WriteMsg>(channel_capacity);
        let (query_tx, query_rx) = mpsc::channel::<QueryMsg>();
        let (release_tx, release_rx) = mpsc::channel::<()>();

        let write_thread = std::thread::Builder::new()
            .name("cerberus-store-stalled-writer".to_string())
            .spawn(move || {
                // Never consumes `write_rx` until the test releases it.
                let _ = release_rx.recv();
                drop(write_rx);
            })
            .map_err(|e| e.to_string())?;
        let query_thread = std::thread::Builder::new()
            .name("cerberus-store-reader".to_string())
            .spawn(move || Self::query_loop(query_rx, reader_conn))
            .map_err(|e| e.to_string())?;

        Ok((
            Self {
                write_tx,
                query_tx,
                dropped_events: std::sync::atomic::AtomicU64::new(0),
                dropped_acknowledged: std::sync::atomic::AtomicU64::new(0),
                rejected_after_close: std::sync::atomic::AtomicU64::new(0),
                rejected_acknowledged: std::sync::atomic::AtomicU64::new(0),
                state: std::sync::atomic::AtomicU8::new(state::ACCEPTING),
                inflight_writes: std::sync::atomic::AtomicUsize::new(0),
                timeout,
                _write_thread: write_thread,
                _query_thread: query_thread,
            },
            release_tx,
        ))
    }
}

fn query_recent_events(conn: &Connection, limit: usize) -> QueryResult {
    let mut stmt = match conn
        .prepare("SELECT id, ts, mode, tool, provider, flags, counts, action_taken, hashed_values, severity, ts_unix FROM audit_events ORDER BY ts_unix DESC LIMIT ?1")
    {
        Ok(s) => s,
        Err(e) => return QueryResult::Error(e.to_string()),
    };
    let iter = match stmt.query_map([limit], |row| {
        let flags: String = row.get(5)?;
        let counts: String = row.get(6)?;
        let hashed: String = row.get(8)?;
        Ok(AuditEvent {
            id: row.get(0)?,
            ts: row.get(1)?,
            mode: row.get(2)?,
            tool: row.get(3)?,
            provider: row.get(4)?,
            flags: serde_json::from_str(&flags).unwrap_or_default(),
            counts: serde_json::from_str(&counts).unwrap_or_default(),
            action_taken: row.get(7)?,
            hashed_values: serde_json::from_str(&hashed).unwrap_or_default(),
            severity: row.get(9)?,
            ts_unix: row.get(10)?,
        })
    }) {
        Ok(i) => i,
        Err(e) => return QueryResult::Error(e.to_string()),
    };
    let mut out = Vec::new();
    for row in iter {
        match row {
            Ok(ev) => out.push(ev),
            Err(e) => return QueryResult::Error(e.to_string()),
        }
    }
    QueryResult::Events(out)
}

fn query_count(conn: &Connection) -> QueryResult {
    match conn.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r.get::<_, usize>(0)) {
        Ok(c) => QueryResult::Count(c),
        Err(e) => QueryResult::Error(e.to_string()),
    }
}

/// Delete events whose `ts_unix` is older than `retention_days`; returns the
/// number of rows removed. With `retention_days = 0` only strictly-future
/// events survive the purge.
fn purge_old(conn: &Connection, retention_days: u64) -> usize {
    let now = chrono::Utc::now().timestamp();
    let days = i64::try_from(retention_days).unwrap_or(0);
    let cutoff = days
        .checked_mul(86_400)
        .and_then(|secs| now.checked_sub(secs))
        .unwrap_or(now);
    match conn.execute("DELETE FROM audit_events WHERE ts_unix < ?1", [cutoff]) {
        Ok(n) => n,
        Err(e) => {
            tracing::error!("audit retention purge error: {e}");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AuditEvent;
    use tempfile::TempDir;

    fn temp_db() -> TempDir {
        TempDir::new().expect("tmp")
    }

    fn make_event(id: &str, action: &str, ts_unix: i64) -> AuditEvent {
        AuditEvent {
            id: id.to_string(),
            ts: "2026-08-20T00:00:00Z".to_string(),
            mode: "local".to_string(),
            tool: "proxy".to_string(),
            provider: "openai".to_string(),
            flags: vec!["secret.openai_api_key".to_string()],
            counts: std::collections::HashMap::new(),
            action_taken: action.to_string(),
            hashed_values: vec!["sha256:deadbeef".to_string()],
            severity: "critical".to_string(),
            ts_unix,
        }
    }

    fn insert_row(conn: &Connection, event: &AuditEvent) {
        conn.execute(
            "INSERT INTO audit_events (id,ts,mode,tool,provider,flags,counts,action_taken,hashed_values,severity,ts_unix) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params![
                event.id, event.ts, event.mode, event.tool, event.provider,
                serde_json::to_string(&event.flags).expect("flags"),
                serde_json::to_string(&event.counts).expect("counts"),
                event.action_taken,
                serde_json::to_string(&event.hashed_values).expect("hashes"),
                event.severity, event.ts_unix,
            ],
        )
        .expect("insert row");
    }

    #[test]
    fn store_round_trip() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let ev = make_event("evt_1", "block", 1_700_000_050);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(store.write_event_async(ev));
        rt.block_on(store.flush()).expect("flush durable");
        let events = rt.block_on(store.recent_events(10));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt_1");
        assert_eq!(rt.block_on(store.event_count()).expect("count"), 1);
    }

    #[test]
    fn store_orders_by_time_desc() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let ev1 = make_event("evt_a", "warn", 1_700_000_000);
        let ev2 = make_event("evt_b", "block", 1_700_000_001);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(store.write_event_async(ev1));
        rt.block_on(store.write_event_async(ev2));
        rt.block_on(store.flush()).expect("flush");
        let events = rt.block_on(store.recent_events(10));
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, "evt_b");
    }

    #[test]
    fn flush_is_durability_barrier_for_all_pending_writes() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let start = chrono::Utc::now().timestamp();
        let n: usize = 7;
        let rt = tokio::runtime::Runtime::new().unwrap();
        for i in 0..n {
            let ts = start + i64::try_from(i).unwrap();
            let ev = make_event(&format!("evt_{i}"), "warn", ts);
            rt.block_on(store.write_event_async(ev));
        }
        rt.block_on(store.flush()).expect("durable barrier");

        let events = rt.block_on(store.recent_events(100));
        assert_eq!(events.len(), n);
        let ids: Vec<String> = events.iter().map(|e| e.id.clone()).collect();
        for i in 0..n {
            assert!(ids.contains(&format!("evt_{i}")));
        }
        // Contiguous in ts: DESC order by ts_unix.
        let ts: Vec<i64> = events.iter().map(|e| e.ts_unix).collect();
        assert!(ts.windows(2).all(|w| w[0] >= w[1]));
        assert_eq!(rt.block_on(store.event_count()).expect("count"), n);
    }

    #[test]
    fn open_purges_events_older_than_retention() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        {
            let conn = Connection::open(&path).expect("db");
            AuditStore::create_tables(&conn).expect("tables");
            // Very old ts_unix (≥90 days of default retention).
            insert_row(&conn, &make_event("evt_old", "block", 1_000_000_000));
            insert_row(&conn, &make_event("evt_new", "warn", chrono::Utc::now().timestamp()));
        }
        let store = AuditStore::open(&path).expect("open store");
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert_eq!(rt.block_on(store.event_count()).expect("count"), 1);
        let events = rt.block_on(store.recent_events(10));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt_new");
        assert!(!events.iter().any(|e| e.id == "evt_old"));
    }

    #[test]
    fn open_with_zero_retention_purges_all_stale_events() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let now = chrono::Utc::now().timestamp();
        {
            let conn = Connection::open(&path).expect("db");
            AuditStore::create_tables(&conn).expect("tables");
            // Recent past (1 h ago) and future (1 h ahead): cutoff = now.
            insert_row(&conn, &make_event("evt_past", "warn", now - 3_600));
            insert_row(&conn, &make_event("evt_future", "warn", now + 3_600));
        }
        let store = AuditStore::open_with(&path, 0).expect("open store");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let events = rt.block_on(store.recent_events(10));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt_future");
        assert!(!events.iter().any(|e| e.id == "evt_past"));
    }

    // ─── Fix code review v4 #6: flush propagates INSERT errors ─────────────

    /// A deterministic `INSERT` failure happens when the `id` (`PRIMARY KEY`)
    /// already exists. The subsequent flush must return `Err` with the
    /// `SQLite` message instead of hiding a previous persistence failure.
    #[test]
    fn flush_reports_prev_insert_failure() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let rt = tokio::runtime::Runtime::new().unwrap();

        let ev = make_event("evt_twin", "block", 1_700_000_100);
        rt.block_on(store.write_event_async(ev));
        rt.block_on(store.flush()).expect("first write durable");
        assert_eq!(rt.block_on(store.event_count()).expect("count"), 1);

        // Second event with the SAME id → the writer's INSERT fails.
        let dup = make_event("evt_twin", "block", 1_700_000_101);
        rt.block_on(store.write_event_async(dup));

        let err = rt
            .block_on(store.flush())
            .expect_err("flush must propagate the INSERT error");
        assert!(
            err.contains("UNIQUE") || err.contains("constraint"),
            "expected a SQLite constraint error, got: {err}"
        );

        // The error was consumed: the next flush (with no new failures) passes.
        rt.block_on(store.flush()).expect("flush with no later failures");
    }

    // ─── Fix review v4 #6b: close() stops the writer orderly ─────────

    #[test]
    fn close_stops_writer_and_fails_subsequent_writes() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(store.write_event_async(make_event("evt_c1", "warn", 1_700_000_200)));
        rt.block_on(store.flush()).expect("durable");
        assert_eq!(rt.block_on(store.event_count()).expect("count"), 1);

        rt.block_on(store.close()).expect("graceful close");

        // The store no longer accepts events and says so honestly: the event
        // is counted as REJECTED post-close (not as disk backpressure) and
        // the subsequent flush fails explaining that the store is closed.
        assert!(!store.is_accepting());
        assert_eq!(store.state_name(), "closed");
        rt.block_on(store.write_event_async(make_event("evt_c2", "warn", 1_700_000_201)));
        assert_eq!(store.rejected_after_close(), 1);
        assert_eq!(store.dropped_events(), 0, "a post-close rejection is not backpressure");
        let err = rt.block_on(store.flush()).expect_err("flush after close must fail");
        assert!(err.contains("store already closed"), "got: {err}");
        assert!(err.contains("1 audit event(s) rejected after close"), "got: {err}");

        // A second close does not emit a barrier again: it fails honestly.
        let err2 = rt.block_on(store.close()).expect_err("idempotent close must report");
        assert!(err2.contains("close already invoked"), "got: {err2}");

        // The query thread still reads what was already persisted before close.
        let events = rt.block_on(store.recent_events(10));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt_c1");
    }

    // ─── Fix review v6 P1: backpressure drops in durability ────────────

    #[test]
    fn flush_reports_dropped_events() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let rt = tokio::runtime::Runtime::new().unwrap();

        // No drops: flush is a clean success.
        rt.block_on(store.flush()).expect("clean flush with no drops");

        // Simulate events lost to backpressure (full channel) by bumping the
        // counter directly — deterministic path.
        store.dropped_events.fetch_add(3, std::sync::atomic::Ordering::Relaxed);

        let err = rt.block_on(store.flush()).expect_err("flush must report drops");
        assert!(err.contains("3 audit event(s) lost to backpressure"), "got: {err}");

        // Drops consumed: a subsequent flush with no new drops goes back to Ok.
        rt.block_on(store.flush())
            .expect("flush with no new drops does not fail again");
    }

    // ─── Fix review v6.1: atomic shutdown, orderly drain, no hangs ──

    /// Shutdown CONCURRENT with active writers. Strong invariant: everything
    /// the store accepted (`WriteOutcome::Queued`) ends up persisted, and
    /// every counted attempt falls into exactly one honest category
    /// (enqueued / backpressure / rejected post-close). Nothing is silently
    /// lost and the close does not hang.
    #[test]
    fn concurrent_shutdown_with_active_writers_persists_everything_accepted() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;

        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        // Small capacity on purpose: forces real backpressure.
        let store = Arc::new(AuditStore::open_with_capacity(&path, 90, 32).expect("open store"));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();

        let attempted = Arc::new(AtomicUsize::new(0));
        let queued = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));
        let keep_going = Arc::new(AtomicBool::new(true));

        let writers: Vec<_> = (0..4)
            .map(|w| {
                let store = Arc::clone(&store);
                let (attempted, queued) = (Arc::clone(&attempted), Arc::clone(&queued));
                let (dropped, rejected) = (Arc::clone(&dropped), Arc::clone(&rejected));
                let keep_going = Arc::clone(&keep_going);
                rt.spawn(async move {
                    let mut i = 0i64;
                    while keep_going.load(SeqCst) && i < 400 {
                        let ev = make_event(&format!("evt_w{w}_{i}"), "warn", 1_700_000_000 + i);
                        let outcome = store.write_event_async(ev).await;
                        attempted.fetch_add(1, SeqCst);
                        match outcome {
                            WriteOutcome::Queued => queued.fetch_add(1, SeqCst),
                            WriteOutcome::DroppedBackpressure => dropped.fetch_add(1, SeqCst),
                            WriteOutcome::RejectedClosed => rejected.fetch_add(1, SeqCst),
                        };
                        i += 1;
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();

        // Orderly close WHILE writers keep pushing events.
        let (flush_res, close_res) = rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(store.begin_closing(), "first transition accepting → closing");
            assert!(!store.is_accepting(), "after begin_closing no events are accepted");
            assert_eq!(store.state_name(), "closing");
            assert!(!store.begin_closing(), "begin_closing does not repeat");
            let f = store.flush().await;
            let c = store.close().await;
            (f, c)
        });

        keep_going.store(false, SeqCst);
        for h in writers {
            rt.block_on(h).expect("writer task must not panic");
        }

        assert_eq!(store.state_name(), "closed");

        // Every post-close write is rejected (not backpressure).
        let post = rt.block_on(store.write_event_async(make_event("evt_post", "warn", 1)));
        assert_eq!(post, WriteOutcome::RejectedClosed);

        // Exhaustive accounting: every attempt has exactly one destination.
        let (a, q, d, r) = (
            attempted.load(SeqCst),
            queued.load(SeqCst),
            dropped.load(SeqCst),
            rejected.load(SeqCst),
        );
        assert_eq!(a, q + d + r, "every attempt falls into a single category");
        assert!(q > 0, "some event must have been enqueued");
        assert_eq!(
            store.dropped_events(),
            d as u64,
            "the backpressure counter matches the outcomes"
        );
        assert!(store.rejected_after_close() >= r as u64);

        // ORDERLY DRAIN: everything accepted is in SQLite.
        let persisted = rt.block_on(store.event_count()).expect("count");
        assert_eq!(persisted, q, "every accepted event must persist after close()");

        // HONEST errors: if there was loss, neither flush nor close hides it.
        if d > 0 || r > 0 {
            assert!(
                flush_res.is_err() || close_res.is_err(),
                "with loss ({d} drops, {r} rejections) the close cannot report a clean success"
            );
        }
        for res in [&flush_res, &close_res] {
            if let Err(e) = res {
                assert!(
                    e.contains("backpressure") || e.contains("rejected after close"),
                    "the error must explain the real loss, got: {e}"
                );
            }
        }
    }

    /// FULL channel with a stalled writer: neither `flush` nor `close` may
    /// hang. The timeout also covers the *enqueue* of the barrier (before,
    /// the blocking unbounded `send` → shutdown hung forever).
    #[test]
    fn full_channel_with_stalled_writer_times_out_instead_of_hanging() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let timeout = Duration::from_millis(150);
        let (store, release) = AuditStore::with_stalled_writer(&path, 1, timeout).expect("store with stalled writer");
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Capacity 1: the first event fills the channel, the second is dropped.
        assert_eq!(
            rt.block_on(store.write_event_async(make_event("evt_s1", "warn", 1_700_000_300))),
            WriteOutcome::Queued
        );
        assert_eq!(
            rt.block_on(store.write_event_async(make_event("evt_s2", "warn", 1_700_000_301))),
            WriteOutcome::DroppedBackpressure
        );

        // flush: the barrier enqueue never fits → timeout, not a hang.
        let started = Instant::now();
        let err = rt.block_on(store.flush()).expect_err("flush must not hang");
        let elapsed = started.elapsed();
        assert!(
            err.contains("timed out enqueueing the durability barrier"),
            "got: {err}"
        );
        assert!(err.contains("1 audit event(s) lost to backpressure"), "got: {err}");
        assert!(elapsed >= timeout, "must respect the deadline, took {elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "took too long: {elapsed:?}");

        // close: same budget, same behavior; the state ends up closed even
        // though the writer never ACKs (no more events are accepted).
        let started = Instant::now();
        let err = rt.block_on(store.close()).expect_err("close must not hang");
        assert!(err.contains("timed out"), "got: {err}");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(store.state_name(), "closed");
        assert_eq!(
            rt.block_on(store.write_event_async(make_event("evt_s3", "warn", 1_700_000_302))),
            WriteOutcome::RejectedClosed
        );

        drop(release);
    }

    #[test]
    fn close_reports_dropped_events() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let rt = tokio::runtime::Runtime::new().unwrap();

        store.dropped_events.fetch_add(2, std::sync::atomic::Ordering::Relaxed);

        let err = rt
            .block_on(store.close())
            .expect_err("a close with drops is NOT a clean success");
        assert!(err.contains("2 audit event(s) lost to backpressure"), "got: {err}");
    }
}
