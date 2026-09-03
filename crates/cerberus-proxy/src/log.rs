//! Logging for the proxy — no secrets in the logs, and never a synchronous
//! write on the request hot path (R9-10 / F5.1).
//!
//! ## Architecture (F5.1 — non-blocking logging)
//!
//! Raw values of secrets/PII are never logged. Only flags, categories,
//! counts and hashes (which are already keyed HMAC-SHA256 hashes produced by
//! the detection engine) are recorded.
//!
//! The hot path emits events through `tracing` into a **bounded, lossy,
//! off-thread writer** (`NonBlockingWriter`): an event handler only executes
//! a `try_send` of the formatted chunk into an 8,192-entry `SyncSender`
//! queue and returns. A single worker thread owns the console sink
//! (`stdout`), writes queued chunks, flushes periodically, and emits an
//! aggregated, content-free dropped-writes notice at most every 30 s. When
//! the queue is full the write is **dropped and counted** (lossy) — the
//! request continues inside its latency budget, never blocked by a slow
//! pipe or log redirect.
//!
//! This is the `WorkerGuard` pattern (the same contract
//! `tracing_appender::non_blocking` + `WorkerGuard` provides), implemented
//! over `std` because the dependency tree had no `tracing-appender` and the
//! unit additionally requires an aggregated dropped-writes counter, which
//! the crate does not expose.
//!
//! Shutdown: [`init_logging`] returns a [`LogGuard`] that MUST be held for
//! the whole process lifetime (the CLI `main` owns it). Dropping it sends a
//! shutdown marker; the worker drains the remaining queue (bounded by
//! [`DRAIN_DEADLINE`]) and performs a final flush before exiting, so a
//! graceful daemon shutdown loses no queued log lines. The wait itself is
//! bounded: a pathologically blocked sink can never hang the shutdown.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cerberus_engine::engine::Finding;
use cerberus_engine::rule::Action;
use tracing::Level;

/// Bounded queue capacity (chunks). Bounded so a saturated consumer can
/// never grow memory nor block producers (F5.1: "cola bounded y modo lossy").
const QUEUE_CAPACITY: usize = 8_192;
/// How often the idle worker flushes the sink and evaluates the drop notice.
const WORKER_TICK: Duration = Duration::from_millis(100);
/// Upper bound for the shutdown drain-and-flush (graceful, not unbounded).
const DRAIN_DEADLINE: Duration = Duration::from_secs(2);
/// Minimum interval between aggregated dropped-writes notices.
const DROP_NOTICE_INTERVAL: Duration = Duration::from_secs(30);

/// Log level for security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEvent {
    /// Blocked request.
    Blocked,
    /// Redacted request.
    Redacted,
    /// Warning (something was detected but let through).
    Warned,
    /// Bypass (break-glass used).
    Bypassed,
    /// REDACTION FAILED and the fail policy decided the outcome: the raw
    /// original was forwarded (fail-open) or the request rejected
    /// (fail-closed). Never recorded as a plain "redacted" (fix P2-2).
    RedactFailed,
    /// Clean request.
    Clean,
}

impl SecurityEvent {
    const fn level(self) -> Level {
        match self {
            Self::Blocked | Self::Bypassed | Self::RedactFailed => Level::WARN,
            Self::Redacted | Self::Warned => Level::INFO,
            Self::Clean => Level::DEBUG,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Blocked => "request blocked by Cerberus",
            Self::Redacted => "request redacted by Cerberus",
            Self::Warned => "request warned by Cerberus",
            Self::Bypassed => "request bypassed (break-glass) by Cerberus",
            Self::RedactFailed => "request REDACTION FAILED — fail policy decided the outcome (raw original forwarded on fail-open; request rejected on fail-closed)",
            Self::Clean => "request clean — no secrets detected",
        }
    }
}

/// Log a security event.
///
/// Never contains raw secret values. Only flags, categories, counts and
/// hashes.
///
/// F5.1: when the event level is disabled by the active filter, this returns
/// BEFORE building the flags/categories/hashes vectors — disabled levels
/// cost one callsite check, zero allocations. The event itself is emitted
/// into the non-blocking writer ([`NonBlockingWriter`]), so even an enabled
/// event never performs a synchronous console write on the hot path.
pub fn log_security_event(event: SecurityEvent, findings: &[Finding], action_taken: Action) {
    // F5.1: consult the callsite filter BEFORE building the field vectors —
    // a disabled level costs one filter check, zero allocations.
    let enabled = match event.level() {
        Level::WARN => tracing::enabled!(Level::WARN),
        Level::INFO => tracing::enabled!(Level::INFO),
        _ => tracing::enabled!(Level::DEBUG),
    };
    if !enabled {
        return;
    }
    let flags: Vec<&str> = findings.iter().map(|f| f.flag.as_str()).collect();
    let categories: Vec<String> = findings.iter().map(|f| f.category.to_string()).collect();
    let hashes: Vec<&str> = findings.iter().map(|f| f.hashed_value.as_str()).collect();

    let msg = event.message();
    match event.level() {
        Level::WARN => {
            tracing::warn!(event_type = msg, action_taken = %action_taken, finding_count = findings.len(), flags = ?flags, categories = ?categories, hashes = ?hashes);
        }
        Level::INFO => {
            tracing::info!(event_type = msg, action_taken = %action_taken, finding_count = findings.len(), flags = ?flags, categories = ?categories, hashes = ?hashes);
        }
        _ => {
            tracing::debug!(event_type = msg, action_taken = %action_taken, finding_count = findings.len(), flags = ?flags, categories = ?categories, hashes = ?hashes);
        }
    }
}

/// One queued item: a formatted chunk, or the shutdown marker.
enum Message {
    Chunk(Vec<u8>),
    Shutdown,
}

/// Cloneable producer half of the non-blocking writer.
///
/// Implements [`io::Write`]: `write` never blocks on the sink — it either
/// enqueues the chunk (`try_send` into the bounded queue) or, when the queue
/// is full, drops the chunk and increments the aggregated dropped counter
/// (lossy mode; the notice carries counts only, never content).
#[derive(Clone)]
struct NonBlockingWriter {
    tx: Arc<SyncSender<Message>>,
    dropped: Arc<AtomicU64>,
}

impl NonBlockingWriter {
    const fn new(tx: Arc<SyncSender<Message>>, dropped: Arc<AtomicU64>) -> Self {
        Self { tx, dropped }
    }
}

impl io::Write for NonBlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.tx.try_send(Message::Chunk(buf.to_vec())) {
            // Enqueued, or the worker is already gone (drop silently): the
            // caller's contract (bytes "written") holds either way.
            Ok(()) | Err(TrySendError::Disconnected(_)) => Ok(buf.len()),
            // Lossy: full queue → drop the chunk, count it. The hot path
            // NEVER blocks or errors on logging.
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(buf.len())
            }
        }
    }

    /// Ordering/flushing is owned by the single worker thread; producers
    /// have nothing to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Shutdown handle for the non-blocking logging worker.
///
/// Held for the whole process lifetime (CLI `main`). Dropping it:
/// 1. sends the shutdown marker,
/// 2. waits (bounded by [`DRAIN_DEADLINE`]) for the worker to drain the
///    remaining queue and flush the sink — no log loss on graceful shutdown.
pub struct LogGuard {
    tx: Arc<SyncSender<Message>>,
    done: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
}

impl LogGuard {
    /// Number of log chunks dropped because the bounded queue was full
    /// (aggregated, lossy mode). Counts only — no content, no secrets.
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        // Best-effort shutdown marker: if the queue is momentarily full the
        // retry gives the worker a fair chance to see it.
        for _ in 0..3 {
            match self.tx.try_send(Message::Shutdown) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => break,
                Err(TrySendError::Full(_)) => std::thread::sleep(WORKER_TICK),
            }
        }
        // Bounded wait for the drain+flush to complete. If the sink is
        // pathologically blocked, the worker's own drain deadline still
        // bounds it and we detach — shutdown must never hang on logging.
        let deadline = Instant::now() + DRAIN_DEADLINE;
        while !self.done.load(Ordering::Relaxed) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Spawn the logging worker over an explicit sink (test-visible core of
/// [`init_logging`], no global subscriber involved).
fn spawn_worker(sink: Box<dyn io::Write + Send>) -> (NonBlockingWriter, LogGuard) {
    let (tx, rx) = sync_channel::<Message>(QUEUE_CAPACITY);
    let tx = Arc::new(tx);
    let dropped = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));

    let worker_dropped = Arc::clone(&dropped);
    let worker_done = Arc::clone(&done);
    let handle = std::thread::Builder::new()
        .name("cerberus-log-worker".to_string())
        .spawn(move || worker_loop(sink, rx, worker_dropped, worker_done))
        .expect("spawn cerberus-log-worker");

    let writer = NonBlockingWriter::new(Arc::clone(&tx), Arc::clone(&dropped));
    let guard = LogGuard { tx, done, dropped };
    let _ = handle; // the worker exits on Shutdown; the guard bounds it
    (writer, guard)
}

/// The logging worker: the ONLY thread that ever writes to the sink.
/// Thread-entry signature takes ownership by design (`std::thread::spawn`
/// requires `'static`).
#[allow(clippy::needless_pass_by_value)]
fn worker_loop(
    mut sink: Box<dyn io::Write + Send>,
    rx: Receiver<Message>,
    dropped: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
) {
    let mut last_notice = Instant::now();
    let mut reported: u64 = 0;
    loop {
        match rx.recv_timeout(WORKER_TICK) {
            Ok(Message::Chunk(chunk)) => {
                let _ = sink.write_all(&chunk);
            }
            // Shutdown marker, or all producers gone without one (e.g. a
            // leaked guard clone): drain and exit exactly like a shutdown.
            Ok(Message::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {
                let _ = sink.flush();
                maybe_report_drops(&mut sink, &dropped, &mut reported, &mut last_notice);
            }
        }
    }
    // Bounded shutdown drain: everything already queued is written out
    // (graceful flush), unless the deadline expires — then the remainder is
    // accounted as dropped. Final flush, mark done.
    let deadline = Instant::now() + DRAIN_DEADLINE;
    while let Ok(Message::Chunk(chunk)) = rx.try_recv() {
        if Instant::now() >= deadline {
            dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = sink.write_all(&chunk);
        }
    }
    let _ = sink.flush();
    done.store(true, Ordering::Relaxed);
}

/// Emit the aggregated dropped-writes notice (counts only, no content —
/// F5.1: "Contador/aviso agregado de mensajes descartados, sin secretos"),
/// rate-limited to one notice per [`DROP_NOTICE_INTERVAL`].
fn maybe_report_drops(
    sink: &mut Box<dyn io::Write + Send>,
    dropped: &AtomicU64,
    reported: &mut u64,
    last_notice: &mut Instant,
) {
    let total = dropped.load(Ordering::Relaxed);
    if total == *reported || last_notice.elapsed() < DROP_NOTICE_INTERVAL {
        return;
    }
    let pending = total - *reported;
    *reported = total;
    *last_notice = Instant::now();
    let notice = format!(
        "cerberus logging: {pending} log write(s) dropped since last notice ({total} total) — bounded queue full; counts only, no content in this notice\n"
    );
    // Written by the worker itself: off the hot path by construction.
    let _ = sink.write_all(notice.as_bytes());
    let _ = sink.flush();
}

/// Size cap for the daemon log file before a single rotation to `.1`
/// (F6.B Appendix B B.5: `cerberus logs`). Bounded so a runaway daemon can
/// never fill the disk with logs.
pub const LOG_FILE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Daemon log tee path (F6.B, B.5): set BEFORE [`init_logging`] by
/// `cerberus start` so the subscriber's worker sink also writes the file.
/// Read exactly once, when the logging worker constructs its sink.
static LOG_TEE_FILE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Request that the logging worker tees every formatted chunk to `path`.
///
/// Must be called BEFORE [`init_logging`]. Appends with a single rotation
/// to `<path>.1` at [`LOG_FILE_MAX_BYTES`]. Returns `false` when the parent
/// directory cannot be created (the caller prints a console-only warning);
/// the file open itself stays best-effort at sink construction.
#[must_use]
pub fn set_log_tee_file(path: &std::path::Path) -> bool {
    if let Some(dir) = path.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return false;
        }
    }
    LOG_TEE_FILE.set(path.to_path_buf()).is_ok()
}

/// Tee sink: every formatted chunk goes to the console AND (best-effort)
/// to the daemon log file. All writes stay on the single logging worker
/// thread (never on the request hot path).
struct TeeSink {
    console: Box<dyn io::Write + Send>,
    file: Option<std::fs::File>,
    path: Option<std::path::PathBuf>,
    size: u64,
    cap: u64,
}

/// The log file is created with mode **0600** (F6.B attempt 2, security
/// P3-1): the tee is designed secret-free (flags/categories/keyed hashes
/// only), but the repo's credential-file discipline for everything under
/// `.cerberus/` is 0600 — defense-in-depth, same rule as the config writes.
/// `mode()` only applies AT CREATION on unix; appends to an existing file
/// keep its mode (a pre-existing file is not silently re-chowned).
fn open_log_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new().create(true).append(true).open(path)
    }
}

impl TeeSink {
    /// Build the sink for the requested tee path (console-only file sink if
    /// the file cannot be opened). Reads the current size so rotation
    /// resumes at the right threshold.
    fn open(path: &std::path::Path) -> Self {
        let file = open_log_file(path).ok();
        let size = file.as_ref().and_then(|f| f.metadata().ok()).map_or(0, |m| m.len());
        Self {
            console: Box::new(io::stdout()),
            file,
            path: Some(path.to_path_buf()),
            size,
            cap: LOG_FILE_MAX_BYTES,
        }
    }

    /// One-shot rotation when the cap is exceeded: current file is renamed
    /// to `<path>.1` (overwriting any previous rotation) and a fresh file
    /// is opened. Best-effort: any failure just truncates in place —
    /// logging MUST never fail the request path.
    fn maybe_rotate(&mut self) {
        let Some(path) = self.path.clone() else { return };
        if self.size <= self.cap {
            return;
        }
        let _ = self.file.take(); // close before renaming
        let rotated = path.with_extension("log.1");
        let _ = std::fs::rename(&path, &rotated);
        self.file = open_log_file(&path).ok();
        self.size = 0;
    }
}

impl io::Write for TeeSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _ = self.console.write_all(buf);
        if let Some(file) = self.file.as_mut() {
            if file.write_all(buf).is_ok() {
                self.size += buf.len() as u64;
                self.maybe_rotate();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let _ = self.console.flush();
        if let Some(file) = self.file.as_mut() {
            let _ = file.flush();
        }
        Ok(())
    }
}

/// Initialize the global logger with format and filter — NON-BLOCKING.
///
/// The `tracing` subscriber writes into [`NonBlockingWriter`]; the returned
/// [`LogGuard`] must be held for the process lifetime and dropped on
/// shutdown (bounded flush — see [`LogGuard`]).
///
/// Calling this after a global subscriber is already installed keeps the
/// existing subscriber and still returns a live guard (the worker drains
/// cleanly on drop). If [`set_log_tee_file`] was called first, the worker
/// ALSO tees to the daemon log file (F6.B B.5).
#[must_use]
pub fn init_logging(log_level: &str) -> LogGuard {
    let sink: Box<dyn io::Write + Send> = match LOG_TEE_FILE.get() {
        Some(path) => Box::new(TeeSink::open(path)),
        None => Box::new(io::stdout()),
    };
    let (writer, guard) = spawn_worker(sink);
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .with_writer(move || writer.clone());
    // Ignore "already set" (e.g. a test harness installed one first): the
    // guard is still valid and shuts the worker down cleanly.
    let _ = subscriber.try_init();
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::rule::{Action, Category, Severity};
    use std::io::Write as _;
    use std::sync::Mutex;

    fn make_finding(flag: &str, action: Action) -> Finding {
        Finding {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action,
            start: 0,
            end: 5,
            hashed_value: "hmac:test".to_string(),
        }
    }

    #[test]
    fn security_event_levels() {
        assert_eq!(SecurityEvent::Blocked.level(), Level::WARN);
        assert_eq!(SecurityEvent::Redacted.level(), Level::INFO);
        assert_eq!(SecurityEvent::Warned.level(), Level::INFO);
        assert_eq!(SecurityEvent::Bypassed.level(), Level::WARN);
        assert_eq!(SecurityEvent::RedactFailed.level(), Level::WARN);
        assert_eq!(SecurityEvent::Clean.level(), Level::DEBUG);
    }

    #[test]
    fn security_event_messages() {
        assert!(SecurityEvent::Blocked.message().contains("blocked"));
        assert!(SecurityEvent::Redacted.message().contains("redacted"));
        assert!(SecurityEvent::Clean.message().contains("clean"));
        // Fix P2-2: the redaction-failure event can never be confused with a
        // successful redaction.
        assert!(SecurityEvent::RedactFailed.message().contains("REDACTION FAILED"));
    }

    #[test]
    fn log_security_event_no_panic() {
        let findings = vec![make_finding("test.flag", Action::Block)];
        log_security_event(SecurityEvent::Blocked, &findings, Action::Block);
    }

    // ─── F5.1: non-blocking writer behavior ────────────────────────────────

    /// In-memory sink shared with the test.
    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl io::Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Worker + guard over a shared in-memory sink.
    fn spawn_into_sink(sink: SharedSink) -> (NonBlockingWriter, LogGuard, SharedSink) {
        let (writer, guard) = spawn_worker(Box::new(sink.clone()));
        (writer, guard, sink)
    }

    /// Wait (bounded) until `needle` appears in the sink.
    fn wait_for(sink: &SharedSink, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let buf = sink.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
            if let Ok(s) = String::from_utf8(buf) {
                if s.contains(needle) {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn worker_writes_queued_chunks_off_thread() {
        let (mut writer, guard, sink) = spawn_into_sink(SharedSink::default());
        writer.write_all(b"queued-line-1\n").expect("write");
        assert!(
            wait_for(&sink, "queued-line-1", Duration::from_secs(2)),
            "worker must deliver the queued chunk"
        );
        drop(guard);
    }

    #[test]
    fn guard_drop_flushes_all_queued_chunks_no_loss_on_shutdown() {
        let (mut writer, guard, sink) = spawn_into_sink(SharedSink::default());
        // Queue several chunks and drop the guard immediately: the bounded
        // shutdown drain must deliver ALL of them (no loss on graceful
        // shutdown).
        for i in 0..50 {
            writer
                .write_all(format!("flush-on-drop-{i}\n").as_bytes())
                .expect("write");
        }
        drop(guard);
        let buf = sink.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
        let text = String::from_utf8(buf).expect("utf8");
        for i in 0..50 {
            assert!(
                text.contains(&format!("flush-on-drop-{i}\n")),
                "lost chunk {i} on shutdown flush"
            );
        }
    }

    #[test]
    fn full_queue_drops_and_counts_instead_of_blocking() {
        // Deterministic saturation: the sink is blocked (its release token
        // is held by the test), so the worker can never drain — the queue
        // fills and stays full. Writes must return promptly (lossy) and the
        // dropped counter must grow. This is the property that keeps the hot
        // path inside its latency budget.
        struct BlockingSink(std::sync::mpsc::Receiver<()>);
        impl io::Write for BlockingSink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                // Blocks until the test drops the release sender.
                let _ = self.0.recv();
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (writer, guard) = spawn_worker(Box::new(BlockingSink(release_rx)));
        let mut writer = writer;
        let started = Instant::now();
        let payload = vec![b'x'; 64];
        for _ in 0..(QUEUE_CAPACITY * 4) {
            let _ = io::Write::write(&mut writer, &payload).expect("write never fails");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "saturated queue must not block the caller (took {elapsed:?})"
        );
        assert!(guard.dropped_count() > 0, "lossy mode must count dropped writes");
        // Release the sink, then drop the guard: the bounded shutdown wait
        // (DRAIN_DEADLINE) covers the drain of what fits.
        drop(release_tx);
        drop(guard);
    }

    #[test]
    fn blocked_sink_does_not_block_the_producer() {
        // A sink whose write blocks while the test holds the lock: producers
        // must return immediately (the bounded queue absorbs or drops),
        // which is exactly the hot-path guarantee. F5.1: "writer bloqueado …
        // la request sigue dentro del presupuesto". The guard drop is still
        // bounded (DRAIN_DEADLINE) even though the worker stays blocked.
        struct BlockingSink(Arc<Mutex<()>>);
        impl io::Write for BlockingSink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let _g = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let lock = Arc::new(Mutex::new(()));
        let blocker = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

        let (writer, guard) = spawn_worker(Box::new(BlockingSink(Arc::clone(&lock))));
        let mut writer = writer;
        let started = Instant::now();
        for _ in 0..1_000 {
            let _ = io::Write::write(&mut writer, b"blocked-sink-probe\n").expect("write never blocks");
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "producer must never wait for a blocked sink (took {elapsed:?})"
        );
        drop(guard);
        drop(blocker);
    }

    /// F6.B (B.5): the tee sink writes every chunk to BOTH the console and
    /// the daemon log file, so `cerberus logs` sees what the daemon logged.
    #[test]
    fn tee_sink_writes_console_and_file() {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-log-tee-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("cerberus.log");
        let sink = TeeSink::open(&path);
        assert!(sink.file.is_some(), "log file must open");

        let (mut writer, guard) = spawn_worker(Box::new(sink));
        writer.write_all(b"tee-probe-line\n").expect("write");
        drop(guard); // bounded drain + flush

        let content = std::fs::read_to_string(&path).expect("read log");
        assert!(
            content.contains("tee-probe-line"),
            "file must receive the chunk: {content}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The tee cap rotates once to `<path>.1` instead of growing unbounded.
    #[test]
    fn tee_sink_rotates_at_the_cap() {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-log-rotate-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("cerberus.log");
        let mut sink = TeeSink {
            console: Box::new(io::sink()),
            file: None,
            path: Some(path.clone()),
            size: LOG_FILE_MAX_BYTES,
            cap: LOG_FILE_MAX_BYTES,
        };
        sink.file = std::fs::OpenOptions::new().create(true).append(true).open(&path).ok();
        io::Write::write_all(&mut sink, b"rotation-trigger\n").expect("write");
        assert!(sink.size < LOG_FILE_MAX_BYTES, "rotation resets the counter");
        assert!(path.with_extension("log.1").exists(), "rotated file exists");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// F6.B attempt 2 (security P3-1): the tee file is CREATED 0600 — the
    /// same credential-file discipline as the config writes (defense in
    /// depth; the content is designed secret-free).
    #[cfg(unix)]
    #[test]
    fn tee_file_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "cerberus-log-mode-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("cerberus.log");
        {
            let _file = open_log_file(&path).expect("create tee file");
        }
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the tee file must be created 0600, got {mode:o}");
        // Appending to the existing file must not change its mode.
        {
            let _file = open_log_file(&path).expect("append");
        }
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "append keeps the mode, got {mode:o}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `set_log_tee_file` stores the path once; a second call cannot
    /// replace it (`OnceLock`) — and reports failure honestly.
    #[test]
    fn tee_file_path_is_set_once() {
        let dir = std::env::temp_dir().join(format!(
            "cerberus-log-teelock-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let first = dir.join("first.log");
        let second = dir.join("second.log");
        if LOG_TEE_FILE.get().is_none() {
            assert!(set_log_tee_file(&first), "first set wins");
        }
        // Whichever state the process is in, a second set must NOT swap it.
        let before = LOG_TEE_FILE.get().cloned();
        let _ = set_log_tee_file(&second);
        assert_eq!(LOG_TEE_FILE.get(), before.as_ref(), "tee path is immutable once set");
        std::fs::remove_dir_all(&dir).ok();
    }
}
