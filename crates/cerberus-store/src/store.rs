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

/// Intervalo mínimo entre purgas de retención (por tiempo, no por conteo).
const PURGE_INTERVAL_SECS: u64 = 60;

/// Capacidad por defecto del canal de escritura (backpressure mitigado):
/// por encima no se bloquea el hot path, pero se descartan eventos con WARN.
const DEFAULT_WRITE_CHANNEL_CAPACITY: usize = 16_384;

/// Timeout por defecto para `flush`/`close`. Cubre la operación COMPLETA:
/// el *enqueue* de la barrera en el canal bounded MÁS la espera del ACK del
/// writer (fix review v6.1: antes `send` era bloqueante e ilimitado, así que
/// un writer atascado con el canal lleno colgaba el shutdown para siempre).
const DEFAULT_STORE_TIMEOUT: Duration = Duration::from_secs(5);

/// Espera entre reintentos de `try_send` mientras el canal está lleno durante
/// el enqueue de una barrera (flush/close). Acotado por el deadline global.
const ENQUEUE_RETRY_BACKOFF: Duration = Duration::from_millis(2);

/// Estado del store (`AuditStore::state`, `AtomicU8`). Las transiciones son
/// monótonas y atómicas: nunca se vuelve a un estado anterior.
///
/// `ACCEPTING` → `CLOSING` → `SHUTDOWN_SENT` → `CLOSED`
///
/// * `ACCEPTING`: admite eventos y barreras.
/// * `CLOSING`: NO admite eventos nuevos (drenaje ordenado en curso), pero el
///   writer sigue vivo y `flush` sigue siendo válido.
/// * `SHUTDOWN_SENT`: la barrera de cierre ya fue emitida por un `close()`;
///   ningún otro `close`/`flush` puede emitir barreras.
/// * `CLOSED`: el writer terminó.
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
    /// Durability barrier (fix review v4 #6): el writer responde `ack` solo
    /// después de haber persistido todos los `Event` anteriores (la cola es
    /// FIFO). Si algún `INSERT` falló desde el último flush, la ack es `Err`
    /// con el mensaje de error de `SQLite`.
    Flush {
        ack: mpsc::SyncSender<Result<(), String>>,
    },
    /// Cierre ordenado del writer (fix review v4 #6b). El ACK transporta el
    /// último error de persistencia pendiente (fix review v5): si hubo un
    /// INSERT fallido sin consumir, se entrega como `Err` — `close()` ya no
    /// confirma éxito cuando se perdió auditoría.
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

/// Resultado (honesto) de un intento de escritura en el hot path.
/// Los callers pueden ignorarlo; los tests y las métricas lo usan para
/// distinguir pérdida por disco lento de rechazo por cierre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Encolado para el writer: se persistirá antes de que `close()` retorne.
    Queued,
    /// Descartado por backpressure (canal lleno, writer vivo).
    DroppedBackpressure,
    /// Rechazado porque el store ya no admite eventos (cierre iniciado).
    RejectedClosed,
}

/// `SQLite` store for audit events with non-blocking async writes.
#[derive(Debug)]
pub struct AuditStore {
    write_tx: mpsc::SyncSender<WriteMsg>,
    query_tx: mpsc::Sender<QueryMsg>,
    /// Eventos descartados por backpressure (canal lleno). El hot path nunca
    /// bloquea: si el canal está lleno se descarta el evento y se contabiliza
    /// aquí (fix review v5 #4 — crecimiento de memoria acotado).
    dropped_events: std::sync::atomic::AtomicU64,
    /// Drops ya informados y "consumidos" por un `flush`/`close` anterior.
    /// El siguiente `flush` solo reporta drops nuevos (total - acknowledged),
    /// para que un flush Ok no vuelva a fallar por drops ya notificados
    /// (fix review v6 P1).
    dropped_acknowledged: std::sync::atomic::AtomicU64,
    /// Eventos RECHAZADOS porque el store ya había iniciado el cierre (o el
    /// writer terminó). Se contabilizan aparte de `dropped_events`: no son
    /// backpressure de disco lento, son escrituras post-cierre — mezclarlos
    /// producía errores deshonestos (fix review v6.1).
    rejected_after_close: std::sync::atomic::AtomicU64,
    /// Rechazos ya informados por un `flush`/`close` anterior.
    rejected_acknowledged: std::sync::atomic::AtomicU64,
    /// Estado atómico accepting/closing/closed (ver módulo [`state`]).
    state: std::sync::atomic::AtomicU8,
    /// Escrituras del hot path que ya pasaron la puerta de estado pero aún no
    /// han terminado su `try_send`. `close()` espera a que llegue a 0 antes de
    /// emitir la barrera de cierre; combinado con el orden `SeqCst` esto hace
    /// IMPOSIBLE que un evento ya encolado se pierda al cerrar (fix v6.1:
    /// antes existía una ventana entre la comprobación de estado y el envío).
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

    /// Events dropped by backpressure since creation (canal lleno, writer
    /// vivo). NO incluye los eventos rechazados tras iniciar el cierre —
    /// esos se cuentan en [`Self::rejected_after_close`].
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Eventos rechazados porque el store ya no admitía escrituras (cierre
    /// iniciado o writer terminado).
    #[must_use]
    pub fn rejected_after_close(&self) -> u64 {
        self.rejected_after_close.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// `true` mientras el store admite eventos nuevos (estado `accepting`).
    #[must_use]
    pub fn is_accepting(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Acquire) == state::ACCEPTING
    }

    /// Nombre del estado actual (`accepting` | `closing` | `shutdown-sent` |
    /// `closed`), para logs y diagnóstico.
    #[must_use]
    pub fn state_name(&self) -> &'static str {
        state::name(self.state.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Override del timeout global de `flush`/`close` (enqueue + ACK).
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Deja de admitir eventos nuevos SIN cerrar el writer: primer paso del
    /// shutdown ordenado. A partir de aquí la cola es finita (nada nuevo
    /// entra), de modo que el `flush` posterior drena un conjunto acotado y
    /// los eventos que lleguen tarde se reportan como rechazos honestos en vez
    /// de perderse en silencio.
    ///
    /// Devuelve `true` si esta llamada realizó la transición
    /// `accepting → closing`, `false` si el cierre ya había empezado.
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
        // Purga de retención al OPEN (una vez).
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
        // Último error de persistencia (fix review v4 #6): un INSERT fallido se
        // retiene y NO se deja perder; el siguiente Flush lo propaga al caller
        // en lugar de ACKear como si todo fuera durable.
        let mut last_error: Option<String> = None;
        while let Ok(msg) = rx.recv() {
            match msg {
                WriteMsg::Event(event) => {
                    if let Err(e) = insert_event(&conn, &event) {
                        tracing::error!("audit write error: {e}");
                        last_error = Some(e);
                    }
                    // Retención periódica POR TIEMPO: purga cada ≥60s, no por conteo.
                    if last_purge.elapsed() >= Duration::from_secs(PURGE_INTERVAL_SECS) {
                        let purged = purge_old(&conn, retention_days);
                        if purged > 0 {
                            tracing::info!("audit retention purge: removed {purged} events");
                        }
                        last_purge = Instant::now();
                    }
                }
                WriteMsg::Flush { ack } => {
                    // Los eventos previos ya se aplicaron (cola FIFO, este thread
                    // los procesa en orden). La ack es la barrera de durabilidad:
                    // Ok(()) solo si no hubo insert fallido desde el último flush.
                    let res = last_error.take().map_or(Ok(()), Err);
                    let _ = ack.send(res);
                }
                WriteMsg::Shutdown { ack } => {
                    // Drenaje ORDENADO antes de morir (fix review v6.1): un
                    // writer no puede tirar eventos que ya estaban encolados
                    // detrás de la barrera de cierre. `close()` marca el store
                    // como `closing` ANTES de emitir esta barrera, así que la
                    // cola restante es finita: se vacía en orden FIFO y solo
                    // entonces se ACKea y se termina.
                    let drained = Self::drain_pending(&rx, &conn, &mut last_error);
                    if drained > 0 {
                        tracing::info!("audit writer drained {drained} pending message(s) at shutdown");
                    }
                    // El ACK transporta el último error de persistencia pendiente
                    // (fix review v5 #4): close() sabrá si se perdió auditoría.
                    let res = last_error.take().map_or(Ok(()), Err);
                    let _ = ack.send(res);
                    return;
                }
            }
        }
    }

    /// Vacía en orden FIFO todo lo que quede en el canal (sin bloquear) y
    /// persiste los `Event` pendientes. Usado por la barrera de `Shutdown`
    /// para garantizar **drenaje ordenado**: nada que ya estuviera encolado se
    /// pierde por el hecho de cerrar. Los `Flush`/`Shutdown` que hubieran
    /// quedado encolados por llamadas concurrentes reciben aquí su respuesta,
    /// para que ningún caller quede esperando un ACK que nunca llega.
    /// Devuelve cuántos mensajes se drenaron.
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
        // Registro de escritura en vuelo ANTES de mirar el estado, con orden
        // `SeqCst` en ambos lados: o este writer ve que el store ya no admite
        // (y rechaza), o `close()` ve `inflight_writes > 0` y espera. Nunca
        // ambos fallan a la vez, así que ningún evento encolado se pierde.
        self.inflight_writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let outcome = self.try_enqueue(event);
        self.inflight_writes.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        outcome
    }

    fn try_enqueue(&self, event: AuditEvent) -> WriteOutcome {
        // Puerta de estado ATÓMICA (fix review v6.1): una vez iniciado el
        // cierre no se admite ni un evento más. Antes se seguía intentando el
        // `try_send` y el fallo se contabilizaba como "backpressure", lo que
        // (a) hacía la cola potencialmente infinita durante el shutdown y
        // (b) producía un error deshonesto ("disco lento") para lo que en
        // realidad era una escritura post-cierre.
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
                // Canal lleno (writer ocupado) → descartar con contador.
                // No bloquea el hot path del proxy.
                let n = self.dropped_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                tracing::warn!("audit write channel full, event dropped (total dropped={n})");
                WriteOutcome::DroppedBackpressure
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                // El writer terminó (cierre en curso o writer caído): NO es
                // backpressure. Se reporta en su propia categoría.
                let n = self
                    .rejected_after_close
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                tracing::warn!("audit writer gone, event rejected (total rejected={n})");
                WriteOutcome::RejectedClosed
            }
        }
    }

    /// Consume los drops nuevos (total - acknowledged) y los marca como
    /// informados. Así un flush Ok tras un flush anterior Err por drops
    /// PREVIOS no vuelve a fallar (fix review v6 P1).
    #[must_use]
    fn consume_dropped(&self) -> u64 {
        let total = self.dropped_events.load(std::sync::atomic::Ordering::Relaxed);
        let acked = self
            .dropped_acknowledged
            .swap(total, std::sync::atomic::Ordering::Relaxed);
        total.saturating_sub(acked)
    }

    /// Igual que [`Self::consume_dropped`] para los eventos rechazados tras
    /// iniciar el cierre.
    #[must_use]
    fn consume_rejected(&self) -> u64 {
        let total = self.rejected_after_close.load(std::sync::atomic::Ordering::Relaxed);
        let acked = self
            .rejected_acknowledged
            .swap(total, std::sync::atomic::Ordering::Relaxed);
        total.saturating_sub(acked)
    }

    /// Combina el resultado del writer (durabilidad) con los drops nuevos
    /// consumidos: si se perdieron eventos por backpressure O el writer acusó
    /// un fallo de persistencia, el resultado es `Err` con todos los motivos.
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

    /// Envía un mensaje barrera al writer (Flush/Shutdown) y espera su ACK,
    /// toda la operación fuera del executor tokio (`spawn_blocking`): ni `send`
    /// (canal bounded puede estar lleno) ni `recv_timeout` bloquean un async
    /// worker.
    /// Devuelve la ack del writer (Ok=previos persistentes, Err=fallo previo).
    async fn barrier_ack(&self, msg: WriteMsg, ack_rx: mpsc::Receiver<Result<(), String>>) -> Result<(), String> {
        self.barrier_ack_until(msg, ack_rx, Instant::now() + self.timeout).await
    }

    /// Espera (sin bloquear el executor) a que no queden escrituras en vuelo,
    /// o a que se agote el deadline. Devuelve las que quedaron sin terminar.
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

    /// Igual que [`Self::barrier_ack`] pero con un deadline ya en curso, para
    /// que el timeout de `close()` cubra quiesce + enqueue + ACK.
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
            // Un ÚNICO deadline para toda la operación (fix review v6.1): el
            // `send` bloqueante sin límite podía colgar el shutdown para
            // siempre si el canal estaba lleno y el writer atascado. Ahora el
            // enqueue reintenta con `try_send` hasta el deadline, y el ACK
            // solo dispone del presupuesto restante.
            let mut pending = msg;
            loop {
                match tx.try_send(pending) {
                    Ok(()) => break,
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        return Err("store channel closed (writer terminado)".to_string());
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
                Err(mpsc::RecvTimeoutError::Disconnected) => Err("store channel closed (writer terminado)".to_string()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    Err(format!("store {op} timed out waiting for writer ACK"))
                }
            }
        })
        .await
        .map_err(|e| format!("spawn_blocking falló: {e}"))?
    }

    /// Durability barrier: blocks until every event previously sent through
    /// [`Self::write_event_async`] has been persisted to `SQLite` by the writer
    /// thread. The hot path stays non-blocking; only this call awaits the ACK
    /// (with a timeout) off the tokio runtime.
    ///
    /// **Error propagation (fix review v4 #6):** si un `INSERT` falló en la
    /// escritura de un evento que está en la cola/escritura ANTES de este
    /// flush, la ack es `Err` con el mensaje de `SQLite` — un flush ya no
    /// acuse un fallo de persistencia previo.
    ///
    /// **Drops por backpressure (fix review v6 P1):** tras la barrera, si
    /// hubo eventos descartados por canal lleno desde el último flush/close,
    /// devuelve `Err` indicando cuántos se perdieron — el hot path no bloquea
    /// pero la durabilidad NO confirma éxito si hubo pérdida.
    ///
    /// Returns `Err` if the writer channel is closed, the writer did not
    /// acknowledge within the timeout, a previous insert failed, or events
    /// were dropped to backpressure.
    pub async fn flush(&self) -> Result<(), String> {
        // `flush` es válido en `accepting` y en `closing` (writer vivo). Una
        // vez emitida la barrera de cierre, no se emiten más barreras: el
        // writer ya terminó o está terminando y un `send` aquí solo produciría
        // un ACK que nunca llega.
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

    /// Alias de [`Self::flush`] con semántica explícita de durabilidad +
    /// propagación de errores de escritura (fix review v4 #6). Usado por el
    /// daemon en el shutdown graceful.
    pub async fn flush_durable(&self) -> Result<(), String> {
        self.flush().await
    }

    /// Cierre ordenado del writer thread. El ACK transporta el último error de
    /// persistencia pendiente (fix review v5 #4): si el writer debía persistir un
    /// evento que falló, `close()` devuelve `Err` — ya no confirma éxito cuando
    /// hay pérdida de auditoría. La desconexión prematura del writer también se
    /// reporta como `Err` (no como éxito).
    ///
    /// **Drops por backpressure (fix review v6 P1):** si se descartaron eventos
    /// por canal lleno no consumidos por un flush previo, el cierre NO es un
    /// éxito limpio: devuelve `Err` con el número de eventos perdidos.
    ///
    /// Returns `Err` si el writer no confirmó dentro del timeout, hubo errores
    /// de persistencia pendientes, o se perdieron eventos por backpressure.
    pub async fn close(&self) -> Result<(), String> {
        // Transición atómica a `shutdown-sent`: exactamente UN `close`
        // concurrente emite la barrera de cierre; el resto falla honestamente
        // en lugar de quedarse esperando un ACK que ya consumió otro.
        // Antes de la barrera el store deja de admitir eventos, de forma que
        // la cola que el writer debe drenar es finita.
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

        // Quiesce: esperar a que las escrituras que ya habían pasado la puerta
        // terminen su `try_send`. Después de este punto ningún hilo puede
        // encolar nada más, así que la cola que el writer drenará es final y
        // el drenaje es completo. La espera consume del MISMO presupuesto de
        // timeout (nunca cuelga).
        self.await_write_quiescence(deadline).await;

        let (ack_tx, ack_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let ack = self
            .barrier_ack_until(WriteMsg::Shutdown { ack: ack_tx }, ack_rx, deadline)
            .await;
        // El writer ya no está (ACKeó y salió, o se agotó el timeout y lo
        // damos por perdido): el estado final es `closed` en ambos casos.
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

/// Persiste un evento. Devuelve el mensaje de error de `SQLite` si el
/// `INSERT` falla (el writer lo retiene para propagarlo en la próxima
/// barrera de durabilidad).
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
    /// Store de test cuyo writer está **atascado**: el receptor del canal se
    /// aparca en un hilo que no lo consume hasta que el `Sender` devuelto se
    /// suelta. Sirve para comprobar que `flush`/`close` respetan el timeout en
    /// el *enqueue* (canal lleno) y no cuelgan para siempre.
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
                // Nunca consume `write_rx` hasta que el test lo libere.
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
        // Contiguos en ts: orden DESC por ts_unix.
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
            // ts_unix muy antiguo (≥90 días de retención por defecto).
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
            // Pasado reciente (1 h atrás) y futuro (1 h adelante): cutoff = now.
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

    // ─── Fix code review v4 #6: flush propaga errores de INSERT ─────────────

    /// Un `INSERT` falla determinísticamente cuando el `id` (`PRIMARY KEY`) ya
    /// existe. El flush posterior debe devolver `Err` con el mensaje de `SQLite`
    /// en lugar de acuse un fallo de persistencia previo.
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

        // Segundo evento con el MISMO id → el INSERT del writer falla.
        let dup = make_event("evt_twin", "block", 1_700_000_101);
        rt.block_on(store.write_event_async(dup));

        let err = rt
            .block_on(store.flush())
            .expect_err("flush debe propagar el error del INSERT");
        assert!(
            err.contains("UNIQUE") || err.contains("constraint"),
            "esperaba error de constraint SQLite, got: {err}"
        );

        // El error se consumió: el siguiente flush (sin nuevos fallos) pasa.
        rt.block_on(store.flush()).expect("flush sin fallos posteriores");
    }

    // ─── Fix review v4 #6b: close() termina el writer ordenadamente ─────────

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

        // El store ya no admite eventos y lo dice con honestidad: el evento se
        // cuenta como RECHAZADO post-cierre (no como backpressure de disco) y
        // el flush posterior falla explicando que el store está cerrado.
        assert!(!store.is_accepting());
        assert_eq!(store.state_name(), "closed");
        rt.block_on(store.write_event_async(make_event("evt_c2", "warn", 1_700_000_201)));
        assert_eq!(store.rejected_after_close(), 1);
        assert_eq!(store.dropped_events(), 0, "un rechazo post-cierre no es backpressure");
        let err = rt.block_on(store.flush()).expect_err("flush tras close debe fallar");
        assert!(err.contains("store already closed"), "got: {err}");
        assert!(err.contains("1 audit event(s) rejected after close"), "got: {err}");

        // Un segundo close no vuelve a emitir barrera: falla honestamente.
        let err2 = rt.block_on(store.close()).expect_err("close idempotente debe reportar");
        assert!(err2.contains("close already invoked"), "got: {err2}");

        // El query thread sigue leyendo lo ya persistido antes del cierre.
        let events = rt.block_on(store.recent_events(10));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt_c1");
    }

    // ─── Fix review v6 P1: drops por backpressure en durabilidad ────────────

    #[test]
    fn flush_reports_dropped_events() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let store = AuditStore::open(&path).expect("open store");
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Sin drops: flush es un éxito limpio.
        rt.block_on(store.flush()).expect("flush limpio sin drops");

        // Simula eventos perdidos por backpressure (canal lleno) colgándolos
        // directamente en el contador — camino determinista.
        store.dropped_events.fetch_add(3, std::sync::atomic::Ordering::Relaxed);

        let err = rt.block_on(store.flush()).expect_err("flush debe reportar drops");
        assert!(err.contains("3 audit event(s) lost to backpressure"), "got: {err}");

        // Drops consumidos: un flush posterior sin drops nuevos vuelve a Ok.
        rt.block_on(store.flush())
            .expect("flush sin drops nuevos no vuelve a fallar");
    }

    // ─── Fix review v6.1: shutdown atómico, drenaje ordenado, sin cuelgues ──

    /// Shutdown CONCURRENTE con writers activos. Invariante fuerte: todo lo
    /// que el store aceptó (`WriteOutcome::Queued`) acaba persistido, y todo
    /// intento contabilizado cae en exactamente una categoría honesta
    /// (encolado / backpressure / rechazado post-cierre). Nada se pierde en
    /// silencio y el cierre no cuelga.
    #[test]
    fn concurrent_shutdown_with_active_writers_persists_everything_accepted() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;

        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        // Capacidad pequeña a propósito: fuerza backpressure real.
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

        // Cierre ordenado MIENTRAS los writers siguen empujando eventos.
        let (flush_res, close_res) = rt.block_on(async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(store.begin_closing(), "primera transición accepting → closing");
            assert!(!store.is_accepting(), "tras begin_closing no se admiten eventos");
            assert_eq!(store.state_name(), "closing");
            assert!(!store.begin_closing(), "begin_closing no se repite");
            let f = store.flush().await;
            let c = store.close().await;
            (f, c)
        });

        keep_going.store(false, SeqCst);
        for h in writers {
            rt.block_on(h).expect("writer task no debe entrar en pánico");
        }

        assert_eq!(store.state_name(), "closed");

        // Toda escritura posterior al cierre se rechaza (no es backpressure).
        let post = rt.block_on(store.write_event_async(make_event("evt_post", "warn", 1)));
        assert_eq!(post, WriteOutcome::RejectedClosed);

        // Contabilidad exhaustiva: cada intento tiene exactamente un destino.
        let (a, q, d, r) = (
            attempted.load(SeqCst),
            queued.load(SeqCst),
            dropped.load(SeqCst),
            rejected.load(SeqCst),
        );
        assert_eq!(a, q + d + r, "cada intento cae en una única categoría");
        assert!(q > 0, "algún evento debió encolarse");
        assert_eq!(
            store.dropped_events(),
            d as u64,
            "el contador de backpressure coincide con los outcomes"
        );
        assert!(store.rejected_after_close() >= r as u64);

        // DRENAJE ORDENADO: todo lo aceptado está en SQLite.
        let persisted = rt.block_on(store.event_count()).expect("count");
        assert_eq!(persisted, q, "todo evento aceptado debe persistir tras close()");

        // Errores HONESTOS: si hubo pérdida, ni flush ni close la esconden.
        if d > 0 || r > 0 {
            assert!(
                flush_res.is_err() || close_res.is_err(),
                "con pérdida ({d} drops, {r} rechazos) el cierre no puede reportar éxito limpio"
            );
        }
        for res in [&flush_res, &close_res] {
            if let Err(e) = res {
                assert!(
                    e.contains("backpressure") || e.contains("rejected after close"),
                    "el error debe explicar la pérdida real, got: {e}"
                );
            }
        }
    }

    /// Canal LLENO con el writer atascado: ni `flush` ni `close` pueden
    /// colgarse. El timeout cubre también el *enqueue* de la barrera (antes el
    /// `send` bloqueante era ilimitado → shutdown colgado para siempre).
    #[test]
    fn full_channel_with_stalled_writer_times_out_instead_of_hanging() {
        let tmp = temp_db();
        let path = tmp.path().join("cerberus.db");
        let timeout = Duration::from_millis(150);
        let (store, release) = AuditStore::with_stalled_writer(&path, 1, timeout).expect("store con writer atascado");
        let rt = tokio::runtime::Runtime::new().unwrap();

        // Capacidad 1: el primer evento ocupa el canal, el segundo se descarta.
        assert_eq!(
            rt.block_on(store.write_event_async(make_event("evt_s1", "warn", 1_700_000_300))),
            WriteOutcome::Queued
        );
        assert_eq!(
            rt.block_on(store.write_event_async(make_event("evt_s2", "warn", 1_700_000_301))),
            WriteOutcome::DroppedBackpressure
        );

        // flush: el enqueue de la barrera nunca cabe → timeout, no cuelgue.
        let started = Instant::now();
        let err = rt.block_on(store.flush()).expect_err("flush no puede colgarse");
        let elapsed = started.elapsed();
        assert!(
            err.contains("timed out enqueueing the durability barrier"),
            "got: {err}"
        );
        assert!(err.contains("1 audit event(s) lost to backpressure"), "got: {err}");
        assert!(elapsed >= timeout, "debe respetar el deadline, tardó {elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "tardó demasiado: {elapsed:?}");

        // close: mismo presupuesto, mismo comportamiento; el estado queda
        // cerrado aunque el writer nunca ACKee (no se admiten más eventos).
        let started = Instant::now();
        let err = rt.block_on(store.close()).expect_err("close no puede colgarse");
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
            .expect_err("cierre con drops NO es éxito limpio");
        assert!(err.contains("2 audit event(s) lost to backpressure"), "got: {err}");
    }
}
