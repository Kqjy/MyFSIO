use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use myfsio_storage::traits::AsyncReadStream;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError};

#[derive(Debug)]
pub struct DiskQueueTimeout;

const PRESSURE_BUCKET_SECONDS: u64 = 60;
const PRESSURE_HISTORY_BUCKETS: usize = 60;
pub const PRESSURE_RECENT_SECONDS: u64 = 300;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct DiskPressureBucket {
    pub start: u64,
    pub waits: u64,
    pub wait_ms_total: u64,
    pub wait_ms_max: u64,
    pub timeouts: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DiskPressureRecent {
    pub window_seconds: u64,
    pub waits: u64,
    pub wait_ms_avg: u64,
    pub wait_ms_max: u64,
    pub timeouts: u64,
}

pub struct DiskLimiter {
    read: Option<Arc<Semaphore>>,
    write: Option<Arc<Semaphore>>,
    read_limit: usize,
    write_limit: usize,
    queue_timeout: Duration,
    queue_timeouts: AtomicU64,
    queue_waits: AtomicU64,
    queue_wait_ms_total: AtomicU64,
    upload_spool_bytes: Arc<AtomicU64>,
    history: Mutex<VecDeque<DiskPressureBucket>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiskPressureSnapshot {
    pub read_limit: usize,
    pub write_limit: usize,
    pub read_permits_in_use: usize,
    pub write_permits_in_use: usize,
    pub queue_timeouts: u64,
    pub queue_waits: u64,
    pub queue_wait_ms_total: u64,
    pub queue_wait_ms_avg: u64,
    pub upload_spool_bytes: u64,
    pub recent: DiskPressureRecent,
    pub history: Vec<DiskPressureBucket>,
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn bucket_start(now: u64) -> u64 {
    now - now % PRESSURE_BUCKET_SECONDS
}

impl DiskLimiter {
    pub fn new(read_limit: usize, write_limit: usize, queue_timeout: Duration) -> Self {
        Self {
            read: (read_limit > 0).then(|| Arc::new(Semaphore::new(read_limit))),
            write: (write_limit > 0).then(|| Arc::new(Semaphore::new(write_limit))),
            read_limit,
            write_limit,
            queue_timeout,
            queue_timeouts: AtomicU64::new(0),
            queue_waits: AtomicU64::new(0),
            queue_wait_ms_total: AtomicU64::new(0),
            upload_spool_bytes: Arc::new(AtomicU64::new(0)),
            history: Mutex::new(VecDeque::with_capacity(PRESSURE_HISTORY_BUCKETS)),
        }
    }

    fn record_at(&self, now: u64, update: impl FnOnce(&mut DiskPressureBucket)) {
        let start = bucket_start(now);
        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        if history.back().is_none_or(|bucket| bucket.start < start) {
            history.push_back(DiskPressureBucket {
                start,
                ..Default::default()
            });
        }
        while history.len() > PRESSURE_HISTORY_BUCKETS {
            history.pop_front();
        }
        if let Some(bucket) = history.back_mut() {
            update(bucket);
        }
    }

    fn record_wait_at(&self, now: u64, wait_ms: u64) {
        self.record_at(now, |bucket| {
            bucket.waits += 1;
            bucket.wait_ms_total += wait_ms;
            bucket.wait_ms_max = bucket.wait_ms_max.max(wait_ms);
        });
    }

    fn record_timeout_at(&self, now: u64) {
        self.record_at(now, |bucket| bucket.timeouts += 1);
    }

    fn history_at(&self, now: u64) -> (DiskPressureRecent, Vec<DiskPressureBucket>) {
        let current = bucket_start(now);
        let first =
            current.saturating_sub(PRESSURE_BUCKET_SECONDS * (PRESSURE_HISTORY_BUCKETS as u64 - 1));
        let recent_from = now.saturating_sub(PRESSURE_RECENT_SECONDS);
        let stored: Vec<DiskPressureBucket> = {
            let history = self.history.lock().unwrap_or_else(|e| e.into_inner());
            history.iter().copied().collect()
        };
        let mut recent = DiskPressureRecent {
            window_seconds: PRESSURE_RECENT_SECONDS,
            ..Default::default()
        };
        let mut recent_wait_total = 0u64;
        for bucket in &stored {
            if bucket.start + PRESSURE_BUCKET_SECONDS > recent_from && bucket.start <= now {
                recent.waits += bucket.waits;
                recent_wait_total += bucket.wait_ms_total;
                recent.wait_ms_max = recent.wait_ms_max.max(bucket.wait_ms_max);
                recent.timeouts += bucket.timeouts;
            }
        }
        if recent.waits > 0 {
            recent.wait_ms_avg = recent_wait_total / recent.waits;
        }
        let series = (0..PRESSURE_HISTORY_BUCKETS as u64)
            .map(|index| {
                let start = first + index * PRESSURE_BUCKET_SECONDS;
                stored
                    .iter()
                    .find(|bucket| bucket.start == start)
                    .copied()
                    .unwrap_or(DiskPressureBucket {
                        start,
                        ..Default::default()
                    })
            })
            .collect();
        (recent, series)
    }

    pub fn spool_gauge(&self) -> Arc<AtomicU64> {
        self.upload_spool_bytes.clone()
    }

    async fn acquire(
        &self,
        semaphore: &Option<Arc<Semaphore>>,
    ) -> Result<Option<OwnedSemaphorePermit>, DiskQueueTimeout> {
        let Some(semaphore) = semaphore else {
            return Ok(None);
        };
        let started = Instant::now();
        match tokio::time::timeout(self.queue_timeout, semaphore.clone().acquire_owned()).await {
            Ok(Ok(permit)) => {
                let wait_ms = started.elapsed().as_millis() as u64;
                self.queue_waits.fetch_add(1, Ordering::Relaxed);
                self.queue_wait_ms_total
                    .fetch_add(wait_ms, Ordering::Relaxed);
                self.record_wait_at(epoch_seconds(), wait_ms);
                Ok(Some(permit))
            }
            Ok(Err(_)) => Ok(None),
            Err(_) => {
                self.queue_timeouts.fetch_add(1, Ordering::Relaxed);
                self.record_timeout_at(epoch_seconds());
                Err(DiskQueueTimeout)
            }
        }
    }

    pub async fn acquire_read(&self) -> Result<Option<OwnedSemaphorePermit>, DiskQueueTimeout> {
        self.acquire(&self.read).await
    }

    pub async fn acquire_write(&self) -> Result<Option<OwnedSemaphorePermit>, DiskQueueTimeout> {
        self.acquire(&self.write).await
    }

    pub fn read_semaphore(&self) -> Option<Arc<Semaphore>> {
        self.read.clone()
    }

    pub fn write_semaphore(&self) -> Option<Arc<Semaphore>> {
        self.write.clone()
    }

    pub fn enabled(&self) -> bool {
        self.read.is_some() || self.write.is_some()
    }

    pub fn queue_timeout(&self) -> Duration {
        self.queue_timeout
    }

    pub fn snapshot(&self) -> DiskPressureSnapshot {
        self.snapshot_at(epoch_seconds())
    }

    fn snapshot_at(&self, now: u64) -> DiskPressureSnapshot {
        let (recent, history) = self.history_at(now);
        let read_in_use = self
            .read
            .as_ref()
            .map(|s| self.read_limit.saturating_sub(s.available_permits()))
            .unwrap_or(0);
        let write_in_use = self
            .write
            .as_ref()
            .map(|s| self.write_limit.saturating_sub(s.available_permits()))
            .unwrap_or(0);
        let waits = self.queue_waits.load(Ordering::Relaxed);
        let wait_total = self.queue_wait_ms_total.load(Ordering::Relaxed);
        DiskPressureSnapshot {
            read_limit: self.read_limit,
            write_limit: self.write_limit,
            read_permits_in_use: read_in_use,
            write_permits_in_use: write_in_use,
            queue_timeouts: self.queue_timeouts.load(Ordering::Relaxed),
            queue_waits: waits,
            queue_wait_ms_total: wait_total,
            queue_wait_ms_avg: if waits > 0 { wait_total / waits } else { 0 },
            upload_spool_bytes: self.upload_spool_bytes.load(Ordering::Relaxed),
            recent,
            history,
        }
    }
}

type PermitFuture =
    Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

struct PermitSlot {
    semaphore: Option<Arc<Semaphore>>,
    permit: Option<OwnedSemaphorePermit>,
    acquiring: Option<PermitFuture>,
}

impl PermitSlot {
    fn new(semaphore: Arc<Semaphore>, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            semaphore: Some(semaphore),
            permit,
            acquiring: None,
        }
    }

    fn poll_hold(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.permit.is_some() {
            return Poll::Ready(());
        }
        let Some(semaphore) = self.semaphore.clone() else {
            return Poll::Ready(());
        };
        if self.acquiring.is_none() {
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    self.permit = Some(permit);
                    return Poll::Ready(());
                }
                Err(TryAcquireError::Closed) => {
                    self.semaphore = None;
                    return Poll::Ready(());
                }
                Err(TryAcquireError::NoPermits) => {
                    self.acquiring = Some(Box::pin(semaphore.acquire_owned()));
                }
            }
        }
        let Some(acquiring) = self.acquiring.as_mut() else {
            return Poll::Ready(());
        };
        match acquiring.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.acquiring = None;
                match result {
                    Ok(permit) => self.permit = Some(permit),
                    Err(_) => self.semaphore = None,
                }
                Poll::Ready(())
            }
        }
    }

    fn release(&mut self) {
        self.permit = None;
    }

    fn take(&mut self) -> Option<OwnedSemaphorePermit> {
        self.permit.take()
    }
}

pub struct DiskReadGate {
    inner: AsyncReadStream,
    slot: PermitSlot,
}

impl DiskReadGate {
    pub fn new(
        inner: AsyncReadStream,
        semaphore: Arc<Semaphore>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            inner,
            slot: PermitSlot::new(semaphore, permit),
        }
    }
}

impl AsyncRead for DiskReadGate {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.slot.poll_hold(cx).is_pending() {
            return Poll::Pending;
        }
        let result = this.inner.as_mut().poll_read(cx, buf);
        if result.is_ready() {
            this.slot.release();
        }
        result
    }
}

#[derive(Clone, Default)]
pub struct DiskTailPermit(Arc<Mutex<Option<OwnedSemaphorePermit>>>);

impl DiskTailPermit {
    fn park(&self, permit: OwnedSemaphorePermit) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(permit);
        }
    }

    pub fn is_parked(&self) -> bool {
        self.0.lock().map(|slot| slot.is_some()).unwrap_or(false)
    }
}

pub struct DiskWriteGate {
    inner: AsyncReadStream,
    slot: PermitSlot,
    stash: Vec<u8>,
    pos: usize,
    len: usize,
    eof: bool,
    parked: bool,
    held_bytes: u64,
    quantum: u64,
    tail: DiskTailPermit,
}

impl DiskWriteGate {
    pub fn new(
        inner: AsyncReadStream,
        semaphore: Arc<Semaphore>,
        permit: Option<OwnedSemaphorePermit>,
        chunk_size: usize,
        tail: DiskTailPermit,
    ) -> Self {
        let chunk_size = chunk_size.max(1);
        Self {
            inner,
            slot: PermitSlot::new(semaphore, permit),
            stash: vec![0u8; chunk_size],
            pos: 0,
            len: 0,
            eof: false,
            parked: false,
            held_bytes: 0,
            quantum: (chunk_size as u64).saturating_mul(4),
            tail,
        }
    }
}

impl AsyncRead for DiskWriteGate {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pos < this.len {
                if this.held_bytes >= this.quantum {
                    this.slot.release();
                    this.held_bytes = 0;
                }
                if this.slot.poll_hold(cx).is_pending() {
                    return Poll::Pending;
                }
                let n = (this.len - this.pos).min(buf.remaining());
                buf.put_slice(&this.stash[this.pos..this.pos + n]);
                this.pos += n;
                this.held_bytes += n as u64;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                if !this.parked {
                    if this.slot.poll_hold(cx).is_pending() {
                        return Poll::Pending;
                    }
                    if let Some(permit) = this.slot.take() {
                        this.tail.park(permit);
                    }
                    this.parked = true;
                }
                return Poll::Ready(Ok(()));
            }
            let mut stash = ReadBuf::new(&mut this.stash);
            match this.inner.as_mut().poll_read(cx, &mut stash) {
                Poll::Pending => {
                    this.slot.release();
                    this.held_bytes = 0;
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let n = stash.filled().len();
                    if n == 0 {
                        this.eof = true;
                    } else {
                        this.pos = 0;
                        this.len = n;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_limiter_returns_no_permit() {
        let limiter = DiskLimiter::new(0, 0, Duration::from_secs(1));
        assert!(!limiter.enabled());
        assert!(limiter.acquire_read().await.unwrap().is_none());
        assert!(limiter.acquire_write().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn limiter_times_out_when_saturated() {
        let limiter = DiskLimiter::new(1, 0, Duration::from_millis(50));
        let held = limiter.acquire_read().await.unwrap();
        assert!(held.is_some());
        assert!(limiter.acquire_read().await.is_err());
        let snap = limiter.snapshot();
        assert_eq!(snap.queue_timeouts, 1);
        assert_eq!(snap.recent.timeouts, 1);
        assert_eq!(snap.history.len(), PRESSURE_HISTORY_BUCKETS);
        assert_eq!(snap.history.last().unwrap().timeouts, 1);
        drop(held);
        assert!(limiter.acquire_read().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn snapshot_reports_in_use() {
        let limiter = DiskLimiter::new(2, 2, Duration::from_secs(1));
        let _r = limiter.acquire_read().await.unwrap();
        let _w = limiter.acquire_write().await.unwrap();
        let snap = limiter.snapshot();
        assert_eq!(snap.read_permits_in_use, 1);
        assert_eq!(snap.write_permits_in_use, 1);
        assert_eq!(snap.read_limit, 2);
    }

    #[test]
    fn pressure_history_rolls_recent_window_and_zero_fills() {
        let limiter = DiskLimiter::new(1, 1, Duration::from_secs(1));
        let base: u64 = 1_800_000_000;
        limiter.record_wait_at(base, 40);
        limiter.record_timeout_at(base + 10);
        limiter.record_wait_at(base + 400, 100);
        limiter.record_wait_at(base + 410, 20);

        let snap = limiter.snapshot_at(base + 415);
        assert_eq!(snap.recent.waits, 2);
        assert_eq!(snap.recent.wait_ms_avg, 60);
        assert_eq!(snap.recent.wait_ms_max, 100);
        assert_eq!(snap.recent.timeouts, 0);
        assert_eq!(snap.history.len(), PRESSURE_HISTORY_BUCKETS);
        let last = snap.history.last().unwrap();
        assert_eq!(last.start, base + 360);
        assert_eq!(last.waits, 2);
        let first_minute = snap.history.iter().find(|b| b.start == base).unwrap();
        assert_eq!(first_minute.timeouts, 1);
        assert_eq!(
            snap.history
                .iter()
                .filter(|b| b.waits == 0 && b.timeouts == 0)
                .count(),
            PRESSURE_HISTORY_BUCKETS - 2
        );

        let later = limiter.snapshot_at(base + 3 * 3600);
        assert!(later
            .history
            .iter()
            .all(|b| b.waits == 0 && b.timeouts == 0));
        assert_eq!(later.recent.waits, 0);

        for minute in 0..90u64 {
            limiter.record_timeout_at(base + 7200 + minute * 60);
        }
        assert!(limiter.history.lock().unwrap().len() <= PRESSURE_HISTORY_BUCKETS);
    }

    fn stream_of(bytes: Vec<u8>) -> AsyncReadStream {
        Box::pin(std::io::Cursor::new(bytes))
    }

    #[tokio::test]
    async fn read_gate_holds_permit_only_during_reads() {
        use futures::FutureExt;
        use tokio::io::AsyncReadExt;

        let semaphore = Arc::new(Semaphore::new(1));
        let initial = semaphore.clone().try_acquire_owned().unwrap();
        let mut gate =
            DiskReadGate::new(stream_of(vec![7u8; 16]), semaphore.clone(), Some(initial));
        let mut buf = [0u8; 4];
        assert_eq!(gate.read(&mut buf).await.unwrap(), 4);
        assert_eq!(semaphore.available_permits(), 1);

        let held = semaphore.clone().try_acquire_owned().unwrap();
        assert!(gate.read(&mut buf).now_or_never().is_none());
        drop(held);
        assert_eq!(gate.read(&mut buf).await.unwrap(), 4);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn write_gate_releases_during_network_waits_and_parks_tail() {
        use futures::FutureExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let semaphore = Arc::new(Semaphore::new(1));
        let (mut client, server) = tokio::io::duplex(64);
        let tail = DiskTailPermit::default();
        let mut gate =
            DiskWriteGate::new(Box::pin(server), semaphore.clone(), None, 4, tail.clone());
        let mut buf = [0u8; 4];

        client.write_all(&[1u8; 8]).await.unwrap();
        assert_eq!(gate.read(&mut buf).await.unwrap(), 4);
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(gate.read(&mut buf).await.unwrap(), 4);
        assert!(gate.read(&mut buf).now_or_never().is_none());
        assert_eq!(semaphore.available_permits(), 1);

        client.write_all(&[2u8; 2]).await.unwrap();
        drop(client);
        assert_eq!(gate.read(&mut buf).await.unwrap(), 2);
        assert_eq!(&buf[..2], &[2u8, 2]);
        assert_eq!(gate.read(&mut buf).await.unwrap(), 0);
        assert!(tail.is_parked());
        drop(gate);
        assert_eq!(semaphore.available_permits(), 0);
        drop(tail);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn write_gate_requeues_after_quantum() {
        use futures::FutureExt;
        use tokio::io::AsyncReadExt;

        let semaphore = Arc::new(Semaphore::new(1));
        let tail = DiskTailPermit::default();
        let mut gate =
            DiskWriteGate::new(stream_of(vec![3u8; 64]), semaphore.clone(), None, 4, tail);
        let mut buf = [0u8; 4];
        for _ in 0..4 {
            assert_eq!(gate.read(&mut buf).await.unwrap(), 4);
        }
        let mut waiter = Box::pin(semaphore.clone().acquire_owned());
        assert!((&mut waiter).now_or_never().is_none());
        assert!(gate.read(&mut buf).now_or_never().is_none());
        let granted = waiter.await.unwrap();
        drop(granted);
        assert_eq!(gate.read(&mut buf).await.unwrap(), 4);
    }
}
