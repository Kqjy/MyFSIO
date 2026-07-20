use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub struct DiskQueueTimeout;

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
        }
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
                self.queue_waits.fetch_add(1, Ordering::Relaxed);
                self.queue_wait_ms_total
                    .fetch_add(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                Ok(Some(permit))
            }
            Ok(Err(_)) => Ok(None),
            Err(_) => {
                self.queue_timeouts.fetch_add(1, Ordering::Relaxed);
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

    pub fn enabled(&self) -> bool {
        self.read.is_some() || self.write.is_some()
    }

    pub fn snapshot(&self) -> DiskPressureSnapshot {
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
        assert_eq!(limiter.snapshot().queue_timeouts, 1);
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
}
