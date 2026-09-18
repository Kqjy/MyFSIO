use super::*;

#[derive(Clone)]
pub(super) struct ListingCompactionWork {
    pub(super) bucket: String,
    pub(super) index: Arc<Mutex<BucketListingIndex>>,
    pub(super) rebuild_lock: Arc<Mutex<()>>,
    pub(super) temp_dir: PathBuf,
}

pub(super) enum ListingCompactionCommand {
    Compact(ListingCompactionWork),
    Shutdown,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct ListingCompactionTestControl {
    pub(super) pause_after_seal: std::sync::atomic::AtomicBool,
    pub(super) sealed: Mutex<HashSet<String>>,
    pub(super) changed: Condvar,
}

pub(super) struct ListingCompactor {
    pub(super) sender: Mutex<Option<mpsc::Sender<ListingCompactionCommand>>>,
    pub(super) pending: Arc<Mutex<HashSet<String>>>,
    pub(super) handle: Mutex<Option<std::thread::JoinHandle<()>>>,
    #[cfg(test)]
    pub(super) test_control: Arc<ListingCompactionTestControl>,
}

impl ListingCompactor {
    pub(super) fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        let pending = Arc::new(Mutex::new(HashSet::new()));
        let worker_pending = pending.clone();
        let retry_sender = sender.clone();
        #[cfg(test)]
        let test_control = Arc::new(ListingCompactionTestControl::default());
        #[cfg(test)]
        let worker_test_control = test_control.clone();
        let handle = std::thread::Builder::new()
            .name("myfsio-listing-compactor".to_string())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    let ListingCompactionCommand::Compact(work) = command else {
                        break;
                    };
                    let result = compact_listing_index_work(
                        &work,
                        #[cfg(test)]
                        &worker_test_control,
                    );
                    match result {
                        Ok(()) => {
                            worker_pending.lock().remove(&work.bucket);
                        }
                        Err(err) => {
                            let retry = {
                                let mut index = work.index.lock();
                                let retry = index.is_valid();
                                if retry {
                                    index.request_compaction_retry();
                                }
                                retry
                            };
                            if retry {
                                tracing::warn!(
                                    bucket = work.bucket,
                                    error = %err,
                                    "listing index background compaction failed; retrying"
                                );
                                std::thread::sleep(std::time::Duration::from_millis(100));
                                if retry_sender
                                    .send(ListingCompactionCommand::Compact(work.clone()))
                                    .is_err()
                                {
                                    worker_pending.lock().remove(&work.bucket);
                                }
                            } else {
                                worker_pending.lock().remove(&work.bucket);
                            }
                        }
                    }
                }
                worker_pending.lock().clear();
            })
            .expect("failed to start listing compactor");
        Self {
            sender: Mutex::new(Some(sender)),
            pending,
            handle: Mutex::new(Some(handle)),
            #[cfg(test)]
            test_control,
        }
    }

    fn enqueue(
        &self,
        bucket: &str,
        index: Arc<Mutex<BucketListingIndex>>,
        rebuild_lock: Arc<Mutex<()>>,
        temp_dir: PathBuf,
    ) {
        if !self.pending.lock().insert(bucket.to_string()) {
            return;
        }
        let command = ListingCompactionCommand::Compact(ListingCompactionWork {
            bucket: bucket.to_string(),
            index,
            rebuild_lock,
            temp_dir,
        });
        let sent = self
            .sender
            .lock()
            .as_ref()
            .is_some_and(|sender| sender.send(command).is_ok());
        if !sent {
            self.pending.lock().remove(bucket);
        }
    }

    pub(super) fn shutdown(&self) {
        #[cfg(test)]
        {
            self.test_control
                .pause_after_seal
                .store(false, std::sync::atomic::Ordering::Release);
            self.test_control.changed.notify_all();
        }
        if let Some(sender) = self.sender.lock().take() {
            let _ = sender.send(ListingCompactionCommand::Shutdown);
        }
        if let Some(handle) = self.handle.lock().take() {
            let _ = handle.join();
        }
    }
}

pub(super) fn compact_listing_index_work(
    work: &ListingCompactionWork,
    #[cfg(test)] test_control: &ListingCompactionTestControl,
) -> std::io::Result<()> {
    loop {
        let sealed = {
            let _rebuild_guard = work.rebuild_lock.lock();
            let mut index = work.index.lock();
            index.seal_for_compaction()?
        };
        let Some(sealed) = sealed else {
            return Ok(());
        };
        #[cfg(test)]
        wait_after_listing_compaction_seal(test_control, &work.bucket);
        let snapshot = crate::listing_index::prepare_compaction_snapshot(&sealed)?;
        let temp_path = work.temp_dir.join(format!(
            "listing-{}-{}-{}.tmp",
            sealed.identity,
            sealed.cutoff_generation,
            Uuid::new_v4()
        ));
        #[cfg(any(test, feature = "failpoints"))]
        crate::listing_index::hit_failpoint(&sealed.listing_dir, "listing:snapshot-write")?;
        crate::listing_index::write_snapshot_temp(&temp_path, &snapshot)?;

        let install_started = {
            let _rebuild_guard = work.rebuild_lock.lock();
            work.index.lock().begin_compaction_install(&sealed)
        };
        if !install_started {
            let _ = std::fs::remove_file(temp_path);
            return Ok(());
        }
        match crate::listing_index::install_snapshot_temp(&temp_path, &sealed.listing_dir) {
            Ok(()) => {}
            Err(_)
                if !temp_path.exists()
                    && crate::listing_index::confirm_compaction_snapshot(&sealed).is_ok() => {}
            Err(err) => {
                work.index
                    .lock()
                    .complete_compaction_install(&sealed, false);
                let _ = std::fs::remove_file(&temp_path);
                return Err(err);
            }
        }
        let cleanup_result = crate::listing_index::delete_covered_journals(
            &sealed.listing_dir,
            sealed.cutoff_generation,
        );
        let mut index = work.index.lock();
        index.complete_compaction_install(&sealed, true);
        let compact_again = index.mark_compact_pending_if_needed();
        drop(index);
        cleanup_result?;
        if !compact_again {
            return Ok(());
        }
    }
}

pub(super) fn wait_for_listing_compaction_install(index: &Arc<Mutex<BucketListingIndex>>) {
    while index.lock().is_compaction_installing() {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[cfg(test)]
pub(super) fn wait_after_listing_compaction_seal(
    control: &ListingCompactionTestControl,
    bucket: &str,
) {
    if !control
        .pause_after_seal
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return;
    }
    let mut sealed = control.sealed.lock();
    sealed.insert(bucket.to_string());
    control.changed.notify_all();
    while control
        .pause_after_seal
        .load(std::sync::atomic::Ordering::Acquire)
    {
        control.changed.wait(&mut sealed);
    }
}

impl FsStorageBackend {
    pub fn shutdown_listing_compactor(&self) {
        if let Some(compactor) = &self.listing_compactor {
            compactor.shutdown();
        }
    }

    pub(super) fn enqueue_listing_compaction(
        &self,
        bucket_name: &str,
        index: Arc<Mutex<BucketListingIndex>>,
        rebuild_lock: Arc<Mutex<()>>,
    ) {
        if let Some(compactor) = &self.listing_compactor {
            compactor.enqueue(bucket_name, index, rebuild_lock, self.system_tmp_dir());
        }
    }

    #[cfg(test)]
    pub(super) fn pause_listing_compactor_after_seal(&self, paused: bool) {
        let Some(compactor) = &self.listing_compactor else {
            return;
        };
        compactor
            .test_control
            .pause_after_seal
            .store(paused, std::sync::atomic::Ordering::Release);
        if !paused {
            compactor.test_control.changed.notify_all();
        }
    }

    #[cfg(test)]
    pub(super) fn wait_for_listing_compactor_seal(
        &self,
        bucket: &str,
        timeout: std::time::Duration,
    ) -> bool {
        let Some(compactor) = &self.listing_compactor else {
            return false;
        };
        let mut sealed = compactor.test_control.sealed.lock();
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if sealed.remove(bucket) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            compactor
                .test_control
                .changed
                .wait_for(&mut sealed, remaining);
        }
    }
}
