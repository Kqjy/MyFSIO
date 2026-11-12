window.BucketDetailUpload = (function() {
  'use strict';

  const MULTIPART_THRESHOLD = 8 * 1024 * 1024;
  const CHUNK_SIZE = 8 * 1024 * 1024;

  function init(ctx) {
    const { escapeHtml } = window.BucketDetailUtils;
    const formatBytes = window.MyFSIO.formatBytes;
    const uploadForm = document.querySelector('[data-upload-form]');
    const uploadFileInput = uploadForm?.querySelector('input[name="object"]');
    if (!uploadForm || !uploadFileInput) return;

    const uploadDialog = document.getElementById('uploadModal');
    const uploadDropZone = uploadForm.querySelector('[data-dropzone]');
    const uploadDropZoneLabel = uploadDropZone?.querySelector('[data-dropzone-label]');
    const uploadDestination = document.getElementById('uploadDestination');
    const uploadSubmitBtn = document.getElementById('uploadSubmitBtn');
    const uploadBtnText = document.getElementById('uploadBtnText');
    const uploadKeyPrefix = document.getElementById('uploadKeyPrefix');
    const uploadObjectKey = uploadForm.querySelector('input[name="object_key"]');
    const singleFileOptions = document.getElementById('singleFileOptions');
    const tray = document.getElementById('uploadTray');
    const trayTitle = document.getElementById('uploadTrayTitle');
    const traySummary = document.getElementById('uploadTraySummary');
    const trayBar = document.getElementById('uploadTrayBar');
    const trayList = document.getElementById('uploadTrayList');
    const trayToggle = document.getElementById('uploadTrayToggle');
    const trayClose = document.getElementById('uploadTrayClose');
    const multipartInitUrl = uploadForm.dataset.multipartInitUrl;
    const multipartPartTemplate = uploadForm.dataset.multipartPartTemplate;
    const multipartCompleteTemplate = uploadForm.dataset.multipartCompleteTemplate;
    const multipartAbortTemplate = uploadForm.dataset.multipartAbortTemplate;

    let isUploading = false;
    let isProcessingQueue = false;
    let uploadCancelled = false;
    let uploadQueue = [];
    let activeXHRs = [];
    let activeMultipartUpload = null;
    let uploadSuccessFiles = [];
    let uploadErrorFiles = [];
    let uploadStats = { totalFiles: 0, completedFiles: 0, totalBytes: 0, uploadedBytes: 0, currentFileLoaded: 0 };

    const csrfToken = () => document.querySelector('input[name="csrf_token"]')?.value || '';
    const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

    const normalizeUploadPrefix = (raw) => {
      let prefix = (raw || '').trim().replace(/^\/+/, '');
      if (prefix && !prefix.endsWith('/')) prefix += '/';
      return prefix;
    };

    const updateUploadDestination = () => {
      if (!uploadDestination) return;
      const bucketName = ctx.objectsContainer?.dataset.bucket || '';
      const prefix = normalizeUploadPrefix(uploadKeyPrefix?.value);
      uploadDestination.textContent = prefix ? `${bucketName}/${prefix}` : bucketName;
    };

    window.addEventListener('beforeunload', (e) => {
      if (isUploading) {
        e.preventDefault();
        e.returnValue = 'Upload in progress. Are you sure you want to leave?';
        return e.returnValue;
      }
    });

    const setTrayCollapsed = (collapsed) => {
      if (!tray) return;
      tray.classList.toggle('is-collapsed', collapsed);
      trayToggle?.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      trayToggle?.setAttribute('aria-label', collapsed ? 'Show uploads' : 'Hide uploads');
    };

    const updateTray = () => {
      if (!tray) return;
      const { totalFiles, completedFiles, totalBytes, uploadedBytes, currentFileLoaded } = uploadStats;
      const effectiveUploaded = Math.min(totalBytes, uploadedBytes + currentFileLoaded);
      const percent = totalBytes > 0 ? Math.round((effectiveUploaded / totalBytes) * 100) : 0;
      if (isUploading) {
        trayTitle.textContent = `Uploading ${Math.min(completedFiles + 1, totalFiles)} of ${totalFiles}`;
        traySummary.textContent = `${formatBytes(effectiveUploaded)} of ${formatBytes(totalBytes)} · ${percent}%`;
        trayClose?.setAttribute('aria-label', 'Cancel uploads');
        trayClose?.setAttribute('data-ui-tip', 'Cancel uploads');
      } else {
        trayClose?.setAttribute('aria-label', 'Dismiss');
        trayClose?.setAttribute('data-ui-tip', 'Dismiss');
      }
      if (trayBar) trayBar.style.width = `${isUploading ? percent : 100}%`;
    };

    const createProgressItem = (file) => {
      const item = document.createElement('div');
      item.className = 'ob-upload-row';
      item.dataset.state = 'queued';
      item.innerHTML = `
        <div class="ob-upload-line">
          <span class="ob-upload-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
          <span class="ob-upload-state">Queued</span>
        </div>
        <div class="ui-bar"><i></i></div>
        <div class="ob-upload-sub">${formatBytes(file.size)}</div>
      `;
      item.querySelector('.ui-bar > i').style.width = '0%';
      return item;
    };

    const updateProgressItem = (item, { loaded, total, status, state, error }) => {
      if (!item) return;
      if (state) item.dataset.state = state;
      const stateEl = item.querySelector('.ob-upload-state');
      const bar = item.querySelector('.ui-bar');
      const subEl = item.querySelector('.ob-upload-sub');
      const current = item.dataset.state;
      if (status) item.dataset.status = status;
      if (typeof loaded === 'number' && typeof total === 'number' && total > 0) {
        const percent = Math.round((loaded / total) * 100);
        bar.firstElementChild.style.width = `${percent}%`;
        if (current === 'uploading') stateEl.textContent = `${percent}%`;
        const detail = item.dataset.status ? ` · ${item.dataset.status}` : '';
        subEl.textContent = `${formatBytes(loaded)} of ${formatBytes(total)}${current === 'uploading' ? detail : ''}`;
      }
      if (current === 'success') {
        stateEl.className = 'ob-upload-state ui-badge ui-badge-ok';
        stateEl.textContent = 'Done';
        bar.hidden = true;
      } else if (current === 'error' || current === 'cancelled') {
        stateEl.className = `ob-upload-state ui-badge ${current === 'error' ? 'ui-badge-bad' : ''}`;
        stateEl.textContent = current === 'error' ? 'Failed' : 'Cancelled';
        bar.hidden = true;
        if (error) subEl.textContent = error;
      }
    };

    const uploadMultipart = async (file, objectKey, metadata, progressItem) => {
      if (uploadCancelled) throw new Error('Upload cancelled');

      updateProgressItem(progressItem, { status: 'starting', loaded: 0, total: file.size });
      const initResp = await fetch(multipartInitUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
        body: JSON.stringify({ object_key: objectKey, metadata })
      });
      if (!initResp.ok) {
        const err = await initResp.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to initiate upload');
      }
      const { upload_id } = await initResp.json();

      const partUrl = multipartPartTemplate.replace('UPLOAD_ID_PLACEHOLDER', upload_id);
      const completeUrl = multipartCompleteTemplate.replace('UPLOAD_ID_PLACEHOLDER', upload_id);
      const abortUrl = multipartAbortTemplate.replace('UPLOAD_ID_PLACEHOLDER', upload_id);

      activeMultipartUpload = { upload_id, abortUrl };

      const parts = [];
      const totalParts = Math.ceil(file.size / CHUNK_SIZE);
      let uploadedBytes = 0;

      try {
        for (let partNumber = 1; partNumber <= totalParts; partNumber++) {
          if (uploadCancelled) throw new Error('Upload cancelled');

          const start = (partNumber - 1) * CHUNK_SIZE;
          const end = Math.min(start + CHUNK_SIZE, file.size);
          const chunk = file.slice(start, end);

          updateProgressItem(progressItem, {
            status: `part ${partNumber}/${totalParts}`,
            loaded: uploadedBytes,
            total: file.size
          });
          uploadStats.currentFileLoaded = uploadedBytes;
          updateTray();

          const partResp = await fetch(`${partUrl}?partNumber=${partNumber}`, {
            method: 'PUT',
            headers: {
              'X-CSRFToken': csrfToken(),
              'Content-Type': 'application/octet-stream'
            },
            body: chunk
          });

          if (uploadCancelled) throw new Error('Upload cancelled');

          if (!partResp.ok) {
            const err = await partResp.json().catch(() => ({}));
            throw new Error(err.error || `Part ${partNumber} failed`);
          }

          const partData = await partResp.json();
          parts.push({ part_number: partNumber, etag: partData.etag });
          uploadedBytes += chunk.size;

          updateProgressItem(progressItem, { loaded: uploadedBytes, total: file.size });
          uploadStats.currentFileLoaded = uploadedBytes;
          updateTray();
        }

        updateProgressItem(progressItem, { status: 'completing', loaded: file.size, total: file.size });
        const completeResp = await fetch(completeUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
          body: JSON.stringify({ parts })
        });

        if (!completeResp.ok) {
          const err = await completeResp.json().catch(() => ({}));
          throw new Error(err.error || 'Failed to complete upload');
        }

        activeMultipartUpload = null;
        return await completeResp.json();
      } catch (err) {
        if (!uploadCancelled) {
          try {
            await fetch(abortUrl, { method: 'DELETE', headers: { 'X-CSRFToken': csrfToken() } });
          } catch { }
        }
        activeMultipartUpload = null;
        throw err;
      }
    };

    const uploadRegular = (file, objectKey, metadata, progressItem) => {
      return new Promise((resolve, reject) => {
        const formData = new FormData();
        formData.append('object', file);
        formData.append('object_key', objectKey);
        if (metadata) formData.append('metadata', JSON.stringify(metadata));
        const token = csrfToken();
        if (token) formData.append('csrf_token', token);

        const xhr = new XMLHttpRequest();
        activeXHRs.push(xhr);
        xhr.open('POST', uploadForm.action, true);
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
        xhr.setRequestHeader('X-CSRFToken', token);

        const removeXHR = () => {
          const idx = activeXHRs.indexOf(xhr);
          if (idx > -1) activeXHRs.splice(idx, 1);
        };

        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) {
            updateProgressItem(progressItem, { loaded: Math.min(e.loaded, file.size), total: file.size });
            uploadStats.currentFileLoaded = Math.min(e.loaded, file.size);
            updateTray();
          }
        });

        xhr.addEventListener('load', () => {
          removeXHR();
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              const data = JSON.parse(xhr.responseText);
              if (data.status === 'error') {
                reject(new Error(data.message || 'Upload failed'));
              } else {
                resolve(data);
              }
            } catch {
              resolve({});
            }
          } else {
            try {
              const data = JSON.parse(xhr.responseText);
              reject(new Error(data.error || data.message || `Upload failed (${xhr.status})`));
            } catch {
              reject(new Error(`Upload failed (${xhr.status})`));
            }
          }
        });

        xhr.addEventListener('error', () => { removeXHR(); reject(new Error('Network error')); });
        xhr.addEventListener('abort', () => { removeXHR(); reject(new Error('Upload cancelled')); });

        xhr.send(formData);
      });
    };

    const uploadSingleFile = async ({ file, objectKey, metadata, progressItem }) => {
      const shouldUseMultipart = file.size >= MULTIPART_THRESHOLD && multipartInitUrl;
      progressItem.scrollIntoView({ block: 'nearest' });
      try {
        let result;
        updateProgressItem(progressItem, { state: 'uploading', loaded: 0, total: file.size });
        if (shouldUseMultipart) {
          result = await uploadMultipart(file, objectKey, metadata, progressItem);
        } else {
          result = await uploadRegular(file, objectKey, metadata, progressItem);
        }
        updateProgressItem(progressItem, { state: 'success', loaded: file.size, total: file.size });
        return result;
      } catch (err) {
        updateProgressItem(progressItem, { state: uploadCancelled ? 'cancelled' : 'error', error: err.message });
        throw err;
      }
    };

    const refreshUploadDropLabel = () => {
      const files = uploadFileInput.files;
      const count = files ? files.length : 0;
      if (uploadDropZoneLabel) {
        if (count === 0) uploadDropZoneLabel.textContent = 'No files selected';
        else uploadDropZoneLabel.textContent = count === 1 ? files[0].name : `${count} files selected`;
      }
      if (singleFileOptions) singleFileOptions.hidden = count > 1;
      if (uploadSubmitBtn) uploadSubmitBtn.disabled = count === 0;
      if (uploadBtnText) {
        if (isUploading) uploadBtnText.textContent = count > 0 ? `Add ${count} to queue` : 'Add to queue';
        else uploadBtnText.textContent = count > 1 ? `Upload ${count} files` : 'Upload';
      }
    };

    const processUploadQueue = async () => {
      if (isProcessingQueue) return;
      isProcessingQueue = true;

      while (uploadQueue.length > 0 && !uploadCancelled) {
        const item = uploadQueue.shift();
        uploadStats.currentFileLoaded = 0;
        updateTray();

        try {
          await uploadSingleFile(item);
          uploadSuccessFiles.push(item.file.name);
        } catch (error) {
          uploadErrorFiles.push({ name: item.file.name, error: error.message || 'Unknown error' });
        }
        ctx.clearVersionsCache();

        if (uploadCancelled) break;
        uploadStats.uploadedBytes += item.file.size;
        uploadStats.completedFiles++;
        uploadStats.currentFileLoaded = 0;
        updateTray();
      }

      isProcessingQueue = false;

      if (uploadQueue.length === 0 && !uploadCancelled) {
        finishUploadSession();
      }
    };

    const reloadObjects = () => {
      const previousKey = ctx.getActiveRow()?.dataset.key || null;
      ctx.loadObjects(false).then(() => {
        if (!previousKey) return;
        const newRow = document.querySelector(`[data-object-row][data-key="${CSS.escape(previousKey)}"]`);
        if (newRow) {
          ctx.selectRow(newRow);
          if (ctx.versioningEnabled) ctx.loadObjectVersions(newRow, { force: true });
        }
      });
    };

    const finishUploadSession = () => {
      isUploading = false;
      uploadFileInput.value = '';
      refreshUploadDropLabel();

      const successCount = uploadSuccessFiles.length;
      const errorCount = uploadErrorFiles.length;
      if (errorCount > 0 && successCount > 0) trayTitle.textContent = `${successCount} uploaded, ${errorCount} failed`;
      else if (errorCount > 0) trayTitle.textContent = `${plural(errorCount, 'upload')} failed`;
      else trayTitle.textContent = `${plural(successCount, 'file')} uploaded`;
      traySummary.textContent = formatBytes(uploadStats.totalBytes);
      tray.dataset.state = errorCount > 0 ? 'error' : 'success';
      updateTray();
      if (errorCount > 0) setTrayCollapsed(false);

      reloadObjects();

      const failureDetail = () => {
        const shown = uploadErrorFiles.slice(0, 2).map(f => `${f.name}: ${f.error}`);
        const remaining = errorCount - shown.length;
        if (remaining > 0) shown.push(`and ${remaining} more`);
        return ` ${shown.join('; ')}`;
      };
      if (successCount > 0 && errorCount > 0) {
        ctx.showMessage({ title: 'Upload complete', body: `${successCount} uploaded, ${errorCount} failed.${failureDetail()}`, variant: 'warning' });
      } else if (successCount > 0) {
        ctx.showMessage({ title: 'Upload complete', body: `${plural(successCount, 'object')} uploaded successfully.`, variant: 'success' });
      } else if (errorCount > 0) {
        ctx.showMessage({ title: 'Upload failed', body: `${plural(errorCount, 'file')} failed to upload.${failureDetail()}`, variant: 'danger' });
      }
      if (successCount > 0) ctx.refreshBucketUsage();
    };

    const cancelAllUploads = async () => {
      uploadCancelled = true;

      activeXHRs.forEach(xhr => {
        try { xhr.abort(); } catch { }
      });
      activeXHRs = [];

      if (activeMultipartUpload) {
        const { abortUrl } = activeMultipartUpload;
        try {
          await fetch(abortUrl, { method: 'DELETE', headers: { 'X-CSRFToken': csrfToken() } });
        } catch { }
        activeMultipartUpload = null;
      }

      uploadQueue.forEach(item => updateProgressItem(item.progressItem, { state: 'cancelled' }));
      uploadQueue = [];
      isUploading = false;
      trayTitle.textContent = 'Upload cancelled';
      traySummary.textContent = `${uploadStats.completedFiles} of ${plural(uploadStats.totalFiles, 'file')} uploaded`;
      tray.dataset.state = 'cancelled';
      updateTray();
      refreshUploadDropLabel();

      ctx.showMessage({ title: 'Upload cancelled', body: 'All uploads have been cancelled.', variant: 'info' });
      ctx.loadObjects(false);
      if (uploadStats.completedFiles > 0) ctx.refreshBucketUsage();
    };

    const dismissTray = () => {
      tray.hidden = true;
      trayList.innerHTML = '';
    };

    trayClose?.addEventListener('click', () => {
      if (isUploading) cancelAllUploads();
      else dismissTray();
    });

    trayToggle?.addEventListener('click', () => {
      setTrayCollapsed(!tray.classList.contains('is-collapsed'));
    });

    const startUploads = (files, { keyPrefix = '', metadata = null, objectKey = '' } = {}) => {
      const list = Array.from(files || []);
      if (list.length === 0 || !tray) return;

      if (!isUploading) {
        isUploading = true;
        uploadCancelled = false;
        uploadSuccessFiles = [];
        uploadErrorFiles = [];
        uploadStats = { totalFiles: 0, completedFiles: 0, totalBytes: 0, uploadedBytes: 0, currentFileLoaded: 0 };
        trayList.innerHTML = '';
        tray.dataset.state = 'uploading';
        tray.hidden = false;
        setTrayCollapsed(false);
      }

      list.forEach((file) => {
        const progressItem = createProgressItem(file);
        trayList.appendChild(progressItem);
        const key = list.length === 1 && objectKey ? objectKey : `${keyPrefix}${file.name}`;
        uploadQueue.push({ file, objectKey: key, metadata, progressItem });
        uploadStats.totalFiles++;
        uploadStats.totalBytes += file.size;
      });
      updateTray();
      processUploadQueue();
    };

    uploadFileInput.addEventListener('change', refreshUploadDropLabel);
    uploadDropZone?.addEventListener('click', () => uploadFileInput.click());
    uploadDropZone?.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      uploadFileInput.click();
    });
    uploadKeyPrefix?.addEventListener('input', updateUploadDestination);

    uploadForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const files = Array.from(uploadFileInput.files || []);
      if (files.length === 0) return;

      const metadataRaw = uploadForm.querySelector('textarea[name="metadata"]')?.value?.trim();
      let metadata = null;
      if (metadataRaw) {
        try {
          metadata = JSON.parse(metadataRaw);
        } catch {
          window.showToast('Metadata must be valid JSON.', 'Invalid metadata', 'danger');
          return;
        }
      }

      const options = {
        keyPrefix: normalizeUploadPrefix(uploadKeyPrefix?.value),
        metadata,
        objectKey: (uploadObjectKey?.value || '').trim().replace(/^\/+/, '')
      };
      window.UI.dialog.close(uploadDialog);
      uploadFileInput.value = '';
      if (uploadObjectKey) uploadObjectKey.value = '';
      refreshUploadDropLabel();
      startUploads(files, options);
    });

    uploadDialog?.addEventListener('ui:open', () => {
      if (uploadKeyPrefix) {
        const prefix = ctx.hasFolders() ? ctx.getCurrentPrefix() : '';
        uploadKeyPrefix.value = prefix || '';
        if (prefix) window.UI.collapse.set('#uploadAdvancedOptions', true);
      }
      updateUploadDestination();
      refreshUploadDropLabel();
    });

    uploadDialog?.addEventListener('close', () => {
      uploadFileInput.value = '';
      refreshUploadDropLabel();
    });

    const wireDropTarget = (target, highlightClass, onFiles) => {
      if (!target) return;
      ['dragenter', 'dragover'].forEach((eventName) => {
        target.addEventListener(eventName, (event) => {
          event.preventDefault();
          event.stopPropagation();
          target.classList.add(highlightClass);
        });
      });
      ['dragleave', 'drop'].forEach((eventName) => {
        target.addEventListener(eventName, (event) => {
          event.preventDefault();
          event.stopPropagation();
          target.classList.remove(highlightClass);
        });
      });
      target.addEventListener('drop', (event) => {
        if (event.dataTransfer?.files?.length) onFiles(event.dataTransfer.files);
      });
    };

    wireDropTarget(uploadDropZone, 'is-dragover', (files) => {
      uploadFileInput.files = files;
      uploadFileInput.dispatchEvent(new Event('change', { bubbles: true }));
    });

    wireDropTarget(ctx.objectsContainer, 'drag-over', (files) => {
      startUploads(files, { keyPrefix: ctx.hasFolders() ? (ctx.getCurrentPrefix() || '') : '' });
    });

    refreshUploadDropLabel();
  }

  return { init: init };
})();
