window.BucketDetailUpload = (function() {
  'use strict';

  const MULTIPART_THRESHOLD = 8 * 1024 * 1024;
  const CHUNK_SIZE = 8 * 1024 * 1024;
  const MAX_PART_RETRIES = 3;
  const RETRY_BASE_DELAY_MS = 1000;

  let state = {
    isUploading: false,
    uploadProgress: { current: 0, total: 0, currentFile: '' }
  };

  let elements = {};
  let callbacks = {};

  function init(config) {
    elements = {
      uploadForm: config.uploadForm,
      uploadFileInput: config.uploadFileInput,
      uploadModal: config.uploadModal,
      uploadModalEl: config.uploadModalEl,
      uploadSubmitBtn: config.uploadSubmitBtn,
      uploadCancelBtn: config.uploadCancelBtn,
      uploadBtnText: config.uploadBtnText,
      uploadDropZone: config.uploadDropZone,
      uploadDropZoneLabel: config.uploadDropZoneLabel,
      uploadProgressStack: config.uploadProgressStack,
      uploadKeyPrefix: config.uploadKeyPrefix,
      singleFileOptions: config.singleFileOptions,
      bulkUploadProgress: config.bulkUploadProgress,
      bulkUploadStatus: config.bulkUploadStatus,
      bulkUploadCounter: config.bulkUploadCounter,
      bulkUploadProgressBar: config.bulkUploadProgressBar,
      bulkUploadCurrentFile: config.bulkUploadCurrentFile,
      bulkUploadResults: config.bulkUploadResults,
      bulkUploadSuccessAlert: config.bulkUploadSuccessAlert,
      bulkUploadErrorAlert: config.bulkUploadErrorAlert,
      bulkUploadSuccessCount: config.bulkUploadSuccessCount,
      bulkUploadErrorCount: config.bulkUploadErrorCount,
      bulkUploadErrorList: config.bulkUploadErrorList,
      floatingProgress: config.floatingProgress,
      floatingProgressBar: config.floatingProgressBar,
      floatingProgressStatus: config.floatingProgressStatus,
      floatingProgressTitle: config.floatingProgressTitle,
      floatingProgressExpand: config.floatingProgressExpand
    };

    callbacks = {
      showMessage: config.showMessage || function() {},
      formatBytes: config.formatBytes || function(b) { return b + ' bytes'; },
      escapeHtml: config.escapeHtml || function(s) { return s; },
      onUploadComplete: config.onUploadComplete || function() {},
      hasFolders: config.hasFolders || function() { return false; },
      getCurrentPrefix: config.getCurrentPrefix || function() { return ''; }
    };

    setupEventListeners();
    setupBeforeUnload();
  }

  function isUploading() {
    return state.isUploading;
  }

  function setupBeforeUnload() {
    window.addEventListener('beforeunload', (e) => {
      if (state.isUploading) {
        e.preventDefault();
        e.returnValue = 'Upload in progress. Are you sure you want to leave?';
        return e.returnValue;
      }
    });
  }

  function showFloatingProgress() {
    if (elements.floatingProgress) {
      elements.floatingProgress.classList.remove('d-none');
    }
  }

  function hideFloatingProgress() {
    if (elements.floatingProgress) {
      elements.floatingProgress.classList.add('d-none');
    }
  }

  function updateFloatingProgress(current, total, currentFile) {
    state.uploadProgress = { current, total, currentFile: currentFile || '' };
    if (elements.floatingProgressBar && total > 0) {
      const percent = Math.round((current / total) * 100);
      elements.floatingProgressBar.style.width = `${percent}%`;
    }
    if (elements.floatingProgressStatus) {
      if (currentFile) {
        elements.floatingProgressStatus.textContent = `${current}/${total} files - ${currentFile}`;
      } else {
        elements.floatingProgressStatus.textContent = `${current}/${total} files completed`;
      }
    }
    if (elements.floatingProgressTitle) {
      elements.floatingProgressTitle.textContent = `Uploading ${total} file${total !== 1 ? 's' : ''}...`;
    }
  }

  function refreshUploadDropLabel() {
    if (!elements.uploadDropZoneLabel || !elements.uploadFileInput) return;
    const files = elements.uploadFileInput.files;
    if (!files || files.length === 0) {
      elements.uploadDropZoneLabel.textContent = 'No file selected';
      if (elements.singleFileOptions) elements.singleFileOptions.classList.remove('d-none');
      return;
    }
    elements.uploadDropZoneLabel.textContent = files.length === 1 ? files[0].name : `${files.length} files selected`;
    if (elements.singleFileOptions) {
      elements.singleFileOptions.classList.toggle('d-none', files.length > 1);
    }
  }

  function updateUploadBtnText() {
    if (!elements.uploadBtnText || !elements.uploadFileInput) return;
    const files = elements.uploadFileInput.files;
    if (!files || files.length <= 1) {
      elements.uploadBtnText.textContent = 'Upload';
    } else {
      elements.uploadBtnText.textContent = `Upload ${files.length} files`;
    }
  }

  function resetUploadUI() {
    if (elements.bulkUploadProgress) elements.bulkUploadProgress.classList.add('d-none');
    if (elements.bulkUploadResults) elements.bulkUploadResults.classList.add('d-none');
    if (elements.bulkUploadSuccessAlert) elements.bulkUploadSuccessAlert.classList.remove('d-none');
    if (elements.bulkUploadErrorAlert) elements.bulkUploadErrorAlert.classList.add('d-none');
    if (elements.bulkUploadErrorList) elements.bulkUploadErrorList.innerHTML = '';
    if (elements.uploadSubmitBtn) elements.uploadSubmitBtn.disabled = false;
    if (elements.uploadFileInput) elements.uploadFileInput.disabled = false;
    if (elements.uploadProgressStack) elements.uploadProgressStack.innerHTML = '';
    if (elements.uploadDropZone) {
      elements.uploadDropZone.classList.remove('upload-locked');
      elements.uploadDropZone.style.pointerEvents = '';
    }
    state.isUploading = false;
    hideFloatingProgress();
  }

  function setUploadLockState(locked) {
    if (elements.uploadDropZone) {
      elements.uploadDropZone.classList.toggle('upload-locked', locked);
      elements.uploadDropZone.style.pointerEvents = locked ? 'none' : '';
    }
    if (elements.uploadFileInput) {
      elements.uploadFileInput.disabled = locked;
    }
  }

  function createProgressItem(file) {
    const item = document.createElement('div');
    item.className = 'upload-progress-item';
    item.dataset.state = 'uploading';
    item.innerHTML = `
      <div class="d-flex justify-content-between align-items-start">
        <div class="min-width-0 flex-grow-1">
          <div class="file-name">${callbacks.escapeHtml(file.name)}</div>
          <div class="file-size">${callbacks.formatBytes(file.size)}</div>
        </div>
        <div class="upload-status text-end ms-2">Preparing...</div>
      </div>
      <div class="progress-container">
        <div class="progress">
          <div class="progress-bar bg-primary" role="progressbar" style="width: 0%"></div>
        </div>
        <div class="progress-text">
          <span class="progress-loaded">0 B</span>
          <span class="progress-percent">0%</span>
        </div>
      </div>
    `;
    return item;
  }

  function updateProgressItem(item, { loaded, total, status, progressState, error }) {
    if (progressState) item.dataset.state = progressState;
    const statusEl = item.querySelector('.upload-status');
    const progressBar = item.querySelector('.progress-bar');
    const progressLoaded = item.querySelector('.progress-loaded');
    const progressPercent = item.querySelector('.progress-percent');

    if (status) {
      statusEl.textContent = status;
      statusEl.className = 'upload-status text-end ms-2';
      if (progressState === 'success') statusEl.classList.add('success');
      if (progressState === 'error') statusEl.classList.add('error');
    }
    if (typeof loaded === 'number' && typeof total === 'number' && total > 0) {
      const percent = Math.round((loaded / total) * 100);
      progressBar.style.width = `${percent}%`;
      progressLoaded.textContent = `${callbacks.formatBytes(loaded)} / ${callbacks.formatBytes(total)}`;
      progressPercent.textContent = `${percent}%`;
    }
    if (error) {
      const progressContainer = item.querySelector('.progress-container');
      if (progressContainer) {
        progressContainer.innerHTML = `<div class="text-danger small mt-1">${callbacks.escapeHtml(error)}</div>`;
      }
    }
  }

  function uploadPartXHR(url, chunk, csrfToken, baseBytes, fileSize, progressItem, partNumber, totalParts) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', url, true);
      xhr.setRequestHeader('X-CSRFToken', csrfToken || '');

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          updateProgressItem(progressItem, {
            status: `Part ${partNumber}/${totalParts}`,
            loaded: baseBytes + e.loaded,
            total: fileSize
          });
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            resolve(JSON.parse(xhr.responseText));
          } catch {
            reject(new Error(`Part ${partNumber}: invalid response`));
          }
        } else {
          try {
            const data = JSON.parse(xhr.responseText);
            reject(new Error(data.error || `Part ${partNumber} failed (${xhr.status})`));
          } catch {
            reject(new Error(`Part ${partNumber} failed (${xhr.status})`));
          }
        }
      });

      xhr.addEventListener('error', () => reject(new Error(`Part ${partNumber}: network error`)));
      xhr.addEventListener('abort', () => reject(new Error(`Part ${partNumber}: aborted`)));

      xhr.send(chunk);
    });
  }

  async function uploadPartWithRetry(url, chunk, csrfToken, baseBytes, fileSize, progressItem, partNumber, totalParts) {
    let lastError;
    for (let attempt = 0; attempt <= MAX_PART_RETRIES; attempt++) {
      try {
        return await uploadPartXHR(url, chunk, csrfToken, baseBytes, fileSize, progressItem, partNumber, totalParts);
      } catch (err) {
        lastError = err;
        if (attempt < MAX_PART_RETRIES) {
          const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
          updateProgressItem(progressItem, {
            status: `Part ${partNumber}/${totalParts} retry ${attempt + 1}/${MAX_PART_RETRIES}...`,
            loaded: baseBytes,
            total: fileSize
          });
          await new Promise(r => setTimeout(r, delay));
        }
      }
    }
    throw lastError;
  }

  async function uploadMultipart(file, objectKey, metadata, progressItem, urls) {
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;

    updateProgressItem(progressItem, { status: 'Initiating...', loaded: 0, total: file.size });
    const initResp = await fetch(urls.initUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken || '' },
      body: JSON.stringify({ object_key: objectKey, metadata })
    });
    if (!initResp.ok) {
      const err = await initResp.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to initiate upload');
    }
    const { upload_id } = await initResp.json();

    const partUrl = urls.partTemplate.replace('UPLOAD_ID_PLACEHOLDER', upload_id);
    const completeUrl = urls.completeTemplate.replace('UPLOAD_ID_PLACEHOLDER', upload_id);
    const abortUrl = urls.abortTemplate.replace('UPLOAD_ID_PLACEHOLDER', upload_id);

    const parts = [];
    const totalParts = Math.ceil(file.size / CHUNK_SIZE);
    let uploadedBytes = 0;

    try {
      for (let partNumber = 1; partNumber <= totalParts; partNumber++) {
        const start = (partNumber - 1) * CHUNK_SIZE;
        const end = Math.min(start + CHUNK_SIZE, file.size);
        const chunk = file.slice(start, end);

        const partData = await uploadPartWithRetry(
          `${partUrl}?partNumber=${partNumber}`,
          chunk, csrfToken, uploadedBytes, file.size,
          progressItem, partNumber, totalParts
        );

        parts.push({ part_number: partNumber, etag: partData.etag });
        uploadedBytes += (end - start);

        updateProgressItem(progressItem, {
          loaded: uploadedBytes,
          total: file.size
        });
      }

      updateProgressItem(progressItem, { status: 'Completing...', loaded: file.size, total: file.size });
      const completeResp = await fetch(completeUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken || '' },
        body: JSON.stringify({ parts })
      });

      if (!completeResp.ok) {
        const err = await completeResp.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to complete upload');
      }

      return await completeResp.json();
    } catch (err) {
      try {
        await fetch(abortUrl, { method: 'DELETE', headers: { 'X-CSRFToken': csrfToken || '' } });
      } catch {}
      throw err;
    }
  }

  async function uploadRegular(file, objectKey, metadata, progressItem, formAction) {
    return new Promise((resolve, reject) => {
      const formData = new FormData();
      formData.append('object', file);
      formData.append('object_key', objectKey);
      if (metadata) formData.append('metadata', JSON.stringify(metadata));
      const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;
      if (csrfToken) formData.append('csrf_token', csrfToken);

      const xhr = new XMLHttpRequest();
      xhr.open('POST', formAction, true);
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
      xhr.setRequestHeader('X-CSRFToken', csrfToken || '');

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          updateProgressItem(progressItem, {
            status: 'Uploading...',
            loaded: e.loaded,
            total: e.total
          });
        }
      });

      xhr.addEventListener('load', () => {
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
            reject(new Error(data.message || `Upload failed (${xhr.status})`));
          } catch {
            reject(new Error(`Upload failed (${xhr.status})`));
          }
        }
      });

      xhr.addEventListener('error', () => reject(new Error('Network error')));
      xhr.addEventListener('abort', () => reject(new Error('Upload aborted')));

      xhr.send(formData);
    });
  }

  async function uploadSingleFile(file, keyPrefix, metadata, progressItem, urls) {
    const objectKey = keyPrefix ? `${keyPrefix}${file.name}` : file.name;
    const shouldUseMultipart = file.size >= MULTIPART_THRESHOLD && urls.initUrl;

    if (!progressItem && elements.uploadProgressStack) {
      progressItem = createProgressItem(file);
      elements.uploadProgressStack.appendChild(progressItem);
    }

    try {
      let result;
      if (shouldUseMultipart) {
        updateProgressItem(progressItem, { status: 'Multipart upload...', loaded: 0, total: file.size });
        result = await uploadMultipart(file, objectKey, metadata, progressItem, urls);
      } else {
        updateProgressItem(progressItem, { status: 'Uploading...', loaded: 0, total: file.size });
        result = await uploadRegular(file, objectKey, metadata, progressItem, urls.formAction);
      }
      updateProgressItem(progressItem, { progressState: 'success', status: 'Complete', loaded: file.size, total: file.size });
      return result;
    } catch (err) {
      updateProgressItem(progressItem, { progressState: 'error', status: 'Failed', error: err.message });
      throw err;
    }
  }

  async function performBulkUpload(files, urls) {
    if (state.isUploading || !files || files.length === 0) return;

    state.isUploading = true;
    setUploadLockState(true);
    const keyPrefix = (elements.uploadKeyPrefix?.value || '').trim();
    const metadataRaw = elements.uploadForm?.querySelector('textarea[name="metadata"]')?.value?.trim();
    let metadata = null;
    if (metadataRaw) {
      try {
        metadata = JSON.parse(metadataRaw);
      } catch {
        callbacks.showMessage({ title: 'Invalid metadata', body: 'Metadata must be valid JSON.', variant: 'danger' });
        resetUploadUI();
        return;
      }
    }

    if (elements.bulkUploadProgress) elements.bulkUploadProgress.classList.remove('d-none');
    if (elements.bulkUploadResults) elements.bulkUploadResults.classList.add('d-none');
    if (elements.uploadSubmitBtn) elements.uploadSubmitBtn.disabled = true;
    if (elements.uploadFileInput) elements.uploadFileInput.disabled = true;

    const successFiles = [];
    const errorFiles = [];
    const total = files.length;

    updateFloatingProgress(0, total, files[0]?.name || '');

    for (let i = 0; i < total; i++) {
      const file = files[i];
      const current = i + 1;

      if (elements.bulkUploadCounter) elements.bulkUploadCounter.textContent = `${current}/${total}`;
      if (elements.bulkUploadCurrentFile) elements.bulkUploadCurrentFile.textContent = `Uploading: ${file.name}`;
      if (elements.bulkUploadProgressBar) {
        const percent = Math.round((current / total) * 100);
        elements.bulkUploadProgressBar.style.width = `${percent}%`;
      }
      updateFloatingProgress(i, total, file.name);

      try {
        await uploadSingleFile(file, keyPrefix, metadata, null, urls);
        successFiles.push(file.name);
      } catch (error) {
        errorFiles.push({ name: file.name, error: error.message || 'Unknown error' });
      }
    }
    updateFloatingProgress(total, total);

    if (elements.bulkUploadProgress) elements.bulkUploadProgress.classList.add('d-none');
    if (elements.bulkUploadResults) elements.bulkUploadResults.classList.remove('d-none');

    if (elements.bulkUploadSuccessCount) elements.bulkUploadSuccessCount.textContent = successFiles.length;
    if (successFiles.length === 0 && elements.bulkUploadSuccessAlert) {
      elements.bulkUploadSuccessAlert.classList.add('d-none');
    }

    if (errorFiles.length > 0) {
      if (elements.bulkUploadErrorCount) elements.bulkUploadErrorCount.textContent = errorFiles.length;
      if (elements.bulkUploadErrorAlert) elements.bulkUploadErrorAlert.classList.remove('d-none');
      if (elements.bulkUploadErrorList) {
        elements.bulkUploadErrorList.innerHTML = errorFiles
          .map(f => `<li><strong>${callbacks.escapeHtml(f.name)}</strong>: ${callbacks.escapeHtml(f.error)}</li>`)
          .join('');
      }
    }

    state.isUploading = false;
    setUploadLockState(false);

    if (successFiles.length > 0) {
      if (elements.uploadBtnText) elements.uploadBtnText.textContent = 'Refreshing...';
      callbacks.onUploadComplete(successFiles, errorFiles);
    } else {
      if (elements.uploadSubmitBtn) elements.uploadSubmitBtn.disabled = false;
      if (elements.uploadFileInput) elements.uploadFileInput.disabled = false;
    }
  }

  function setupEventListeners() {
    if (elements.uploadFileInput) {
      elements.uploadFileInput.addEventListener('change', () => {
        if (state.isUploading) return;
        refreshUploadDropLabel();
        updateUploadBtnText();
        resetUploadUI();
      });
    }

    if (elements.uploadDropZone) {
      elements.uploadDropZone.addEventListener('click', () => {
        if (state.isUploading) return;
        elements.uploadFileInput?.click();
      });
    }

    if (elements.floatingProgressExpand) {
      elements.floatingProgressExpand.addEventListener('click', () => {
        if (elements.uploadModal) {
          elements.uploadModal.show();
        }
      });
    }

    if (elements.uploadModalEl) {
      elements.uploadModalEl.addEventListener('hide.bs.modal', () => {
        if (state.isUploading) {
          showFloatingProgress();
        }
      });

      elements.uploadModalEl.addEventListener('hidden.bs.modal', () => {
        if (!state.isUploading) {
          resetUploadUI();
          if (elements.uploadFileInput) elements.uploadFileInput.value = '';
          refreshUploadDropLabel();
          updateUploadBtnText();
        }
      });

      elements.uploadModalEl.addEventListener('show.bs.modal', () => {
        if (state.isUploading) {
          hideFloatingProgress();
        }
        if (callbacks.hasFolders() && callbacks.getCurrentPrefix()) {
          if (elements.uploadKeyPrefix) {
            elements.uploadKeyPrefix.value = callbacks.getCurrentPrefix();
          }
        } else if (elements.uploadKeyPrefix) {
          elements.uploadKeyPrefix.value = '';
        }
      });
    }
  }

  function wireDropTarget(target, options) {
    const { highlightClass = '', autoOpenModal = false } = options || {};
    if (!target) return;

    const preventDefaults = (event) => {
      event.preventDefault();
      event.stopPropagation();
    };

    ['dragenter', 'dragover'].forEach((eventName) => {
      target.addEventListener(eventName, (event) => {
        preventDefaults(event);
        if (state.isUploading) return;
        if (highlightClass) {
          target.classList.add(highlightClass);
        }
      });
    });

    ['dragleave', 'drop'].forEach((eventName) => {
      target.addEventListener(eventName, (event) => {
        preventDefaults(event);
        if (highlightClass) {
          target.classList.remove(highlightClass);
        }
      });
    });

    target.addEventListener('drop', (event) => {
      if (state.isUploading) return;
      if (!event.dataTransfer?.files?.length || !elements.uploadFileInput) {
        return;
      }
      elements.uploadFileInput.files = event.dataTransfer.files;
      elements.uploadFileInput.dispatchEvent(new Event('change', { bubbles: true }));
      if (autoOpenModal && elements.uploadModal) {
        elements.uploadModal.show();
      }
    });
  }

  return {
    init: init,
    isUploading: isUploading,
    performBulkUpload: performBulkUpload,
    wireDropTarget: wireDropTarget,
    resetUploadUI: resetUploadUI,
    refreshUploadDropLabel: refreshUploadDropLabel,
    updateUploadBtnText: updateUploadBtnText
  };
})();
