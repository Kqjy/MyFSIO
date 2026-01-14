(function () {
  'use strict';

  const { formatBytes, escapeHtml, fallbackCopy, setupJsonAutoIndent } = window.BucketDetailUtils || {
    formatBytes: (bytes) => {
      if (!Number.isFinite(bytes)) return `${bytes} bytes`;
      const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
      let i = 0;
      let size = bytes;
      while (size >= 1024 && i < units.length - 1) {
        size /= 1024;
        i++;
      }
      return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
    },
    escapeHtml: (value) => {
      if (value === null || value === undefined) return '';
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    },
    fallbackCopy: () => false,
    setupJsonAutoIndent: () => { }
  };

  setupJsonAutoIndent(document.getElementById('policyDocument'));

  const selectAllCheckbox = document.querySelector('[data-select-all]');
  const bulkDeleteButton = document.querySelector('[data-bulk-delete-trigger]');
  const bulkDeleteLabel = bulkDeleteButton?.querySelector('[data-bulk-delete-label]');
  const bulkDeleteModalEl = document.getElementById('bulkDeleteModal');
  const bulkDeleteModal = bulkDeleteModalEl ? new bootstrap.Modal(bulkDeleteModalEl) : null;
  const bulkDeleteList = document.getElementById('bulkDeleteList');
  const bulkDeleteCount = document.getElementById('bulkDeleteCount');
  const bulkDeleteStatus = document.getElementById('bulkDeleteStatus');
  const bulkDeleteConfirm = document.getElementById('bulkDeleteConfirm');
  const bulkDeletePurge = document.getElementById('bulkDeletePurge');
  const previewPanel = document.getElementById('preview-panel');
  const previewEmpty = document.getElementById('preview-empty');
  const previewKey = document.getElementById('preview-key');
  const previewSize = document.getElementById('preview-size');
  const previewModified = document.getElementById('preview-modified');
  const previewEtag = document.getElementById('preview-etag');
  const previewMetadata = document.getElementById('preview-metadata');
  const previewMetadataList = document.getElementById('preview-metadata-list');
  const previewPlaceholder = document.getElementById('preview-placeholder');
  const previewImage = document.getElementById('preview-image');
  const previewVideo = document.getElementById('preview-video');
  const previewIframe = document.getElementById('preview-iframe');
  const downloadButton = document.getElementById('downloadButton');
  const presignButton = document.getElementById('presignButton');
  const presignModalEl = document.getElementById('presignModal');
  const presignModal = presignModalEl ? new bootstrap.Modal(presignModalEl) : null;
  const presignMethod = document.getElementById('presignMethod');
  const presignTtl = document.getElementById('presignTtl');
  const presignLink = document.getElementById('presignLink');
  const copyPresignLink = document.getElementById('copyPresignLink');
  const copyPresignDefaultLabel = copyPresignLink?.textContent?.trim() || 'Copy';
  const generatePresignButton = document.getElementById('generatePresignButton');
  const policyForm = document.getElementById('bucketPolicyForm');
  const policyTextarea = document.getElementById('policyDocument');
  const policyPreset = document.getElementById('policyPreset');
  const policyMode = document.getElementById('policyMode');
  const uploadForm = document.querySelector('[data-upload-form]');
  const uploadModalEl = document.getElementById('uploadModal');
  const uploadModal = uploadModalEl ? bootstrap.Modal.getOrCreateInstance(uploadModalEl) : null;
  const uploadFileInput = uploadForm?.querySelector('input[name="object"]');
  const uploadDropZone = uploadForm?.querySelector('[data-dropzone]');
  const uploadDropZoneLabel = uploadDropZone?.querySelector('[data-dropzone-label]');
  const messageModalEl = document.getElementById('messageModal');
  const messageModal = messageModalEl ? new bootstrap.Modal(messageModalEl) : null;
  const messageModalTitle = document.getElementById('messageModalTitle');
  const messageModalBody = document.getElementById('messageModalBody');
  const messageModalAction = document.getElementById('messageModalAction');
  let messageModalActionHandler = null;
  let isGeneratingPresign = false;
  const objectsContainer = document.querySelector('.objects-table-container[data-bucket]');
  const bulkDeleteEndpoint = objectsContainer?.dataset.bulkDeleteEndpoint || '';
  const objectsApiUrl = objectsContainer?.dataset.objectsApi || '';
  const objectsStreamUrl = objectsContainer?.dataset.objectsStream || '';
  const versionPanel = document.getElementById('version-panel');
  const versionList = document.getElementById('version-list');
  const refreshVersionsButton = document.getElementById('refreshVersionsButton');
  const archivedCard = document.getElementById('archived-objects-card');
  const archivedBody = archivedCard?.querySelector('[data-archived-body]');
  const archivedCountBadge = archivedCard?.querySelector('[data-archived-count]');
  const archivedRefreshButton = archivedCard?.querySelector('[data-archived-refresh]');
  const archivedEndpoint = archivedCard?.dataset.archivedEndpoint;
  let versioningEnabled = objectsContainer?.dataset.versioning === 'true';
  const versionsCache = new Map();
  let activeRow = null;
  const selectedRows = new Map();
  let bulkDeleting = false;
  if (presignButton) presignButton.disabled = true;
  if (generatePresignButton) generatePresignButton.disabled = true;
  if (downloadButton) downloadButton.classList.add('disabled');

  const objectCountBadge = document.getElementById('object-count-badge');
  const loadMoreContainer = document.getElementById('load-more-container');
  const loadMoreSpinner = document.getElementById('load-more-spinner');
  const loadMoreStatus = document.getElementById('load-more-status');
  const objectsLoadingRow = document.getElementById('objects-loading-row');
  let nextContinuationToken = null;
  let totalObjectCount = 0;
  let loadedObjectCount = 0;
  let isLoadingObjects = false;
  let hasMoreObjects = false;
  let currentFilterTerm = '';
  let pageSize = 5000;
  let currentPrefix = '';
  let allObjects = [];
  let urlTemplates = null;
  let streamAbortController = null;
  let useStreaming = !!objectsStreamUrl;
  let streamingComplete = false;
  const STREAM_RENDER_BATCH = 500;
  let pendingStreamObjects = [];
  let streamRenderScheduled = false;

  const buildUrlFromTemplate = (template, key) => {
    if (!template) return '';
    return template.replace('KEY_PLACEHOLDER', encodeURIComponent(key).replace(/%2F/g, '/'));
  };

  const ROW_HEIGHT = 53;
  const BUFFER_ROWS = 10;
  let visibleItems = [];
  let renderedRange = { start: 0, end: 0 };

  const createObjectRow = (obj, displayKey = null) => {
    const tr = document.createElement('tr');
    tr.dataset.objectRow = '';
    tr.dataset.key = obj.key;
    tr.dataset.size = obj.size;
    tr.dataset.lastModified = obj.lastModified || obj.last_modified;
    tr.dataset.lastModifiedDisplay = obj.lastModifiedDisplay || obj.last_modified_display || new Date(obj.lastModified || obj.last_modified).toLocaleString();
    tr.dataset.lastModifiedIso = obj.lastModifiedIso || obj.last_modified_iso || obj.lastModified || obj.last_modified;
    tr.dataset.etag = obj.etag;
    tr.dataset.previewUrl = obj.previewUrl || obj.preview_url;
    tr.dataset.downloadUrl = obj.downloadUrl || obj.download_url;
    tr.dataset.presignEndpoint = obj.presignEndpoint || obj.presign_endpoint;
    tr.dataset.deleteEndpoint = obj.deleteEndpoint || obj.delete_endpoint;
    tr.dataset.metadata = typeof obj.metadata === 'string' ? obj.metadata : JSON.stringify(obj.metadata || {});
    tr.dataset.versionsEndpoint = obj.versionsEndpoint || obj.versions_endpoint;
    tr.dataset.restoreTemplate = obj.restoreTemplate || obj.restore_template;
    tr.dataset.tagsUrl = obj.tagsUrl || obj.tags_url;
    tr.dataset.copyUrl = obj.copyUrl || obj.copy_url;
    tr.dataset.moveUrl = obj.moveUrl || obj.move_url;

    const keyToShow = displayKey || obj.key;
    const lastModDisplay = obj.lastModifiedDisplay || obj.last_modified_display || new Date(obj.lastModified || obj.last_modified).toLocaleDateString();

    tr.innerHTML = `
      <td class="text-center align-middle">
        <input class="form-check-input" type="checkbox" data-object-select aria-label="Select ${escapeHtml(obj.key)}" />
      </td>
      <td class="object-key text-break" title="${escapeHtml(obj.key)}">
        <div class="fw-medium">${escapeHtml(keyToShow)}</div>
        <div class="text-muted small">Modified ${escapeHtml(lastModDisplay)}</div>
      </td>
      <td class="text-end text-nowrap">
        <span class="text-muted small">${formatBytes(obj.size)}</span>
      </td>
      <td class="text-end">
        <div class="btn-group btn-group-sm" role="group">
          <a
            class="btn btn-outline-primary btn-icon"
            href="${escapeHtml(obj.downloadUrl || obj.download_url)}"
            target="_blank"
            title="Download"
            aria-label="Download"
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="#0d6efd" class="bi bi-download" viewBox="0 0 16 16" aria-hidden="true">
              <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z" />
              <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z" />
            </svg>
          </a>
          <div class="dropdown d-inline-block">
            <button class="btn btn-outline-secondary btn-icon dropdown-toggle" type="button" data-bs-toggle="dropdown" data-bs-auto-close="true" aria-expanded="false" title="More actions">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16">
                <path d="M9.5 13a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/>
              </svg>
            </button>
            <ul class="dropdown-menu dropdown-menu-end" style="position: fixed;">
              <li><button class="dropdown-item" type="button" onclick="openCopyMoveModal('copy', '${escapeHtml(obj.key)}')">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-2" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2Zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6ZM2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-1h1v1a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h1v1H2Z"/></svg>
                Copy
              </button></li>
              <li><button class="dropdown-item" type="button" onclick="openCopyMoveModal('move', '${escapeHtml(obj.key)}')">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-2" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8z"/></svg>
                Move
              </button></li>
              <li><hr class="dropdown-divider"></li>
              <li><button class="dropdown-item text-danger" type="button" data-delete-object>
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-2" viewBox="0 0 16 16"><path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/><path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/></svg>
                Delete
              </button></li>
            </ul>
          </div>
        </div>
      </td>
    `;

    return tr;
  };

  const showEmptyState = () => {
    if (!objectsTableBody) return;
    objectsTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="py-5">
          <div class="empty-state">
            <div class="empty-state-icon mx-auto" style="width: 64px; height: 64px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" viewBox="0 0 16 16">
                <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                <path d="M7.646 1.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1-.708.708L8.5 2.707V11.5a.5.5 0 0 1-1 0V2.707L5.354 4.854a.5.5 0 1 1-.708-.708l3-3z"/>
              </svg>
            </div>
            <h6 class="mb-2">No objects yet</h6>
            <p class="text-muted small mb-3">Drag and drop files here or click Upload to get started.</p>
            <button class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#uploadModal">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">
                <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                <path d="M7.646 1.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1-.708.708L8.5 2.707V11.5a.5.5 0 0 1-1 0V2.707L5.354 4.854a.5.5 0 1 1-.708-.708l3-3z"/>
              </svg>
              Upload Files
            </button>
          </div>
        </td>
      </tr>
    `;
  };

  const showLoadError = (message) => {
    if (!objectsTableBody) return;
    objectsTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="py-5">
          <div class="text-center text-danger">
            <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" class="mb-2" viewBox="0 0 16 16">
              <path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>
            </svg>
            <p class="mb-2">Failed to load objects</p>
            <p class="small text-muted mb-3">${escapeHtml(message)}</p>
            <button class="btn btn-outline-primary btn-sm" onclick="loadObjects()">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">
                <path fill-rule="evenodd" d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2v1z"/>
                <path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466z"/>
              </svg>
              Retry
            </button>
          </div>
        </td>
      </tr>
    `;
  };

  const updateObjectCountBadge = () => {
    if (!objectCountBadge) return;
    if (totalObjectCount === 0) {
      objectCountBadge.textContent = '0 objects';
    } else {
      objectCountBadge.textContent = `${totalObjectCount.toLocaleString()} object${totalObjectCount !== 1 ? 's' : ''}`;
    }
  };

  let topSpacer = null;
  let bottomSpacer = null;

  const initVirtualScrollElements = () => {
    if (!objectsTableBody) return;

    if (!topSpacer) {
      topSpacer = document.createElement('tr');
      topSpacer.id = 'virtual-top-spacer';
      topSpacer.innerHTML = '<td colspan="4" style="padding: 0; border: none;"></td>';
    }
    if (!bottomSpacer) {
      bottomSpacer = document.createElement('tr');
      bottomSpacer.id = 'virtual-bottom-spacer';
      bottomSpacer.innerHTML = '<td colspan="4" style="padding: 0; border: none;"></td>';
    }
  };

  const computeVisibleItems = () => {
    const items = [];
    const folders = new Set();

    allObjects.forEach(obj => {
      if (!obj.key.startsWith(currentPrefix)) return;

      const remainder = obj.key.slice(currentPrefix.length);

      if (!remainder) return;

      const isFolderMarker = obj.key.endsWith('/') && obj.size === 0;
      const slashIndex = remainder.indexOf('/');

      if (slashIndex === -1 && !isFolderMarker) {
        if (!currentFilterTerm || remainder.toLowerCase().includes(currentFilterTerm)) {
          items.push({ type: 'file', data: obj, displayKey: remainder });
        }
      } else {
        const effectiveSlashIndex = isFolderMarker && slashIndex === remainder.length - 1
          ? slashIndex
          : (slashIndex === -1 ? remainder.length - 1 : slashIndex);
        const folderName = remainder.slice(0, effectiveSlashIndex);
        const folderPath = currentPrefix + folderName + '/';
        if (!folders.has(folderPath)) {
          folders.add(folderPath);
          if (!currentFilterTerm || folderName.toLowerCase().includes(currentFilterTerm)) {
            items.push({ type: 'folder', path: folderPath, displayKey: folderName });
          }
        }
      }
    });

    items.sort((a, b) => {
      if (a.type === 'folder' && b.type === 'file') return -1;
      if (a.type === 'file' && b.type === 'folder') return 1;
      const aKey = a.type === 'folder' ? a.path : a.data.key;
      const bKey = b.type === 'folder' ? b.path : b.data.key;
      return aKey.localeCompare(bKey);
    });

    return items;
  };

  const renderVirtualRows = () => {
    if (!objectsTableBody || !scrollContainer) return;

    const containerHeight = scrollContainer.clientHeight;
    const scrollTop = scrollContainer.scrollTop;

    const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER_ROWS);
    const endIndex = Math.min(visibleItems.length, Math.ceil((scrollTop + containerHeight) / ROW_HEIGHT) + BUFFER_ROWS);

    if (startIndex === renderedRange.start && endIndex === renderedRange.end) return;

    renderedRange = { start: startIndex, end: endIndex };

    objectsTableBody.innerHTML = '';

    initVirtualScrollElements();
    topSpacer.querySelector('td').style.height = `${startIndex * ROW_HEIGHT}px`;
    objectsTableBody.appendChild(topSpacer);

    for (let i = startIndex; i < endIndex; i++) {
      const item = visibleItems[i];
      if (!item) continue;

      let row;
      if (item.type === 'folder') {
        row = createFolderRow(item.path, item.displayKey);
      } else {
        row = createObjectRow(item.data, item.displayKey);
      }
      row.dataset.virtualIndex = i;
      objectsTableBody.appendChild(row);
    }

    const remainingRows = visibleItems.length - endIndex;
    bottomSpacer.querySelector('td').style.height = `${remainingRows * ROW_HEIGHT}px`;
    objectsTableBody.appendChild(bottomSpacer);

    attachRowHandlers();
  };

  let scrollTimeout = null;
  const handleVirtualScroll = () => {
    if (scrollTimeout) cancelAnimationFrame(scrollTimeout);
    scrollTimeout = requestAnimationFrame(renderVirtualRows);
  };

  const refreshVirtualList = () => {
    visibleItems = computeVisibleItems();
    renderedRange = { start: -1, end: -1 };

    if (visibleItems.length === 0) {
      if (allObjects.length === 0 && !hasMoreObjects) {
        showEmptyState();
      } else {
        objectsTableBody.innerHTML = `
          <tr>
            <td colspan="4" class="py-5">
              <div class="empty-state">
                <div class="empty-state-icon mx-auto" style="width: 64px; height: 64px;">
                  <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" viewBox="0 0 16 16">
                    <path d="M9.828 3h3.982a2 2 0 0 1 1.992 2.181l-.637 7A2 2 0 0 1 13.174 14H2.825a2 2 0 0 1-1.991-1.819l-.637-7a1.99 1.99 0 0 1 .342-1.31L.5 3a2 2 0 0 1 2-2h3.672a2 2 0 0 1 1.414.586l.828.828A2 2 0 0 0 9.828 3zm-8.322.12C1.72 3.042 1.95 3 2.19 3h5.396l-.707-.707A1 1 0 0 0 6.172 2H2.5a1 1 0 0 0-1 .981l.006.139z"/>
                  </svg>
                </div>
                <h6 class="mb-2">Empty folder</h6>
                <p class="text-muted small mb-0">This folder contains no objects${hasMoreObjects ? ' yet. Loading more...' : '.'}</p>
              </div>
            </td>
          </tr>
        `;
      }
    } else {
      renderVirtualRows();
    }

    updateFolderViewStatus();
  };

  const updateFolderViewStatus = () => {
    const folderViewStatusEl = document.getElementById('folder-view-status');
    if (!folderViewStatusEl) return;

    if (currentPrefix) {
      const folderCount = visibleItems.filter(i => i.type === 'folder').length;
      const fileCount = visibleItems.filter(i => i.type === 'file').length;
      folderViewStatusEl.innerHTML = `<span class="text-muted">${folderCount} folder${folderCount !== 1 ? 's' : ''}, ${fileCount} file${fileCount !== 1 ? 's' : ''} in this view</span>`;
      folderViewStatusEl.classList.remove('d-none');
    } else {
      folderViewStatusEl.classList.add('d-none');
    }
  };

  const processStreamObject = (obj) => {
    const key = obj.key;
    return {
      key: key,
      size: obj.size,
      lastModified: obj.last_modified,
      lastModifiedDisplay: obj.last_modified_display,
      lastModifiedIso: obj.last_modified_iso,
      etag: obj.etag,
      previewUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.preview, key) : '',
      downloadUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.download, key) : '',
      presignEndpoint: urlTemplates ? buildUrlFromTemplate(urlTemplates.presign, key) : '',
      deleteEndpoint: urlTemplates ? buildUrlFromTemplate(urlTemplates.delete, key) : '',
      metadata: '{}',
      versionsEndpoint: urlTemplates ? buildUrlFromTemplate(urlTemplates.versions, key) : '',
      restoreTemplate: urlTemplates ? urlTemplates.restore.replace('KEY_PLACEHOLDER', encodeURIComponent(key).replace(/%2F/g, '/')) : '',
      tagsUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.tags, key) : '',
      copyUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.copy, key) : '',
      moveUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.move, key) : ''
    };
  };

  const flushPendingStreamObjects = () => {
    if (pendingStreamObjects.length === 0) return;
    const batch = pendingStreamObjects.splice(0, pendingStreamObjects.length);
    batch.forEach(obj => {
      loadedObjectCount++;
      allObjects.push(obj);
    });
    updateObjectCountBadge();
    if (loadMoreStatus) {
      if (streamingComplete) {
        loadMoreStatus.textContent = `${loadedObjectCount.toLocaleString()} objects`;
      } else {
        const countText = totalObjectCount > 0 ? ` of ${totalObjectCount.toLocaleString()}` : '';
        loadMoreStatus.textContent = `${loadedObjectCount.toLocaleString()}${countText} loading...`;
      }
    }
    refreshVirtualList();
    streamRenderScheduled = false;
  };

  const scheduleStreamRender = () => {
    if (streamRenderScheduled) return;
    streamRenderScheduled = true;
    requestAnimationFrame(flushPendingStreamObjects);
  };

  const loadObjectsStreaming = async () => {
    if (isLoadingObjects) return;
    isLoadingObjects = true;
    streamingComplete = false;

    if (objectsLoadingRow) objectsLoadingRow.style.display = '';
    nextContinuationToken = null;
    loadedObjectCount = 0;
    totalObjectCount = 0;
    allObjects = [];
    pendingStreamObjects = [];

    streamAbortController = new AbortController();

    try {
      const params = new URLSearchParams();
      if (currentPrefix) params.set('prefix', currentPrefix);

      const response = await fetch(`${objectsStreamUrl}?${params}`, {
        signal: streamAbortController.signal
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      if (objectsLoadingRow) objectsLoadingRow.remove();

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const msg = JSON.parse(line);
            switch (msg.type) {
              case 'meta':
                urlTemplates = msg.url_templates;
                versioningEnabled = msg.versioning_enabled;
                if (objectsContainer) {
                  objectsContainer.dataset.versioning = versioningEnabled ? 'true' : 'false';
                }
                break;
              case 'count':
                totalObjectCount = msg.total_count || 0;
                break;
              case 'object':
                pendingStreamObjects.push(processStreamObject(msg));
                if (pendingStreamObjects.length >= STREAM_RENDER_BATCH) {
                  scheduleStreamRender();
                }
                break;
              case 'error':
                throw new Error(msg.error);
              case 'done':
                streamingComplete = true;
                break;
            }
          } catch (parseErr) {
            console.warn('Failed to parse stream line:', line, parseErr);
          }
        }
        if (pendingStreamObjects.length > 0) {
          scheduleStreamRender();
        }
      }

      if (buffer.trim()) {
        try {
          const msg = JSON.parse(buffer);
          if (msg.type === 'object') {
            pendingStreamObjects.push(processStreamObject(msg));
          } else if (msg.type === 'done') {
            streamingComplete = true;
          }
        } catch (e) { }
      }

      flushPendingStreamObjects();
      streamingComplete = true;
      hasMoreObjects = false;
      updateObjectCountBadge();

      if (loadMoreStatus) {
        loadMoreStatus.textContent = `${loadedObjectCount.toLocaleString()} objects`;
      }
      refreshVirtualList();
      renderBreadcrumb(currentPrefix);

    } catch (error) {
      if (error.name === 'AbortError') return;
      console.error('Streaming failed, falling back to paginated:', error);
      useStreaming = false;
      isLoadingObjects = false;
      await loadObjectsPaginated(false);
      return;
    } finally {
      isLoadingObjects = false;
      streamAbortController = null;
    }
  };

  const loadObjectsPaginated = async (append = false) => {
    if (isLoadingObjects) return;
    isLoadingObjects = true;

    if (!append) {
      if (objectsLoadingRow) objectsLoadingRow.style.display = '';
      nextContinuationToken = null;
      loadedObjectCount = 0;
      totalObjectCount = 0;
      allObjects = [];
    }

    if (append && loadMoreSpinner) {
      loadMoreSpinner.classList.remove('d-none');
    }

    try {
      const params = new URLSearchParams({ max_keys: String(pageSize) });
      if (nextContinuationToken) {
        params.set('continuation_token', nextContinuationToken);
      }

      const response = await fetch(`${objectsApiUrl}?${params}`);
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      const data = await response.json();

      versioningEnabled = data.versioning_enabled;
      if (objectsContainer) {
        objectsContainer.dataset.versioning = versioningEnabled ? 'true' : 'false';
      }

      totalObjectCount = data.total_count || 0;
      nextContinuationToken = data.next_continuation_token;

      if (!append && objectsLoadingRow) {
        objectsLoadingRow.remove();
      }

      if (data.url_templates && !urlTemplates) {
        urlTemplates = data.url_templates;
      }

      data.objects.forEach(obj => {
        loadedObjectCount++;
        allObjects.push(processStreamObject(obj));
      });

      updateObjectCountBadge();
      hasMoreObjects = data.is_truncated;

      if (loadMoreStatus) {
        if (data.is_truncated) {
          loadMoreStatus.textContent = `${loadedObjectCount.toLocaleString()} of ${totalObjectCount.toLocaleString()} loaded`;
        } else {
          loadMoreStatus.textContent = `${loadedObjectCount.toLocaleString()} objects`;
        }
      }

      refreshVirtualList();
      renderBreadcrumb(currentPrefix);

    } catch (error) {
      console.error('Failed to load objects:', error);
      if (!append) {
        showLoadError(error.message);
      } else {
        showMessage({ title: 'Load Failed', body: error.message, variant: 'danger' });
      }
    } finally {
      isLoadingObjects = false;
      if (loadMoreSpinner) {
        loadMoreSpinner.classList.add('d-none');
      }
    }
  };

  const loadObjects = async (append = false) => {
    if (useStreaming && !append) {
      return loadObjectsStreaming();
    }
    return loadObjectsPaginated(append);
  };

  const attachRowHandlers = () => {
    const objectRows = document.querySelectorAll('[data-object-row]');
    objectRows.forEach(row => {
      if (row.dataset.handlersAttached) return;
      row.dataset.handlersAttached = 'true';

      const deleteBtn = row.querySelector('[data-delete-object]');
      deleteBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        const deleteModalEl = document.getElementById('deleteObjectModal');
        const deleteModal = deleteModalEl ? bootstrap.Modal.getOrCreateInstance(deleteModalEl) : null;
        const deleteObjectForm = document.getElementById('deleteObjectForm');
        const deleteObjectKey = document.getElementById('deleteObjectKey');
        if (deleteModal && deleteObjectForm) {
          deleteObjectForm.setAttribute('action', row.dataset.deleteEndpoint);
          if (deleteObjectKey) deleteObjectKey.textContent = row.dataset.key;
          deleteModal.show();
        }
      });

      const selectCheckbox = row.querySelector('[data-object-select]');
      selectCheckbox?.addEventListener('click', (event) => event.stopPropagation());
      selectCheckbox?.addEventListener('change', () => {
        toggleRowSelection(row, selectCheckbox.checked);
      });

      if (selectedRows.has(row.dataset.key)) {
        selectCheckbox.checked = true;
        row.classList.add('table-active');
      }
    });

    const folderRows = document.querySelectorAll('.folder-row');
    folderRows.forEach(row => {
      if (row.dataset.handlersAttached) return;
      row.dataset.handlersAttached = 'true';

      const folderPath = row.dataset.folderPath;

      const checkbox = row.querySelector('[data-folder-select]');
      checkbox?.addEventListener('change', (e) => {
        e.stopPropagation();
        const folderObjects = allObjects.filter(obj => obj.key.startsWith(folderPath));
        folderObjects.forEach(obj => {
          if (checkbox.checked) {
            selectedRows.set(obj.key, obj);
          } else {
            selectedRows.delete(obj.key);
          }
        });
        updateBulkDeleteState();
      });

      const folderBtn = row.querySelector('button');
      folderBtn?.addEventListener('click', (e) => {
        e.stopPropagation();
        navigateToFolder(folderPath);
      });

      row.addEventListener('click', (e) => {
        if (e.target.closest('[data-folder-select]') || e.target.closest('button')) return;
        navigateToFolder(folderPath);
      });
    });

    updateBulkDeleteState();
  };

  const scrollSentinel = document.getElementById('scroll-sentinel');
  const scrollContainer = document.querySelector('.objects-table-container');

  if (scrollContainer) {
    scrollContainer.addEventListener('scroll', handleVirtualScroll, { passive: true });
  }

  if (scrollSentinel && scrollContainer) {
    const containerObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting && hasMoreObjects && !isLoadingObjects) {
          loadObjects(true);
        }
      });
    }, {
      root: scrollContainer,
      rootMargin: '500px',
      threshold: 0
    });
    containerObserver.observe(scrollSentinel);

    const viewportObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting && hasMoreObjects && !isLoadingObjects) {
          loadObjects(true);
        }
      });
    }, {
      root: null,
      rootMargin: '500px',
      threshold: 0
    });
    viewportObserver.observe(scrollSentinel);
  }


  if (objectsApiUrl) {
    loadObjects();
  }

  const folderBreadcrumb = document.getElementById('folder-breadcrumb');
  const objectsTableBody = document.querySelector('#objects-table tbody');

  if (objectsTableBody) {
    objectsTableBody.addEventListener('click', (e) => {
      const row = e.target.closest('[data-object-row]');
      if (!row) return;

      if (e.target.closest('[data-delete-object]') || e.target.closest('[data-object-select]') || e.target.closest('a')) {
        return;
      }

      selectRow(row);
    });
  }

  const hasFolders = () => allObjects.some(obj => obj.key.includes('/'));

  const getFoldersAtPrefix = (prefix) => {
    const folders = new Set();
    const files = [];

    allObjects.forEach(obj => {
      const key = obj.key;
      if (!key.startsWith(prefix)) return;

      const remainder = key.slice(prefix.length);
      const slashIndex = remainder.indexOf('/');

      if (slashIndex === -1) {

        files.push(obj);
      } else {

        const folderName = remainder.slice(0, slashIndex + 1);
        folders.add(prefix + folderName);
      }
    });

    return { folders: Array.from(folders).sort(), files };
  };

  const countObjectsInFolder = (folderPrefix) => {
    const count = allObjects.filter(obj => obj.key.startsWith(folderPrefix)).length;
    return { count, mayHaveMore: hasMoreObjects };
  };

  const renderBreadcrumb = (prefix) => {
    if (!folderBreadcrumb) return;

    if (!prefix && !hasFolders()) {
      folderBreadcrumb.classList.add('d-none');
      return;
    }

    folderBreadcrumb.classList.remove('d-none');
    const ol = folderBreadcrumb.querySelector('ol');
    ol.innerHTML = '';

    const rootLi = document.createElement('li');
    rootLi.className = 'breadcrumb-item';
    if (!prefix) {
      rootLi.classList.add('active');
      rootLi.setAttribute('aria-current', 'page');
      rootLi.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">
          <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146zM2.5 14V7.707l5.5-5.5 5.5 5.5V14H10v-4a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v4H2.5z"/>
        </svg>
        Root
      `;
    } else {
      rootLi.innerHTML = `
        <a href="#" data-folder-nav="" class="text-decoration-none">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">
            <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146zM2.5 14V7.707l5.5-5.5 5.5 5.5V14H10v-4a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v4H2.5z"/>
          </svg>
          Root
        </a>
      `;
    }
    ol.appendChild(rootLi);

    if (prefix) {
      const parts = prefix.split('/').filter(Boolean);
      let accumulated = '';
      parts.forEach((part, index) => {
        accumulated += part + '/';
        const li = document.createElement('li');
        li.className = 'breadcrumb-item';

        if (index === parts.length - 1) {
          li.classList.add('active');
          li.setAttribute('aria-current', 'page');
          li.textContent = part;
        } else {
          const a = document.createElement('a');
          a.href = '#';
          a.className = 'text-decoration-none';
          a.dataset.folderNav = accumulated;
          a.textContent = part;
          li.appendChild(a);
        }
        ol.appendChild(li);
      });
    }

    ol.querySelectorAll('[data-folder-nav]').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        navigateToFolder(link.dataset.folderNav);
      });
    });
  };

  const getObjectsInFolder = (folderPrefix) => {
    return allObjects.filter(obj => obj.key.startsWith(folderPrefix));
  };

  const createFolderRow = (folderPath, displayName = null) => {
    const folderName = displayName || folderPath.slice(currentPrefix.length).replace(/\/$/, '');
    const { count: objectCount, mayHaveMore } = countObjectsInFolder(folderPath);
    const countDisplay = mayHaveMore ? `${objectCount}+` : objectCount;

    const tr = document.createElement('tr');
    tr.className = 'folder-row';
    tr.dataset.folderPath = folderPath;
    tr.style.cursor = 'pointer';

    tr.innerHTML = `
      <td class="text-center align-middle" onclick="event.stopPropagation();">
        <input class="form-check-input" type="checkbox" data-folder-select="${escapeHtml(folderPath)}" aria-label="Select folder" />
      </td>
      <td class="object-key text-break">
        <div class="fw-medium d-flex align-items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="text-warning flex-shrink-0" viewBox="0 0 16 16">
            <path d="M9.828 3h3.982a2 2 0 0 1 1.992 2.181l-.637 7A2 2 0 0 1 13.174 14H2.825a2 2 0 0 1-1.991-1.819l-.637-7a1.99 1.99 0 0 1 .342-1.31L.5 3a2 2 0 0 1 2-2h3.672a2 2 0 0 1 1.414.586l.828.828A2 2 0 0 0 9.828 3zm-8.322.12C1.72 3.042 1.95 3 2.19 3h5.396l-.707-.707A1 1 0 0 0 6.172 2H2.5a1 1 0 0 0-1 .981l.006.139z"/>
          </svg>
          <span>${escapeHtml(folderName)}/</span>
        </div>
        <div class="text-muted small ms-4 ps-2">${countDisplay} object${objectCount !== 1 ? 's' : ''}</div>
      </td>
      <td class="text-end text-nowrap">
        <span class="text-muted small">—</span>
      </td>
      <td class="text-end">
        <button type="button" class="btn btn-outline-primary btn-sm" title="Open folder">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16">
            <path fill-rule="evenodd" d="M4.646 1.646a.5.5 0 0 1 .708 0l6 6a.5.5 0 0 1 0 .708l-6 6a.5.5 0 0 1-.708-.708L10.293 8 4.646 2.354a.5.5 0 0 1 0-.708z"/>
          </svg>
        </button>
      </td>
    `;

    return tr;
  };

  const navigateToFolder = (prefix) => {
    currentPrefix = prefix;

    if (scrollContainer) scrollContainer.scrollTop = 0;

    refreshVirtualList();
    renderBreadcrumb(prefix);

    selectedRows.clear();

    if (typeof updateBulkDeleteState === 'function') {
      updateBulkDeleteState();
    }

    if (previewPanel) previewPanel.classList.add('d-none');
    if (previewEmpty) previewEmpty.classList.remove('d-none');
    activeRow = null;
  };

  const renderObjectsView = () => {
    if (!objectsTableBody) return;

    const { folders, files } = getFoldersAtPrefix(currentPrefix);

    objectsTableBody.innerHTML = '';

    folders.forEach(folderPath => {
      objectsTableBody.appendChild(createFolderRow(folderPath));
    });

    files.forEach(obj => {
      objectsTableBody.appendChild(obj.element);
      obj.element.style.display = '';

      const keyCell = obj.element.querySelector('.object-key .fw-medium');
      if (keyCell && currentPrefix) {
        const displayName = obj.key.slice(currentPrefix.length);
        keyCell.textContent = displayName;
        keyCell.closest('.object-key').title = obj.key;
      } else if (keyCell) {
        keyCell.textContent = obj.key;
      }
    });

    allObjects.forEach(obj => {
      if (!files.includes(obj)) {
        obj.element.style.display = 'none';
      }
    });

    if (folders.length === 0 && files.length === 0) {
      const emptyRow = document.createElement('tr');
      emptyRow.innerHTML = `
        <td colspan="4" class="py-5">
          <div class="empty-state">
            <div class="empty-state-icon mx-auto" style="width: 64px; height: 64px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="currentColor" viewBox="0 0 16 16">
                <path d="M9.828 3h3.982a2 2 0 0 1 1.992 2.181l-.637 7A2 2 0 0 1 13.174 14H2.825a2 2 0 0 1-1.991-1.819l-.637-7a1.99 1.99 0 0 1 .342-1.31L.5 3a2 2 0 0 1 2-2h3.672a2 2 0 0 1 1.414.586l.828.828A2 2 0 0 0 9.828 3zm-8.322.12C1.72 3.042 1.95 3 2.19 3h5.396l-.707-.707A1 1 0 0 0 6.172 2H2.5a1 1 0 0 0-1 .981l.006.139z"/>
              </svg>
            </div>
            <h6 class="mb-2">Empty folder</h6>
            <p class="text-muted small mb-0">This folder contains no objects.</p>
          </div>
        </td>
      `;
      objectsTableBody.appendChild(emptyRow);
    }

    if (typeof updateBulkDeleteState === 'function') {
      updateBulkDeleteState();
    }
  };

  const showMessage = ({ title = 'Notice', body = '', bodyHtml = null, variant = 'info', actionText = null, onAction = null }) => {
    if (!actionText && !onAction && window.showToast) {
      window.showToast(body || title, title, variant);
      return;
    }
    if (!messageModal) {
      window.alert(body || title);
      return;
    }
    document.querySelectorAll('.modal.show').forEach(modal => {
      const instance = bootstrap.Modal.getInstance(modal);
      if (instance && modal.id !== 'messageModal') {
        instance.hide();
      }
    });
    const iconEl = document.getElementById('messageModalIcon');
    if (iconEl) {
      const iconPaths = {
        success: '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>',
        danger: '<path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>',
        warning: '<path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>',
        info: '<path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/>'
      };
      const iconColors = { success: 'text-success', danger: 'text-danger', warning: 'text-warning', info: 'text-primary' };
      iconEl.innerHTML = iconPaths[variant] || iconPaths.info;
      iconEl.classList.remove('text-success', 'text-danger', 'text-warning', 'text-primary');
      iconEl.classList.add(iconColors[variant] || 'text-primary');
    }
    messageModalTitle.textContent = title;
    if (bodyHtml) {
      messageModalBody.innerHTML = bodyHtml;
    } else {
      messageModalBody.textContent = body;
    }
    messageModalActionHandler = null;
    const variantClass = {
      success: 'btn-success',
      danger: 'btn-danger',
      warning: 'btn-warning',
      info: 'btn-primary',
    };
    Object.values(variantClass).forEach((cls) => messageModalAction.classList.remove(cls));
    if (actionText && typeof onAction === 'function') {
      messageModalAction.textContent = actionText;
      messageModalAction.classList.remove('d-none');
      messageModalAction.classList.add(variantClass[variant] || 'btn-primary');
      messageModalActionHandler = onAction;
    } else {
      messageModalAction.classList.add('d-none');
    }
    setTimeout(() => messageModal.show(), 150);
  };

  messageModalAction?.addEventListener('click', () => {
    if (typeof messageModalActionHandler === 'function') {
      messageModalActionHandler();
    }
    messageModal?.hide();
  });

  messageModalEl?.addEventListener('hidden.bs.modal', () => {
    messageModalActionHandler = null;
    messageModalAction.classList.add('d-none');
  });

  const normalizePolicyTemplate = (rawTemplate) => {
    if (!rawTemplate) {
      return '';
    }
    try {
      let parsed = JSON.parse(rawTemplate);
      if (typeof parsed === 'string') {
        parsed = JSON.parse(parsed);
      }
      return JSON.stringify(parsed, null, 2);
    } catch {
      return rawTemplate;
    }
  };

  let publicPolicyTemplate = normalizePolicyTemplate(policyTextarea?.dataset.publicTemplate || '');
  let customPolicyDraft = policyTextarea?.value || '';

  const setPolicyTextareaState = (readonly) => {
    if (!policyTextarea) return;
    if (readonly) {
      policyTextarea.setAttribute('readonly', 'readonly');
      policyTextarea.classList.add('bg-body-secondary');
    } else {
      policyTextarea.removeAttribute('readonly');
      policyTextarea.classList.remove('bg-body-secondary');
    }
  };

  const policyReadonlyHint = document.getElementById('policyReadonlyHint');

  const applyPolicyPreset = (preset) => {
    if (!policyTextarea || !policyMode) return;
    const isPresetMode = preset === 'private' || preset === 'public';
    if (policyReadonlyHint) {
      policyReadonlyHint.classList.toggle('d-none', !isPresetMode);
    }
    switch (preset) {
      case 'private':
        setPolicyTextareaState(true);
        policyTextarea.value = '';
        policyMode.value = 'delete';
        break;
      case 'public':
        setPolicyTextareaState(true);
        policyTextarea.value = publicPolicyTemplate || '';
        policyMode.value = 'upsert';
        break;
      default:
        setPolicyTextareaState(false);
        policyTextarea.value = customPolicyDraft;
        policyMode.value = 'upsert';
        break;
    }
  };

  policyTextarea?.addEventListener('input', () => {
    if (policyPreset?.value === 'custom') {
      customPolicyDraft = policyTextarea.value;
    }
  });

  const presetButtons = document.querySelectorAll('.preset-btn[data-preset]');
  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const preset = btn.dataset.preset;
      if (policyPreset) policyPreset.value = preset;
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      applyPolicyPreset(preset);
    });
  });

  if (policyPreset) {
    applyPolicyPreset(policyPreset.value || policyPreset.dataset.default || 'custom');
  }

  policyForm?.addEventListener('submit', () => {
    if (!policyMode || !policyPreset || !policyTextarea) {
      return;
    }
    if (policyPreset.value === 'private') {
      policyMode.value = 'delete';
      policyTextarea.value = '';
    } else if (policyPreset.value === 'public') {
      policyMode.value = 'upsert';
      policyTextarea.value = publicPolicyTemplate || policyTextarea.value;
    } else {
      policyMode.value = 'upsert';
    }
  });

  const bulkActionsWrapper = document.getElementById('bulk-actions-wrapper');
  const updateBulkDeleteState = () => {
    const selectedCount = selectedRows.size;
    if (bulkDeleteButton) {
      const shouldShow = Boolean(bulkDeleteEndpoint) && (selectedCount > 0 || bulkDeleting);
      bulkDeleteButton.disabled = !bulkDeleteEndpoint || selectedCount === 0 || bulkDeleting;
      if (bulkDeleteLabel) {
        bulkDeleteLabel.textContent = selectedCount ? `Delete (${selectedCount})` : 'Delete';
      }
      if (bulkActionsWrapper) {
        bulkActionsWrapper.classList.toggle('d-none', !shouldShow);
      }
    }
    if (bulkDeleteConfirm) {
      bulkDeleteConfirm.disabled = selectedCount === 0 || bulkDeleting;
    }
    if (selectAllCheckbox) {
      const filesInView = visibleItems.filter(item => item.type === 'file');
      const total = filesInView.length;
      const visibleSelectedCount = filesInView.filter(item => selectedRows.has(item.data.key)).length;
      selectAllCheckbox.disabled = total === 0;
      selectAllCheckbox.checked = visibleSelectedCount > 0 && visibleSelectedCount === total && total > 0;
      selectAllCheckbox.indeterminate = visibleSelectedCount > 0 && visibleSelectedCount < total;
    }
  };

  function toggleRowSelection(row, shouldSelect) {
    if (!row || !row.dataset.key) return;
    if (shouldSelect) {
      selectedRows.set(row.dataset.key, row);
    } else {
      selectedRows.delete(row.dataset.key);
    }
    updateBulkDeleteState();
  }

  const renderBulkDeletePreview = () => {
    if (!bulkDeleteList) return;
    const keys = Array.from(selectedRows.keys());
    bulkDeleteList.innerHTML = '';
    if (bulkDeleteCount) {
      const label = keys.length === 1 ? 'object' : 'objects';
      bulkDeleteCount.textContent = `${keys.length} ${label} selected`;
    }
    if (!keys.length) {
      const empty = document.createElement('li');
      empty.className = 'list-group-item py-2 small text-muted';
      empty.textContent = 'No objects selected.';
      bulkDeleteList.appendChild(empty);
      if (bulkDeleteStatus) {
        bulkDeleteStatus.textContent = '';
      }
      return;
    }
    const preview = keys.slice(0, 6);
    preview.forEach((key) => {
      const item = document.createElement('li');
      item.className = 'list-group-item py-1 small text-break';
      item.textContent = key;
      bulkDeleteList.appendChild(item);
    });
    if (bulkDeleteStatus) {
      bulkDeleteStatus.textContent = keys.length > preview.length ? `+${keys.length - preview.length} more not shown` : '';
    }
  };

  const openBulkDeleteModal = () => {
    if (!bulkDeleteModal) {
      return;
    }
    if (selectedRows.size === 0) {
      showMessage({ title: 'Select objects', body: 'Choose at least one object to delete.', variant: 'warning' });
      return;
    }
    renderBulkDeletePreview();
    if (bulkDeletePurge) {
      bulkDeletePurge.checked = false;
    }
    if (bulkDeleteConfirm) {
      bulkDeleteConfirm.disabled = bulkDeleting;
      bulkDeleteConfirm.textContent = bulkDeleting ? 'Deleting…' : 'Delete objects';
    }
    bulkDeleteModal.show();
  };

  const performBulkDelete = async () => {
    if (!bulkDeleteEndpoint || selectedRows.size === 0 || !bulkDeleteConfirm) {
      return;
    }
    bulkDeleting = true;
    bulkDeleteConfirm.disabled = true;
    bulkDeleteConfirm.textContent = 'Deleting…';
    updateBulkDeleteState();
    const payload = {
      keys: Array.from(selectedRows.keys()),
    };
    if (versioningEnabled && bulkDeletePurge?.checked) {
      payload.purge_versions = true;
    }
    try {
      const response = await fetch(bulkDeleteEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'XMLHttpRequest',
        },
        body: JSON.stringify(payload),
      });
      let data = {};
      try {
        data = await response.json();
      } catch {
        data = {};
      }
      if (!response.ok || data.error) {
        throw new Error(data.error || data.message || 'Unable to delete selected objects');
      }
      bulkDeleteModal?.hide();
      const deletedCount = Array.isArray(data.deleted) ? data.deleted.length : selectedRows.size;
      const errorCount = Array.isArray(data.errors) ? data.errors.length : 0;
      const messageParts = [];
      if (deletedCount) {
        messageParts.push(`${deletedCount} deleted`);
      }
      if (errorCount) {
        messageParts.push(`${errorCount} failed`);
      }
      const summary = messageParts.length ? messageParts.join(', ') : 'Bulk delete finished';
      showMessage({ title: 'Bulk delete complete', body: data.message || summary, variant: errorCount ? 'warning' : 'success' });
      selectedRows.clear();
      previewEmpty.classList.remove('d-none');
      previewPanel.classList.add('d-none');
      activeRow = null;
      loadObjects(false);
    } catch (error) {
      bulkDeleteModal?.hide();
      showMessage({ title: 'Delete failed', body: (error && error.message) || 'Unable to delete selected objects', variant: 'danger' });
    } finally {
      bulkDeleting = false;
      if (bulkDeleteConfirm) {
        bulkDeleteConfirm.disabled = false;
        bulkDeleteConfirm.textContent = 'Delete objects';
      }
      updateBulkDeleteState();
    }
  };

  const updateGeneratePresignState = () => {
    if (!generatePresignButton) return;
    if (isGeneratingPresign) {
      generatePresignButton.disabled = true;
      generatePresignButton.textContent = 'Generating…';
      return;
    }
    generatePresignButton.textContent = 'Generate link';
    generatePresignButton.disabled = !activeRow;
  };

  const requestPresignedUrl = async () => {
    if (!activeRow) {
      showMessage({ title: 'Select an object', body: 'Choose an object before generating a presigned URL.', variant: 'warning' });
      return;
    }
    const endpoint = activeRow.dataset.presignEndpoint;
    if (!endpoint) {
      showMessage({ title: 'Unavailable', body: 'Presign endpoint unavailable for this object.', variant: 'danger' });
      return;
    }
    if (isGeneratingPresign) {
      return;
    }
    isGeneratingPresign = true;
    updateGeneratePresignState();
    presignLink.value = '';
    try {
      const payload = {
        method: presignMethod?.value || 'GET',
        expires_in: Number(presignTtl?.value) || 900,
      };
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Unable to generate presigned URL');
      }
      presignLink.value = data.url;
    } catch (error) {
      presignModal?.hide();
      showMessage({ title: 'Presign failed', body: (error && error.message) || 'Unable to generate presigned URL', variant: 'danger' });
    } finally {
      isGeneratingPresign = false;
      updateGeneratePresignState();
    }
  };

  const renderMetadata = (metadata) => {
    if (!previewMetadata || !previewMetadataList) return;
    previewMetadataList.innerHTML = '';
    if (!metadata || Object.keys(metadata).length === 0) {
      previewMetadata.classList.add('d-none');
      return;
    }
    previewMetadata.classList.remove('d-none');
    Object.entries(metadata).forEach(([key, value]) => {
      const wrapper = document.createElement('div');
      wrapper.className = 'metadata-entry';
      const label = document.createElement('div');
      label.className = 'metadata-key small';
      label.textContent = key;
      const val = document.createElement('div');
      val.className = 'metadata-value text-break';
      val.textContent = value;
      wrapper.appendChild(label);
      wrapper.appendChild(val);
      previewMetadataList.appendChild(wrapper);
    });
  };

  const describeVersionReason = (reason) => {
    switch (reason) {
      case 'delete':
        return 'delete marker';
      case 'restore-overwrite':
        return 'restore overwrite';
      default:
        return reason || 'update';
    }
  };

  const confirmVersionRestore = (row, version, label = null, onConfirm) => {
    if (!version) return;
    const timestamp = version.archived_at ? new Date(version.archived_at).toLocaleString() : version.version_id;
    const sizeLabel = formatBytes(Number(version.size) || 0);
    const reasonLabel = describeVersionReason(version.reason);
    const targetLabel = label || row?.dataset.key || 'this object';
    const metadata = version.metadata && typeof version.metadata === 'object' ? Object.entries(version.metadata) : [];
    const metadataHtml = metadata.length
      ? `<div class="mt-3"><div class="fw-semibold text-uppercase small">Metadata</div><hr class="my-2"><div class="metadata-stack small">${metadata
        .map(
          ([key, value]) =>
            `<div class="metadata-entry"><div class="metadata-key small">${escapeHtml(key)}</div><div class="metadata-value text-break">${escapeHtml(value)}</div></div>`
        )
        .join('')}</div></div>`
      : '';
    const summaryHtml = `
      <div class="small">
        <div><strong>Target:</strong> ${escapeHtml(targetLabel)}</div>
        <div><strong>Version ID:</strong> ${escapeHtml(version.version_id)}</div>
        <div><strong>Timestamp:</strong> ${escapeHtml(timestamp)}</div>
        <div><strong>Size:</strong> ${escapeHtml(sizeLabel)}</div>
        <div><strong>Reason:</strong> ${escapeHtml(reasonLabel)}</div>
      </div>
      ${metadataHtml}
    `;
    const fallbackText = `Restore ${targetLabel} from ${timestamp}? Size ${sizeLabel}. Reason: ${reasonLabel}.`;
    showMessage({
      title: 'Restore archived version?',
      body: fallbackText,
      bodyHtml: summaryHtml,
      variant: 'warning',
      actionText: 'Restore version',
      onAction: () => {
        if (typeof onConfirm === 'function') {
          onConfirm();
        } else {
          restoreVersion(row, version);
        }
      },
    });
  };

  const updateArchivedCount = (count) => {
    if (!archivedCountBadge) return;
    const label = count === 1 ? 'item' : 'items';
    archivedCountBadge.textContent = `${count} ${label}`;
  };

  function renderArchivedRows(items) {
    if (!archivedBody) return;
    archivedBody.innerHTML = '';
    if (!items || items.length === 0) {
      archivedBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-3">No archived-only objects.</td></tr>';
      updateArchivedCount(0);
      return;
    }
    updateArchivedCount(items.length);
    items.forEach((item) => {
      const row = document.createElement('tr');

      const keyCell = document.createElement('td');
      const keyLabel = document.createElement('div');
      keyLabel.className = 'fw-semibold text-break';
      keyLabel.textContent = item.key;
      const badgeWrap = document.createElement('div');
      badgeWrap.className = 'mt-1';
      const badge = document.createElement('span');
      badge.className = 'badge text-bg-warning';
      badge.textContent = 'Archived';
      badgeWrap.appendChild(badge);
      keyCell.appendChild(keyLabel);
      keyCell.appendChild(badgeWrap);

      const latestCell = document.createElement('td');
      if (item.latest) {
        const ts = item.latest.archived_at ? new Date(item.latest.archived_at).toLocaleString() : item.latest.version_id;
        const sizeLabel = formatBytes(Number(item.latest.size) || 0);
        latestCell.innerHTML = `<div class="small">${ts}</div><div class="text-muted small">${sizeLabel} · ${describeVersionReason(item.latest.reason)}</div>`;
      } else {
        latestCell.innerHTML = '<span class="text-muted small">Unknown</span>';
      }

      const countCell = document.createElement('td');
      countCell.className = 'text-end text-muted';
      countCell.textContent = item.versions;

      const actionsCell = document.createElement('td');
      actionsCell.className = 'text-end';
      const btnGroup = document.createElement('div');
      btnGroup.className = 'btn-group btn-group-sm';

      const restoreButton = document.createElement('button');
      restoreButton.type = 'button';
      restoreButton.className = 'btn btn-outline-primary';
      restoreButton.textContent = 'Restore';
      restoreButton.disabled = !item.latest || !item.restore_url;
      restoreButton.addEventListener('click', () => confirmVersionRestore(null, item.latest, item.key, () => restoreArchivedObject(item)));

      const purgeButton = document.createElement('button');
      purgeButton.type = 'button';
      purgeButton.className = 'btn btn-outline-danger';
      purgeButton.textContent = 'Delete versions';
      purgeButton.addEventListener('click', () => confirmArchivedPurge(item));

      btnGroup.appendChild(restoreButton);
      btnGroup.appendChild(purgeButton);
      actionsCell.appendChild(btnGroup);

      row.appendChild(keyCell);
      row.appendChild(latestCell);
      row.appendChild(countCell);
      row.appendChild(actionsCell);
      archivedBody.appendChild(row);
    });
  }

  async function restoreArchivedObject(item) {
    if (!item?.restore_url) return;
    try {
      const response = await fetch(item.restore_url, { method: 'POST' });
      let data = {};
      try {
        data = await response.json();
      } catch {
        data = {};
      }
      if (!response.ok) {
        throw new Error(data.error || 'Unable to restore archived object');
      }
      showMessage({ title: 'Restore scheduled', body: data.message || 'Object restored from archive.', variant: 'success' });
      await loadArchivedObjects();
      loadObjects(false);
    } catch (error) {
      showMessage({ title: 'Restore failed', body: (error && error.message) || 'Unable to restore archived object', variant: 'danger' });
    }
  }

  async function purgeArchivedObject(item) {
    if (!item?.purge_url) return;
    try {
      const response = await fetch(item.purge_url, {
        method: 'POST',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      });
      let data = {};
      try {
        data = await response.json();
      } catch {
        data = {};
      }
      if (!response.ok) {
        throw new Error(data.error || 'Unable to delete archived versions');
      }
      showMessage({ title: 'Archived versions removed', body: data.message || 'All archived data for this key has been deleted.', variant: 'success' });
      await loadArchivedObjects();
    } catch (error) {
      showMessage({ title: 'Delete failed', body: (error && error.message) || 'Unable to delete archived versions', variant: 'danger' });
    }
  }

  function confirmArchivedPurge(item) {
    const label = item?.key || 'this object';
    const count = item?.versions || 0;
    const countLabel = count === 1 ? 'version' : 'versions';
    showMessage({
      title: 'Delete archived versions?',
      body: `Permanently remove ${count} archived ${countLabel} for ${label}? This cannot be undone.`,
      variant: 'danger',
      actionText: 'Delete versions',
      onAction: () => purgeArchivedObject(item),
    });
  }

  async function loadArchivedObjects() {
    if (!archivedEndpoint || !archivedBody) return;
    archivedBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-3">Loading…</td></tr>';
    try {
      const response = await fetch(archivedEndpoint);
      let data = {};
      try {
        data = await response.json();
      } catch {
        data = {};
      }
      if (!response.ok) {
        throw new Error(data.error || 'Unable to load archived objects');
      }
      const items = Array.isArray(data.objects) ? data.objects : [];
      renderArchivedRows(items);
    } catch (error) {
      archivedBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger py-3">${(error && error.message) || 'Unable to load archived objects'}</td></tr>`;
      updateArchivedCount(0);
    }
  }

  if (archivedRefreshButton) {
    archivedRefreshButton.addEventListener('click', () => loadArchivedObjects());
  }
  if (archivedCard && archivedEndpoint) {
    loadArchivedObjects();
  }

  async function restoreVersion(row, version) {
    if (!row || !version?.version_id) return;
    const template = row.dataset.restoreTemplate;
    if (!template) return;
    const url = template.replace('VERSION_ID_PLACEHOLDER', version.version_id);
    try {
      const response = await fetch(url, { method: 'POST' });
      let data = {};
      try {
        data = await response.json();
      } catch {
        data = {};
      }
      if (!response.ok) {
        throw new Error(data.error || 'Unable to restore version');
      }
      const endpoint = row.dataset.versionsEndpoint;
      if (endpoint) {
        versionsCache.delete(endpoint);
      }
      await loadObjectVersions(row, { force: true });
      showMessage({ title: 'Version restored', body: data.message || 'The selected version has been restored.', variant: 'success' });
      loadObjects(false);
    } catch (error) {
      showMessage({ title: 'Restore failed', body: (error && error.message) || 'Unable to restore version', variant: 'danger' });
    }
  }

  function renderVersionEntries(entries, row) {
    if (!versionList) return;
    if (!entries || entries.length === 0) {
      versionList.innerHTML = '<p class="text-muted small mb-0">No previous versions yet.</p>';
      return;
    }
    versionList.innerHTML = '';
    entries.forEach((entry, index) => {
      const versionNumber = index + 1;
      const item = document.createElement('div');
      item.className = 'd-flex align-items-center justify-content-between py-2 border-bottom';
      const textStack = document.createElement('div');
      textStack.className = 'me-3';
      const heading = document.createElement('div');
      heading.className = 'd-flex align-items-center';
      const badge = document.createElement('span');
      badge.className = 'badge text-bg-secondary me-2';
      badge.textContent = `#${versionNumber}`;
      const title = document.createElement('div');
      title.className = 'fw-semibold small';
      const timestamp = entry.archived_at ? new Date(entry.archived_at).toLocaleString() : entry.version_id;
      title.textContent = timestamp;
      heading.appendChild(badge);
      heading.appendChild(title);
      const meta = document.createElement('div');
      meta.className = 'text-muted small';
      const reason = describeVersionReason(entry.reason);
      const sizeLabel = formatBytes(Number(entry.size) || 0);
      meta.textContent = `${sizeLabel} · ${reason}`;
      textStack.appendChild(heading);
      textStack.appendChild(meta);
      const restoreButton = document.createElement('button');
      restoreButton.type = 'button';
      restoreButton.className = 'btn btn-outline-primary btn-sm';
      restoreButton.textContent = 'Restore';
      restoreButton.addEventListener('click', () => confirmVersionRestore(row, entry));
      item.appendChild(textStack);
      item.appendChild(restoreButton);
      versionList.appendChild(item);
    });
  }

  async function loadObjectVersions(row, { force = false } = {}) {
    if (!versionPanel || !versionList || !versioningEnabled) {
      versionPanel?.classList.add('d-none');
      return;
    }
    if (!row) {
      versionPanel.classList.add('d-none');
      return;
    }
    const endpoint = row.dataset.versionsEndpoint;
    if (!endpoint) {
      versionPanel.classList.add('d-none');
      return;
    }
    versionPanel.classList.remove('d-none');
    if (!force && versionsCache.has(endpoint)) {
      renderVersionEntries(versionsCache.get(endpoint), row);
      return;
    }
    versionList.innerHTML = '<div class="text-muted small">Loading versions…</div>';
    try {
      const response = await fetch(endpoint);
      let data = {};
      try {
        data = await response.json();
      } catch {
        data = {};
      }
      if (!response.ok) {
        throw new Error(data.error || 'Unable to load versions');
      }
      const entries = Array.isArray(data.versions) ? data.versions : [];
      versionsCache.set(endpoint, entries);
      renderVersionEntries(entries, row);
    } catch (error) {
      versionList.innerHTML = `<p class="text-danger small mb-0">${(error && error.message) || 'Unable to load versions'}</p>`;
    }
  }

  renderMetadata(null);
  const deleteModalEl = document.getElementById('deleteObjectModal');
  const deleteModal = deleteModalEl ? new bootstrap.Modal(deleteModalEl) : null;
  const deleteObjectForm = document.getElementById('deleteObjectForm');
  const deleteObjectKey = document.getElementById('deleteObjectKey');

  if (deleteObjectForm) {
    deleteObjectForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = deleteObjectForm.querySelector('[type="submit"]');
      const originalHtml = submitBtn ? submitBtn.innerHTML : '';
      try {
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Deleting...';
        }
        const formData = new FormData(deleteObjectForm);
        const csrfToken = formData.get('csrf_token') || (window.getCsrfToken ? window.getCsrfToken() : '');
        const formAction = deleteObjectForm.getAttribute('action');
        const response = await fetch(formAction, {
          method: 'POST',
          headers: {
            'X-CSRFToken': csrfToken,
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: formData
        });
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
          throw new Error('Server returned an unexpected response. Please try again.');
        }
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || 'Unable to delete object');
        }
        if (deleteModal) deleteModal.hide();
        showMessage({ title: 'Object deleted', body: data.message || 'The object has been deleted.', variant: 'success' });
        previewEmpty.classList.remove('d-none');
        previewPanel.classList.add('d-none');
        activeRow = null;
        loadObjects(false);
      } catch (err) {
        if (deleteModal) deleteModal.hide();
        showMessage({ title: 'Delete failed', body: err.message || 'Unable to delete object', variant: 'danger' });
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = originalHtml;
        }
      }
    });
  }

  const resetPreviewMedia = () => {
    [previewImage, previewVideo, previewIframe].forEach((el) => {
      el.classList.add('d-none');
      if (el.tagName === 'VIDEO') {
        el.pause();
        el.removeAttribute('src');
      }
      if (el.tagName === 'IFRAME') {
        el.setAttribute('src', 'about:blank');
      }
    });
    previewPlaceholder.classList.remove('d-none');
  };

  function metadataFromRow(row) {
    if (!row || !row.dataset.metadata) {
      return null;
    }
    try {
      const parsed = JSON.parse(row.dataset.metadata);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (err) {
      console.warn('Failed to parse metadata for row', err);
    }
    return null;
  }

  function selectRow(row) {
    document.querySelectorAll('[data-object-row]').forEach((r) => r.classList.remove('table-active'));
    row.classList.add('table-active');
    previewEmpty.classList.add('d-none');
    previewPanel.classList.remove('d-none');
    activeRow = row;
    renderMetadata(metadataFromRow(row));

    previewKey.textContent = row.dataset.key;
    previewSize.textContent = formatBytes(Number(row.dataset.size));
    previewModified.textContent = row.dataset.lastModifiedIso || row.dataset.lastModified;
    previewEtag.textContent = row.dataset.etag;
    downloadButton.href = row.dataset.downloadUrl;
    downloadButton.classList.remove('disabled');
    if (presignButton) {
      presignButton.dataset.endpoint = row.dataset.presignEndpoint;
      presignButton.disabled = false;
    }
    if (generatePresignButton) {
      generatePresignButton.disabled = false;
    }
    updateGeneratePresignState();
    if (versioningEnabled) {
      loadObjectVersions(row);
    }

    resetPreviewMedia();
    const previewUrl = row.dataset.previewUrl;
    const lower = row.dataset.key.toLowerCase();
    if (lower.match(/\.(png|jpg|jpeg|gif|webp|svg)$/)) {
      previewImage.src = previewUrl;
      previewImage.classList.remove('d-none');
      previewPlaceholder.classList.add('d-none');
    } else if (lower.match(/\.(mp4|webm|ogg)$/)) {
      previewVideo.src = previewUrl;
      previewVideo.classList.remove('d-none');
      previewPlaceholder.classList.add('d-none');
    } else if (lower.match(/\.(txt|log|json|md|csv)$/)) {
      previewIframe.src = previewUrl;
      previewIframe.classList.remove('d-none');
      previewPlaceholder.classList.add('d-none');
    }
  }

  updateBulkDeleteState();

  function initFolderNavigation() {
    if (hasFolders()) {
      renderBreadcrumb(currentPrefix);
      renderObjectsView();
    }
    if (typeof updateFolderViewStatus === 'function') {
      updateFolderViewStatus();
    }
    if (typeof updateFilterWarning === 'function') {
      updateFilterWarning();
    }
  }

  bulkDeleteButton?.addEventListener('click', () => openBulkDeleteModal());
  bulkDeleteConfirm?.addEventListener('click', () => performBulkDelete());

  const filterWarning = document.getElementById('filter-warning');
  const filterWarningText = document.getElementById('filter-warning-text');
  const folderViewStatus = document.getElementById('folder-view-status');

  const updateFilterWarning = () => {
    if (!filterWarning) return;
    const isFiltering = currentFilterTerm.length > 0;
    if (isFiltering && hasMoreObjects) {
      filterWarning.classList.remove('d-none');
    } else {
      filterWarning.classList.add('d-none');
    }
  };

  document.getElementById('object-search')?.addEventListener('input', (event) => {
    currentFilterTerm = event.target.value.toLowerCase();
    updateFilterWarning();
    refreshVirtualList();
  });

  refreshVersionsButton?.addEventListener('click', () => {
    if (!activeRow) {
      versionList.innerHTML = '<p class="text-muted small mb-0">Select an object to view versions.</p>';
      return;
    }
    const endpoint = activeRow.dataset.versionsEndpoint;
    if (endpoint) {
      versionsCache.delete(endpoint);
    }
    loadObjectVersions(activeRow, { force: true });
  });

  presignButton?.addEventListener('click', () => {
    if (!activeRow) {
      showMessage({ title: 'Select an object', body: 'Choose an object before generating a presigned URL.', variant: 'warning' });
      return;
    }
    presignLink.value = '';
    presignModal?.show();
    requestPresignedUrl();
  });

  generatePresignButton?.addEventListener('click', () => {
    requestPresignedUrl();
  });

  copyPresignLink?.addEventListener('click', async () => {
    if (!presignLink?.value) {
      return;
    }

    const fallbackCopy = (text) => {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      let success = false;
      try {
        success = document.execCommand('copy');
      } catch (err) {
        success = false;
      }
      textArea.remove();
      return success;
    };

    let copied = false;

    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(presignLink.value);
        copied = true;
      } catch (error) {

      }
    }

    if (!copied) {
      copied = fallbackCopy(presignLink.value);
    }

    if (copied) {
      copyPresignLink.textContent = 'Copied!';
      window.setTimeout(() => {
        copyPresignLink.textContent = copyPresignDefaultLabel;
      }, 1500);
    } else {
      showMessage({ title: 'Copy Failed', body: 'Unable to copy link to clipboard. Please select the link and copy manually.', variant: 'warning' });
    }
  });

  if (uploadForm && uploadFileInput) {
    const uploadSubmitBtn = document.getElementById('uploadSubmitBtn');
    const uploadCancelBtn = document.getElementById('uploadCancelBtn');
    const uploadBtnText = document.getElementById('uploadBtnText');
    const bulkUploadProgress = document.getElementById('bulkUploadProgress');
    const bulkUploadStatus = document.getElementById('bulkUploadStatus');
    const bulkUploadCounter = document.getElementById('bulkUploadCounter');
    const bulkUploadProgressBar = document.getElementById('bulkUploadProgressBar');
    const bulkUploadCurrentFile = document.getElementById('bulkUploadCurrentFile');
    const bulkUploadResults = document.getElementById('bulkUploadResults');
    const bulkUploadSuccessAlert = document.getElementById('bulkUploadSuccessAlert');
    const bulkUploadErrorAlert = document.getElementById('bulkUploadErrorAlert');
    const bulkUploadSuccessCount = document.getElementById('bulkUploadSuccessCount');
    const bulkUploadErrorCount = document.getElementById('bulkUploadErrorCount');
    const bulkUploadErrorList = document.getElementById('bulkUploadErrorList');
    const uploadKeyPrefix = document.getElementById('uploadKeyPrefix');
    const singleFileOptions = document.getElementById('singleFileOptions');
    const floatingProgress = document.getElementById('floatingUploadProgress');
    const floatingProgressBar = document.getElementById('floatingUploadProgressBar');
    const floatingProgressStatus = document.getElementById('floatingUploadStatus');
    const floatingProgressTitle = document.getElementById('floatingUploadTitle');
    const floatingProgressExpand = document.getElementById('floatingUploadExpand');
    const floatingProgressCancel = document.getElementById('floatingUploadCancel');
    const uploadQueueContainer = document.getElementById('uploadQueueContainer');
    const uploadQueueList = document.getElementById('uploadQueueList');
    const uploadQueueCount = document.getElementById('uploadQueueCount');
    const clearUploadQueueBtn = document.getElementById('clearUploadQueueBtn');
    let isUploading = false;
    let uploadQueue = [];
    let activeXHRs = [];
    let activeMultipartUpload = null;
    let uploadCancelled = false;
    let uploadStats = {
      totalFiles: 0,
      completedFiles: 0,
      totalBytes: 0,
      uploadedBytes: 0,
      currentFileBytes: 0,
      currentFileLoaded: 0,
      currentFileName: ''
    };

    window.addEventListener('beforeunload', (e) => {
      if (isUploading) {
        e.preventDefault();
        e.returnValue = 'Upload in progress. Are you sure you want to leave?';
        return e.returnValue;
      }
    });

    const showFloatingProgress = () => {
      if (floatingProgress) {
        floatingProgress.classList.remove('d-none');
      }
    };

    const hideFloatingProgress = () => {
      if (floatingProgress) {
        floatingProgress.classList.add('d-none');
      }
    };

    const updateFloatingProgress = () => {
      const { totalFiles, completedFiles, totalBytes, uploadedBytes, currentFileLoaded, currentFileName } = uploadStats;
      const effectiveUploaded = uploadedBytes + currentFileLoaded;

      if (floatingProgressBar && totalBytes > 0) {
        const percent = Math.round((effectiveUploaded / totalBytes) * 100);
        floatingProgressBar.style.width = `${percent}%`;
      }
      if (floatingProgressStatus) {
        const bytesText = `${formatBytes(effectiveUploaded)} / ${formatBytes(totalBytes)}`;
        const queuedCount = uploadQueue.length;
        let statusText = `${completedFiles}/${totalFiles} files`;
        if (queuedCount > 0) {
          statusText += ` (+${queuedCount} queued)`;
        }
        statusText += ` • ${bytesText}`;
        floatingProgressStatus.textContent = statusText;
      }
      if (floatingProgressTitle) {
        const remaining = totalFiles - completedFiles;
        const queuedCount = uploadQueue.length;
        let title = `Uploading ${remaining} file${remaining !== 1 ? 's' : ''}`;
        if (queuedCount > 0) {
          title += ` (+${queuedCount} queued)`;
        }
        floatingProgressTitle.textContent = title + '...';
      }
    };

    floatingProgressExpand?.addEventListener('click', () => {
      if (uploadModal) {
        uploadModal.show();
      }
    });

    const cancelAllUploads = async () => {
      uploadCancelled = true;

      activeXHRs.forEach(xhr => {
        try { xhr.abort(); } catch { }
      });
      activeXHRs = [];

      if (activeMultipartUpload) {
        const { abortUrl } = activeMultipartUpload;
        const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;
        try {
          await fetch(abortUrl, { method: 'DELETE', headers: { 'X-CSRFToken': csrfToken || '' } });
        } catch { }
        activeMultipartUpload = null;
      }

      uploadQueue = [];
      isProcessingQueue = false;
      isUploading = false;
      setUploadLockState(false);
      hideFloatingProgress();
      resetUploadUI();

      showMessage({ title: 'Upload cancelled', body: 'All uploads have been cancelled.', variant: 'info' });
      loadObjects(false);
    };

    floatingProgressCancel?.addEventListener('click', () => {
      cancelAllUploads();
    });

    const refreshUploadDropLabel = () => {
      if (!uploadDropZoneLabel) return;
      if (isUploading) {
        uploadDropZoneLabel.textContent = 'Drop files here to add to queue';
        if (singleFileOptions) singleFileOptions.classList.add('d-none');
        return;
      }
      const files = uploadFileInput.files;
      if (!files || files.length === 0) {
        uploadDropZoneLabel.textContent = 'No file selected';
        if (singleFileOptions) singleFileOptions.classList.remove('d-none');
        return;
      }
      uploadDropZoneLabel.textContent = files.length === 1 ? files[0].name : `${files.length} files selected`;

      if (singleFileOptions) {
        singleFileOptions.classList.toggle('d-none', files.length > 1);
      }
    };

    const updateUploadBtnText = () => {
      if (!uploadBtnText) return;
      if (isUploading) {
        const files = uploadFileInput.files;
        if (files && files.length > 0) {
          uploadBtnText.textContent = `Add ${files.length} to queue`;
          if (uploadSubmitBtn) uploadSubmitBtn.disabled = false;
        } else {
          uploadBtnText.textContent = 'Uploading...';
        }
        return;
      }
      const files = uploadFileInput.files;
      if (!files || files.length <= 1) {
        uploadBtnText.textContent = 'Upload';
      } else {
        uploadBtnText.textContent = `Upload ${files.length} files`;
      }
    };

    const resetUploadUI = () => {
      if (bulkUploadProgress) bulkUploadProgress.classList.add('d-none');
      if (bulkUploadResults) bulkUploadResults.classList.add('d-none');
      if (bulkUploadSuccessAlert) bulkUploadSuccessAlert.classList.remove('d-none');
      if (bulkUploadErrorAlert) bulkUploadErrorAlert.classList.add('d-none');
      if (bulkUploadErrorList) bulkUploadErrorList.innerHTML = '';
      if (uploadSubmitBtn) uploadSubmitBtn.disabled = false;
      if (uploadFileInput) uploadFileInput.disabled = false;
      const progressStack = document.querySelector('[data-upload-progress]');
      if (progressStack) progressStack.innerHTML = '';
      if (uploadDropZone) {
        uploadDropZone.classList.remove('upload-locked');
        uploadDropZone.style.pointerEvents = '';
      }
      isUploading = false;
      hideFloatingProgress();
    };

    const MULTIPART_THRESHOLD = 8 * 1024 * 1024;
    const CHUNK_SIZE = 8 * 1024 * 1024;
    const uploadProgressStack = document.querySelector('[data-upload-progress]');
    const multipartInitUrl = uploadForm.dataset.multipartInitUrl;
    const multipartPartTemplate = uploadForm.dataset.multipartPartTemplate;
    const multipartCompleteTemplate = uploadForm.dataset.multipartCompleteTemplate;
    const multipartAbortTemplate = uploadForm.dataset.multipartAbortTemplate;

    const createProgressItem = (file) => {
      const item = document.createElement('div');
      item.className = 'upload-progress-item';
      item.dataset.state = 'uploading';
      item.innerHTML = `
        <div class="d-flex justify-content-between align-items-start">
          <div class="min-width-0 flex-grow-1">
            <div class="file-name">${escapeHtml(file.name)}</div>
            <div class="file-size">${formatBytes(file.size)}</div>
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
    };

    const updateProgressItem = (item, { loaded, total, status, state, error }) => {
      if (state) item.dataset.state = state;
      const statusEl = item.querySelector('.upload-status');
      const progressBar = item.querySelector('.progress-bar');
      const progressLoaded = item.querySelector('.progress-loaded');
      const progressPercent = item.querySelector('.progress-percent');

      if (status) {
        statusEl.textContent = status;
        statusEl.className = 'upload-status text-end ms-2';
        if (state === 'success') statusEl.classList.add('success');
        if (state === 'error') statusEl.classList.add('error');
      }
      if (typeof loaded === 'number' && typeof total === 'number' && total > 0) {
        const percent = Math.round((loaded / total) * 100);
        progressBar.style.width = `${percent}%`;
        progressLoaded.textContent = `${formatBytes(loaded)} / ${formatBytes(total)}`;
        progressPercent.textContent = `${percent}%`;
      }
      if (error) {
        const progressContainer = item.querySelector('.progress-container');
        if (progressContainer) {
          progressContainer.innerHTML = `<div class="text-danger small mt-1">${escapeHtml(error)}</div>`;
        }
      }
    };

    const uploadMultipart = async (file, objectKey, metadata, progressItem) => {
      const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;

      if (uploadCancelled) throw new Error('Upload cancelled');

      updateProgressItem(progressItem, { status: 'Initiating...', loaded: 0, total: file.size });
      const initResp = await fetch(multipartInitUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken || '' },
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
            status: `Part ${partNumber}/${totalParts}`,
            loaded: uploadedBytes,
            total: file.size
          });
          uploadStats.currentFileLoaded = uploadedBytes;
          updateFloatingProgress();

          const partResp = await fetch(`${partUrl}?partNumber=${partNumber}`, {
            method: 'PUT',
            headers: {
              'X-CSRFToken': csrfToken || '',
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

          updateProgressItem(progressItem, {
            loaded: uploadedBytes,
            total: file.size
          });
          uploadStats.currentFileLoaded = uploadedBytes;
          updateFloatingProgress();
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

        activeMultipartUpload = null;
        return await completeResp.json();
      } catch (err) {
        if (!uploadCancelled) {
          try {
            await fetch(abortUrl, { method: 'DELETE', headers: { 'X-CSRFToken': csrfToken || '' } });
          } catch { }
        }
        activeMultipartUpload = null;
        throw err;
      }
    };

    const uploadRegular = async (file, objectKey, metadata, progressItem) => {
      return new Promise((resolve, reject) => {
        const formData = new FormData();
        formData.append('object', file);
        formData.append('object_key', objectKey);
        if (metadata) formData.append('metadata', JSON.stringify(metadata));
        const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;
        if (csrfToken) formData.append('csrf_token', csrfToken);

        const xhr = new XMLHttpRequest();
        activeXHRs.push(xhr);
        xhr.open('POST', uploadForm.action, true);
        xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

        const removeXHR = () => {
          const idx = activeXHRs.indexOf(xhr);
          if (idx > -1) activeXHRs.splice(idx, 1);
        };

        xhr.upload.addEventListener('progress', (e) => {
          if (e.lengthComputable) {
            updateProgressItem(progressItem, {
              status: 'Uploading...',
              loaded: e.loaded,
              total: e.total
            });
            uploadStats.currentFileLoaded = e.loaded;
            updateFloatingProgress();
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
              reject(new Error(data.message || `Upload failed (${xhr.status})`));
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

    const uploadSingleFile = async (file, keyPrefix = '', metadata = null, progressItem = null) => {
      const objectKey = keyPrefix ? `${keyPrefix}${file.name}` : file.name;
      const shouldUseMultipart = file.size >= MULTIPART_THRESHOLD && multipartInitUrl;

      if (!progressItem && uploadProgressStack) {
        progressItem = createProgressItem(file);
        uploadProgressStack.appendChild(progressItem);
      }

      try {
        let result;
        if (shouldUseMultipart) {
          updateProgressItem(progressItem, { status: 'Multipart upload...', loaded: 0, total: file.size });
          result = await uploadMultipart(file, objectKey, metadata, progressItem);
        } else {
          updateProgressItem(progressItem, { status: 'Uploading...', loaded: 0, total: file.size });
          result = await uploadRegular(file, objectKey, metadata, progressItem);
        }
        updateProgressItem(progressItem, { state: 'success', status: 'Complete', loaded: file.size, total: file.size });
        return result;
      } catch (err) {
        updateProgressItem(progressItem, { state: 'error', status: 'Failed', error: err.message });
        throw err;
      }
    };

    const setUploadLockState = (locked) => {
      if (uploadDropZone) {
        uploadDropZone.classList.toggle('upload-locked', locked);
      }
    };

    let uploadSuccessFiles = [];
    let uploadErrorFiles = [];
    let isProcessingQueue = false;

    const updateQueueListDisplay = () => {
      if (!uploadQueueList || !uploadQueueContainer || !uploadQueueCount) return;
      if (uploadQueue.length === 0) {
        uploadQueueContainer.classList.add('d-none');
        return;
      }
      uploadQueueContainer.classList.remove('d-none');
      uploadQueueCount.textContent = uploadQueue.length;
      uploadQueueList.innerHTML = uploadQueue.map((item, idx) => `
        <li class="d-flex align-items-center justify-content-between py-1 ${idx > 0 ? 'border-top' : ''}">
          <span class="text-truncate me-2" style="max-width: 300px;" title="${escapeHtml(item.file.name)}">
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="text-muted me-1" viewBox="0 0 16 16">
              <path d="M4 0h5.293A1 1 0 0 1 10 .293L13.707 4a1 1 0 0 1 .293.707V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2zm5.5 1.5v2a1 1 0 0 0 1 1h2l-3-3z"/>
            </svg>
            ${escapeHtml(item.file.name)}
          </span>
          <span class="text-muted">${formatBytes(item.file.size)}</span>
        </li>
      `).join('');
    };

    const addFilesToQueue = (files, keyPrefix, metadata) => {
      for (const file of files) {
        uploadQueue.push({ file, keyPrefix, metadata });
        uploadStats.totalFiles++;
        uploadStats.totalBytes += file.size;
      }
      updateFloatingProgress();
      updateQueueListDisplay();
    };

    const clearUploadQueue = () => {
      const clearedCount = uploadQueue.length;
      if (clearedCount === 0) return;
      for (const item of uploadQueue) {
        uploadStats.totalFiles--;
        uploadStats.totalBytes -= item.file.size;
      }
      uploadQueue.length = 0;
      updateFloatingProgress();
      updateQueueListDisplay();
    };

    if (clearUploadQueueBtn) {
      clearUploadQueueBtn.addEventListener('click', clearUploadQueue);
    }

    const processUploadQueue = async () => {
      if (isProcessingQueue) return;
      isProcessingQueue = true;

      while (uploadQueue.length > 0 && !uploadCancelled) {
        const item = uploadQueue.shift();
        const { file, keyPrefix, metadata } = item;
        updateQueueListDisplay();

        uploadStats.currentFileName = file.name;
        uploadStats.currentFileBytes = file.size;
        uploadStats.currentFileLoaded = 0;

        if (bulkUploadCounter) {
          const queuedCount = uploadQueue.length;
          let counterText = `${uploadStats.completedFiles + 1}/${uploadStats.totalFiles}`;
          if (queuedCount > 0) {
            counterText += ` (+${queuedCount} queued)`;
          }
          bulkUploadCounter.textContent = counterText;
        }
        if (bulkUploadCurrentFile) {
          bulkUploadCurrentFile.textContent = `Uploading: ${file.name}`;
        }
        if (bulkUploadProgressBar) {
          const percent = Math.round(((uploadStats.completedFiles + 1) / uploadStats.totalFiles) * 100);
          bulkUploadProgressBar.style.width = `${percent}%`;
        }
        updateFloatingProgress();

        try {
          await uploadSingleFile(file, keyPrefix, metadata);
          uploadSuccessFiles.push(file.name);
        } catch (error) {
          uploadErrorFiles.push({ name: file.name, error: error.message || 'Unknown error' });
        }

        uploadStats.uploadedBytes += file.size;
        uploadStats.completedFiles++;
        uploadStats.currentFileLoaded = 0;
        updateFloatingProgress();
      }

      isProcessingQueue = false;

      if (uploadQueue.length === 0 && !uploadCancelled) {
        finishUploadSession();
      }
    };

    const finishUploadSession = () => {
      if (bulkUploadProgress) bulkUploadProgress.classList.add('d-none');
      if (bulkUploadResults) bulkUploadResults.classList.remove('d-none');
      hideFloatingProgress();

      if (bulkUploadSuccessCount) bulkUploadSuccessCount.textContent = uploadSuccessFiles.length;
      if (uploadSuccessFiles.length === 0 && bulkUploadSuccessAlert) {
        bulkUploadSuccessAlert.classList.add('d-none');
      }

      if (uploadErrorFiles.length > 0) {
        if (bulkUploadErrorCount) bulkUploadErrorCount.textContent = uploadErrorFiles.length;
        if (bulkUploadErrorAlert) bulkUploadErrorAlert.classList.remove('d-none');
        if (bulkUploadErrorList) {
          bulkUploadErrorList.innerHTML = uploadErrorFiles
            .map(f => `<li><strong>${escapeHtml(f.name)}</strong>: ${escapeHtml(f.error)}</li>`)
            .join('');
        }
      }

      isUploading = false;
      setUploadLockState(false);
      refreshUploadDropLabel();
      updateUploadBtnText();
      updateQueueListDisplay();

      if (uploadSubmitBtn) uploadSubmitBtn.disabled = false;
      if (uploadFileInput) {
        uploadFileInput.disabled = false;
        uploadFileInput.value = '';
      }

      loadObjects(false);

      const successCount = uploadSuccessFiles.length;
      const errorCount = uploadErrorFiles.length;
      if (successCount > 0 && errorCount > 0) {
        showMessage({ title: 'Upload complete', body: `${successCount} uploaded, ${errorCount} failed.`, variant: 'warning' });
      } else if (successCount > 0) {
        showMessage({ title: 'Upload complete', body: `${successCount} object(s) uploaded successfully.`, variant: 'success' });
      } else if (errorCount > 0) {
        showMessage({ title: 'Upload failed', body: `${errorCount} file(s) failed to upload.`, variant: 'danger' });
      }
    };

    const performBulkUpload = async (files) => {
      if (!files || files.length === 0) return;

      const keyPrefix = (uploadKeyPrefix?.value || '').trim();
      const metadataRaw = uploadForm.querySelector('textarea[name="metadata"]')?.value?.trim();
      let metadata = null;
      if (metadataRaw) {
        try {
          metadata = JSON.parse(metadataRaw);
        } catch {
          showMessage({ title: 'Invalid metadata', body: 'Metadata must be valid JSON.', variant: 'danger' });
          return;
        }
      }

      if (!isUploading) {
        isUploading = true;
        uploadCancelled = false;
        uploadSuccessFiles = [];
        uploadErrorFiles = [];
        uploadStats = {
          totalFiles: 0,
          completedFiles: 0,
          totalBytes: 0,
          uploadedBytes: 0,
          currentFileBytes: 0,
          currentFileLoaded: 0,
          currentFileName: ''
        };

        if (bulkUploadProgress) bulkUploadProgress.classList.remove('d-none');
        if (bulkUploadResults) bulkUploadResults.classList.add('d-none');
        if (uploadSubmitBtn) uploadSubmitBtn.disabled = true;
        refreshUploadDropLabel();
        updateUploadBtnText();

        if (uploadModal) uploadModal.hide();
        showFloatingProgress();
      }

      const fileCount = files.length;
      addFilesToQueue(Array.from(files), keyPrefix, metadata);

      if (uploadFileInput) {
        uploadFileInput.value = '';
      }
      refreshUploadDropLabel();
      updateUploadBtnText();

      processUploadQueue();
    };

    refreshUploadDropLabel();
    uploadFileInput.addEventListener('change', () => {
      refreshUploadDropLabel();
      updateUploadBtnText();
      if (!isUploading) {
        resetUploadUI();
      }
    });
    uploadDropZone?.addEventListener('click', () => {
      uploadFileInput?.click();
    });

    uploadForm.addEventListener('submit', async (event) => {
      const files = uploadFileInput.files;
      if (!files || files.length === 0) return;

      const keyPrefix = (uploadKeyPrefix?.value || '').trim();

      if (files.length === 1 && !keyPrefix) {
        const customKey = uploadForm.querySelector('input[name="object_key"]')?.value?.trim();
        if (customKey) {

          if (uploadSubmitBtn) {
            uploadSubmitBtn.disabled = true;
            if (uploadBtnText) uploadBtnText.textContent = 'Uploading...';
          }
          return;
        }
      }

      event.preventDefault();

      if (uploadSubmitBtn) {
        uploadSubmitBtn.disabled = true;
        if (uploadBtnText) uploadBtnText.textContent = 'Uploading...';
      }

      await performBulkUpload(Array.from(files));
    });

    uploadModalEl?.addEventListener('show.bs.modal', () => {
      if (hasFolders() && currentPrefix) {
        uploadKeyPrefix.value = currentPrefix;

        const advancedToggle = document.querySelector('[data-bs-target="#advancedUploadOptions"]');
        const advancedCollapse = document.getElementById('advancedUploadOptions');
        if (advancedToggle && advancedCollapse && !advancedCollapse.classList.contains('show')) {
          new bootstrap.Collapse(advancedCollapse, { show: true });
        }
      } else if (uploadKeyPrefix) {

        uploadKeyPrefix.value = '';
      }
    });

    uploadModalEl?.addEventListener('hide.bs.modal', (event) => {
      if (isUploading) {
        showFloatingProgress();
      }
    });

    uploadModalEl?.addEventListener('hidden.bs.modal', () => {
      if (!isUploading) {
        resetUploadUI();
        uploadFileInput.value = '';
        refreshUploadDropLabel();
        updateUploadBtnText();
      }
    });

    uploadModalEl?.addEventListener('show.bs.modal', () => {
      if (isUploading) {
        hideFloatingProgress();
      }
    });

    const preventDefaults = (event) => {
      event.preventDefault();
      event.stopPropagation();
    };

    const wireDropTarget = (target, { highlightClass = '', autoOpenModal = false } = {}) => {
      if (!target) return;
      ['dragenter', 'dragover'].forEach((eventName) => {
        target.addEventListener(eventName, (event) => {
          preventDefaults(event);
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
        if (!event.dataTransfer?.files?.length) {
          return;
        }
        if (isUploading) {
          performBulkUpload(event.dataTransfer.files);
        } else {
          if (uploadFileInput) {
            uploadFileInput.files = event.dataTransfer.files;
            uploadFileInput.dispatchEvent(new Event('change', { bubbles: true }));
          }
          if (autoOpenModal && uploadModal) {
            uploadModal.show();
          }
        }
      });
    };

    if (uploadDropZone) {
      wireDropTarget(uploadDropZone, { highlightClass: 'is-dragover' });
    }

    if (objectsContainer) {
      wireDropTarget(objectsContainer, { highlightClass: 'drag-over', autoOpenModal: true });
    }
  }

  const bulkDownloadButton = document.querySelector('[data-bulk-download-trigger]');
  const bulkDownloadEndpoint = document.getElementById('objects-drop-zone')?.dataset.bulkDownloadEndpoint;

  const updateBulkDownloadState = () => {
    if (!bulkDownloadButton) return;
    const selectedCount = document.querySelectorAll('[data-object-select]:checked').length;
    bulkDownloadButton.disabled = selectedCount === 0;
  };

  selectAllCheckbox?.addEventListener('change', (event) => {
    const shouldSelect = Boolean(event.target?.checked);

    const filesInView = visibleItems.filter(item => item.type === 'file');

    filesInView.forEach(item => {
      if (shouldSelect) {
        selectedRows.set(item.data.key, item.data);
      } else {
        selectedRows.delete(item.data.key);
      }
    });

    document.querySelectorAll('[data-folder-select]').forEach(cb => {
      cb.checked = shouldSelect;
    });

    document.querySelectorAll('[data-object-row]').forEach((row) => {
      const checkbox = row.querySelector('[data-object-select]');
      if (checkbox) {
        checkbox.checked = shouldSelect;
      }
    });

    updateBulkDeleteState();
    setTimeout(updateBulkDownloadState, 0);
  });

  bulkDownloadButton?.addEventListener('click', async () => {
    if (!bulkDownloadEndpoint) return;
    const selected = Array.from(selectedRows.keys());
    if (selected.length === 0) return;

    bulkDownloadButton.disabled = true;
    const originalHtml = bulkDownloadButton.innerHTML;
    bulkDownloadButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Downloading...';

    try {
      const response = await fetch(bulkDownloadEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '',
        },
        body: JSON.stringify({ keys: selected }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || 'Download failed');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${document.getElementById('objects-drop-zone').dataset.bucket}-download.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (error) {
      showMessage({ title: 'Download Failed', body: error.message, variant: 'danger' });
    } finally {
      bulkDownloadButton.disabled = false;
      bulkDownloadButton.innerHTML = originalHtml;
    }
  });

  const replicationStatsContainer = document.getElementById('replication-stats-cards');
  if (replicationStatsContainer) {
    const statusEndpoint = replicationStatsContainer.dataset.statusEndpoint;
    const syncedEl = replicationStatsContainer.querySelector('[data-stat="synced"]');
    const pendingEl = replicationStatsContainer.querySelector('[data-stat="pending"]');
    const orphanedEl = replicationStatsContainer.querySelector('[data-stat="orphaned"]');
    const bytesEl = replicationStatsContainer.querySelector('[data-stat="bytes"]');
    const lastSyncEl = document.getElementById('replication-last-sync');
    const lastSyncTimeEl = document.querySelector('[data-stat="last-sync-time"]');
    const lastSyncKeyEl = document.querySelector('[data-stat="last-sync-key"]');
    const endpointWarning = document.getElementById('replication-endpoint-warning');
    const endpointErrorEl = document.getElementById('replication-endpoint-error');
    const statusAlert = document.getElementById('replication-status-alert');
    const statusBadge = document.getElementById('replication-status-badge');
    const statusText = document.getElementById('replication-status-text');
    const pauseForm = document.getElementById('pause-replication-form');

    const loadReplicationStats = async () => {
      try {
        const resp = await fetch(statusEndpoint);
        if (!resp.ok) throw new Error('Failed to fetch stats');
        const data = await resp.json();

        // Handle endpoint health status
        if (data.endpoint_healthy === false) {
          // Show warning and hide success alert
          if (endpointWarning) {
            endpointWarning.classList.remove('d-none');
            if (endpointErrorEl && data.endpoint_error) {
              endpointErrorEl.textContent = data.endpoint_error + '. Replication is paused until the endpoint is available.';
            }
          }
          if (statusAlert) statusAlert.classList.add('d-none');

          // Update status badge to show "Paused" with warning styling
          if (statusBadge) {
            statusBadge.className = 'badge bg-warning-subtle text-warning px-3 py-2';
            statusBadge.innerHTML = `
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="me-1" viewBox="0 0 16 16">
                <path d="M5.5 3.5A1.5 1.5 0 0 1 7 5v6a1.5 1.5 0 0 1-3 0V5a1.5 1.5 0 0 1 1.5-1.5zm5 0A1.5 1.5 0 0 1 12 5v6a1.5 1.5 0 0 1-3 0V5a1.5 1.5 0 0 1 1.5-1.5z"/>
              </svg>
              <span>Paused (Endpoint Unavailable)</span>`;
          }

          // Hide the pause button since replication is effectively already paused
          if (pauseForm) pauseForm.classList.add('d-none');
        } else {
          // Hide warning and show success alert
          if (endpointWarning) endpointWarning.classList.add('d-none');
          if (statusAlert) statusAlert.classList.remove('d-none');

          // Restore status badge to show "Enabled"
          if (statusBadge) {
            statusBadge.className = 'badge bg-success-subtle text-success px-3 py-2';
            statusBadge.innerHTML = `
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="me-1" viewBox="0 0 16 16">
                <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>
              </svg>
              <span>Enabled</span>`;
          }

          // Show the pause button
          if (pauseForm) pauseForm.classList.remove('d-none');
        }

        if (syncedEl) syncedEl.textContent = data.objects_synced;
        if (pendingEl) {
          pendingEl.textContent = data.objects_pending;
          if (data.objects_pending > 0) pendingEl.classList.add('text-warning');
        }
        if (orphanedEl) orphanedEl.textContent = data.objects_orphaned;
        if (bytesEl) bytesEl.textContent = formatBytes(data.bytes_synced);

        if (data.last_sync_at && lastSyncEl) {
          lastSyncEl.style.display = '';
          const date = new Date(data.last_sync_at * 1000);
          if (lastSyncTimeEl) lastSyncTimeEl.textContent = date.toLocaleString();
          if (lastSyncKeyEl && data.last_sync_key) {
            lastSyncKeyEl.innerHTML = ' — <code class="small">' + escapeHtml(data.last_sync_key) + '</code>';
          }
        }
      } catch (err) {
        console.error('Failed to load replication stats:', err);
        if (syncedEl) syncedEl.textContent = '—';
        if (pendingEl) pendingEl.textContent = '—';
        if (orphanedEl) orphanedEl.textContent = '—';
        if (bytesEl) bytesEl.textContent = '—';
      }
    };

    loadReplicationStats();

    if (window.pollingManager) {
      window.pollingManager.start('replication', loadReplicationStats);
    }

    const refreshBtn = document.querySelector('[data-refresh-replication]');
    refreshBtn?.addEventListener('click', () => {

      if (syncedEl) syncedEl.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
      if (pendingEl) pendingEl.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
      if (orphanedEl) orphanedEl.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
      if (bytesEl) bytesEl.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
      loadReplicationStats();
      loadReplicationFailures();
    });

    const failuresCard = document.getElementById('replication-failures-card');
    const failuresBody = document.getElementById('replication-failures-body');
    const failureCountBadge = document.getElementById('replication-failure-count');
    const retryAllBtn = document.getElementById('retry-all-failures-btn');
    const clearFailuresBtn = document.getElementById('clear-failures-btn');
    const showMoreFailuresBtn = document.getElementById('show-more-failures');
    const failuresPagination = document.getElementById('replication-failures-pagination');
    const failuresShownCount = document.getElementById('failures-shown-count');
    const clearFailuresModal = document.getElementById('clearFailuresModal');
    const confirmClearFailuresBtn = document.getElementById('confirmClearFailuresBtn');
    const clearFailuresModalInstance = clearFailuresModal ? new bootstrap.Modal(clearFailuresModal) : null;

    let failuresExpanded = false;
    let currentFailures = [];

    const loadReplicationFailures = async () => {
      if (!failuresCard) return;

      const endpoint = failuresCard.dataset.failuresEndpoint;
      const limit = failuresExpanded ? 50 : 5;

      try {
        const resp = await fetch(`${endpoint}?limit=${limit}`);
        if (!resp.ok) throw new Error('Failed to fetch failures');
        const data = await resp.json();

        currentFailures = data.failures;
        const total = data.total;

        if (total > 0) {
          failuresCard.style.display = '';
          failureCountBadge.textContent = total;
          renderFailures(currentFailures);

          if (total > 5 && !failuresExpanded) {
            failuresPagination.style.display = '';
            failuresShownCount.textContent = `Showing ${Math.min(5, total)} of ${total}`;
          } else {
            failuresPagination.style.display = 'none';
          }
        } else {
          failuresCard.style.display = 'none';
        }
      } catch (err) {
        console.error('Failed to load replication failures:', err);
      }
    };

    const renderFailures = (failures) => {
      if (!failuresBody) return;
      failuresBody.innerHTML = failures.map(f => `
        <tr>
          <td class="ps-3" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(f.object_key)}">
            <code class="small">${escapeHtml(f.object_key)}</code>
          </td>
          <td class="small text-muted" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(f.error_message)}">
            ${escapeHtml(f.error_message)}
          </td>
          <td class="small text-muted">${new Date(f.timestamp * 1000).toLocaleString()}</td>
          <td class="text-center"><span class="badge bg-secondary">${f.failure_count}</span></td>
          <td class="text-end pe-3">
            <button class="btn btn-sm btn-outline-primary py-0 px-2" onclick="retryFailure(this, '${escapeHtml(f.object_key)}')" title="Retry">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">
                <path fill-rule="evenodd" d="M8 3a5 5 0 1 1-4.546 2.914.5.5 0 0 0-.908-.417A6 6 0 1 0 8 2v1z"/>
                <path d="M8 4.466V.534a.25.25 0 0 0-.41-.192L5.23 2.308a.25.25 0 0 0 0 .384l2.36 1.966A.25.25 0 0 0 8 4.466z"/>
              </svg>
            </button>
            <button class="btn btn-sm btn-outline-secondary py-0 px-2" onclick="dismissFailure(this, '${escapeHtml(f.object_key)}')" title="Dismiss">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">
                <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>
              </svg>
            </button>
          </td>
        </tr>
      `).join('');
    };

    window.retryFailure = async (btn, objectKey) => {
      const originalHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" style="width: 12px; height: 12px;"></span>';
      const endpoint = failuresCard.dataset.retryEndpoint.replace('__KEY__', encodeURIComponent(objectKey));
      try {
        const resp = await fetch(endpoint, { method: 'POST' });
        if (resp.ok) {
          loadReplicationFailures();
        }
      } catch (err) {
        console.error('Failed to retry:', err);
        btn.disabled = false;
        btn.innerHTML = originalHtml;
      }
    };

    window.dismissFailure = async (btn, objectKey) => {
      const originalHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" style="width: 12px; height: 12px;"></span>';
      const endpoint = failuresCard.dataset.dismissEndpoint.replace('__KEY__', encodeURIComponent(objectKey));
      try {
        const resp = await fetch(endpoint, { method: 'DELETE' });
        if (resp.ok) {
          loadReplicationFailures();
        }
      } catch (err) {
        console.error('Failed to dismiss:', err);
        btn.disabled = false;
        btn.innerHTML = originalHtml;
      }
    };

    retryAllBtn?.addEventListener('click', async () => {
      const btn = retryAllBtn;
      const originalHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>Retrying...';
      const endpoint = failuresCard.dataset.retryAllEndpoint;
      try {
        const resp = await fetch(endpoint, { method: 'POST' });
        if (resp.ok) {
          loadReplicationFailures();
        }
      } catch (err) {
        console.error('Failed to retry all:', err);
      } finally {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
      }
    });

    clearFailuresBtn?.addEventListener('click', () => {
      clearFailuresModalInstance?.show();
    });

    confirmClearFailuresBtn?.addEventListener('click', async () => {
      const btn = confirmClearFailuresBtn;
      const originalHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>Clearing...';
      const endpoint = failuresCard.dataset.clearEndpoint;
      try {
        const resp = await fetch(endpoint, { method: 'DELETE' });
        if (resp.ok) {
          clearFailuresModalInstance?.hide();
          loadReplicationFailures();
        }
      } catch (err) {
        console.error('Failed to clear failures:', err);
      } finally {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
      }
    });

    showMoreFailuresBtn?.addEventListener('click', () => {
      failuresExpanded = !failuresExpanded;
      showMoreFailuresBtn.textContent = failuresExpanded ? 'Show less' : 'Show more...';
      loadReplicationFailures();
    });

    loadReplicationFailures();
  }

  const algoAes256Radio = document.getElementById('algo_aes256');
  const algoKmsRadio = document.getElementById('algo_kms');
  const kmsKeySection = document.getElementById('kmsKeySection');
  const encryptionForm = document.getElementById('encryptionForm');
  const encryptionAction = document.getElementById('encryptionAction');
  const disableEncryptionBtn = document.getElementById('disableEncryptionBtn');

  const updateKmsKeyVisibility = () => {
    if (!kmsKeySection) return;
    const showKms = algoKmsRadio?.checked;
    kmsKeySection.style.display = showKms ? '' : 'none';
  };

  algoAes256Radio?.addEventListener('change', updateKmsKeyVisibility);
  algoKmsRadio?.addEventListener('change', updateKmsKeyVisibility);

  disableEncryptionBtn?.addEventListener('click', () => {
    if (encryptionAction && encryptionForm) {
      if (confirm('Are you sure you want to disable default encryption? New objects will not be encrypted automatically.')) {
        encryptionAction.value = 'disable';
        encryptionForm.submit();
      }
    }
  });

  const targetBucketInput = document.getElementById('target_bucket');
  const targetBucketFeedback = document.getElementById('target_bucket_feedback');

  const validateBucketName = (name) => {
    if (!name) return { valid: false, error: 'Bucket name is required' };
    if (name.length < 3) return { valid: false, error: 'Bucket name must be at least 3 characters' };
    if (name.length > 63) return { valid: false, error: 'Bucket name must be 63 characters or less' };
    if (!/^[a-z0-9]/.test(name)) return { valid: false, error: 'Bucket name must start with a lowercase letter or number' };
    if (!/[a-z0-9]$/.test(name)) return { valid: false, error: 'Bucket name must end with a lowercase letter or number' };
    if (/[A-Z]/.test(name)) return { valid: false, error: 'Bucket name must not contain uppercase letters' };
    if (/_/.test(name)) return { valid: false, error: 'Bucket name must not contain underscores' };
    if (/\.\.|--/.test(name)) return { valid: false, error: 'Bucket name must not contain consecutive periods or hyphens' };
    if (/^\d+\.\d+\.\d+\.\d+$/.test(name)) return { valid: false, error: 'Bucket name must not be formatted as an IP address' };
    if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(name) && name.length > 2) return { valid: false, error: 'Bucket name contains invalid characters. Use only lowercase letters, numbers, hyphens, and periods.' };
    return { valid: true, error: null };
  };

  const updateBucketNameValidation = () => {
    if (!targetBucketInput || !targetBucketFeedback) return;
    const name = targetBucketInput.value.trim();
    if (!name) {
      targetBucketInput.classList.remove('is-valid', 'is-invalid');
      targetBucketFeedback.textContent = '';
      return;
    }
    const result = validateBucketName(name);
    targetBucketInput.classList.toggle('is-valid', result.valid);
    targetBucketInput.classList.toggle('is-invalid', !result.valid);
    targetBucketFeedback.textContent = result.error || '';
  };

  targetBucketInput?.addEventListener('input', updateBucketNameValidation);
  targetBucketInput?.addEventListener('blur', updateBucketNameValidation);

  const replicationForm = targetBucketInput?.closest('form');
  replicationForm?.addEventListener('submit', (e) => {
    const name = targetBucketInput.value.trim();
    const result = validateBucketName(name);
    if (!result.valid) {
      e.preventDefault();
      updateBucketNameValidation();
      targetBucketInput.focus();
      return false;
    }
  });

  const formatPolicyBtn = document.getElementById('formatPolicyBtn');
  const policyValidationStatus = document.getElementById('policyValidationStatus');
  const policyValidBadge = document.getElementById('policyValidBadge');
  const policyInvalidBadge = document.getElementById('policyInvalidBadge');
  const policyErrorDetail = document.getElementById('policyErrorDetail');

  const validatePolicyJson = () => {
    if (!policyTextarea || !policyValidationStatus) return;
    const value = policyTextarea.value.trim();
    if (!value) {
      policyValidationStatus.classList.add('d-none');
      policyErrorDetail?.classList.add('d-none');
      return;
    }
    policyValidationStatus.classList.remove('d-none');
    try {
      JSON.parse(value);
      policyValidBadge?.classList.remove('d-none');
      policyInvalidBadge?.classList.add('d-none');
      policyErrorDetail?.classList.add('d-none');
    } catch (err) {
      policyValidBadge?.classList.add('d-none');
      policyInvalidBadge?.classList.remove('d-none');
      if (policyErrorDetail) {
        policyErrorDetail.textContent = err.message;
        policyErrorDetail.classList.remove('d-none');
      }
    }
  };

  policyTextarea?.addEventListener('input', validatePolicyJson);
  policyTextarea?.addEventListener('blur', validatePolicyJson);

  formatPolicyBtn?.addEventListener('click', () => {
    if (!policyTextarea) return;
    const value = policyTextarea.value.trim();
    if (!value) return;
    try {
      const parsed = JSON.parse(value);
      policyTextarea.value = JSON.stringify(parsed, null, 2);
      validatePolicyJson();
    } catch (err) {
      validatePolicyJson();
    }
  });

  if (policyTextarea && policyPreset?.value === 'custom') {
    validatePolicyJson();
  }

  const lifecycleCard = document.getElementById('lifecycle-rules-card');
  const lifecycleUrl = lifecycleCard?.dataset.lifecycleUrl;
  const lifecycleRulesBody = document.getElementById('lifecycle-rules-body');
  const addLifecycleRuleModalEl = document.getElementById('addLifecycleRuleModal');
  const addLifecycleRuleModal = addLifecycleRuleModalEl ? new bootstrap.Modal(addLifecycleRuleModalEl) : null;
  let lifecycleRules = [];

  const loadLifecycleRules = async () => {
    if (!lifecycleUrl || !lifecycleRulesBody) return;
    lifecycleRulesBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4"><div class="spinner-border spinner-border-sm me-2" role="status"></div>Loading...</td></tr>';
    try {
      const resp = await fetch(lifecycleUrl);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to load lifecycle rules');
      lifecycleRules = data.rules || [];
      renderLifecycleRules();
    } catch (err) {
      lifecycleRulesBody.innerHTML = `<tr><td colspan="7" class="text-center text-danger py-4">${escapeHtml(err.message)}</td></tr>`;
    }
  };

  const renderLifecycleRules = () => {
    if (!lifecycleRulesBody) return;
    if (lifecycleRules.length === 0) {
      lifecycleRulesBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No lifecycle rules configured</td></tr>';
      return;
    }
    lifecycleRulesBody.innerHTML = lifecycleRules.map((rule, idx) => {
      const expiration = rule.Expiration?.Days ? `${rule.Expiration.Days}d` : '-';
      const noncurrent = rule.NoncurrentVersionExpiration?.NoncurrentDays ? `${rule.NoncurrentVersionExpiration.NoncurrentDays}d` : '-';
      const abortMpu = rule.AbortIncompleteMultipartUpload?.DaysAfterInitiation ? `${rule.AbortIncompleteMultipartUpload.DaysAfterInitiation}d` : '-';
      const statusClass = rule.Status === 'Enabled' ? 'bg-success' : 'bg-secondary';
      return `<tr>
        <td><code class="small">${escapeHtml(rule.ID || '')}</code></td>
        <td><code class="small">${escapeHtml(rule.Filter?.Prefix || '*')}</code></td>
        <td><span class="badge ${statusClass}">${escapeHtml(rule.Status)}</span></td>
        <td class="small">${expiration}</td>
        <td class="small">${noncurrent}</td>
        <td class="small">${abortMpu}</td>
        <td class="text-end">
          <div class="btn-group btn-group-sm">
            <button class="btn btn-outline-secondary" onclick="editLifecycleRule(${idx})" title="Edit rule">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16"><path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168l10-10zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293l6.5-6.5zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325z"/></svg>
            </button>
            <button class="btn btn-outline-danger" onclick="deleteLifecycleRule(${idx})" title="Delete rule">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16"><path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/><path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/></svg>
            </button>
          </div>
        </td>
      </tr>`;
    }).join('');
  };

  window.editLifecycleRule = (idx) => {
    const rule = lifecycleRules[idx];
    if (!rule) return;
    document.getElementById('lifecycleRuleId').value = rule.ID || '';
    document.getElementById('lifecycleRuleStatus').value = rule.Status || 'Enabled';
    document.getElementById('lifecycleRulePrefix').value = rule.Filter?.Prefix || '';
    document.getElementById('lifecycleExpirationDays').value = rule.Expiration?.Days || '';
    document.getElementById('lifecycleNoncurrentDays').value = rule.NoncurrentVersionExpiration?.NoncurrentDays || '';
    document.getElementById('lifecycleAbortMpuDays').value = rule.AbortIncompleteMultipartUpload?.DaysAfterInitiation || '';
    window.editingLifecycleIdx = idx;
    addLifecycleRuleModal?.show();
  };

  window.editingLifecycleIdx = null;

  window.deleteLifecycleRule = async (idx) => {
    lifecycleRules.splice(idx, 1);
    await saveLifecycleRules();
  };

  const saveLifecycleRules = async () => {
    if (!lifecycleUrl) return;
    try {
      const resp = await fetch(lifecycleUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify({ rules: lifecycleRules })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to save');
      showMessage({ title: 'Lifecycle rules saved', body: 'Configuration updated successfully.', variant: 'success' });
      renderLifecycleRules();
    } catch (err) {
      showMessage({ title: 'Save failed', body: err.message, variant: 'danger' });
    }
  };

  document.getElementById('addLifecycleRuleConfirm')?.addEventListener('click', async () => {
    const ruleId = document.getElementById('lifecycleRuleId')?.value?.trim();
    const status = document.getElementById('lifecycleRuleStatus')?.value || 'Enabled';
    const prefix = document.getElementById('lifecycleRulePrefix')?.value?.trim() || '';
    const expDays = parseInt(document.getElementById('lifecycleExpirationDays')?.value) || 0;
    const ncDays = parseInt(document.getElementById('lifecycleNoncurrentDays')?.value) || 0;
    const abortDays = parseInt(document.getElementById('lifecycleAbortMpuDays')?.value) || 0;
    if (!ruleId) { showMessage({ title: 'Validation error', body: 'Rule ID is required', variant: 'warning' }); return; }
    if (expDays === 0 && ncDays === 0 && abortDays === 0) { showMessage({ title: 'Validation error', body: 'At least one action is required', variant: 'warning' }); return; }
    const rule = { ID: ruleId, Status: status, Filter: { Prefix: prefix } };
    if (expDays > 0) rule.Expiration = { Days: expDays };
    if (ncDays > 0) rule.NoncurrentVersionExpiration = { NoncurrentDays: ncDays };
    if (abortDays > 0) rule.AbortIncompleteMultipartUpload = { DaysAfterInitiation: abortDays };
    if (typeof window.editingLifecycleIdx === 'number' && window.editingLifecycleIdx !== null) {
      lifecycleRules[window.editingLifecycleIdx] = rule;
      window.editingLifecycleIdx = null;
    } else {
      lifecycleRules.push(rule);
    }
    await saveLifecycleRules();
    addLifecycleRuleModal?.hide();
    document.getElementById('lifecycleRuleId').value = '';
    document.getElementById('lifecycleRulePrefix').value = '';
    document.getElementById('lifecycleExpirationDays').value = '';
    document.getElementById('lifecycleNoncurrentDays').value = '';
    document.getElementById('lifecycleAbortMpuDays').value = '';
    document.getElementById('lifecycleRuleStatus').value = 'Enabled';
  });

  const corsCard = document.getElementById('cors-rules-card');
  const corsUrl = corsCard?.dataset.corsUrl;
  const corsRulesBody = document.getElementById('cors-rules-body');
  const addCorsRuleModalEl = document.getElementById('addCorsRuleModal');
  const addCorsRuleModal = addCorsRuleModalEl ? new bootstrap.Modal(addCorsRuleModalEl) : null;
  let corsRules = [];

  const loadCorsRules = async () => {
    if (!corsUrl || !corsRulesBody) return;
    corsRulesBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4"><div class="spinner-border spinner-border-sm me-2" role="status"></div>Loading...</td></tr>';
    try {
      const resp = await fetch(corsUrl);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to load CORS rules');
      corsRules = data.rules || [];
      renderCorsRules();
    } catch (err) {
      corsRulesBody.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-4">${escapeHtml(err.message)}</td></tr>`;
    }
  };

  const renderCorsRules = () => {
    if (!corsRulesBody) return;
    if (corsRules.length === 0) {
      corsRulesBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">No CORS rules configured</td></tr>';
      return;
    }
    corsRulesBody.innerHTML = corsRules.map((rule, idx) => {
      const origins = (rule.AllowedOrigins || []).map(o => `<code class="small">${escapeHtml(o)}</code>`).join(', ');
      const methods = (rule.AllowedMethods || []).map(m => `<span class="badge bg-primary-subtle text-primary">${escapeHtml(m)}</span>`).join(' ');
      const headers = (rule.AllowedHeaders || []).slice(0, 3).map(h => `<code class="small">${escapeHtml(h)}</code>`).join(', ');
      return `<tr>
        <td>${origins || '<span class="text-muted">None</span>'}</td>
        <td>${methods || '<span class="text-muted">None</span>'}</td>
        <td>${headers || '<span class="text-muted">*</span>'}</td>
        <td>${rule.MaxAgeSeconds || '<span class="text-muted">-</span>'}</td>
        <td class="text-end">
          <div class="btn-group btn-group-sm">
            <button class="btn btn-outline-secondary" onclick="editCorsRule(${idx})" title="Edit rule">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16"><path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168l10-10zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293l6.5-6.5zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325z"/></svg>
            </button>
            <button class="btn btn-outline-danger" onclick="deleteCorsRule(${idx})" title="Delete rule">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16"><path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/><path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/></svg>
            </button>
          </div>
        </td>
      </tr>`;
    }).join('');
  };

  window.editCorsRule = (idx) => {
    const rule = corsRules[idx];
    if (!rule) return;
    document.getElementById('corsAllowedOrigins').value = (rule.AllowedOrigins || []).join('\n');
    document.getElementById('corsAllowedHeaders').value = (rule.AllowedHeaders || []).join('\n');
    document.getElementById('corsExposeHeaders').value = (rule.ExposeHeaders || []).join('\n');
    document.getElementById('corsMaxAge').value = rule.MaxAgeSeconds || '';
    document.getElementById('corsMethodGet').checked = (rule.AllowedMethods || []).includes('GET');
    document.getElementById('corsMethodPut').checked = (rule.AllowedMethods || []).includes('PUT');
    document.getElementById('corsMethodPost').checked = (rule.AllowedMethods || []).includes('POST');
    document.getElementById('corsMethodDelete').checked = (rule.AllowedMethods || []).includes('DELETE');
    document.getElementById('corsMethodHead').checked = (rule.AllowedMethods || []).includes('HEAD');
    window.editingCorsIdx = idx;
    addCorsRuleModal?.show();
  };

  window.editingCorsIdx = null;

  window.deleteCorsRule = async (idx) => {
    corsRules.splice(idx, 1);
    await saveCorsRules();
  };

  const saveCorsRules = async () => {
    if (!corsUrl) return;
    try {
      const resp = await fetch(corsUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify({ rules: corsRules })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to save');
      showMessage({ title: 'CORS rules saved', body: 'Configuration updated successfully.', variant: 'success' });
      renderCorsRules();
    } catch (err) {
      showMessage({ title: 'Save failed', body: err.message, variant: 'danger' });
    }
  };

  document.getElementById('addCorsRuleConfirm')?.addEventListener('click', async () => {
    const originsRaw = document.getElementById('corsAllowedOrigins')?.value?.trim() || '';
    const origins = originsRaw.split('\n').map(s => s.trim()).filter(Boolean);
    const methods = [];
    if (document.getElementById('corsMethodGet')?.checked) methods.push('GET');
    if (document.getElementById('corsMethodPut')?.checked) methods.push('PUT');
    if (document.getElementById('corsMethodPost')?.checked) methods.push('POST');
    if (document.getElementById('corsMethodDelete')?.checked) methods.push('DELETE');
    if (document.getElementById('corsMethodHead')?.checked) methods.push('HEAD');
    const headersRaw = document.getElementById('corsAllowedHeaders')?.value?.trim() || '';
    const headers = headersRaw.split('\n').map(s => s.trim()).filter(Boolean);
    const exposeRaw = document.getElementById('corsExposeHeaders')?.value?.trim() || '';
    const expose = exposeRaw.split('\n').map(s => s.trim()).filter(Boolean);
    const maxAge = parseInt(document.getElementById('corsMaxAge')?.value) || 0;
    if (origins.length === 0) { showMessage({ title: 'Validation error', body: 'At least one origin is required', variant: 'warning' }); return; }
    if (methods.length === 0) { showMessage({ title: 'Validation error', body: 'At least one method is required', variant: 'warning' }); return; }
    const rule = { AllowedOrigins: origins, AllowedMethods: methods };
    if (headers.length > 0) rule.AllowedHeaders = headers;
    if (expose.length > 0) rule.ExposeHeaders = expose;
    if (maxAge > 0) rule.MaxAgeSeconds = maxAge;
    if (typeof window.editingCorsIdx === 'number' && window.editingCorsIdx !== null) {
      corsRules[window.editingCorsIdx] = rule;
      window.editingCorsIdx = null;
    } else {
      corsRules.push(rule);
    }
    await saveCorsRules();
    addCorsRuleModal?.hide();
    document.getElementById('corsAllowedOrigins').value = '';
    document.getElementById('corsAllowedHeaders').value = '';
    document.getElementById('corsExposeHeaders').value = '';
    document.getElementById('corsMaxAge').value = '';
    document.getElementById('corsMethodGet').checked = false;
    document.getElementById('corsMethodPut').checked = false;
    document.getElementById('corsMethodPost').checked = false;
    document.getElementById('corsMethodDelete').checked = false;
    document.getElementById('corsMethodHead').checked = false;
  });

  const aclCard = document.getElementById('bucket-acl-card');
  const aclUrl = aclCard?.dataset.aclUrl;
  const aclOwnerEl = document.getElementById('acl-owner');
  const aclGrantsList = document.getElementById('acl-grants-list');
  const aclLoading = document.getElementById('acl-loading');
  const aclContent = document.getElementById('acl-content');
  const cannedAclSelect = document.getElementById('cannedAclSelect');

  const loadAcl = async () => {
    if (!aclUrl) return;
    try {
      const resp = await fetch(aclUrl);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to load ACL');
      if (aclOwnerEl) aclOwnerEl.textContent = data.owner || '-';
      if (aclGrantsList) {
        const grants = data.grants || [];
        if (grants.length === 0) {
          aclGrantsList.innerHTML = '<div class="list-group-item text-muted text-center py-2">No grants</div>';
        } else {
          aclGrantsList.innerHTML = grants.map(g => `<div class="list-group-item d-flex justify-content-between align-items-center"><code class="small">${escapeHtml(g.grantee)}</code><span class="badge bg-secondary">${escapeHtml(g.permission)}</span></div>`).join('');
        }
      }
      if (aclLoading) aclLoading.classList.add('d-none');
      if (aclContent) aclContent.classList.remove('d-none');
    } catch (err) {
      if (aclLoading) aclLoading.classList.add('d-none');
      if (aclContent) aclContent.classList.remove('d-none');
      if (aclGrantsList) aclGrantsList.innerHTML = `<div class="list-group-item text-danger text-center py-2">${escapeHtml(err.message)}</div>`;
    }
  };

  cannedAclSelect?.addEventListener('change', async () => {
    const canned = cannedAclSelect.value;
    if (!canned || !aclUrl) return;
    try {
      const resp = await fetch(aclUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify({ canned_acl: canned })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to set ACL');
      showMessage({ title: 'ACL updated', body: `Bucket ACL set to "${canned}"`, variant: 'success' });
      await loadAcl();
    } catch (err) {
      showMessage({ title: 'ACL update failed', body: err.message, variant: 'danger' });
    }
  });

  document.querySelectorAll('[data-set-acl]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const canned = btn.dataset.setAcl;
      if (!canned || !aclUrl) return;
      btn.disabled = true;
      const originalText = btn.innerHTML;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
      try {
        const resp = await fetch(aclUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
          body: JSON.stringify({ canned_acl: canned })
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.error || 'Failed to set ACL');
        showMessage({ title: 'ACL updated', body: `Bucket ACL set to "${canned}"`, variant: 'success' });
        await loadAcl();
      } catch (err) {
        showMessage({ title: 'ACL update failed', body: err.message, variant: 'danger' });
      } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
      }
    });
  });

  document.getElementById('objects-table')?.addEventListener('show.bs.dropdown', function (e) {
    const dropdown = e.target.closest('.dropdown');
    const menu = dropdown?.querySelector('.dropdown-menu');
    const btn = e.target;
    if (!menu || !btn) return;
    const btnRect = btn.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.top = (btnRect.bottom + 4) + 'px';
    menu.style.left = 'auto';
    menu.style.right = (window.innerWidth - btnRect.right) + 'px';
    menu.style.transform = 'none';
  });

  const previewTagsPanel = document.getElementById('preview-tags');
  const previewTagsList = document.getElementById('preview-tags-list');
  const previewTagsEmpty = document.getElementById('preview-tags-empty');
  const previewTagsCount = document.getElementById('preview-tags-count');
  const previewTagsEditor = document.getElementById('preview-tags-editor');
  const previewTagsInputs = document.getElementById('preview-tags-inputs');
  const editTagsButton = document.getElementById('editTagsButton');
  const addTagRow = document.getElementById('addTagRow');
  const saveTagsButton = document.getElementById('saveTagsButton');
  const cancelTagsButton = document.getElementById('cancelTagsButton');
  let currentObjectTags = [];
  let isEditingTags = false;

  const loadObjectTags = async (row) => {
    if (!row || !previewTagsPanel) return;
    const tagsUrl = row.dataset.tagsUrl;
    if (!tagsUrl) {
      previewTagsPanel.classList.add('d-none');
      return;
    }
    previewTagsPanel.classList.remove('d-none');
    try {
      const resp = await fetch(tagsUrl);
      const data = await resp.json();
      currentObjectTags = data.tags || [];
      renderObjectTags();
    } catch (err) {
      currentObjectTags = [];
      renderObjectTags();
    }
  };

  const renderObjectTags = () => {
    if (!previewTagsList || !previewTagsEmpty || !previewTagsCount) return;
    previewTagsCount.textContent = currentObjectTags.length;
    if (currentObjectTags.length === 0) {
      previewTagsList.innerHTML = '';
      previewTagsEmpty.classList.remove('d-none');
    } else {
      previewTagsEmpty.classList.add('d-none');
      previewTagsList.innerHTML = currentObjectTags.map(t => `<span class="badge bg-info-subtle text-info">${escapeHtml(t.Key)}=${escapeHtml(t.Value)}</span>`).join('');
    }
  };

  const renderTagEditor = () => {
    if (!previewTagsInputs) return;
    previewTagsInputs.innerHTML = currentObjectTags.map((t, idx) => `
      <div class="input-group input-group-sm mb-1">
        <input type="text" class="form-control" placeholder="Key" value="${escapeHtml(t.Key)}" data-tag-key="${idx}">
        <input type="text" class="form-control" placeholder="Value" value="${escapeHtml(t.Value)}" data-tag-value="${idx}">
        <button class="btn btn-outline-danger" type="button" onclick="removeTagRow(${idx})">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16"><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/></svg>
        </button>
      </div>
    `).join('');
  };

  window.removeTagRow = (idx) => {
    currentObjectTags.splice(idx, 1);
    renderTagEditor();
  };

  editTagsButton?.addEventListener('click', () => {
    isEditingTags = true;
    previewTagsList.classList.add('d-none');
    previewTagsEmpty.classList.add('d-none');
    previewTagsEditor?.classList.remove('d-none');
    renderTagEditor();
  });

  cancelTagsButton?.addEventListener('click', () => {
    isEditingTags = false;
    previewTagsEditor?.classList.add('d-none');
    previewTagsList.classList.remove('d-none');
    renderObjectTags();
  });

  addTagRow?.addEventListener('click', () => {
    if (currentObjectTags.length >= 10) {
      showMessage({ title: 'Limit reached', body: 'Maximum 10 tags allowed per object.', variant: 'warning' });
      return;
    }
    currentObjectTags.push({ Key: '', Value: '' });
    renderTagEditor();
  });

  saveTagsButton?.addEventListener('click', async () => {
    if (!activeRow) return;
    const tagsUrl = activeRow.dataset.tagsUrl;
    if (!tagsUrl) return;
    const inputs = previewTagsInputs?.querySelectorAll('.input-group');
    const newTags = [];
    inputs?.forEach((group, idx) => {
      const key = group.querySelector(`[data-tag-key="${idx}"]`)?.value?.trim() || '';
      const value = group.querySelector(`[data-tag-value="${idx}"]`)?.value?.trim() || '';
      if (key) newTags.push({ Key: key, Value: value });
    });
    try {
      const resp = await fetch(tagsUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify({ tags: newTags })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to save tags');
      currentObjectTags = newTags;
      isEditingTags = false;
      previewTagsEditor?.classList.add('d-none');
      previewTagsList.classList.remove('d-none');
      renderObjectTags();
      showMessage({ title: 'Tags saved', body: 'Object tags updated successfully.', variant: 'success' });
    } catch (err) {
      showMessage({ title: 'Save failed', body: err.message, variant: 'danger' });
    }
  });

  const copyMoveModalEl = document.getElementById('copyMoveModal');
  const copyMoveModal = copyMoveModalEl ? new bootstrap.Modal(copyMoveModalEl) : null;
  const copyMoveActionLabel = document.getElementById('copyMoveActionLabel');
  const copyMoveConfirmLabel = document.getElementById('copyMoveConfirmLabel');
  const copyMoveSource = document.getElementById('copyMoveSource');
  const copyMoveDestBucket = document.getElementById('copyMoveDestBucket');
  const copyMoveDestKey = document.getElementById('copyMoveDestKey');
  const copyMoveConfirm = document.getElementById('copyMoveConfirm');
  const bucketsForCopyUrl = objectsContainer?.dataset.bucketsForCopyUrl;
  let copyMoveAction = 'copy';
  let copyMoveSourceKey = '';

  window.openCopyMoveModal = async (action, key) => {
    copyMoveAction = action;
    copyMoveSourceKey = key;
    if (copyMoveActionLabel) copyMoveActionLabel.textContent = action === 'move' ? 'Move' : 'Copy';
    if (copyMoveConfirmLabel) copyMoveConfirmLabel.textContent = action === 'move' ? 'Move' : 'Copy';
    if (copyMoveSource) copyMoveSource.textContent = key;
    if (copyMoveDestKey) copyMoveDestKey.value = key;
    if (copyMoveDestBucket) {
      copyMoveDestBucket.innerHTML = '<option value="">Loading buckets...</option>';
      try {
        const resp = await fetch(bucketsForCopyUrl);
        const data = await resp.json();
        const buckets = data.buckets || [];
        copyMoveDestBucket.innerHTML = buckets.map(b => `<option value="${escapeHtml(b)}">${escapeHtml(b)}</option>`).join('');
      } catch {
        copyMoveDestBucket.innerHTML = '<option value="">Failed to load buckets</option>';
      }
    }
    copyMoveModal?.show();
  };

  copyMoveConfirm?.addEventListener('click', async () => {
    const destBucket = copyMoveDestBucket?.value;
    const destKey = copyMoveDestKey?.value?.trim();
    if (!destBucket || !destKey) { showMessage({ title: 'Validation error', body: 'Destination bucket and key are required', variant: 'warning' }); return; }
    const actionUrl = copyMoveAction === 'move'
      ? urlTemplates?.move?.replace('KEY_PLACEHOLDER', encodeURIComponent(copyMoveSourceKey).replace(/%2F/g, '/'))
      : urlTemplates?.copy?.replace('KEY_PLACEHOLDER', encodeURIComponent(copyMoveSourceKey).replace(/%2F/g, '/'));
    if (!actionUrl) { showMessage({ title: 'Error', body: 'Copy/move URL not configured', variant: 'danger' }); return; }
    try {
      const resp = await fetch(actionUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify({ dest_bucket: destBucket, dest_key: destKey })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || `Failed to ${copyMoveAction} object`);
      showMessage({ title: `Object ${copyMoveAction === 'move' ? 'moved' : 'copied'}`, body: `Successfully ${copyMoveAction === 'move' ? 'moved' : 'copied'} to ${destBucket}/${destKey}`, variant: 'success' });
      copyMoveModal?.hide();
      if (copyMoveAction === 'move') {
        previewEmpty.classList.remove('d-none');
        previewPanel.classList.add('d-none');
        activeRow = null;
        loadObjects(false);
      }
    } catch (err) {
      showMessage({ title: `${copyMoveAction === 'move' ? 'Move' : 'Copy'} failed`, body: err.message, variant: 'danger' });
    }
  });

  const originalSelectRow = selectRow;
  selectRow = (row) => {
    originalSelectRow(row);
    loadObjectTags(row);
  };

  if (lifecycleCard) loadLifecycleRules();

  const lifecycleHistoryCard = document.getElementById('lifecycle-history-card');
  const lifecycleHistoryBody = document.getElementById('lifecycle-history-body');
  const lifecycleHistoryPagination = document.getElementById('lifecycle-history-pagination');
  const showMoreHistoryBtn = document.getElementById('show-more-history');
  const historyShownCount = document.getElementById('history-shown-count');
  let historyExpanded = false;

  const loadLifecycleHistory = async () => {
    if (!lifecycleHistoryCard || !lifecycleHistoryBody) return;

    const endpoint = lifecycleHistoryCard.dataset.historyEndpoint;
    const limit = historyExpanded ? 50 : 5;

    lifecycleHistoryBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4"><div class="spinner-border spinner-border-sm me-2" role="status"></div>Loading...</td></tr>';

    try {
      const resp = await fetch(`${endpoint}?limit=${limit}`);
      if (!resp.ok) throw new Error('Failed to fetch history');
      const data = await resp.json();

      if (!data.enabled) {
        lifecycleHistoryBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Lifecycle enforcement is not enabled</td></tr>';
        return;
      }

      const executions = data.executions || [];
      const total = data.total || 0;

      if (executions.length === 0) {
        lifecycleHistoryBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">No executions recorded yet</td></tr>';
        lifecycleHistoryPagination.style.display = 'none';
        return;
      }

      lifecycleHistoryBody.innerHTML = executions.map(e => {
        const date = new Date(e.timestamp * 1000);
        const hasErrors = e.errors && e.errors.length > 0;
        const hasActivity = e.objects_deleted > 0 || e.versions_deleted > 0 || e.uploads_aborted > 0;
        let statusBadge;
        if (hasErrors) {
          statusBadge = '<span class="badge bg-danger">Errors</span>';
        } else if (hasActivity) {
          statusBadge = '<span class="badge bg-success">Success</span>';
        } else {
          statusBadge = '<span class="badge bg-secondary">No action</span>';
        }
        const errorTooltip = hasErrors ? ` title="${escapeHtml(e.errors.join('; '))}"` : '';
        return `<tr${errorTooltip}>
          <td class="small">${date.toLocaleString()}</td>
          <td class="text-center"><span class="badge bg-danger-subtle text-danger">${e.objects_deleted}</span></td>
          <td class="text-center"><span class="badge bg-warning-subtle text-warning">${e.versions_deleted}</span></td>
          <td class="text-center"><span class="badge bg-secondary">${e.uploads_aborted}</span></td>
          <td class="text-center">${statusBadge}</td>
        </tr>`;
      }).join('');

      if (total > 5 && !historyExpanded) {
        lifecycleHistoryPagination.style.display = '';
        historyShownCount.textContent = `Showing ${Math.min(5, total)} of ${total}`;
      } else {
        lifecycleHistoryPagination.style.display = 'none';
      }
    } catch (err) {
      console.error('Failed to load lifecycle history:', err);
      lifecycleHistoryBody.innerHTML = '<tr><td colspan="5" class="text-center text-danger py-4">Failed to load history</td></tr>';
    }
  };

  showMoreHistoryBtn?.addEventListener('click', () => {
    historyExpanded = !historyExpanded;
    showMoreHistoryBtn.textContent = historyExpanded ? 'Show less' : 'Show more...';
    loadLifecycleHistory();
  });

  if (lifecycleHistoryCard) {
    loadLifecycleHistory();
    if (window.pollingManager) {
      window.pollingManager.start('lifecycle', loadLifecycleHistory);
    }
  }

  if (corsCard) loadCorsRules();
  if (aclCard) loadAcl();

  function updateVersioningBadge(enabled) {
    var badge = document.querySelector('.badge.rounded-pill');
    if (!badge) return;
    badge.classList.remove('text-bg-success', 'text-bg-secondary');
    badge.classList.add(enabled ? 'text-bg-success' : 'text-bg-secondary');
    var icon = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
      '<path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2zm.995-14.901a1 1 0 1 0-1.99 0A5.002 5.002 0 0 0 3 6c0 1.098-.5 6-2 7h14c-1.5-1-2-5.902-2-7 0-2.42-1.72-4.44-4.005-4.901z"/>' +
      '</svg>';
    badge.innerHTML = icon + (enabled ? 'Versioning On' : 'Versioning Off');
    versioningEnabled = enabled;
  }

  function interceptForm(formId, options) {
    var form = document.getElementById(formId);
    if (!form) return;

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      window.UICore.submitFormAjax(form, {
        successMessage: options.successMessage || 'Operation completed',
        onSuccess: function (data) {
          if (options.onSuccess) options.onSuccess(data);
          if (options.closeModal) {
            var modal = bootstrap.Modal.getInstance(document.getElementById(options.closeModal));
            if (modal) modal.hide();
          }
          if (options.reload) {
            setTimeout(function () { location.reload(); }, 500);
          }
        }
      });
    });
  }

  function updateVersioningCard(enabled) {
    var card = document.getElementById('bucket-versioning-card');
    if (!card) return;
    var cardBody = card.querySelector('.card-body');
    if (!cardBody) return;

    var enabledHtml = '<div class="alert alert-success d-flex align-items-start mb-4" role="alert">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
      '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>' +
      '</svg><div><strong>Versioning is enabled</strong>' +
      '<p class="mb-0 small">All previous versions of objects are preserved. You can roll back accidental changes or deletions at any time.</p>' +
      '</div></div>' +
      '<button class="btn btn-outline-danger" type="button" data-bs-toggle="modal" data-bs-target="#suspendVersioningModal">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
      '<path d="M5.5 3.5A1.5 1.5 0 0 1 7 5v6a1.5 1.5 0 0 1-3 0V5a1.5 1.5 0 0 1 1.5-1.5zm5 0A1.5 1.5 0 0 1 12 5v6a1.5 1.5 0 0 1-3 0V5a1.5 1.5 0 0 1 1.5-1.5z"/>' +
      '</svg>Suspend Versioning</button>';

    var disabledHtml = '<div class="alert alert-secondary d-flex align-items-start mb-4" role="alert">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
      '<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>' +
      '<path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>' +
      '</svg><div><strong>Versioning is suspended</strong>' +
      '<p class="mb-0 small">New object uploads overwrite existing objects. Enable versioning to preserve previous versions.</p>' +
      '</div></div>' +
      '<form method="post" id="enableVersioningForm">' +
      '<input type="hidden" name="csrf_token" value="' + window.UICore.getCsrfToken() + '" />' +
      '<input type="hidden" name="state" value="enable" />' +
      '<button class="btn btn-success" type="submit">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
      '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>' +
      '</svg>Enable Versioning</button></form>';

    cardBody.innerHTML = enabled ? enabledHtml : disabledHtml;

    var archivedCardEl = document.getElementById('archived-objects-card');
    if (archivedCardEl) {
      archivedCardEl.style.display = enabled ? '' : 'none';
    }

    var dropZone = document.getElementById('objects-drop-zone');
    if (dropZone) {
      dropZone.setAttribute('data-versioning', enabled ? 'true' : 'false');
    }

    if (!enabled) {
      var newForm = document.getElementById('enableVersioningForm');
      if (newForm) {
        newForm.setAttribute('action', window.BucketDetailConfig?.endpoints?.versioning || '');
        newForm.addEventListener('submit', function (e) {
          e.preventDefault();
          window.UICore.submitFormAjax(newForm, {
            successMessage: 'Versioning enabled',
            onSuccess: function () {
              updateVersioningBadge(true);
              updateVersioningCard(true);
            }
          });
        });
      }
    }
  }

  function updateEncryptionCard(enabled, algorithm) {
    var encCard = document.getElementById('bucket-encryption-card');
    if (!encCard) return;
    var alertContainer = encCard.querySelector('.alert');
    if (alertContainer) {
      if (enabled) {
        alertContainer.className = 'alert alert-success d-flex align-items-start mb-4';
        var algoText = algorithm === 'aws:kms' ? 'KMS' : 'AES-256';
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.775 11.775 0 0 1-2.517 2.453 7.159 7.159 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7.158 7.158 0 0 1-1.048-.625 11.777 11.777 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 62.456 62.456 0 0 1 5.072.56z"/>' +
          '<path d="M9.5 6.5a1.5 1.5 0 0 1-1 1.415l.385 1.99a.5.5 0 0 1-.491.595h-.788a.5.5 0 0 1-.49-.595l.384-1.99a1.5 1.5 0 1 1 2-1.415z"/>' +
          '</svg><div><strong>Default encryption enabled (' + algoText + ')</strong>' +
          '<p class="mb-0 small">All new objects uploaded to this bucket will be automatically encrypted.</p></div>';
      } else {
        alertContainer.className = 'alert alert-secondary d-flex align-items-start mb-4';
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M11 1a2 2 0 0 0-2 2v4a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2h5V3a3 3 0 0 1 6 0v4a.5.5 0 0 1-1 0V3a2 2 0 0 0-2-2zM3 8a1 1 0 0 0-1 1v5a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V9a1 1 0 0 0-1-1H3z"/>' +
          '</svg><div><strong>Default encryption disabled</strong>' +
          '<p class="mb-0 small">Objects are stored without default encryption. You can enable server-side encryption below.</p></div>';
      }
    }
    var disableBtn = document.getElementById('disableEncryptionBtn');
    if (disableBtn) {
      disableBtn.style.display = enabled ? '' : 'none';
    }
  }

  function updateQuotaCard(hasQuota, maxBytes, maxObjects) {
    var quotaCard = document.getElementById('bucket-quota-card');
    if (!quotaCard) return;
    var alertContainer = quotaCard.querySelector('.alert');
    if (alertContainer) {
      if (hasQuota) {
        alertContainer.className = 'alert alert-info d-flex align-items-start mb-4';
        var quotaParts = [];
        if (maxBytes) quotaParts.push(formatBytes(maxBytes) + ' storage');
        if (maxObjects) quotaParts.push(maxObjects.toLocaleString() + ' objects');
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8 4a.905.905 0 0 0-.9.995l.35 3.507a.552.552 0 0 0 1.1 0l.35-3.507A.905.905 0 0 0 8 4zm.002 6a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"/>' +
          '</svg><div><strong>Storage quota active</strong>' +
          '<p class="mb-0 small">This bucket is limited to ' + quotaParts.join(' and ') + '.</p></div>';
      } else {
        alertContainer.className = 'alert alert-secondary d-flex align-items-start mb-4';
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>' +
          '<path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>' +
          '</svg><div><strong>No storage quota</strong>' +
          '<p class="mb-0 small">This bucket has no storage or object count limits. Set limits below to control usage.</p></div>';
      }
    }
    var removeBtn = document.getElementById('removeQuotaBtn');
    if (removeBtn) {
      removeBtn.style.display = hasQuota ? '' : 'none';
    }
    var maxMbInput = document.getElementById('max_mb');
    var maxObjInput = document.getElementById('max_objects');
    if (maxMbInput) maxMbInput.value = maxBytes ? Math.floor(maxBytes / 1048576) : '';
    if (maxObjInput) maxObjInput.value = maxObjects || '';
  }

  function updatePolicyCard(hasPolicy, preset) {
    var policyCard = document.querySelector('#permissions-pane .card');
    if (!policyCard) return;
    var alertContainer = policyCard.querySelector('.alert');
    if (alertContainer) {
      if (hasPolicy) {
        alertContainer.className = 'alert alert-info d-flex align-items-start mb-4';
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm.93-9.412-1 4.705c-.07.34.029.533.304.533.194 0 .487-.07.686-.246l-.088.416c-.287.346-.92.598-1.465.598-.703 0-1.002-.422-.808-1.319l.738-3.468c.064-.293.006-.399-.287-.47l-.451-.081.082-.381 2.29-.287zM8 5.5a1 1 0 1 1 0-2 1 1 0 0 1 0 2z"/>' +
          '</svg><div><strong>Policy attached</strong>' +
          '<p class="mb-0 small">A bucket policy is attached to this bucket. Access is granted via both IAM and bucket policy rules.</p></div>';
      } else {
        alertContainer.className = 'alert alert-secondary d-flex align-items-start mb-4';
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>' +
          '<path d="m8.93 6.588-2.29.287-.082.38.45.083c.294.07.352.176.288.469l-.738 3.468c-.194.897.105 1.319.808 1.319.545 0 1.178-.252 1.465-.598l.088-.416c-.2.176-.492.246-.686.246-.275 0-.375-.193-.304-.533L8.93 6.588zM9 4.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0z"/>' +
          '</svg><div><strong>IAM only</strong>' +
          '<p class="mb-0 small">No bucket policy is attached. Access is controlled by IAM policies only.</p></div>';
      }
    }
    document.querySelectorAll('.preset-btn').forEach(function (btn) {
      btn.classList.remove('active');
      if (btn.dataset.preset === preset) btn.classList.add('active');
    });
    var presetInputEl = document.getElementById('policyPreset');
    if (presetInputEl) presetInputEl.value = preset;
    var deletePolicyBtn = document.getElementById('deletePolicyBtn');
    if (deletePolicyBtn) {
      deletePolicyBtn.style.display = hasPolicy ? '' : 'none';
    }
  }

  interceptForm('enableVersioningForm', {
    successMessage: 'Versioning enabled',
    onSuccess: function (data) {
      updateVersioningBadge(true);
      updateVersioningCard(true);
    }
  });

  interceptForm('suspendVersioningForm', {
    successMessage: 'Versioning suspended',
    closeModal: 'suspendVersioningModal',
    onSuccess: function (data) {
      updateVersioningBadge(false);
      updateVersioningCard(false);
    }
  });

  interceptForm('encryptionForm', {
    successMessage: 'Encryption settings saved',
    onSuccess: function (data) {
      updateEncryptionCard(data.enabled !== false, data.algorithm || 'AES256');
    }
  });

  interceptForm('quotaForm', {
    successMessage: 'Quota settings saved',
    onSuccess: function (data) {
      updateQuotaCard(data.has_quota, data.max_bytes, data.max_objects);
    }
  });

  interceptForm('bucketPolicyForm', {
    successMessage: 'Bucket policy saved',
    onSuccess: function (data) {
      var policyModeEl = document.getElementById('policyMode');
      var policyPresetEl = document.getElementById('policyPreset');
      var preset = policyModeEl && policyModeEl.value === 'delete' ? 'private' :
        (policyPresetEl?.value || 'custom');
      updatePolicyCard(preset !== 'private', preset);
    }
  });

  var deletePolicyForm = document.getElementById('deletePolicyForm');
  if (deletePolicyForm) {
    deletePolicyForm.addEventListener('submit', function (e) {
      e.preventDefault();
      window.UICore.submitFormAjax(deletePolicyForm, {
        successMessage: 'Bucket policy deleted',
        onSuccess: function (data) {
          var modal = bootstrap.Modal.getInstance(document.getElementById('deletePolicyModal'));
          if (modal) modal.hide();
          updatePolicyCard(false, 'private');
          var policyTextarea = document.getElementById('policyDocument');
          if (policyTextarea) policyTextarea.value = '';
        }
      });
    });
  }

  var disableEncBtn = document.getElementById('disableEncryptionBtn');
  if (disableEncBtn) {
    disableEncBtn.addEventListener('click', function () {
      var form = document.getElementById('encryptionForm');
      if (!form) return;
      document.getElementById('encryptionAction').value = 'disable';
      window.UICore.submitFormAjax(form, {
        successMessage: 'Encryption disabled',
        onSuccess: function (data) {
          document.getElementById('encryptionAction').value = 'enable';
          updateEncryptionCard(false, null);
        }
      });
    });
  }

  var removeQuotaBtn = document.getElementById('removeQuotaBtn');
  if (removeQuotaBtn) {
    removeQuotaBtn.addEventListener('click', function () {
      var form = document.getElementById('quotaForm');
      if (!form) return;
      document.getElementById('quotaAction').value = 'remove';
      window.UICore.submitFormAjax(form, {
        successMessage: 'Quota removed',
        onSuccess: function (data) {
          document.getElementById('quotaAction').value = 'set';
          updateQuotaCard(false, null, null);
        }
      });
    });
  }

  function reloadReplicationPane() {
    var replicationPane = document.getElementById('replication-pane');
    if (!replicationPane) return;
    fetch(window.location.pathname + '?tab=replication', {
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
      .then(function (resp) { return resp.text(); })
      .then(function (html) {
        var parser = new DOMParser();
        var doc = parser.parseFromString(html, 'text/html');
        var newPane = doc.getElementById('replication-pane');
        if (newPane) {
          replicationPane.innerHTML = newPane.innerHTML;
          initReplicationForms();
          initReplicationStats();
        }
      })
      .catch(function (err) {
        console.error('Failed to reload replication pane:', err);
      });
  }

  function initReplicationForms() {
    document.querySelectorAll('form[action*="replication"]').forEach(function (form) {
      if (form.dataset.ajaxBound) return;
      form.dataset.ajaxBound = 'true';
      var actionInput = form.querySelector('input[name="action"]');
      if (!actionInput) return;
      var action = actionInput.value;

      form.addEventListener('submit', function (e) {
        e.preventDefault();
        var msg = action === 'pause' ? 'Replication paused' :
          action === 'resume' ? 'Replication resumed' :
            action === 'delete' ? 'Replication disabled' :
              action === 'create' ? 'Replication configured' : 'Operation completed';
        window.UICore.submitFormAjax(form, {
          successMessage: msg,
          onSuccess: function (data) {
            var modal = bootstrap.Modal.getInstance(document.getElementById('disableReplicationModal'));
            if (modal) modal.hide();
            reloadReplicationPane();
          }
        });
      });
    });
  }

  function initReplicationStats() {
    var statsContainer = document.getElementById('replication-stats-cards');
    if (!statsContainer) return;
    var statusEndpoint = statsContainer.dataset.statusEndpoint;
    if (!statusEndpoint) return;

    var syncedEl = statsContainer.querySelector('[data-stat="synced"]');
    var pendingEl = statsContainer.querySelector('[data-stat="pending"]');
    var orphanedEl = statsContainer.querySelector('[data-stat="orphaned"]');
    var bytesEl = statsContainer.querySelector('[data-stat="bytes"]');

    fetch(statusEndpoint)
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        if (syncedEl) syncedEl.textContent = data.objects_synced || 0;
        if (pendingEl) pendingEl.textContent = data.objects_pending || 0;
        if (orphanedEl) orphanedEl.textContent = data.objects_orphaned || 0;
        if (bytesEl) bytesEl.textContent = formatBytes(data.bytes_synced || 0);
      })
      .catch(function (err) {
        console.error('Failed to load replication stats:', err);
      });
  }

  initReplicationForms();
  initReplicationStats();

  var deleteBucketForm = document.getElementById('deleteBucketForm');
  if (deleteBucketForm) {
    deleteBucketForm.addEventListener('submit', function (e) {
      e.preventDefault();
      window.UICore.submitFormAjax(deleteBucketForm, {
        onSuccess: function () {
          sessionStorage.setItem('flashMessage', JSON.stringify({ title: 'Bucket deleted', variant: 'success' }));
          window.location.href = window.BucketDetailConfig?.endpoints?.bucketsOverview || '/ui/buckets';
        }
      });
    });
  }

  window.BucketDetailConfig = window.BucketDetailConfig || {};

})();
