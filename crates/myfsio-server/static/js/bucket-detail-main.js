(function () {
  'use strict';

  const formatBytes = window.MyFSIO.formatBytes;
  const { escapeHtml, fallbackCopy, setupJsonAutoIndent } = window.BucketDetailUtils || {
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

  const fileTypeBadge = (key) => {
    const name = key.split('/').pop() || '';
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 ? name.slice(dot + 1) : '';
    const label = ext && ext.length <= 4 && /^[a-z0-9]+$/i.test(ext) ? ext.toUpperCase() : 'FILE';
    return `<span class="ui-fileicon" aria-hidden="true">${escapeHtml(label)}</span>`;
  };

  const selectAllCheckbox = document.querySelector('[data-select-all]');
  const bulkDeleteButton = document.querySelector('[data-bulk-delete-trigger]');
  const bulkDeleteLabel = bulkDeleteButton?.querySelector('[data-bulk-delete-label]');
  const bulkDeleteModalEl = document.getElementById('bulkDeleteModal');
  const dialogHandle = (el) => (el ? { show: () => window.UI.dialog.open(el), hide: () => window.UI.dialog.close(el) } : null);
  const bulkDeleteModal = dialogHandle(bulkDeleteModalEl);
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
  const previewPlaceholderDefault = previewPlaceholder ? previewPlaceholder.innerHTML : '';
  const previewErrorAlert = document.getElementById('preview-error-alert');
  const previewDetailsMeta = document.getElementById('preview-details-meta');
  const previewImage = document.getElementById('preview-image');
  const previewVideo = document.getElementById('preview-video');
  const previewAudio = document.getElementById('preview-audio');
  const previewText = document.getElementById('preview-text');
  const previewIframe = document.getElementById('preview-iframe');
  const previewStage = previewPlaceholder ? previewPlaceholder.closest('.preview-stage') : document.querySelector('.preview-stage');
  const setAudioStage = (active) => {
    if (previewStage) previewStage.classList.toggle('preview-stage-audio', !!active);
  };
  const downloadButton = document.getElementById('downloadButton');
  const presignButton = document.getElementById('presignButton');
  const presignModalEl = document.getElementById('presignModal');
  const presignModal = dialogHandle(presignModalEl);
  const presignMethod = document.getElementById('presignMethod');
  const presignExpiryPreset = document.getElementById('presignExpiryPreset');
  const presignCustomExpiry = document.getElementById('presignCustomExpiry');
  const presignTtl = document.getElementById('presignTtl');
  const presignTtlFeedback = document.getElementById('presignTtlFeedback');
  const presignClampNote = document.getElementById('presignClampNote');
  const presignLink = document.getElementById('presignLink');
  const copyPresignLink = document.getElementById('copyPresignLink');
  const copyPresignDefaultLabel = copyPresignLink?.textContent?.trim() || 'Copy';
  const generatePresignButton = document.getElementById('generatePresignButton');
  const policyForm = document.getElementById('bucketPolicyForm');
  const policyTextarea = document.getElementById('policyDocument');
  const policyPreset = document.getElementById('policyPreset');
  const policyMode = document.getElementById('policyMode');
  const messageModalEl = document.getElementById('messageModal');
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
  let archivedCard = document.getElementById('archived-objects-card');
  let archivedBody = archivedCard?.querySelector('[data-archived-body]');
  let archivedCountBadge = archivedCard?.querySelector('[data-archived-count]');
  let archivedRefreshButton = archivedCard?.querySelector('[data-archived-refresh]');
  let archivedEndpoint = archivedCard?.dataset.archivedEndpoint;
  let archivedObjectsChip = document.getElementById('archived-objects-chip');
  let archivedItemsCache = null;
  let archivedLoadPromise = null;
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
  let currentSortField = 'name';
  let currentSortDir = 'asc';
  let pageSize = 5000;
  const normalizeFolderPrefix = (raw) => {
    let p = (raw || '').replace(/^\/+/, '');
    if (p && !p.endsWith('/')) p += '/';
    return p;
  };
  const folderUrl = (prefix) => {
    const url = new URL(window.location.href);
    if (prefix) {
      url.searchParams.set('prefix', prefix);
    } else {
      url.searchParams.delete('prefix');
    }
    return url.pathname + url.search + url.hash;
  };
  const syncPrefixToUrl = (prefix) => {
    const target = folderUrl(prefix);
    const current = window.location.pathname + window.location.search + window.location.hash;
    if (target === current) return;
    history.pushState({ objectPrefix: prefix }, '', target);
  };
  let currentPrefix = normalizeFolderPrefix(new URLSearchParams(window.location.search).get('prefix'));
  let allObjects = [];
  let streamFolders = [];
  let useDelimiterMode = true;
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

  let ROW_HEIGHT = 53;
  let rowHeightMeasured = false;
  const BUFFER_ROWS = 10;
  let visibleItems = [];
  let renderedRange = { start: 0, end: 0 };

  let memoizedVisibleItems = null;
  let memoizedInputs = { objectCount: -1, folderCount: -1, prefix: null, filterTerm: null };

  const createObjectRow = (obj, displayKey = null) => {
    const tr = document.createElement('tr');
    tr.dataset.objectRow = '';
    tr.dataset.key = obj.key;
    tr.dataset.size = obj.size;
    tr.dataset.lastModified = obj.lastModified ?? obj.last_modified ?? '';
    tr.dataset.lastModifiedDisplay = obj.lastModifiedDisplay ?? obj.last_modified_display ?? obj.lastModified ?? obj.last_modified ?? '';
    tr.dataset.lastModifiedIso = obj.lastModifiedIso ?? obj.last_modified_iso ?? obj.lastModified ?? obj.last_modified ?? '';
    tr.dataset.etag = obj.etag ?? '';
    tr.dataset.previewUrl = obj.previewUrl ?? obj.preview_url ?? '';
    tr.dataset.downloadUrl = obj.downloadUrl ?? obj.download_url ?? '';
    tr.dataset.presignEndpoint = obj.presignEndpoint ?? obj.presign_endpoint ?? '';
    tr.dataset.deleteEndpoint = obj.deleteEndpoint ?? obj.delete_endpoint ?? '';
    tr.dataset.metadataUrl = obj.metadataUrl ?? obj.metadata_url ?? '';
    tr.dataset.versionsEndpoint = obj.versionsEndpoint ?? obj.versions_endpoint ?? '';
    tr.dataset.restoreTemplate = obj.restoreTemplate ?? obj.restore_template ?? '';
    tr.dataset.tagsUrl = obj.tagsUrl ?? obj.tags_url ?? '';
    tr.dataset.copyUrl = obj.copyUrl ?? obj.copy_url ?? '';
    tr.dataset.moveUrl = obj.moveUrl ?? obj.move_url ?? '';

    const keyToShow = displayKey || obj.key;
    const lastModDisplay = obj.lastModifiedDisplay || obj.last_modified_display || obj.lastModified || obj.last_modified || '';

    tr.innerHTML = `
      <td class="ob-col-check">
        <input type="checkbox" data-object-select aria-label="Select ${escapeHtml(obj.key)}" />
      </td>
      <td class="object-key" title="${escapeHtml(obj.key)}">
        <div class="ui-name">
          ${fileTypeBadge(obj.key)}
          <span class="ob-name">
            <span>${escapeHtml(keyToShow)}</span>
            <span class="ob-name-sub ui-show-m">${escapeHtml(lastModDisplay)}</span>
          </span>
        </div>
      </td>
      <td class="is-num ob-col-size">${formatBytes(obj.size)}</td>
      <td class="ui-muted ob-col-date ui-hide-m">${escapeHtml(lastModDisplay)}</td>
      <td class="ob-col-actions">
        <button class="icon-btn" type="button" data-row-menu aria-haspopup="menu" aria-label="Actions for ${escapeHtml(obj.key)}">
          <svg class="ic" aria-hidden="true"><use href="#i-more"/></svg>
        </button>
      </td>
    `;

    return tr;
  };

  const showEmptyState = () => {
    if (!objectsTableBody) return;
    objectsTableBody.innerHTML = `
      <tr>
        <td colspan="5">
          <div class="ui-empty">
            <svg class="ic" aria-hidden="true"><use href="#i-upload"/></svg>
            <h2>No objects yet</h2>
            <p>Drag and drop files here or use Upload to get started.</p>
            <button class="ui-btn ui-btn-primary" type="button" data-ui-open="#uploadModal">
              <svg class="ic" aria-hidden="true"><use href="#i-upload"/></svg>
              Upload files
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
        <td colspan="5">
          <div class="ui-empty">
            <h2>Failed to load objects</h2>
            <p>${escapeHtml(message)}</p>
            <button class="ui-btn" type="button" onclick="loadObjects()">Retry</button>
          </div>
        </td>
      </tr>
    `;
  };

  let bucketTotalObjects = objectsContainer ? parseInt(objectsContainer.dataset.bucketTotalObjects || '0', 10) : 0;

  const updateObjectCountBadge = () => {
    if (!objectCountBadge) return;
    if (useDelimiterMode) {
      const total = Number.isFinite(bucketTotalObjects) ? bucketTotalObjects : totalObjectCount;
      objectCountBadge.textContent = `${total.toLocaleString()} object${total !== 1 ? 's' : ''}`;
    } else {
      objectCountBadge.textContent = `${totalObjectCount.toLocaleString()} object${totalObjectCount !== 1 ? 's' : ''}`;
    }
  };

  const renderObjectsLimit = (totalObjects, maxObjects) => {
    if (maxObjects && maxObjects > 0) {
      const pct = Math.min(100, Math.floor(totalObjects / maxObjects * 100));
      const cls = pct >= 90 ? 'bg-danger' : pct >= 75 ? 'bg-warning' : 'bg-success';
      return '<div class="progress mt-2" style="height: 4px;">' +
        '<div class="progress-bar ' + cls + '" style="width: ' + pct + '%"></div>' +
        '</div>' +
        '<div class="small text-muted mt-1">' + pct + '% of ' + maxObjects.toLocaleString() + ' stored-copy limit</div>';
    }
    return '<div class="small text-muted mt-2">No stored-copy limit</div>';
  };

  const renderBytesLimit = (totalBytes, maxBytes) => {
    if (maxBytes && maxBytes > 0) {
      const pct = Math.min(100, Math.floor(totalBytes / maxBytes * 100));
      const cls = pct >= 90 ? 'bg-danger' : pct >= 75 ? 'bg-warning' : 'bg-success';
      return '<div class="progress mt-2" style="height: 4px;">' +
        '<div class="progress-bar ' + cls + '" style="width: ' + pct + '%"></div>' +
        '</div>' +
        '<div class="small text-muted mt-1">' + pct + '% of ' + formatBytes(maxBytes) + ' limit</div>';
    }
    return '<div class="small text-muted mt-2">No limit</div>';
  };

  const redrawUsageLimits = () => {
    const objectsCard = document.querySelector('[data-usage-objects]');
    const objectsLimit = document.querySelector('[data-usage-objects-limit]');
    if (objectsCard && objectsLimit) {
      const totalObjects = parseInt(objectsCard.dataset.totalObjects || '0', 10);
      const maxObjectsRaw = objectsCard.dataset.maxObjects;
      const maxObjects = maxObjectsRaw ? parseInt(maxObjectsRaw, 10) : 0;
      objectsLimit.innerHTML = renderObjectsLimit(totalObjects, maxObjects);
    }
    const bytesCard = document.querySelector('[data-usage-bytes]');
    const bytesLimit = document.querySelector('[data-usage-bytes-limit]');
    if (bytesCard && bytesLimit) {
      const totalBytes = parseInt(bytesCard.dataset.totalBytes || '0', 10);
      const maxBytesRaw = bytesCard.dataset.maxBytes;
      const maxBytes = maxBytesRaw ? parseInt(maxBytesRaw, 10) : 0;
      bytesLimit.innerHTML = renderBytesLimit(totalBytes, maxBytes);
    }
  };

  const refreshBucketUsage = async () => {
    try {
      const bucketName = objectsContainer?.dataset.bucket;
      if (!bucketName) return;
      const url = `/ui/buckets/${encodeURIComponent(bucketName)}/stats`;
      const response = await fetch(url, { headers: { 'Accept': 'application/json' } });
      if (!response.ok) return;
      const data = await response.json();

      const objectsCard = document.querySelector('[data-usage-objects]');
      const objectsValue = document.querySelector('[data-usage-objects-value]');
      if (objectsCard) objectsCard.dataset.totalObjects = String(data.total_objects);
      if (objectsValue) objectsValue.textContent = data.objects.toLocaleString();
      const versionsValue = document.querySelector('[data-usage-versions-value]');
      if (versionsValue) versionsValue.textContent = data.version_count.toLocaleString();
      bucketTotalObjects = data.objects;
      if (objectsContainer) objectsContainer.dataset.bucketTotalObjects = String(data.objects);
      updateObjectCountBadge();

      const bytesCard = document.querySelector('[data-usage-bytes]');
      const bytesValue = document.querySelector('[data-usage-bytes-value]');
      if (bytesCard) bytesCard.dataset.totalBytes = String(data.total_bytes);
      if (bytesValue) bytesValue.textContent = formatBytes(data.total_bytes);

      redrawUsageLimits();
    } catch (e) { }
  };

  let topSpacer = null;
  let bottomSpacer = null;

  const initVirtualScrollElements = () => {
    if (!objectsTableBody) return;

    if (!topSpacer) {
      topSpacer = document.createElement('tr');
      topSpacer.id = 'virtual-top-spacer';
      topSpacer.innerHTML = '<td colspan="5" style="padding: 0; border: none;"></td>';
    }
    if (!bottomSpacer) {
      bottomSpacer = document.createElement('tr');
      bottomSpacer.id = 'virtual-bottom-spacer';
      bottomSpacer.innerHTML = '<td colspan="5" style="padding: 0; border: none;"></td>';
    }
  };

  const computeVisibleItems = (forceRecompute = false) => {
    const currentInputs = {
      objectCount: allObjects.length,
      folderCount: streamFolders.length,
      prefix: currentPrefix,
      filterTerm: currentFilterTerm,
      sortField: currentSortField,
      sortDir: currentSortDir
    };

    if (!forceRecompute &&
        memoizedVisibleItems !== null &&
        memoizedInputs.objectCount === currentInputs.objectCount &&
        memoizedInputs.folderCount === currentInputs.folderCount &&
        memoizedInputs.prefix === currentInputs.prefix &&
        memoizedInputs.filterTerm === currentInputs.filterTerm &&
        memoizedInputs.sortField === currentInputs.sortField &&
        memoizedInputs.sortDir === currentInputs.sortDir) {
      return memoizedVisibleItems;
    }

    const items = [];

    if (searchResults !== null) {
      searchResults.forEach(obj => {
        items.push({ type: 'file', data: obj, displayKey: obj.key });
      });
    } else if (useDelimiterMode && streamFolders.length > 0) {
      streamFolders.forEach(folderPath => {
        const folderName = folderPath.slice(currentPrefix.length).replace(/\/$/, '');
        items.push({ type: 'folder', path: folderPath, displayKey: folderName });
      });
      allObjects.forEach(obj => {
        const remainder = obj.key.slice(currentPrefix.length);
        if (!remainder) return;
        items.push({ type: 'file', data: obj, displayKey: remainder });
      });
    } else {
      const folders = new Set();

      allObjects.forEach(obj => {
        if (!obj.key.startsWith(currentPrefix)) return;

        const remainder = obj.key.slice(currentPrefix.length);

        if (!remainder) return;

        const isFolderMarker = obj.key.endsWith('/') && obj.size === 0;
        const slashIndex = remainder.indexOf('/');

        if (slashIndex === -1 && !isFolderMarker) {
          items.push({ type: 'file', data: obj, displayKey: remainder });
        } else {
          const effectiveSlashIndex = isFolderMarker && slashIndex === remainder.length - 1
            ? slashIndex
            : (slashIndex === -1 ? remainder.length - 1 : slashIndex);
          const folderName = remainder.slice(0, effectiveSlashIndex);
          const folderPath = currentPrefix + folderName + '/';
          if (!folders.has(folderPath)) {
            folders.add(folderPath);
            items.push({ type: 'folder', path: folderPath, displayKey: folderName });
          }
        }
      });
    }

    items.sort((a, b) => {
      if (a.type === 'folder' && b.type === 'file') return -1;
      if (a.type === 'file' && b.type === 'folder') return 1;
      if (a.type === 'folder' && b.type === 'folder') {
        return a.path.localeCompare(b.path);
      }
      const dir = currentSortDir === 'asc' ? 1 : -1;
      if (currentSortField === 'size') {
        return (a.data.size - b.data.size) * dir;
      }
      if (currentSortField === 'date') {
        const aTime = new Date(a.data.lastModified || a.data.last_modified || 0).getTime();
        const bTime = new Date(b.data.lastModified || b.data.last_modified || 0).getTime();
        return (aTime - bTime) * dir;
      }
      return a.data.key.localeCompare(b.data.key) * dir;
    });

    memoizedVisibleItems = items;
    memoizedInputs = currentInputs;
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

    if (!rowHeightMeasured) {
      const firstRow = objectsTableBody.querySelector('[data-virtual-index]');
      const measured = firstRow?.getBoundingClientRect().height;
      if (measured) {
        rowHeightMeasured = true;
        if (Math.abs(measured - ROW_HEIGHT) > 1) {
          ROW_HEIGHT = measured;
          renderedRange = { start: -1, end: -1 };
          renderVirtualRows();
        }
      }
    }
  };

  let scrollTimeout = null;
  const handleVirtualScroll = () => {
    if (scrollTimeout) cancelAnimationFrame(scrollTimeout);
    scrollTimeout = requestAnimationFrame(() => {
      renderVirtualRows();
      const c = document.querySelector('.objects-table-container');
      if (c && c.scrollHeight - c.scrollTop - c.clientHeight < 500) {
        if (typeof loadMoreOnSentinel === 'function') loadMoreOnSentinel();
      }
    });
  };

  const refreshVirtualList = () => {
    visibleItems = computeVisibleItems();
    renderedRange = { start: -1, end: -1 };

    if (visibleItems.length === 0) {
      if (allObjects.length === 0 && streamFolders.length === 0 && !hasMoreObjects) {
        showEmptyState();
      } else {
        const isFiltering = currentFilterTerm && currentFilterTerm.length > 0;
        const title = isFiltering ? 'No matches' : 'Empty folder';
        const body = isFiltering
          ? `No objects match "${escapeHtml(currentFilterTerm)}".`
          : `This folder contains no objects${hasMoreObjects ? ' yet. Loading more...' : '.'}`;
        objectsTableBody.innerHTML = `
          <tr>
            <td colspan="5">
              <div class="ui-empty">
            <svg class="ic" aria-hidden="true"><use href="#i-folder"/></svg>
            <h2>${title}</h2>
            <p>${body}</p>
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
    folderViewStatusEl.classList.add('is-hidden');
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
      metadataUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.metadata, key) : '',
      versionsEndpoint: urlTemplates ? buildUrlFromTemplate(urlTemplates.versions, key) : '',
      restoreTemplate: urlTemplates ? urlTemplates.restore.replace('KEY_PLACEHOLDER', encodeURIComponent(key).replace(/%2F/g, '/')) : '',
      tagsUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.tags, key) : '',
      copyUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.copy, key) : '',
      moveUrl: urlTemplates ? buildUrlFromTemplate(urlTemplates.move, key) : ''
    };
  };

  let lastStreamRenderTime = 0;
  const STREAM_RENDER_THROTTLE_MS = 500;

  const buildBottomStatusText = (complete) => {
    if (!complete) {
      const countText = totalObjectCount > 0 ? ` of ${totalObjectCount.toLocaleString()}` : '';
      return `${loadedObjectCount.toLocaleString()}${countText} loading...`;
    }
    const parts = [];
    if (useDelimiterMode && streamFolders.length > 0) {
      parts.push(`${streamFolders.length.toLocaleString()} folder${streamFolders.length !== 1 ? 's' : ''}`);
    }
    parts.push(`${loadedObjectCount.toLocaleString()} object${loadedObjectCount !== 1 ? 's' : ''}`);
    return parts.join(', ');
  };

  const flushPendingStreamObjects = () => {
    if (pendingStreamObjects.length > 0) {
      const batch = pendingStreamObjects.splice(0, pendingStreamObjects.length);
      batch.forEach(obj => {
        loadedObjectCount++;
        allObjects.push(obj);
      });
    }
    updateObjectCountBadge();
    if (loadMoreStatus) {
      loadMoreStatus.textContent = buildBottomStatusText(streamingComplete);
    }
    if (objectsLoadingRow && objectsLoadingRow.parentNode) {
      const loadingText = objectsLoadingRow.querySelector('p');
      if (loadingText) {
        const countText = totalObjectCount > 0 ? ` of ${totalObjectCount.toLocaleString()}` : '';
        loadingText.textContent = `Loading ${loadedObjectCount.toLocaleString()}${countText} objects...`;
      }
    }
    const now = performance.now();
    if (!streamingComplete && now - lastStreamRenderTime < STREAM_RENDER_THROTTLE_MS) {
      streamRenderScheduled = false;
      return;
    }
    lastStreamRenderTime = now;
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
    streamFolders = [];
    memoizedVisibleItems = null;
    memoizedInputs = { objectCount: -1, folderCount: -1, prefix: null, filterTerm: null };
    pendingStreamObjects = [];
    lastStreamRenderTime = 0;

    streamAbortController = new AbortController();

    try {
      const params = new URLSearchParams();
      if (currentPrefix) params.set('prefix', currentPrefix);
      if (useDelimiterMode) params.set('delimiter', '/');

      const response = await fetch(`${objectsStreamUrl}?${params}`, {
        signal: streamAbortController.signal
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      if (objectsLoadingRow) {
        const loadingText = objectsLoadingRow.querySelector('p');
        if (loadingText) loadingText.textContent = 'Receiving objects...';
      }

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
                if (!currentPrefix) {
                  bucketTotalObjects = totalObjectCount;
                  updateObjectCountBadge();
                }
                if (objectsLoadingRow) {
                  const loadingText = objectsLoadingRow.querySelector('p');
                  if (loadingText) loadingText.textContent = `Loading 0 of ${totalObjectCount.toLocaleString()} objects...`;
                }
                break;
              case 'folder':
                streamFolders.push(msg.prefix);
                scheduleStreamRender();
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

      streamingComplete = true;
      flushPendingStreamObjects();
      hasMoreObjects = false;
      totalObjectCount = loadedObjectCount;
      if (!currentPrefix && !useDelimiterMode) bucketTotalObjects = totalObjectCount;
      updateObjectCountBadge();

      if (objectsLoadingRow && objectsLoadingRow.parentNode) {
        objectsLoadingRow.remove();
      }

      if (loadMoreStatus) {
        loadMoreStatus.textContent = buildBottomStatusText(true);
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
      streamFolders = [];
      memoizedVisibleItems = null;
      memoizedInputs = { objectCount: -1, folderCount: -1, prefix: null, filterTerm: null };
    }

    if (append && loadMoreSpinner) {
      loadMoreSpinner.classList.remove('is-hidden');
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
      if (!append && !currentPrefix) bucketTotalObjects = totalObjectCount;
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
        loadMoreSpinner.classList.add('is-hidden');
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

      const selectCheckbox = row.querySelector('[data-object-select]');
      selectCheckbox?.addEventListener('click', (event) => event.stopPropagation());
      selectCheckbox?.addEventListener('change', () => {
        toggleRowSelection(row, selectCheckbox.checked);
      });

      if (selectedRows.has(row.dataset.key)) {
        selectCheckbox.checked = true;
        row.classList.add('is-selected');
      }

      if (activeRow && activeRow.dataset.key === row.dataset.key) {
        row.classList.add('is-selected');
        activeRow = row;
      }
    });

    const folderRows = document.querySelectorAll('.folder-row');
    folderRows.forEach(row => {
      if (row.dataset.handlersAttached) return;
      row.dataset.handlersAttached = 'true';

      const folderPath = row.dataset.folderPath;

      const checkbox = row.querySelector('[data-folder-select]');
      if (checkbox && selectedRows.has(folderPath)) {
        checkbox.checked = true;
      }
      checkbox?.addEventListener('change', (e) => {
        e.stopPropagation();
        if (checkbox.checked) {
          selectedRows.set(folderPath, { key: folderPath, isFolder: true });
        } else {
          selectedRows.delete(folderPath);
        }
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
        if (e.target.closest('[data-folder-select]') || e.target.closest('button') || e.target.closest('[data-folder-link]')) return;
        navigateToFolder(folderPath);
      });

      const folderLink = row.querySelector('[data-folder-link]');
      folderLink?.addEventListener('click', (e) => {
        if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button !== 0) return;
        e.preventDefault();
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

  const isSentinelVisible = () => {
    if (!scrollSentinel) return false;
    const rect = scrollSentinel.getBoundingClientRect();
    if (scrollContainer) {
      const cr = scrollContainer.getBoundingClientRect();
      return rect.top <= cr.bottom + 500 && rect.bottom >= cr.top - 500;
    }
    return rect.top <= window.innerHeight + 500 && rect.bottom >= -500;
  };

  const loadMoreOnSentinel = () => {
    if (searchResults !== null) {
      if (searchNextToken && !searchLoading) {
        performServerSearch(currentFilterTerm, true);
      }
      return;
    }
    if (hasMoreObjects && !isLoadingObjects) {
      loadObjects(true);
    }
  };

  if (scrollSentinel && scrollContainer) {
    const containerObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) loadMoreOnSentinel();
      });
    }, {
      root: scrollContainer,
      rootMargin: '500px',
      threshold: 0
    });
    containerObserver.observe(scrollSentinel);

    const viewportObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) loadMoreOnSentinel();
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

      const menuButton = e.target.closest('[data-row-menu]');
      if (menuButton) {
        rowMenuTarget = row;
        window.UI.menu.open('#objectRowMenu', menuButton);
        return;
      }

      if (e.target.closest('[data-object-select]') || e.target.closest('a')) {
        return;
      }

      selectRow(row);
    });
  }

  let rowMenuTarget = null;

  const openDeleteObjectDialog = (row) => {
    const deleteModalEl = document.getElementById('deleteObjectModal');
    const deleteModal = dialogHandle(deleteModalEl);
    const deleteObjectForm = document.getElementById('deleteObjectForm');
    const deleteObjectKey = document.getElementById('deleteObjectKey');
    if (deleteModal && deleteObjectForm) {
      deleteObjectForm.setAttribute('action', row.dataset.deleteEndpoint);
      if (deleteObjectKey) deleteObjectKey.textContent = row.dataset.key;
      deleteModal.show();
    }
  };

  const runObjectAction = (action, row) => {
    if (!row || !row.dataset.key) return;
    if (action === 'details') {
      selectRow(row);
    } else if (action === 'download') {
      if (row.dataset.downloadUrl) window.open(row.dataset.downloadUrl, '_blank', 'noopener');
    } else if (action === 'share') {
      selectRow(row);
      presignButton?.click();
    } else if (action === 'copy' || action === 'move') {
      window.openCopyMoveModal(action, row.dataset.key);
    } else if (action === 'delete') {
      openDeleteObjectDialog(row);
    }
  };

  document.getElementById('objectRowMenu')?.addEventListener('click', (e) => {
    const item = e.target.closest('[data-row-action]');
    if (!item) return;
    runObjectAction(item.dataset.rowAction, rowMenuTarget);
  });

  const closeObjectDrawer = () => {
    document.querySelectorAll('[data-object-row]').forEach((r) => r.classList.remove('is-selected'));
    if (previewPanel) previewPanel.classList.add('is-hidden');
    if (previewEmpty) previewEmpty.classList.remove('is-hidden');
    activeRow = null;
  };

  document.getElementById('objectDrawerClose')?.addEventListener('click', closeObjectDrawer);

  document.querySelectorAll('[data-drawer-action]').forEach((button) => {
    button.addEventListener('click', () => runObjectAction(button.dataset.drawerAction, activeRow));
  });

  document.getElementById('bulk-selection-clear')?.addEventListener('click', () => {
    selectedRows.clear();
    document.querySelectorAll('[data-object-select], [data-folder-select]').forEach((checkbox) => {
      checkbox.checked = false;
    });
    updateBulkDeleteState();
  });

  document.getElementById('filter-warning-dismiss')?.addEventListener('click', () => {
    document.getElementById('filter-warning')?.classList.add('is-hidden');
  });

  const hasFolders = () => streamFolders.length > 0 || allObjects.some(obj => obj.key.includes('/'));

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
    if (useDelimiterMode) {
      return { count: 0, mayHaveMore: true };
    }
    const count = allObjects.filter(obj => obj.key.startsWith(folderPrefix)).length;
    return { count, mayHaveMore: hasMoreObjects };
  };

  const renderBreadcrumb = (prefix) => {
    if (!folderBreadcrumb) return;
    const ol = folderBreadcrumb.querySelector('ol');
    if (!ol) return;
    ol.innerHTML = '';
    const rootLabel = objectsContainer?.dataset.bucket || 'Root';
    const parts = (prefix || '').split('/').filter(Boolean);

    const appendCrumb = (label, target, isCurrent) => {
      const li = document.createElement('li');
      if (isCurrent) {
        li.setAttribute('aria-current', 'page');
        li.textContent = label;
      } else {
        const a = document.createElement('a');
        a.href = folderUrl(target);
        a.dataset.folderNav = target;
        a.textContent = label;
        a.addEventListener('click', (e) => {
          if (e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return;
          e.preventDefault();
          navigateToFolder(target);
        });
        li.appendChild(a);
      }
      ol.appendChild(li);
    };

    appendCrumb(rootLabel, '', parts.length === 0);
    let accumulated = '';
    parts.forEach((part, index) => {
      accumulated += part + '/';
      appendCrumb(part, accumulated, index === parts.length - 1);
    });
  };

  const createFolderRow = (folderPath, displayName = null) => {
    const folderName = displayName || folderPath.slice(currentPrefix.length).replace(/\/$/, '');
    const { count: objectCount, mayHaveMore } = countObjectsInFolder(folderPath);
    let countLine = '';
    if (useDelimiterMode) {
      countLine = '';
    } else {
      const countDisplay = mayHaveMore ? `${objectCount}+` : objectCount;
      countLine = `<span class="ob-name-sub">${countDisplay} object${objectCount !== 1 ? 's' : ''}</span>`;
    }

    const tr = document.createElement('tr');
    tr.className = 'folder-row';
    tr.dataset.folderPath = folderPath;
    tr.style.cursor = 'pointer';

    tr.innerHTML = `
      <td class="ob-col-check" onclick="event.stopPropagation();">
        <input type="checkbox" data-folder-select="${escapeHtml(folderPath)}" aria-label="Select folder ${escapeHtml(folderName)}" />
      </td>
      <td class="object-key">
        <div class="ui-name">
          <span class="ui-fileicon is-accent" aria-hidden="true"><svg class="ic"><use href="#i-folder"/></svg></span>
          <span class="ob-name">
            <a href="${escapeHtml(folderUrl(folderPath))}" data-folder-link>${escapeHtml(folderName)}/</a>
            ${countLine}
          </span>
        </div>
      </td>
      <td class="is-num ob-col-size ui-muted">—</td>
      <td class="ui-muted ob-col-date ui-hide-m">Folder</td>
      <td class="ob-col-actions">
        <button type="button" class="icon-btn" aria-label="Open folder ${escapeHtml(folderName)}">
          <svg class="ic" aria-hidden="true"><use href="#i-chevron"/></svg>
        </button>
      </td>
    `;

    return tr;
  };

  const navigateToFolder = (prefix, { updateHistory = true } = {}) => {
    if (streamAbortController) {
      streamAbortController.abort();
      streamAbortController = null;
    }

    if (updateHistory) {
      syncPrefixToUrl(prefix);
    }
    currentPrefix = prefix;

    if (scrollContainer) scrollContainer.scrollTop = 0;

    selectedRows.clear();

    if (typeof updateBulkDeleteState === 'function') {
      updateBulkDeleteState();
    }

    if (previewPanel) previewPanel.classList.add('is-hidden');
    if (previewEmpty) previewEmpty.classList.remove('is-hidden');
    activeRow = null;

    isLoadingObjects = false;
    loadObjects(false);
  };

  window.addEventListener('popstate', () => {
    const prefix = normalizeFolderPrefix(new URLSearchParams(window.location.search).get('prefix'));
    if (prefix !== currentPrefix) {
      navigateToFolder(prefix, { updateHistory: false });
    }
  });

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
      const isFiltering = currentFilterTerm && currentFilterTerm.length > 0;
      const title = isFiltering ? 'No matches' : 'Empty folder';
      const body = isFiltering
        ? `No objects match "${escapeHtml(currentFilterTerm)}".`
        : 'This folder contains no objects.';
      const emptyRow = document.createElement('tr');
      emptyRow.innerHTML = `
        <td colspan="5">
          <div class="ui-empty">
            <svg class="ic" aria-hidden="true"><use href="#i-folder"/></svg>
            <h2>${title}</h2>
            <p>${body}</p>
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
    if (!messageModalEl) {
      window.alert(body || title);
      return;
    }
    document.querySelectorAll('.modal.show').forEach(modal => {
      const instance = bootstrap.Modal.getInstance(modal);
      if (instance && modal.id !== 'messageModal') {
        instance.hide();
      }
    });
    messageModalTitle.textContent = title;
    if (bodyHtml) {
      messageModalBody.innerHTML = bodyHtml;
    } else {
      messageModalBody.textContent = body;
    }
    messageModalActionHandler = null;
    messageModalAction.classList.toggle('ui-btn-danger-fill', variant === 'danger');
    messageModalAction.classList.toggle('ui-btn-primary', variant !== 'danger');
    if (actionText && typeof onAction === 'function') {
      messageModalAction.textContent = actionText;
      messageModalAction.hidden = false;
      messageModalActionHandler = onAction;
    } else {
      messageModalAction.hidden = true;
    }
    document.querySelectorAll('dialog.ui-dialog[open]').forEach((openDialog) => {
      if (openDialog !== messageModalEl) window.UI.dialog.close(openDialog);
    });
    window.UI.dialog.open(messageModalEl);
  };

  messageModalAction?.addEventListener('click', () => {
    const handler = messageModalActionHandler;
    window.UI.dialog.close(messageModalEl);
    if (typeof handler === 'function') handler();
  });

  messageModalEl?.addEventListener('close', () => {
    messageModalActionHandler = null;
    messageModalAction.hidden = true;
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
  const policyReadonlyHint = document.getElementById('policyReadonlyHint');
  const presetButtons = Array.from(document.querySelectorAll('.preset-btn[data-preset]'));

  const setActivePolicyPreset = (preset) => {
    if (policyPreset) {
      policyPreset.value = preset;
    }
    presetButtons.forEach(button => {
      button.classList.toggle('active', button.dataset.preset === preset);
    });
  };

  const setPolicyTextareaState = (readonly) => {
    if (!policyTextarea) return;
    if (readonly) {
      policyTextarea.setAttribute('readonly', 'readonly');
      policyTextarea.classList.add('bg-body-secondary');
      policyTextarea.classList.add('policy-editor-disabled');
      policyTextarea.setAttribute('aria-disabled', 'true');
    } else {
      policyTextarea.removeAttribute('readonly');
      policyTextarea.classList.remove('bg-body-secondary');
      policyTextarea.classList.remove('policy-editor-disabled');
      policyTextarea.removeAttribute('aria-disabled');
    }
  };

  const applyPolicyPreset = (preset) => {
    if (!policyTextarea || !policyMode) return;
    const isPresetMode = preset === 'private' || preset === 'public';
    if (policyReadonlyHint) {
      policyReadonlyHint.classList.toggle('is-hidden', !isPresetMode);
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

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      setActivePolicyPreset(btn.dataset.preset);
      applyPolicyPreset(btn.dataset.preset);
    });
  });

  if (policyPreset) {
    setActivePolicyPreset(policyPreset.value || policyPreset.dataset.default || 'custom');
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
  const bulkSelectionCount = document.getElementById('bulk-selection-count');
  const bulkDownloadButton = document.querySelector('[data-bulk-download-trigger]');
  const updateBulkDownloadState = () => {
    if (!bulkDownloadButton) return;
    bulkDownloadButton.disabled = selectedRows.size === 0;
  };
  const updateBulkDeleteState = () => {
    const selectedCount = selectedRows.size;
    if (bulkDeleteButton) {
      const shouldShow = Boolean(bulkDeleteEndpoint) && (selectedCount > 0 || bulkDeleting);
      bulkDeleteButton.disabled = !bulkDeleteEndpoint || selectedCount === 0 || bulkDeleting;
      if (bulkDeleteLabel) {
        bulkDeleteLabel.textContent = selectedCount ? `Delete (${selectedCount})` : 'Delete';
      }
      if (bulkActionsWrapper) {
        bulkActionsWrapper.classList.toggle('is-hidden', !shouldShow);
      }
      if (bulkSelectionCount) {
        let selectedBytes = 0;
        selectedRows.forEach((entry) => {
          const size = Number(entry?.dataset ? entry.dataset.size : entry?.size);
          if (Number.isFinite(size)) selectedBytes += size;
        });
        bulkSelectionCount.textContent = `${selectedCount} selected` + (selectedBytes > 0 ? ` · ${formatBytes(selectedBytes)}` : '');
      }
    }
    if (bulkDeleteConfirm) {
      bulkDeleteConfirm.disabled = selectedCount === 0 || bulkDeleting;
    }
    if (selectAllCheckbox) {
      const filesInView = visibleItems.filter(item => item.type === 'file');
      const foldersInView = visibleItems.filter(item => item.type === 'folder');
      const total = filesInView.length + foldersInView.length;
      const fileSelectedCount = filesInView.filter(item => selectedRows.has(item.data.key)).length;
      const folderSelectedCount = foldersInView.filter(item => selectedRows.has(item.path)).length;
      const visibleSelectedCount = fileSelectedCount + folderSelectedCount;
      selectAllCheckbox.disabled = total === 0;
      selectAllCheckbox.checked = visibleSelectedCount > 0 && visibleSelectedCount === total && total > 0;
      selectAllCheckbox.indeterminate = visibleSelectedCount > 0 && visibleSelectedCount < total;
    }
    updateBulkDownloadState();
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
      const folderCount = keys.filter(k => k.endsWith('/')).length;
      const objectCount = keys.length - folderCount;
      const parts = [];
      if (folderCount) parts.push(`${folderCount} folder${folderCount !== 1 ? 's' : ''}`);
      if (objectCount) parts.push(`${objectCount} object${objectCount !== 1 ? 's' : ''}`);
      bulkDeleteCount.textContent = `${parts.join(' and ')} selected`;
    }
    if (!keys.length) {
      const empty = document.createElement('li');
      empty.className = 'ui-muted';
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
      item.className = 'ui-mono';
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
      previewEmpty.classList.remove('is-hidden');
      previewPanel.classList.add('is-hidden');
      activeRow = null;
      loadObjects(false);
      refreshBucketUsage();
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
      generatePresignButton.innerHTML = '<span class="ui-spinner" role="status" aria-hidden="true"></span> Generating…';
      return;
    }
    generatePresignButton.textContent = 'Generate link';
    generatePresignButton.disabled = !activeRow;
  };

  const syncPresignExpiryPreset = () => {
    const custom = presignExpiryPreset?.value === 'custom';
    presignCustomExpiry?.classList.toggle('is-hidden', !custom);
    presignTtl?.classList.remove('is-invalid');
    presignClampNote?.classList.add('is-hidden');
  };

  const selectedPresignExpiry = () => {
    if (presignExpiryPreset?.value !== 'custom') {
      return Number(presignExpiryPreset?.value || 900);
    }
    const raw = presignTtl?.value.trim() || '';
    const value = Number(raw);
    const valid = raw !== ''
      && Number.isSafeInteger(value)
      && presignTtl?.checkValidity();
    presignTtl?.classList.toggle('is-invalid', !valid);
    if (!valid) {
      presignTtl?.focus();
      return null;
    }
    return value;
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
    const expiresIn = selectedPresignExpiry();
    if (expiresIn === null) {
      return;
    }
    isGeneratingPresign = true;
    updateGeneratePresignState();
    presignLink.value = '';
    presignClampNote?.classList.add('is-hidden');
    try {
      const payload = {
        method: presignMethod?.value || 'GET',
        expires_in: expiresIn,
      };
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        if (response.status === 400 && data.error && data.error.toLowerCase().includes('expiry')) {
          if (presignTtlFeedback) presignTtlFeedback.textContent = data.error;
          presignTtl?.classList.add('is-invalid');
          presignCustomExpiry?.classList.remove('is-hidden');
          return;
        }
        throw new Error(data.error || 'Unable to generate presigned URL');
      }
      presignLink.value = data.url;
      if (data.clamped && presignClampNote) {
        const effective = Number(data.effective_expires_in ?? data.expires_in);
        const maximum = Number(presignTtl?.max || 0);
        const bound = effective === maximum ? 'maximum' : 'minimum';
        presignClampNote.textContent = `Expiry clamped to ${effective} seconds (server ${bound})`;
        presignClampNote.classList.remove('is-hidden');
      }
    } catch (error) {
      presignModal?.hide();
      showMessage({ title: 'Presign failed', body: (error && error.message) || 'Unable to generate presigned URL', variant: 'danger' });
    } finally {
      isGeneratingPresign = false;
      if (presignLink?.value && generatePresignButton) {
        generatePresignButton.disabled = false;
        generatePresignButton.textContent = 'Link ready';
        window.setTimeout(updateGeneratePresignState, 1200);
      } else {
        updateGeneratePresignState();
      }
    }
  };

  const INTERNAL_METADATA_KEYS = new Set([
    '__etag__',
    '__size__',
    '__content_type__',
    '__last_modified__',
    '__storage_class__',
  ]);

  const isInternalKey = (key) => INTERNAL_METADATA_KEYS.has(key.toLowerCase());

  const renderMetadata = (metadata) => {
    if (!previewMetadata || !previewMetadataList) return;
    previewMetadataList.innerHTML = '';
    if (!metadata) {
      previewMetadata.classList.add('is-hidden');
      return;
    }
    const userMetadata = Object.entries(metadata).filter(([key]) => !isInternalKey(key));
    if (userMetadata.length === 0) {
      previewMetadata.classList.add('is-hidden');
      return;
    }
    previewMetadata.classList.remove('is-hidden');
    userMetadata.forEach(([key, value]) => {
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

  const versionTimestamp = (entry) => {
    if (!entry) return '';
    if (entry.archived_at_display) return entry.archived_at_display;
    const raw = entry.archived_at || entry.last_modified;
    return raw || entry.version_id;
  };

  const confirmVersionRestore = (row, version, label = null, onConfirm) => {
    if (!version) return;
    const timestamp = versionTimestamp(version);
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
    const label = count === 1 ? 'item' : 'items';
    if (archivedCountBadge) {
      archivedCountBadge.textContent = `${count} ${label}`;
      archivedCountBadge.classList.remove('is-hidden');
    }
    if (archivedObjectsChip) {
      archivedObjectsChip.textContent = `${count.toLocaleString()} archived`;
      archivedObjectsChip.dataset.state = 'loaded';
      archivedObjectsChip.classList.remove('is-hidden');
    }
  };

  const renderArchivedLoadError = (message) => {
    if (archivedBody) {
      archivedBody.innerHTML = '';
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = 4;
      cell.className = 'text-center text-danger py-3';
      const text = document.createElement('div');
      text.textContent = message;
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'btn btn-outline-danger btn-sm mt-2';
      retry.textContent = 'Retry';
      retry.addEventListener('click', () => loadArchivedObjects(true));
      cell.appendChild(text);
      cell.appendChild(retry);
      row.appendChild(cell);
      archivedBody.appendChild(row);
    }
    if (archivedCountBadge) archivedCountBadge.classList.add('is-hidden');
    if (archivedObjectsChip) {
      archivedObjectsChip.textContent = 'Archived count unavailable · Retry';
      archivedObjectsChip.dataset.state = 'error';
      archivedObjectsChip.classList.remove('is-hidden');
    }
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
        const ts = versionTimestamp(item.latest);
        const sizeLabel = formatBytes(Number(item.latest.size) || 0);
        latestCell.innerHTML = `<div class="small">${escapeHtml(ts)}</div><div class="text-muted small">${sizeLabel} · ${describeVersionReason(item.latest.reason)}</div>`;
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
      await loadArchivedObjects(true);
      loadObjects(false);
      refreshBucketUsage();
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
      await loadArchivedObjects(true);
      refreshBucketUsage();
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

  async function loadArchivedObjects(force = false) {
    if (!archivedEndpoint) return;
    if (archivedLoadPromise) return archivedLoadPromise;
    if (!force && archivedItemsCache) {
      renderArchivedRows(archivedItemsCache);
      return;
    }
    archivedBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-3">Loading…</td></tr>';
    archivedLoadPromise = (async () => {
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
        archivedItemsCache = Array.isArray(data.objects) ? data.objects : [];
        renderArchivedRows(archivedItemsCache);
      } catch (error) {
        renderArchivedLoadError((error && error.message) || 'Unable to load archived objects');
      }
    })();
    try {
      await archivedLoadPromise;
    } finally {
      archivedLoadPromise = null;
    }
  }

  if (archivedRefreshButton) {
    archivedRefreshButton.addEventListener('click', () => loadArchivedObjects(true));
  }

  const propertiesTab = document.getElementById('properties-tab');
  if (propertiesTab) {
    propertiesTab.addEventListener('shown.bs.tab', () => {
      if (archivedCard && archivedEndpoint) {
        loadArchivedObjects();
      }
      if (propertiesTab.dataset.scrollToArchived === 'true') {
        propertiesTab.dataset.scrollToArchived = 'false';
        archivedCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  }

  archivedObjectsChip?.addEventListener('click', () => {
    if (archivedObjectsChip.dataset.state === 'error') {
      loadArchivedObjects(true);
      return;
    }
    if (!propertiesTab) return;
    propertiesTab.dataset.scrollToArchived = 'true';
    bootstrap.Tab.getOrCreateInstance(propertiesTab).show();
    if (propertiesTab.classList.contains('active')) {
      propertiesTab.dataset.scrollToArchived = 'false';
      archivedCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });

  const archivedLoadTrigger = document.getElementById('pagination-controls');
  if (versioningEnabled && archivedLoadTrigger && archivedEndpoint) {
    const archivedObserver = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      archivedObserver.disconnect();
      loadArchivedObjects();
    });
    archivedObserver.observe(archivedLoadTrigger);
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
      refreshBucketUsage();
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
      const timestamp = versionTimestamp(entry);
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
      versionPanel?.classList.add('is-hidden');
      return;
    }
    if (!row) {
      versionPanel.classList.add('is-hidden');
      return;
    }
    const endpoint = row.dataset.versionsEndpoint;
    if (!endpoint) {
      versionPanel.classList.add('is-hidden');
      return;
    }
    versionPanel.classList.remove('is-hidden');
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
  const deleteModal = dialogHandle(deleteModalEl);
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
        previewEmpty.classList.remove('is-hidden');
        previewPanel.classList.add('is-hidden');
        activeRow = null;
        loadObjects(false);
        refreshBucketUsage();
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
    setAudioStage(false);
    [previewImage, previewVideo, previewAudio, previewIframe].forEach((el) => {
      if (!el) return;
      el.classList.add('is-hidden');
      if (el.tagName === 'IMG') {
        el.removeAttribute('src');
        el.onload = null;
      }
      if (el.tagName === 'VIDEO' || el.tagName === 'AUDIO') {
        el.pause();
        el.removeAttribute('src');
      }
      if (el.tagName === 'IFRAME') {
        el.setAttribute('src', 'about:blank');
      }
    });
    if (previewText) {
      previewText.classList.add('is-hidden');
      previewText.textContent = '';
    }
    previewPlaceholder.innerHTML = previewPlaceholderDefault;
    previewPlaceholder.classList.remove('is-hidden');
  };

  const renderPreviewUnavailable = () => {
    if (!previewPlaceholder) return;
    setAudioStage(false);
    previewIframe?.classList.add('is-hidden');
    previewPlaceholder.innerHTML = '<div class="preview-unavailable-card"><div class="fw-semibold mb-1">Preview unavailable</div><div class="small text-muted">Download to view</div></div>';
    previewPlaceholder.classList.remove('is-hidden');
  };

  let previewFailed = false;

  const handlePreviewError = () => {
    previewFailed = true;
    if (downloadButton) {
      downloadButton.classList.add('disabled');
      downloadButton.removeAttribute('href');
    }
    if (presignButton) presignButton.disabled = true;
    if (generatePresignButton) generatePresignButton.disabled = true;
    if (previewDetailsMeta) previewDetailsMeta.classList.add('is-hidden');
    if (previewMetadata) previewMetadata.classList.add('is-hidden');
    const tagsPanel = document.getElementById('preview-tags');
    if (tagsPanel) tagsPanel.classList.add('is-hidden');
    const versionPanel = document.getElementById('version-panel');
    if (versionPanel) versionPanel.classList.add('is-hidden');
    if (previewErrorAlert) {
      previewErrorAlert.textContent = 'Unable to load object \u2014 it may have been deleted, or the server returned an error.';
      previewErrorAlert.classList.remove('is-hidden');
    }
  };

  const clearPreviewError = () => {
    previewFailed = false;
    if (previewErrorAlert) previewErrorAlert.classList.add('is-hidden');
    if (previewDetailsMeta) previewDetailsMeta.classList.remove('is-hidden');
  };

  async function fetchMetadata(metadataUrl) {
    if (!metadataUrl) return null;
    try {
      const resp = await fetch(metadataUrl);
      if (resp.ok) {
        const data = await resp.json();
        return data.metadata || {};
      }
    } catch (e) {
      console.warn('Failed to load metadata', e);
    }
    return null;
  }

  async function selectRow(row) {
    document.querySelectorAll('[data-object-row]').forEach((r) => r.classList.remove('is-selected'));
    row.classList.add('is-selected');
    previewEmpty.classList.add('is-hidden');
    previewPanel.classList.remove('is-hidden');
    activeRow = row;
    renderMetadata(null);
    clearPreviewError();

    previewKey.textContent = row.dataset.key;
    previewSize.textContent = formatBytes(Number(row.dataset.size));
    previewModified.textContent = row.dataset.lastModifiedDisplay || row.dataset.lastModifiedIso || row.dataset.lastModified;
    previewEtag.textContent = row.dataset.etag;
    const previewS3Uri = document.getElementById('preview-s3-uri');
    if (previewS3Uri) previewS3Uri.textContent = `s3://${objectsContainer?.dataset.bucket || ''}/${row.dataset.key}`;
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
    if (previewUrl && lower.match(/\.(png|jpg|jpeg|gif|webp|svg|ico|bmp)$/)) {
      previewPlaceholder.innerHTML = '<div class="ui-spinner" role="status"></div><div class="ui-hint">Loading preview\u2026</div>';
      const currentRow = row;
      fetch(previewUrl)
        .then((r) => {
          if (activeRow !== currentRow) return;
          if (!r.ok) {
            previewPlaceholder.innerHTML = '<div class="small text-muted">Failed to load preview</div>';
            handlePreviewError();
            return;
          }
          return r.blob();
        })
        .then((blob) => {
          if (!blob || activeRow !== currentRow) return;
          const url = URL.createObjectURL(blob);
          previewImage.onload = () => {
            if (activeRow !== currentRow) { URL.revokeObjectURL(url); return; }
            previewImage.classList.remove('is-hidden');
            previewPlaceholder.classList.add('is-hidden');
          };
          previewImage.onerror = () => {
            if (activeRow !== currentRow) { URL.revokeObjectURL(url); return; }
            URL.revokeObjectURL(url);
            previewPlaceholder.innerHTML = '<div class="small text-muted">Failed to load preview</div>';
          };
          previewImage.src = url;
        })
        .catch(() => {
          if (activeRow !== currentRow) return;
          previewPlaceholder.innerHTML = '<div class="small text-muted">Failed to load preview</div>';
          handlePreviewError();
        });
    } else if (previewUrl && lower.match(/\.(mp4|webm|ogv|mov|avi|mkv)$/)) {
      const currentRow = row;
      previewVideo.onerror = () => {
        if (activeRow !== currentRow) return;
        previewVideo.classList.add('is-hidden');
        previewPlaceholder.classList.remove('is-hidden');
        previewPlaceholder.innerHTML = '<div class="small text-muted">Failed to load preview</div>';
        handlePreviewError();
      };
      previewVideo.src = previewUrl;
      previewVideo.classList.remove('is-hidden');
      previewPlaceholder.classList.add('is-hidden');
    } else if (previewUrl && lower.match(/\.(mp3|wav|flac|ogg|aac|m4a|wma)$/)) {
      const currentRow = row;
      previewAudio.onerror = () => {
        if (activeRow !== currentRow) return;
        setAudioStage(false);
        previewAudio.classList.add('is-hidden');
        previewPlaceholder.classList.remove('is-hidden');
        previewPlaceholder.innerHTML = '<div class="small text-muted">Failed to load preview</div>';
        handlePreviewError();
      };
      previewAudio.src = previewUrl;
      previewAudio.classList.remove('is-hidden');
      previewPlaceholder.classList.add('is-hidden');
      setAudioStage(true);
    } else if (previewUrl && lower.match(/\.(pdf)$/)) {
      const currentRow = row;
      previewIframe.onerror = () => {
        if (activeRow !== currentRow) return;
        renderPreviewUnavailable();
      };
      previewPlaceholder.innerHTML = '<div class="ui-spinner" role="status"></div><div class="ui-hint">Loading preview\u2026</div>';
      fetch(previewUrl, { headers: { 'Range': 'bytes=0-4', 'Accept': 'application/pdf' } })
        .then(async response => {
          if (activeRow !== currentRow) return false;
          if (!response.ok) {
            if (response.status === 415) {
              renderPreviewUnavailable();
              return false;
            }
            throw new Error('Unable to validate PDF preview');
          }
          if (response.body) await response.body.cancel();
          return true;
        })
        .then(valid => {
          if (!valid || activeRow !== currentRow) return;
          previewIframe.src = previewUrl;
          previewIframe.classList.remove('is-hidden');
          previewPlaceholder.classList.add('is-hidden');
        })
        .catch(() => {
          if (activeRow !== currentRow) return;
          renderPreviewUnavailable();
        });
    } else if (previewUrl && previewText && lower.match(/\.(txt|log|json|md|csv|xml|html|htm|js|ts|py|java|c|cpp|h|css|scss|yaml|yml|toml|ini|cfg|conf|sh|bat|rs|go|rb|php|sql|r|swift|kt|scala|pl|lua|zig|ex|exs|hs|erl|ps1|psm1|psd1|fish|zsh|env|properties|gradle|makefile|dockerfile|vagrantfile|gitignore|gitattributes|editorconfig|eslintrc|prettierrc)$/)) {
      previewText.textContent = 'Loading\u2026';
      previewText.classList.remove('is-hidden');
      previewPlaceholder.classList.add('is-hidden');
      const currentRow = row;
      fetch(previewUrl)
        .then((r) => {
          if (!r.ok) throw new Error(r.statusText);
          const len = parseInt(r.headers.get('Content-Length') || '0', 10);
          if (len > 512 * 1024) {
            return r.text().then((t) => t.slice(0, 512 * 1024) + '\n\n--- Truncated (file too large for preview) ---');
          }
          return r.text();
        })
        .then((text) => {
          if (activeRow !== currentRow) return;
          previewText.textContent = text;
        })
        .catch(() => {
          if (activeRow !== currentRow) return;
          previewText.classList.add('is-hidden');
          previewPlaceholder.classList.remove('is-hidden');
          previewPlaceholder.innerHTML = '<div class="small text-muted">Failed to load preview</div>';
          handlePreviewError();
        });
    }

    const metadataUrl = row.dataset.metadataUrl;
    if (metadataUrl) {
      const metadata = await fetchMetadata(metadataUrl);
      if (activeRow === row && !previewFailed) {
        renderMetadata(metadata);
      }
    }
  }

  updateBulkDeleteState();

  bulkDeleteButton?.addEventListener('click', () => openBulkDeleteModal());
  bulkDeleteConfirm?.addEventListener('click', () => performBulkDelete());

  const filterWarning = document.getElementById('filter-warning');
  const filterWarningText = document.getElementById('filter-warning-text');
  const folderViewStatus = document.getElementById('folder-view-status');

  let searchDebounceTimer = null;
  let searchAbortController = null;
  let searchResults = null;
  let searchNextToken = null;
  let searchLoading = false;
  const SEARCH_PAGE_SIZE = 500;

  const updateFilterWarning = () => {
    if (!filterWarning) return;
    filterWarning.classList.add('is-hidden');
  };

  const performServerSearch = async (term, append = false) => {
    if (!append && searchAbortController) searchAbortController.abort();
    if (append && (searchLoading || !searchNextToken)) return;
    if (!append) {
      searchAbortController = new AbortController();
    }
    searchLoading = true;
    if (append && loadMoreSpinner) loadMoreSpinner.classList.remove('is-hidden');

    let succeeded = false;
    try {
      const params = new URLSearchParams({ q: term, limit: String(SEARCH_PAGE_SIZE) });
      if (currentPrefix) params.set('prefix', currentPrefix);
      if (append && searchNextToken) params.set('start_after', searchNextToken);
      const searchUrl = objectsStreamUrl.replace('/stream', '/search');
      const response = await fetch(`${searchUrl}?${params}`, {
        signal: searchAbortController?.signal
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const newResults = (data.results || []).map(obj => processStreamObject(obj));
      if (append && Array.isArray(searchResults)) {
        searchResults = searchResults.concat(newResults);
      } else {
        searchResults = newResults;
      }
      searchNextToken = data.truncated ? (data.next_token || null) : null;
      memoizedVisibleItems = null;
      memoizedInputs = { objectCount: -1, folderCount: -1, prefix: null, filterTerm: null };
      refreshVirtualList();
      if (loadMoreStatus) {
        const countText = searchResults.length.toLocaleString();
        const more = searchNextToken ? '+' : '';
        const noun = searchResults.length === 1 ? 'result' : 'results';
        loadMoreStatus.textContent = searchNextToken
          ? `${countText}${more} ${noun} (scroll to load more)`
          : `${countText} ${noun}`;
      }
      succeeded = true;
    } catch (e) {
      if (e.name === 'AbortError') return;
      if (loadMoreStatus) {
        loadMoreStatus.textContent = 'Search failed (scroll to retry)';
      }
    } finally {
      searchLoading = false;
      if (loadMoreSpinner) loadMoreSpinner.classList.add('is-hidden');
    }

    if (succeeded && searchNextToken && !searchLoading && isSentinelVisible()) {
      performServerSearch(currentFilterTerm, true);
    }
  };

  document.getElementById('object-search')?.addEventListener('input', (event) => {
    const newTerm = event.target.value.toLowerCase();
    const wasFiltering = currentFilterTerm.length > 0;
    const isFiltering = newTerm.length > 0;
    currentFilterTerm = newTerm;

    clearTimeout(searchDebounceTimer);

    if (isFiltering) {
      searchDebounceTimer = setTimeout(() => performServerSearch(newTerm), 300);
      return;
    }

    if (!isFiltering && wasFiltering) {
      if (searchAbortController) searchAbortController.abort();
      searchResults = null;
      searchNextToken = null;
      memoizedVisibleItems = null;
      memoizedInputs = { objectCount: -1, folderCount: -1, prefix: null, filterTerm: null };
      if (loadMoreStatus) {
        loadMoreStatus.textContent = buildBottomStatusText(streamingComplete);
      }
    }

    updateFilterWarning();
    refreshVirtualList();
  });

  document.querySelectorAll('[data-sort-field]').forEach(el => {
    el.addEventListener('click', (e) => {
      e.preventDefault();
      const field = el.dataset.sortField;
      const dir = el.dataset.sortDir || 'asc';
      currentSortField = field;
      currentSortDir = dir;
      document.querySelectorAll('[data-sort-field]').forEach(s => s.classList.remove('active'));
      el.classList.add('active');
      var label = document.getElementById('sort-dropdown-label');
      if (label) label.textContent = el.textContent.trim();
      refreshVirtualList();
    });
  });

  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT' || e.target.isContentEditable) return;

    if (e.key === '/' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      document.getElementById('object-search')?.focus();
    }

    if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      var kbModal = document.getElementById('keyboardShortcutsModal');
      if (kbModal) {
        if (kbModal.open) window.UI.dialog.close(kbModal);
        else window.UI.dialog.open(kbModal);
      }
    }

    if (e.key === 'Escape') {
      var searchInput = document.getElementById('object-search');
      if (searchInput && document.activeElement === searchInput) {
        searchInput.value = '';
        const wasFiltering = currentFilterTerm.length > 0;
        currentFilterTerm = '';
        if (wasFiltering) {
          clearTimeout(searchDebounceTimer);
          if (searchAbortController) searchAbortController.abort();
          searchResults = null;
          memoizedVisibleItems = null;
          memoizedInputs = { objectCount: -1, folderCount: -1, prefix: null, filterTerm: null };
          if (loadMoreStatus) {
            loadMoreStatus.textContent = buildBottomStatusText(streamingComplete);
          }
        }
        refreshVirtualList();
        searchInput.blur();
      }
    }

    if (e.key === 'Delete' && !e.ctrlKey && !e.metaKey) {
      if (selectedRows.size > 0 && bulkDeleteButton && !bulkDeleteButton.disabled) {
        bulkDeleteButton.click();
      }
    }

    if (e.key === 'a' && (e.ctrlKey || e.metaKey)) {
      if (visibleItems.length > 0 && selectAllCheckbox) {
        e.preventDefault();
        selectAllCheckbox.checked = true;
        selectAllCheckbox.dispatchEvent(new Event('change'));
      }
    }
  });

  const ctxMenu = document.getElementById('objectContextMenu');
  let ctxTargetRow = null;

  const hideContextMenu = () => {
    if (ctxMenu) ctxMenu.classList.add('is-hidden');
    ctxTargetRow = null;
  };

  if (ctxMenu) {
    document.addEventListener('click', hideContextMenu);
    document.addEventListener('contextmenu', (e) => {
      const row = e.target.closest('[data-object-row]');
      if (!row) { hideContextMenu(); return; }
      e.preventDefault();
      ctxTargetRow = row;

      const x = Math.min(e.clientX, window.innerWidth - 200);
      const y = Math.min(e.clientY, window.innerHeight - 200);
      ctxMenu.style.left = x + 'px';
      ctxMenu.style.top = y + 'px';
      ctxMenu.classList.remove('is-hidden');
    });

    ctxMenu.querySelectorAll('[data-ctx-action]').forEach(btn => {
      btn.addEventListener('click', () => {
        if (!ctxTargetRow) return;
        const action = btn.dataset.ctxAction;
        const key = ctxTargetRow.dataset.key;
        const bucket = objectsContainer?.dataset.bucket || '';

        if (action === 'download') {
          const url = ctxTargetRow.dataset.downloadUrl;
          if (url) window.open(url, '_blank');
        } else if (action === 'copy-path') {
          const s3Path = 's3://' + bucket + '/' + key;
          if (navigator.clipboard) {
            navigator.clipboard.writeText(s3Path).then(() => {
              if (window.showToast) window.showToast('Copied: ' + s3Path, 'Copied', 'success');
            });
          }
        } else if (action === 'presign') {
          selectRow(ctxTargetRow);
          presignLink.value = '';
          presignModal?.show();
          requestPresignedUrl();
        } else if (action === 'delete') {
          const deleteEndpoint = ctxTargetRow.dataset.deleteEndpoint;
          if (deleteEndpoint) {
            selectRow(ctxTargetRow);
            const deleteModalEl = document.getElementById('deleteObjectModal');
            const deleteModal = dialogHandle(deleteModalEl);
            const deleteObjectForm = document.getElementById('deleteObjectForm');
            const deleteObjectKey = document.getElementById('deleteObjectKey');
            if (deleteModal && deleteObjectForm) {
              deleteObjectForm.setAttribute('action', deleteEndpoint);
              if (deleteObjectKey) deleteObjectKey.textContent = key;
              deleteModal.show();
            }
          }
        }
        hideContextMenu();
      });
    });
  }

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

  presignExpiryPreset?.addEventListener('change', syncPresignExpiryPreset);
  presignTtl?.addEventListener('input', () => {
    presignTtl.classList.remove('is-invalid');
    presignClampNote?.classList.add('is-hidden');
  });
  syncPresignExpiryPreset();

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

  window.BucketDetailUpload.init({
    objectsContainer,
    showMessage,
    refreshBucketUsage,
    clearVersionsCache: () => versionsCache.clear(),
    hasFolders,
    loadObjects: (append) => loadObjects(append),
    loadObjectVersions: (row, options) => loadObjectVersions(row, options),
    selectRow: (row) => selectRow(row),
    getActiveRow: () => activeRow,
    getCurrentPrefix: () => currentPrefix,
    get versioningEnabled() { return versioningEnabled; }
  });

  const bulkDownloadEndpoint = document.getElementById('objects-drop-zone')?.dataset.bulkDownloadEndpoint;

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

    const foldersInView = visibleItems.filter(item => item.type === 'folder');
    foldersInView.forEach(item => {
      if (shouldSelect) {
        selectedRows.set(item.path, { key: item.path, isFolder: true });
      } else {
        selectedRows.delete(item.path);
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
  });

  bulkDownloadButton?.addEventListener('click', async () => {
    if (!bulkDownloadEndpoint) return;
    const selected = Array.from(selectedRows.keys());
    if (selected.length === 0) return;

    bulkDownloadButton.disabled = true;
    const originalHtml = bulkDownloadButton.innerHTML;
    bulkDownloadButton.innerHTML = '<span class="ui-spinner" role="status" aria-hidden="true"></span> Downloading...';

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

    const REPLICATION_POLL_ACTIVE_MS = 2000;
    const REPLICATION_POLL_IDLE_MS = 30000;
    let replicationPollMode = 'idle';
    let optimisticRunActive = false;

    const ensurePollMode = (mode) => {
      if (!window.pollingManager) return;
      if (replicationPollMode === mode) return;
      replicationPollMode = mode;
      const interval = mode === 'active' ? REPLICATION_POLL_ACTIVE_MS : REPLICATION_POLL_IDLE_MS;
      window.pollingManager.start('replication', loadReplicationStats, interval);
    };

    const formatElapsed = (seconds) => {
      if (seconds == null || isNaN(seconds) || seconds < 0) return '';
      seconds = Math.floor(seconds);
      if (seconds < 60) return `${seconds}s`;
      const m = Math.floor(seconds / 60);
      const s = seconds % 60;
      if (m < 60) return `${m}m ${s}s`;
      const h = Math.floor(m / 60);
      return `${h}h ${m % 60}m`;
    };

    const renderCurrentRun = (run) => {
      const card = document.getElementById('replication-current-run-card');
      if (!card) return;
      if (!run) {
        if (!optimisticRunActive) {
          card.style.display = 'none';
        }
        return;
      }
      optimisticRunActive = false;
      card.style.display = '';

      const titleEl = document.getElementById('current-run-title');
      const kindEl = document.getElementById('current-run-kind');
      const elapsedEl = document.getElementById('current-run-elapsed');
      const summaryEl = document.getElementById('current-run-summary');
      const progressEl = document.getElementById('current-run-progress');
      const inFlightEl = document.getElementById('current-run-in-flight');
      const failedEl = document.getElementById('current-run-failed');
      const lastObjEl = document.getElementById('current-run-last-object');

      if (kindEl) {
        kindEl.textContent = run.kind === 'retry_all' ? 'Retrying failures' : 'Resuming all objects';
      }
      if (titleEl) {
        titleEl.textContent = 'Replication run in progress';
      }
      if (elapsedEl && run.started_at) {
        const elapsed = (Date.now() / 1000) - run.started_at;
        elapsedEl.textContent = formatElapsed(elapsed);
      }
      const total = run.total_queued || 0;
      const completed = run.completed || 0;
      const failed = run.failed || 0;
      const inFlight = run.in_flight || 0;
      if (inFlightEl) inFlightEl.textContent = inFlight;
      if (failedEl) failedEl.textContent = failed;
      if (lastObjEl) {
        lastObjEl.textContent = run.last_object || '';
        lastObjEl.title = run.last_object || '';
      }
      if (summaryEl) {
        if (!run.enumeration_done) {
          summaryEl.textContent = `Enumerating objects... ${total.toLocaleString()} queued so far`;
        } else {
          const processed = completed + failed;
          summaryEl.textContent = `${processed.toLocaleString()} of ${total.toLocaleString()} processed (${completed.toLocaleString()} succeeded, ${failed.toLocaleString()} failed)`;
        }
      }
      if (progressEl) {
        let pct = 0;
        if (run.enumeration_done && total > 0) {
          pct = Math.min(100, Math.round(((completed + failed) / total) * 100));
          progressEl.classList.remove('progress-bar-animated');
        } else {
          progressEl.classList.add('progress-bar-animated');
          pct = total > 0 ? Math.min(95, Math.round(((completed + failed) / total) * 100)) : 0;
        }
        progressEl.style.width = `${pct}%`;
        progressEl.setAttribute('aria-valuenow', pct);
      }
    };

    const renderLastRun = (lastRun, currentRun) => {
      const card = document.getElementById('replication-last-run-card');
      const summaryEl = document.getElementById('last-run-summary');
      if (!card || !summaryEl) return;
      if (currentRun || !lastRun) {
        card.style.display = 'none';
        return;
      }
      const total = lastRun.total_queued || 0;
      const completed = lastRun.completed || 0;
      const failed = lastRun.failed || 0;
      const elapsed = lastRun.finished_at && lastRun.started_at
        ? formatElapsed(lastRun.finished_at - lastRun.started_at)
        : '';
      const kind = lastRun.kind === 'retry_all' ? 'Retry-all' : 'Resume-all';
      summaryEl.textContent = `${kind} — ${completed.toLocaleString()}/${total.toLocaleString()} synced, ${failed.toLocaleString()} failed${elapsed ? ` in ${elapsed}` : ''}`;
      card.style.display = '';
    };

    const renderAmbientStrip = (data) => {
      const strip = document.getElementById('replication-ambient-strip');
      if (!strip) return;
      const live = data.live || {};
      const healer = data.healer || {};
      const showAny = (live.in_flight || 0) > 0
        || (live.replicated_total || 0) > 0
        || (live.failed_total || 0) > 0
        || healer.running
        || healer.last_pass_at;
      if (!showAny) {
        strip.style.display = 'none';
        return;
      }
      strip.style.display = '';
      const liveInFlightEl = document.getElementById('live-in-flight');
      const liveReplicatedEl = document.getElementById('live-replicated');
      const liveFailedEl = document.getElementById('live-failed');
      const healerStatusEl = document.getElementById('healer-status');
      if (liveInFlightEl) liveInFlightEl.textContent = (live.in_flight || 0).toLocaleString();
      if (liveReplicatedEl) liveReplicatedEl.textContent = (live.replicated_total || 0).toLocaleString();
      if (liveFailedEl) liveFailedEl.textContent = (live.failed_total || 0).toLocaleString();
      if (healerStatusEl) {
        if (healer.running) {
          healerStatusEl.textContent = 'running...';
        } else if (healer.last_pass_at) {
          const ago = Math.max(0, Math.floor((Date.now() / 1000) - healer.last_pass_at));
          healerStatusEl.textContent = `idle (last pass ${healer.last_pass_healed || 0} healed, ${formatElapsed(ago)} ago)`;
        } else {
          healerStatusEl.textContent = 'idle';
        }
      }
    };

    const loadReplicationStats = async () => {
      try {
        const resp = await fetch(statusEndpoint);
        if (!resp.ok) throw new Error('Failed to fetch stats');
        const data = await resp.json();

        if (data.endpoint_healthy === false) {
          if (endpointWarning) {
            endpointWarning.classList.remove('is-hidden');
            if (endpointErrorEl && data.endpoint_error) {
              endpointErrorEl.textContent = data.endpoint_error + '. Replication is paused until the endpoint is available.';
            }
          }
          if (statusAlert) statusAlert.classList.add('is-hidden');

          if (statusBadge) {
            statusBadge.className = 'badge bg-warning-subtle text-warning px-3 py-2';
            statusBadge.innerHTML = `
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="me-1" viewBox="0 0 16 16">
                <path d="M5.5 3.5A1.5 1.5 0 0 1 7 5v6a1.5 1.5 0 0 1-3 0V5a1.5 1.5 0 0 1 1.5-1.5zm5 0A1.5 1.5 0 0 1 12 5v6a1.5 1.5 0 0 1-3 0V5a1.5 1.5 0 0 1 1.5-1.5z"/>
              </svg>
              <span>Paused (Endpoint Unavailable)</span>`;
          }

          if (pauseForm) pauseForm.classList.add('is-hidden');
        } else {
          if (endpointWarning) endpointWarning.classList.add('is-hidden');
          if (statusAlert) statusAlert.classList.remove('is-hidden');

          if (statusBadge) {
            statusBadge.className = 'badge bg-success-subtle text-success px-3 py-2';
            statusBadge.innerHTML = `
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="me-1" viewBox="0 0 16 16">
                <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>
              </svg>
              <span>Enabled</span>`;
          }

          if (pauseForm) pauseForm.classList.remove('is-hidden');
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

        renderCurrentRun(data.current_run);
        renderLastRun(data.last_run, data.current_run);
        renderAmbientStrip(data);
        ensurePollMode(data.current_run ? 'active' : 'idle');
      } catch (err) {
        console.error('Failed to load replication stats:', err);
        if (syncedEl) syncedEl.textContent = '—';
        if (pendingEl) pendingEl.textContent = '—';
        if (orphanedEl) orphanedEl.textContent = '—';
        if (bytesEl) bytesEl.textContent = '—';
      }
    };

    const showOptimisticRun = (kind) => {
      optimisticRunActive = true;
      const card = document.getElementById('replication-current-run-card');
      if (card) card.style.display = '';
      const lastRunCard = document.getElementById('replication-last-run-card');
      if (lastRunCard) lastRunCard.style.display = 'none';
      const titleEl = document.getElementById('current-run-title');
      const kindEl = document.getElementById('current-run-kind');
      const summaryEl = document.getElementById('current-run-summary');
      const progressEl = document.getElementById('current-run-progress');
      const inFlightEl = document.getElementById('current-run-in-flight');
      const failedEl = document.getElementById('current-run-failed');
      const lastObjEl = document.getElementById('current-run-last-object');
      const elapsedEl = document.getElementById('current-run-elapsed');
      if (titleEl) titleEl.textContent = 'Replication run starting';
      if (kindEl) kindEl.textContent = kind === 'retry_all' ? 'Retrying failures' : 'Resuming all objects';
      if (summaryEl) summaryEl.textContent = 'Starting...';
      if (progressEl) {
        progressEl.classList.add('progress-bar-animated');
        progressEl.style.width = '0%';
      }
      if (inFlightEl) inFlightEl.textContent = '0';
      if (failedEl) failedEl.textContent = '0';
      if (lastObjEl) { lastObjEl.textContent = ''; lastObjEl.title = ''; }
      if (elapsedEl) elapsedEl.textContent = '';
      ensurePollMode('active');
    };
    window.__myfsioShowOptimisticRun = showOptimisticRun;

    loadReplicationStats();

    if (window.pollingManager) {
      window.pollingManager.start('replication', loadReplicationStats, REPLICATION_POLL_IDLE_MS);
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
          } 
          else {
            failuresPagination.style.display = 'none';
          }
        } 
        else {
          failuresCard.style.display = 'none';
        }
      } catch (err) {
        console.error('Failed to load replication failures:', err);
      }
    };

    const renderFailures = (failures) => {
      if (!failuresBody) return;
      failuresBody.innerHTML = failures.map(f => `
        <tr data-object-key="${escapeHtml(f.object_key)}">
          <td class="ps-3" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(f.object_key)}">
            <code class="small">${escapeHtml(f.object_key)}</code>
          </td>
          <td class="small text-muted" style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(f.error_message)}">
            ${f.permanent ? '<span class="badge bg-warning text-dark me-1">Not retried</span>' : ''}${escapeHtml(f.error_message)}
          </td>
          <td class="small text-muted">${new Date(f.timestamp * 1000).toLocaleString()}</td>
          <td class="text-center"><span class="badge bg-secondary">${f.failure_count}</span></td>
          <td class="text-end pe-3">
            <button class="btn btn-sm btn-outline-primary py-0 px-2" data-retry-failure title="Retry">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">
                <path fill-rule="evenodd" d="M8 3a5 5 0 1 1-4.546 2.914.5.5 0 0 0-.908-.417A6 6 0 1 0 8 2v1z"/>
                <path d="M8 4.466V.534a.25.25 0 0 0-.41-.192L5.23 2.308a.25.25 0 0 0 0 .384l2.36 1.966A.25.25 0 0 0 8 4.466z"/>
              </svg>
            </button>
            <button class="btn btn-sm btn-outline-secondary py-0 px-2" data-dismiss-failure title="Dismiss">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">
                <path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>
              </svg>
            </button>
          </td>
        </tr>
      `).join('');
    };

    failuresBody?.addEventListener('click', (e) => {
      const retryBtn = e.target.closest('[data-retry-failure]');
      if (retryBtn) {
        window.retryFailure(retryBtn, retryBtn.closest('tr')?.dataset.objectKey ?? '');
        return;
      }
      const dismissBtn = e.target.closest('[data-dismiss-failure]');
      if (dismissBtn) {
        window.dismissFailure(dismissBtn, dismissBtn.closest('tr')?.dataset.objectKey ?? '');
      }
    });

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
      if (typeof window.__myfsioShowOptimisticRun === 'function') {
        window.__myfsioShowOptimisticRun('retry_all');
      }
      try {
        const resp = await fetch(endpoint, { method: 'POST' });
        optimisticRunActive = false;
        if (resp.ok) {
          let body = null;
          try { body = await resp.json(); } catch (_) {}
          const startedRunId = body && body.run_id;
          if (!startedRunId) {
            const msg = (body && body.skipped && body.skipped > 0)
              ? 'Retry-all could not start: target endpoint or rule is not currently usable.'
              : 'No failures to retry.';
            if (window.showToast) window.showToast(msg, 'Retry-all', 'info');
          }
          loadReplicationStats();
          loadReplicationFailures();
        } else if (resp.status === 409) {
          let message = 'Another replication batch is running for this bucket. Try again when it finishes.';
          try {
            const data = await resp.json();
            if (data && (data.error || data.message)) message = data.error || data.message;
          } catch (_) {}
          loadReplicationStats();
          if (window.showToast) window.showToast(message, 'Conflict', 'warning');
        } else {
          loadReplicationStats();
          if (window.showToast) window.showToast('Retry-all request failed', 'Error', 'danger');
        }
      } catch (err) {
        console.error('Failed to retry all:', err);
        optimisticRunActive = false;
        loadReplicationStats();
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
      policyValidationStatus.classList.add('is-hidden');
      policyErrorDetail?.classList.add('is-hidden');
      return;
    }
    policyValidationStatus.classList.remove('is-hidden');
    try {
      JSON.parse(value);
      policyValidBadge?.classList.remove('is-hidden');
      policyInvalidBadge?.classList.add('is-hidden');
      policyErrorDetail?.classList.add('is-hidden');
    } catch (err) {
      policyValidBadge?.classList.add('is-hidden');
      policyInvalidBadge?.classList.remove('is-hidden');
      if (policyErrorDetail) {
        policyErrorDetail.textContent = err.message;
        policyErrorDetail.classList.remove('is-hidden');
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

  window.deleteLifecycleRule = (idx) => {
    const rule = lifecycleRules[idx];
    const ruleName = rule && rule.ID ? `"${rule.ID}"` : 'this rule';
    showMessage({
      title: 'Delete lifecycle rule',
      body: `Delete lifecycle rule ${ruleName}? This cannot be undone.`,
      variant: 'danger',
      actionText: 'Delete rule',
      onAction: async () => {
        lifecycleRules.splice(idx, 1);
        await saveLifecycleRules('Lifecycle rule deleted');
      },
    });
  };

  const saveLifecycleRules = async (successTitle) => {
    if (!lifecycleUrl) return;
    try {
      const resp = await fetch(lifecycleUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify({ rules: lifecycleRules })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to save');
      showMessage({ title: successTitle || 'Lifecycle rules saved', body: 'Configuration updated successfully.', variant: 'success' });
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

  window.deleteCorsRule = (idx) => {
    showMessage({
      title: 'Delete CORS rule',
      body: `Delete CORS rule #${idx + 1}? This cannot be undone.`,
      variant: 'danger',
      actionText: 'Delete rule',
      onAction: async () => {
        corsRules.splice(idx, 1);
        await saveCorsRules('CORS rule deleted');
      },
    });
  };

  const saveCorsRules = async (successTitle) => {
    if (!corsUrl) return;
    try {
      const resp = await fetch(corsUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': window.getCsrfToken ? window.getCsrfToken() : '' },
        body: JSON.stringify({ rules: corsRules })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to save');
      showMessage({ title: successTitle || 'CORS rules saved', body: 'Configuration updated successfully.', variant: 'success' });
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
      if (aclLoading) aclLoading.classList.add('is-hidden');
      if (aclContent) aclContent.classList.remove('is-hidden');
    } catch (err) {
      if (aclLoading) aclLoading.classList.add('is-hidden');
      if (aclContent) aclContent.classList.remove('is-hidden');
      if (aclGrantsList) aclGrantsList.innerHTML = `<div class="list-group-item text-danger text-center py-2">${escapeHtml(err.message)}</div>`;
    }
  };

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
  let savedObjectTags = [];

  const loadObjectTags = async (row) => {
    if (!row || !previewTagsPanel) return;
    if (previewFailed) {
      previewTagsPanel.classList.add('is-hidden');
      return;
    }
    const tagsUrl = row.dataset.tagsUrl;
    if (!tagsUrl) {
      previewTagsPanel.classList.add('is-hidden');
      return;
    }
    previewTagsPanel.classList.remove('is-hidden');
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
      previewTagsEmpty.classList.remove('is-hidden');
    } else {
      previewTagsEmpty.classList.add('is-hidden');
      previewTagsList.innerHTML = currentObjectTags.map(t => `<span class="tag-pill"><span class="tag-pill-key">${escapeHtml(t.Key)}</span><span class="tag-pill-value">${escapeHtml(t.Value)}</span></span>`).join('');
    }
  };

  const syncTagInputs = () => {
    previewTagsInputs?.querySelectorAll('.tag-editor-row').forEach((row, idx) => {
      if (idx < currentObjectTags.length) {
        currentObjectTags[idx].Key = row.querySelector(`[data-tag-key="${idx}"]`)?.value || '';
        currentObjectTags[idx].Value = row.querySelector(`[data-tag-value="${idx}"]`)?.value || '';
      }
    });
  };

  const renderTagEditor = () => {
    if (!previewTagsInputs) return;
    previewTagsInputs.innerHTML = currentObjectTags.map((t, idx) => `
      <div class="tag-editor-row">
        <input type="text" class="form-control form-control-sm" placeholder="e.g. Environment" value="${escapeHtml(t.Key)}" data-tag-key="${idx}">
        <input type="text" class="form-control form-control-sm" placeholder="e.g. Production" value="${escapeHtml(t.Value)}" data-tag-value="${idx}">
        <button class="tag-editor-delete" type="button" onclick="removeTagRow(${idx})">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16"><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/></svg>
        </button>
      </div>
    `).join('');
  };

  window.removeTagRow = (idx) => {
    syncTagInputs();
    currentObjectTags.splice(idx, 1);
    renderTagEditor();
  };

  editTagsButton?.addEventListener('click', () => {
    savedObjectTags = currentObjectTags.map(t => ({ Key: t.Key, Value: t.Value }));
    isEditingTags = true;
    previewTagsList.classList.add('is-hidden');
    previewTagsEmpty.classList.add('is-hidden');
    previewTagsEditor?.classList.remove('is-hidden');
    const card = previewTagsEditor?.querySelector('.tag-editor-card');
    if (card) {
      card.style.opacity = '0';
      card.style.transition = 'opacity 0.2s ease';
      requestAnimationFrame(() => { card.style.opacity = '1'; });
    }
    renderTagEditor();
  });

  cancelTagsButton?.addEventListener('click', () => {
    isEditingTags = false;
    currentObjectTags = savedObjectTags.map(t => ({ Key: t.Key, Value: t.Value }));
    previewTagsEditor?.classList.add('is-hidden');
    previewTagsList.classList.remove('is-hidden');
    renderObjectTags();
  });

  addTagRow?.addEventListener('click', () => {
    if (currentObjectTags.length >= 10) {
      showMessage({ title: 'Limit reached', body: 'Maximum 10 tags allowed per object.', variant: 'warning' });
      return;
    }
    syncTagInputs();
    currentObjectTags.push({ Key: '', Value: '' });
    renderTagEditor();
  });

  saveTagsButton?.addEventListener('click', async () => {
    if (!activeRow) return;
    const tagsUrl = activeRow.dataset.tagsUrl;
    if (!tagsUrl) return;
    const inputs = previewTagsInputs?.querySelectorAll('.tag-editor-row');
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
      previewTagsEditor?.classList.add('is-hidden');
      previewTagsList.classList.remove('is-hidden');
      renderObjectTags();
      showMessage({ title: 'Tags saved', body: 'Object tags updated successfully.', variant: 'success' });
    } catch (err) {
      showMessage({ title: 'Save failed', body: err.message, variant: 'danger' });
    }
  });

  const copyMoveModalEl = document.getElementById('copyMoveModal');
  const copyMoveActionLabel = document.getElementById('copyMoveActionLabel');
  const copyMoveConfirmLabel = document.getElementById('copyMoveConfirmLabel');
  const copyMoveSource = document.getElementById('copyMoveSource');
  const copyMoveDestBucket = document.getElementById('copyMoveDestBucket');
  const copyMoveDestKey = document.getElementById('copyMoveDestKey');
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
        const currentBucket = objectsContainer?.dataset.bucket || '';
        copyMoveDestBucket.innerHTML = buckets.map(b => `<option value="${escapeHtml(b)}"${b === currentBucket ? ' selected' : ''}>${escapeHtml(b)}</option>`).join('');
        if (currentBucket && buckets.includes(currentBucket)) copyMoveDestBucket.value = currentBucket;
      } catch {
        copyMoveDestBucket.innerHTML = '<option value="">Failed to load buckets</option>';
      }
    }
    window.UI.dialog.open(copyMoveModalEl);
  };

  document.getElementById('copyMoveForm')?.addEventListener('submit', async (event) => {
    event.preventDefault();
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
      window.UI.dialog.close(copyMoveModalEl);
      if (copyMoveAction === 'move') {
        previewEmpty.classList.remove('is-hidden');
        previewPanel.classList.add('is-hidden');
        activeRow = null;
      }
      const currentBucket = objectsContainer?.dataset.bucket;
      if (copyMoveAction === 'move' || destBucket === currentBucket) {
        loadObjects(false);
      }
      refreshBucketUsage();
    } catch (err) {
      showMessage({ title: `${copyMoveAction === 'move' ? 'Move' : 'Copy'} failed`, body: err.message, variant: 'danger' });
    }
  });

  const originalSelectRow = selectRow;
  selectRow = async (row) => {
    await originalSelectRow(row);
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
    const lifecycleTab = document.getElementById('lifecycle-tab');
    const lifecyclePane = document.getElementById('lifecycle-pane');
    const startLifecyclePolling = () => {
      if (window.pollingManager) {
        window.pollingManager.start('lifecycle', loadLifecycleHistory);
      } else {
        loadLifecycleHistory();
      }
    };
    const stopLifecyclePolling = () => {
      if (window.pollingManager) {
        window.pollingManager.stop('lifecycle');
      }
    };
    if (lifecyclePane && lifecyclePane.classList.contains('show') && lifecyclePane.classList.contains('active')) {
      startLifecyclePolling();
    }
    lifecycleTab?.addEventListener('shown.bs.tab', startLifecyclePolling);
    lifecycleTab?.addEventListener('hidden.bs.tab', stopLifecyclePolling);
  }

  if (corsCard) loadCorsRules();
  if (aclCard) loadAcl();

  function updateVersioningBadge(state) {
    var badge = document.querySelector('.badge.rounded-pill');
    if (!badge) return;
    var enabled = state === true || state === 'enabled';
    var suspended = state === 'suspended';
    badge.classList.remove('text-bg-success', 'text-bg-warning', 'text-bg-secondary');
    badge.classList.add(enabled ? 'text-bg-success' : suspended ? 'text-bg-warning' : 'text-bg-secondary');
    badge.classList.add('d-inline-flex', 'align-items-center');
    var icon = '<svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" fill="currentColor" class="me-1 flex-shrink-0" viewBox="0 0 16 16">' +
      '<path d="M8.515 1.019A7 7 0 0 0 8 1V0a8 8 0 0 1 .589.022l-.074.997zm2.004.45a7.003 7.003 0 0 0-.985-.299l.219-.976c.383.086.76.2 1.126.342l-.36.933zm1.37.71a7.01 7.01 0 0 0-.439-.27l.493-.87a8.025 8.025 0 0 1 .979.654l-.615.789a6.996 6.996 0 0 0-.418-.302zm1.834 1.79a6.99 6.99 0 0 0-.653-.796l.724-.69c.27.285.52.59.747.91l-.818.576zm.744 1.352a7.08 7.08 0 0 0-.214-.468l.893-.45a7.976 7.976 0 0 1 .45 1.088l-.95.313a7.023 7.023 0 0 0-.179-.483zm.53 2.507a6.991 6.991 0 0 0-.1-1.025l.985-.17c.067.386.106.778.116 1.17l-1 .025zm-.131 1.538c.033-.17.06-.339.081-.51l.993.123a7.957 7.957 0 0 1-.23 1.155l-.964-.267c.046-.165.086-.332.12-.501zm-.952 2.379c.184-.29.346-.594.486-.908l.914.405c-.16.36-.345.706-.555 1.038l-.845-.535zm-.964 1.205c.122-.122.239-.248.35-.378l.758.653a8.073 8.073 0 0 1-.401.432l-.707-.707z"/>' +
      '<path d="M8 1a7 7 0 1 0 4.95 11.95l.707.707A8.001 8.001 0 1 1 8 0v1z"/>' +
      '<path d="M7.5 3a.5.5 0 0 1 .5.5v5.21l3.248 1.856a.5.5 0 0 1-.496.868l-3.5-2A.5.5 0 0 1 7 9V3.5a.5.5 0 0 1 .5-.5z"/>' +
      '</svg>';
    badge.innerHTML = icon + (enabled ? 'Versioning On' : suspended ? 'Versioning Suspended' : 'Versioning Off');
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
    } else if (enabled) {
      var endpoint = window.BucketDetailConfig?.endpoints?.archivedObjects || '';
      if (endpoint) {
        var html = '<div class="card shadow-sm mt-4" id="archived-objects-card" data-archived-endpoint="' + endpoint + '">' +
          '<div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">' +
          '<div class="d-flex align-items-center">' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" class="text-warning me-2" viewBox="0 0 16 16">' +
          '<path d="M0 2a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1v7.5a2.5 2.5 0 0 1-2.5 2.5h-9A2.5 2.5 0 0 1 1 12.5V5a1 1 0 0 1-1-1V2zm2 3v7.5A1.5 1.5 0 0 0 3.5 14h9a1.5 1.5 0 0 0 1.5-1.5V5H2zm13-3H1v2h14V2zM5 7.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5z"/>' +
          '</svg><span class="fw-semibold">Archived Objects</span></div>' +
          '<div class="d-flex align-items-center gap-2">' +
          '<span class="badge text-bg-secondary is-hidden" data-archived-count></span>' +
          '<button class="btn btn-outline-secondary btn-sm" type="button" data-archived-refresh>' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
          '<path fill-rule="evenodd" d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2v1z"/>' +
          '<path d="M8 4.466V.534a.25.25 0 0 0-.41-.192L5.23 2.308a.25.25 0 0 0 0 .384l2.36 1.966A.25.25 0 0 0 8 4.466z"/>' +
          '</svg>Refresh</button></div></div>' +
          '<div class="card-body">' +
          '<p class="text-muted small mb-3">Objects that have been deleted while versioning is enabled. Their previous versions remain available until you restore or purge them.</p>' +
          '<div class="table-responsive"><table class="table table-sm table-hover align-middle mb-0">' +
          '<thead class="table-light"><tr>' +
          '<th scope="col"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1 text-muted" viewBox="0 0 16 16">' +
          '<path d="M4 0h5.293A1 1 0 0 1 10 .293L13.707 4a1 1 0 0 1 .293.707V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2zm5.5 1.5v2a1 1 0 0 0 1 1h2l-3-3z"/>' +
          '</svg>Key</th>' +
          '<th scope="col">Latest Version</th>' +
          '<th scope="col" class="text-center">Versions</th>' +
          '<th scope="col" class="text-end">Actions</th>' +
          '</tr></thead>' +
          '<tbody data-archived-body><tr><td colspan="4" class="text-center text-muted py-4">' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="mb-2 d-block mx-auto" viewBox="0 0 16 16">' +
          '<path d="M0 2a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v2a1 1 0 0 1-1 1v7.5a2.5 2.5 0 0 1-2.5 2.5h-9A2.5 2.5 0 0 1 1 12.5V5a1 1 0 0 1-1-1V2zm2 3v7.5A1.5 1.5 0 0 0 3.5 14h9a1.5 1.5 0 0 0 1.5-1.5V5H2zm13-3H1v2h14V2zM5 7.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5z"/>' +
          '</svg>No archived objects</td></tr></tbody>' +
          '</table></div></div></div>';
        card.insertAdjacentHTML('afterend', html);
        archivedCard = document.getElementById('archived-objects-card');
        archivedBody = archivedCard.querySelector('[data-archived-body]');
        archivedCountBadge = archivedCard.querySelector('[data-archived-count]');
        archivedRefreshButton = archivedCard.querySelector('[data-archived-refresh]');
        archivedEndpoint = endpoint;
        archivedItemsCache = null;
        archivedRefreshButton.addEventListener('click', function() { loadArchivedObjects(true); });
        if (!archivedObjectsChip) {
          archivedObjectsChip = document.createElement('button');
          archivedObjectsChip.type = 'button';
          archivedObjectsChip.id = 'archived-objects-chip';
          archivedObjectsChip.className = 'btn btn-link btn-sm py-0 px-1 text-decoration-none is-hidden';
          document.getElementById('pagination-controls')?.appendChild(archivedObjectsChip);
          archivedObjectsChip.addEventListener('click', function() {
            if (archivedObjectsChip.dataset.state === 'error') {
              loadArchivedObjects(true);
              return;
            }
            if (!propertiesTab) return;
            propertiesTab.dataset.scrollToArchived = 'true';
            bootstrap.Tab.getOrCreateInstance(propertiesTab).show();
            if (propertiesTab.classList.contains('active')) {
              propertiesTab.dataset.scrollToArchived = 'false';
              archivedCard?.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
          });
        }
        loadArchivedObjects();
      }
    }

    var dropZone = document.getElementById('objects-drop-zone');
    if (dropZone) {
      dropZone.setAttribute('data-versioning', enabled ? 'true' : 'false');
    }

    var bulkPurgeWrap = document.getElementById('bulkDeletePurgeWrap');
    if (bulkPurgeWrap) {
      bulkPurgeWrap.classList.toggle('is-hidden', !enabled);
    }
    var singleDeleteVerWrap = document.getElementById('deleteObjectVersioningWrap');
    if (singleDeleteVerWrap) {
      singleDeleteVerWrap.classList.toggle('is-hidden', !enabled);
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

    var objectsCard = document.querySelector('[data-usage-objects]');
    if (objectsCard) {
      objectsCard.dataset.maxObjects = maxObjects && maxObjects > 0 ? String(maxObjects) : '';
    }
    var bytesCard = document.querySelector('[data-usage-bytes]');
    if (bytesCard) {
      bytesCard.dataset.maxBytes = maxBytes && maxBytes > 0 ? String(maxBytes) : '';
    }
    redrawUsageLimits();
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
      updateVersioningBadge('suspended');
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

  interceptForm('websiteForm', {
    successMessage: 'Website settings saved',
    onSuccess: function (data) {
      updateWebsiteCard(data.enabled !== false, data.index_document, data.error_document);
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

  var confirmDisableEncBtn = document.getElementById('confirmDisableEncryptionBtn');
  if (confirmDisableEncBtn) {
    confirmDisableEncBtn.addEventListener('click', function () {
      var form = document.getElementById('encryptionForm');
      if (!form) return;
      document.getElementById('encryptionAction').value = 'disable';
      var modalEl = document.getElementById('disableEncryptionModal');
      var modal = modalEl ? bootstrap.Modal.getInstance(modalEl) : null;
      window.UICore.submitFormAjax(form, {
        successMessage: 'Encryption disabled',
        onSuccess: function (data) {
          document.getElementById('encryptionAction').value = 'enable';
          if (modal) modal.hide();
          updateEncryptionCard(false, null);
        },
        onError: function () {
          document.getElementById('encryptionAction').value = 'enable';
          if (modal) modal.hide();
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

  function updateWebsiteCard(enabled, indexDoc, errorDoc) {
    var card = document.getElementById('bucket-website-card');
    if (!card) return;
    var alertContainer = card.querySelector('.alert');
    if (alertContainer) {
      if (enabled) {
        alertContainer.className = 'alert alert-success d-flex align-items-start mb-4';
        var detail = 'Index: <code>' + escapeHtml(indexDoc || 'index.html') + '</code>';
        if (errorDoc) detail += '<br>Error: <code>' + escapeHtml(errorDoc) + '</code>';
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>' +
          '</svg><div><strong>Website hosting is enabled</strong>' +
          '<p class="mb-0 small">' + detail + '</p></div>';
      } else {
        alertContainer.className = 'alert alert-secondary d-flex align-items-start mb-4';
        alertContainer.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="me-2 flex-shrink-0" viewBox="0 0 16 16">' +
          '<path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>' +
          '<path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/>' +
          '</svg><div><strong>Website hosting is disabled</strong>' +
          '<p class="mb-0 small">Enable website hosting to serve bucket contents as a static website.</p></div>';
      }
    }
    var disableBtn = document.getElementById('disableWebsiteBtn');
    if (disableBtn) {
      disableBtn.style.display = enabled ? '' : 'none';
    }
    var submitBtn = document.getElementById('websiteSubmitBtn');
    if (submitBtn) {
      submitBtn.classList.remove('btn-primary', 'btn-success');
      submitBtn.classList.add(enabled ? 'btn-primary' : 'btn-success');
    }
    var submitLabel = document.getElementById('websiteSubmitLabel');
    if (submitLabel) {
      submitLabel.textContent = enabled ? 'Save Website Settings' : 'Enable Website Hosting';
    }
  }

  var disableWebsiteBtn = document.getElementById('disableWebsiteBtn');
  if (disableWebsiteBtn) {
    disableWebsiteBtn.addEventListener('click', function () {
      var form = document.getElementById('websiteForm');
      if (!form) return;
      document.getElementById('websiteAction').value = 'disable';
      window.UICore.submitFormAjax(form, {
        successMessage: 'Website hosting disabled',
        onSuccess: function (data) {
          document.getElementById('websiteAction').value = 'enable';
          updateWebsiteCard(false, null, null);
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
          sessionStorage.setItem('flashMessage', JSON.stringify({ title: 'Success', body: 'Bucket deleted', variant: 'success' }));
          window.location.href = window.BucketDetailConfig?.endpoints?.bucketsOverview || '/ui/buckets';
        }
      });
    });
  }

  window.BucketDetailConfig = window.BucketDetailConfig || {};

})();
