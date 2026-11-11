(function () {
  var domainsConfig = document.getElementById('websiteDomainsConfig');
  function normalizeDomain(val) {
    val = val.trim().toLowerCase();
    if (val.indexOf('https://') === 0) val = val.substring(8);
    else if (val.indexOf('http://') === 0) val = val.substring(7);
    var slashIdx = val.indexOf('/');
    if (slashIdx !== -1) val = val.substring(0, slashIdx);
    var qIdx = val.indexOf('?');
    if (qIdx !== -1) val = val.substring(0, qIdx);
    var hIdx = val.indexOf('#');
    if (hIdx !== -1) val = val.substring(0, hIdx);
    var colonIdx = val.indexOf(':');
    if (colonIdx !== -1) val = val.substring(0, colonIdx);
    return val;
  }

  var domainInput = document.getElementById('domain');
  var preview = document.getElementById('domainPreview');
  var previewUrl = document.getElementById('domainPreviewUrl');
  if (domainInput && preview) {
    domainInput.addEventListener('input', function () {
      var clean = normalizeDomain(this.value);
      if (clean && /^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$/.test(clean)) {
        previewUrl.textContent = 'http://' + clean;
        preview.classList.remove('d-none');
      } else {
        preview.classList.add('d-none');
      }
    });

    var createForm = document.getElementById('createDomainForm');
    if (createForm) {
      createForm.addEventListener('submit', function () {
        domainInput.value = normalizeDomain(domainInput.value);
      });
    }
  }

  var editModal = document.getElementById('editDomainModal');
  if (editModal) {
    editModal.addEventListener('show.bs.modal', function (event) {
      var btn = event.relatedTarget;
      var domain = btn.getAttribute('data-domain');
      var bucket = btn.getAttribute('data-bucket');
      document.getElementById('editDomainName').value = domain;
      var editBucket = document.getElementById('editBucket');
      if (editBucket && editBucket.tagName === 'SELECT') {
        var stale = editBucket.querySelector('option[data-missing-bucket]');
        if (stale) stale.remove();
        editBucket.value = bucket;
        if (editBucket.value !== bucket) {
          var opt = document.createElement('option');
          opt.value = bucket;
          opt.textContent = bucket + ' (unavailable — no website hosting)';
          opt.setAttribute('data-missing-bucket', '');
          editBucket.appendChild(opt);
          editBucket.value = bucket;
        }
      } else if (editBucket) {
        editBucket.value = bucket;
      }
      document.getElementById('editDomainForm').action = domainsConfig.dataset.updateUrl.replace('__DOMAIN__', encodeURIComponent(domain));
    });
  }

  var deleteModal = document.getElementById('deleteDomainModal');
  if (deleteModal) {
    deleteModal.addEventListener('show.bs.modal', function (event) {
      var btn = event.relatedTarget;
      var domain = btn.getAttribute('data-domain');
      var bucket = btn.getAttribute('data-bucket') || '';
      document.getElementById('deleteDomainName').textContent = domain;
      document.getElementById('deleteBucketName').textContent = bucket;
      document.getElementById('deleteDomainForm').action = domainsConfig.dataset.deleteUrl.replace('__DOMAIN__', encodeURIComponent(domain));
    });
  }

  var DNS_CHECK_URL = domainsConfig.dataset.dnsCheckUrl;
  var DNS_ICONS = {
    unknown: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286zm1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94z"/></svg>',
    ok: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>',
    warning: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>',
    error: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293 5.354 4.646z"/></svg>'
  };
  var DNS_TONES = {
    unknown: 'text-muted',
    ok: 'text-success',
    warning: 'text-warning',
    error: 'text-danger'
  };

  function setDnsState(row, state, message, detail) {
    var icon = row.querySelector('.dns-status-icon');
    var text = row.querySelector('.dns-status-text');
    var button = row.querySelector('.dns-check-btn');
    if (icon) {
      icon.className = 'dns-status-icon ' + (DNS_TONES[state] || 'text-muted');
      icon.innerHTML = DNS_ICONS[state] || DNS_ICONS.unknown;
    }
    if (button) {
      button.setAttribute('title', detail || message || 'Check DNS for this domain');
    }
    if (text) {
      if (message) {
        text.className = 'small mt-1 dns-status-text ' + (DNS_TONES[state] || 'text-muted');
        text.textContent = message;
      } else {
        text.className = 'small mt-1 d-none dns-status-text';
        text.textContent = '';
      }
    }
  }

  function checkDns(row) {
    var domain = row.getAttribute('data-domain') || '';
    if (!domain) return Promise.resolve();
    var icon = row.querySelector('.dns-status-icon');
    if (icon) {
      icon.className = 'dns-status-icon text-muted';
      icon.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    }
    var text = row.querySelector('.dns-status-text');
    if (text) {
      text.className = 'small mt-1 text-muted dns-status-text';
      text.textContent = 'Checking DNS...';
    }
    return fetch(DNS_CHECK_URL.replace('__DOMAIN__', encodeURIComponent(domain)), {
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        setDnsState(row, data.status || 'error', data.message || 'DNS check returned no result.', data.detail);
      })
      .catch(function () {
        setDnsState(row, 'error', 'DNS check request failed.');
      });
  }

  document.querySelectorAll('.dns-check-btn').forEach(function (button) {
    button.addEventListener('click', function () {
      var row = button.closest('tr');
      if (row) checkDns(row);
    });
  });

  var checkAllBtn = document.getElementById('btnCheckAllDns');
  if (checkAllBtn) {
    checkAllBtn.addEventListener('click', function () {
      var rows = Array.prototype.slice.call(document.querySelectorAll('#domainTable tbody tr'))
        .filter(function (row) { return row.style.display !== 'none'; });
      if (!rows.length) return;
      checkAllBtn.disabled = true;
      Promise.all(rows.map(checkDns)).then(function () {
        checkAllBtn.disabled = false;
      });
    });
  }

  var searchInput = document.getElementById('domainSearch');
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      var q = this.value.toLowerCase();
      var rows = document.querySelectorAll('#domainTable tbody tr');
      var visible = 0;
      rows.forEach(function (row) {
        var domain = (row.getAttribute('data-domain') || '').toLowerCase();
        var bucket = (row.getAttribute('data-bucket') || '').toLowerCase();
        var match = !q || domain.indexOf(q) !== -1 || bucket.indexOf(q) !== -1;
        row.style.display = match ? '' : 'none';
        if (match) visible++;
      });
      var noResults = document.getElementById('noSearchResults');
      if (noResults) {
        noResults.classList.toggle('d-none', visible > 0);
      }
    });
  }
})();
