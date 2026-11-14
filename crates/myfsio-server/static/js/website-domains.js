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
        preview.hidden = false;
      } else {
        preview.hidden = true;
      }
    });

    var createForm = document.getElementById('createDomainForm');
    if (createForm) {
      createForm.addEventListener('submit', function () {
        domainInput.value = normalizeDomain(domainInput.value);
      });
    }
  }

  function openEdit(row, opener) {
    var domain = row.getAttribute('data-domain');
    var bucket = row.getAttribute('data-bucket');
    document.getElementById('editDomainName').value = domain;
    var editBucket = document.getElementById('editBucket');
    if (editBucket) {
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
    }
    document.getElementById('editDomainForm').action = domainsConfig.dataset.updateUrl.replace('__DOMAIN__', encodeURIComponent(domain));
    window.UI.dialog.open('#editDomainDialog', opener);
  }

  function openDelete(row, opener) {
    var domain = row.getAttribute('data-domain');
    document.getElementById('deleteDomainName').textContent = domain;
    document.getElementById('deleteBucketName').textContent = row.getAttribute('data-bucket') || '';
    document.getElementById('deleteDomainForm').action = domainsConfig.dataset.deleteUrl.replace('__DOMAIN__', encodeURIComponent(domain));
    window.UI.dialog.open('#deleteDomainDialog', opener);
  }

  document.addEventListener('click', function (event) {
    var btn = event.target.closest('[data-domain-action]');
    if (!btn) return;
    var row = btn.closest('tr');
    if (!row) return;
    if (btn.getAttribute('data-domain-action') === 'edit') openEdit(row, btn);
    else openDelete(row, btn);
  });

  var DNS_CHECK_URL = domainsConfig.dataset.dnsCheckUrl;
  var DNS_BADGES = {
    unknown: ['', 'Unknown'],
    ok: [' ui-badge-ok', 'Resolves here'],
    warning: [' ui-badge-warn', 'Check'],
    error: [' ui-badge-bad', 'Failed']
  };
  var DNS_TEXT_TONES = {
    ok: ' is-ok',
    warning: ' is-warn',
    error: ' is-bad'
  };

  function setDnsState(row, state, message, detail) {
    var text = row.querySelector('.dns-status-text');
    var button = row.querySelector('.dns-check-btn');
    var badge = DNS_BADGES[state] || DNS_BADGES.unknown;
    if (button) {
      button.className = 'ui-badge adm-badge-btn dns-check-btn' + badge[0];
      button.textContent = badge[1];
      button.setAttribute('data-ui-tip', detail || message || 'Check DNS for this domain');
    }
    if (text) {
      text.className = 'adm-sub dns-status-text' + (DNS_TEXT_TONES[state] || '');
      text.textContent = message || '';
      text.hidden = !message;
    }
  }

  function checkDns(row) {
    var domain = row.getAttribute('data-domain') || '';
    if (!domain) return Promise.resolve();
    var button = row.querySelector('.dns-check-btn');
    if (button) {
      button.className = 'ui-badge adm-badge-btn dns-check-btn';
      button.textContent = 'Checking…';
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
        .filter(function (row) { return !row.hidden; });
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
        row.hidden = !match;
        if (match) visible++;
      });
      var noResults = document.getElementById('noSearchResults');
      if (noResults) noResults.hidden = visible > 0;
      var wrap = document.querySelector('#domainTable').closest('.ui-table-wrap');
      if (wrap) wrap.hidden = visible === 0;
    });
  }
})();
