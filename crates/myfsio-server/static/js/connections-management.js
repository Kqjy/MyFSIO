window.ConnectionsManagement = (function() {
  'use strict';

  var endpoints = {};
  var csrfToken = '';
  var tuningFields = [
    ['tuning_profile', 'tuningProfile'],
    ['tuning_part_size_mb', 'tuningPartSizeMb'],
    ['tuning_concurrency', 'tuningConcurrency'],
    ['tuning_buffer_kb', 'tuningBufferKb'],
    ['tuning_in_place_retries', 'tuningInPlaceRetries']
  ];

  function byId(id) {
    return document.getElementById(id);
  }

  function maskKey(key) {
    key = key || '';
    return key.length > 12 ? key.slice(0, 8) + '...' + key.slice(-4) : key;
  }

  function setTestResult(kind, message) {
    var el = byId('connectionTestResult');
    if (!el) return;
    el.hidden = !message;
    el.className = 'adm-test-result' + (kind ? ' is-' + kind : '');
    el.textContent = message || '';
  }

  async function testConnection() {
    var form = byId('connectionForm');
    if (!form) return;

    var data = {};
    new FormData(form).forEach(function(value, key) {
      if (key !== 'csrf_token') data[key] = value;
    });

    setTestResult('', 'Testing connection…');

    var controller = new AbortController();
    var timeoutId = setTimeout(function() { controller.abort(); }, 20000);

    try {
      var response = await fetch(endpoints.test, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken
        },
        body: JSON.stringify(data),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      var result = await response.json();
      setTestResult(response.ok ? 'ok' : 'bad', result.message);
    } catch (error) {
      clearTimeout(timeoutId);
      setTestResult('bad', error.name === 'AbortError'
        ? 'Connection test timed out - endpoint may be unreachable'
        : 'Connection failed: Network error');
    }
  }

  function setStatus(statusEl, status, label, detail) {
    var tone = { healthy: ' ui-badge-ok', unhealthy: ' ui-badge-bad', unknown: ' ui-badge-warn' }[status] || '';
    statusEl.className = 'ui-badge connection-status' + tone;
    statusEl.setAttribute('data-status', status);
    statusEl.textContent = label;
    if (detail) statusEl.setAttribute('data-ui-tip', detail);
    else statusEl.removeAttribute('data-ui-tip');
  }

  async function checkConnectionHealth(connectionId, statusEl) {
    if (!statusEl) return;
    setStatus(statusEl, 'checking', 'Checking');

    try {
      var controller = new AbortController();
      var timeoutId = setTimeout(function() { controller.abort(); }, 10000);
      var response = await fetch(endpoints.healthTemplate.replace('CONNECTION_ID', connectionId), {
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      var data = await response.json();
      if (data.healthy) setStatus(statusEl, 'healthy', 'Connected');
      else setStatus(statusEl, 'unhealthy', 'Unreachable', data.error || '');
    } catch (error) {
      setStatus(statusEl, 'unknown', 'Unknown', 'Could not check status');
    }
  }

  function checkAllConnectionHealth() {
    document.querySelectorAll('tr[data-connection-id]').forEach(function(row, index) {
      var statusEl = row.querySelector('.connection-status');
      setTimeout(function() {
        checkConnectionHealth(row.getAttribute('data-connection-id'), statusEl);
      }, index * 200);
    });
  }

  function fillRow(row, conn) {
    row.setAttribute('data-connection-id', conn.id);
    row.dataset.name = conn.name || '';
    row.dataset.endpoint = conn.endpoint_url || '';
    row.dataset.region = conn.region || '';
    if (conn.access_key) row.dataset.access = conn.access_key;
    tuningFields.forEach(function(field) {
      var value = conn[field[0]];
      row.dataset[field[1]] = value === null || value === undefined ? '' : String(value);
    });
    row.querySelector('.conn-name').textContent = row.dataset.name;
    row.querySelector('.conn-endpoint').textContent = row.dataset.endpoint;
    row.querySelector('.conn-region').textContent = row.dataset.region;
    row.querySelector('.conn-access-key').textContent = maskKey(row.dataset.access);
  }

  function rowFor(connectionId) {
    return document.querySelector('tr[data-connection-id="' + CSS.escape(connectionId) + '"]');
  }

  function syncEmptyState() {
    var hasRows = document.querySelectorAll('tr[data-connection-id]').length > 0;
    byId('connectionsTableWrap').hidden = !hasRows;
    byId('connectionsEmpty').hidden = hasRows;
  }

  function openConnectionDialog(row, opener) {
    var form = byId('connectionForm');
    var editing = !!row;
    var secret = byId('conn_secret_key');
    form.reset();
    form.dataset.connectionId = editing ? row.getAttribute('data-connection-id') : '';
    form.action = editing
      ? endpoints.updateTemplate.replace('CONNECTION_ID', form.dataset.connectionId)
      : endpoints.create;

    if (editing) {
      byId('conn_name').value = row.dataset.name || '';
      byId('conn_endpoint_url').value = row.dataset.endpoint || '';
      byId('conn_region').value = row.dataset.region || '';
      byId('conn_access_key').value = row.dataset.access || '';
      tuningFields.forEach(function(field) {
        byId('conn_' + field[0]).value = row.dataset[field[1]] || '';
      });
    }

    secret.type = 'password';
    secret.required = !editing;
    byId('conn_secret_hint').hidden = !editing;
    byId('connSecretToggle').textContent = 'Show';
    byId('connSecretToggle').setAttribute('aria-pressed', 'false');
    byId('connectionDialogTitle').textContent = editing ? 'Edit connection' : 'Add connection';
    byId('connectionSubmitBtn').textContent = editing ? 'Save' : 'Add connection';
    setTestResult('', '');
    window.UI.dialog.open('#connectionDialog', opener);
  }

  function openDeleteDialog(row, opener) {
    var form = byId('deleteConnectionForm');
    form.dataset.connectionId = row.getAttribute('data-connection-id');
    form.action = endpoints.deleteTemplate.replace('CONNECTION_ID', form.dataset.connectionId);
    byId('deleteConnectionName').textContent = row.dataset.name || '';
    window.UI.dialog.open('#deleteConnectionDialog', opener);
  }

  function setupEventListeners() {
    byId('addConnectionBtn').addEventListener('click', function(event) {
      openConnectionDialog(null, event.currentTarget);
    });

    byId('connectionsBody').addEventListener('click', function(event) {
      var button = event.target.closest('[data-connection-action]');
      if (!button) return;
      var row = button.closest('tr[data-connection-id]');
      if (!row) return;
      if (button.getAttribute('data-connection-action') === 'edit') openConnectionDialog(row, button);
      else openDeleteDialog(row, button);
    });

    byId('testConnectionBtn').addEventListener('click', testConnection);

    byId('connSecretToggle').addEventListener('click', function(event) {
      var secret = byId('conn_secret_key');
      var reveal = secret.type === 'password';
      secret.type = reveal ? 'text' : 'password';
      event.currentTarget.textContent = reveal ? 'Hide' : 'Show';
      event.currentTarget.setAttribute('aria-pressed', reveal ? 'true' : 'false');
    });

    var form = byId('connectionForm');
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      var connId = form.dataset.connectionId || '';
      window.UICore.submitFormAjax(form, {
        successMessage: connId ? 'Connection updated' : 'Connection created',
        onSuccess: function(data) {
          if (!data.connection) {
            location.reload();
            return;
          }
          window.UI.dialog.close('#connectionDialog');
          var row = connId ? rowFor(connId) : null;
          if (!row) {
            row = byId('connectionRowTemplate').content.firstElementChild.cloneNode(true);
            byId('connectionsBody').appendChild(row);
          }
          fillRow(row, data.connection);
          syncEmptyState();
          checkConnectionHealth(data.connection.id, row.querySelector('.connection-status'));
        }
      });
    });

    var deleteForm = byId('deleteConnectionForm');
    deleteForm.addEventListener('submit', function(event) {
      event.preventDefault();
      window.UICore.submitFormAjax(deleteForm, {
        successMessage: 'Connection deleted',
        onSuccess: function() {
          window.UI.dialog.close('#deleteConnectionDialog');
          var row = rowFor(deleteForm.dataset.connectionId || '');
          if (row) row.remove();
          syncEmptyState();
        }
      });
    });
  }

  function init(config) {
    endpoints = config.endpoints || {};
    csrfToken = config.csrfToken || '';
    setupEventListeners();
    checkAllConnectionHealth();
  }

  return {
    init: init,
    testConnection: testConnection,
    checkConnectionHealth: checkConnectionHealth
  };
})();

(function() {
  var el = document.getElementById('connectionsConfig');
  if (!el) return;
  var data = el.dataset;
  ConnectionsManagement.init({
    csrfToken: data.csrfToken,
    endpoints: {
      test: data.test,
      create: data.create,
      updateTemplate: data.updateTemplate,
      deleteTemplate: data.deleteTemplate,
      healthTemplate: data.healthTemplate
    }
  });
})();
