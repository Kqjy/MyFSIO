window.ConnectionsManagement = (function() {
  'use strict';

  var endpoints = {};
  var csrfToken = '';

  function init(config) {
    endpoints = config.endpoints || {};
    csrfToken = config.csrfToken || '';

    setupEventListeners();
    checkAllConnectionHealth();
  }

  function togglePassword(id) {
    var input = document.getElementById(id);
    if (input) {
      input.type = input.type === 'password' ? 'text' : 'password';
    }
  }

  async function testConnection(formId, resultId) {
    var form = document.getElementById(formId);
    var resultDiv = document.getElementById(resultId);
    if (!form || !resultDiv) return;

    var formData = new FormData(form);
    var data = {};
    formData.forEach(function(value, key) {
      if (key !== 'csrf_token') {
        data[key] = value;
      }
    });

    resultDiv.innerHTML = '<div class="text-info"><span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Testing connection...</div>';

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
      if (response.ok) {
        resultDiv.innerHTML = '<div class="text-success">' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
          '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>' +
          '</svg>' + window.UICore.escapeHtml(result.message) + '</div>';
      } else {
        resultDiv.innerHTML = '<div class="text-danger">' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
          '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293 5.354 4.646z"/>' +
          '</svg>' + window.UICore.escapeHtml(result.message) + '</div>';
      }
    } catch (error) {
      clearTimeout(timeoutId);
      var message = error.name === 'AbortError'
        ? 'Connection test timed out - endpoint may be unreachable'
        : 'Connection failed: Network error';
      resultDiv.innerHTML = '<div class="text-danger">' +
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
        '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293 5.354 4.646z"/>' +
        '</svg>' + message + '</div>';
    }
  }

  async function checkConnectionHealth(connectionId, statusEl) {
    if (!statusEl) return;

    try {
      var controller = new AbortController();
      var timeoutId = setTimeout(function() { controller.abort(); }, 15000);

      var response = await fetch(endpoints.healthTemplate.replace('CONNECTION_ID', connectionId), {
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      var data = await response.json();
      if (data.healthy) {
        statusEl.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="text-success" viewBox="0 0 16 16">' +
          '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>';
        statusEl.setAttribute('data-status', 'healthy');
        statusEl.setAttribute('title', 'Connected');
      } else {
        statusEl.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="text-danger" viewBox="0 0 16 16">' +
          '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293 5.354 4.646z"/></svg>';
        statusEl.setAttribute('data-status', 'unhealthy');
        statusEl.setAttribute('title', data.error || 'Unreachable');
      }
    } catch (error) {
      statusEl.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="text-warning" viewBox="0 0 16 16">' +
        '<path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>';
      statusEl.setAttribute('data-status', 'unknown');
      statusEl.setAttribute('title', 'Could not check status');
    }
  }

  function checkAllConnectionHealth() {
    var rows = document.querySelectorAll('tr[data-connection-id]');
    rows.forEach(function(row, index) {
      var connectionId = row.getAttribute('data-connection-id');
      var statusEl = row.querySelector('.connection-status');
      if (statusEl) {
        setTimeout(function() {
          checkConnectionHealth(connectionId, statusEl);
        }, index * 200);
      }
    });
  }

  function updateConnectionCount() {
    var countBadge = document.querySelector('.badge.bg-primary.bg-opacity-10.text-primary.fs-6');
    if (countBadge) {
      var remaining = document.querySelectorAll('tr[data-connection-id]').length;
      countBadge.textContent = remaining + ' connection' + (remaining !== 1 ? 's' : '');
    }
  }

  function createConnectionRowHtml(conn) {
    var ak = conn.access_key || '';
    var maskedKey = ak.length > 12 ? ak.slice(0, 8) + '...' + ak.slice(-4) : ak;

    return '<tr data-connection-id="' + window.UICore.escapeHtml(conn.id) + '">' +
      '<td class="text-center">' +
      '<span class="connection-status" data-status="checking" title="Checking...">' +
      '<span class="spinner-border spinner-border-sm text-muted" role="status" style="width: 12px; height: 12px;"></span>' +
      '</span></td>' +
      '<td><div class="d-flex align-items-center gap-2">' +
      '<div class="connection-icon"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">' +
      '<path d="M4.406 3.342A5.53 5.53 0 0 1 8 2c2.69 0 4.923 2 5.166 4.579C14.758 6.804 16 8.137 16 9.773 16 11.569 14.502 13 12.687 13H3.781C1.708 13 0 11.366 0 9.318c0-1.763 1.266-3.223 2.942-3.593.143-.863.698-1.723 1.464-2.383z"/></svg></div>' +
      '<span class="fw-medium">' + window.UICore.escapeHtml(conn.name) + '</span>' +
      '</div></td>' +
      '<td><span class="text-muted small text-truncate d-inline-block" style="max-width: 200px;" title="' + window.UICore.escapeHtml(conn.endpoint_url) + '">' + window.UICore.escapeHtml(conn.endpoint_url) + '</span></td>' +
      '<td><span class="badge bg-primary bg-opacity-10 text-primary">' + window.UICore.escapeHtml(conn.region) + '</span></td>' +
      '<td><code class="small">' + window.UICore.escapeHtml(maskedKey) + '</code></td>' +
      '<td class="text-end"><div class="btn-group btn-group-sm" role="group">' +
      '<button type="button" class="btn btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#editConnectionModal" ' +
      'data-id="' + window.UICore.escapeHtml(conn.id) + '" data-name="' + window.UICore.escapeHtml(conn.name) + '" ' +
      'data-endpoint="' + window.UICore.escapeHtml(conn.endpoint_url) + '" data-region="' + window.UICore.escapeHtml(conn.region) + '" ' +
      'data-access="' + window.UICore.escapeHtml(conn.access_key) + '" data-secret="' + window.UICore.escapeHtml(conn.secret_key || '') + '" title="Edit connection">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16">' +
      '<path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168l10-10zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293l6.5-6.5z"/></svg></button>' +
      '<button type="button" class="btn btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteConnectionModal" ' +
      'data-id="' + window.UICore.escapeHtml(conn.id) + '" data-name="' + window.UICore.escapeHtml(conn.name) + '" title="Delete connection">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16">' +
      '<path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>' +
      '<path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/></svg></button>' +
      '</div></td></tr>';
  }

  function setupEventListeners() {
    var testBtn = document.getElementById('testConnectionBtn');
    if (testBtn) {
      testBtn.addEventListener('click', function() {
        testConnection('createConnectionForm', 'testResult');
      });
    }

    var editTestBtn = document.getElementById('editTestConnectionBtn');
    if (editTestBtn) {
      editTestBtn.addEventListener('click', function() {
        testConnection('editConnectionForm', 'editTestResult');
      });
    }

    var editModal = document.getElementById('editConnectionModal');
    if (editModal) {
      editModal.addEventListener('show.bs.modal', function(event) {
        var button = event.relatedTarget;
        if (!button) return;

        var id = button.getAttribute('data-id');

        document.getElementById('edit_name').value = button.getAttribute('data-name') || '';
        document.getElementById('edit_endpoint_url').value = button.getAttribute('data-endpoint') || '';
        document.getElementById('edit_region').value = button.getAttribute('data-region') || '';
        document.getElementById('edit_access_key').value = button.getAttribute('data-access') || '';
        document.getElementById('edit_secret_key').value = button.getAttribute('data-secret') || '';
        document.getElementById('editTestResult').innerHTML = '';

        var form = document.getElementById('editConnectionForm');
        form.action = endpoints.updateTemplate.replace('CONNECTION_ID', id);
      });
    }

    var deleteModal = document.getElementById('deleteConnectionModal');
    if (deleteModal) {
      deleteModal.addEventListener('show.bs.modal', function(event) {
        var button = event.relatedTarget;
        if (!button) return;

        var id = button.getAttribute('data-id');
        var name = button.getAttribute('data-name');

        document.getElementById('deleteConnectionName').textContent = name;
        var form = document.getElementById('deleteConnectionForm');
        form.action = endpoints.deleteTemplate.replace('CONNECTION_ID', id);
      });
    }

    var createForm = document.getElementById('createConnectionForm');
    if (createForm) {
      createForm.addEventListener('submit', function(e) {
        e.preventDefault();
        window.UICore.submitFormAjax(createForm, {
          successMessage: 'Connection created',
          onSuccess: function(data) {
            createForm.reset();
            document.getElementById('testResult').innerHTML = '';

            if (data.connection) {
              var emptyState = document.querySelector('.empty-state');
              if (emptyState) {
                var cardBody = emptyState.closest('.card-body');
                if (cardBody) {
                  cardBody.innerHTML = '<div class="table-responsive"><table class="table table-hover align-middle mb-0">' +
                    '<thead class="table-light"><tr>' +
                    '<th scope="col" style="width: 50px;">Status</th>' +
                    '<th scope="col">Name</th><th scope="col">Endpoint</th>' +
                    '<th scope="col">Region</th><th scope="col">Access Key</th>' +
                    '<th scope="col" class="text-end">Actions</th></tr></thead>' +
                    '<tbody></tbody></table></div>';
                }
              }

              var tbody = document.querySelector('table tbody');
              if (tbody) {
                tbody.insertAdjacentHTML('beforeend', createConnectionRowHtml(data.connection));
                var newRow = tbody.lastElementChild;
                var statusEl = newRow.querySelector('.connection-status');
                if (statusEl) {
                  checkConnectionHealth(data.connection.id, statusEl);
                }
              }
              updateConnectionCount();
            } else {
              location.reload();
            }
          }
        });
      });
    }

    var editForm = document.getElementById('editConnectionForm');
    if (editForm) {
      editForm.addEventListener('submit', function(e) {
        e.preventDefault();
        window.UICore.submitFormAjax(editForm, {
          successMessage: 'Connection updated',
          onSuccess: function(data) {
            var modal = bootstrap.Modal.getInstance(document.getElementById('editConnectionModal'));
            if (modal) modal.hide();

            var connId = editForm.action.split('/').slice(-2)[0];
            var row = document.querySelector('tr[data-connection-id="' + connId + '"]');
            if (row && data.connection) {
              var nameCell = row.querySelector('.fw-medium');
              if (nameCell) nameCell.textContent = data.connection.name;

              var endpointCell = row.querySelector('.text-truncate');
              if (endpointCell) {
                endpointCell.textContent = data.connection.endpoint_url;
                endpointCell.title = data.connection.endpoint_url;
              }

              var regionBadge = row.querySelector('.badge.bg-primary');
              if (regionBadge) regionBadge.textContent = data.connection.region;

              var accessCode = row.querySelector('code.small');
              if (accessCode && data.connection.access_key) {
                var ak = data.connection.access_key;
                accessCode.textContent = ak.slice(0, 8) + '...' + ak.slice(-4);
              }

              var editBtn = row.querySelector('[data-bs-target="#editConnectionModal"]');
              if (editBtn) {
                editBtn.setAttribute('data-name', data.connection.name);
                editBtn.setAttribute('data-endpoint', data.connection.endpoint_url);
                editBtn.setAttribute('data-region', data.connection.region);
                editBtn.setAttribute('data-access', data.connection.access_key);
                if (data.connection.secret_key) {
                  editBtn.setAttribute('data-secret', data.connection.secret_key);
                }
              }

              var deleteBtn = row.querySelector('[data-bs-target="#deleteConnectionModal"]');
              if (deleteBtn) {
                deleteBtn.setAttribute('data-name', data.connection.name);
              }

              var statusEl = row.querySelector('.connection-status');
              if (statusEl) {
                checkConnectionHealth(connId, statusEl);
              }
            }
          }
        });
      });
    }

    var deleteForm = document.getElementById('deleteConnectionForm');
    if (deleteForm) {
      deleteForm.addEventListener('submit', function(e) {
        e.preventDefault();
        window.UICore.submitFormAjax(deleteForm, {
          successMessage: 'Connection deleted',
          onSuccess: function(data) {
            var modal = bootstrap.Modal.getInstance(document.getElementById('deleteConnectionModal'));
            if (modal) modal.hide();

            var connId = deleteForm.action.split('/').slice(-2)[0];
            var row = document.querySelector('tr[data-connection-id="' + connId + '"]');
            if (row) {
              row.remove();
            }

            updateConnectionCount();

            if (document.querySelectorAll('tr[data-connection-id]').length === 0) {
              location.reload();
            }
          }
        });
      });
    }
  }

  return {
    init: init,
    togglePassword: togglePassword,
    testConnection: testConnection,
    checkConnectionHealth: checkConnectionHealth
  };
})();
