window.BucketDetailOperations = (function() {
  'use strict';

  let showMessage = function() {};
  let escapeHtml = function(s) { return s; };

  function init(config) {
    showMessage = config.showMessage || showMessage;
    escapeHtml = config.escapeHtml || escapeHtml;
  }

  async function loadLifecycleRules(card, endpoint) {
    if (!card || !endpoint) return;
    const body = card.querySelector('[data-lifecycle-body]');
    if (!body) return;

    try {
      const response = await fetch(endpoint);
      const data = await response.json();

      if (!response.ok) {
        body.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">${escapeHtml(data.error || 'Failed to load')}</td></tr>`;
        return;
      }

      const rules = data.rules || [];
      if (rules.length === 0) {
        body.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No lifecycle rules configured</td></tr>';
        return;
      }

      body.innerHTML = rules.map(rule => {
        const actions = [];
        if (rule.expiration_days) actions.push(`Delete after ${rule.expiration_days} days`);
        if (rule.noncurrent_days) actions.push(`Delete old versions after ${rule.noncurrent_days} days`);
        if (rule.abort_mpu_days) actions.push(`Abort incomplete MPU after ${rule.abort_mpu_days} days`);

        return `
          <tr>
            <td class="fw-medium">${escapeHtml(rule.id)}</td>
            <td><code>${escapeHtml(rule.prefix || '(all)')}</code></td>
            <td>${actions.map(a => `<div class="small">${escapeHtml(a)}</div>`).join('')}</td>
            <td>
              <span class="badge ${rule.status === 'Enabled' ? 'text-bg-success' : 'text-bg-secondary'}">${escapeHtml(rule.status)}</span>
            </td>
            <td class="text-end">
              <button class="btn btn-sm btn-outline-danger" onclick="BucketDetailOperations.deleteLifecycleRule('${escapeHtml(rule.id)}')">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">
                  <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                  <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
                </svg>
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      body.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function loadCorsRules(card, endpoint) {
    if (!card || !endpoint) return;
    const body = document.getElementById('cors-rules-body');
    if (!body) return;

    try {
      const response = await fetch(endpoint);
      const data = await response.json();

      if (!response.ok) {
        body.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">${escapeHtml(data.error || 'Failed to load')}</td></tr>`;
        return;
      }

      const rules = data.rules || [];
      if (rules.length === 0) {
        body.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-3">No CORS rules configured</td></tr>';
        return;
      }

      body.innerHTML = rules.map((rule, idx) => `
        <tr>
          <td>${(rule.allowed_origins || []).map(o => `<code class="d-block">${escapeHtml(o)}</code>`).join('')}</td>
          <td>${(rule.allowed_methods || []).map(m => `<span class="badge text-bg-secondary me-1">${escapeHtml(m)}</span>`).join('')}</td>
          <td class="small text-muted">${(rule.allowed_headers || []).slice(0, 3).join(', ')}${(rule.allowed_headers || []).length > 3 ? '...' : ''}</td>
          <td class="text-muted">${rule.max_age_seconds || 0}s</td>
          <td class="text-end">
            <button class="btn btn-sm btn-outline-danger" onclick="BucketDetailOperations.deleteCorsRule(${idx})">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">
                <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5zm3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6z"/>
                <path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/>
              </svg>
            </button>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      body.innerHTML = `<tr><td colspan="5" class="text-center text-danger py-3">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function loadAcl(card, endpoint) {
    if (!card || !endpoint) return;
    const body = card.querySelector('[data-acl-body]');
    if (!body) return;

    try {
      const response = await fetch(endpoint);
      const data = await response.json();

      if (!response.ok) {
        body.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-3">${escapeHtml(data.error || 'Failed to load')}</td></tr>`;
        return;
      }

      const grants = data.grants || [];
      if (grants.length === 0) {
        body.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-3">No ACL grants configured</td></tr>';
        return;
      }

      body.innerHTML = grants.map(grant => {
        const grantee = grant.grantee_type === 'CanonicalUser'
          ? grant.display_name || grant.grantee_id
          : grant.grantee_uri || grant.grantee_type;
        return `
          <tr>
            <td class="fw-medium">${escapeHtml(grantee)}</td>
            <td><span class="badge text-bg-info">${escapeHtml(grant.permission)}</span></td>
            <td class="text-muted small">${escapeHtml(grant.grantee_type)}</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      body.innerHTML = `<tr><td colspan="3" class="text-center text-danger py-3">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  async function deleteLifecycleRule(ruleId) {
    if (!confirm(`Delete lifecycle rule "${ruleId}"?`)) return;
    const card = document.getElementById('lifecycle-rules-card');
    if (!card) return;
    const endpoint = card.dataset.lifecycleUrl;
    const csrfToken = window.getCsrfToken ? window.getCsrfToken() : '';

    try {
      const resp = await fetch(endpoint, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({ rule_id: ruleId })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to delete');
      showMessage({ title: 'Rule deleted', body: `Lifecycle rule "${ruleId}" has been deleted.`, variant: 'success' });
      loadLifecycleRules(card, endpoint);
    } catch (err) {
      showMessage({ title: 'Delete failed', body: err.message, variant: 'danger' });
    }
  }

  async function deleteCorsRule(index) {
    if (!confirm('Delete this CORS rule?')) return;
    const card = document.getElementById('cors-rules-card');
    if (!card) return;
    const endpoint = card.dataset.corsUrl;
    const csrfToken = window.getCsrfToken ? window.getCsrfToken() : '';

    try {
      const resp = await fetch(endpoint, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        body: JSON.stringify({ rule_index: index })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'Failed to delete');
      showMessage({ title: 'Rule deleted', body: 'CORS rule has been deleted.', variant: 'success' });
      loadCorsRules(card, endpoint);
    } catch (err) {
      showMessage({ title: 'Delete failed', body: err.message, variant: 'danger' });
    }
  }

  return {
    init: init,
    loadLifecycleRules: loadLifecycleRules,
    loadCorsRules: loadCorsRules,
    loadAcl: loadAcl,
    deleteLifecycleRule: deleteLifecycleRule,
    deleteCorsRule: deleteCorsRule
  };
})();
