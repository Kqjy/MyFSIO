window.IAMManagement = (function() {
  'use strict';

  var users = [];
  var currentUserKey = null;
  var endpoints = {};
  var csrfToken = '';
  var selectedId = null;
  var draft = [];
  var dirty = false;
  var rotateUserId = null;

  var GRID_ACTIONS = ['list', 'read', 'write', 'delete'];

  var ALL_S3_ACTIONS = [
    'list', 'read', 'write', 'delete', 'share', 'policy',
    'replication', 'lifecycle', 'cors',
    'create_bucket', 'delete_bucket',
    'versioning', 'tagging', 'encryption', 'quota',
    'object_lock', 'notification', 'logging', 'website'
  ];

  var policyTemplates = {
    full: [{ bucket: '*', actions: ['*'] }],
    readonly: [{ bucket: '*', actions: ['list', 'read'] }],
    writer: [{ bucket: '*', actions: ['list', 'read', 'write'] }],
    operator: [{ bucket: '*', actions: ['list', 'read', 'write', 'delete', 'create_bucket', 'delete_bucket'] }],
    bucketadmin: [{ bucket: '*', actions: ['list', 'read', 'write', 'delete', 'share', 'policy', 'create_bucket', 'delete_bucket', 'versioning', 'tagging', 'encryption', 'cors', 'lifecycle', 'quota', 'object_lock', 'notification', 'logging', 'website', 'replication'] }]
  };

  var EXPIRY_PRESETS = { '1h': 3600000, '24h': 86400000, '7d': 7 * 86400000, '30d': 30 * 86400000, '90d': 90 * 86400000 };

  function byId(id) {
    return document.getElementById(id);
  }

  function isDenyPolicy(p) {
    return String(p.effect || 'Allow').toLowerCase() === 'deny';
  }

  function isConditional(p) {
    return !!p.condition && typeof p.condition === 'object';
  }

  function hasPrefix(p) {
    var prefix = (p.prefix === undefined || p.prefix === null) ? '*' : String(p.prefix).trim();
    return prefix !== '' && prefix !== '*';
  }

  function hasWildcardAction(p) {
    return (p.actions || []).indexOf('*') >= 0;
  }

  function isAdminUser(policies) {
    if (!policies || !policies.length) return false;
    if (policies.some(isDenyPolicy)) return false;
    return policies.some(function(p) {
      return p.bucket === '*' && hasWildcardAction(p) && !hasPrefix(p) && !isConditional(p);
    });
  }

  function getPermissionLevel(actions) {
    if (!actions || !actions.length) return 'no actions';
    if (actions.indexOf('*') >= 0) return 'full access';
    if (ALL_S3_ACTIONS.every(function(a) { return actions.indexOf(a) >= 0; })) return 'full access';
    var has = function(a) { return actions.indexOf(a) >= 0; };
    if (has('list') && has('read') && has('write') && has('delete')) return 'read/write/delete';
    if (has('list') && has('read') && has('write')) return 'read/write';
    if (has('list') && has('read')) return 'read only';
    return 'custom';
  }

  function accessSummary(policies) {
    policies = policies || [];
    if (isAdminUser(policies)) return { label: 'Admin', tone: 'ui-badge-bad' };
    var allows = policies.filter(function(p) { return !isDenyPolicy(p); });
    if (!allows.length) return { label: 'No access', tone: '' };
    var buckets = [];
    var levels = [];
    allows.forEach(function(p) {
      if (buckets.indexOf(p.bucket) < 0) buckets.push(p.bucket);
      var level = getPermissionLevel(p.actions);
      if (levels.indexOf(level) < 0) levels.push(level);
    });
    var scope = buckets.indexOf('*') >= 0
      ? 'All buckets'
      : buckets.length + ' bucket' + (buckets.length !== 1 ? 's' : '');
    var label = scope + ' · ' + (levels.length === 1 ? levels[0] : 'mixed');
    if (allows.length !== policies.length) label += ' · deny rules';
    return { label: label, tone: 'ui-badge-accent' };
  }

  function expiryState(expiresAt) {
    if (!expiresAt) return { label: 'Never', tone: null };
    var when = new Date(expiresAt);
    if (isNaN(when.getTime())) return { label: String(expiresAt), tone: null };
    var remaining = when.getTime() - Date.now();
    if (remaining <= 0) return { label: 'Expired', tone: 'ui-badge-bad', when: when };
    if (remaining <= 7 * 86400000) return { label: 'Expiring soon', tone: 'ui-badge-warn', when: when };
    return { label: when.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }), tone: null, when: when };
  }

  function buildUserUrl(template, userId) {
    return template.replace('USER_ID', encodeURIComponent(userId));
  }

  function getUser(userId) {
    return users.find(function(u) { return u.user_id === userId; }) || null;
  }

  function rowFor(userId) {
    return document.querySelector('.iam-user-item[data-user-id="' + CSS.escape(userId) + '"]');
  }

  function initials(name) {
    return String(name || '').slice(0, 2);
  }

  function clonePolicies(policies) {
    return JSON.parse(JSON.stringify(policies || []));
  }

  function toLocalInput(date) {
    return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  }

  function fillRow(row, user) {
    var name = user.display_name || user.access_key;
    row.setAttribute('data-user-id', user.user_id);
    row.setAttribute('data-access-key', user.access_key);
    row.setAttribute('data-display-name', name.toLowerCase());
    row.setAttribute('data-access-key-filter', String(user.access_key || '').toLowerCase());
    row.querySelector('.ak-avatar').textContent = initials(name);
    row.querySelector('.ak-user-name').textContent = name;
    row.querySelector('.ak-user-key').textContent = user.access_key;
    fillRowAccess(row, user);
    fillRowExpiry(row, user);
  }

  function fillRowAccess(row, user) {
    var summary = accessSummary(user.policies);
    var badge = row.querySelector('.ak-user-access');
    badge.className = 'ui-badge ak-user-access' + (summary.tone ? ' ' + summary.tone : '');
    badge.textContent = summary.label;
  }

  function fillRowExpiry(row, user) {
    var state = expiryState(user.expires_at);
    var el = document.createElement('span');
    el.className = state.tone ? 'ui-badge ' + state.tone : 'ui-muted';
    el.textContent = state.label;
    if (state.when) el.setAttribute('data-ui-tip', state.when.toLocaleString());
    row.querySelector('.ak-user-expiry').replaceChildren(el);
  }

  function updateCounts() {
    var soon = users.filter(function(u) {
      var tone = expiryState(u.expires_at).tone;
      return tone === 'ui-badge-warn';
    }).length;
    var expired = users.filter(function(u) {
      return expiryState(u.expires_at).tone === 'ui-badge-bad';
    }).length;
    var text = users.length + ' user' + (users.length !== 1 ? 's' : '');
    if (soon) text += ' · ' + soon + ' key' + (soon !== 1 ? 's' : '') + ' expiring within 7 days';
    if (expired) text += ' · ' + expired + ' expired';
    byId('iamUserCount').textContent = text;
    byId('iamTableWrap').hidden = users.length === 0;
    byId('iamEmpty').hidden = users.length > 0;
  }

  function setDirty(value) {
    dirty = value;
    byId('permGridSave').disabled = !value;
  }

  function gridEditable(policy) {
    return !isDenyPolicy(policy) && !isConditional(policy) && !hasPrefix(policy) && !hasWildcardAction(policy);
  }

  function gridRowNote(policy) {
    var notes = [];
    if (isDenyPolicy(policy)) notes.push('Deny');
    if (hasWildcardAction(policy)) notes.push('Full access');
    if (hasPrefix(policy)) notes.push('prefix ' + policy.prefix);
    if (isConditional(policy)) notes.push('conditional');
    var extra = (policy.actions || []).filter(function(a) {
      return a !== '*' && GRID_ACTIONS.indexOf(a) < 0;
    }).length;
    if (extra) notes.push('+' + extra + ' more');
    return notes.join(' · ');
  }

  function renderGrid() {
    var body = byId('permGridBody');
    var locked = false;
    body.replaceChildren();
    draft.forEach(function(policy, index) {
      var editable = gridEditable(policy);
      if (!editable) locked = true;
      var bucketLabel = policy.bucket === '*' ? 'All buckets' : policy.bucket;
      var tr = document.createElement('tr');
      var nameCell = document.createElement('td');
      var name = document.createElement('div');
      name.className = 'ak-grid-bucket';
      name.textContent = bucketLabel;
      nameCell.appendChild(name);
      var note = gridRowNote(policy);
      if (note) {
        var noteEl = document.createElement('div');
        noteEl.className = 'ui-muted st-sub' + (isDenyPolicy(policy) ? ' st-bad' : '');
        noteEl.textContent = note;
        nameCell.appendChild(noteEl);
      }
      tr.appendChild(nameCell);
      GRID_ACTIONS.forEach(function(action) {
        var td = document.createElement('td');
        var box = document.createElement('input');
        box.type = 'checkbox';
        box.checked = hasWildcardAction(policy) || (policy.actions || []).indexOf(action) >= 0;
        box.disabled = !editable;
        box.setAttribute('aria-label', action + ' on ' + bucketLabel);
        box.setAttribute('data-grid-index', index);
        box.setAttribute('data-grid-action', action);
        td.appendChild(box);
        tr.appendChild(td);
      });
      var removeCell = document.createElement('td');
      var remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'ui-btn ui-btn-sm ui-btn-ghost';
      remove.textContent = 'Remove';
      remove.setAttribute('aria-label', 'Remove ' + bucketLabel);
      remove.setAttribute('data-grid-remove', index);
      removeCell.appendChild(remove);
      tr.appendChild(removeCell);
      body.appendChild(tr);
    });
    byId('permGridWrap').hidden = draft.length === 0;
    byId('permGridEmpty').hidden = draft.length > 0;
    byId('permGridNote').hidden = !locked;
  }

  function renderPanel() {
    var user = selectedId ? getUser(selectedId) : null;
    byId('userPanel').hidden = !user;
    byId('userPanelEmpty').hidden = !!user;
    document.querySelectorAll('.iam-user-item').forEach(function(row) {
      row.classList.toggle('is-selected', !!user && row.getAttribute('data-user-id') === user.user_id);
    });
    if (!user) return;
    var name = user.display_name || user.access_key;
    byId('panelAvatar').textContent = initials(name);
    byId('panelName').textContent = name;
    byId('panelKey').textContent = user.access_key;
    var admin = isAdminUser(user.policies);
    var role = byId('panelRole');
    role.className = 'ui-badge' + (admin ? ' ui-badge-bad' : '');
    role.textContent = admin ? 'Admin' : 'User';
    var state = expiryState(user.expires_at);
    byId('panelExpiry').textContent = !user.expires_at
      ? 'Key never expires'
      : (state.tone === 'ui-badge-bad' ? 'Key expired ' : 'Key expires ') + (state.when ? state.when.toLocaleString() : user.expires_at);
    renderGrid();
  }

  function selectUser(userId, reveal) {
    if (dirty && selectedId && selectedId !== userId) {
      var previous = getUser(selectedId);
      if (previous) {
        window.showToast('Unsaved permission changes for ' + (previous.display_name || previous.access_key) + ' were discarded.', 'Permissions', 'warning');
      }
    }
    if (selectedId !== userId || !dirty) {
      var user = userId ? getUser(userId) : null;
      draft = clonePolicies(user ? user.policies : []);
      setDirty(false);
    }
    selectedId = userId;
    renderPanel();
    if (reveal && userId && window.matchMedia('(max-width: 767.98px)').matches) {
      byId('userPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function applyPolicies(userId, policies) {
    var user = getUser(userId);
    if (!user) return;
    user.policies = policies || [];
    var row = rowFor(userId);
    if (row) fillRowAccess(row, user);
    if (selectedId === userId) {
      draft = clonePolicies(user.policies);
      setDirty(false);
      renderPanel();
    }
  }

  function setupUserTable() {
    byId('iamUsersBody').addEventListener('click', function(event) {
      var row = event.target.closest('.iam-user-item');
      if (!row) return;
      selectUser(row.getAttribute('data-user-id'), !!event.target.closest('[data-user-manage]'));
    });

    var searchInput = byId('iam-user-search');
    searchInput.addEventListener('input', function() {
      var query = searchInput.value.toLowerCase().trim();
      var visible = 0;
      document.querySelectorAll('.iam-user-item').forEach(function(row) {
        var matches = !query ||
          (row.getAttribute('data-display-name') || '').indexOf(query) >= 0 ||
          (row.getAttribute('data-access-key-filter') || '').indexOf(query) >= 0;
        row.hidden = !matches;
        if (matches) visible++;
      });
      byId('iam-no-results').hidden = visible > 0 || users.length === 0;
    });
  }

  function setupGrid() {
    var body = byId('permGridBody');
    body.addEventListener('change', function(event) {
      var box = event.target.closest('[data-grid-action]');
      if (!box) return;
      var policy = draft[Number(box.getAttribute('data-grid-index'))];
      if (!policy) return;
      var action = box.getAttribute('data-grid-action');
      var actions = (policy.actions || []).filter(function(a) { return a !== action; });
      if (box.checked) actions.push(action);
      policy.actions = actions;
      setDirty(true);
    });

    body.addEventListener('click', function(event) {
      var remove = event.target.closest('[data-grid-remove]');
      if (!remove) return;
      draft.splice(Number(remove.getAttribute('data-grid-remove')), 1);
      setDirty(true);
      renderGrid();
    });

    var bucketInput = byId('permGridBucket');
    function addBucket() {
      var bucket = bucketInput.value.trim();
      if (!bucket) {
        bucketInput.focus();
        return;
      }
      var exists = draft.some(function(p) { return p.bucket === bucket && gridEditable(p); });
      if (exists) {
        window.showToast((bucket === '*' ? 'All buckets' : bucket) + ' is already in the list.', 'Permissions', 'warning');
        return;
      }
      draft.push({ bucket: bucket, actions: ['list', 'read'] });
      bucketInput.value = '';
      setDirty(true);
      renderGrid();
    }
    byId('permGridAdd').addEventListener('click', addBucket);
    bucketInput.addEventListener('keydown', function(event) {
      if (event.key !== 'Enter') return;
      event.preventDefault();
      addBucket();
    });

    var form = byId('permGridForm');
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      if (!selectedId) return;
      var userId = selectedId;
      byId('permGridPolicies').value = JSON.stringify(draft);
      form.action = buildUserUrl(endpoints.updatePolicies, userId);
      window.UICore.submitFormAjax(form, {
        successMessage: 'Permissions updated',
        onSuccess: function(data) {
          applyPolicies(userId, data.policies || clonePolicies(draft));
        }
      }).then(function() {
        setDirty(dirty);
      });
    });
  }

  function openRename(user, opener) {
    byId('editUserDisplayName').value = user.display_name || '';
    byId('editUserForm').action = buildUserUrl(endpoints.updateUser, user.user_id);
    byId('editUserForm').setAttribute('data-user-id', user.user_id);
    window.UI.dialog.open('#editUserModal', opener);
  }

  function openDelete(user, opener) {
    byId('deleteUserLabel').textContent = user.display_name || user.access_key;
    byId('deleteUserForm').action = buildUserUrl(endpoints.deleteUser, user.user_id);
    byId('deleteUserForm').setAttribute('data-user-id', user.user_id);
    byId('deleteSelfWarning').hidden = user.access_key !== currentUserKey;
    window.UI.dialog.open('#deleteUserModal', opener);
  }

  function setRotateState(done) {
    byId('rotateSecretConfirm').hidden = done;
    byId('rotateSecretResult').hidden = !done;
    byId('confirmRotateBtn').hidden = done;
    byId('rotateCancelBtn').hidden = done;
    byId('rotateDoneBtn').hidden = !done;
  }

  function openRotate(user, opener) {
    rotateUserId = user.user_id;
    byId('rotateUserLabel').textContent = user.access_key;
    byId('newSecretKey').value = '';
    setRotateState(false);
    window.UI.dialog.open('#rotateSecretModal', opener);
  }

  function openExpiry(user, opener) {
    var input = byId('expiryDateInput');
    var when = user.expires_at ? new Date(user.expires_at) : null;
    input.value = when && !isNaN(when.getTime()) ? toLocalInput(when) : '';
    byId('expiryUserLabel').textContent = user.access_key;
    byId('expiryForm').action = buildUserUrl(endpoints.updateExpiry, user.user_id);
    window.UI.dialog.open('#expiryModal', opener);
  }

  function openPolicies(user, opener) {
    byId('policyEditorUserLabel').textContent = user.access_key;
    byId('policyEditorUserId').value = user.user_id;
    byId('policyEditorDocument').value = JSON.stringify(dirty ? draft : user.policies || [], null, 2);
    window.UI.dialog.open('#policyEditorModal', opener);
  }

  function setupPanelActions() {
    var openers = {
      rename: openRename,
      rotate: openRotate,
      expiry: openExpiry,
      delete: openDelete,
      policies: openPolicies
    };
    byId('userPanel').addEventListener('click', function(event) {
      var button = event.target.closest('[data-user-action]');
      if (!button) return;
      var user = selectedId ? getUser(selectedId) : null;
      var open = openers[button.getAttribute('data-user-action')];
      if (user && open) open(user, button);
    });

    var keyButton = byId('panelKey');
    keyButton.addEventListener('click', function() {
      window.UICore.copyToClipboard(keyButton.textContent).then(function(ok) {
        if (ok) window.showToast('Access key copied', 'Copied', 'success');
      });
    });
  }

  function setupCopyButtons() {
    document.addEventListener('click', function(event) {
      var inputButton = event.target.closest('[data-copy-input]');
      if (inputButton) {
        var input = byId(inputButton.getAttribute('data-copy-input'));
        if (input) window.UICore.copyToClipboard(input.value, inputButton, 'Copy');
        return;
      }
      var textButton = event.target.closest('[data-copy-text]');
      if (textButton) {
        var target = byId(textButton.getAttribute('data-copy-text'));
        if (target) window.UICore.copyToClipboard(target.textContent, textButton, 'Copy JSON');
      }
    });
  }

  function generateSecureHex(byteCount) {
    var arr = new Uint8Array(byteCount);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  function generateSecureBase64(byteCount) {
    var arr = new Uint8Array(byteCount);
    crypto.getRandomValues(arr);
    var binary = '';
    for (var i = 0; i < arr.length; i++) {
      binary += String.fromCharCode(arr[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function setupTemplates(attribute, textarea) {
    document.querySelectorAll('[' + attribute + ']').forEach(function(button) {
      button.addEventListener('click', function() {
        var template = policyTemplates[button.getAttribute(attribute)];
        if (template) textarea.value = JSON.stringify(template, null, 2);
      });
    });
  }

  function setupCreateUser() {
    var form = byId('createUserForm');
    var policiesEl = byId('createUserPolicies');
    window.UICore.setupJsonAutoIndent(policiesEl);
    setupTemplates('data-create-policy-template', policiesEl);

    byId('createUserBtn').addEventListener('click', function() {
      window.UI.dialog.open('#createUserModal', this);
      byId('createUserDisplayName').focus();
    });
    byId('generateAccessKeyBtn').addEventListener('click', function() {
      byId('createUserAccessKey').value = generateSecureHex(8);
    });
    byId('generateSecretKeyBtn').addEventListener('click', function() {
      byId('createUserSecretKey').value = generateSecureBase64(24);
    });

    form.addEventListener('submit', function(event) {
      event.preventDefault();
      window.UICore.submitFormAjax(form, {
        successMessage: 'User created',
        onSuccess: function(data) {
          window.UI.dialog.close('#createUserModal');
          form.reset();
          var user = {
            user_id: data.user_id,
            access_key: data.access_key,
            display_name: data.display_name,
            expires_at: data.expires_at || '',
            policies: data.policies || []
          };
          users.push(user);
          var row = byId('iamUserRowTemplate').content.firstElementChild.cloneNode(true);
          fillRow(row, user);
          byId('iamUsersBody').appendChild(row);
          updateCounts();
          selectUser(user.user_id, false);
          if (data.secret_key) {
            byId('newUserAccessKey').value = data.access_key;
            byId('newUserSecret').value = data.secret_key;
            window.UI.dialog.open('#credentialsDialog');
          }
        }
      });
    });

    byId('credentialsDialog').addEventListener('close', function() {
      byId('newUserSecret').value = '';
    });
  }

  function setupPolicyEditor() {
    var form = byId('policyEditorForm');
    var textarea = byId('policyEditorDocument');
    window.UICore.setupJsonAutoIndent(textarea);
    setupTemplates('data-policy-template', textarea);

    form.addEventListener('submit', function(event) {
      event.preventDefault();
      var userId = byId('policyEditorUserId').value;
      if (!userId) return;
      form.action = buildUserUrl(endpoints.updatePolicies, userId);
      window.UICore.submitFormAjax(form, {
        successMessage: 'Policies updated',
        onSuccess: function(data) {
          window.UI.dialog.close('#policyEditorModal');
          if (data.policies) applyPolicies(userId, data.policies);
          else window.location.reload();
        }
      });
    });
  }

  function setupRename() {
    var form = byId('editUserForm');
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      var userId = form.getAttribute('data-user-id');
      window.UICore.submitFormAjax(form, {
        successMessage: 'User updated',
        onSuccess: function(data) {
          window.UI.dialog.close('#editUserModal');
          var user = getUser(userId);
          if (!user) return;
          user.display_name = data.display_name || byId('editUserDisplayName').value;
          var row = rowFor(userId);
          if (row) fillRow(row, user);
          if (selectedId === userId) renderPanel();
          if (user.access_key === currentUserKey) {
            document.querySelectorAll('.sidebar-user[data-username]').forEach(function(el) {
              el.setAttribute('data-username', user.display_name);
            });
          }
        }
      });
    });
  }

  function setupDelete() {
    var form = byId('deleteUserForm');
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      var userId = form.getAttribute('data-user-id');
      window.UICore.submitFormAjax(form, {
        successMessage: 'User deleted',
        onSuccess: function() {
          window.UI.dialog.close('#deleteUserModal');
          var user = getUser(userId);
          if (user && user.access_key === currentUserKey) {
            window.location.href = '/ui/';
            return;
          }
          var row = rowFor(userId);
          if (row) row.remove();
          users = users.filter(function(u) { return u.user_id !== userId; });
          updateCounts();
          if (selectedId === userId) {
            setDirty(false);
            selectUser(users.length ? users[0].user_id : null, false);
          }
        }
      });
    });
  }

  function setupRotate() {
    var confirmBtn = byId('confirmRotateBtn');
    confirmBtn.addEventListener('click', async function() {
      if (!rotateUserId) return;
      confirmBtn.disabled = true;
      confirmBtn.textContent = 'Rotating…';
      try {
        var response = await fetch(buildUserUrl(endpoints.rotateSecret, rotateUserId), {
          method: 'POST',
          headers: { 'Accept': 'application/json', 'X-CSRFToken': csrfToken }
        });
        var data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Failed to rotate secret');
        byId('newSecretKey').value = data.secret_key;
        setRotateState(true);
      } catch (err) {
        window.showToast(err.message, 'Error', 'error');
        window.UI.dialog.close('#rotateSecretModal');
      } finally {
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Rotate key';
      }
    });

    byId('rotateSecretModal').addEventListener('close', function() {
      byId('newSecretKey').value = '';
    });
  }

  function setupExpiry() {
    var input = byId('expiryDateInput');
    document.querySelectorAll('[data-expiry-preset]').forEach(function(button) {
      button.addEventListener('click', function() {
        var ms = EXPIRY_PRESETS[button.getAttribute('data-expiry-preset')];
        input.value = ms ? toLocalInput(new Date(Date.now() + ms)) : '';
      });
    });

    var form = byId('expiryForm');
    form.addEventListener('submit', function(event) {
      event.preventDefault();
      window.UICore.submitFormAjax(form, {
        successMessage: 'Expiry updated',
        onSuccess: function() {
          window.UI.dialog.close('#expiryModal');
          window.location.reload();
        }
      });
    });
  }

  function init(config) {
    users = config.users || [];
    currentUserKey = config.currentUserKey || null;
    endpoints = config.endpoints || {};
    csrfToken = config.csrfToken || '';

    if (config.iamLocked) return;

    users.forEach(function(user) {
      var row = rowFor(user.user_id);
      if (row) fillRow(row, user);
    });
    updateCounts();

    setupUserTable();
    setupGrid();
    setupPanelActions();
    setupCopyButtons();
    setupCreateUser();
    setupPolicyEditor();
    setupRename();
    setupDelete();
    setupRotate();
    setupExpiry();

    if (users.length && window.matchMedia('(min-width: 768px)').matches) {
      selectUser(users[0].user_id, false);
    }
  }

  return {
    init: init
  };
})();

(function() {
  var el = document.getElementById('iamConfig');
  if (!el) return;
  var data = el.dataset;
  var usersEl = document.getElementById('iamUsersJson');
  IAMManagement.init({
    users: JSON.parse((usersEl && usersEl.textContent) || '[]'),
    currentUserKey: data.currentUserKey,
    iamLocked: data.iamLocked === 'true',
    csrfToken: data.csrfToken,
    endpoints: {
      createUser: data.createUser,
      updateUser: data.updateUser,
      deleteUser: data.deleteUser,
      updatePolicies: data.updatePolicies,
      rotateSecret: data.rotateSecret,
      updateExpiry: data.updateExpiry
    }
  });
})();
