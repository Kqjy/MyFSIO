window.IAMManagement = (function() {
  'use strict';

  var users = [];
  var currentUserKey = null;
  var endpoints = {};
  var csrfToken = '';
  var iamLocked = false;

  var policyModal = null;
  var editUserModal = null;
  var deleteUserModal = null;
  var rotateSecretModal = null;
  var expiryModal = null;
  var currentRotateKey = null;
  var currentEditKey = null;
  var currentDeleteKey = null;
  var currentEditAccessKey = null;
  var currentDeleteAccessKey = null;
  var currentExpiryKey = null;
  var currentExpiryAccessKey = null;

  var ALL_S3_ACTIONS = [
    'list', 'read', 'write', 'delete', 'share', 'policy',
    'replication', 'lifecycle', 'cors',
    'create_bucket', 'delete_bucket',
    'versioning', 'tagging', 'encryption', 'quota',
    'object_lock', 'notification', 'logging', 'website'
  ];

  var policyTemplates = {
    full: [{ bucket: '*', actions: ['list', 'read', 'write', 'delete', 'share', 'policy', 'create_bucket', 'delete_bucket', 'replication', 'lifecycle', 'cors', 'versioning', 'tagging', 'encryption', 'quota', 'object_lock', 'notification', 'logging', 'website', 'iam:*'] }],
    readonly: [{ bucket: '*', actions: ['list', 'read'] }],
    writer: [{ bucket: '*', actions: ['list', 'read', 'write'] }],
    operator: [{ bucket: '*', actions: ['list', 'read', 'write', 'delete', 'create_bucket', 'delete_bucket'] }],
    bucketadmin: [{ bucket: '*', actions: ['list', 'read', 'write', 'delete', 'share', 'policy', 'create_bucket', 'delete_bucket', 'versioning', 'tagging', 'encryption', 'cors', 'lifecycle', 'quota', 'object_lock', 'notification', 'logging', 'website', 'replication'] }]
  };

  function isAdminUser(policies) {
    if (!policies || !policies.length) return false;
    return policies.some(function(p) {
      return p.actions && (p.actions.indexOf('iam:*') >= 0 || p.actions.indexOf('*') >= 0);
    });
  }

  function getPermissionLevel(actions) {
    if (!actions || !actions.length) return 'Custom (0)';
    if (actions.indexOf('*') >= 0) return 'Full Access';
    if (actions.length >= ALL_S3_ACTIONS.length) {
      var hasAll = ALL_S3_ACTIONS.every(function(a) { return actions.indexOf(a) >= 0; });
      if (hasAll) return 'Full Access';
    }
    var has = function(a) { return actions.indexOf(a) >= 0; };
    if (has('list') && has('read') && has('write') && has('delete')) return 'Read + Write + Delete';
    if (has('list') && has('read') && has('write')) return 'Read + Write';
    if (has('list') && has('read')) return 'Read Only';
    return 'Custom (' + actions.length + ')';
  }

  function getBucketLabel(bucket) {
    return bucket === '*' ? 'All Buckets' : bucket;
  }

  function buildUserUrl(template, userId) {
    return template.replace('USER_ID', encodeURIComponent(userId));
  }

  function getUserByIdentifier(identifier) {
    return users.find(function(u) {
      return u.user_id === identifier || u.access_key === identifier;
    }) || null;
  }

  function getUserById(userId) {
    return users.find(function(u) { return u.user_id === userId; }) || null;
  }

  function init(config) {
    users = config.users || [];
    currentUserKey = config.currentUserKey || null;
    endpoints = config.endpoints || {};
    csrfToken = config.csrfToken || '';
    iamLocked = config.iamLocked || false;

    if (iamLocked) return;

    initModals();
    setupJsonAutoIndent();
    setupCopyButtons();
    setupPolicyEditor();
    setupCreateUserModal();
    setupEditUserModal();
    setupDeleteUserModal();
    setupRotateSecretModal();
    setupExpiryModal();
    setupFormHandlers();
    setupSearch();
    setupCopyAccessKeyButtons();
  }

  function initModals() {
    var policyModalEl = document.getElementById('policyEditorModal');
    var editModalEl = document.getElementById('editUserModal');
    var deleteModalEl = document.getElementById('deleteUserModal');
    var rotateModalEl = document.getElementById('rotateSecretModal');
    var expiryModalEl = document.getElementById('expiryModal');

    if (policyModalEl) policyModal = new bootstrap.Modal(policyModalEl);
    if (editModalEl) editUserModal = new bootstrap.Modal(editModalEl);
    if (deleteModalEl) deleteUserModal = new bootstrap.Modal(deleteModalEl);
    if (rotateModalEl) rotateSecretModal = new bootstrap.Modal(rotateModalEl);
    if (expiryModalEl) expiryModal = new bootstrap.Modal(expiryModalEl);
  }

  function setupJsonAutoIndent() {
    window.UICore.setupJsonAutoIndent(document.getElementById('policyEditorDocument'));
    window.UICore.setupJsonAutoIndent(document.getElementById('createUserPolicies'));
  }

  function setupCopyButtons() {
    document.querySelectorAll('.config-copy').forEach(function(button) {
      button.addEventListener('click', async function() {
        var targetId = button.dataset.copyTarget;
        var target = document.getElementById(targetId);
        if (!target) return;
        await window.UICore.copyToClipboard(target.innerText, button, 'Copy JSON');
      });
    });

    var accessKeyCopyButton = document.querySelector('[data-access-key-copy]');
    if (accessKeyCopyButton) {
      accessKeyCopyButton.addEventListener('click', async function() {
        var accessKeyInput = document.getElementById('disclosedAccessKeyValue');
        if (!accessKeyInput) return;
        await window.UICore.copyToClipboard(accessKeyInput.value, accessKeyCopyButton, 'Copy');
      });
    }

    var secretCopyButton = document.querySelector('[data-secret-copy]');
    if (secretCopyButton) {
      secretCopyButton.addEventListener('click', async function() {
        var secretInput = document.getElementById('disclosedSecretValue');
        if (!secretInput) return;
        await window.UICore.copyToClipboard(secretInput.value, secretCopyButton, 'Copy');
      });
    }
  }

  function getUserPolicies(identifier) {
    var user = getUserByIdentifier(identifier);
    return user ? JSON.stringify(user.policies, null, 2) : '';
  }

  function applyPolicyTemplate(name, textareaEl) {
    if (policyTemplates[name] && textareaEl) {
      textareaEl.value = JSON.stringify(policyTemplates[name], null, 2);
    }
  }

  function setupPolicyEditor() {
    var userLabelEl = document.getElementById('policyEditorUserLabel');
    var userInputEl = document.getElementById('policyEditorUserId');
    var textareaEl = document.getElementById('policyEditorDocument');

    document.querySelectorAll('[data-policy-template]').forEach(function(button) {
      button.addEventListener('click', function() {
        applyPolicyTemplate(button.dataset.policyTemplate, textareaEl);
      });
    });

    document.querySelectorAll('[data-policy-editor]').forEach(function(button) {
      button.addEventListener('click', function() {
        var userId = button.dataset.userId;
        var accessKey = button.dataset.accessKey || userId;
        if (!userId) return;

        userLabelEl.textContent = accessKey;
        userInputEl.value = userId;
        textareaEl.value = getUserPolicies(userId);

        policyModal.show();
      });
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

  function setupCreateUserModal() {
    var createUserPoliciesEl = document.getElementById('createUserPolicies');

    document.querySelectorAll('[data-create-policy-template]').forEach(function(button) {
      button.addEventListener('click', function() {
        applyPolicyTemplate(button.dataset.createPolicyTemplate, createUserPoliciesEl);
      });
    });

    var genAccessKeyBtn = document.getElementById('generateAccessKeyBtn');
    if (genAccessKeyBtn) {
      genAccessKeyBtn.addEventListener('click', function() {
        var input = document.getElementById('createUserAccessKey');
        if (input) input.value = generateSecureHex(8);
      });
    }

    var genSecretKeyBtn = document.getElementById('generateSecretKeyBtn');
    if (genSecretKeyBtn) {
      genSecretKeyBtn.addEventListener('click', function() {
        var input = document.getElementById('createUserSecretKey');
        if (input) input.value = generateSecureBase64(24);
      });
    }
  }

  function setupEditUserModal() {
    var editUserForm = document.getElementById('editUserForm');
    var editUserDisplayName = document.getElementById('editUserDisplayName');

    document.querySelectorAll('[data-edit-user]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var key = btn.dataset.userId;
        var accessKey = btn.dataset.accessKey || key;
        var name = btn.dataset.displayName;
        currentEditKey = key;
        currentEditAccessKey = accessKey;
        editUserDisplayName.value = name;
        editUserForm.action = buildUserUrl(endpoints.updateUser, key);
        editUserModal.show();
      });
    });
  }

  function setupDeleteUserModal() {
    var deleteUserForm = document.getElementById('deleteUserForm');
    var deleteUserLabel = document.getElementById('deleteUserLabel');
    var deleteSelfWarning = document.getElementById('deleteSelfWarning');

    document.querySelectorAll('[data-delete-user]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var key = btn.dataset.userId;
        var accessKey = btn.dataset.accessKey || key;
        currentDeleteKey = key;
        currentDeleteAccessKey = accessKey;
        deleteUserLabel.textContent = accessKey;
        deleteUserForm.action = buildUserUrl(endpoints.deleteUser, key);

        if (accessKey === currentUserKey) {
          deleteSelfWarning.classList.remove('d-none');
        } else {
          deleteSelfWarning.classList.add('d-none');
        }

        deleteUserModal.show();
      });
    });
  }

  function setupRotateSecretModal() {
    var rotateUserLabel = document.getElementById('rotateUserLabel');
    var confirmRotateBtn = document.getElementById('confirmRotateBtn');
    var rotateCancelBtn = document.getElementById('rotateCancelBtn');
    var rotateDoneBtn = document.getElementById('rotateDoneBtn');
    var rotateSecretConfirm = document.getElementById('rotateSecretConfirm');
    var rotateSecretResult = document.getElementById('rotateSecretResult');
    var newSecretKeyInput = document.getElementById('newSecretKey');
    var copyNewSecretBtn = document.getElementById('copyNewSecret');

    document.querySelectorAll('[data-rotate-user]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        currentRotateKey = btn.dataset.userId;
        rotateUserLabel.textContent = btn.dataset.accessKey || currentRotateKey;

        rotateSecretConfirm.classList.remove('d-none');
        rotateSecretResult.classList.add('d-none');
        confirmRotateBtn.classList.remove('d-none');
        rotateCancelBtn.classList.remove('d-none');
        rotateDoneBtn.classList.add('d-none');

        rotateSecretModal.show();
      });
    });

    if (confirmRotateBtn) {
      confirmRotateBtn.addEventListener('click', async function() {
        if (!currentRotateKey) return;

        window.UICore.setButtonLoading(confirmRotateBtn, true, 'Rotating...');

        try {
          var url = buildUserUrl(endpoints.rotateSecret, currentRotateKey);
          var response = await fetch(url, {
            method: 'POST',
            headers: {
              'Accept': 'application/json',
              'X-CSRFToken': csrfToken
            }
          });

          if (!response.ok) {
            var data = await response.json();
            throw new Error(data.error || 'Failed to rotate secret');
          }

          var data = await response.json();
          newSecretKeyInput.value = data.secret_key;

          rotateSecretConfirm.classList.add('d-none');
          rotateSecretResult.classList.remove('d-none');
          confirmRotateBtn.classList.add('d-none');
          rotateCancelBtn.classList.add('d-none');
          rotateDoneBtn.classList.remove('d-none');

        } catch (err) {
          if (window.showToast) {
            window.showToast(err.message, 'Error', 'danger');
          }
          rotateSecretModal.hide();
        } finally {
          window.UICore.setButtonLoading(confirmRotateBtn, false);
        }
      });
    }

    if (copyNewSecretBtn) {
      copyNewSecretBtn.addEventListener('click', async function() {
        await window.UICore.copyToClipboard(newSecretKeyInput.value, copyNewSecretBtn, 'Copy');
      });
    }

    if (rotateDoneBtn) {
      rotateDoneBtn.addEventListener('click', function() {
        window.location.reload();
      });
    }
  }

  function openExpiryModal(key, expiresAt) {
    currentExpiryKey = key;
    var user = getUserByIdentifier(key);
    var label = document.getElementById('expiryUserLabel');
    var input = document.getElementById('expiryDateInput');
    var form = document.getElementById('expiryForm');
    if (label) label.textContent = currentExpiryAccessKey || (user ? user.access_key : key);
    if (expiresAt) {
      try {
        var dt = new Date(expiresAt);
        var local = new Date(dt.getTime() - dt.getTimezoneOffset() * 60000);
        if (input) input.value = local.toISOString().slice(0, 16);
      } catch(e) {
        if (input) input.value = '';
      }
    } else {
      if (input) input.value = '';
    }
    if (form) form.action = buildUserUrl(endpoints.updateExpiry, key);
    var modalEl = document.getElementById('expiryModal');
    if (modalEl) {
      var modal = bootstrap.Modal.getOrCreateInstance(modalEl);
      modal.show();
    }
  }

  function setupExpiryModal() {
    document.querySelectorAll('[data-expiry-user]').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.preventDefault();
        currentExpiryAccessKey = btn.dataset.accessKey || btn.dataset.userId;
        openExpiryModal(btn.dataset.userId, btn.dataset.expiresAt || '');
      });
    });

    document.querySelectorAll('[data-expiry-preset]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var preset = btn.dataset.expiryPreset;
        var input = document.getElementById('expiryDateInput');
        if (!input) return;
        if (preset === 'clear') {
          input.value = '';
          return;
        }
        var now = new Date();
        var ms = 0;
        if (preset === '1h') ms = 3600000;
        else if (preset === '24h') ms = 86400000;
        else if (preset === '7d') ms = 7 * 86400000;
        else if (preset === '30d') ms = 30 * 86400000;
        else if (preset === '90d') ms = 90 * 86400000;
        var future = new Date(now.getTime() + ms);
        var local = new Date(future.getTime() - future.getTimezoneOffset() * 60000);
        input.value = local.toISOString().slice(0, 16);
      });
    });

    var expiryForm = document.getElementById('expiryForm');
    if (expiryForm) {
      expiryForm.addEventListener('submit', function(e) {
        e.preventDefault();
        window.UICore.submitFormAjax(expiryForm, {
          successMessage: 'Expiry updated',
          onSuccess: function() {
            var modalEl = document.getElementById('expiryModal');
            if (modalEl) bootstrap.Modal.getOrCreateInstance(modalEl).hide();
            window.location.reload();
          }
        });
      });
    }
  }

  function createUserCardHtml(user) {
    var userId = user.user_id || '';
    var accessKey = user.access_key || userId;
    var displayName = user.display_name || accessKey;
    var policies = user.policies || [];
    var expiresAt = user.expires_at || '';
    var admin = isAdminUser(policies);
    var cardClass = 'card h-100 iam-user-card' + (admin ? ' iam-admin-card' : '');
    var roleBadge = admin
      ? '<span class="iam-role-badge iam-role-admin" data-role-badge>Admin</span>'
      : '<span class="iam-role-badge iam-role-user" data-role-badge>User</span>';

    var policyBadges = '';
    if (policies && policies.length > 0) {
      policyBadges = policies.map(function(p) {
        var bucketLabel = getBucketLabel(p.bucket);
        var permLevel = getPermissionLevel(p.actions);
        return '<span class="iam-perm-badge">' +
          '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
          '<path d="M2.522 5H2a.5.5 0 0 0-.494.574l1.372 9.149A1.5 1.5 0 0 0 4.36 16h7.278a1.5 1.5 0 0 0 1.483-1.277l1.373-9.149A.5.5 0 0 0 14 5h-.522A5.5 5.5 0 0 0 2.522 5zm1.005 0a4.5 4.5 0 0 1 8.945 0H3.527z"/>' +
          '</svg>' + window.UICore.escapeHtml(bucketLabel) + ' &middot; ' + window.UICore.escapeHtml(permLevel) + '</span>';
      }).join('');
    } else {
      policyBadges = '<span class="badge bg-secondary bg-opacity-10 text-secondary">No policies</span>';
    }

    var esc = window.UICore.escapeHtml;
    return '<div class="col-md-6 col-xl-4 iam-user-item" data-user-id="' + esc(userId) + '" data-access-key="' + esc(accessKey) + '" data-display-name="' + esc(displayName.toLowerCase()) + '" data-access-key-filter="' + esc(accessKey.toLowerCase()) + '">' +
      '<div class="' + cardClass + '">' +
      '<div class="card-body">' +
      '<div class="d-flex align-items-start justify-content-between mb-3">' +
      '<div class="d-flex align-items-center gap-3 min-width-0 overflow-hidden">' +
      '<div class="user-avatar user-avatar-lg flex-shrink-0">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" viewBox="0 0 16 16">' +
      '<path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0zm4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4zm-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10c-2.29 0-3.516.68-4.168 1.332-.678.678-.83 1.418-.832 1.664h10z"/>' +
      '</svg></div>' +
      '<div class="min-width-0">' +
      '<div class="d-flex align-items-center gap-2 mb-0">' +
      '<h6 class="fw-semibold mb-0 text-truncate" title="' + esc(displayName) + '">' + esc(displayName) + '</h6>' +
      roleBadge +
      '</div>' +
      '<div class="d-flex align-items-center gap-1">' +
      '<code class="small text-muted text-truncate" title="' + esc(accessKey) + '">' + esc(accessKey) + '</code>' +
      '<button type="button" class="iam-copy-key" title="Copy access key" data-copy-access-key="' + esc(accessKey) + '">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16">' +
      '<path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1v-1z"/>' +
      '<path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5h3zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3z"/>' +
      '</svg></button>' +
      '</div>' +
      '</div></div>' +
      '<div class="dropdown flex-shrink-0">' +
      '<button class="btn btn-sm btn-icon" type="button" data-bs-toggle="dropdown" aria-expanded="false">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16">' +
      '<path d="M9.5 13a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm0-5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/>' +
      '</svg></button>' +
      '<ul class="dropdown-menu dropdown-menu-end">' +
      '<li><button class="dropdown-item" type="button" data-edit-user data-user-id="' + esc(userId) + '" data-access-key="' + esc(accessKey) + '" data-display-name="' + esc(displayName) + '">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-2" viewBox="0 0 16 16"><path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168l10-10zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207 11.207 2.5zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293l6.5-6.5z"/></svg>Edit Name</button></li>' +
      '<li><button class="dropdown-item" type="button" data-expiry-user data-user-id="' + esc(userId) + '" data-access-key="' + esc(accessKey) + '" data-expires-at="' + esc(expiresAt) + '">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-2" viewBox="0 0 16 16"><path d="M8 3.5a.5.5 0 0 0-1 0V9a.5.5 0 0 0 .252.434l3.5 2a.5.5 0 0 0 .496-.868L8 8.71V3.5z"/><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16zm7-8A7 7 0 1 1 1 8a7 7 0 0 1 14 0z"/></svg>Set Expiry</button></li>' +
      '<li><button class="dropdown-item" type="button" data-rotate-user data-user-id="' + esc(userId) + '" data-access-key="' + esc(accessKey) + '">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-2" viewBox="0 0 16 16"><path d="M11.534 7h3.932a.25.25 0 0 1 .192.41l-1.966 2.36a.25.25 0 0 1-.384 0l-1.966-2.36a.25.25 0 0 1 .192-.41zm-11 2h3.932a.25.25 0 0 0 .192-.41L2.692 6.23a.25.25 0 0 0-.384 0L.342 8.59A.25.25 0 0 0 .534 9z"/><path fill-rule="evenodd" d="M8 3c-1.552 0-2.94.707-3.857 1.818a.5.5 0 1 1-.771-.636A6.002 6.002 0 0 1 13.917 7H12.9A5.002 5.002 0 0 0 8 3zM3.1 9a5.002 5.002 0 0 0 8.757 2.182.5.5 0 1 1 .771.636A6.002 6.002 0 0 1 2.083 9H3.1z"/></svg>Rotate Secret</button></li>' +
      '<li><hr class="dropdown-divider"></li>' +
      '<li><button class="dropdown-item text-danger" type="button" data-delete-user data-user-id="' + esc(userId) + '" data-access-key="' + esc(accessKey) + '">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-2" viewBox="0 0 16 16"><path d="M5.5 5.5a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0v-6a.5.5 0 0 1 .5-.5zm2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0v-6a.5.5 0 0 1 .5-.5zm3 .5v6a.5.5 0 0 1-1 0v-6a.5.5 0 0 1 1 0z"/><path fill-rule="evenodd" d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1v1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4H4.118zM2.5 3V2h11v1h-11z"/></svg>Delete User</button></li>' +
      '</ul></div></div>' +
      '<div class="mb-3">' +
      '<div class="small text-muted mb-2">Bucket Permissions</div>' +
      '<div class="d-flex flex-wrap gap-1" data-policy-badges>' + policyBadges + '</div></div>' +
      '<button class="btn btn-outline-primary btn-sm w-100" type="button" data-policy-editor data-user-id="' + esc(userId) + '" data-access-key="' + esc(accessKey) + '">' +
      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16"><path d="M8 4.754a3.246 3.246 0 1 0 0 6.492 3.246 3.246 0 0 0 0-6.492zM5.754 8a2.246 2.246 0 1 1 4.492 0 2.246 2.246 0 0 1-4.492 0z"/><path d="M9.796 1.343c-.527-1.79-3.065-1.79-3.592 0l-.094.319a.873.873 0 0 1-1.255.52l-.292-.16c-1.64-.892-3.433.902-2.54 2.541l.159.292a.873.873 0 0 1-.52 1.255l-.319.094c-1.79.527-1.79 3.065 0 3.592l.319.094a.873.873 0 0 1 .52 1.255l-.16.292c-.892 1.64.901 3.434 2.541 2.54l.292-.159a.873.873 0 0 1 1.255.52l.094.319c.527 1.79 3.065 1.79 3.592 0l.094-.319a.873.873 0 0 1 1.255-.52l.292.16c1.64.893 3.434-.902 2.54-2.541l-.159-.292a.873.873 0 0 1 .52-1.255l.319-.094c1.79-.527 1.79-3.065 0-3.592l-.319-.094a.873.873 0 0 1-.52-1.255l.16-.292c.893-1.64-.902-3.433-2.541-2.54l-.292.159a.873.873 0 0 1-1.255-.52l-.094-.319z"/></svg>Manage Policies</button>' +
      '</div></div></div>';
  }

  function attachUserCardHandlers(cardElement, user) {
    var userId = user.user_id;
    var accessKey = user.access_key;
    var displayName = user.display_name;
    var expiresAt = user.expires_at || '';
    var editBtn = cardElement.querySelector('[data-edit-user]');
    if (editBtn) {
      editBtn.addEventListener('click', function() {
        currentEditKey = userId;
        currentEditAccessKey = accessKey;
        document.getElementById('editUserDisplayName').value = displayName;
        document.getElementById('editUserForm').action = buildUserUrl(endpoints.updateUser, userId);
        editUserModal.show();
      });
    }

    var deleteBtn = cardElement.querySelector('[data-delete-user]');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', function() {
        currentDeleteKey = userId;
        currentDeleteAccessKey = accessKey;
        document.getElementById('deleteUserLabel').textContent = accessKey;
        document.getElementById('deleteUserForm').action = buildUserUrl(endpoints.deleteUser, userId);
        var deleteSelfWarning = document.getElementById('deleteSelfWarning');
        if (accessKey === currentUserKey) {
          deleteSelfWarning.classList.remove('d-none');
        } else {
          deleteSelfWarning.classList.add('d-none');
        }
        deleteUserModal.show();
      });
    }

    var rotateBtn = cardElement.querySelector('[data-rotate-user]');
    if (rotateBtn) {
      rotateBtn.addEventListener('click', function() {
        currentRotateKey = userId;
        document.getElementById('rotateUserLabel').textContent = accessKey;
        document.getElementById('rotateSecretConfirm').classList.remove('d-none');
        document.getElementById('rotateSecretResult').classList.add('d-none');
        document.getElementById('confirmRotateBtn').classList.remove('d-none');
        document.getElementById('rotateCancelBtn').classList.remove('d-none');
        document.getElementById('rotateDoneBtn').classList.add('d-none');
        rotateSecretModal.show();
      });
    }

    var expiryBtn = cardElement.querySelector('[data-expiry-user]');
    if (expiryBtn) {
      expiryBtn.addEventListener('click', function(e) {
        e.preventDefault();
        currentExpiryAccessKey = accessKey;
        openExpiryModal(userId, expiresAt);
      });
    }

    var policyBtn = cardElement.querySelector('[data-policy-editor]');
    if (policyBtn) {
      policyBtn.addEventListener('click', function() {
        document.getElementById('policyEditorUserLabel').textContent = accessKey;
        document.getElementById('policyEditorUserId').value = userId;
        document.getElementById('policyEditorDocument').value = getUserPolicies(userId);
        policyModal.show();
      });
    }

    var copyBtn = cardElement.querySelector('[data-copy-access-key]');
    if (copyBtn) {
      copyBtn.addEventListener('click', function() {
        copyAccessKey(copyBtn);
      });
    }
  }

  function updateUserCount() {
    var countEl = document.querySelector('.card-header .text-muted.small');
    if (countEl) {
      var count = document.querySelectorAll('.iam-user-card').length;
      countEl.textContent = count + ' user' + (count !== 1 ? 's' : '') + ' configured';
    }
  }

  function setupFormHandlers() {
    var createUserForm = document.querySelector('#createUserModal form');
    if (createUserForm) {
      createUserForm.addEventListener('submit', function(e) {
        e.preventDefault();
        window.UICore.submitFormAjax(createUserForm, {
          successMessage: 'User created',
          onSuccess: function(data) {
            var modal = bootstrap.Modal.getInstance(document.getElementById('createUserModal'));
            if (modal) modal.hide();
            createUserForm.reset();

            var existingAlert = document.querySelector('.alert.alert-info.border-0.shadow-sm');
            if (existingAlert) existingAlert.remove();

            if (data.secret_key) {
              var alertHtml = '<div class="alert alert-info border-0 shadow-sm mb-4" role="alert" id="newUserSecretAlert">' +
                '<div class="d-flex align-items-start gap-2 mb-2">' +
                '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-key flex-shrink-0 mt-1" viewBox="0 0 16 16">' +
                '<path d="M0 8a4 4 0 0 1 7.465-2H14a.5.5 0 0 1 .354.146l1.5 1.5a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0L13 9.207l-.646.647a.5.5 0 0 1-.708 0L11 9.207l-.646.647a.5.5 0 0 1-.708 0L9 9.207l-.646.647A.5.5 0 0 1 8 10h-.535A4 4 0 0 1 0 8zm4-3a3 3 0 1 0 2.712 4.285A.5.5 0 0 1 7.163 9h.63l.853-.854a.5.5 0 0 1 .708 0l.646.647.646-.647a.5.5 0 0 1 .708 0l.646.647.646-.647a.5.5 0 0 1 .708 0l.646.647.793-.793-1-1h-6.63a.5.5 0 0 1-.451-.285A3 3 0 0 0 4 5z"/><path d="M4 8a1 1 0 1 1-2 0 1 1 0 0 1 2 0z"/>' +
                '</svg>' +
                '<div class="flex-grow-1">' +
                '<div class="fw-semibold">New user created: <code>' + window.UICore.escapeHtml(data.access_key) + '</code></div>' +
                '<p class="mb-2 small">These credentials are only shown once. Copy them now and store them securely.</p>' +
                '</div>' +
                '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>' +
                '</div>' +
                '<div class="input-group mb-2">' +
                '<span class="input-group-text"><strong>Access key</strong></span>' +
                '<input class="form-control font-monospace" type="text" value="' + window.UICore.escapeHtml(data.access_key) + '" readonly />' +
                '<button class="btn btn-outline-primary" type="button" id="copyNewUserAccessKey">Copy</button>' +
                '</div>' +
                '<div class="input-group">' +
                '<span class="input-group-text"><strong>Secret key</strong></span>' +
                '<input class="form-control font-monospace" type="text" value="' + window.UICore.escapeHtml(data.secret_key) + '" readonly id="newUserSecret" />' +
                '<button class="btn btn-outline-primary" type="button" id="copyNewUserSecret">Copy</button>' +
                '</div></div>';
              var container = document.querySelector('.page-header');
              if (container) {
                container.insertAdjacentHTML('afterend', alertHtml);
                document.getElementById('copyNewUserAccessKey').addEventListener('click', async function() {
                  await window.UICore.copyToClipboard(data.access_key, this, 'Copy');
                });
                document.getElementById('copyNewUserSecret').addEventListener('click', async function() {
                  await window.UICore.copyToClipboard(data.secret_key, this, 'Copy');
                });
              }
            }

            var usersGrid = document.querySelector('.row.g-3');
            var emptyState = document.querySelector('.empty-state');
            if (emptyState) {
              var emptyCol = emptyState.closest('.col-12');
              if (emptyCol) emptyCol.remove();
              if (!usersGrid) {
                var cardBody = document.querySelector('.card-body.px-4.pb-4');
                if (cardBody) {
                  cardBody.innerHTML = '<div class="row g-3"></div>';
                  usersGrid = cardBody.querySelector('.row.g-3');
                }
              }
            }

            if (usersGrid) {
              var newUser = {
                user_id: data.user_id,
                access_key: data.access_key,
                display_name: data.display_name,
                expires_at: data.expires_at || '',
                policies: data.policies || []
              };
              var cardHtml = createUserCardHtml(newUser);
              usersGrid.insertAdjacentHTML('beforeend', cardHtml);
              var newCard = usersGrid.lastElementChild;
              attachUserCardHandlers(newCard, newUser);
              users.push(newUser);
              updateUserCount();
            }
          }
        });
      });
    }

    var policyEditorForm = document.getElementById('policyEditorForm');
    if (policyEditorForm) {
      policyEditorForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var userInputEl = document.getElementById('policyEditorUserId');
        var userId = userInputEl.value;
        if (!userId) return;

        var template = policyEditorForm.dataset.actionTemplate;
        policyEditorForm.action = template.replace('USER_ID_PLACEHOLDER', encodeURIComponent(userId));

        window.UICore.submitFormAjax(policyEditorForm, {
          successMessage: 'Policies updated',
          onSuccess: function(data) {
            policyModal.hide();

            var userCard = document.querySelector('.iam-user-item[data-user-id="' + userId + '"]');
            if (userCard) {
              var cardEl = userCard.querySelector('.iam-user-card');
              var badgeContainer = cardEl ? cardEl.querySelector('[data-policy-badges]') : null;
              if (badgeContainer && data.policies) {
                var badges = data.policies.map(function(p) {
                  var bl = getBucketLabel(p.bucket);
                  var pl = getPermissionLevel(p.actions);
                  return '<span class="iam-perm-badge">' +
                    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" fill="currentColor" class="me-1" viewBox="0 0 16 16">' +
                    '<path d="M2.522 5H2a.5.5 0 0 0-.494.574l1.372 9.149A1.5 1.5 0 0 0 4.36 16h7.278a1.5 1.5 0 0 0 1.483-1.277l1.373-9.149A.5.5 0 0 0 14 5h-.522A5.5 5.5 0 0 0 2.522 5zm1.005 0a4.5 4.5 0 0 1 8.945 0H3.527z"/>' +
                    '</svg>' + window.UICore.escapeHtml(bl) + ' &middot; ' + window.UICore.escapeHtml(pl) + '</span>';
                }).join('');
                badgeContainer.innerHTML = badges || '<span class="badge bg-secondary bg-opacity-10 text-secondary">No policies</span>';
              }
              if (cardEl) {
                var nowAdmin = isAdminUser(data.policies);
                cardEl.classList.toggle('iam-admin-card', nowAdmin);
                var roleBadgeEl = cardEl.querySelector('[data-role-badge]');
                if (roleBadgeEl) {
                  if (nowAdmin) {
                    roleBadgeEl.className = 'iam-role-badge iam-role-admin';
                    roleBadgeEl.textContent = 'Admin';
                  } else {
                    roleBadgeEl.className = 'iam-role-badge iam-role-user';
                    roleBadgeEl.textContent = 'User';
                  }
                }
              }
            }

            var userIndex = users.findIndex(function(u) { return u.user_id === userId; });
            if (userIndex >= 0 && data.policies) {
              users[userIndex].policies = data.policies;
            }
          }
        });
      });
    }

    var editUserForm = document.getElementById('editUserForm');
    if (editUserForm) {
      editUserForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var key = currentEditKey;
        window.UICore.submitFormAjax(editUserForm, {
          successMessage: 'User updated',
          onSuccess: function(data) {
            editUserModal.hide();

            var newName = data.display_name || document.getElementById('editUserDisplayName').value;
            var editBtn = document.querySelector('[data-edit-user][data-user-id="' + key + '"]');
            if (editBtn) {
              editBtn.setAttribute('data-display-name', newName);
              var card = editBtn.closest('.iam-user-card');
              if (card) {
                var nameEl = card.querySelector('h6');
                if (nameEl) {
                  nameEl.textContent = newName;
                  nameEl.title = newName;
                }
                var itemWrapper = card.closest('.iam-user-item');
                if (itemWrapper) {
                  itemWrapper.setAttribute('data-display-name', newName.toLowerCase());
                }
              }
            }

            var userIndex = users.findIndex(function(u) { return u.user_id === key; });
            if (userIndex >= 0) {
              users[userIndex].display_name = newName;
            }

            if (currentEditAccessKey === currentUserKey) {
              document.querySelectorAll('.sidebar-user .user-name').forEach(function(el) {
                var truncated = newName.length > 16 ? newName.substring(0, 16) + '...' : newName;
                el.textContent = truncated;
                el.title = newName;
              });
              document.querySelectorAll('.sidebar-user[data-username]').forEach(function(el) {
                el.setAttribute('data-username', newName);
              });
            }
          }
        });
      });
    }

    var deleteUserForm = document.getElementById('deleteUserForm');
    if (deleteUserForm) {
      deleteUserForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var key = currentDeleteKey;
        window.UICore.submitFormAjax(deleteUserForm, {
          successMessage: 'User deleted',
          onSuccess: function(data) {
            deleteUserModal.hide();

            if (currentDeleteAccessKey === currentUserKey) {
              window.location.href = '/ui/';
              return;
            }

            var deleteBtn = document.querySelector('[data-delete-user][data-user-id="' + key + '"]');
            if (deleteBtn) {
              var cardCol = deleteBtn.closest('[class*="col-"]');
              if (cardCol) {
                cardCol.remove();
              }
            }

            users = users.filter(function(u) { return u.user_id !== key; });
            updateUserCount();
          }
        });
      });
    }
  }

  function setupSearch() {
    var searchInput = document.getElementById('iam-user-search');
    if (!searchInput) return;

    searchInput.addEventListener('input', function() {
      var query = searchInput.value.toLowerCase().trim();
      var items = document.querySelectorAll('.iam-user-item');
      var noResults = document.getElementById('iam-no-results');
      var visibleCount = 0;

      items.forEach(function(item) {
        var name = item.getAttribute('data-display-name') || '';
        var key = item.getAttribute('data-access-key-filter') || '';
        var matches = !query || name.indexOf(query) >= 0 || key.indexOf(query) >= 0;
        item.classList.toggle('d-none', !matches);
        if (matches) visibleCount++;
      });

      if (noResults) {
        noResults.classList.toggle('d-none', visibleCount > 0);
      }
    });
  }

  function copyAccessKey(btn) {
    var key = btn.getAttribute('data-copy-access-key');
    if (!key) return;
    var originalHtml = btn.innerHTML;
    navigator.clipboard.writeText(key).then(function() {
      btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>';
      btn.style.color = '#22c55e';
      setTimeout(function() {
        btn.innerHTML = originalHtml;
        btn.style.color = '';
      }, 1200);
    }).catch(function() {});
  }

  function setupCopyAccessKeyButtons() {
    document.querySelectorAll('[data-copy-access-key]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        copyAccessKey(btn);
      });
    });
  }

  return {
    init: init
  };
})();
