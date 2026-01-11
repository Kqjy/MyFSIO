window.UICore = (function() {
  'use strict';

  function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) return bytes + ' bytes';
    const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let size = bytes;
    while (size >= 1024 && i < units.length - 1) {
      size /= 1024;
      i++;
    }
    return size.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  async function submitFormAjax(form, options) {
    options = options || {};
    var onSuccess = options.onSuccess || function() {};
    var onError = options.onError || function() {};
    var successMessage = options.successMessage || 'Operation completed';

    var formData = new FormData(form);
    var csrfToken = getCsrfToken();
    var submitBtn = form.querySelector('[type="submit"]');
    var originalHtml = submitBtn ? submitBtn.innerHTML : '';

    try {
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Saving...';
      }

      var formAction = form.getAttribute('action') || form.action;
      var response = await fetch(formAction, {
        method: form.getAttribute('method') || 'POST',
        headers: {
          'X-CSRFToken': csrfToken,
          'Accept': 'application/json',
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: formData,
        redirect: 'follow'
      });

      var contentType = response.headers.get('content-type') || '';
      if (!contentType.includes('application/json')) {
        throw new Error('Server returned an unexpected response. Please try again.');
      }

      var data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'HTTP ' + response.status);
      }

      window.showToast(data.message || successMessage, 'Success', 'success');
      onSuccess(data);

    } catch (err) {
      window.showToast(err.message, 'Error', 'error');
      onError(err);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalHtml;
      }
    }
  }

  function PollingManager() {
    this.intervals = {};
    this.callbacks = {};
    this.timers = {};
    this.defaults = {
      replication: 30000,
      lifecycle: 60000,
      connectionHealth: 60000,
      bucketStats: 120000
    };
    this._loadSettings();
  }

  PollingManager.prototype._loadSettings = function() {
    try {
      var stored = localStorage.getItem('myfsio-polling-intervals');
      if (stored) {
        var settings = JSON.parse(stored);
        for (var key in settings) {
          if (settings.hasOwnProperty(key)) {
            this.defaults[key] = settings[key];
          }
        }
      }
    } catch (e) {
      console.warn('Failed to load polling settings:', e);
    }
  };

  PollingManager.prototype.saveSettings = function(settings) {
    try {
      for (var key in settings) {
        if (settings.hasOwnProperty(key)) {
          this.defaults[key] = settings[key];
        }
      }
      localStorage.setItem('myfsio-polling-intervals', JSON.stringify(this.defaults));
    } catch (e) {
      console.warn('Failed to save polling settings:', e);
    }
  };

  PollingManager.prototype.start = function(key, callback, interval) {
    this.stop(key);
    var ms = interval !== undefined ? interval : (this.defaults[key] || 30000);
    if (ms <= 0) return;

    this.callbacks[key] = callback;
    this.intervals[key] = ms;

    callback();

    var self = this;
    this.timers[key] = setInterval(function() {
      if (!document.hidden) {
        callback();
      }
    }, ms);
  };

  PollingManager.prototype.stop = function(key) {
    if (this.timers[key]) {
      clearInterval(this.timers[key]);
      delete this.timers[key];
    }
  };

  PollingManager.prototype.stopAll = function() {
    for (var key in this.timers) {
      if (this.timers.hasOwnProperty(key)) {
        clearInterval(this.timers[key]);
      }
    }
    this.timers = {};
  };

  PollingManager.prototype.updateInterval = function(key, newInterval) {
    var callback = this.callbacks[key];
    this.defaults[key] = newInterval;
    this.saveSettings(this.defaults);
    if (callback) {
      this.start(key, callback, newInterval);
    }
  };

  PollingManager.prototype.getSettings = function() {
    var result = {};
    for (var key in this.defaults) {
      if (this.defaults.hasOwnProperty(key)) {
        result[key] = this.defaults[key];
      }
    }
    return result;
  };

  var pollingManager = new PollingManager();

  document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
      pollingManager.stopAll();
    } else {
      for (var key in pollingManager.callbacks) {
        if (pollingManager.callbacks.hasOwnProperty(key)) {
          pollingManager.start(key, pollingManager.callbacks[key], pollingManager.intervals[key]);
        }
      }
    }
  });

  return {
    getCsrfToken: getCsrfToken,
    formatBytes: formatBytes,
    escapeHtml: escapeHtml,
    submitFormAjax: submitFormAjax,
    PollingManager: PollingManager,
    pollingManager: pollingManager
  };
})();

window.pollingManager = window.UICore.pollingManager;

window.UICore.copyToClipboard = async function(text, button, originalText) {
  try {
    await navigator.clipboard.writeText(text);
    if (button) {
      var prevText = button.textContent;
      button.textContent = 'Copied!';
      setTimeout(function() {
        button.textContent = originalText || prevText;
      }, 1500);
    }
    return true;
  } catch (err) {
    console.error('Copy failed:', err);
    return false;
  }
};

window.UICore.setButtonLoading = function(button, isLoading, loadingText) {
  if (!button) return;
  if (isLoading) {
    button._originalHtml = button.innerHTML;
    button._originalDisabled = button.disabled;
    button.disabled = true;
    button.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>' + (loadingText || 'Loading...');
  } else {
    button.disabled = button._originalDisabled || false;
    button.innerHTML = button._originalHtml || button.innerHTML;
  }
};

window.UICore.updateBadgeCount = function(selector, count, singular, plural) {
  var badge = document.querySelector(selector);
  if (badge) {
    var label = count === 1 ? (singular || '') : (plural || 's');
    badge.textContent = count + ' ' + label;
  }
};

window.UICore.setupJsonAutoIndent = function(textarea) {
  if (!textarea) return;

  textarea.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();

      var start = this.selectionStart;
      var end = this.selectionEnd;
      var value = this.value;

      var lineStart = value.lastIndexOf('\n', start - 1) + 1;
      var currentLine = value.substring(lineStart, start);

      var indentMatch = currentLine.match(/^(\s*)/);
      var indent = indentMatch ? indentMatch[1] : '';

      var trimmedLine = currentLine.trim();
      var lastChar = trimmedLine.slice(-1);

      var newIndent = indent;
      var insertAfter = '';

      if (lastChar === '{' || lastChar === '[') {
        newIndent = indent + '  ';

        var charAfterCursor = value.substring(start, start + 1).trim();
        if ((lastChar === '{' && charAfterCursor === '}') ||
            (lastChar === '[' && charAfterCursor === ']')) {
          insertAfter = '\n' + indent;
        }
      } else if (lastChar === ',' || lastChar === ':') {
        newIndent = indent;
      }

      var insertion = '\n' + newIndent + insertAfter;
      var newValue = value.substring(0, start) + insertion + value.substring(end);

      this.value = newValue;

      var newCursorPos = start + 1 + newIndent.length;
      this.selectionStart = this.selectionEnd = newCursorPos;

      this.dispatchEvent(new Event('input', { bubbles: true }));
    }

    if (e.key === 'Tab') {
      e.preventDefault();
      var start = this.selectionStart;
      var end = this.selectionEnd;

      if (e.shiftKey) {
        var lineStart = this.value.lastIndexOf('\n', start - 1) + 1;
        var lineContent = this.value.substring(lineStart, start);
        if (lineContent.startsWith('  ')) {
          this.value = this.value.substring(0, lineStart) +
                       this.value.substring(lineStart + 2);
          this.selectionStart = this.selectionEnd = Math.max(lineStart, start - 2);
        }
      } else {
        this.value = this.value.substring(0, start) + '  ' + this.value.substring(end);
        this.selectionStart = this.selectionEnd = start + 2;
      }

      this.dispatchEvent(new Event('input', { bubbles: true }));
    }
  });
};
