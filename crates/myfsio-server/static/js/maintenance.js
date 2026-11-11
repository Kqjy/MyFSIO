(function () {
  var csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  var formatBytes = window.MyFSIO.formatBytes;

  var pageConfig = document.getElementById('maintenancePageConfig').dataset;
  var _displayTimezone = pageConfig.displayTimezone;

  function formatTimestamp(ts) {
    var d = new Date(ts * 1000);
    try {
      var opts = {year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: _displayTimezone, timeZoneName: 'short'};
      return d.toLocaleString('en-US', opts);
    } catch (e) {
      var pad = function (n) { return n < 10 ? '0' + n : '' + n; };
      return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) +
             ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ' UTC';
    }
  }

  function formatDuration(seconds) {
    if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) return '—';
    var roundedHundredths = Math.round(seconds * 100) / 100;
    if (roundedHundredths < 60) return roundedHundredths.toFixed(2) + 's';

    var totalSeconds = Math.round(seconds);
    var hours = Math.floor(totalSeconds / 3600);
    var minutes = Math.floor((totalSeconds % 3600) / 60);
    var remainingSeconds = totalSeconds % 60;
    var pad = function (value) { return value < 10 ? '0' + value : '' + value; };
    if (hours > 0) return hours + 'h ' + pad(minutes) + 'm ' + pad(remainingSeconds) + 's';
    return minutes + 'm ' + pad(remainingSeconds) + 's';
  }

  var _gcHistoryIcon = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16">' +
    '<path d="M8.515 1.019A7 7 0 0 0 8 1V0a8 8 0 0 1 .589.022l-.074.997zm2.004.45a7.003 7.003 0 0 0-.985-.299l.219-.976c.383.086.76.2 1.126.342l-.36.933zm1.37.71a7.01 7.01 0 0 0-.439-.27l.493-.87a8.025 8.025 0 0 1 .979.654l-.615.789a6.996 6.996 0 0 0-.418-.302zm1.834 1.79a6.99 6.99 0 0 0-.653-.796l.724-.69c.27.285.52.59.747.91l-.818.576zm.744 1.352a7.08 7.08 0 0 0-.214-.468l.893-.45a7.976 7.976 0 0 1 .45 1.088l-.95.313a7.023 7.023 0 0 0-.179-.483zm.53 2.507a6.991 6.991 0 0 0-.1-1.025l.985-.17c.067.386.106.778.116 1.17l-1 .025zm-.131 1.538c.033-.17.06-.339.081-.51l.993.123a7.957 7.957 0 0 1-.23 1.155l-.964-.267c.046-.165.086-.332.12-.501zm-.952 2.379c.184-.29.346-.594.486-.908l.914.405c-.16.36-.345.706-.555 1.038l-.845-.535zm-.964 1.205c.122-.122.239-.248.35-.378l.758.653a8.073 8.073 0 0 1-.401.432l-.707-.707z"/>' +
    '<path d="M8 1a7 7 0 1 0 4.95 11.95l.707.707A8.001 8.001 0 1 1 8 0v1z"/>' +
    '<path d="M7.5 3a.5.5 0 0 1 .5.5v5.21l3.248 1.856a.5.5 0 0 1-.496.868l-3.5-2A.5.5 0 0 1 7 8V3.5a.5.5 0 0 1 .5-.5z"/></svg>';

  function _gcRefreshHistory() {
    fetch(pageConfig.gcHistoryUrl + '?limit=10', {
      headers: {'X-CSRFToken': csrfToken},
      cache: 'no-store'
    })
    .then(function (r) { return r.json(); })
    .then(function (hist) {
      var container = document.getElementById('gcHistoryContainer');
      if (!container) return;
      var execs = hist.executions || [];
      if (execs.length === 0) {
        container.innerHTML = '<div class="text-center py-2"><p class="text-muted small mb-0">No executions recorded yet.</p></div>';
        return;
      }
      var html = '<h6 class="fw-semibold small text-muted mb-2 d-flex align-items-center gap-2">' +
        _gcHistoryIcon + ' Recent Executions</h6>' +
        '<div class="table-responsive"><table class="table table-sm small mb-0">' +
        '<thead class="table-light"><tr><th>Time</th><th class="text-center">Cleaned</th>' +
        '<th class="text-center">Freed</th><th class="text-center">Duration</th>' +
        '<th class="text-center">Mode</th></tr></thead><tbody>';
      execs.forEach(function (exec) {
        var r = exec.result || {};
        var cleaned = (r.temp_files_deleted || 0) + (r.multipart_uploads_deleted || 0) +
          (r.lock_files_deleted || 0) + (r.orphaned_metadata_deleted || 0) +
          (r.orphaned_versions_deleted || 0) + (r.empty_dirs_removed || 0) +
          (r.quarantine_entries_deleted || 0);
        var freed = r.total_bytes_freed != null ? r.total_bytes_freed :
          (r.temp_bytes_freed || 0) + (r.quarantine_bytes_freed || 0) +
          (r.multipart_bytes_freed || 0) + (r.orphaned_version_bytes_freed || 0);
        var mode = exec.dry_run
          ? '<span class="badge bg-warning bg-opacity-10 text-warning">Dry run</span>'
          : '<span class="badge bg-primary bg-opacity-10 text-primary">Live</span>';
        html += '<tr><td class="text-nowrap">' + formatTimestamp(exec.timestamp) + '</td>' +
          '<td class="text-center">' + cleaned + '</td>' +
          '<td class="text-center">' + formatBytes(freed) + '</td>' +
          '<td class="text-center text-nowrap">' + formatDuration(r.execution_time_seconds) + '</td>' +
          '<td class="text-center">' + mode + '</td></tr>';
      });
      html += '</tbody></table></div>';
      container.innerHTML = html;
    })
    .catch(function () {});
  }

  function _integrityRefreshHistory() {
    fetch(pageConfig.integrityHistoryUrl + '?limit=10', {
      headers: {'X-CSRFToken': csrfToken},
      cache: 'no-store'
    })
    .then(function (r) { return r.json(); })
    .then(function (hist) {
      var container = document.getElementById('integrityHistoryContainer');
      if (!container) return;
      var execs = hist.executions || [];
      if (execs.length === 0) {
        container.innerHTML = '<div class="text-center py-2"><p class="text-muted small mb-0">No scans recorded yet.</p></div>';
        return;
      }
      var html = '<h6 class="fw-semibold small text-muted mb-2 d-flex align-items-center gap-2">' +
        _gcHistoryIcon + ' Recent Scans</h6>' +
        '<div class="table-responsive"><table class="table table-sm small mb-0">' +
        '<thead class="table-light"><tr><th>Time</th><th class="text-center">Scanned</th>' +
        '<th class="text-center">Issues</th><th class="text-center">Healed</th>' +
        '<th class="text-center">Duration</th>' +
        '<th class="text-center">Mode</th></tr></thead><tbody>';
      execs.forEach(function (exec) {
        var r = exec.result || {};
        var issues = (r.corrupted_objects || 0) + (r.orphaned_objects || 0) +
          (r.phantom_metadata || 0) + (r.stale_versions || 0) +
          (r.legacy_metadata_drifts || 0) +
          (r.poisoned_objects || 0) + (r.invalid_metadata_keys || 0);
        var issueHtml = issues > 0
          ? '<span class="text-danger fw-medium">' + issues + '</span>'
          : '<span class="text-success">0</span>';
        var mode = exec.dry_run
          ? '<span class="badge bg-warning bg-opacity-10 text-warning">Dry</span>'
          : (exec.auto_heal
            ? '<span class="badge bg-success bg-opacity-10 text-success">Heal</span>'
            : '<span class="badge bg-primary bg-opacity-10 text-primary">Scan</span>');
        html += '<tr><td class="text-nowrap">' + formatTimestamp(exec.timestamp) + '</td>' +
          '<td class="text-center">' + (r.objects_scanned || 0) + '</td>' +
          '<td class="text-center">' + issueHtml + '</td>' +
          '<td class="text-center">' + (r.issues_healed || 0) + '</td>' +
          '<td class="text-center text-nowrap">' + formatDuration(r.execution_time_seconds) + '</td>' +
          '<td class="text-center">' + mode + '</td></tr>';
      });
      html += '</tbody></table></div>';
      container.innerHTML = html;
    })
    .catch(function () {});
  }

  function makeStatusPoller(opts) {
    var timer = null;
    var failures = 0;
    function schedule(ms) {
      clearTimeout(timer);
      timer = setTimeout(tick, ms);
    }
    function tick() {
      if (document.hidden) {
        schedule(2000);
        return;
      }
      fetch(opts.statusUrl, {
        headers: {'X-CSRFToken': csrfToken},
        cache: 'no-store'
      })
      .then(function (r) {
        if (!r.ok) throw new Error('status ' + r.status);
        return r.json();
      })
      .then(function (status) {
        failures = 0;
        if (status.scanning) {
          var elapsed = status.scan_elapsed_seconds || 0;
          document.getElementById(opts.elapsedId).textContent = ' (' + elapsed.toFixed(0) + 's)';
          schedule(2000);
        } else {
          opts.setScanning(false);
          opts.onDone();
        }
      })
      .catch(function () {
        failures++;
        schedule(failures >= 5 ? 15000 : 3000);
      });
    }
    return {
      start: function () {
        failures = 0;
        schedule(2000);
      }
    };
  }

  function _gcSetScanning(scanning) {
    var banner = document.getElementById('gcScanningBanner');
    var btns = ['gcRunBtn', 'gcDryRunBtn'];
    if (scanning) {
      banner.classList.remove('d-none');
      btns.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.disabled = true;
      });
    } else {
      banner.classList.add('d-none');
      document.getElementById('gcScanElapsed').textContent = '';
      btns.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.disabled = false;
      });
    }
  }

  function _gcShowResult(data, dryRun) {
    var container = document.getElementById('gcResult');
    var alert = document.getElementById('gcResultAlert');
    var title = document.getElementById('gcResultTitle');
    var body = document.getElementById('gcResultBody');
    container.classList.remove('d-none');

    var totalItems = (data.temp_files_deleted || 0) + (data.multipart_uploads_deleted || 0) +
                      (data.lock_files_deleted || 0) + (data.orphaned_metadata_deleted || 0) +
                      (data.orphaned_versions_deleted || 0) + (data.empty_dirs_removed || 0) +
                      (data.quarantine_entries_deleted || 0);
    var totalFreed = data.total_bytes_freed != null ? data.total_bytes_freed :
                     (data.temp_bytes_freed || 0) + (data.quarantine_bytes_freed || 0) +
                     (data.multipart_bytes_freed || 0) + (data.orphaned_version_bytes_freed || 0);

    alert.className = totalItems > 0 ? 'alert alert-success mb-0 small' : 'alert alert-info mb-0 small';
    title.textContent = (dryRun ? '[Dry Run] ' : '') + 'Completed in ' + (data.execution_time_seconds || 0).toFixed(2) + 's';

    var lines = [];
    if (data.temp_files_deleted) lines.push('Temp files: ' + data.temp_files_deleted + ' (' + formatBytes(data.temp_bytes_freed) + ')');
    if (data.multipart_uploads_deleted) lines.push('Multipart uploads: ' + data.multipart_uploads_deleted + ' (' + formatBytes(data.multipart_bytes_freed) + ')');
    if (data.lock_files_deleted) lines.push('Lock files: ' + data.lock_files_deleted);
    if (data.orphaned_metadata_deleted) lines.push('Orphaned metadata: ' + data.orphaned_metadata_deleted);
    if (data.orphaned_versions_deleted) lines.push('Orphaned versions: ' + data.orphaned_versions_deleted + ' (' + formatBytes(data.orphaned_version_bytes_freed) + ')');
    if (data.quarantine_entries_deleted) lines.push('Quarantine entries: ' + data.quarantine_entries_deleted + ' (' + formatBytes(data.quarantine_bytes_freed) + ')');
    if (data.quarantine_entries_protected) lines.push('Quarantine entries retained for recovery: ' + data.quarantine_entries_protected);
    if (data.empty_dirs_removed) lines.push('Empty directories: ' + data.empty_dirs_removed);
    if (totalItems === 0) lines.push('Nothing to clean up.');
    if (totalFreed > 0) lines.push('Total freed: ' + formatBytes(totalFreed));
    if (data.errors && data.errors.length > 0) lines.push('Errors: ' + data.errors.join(', '));

    body.innerHTML = lines.join('<br>');
  }

  var _gcPoller = makeStatusPoller({
    statusUrl: pageConfig.gcStatusUrl,
    elapsedId: 'gcScanElapsed',
    setScanning: _gcSetScanning,
    onDone: function () {
      _gcRefreshHistory();
      fetch(pageConfig.gcHistoryUrl + '?limit=1', {
        headers: {'X-CSRFToken': csrfToken},
        cache: 'no-store'
      })
      .then(function (r) { return r.json(); })
      .then(function (hist) {
        if (hist.executions && hist.executions.length > 0) {
          var latest = hist.executions[0];
          _gcShowResult(latest.result, latest.dry_run);
        }
      })
      .catch(function () {});
    }
  });

  function runGC(dryRun) {
    document.getElementById('gcResult').classList.add('d-none');
    _gcSetScanning(true);

    fetch(pageConfig.gcRunUrl, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken},
      body: JSON.stringify({dry_run: dryRun})
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.error) {
        _gcSetScanning(false);
        var container = document.getElementById('gcResult');
        var alert = document.getElementById('gcResultAlert');
        var title = document.getElementById('gcResultTitle');
        var body = document.getElementById('gcResultBody');
        container.classList.remove('d-none');
        alert.className = 'alert alert-danger mb-0 small';
        title.textContent = 'Error';
        body.textContent = data.error;
        return;
      }
      if (data.status === 'started' || data.scanning === true || data.running === true) {
        _gcPoller.start();
        return;
      }
      _gcSetScanning(false);
      _gcShowResult(data, dryRun);
      _gcRefreshHistory();
    })
    .catch(function (err) {
      _gcSetScanning(false);
      var container = document.getElementById('gcResult');
      var alert = document.getElementById('gcResultAlert');
      var title = document.getElementById('gcResultTitle');
      var body = document.getElementById('gcResultBody');
      container.classList.remove('d-none');
      alert.className = 'alert alert-danger mb-0 small';
      title.textContent = 'Error';
      body.textContent = err.message;
    });
  };

  if (pageConfig.gcScanning === 'true') {
  _gcSetScanning(true);
  _gcPoller.start();
  }

  function _integritySetScanning(scanning) {
    var banner = document.getElementById('integrityScanningBanner');
    var btns = ['integrityRunBtn', 'integrityHealBtn', 'integrityDryRunBtn'];
    if (scanning) {
      banner.classList.remove('d-none');
      btns.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.disabled = true;
      });
    } else {
      banner.classList.add('d-none');
      document.getElementById('integrityScanElapsed').textContent = '';
      btns.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.disabled = false;
      });
    }
  }

  function _integrityShowResult(data, dryRun, autoHeal) {
    var container = document.getElementById('integrityResult');
    var alert = document.getElementById('integrityResultAlert');
    var title = document.getElementById('integrityResultTitle');
    var body = document.getElementById('integrityResultBody');
    container.classList.remove('d-none');

    var totalIssues = (data.corrupted_objects || 0) + (data.orphaned_objects || 0) +
                       (data.phantom_metadata || 0) + (data.stale_versions || 0) +
                       (data.legacy_metadata_drifts || 0) +
                       (data.poisoned_objects || 0) + (data.invalid_metadata_keys || 0);

    var prefix = dryRun ? '[Dry Run] ' : (autoHeal ? '[Heal] ' : '');
    alert.className = totalIssues > 0 ? 'alert alert-warning mb-0 small' : 'alert alert-success mb-0 small';
    title.textContent = prefix + 'Completed in ' + (data.execution_time_seconds || 0).toFixed(2) + 's';

    var lines = [];
    lines.push('Scanned: ' + (data.objects_scanned || 0) + ' objects in ' + (data.buckets_scanned || 0) + ' buckets');
    lines.push('Checksummed: ' + (data.checksummed_objects || 0) +
      ' (multipart: ' + (data.multipart_objects_checked || 0) + ')');
    if (data.encrypted_objects_unverifiable) {
      lines.push('Encrypted objects not content-verified: ' + data.encrypted_objects_unverifiable);
    }
    if (data.multipart_objects_unverifiable) {
      lines.push('Multipart objects without a part-size manifest: ' + data.multipart_objects_unverifiable);
    }
    if (data.version_contents_unverifiable) {
      lines.push('Version contents not checksummed: ' + data.version_contents_unverifiable);
    }
    if (totalIssues === 0) {
      lines.push('No issues found.');
    } else {
      if (data.corrupted_objects) lines.push('Corrupted objects: ' + data.corrupted_objects);
      if (data.orphaned_objects) lines.push('Orphaned objects: ' + data.orphaned_objects);
      if (data.phantom_metadata) lines.push('Phantom metadata: ' + data.phantom_metadata);
      if (data.stale_versions) lines.push('Stale versions: ' + data.stale_versions);
      if (data.legacy_metadata_drifts) lines.push('Legacy metadata drifts: ' + data.legacy_metadata_drifts);
      if (data.poisoned_objects) lines.push('Awaiting recovery: ' + data.poisoned_objects);
      if (data.invalid_metadata_keys) lines.push('Invalid metadata keys: ' + data.invalid_metadata_keys);
      if (data.issues_healed) lines.push('Issues healed: ' + data.issues_healed);
      if (data.issues_would_heal) lines.push('Issues that would be healed: ' + data.issues_would_heal);
    }
    if (data.errors && data.errors.length > 0) lines.push('Errors: ' + data.errors.join(', '));

    body.innerHTML = lines.join('<br>');
  }

  var _integrityPoller = makeStatusPoller({
    statusUrl: pageConfig.integrityStatusUrl,
    elapsedId: 'integrityScanElapsed',
    setScanning: _integritySetScanning,
    onDone: function () {
      _integrityRefreshHistory();
      fetch(pageConfig.integrityHistoryUrl + '?limit=1', {
        headers: {'X-CSRFToken': csrfToken},
        cache: 'no-store'
      })
      .then(function (r) { return r.json(); })
      .then(function (hist) {
        if (hist.executions && hist.executions.length > 0) {
          var latest = hist.executions[0];
          _integrityShowResult(latest.result, latest.dry_run, latest.auto_heal);
        }
      })
      .catch(function () {});
    }
  });

  function runIntegrity(dryRun, autoHeal) {
    document.getElementById('integrityResult').classList.add('d-none');
    _integritySetScanning(true);

    fetch(pageConfig.integrityRunUrl, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrfToken},
      body: JSON.stringify({dry_run: dryRun, auto_heal: autoHeal})
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.error) {
        _integritySetScanning(false);
        var container = document.getElementById('integrityResult');
        var alert = document.getElementById('integrityResultAlert');
        var title = document.getElementById('integrityResultTitle');
        var body = document.getElementById('integrityResultBody');
        container.classList.remove('d-none');
        alert.className = 'alert alert-danger mb-0 small';
        title.textContent = 'Error';
        body.textContent = data.error;
        return;
      }
      if (data.status === 'started' || data.scanning === true || data.running === true) {
        _integrityPoller.start();
        return;
      }
      _integritySetScanning(false);
      _integrityShowResult(data, dryRun, autoHeal);
      _integrityRefreshHistory();
    })
    .catch(function (err) {
      _integritySetScanning(false);
      var container = document.getElementById('integrityResult');
      var alert = document.getElementById('integrityResultAlert');
      var title = document.getElementById('integrityResultTitle');
      var body = document.getElementById('integrityResultBody');
      container.classList.remove('d-none');
      alert.className = 'alert alert-danger mb-0 small';
      title.textContent = 'Error';
      body.textContent = err.message;
    });
  };

  document.querySelectorAll('[data-gc-run]').forEach(function (button) {
    button.addEventListener('click', function () {
      runGC(button.getAttribute('data-gc-run') === 'dry');
    });
  });

  document.querySelectorAll('[data-integrity-run]').forEach(function (button) {
    button.addEventListener('click', function () {
      var mode = button.getAttribute('data-integrity-run');
      runIntegrity(mode === 'dry', mode !== 'scan');
    });
  });

  document.querySelectorAll('[data-dismiss-result]').forEach(function (button) {
    button.addEventListener('click', function () {
      document.getElementById(button.getAttribute('data-dismiss-result')).classList.add('d-none');
    });
  });

  if (pageConfig.integrityScanning === 'true') {
  _integritySetScanning(true);
  _integrityPoller.start();
  }
})();
