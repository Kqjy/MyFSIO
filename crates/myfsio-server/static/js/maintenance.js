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
        container.innerHTML = '<p class="ui-muted mt-none">No executions recorded yet.</p>';
        return;
      }
      var html = '<h3 class="mt-subhead">Recent executions</h3>' +
        '<div class="ui-table-wrap"><table class="ui-table mt-history">' +
        '<thead><tr><th scope="col">Time</th><th scope="col" class="st-num">Cleaned</th>' +
        '<th scope="col" class="st-num">Freed</th><th scope="col" class="st-num">Duration</th>' +
        '<th scope="col">Mode</th></tr></thead><tbody>';
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
          ? '<span class="ui-badge ui-badge-warn">Dry run</span>'
          : '<span class="ui-badge ui-badge-accent">Live</span>';
        html += '<tr><td class="mt-when">' + formatTimestamp(exec.timestamp) + '</td>' +
          '<td class="st-num">' + cleaned + '</td>' +
          '<td class="st-num">' + formatBytes(freed) + '</td>' +
          '<td class="st-num">' + formatDuration(r.execution_time_seconds) + '</td>' +
          '<td>' + mode + '</td></tr>';
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
        container.innerHTML = '<p class="ui-muted mt-none">No scans recorded yet.</p>';
        return;
      }
      var html = '<h3 class="mt-subhead">Recent scans</h3>' +
        '<div class="ui-table-wrap"><table class="ui-table mt-history">' +
        '<thead><tr><th scope="col">Time</th><th scope="col" class="st-num">Scanned</th>' +
        '<th scope="col" class="st-num">Issues</th><th scope="col" class="st-num">Healed</th>' +
        '<th scope="col" class="st-num">Duration</th>' +
        '<th scope="col">Mode</th></tr></thead><tbody>';
      execs.forEach(function (exec) {
        var r = exec.result || {};
        var issues = (r.corrupted_objects || 0) + (r.orphaned_objects || 0) +
          (r.phantom_metadata || 0) + (r.stale_versions || 0) +
          (r.legacy_metadata_drifts || 0) +
          (r.poisoned_objects || 0) + (r.invalid_metadata_keys || 0);
        var issueHtml = issues > 0
          ? '<strong class="st-bad">' + issues + '</strong>'
          : '<span class="st-ok">0</span>';
        var mode = exec.dry_run
          ? '<span class="ui-badge ui-badge-warn">Dry</span>'
          : (exec.auto_heal
            ? '<span class="ui-badge ui-badge-ok">Heal</span>'
            : '<span class="ui-badge ui-badge-accent">Scan</span>');
        html += '<tr><td class="mt-when">' + formatTimestamp(exec.timestamp) + '</td>' +
          '<td class="st-num">' + (r.objects_scanned || 0) + '</td>' +
          '<td class="st-num">' + issueHtml + '</td>' +
          '<td class="st-num">' + (r.issues_healed || 0) + '</td>' +
          '<td class="st-num">' + formatDuration(r.execution_time_seconds) + '</td>' +
          '<td>' + mode + '</td></tr>';
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
      banner.classList.remove('is-hidden');
      btns.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.disabled = true;
      });
    } else {
      banner.classList.add('is-hidden');
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
    container.classList.remove('is-hidden');

    var totalItems = (data.temp_files_deleted || 0) + (data.multipart_uploads_deleted || 0) +
                      (data.lock_files_deleted || 0) + (data.orphaned_metadata_deleted || 0) +
                      (data.orphaned_versions_deleted || 0) + (data.empty_dirs_removed || 0) +
                      (data.quarantine_entries_deleted || 0);
    var totalFreed = data.total_bytes_freed != null ? data.total_bytes_freed :
                     (data.temp_bytes_freed || 0) + (data.quarantine_bytes_freed || 0) +
                     (data.multipart_bytes_freed || 0) + (data.orphaned_version_bytes_freed || 0);

    alert.className = totalItems > 0 ? 'adm-note adm-note-ok' : 'adm-note';
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
    document.getElementById('gcResult').classList.add('is-hidden');
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
        container.classList.remove('is-hidden');
        alert.className = 'adm-note adm-note-bad';
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
      container.classList.remove('is-hidden');
      alert.className = 'adm-note adm-note-bad';
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
      banner.classList.remove('is-hidden');
      btns.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.disabled = true;
      });
    } else {
      banner.classList.add('is-hidden');
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
    container.classList.remove('is-hidden');

    var totalIssues = (data.corrupted_objects || 0) + (data.orphaned_objects || 0) +
                       (data.phantom_metadata || 0) + (data.stale_versions || 0) +
                       (data.legacy_metadata_drifts || 0) +
                       (data.poisoned_objects || 0) + (data.invalid_metadata_keys || 0);

    var prefix = dryRun ? '[Dry Run] ' : (autoHeal ? '[Heal] ' : '');
    alert.className = totalIssues > 0 ? 'adm-note adm-note-warn' : 'adm-note adm-note-ok';
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
    document.getElementById('integrityResult').classList.add('is-hidden');
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
        container.classList.remove('is-hidden');
        alert.className = 'adm-note adm-note-bad';
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
      container.classList.remove('is-hidden');
      alert.className = 'adm-note adm-note-bad';
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
      document.getElementById(button.getAttribute('data-dismiss-result')).classList.add('is-hidden');
    });
  });

  if (pageConfig.integrityScanning === 'true') {
  _integritySetScanning(true);
  _integrityPoller.start();
  }
})();
