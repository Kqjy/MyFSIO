var metricsPageConfig = document.getElementById('metricsPageConfig').dataset;
var _displayTimezone = metricsPageConfig.displayTimezone;

function withDisplayTimezone(opts) {
  var out = {};
  Object.keys(opts).forEach(function(key) { out[key] = opts[key]; });
  out.timeZone = _displayTimezone;
  return out;
}

function formatTime(ts) {
  var d = new Date(ts);
  if (isNaN(d.getTime())) return '—';
  var opts = { hour: '2-digit', minute: '2-digit' };
  try {
    return d.toLocaleTimeString('en-US', withDisplayTimezone(opts));
  } catch (e) {
    return d.toLocaleTimeString('en-US', opts);
  }
}

function formatChartDate(ts) {
  var d = new Date(ts);
  if (isNaN(d.getTime())) return '';
  var opts = { month: 'short', day: 'numeric' };
  try {
    return d.toLocaleDateString('en-US', withDisplayTimezone(opts));
  } catch (e) {
    return d.toLocaleDateString('en-US', opts);
  }
}

function chartDayKey(ts) {
  var d = new Date(ts);
  if (isNaN(d.getTime())) return '';
  var opts = { year: 'numeric', month: '2-digit', day: '2-digit' };
  try {
    return d.toLocaleDateString('en-US', withDisplayTimezone(opts));
  } catch (e) {
    return d.toLocaleDateString('en-US', opts);
  }
}

function formatFullTimestamp(ts) {
  var d = new Date(ts);
  if (isNaN(d.getTime())) return '—';
  var opts = { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' };
  try {
    return d.toLocaleString('en-US', withDisplayTimezone(opts));
  } catch (e) {
    return d.toISOString();
  }
}

function buildChartLabels(timestamps) {
  var keys = timestamps.map(chartDayKey).filter(function(key) { return key !== ''; });
  var spansDays = keys.length > 1 && keys[0] !== keys[keys.length - 1];
  return timestamps.map(function(ts) {
    return spansDays ? [formatChartDate(ts), formatTime(ts)] : formatTime(ts);
  });
}

function chartTooltipTitle(getTimestamps) {
  return function(items) {
    if (!items || !items.length) return '';
    var timestamps = getTimestamps() || [];
    var ts = timestamps[items[0].dataIndex];
    return ts === undefined ? '' : formatFullTimestamp(ts);
  };
}

function formatEventTimestamp(ts) {
  var d = new Date(ts);
  if (isNaN(d.getTime())) return { date: '—', time: '', full: '' };
  var dateOpts = { month: 'short', day: '2-digit', timeZone: _displayTimezone };
  var timeOpts = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: _displayTimezone };
  var fullOpts = { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: _displayTimezone, timeZoneName: 'short' };
  try {
    return {
      date: d.toLocaleDateString('en-US', dateOpts),
      time: d.toLocaleTimeString('en-US', timeOpts),
      full: d.toLocaleString('en-US', fullOpts)
    };
  } catch (e) {
    var iso = d.toISOString();
    return { date: iso.slice(0, 10), time: iso.slice(11, 19) + 'Z', full: iso };
  }
}

function formatUptime(seconds) {
  seconds = Math.max(0, Number(seconds) || 0);
  if (seconds < 86400) {
    var hours = Math.floor(seconds / 3600);
    var minutes = Math.floor((seconds % 3600) / 60);
    return hours + 'h ' + minutes + 'm';
  }
  var days = Math.floor(seconds / 86400);
  var remHours = Math.floor((seconds % 86400) / 3600);
  return days + 'd ' + remHours + 'h';
}

function parseMetricsResponse(response) {
  if (!response.ok) throw new Error('Request failed with status ' + response.status);
  return response.json();
}

try {
(function() {
  var POLL_INTERVAL = 5000;
  var paused = false;
  window.__metricsPaused = false;
  var chartsAvailable = typeof SvgChart !== 'undefined';
  if (!chartsAvailable) {
    var chartBanner = document.getElementById('metrics-error-banner');
    if (chartBanner) {
      chartBanner.classList.remove('d-none');
      var chartBannerMsg = chartBanner.querySelector('div');
      if (chartBannerMsg) chartBannerMsg.textContent = 'Charts unavailable: the chart module failed to load. Metric values will still refresh, but gauges and graphs cannot be drawn.';
    }
  }
  var countdown = 5;
  var countdownEl = document.getElementById('refreshCountdown');
  var pauseBtn = document.getElementById('pauseBtn');
  var pauseIcon = document.getElementById('pauseIcon');
  var playIcon = document.getElementById('playIcon');
  var refreshBtn = document.getElementById('refreshMetricsBtn');
  var liveDot = document.getElementById('liveIndicatorDot');
  var countdownTimer = null;
  var fetchTimer = null;

  var HEALTH_CHECK_LABELS = {
    cpu: 'CPU',
    memory: 'memory',
    disk: 'disk space',
    server_errors: 'S3 5xx rate (15 min)',
    disk_queue: 'disk queue (5 min)',
    replication: 'replication'
  };
  var HEALTH_ICONS = {
    ok: '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>',
    warning: '<path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>',
    critical: '<path d="M11.46.146A.5.5 0 0 0 11.107 0H4.893a.5.5 0 0 0-.353.146L.146 4.54A.5.5 0 0 0 0 4.893v6.214a.5.5 0 0 0 .146.353l4.394 4.394a.5.5 0 0 0 .353.146h6.214a.5.5 0 0 0 .353-.146l4.394-4.394a.5.5 0 0 0 .146-.353V4.893a.5.5 0 0 0-.146-.353L11.46.146zM8 4c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 4.995A.905.905 0 0 1 8 4zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/>'
  };

  function escapeText(value) {
    if (window.UICore && window.UICore.escapeHtml) return window.UICore.escapeHtml(value);
    if (value === null || value === undefined) return '';
    return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  function renderHealth(health) {
    if (!health) return;
    var status = HEALTH_ICONS[health.status] ? health.status : 'ok';
    var issues = health.issues || [];
    var banner = document.getElementById('healthBanner');
    if (banner) banner.className = 'card border-0 shadow-sm mb-4 health-banner health-' + status;
    var icon = document.getElementById('healthBannerIcon');
    if (icon) icon.innerHTML = HEALTH_ICONS[status];
    var title = document.getElementById('healthTitle');
    if (title) title.textContent = status === 'critical' ? 'Critical issues detected' : (status === 'warning' ? 'Needs attention' : 'All systems normal');
    var detail = document.getElementById('healthDetail');
    if (detail) {
      detail.textContent = issues.length > 0
        ? issues.length + ' issue' + (issues.length === 1 ? '' : 's')
        : 'Checked ' + (health.checks || []).map(function(check) { return HEALTH_CHECK_LABELS[check] || check; }).join(', ');
    }
    var list = document.getElementById('healthIssues');
    if (list) {
      list.innerHTML = issues.map(function(issue) {
        var critical = issue.severity === 'critical';
        return '<li><span class="badge ' + (critical ? 'bg-danger-subtle text-danger-emphasis' : 'bg-warning-subtle text-warning-emphasis') + '">' + (critical ? 'Critical' : 'Warning') + '</span> ' +
          '<span class="fw-semibold">' + escapeText(issue.label) + '</span> ' +
          '<span class="text-muted">' + escapeText(issue.detail) + '</span></li>';
      }).join('');
      list.classList.toggle('d-none', issues.length === 0);
    }
  }

  var sparklineBuffers = { cpu: [], mem: [], disk: [] };
  var SPARK_MAX = 60;

  var gaugeBg = 'rgba(128, 128, 128, 0.08)';

  function createGauge(id, value, color, warnValue) {
    if (!chartsAvailable) return null;
    var ctx = document.getElementById(id);
    if (!ctx) return null;
    return new SvgChart(ctx, {
      type: 'doughnut',
      data: {
        datasets: [{
          data: [value, Math.max(0, 100 - value)],
          backgroundColor: [color, gaugeBg],
          borderWidth: 0,
          borderRadius: 2
        }]
      },
      options: {
        cutout: '76%',
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { display: false },
          tooltip: { enabled: false },
          gaugeCenter: { warnValue: warnValue || 999 }
        }
      }
    });
  }

  function createSparkline(id, color) {
    if (!chartsAvailable) return null;
    var ctx = document.getElementById(id);
    if (!ctx) return null;
    return new SvgChart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          data: [],
          borderColor: color,
          backgroundColor: color + '15',
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 1.5
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: { legend: { display: false }, tooltip: { enabled: false }, emptyState: { disabled: true } },
        scales: {
          x: { display: false },
          y: { display: false, min: 0, max: 100 }
        }
      }
    });
  }

  var cpuGauge = createGauge('cpuGauge', Number(metricsPageConfig.cpuPercent) || 0, '#3b82f6', 80);
  var memGauge = createGauge('memGauge', Number(metricsPageConfig.memoryPercent) || 0, '#06b6d4', 85);
  var diskGauge = createGauge('diskGauge', Number(metricsPageConfig.diskPercent) || 0, '#f59e0b', 90);

  var cpuSpark = createSparkline('cpuSparkline', '#3b82f6');
  var memSpark = createSparkline('memSparkline', '#06b6d4');
  var diskSpark = createSparkline('diskSparkline', '#f59e0b');

  function updateGauge(chart, value) {
    if (!chart) return;
    chart.data.datasets[0].data = [value, Math.max(0, 100 - value)];
    chart.update('none');
  }

  function updateSparkline(chart, buffer) {
    if (!chart) return;
    chart.data.labels = buffer.map(function(_, i) { return i; });
    chart.data.datasets[0].data = buffer;
    chart.update('none');
  }

  var historySparklines = metricsPageConfig.historyEnabled === 'true';
  var sparkBase = { cpu: [], mem: [], disk: [] };
  var sparkLive = null;
  var SPARK_HISTORY_REFRESH_MS = 300000;

  function sparkSeries(key) {
    if (!historySparklines) return sparklineBuffers[key];
    return sparkLive ? sparkBase[key].concat([sparkLive[key]]) : sparkBase[key].slice();
  }

  function renderSparklines() {
    updateSparkline(cpuSpark, sparkSeries('cpu'));
    updateSparkline(memSpark, sparkSeries('mem'));
    updateSparkline(diskSpark, sparkSeries('disk'));
  }

  function loadSparkHistory() {
    if (!historySparklines || document.hidden) return;
    fetch('/ui/metrics/history?hours=1&points=60')
      .then(parseMetricsResponse)
      .then(function(data) {
        var points = (data && data.history) || [];
        sparkBase = {
          cpu: points.map(function(point) { return Number(point.cpu_percent) || 0; }),
          mem: points.map(function(point) { return Number(point.memory_percent) || 0; }),
          disk: points.map(function(point) { return Number(point.disk_percent) || 0; })
        };
        renderSparklines();
      })
      .catch(function() {});
  }

  function updateMetrics() {
    fetch('/ui/metrics/api')
      .then(parseMetricsResponse)
      .then(function(data) {
        if (window.renderDiskPressure) window.renderDiskPressure(data.disk_pressure, data.replication_queue);
        updateGauge(cpuGauge, data.cpu_percent);
        updateGauge(memGauge, data.memory.percent);
        updateGauge(diskGauge, data.disk.percent);

        if (historySparklines) {
          sparkLive = { cpu: data.cpu_percent, mem: data.memory.percent, disk: data.disk.percent };
        } else {
          sparklineBuffers.cpu.push(data.cpu_percent);
          sparklineBuffers.mem.push(data.memory.percent);
          sparklineBuffers.disk.push(data.disk.percent);
          if (sparklineBuffers.cpu.length > SPARK_MAX) sparklineBuffers.cpu.shift();
          if (sparklineBuffers.mem.length > SPARK_MAX) sparklineBuffers.mem.shift();
          if (sparklineBuffers.disk.length > SPARK_MAX) sparklineBuffers.disk.shift();
        }
        renderSparklines();

        var el;
        el = document.querySelector('[data-metric="cpu_status"]');
        if (el) {
          if (data.cpu_percent > 80) { el.textContent = 'High'; el.className = 'badge bg-danger-subtle text-danger'; }
          else if (data.cpu_percent > 50) { el.textContent = 'Medium'; el.className = 'badge bg-warning-subtle text-warning'; }
          else { el.textContent = 'Normal'; el.className = 'badge bg-success-subtle text-success'; }
        }

        el = document.querySelector('[data-metric="memory_used"]');
        if (el) el.textContent = data.memory.used;
        el = document.querySelector('[data-metric="memory_total"]');
        if (el) el.textContent = data.memory.total;
        el = document.querySelector('[data-metric="disk_free"]');
        if (el) el.textContent = data.disk.free;
        el = document.querySelector('[data-metric="disk_total"]');
        if (el) el.textContent = data.disk.total;
        el = document.querySelector('[data-metric="storage_used"]');
        if (el) el.textContent = data.app.storage_used;
        el = document.querySelector('[data-metric="buckets_count"]');
        if (el) el.textContent = data.app.buckets;
        el = document.querySelector('[data-metric="objects_count"]');
        if (el) el.textContent = data.app.objects;
        el = document.querySelector('[data-metric="versions_count"]');
        if (el) el.textContent = data.app.versions;
        el = document.querySelector('[data-metric="versions_bytes"]');
        if (el && data.app.versions_bytes) el.textContent = data.app.versions_bytes;
        el = document.querySelector('[data-metric="health_uptime"]');
        if (el) el.textContent = data.app.uptime_display || formatUptime(data.app.uptime_seconds);

        renderHealth(data.health);

        countdown = 5;
        var errBanner = document.getElementById('metrics-error-banner');
        if (errBanner) errBanner.classList.add('d-none');
      })
      .catch(function() {
        var errBanner = document.getElementById('metrics-error-banner');
        if (errBanner) errBanner.classList.remove('d-none');
      });
  }

  function startCountdown() {
    if (countdownTimer) clearInterval(countdownTimer);
    countdown = 5;
    if (countdownEl) countdownEl.textContent = countdown;
    countdownTimer = setInterval(function() {
      if (paused) return;
      countdown--;
      if (countdownEl) countdownEl.textContent = Math.max(0, countdown);
      if (countdown <= 0) countdown = 5;
    }, 1000);
  }

  function startPolling() {
    if (fetchTimer) clearInterval(fetchTimer);
    fetchTimer = setInterval(function() {
      if (!document.hidden && !paused) updateMetrics();
    }, POLL_INTERVAL);
    startCountdown();
  }

  if (pauseBtn) {
    pauseBtn.addEventListener('click', function() {
      paused = !paused;
      window.__metricsPaused = paused;
      pauseIcon.classList.toggle('d-none', paused);
      playIcon.classList.toggle('d-none', !paused);
      if (liveDot) liveDot.style.animationPlayState = paused ? 'paused' : 'running';
      pauseBtn.title = paused ? 'Resume auto-refresh' : 'Pause auto-refresh';
      if (!paused) { updateMetrics(); countdown = 5; }
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', function() {
      updateMetrics();
      countdown = 5;
    });
  }

  document.addEventListener('visibilitychange', function() {
    if (!document.hidden && !paused) {
      updateMetrics();
      startPolling();
    }
  });

  updateMetrics();
  startPolling();
  loadSparkHistory();
  if (historySparklines) setInterval(loadSparkHistory, SPARK_HISTORY_REFRESH_MS);

  function downloadJson(data, filename) {
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  var exportSystem = document.getElementById('exportSystem');
  if (exportSystem) {
    exportSystem.addEventListener('click', function(e) {
      e.preventDefault();
      fetch('/ui/metrics/api').then(parseMetricsResponse).then(function(d) {
        downloadJson(d, 'system-metrics-' + new Date().toISOString().slice(0,19).replace(/:/g, '-') + '.json');
      });
    });
  }

  var exportOps = document.getElementById('exportOps');
  if (exportOps) {
    exportOps.addEventListener('click', function(e) {
      e.preventDefault();
      var exportScope = document.querySelector('input[name="opScope"]:checked');
      var exportRange = document.getElementById('opRange');
      var exportQuery = 'hours=' + encodeURIComponent(exportRange ? exportRange.value : '1') + '&scope=' + encodeURIComponent(exportScope ? exportScope.value : 'api');
      fetch('/ui/metrics/operations?' + exportQuery).then(parseMetricsResponse).then(function(d) {
        downloadJson(d, 'operation-metrics-' + new Date().toISOString().slice(0,19).replace(/:/g, '-') + '.json');
      });
    });
  }

  var exportHistory = document.getElementById('exportHistory');
  if (exportHistory) {
    exportHistory.addEventListener('click', function(e) {
      e.preventDefault();
      var hours = document.getElementById('historyTimeRange') ? document.getElementById('historyTimeRange').value : 24;
      fetch('/ui/metrics/history?hours=' + hours).then(parseMetricsResponse).then(function(d) {
        downloadJson(d, 'metrics-history-' + new Date().toISOString().slice(0,19).replace(/:/g, '-') + '.json');
      });
    });
  }
})();
} catch (error) {
  var metricsBanner = document.getElementById('metrics-error-banner');
  if (metricsBanner) metricsBanner.classList.remove('d-none');
}
