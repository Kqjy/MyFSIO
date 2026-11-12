function bootstrapOperationsSection() {
(function() {
  var chartsAvailable = typeof SvgChart !== 'undefined';
  var methodStatusChart = null;
  var endpointChart = null;
  var latencyEndpointChart = null;
  var trendReqRate = null;
  var trendThroughput = null;
  var trendLatency = null;
  var trendErrorRate = null;
  var trendErrorCodes = null;
  var opStatus = document.getElementById('opStatus');
  var opTrendStatus = document.getElementById('opTrendStatus');
  var opRange = document.getElementById('opRange');
  var opScope = 'api';
  var filterGeneration = 0;
  var SCOPE_KEY = 'myfsioOpsScope';
  var RANGE_KEY = 'myfsioOpsRange';
  var LEGACY_RANGE_KEY = 'myfsioOpsHealthRange';
  var recentErrorsStatus = document.getElementById('recentErrorsStatus');
  var opErrorFeed = document.getElementById('opErrorFeed');
  var opCodeChips = document.getElementById('opCodeChips');
  var opFeedMore = document.getElementById('opFeedMore');
  var opFeedMoreWrap = document.getElementById('opFeedMoreWrap');
  var opGroupToggle = document.getElementById('opGroupToggle');
  var opTimer = null;
  var trendTimer = null;
  var opTrendTimestamps = [];
  var recentErrorsTimer = null;
  var selectedCode = null;
  var severityFilter = 'all';
  var groupedMode = true;
  var feedExpanded = Object.create(null);
  var GROUP_PAGE = 5;
  var EVENT_PAGE = 25;
  var groupLimit = GROUP_PAGE;
  var eventLimit = EVENT_PAGE;
  var recentErrorsData = { errors: [], total_buffered: 0 };
  var statusByCode = Object.create(null);
  var lastErrorSummary = null;
  var healthBars = [];
  var healthIntervalMinutes = 5;
  var healthBucketMinutes = 5;
  var latestWindowBar = null;
  var HEALTH_MAX_BARS = 95;
  var SERVER_ERROR_CODES = ['InternalError', 'ServiceUnavailable', 'SlowDown', 'NotImplemented'];
  var EMPTY_ERRORS_HTML = '<div class="text-muted small text-center py-4"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-check-circle mb-2 text-success" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M10.97 4.97a.235.235 0 0 0-.02.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-1.071-1.05z"/></svg><div>No recent errors</div></div>';
  var operationsLoadInFlight = false;
  var operationsLoadSucceeded = false;
  var esc = window.UICore && window.UICore.escapeHtml ? window.UICore.escapeHtml : function(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  };

  if (!chartsAvailable && opStatus) {
    opStatus.textContent = 'Charts unavailable: the chart module failed to load.';
  }

  var endpointColors = {
    'object': '#3b82f6', 'bucket': '#10b981', 'ui': '#6b7280',
    'service': '#06b6d4', 'kms': '#f59e0b'
  };
  var endpointPalette = ['#3b82f6', '#10b981', '#06b6d4', '#f59e0b', '#8b5cf6', '#ec4899', '#14b8a6', '#6366f1', '#84cc16', '#6b7280'];
  var errorSeriesColors = ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#6b7280'];
  var ENDPOINT_CHART_LIMIT = 10;

  function endpointColor(name, index) {
    return endpointColors[name] || endpointPalette[index % endpointPalette.length];
  }

  function rangeHours() {
    return opRange ? opRange.value : '1';
  }

  function filterQuery() {
    return 'hours=' + encodeURIComponent(rangeHours()) + '&scope=' + encodeURIComponent(opScope);
  }

  function pluralize(count, word) {
    return count + ' ' + word + (Number(count) === 1 ? '' : 's');
  }

  function formatSpan(seconds) {
    seconds = Math.max(0, Math.round(Number(seconds) || 0));
    if (seconds < 60) return seconds + 's';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
    var minutes = Math.floor((seconds % 3600) / 60);
    return Math.floor(seconds / 3600) + 'h' + (minutes ? ' ' + minutes + 'm' : '');
  }

  var formatBytes = window.MyFSIO.formatBytes;

  function trendChartOpts(color, yCallback, valueFormat) {
    return {
      type: 'line',
      data: { labels: [], datasets: [{
        data: [], borderColor: color, backgroundColor: color + '15',
        fill: true, tension: 0.3, pointRadius: 2, pointHoverRadius: 5, borderWidth: 1.5
      }]},
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { title: chartTooltipTitle(function() { return opTrendTimestamps; }) } }
        },
        scales: {
          x: { display: true, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8, font: { size: 10 } } },
          y: { display: true, beginAtZero: true, valueFormat: valueFormat, ticks: { callback: yCallback, font: { size: 10 } } }
        }
      }
    };
  }

  function initOpCharts() {
    if (!chartsAvailable) return;
    var msCtx = document.getElementById('methodStatusChart');
    var eCtx = document.getElementById('endpointChart');
    var leCtx = document.getElementById('latencyEndpointChart');

    if (msCtx) {
      methodStatusChart = new SvgChart(msCtx, {
        type: 'bar',
        data: {
          labels: [],
          datasets: [
            { label: 'Success', data: [], backgroundColor: '#10b981', borderRadius: 4 },
            { label: 'Errors', data: [], backgroundColor: '#ef4444', borderRadius: 4 }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false, indexAxis: 'y', animation: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 10 } } } },
          scales: {
            x: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
            y: { stacked: true }
          }
        }
      });
    }

    if (eCtx) {
      endpointChart = new SvgChart(eCtx, {
        type: 'bar',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4 }] },
        options: {
          responsive: true, maintainAspectRatio: false, indexAxis: 'y', animation: false,
          plugins: { legend: { display: false } },
          scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
        }
      });
    }

    if (leCtx) {
      latencyEndpointChart = new SvgChart(leCtx, {
        type: 'bar',
        data: {
          labels: [],
          datasets: [
            { label: 'Avg', data: [], backgroundColor: '#6366f180', borderRadius: 4 },
            { label: 'P95', data: [], backgroundColor: '#8b5cf680', borderRadius: 4 },
            { label: 'Max', data: [], backgroundColor: '#ef444480', borderRadius: 4 }
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false, animation: false,
          plugins: { legend: { position: 'top', labels: { boxWidth: 12, font: { size: 10 } } } },
          scales: { y: { beginAtZero: true, valueFormat: function(v) { return SvgChart.valueText(v) + ' ms'; }, ticks: { callback: function(v, step) { return SvgChart.tickText(v, step) + 'ms'; } } } }
        }
      });
    }

    var trCtx = document.getElementById('opTrendReqRate');
    var ttCtx = document.getElementById('opTrendThroughput');
    var tlCtx = document.getElementById('opTrendLatency');
    var teCtx = document.getElementById('opTrendErrorRate');
    var ecCtx = document.getElementById('opTrendErrorCodes');

    if (trCtx) trendReqRate = new SvgChart(trCtx, trendChartOpts('#3b82f6', SvgChart.tickText, function(v) { return SvgChart.valueText(v) + ' req/s'; }));
    if (ttCtx) {
      trendThroughput = new SvgChart(ttCtx, trendChartOpts('#10b981', function(v) { return formatBytes(v) + '/s'; }, function(v) {
        return (v > 0 && v < 1 ? SvgChart.valueText(v) + ' B' : formatBytes(v)) + '/s';
      }));
      trendThroughput.options.scales.y.ticks.precision = 0;
    }
    if (tlCtx) trendLatency = new SvgChart(tlCtx, trendChartOpts('#8b5cf6', function(v, step) { return SvgChart.tickText(v, step) + 'ms'; }, function(v) { return SvgChart.valueText(v) + ' ms'; }));
    if (teCtx) trendErrorRate = new SvgChart(teCtx, trendChartOpts('#ef4444', function(v, step) { return SvgChart.tickText(v, step) + '%'; }, function(v) { return SvgChart.valueText(v) + '%'; }));
    if (ecCtx) {
      trendErrorCodes = new SvgChart(ecCtx, {
        type: 'bar',
        data: { labels: [], datasets: [] },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          plugins: {
            legend: { position: 'top', labels: { boxWidth: 12, font: { size: 10 } } },
            tooltip: { callbacks: { title: chartTooltipTitle(function() { return opTrendTimestamps; }) } }
          },
          scales: {
            x: { stacked: true, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 12, font: { size: 10 } } },
            y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }
          }
        }
      });
    }
  }

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function renderRetryStatus(element, message, loader) {
    if (!element) return;
    element.textContent = message + ' ';
    var retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'btn btn-link btn-sm p-0 align-baseline';
    retry.textContent = 'Retry';
    retry.addEventListener('click', loader);
    element.appendChild(retry);
  }

  function renderOperationsLoadError() {
    renderRetryStatus(opStatus, 'Unable to load operations.', function() { loadOperationsSection(true); });
  }

  function applyRetention(retentionHours) {
    if (!opRange || !retentionHours) return;
    Array.prototype.forEach.call(opRange.options, function(option) {
      var hours = Number(option.value);
      option.disabled = hours > 1 && hours > retentionHours;
      option.title = option.disabled ? 'Operation metrics are retained for ' + pluralize(retentionHours, 'hour') : '';
    });
  }

  function updateOpMetrics(force) {
    if ((!force && document.hidden) || operationsLoadInFlight) return;
    operationsLoadInFlight = true;
    var generation = filterGeneration;
    return fetch('/ui/metrics/operations?' + filterQuery())
      .then(parseMetricsResponse)
      .then(function(data) {
        if (generation !== filterGeneration) return;
        operationsLoadSucceeded = true;
        applyRetention(data.retention_hours);
        if (!data.enabled || !data.stats) {
          if (opStatus) opStatus.textContent = 'Not available';
          return;
        }
        var stats = data.stats;
        var totals = stats.totals || {};

        var statusClasses = stats.by_status_class || {};
        var hasStatusClasses = Object.keys(statusClasses).length > 0;
        var serverErrors = hasStatusClasses ? (statusClasses['5xx'] || 0) : 0;
        var clientErrors = hasStatusClasses ? (statusClasses['4xx'] || 0) : (totals.error_count || 0);

        setText('opTotalRequests', (totals.count || 0).toLocaleString());
        setText('opSuccessRate', totals.count > 0 ? ((totals.success_count / totals.count) * 100).toFixed(1) + '%' : '—');
        setText('opSuccessCount', (totals.success_count || 0).toLocaleString() + ' ok');
        setText('opServerErrors', serverErrors.toLocaleString());
        setText('opClientErrors', clientErrors.toLocaleString());
        var rps = stats.window_seconds > 0 ? (totals.count || 0) / stats.window_seconds : 0;
        setText('opReqPerSec', rps.toFixed(2));
        setText('opAvgLatency', (totals.latency_avg_ms || 0).toFixed(1) + 'ms');
        setText('opP95Latency', (totals.latency_p95_ms || totals.latency_max_ms || 0).toFixed(1) + 'ms');
        setText('opBytesIn', formatBytes(totals.bytes_in || 0));
        setText('opBytesOut', formatBytes(totals.bytes_out || 0));

        var live = stats.live || {};
        var liveClasses = live.by_status_class || {};
        var windowEnd = Date.now();
        latestWindowBar = {
          start: new Date(windowEnd - (live.window_seconds || 0) * 1000).toISOString(),
          end: new Date(windowEnd).toISOString(),
          total: live.count || 0,
          c4: liveClasses['4xx'] || 0,
          c5: liveClasses['5xx'] || 0
        };
        renderHealthBar();

        if (methodStatusChart && stats.by_method) {
          var methods = Object.keys(stats.by_method).sort();
          methodStatusChart.data.labels = methods;
          methodStatusChart.data.datasets[0].data = methods.map(function(m) { return stats.by_method[m].success_count || 0; });
          methodStatusChart.data.datasets[1].data = methods.map(function(m) { return stats.by_method[m].error_count || 0; });
          methodStatusChart.update('none');
        }

        var endpoints = Object.keys(stats.by_endpoint || {}).sort(function(a, b) {
          return (stats.by_endpoint[b].count || 0) - (stats.by_endpoint[a].count || 0);
        }).slice(0, ENDPOINT_CHART_LIMIT);

        if (endpointChart && stats.by_endpoint) {
          endpointChart.data.labels = endpoints;
          endpointChart.data.datasets[0].data = endpoints.map(function(e) { return stats.by_endpoint[e].count; });
          endpointChart.data.datasets[0].backgroundColor = endpoints.map(endpointColor);
          endpointChart.update('none');
        }

        if (latencyEndpointChart && stats.by_endpoint) {
          var eps = endpoints;
          latencyEndpointChart.data.labels = eps;
          latencyEndpointChart.data.datasets[0].data = eps.map(function(e) { return stats.by_endpoint[e].latency_avg_ms || 0; });
          latencyEndpointChart.data.datasets[1].data = eps.map(function(e) { return stats.by_endpoint[e].latency_p95_ms || stats.by_endpoint[e].latency_max_ms || 0; });
          latencyEndpointChart.data.datasets[2].data = eps.map(function(e) { return stats.by_endpoint[e].latency_max_ms || 0; });
          latencyEndpointChart.update('none');
        }

        if (opStatus) {
          var rangeSeconds = (stats.hours || Number(rangeHours())) * 3600;
          var covered = stats.window_seconds || 0;
          opStatus.textContent = covered + 60 < rangeSeconds
            ? 'Data covers the last ' + formatSpan(covered)
            : pluralize(stats.snapshot_count || 0, 'snapshot') + ' + live window';
          opStatus.title = 'Totals merge persisted snapshots (taken every ' + pluralize(data.interval_minutes || 5, 'minute') + ') with the live window';
        }
      })
      .catch(function() {
        if (generation === filterGeneration) renderOperationsLoadError();
      })
      .finally(function() {
        operationsLoadInFlight = false;
        if (generation !== filterGeneration) updateOpMetrics(true);
      });
  }

  function bucketTitleForCode(code, errorBuckets) {
    var rows = [];
    Object.keys(errorBuckets || {}).forEach(function(bucket) {
      var count = errorBuckets[bucket] && errorBuckets[bucket][code] ? errorBuckets[bucket][code] : 0;
      if (count > 0) rows.push([bucket, count]);
    });
    rows.sort(function(a, b) { return b[1] - a[1]; });
    return rows.slice(0, 5).map(function(row) { return row[0] + ': ' + row[1]; }).join(', ');
  }

  function isServerErrorCode(code) {
    if (Object.prototype.hasOwnProperty.call(statusByCode, code)) return statusByCode[code] >= 500;
    return SERVER_ERROR_CODES.indexOf(code) !== -1;
  }

  function selectErrorCode(code) {
    selectedCode = code || null;
    groupLimit = GROUP_PAGE;
    eventLimit = EVENT_PAGE;
    renderErrorFeed();
    updateErrorCodeSelection();
  }

  function attachErrorCodeClicks() {
    var errorBody = document.getElementById('errorCodesBody');
    if (!errorBody) return;
    errorBody.querySelectorAll('[data-error-code]').forEach(function(row) {
      row.addEventListener('click', function() {
        var code = row.getAttribute('data-error-code');
        selectErrorCode(selectedCode === code ? null : code);
      });
    });
  }

  function updateErrorCodeSelection() {
    var errorBody = document.getElementById('errorCodesBody');
    if (!errorBody) return;
    errorBody.querySelectorAll('[data-error-code]').forEach(function(row) {
      row.classList.toggle('ops-bar-active', selectedCode === row.getAttribute('data-error-code'));
    });
  }

  function renderErrorSummary(summary) {
    lastErrorSummary = summary;
    var errorBody = document.getElementById('errorCodesBody');
    if (errorBody) {
      var summaryCodes = summary.error_codes || {};
      var errorCodes = Object.keys(summaryCodes).map(function(code) { return [code, summaryCodes[code]]; });
      errorCodes.sort(function(a, b) { return b[1] - a[1]; });
      var totalErrors = summary.total_errors || errorCodes.reduce(function(sum, entry) { return sum + entry[1]; }, 0);
      errorCodes = errorCodes.slice(0, 8);
      if (errorCodes.length === 0) {
        var emptyCodesText = opScope === 'ui' ? 'Console requests carry no S3 error code; see Recent errors' : 'No errors in this range';
        errorBody.innerHTML = '<div class="text-muted small text-center py-4"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-check-circle mb-2 text-success" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M10.97 4.97a.235.235 0 0 0-.02.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-1.071-1.05z"/></svg><div>' + esc(emptyCodesText) + '</div></div>';
      } else {
        errorBody.innerHTML = errorCodes.map(function(entry) {
          var code = entry[0];
          var count = entry[1];
          var pct = totalErrors > 0 ? Math.round((count / totalErrors) * 100) : 0;
          var title = bucketTitleForCode(code, summary.error_buckets || {});
          var server = isServerErrorCode(code);
          return '<button type="button" class="ops-bar-row ops-bar-btn" data-error-code="' + esc(code) + '" title="' + esc(title) + '">' +
            '<code class="text-truncate ' + (server ? 'text-danger' : 'text-body') + '">' + esc(code) + '</code>' +
            '<span class="text-muted">' + count.toLocaleString() + ' · ' + pct + '%</span>' +
            '<span class="progress"><span class="progress-bar ' + (server ? 'bg-danger' : 'bg-warning') + '" style="width: ' + pct + '%"></span></span>' +
            '</button>';
        }).join('');
        attachErrorCodeClicks();
        updateErrorCodeSelection();
      }
    }

    var bucketBody = document.getElementById('errorBucketsBody');
    if (bucketBody) {
      var errorBuckets = summary.error_buckets || {};
      var buckets = Object.keys(errorBuckets).map(function(name) {
        var perCode = errorBuckets[name] || {};
        var sum = Object.keys(perCode).reduce(function(acc, code) { return acc + perCode[code]; }, 0);
        return [name, sum];
      });
      buckets.sort(function(a, b) { return b[1] - a[1]; });
      buckets = buckets.slice(0, 6);
      if (buckets.length === 0) {
        bucketBody.innerHTML = '<div class="text-muted small">No bucket-scoped errors</div>';
      } else {
        var maxBucket = buckets[0][1];
        bucketBody.innerHTML = buckets.map(function(entry, index) {
          var label = entry[0] === '(other)' ? 'other buckets' : entry[0];
          var pct = maxBucket > 0 ? Math.round((entry[1] / maxBucket) * 100) : 0;
          return '<div class="ops-bar-row' + (index === buckets.length - 1 ? ' mb-0' : '') + '">' +
            '<span class="text-truncate" title="' + esc(label) + '">' + esc(label) + '</span>' +
            '<span class="text-muted">' + entry[1].toLocaleString() + '</span>' +
            '<span class="progress"><span class="progress-bar bg-secondary" style="width: ' + pct + '%"></span></span>' +
            '</div>';
        }).join('');
      }
    }
  }

  function loadErrorSummary(force) {
    if (!force && (document.hidden || window.__metricsPaused)) return;
    var generation = filterGeneration;
    fetch('/ui/metrics/operations/error-summary?' + filterQuery())
      .then(parseMetricsResponse)
      .then(function(data) {
        if (generation !== filterGeneration || !data.enabled) return;
        renderErrorSummary(data);
      })
      .catch(function() {
        if (generation !== filterGeneration) return;
        var errorBody = document.getElementById('errorCodesBody');
        if (errorBody) {
          errorBody.innerHTML = '';
          var retry = document.createElement('button');
          retry.type = 'button';
          retry.className = 'btn btn-link btn-sm';
          retry.textContent = 'Unable to load error summary · Retry';
          retry.addEventListener('click', function() { loadErrorSummary(true); });
          errorBody.appendChild(retry);
        }
      });
  }

  function opRelativeTime(timestamp) {
    var then = new Date(timestamp).getTime();
    if (isNaN(then)) return '—';
    var diff = Math.max(0, Date.now() - then) / 1000;
    if (diff < 60) return Math.floor(diff) + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  function buildErrorGroups(errors) {
    var map = Object.create(null);
    var order = [];
    errors.forEach(function(err) {
      var groupKey = 'g|' + err.code + '|#|' + err.method + '|#|' + (err.bucket || '') + '|#|' + err.status;
      var group = map[groupKey];
      if (!group) {
        group = {
          key: groupKey,
          code: err.code,
          method: err.method,
          bucket: err.bucket || '',
          status: err.status,
          count: 0,
          firstTs: err.timestamp,
          lastTs: err.timestamp,
          keyName: '',
          requestId: '',
          latency: 0,
          maxLatency: 0,
          source: '',
          seenKeys: Object.create(null),
          distinctKeys: 0
        };
        map[groupKey] = group;
        order.push(group);
      }
      var latency = Number(err.latency_ms) || 0;
      var ts = new Date(err.timestamp).getTime();
      group.count += 1;
      if (latency > group.maxLatency) group.maxLatency = latency;
      if (ts < new Date(group.firstTs).getTime()) group.firstTs = err.timestamp;
      if (group.count === 1 || ts >= new Date(group.lastTs).getTime()) {
        group.lastTs = err.timestamp;
        group.keyName = err.key || '';
        group.requestId = err.request_id || '';
        group.latency = latency;
        group.source = err.source || '';
      }
      if (err.key && !Object.prototype.hasOwnProperty.call(group.seenKeys, err.key)) {
        group.seenKeys[err.key] = true;
        group.distinctKeys += 1;
      }
    });
    order.sort(function(a, b) {
      var sa = Number(a.status) >= 500 ? 1 : 0;
      var sb = Number(b.status) >= 500 ? 1 : 0;
      if (sa !== sb) return sb - sa;
      return new Date(b.lastTs).getTime() - new Date(a.lastTs).getTime();
    });
    return order;
  }

  function buildErrorEvents(errors) {
    return errors.map(function(err) {
      var latency = Number(err.latency_ms) || 0;
      return {
        key: 'e|' + err.timestamp + '|#|' + err.code + '|#|' + (err.request_id || '') + '|#|' + err.method + '|#|' + (err.key || ''),
        code: err.code,
        method: err.method,
        bucket: err.bucket || '',
        status: err.status,
        count: 1,
        firstTs: err.timestamp,
        lastTs: err.timestamp,
        keyName: err.key || '',
        requestId: err.request_id || '',
        latency: latency,
        maxLatency: latency,
        source: err.source || '',
        distinctKeys: err.key ? 1 : 0
      };
    });
  }

  function feedRowHtml(item) {
    var isServer = Number(item.status) >= 500;
    var statusClass = isServer ? 'bg-danger-subtle text-danger' : 'bg-warning-subtle text-warning-emphasis';
    var target;
    if (!item.bucket) target = '—';
    else if (item.distinctKeys > 1) target = item.bucket + '/… · ' + item.distinctKeys + ' distinct keys';
    else if (item.keyName) target = item.bucket + '/' + item.keyName;
    else target = item.bucket;
    var lastSeen = formatEventTimestamp(item.lastTs);
    var details = '';
    if (item.keyName) details += '<dt>Latest key</dt><dd><code>' + esc(item.keyName) + '</code></dd>';
    details += '<dt>Request ID</dt><dd><code>' + esc(item.requestId || '—') + '</code></dd>';
    if (item.count > 1) details += '<dt>First seen</dt><dd>' + esc(formatEventTimestamp(item.firstTs).full) + '</dd>';
    details += '<dt>Last seen</dt><dd>' + esc(lastSeen.full) + '</dd>';
    var latencyText = item.latency.toFixed(1) + ' ms';
    if (item.count > 1) latencyText += ' · max ' + item.maxLatency.toFixed(1) + ' ms';
    details += '<dt>Latency</dt><dd>' + esc(latencyText) + '</dd>';
    details += '<dt>Source</dt><dd>' + esc(item.source || '—') + '</dd>';
    return '<details data-feed-key="' + esc(item.key) + '"' + (feedExpanded[item.key] ? ' open' : '') + '>' +
      '<summary>' +
      '<span class="ops-dot ' + (isServer ? 'ops-dot-5' : 'ops-dot-4') + '"></span>' +
      '<div style="min-width: 0;">' +
      '<div class="ops-line1">' +
      '<code class="fw-semibold ' + (isServer ? 'text-danger' : 'text-body') + '">' + esc(item.code) + '</code>' +
      '<span class="badge ' + statusClass + '">' + esc(item.status) + '</span>' +
      '<span class="badge bg-secondary-subtle text-secondary">' + esc(item.method) + '</span>' +
      (item.source && item.source !== 'api' ? '<span class="badge bg-info-subtle text-info-emphasis">' + esc(item.source) + '</span>' : '') +
      '</div>' +
      '<div class="ops-line2" title="' + esc(target) + '">' + esc(target) + '</div>' +
      '</div>' +
      '<div class="ops-meta">' +
      (item.count > 1 ? '<b>&times;' + item.count + '</b>' : '') +
      '<span title="' + esc(lastSeen.full) + '">' + esc(opRelativeTime(item.lastTs)) + '</span>' +
      '</div>' +
      '</summary>' +
      '<div class="ops-more"><dl>' + details + '</dl></div>' +
      '</details>';
  }

  function renderCodeChips(errors) {
    if (!opCodeChips) return;
    var counts = Object.create(null);
    errors.forEach(function(err) {
      counts[err.code] = (counts[err.code] || 0) + 1;
    });
    var entries = Object.keys(counts).map(function(code) { return [code, counts[code]]; });
    entries.sort(function(a, b) { return b[1] - a[1]; });
    if (entries.length === 0) {
      opCodeChips.innerHTML = '';
      opCodeChips.classList.add('d-none');
      return;
    }
    var shown = entries.slice(0, 6);
    var hidden = entries.length - shown.length;
    if (selectedCode && !shown.some(function(entry) { return entry[0] === selectedCode; })) {
      var extra = entries.filter(function(entry) { return entry[0] === selectedCode; })[0];
      if (extra) {
        shown = shown.concat([extra]);
        hidden -= 1;
      }
    }
    var html = '<button type="button" class="btn btn-sm rounded-pill ' + (selectedCode ? 'btn-outline-secondary' : 'btn-primary') + '" data-chip-code="">All <span class="opacity-75">' + errors.length + '</span></button>';
    html += shown.map(function(entry) {
      var active = selectedCode === entry[0];
      return '<button type="button" class="btn btn-sm rounded-pill ' + (active ? 'btn-primary' : 'btn-outline-secondary') + '" data-chip-code="' + esc(entry[0]) + '">' + esc(entry[0]) + ' <span class="opacity-75">' + entry[1] + '</span></button>';
    }).join('');
    if (hidden > 0) html += '<span class="small text-muted align-self-center">+' + hidden + ' more</span>';
    opCodeChips.innerHTML = html;
    opCodeChips.classList.remove('d-none');
    opCodeChips.querySelectorAll('[data-chip-code]').forEach(function(chip) {
      chip.addEventListener('click', function() {
        selectErrorCode(chip.getAttribute('data-chip-code'));
      });
    });
  }

  function renderErrorFeed() {
    if (!opErrorFeed) return;
    var all = recentErrorsData.errors || [];
    var buffered = recentErrorsData.total_buffered || 0;
    var filtered = all.filter(function(err) {
      var status = Number(err.status) || 0;
      if (severityFilter === '5xx') return status >= 500;
      if (severityFilter === '4xx') return status < 500;
      return true;
    });
    renderCodeChips(filtered);
    var scoped = selectedCode ? filtered.filter(function(err) { return err.code === selectedCode; }) : filtered;
    var items = groupedMode ? buildErrorGroups(scoped) : buildErrorEvents(scoped);

    if (items.length === 0) {
      opErrorFeed.innerHTML = all.length === 0 ? EMPTY_ERRORS_HTML : '<div class="text-muted small text-center py-4">No matching errors</div>';
      if (opFeedMoreWrap) opFeedMoreWrap.classList.add('d-none');
      if (recentErrorsStatus) recentErrorsStatus.textContent = '0 shown · ' + buffered.toLocaleString() + ' buffered';
      return;
    }

    var limit = groupedMode ? groupLimit : eventLimit;
    var visible = items.slice(0, limit);
    opErrorFeed.innerHTML = visible.map(feedRowHtml).join('');
    opErrorFeed.querySelectorAll('details[data-feed-key]').forEach(function(node) {
      node.addEventListener('toggle', function() {
        var key = node.getAttribute('data-feed-key');
        if (node.open) feedExpanded[key] = true;
        else delete feedExpanded[key];
      });
    });

    var remaining = items.length - visible.length;
    if (opFeedMoreWrap && opFeedMore) {
      if (remaining > 0) {
        opFeedMore.textContent = 'Show ' + remaining.toLocaleString() + ' more';
        opFeedMoreWrap.classList.remove('d-none');
      } else {
        opFeedMoreWrap.classList.add('d-none');
      }
    }

    if (recentErrorsStatus) {
      recentErrorsStatus.textContent = groupedMode
        ? pluralize(items.length.toLocaleString(), 'group') + ' from ' + pluralize(scoped.length.toLocaleString(), 'error') + ' · ' + buffered.toLocaleString() + ' buffered'
        : visible.length.toLocaleString() + ' of ' + scoped.length.toLocaleString() + ' events · ' + buffered.toLocaleString() + ' buffered';
    }
  }

  function healthClassFor(bar) {
    if (bar.c5 > 0) return 'ops-h-err';
    if (bar.c4 > 0) return 'ops-h-warn';
    if (bar.total > 0) return 'ops-h-ok';
    return 'ops-h-zero';
  }

  function renderHealthBar() {
    var barEl = document.getElementById('opHealthBar');
    var emptyEl = document.getElementById('opHealthEmpty');
    var labelsEl = document.getElementById('opHealthLabels');
    var scaleEl = document.getElementById('opHealthScale');
    if (!barEl) return;
    if (healthBars.length === 0) {
      barEl.innerHTML = '';
      barEl.classList.add('d-none');
      if (labelsEl) labelsEl.classList.add('d-none');
      if (scaleEl) scaleEl.textContent = '';
      if (emptyEl) {
        emptyEl.textContent = 'Collecting data — first snapshot in up to ' + healthIntervalMinutes + ' min';
        emptyEl.classList.remove('d-none');
      }
      return;
    }
    if (emptyEl) emptyEl.classList.add('d-none');
    barEl.classList.remove('d-none');
    if (labelsEl) labelsEl.classList.remove('d-none');

    var bars = healthBars.slice();
    if (latestWindowBar) bars.push(latestWindowBar);
    barEl.innerHTML = bars.map(function(bar) {
      var title = formatEventTimestamp(bar.start).time + ' – ' + formatEventTimestamp(bar.end).time +
        ' · ' + bar.total.toLocaleString() + ' requests · ' + bar.c4.toLocaleString() + ' 4xx · ' + bar.c5.toLocaleString() + ' 5xx';
      return '<span class="' + healthClassFor(bar) + '" title="' + esc(title) + '"></span>';
    }).join('');

    var startLabel = document.getElementById('opHealthStart');
    var midLabel = document.getElementById('opHealthMid');
    var endLabel = document.getElementById('opHealthEnd');
    if (startLabel) startLabel.textContent = formatEventTimestamp(bars[0].start).time;
    if (midLabel) midLabel.textContent = formatEventTimestamp(bars[Math.floor(bars.length / 2)].start).time;
    if (endLabel) endLabel.textContent = 'now';
    if (scaleEl) scaleEl.textContent = 'one bar per ' + healthBucketMinutes + ' min';
  }

  function applyHealthHistory(data) {
        healthIntervalMinutes = data.interval_minutes || 5;
        var raw = (data.enabled && data.history) ? data.history : [];
        var bars = zeroFillHistory(raw, healthIntervalMinutes).map(function(snapshot) {
          var classes = snapshot.by_status_class || {};
          var totals = snapshot.totals || {};
          var endMs = new Date(snapshot.timestamp).getTime();
          var spanMs = (snapshot.window_seconds || healthIntervalMinutes * 60) * 1000;
          return {
            start: new Date(endMs - spanMs).toISOString(),
            end: new Date(endMs).toISOString(),
            total: totals.count || 0,
            c4: classes['4xx'] || 0,
            c5: classes['5xx'] || 0
          };
        });
        var step = Math.max(1, Math.ceil(bars.length / HEALTH_MAX_BARS));
        if (step > 1) {
          var merged = [];
          for (var i = 0; i < bars.length; i += step) {
            var chunk = bars.slice(i, i + step);
            merged.push({
              start: chunk[0].start,
              end: chunk[chunk.length - 1].end,
              total: chunk.reduce(function(sum, bar) { return sum + bar.total; }, 0),
              c4: chunk.reduce(function(sum, bar) { return sum + bar.c4; }, 0),
              c5: chunk.reduce(function(sum, bar) { return sum + bar.c5; }, 0)
            });
          }
          bars = merged;
        }
        healthBucketMinutes = healthIntervalMinutes * step;
        healthBars = bars;
        renderHealthBar();
  }

  function loadOpHistory(force) {
    if (!force && (document.hidden || window.__metricsPaused)) return;
    var generation = filterGeneration;
    fetch('/ui/metrics/operations/history?' + filterQuery())
      .then(parseMetricsResponse)
      .then(function(data) {
        if (generation !== filterGeneration) return;
        applyHealthHistory(data);
        applyTrendHistory(data);
      })
      .catch(function() {
        if (generation !== filterGeneration) return;
        var emptyEl = document.getElementById('opHealthEmpty');
        if (emptyEl && healthBars.length === 0) {
          emptyEl.textContent = 'Unable to load request health.';
          emptyEl.classList.remove('d-none');
        }
        renderRetryStatus(opTrendStatus, 'Unable to load operation history.', function() { loadOpHistory(true); });
      });
  }

  function loadRecentErrors(force) {
    if (!force && (document.hidden || window.__metricsPaused)) return;
    var generation = filterGeneration;
    fetch('/ui/metrics/operations/errors?limit=256&' + filterQuery())
      .then(parseMetricsResponse)
      .then(function(data) {
        if (generation !== filterGeneration) return;
        if (!data.enabled) {
          if (recentErrorsStatus) recentErrorsStatus.textContent = 'Not available';
          if (opErrorFeed) opErrorFeed.innerHTML = '<div class="text-muted small text-center py-4">Not available</div>';
          return;
        }
        recentErrorsData = { errors: data.errors || [], total_buffered: data.total_buffered || 0 };
        statusByCode = Object.create(null);
        recentErrorsData.errors.forEach(function(err) {
          if (!Object.prototype.hasOwnProperty.call(statusByCode, err.code)) statusByCode[err.code] = Number(err.status) || 0;
        });
        renderErrorFeed();
        if (lastErrorSummary) renderErrorSummary(lastErrorSummary);
      })
      .catch(function() {
        if (generation !== filterGeneration) return;
        renderRetryStatus(recentErrorsStatus, 'Unable to load recent errors.', function() { loadRecentErrors(true); });
      });
  }

  function zeroSnapshot(timestamp, intervalMinutes) {
    return {
      timestamp: new Date(timestamp).toISOString(),
      window_seconds: intervalMinutes * 60,
      totals: { count: 0, success_count: 0, error_count: 0, latency_avg_ms: 0, bytes_in: 0, bytes_out: 0 },
      by_status_class: {},
      error_codes: {}
    };
  }

  function zeroFillHistory(history, intervalMinutes) {
    var sorted = history.slice().sort(function(a, b) { return new Date(a.timestamp) - new Date(b.timestamp); });
    if (sorted.length <= 1) return sorted;
    var intervalMs = Math.max(1, intervalMinutes) * 60000;
    var filled = [sorted[0]];
    var lastTs = new Date(sorted[0].timestamp).getTime();
    for (var i = 1; i < sorted.length; i++) {
      var ts = new Date(sorted[i].timestamp).getTime();
      while (ts - lastTs > intervalMs * 1.5) {
        lastTs += intervalMs;
        filled.push(zeroSnapshot(lastTs, intervalMinutes));
      }
      filled.push(sorted[i]);
      lastTs = ts;
    }
    return filled;
  }

  function updateErrorCodesTrend(history, labels) {
    if (!trendErrorCodes) return;
    var totals = {};
    history.forEach(function(h) {
      Object.entries(h.error_codes || {}).forEach(function(entry) {
        totals[entry[0]] = (totals[entry[0]] || 0) + entry[1];
      });
    });
    var topCodes = Object.entries(totals).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 5).map(function(entry) { return entry[0]; });
    var hasOther = Object.keys(totals).some(function(code) { return topCodes.indexOf(code) === -1; });
    var series = topCodes.slice();
    if (hasOther) series.push('other');
    trendErrorCodes.data.labels = labels;
    trendErrorCodes.data.datasets = series.map(function(code, index) {
      return {
        label: code,
        data: history.map(function(h) {
          var codes = h.error_codes || {};
          if (code !== 'other') return codes[code] || 0;
          return Object.keys(codes).reduce(function(sum, key) {
            return topCodes.indexOf(key) === -1 ? sum + codes[key] : sum;
          }, 0);
        }),
        backgroundColor: errorSeriesColors[index % errorSeriesColors.length],
        borderWidth: 0,
        stack: 'errors'
      };
    });
    trendErrorCodes.update('none');
  }

  function clearTrends() {
    opTrendTimestamps = [];
    [trendReqRate, trendThroughput, trendLatency, trendErrorRate].forEach(function(chart) {
      if (!chart) return;
      chart.data.labels = [];
      chart.data.datasets[0].data = [];
      chart.update('none');
    });
    if (trendErrorCodes) {
      trendErrorCodes.data.labels = [];
      trendErrorCodes.data.datasets = [];
      trendErrorCodes.update('none');
    }
  }

  function applyTrendHistory(data) {
        if (!data.enabled || !data.history || data.history.length === 0) {
          clearTrends();
          if (opTrendStatus) opTrendStatus.textContent = 'No snapshots in this range yet. Snapshots are taken every ' + pluralize(data.interval_minutes || 5, 'minute') + '.';
          return;
        }
        var hasTraffic = data.history.some(function(h) { return ((h.totals || {}).count || 0) > 0; });
        if (!hasTraffic) {
          clearTrends();
          if (opTrendStatus) opTrendStatus.textContent = 'No requests from this source in the selected range.';
          return;
        }
        var history = zeroFillHistory(data.history, data.interval_minutes || 5);
        opTrendTimestamps = history.map(function(h) { return h.timestamp; });
        var labels = buildChartLabels(opTrendTimestamps);
        var reqRates = history.map(function(h) { return h.window_seconds > 0 ? (h.totals.count || 0) / h.window_seconds : 0; });
        var throughputs = history.map(function(h) { return h.window_seconds > 0 ? ((h.totals.bytes_in || 0) + (h.totals.bytes_out || 0)) / h.window_seconds : 0; });
        var latencies = history.map(function(h) { return h.totals.latency_avg_ms || 0; });
        var errorRates = history.map(function(h) { return h.totals.count > 0 ? ((h.totals.error_count || 0) / h.totals.count * 100) : 0; });

        function updateTrend(chart, lbls, vals) {
          if (!chart) return;
          chart.data.labels = lbls;
          chart.data.datasets[0].data = vals;
          chart.update('none');
        }
        updateTrend(trendReqRate, labels, reqRates);
        updateTrend(trendThroughput, labels, throughputs);
        updateTrend(trendLatency, labels, latencies);
        updateTrend(trendErrorRate, labels, errorRates);
        updateErrorCodesTrend(history, labels);

        if (opTrendStatus) opTrendStatus.textContent = pluralize(data.history.length, 'snapshot');
  }

  function startOpPolling() {
    if (opTimer) clearInterval(opTimer);
    opTimer = setInterval(function() {
      if (!document.hidden && !window.__metricsPaused) {
        updateOpMetrics();
        loadErrorSummary(false);
      }
    }, 5000);
    if (recentErrorsTimer) clearInterval(recentErrorsTimer);
    recentErrorsTimer = setInterval(function() {
      if (!document.hidden && !window.__metricsPaused) loadRecentErrors(false);
    }, 10000);
    if (trendTimer) clearInterval(trendTimer);
    trendTimer = setInterval(function() {
      if (!document.hidden && !window.__metricsPaused) loadOpHistory(false);
    }, 60000);
  }

  function loadOperationsSection(force) {
    updateOpMetrics(force);
    loadErrorSummary(Boolean(force));
    loadRecentErrors(Boolean(force));
    loadOpHistory(Boolean(force));
  }

  function persistFilter(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (storageError) {
      void storageError;
    }
  }

  function restoreFilters() {
    try {
      var storedScope = window.localStorage.getItem(SCOPE_KEY);
      if (['api', 'ui', 'internal', 'all'].indexOf(storedScope) !== -1) opScope = storedScope;
      var storedRange = window.localStorage.getItem(RANGE_KEY) || window.localStorage.getItem(LEGACY_RANGE_KEY);
      if (opRange && (storedRange === '1' || storedRange === '6' || storedRange === '24')) opRange.value = storedRange;
    } catch (storageError) {
      void storageError;
    }
    var scopeInput = document.querySelector('input[name="opScope"][value="' + opScope + '"]');
    if (scopeInput) scopeInput.checked = true;
  }

  function onFiltersChanged() {
    filterGeneration += 1;
    selectedCode = null;
    groupLimit = GROUP_PAGE;
    eventLimit = EVENT_PAGE;
    feedExpanded = Object.create(null);
    healthBars = [];
    latestWindowBar = null;
    lastErrorSummary = null;
    if (opStatus) opStatus.textContent = 'Loading...';
    renderHealthBar();
    loadOperationsSection(true);
  }

  if (opRange) {
    opRange.addEventListener('change', function() {
      persistFilter(RANGE_KEY, opRange.value);
      onFiltersChanged();
    });
  }

  document.querySelectorAll('input[name="opScope"]').forEach(function(input) {
    input.addEventListener('change', function() {
      if (!input.checked) return;
      opScope = input.value;
      persistFilter(SCOPE_KEY, opScope);
      onFiltersChanged();
    });
  });

  document.querySelectorAll('input[name="opSeverity"]').forEach(function(input) {
    input.addEventListener('change', function() {
      if (!input.checked) return;
      severityFilter = input.value;
      selectedCode = null;
      groupLimit = GROUP_PAGE;
      eventLimit = EVENT_PAGE;
      renderErrorFeed();
      updateErrorCodeSelection();
    });
  });

  if (opFeedMore) {
    opFeedMore.addEventListener('click', function() {
      if (groupedMode) groupLimit += 10;
      else eventLimit += EVENT_PAGE;
      renderErrorFeed();
    });
  }

  if (opGroupToggle) {
    opGroupToggle.addEventListener('click', function(event) {
      event.preventDefault();
      groupedMode = !groupedMode;
      groupLimit = GROUP_PAGE;
      eventLimit = EVENT_PAGE;
      opGroupToggle.textContent = groupedMode ? 'Show individual events' : 'Group repeated errors';
      renderErrorFeed();
    });
  }

  document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
      if (opTimer) clearInterval(opTimer);
      if (trendTimer) clearInterval(trendTimer);
      if (recentErrorsTimer) clearInterval(recentErrorsTimer);
      opTimer = null;
      trendTimer = null;
      recentErrorsTimer = null;
    } else {
      if (!window.__metricsPaused) {
        updateOpMetrics();
        loadErrorSummary(false);
        loadRecentErrors(false);
        loadOpHistory(false);
      }
      startOpPolling();
    }
  });

  var operationsTabButton = document.getElementById('opsTabBtn');
  operationsTabButton?.addEventListener('shown.bs.tab', function() {
    [methodStatusChart, endpointChart, latencyEndpointChart, trendReqRate, trendThroughput, trendLatency, trendErrorRate, trendErrorCodes].forEach(function(chart) {
      if (chart) chart.resize();
    });
    if (!operationsLoadSucceeded) loadOperationsSection(true);
  });

  restoreFilters();
  initOpCharts();
  renderHealthBar();
  loadOperationsSection(false);
  startOpPolling();
})();
}
function renderOperationsBootstrapError() {
  var operationsStatus = document.getElementById('opStatus');
  if (operationsStatus) {
    operationsStatus.textContent = 'Unable to initialize operations. ';
    var operationsRetry = document.createElement('button');
    operationsRetry.type = 'button';
    operationsRetry.className = 'btn btn-link btn-sm p-0 align-baseline';
    operationsRetry.textContent = 'Retry';
    operationsRetry.addEventListener('click', tryBootstrapOperationsSection);
    operationsStatus.appendChild(operationsRetry);
  }
}
function tryBootstrapOperationsSection() {
  try {
    bootstrapOperationsSection();
  } catch (error) {
    renderOperationsBootstrapError();
  }
}
tryBootstrapOperationsSection();
