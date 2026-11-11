function bootstrapHistorySection() {
(function() {
  if (typeof SvgChart === 'undefined') {
    var historyStatusEl = document.getElementById('historyStatus');
    if (historyStatusEl) historyStatusEl.textContent = 'Charts unavailable: the chart module failed to load.';
    return;
  }
  var cpuChart = null;
  var memoryChart = null;
  var diskChart = null;
  var storageChart = null;
  var storageBucketChart = null;
  var storageMode = 'total';
  var STORAGE_MODE_KEY = 'myfsioStorageMode';
  var STORAGE_BUCKET_LIMIT = 6;
  var OTHER_BUCKETS_KEY = '(other)';
  var bucketPalette = ['#10b981', '#3b82f6', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4', '#9ca3af'];
  var formatBytes = window.MyFSIO.formatBytes;
  var percentFormat = {
    percent: true,
    value: function(v) { return Number(v).toFixed(2) + '%'; },
    tick: function(v) { return v + '%'; }
  };
  var bytesFormat = {
    percent: false,
    value: function(v) { return formatBytes(Number(v) || 0); },
    tick: function(v) { return formatBytes(Math.max(0, Number(v) || 0)); }
  };
  var historyStatus = document.getElementById('historyStatus');
  var timeRangeSelect = document.getElementById('historyTimeRange');
  var historyTimer = null;
  var historyLoadInFlight = false;
  var historyLoadSucceeded = false;
  var renderedHistory = [];
  var renderedHistoryTimestamps = [];
  var renderedHistoryAggregated = false;
  var renderedBucketSeconds = null;

  function formatBucketSpan(seconds) {
    var value = Number(seconds);
    if (!Number.isFinite(value) || value <= 0) return 'unknown interval';
    if (value < 60) return Math.round(value) + ' sec';
    var minutes = value / 60;
    if (minutes < 60) return (Number.isInteger(minutes) ? minutes : minutes.toFixed(1)) + ' min';
    var hours = minutes / 60;
    return (Number.isInteger(hours) ? hours : hours.toFixed(1)) + ' hr';
  }

  function createChart(ctx, label, color, metricKey, format) {
    return new SvgChart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: label,
          data: [],
          borderColor: color,
          backgroundColor: color + '15',
          fill: true,
          tension: 0.3,
          pointRadius: 2,
          pointHoverRadius: 5,
          borderWidth: 1.5,
          hitRadius: 10,
          cubicInterpolationMode: format.percent ? 'default' : 'monotone',
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: chartTooltipTitle(function() { return renderedHistoryTimestamps; }),
              label: function(ctx) {
                if (!renderedHistoryAggregated) return format.value(ctx.parsed.y);
                var point = renderedHistory[ctx.dataIndex] || {};
                var minimum = point[metricKey + '_min'];
                var maximum = point[metricKey + '_max'];
                return [
                  label + ' avg: ' + format.value(ctx.parsed.y),
                  'Min: ' + format.value(minimum === undefined || minimum === null ? ctx.parsed.y : minimum),
                  'Max: ' + format.value(maximum === undefined || maximum === null ? ctx.parsed.y : maximum),
                  'Bucket span: ' + formatBucketSpan(renderedBucketSeconds)
                ];
              }
            }
          }
        },
        scales: {
          x: { display: true, ticks: { maxRotation: 0, font: { size: 10 }, autoSkip: true, maxTicksLimit: 12 } },
          y: format.percent
            ? { display: true, min: 0, max: 100, ticks: { callback: format.tick } }
            : { display: true, ticks: { callback: format.tick, maxTicksLimit: 6 } }
        }
      }
    });
  }

  function initCharts() {
    var cpuCtx = document.getElementById('cpuHistoryChart');
    var memCtx = document.getElementById('memoryHistoryChart');
    var diskCtx = document.getElementById('diskHistoryChart');
    var storageCtx = document.getElementById('storageHistoryChart');
    if (cpuCtx) cpuChart = createChart(cpuCtx, 'CPU %', '#3b82f6', 'cpu_percent', percentFormat);
    if (memCtx) memoryChart = createChart(memCtx, 'Memory %', '#06b6d4', 'memory_percent', percentFormat);
    if (diskCtx) diskChart = createChart(diskCtx, 'Disk %', '#f59e0b', 'disk_percent', percentFormat);
    if (storageCtx) storageChart = createChart(storageCtx, 'Stored', '#10b981', 'storage_bytes', bytesFormat);
    var bucketCtx = document.getElementById('storageBucketChart');
    if (bucketCtx) {
      storageBucketChart = new SvgChart(bucketCtx, {
        type: 'line',
        data: { labels: [], datasets: [] },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: false,
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 10 } } },
            emptyState: { message: 'Per-bucket sizes are recorded from this version on' },
            tooltip: {
              callbacks: {
                title: chartTooltipTitle(function() { return renderedHistoryTimestamps; }),
                label: function(ctx) { return ctx.dataset.label + ': ' + formatBytes(Number(ctx.parsed.y) || 0); }
              }
            }
          },
          scales: {
            x: { display: true, ticks: { maxRotation: 0, font: { size: 10 }, autoSkip: true, maxTicksLimit: 12 } },
            y: { display: true, stacked: true, beginAtZero: true, ticks: { maxTicksLimit: 6, callback: function(v) { return formatBytes(Math.max(0, Number(v) || 0)); } } }
          }
        }
      });
    }
  }

  function renderHistoryLoadError() {
    if (!historyStatus) return;
    historyStatus.textContent = 'Unable to load history. ';
    var retry = document.createElement('button');
    retry.type = 'button';
    retry.className = 'btn btn-link btn-sm p-0 align-baseline';
    retry.textContent = 'Retry';
    retry.addEventListener('click', function() { loadHistory(true); });
    historyStatus.appendChild(retry);
  }

  function renderBucketChart(history, labels) {
    if (!storageBucketChart) return;
    var latest = Object.create(null);
    history.forEach(function(point) {
      Object.keys(point.bucket_bytes || {}).forEach(function(name) {
        latest[name] = Number(point.bucket_bytes[name]) || 0;
      });
    });
    var ranked = Object.keys(latest).filter(function(name) { return name !== OTHER_BUCKETS_KEY; });
    ranked.sort(function(a, b) { return latest[b] - latest[a]; });
    var shown = ranked.slice(0, STORAGE_BUCKET_LIMIT);
    var folded = ranked.slice(STORAGE_BUCKET_LIMIT);
    var hasOther = folded.length > 0 || Object.prototype.hasOwnProperty.call(latest, OTHER_BUCKETS_KEY);
    function recorded(point) {
      return point.bucket_bytes && Object.keys(point.bucket_bytes).length > 0;
    }
    var series = shown.map(function(name) {
      return {
        label: name,
        value: function(point) { return recorded(point) ? (Number(point.bucket_bytes[name]) || 0) : null; }
      };
    });
    if (hasOther) {
      series.push({
        label: 'Other buckets',
        value: function(point) {
          if (!recorded(point)) return null;
          return folded.concat([OTHER_BUCKETS_KEY]).reduce(function(sum, name) { return sum + (Number(point.bucket_bytes[name]) || 0); }, 0);
        }
      });
    }
    storageBucketChart.data.labels = series.length ? labels : [];
    storageBucketChart.data.datasets = series.map(function(entry, index) {
      var color = bucketPalette[index % bucketPalette.length];
      return {
        label: entry.label,
        data: history.map(entry.value),
        borderColor: color,
        backgroundColor: color + '33',
        fill: index === 0 ? 'origin' : '-1',
        tension: 0.3,
        cubicInterpolationMode: 'monotone',
        pointRadius: 0,
        pointHoverRadius: 4,
        borderWidth: 1.5
      };
    });
    storageBucketChart.update('none');
  }

  function applyStorageMode(mode) {
    storageMode = mode === 'buckets' ? 'buckets' : 'total';
    var totalWrap = document.getElementById('storageTotalWrap');
    var bucketWrap = document.getElementById('storageBucketWrap');
    if (totalWrap) totalWrap.classList.toggle('d-none', storageMode !== 'total');
    if (bucketWrap) bucketWrap.classList.toggle('d-none', storageMode !== 'buckets');
    var input = document.querySelector('input[name="storageMode"][value="' + storageMode + '"]');
    if (input) input.checked = true;
    [storageChart, storageBucketChart].forEach(function(chart) { if (chart) chart.resize(); });
  }

  function loadHistory(force) {
    if ((!force && (document.hidden || window.__metricsPaused)) || historyLoadInFlight) return;
    historyLoadInFlight = true;
    var hours = timeRangeSelect ? timeRangeSelect.value : 24;
    return fetch('/ui/metrics/history?hours=' + encodeURIComponent(hours) + '&points=240')
      .then(parseMetricsResponse)
      .then(function(data) {
        historyLoadSucceeded = true;
        if (!data.enabled || !data.history || data.history.length === 0) {
          if (historyStatus) historyStatus.textContent = 'No history data yet. Recorded every ' + (data.interval_minutes || 5) + ' min.';
          return;
        }
        var history = data.history;
        renderedHistory = history;
        renderedHistoryAggregated = Boolean(data.aggregated);
        renderedBucketSeconds = data.bucket_seconds;
        renderedHistoryTimestamps = history.map(function(h) { return h.timestamp; });
        var labels = buildChartLabels(renderedHistoryTimestamps);

        function updateChart(chart, data) {
          if (!chart) return;
          chart.data.labels = labels;
          chart.data.datasets[0].data = data;
          chart.update('none');
        }
        updateChart(cpuChart, history.map(function(h) { return h.cpu_percent; }));
        updateChart(memoryChart, history.map(function(h) { return h.memory_percent; }));
        updateChart(diskChart, history.map(function(h) { return h.disk_percent; }));
        var storageSeries = history.map(function(h) { return Number(h.storage_bytes) || 0; });
        if (storageChart && storageSeries.length) {
          var storageLow = Math.min.apply(null, storageSeries);
          var storageHigh = Math.max.apply(null, storageSeries);
          var storagePad = (storageHigh - storageLow) * 0.1 || Math.max(storageHigh * 0.05, 1024);
          storageChart.options.scales.y.min = Math.max(0, storageLow - storagePad);
          storageChart.options.scales.y.max = storageHigh + storagePad;
        }
        updateChart(storageChart, storageSeries);
        renderBucketChart(history, labels);
        var deltaEl = document.getElementById('storageHistoryDelta');
        if (deltaEl) {
          var delta = storageSeries.length > 1 ? storageSeries[storageSeries.length - 1] - storageSeries[0] : 0;
          deltaEl.textContent = storageSeries.length > 1
            ? (delta >= 0 ? '+' : '\u2212') + formatBytes(Math.abs(delta)) + ' over range'
            : '';
        }

        if (historyStatus) {
          var sampleCount = Number(data.sample_count);
          if (!Number.isFinite(sampleCount)) sampleCount = history.length;
          historyStatus.textContent = data.aggregated
            ? sampleCount.toLocaleString() + ' samples \u2192 ' + history.length.toLocaleString() + ' buckets (avg over ' + formatBucketSpan(data.bucket_seconds) + ')'
            : sampleCount.toLocaleString() + ' samples';
        }
      })
      .catch(function() {
        renderHistoryLoadError();
      })
      .finally(function() {
        historyLoadInFlight = false;
      });
  }

  function startHistoryPolling() {
    if (historyTimer) clearInterval(historyTimer);
    historyTimer = setInterval(loadHistory, 60000);
  }

  if (timeRangeSelect) timeRangeSelect.addEventListener('change', loadHistory);

  document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
      if (historyTimer) clearInterval(historyTimer);
      historyTimer = null;
    } else {
      loadHistory();
      startHistoryPolling();
    }
  });

  var historyTabButton = document.getElementById('historyTabBtn');
  historyTabButton?.addEventListener('shown.bs.tab', function() {
    [cpuChart, memoryChart, diskChart, storageChart, storageBucketChart].forEach(function(chart) {
      if (chart) chart.resize();
    });
    if (!historyLoadSucceeded) loadHistory(true);
  });

  initCharts();
  try {
    applyStorageMode(window.localStorage.getItem(STORAGE_MODE_KEY) || 'total');
  } catch (storageError) {
    applyStorageMode('total');
  }
  document.querySelectorAll('input[name="storageMode"]').forEach(function(input) {
    input.addEventListener('change', function() {
      if (!input.checked) return;
      applyStorageMode(input.value);
      try {
        window.localStorage.setItem(STORAGE_MODE_KEY, storageMode);
      } catch (storageError) {
        void storageError;
      }
    });
  });
  loadHistory();
  startHistoryPolling();
})();
}
function renderHistoryBootstrapError() {
  var historyInitStatus = document.getElementById('historyStatus');
  if (historyInitStatus) {
    historyInitStatus.textContent = 'Unable to initialize history. ';
    var historyInitRetry = document.createElement('button');
    historyInitRetry.type = 'button';
    historyInitRetry.className = 'btn btn-link btn-sm p-0 align-baseline';
    historyInitRetry.textContent = 'Retry';
    historyInitRetry.addEventListener('click', tryBootstrapHistorySection);
    historyInitStatus.appendChild(historyInitRetry);
  }
}
function tryBootstrapHistorySection() {
  try {
    bootstrapHistorySection();
  } catch (error) {
    renderHistoryBootstrapError();
  }
}
tryBootstrapHistorySection();
