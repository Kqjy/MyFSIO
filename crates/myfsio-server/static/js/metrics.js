(function() {
  function element(name) {
    return document.querySelector('[data-disk-pressure="' + name + '"]');
  }

  function setValue(name, value) {
    var target = element(name);
    if (target) target.textContent = value;
  }

  var formatBytes = window.MyFSIO.formatBytes;
  var trendChart = null;

  function count(value) {
    return Math.max(0, Number(value) || 0);
  }

  function formatPermits(inUse, limit) {
    var used = count(inUse).toLocaleString();
    var configured = count(limit);
    return configured > 0 ? used + ' / ' + configured.toLocaleString() : used + ' / unlimited';
  }

  function minuteLabel(startSeconds) {
    var millis = count(startSeconds) * 1000;
    if (typeof formatTime === 'function') return formatTime(millis);
    var date = new Date(millis);
    return String(date.getHours()).padStart(2, '0') + ':' + String(date.getMinutes()).padStart(2, '0');
  }

  function renderTrend(history, enabled) {
    var wrap = document.getElementById('diskPressureTrendWrap');
    if (wrap) wrap.classList.toggle('d-none', !enabled);
    if (!enabled || typeof Chart === 'undefined') return;
    var canvas = document.getElementById('diskPressureTrend');
    if (!canvas) return;
    var buckets = Array.isArray(history) ? history : [];
    var labels = buckets.map(function(bucket) { return minuteLabel(bucket.start); });
    var waits = buckets.map(function(bucket) {
      return count(bucket.waits) > 0 ? Math.round(count(bucket.wait_ms_total) / count(bucket.waits)) : 0;
    });
    var timeouts = buckets.map(function(bucket) { return count(bucket.timeouts); });
    if (trendChart) {
      trendChart.data.labels = labels;
      trendChart.data.datasets[0].data = timeouts;
      trendChart.data.datasets[1].data = waits;
      trendChart.update('none');
      return;
    }
    trendChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          { type: 'bar', label: '503 timeouts', data: timeouts, backgroundColor: '#ef4444', borderRadius: 2, yAxisID: 'yTimeouts', order: 2 },
          { type: 'line', label: 'Avg permit wait (ms)', data: waits, borderColor: '#8b5cf6', backgroundColor: '#8b5cf615', fill: true, tension: 0.3, pointRadius: 0, pointHoverRadius: 3, borderWidth: 1.5, yAxisID: 'yWait', order: 1 }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        interaction: { mode: 'index', intersect: false },
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 7, font: { size: 10 } } },
          yWait: { position: 'left', beginAtZero: true, ticks: { maxTicksLimit: 3, font: { size: 10 }, callback: function(v) { return v + 'ms'; } } },
          yTimeouts: { position: 'right', beginAtZero: true, grid: { display: false }, ticks: { precision: 0, maxTicksLimit: 3, font: { size: 10 } } }
        }
      }
    });
  }

  window.renderDiskPressure = function(diskPressure, replicationQueue) {
    var pressure = diskPressure || {};
    var replication = replicationQueue || {};
    var recent = pressure.recent || {};
    var enabled = pressure.enabled === true;
    var status = document.getElementById('diskPressureStatus');
    var hint = document.getElementById('diskPressureDisabledHint');
    var recentTimeouts = count(recent.timeouts);
    if (status) {
      if (!enabled) {
        status.textContent = 'Admission disabled';
        status.className = 'badge bg-secondary-subtle text-secondary';
      } else if (recentTimeouts > 0) {
        status.textContent = 'Shedding load';
        status.className = 'badge bg-danger-subtle text-danger-emphasis';
      } else {
        status.textContent = 'Admission active';
        status.className = 'badge bg-success-subtle text-success';
      }
    }
    if (hint) hint.classList.toggle('d-none', enabled);
    setValue('read_permits', formatPermits(pressure.read_permits_in_use, pressure.read_limit));
    setValue('write_permits', formatPermits(pressure.write_permits_in_use, pressure.write_limit));
    setValue('recent_wait_avg', count(recent.wait_ms_avg).toLocaleString());
    setValue('recent_wait_max', count(recent.wait_ms_max).toLocaleString());
    setValue('recent_timeouts', recentTimeouts.toLocaleString());
    var timeoutsEl = element('recent_timeouts');
    if (timeoutsEl) timeoutsEl.classList.toggle('text-danger', recentTimeouts > 0);
    setValue('queue_timeouts_total', count(pressure.queue_timeouts).toLocaleString());
    setValue('upload_spool_bytes', formatBytes(pressure.upload_spool_bytes));
    var capacity = count(replication.capacity);
    var depth = count(replication.depth).toLocaleString();
    setValue('replication_depth', capacity > 0 ? depth + ' / ' + capacity.toLocaleString() : depth);
    setValue('replication_overflow_total', count(replication.overflow_total).toLocaleString());
    renderTrend(pressure.history, enabled);
  };
})();
