(function() {
  function setValue(name, value) {
    var element = document.querySelector('[data-disk-pressure="' + name + '"]');
    if (element) element.textContent = value;
  }

  function formatBytes(bytes) {
    var value = Math.max(0, Number(bytes) || 0);
    if (value < 1024) return value + ' B';
    var units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
    var unit = -1;
    do {
      value /= 1024;
      unit++;
    } while (value >= 1024 && unit < units.length - 1);
    return value.toLocaleString(undefined, { maximumFractionDigits: value < 10 ? 1 : 0 }) + ' ' + units[unit];
  }

  function formatPermits(inUse, limit) {
    var used = Math.max(0, Number(inUse) || 0).toLocaleString();
    var configured = Math.max(0, Number(limit) || 0);
    return configured > 0 ? used + ' / ' + configured.toLocaleString() : used + ' / unlimited';
  }

  window.renderDiskPressure = function(diskPressure, replicationQueue) {
    var pressure = diskPressure || {};
    var replication = replicationQueue || {};
    var enabled = pressure.enabled === true;
    var status = document.getElementById('diskPressureStatus');
    var hint = document.getElementById('diskPressureDisabledHint');
    if (status) {
      status.textContent = enabled ? 'Admission active' : 'Admission disabled';
      status.className = enabled
        ? 'badge bg-success-subtle text-success'
        : 'badge bg-secondary-subtle text-secondary';
    }
    if (hint) hint.classList.toggle('d-none', enabled);
    setValue('read_permits', formatPermits(pressure.read_permits_in_use, pressure.read_limit));
    setValue('write_permits', formatPermits(pressure.write_permits_in_use, pressure.write_limit));
    setValue('queue_wait_ms_avg', Math.max(0, Number(pressure.queue_wait_ms_avg) || 0).toLocaleString());
    setValue('queue_timeouts', Math.max(0, Number(pressure.queue_timeouts) || 0).toLocaleString());
    setValue('upload_spool_bytes', formatBytes(pressure.upload_spool_bytes));
    setValue('replication_depth', Math.max(0, Number(replication.depth) || 0).toLocaleString());
    setValue('replication_overflow_total', Math.max(0, Number(replication.overflow_total) || 0).toLocaleString());
  };
})();
