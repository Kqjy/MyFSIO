(function() {
  const source = document.getElementById('bucketDetailEndpoints');
  const data = source ? source.dataset : {};
  window.BucketDetailConfig = {
    endpoints: {
      versioning: data.versioning || '',
      bucketsOverview: data.bucketsOverview || '',
      archivedObjects: data.archivedObjects || ''
    }
  };
})();

(function() {
  const bidirWarning = document.getElementById('bidirWarningBucket');
  const modeRadios = document.querySelectorAll('input[name="replication_mode"]');

  function updateBidirWarning() {
    if (!bidirWarning) return;
    const selected = document.querySelector('input[name="replication_mode"]:checked');
    if (selected && selected.value === 'bidirectional') {
      bidirWarning.classList.remove('is-hidden');
    } else {
      bidirWarning.classList.add('is-hidden');
    }
  }

  modeRadios.forEach(function(radio) {
    radio.addEventListener('change', updateBidirWarning);
  });

  updateBidirWarning();
})();
