(function () {
  const searchInput = document.getElementById('bucket-search');
  const accessFilter = document.getElementById('bucket-access-filter');
  const bucketItems = document.querySelectorAll('.bucket-item');
  const noResults = document.getElementById('bucket-no-results');
  const countLabel = document.getElementById('bucket-count');
  const table = document.getElementById('buckets-container');

  function applyFilters() {
    const term = (searchInput ? searchInput.value : '').trim().toLowerCase();
    const access = accessFilter ? accessFilter.value : 'all';
    let visibleCount = 0;

    bucketItems.forEach(item => {
      const name = item.querySelector('.bucket-name').textContent.toLowerCase();
      const matchesName = !term || name.includes(term);
      const matchesAccess = access === 'all' || (item.dataset.access || '') === access;
      item.hidden = !(matchesName && matchesAccess);
      if (!item.hidden) visibleCount++;
    });

    const empty = bucketItems.length > 0 && visibleCount === 0;
    if (noResults) noResults.hidden = !empty;
    if (table) table.hidden = empty;
    if (countLabel) {
      countLabel.textContent = visibleCount === bucketItems.length
        ? bucketItems.length + (bucketItems.length === 1 ? ' bucket' : ' buckets')
        : visibleCount + ' of ' + bucketItems.length + ' shown';
    }
  }

  if (searchInput) searchInput.addEventListener('input', applyFilters);
  if (accessFilter) accessFilter.addEventListener('change', applyFilters);
  applyFilters();

  document.querySelectorAll('[data-bucket-row]').forEach((row) => {
    row.addEventListener('click', (event) => {
      if (event.target.closest('a, button, input, [data-ignore-row-click]')) return;
      if (row.dataset.href) window.location.href = row.dataset.href;
    });
  });

  var createForm = document.getElementById('createBucketForm');
  if (createForm) {
    var createModalEl = document.getElementById('createBucketModal');
    var createNameInput = document.getElementById('createBucketName');
    var createNameHelp = document.getElementById('createBucketHelp');
    var createNameError = document.getElementById('createBucketError');
    var createVersioning = document.getElementById('createBucketVersioning');
    var syncCreateNameHelp = function() {
      var invalid = createNameInput.classList.contains('is-invalid');
      if (createNameHelp) createNameHelp.hidden = invalid;
      if (createNameError) createNameError.hidden = !invalid;
    };
    if (createNameInput) {
      createNameInput.addEventListener('input', function() {
        createNameInput.classList.remove('is-invalid');
        syncCreateNameHelp();
      });
    }
    createForm.addEventListener('submit', function(e) {
      e.preventDefault();
      if (createNameInput && !createNameInput.checkValidity()) {
        createNameInput.classList.add('is-invalid');
        syncCreateNameHelp();
        createNameInput.focus();
        return;
      }
      if (createNameInput) {
        createNameInput.classList.remove('is-invalid');
        syncCreateNameHelp();
      }
      window.UICore.submitFormAjax(createForm, {
        successMessage: 'Bucket created',
        onSuccess: function(data) {
          (async function() {
            var bucketName = data.bucket_name || '';
            if (bucketName && createVersioning && createVersioning.checked) {
              var versioningUrl = createForm.dataset.versioningUrlTemplate.replace('__BUCKET__', bucketName);
              try {
                var versioningResponse = await fetch(versioningUrl, {
                  method: 'POST',
                  headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest'
                  },
                  body: new URLSearchParams({ state: 'enable' })
                });
                var versioningData = await versioningResponse.json();
                if (!versioningResponse.ok) {
                  throw new Error(versioningData.error || 'Unable to enable versioning');
                }
              } catch (error) {
                sessionStorage.setItem('flashMessage', JSON.stringify({
                  title: 'Error',
                  body: 'Bucket created, but versioning could not be enabled: ' + ((error && error.message) || 'Unknown error'),
                  variant: 'danger'
                }));
              }
            }
            window.UI.dialog.close(createModalEl);
            if (bucketName) {
              window.location.href = createForm.dataset.detailUrlTemplate.replace('__BUCKET__', bucketName);
            } else {
              location.reload();
            }
          })();
        }
      });
    });
  }
})();
