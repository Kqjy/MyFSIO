(function() {
    const selectAllCheckbox = document.getElementById('selectAll');
    const bucketCheckboxes = document.querySelectorAll('.bucket-checkbox:not(:disabled)');
    const submitBtn = document.getElementById('submitBtn');
    const modeSelect = document.getElementById('mode');
    const bidirWarning = document.getElementById('bidirWarning');

    function updateBidirWarning() {
        if (modeSelect && bidirWarning) {
            bidirWarning.hidden = modeSelect.value !== 'bidirectional';
        }
    }

    if (modeSelect) {
        modeSelect.addEventListener('change', updateBidirWarning);
        updateBidirWarning();
    }

    function updateSubmitButton() {
        const checkedCount = document.querySelectorAll('.bucket-checkbox:checked').length;
        if (submitBtn) {
            submitBtn.disabled = checkedCount === 0;
            submitBtn.textContent = checkedCount > 0
                ? `Create ${checkedCount} replication rule${checkedCount > 1 ? 's' : ''}`
                : 'Create replication rules';
        }
    }

    function updateSelectAll() {
        if (selectAllCheckbox && bucketCheckboxes.length > 0) {
            const allChecked = Array.from(bucketCheckboxes).every(cb => cb.checked);
            const someChecked = Array.from(bucketCheckboxes).some(cb => cb.checked);
            selectAllCheckbox.checked = allChecked;
            selectAllCheckbox.indeterminate = someChecked && !allChecked;
        }
    }

    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function() {
            bucketCheckboxes.forEach(cb => {
                cb.checked = this.checked;
            });
            updateSubmitButton();
        });
    }

    bucketCheckboxes.forEach(cb => {
        cb.addEventListener('change', function() {
            updateSelectAll();
            updateSubmitButton();
        });
    });

    updateSelectAll();
    updateSubmitButton();
})();
