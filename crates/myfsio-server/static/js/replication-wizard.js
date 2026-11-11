(function() {
    const selectAllCheckbox = document.getElementById('selectAll');
    const bucketCheckboxes = document.querySelectorAll('.bucket-checkbox:not(:disabled)');
    const submitBtn = document.getElementById('submitBtn');
    const modeSelect = document.getElementById('mode');
    const bidirWarning = document.getElementById('bidirWarning');

    function updateBidirWarning() {
        if (modeSelect && bidirWarning) {
            if (modeSelect.value === 'bidirectional') {
                bidirWarning.classList.remove('d-none');
            } else {
                bidirWarning.classList.add('d-none');
            }
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
            const text = checkedCount > 0
                ? `Create ${checkedCount} Replication Rule${checkedCount > 1 ? 's' : ''}`
                : 'Create Replication Rules';
            submitBtn.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" class="me-1" viewBox="0 0 16 16">
                    <path d="M10.97 4.97a.75.75 0 0 1 1.07 1.05l-3.99 4.99a.75.75 0 0 1-1.08.02L4.324 8.384a.75.75 0 1 1 1.06-1.06l2.094 2.093 3.473-4.425a.267.267 0 0 1 .02-.022z"/>
                </svg>
                ${text}
            `;
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
