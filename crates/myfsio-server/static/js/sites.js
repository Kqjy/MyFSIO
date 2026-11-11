(function() {
    function escapeHtml(s) {
        if (window.UICore && window.UICore.escapeHtml) return window.UICore.escapeHtml(s);
        return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' }[c];
        });
    }

    var editPeerModal = document.getElementById('editPeerModal');
    if (editPeerModal) {
        editPeerModal.addEventListener('show.bs.modal', function (event) {
            var button = event.relatedTarget;
            var siteId = button.getAttribute('data-site-id');
            document.getElementById('edit_site_id').value = siteId;
            document.getElementById('edit_endpoint').value = button.getAttribute('data-endpoint');
            document.getElementById('edit_region').value = button.getAttribute('data-region');
            document.getElementById('edit_priority').value = button.getAttribute('data-priority');
            document.getElementById('edit_display_name').value = button.getAttribute('data-display-name');
            document.getElementById('edit_connection_id').value = button.getAttribute('data-connection-id');
            document.getElementById('edit_peer_inbound_access_key').value = button.getAttribute('data-peer-inbound-access-key') || '';
            document.getElementById('editPeerForm').action = '/ui/sites/peers/' + encodeURIComponent(siteId) + '/update';
        });
    }

    document.querySelectorAll('.link-no-connection').forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            var siteId = this.getAttribute('data-site-id');
            var row = this.closest('tr[data-site-id]');
            if (row) {
                var btn = row.querySelector('.btn[data-bs-target="#editPeerModal"]');
                if (btn) btn.click();
            }
        });
    });

    var deletePeerModal = document.getElementById('deletePeerModal');
    if (deletePeerModal) {
        deletePeerModal.addEventListener('show.bs.modal', function (event) {
            var button = event.relatedTarget;
            var siteId = button.getAttribute('data-site-id');
            var displayName = button.getAttribute('data-display-name');
            document.getElementById('deletePeerName').textContent = displayName;
            document.getElementById('deletePeerForm').action = '/ui/sites/peers/' + encodeURIComponent(siteId) + '/delete';
        });
    }

    function formatTimeAgo(date) {
        var seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 60) return 'just now';
        var minutes = Math.floor(seconds / 60);
        if (minutes < 60) return minutes + 'm ago';
        var hours = Math.floor(minutes / 60);
        if (hours < 24) return hours + 'h ago';
        return Math.floor(hours / 24) + 'd ago';
    }

    function doHealthCheck(siteId) {
        var row = document.querySelector('tr[data-site-id="' + CSS.escape(siteId) + '"]');
        var statusSpan = row ? row.querySelector('.peer-health-status') : null;
        if (!statusSpan) return Promise.resolve();

        statusSpan.innerHTML = '<span class="spinner-border spinner-border-sm text-muted" role="status" style="width: 14px; height: 14px;"></span>';

        return fetch('/ui/sites/peers/' + encodeURIComponent(siteId) + '/health')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                var now = new Date();
                statusSpan.setAttribute('data-last-checked', now.toISOString());
                if (data.is_healthy) {
                    statusSpan.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="text-success" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/></svg>';
                    statusSpan.title = 'Healthy (checked ' + formatTimeAgo(now) + ')';
                    return { siteId: siteId, healthy: true };
                } else {
                    statusSpan.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="text-danger" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293 5.354 4.646z"/></svg>';
                    statusSpan.title = 'Unhealthy' + (data.error ? ': ' + data.error : '') + ' (checked ' + formatTimeAgo(now) + ')';
                    return { siteId: siteId, healthy: false, error: data.error };
                }
            })
            .catch(function(err) {
                statusSpan.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="text-muted" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286zm1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94z"/></svg>';
                statusSpan.title = 'Check failed';
                return { siteId: siteId, healthy: null };
            });
    }

    document.querySelectorAll('.btn-check-health').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var siteId = this.getAttribute('data-site-id');
            doHealthCheck(siteId).then(function(result) {
                if (!result) return;
                if (result.healthy === true) {
                    if (window.showToast) window.showToast('Peer site is healthy', 'Health Check', 'success');
                } else if (result.healthy === false) {
                    if (window.showToast) window.showToast(result.error || 'Peer site is unhealthy', 'Health Check', 'error');
                } else {
                    if (window.showToast) window.showToast('Failed to check health', 'Health Check', 'error');
                }
            });
        });
    });

    var checkAllBtn = document.getElementById('btnCheckAllHealth');
    if (checkAllBtn) {
        checkAllBtn.addEventListener('click', function() {
            var btn = this;
            var originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Checking...';

            var siteIds = [];
            document.querySelectorAll('.peer-health-status').forEach(function(el) {
                siteIds.push(el.getAttribute('data-site-id'));
            });

            var promises = siteIds.map(function(id) { return doHealthCheck(id); });
            Promise.all(promises).then(function(results) {
                var healthy = results.filter(function(r) { return r && r.healthy === true; }).length;
                var unhealthy = results.filter(function(r) { return r && r.healthy === false; }).length;
                var failed = results.filter(function(r) { return r && r.healthy === null; }).length;

                var msg = healthy + ' healthy';
                if (unhealthy > 0) msg += ', ' + unhealthy + ' unhealthy';
                if (failed > 0) msg += ', ' + failed + ' failed';
                if (window.showToast) window.showToast(msg, 'Health Check', unhealthy > 0 ? 'warning' : 'success');

                btn.disabled = false;
                btn.innerHTML = originalHtml;
            });
        });
    }

    document.querySelectorAll('.btn-load-stats').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var siteId = this.getAttribute('data-site-id');
            var detailDiv = document.getElementById('stats-' + siteId);
            if (!detailDiv) return;

            detailDiv.classList.remove('d-none');
            detailDiv.innerHTML = '<span class="spinner-border spinner-border-sm text-muted" style="width: 12px; height: 12px;"></span> Loading...';

            fetch('/ui/sites/peers/' + encodeURIComponent(siteId) + '/sync-stats')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (data.error) {
                        detailDiv.innerHTML = '<span class="text-danger">' + escapeHtml(data.error) + '</span>';
                    } else {
                        var lastSync = data.last_sync_at
                            ? new Date(data.last_sync_at * 1000).toLocaleString()
                            : 'Never';
                        detailDiv.innerHTML =
                            '<div class="d-flex flex-wrap gap-2 mb-1">' +
                                '<span class="text-success"><strong>' + escapeHtml(String(data.objects_synced)) + '</strong> synced</span>' +
                                '<span class="text-warning"><strong>' + escapeHtml(String(data.objects_pending)) + '</strong> pending</span>' +
                                '<span class="text-danger"><strong>' + escapeHtml(String(data.objects_failed)) + '</strong> failed</span>' +
                            '</div>' +
                            '<div class="text-muted" style="font-size: 0.75rem;">Last sync: ' + escapeHtml(lastSync) + '</div>';
                    }
                })
                .catch(function() {
                    detailDiv.innerHTML = '<span class="text-danger">Failed to load stats</span>';
                });
        });
    });

    document.querySelectorAll('.bidir-status-icon').forEach(function(icon) {
        icon.addEventListener('click', function() {
            var siteId = this.getAttribute('data-site-id');
            var row = this.closest('tr[data-site-id]');
            var btn = row ? row.querySelector('.btn-check-bidir') : null;
            if (btn) btn.click();
        });
    });

    document.querySelectorAll('.btn-check-bidir').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var siteId = this.getAttribute('data-site-id');
            var displayName = this.getAttribute('data-display-name');
            var modal = new bootstrap.Modal(document.getElementById('bidirStatusModal'));
            var contentDiv = document.getElementById('bidirStatusContent');
            var wizardLink = document.getElementById('bidirWizardLink');

            contentDiv.innerHTML =
                '<div class="text-center py-4">' +
                    '<span class="spinner-border text-primary" role="status"></span>' +
                    '<p class="text-muted mt-2 mb-0">Checking bidirectional configuration with ' + escapeHtml(displayName) + '...</p>' +
                '</div>';
            wizardLink.classList.add('d-none');
            modal.show();

            fetch('/ui/sites/peers/' + encodeURIComponent(siteId) + '/bidirectional-status')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var html = '';

                    if (data.is_fully_configured) {
                        html += '<div class="alert alert-success d-flex align-items-center mb-4" role="alert">' +
                            '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="flex-shrink-0 me-2" viewBox="0 0 16 16">' +
                                '<path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>' +
                            '</svg>' +
                            '<div><strong>Bidirectional sync is fully configured!</strong><br><small>Both sites are set up to sync data in both directions.</small></div>' +
                        '</div>';
                    } else if (data.issues && data.issues.length > 0) {
                        var errors = data.issues.filter(function(i) { return i.severity === 'error'; });
                        var warnings = data.issues.filter(function(i) { return i.severity === 'warning'; });

                        if (errors.length > 0) {
                            html += '<div class="alert alert-danger mb-3" role="alert">' +
                                '<h6 class="alert-heading fw-bold mb-2">' +
                                    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="me-1" viewBox="0 0 16 16"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.354 4.646a.5.5 0 1 0-.708.708L7.293 8l-2.647 2.646a.5.5 0 0 0 .708.708L8 8.707l2.646 2.647a.5.5 0 0 0 .708-.708L8.707 8l2.647-2.646a.5.5 0 0 0-.708-.708L8 7.293 5.354 4.646z"/></svg>' +
                                    ' Configuration Errors</h6><ul class="mb-0 ps-3">';
                            errors.forEach(function(issue) {
                                html += '<li><strong>' + escapeHtml(issue.code) + ':</strong> ' + escapeHtml(issue.message) + '</li>';
                            });
                            html += '</ul></div>';
                        }

                        if (warnings.length > 0) {
                            html += '<div class="alert alert-warning mb-3" role="alert">' +
                                '<h6 class="alert-heading fw-bold mb-2">' +
                                    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="me-1" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg>' +
                                    ' Warnings</h6><ul class="mb-0 ps-3">';
                            warnings.forEach(function(issue) {
                                html += '<li><strong>' + escapeHtml(issue.code) + ':</strong> ' + escapeHtml(issue.message) + '</li>';
                            });
                            html += '</ul></div>';
                        }
                    }

                    html += '<div class="row g-3">';
                    html += '<div class="col-md-6"><div class="card h-100"><div class="card-header bg-light py-2"><strong>This Site (Local)</strong></div>' +
                        '<div class="card-body small">' +
                            '<p class="mb-1"><strong>Site ID:</strong> ' + (data.local_site_id ? escapeHtml(data.local_site_id) : '<span class="text-danger">Not configured</span>') + '</p>' +
                            '<p class="mb-1"><strong>Endpoint:</strong> ' + (data.local_endpoint ? escapeHtml(data.local_endpoint) : '<span class="text-danger">Not configured</span>') + '</p>' +
                            '<p class="mb-1"><strong>Site Sync Worker:</strong> ' + (data.local_site_sync_enabled ? '<span class="text-success">Enabled</span>' : '<span class="text-warning">Disabled</span>') + '</p>' +
                            '<p class="mb-0"><strong>Bidirectional Rules:</strong> ' + (data.local_bidirectional_rules ? data.local_bidirectional_rules.length : 0) + '</p>' +
                        '</div></div></div>';

                    if (data.remote_status) {
                        var rs = data.remote_status;
                        html += '<div class="col-md-6"><div class="card h-100"><div class="card-header bg-light py-2"><strong>Remote Site (' + escapeHtml(displayName) + ')</strong></div>' +
                            '<div class="card-body small">';
                        if (rs.admin_access_denied) {
                            html += '<p class="text-warning mb-0">Admin access denied - cannot verify remote configuration</p>';
                        } else if (rs.reachable === false) {
                            html += '<p class="text-danger mb-0">Could not reach remote admin API</p>';
                        } else {
                            html += '<p class="mb-1"><strong>Has Peer Entry for Us:</strong> ' + (rs.has_peer_for_us ? '<span class="text-success">Yes</span>' : '<span class="text-danger">No</span>') + '</p>' +
                                '<p class="mb-1"><strong>Connection Configured:</strong> ' + (rs.peer_connection_configured ? '<span class="text-success">Yes</span>' : '<span class="text-danger">No</span>') + '</p>';
                        }
                        html += '</div></div></div>';
                    } else {
                        html += '<div class="col-md-6"><div class="card h-100"><div class="card-header bg-light py-2"><strong>Remote Site (' + escapeHtml(displayName) + ')</strong></div>' +
                            '<div class="card-body small"><p class="text-muted mb-0">Could not check remote status</p></div></div></div>';
                    }
                    html += '</div>';

                    if (data.local_bidirectional_rules && data.local_bidirectional_rules.length > 0) {
                        html += '<div class="mt-3"><h6 class="fw-semibold">Local Bidirectional Rules</h6>' +
                            '<table class="table table-sm table-bordered mb-0"><thead class="table-light"><tr><th>Source Bucket</th><th>Target Bucket</th><th>Status</th></tr></thead><tbody>';
                        data.local_bidirectional_rules.forEach(function(rule) {
                            html += '<tr><td>' + escapeHtml(rule.bucket_name) + '</td><td>' + escapeHtml(rule.target_bucket) + '</td>' +
                                '<td>' + (rule.enabled ? '<span class="badge bg-success">Enabled</span>' : '<span class="badge bg-secondary">Disabled</span>') + '</td></tr>';
                        });
                        html += '</tbody></table></div>';
                    }

                    if (!data.is_fully_configured) {
                        html += '<div class="alert alert-info mt-3 mb-0" role="alert">' +
                            '<h6 class="alert-heading fw-bold">How to Fix</h6>' +
                            '<ol class="mb-0 ps-3">' +
                                '<li>Ensure this site has a Site ID and Endpoint URL configured</li>' +
                                '<li>On the remote site, register this site as a peer with a connection</li>' +
                                '<li>Create bidirectional replication rules on both sites</li>' +
                                '<li>Enable SITE_SYNC_ENABLED=true on both sites</li>' +
                            '</ol></div>';
                        var blockingErrors = ['NO_CONNECTION', 'CONNECTION_NOT_FOUND', 'REMOTE_UNREACHABLE', 'ENDPOINT_NOT_ALLOWED'];
                        var hasBlockingError = data.issues && data.issues.some(function(i) { return blockingErrors.indexOf(i.code) !== -1; });
                        if (!hasBlockingError) {
                            wizardLink.href = '/ui/replication/new?site_id=' + encodeURIComponent(siteId);
                            wizardLink.classList.remove('d-none');
                        }
                    }

                    contentDiv.innerHTML = html;
                })
                .catch(function(err) {
                    contentDiv.innerHTML = '<div class="alert alert-danger" role="alert"><strong>Error:</strong> Failed to check bidirectional status. ' + escapeHtml(err.message || '') + '</div>';
                });
        });
    });

    var revokePeerCredModal = document.getElementById('revokePeerCredModal');
    if (revokePeerCredModal) {
        revokePeerCredModal.addEventListener('show.bs.modal', function (event) {
            var button = event.relatedTarget;
            if (!button) return;
            var ak = button.getAttribute('data-access-key') || '';
            var siteId = button.getAttribute('data-site-id') || '';
            document.getElementById('revokePeerCredAccessKey').textContent = ak;
            document.getElementById('revokePeerCredSiteId').textContent = siteId;
            document.getElementById('revokePeerCredForm').action = '/ui/peer-credentials/' + encodeURIComponent(ak) + '/delete';
        });
    }

    var peerCredIssuedDataEl = document.getElementById('peer-cred-issued-data');
    if (peerCredIssuedDataEl) {
        try {
            var issued = JSON.parse(peerCredIssuedDataEl.dataset.payload || '{}');
            var modalEl = document.getElementById('peerCredIssuedModal');
            if (modalEl && issued && issued.access_key) {
                document.getElementById('peerCredIssuedAccessKey').value = issued.access_key || '';
                document.getElementById('peerCredIssuedSecretKey').value = issued.secret_key || '';
                document.getElementById('peerCredIssuedSiteId').value = issued.site_id || '';
                new bootstrap.Modal(modalEl).show();
            }
        } catch (e) {}
    }

    document.querySelectorAll('.btn-copy-cred').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var targetId = this.getAttribute('data-copy-target');
            var label = this.getAttribute('data-copy-label') || 'Value';
            var input = document.getElementById(targetId);
            if (!input) return;
            var value = input.value;
            if (window.UICore && window.UICore.copyToClipboard) {
                window.UICore.copyToClipboard(value).then(function(ok) {
                    if (ok && window.showToast) window.showToast(label + ' copied', 'Copied', 'success');
                });
            } else {
                input.select();
                try { document.execCommand('copy'); } catch (e) {}
            }
        });
    });

    document.querySelectorAll('.btn-copy-endpoint').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            var url = this.getAttribute('data-url');
            if (window.UICore && window.UICore.copyToClipboard) {
                window.UICore.copyToClipboard(url).then(function(ok) {
                    if (ok && window.showToast) window.showToast('Endpoint URL copied', 'Copied', 'success');
                });
            }
        });
    });

    var localSiteForm = document.getElementById('localSiteForm');
    if (localSiteForm) {
        localSiteForm.addEventListener('submit', function(e) {
            e.preventDefault();
            window.UICore.submitFormAjax(this, {
                successMessage: 'Local site configuration updated',
                onSuccess: function() {
                    setTimeout(function() { location.reload(); }, 800);
                }
            });
        });
    }

    var addPeerForm = document.getElementById('addPeerForm');
    if (addPeerForm) {
        addPeerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            window.UICore.submitFormAjax(this, {
                successMessage: 'Peer site added',
                onSuccess: function(data) {
                    if (data.redirect) {
                        setTimeout(function() { window.location.href = data.redirect; }, 800);
                    } else {
                        setTimeout(function() { location.reload(); }, 800);
                    }
                }
            });
        });
    }

    var editPeerForm = document.getElementById('editPeerForm');
    if (editPeerForm) {
        editPeerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var modal = bootstrap.Modal.getInstance(document.getElementById('editPeerModal'));
            window.UICore.submitFormAjax(this, {
                successMessage: 'Peer site updated',
                onSuccess: function() {
                    if (modal) modal.hide();
                    setTimeout(function() { location.reload(); }, 800);
                }
            });
        });
    }

    var deletePeerForm = document.getElementById('deletePeerForm');
    if (deletePeerForm) {
        deletePeerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            var modal = bootstrap.Modal.getInstance(document.getElementById('deletePeerModal'));
            window.UICore.submitFormAjax(this, {
                successMessage: 'Peer site deleted',
                onSuccess: function() {
                    if (modal) modal.hide();
                    setTimeout(function() { location.reload(); }, 800);
                }
            });
        });
    }
    document.querySelectorAll('.peer-actions-dropdown').forEach(function(dd, idx) {
        var menu = dd.querySelector('.dropdown-menu');
        if (!menu) return;
        var pairId = 'peer-dd-' + idx;
        dd.dataset.peerDdPair = pairId;
        menu.dataset.peerDdPair = pairId;
        function reposition() {
            var toggle = dd.querySelector('[data-bs-toggle="dropdown"]');
            if (!toggle) return;
            var rect = toggle.getBoundingClientRect();
            var menuWidth = menu.offsetWidth;
            var menuHeight = menu.offsetHeight;
            var pad = 8;
            var left = rect.right - menuWidth;
            if (left + menuWidth > window.innerWidth - pad) left = window.innerWidth - pad - menuWidth;
            if (left < pad) left = pad;
            var top = rect.bottom;
            if (top + menuHeight > window.innerHeight - pad) {
                top = Math.max(pad, rect.top - menuHeight);
            }
            menu.style.position = 'fixed';
            menu.style.top = top + 'px';
            menu.style.left = left + 'px';
            menu.style.right = 'auto';
            menu.style.bottom = 'auto';
            menu.style.transform = 'none';
        }
        dd.addEventListener('show.bs.dropdown', function() {
            if (menu.parentNode !== document.body) document.body.appendChild(menu);
        });
        dd.addEventListener('shown.bs.dropdown', reposition);
        dd.addEventListener('hidden.bs.dropdown', function() {
            menu.style.cssText = '';
            if (menu.parentNode !== dd) dd.appendChild(menu);
        });
        window.addEventListener('resize', function() { if (menu.classList.contains('show')) reposition(); });
        window.addEventListener('scroll', function() { if (menu.classList.contains('show')) reposition(); }, true);
    });
})();

(function () {
    function fmtRel(ts) {
        var diff = Math.max(0, Math.floor(Date.now() / 1000 - ts));
        if (diff < 60) return diff + "s ago";
        if (diff < 3600) return Math.floor(diff / 60) + "m ago";
        if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
        return Math.floor(diff / 86400) + "d ago";
    }
    function refresh() {
        document.querySelectorAll("[data-last-sync-at]").forEach(function (el) {
            var ts = parseFloat(el.getAttribute("data-last-sync-at"));
            var span = el.querySelector(".last-sync-rel");
            if (span && !isNaN(ts)) span.textContent = fmtRel(ts);
        });
    }
    refresh();
    setInterval(refresh, 30000);
})();
