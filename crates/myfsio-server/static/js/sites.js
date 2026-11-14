(function() {
    'use strict';

    function byId(id) {
        return document.getElementById(id);
    }

    function el(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = String(text);
        return node;
    }

    function toast(message, title, type) {
        if (window.showToast) window.showToast(message, title, type);
    }

    function peerUrl(siteId, suffix) {
        return '/ui/sites/peers/' + encodeURIComponent(siteId) + '/' + suffix;
    }

    function rowFor(siteId) {
        return document.querySelector('tr[data-site-id="' + CSS.escape(siteId) + '"]');
    }

    function reloadSoon() {
        setTimeout(function() { location.reload(); }, 800);
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

    var healthTones = { healthy: ' ui-badge-ok', unhealthy: ' ui-badge-bad', unknown: ' ui-badge-warn' };

    function setHealth(siteId, state, label, detail) {
        var row = rowFor(siteId);
        var badge = row ? row.querySelector('.peer-health-status') : null;
        if (badge) {
            badge.className = 'ui-badge peer-health-status' + (healthTones[state] || '');
            badge.textContent = label;
            if (detail) badge.setAttribute('data-ui-tip', detail);
            else badge.removeAttribute('data-ui-tip');
        }
        var node = document.querySelector('[data-topo-health="' + CSS.escape(siteId) + '"]');
        if (node) {
            node.className = 'ui-badge' + (healthTones[state] || '');
            node.textContent = label;
        }
        var link = document.querySelector('[data-topo-link="' + CSS.escape(siteId) + '"]');
        if (link && state === 'unhealthy') link.classList.add('is-bad');
    }

    function stampChecked() {
        var stamp = byId('peersCheckedAt');
        if (!stamp) return;
        stamp.dataset.checkedAt = String(Date.now());
        stamp.textContent = 'Checked just now';
    }

    function doHealthCheck(siteId) {
        setHealth(siteId, 'checking', 'Checking');
        return fetch(peerUrl(siteId, 'health'))
            .then(function(response) { return response.json(); })
            .then(function(data) {
                stampChecked();
                if (data.is_healthy) {
                    setHealth(siteId, 'healthy', 'Healthy');
                    return { siteId: siteId, healthy: true };
                }
                setHealth(siteId, 'unhealthy', 'Unreachable', data.error || '');
                return { siteId: siteId, healthy: false, error: data.error };
            })
            .catch(function() {
                setHealth(siteId, 'unknown', 'Unknown', 'Could not check health');
                return { siteId: siteId, healthy: null };
            });
    }

    function checkOne(siteId) {
        doHealthCheck(siteId).then(function(result) {
            if (result.healthy === true) toast('Peer site is healthy', 'Health check', 'success');
            else if (result.healthy === false) toast(result.error || 'Peer site is unreachable', 'Health check', 'error');
            else toast('Failed to check health', 'Health check', 'error');
        });
    }

    var checkAllBtn = byId('btnCheckAllHealth');
    if (checkAllBtn) {
        checkAllBtn.addEventListener('click', function() {
            var label = checkAllBtn.textContent;
            checkAllBtn.disabled = true;
            checkAllBtn.textContent = 'Checking…';
            var siteIds = Array.prototype.map.call(document.querySelectorAll('#peerTable tr[data-site-id]'), function(row) {
                return row.getAttribute('data-site-id');
            });
            Promise.all(siteIds.map(doHealthCheck)).then(function(results) {
                var healthy = results.filter(function(r) { return r.healthy === true; }).length;
                var unhealthy = results.filter(function(r) { return r.healthy === false; }).length;
                var failed = results.filter(function(r) { return r.healthy === null; }).length;
                var msg = healthy + ' healthy';
                if (unhealthy > 0) msg += ', ' + unhealthy + ' unreachable';
                if (failed > 0) msg += ', ' + failed + ' failed';
                toast(msg, 'Health check', unhealthy > 0 || failed > 0 ? 'warning' : 'success');
                checkAllBtn.disabled = false;
                checkAllBtn.textContent = label;
            });
        });
    }

    function loadPending(row) {
        var cell = row.querySelector('.peer-pending');
        if (!cell || !row.dataset.hasStats) return;
        fetch(peerUrl(row.getAttribute('data-site-id'), 'sync-stats'))
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.error) {
                    cell.textContent = '—';
                    cell.setAttribute('data-ui-tip', data.error);
                    return;
                }
                var pending = Number(data.objects_pending) || 0;
                var failed = Number(data.objects_failed) || 0;
                cell.textContent = pending.toLocaleString() + (pending === 1 ? ' object' : ' objects');
                cell.classList.toggle('ui-muted', pending === 0);
                var lastSync = data.last_sync_at ? new Date(data.last_sync_at * 1000).toLocaleString() : 'never';
                cell.setAttribute('data-ui-tip',
                    (Number(data.objects_synced) || 0).toLocaleString() + ' synced, ' + failed.toLocaleString() + ' failed, last sync ' + lastSync);
                if (failed > 0) {
                    cell.classList.add('st-bad');
                    cell.textContent += ' · ' + failed.toLocaleString() + ' failed';
                }
            })
            .catch(function() {
                cell.textContent = '—';
            });
    }

    document.querySelectorAll('#peerTable tr[data-site-id]').forEach(function(row, index) {
        setTimeout(function() { loadPending(row); }, index * 150);
    });

    function openEditPeer(row, opener) {
        var siteId = row.getAttribute('data-site-id');
        byId('edit_site_id').value = siteId;
        byId('edit_endpoint').value = row.dataset.endpoint || '';
        byId('edit_region').value = row.dataset.region || '';
        byId('edit_priority').value = row.dataset.priority || '';
        byId('edit_display_name').value = row.dataset.displayName || '';
        byId('edit_connection_id').value = row.dataset.connectionId || '';
        byId('edit_peer_inbound_access_key').value = row.dataset.peerInboundAccessKey || '';
        byId('editPeerForm').action = peerUrl(siteId, 'update');
        window.UI.dialog.open('#editPeerDialog', opener);
    }

    function openDeletePeer(row, opener) {
        byId('deletePeerName').textContent = row.dataset.label || row.getAttribute('data-site-id');
        byId('deletePeerForm').action = peerUrl(row.getAttribute('data-site-id'), 'delete');
        window.UI.dialog.open('#deletePeerDialog', opener);
    }

    function note(kind, title, lines) {
        var box = el('div', 'adm-note' + (kind ? ' adm-note-' + kind : ''));
        if (title) box.appendChild(el('p', 'adm-note-strong', title));
        if (lines && lines.length) {
            var list = el('ul', 'st-issues');
            lines.forEach(function(line) {
                var item = el('li');
                item.appendChild(el('strong', '', line.code + ': '));
                item.appendChild(document.createTextNode(line.message));
                list.appendChild(item);
            });
            box.appendChild(list);
        }
        return box;
    }

    function fact(list, label, value, tone) {
        list.appendChild(el('dt', '', label));
        list.appendChild(el('dd', tone ? 'st-' + tone : '', value));
    }

    function factsCard(title) {
        var card = el('section', 'st-facts-card');
        card.appendChild(el('h3', 'adm-card-title', title));
        var list = el('dl', 'adm-facts');
        card.appendChild(list);
        return { card: card, list: list };
    }

    function renderBidirStatus(data, siteId, label) {
        var content = byId('bidirStatusContent');
        var wizardLink = byId('bidirWizardLink');
        content.replaceChildren();

        if (data.is_fully_configured) {
            var ok = note('ok', 'Two-way sync is fully configured');
            ok.appendChild(el('p', '', 'Both sites are set up to sync data in both directions.'));
            content.appendChild(ok);
        } else if (data.issues && data.issues.length > 0) {
            var errors = data.issues.filter(function(i) { return i.severity === 'error'; });
            var warnings = data.issues.filter(function(i) { return i.severity === 'warning'; });
            if (errors.length > 0) content.appendChild(note('bad', 'Configuration errors', errors));
            if (warnings.length > 0) content.appendChild(note('warn', 'Warnings', warnings));
        }

        var grid = el('div', 'adm-grid2 st-facts-grid');
        var local = factsCard('This site');
        fact(local.list, 'Site ID', data.local_site_id || 'Not configured', data.local_site_id ? '' : 'bad');
        fact(local.list, 'Endpoint', data.local_endpoint || 'Not configured', data.local_endpoint ? '' : 'bad');
        fact(local.list, 'Site sync worker', data.local_site_sync_enabled ? 'Enabled' : 'Disabled', data.local_site_sync_enabled ? 'ok' : 'warn');
        fact(local.list, 'Two-way rules', data.local_bidirectional_rules ? data.local_bidirectional_rules.length : 0);
        grid.appendChild(local.card);

        var remote = factsCard(label);
        var rs = data.remote_status;
        if (!rs) {
            remote.card.appendChild(el('p', 'ui-muted', 'Could not check remote status'));
        } else if (rs.admin_access_denied) {
            remote.card.appendChild(el('p', 'st-warn', 'Admin access denied - cannot verify remote configuration'));
        } else if (rs.reachable === false) {
            remote.card.appendChild(el('p', 'st-bad', 'Could not reach remote admin API'));
        } else {
            fact(remote.list, 'Has peer entry for us', rs.has_peer_for_us ? 'Yes' : 'No', rs.has_peer_for_us ? 'ok' : 'bad');
            fact(remote.list, 'Connection configured', rs.peer_connection_configured ? 'Yes' : 'No', rs.peer_connection_configured ? 'ok' : 'bad');
        }
        grid.appendChild(remote.card);
        content.appendChild(grid);

        if (data.local_bidirectional_rules && data.local_bidirectional_rules.length > 0) {
            var wrap = el('div', 'ui-table-wrap st-facts-card');
            var table = el('table', 'ui-table');
            var head = el('tr');
            ['Source bucket', 'Target bucket', 'Status'].forEach(function(title) {
                var th = el('th', '', title);
                th.scope = 'col';
                head.appendChild(th);
            });
            var thead = el('thead');
            thead.appendChild(head);
            table.appendChild(thead);
            var body = el('tbody');
            data.local_bidirectional_rules.forEach(function(rule) {
                var tr = el('tr');
                tr.appendChild(el('td', 'adm-wrap', rule.bucket_name));
                tr.appendChild(el('td', 'adm-wrap', rule.target_bucket));
                var status = el('td');
                status.appendChild(el('span', 'ui-badge' + (rule.enabled ? ' ui-badge-ok' : ''), rule.enabled ? 'Enabled' : 'Disabled'));
                tr.appendChild(status);
                body.appendChild(tr);
            });
            table.appendChild(body);
            wrap.appendChild(table);
            content.appendChild(wrap);
        }

        if (!data.is_fully_configured) {
            var fix = el('div', 'adm-note');
            fix.appendChild(el('p', 'adm-note-strong', 'How to fix'));
            var steps = el('ol');
            [
                'Ensure this site has a Site ID and Endpoint URL configured',
                'On the remote site, register this site as a peer with a connection',
                'Create two-way replication rules on both sites',
                'Enable SITE_SYNC_ENABLED=true on both sites'
            ].forEach(function(step) { steps.appendChild(el('li', '', step)); });
            fix.appendChild(steps);
            content.appendChild(fix);
            var blocking = ['NO_CONNECTION', 'CONNECTION_NOT_FOUND', 'REMOTE_UNREACHABLE', 'ENDPOINT_NOT_ALLOWED'];
            var blocked = data.issues && data.issues.some(function(i) { return blocking.indexOf(i.code) !== -1; });
            if (!blocked) {
                wizardLink.href = '/ui/replication/new?site_id=' + encodeURIComponent(siteId);
                wizardLink.hidden = false;
            }
        }
    }

    function openBidirStatus(row, opener) {
        var siteId = row.getAttribute('data-site-id');
        var label = row.dataset.label || siteId;
        var content = byId('bidirStatusContent');
        content.replaceChildren(el('p', 'ui-muted', 'Checking two-way configuration with ' + label + '…'));
        byId('bidirWizardLink').hidden = true;
        window.UI.dialog.open('#bidirStatusDialog', opener);

        fetch(peerUrl(siteId, 'bidirectional-status'))
            .then(function(response) { return response.json(); })
            .then(function(data) { renderBidirStatus(data, siteId, label); })
            .catch(function(err) {
                content.replaceChildren(note('bad', 'Failed to check two-way status. ' + (err.message || '')));
            });
    }

    var peerTable = byId('peerTable');
    if (peerTable) {
        peerTable.addEventListener('click', function(event) {
            var copy = event.target.closest('.btn-copy-endpoint');
            if (copy) {
                window.UICore.copyToClipboard(copy.getAttribute('data-url')).then(function(ok) {
                    if (ok) toast('Endpoint URL copied', 'Copied', 'success');
                });
                return;
            }
            var button = event.target.closest('[data-peer-action]');
            if (!button || button.disabled) return;
            var row = button.closest('tr[data-site-id]');
            if (!row) return;
            var opener = row.querySelector('[popovertarget]');
            var action = button.getAttribute('data-peer-action');
            if (action === 'health') checkOne(row.getAttribute('data-site-id'));
            else if (action === 'edit') openEditPeer(row, opener);
            else if (action === 'delete') openDeletePeer(row, opener);
            else if (action === 'bidir') openBidirStatus(row, opener);
        });
    }

    document.querySelectorAll('.btn-revoke-peer-cred').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var ak = btn.getAttribute('data-access-key') || '';
            byId('revokePeerCredAccessKey').textContent = ak;
            byId('revokePeerCredSiteId').textContent = btn.getAttribute('data-site-id') || '';
            byId('revokePeerCredForm').action = '/ui/peer-credentials/' + encodeURIComponent(ak) + '/delete';
            window.UI.dialog.open('#revokePeerCredDialog', btn);
        });
    });

    var issuedEl = byId('peer-cred-issued-data');
    if (issuedEl) {
        var issued = null;
        try {
            issued = JSON.parse(issuedEl.dataset.payload || '{}');
        } catch (e) {
            issued = null;
        }
        if (issued && issued.access_key) {
            byId('peerCredIssuedAccessKey').value = issued.access_key || '';
            byId('peerCredIssuedSecretKey').value = issued.secret_key || '';
            byId('peerCredIssuedSiteId').value = issued.site_id || '';
            window.UI.dialog.open('#peerCredIssuedDialog');
        }
    }

    document.querySelectorAll('.btn-copy-cred').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var input = byId(btn.getAttribute('data-copy-target'));
            if (!input) return;
            var label = btn.getAttribute('data-copy-label') || 'Value';
            window.UICore.copyToClipboard(input.value).then(function(ok) {
                if (ok) toast(label + ' copied', 'Copied', 'success');
            });
        });
    });

    function ajaxForm(id, successMessage, dialogSelector) {
        var form = byId(id);
        if (!form) return;
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            window.UICore.submitFormAjax(form, {
                successMessage: successMessage,
                onSuccess: function(data) {
                    if (dialogSelector) window.UI.dialog.close(dialogSelector);
                    if (data && data.redirect) setTimeout(function() { window.location.href = data.redirect; }, 800);
                    else reloadSoon();
                }
            });
        });
    }

    ajaxForm('localSiteForm', 'Local site configuration updated');
    ajaxForm('addPeerForm', 'Peer site added');
    ajaxForm('editPeerForm', 'Peer site updated', '#editPeerDialog');
    ajaxForm('deletePeerForm', 'Peer site deleted', '#deletePeerDialog');

    var addPeerCard = byId('addPeerCard');
    var addPeerForm = byId('addPeerForm');
    var lastStep = 3;
    var currentStep = 1;

    function stepPanel(step) {
        return addPeerForm.querySelector('[data-peer-step="' + step + '"]');
    }

    function stepIsValid(step) {
        var fields = stepPanel(step).querySelectorAll('input, select');
        for (var i = 0; i < fields.length; i++) {
            if (!fields[i].checkValidity()) {
                fields[i].reportValidity();
                return false;
            }
        }
        return true;
    }

    function fillReview() {
        var review = byId('addPeerReview');
        var connection = byId('peer_connection_id');
        review.replaceChildren();
        fact(review, 'Site ID', byId('peer_site_id').value);
        fact(review, 'Endpoint', byId('peer_endpoint').value);
        fact(review, 'Region', byId('peer_region').value || '—');
        fact(review, 'Priority', byId('peer_priority').value || '100');
        fact(review, 'Display name', byId('peer_display_name').value || '—');
        fact(review, 'Connection', connection.value ? connection.options[connection.selectedIndex].textContent : 'No connection', connection.value ? '' : 'warn');
        fact(review, 'Peer inbound access key', byId('peer_inbound_access_key').value || 'Not set (one-way only)');
    }

    function showStep(step) {
        currentStep = step;
        for (var i = 1; i <= lastStep; i++) {
            stepPanel(i).hidden = i !== step;
            var marker = addPeerForm.querySelector('[data-step-marker="' + i + '"]');
            marker.classList.toggle('is-on', i === step);
            marker.classList.toggle('is-done', i < step);
            if (i === step) marker.setAttribute('aria-current', 'step');
            else marker.removeAttribute('aria-current');
        }
        byId('addPeerBack').hidden = step === 1;
        byId('addPeerNext').hidden = step === lastStep;
        byId('addPeerSubmit').hidden = step !== lastStep;
        if (step === lastStep) fillReview();
    }

    function setPeerTest(tone, label, detail) {
        var badge = byId('peerTestResult');
        badge.className = 'ui-badge' + (tone ? ' ui-badge-' + tone : '');
        badge.textContent = label;
        if (detail) badge.setAttribute('data-ui-tip', detail);
        else badge.removeAttribute('data-ui-tip');
    }

    if (addPeerCard && addPeerForm) {
        byId('addPeerBtn').addEventListener('click', function() {
            addPeerCard.hidden = false;
            showStep(currentStep);
            addPeerCard.scrollIntoView({ block: 'start' });
            var first = stepPanel(currentStep).querySelector('input, select');
            if (first) first.focus({ preventScroll: true });
        });

        byId('addPeerCancel').addEventListener('click', function() {
            addPeerForm.reset();
            setPeerTest('', 'Not tested');
            showStep(1);
            addPeerCard.hidden = true;
            byId('addPeerBtn').focus();
        });

        byId('addPeerBack').addEventListener('click', function() {
            showStep(currentStep - 1);
        });

        byId('addPeerNext').addEventListener('click', function() {
            if (stepIsValid(currentStep)) showStep(currentStep + 1);
        });

        addPeerForm.addEventListener('keydown', function(event) {
            if (event.key !== 'Enter' || currentStep === lastStep) return;
            if (event.target instanceof HTMLInputElement) {
                event.preventDefault();
                byId('addPeerNext').click();
            }
        });

        byId('peer_connection_id').addEventListener('change', function() {
            setPeerTest('', 'Not tested');
        });

        byId('peerTestBtn').addEventListener('click', function() {
            var connectionId = byId('peer_connection_id').value;
            if (!connectionId) {
                setPeerTest('warn', 'Choose a connection');
                return;
            }
            var started = Date.now();
            setPeerTest('', 'Testing…');
            fetch('/ui/connections/' + encodeURIComponent(connectionId) + '/health')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    if (data.healthy) setPeerTest('ok', 'Reachable in ' + (Date.now() - started) + ' ms');
                    else setPeerTest('bad', 'Unreachable', data.error || '');
                })
                .catch(function() {
                    setPeerTest('warn', 'Test failed', 'Could not run the test');
                });
        });
    }

    function fmtRel(ts) {
        var diff = Math.max(0, Math.floor(Date.now() / 1000 - ts));
        if (diff < 60) return diff + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
    }

    function refreshRelativeTimes() {
        document.querySelectorAll('[data-last-sync-at]').forEach(function(node) {
            var ts = parseFloat(node.getAttribute('data-last-sync-at'));
            var span = node.querySelector('.last-sync-rel');
            if (span && !isNaN(ts)) span.textContent = fmtRel(ts);
        });
        var stamp = byId('peersCheckedAt');
        if (stamp && stamp.dataset.checkedAt) {
            stamp.textContent = 'Checked ' + formatTimeAgo(new Date(Number(stamp.dataset.checkedAt)));
        }
    }

    refreshRelativeTimes();
    setInterval(refreshRelativeTimes, 30000);
})();
