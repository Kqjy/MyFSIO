(function () {
    var fmtBytes = window.MyFSIO.formatBytes;
    function fmtCount(value) {
        var n = Number(value);
        return isFinite(n) ? n.toLocaleString() : String(value == null ? 0 : value);
    }
    function fmtRel(ts) {
        var diff = Math.max(0, Math.floor(Date.now() / 1000 - ts));
        if (diff < 60) return diff + "s ago";
        if (diff < 3600) return Math.floor(diff / 60) + "m ago";
        if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
        return Math.floor(diff / 86400) + "d ago";
    }
    function pctColor(p) {
        if (p >= 80) return "bg-danger";
        if (p >= 60) return "bg-warning";
        return "bg-success";
    }
    function applyBytesFormat(root) {
        (root || document).querySelectorAll("[data-bytes]").forEach(function (el) {
            var n = parseInt(el.getAttribute("data-bytes"), 10);
            if (!isNaN(n)) el.textContent = fmtBytes(n);
        });
    }
    function applyDiskBars(root) {
        (root || document).querySelectorAll(".site-disk-bar").forEach(function (bar) {
            var total = parseFloat(bar.getAttribute("data-total")) || 0;
            var avail = parseFloat(bar.getAttribute("data-available")) || 0;
            var used = Math.max(0, total - avail);
            var pct = total > 0 ? (used / total) * 100 : 0;
            bar.style.width = pct.toFixed(1) + "%";
            bar.classList.remove("bg-success", "bg-warning", "bg-danger", "bg-primary");
            bar.classList.add(pctColor(pct));
            var card = bar.closest(".site-card");
            if (card) {
                var usedEl = card.querySelector(".site-disk-used");
                if (usedEl) {
                    usedEl.setAttribute("data-bytes", String(Math.floor(used)));
                    usedEl.textContent = fmtBytes(used);
                }
            }
        });
    }
    function applyPctBars(root) {
        var pairs = [
            [".site-cpu-bar", ".site-cpu-label"],
            [".site-mem-bar", ".site-mem-label"],
            [".site-diskpct-bar", ".site-diskpct-label"],
        ];
        pairs.forEach(function (sel) {
            (root || document).querySelectorAll(sel[0]).forEach(function (bar) {
                var label = bar.closest(".site-card").querySelector(sel[1]);
                var pct = parseFloat(label ? label.textContent : "0") || 0;
                bar.classList.remove("bg-success", "bg-warning", "bg-danger");
                bar.classList.add(pctColor(pct));
            });
        });
    }
    function refreshRel() {
        document.querySelectorAll("[data-last-sync-at]").forEach(function (el) {
            var ts = parseFloat(el.getAttribute("data-last-sync-at"));
            var span = el.querySelector(".last-sync-rel");
            if (span && !isNaN(ts)) span.textContent = fmtRel(ts);
        });
    }

    function updateCard(card, site) {
        if (!card) return;
        var online = !!site.online;
        var stale = !!site.stale;

        function toggle(sel, show) {
            var el = card.querySelector(sel);
            if (el) el.classList.toggle("d-none", !show);
        }
        toggle(".site-status-online", online);
        toggle(".site-status-offline", !online);
        toggle(".site-status-stale", stale);
        toggle(".site-online-content", online);
        toggle(".site-offline-content", !online);

        toggle(".site-capacity-block", !!site.capacity);
        toggle(".site-system-block", !!(site.system && site.system.cpu_percent != null));
        toggle(".site-sync-block", !!site.sync);

        if (online) {
            var setNum = function (sel, val) {
                var el = card.querySelector(sel);
                if (el) el.textContent = fmtCount(val == null ? 0 : val);
            };
            setNum(".site-buckets", site.buckets);
            setNum(".site-objects", site.objects);
            var sizeEl = card.querySelector(".site-size");
            if (sizeEl) {
                sizeEl.setAttribute("data-bytes", String(site.size_bytes || 0));
                sizeEl.textContent = fmtBytes(site.size_bytes || 0);
            }
            var capacity = site.capacity || {};
            var diskBar = card.querySelector(".site-disk-bar");
            if (diskBar) {
                diskBar.setAttribute("data-total", String(capacity.total_bytes || 0));
                diskBar.setAttribute("data-available", String(capacity.available_bytes || 0));
            }
            var diskTotalEl = card.querySelector(".site-disk-total");
            if (diskTotalEl) {
                diskTotalEl.setAttribute("data-bytes", String(capacity.total_bytes || 0));
                diskTotalEl.textContent = fmtBytes(capacity.total_bytes || 0);
            }
            var sys = site.system || {};
            var setPct = function (labelSel, val) {
                var label = card.querySelector(labelSel);
                if (label) label.textContent = (val == null ? 0 : val) + "%";
            };
            setPct(".site-cpu-label", sys.cpu_percent);
            setPct(".site-mem-label", sys.memory_percent);
            setPct(".site-diskpct-label", sys.disk_percent);
            var setBarPct = function (sel, val) {
                var bar = card.querySelector(sel);
                if (bar) bar.style.width = (val == null ? 0 : val) + "%";
            };
            setBarPct(".site-cpu-bar", sys.cpu_percent);
            setBarPct(".site-mem-bar", sys.memory_percent);
            setBarPct(".site-diskpct-bar", sys.disk_percent);

            var sync = site.sync || {};
            var syncLabel = card.querySelector(".site-sync-label");
            if (syncLabel) {
                var lastSyncTs = Number(sync.last_sync_at);
                if (isFinite(lastSyncTs) && lastSyncTs > 0) {
                    syncLabel.innerHTML = '<span data-last-sync-at="' + lastSyncTs + '">last sync <span class="last-sync-rel">' + fmtRel(lastSyncTs) + '</span></span>';
                } else {
                    syncLabel.innerHTML = '<span class="text-muted">no sync yet</span>';
                }
            }
            var errBadge = card.querySelector(".site-sync-errors");
            var errCount = sync.errors || 0;
            if (errBadge) {
                errBadge.classList.toggle("d-none", errCount === 0);
                var c = errBadge.querySelector(".site-sync-errors-count");
                if (c) c.textContent = errCount;
            }
        } else {
            renderPeerError(card, site);
        }
        card.classList.toggle("is-offline", !online);
    }

    var ERROR_TONES = {
        not_configured: "tone-secondary",
        unauthorized: "tone-warning",
        http: "tone-warning",
    };

    function renderPeerError(card, site) {
        var info = site.error_info || {};
        var setText = function (sel, text) {
            var el = card.querySelector(sel);
            if (el) el.textContent = text;
        };
        var setShown = function (sel, shown) {
            var el = card.querySelector(sel);
            if (el) el.classList.toggle("d-none", !shown);
        };
        setText(".peer-error-title", info.title || "Peer unreachable");
        setText(".peer-error-summary", info.summary || site.error || "The peer could not be reached.");

        var status = info.status;
        setShown(".peer-error-status", !!status);
        if (status) setText(".peer-error-status", "HTTP " + status);

        var source = info.source || "";
        setShown(".peer-error-source", !!source);
        if (source) setText(".peer-error-source", "via " + source);

        var hint = info.hint || "";
        setShown(".peer-error-hint", !!hint);
        if (hint) setText(".peer-error-hint-text", hint);

        var detail = info.detail || "";
        setShown(".peer-error-details", !!detail);
        if (detail) setText(".peer-error-detail-text", detail);

        var icon = card.querySelector(".peer-error-icon");
        if (icon) {
            icon.classList.remove("tone-secondary", "tone-warning", "tone-danger");
            icon.classList.add(ERROR_TONES[info.kind] || "tone-danger");
        }
    }

    function setOnlineBadge(online, total) {
        var badge = document.getElementById("cluster-online-badge");
        if (!badge) return;
        badge.textContent = online + " / " + total + " online";
        badge.classList.remove(
            "bg-success", "text-success", "bg-warning", "text-warning", "bg-danger", "text-danger"
        );
        var tone = online === total ? "success" : (online === 0 ? "danger" : "warning");
        badge.classList.add("bg-" + tone, "text-" + tone);
    }

    var pageReloading = false;
    var pollFailures = 0;
    var MAX_POLL_FAILURES = 5;

    function poll(force) {
        var url = "/ui/cluster/data" + (force ? "?force=1" : "");
        var icon = document.getElementById("cluster-refresh-icon");
        var btn = document.getElementById("cluster-refresh-btn");
        if (force && icon) icon.classList.add("spin");
        if (force && btn) btn.disabled = true;
        return fetch(url, { credentials: "same-origin", cache: "no-store" })
            .then(function (r) {
                if (!r.ok) { pollFailures++; return null; }
                pollFailures = 0;
                return r.json();
            })
            .then(function (data) {
                if (!data) return;
                var totals = data.totals || {};
                var setTotal = function (id, v) {
                    var el = document.getElementById(id);
                    if (el) el.textContent = fmtCount(v == null ? 0 : v);
                };
                setTotal("cluster-total-sites", totals.total_count);
                setTotal("cluster-total-buckets", totals.buckets);
                setTotal("cluster-total-objects", totals.objects);
                var sizeEl = document.getElementById("cluster-total-size");
                if (sizeEl) {
                    sizeEl.setAttribute("data-bytes", String(totals.size_bytes || 0));
                    sizeEl.textContent = fmtBytes(totals.size_bytes || 0);
                }
                setOnlineBadge(totals.online_count || 0, totals.total_count || 0);

                var sawNewSite = false;
                (data.sites || []).forEach(function (site) {
                    var card = document.querySelector('.site-card[data-site-id="' + CSS.escape(String(site.site_id)) + '"]');
                    if (card) updateCard(card, site);
                    else sawNewSite = true;
                });
                if (sawNewSite && !pageReloading) {
                    pageReloading = true;
                    location.reload();
                    return;
                }

                applyDiskBars();
                applyPctBars();
                var stamp = document.getElementById("cluster-updated-at");
                if (stamp) stamp.textContent = "updated " + new Date().toLocaleTimeString();
            })
            .catch(function () { pollFailures++; })
            .finally(function () {
                if (icon) icon.classList.remove("spin");
                if (btn) btn.disabled = false;
            });
    }

    applyBytesFormat();
    applyDiskBars();
    applyPctBars();
    refreshRel();
    setInterval(refreshRel, 5000);

    var degradedTicks = 0;
    function pollTick() {
        if (pageReloading) return;
        if (pollFailures >= MAX_POLL_FAILURES) {
            degradedTicks++;
            if (degradedTicks % 6 !== 0) return;
        } else {
            degradedTicks = 0;
        }
        poll(false);
    }
    document.addEventListener("DOMContentLoaded", function () {
        if (window.UICore && window.UICore.pollingManager) {
            window.UICore.pollingManager.start("cluster-overview", pollTick, 10000);
        } else {
            setInterval(function () { if (!document.hidden) pollTick(); }, 10000);
        }
    });

    var refreshBtn = document.getElementById("cluster-refresh-btn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function () { poll(true); });
    }

    document.addEventListener("click", function (event) {
        var btn = event.target.closest ? event.target.closest(".site-retry-btn") : null;
        if (!btn) return;
        btn.disabled = true;
        poll(true).finally(function () { btn.disabled = false; });
    });
})();
