(function() {
  var nav = document.getElementById('appNav');
  if (!nav || typeof HTMLDialogElement === 'undefined') return;

  var bucketTabs = ['properties', 'permissions', 'replication', 'lifecycle', 'cors'];
  var dialog = document.createElement('dialog');
  dialog.className = 'cmdk';
  dialog.setAttribute('aria-label', 'Command palette');
  dialog.innerHTML =
    '<input class="cmdk-input" type="search" autocomplete="off" spellcheck="false" placeholder="Jump to a bucket, page or setting" aria-label="Search" aria-controls="cmdkList">' +
    '<ul class="cmdk-list" id="cmdkList" role="listbox"></ul>' +
    '<div class="cmdk-foot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div>';
  document.body.appendChild(dialog);
  var input = dialog.querySelector('.cmdk-input');
  var list = dialog.querySelector('.cmdk-list');
  var pages = [];
  var buckets = null;
  var matches = [];
  var active = 0;

  nav.querySelectorAll('a.app-nav-link').forEach(function(link) {
    pages.push({ kind: 'Page', label: link.textContent.trim(), href: link.getAttribute('href') });
  });

  function loadBuckets() {
    if (buckets) return;
    buckets = [];
    var bucketsLink = nav.querySelector('a.app-nav-link');
    if (!bucketsLink) return;
    var base = bucketsLink.getAttribute('href').replace(/\/$/, '');
    fetch(base, { credentials: 'same-origin', headers: { Accept: 'text/html' } })
      .then(function(response) { return response.ok ? response.text() : ''; })
      .then(function(html) {
        var seen = Object.create(null);
        var parsed = new DOMParser().parseFromString(html, 'text/html');
        parsed.querySelectorAll('a[href^="' + base + '/"], [data-href^="' + base + '/"]').forEach(function(link) {
          var path = (link.getAttribute('href') || link.getAttribute('data-href')).split('?')[0];
          var name = decodeURIComponent(path.slice(base.length + 1));
          if (!name || name.indexOf('/') !== -1 || seen[name]) return;
          seen[name] = true;
          buckets.push({ kind: 'Bucket', label: name, href: path });
          bucketTabs.forEach(function(tab) {
            buckets.push({ kind: 'Setting', label: name + ' › ' + (tab === 'cors' ? 'CORS' : tab.charAt(0).toUpperCase() + tab.slice(1)), href: path + '?tab=' + tab, secondary: true });
          });
        });
        if (dialog.open) render();
      })
      .catch(function() {});
  }

  function score(item, terms) {
    var text = item.label.toLowerCase();
    var total = 0;
    for (var i = 0; i < terms.length; i++) {
      var at = text.indexOf(terms[i]);
      if (at === -1) return -1;
      total += at === 0 ? 0 : 1 + at / 100;
    }
    return total + (item.secondary ? 5 : 0);
  }

  function render() {
    var terms = input.value.toLowerCase().split(/\s+/).filter(Boolean);
    var items = pages.concat(buckets || []);
    if (!terms.length) {
      matches = items.filter(function(item) { return !item.secondary; });
    } else {
      matches = items.map(function(item) { return { item: item, score: score(item, terms) }; })
        .filter(function(entry) { return entry.score >= 0; })
        .sort(function(a, b) { return a.score - b.score; })
        .map(function(entry) { return entry.item; });
    }
    matches = matches.slice(0, 40);
    active = Math.min(active, Math.max(0, matches.length - 1));
    list.innerHTML = '';
    if (!matches.length) {
      var empty = document.createElement('li');
      empty.className = 'cmdk-empty';
      empty.textContent = 'Nothing matches “' + input.value + '”';
      list.appendChild(empty);
      return;
    }
    matches.forEach(function(item, index) {
      var row = document.createElement('li');
      row.className = 'cmdk-item';
      row.setAttribute('role', 'option');
      row.setAttribute('aria-selected', index === active ? 'true' : 'false');
      var label = document.createElement('span');
      label.className = 'cmdk-label';
      label.textContent = item.label;
      var kind = document.createElement('span');
      kind.className = 'cmdk-kind';
      kind.textContent = item.kind;
      row.appendChild(label);
      row.appendChild(kind);
      row.addEventListener('click', function() { window.location.href = item.href; });
      row.addEventListener('pointermove', function() {
        if (active !== index) {
          active = index;
          highlight();
        }
      });
      list.appendChild(row);
    });
  }

  function highlight() {
    list.querySelectorAll('.cmdk-item').forEach(function(row, index) {
      row.setAttribute('aria-selected', index === active ? 'true' : 'false');
      if (index === active) row.scrollIntoView({ block: 'nearest' });
    });
  }

  function open() {
    if (dialog.open) return;
    input.value = '';
    active = 0;
    loadBuckets();
    render();
    dialog.showModal();
    input.focus();
  }

  input.addEventListener('input', function() {
    active = 0;
    render();
  });

  input.addEventListener('keydown', function(event) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (!matches.length) return;
      active = (active + (event.key === 'ArrowDown' ? 1 : matches.length - 1)) % matches.length;
      highlight();
    } else if (event.key === 'Enter') {
      event.preventDefault();
      if (matches[active]) window.location.href = matches[active].href;
    }
  });

  dialog.addEventListener('click', function(event) {
    if (event.target === dialog) dialog.close();
  });

  document.addEventListener('keydown', function(event) {
    if ((event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      if (dialog.open) dialog.close();
      else open();
    }
  });

  document.querySelectorAll('[data-command-palette-open]').forEach(function(button) {
    button.addEventListener('click', open);
  });
})();
