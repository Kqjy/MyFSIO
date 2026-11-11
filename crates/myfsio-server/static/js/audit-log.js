(function() {
  var table = document.getElementById('auditTable');
  var search = document.getElementById('auditSearch');
  var direction = document.getElementById('auditDirection');
  var result = document.getElementById('auditResult');
  var count = document.getElementById('auditCount');
  var noMatch = document.getElementById('auditNoMatch');
  if (!table || !search) return;

  var rows = Array.prototype.map.call(table.querySelectorAll('tr[data-audit-row]'), function(row) {
    return { row: row, text: row.textContent.toLowerCase() };
  });

  function readParams() {
    var params = new URLSearchParams(window.location.search);
    search.value = params.get('q') || '';
    direction.value = params.get('direction') || '';
    result.value = params.get('result') || '';
  }

  function writeParams() {
    var params = new URLSearchParams();
    if (search.value.trim()) params.set('q', search.value.trim());
    if (direction.value) params.set('direction', direction.value);
    if (result.value) params.set('result', result.value);
    var query = params.toString();
    window.history.replaceState(null, '', window.location.pathname + (query ? '?' + query : ''));
  }

  function apply() {
    var terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
    var shown = 0;
    rows.forEach(function(entry) {
      var visible = (!direction.value || entry.row.getAttribute('data-direction') === direction.value) &&
        (!result.value || entry.row.getAttribute('data-result') === result.value) &&
        terms.every(function(term) { return entry.text.indexOf(term) !== -1; });
      entry.row.hidden = !visible;
      if (visible) shown++;
    });
    if (noMatch) noMatch.hidden = shown > 0 || rows.length === 0;
    count.textContent = shown === rows.length
      ? rows.length + (rows.length === 1 ? ' entry' : ' entries')
      : shown + ' of ' + rows.length + ' entries';
  }

  function changed() {
    writeParams();
    apply();
  }

  readParams();
  apply();
  search.addEventListener('input', changed);
  direction.addEventListener('change', changed);
  result.addEventListener('change', changed);
})();
