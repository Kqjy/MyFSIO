(function() {
  var layout = document.getElementById('docsLayout');
  var body = document.getElementById('docsBody');
  var toc = document.getElementById('docsToc');
  var search = document.getElementById('docsSearch');
  var status = document.getElementById('docsSearchStatus');
  var toggle = document.getElementById('docsIndexToggle');
  var pager = document.getElementById('docsPager');
  var prev = document.getElementById('docsPrev');
  var next = document.getElementById('docsNext');
  if (!layout || !body || !toc || !search) return;

  var sections = [];
  toc.querySelectorAll('a[href^="#"]').forEach(function(link) {
    var article = document.getElementById(link.getAttribute('href').slice(1));
    if (!article) return;
    var count = document.createElement('span');
    count.className = 'docs-toc-count';
    count.hidden = true;
    link.appendChild(count);
    sections.push({
      id: article.id,
      article: article,
      link: link,
      item: link.parentNode,
      count: count,
      title: link.firstChild.textContent,
      text: article.textContent.toLowerCase()
    });
  });
  if (!sections.length) return;

  var current = null;
  var visible = sections.slice();

  function sectionFor(hash) {
    var id = decodeURIComponent((hash || '').replace(/^#/, ''));
    if (!id) return null;
    var target = document.getElementById(id);
    if (!target) return null;
    for (var i = 0; i < sections.length; i++) {
      if (sections[i].article.contains(target)) return { section: sections[i], target: target };
    }
    return null;
  }

  function setPagerLink(link, section, label) {
    link.hidden = !section;
    if (!section) return;
    link.setAttribute('href', '#' + section.id);
    link.textContent = label + section.title;
  }

  function show(section, target) {
    current = section;
    sections.forEach(function(entry) {
      var active = entry === section;
      entry.article.classList.toggle('is-active', active);
      if (active) entry.link.setAttribute('aria-current', 'true');
      else entry.link.removeAttribute('aria-current');
    });
    var index = sections.indexOf(section);
    setPagerLink(prev, sections[index - 1], '← ');
    setPagerLink(next, sections[index + 1], '→ ');
    pager.hidden = false;
    setIndexOpen(false);
    if (target && target !== section.article) target.scrollIntoView({ block: 'start' });
    else window.scrollTo(0, 0);
    var scroller = document.querySelector('.app-main');
    if (scroller && (!target || target === section.article)) scroller.scrollTop = 0;
  }

  function countMatches(text, term) {
    var total = 0;
    var at = text.indexOf(term);
    while (at !== -1) {
      total++;
      at = text.indexOf(term, at + term.length);
    }
    return total;
  }

  function applySearch() {
    var terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
    visible = [];
    sections.forEach(function(entry) {
      var hits = 0;
      var matched = terms.every(function(term) {
        var found = countMatches(entry.text, term);
        hits += found;
        return found > 0;
      });
      entry.item.hidden = !matched;
      entry.count.hidden = !terms.length || !matched;
      entry.count.textContent = hits;
      if (matched) visible.push(entry);
    });
    if (terms.length) {
      visible.sort(function(a, b) { return Number(b.count.textContent) - Number(a.count.textContent); });
      visible.forEach(function(entry) { toc.appendChild(entry.item); });
      setIndexOpen(true);
    } else {
      sections.forEach(function(entry) { toc.appendChild(entry.item); });
    }
    status.hidden = !terms.length;
    status.textContent = visible.length
      ? visible.length + (visible.length === 1 ? ' section matches' : ' sections match') + ' — Enter opens the best one'
      : 'No section mentions “' + search.value.trim() + '”';
  }

  function setIndexOpen(open) {
    layout.classList.toggle('is-index-open', open);
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function route() {
    var found = sectionFor(window.location.hash);
    if (found) show(found.section, found.target);
    else show(sections[0], null);
  }

  layout.classList.add('docs-split');
  toggle.addEventListener('click', function() {
    setIndexOpen(!layout.classList.contains('is-index-open'));
  });
  search.addEventListener('input', applySearch);
  search.addEventListener('keydown', function(event) {
    if (event.key === 'Enter' && visible.length) {
      event.preventDefault();
      window.location.hash = visible[0].id;
    } else if (event.key === 'Escape' && search.value) {
      search.value = '';
      applySearch();
    }
  });
  toc.addEventListener('click', function(event) {
    var link = event.target.closest('a');
    if (link && current && link.getAttribute('href') === '#' + current.id) setIndexOpen(false);
  });
  document.addEventListener('keydown', function(event) {
    if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
    var tag = event.target.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || event.target.isContentEditable) return;
    event.preventDefault();
    search.focus();
  });
  window.addEventListener('hashchange', route);
  route();
})();
