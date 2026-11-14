(function () {
  const storageKey = 'myfsio-theme';
  const toggle = document.getElementById('themeToggle');

  const applyTheme = (theme) => {
    document.documentElement.dataset.bsTheme = theme;
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(storageKey, theme);
    } catch (err) {}
    if (toggle) {
      const label = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
      toggle.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
      toggle.setAttribute('aria-label', label);
      toggle.setAttribute('data-ui-tip', label);
    }
  };

  applyTheme(document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light');
  toggle?.addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    window.UI.tooltip.hide();
  });
})();

(function () {
  const nav = document.getElementById('appNav');
  const scrim = document.getElementById('appScrim');
  if (!nav || !scrim) return;
  const openers = [document.getElementById('appMenuBtn'), document.getElementById('appTabMore')].filter(Boolean);
  let lastOpener = null;

  const background = Array.from(document.querySelectorAll('.app-main, .app-tabbar'));
  const focusableSelector = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  const isOpen = () => nav.classList.contains('is-open');
  const focusableItems = () => Array.from(nav.querySelectorAll(focusableSelector)).filter(el => el.getClientRects().length > 0);

  const setOpen = (open) => {
    nav.classList.toggle('is-open', open);
    scrim.classList.toggle('is-open', open);
    document.documentElement.classList.toggle('app-nav-locked', open);
    background.forEach(el => { el.inert = open; });
    openers.forEach(btn => btn.setAttribute('aria-expanded', open ? 'true' : 'false'));
    if (open) {
      nav.querySelector('[aria-current="page"], .app-nav-link')?.focus();
    } else if (lastOpener) {
      lastOpener.focus();
      lastOpener = null;
    }
  };

  openers.forEach(btn => btn.addEventListener('click', () => {
    lastOpener = btn;
    setOpen(!isOpen());
  }));
  scrim.addEventListener('click', () => setOpen(false));
  document.getElementById('appNavClose')?.addEventListener('click', (event) => {
    event.preventDefault();
    setOpen(false);
  });
  document.addEventListener('keydown', (event) => {
    if (!isOpen()) return;
    if (event.key === 'Escape') {
      setOpen(false);
      return;
    }
    if (event.key !== 'Tab') return;
    const items = focusableItems();
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (!nav.contains(active)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && active === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  });
  window.matchMedia('(min-width: 992px)').addEventListener('change', (event) => {
    if (event.matches && isOpen()) setOpen(false);
  });
  window.addEventListener('pageshow', (event) => {
    if (event.persisted && isOpen()) setOpen(false);
  });
})();

(function () {
  const island = document.getElementById('flashedMessages');
  if (!island) return;
  let messages = [];
  try {
    messages = JSON.parse(island.textContent || '[]');
  } catch (err) {}
  messages.forEach((flash) => {
    const type = flash.category === 'danger' ? 'error' : flash.category;
    window.showToast(flash.message, type === 'error' ? 'Error' : 'Notification', type);
  });
})();
