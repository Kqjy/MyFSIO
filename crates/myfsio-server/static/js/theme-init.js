(function () {
  let theme = 'light';
  try {
    theme = localStorage.getItem('myfsio-theme') === 'dark' ? 'dark' : 'light';
  } catch (err) {}
  document.documentElement.dataset.bsTheme = theme;
  document.documentElement.dataset.theme = theme;
})();

