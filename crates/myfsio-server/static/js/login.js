(function () {
  const secret = document.getElementById('loginSecretKey');
  const reveal = document.getElementById('loginReveal');
  if (!secret || !reveal) return;
  reveal.hidden = false;
  reveal.addEventListener('click', () => {
    const show = secret.type === 'password';
    secret.type = show ? 'text' : 'password';
    reveal.textContent = show ? 'Hide' : 'Show';
    reveal.setAttribute('aria-pressed', show ? 'true' : 'false');
    secret.focus();
  });
  secret.form?.addEventListener('submit', () => {
    secret.type = 'password';
  });
})();
