window.myfsioCsrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
window.getCsrfToken = () => window.myfsioCsrfToken;
(function () {
  const originalFetch = window.fetch;
  let sessionRedirecting = false;
  window.fetch = function (input, init) {
    init = init || {};
    const method = (init.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const headers = new Headers(init.headers || {});
      if (window.myfsioCsrfToken) {
        headers.set('X-CSRFToken', window.myfsioCsrfToken);
      }
      init.headers = headers;
    }
    return originalFetch.call(this, input, init).then(async response => {
      let sameOrigin = false;
      try {
        const requestUrl = input instanceof Request ? input.url : String(input);
        sameOrigin = new URL(requestUrl, window.location.href).origin === window.location.origin;
      } catch (error) {}
      if (!sameOrigin || sessionRedirecting) {
        return response;
      }
      let expired = response.status === 401;
      if (!expired && (response.headers.get('content-type') || '').includes('application/json')) {
        try {
          const data = await response.clone().json();
          expired = data && data.error === 'Your session is no longer valid.';
        } catch (error) {}
      }
      if (expired && window.location.pathname !== '/login') {
        sessionRedirecting = true;
        const next = window.location.pathname + window.location.search;
        window.location.assign('/login?next=' + encodeURIComponent(next));
      }
      return response;
    });
  };
})();

