let cachedToken = null;

/**
 * Display a feedback message inside a target container.
 *
 * @param {HTMLElement} element
 * @param {string} text
 * @param {'success'|'error'} type
 */
function showMessage(element, text, type) {
  if (!element) return;
  element.textContent = text;
  element.className = `message show ${type}`;
}

/**
 * Fetch and update the configuration banner showing active mode and SameSite.
 */
async function loadModeBanner() {
  const banner = document.getElementById('mode-banner');
  if (!banner) return;

  try {
    const res = await fetch('/api/mode');
    const data = await res.json();
    banner.textContent = `Protection Mode: ${data.mode.toUpperCase()} | Cookie SameSite: ${data.sameSite.toUpperCase()}`;
    if (data.mode === 'secure') {
      banner.className = 'banner secure';
    } else if (data.mode === 'off') {
      banner.className = 'banner off';
    } else {
      banner.className = 'banner';
    }
  } catch {
    banner.textContent = 'Server configuration unavailable';
  }
}

/**
 * Retrieve a CSRF token from the server.
 * Never stores or returns the string "null".
 *
 * @returns {Promise<string|null>}
 */
async function fetchCsrfToken() {
  try {
    const res = await fetch('/api/csrf-token', { credentials: 'include' });
    if (!res.ok) return null;
    const data = await res.json();
    if (data && typeof data.token === 'string' && data.token !== 'null' && data.token.length > 0) {
      cachedToken = data.token;
      return cachedToken;
    }
    cachedToken = null;
    return null;
  } catch {
    cachedToken = null;
    return null;
  }
}

/**
 * Wrapper around fetch that automatically attaches the CSRF token header
 * and retries once if the token expired.
 *
 * @param {string} url
 * @param {RequestInit} [options={}]
 * @param {boolean} [isRetry=false]
 * @returns {Promise<{ res: Response, data: any }>}
 */
async function apiRequest(url, options = {}, isRetry = false) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  // For state-changing methods, attach token if available (never send string "null")
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    if (cachedToken && cachedToken !== 'null') {
      headers['x-csrf-token'] = cachedToken;
    }
  }

  const res = await fetch(url, {
    ...options,
    headers,
    credentials: 'include',
  });

  let data = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  }

  // Automatic retry on expired token
  if (res.status === 403 && data && data.code === 'CSRF_TOKEN_EXPIRED' && !isRetry) {
    console.warn('CSRF token expired. Fetching fresh token and retrying...');
    await fetchCsrfToken();
    return apiRequest(url, options, true);
  }

  return { res, data };
}

// Initialize application on DOM ready
document.addEventListener('DOMContentLoaded', async () => {
  await loadModeBanner();
  await fetchCsrfToken();

  // ----------------------------------------------------
  // LOGIN PAGE LOGIC
  // ----------------------------------------------------
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    const loginMessage = document.getElementById('login-message');

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;

      try {
        const { res, data } = await apiRequest('/api/login', {
          method: 'POST',
          body: JSON.stringify({ username, password }),
        });

        if (res.ok) {
          // Fetch fresh post-login token bound to regenerated session
          await fetchCsrfToken();
          window.location.href = '/dashboard.html';
        } else {
          showMessage(
            loginMessage,
            (data && (data.error || data.code)) || 'Authentication failed',
            'error'
          );
        }
      } catch (err) {
        showMessage(loginMessage, 'Network error during login', 'error');
      }
    });
  }

  // ----------------------------------------------------
  // DASHBOARD PAGE LOGIC
  // ----------------------------------------------------
  const userNameElem = document.getElementById('user-name');
  if (userNameElem) {
    const userEmailElem = document.getElementById('user-email');
    const userBalanceElem = document.getElementById('user-balance');
    const emailForm = document.getElementById('email-form');
    const emailMessage = document.getElementById('email-message');
    const transferForm = document.getElementById('transfer-form');
    const transferMessage = document.getElementById('transfer-message');
    const logoutBtn = document.getElementById('logout-btn');

    async function loadUserProfile() {
      try {
        const { res, data } = await apiRequest('/api/me');
        if (!res.ok) {
          window.location.href = '/login.html';
          return;
        }
        userNameElem.textContent = data.username;
        userEmailElem.textContent = data.email;
        userBalanceElem.textContent = `$${data.balance}`;
      } catch {
        window.location.href = '/login.html';
      }
    }

    await loadUserProfile();

    // Handle change-email
    if (emailForm) {
      emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('new-email').value.trim();
        try {
          const { res, data } = await apiRequest('/api/change-email', {
            method: 'POST',
            body: JSON.stringify({ email }),
          });

          if (res.ok) {
            showMessage(emailMessage, 'Email updated successfully!', 'success');
            userEmailElem.textContent = email;
            document.getElementById('new-email').value = '';
          } else {
            showMessage(
              emailMessage,
              (data && (data.error ? `${data.error} (${data.code || ''})` : data.code)) ||
                'Failed to update email',
              'error'
            );
          }
        } catch {
          showMessage(emailMessage, 'Network error while updating email', 'error');
        }
      });
    }

    // Handle transfer
    if (transferForm) {
      transferForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const to = document.getElementById('transfer-to').value.trim();
        const amount = parseFloat(document.getElementById('transfer-amount').value);

        try {
          const { res, data } = await apiRequest('/api/transfer', {
            method: 'POST',
            body: JSON.stringify({ to, amount }),
          });

          if (res.ok) {
            showMessage(
              transferMessage,
              `Successfully transferred $${amount} to ${to}`,
              'success'
            );
            userBalanceElem.textContent = `$${data.balance}`;
            document.getElementById('transfer-amount').value = '';
          } else {
            showMessage(
              transferMessage,
              (data && (data.error ? `${data.error} (${data.code || ''})` : data.code)) ||
                'Transfer failed',
              'error'
            );
          }
        } catch {
          showMessage(transferMessage, 'Network error while initiating transfer', 'error');
        }
      });
    }

    // Handle logout
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async () => {
        await apiRequest('/api/logout', { method: 'POST' });
        cachedToken = null;
        window.location.href = '/login.html';
      });
    }
  }
});
