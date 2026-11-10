// INTENTIONALLY VULNERABLE. For learning only. Never use in a real app.

/**
 * Attacker client helper.
 * Simulates the attacker (Mallory) legitimately interacting with the victim server
 * to obtain a valid CSRF token registered in the server's state.
 *
 * It sends proper same-origin headers and maintains an isolated cookie jar,
 * behaving exactly like a real user browsing http://localhost:5001.
 */
class AttackerClient {
  constructor(victimBaseUrl = 'http://localhost:5001') {
    this.victimBaseUrl = victimBaseUrl;
    this.cookieJar = new Map();
  }

  // Update in-memory cookie jar from Set-Cookie headers
  _updateCookies(res) {
    const rawHeaders = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const header of rawHeaders) {
      const parts = header.split(';')[0].split('=');
      if (parts.length >= 2) {
        this.cookieJar.set(parts[0].trim(), parts.slice(1).join('=').trim());
      }
    }
  }

  // Format cookie jar into standard Cookie request header
  _getCookieHeader() {
    return Array.from(this.cookieJar.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  /**
   * Log in as Mallory on the victim app and obtain a valid CSRF token.
   *
   * @returns {Promise<{ token: string|null, cookies: string }>}
   */
  async acquireMalloryToken() {
    const origin = this.victimBaseUrl;

    // Step 1: Request pre-login anonymous token
    const preTokenRes = await fetch(`${this.victimBaseUrl}/api/csrf-token`, {
      method: 'GET',
      headers: {
        Origin: origin,
        'Sec-Fetch-Site': 'same-origin',
        Referer: `${this.victimBaseUrl}/login.html`,
      },
    });
    this._updateCookies(preTokenRes);
    const preTokenData = await preTokenRes.json().catch(() => ({}));
    const preToken = preTokenData.token || null;

    // Step 2: Log in as Mallory
    const loginHeaders = {
      'Content-Type': 'application/json',
      Origin: origin,
      'Sec-Fetch-Site': 'same-origin',
      Referer: `${this.victimBaseUrl}/login.html`,
      Cookie: this._getCookieHeader(),
    };
    if (preToken) {
      loginHeaders['x-csrf-token'] = preToken;
    }

    const loginRes = await fetch(`${this.victimBaseUrl}/api/login`, {
      method: 'POST',
      headers: loginHeaders,
      body: JSON.stringify({
        username: 'mallory',
        password: 'mallory-password',
      }),
    });
    this._updateCookies(loginRes);

    // Step 3: Request post-login token bound to Mallory's active session
    const postTokenRes = await fetch(`${this.victimBaseUrl}/api/csrf-token`, {
      method: 'GET',
      headers: {
        Origin: origin,
        'Sec-Fetch-Site': 'same-origin',
        Referer: `${this.victimBaseUrl}/dashboard.html`,
        Cookie: this._getCookieHeader(),
      },
    });
    this._updateCookies(postTokenRes);
    const postTokenData = await postTokenRes.json().catch(() => ({}));
    const malloryToken = postTokenData.token || null;

    return {
      token: malloryToken,
      cookies: this._getCookieHeader(),
    };
  }
}

module.exports = {
  AttackerClient,
};
