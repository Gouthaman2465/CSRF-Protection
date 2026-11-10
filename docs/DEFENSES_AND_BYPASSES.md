# Defensive Layers, Attack Bypasses, and Architectural Design

This document details the mechanics of each defensive layer, examines the root causes of the bypass demonstrations, documents all key design decisions, and compares the solution with industry-standard libraries.

---

## 1. Analysis of Defensive Layers

### Layer 1: Session-Bound Cryptographic Double-Submit Token
- **What it stops**: Classic cross-site form submissions, cross-site fetch mutations, token-planting attacks, cookie-tossing from sibling subdomains, and replay attacks with expired tokens.
- **What it does not stop**: Cross-Site Scripting (XSS). If an attacker achieves JavaScript execution on the victim origin, they can read the token or DOM and include it in forged requests.
- **Performance / Architectural Cost**: Minimal CPU overhead (one HMAC-SHA256 calculation per state-changing request). Zero database or server-side session lookups required for token validation.

### Layer 2: Strict Origin & Referer Allowlist
- **What it stops**: Requests arriving from unauthorized third-party origins (`Origin: http://127.0.0.1:7000`, `Origin: null`, or untrusted `Referer` headers).
- **What it does not stop**: Attacks originating from within the same origin, requests where both headers are absent (unless explicitly blocked), or network-layer proxies that rewrite headers.
- **Performance / Architectural Cost**: Near-zero CPU cost (simple string lookup in an in-memory Set/Array).

### Layer 3: W3C Fetch Metadata (`Sec-Fetch-Site`)
- **What it stops**: Any cross-site navigation or fetch request before parsing headers or cookies (`cross-site`, `same-site`, `none`).
- **What it does not stop**: Legacy browsers that do not support W3C Fetch Metadata (e.g. Internet Explorer, very old mobile browsers).
- **Performance / Architectural Cost**: Single string check (`normalized === 'same-origin'`). Extremely high performance.

### Layer 4: Cookie `SameSite` Attribute (`Lax` / `Strict`)
- **What it stops**: Ambient transmission of session cookies on cross-site requests. For `SameSite=Strict`, all cross-site requests omit cookies. For `SameSite=Lax`, cross-site POST form submissions omit cookies.
- **What it does not stop**:
  1. Older browsers that do not support SameSite.
  2. Same-site subdomains (e.g., `attacker.example.com` to `victim.example.com`).
  3. State-changing `GET` requests (which still send `SameSite=Lax` cookies upon top-level navigation).
  4. The 2-minute "Lax+POST" exception in certain Chromium builds for cookies lacking an explicit SameSite value.
- **Performance / Architectural Cost**: Completely free; enforced natively by the browser.

---

## 2. Deep Dive: The Two Attack Bypasses

### Bypass Demo 1: Unbound Token Bypass (`weak-token` Mode)

#### How the Attack Works
1. Mallory opens an automated client (`attackerClient.js`) that legitimately connects to `http://localhost:5001`.
2. Mallory signs into her own attacker account (`mallory` / `mallory-password`) and requests a token via `GET /api/csrf-token`.
3. The server issues token $T_M$ and stores it in a global set (`issuedTokens.add(token)`).
4. Mallory embeds $T_M$ into an attack webpage:
   ```html
   <form action="http://localhost:5001/api/change-email" method="POST">
     <input type="hidden" name="email" value="hacked@evil.test">
     <input type="hidden" name="_csrf" value="<T_M>">
   </form>
   ```
5. Alice (the victim), who is authenticated with session $S_A$, visits Mallory's webpage.
6. Alice's browser auto-submits the form. The browser attaches Alice's session cookie `sid=S_A`, while the form body supplies Mallory's token $T_M$.

#### Why the Weak Version Fails
The server middleware inspects `req.body._csrf` and checks `issuedTokens.has(token)`. Because $T_M$ is in the set, the server approves the request. It fails to verify that $T_M$ belongs to Alice!

#### Why `secure` Mode Blocks It
In `secure` mode, the token is structurally bound to the session ID:
$$\text{HMAC}(\text{secret}, S_A \parallel \text{"\|"} \parallel \text{salt} \parallel \text{"\|"} \parallel \text{expiry})$$
When Alice's browser submits $T_M$, the server computes the expected HMAC using Alice's active session ID ($S_A$). Because $T_M$ was generated for Mallory ($S_M$), the hashes do not match. The server immediately terminates the request with `CSRF_TOKEN_NOT_BOUND_TO_SESSION`.

---

### Bypass Demo 2: Stripped Referer Bypass (`weak-referer` Mode)

#### How the Attack Works
1. Mallory creates an attack form targeting `http://localhost:5001/api/change-email`.
2. Mallory adds a standard HTML referrer policy directive in the `<head>` of her page:
   ```html
   <meta name="referrer" content="no-referrer">
   ```
3. When Alice visits the page, the form submits to the victim application.
4. Per the W3C Referrer Policy specification, Alice's browser completely omits the `Referer` request header.

#### Why the Weak Version Fails
The naive middleware contains the following flaw:
```javascript
if (req.headers.referer) {
  // Check origin...
}
// If referer is missing, execution falls through and succeeds!
next();
```
Because the attacker suppressed the header, the validation check was skipped entirely.

#### Why `secure` Mode Blocks It
The `secure` origin layer implements a strict combination rule:
1. It inspects `Sec-Fetch-Site` first (which reports `cross-site` and blocks).
2. It requires `Origin` or `Referer` to be present and match an allowed origin.
3. If both `Origin` and `Referer` are missing, the request is unconditionally rejected with `ORIGIN_MISSING`.

---

## 3. Design Decisions and Rationale

### 1. Why HMAC over `sessionId | random | expiry`?
Binding the HMAC to `sessionId` ensures that tokens cannot be shared across sessions or users. Adding a random 16-byte salt ensures that consecutive tokens generated for the same session remain cryptographically unique (preventing token reuse across distinct API calls if desired). Adding `expiry` ensures that old tokens automatically expire without requiring server-side state or revocation lists.

### 2. Why Signed Double-Submit Cookie?
Standard stateless double-submit cookies (comparing header token directly to cookie token) are vulnerable to **cookie tossing**: if an attacker can set a cookie on `.example.com` or an insecure sibling subdomain, they can overwrite the victim's cookie with an arbitrary value and supply the matching header value.
By signing the cookie with a server secret and binding it to the session ID, an attacker cannot forge valid cookie-token pairs.

### 3. Why Token Reuse?
In modern Single-Page Applications (SPAs), web pages dispatch multiple concurrent background `fetch` requests upon loading. If a server issues a brand-new token on every GET request, concurrent requests race to update cookies, invalidating tokens and breaking the user experience. By reusing valid tokens that have more than 20% of their TTL remaining, the application remains fast, stable, and race-condition free.

### 4. Why an Allowlist of Safe Methods?
Denylisting methods (e.g. checking only `POST`, `PUT`, `DELETE`) is an anti-pattern. Developers frequently introduce `PATCH`, `CONNECT`, or custom HTTP verbs that slip past denylists. An allowlist (`GET`, `HEAD`, `OPTIONS`) guarantees that any request capable of mutating server state undergoes mandatory security verification.

### 5. Why Keep `express.urlencoded` Parser Enabled?
In standard browser environments, cross-site HTML forms can only transmit data formatted as `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. Cross-site JSON requests trigger a mandatory browser CORS preflight (`OPTIONS`) request. Keeping the urlencoded parser active is essential for demonstrating the vulnerability of classic HTML form-based CSRF.

### 6. Why Dual-Layer (Origin AND Token)?
Origin validation (Fetch Metadata and Origin header) is extremely fast and natively enforced by modern browsers. However, legacy HTTP clients, non-standard agents, and webview environments may omit or spoof headers. Session-bound cryptographic tokens provide robust application-level validation. Operating both layers together provides true defense in depth.

### 7. Why Protect `/api/login` (Login CSRF)?
In a Login CSRF attack, Mallory tricks Alice's browser into authenticating with *Mallory's* credentials. Alice subsequently conducts sensitive operations (e.g., adding credit cards, searching personal medical data) inside an account controlled by Mallory. Protecting `/api/login` ensures authentication requests cannot be forged from external origins.

### 8. Why Session Regeneration on Login?
Regenerating the session ID upon authentication stops **session fixation** attacks and automatically breaks any CSRF tokens that were issued to an anonymous user prior to logging in.

### 9. Why a Tiny Custom Session Store in the Lab?
Standard libraries like `express-session` refuse to set `Secure` cookies over plain HTTP connections by default, which complicates local loopback demonstrations. A transparent ~50-line in-memory session store provides total visibility into cookie attributes without third-party magic.

### 10. Why `SESSION_SAMESITE=none` by Default in the Lab?
Modern browsers default cookies to `SameSite=Lax`, which silently suppresses cross-site POST form submissions and masks the underlying vulnerabilities. Setting `SameSite=none` in the lab strips away this ambient browser guardrail, allowing students and interviewers to observe raw CSRF attacks and analyze the behavior of server-side defense layers directly.

---

## 4. Industry Library Comparison & Deprecation Notes

### Why `csurf` is Deprecated
For many years, `csurf` was the standard CSRF middleware for Express. However, it was deprecated by the Express security team due to several critical architectural limitations:
1. **Cookie-Tossing Vulnerability**: Its double-submit cookie implementation did not bind tokens to sessions, leaving applications vulnerable to cookie-tossing attacks from sibling subdomains.
2. **Hidden Session Dependencies**: It frequently caused unhandled crashes if session middleware or body parsers were misordered.
3. **No Modern Browser Integration**: It lacked support for W3C Fetch Metadata (`Sec-Fetch-Site`) and modern SameSite paradigms.

### Comparison with `csrf-csrf`
The modern community replacement is `csrf-csrf`. Like our custom middleware, `csrf-csrf` uses a signed double-submit cookie pattern. However, our handcrafted implementation offers distinct advantages for educational and AppSec interview purposes:
- **Zero Black-Box Abstractions**: Every step of token signing, constant-time comparison, and header validation is plainly visible in concise, readable code.
- **Granular Error Codes**: Provides precise reason codes (`FETCH_METADATA_CROSS_SITE`, `ORIGIN_MISMATCH`, `CSRF_TOKEN_NOT_BOUND_TO_SESSION`) that simplify debugging and security telemetry.
- **Dual-Layer Orchestration**: Tightly integrates modern W3C Fetch Metadata alongside cryptographic token checks.
