# CSRF Protection: Test Run and Guided Demo Manual

This document provides a complete, repeatable guide for running both the automated test suites and the interactive manual attack demonstrations from scratch.

---

## 1. Prerequisites

Before beginning, ensure your environment meets the following requirements:
- **Node.js**: Version `>=18.0.0` (Verify with `node -v`).
- **npm**: Version `>=9.0.0` (Verify with `npm -v`).
- **Operating System**: Linux, macOS, or Windows (WSL recommended on Windows).
- **Network Ports**: Ports `5001` (victim) and `7000` (attacker) must be available on the loopback interface (`127.0.0.1`).

---

## 2. One-Time Setup Commands

Run the following commands in the project root directory:

```bash
# Step 1: Install production and development dependencies
npm install

# Step 2: Initialize environment file (.env) with a random 64-char CSRF_SECRET
npm run setup

# Step 3: Install the Playwright Chromium browser binary
npm run browsers
```

---

## 3. Automated Test Suite Execution

### 1. Run Unit and Integration Tests (Jest)
Executes all unit tests (`tests/unit/`) and API integration tests (`tests/integration/`):

```bash
npm test
```

**Expected Output:**
```text
PASS tests/integration/normalFlow.test.js
PASS tests/integration/secureModeBlocks.test.js
PASS tests/integration/independentLayers.test.js
PASS tests/integration/weakModes.test.js
PASS tests/integration/securityProperties.test.js
PASS tests/unit/token.test.js
PASS tests/unit/config.test.js
PASS tests/unit/originCheck.test.js
PASS tests/unit/fetchMetadata.test.js
PASS tests/unit/methods.test.js

Test Suites: 10 passed, 10 total
Tests:       60 passed, 60 total
Snapshots:   0 total
Time:        ~7.5s
```

### 2. Run End-to-End Browser Tests (Playwright)
Executes all 21 browser automation tests against real Chromium instances, verifying the 16-cell attack matrix, legitimate UI workflows, and the SameSite defense layer:

```bash
npm run test:e2e
```

**Expected Output:**
```text
Running 21 tests using 1 worker
  ✓ Matrix [Mode: off] Attack: change-email -> SUCCEEDS (✓)
  ✓ Matrix [Mode: off] Attack: transfer -> SUCCEEDS (✓)
  ...
  ✓ Matrix [Mode: secure] Attack: change-email -> BLOCKED (✗)
  ...
  ✓ Legitimate user workflow in "secure" mode
  ✓ Mode "off" with SESSION_SAMESITE=lax blocks basic cross-site form submission
21 passed (~15s)
```

### 3. Run Everything Together
Executes both Jest and Playwright in succession:

```bash
npm run test:all
```

**Artifacts Location:**
- Browser screenshots: `docs/screenshots/<mode>__<attack>.png`
- Playwright HTML reports (if enabled): `playwright-report/`

---

## 4. Manual Guided Walkthrough (Mode-by-Mode)

Follow these guided steps to observe how CSRF attacks execute and how each defense behaves.
For these interactive walkthroughs, use a standard browser (e.g. Chrome, Firefox, Edge).

---

### Phase 1: Mode `off` (Zero Protection)

1. **Start the Lab**:
   ```bash
   npm run lab:off
   ```
2. **Victim Login**:
   - Open browser and navigate to: `http://localhost:5001/login.html`
   - Observe top banner: `Protection Mode: OFF | Cookie SameSite: NONE`
   - Sign in with:
     - Username: `alice`
     - Password: `alice-password`
   - You will be redirected to `http://localhost:5001/dashboard.html`.
   - Note Alice's starting state:
     - **Email**: `alice@example.com`
     - **Balance**: `$1000`
3. **Execute Attack (Change-Email)**:
   - In the same browser, open a new tab and go to: `http://127.0.0.1:7000/attack-change-email.html`
   - The form submits immediately to `http://localhost:5001/api/change-email`.
   - **What you see**: A page displaying green text: `"Done - Email changed to hacked@evil.test"`.
4. **Verify Impact**:
   - Click "Back to Dashboard" or reload `http://localhost:5001/dashboard.html`.
   - Notice that Alice's email has been compromised to `hacked@evil.test` without her consent.
5. **Execute Attack (Transfer)**:
   - In the attacker tab, go to: `http://127.0.0.1:7000/attack-transfer.html`
   - **What you see**: `"Done - Transferred 500 to mallory"`.
   - Return to the dashboard: Alice's balance dropped from `$1000` to `$500`.
6. **Stop Server**: Press `Ctrl+C` in your terminal.

---

### Phase 2: Mode `weak-referer` (Bypass Demo 2)

1. **Start the Lab**:
   ```bash
   npm run lab:weak-referer
   ```
2. **Victim Login**:
   - Navigate to `http://localhost:5001/login.html`.
   - Log in as `alice` / `alice-password`.
3. **Attempt Basic Attack (Blocked)**:
   - Open `http://127.0.0.1:7000/attack-change-email.html`.
   - **What you see**: Red error page: `"Blocked by CSRF protection: ORIGIN_MISMATCH"`.
   - **Why**: The browser sent `Referer: http://127.0.0.1:7000/attack-change-email.html`. Because the server checks `Referer`, it blocked the request!
4. **Execute Bypass Attack (Stripped Referer)**:
   - Now open: `http://127.0.0.1:7000/attack-no-referrer.html`.
   - **What you see**: Green page: `"Done - Email changed to hacked@evil.test"`.
   - **Why the bypass works**: The page includes `<meta name="referrer" content="no-referrer">`. The browser stripped the `Referer` header entirely. The server's naive code only checked the header *if present*, so when missing, it allowed the request!
5. **Stop Server**: Press `Ctrl+C`.

---

### Phase 3: Mode `weak-token` (Bypass Demo 1)

1. **Start the Lab**:
   ```bash
   npm run lab:weak-token
   ```
2. **Victim Login**:
   - Navigate to `http://localhost:5001/login.html`.
   - Log in as `alice` / `alice-password`.
3. **Attempt Basic Attack (Blocked)**:
   - Open `http://127.0.0.1:7000/attack-change-email.html`.
   - **What you see**: Red error page: `"Blocked by CSRF protection: CSRF_TOKEN_MISSING"`.
   - **Why**: The basic attack form has no token, so it gets blocked.
4. **Execute Bypass Attack (Unbound Attacker Token)**:
   - Now open: `http://127.0.0.1:7000/attack-unbound-token.html`.
   - **What you see**: Green page: `"Done - Email changed to hacked@evil.test"`.
   - **Why the bypass works**: The attacker server logged into its own account (`mallory`), received a valid CSRF token registered in the server's global set, and embedded it in a hidden `_csrf` input. When Alice's browser submitted the form, the server saw that the token existed in its database, but never checked if the token belonged to Alice!
5. **Stop Server**: Press `Ctrl+C`.

---

### Phase 4: Mode `secure` (Full Defense in Depth)

1. **Start the Lab**:
   ```bash
   npm run lab:secure
   ```
2. **Victim Login**:
   - Navigate to `http://localhost:5001/login.html`.
   - Log in as `alice` / `alice-password`.
   - Note banner: `Protection Mode: SECURE | Cookie SameSite: NONE`.
3. **Test Legitimate User Operations**:
   - On the dashboard, enter a new email `alice-secure@example.com` and click "Update Email".
   - It succeeds immediately and updates the dashboard.
   - Enter recipient `mallory` and amount `100` and click "Send Transfer".
   - It succeeds, updating the balance to `$900`.
4. **Attempt All Attack Vectors**:
   - Open `http://127.0.0.1:7000/attack-change-email.html` -> **Blocked** (`FETCH_METADATA_CROSS_SITE`).
   - Open `http://127.0.0.1:7000/attack-transfer.html` -> **Blocked** (`FETCH_METADATA_CROSS_SITE`).
   - Open `http://127.0.0.1:7000/attack-unbound-token.html` -> **Blocked** (`FETCH_METADATA_CROSS_SITE` / `CSRF_TOKEN_NOT_BOUND_TO_SESSION`).
   - Open `http://127.0.0.1:7000/attack-no-referrer.html` -> **Blocked** (`FETCH_METADATA_CROSS_SITE` / `ORIGIN_MISSING`).
5. **Result**: Every attack is blocked, while legitimate actions proceed smoothly.
6. **Stop Server**: Press `Ctrl+C`.

---

## 5. Troubleshooting Guide

| Problem | Root Cause | Solution |
|---|---|---|
| `EADDRINUSE: address already in use 127.0.0.1:5001` or `:7000` | A background Node.js process is already listening on the port. | Terminate the process: `lsof -ti :5001,7000 \| xargs kill -9`. |
| Browser says `ERR_UNSAFE_PORT` for the attacker site | Chrome, Edge and Firefox refuse some ports, including 6000 to 6063 (reserved for X11). | The lab uses port `7000` for this reason. If you change `ATTACKER_PORT`, do not pick a blocked port. |
| `EADDRINUSE` on port `7000` (macOS) | On macOS 12 and later, the AirPlay Receiver service listens on port 7000. | Turn off AirPlay Receiver in System Settings, or set `ATTACKER_PORT=7100` in `.env`. |
| `localhost:5001` does not connect (IPv4 vs IPv6) | Node.js v18+ resolves `localhost` to `::1` (IPv6) by default on some Linux distributions, but servers bound to `127.0.0.1` listen on IPv4. | The project explicitly binds servers to `127.0.0.1` and uses `http://localhost:5001` for the victim origin. Happy Eyeballs in modern Chromium automatically connects to IPv4 loopback. |
| Cookies not persisting over plain HTTP | The `Secure` cookie flag is set while navigating over non-HTTPS plain HTTP. | `src/auth/sessions.js` and `src/csrf/index.js` only set `secure: true` when `SameSite=none` or `NODE_ENV=production`. Modern Chromium allows `Secure` cookies over `http://localhost` per W3C secure contexts spec. |
| In-memory state desynchronized | Changes from previous tests persisted in memory. | State is held entirely in memory. Simply restart the server process to reset all seed accounts (`alice`, `mallory`) and clear all active sessions. |
