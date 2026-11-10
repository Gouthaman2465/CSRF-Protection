const { loadConfig, warnIfInsecureSameSite } = require('./config');
const { createApp } = require('./app');

const config = loadConfig();
warnIfInsecureSameSite(config);

const app = createApp(config);
const HOST = '127.0.0.1'; // Listen strictly on loopback interface

const server = app.listen(config.victimPort, HOST, () => {
  console.log(`Victim application running at http://localhost:${config.victimPort}`);
  console.log(`Protection mode: ${config.mode}`);
  console.log(`Session SameSite: ${config.sameSite}`);
});

module.exports = server;
