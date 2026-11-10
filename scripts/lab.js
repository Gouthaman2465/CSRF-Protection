const { loadConfig, warnIfInsecureSameSite } = require('../src/config');
const { createApp } = require('../src/app');
const { createAttackerApp } = require('../attacker/server');

// Parse --mode=<mode> argument from CLI
let modeArg = null;
for (const arg of process.argv.slice(2)) {
  if (arg.startsWith('--mode=')) {
    modeArg = arg.split('=')[1];
  }
}

if (modeArg) {
  process.env.PROTECTION_MODE = modeArg;
}

const config = loadConfig();
warnIfInsecureSameSite(config);

const victimApp = createApp(config);
const attackerApp = createAttackerApp({
  victimUrl: `http://localhost:${config.victimPort}`,
});

const HOST = '127.0.0.1'; // Listen strictly on loopback interface

const victimServer = victimApp.listen(config.victimPort, HOST, () => {
  const attackerServer = attackerApp.listen(config.attackerPort, HOST, () => {
    console.log('======================================================================');
    console.log('               CSRF PROTECTION INTERACTIVE LAB RUNNING                 ');
    console.log('======================================================================');
    console.log(`Active Protection Mode : ${config.mode.toUpperCase()}`);
    console.log(`Session Cookie SameSite: ${config.sameSite.toUpperCase()}`);
    console.log(`Victim Portal URL      : http://localhost:${config.victimPort}`);
    console.log(`Attacker Portal URL    : http://127.0.0.1:${config.attackerPort}`);
    console.log('----------------------------------------------------------------------');
    console.log('DEMO ACCOUNTS (Seed Data):');
    console.log('  Victim  : alice   / alice-password   (Balance: $1000)');
    console.log('  Attacker: mallory / mallory-password (Balance: $0)');
    console.log('----------------------------------------------------------------------');
    console.log('Press Ctrl+C to terminate the lab servers.');
    console.log('======================================================================\n');
  });

  const cleanup = () => {
    console.log('\nShutting down lab servers...');
    victimServer.close();
    attackerServer.close();
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
});
