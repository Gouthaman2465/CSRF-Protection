const dotenv = require('dotenv');

// Load environment variables from .env if present
dotenv.config();

/**
 * Validates and normalizes configuration options.
 * Crashes (throws) with clear messages on invalid configuration.
 *
 * @param {Record<string, any>} [customEnv] Optional environment dictionary for testing
 * @returns {Record<string, any>} Normalized configuration object
 */
function loadConfig(customEnv) {
  const env = customEnv || process.env;

  const validModes = ['off', 'weak-token', 'weak-referer', 'secure'];
  const mode = (env.PROTECTION_MODE || 'secure').toLowerCase();
  if (!validModes.includes(mode)) {
    throw new Error(
      `Invalid PROTECTION_MODE "${mode}". Allowed modes: ${validModes.join(', ')}`
    );
  }

  const parseBool = (val, defaultVal) => {
    if (val === undefined || val === null || val === '') return defaultVal;
    if (typeof val === 'boolean') return val;
    return val.toString().toLowerCase() === 'true';
  };

  const enableTokenCheck = parseBool(env.ENABLE_TOKEN_CHECK, true);
  const enableOriginCheck = parseBool(env.ENABLE_ORIGIN_CHECK, true);

  const secret = env.CSRF_SECRET || '';
  if (mode === 'secure' && enableTokenCheck) {
    if (!secret || secret.length < 32) {
      throw new Error(
        'CSRF_SECRET is required and must be at least 32 characters long when running in secure mode with token checks enabled.'
      );
    }
  }

  const parsePort = (val, defaultPort, name) => {
    if (!val) return defaultPort;
    const num = parseInt(val, 10);
    if (isNaN(num) || num < 1 || num > 65535) {
      throw new Error(`Invalid ${name}: "${val}". Must be an integer between 1 and 65535.`);
    }
    return num;
  };

  const victimPort = parsePort(env.VICTIM_PORT, 5001, 'VICTIM_PORT');
  const attackerPort = parsePort(env.ATTACKER_PORT, 7000, 'ATTACKER_PORT');

  const rawOrigins = env.ALLOWED_ORIGINS || 'http://localhost:5001';
  const allowedOrigins = rawOrigins
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  if (allowedOrigins.length === 0) {
    throw new Error('ALLOWED_ORIGINS must contain at least one valid origin.');
  }

  const validSameSite = ['none', 'lax', 'strict'];
  const sameSite = (env.SESSION_SAMESITE || 'none').toLowerCase();
  if (!validSameSite.includes(sameSite)) {
    throw new Error(
      `Invalid SESSION_SAMESITE "${sameSite}". Allowed values: ${validSameSite.join(', ')}`
    );
  }

  const tokenTtlMinutes = parseFloat(env.TOKEN_TTL_MINUTES || '60');
  if (isNaN(tokenTtlMinutes) || tokenTtlMinutes <= 0) {
    throw new Error('TOKEN_TTL_MINUTES must be a positive number.');
  }

  const config = {
    mode,
    secret,
    victimPort,
    attackerPort,
    allowedOrigins,
    sameSite,
    tokenTtlMinutes,
    tokenTtlMs: tokenTtlMinutes * 60 * 1000,
    enableTokenCheck,
    enableOriginCheck,
  };

  return config;
}

// Print warning about SameSite=none if running in a process context
function warnIfInsecureSameSite(config) {
  if (config.sameSite === 'none') {
    console.warn('\n============================================================');
    console.warn('[SECURITY WARNING] SESSION_SAMESITE is set to "none".');
    console.warn('This setting allows cross-site requests to include credentials.');
    console.warn('This is intended ONLY for testing CSRF attacks in the lab.');
    console.warn('In production applications, always use "lax" or "strict".');
    console.warn('============================================================\n');
  }
}

module.exports = {
  loadConfig,
  warnIfInsecureSameSite,
};
