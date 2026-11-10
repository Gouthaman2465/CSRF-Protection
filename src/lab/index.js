// INTENTIONALLY VULNERABLE. For learning only. Never use in a real app.

const { createOffProtection } = require('./off');
const { createWeakTokenProtection } = require('./weakToken');
const { createWeakRefererProtection } = require('./weakReferer');
const { createCsrfProtection } = require('../csrf/index');

/**
 * Factory selecting the active CSRF protection implementation according to configuration.
 *
 * @param {object} config System configuration object
 * @param {Function} getSessionId Function returning the current session ID
 * @returns {{ middleware: Function, issueToken: Function }}
 */
function getProtectionByMode(config, getSessionId) {
  const mode = config.mode || 'secure';

  const cookieOptions = {
    sameSite: config.sameSite || 'none',
    secure: config.sameSite === 'none' || process.env.NODE_ENV === 'production',
  };

  switch (mode) {
    case 'off':
      return createOffProtection();

    case 'weak-token':
      return createWeakTokenProtection({
        cookieOptions,
      });

    case 'weak-referer':
      return createWeakRefererProtection({
        allowedOrigins: config.allowedOrigins,
      });

    case 'secure':
    default:
      return createCsrfProtection({
        secret: config.secret,
        getSessionId,
        ttlMs: config.tokenTtlMs,
        allowedOrigins: config.allowedOrigins,
        cookieOptions,
        enableTokenCheck: config.enableTokenCheck,
        enableOriginCheck: config.enableOriginCheck,
      });
  }
}

module.exports = {
  getProtectionByMode,
};
