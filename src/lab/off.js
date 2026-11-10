// INTENTIONALLY VULNERABLE. For learning only. Never use in a real app.

/**
 * Completely unshielded mode with no CSRF defense.
 * Any cross-site request will succeed.
 */
function createOffProtection() {
  function middleware(req, res, next) {
    next();
  }

  function issueToken() {
    return null;
  }

  return {
    middleware,
    issueToken,
  };
}

module.exports = {
  createOffProtection,
};
