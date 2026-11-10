// NOTE: This is a tiny in-memory session store built specifically for this
// educational lab. In production, use a hardened store such as Redis or Postgres.
const crypto = require('crypto');

const IDLE_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const sessions = new Map();

function createSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Create a new session with initial data.
 */
function createSession(data = {}) {
  const id = createSessionId();
  const session = {
    id,
    data: { ...data },
    createdAt: Date.now(),
    lastAccess: Date.now(),
  };
  sessions.set(id, session);
  return session;
}

/**
 * Retrieve session by ID. Discards sessions that exceeded idle timeout.
 */
function getSession(id) {
  if (!id || !sessions.has(id)) return null;
  const session = sessions.get(id);
  if (Date.now() - session.lastAccess > IDLE_TIMEOUT_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastAccess = Date.now();
  return session;
}

/**
 * Destroy a session.
 */
function destroySession(id) {
  if (id) sessions.delete(id);
}

/**
 * Regenerate session ID (stops session fixation and breaks old CSRF tokens).
 */
function regenerateSession(oldId, newData = null) {
  const oldSession = oldId ? sessions.get(oldId) : null;
  const data = newData || (oldSession ? oldSession.data : {});
  if (oldId) sessions.delete(oldId);
  return createSession(data);
}

/**
 * Clear all sessions (used for clean test runs).
 */
function resetSessions() {
  sessions.clear();
}

/**
 * Set session cookie on response with correct flags.
 */
function setSessionCookie(res, sessionId, config) {
  const secure = config.sameSite === 'none' || process.env.NODE_ENV === 'production';
  res.cookie('sid', sessionId, {
    httpOnly: true,
    path: '/',
    sameSite: config.sameSite,
    secure,
  });
}

/**
 * Clear session cookie on response.
 */
function clearSessionCookie(res, config) {
  const secure = config.sameSite === 'none' || process.env.NODE_ENV === 'production';
  res.clearCookie('sid', {
    path: '/',
    sameSite: config.sameSite,
    secure,
  });
}

module.exports = {
  createSession,
  getSession,
  destroySession,
  regenerateSession,
  resetSessions,
  setSessionCookie,
  clearSessionCookie,
};
