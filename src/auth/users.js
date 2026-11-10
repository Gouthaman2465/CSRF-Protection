const crypto = require('crypto');

/**
 * Hash a plaintext password with scrypt and a unique salt.
 *
 * @param {string} password Plaintext password
 * @param {string} [salt] Hex-encoded salt
 * @returns {{ salt: string, hash: string }} Salt and derived key in hex
 */
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derivedKey = crypto.scryptSync(password, salt, 64);
  return {
    salt,
    hash: derivedKey.toString('hex'),
  };
}

/**
 * Verify a password against stored salt and hash using timingSafeEqual.
 *
 * @param {string} password Plaintext password to check
 * @param {{ salt: string, hash: string }} user User record containing salt and hash
 * @returns {boolean} True if password matches
 */
function verifyPassword(password, user) {
  if (!user || !user.salt || !user.hash) return false;
  const derivedKey = crypto.scryptSync(password, user.salt, 64);
  const storedBuffer = Buffer.from(user.hash, 'hex');
  if (derivedKey.length !== storedBuffer.length) return false;
  return crypto.timingSafeEqual(derivedKey, storedBuffer);
}

// In-memory user database
let users = {};

/**
 * Reset users to initial seed state.
 */
function resetUsers() {
  const aliceCreds = hashPassword('alice-password');
  const malloryCreds = hashPassword('mallory-password');

  users = {
    alice: {
      username: 'alice',
      salt: aliceCreds.salt,
      hash: aliceCreds.hash,
      email: 'alice@example.com',
      balance: 1000,
    },
    mallory: {
      username: 'mallory',
      salt: malloryCreds.salt,
      hash: malloryCreds.hash,
      email: 'mallory@example.com',
      balance: 0,
    },
  };
}

// Initialize seed data
resetUsers();

/**
 * Find user by username.
 *
 * @param {string} username
 * @returns {object|undefined}
 */
function findUser(username) {
  return users[username];
}

/**
 * Clean user input to prevent log forging (removes \r and \n control characters).
 *
 * @param {any} input
 * @returns {string} Sanitized string
 */
function cleanForLogs(input) {
  if (typeof input !== 'string') return String(input || '');
  return input.replace(/[\r\n\x00-\x1f\x7f]/g, '');
}

/**
 * Validate username format: string, 1 to 32 chars, [a-zA-Z0-9_]
 *
 * @param {any} username
 * @returns {boolean}
 */
function isValidUsername(username) {
  if (typeof username !== 'string') return false;
  return /^[a-zA-Z0-9_]{1,32}$/.test(username);
}

/**
 * Validate email format: string, max 254 chars, simple valid email regex
 *
 * @param {any} email
 * @returns {boolean}
 */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  if (email.length > 254 || email.length < 3) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

module.exports = {
  findUser,
  verifyPassword,
  hashPassword,
  resetUsers,
  cleanForLogs,
  isValidUsername,
  isValidEmail,
};
