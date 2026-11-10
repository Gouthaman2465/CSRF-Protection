/**
 * Validates the Sec-Fetch-Site header for state-changing requests.
 * Modern browsers send this header to indicate request origin context.
 *
 * Rule: If Sec-Fetch-Site is present, allow only 'same-origin'.
 * Values 'cross-site', 'same-site', and 'none' are rejected.
 *
 * @param {import('express').Request} req Incoming HTTP request
 * @returns {{ valid: boolean, code?: string, present: boolean }}
 */
function checkFetchMetadata(req) {
  const secFetchSite = req.headers['sec-fetch-site'];

  if (secFetchSite === undefined || secFetchSite === null || secFetchSite === '') {
    return { valid: true, present: false };
  }

  const normalized = Array.isArray(secFetchSite)
    ? secFetchSite[0].toLowerCase()
    : secFetchSite.toLowerCase();

  if (normalized === 'same-origin') {
    return { valid: true, present: true };
  }

  return {
    valid: false,
    code: 'FETCH_METADATA_CROSS_SITE',
    present: true,
  };
}

module.exports = {
  checkFetchMetadata,
};
