const { checkFetchMetadata } = require('../../src/csrf/fetchMetadata');

describe('Fetch Metadata Module (Section 6 Rule 4)', () => {
  test('allows same-origin requests', () => {
    const req = { headers: { 'sec-fetch-site': 'same-origin' } };
    const result = checkFetchMetadata(req);
    expect(result.valid).toBe(true);
    expect(result.present).toBe(true);
  });

  test('blocks cross-site requests', () => {
    const req = { headers: { 'sec-fetch-site': 'cross-site' } };
    const result = checkFetchMetadata(req);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('FETCH_METADATA_CROSS_SITE');
  });

  test('blocks same-site (subdomain) requests for unsafe methods', () => {
    const req = { headers: { 'sec-fetch-site': 'same-site' } };
    const result = checkFetchMetadata(req);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('FETCH_METADATA_CROSS_SITE');
  });

  test('blocks user-direct (none) requests when present on state changes', () => {
    const req = { headers: { 'sec-fetch-site': 'none' } };
    const result = checkFetchMetadata(req);
    expect(result.valid).toBe(false);
    expect(result.code).toBe('FETCH_METADATA_CROSS_SITE');
  });

  test('reports not present when header is missing without blocking directly', () => {
    const req = { headers: {} };
    const result = checkFetchMetadata(req);
    expect(result.valid).toBe(true);
    expect(result.present).toBe(false);
  });
});
