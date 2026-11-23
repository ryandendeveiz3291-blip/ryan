import assert from 'node:assert/strict';
import test from 'node:test';
import worker from './index.mjs';

const ORIGIN = 'https://ryandendeveiz3291-blip.github.io';
const TEST_PASSWORD = 'test-only-password-with-enough-length-42';
const TEST_SESSION_SECRET = 'test-session-signing-secret-not-for-deploy-012345';

function makeEnv({ password = TEST_PASSWORD, allowed = true, success = true } = {}) {
  return {
    OWNER_PASSWORD: password,
    SESSION_SECRET: TEST_SESSION_SECRET,
    LOGIN_LIMITER: {
      async limit() {
        return { success: allowed ? success : false };
      }
    }
  };
}

function makeRequest(path, { method = 'GET', origin = ORIGIN, headers = {}, body } = {}) {
  return new Request('https://owner-auth.example.workers.dev' + path, {
    method,
    headers: { Origin: origin, ...headers },
    body
  });
}

test('rejects requests from origins other than the published game', async () => {
  const response = await worker.fetch(makeRequest('/api/session', { origin: 'https://evil.example' }), makeEnv());
  assert.equal(response.status, 403);
});

test('requires a strong server-side password configuration', async () => {
  const response = await worker.fetch(
    makeRequest('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'short' })
    }),
    makeEnv({ password: 'too-short' })
  );
  assert.equal(response.status, 503);
});

test('rejects incorrect passwords without issuing a session', async () => {
  const response = await worker.fetch(
    makeRequest('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: 'incorrect-password-value' })
    }),
    makeEnv()
  );
  assert.equal(response.status, 401);
});

test('limits login attempts per client IP', async () => {
  const response = await worker.fetch(
    makeRequest('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.0.2.1' },
      body: JSON.stringify({ password: TEST_PASSWORD })
    }),
    makeEnv({ allowed: false })
  );
  assert.equal(response.status, 429);
});

test('issues a short-lived signed owner session and validates it server-side', async () => {
  const login = await worker.fetch(
    makeRequest('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: TEST_PASSWORD })
    }),
    makeEnv()
  );
  assert.equal(login.status, 200);
  assert.equal(login.headers.get('Cache-Control'), 'no-store');
  assert.equal(login.headers.get('Access-Control-Allow-Origin'), ORIGIN);
  const { token, expiresAt } = await login.json();
  assert.equal(typeof token, 'string');
  assert.ok(expiresAt > Date.now());

  const session = await worker.fetch(
    makeRequest('/api/session', { headers: { Authorization: 'Bearer ' + token } }),
    makeEnv()
  );
  assert.equal(session.status, 200);
  assert.deepEqual(await session.json(), {
    authenticated: true,
    role: 'owner',
    expiresAt
  });

  const tampered = await worker.fetch(
    makeRequest('/api/session', { headers: { Authorization: 'Bearer ' + token + 'x' } }),
    makeEnv()
  );
  assert.equal(tampered.status, 401);
});
