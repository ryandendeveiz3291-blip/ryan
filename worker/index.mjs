const ALLOWED_ORIGIN = 'https://ryandendeveiz3291-blip.github.io';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MIN_PASSWORD_LENGTH = 24;
const MIN_SESSION_SECRET_LENGTH = 32;
const encoder = new TextEncoder();

function authConfigured(env) {
  return typeof env.OWNER_PASSWORD === 'string' &&
    [...env.OWNER_PASSWORD].length >= MIN_PASSWORD_LENGTH &&
    typeof env.SESSION_SECRET === 'string' &&
    [...env.SESSION_SECRET].length >= MIN_SESSION_SECRET_LENGTH;
}

function responseHeaders(origin) {
  const headers = new Headers({
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff'
  });
  if (origin === ALLOWED_ORIGIN) {
    headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    headers.set('Vary', 'Origin');
  }
  return headers;
}

function jsonResponse(origin, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders(origin)
  });
}

function encodeBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

async function importSigningKey(password) {
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function createSessionToken(secret) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const payload = encodeBase64Url(encoder.encode(JSON.stringify({
    iss: 'frontier-owner-auth',
    sub: 'owner',
    iat: issuedAt,
    exp: issuedAt + SESSION_TTL_SECONDS
  })));
  const signature = await crypto.subtle.sign(
    'HMAC',
    await importSigningKey(secret),
    encoder.encode(payload)
  );
  return {
    token: payload + '.' + encodeBase64Url(new Uint8Array(signature)),
    expiresAt: (issuedAt + SESSION_TTL_SECONDS) * 1000
  };
}

async function verifySessionToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  let signature;
  let payload;
  try {
    signature = decodeBase64Url(parts[1]);
    payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(parts[0])));
  } catch {
    return null;
  }

  const validSignature = await crypto.subtle.verify(
    'HMAC',
    await importSigningKey(secret),
    signature,
    encoder.encode(parts[0])
  );
  const now = Math.floor(Date.now() / 1000);
  if (
    !validSignature ||
    payload.iss !== 'frontier-owner-auth' ||
    payload.sub !== 'owner' ||
    !Number.isInteger(payload.iat) ||
    !Number.isInteger(payload.exp) ||
    payload.iat > now ||
    payload.exp <= now ||
    payload.exp - payload.iat !== SESSION_TTL_SECONDS
  ) {
    return null;
  }
  return payload;
}

async function passwordMatches(candidate, expected) {
  const [candidateHash, expectedHash] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(candidate)),
    crypto.subtle.digest('SHA-256', encoder.encode(expected))
  ]);
  const candidateBytes = new Uint8Array(candidateHash);
  const expectedBytes = new Uint8Array(expectedHash);
  let difference = 0;
  for (let index = 0; index < candidateBytes.length; index++) {
    difference |= candidateBytes[index] ^ expectedBytes[index];
  }
  return difference === 0;
}

async function readLoginBody(request) {
  const contentLength = Number(request.headers.get('Content-Length'));
  if (Number.isFinite(contentLength) && contentLength > 2048) return null;
  const reader = request.body?.getReader();
  if (!reader) return null;
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 2048) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    if (origin !== ALLOWED_ORIGIN) return jsonResponse(origin, 403, { error: 'origin_not_allowed' });

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: responseHeaders(origin) });
    }

    const { pathname } = new URL(request.url);
    if (pathname === '/api/login' && request.method === 'POST') {
      if (!authConfigured(env)) {
        return jsonResponse(origin, 503, { error: 'owner_auth_not_configured' });
      }
      if (!env.LOGIN_LIMITER) {
        return jsonResponse(origin, 503, { error: 'login_rate_limit_not_configured' });
      }
      const contentType = request.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase();
      if (contentType !== 'application/json') {
        return jsonResponse(origin, 415, { error: 'json_required' });
      }

      const body = await readLoginBody(request);
      if (!body || typeof body.password !== 'string' || body.password.length > 256) {
        return jsonResponse(origin, 400, { error: 'invalid_request' });
      }

      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const limit = await env.LOGIN_LIMITER.limit({ key: ip + ':owner-login' });
      if (!limit.success) return jsonResponse(origin, 429, { error: 'rate_limited' });
      if (!await passwordMatches(body.password, env.OWNER_PASSWORD)) {
        return jsonResponse(origin, 401, { error: 'invalid_credentials' });
      }

      return jsonResponse(origin, 200, await createSessionToken(env.SESSION_SECRET));
    }

    if (pathname === '/api/session' && request.method === 'GET') {
      if (!authConfigured(env)) {
        return jsonResponse(origin, 503, { error: 'owner_auth_not_configured' });
      }
      const authorization = request.headers.get('Authorization') || '';
      const match = /^Bearer ([A-Za-z0-9._-]{20,2048})$/.exec(authorization);
      if (!match) return jsonResponse(origin, 401, { error: 'invalid_session' });
      const session = await verifySessionToken(match[1], env.SESSION_SECRET);
      if (!session) return jsonResponse(origin, 401, { error: 'invalid_session' });
      return jsonResponse(origin, 200, {
        authenticated: true,
        role: 'owner',
        expiresAt: session.exp * 1000
      });
    }

    return jsonResponse(origin, 404, { error: 'not_found' });
  }
};
