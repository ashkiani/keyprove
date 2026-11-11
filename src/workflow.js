/**
 * KeyProve higher-level enrollment and request authentication.
 * Framework/database independence: the host supplies storage and HTTP adapters.
 */
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { createVerifier, verifyEnrollmentProof, keyIdFromPublicKey, KeyproveError } from './server.js';
import { registrationPage, loginPage, adminPage, getUiAsset } from './pages.js';

const randomToken = (n = 24) => randomBytes(n).toString('base64url');
const sha = value => createHash('sha256').update(value).digest('hex');
const fail = code => { throw new KeyproveError(code); };

function normalizeEmail(value) {
  if (typeof value !== 'string') fail('INVALID_EMAIL');
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fail('INVALID_EMAIL');
  return email;
}
function originOf(value) {
  let uri;
  try { uri = new URL(value); } catch { fail('INVALID_ORIGIN'); }
  if (uri.origin !== value || !/^https?:$/.test(uri.protocol)) fail('INVALID_ORIGIN');
  if (uri.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(uri.hostname)) fail('INVALID_ORIGIN');
  return uri.origin;
}
function positiveMs(name, value, max) {
  if (!Number.isSafeInteger(value) || value < 1000 || value > max) throw new TypeError(`Invalid ${name}`);
}
function requireStorage(storage) {
  for (const op of ['save', 'get', 'consume']) {
    if (typeof storage?.[op] !== 'function') throw new TypeError(`storage.${op}() callback is required`);
  }
  return storage;
}
function safeAdminToken(received, configured) {
  if (!configured || typeof configured !== 'string') fail('ADMIN_DISABLED');
  if (typeof received !== 'string' || received.length > 4096) fail('ADMIN_UNAUTHORIZED');
  const a = createHash('sha256').update(received).digest();
  const b = createHash('sha256').update(configured).digest();
  if (!timingSafeEqual(a, b)) fail('ADMIN_UNAUTHORIZED');
}
/**
 * Single-process example storage. All three callbacks are synchronous up to the
 * first return and consume removes an item atomically in the JS event loop.
 * Not persistent and not suitable for multiple Node processes.
 */
export function createMemoryStorage({ limit = 20_000 } = {}) {
  const values = new Map();
  const keyOf = (type, id) => `${type}:${id}`;
  return {
    async save(type, id, value) {
      const now = Date.now();
      for (const [key, item] of values) if (item?.expiresAt && item.expiresAt <= now) values.delete(key);
      const key = keyOf(type, id);
      if (values.has(key)) fail('ALREADY_EXISTS');
      if (values.size >= limit) fail('STORAGE_CAPACITY');
      values.set(key, structuredClone(value));
    },
    async get(type, id) {
      const value = values.get(keyOf(type, id));
      return value ? structuredClone(value) : null;
    },
    async consume(type, id) {
      const key = keyOf(type, id);
      const value = values.get(key);
      values.delete(key);
      return value ? structuredClone(value) : null;
    }
  };
}

/**
 * Storage contract:
 *   save(type,id,record): create-only, unique ID; rejects duplicates
 *   get(type,id): record or null
 *   consume(type,id): remove and return once, atomically across all instances
 * Types: invitation, enrollment, publicKey, challenge.
 * `publicKey` records are never consumed by KeyProve.
 */
export function createKeyprove({ storage = createMemoryStorage(), adminToken, expectedOrigin,
  invitationTtlMs = 24 * 60 * 60 * 1000, enrollmentTtlMs = 5 * 60 * 1000,
  challengeTtlMs = 60_000, maxClockSkewSeconds = 90 } = {}) {
  requireStorage(storage);
  if (expectedOrigin !== undefined) originOf(expectedOrigin);
  positiveMs('invitationTtlMs', invitationTtlMs, 30 * 24 * 60 * 60 * 1000);
  positiveMs('enrollmentTtlMs', enrollmentTtlMs, 60 * 60 * 1000);
  const verifier = createVerifier({
    expectedOrigin,
    resolveKey: keyId => storage.get('publicKey', keyId),
    challengeStore: {
      save: (id, record) => storage.save('challenge', id, record),
      consume: id => storage.consume('challenge', id)
    },
    challengeTtlMs, maxClockSkewSeconds
  });

  async function issueRegistrationToken({ email, adminToken: providedAdminToken }) {
    safeAdminToken(providedAdminToken, adminToken);
    email = normalizeEmail(email);
    const token = randomToken(24);
    const tokenHash = sha(token);
    const expiresAt = Date.now() + invitationTtlMs;
    await storage.save('invitation', tokenHash, { email, expiresAt });
    return { email, token, expiresAt: new Date(expiresAt).toISOString() };
  }

  async function startRegistration({ email, invitationToken, origin }) {
    email = normalizeEmail(email);
    origin = originOf(origin);
    if (expectedOrigin && origin !== expectedOrigin) fail('INVALID_ORIGIN');
    if (typeof invitationToken !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(invitationToken)) fail('INVALID_INVITATION');
    const invitationId = sha(invitationToken);
    const invite = await storage.get('invitation', invitationId);
    if (!invite || invite.email !== email || invite.expiresAt <= Date.now()) fail('INVALID_INVITATION');
    const token = randomToken(24);
    const challenge = randomToken(32);
    const expiresAt = Date.now() + enrollmentTtlMs;
    await storage.save('enrollment', sha(token), { email, origin, challenge, invitationId, expiresAt });
    return { token, challenge, origin, expiresInSeconds: Math.ceil(enrollmentTtlMs / 1000) };
  }

  async function finishRegistration({ email, token, challenge, publicKey, signature }) {
    email = normalizeEmail(email);
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{32}$/.test(token)) fail('INVALID_ENROLLMENT');
    const enrollId = sha(token);
    const pending = await storage.get('enrollment', enrollId);
    if (!pending || pending.email !== email || pending.challenge !== challenge ||
        pending.expiresAt <= Date.now()) fail('INVALID_ENROLLMENT');
    let valid = false;
    try { valid = verifyEnrollmentProof({ email, origin: pending.origin, token, challenge, publicKey, signature }); }
    catch { /* Malformed public keys/signatures fail closed. */ }
    if (!valid) fail('INVALID_ENROLLMENT_PROOF');
    let keyId;
    try { keyId = keyIdFromPublicKey(publicKey); } catch { fail('INVALID_ENROLLMENT_PROOF'); }
    if (await storage.get('publicKey', keyId)) fail('KEY_ALREADY_REGISTERED');
    // No unauthenticated request can consume a valid invitation. Storage must
    // implement consume() as a single atomic operation across processes.
    const claimedEnrollment = await storage.consume('enrollment', enrollId);
    if (!claimedEnrollment || claimedEnrollment.email !== email ||
        claimedEnrollment.challenge !== challenge || claimedEnrollment.expiresAt <= Date.now()) fail('INVALID_ENROLLMENT');
    const invitation = await storage.consume('invitation', pending.invitationId);
    if (!invitation || invitation.email !== email || invitation.expiresAt <= Date.now()) fail('INVALID_INVITATION');
    // save() must be create-only so concurrent registration cannot overwrite a key.
    await storage.save('publicKey', keyId, { keyId, publicKey, subject: email, email, createdAt: Date.now(), revoked: false });
    return { email, keyId };
  }

  const api = {
    issueRegistrationToken,
    startRegistration,
    finishRegistration,
    issueChallenge: keyId => verifier.issueChallenge(keyId),
    verifyRequest: request => verifier.verifyRequest(request),
    verifyNodeRequest: (request, rawBody, options) => verifier.verifyNodeRequest(request, rawBody, options),
    registrationPage,
    loginPage,
    adminPage,
    getUiAsset,
    /**
     * Generic HTTP bridge. The host chooses routes and how to read/write a
     * response. KeyProve never imports or accesses a framework response object.
     * `readRequest` -> { method, headers, body, origin? }; `sendResponse(result)`.
     */
    async handle(action, { readRequest = async () => ({}), sendResponse, pageOptions, asset } = {}) {
      let result;
      try {
        if (action === 'registration-page' || action === 'login-page' || action === 'admin-page') {
          const page = action === 'registration-page' ? registrationPage(pageOptions) :
            action === 'login-page' ? loginPage(pageOptions) : adminPage(pageOptions);
          result = { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            'Referrer-Policy': 'no-referrer' }, body: page };
        } else if (action === 'asset') {
          const item = getUiAsset(asset);
          result = { status: 200, headers: { 'Content-Type': item.contentType,
            'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff' }, body: item.body };
        } else {
          const req = await readRequest();
          if (req?.method !== 'POST') fail('METHOD_NOT_ALLOWED');
          let data = req.body;
          if (typeof data === 'string' && data.length <= 32_768) {
            try { data = JSON.parse(data); } catch { fail('INVALID_REQUEST'); }
          }
          if (!data || typeof data !== 'object' || Array.isArray(data)) fail('INVALID_REQUEST');
          let value;
          switch (action) {
            case 'admin-invite': {
              const raw = req.headers?.authorization ?? req.headers?.Authorization;
              const match = typeof raw === 'string' && /^Bearer ([^\s]+)$/.exec(raw);
              value = await issueRegistrationToken({ email: data.email, adminToken: match?.[1] });
              break;
            }
            case 'registration-start':
              value = await startRegistration({ email: data.email, invitationToken: data.invitationToken, origin: req.origin });
              break;
            case 'registration-finish': value = await finishRegistration(data); break;
            case 'challenge': value = await verifier.issueChallenge(data.keyId); break;
            default: fail('UNKNOWN_ACTION');
          }
          result = { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }, body: JSON.stringify(value) };
        }
      } catch (error) {
        const isClient = error instanceof KeyproveError;
        const status = error.code === 'ADMIN_UNAUTHORIZED' || error.code === 'ADMIN_DISABLED' ? 403 :
          error.code === 'METHOD_NOT_ALLOWED' ? 405 :
          error.code === 'ALREADY_EXISTS' || error.code === 'KEY_ALREADY_REGISTERED' ? 409 :
          isClient ? 400 : 500;
        result = { status, headers: { 'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
          body: JSON.stringify({ error: isClient ? error.code : 'INTERNAL_ERROR' }) };
      }
      if (sendResponse) await sendResponse(result);
      return result;
    }
  };
  return api;
}
