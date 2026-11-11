/** KeyProve Node verification. Storage and application policy are provided by the caller. */
import { randomBytes, createHash, createPublicKey, timingSafeEqual, verify as verifySignature } from 'node:crypto';
import {
  COVERED_GET, COVERED_POST, SIGNATURE_ALGORITHM, SIGNATURE_TAG,
  parseSignatureInput, parseSignatureHeader, parseContentDigest, signatureBase, jwkThumbprintSource
} from './signatures.js';

export class KeyproveError extends Error {
  constructor(code, message = code) { super(message); this.name = 'KeyproveError'; this.code = code; }
}
const fail = (code) => { throw new KeyproveError(code); };
function validNonce(n) { return typeof n === 'string' && /^[A-Za-z0-9_-]{43}$/.test(n); }
function canonicalJwk(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk
      || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x || '') || !/^[A-Za-z0-9_-]{43}$/.test(jwk.y || '')) fail('BAD_PUBLIC_KEY');
  const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, format: 'jwk' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') fail('BAD_PUBLIC_KEY');
  return { jwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, key };
}
export function keyIdFromPublicKey(publicKey) {
  const { jwk } = canonicalJwk(publicKey);
  return 'jwk-sha256-' + createHash('sha256').update(jwkThumbprintSource(jwk)).digest('base64url');
}
function header(headers, rawHeaders, lowerName) {
  if (rawHeaders) {
    let matches = 0;
    let value;
    for (let i = 0; i < rawHeaders.length; i += 2) {
      if (String(rawHeaders[i]).toLowerCase() === lowerName) {
        matches++;
        value = rawHeaders[i+1];
      }
    }
    if (matches !== 1 || typeof value !== 'string') fail('BAD_HEADERS');
    return value;
  }
  const candidates = Object.entries(headers || {}).filter(([key]) => key.toLowerCase() === lowerName);
  if (candidates.length !== 1 || typeof candidates[0][1] !== 'string') fail('BAD_HEADERS');
  return candidates[0][1];
}
function optionalHeader(headers, rawHeaders, lowerName) {
  if (rawHeaders) {
    const values = [];
    for (let i = 0; i < rawHeaders.length; i += 2) {
      if (String(rawHeaders[i]).toLowerCase() === lowerName) values.push(rawHeaders[i+1]);
    }
    if (values.length > 1) fail('BAD_HEADERS');
    return values[0];
  }
  const candidates = Object.entries(headers || {}).filter(([key]) => key.toLowerCase() === lowerName);
  if (candidates.length > 1) fail('BAD_HEADERS');
  return candidates[0]?.[1];
}

/** Volatile replay state for one Node process; use a shared atomic store for multiple instances. */
export function createMemoryChallengeStore({ limit = 10_000 } = {}) {
  const items = new Map();
  return {
    async save(nonce, data) {
      const now = Date.now();
      for (const [id, entry] of items) if (entry.expiresAt <= now) items.delete(id);
      if (items.size >= limit) throw new KeyproveError('CHALLENGE_CAPACITY');
      if (items.has(nonce)) throw new KeyproveError('CHALLENGE_COLLISION');
      items.set(nonce, { ...data });
    },
    async consume(nonce) {
      const entry = items.get(nonce);
      items.delete(nonce); // Atomic within a single JavaScript event loop.
      return entry && entry.expiresAt > Date.now() ? entry : null;
    }
  };
}

/**
 * Supply resolveKey(keyId) -> { publicKey: JWK, subject: your-user-id, ... } | null.
 * Supply challengeStore.save(nonce,{keyId,expiresAt}) and .consume(nonce) -> saved | null.
 * The consume operation MUST be atomic across processes when using persistent storage.
 */
export function createVerifier({ resolveKey, expectedOrigin, challengeStore = createMemoryChallengeStore(),
  challengeTtlMs = 60_000, maxClockSkewSeconds = 90 } = {}) {
  if (typeof resolveKey !== 'function') throw new TypeError('resolveKey(keyId) callback required');
  if (!challengeStore || typeof challengeStore.save !== 'function' || typeof challengeStore.consume !== 'function') {
    throw new TypeError('An atomic challengeStore with save() and consume() is required');
  }
  const originUrl = new URL(expectedOrigin);
  if (originUrl.origin !== expectedOrigin || !/^https?:$/.test(originUrl.protocol)) {
    throw new Error('expectedOrigin must be a bare HTTP(S) origin');
  }
  if (originUrl.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(originUrl.hostname)) {
    throw new Error('HTTPS required outside localhost');
  }
  if (!Number.isSafeInteger(challengeTtlMs) || challengeTtlMs < 1000 || challengeTtlMs > 300000) throw new Error('Invalid TTL');
  async function resolvedKey(keyId) {
    if (!/^jwk-sha256-[A-Za-z0-9_-]{43}$/.test(keyId || '')) fail('UNKNOWN_KEY');
    const record = await resolveKey(keyId);
    if (!record || !record.publicKey || record.revoked === true) fail('UNKNOWN_KEY');
    if (keyIdFromPublicKey(record.publicKey) !== keyId) fail('UNKNOWN_KEY');
    return record;
  }
  return {
    async issueChallenge(keyId) {
      await resolvedKey(keyId);
      const nonce = randomBytes(32).toString('base64url');
      await challengeStore.save(nonce, { keyId, expiresAt: Date.now() + challengeTtlMs });
      return { nonce, expiresInSeconds: Math.ceil(challengeTtlMs / 1000) };
    },
    async verifyRequest({ method, targetUri, headers, rawHeaders, rawBody = Buffer.alloc(0) }) {
      const url = new URL(targetUri);
      if (url.origin !== expectedOrigin || url.hash) fail('BAD_TARGET');
      if (typeof method !== 'string' || !/^[A-Z]+$/.test(method)) fail('BAD_METHOD');
      if (!(typeof rawBody === 'string' || Buffer.isBuffer(rawBody) || rawBody instanceof Uint8Array)) fail('BAD_BODY');
      const bytes = Buffer.from(rawBody);
      const hasBody = method !== 'GET' && method !== 'HEAD';
      if (!hasBody && bytes.length) fail('BAD_BODY');
      let input, rawSignature;
      try {
        input = parseSignatureInput(header(headers, rawHeaders, 'signature-input'));
        rawSignature = parseSignatureHeader(header(headers, rawHeaders, 'signature'));
      } catch { fail('BAD_SIGNATURE'); }
      const { components, parameters, metadata } = input;
      const expectedComponents = hasBody ? COVERED_POST : COVERED_GET;
      if (components.length !== expectedComponents.length ||
          expectedComponents.some((name, i) => components[i] !== name) ||
          metadata.alg !== SIGNATURE_ALGORITHM || metadata.tag !== SIGNATURE_TAG ||
          !validNonce(metadata.nonce) || !Number.isSafeInteger(metadata.created) ||
          Math.abs(Date.now()/1000 - metadata.created) > maxClockSkewSeconds) fail('BAD_POLICY');
      const record = await resolvedKey(metadata.keyid);
      const fields = {};
      if (hasBody) {
        let declared;
        try {
          fields['content-type'] = header(headers, rawHeaders, 'content-type').trim();
          fields['content-digest'] = header(headers, rawHeaders, 'content-digest').trim();
          declared = Buffer.from(parseContentDigest(fields['content-digest']), 'base64');
        } catch { fail('BAD_DIGEST'); }
        if (declared.length !== 32 || !timingSafeEqual(declared, createHash('sha256').update(bytes).digest())) fail('BAD_DIGEST');
      } else if (optionalHeader(headers, rawHeaders, 'content-digest')) {
        fail('UNSIGNED_DIGEST');
      }
      const base = signatureBase({ components, parameters, method, targetUri: url.href, fields });
      const sig = Buffer.from(rawSignature, 'base64');
      const { key } = canonicalJwk(record.publicKey);
      if (sig.length !== 64 || !verifySignature('sha256', Buffer.from(base, 'utf8'),
        { key, dsaEncoding: 'ieee-p1363' }, sig)) fail('BAD_SIGNATURE');
      // Never consume a challenge before checking the signature (prevents unauthenticated burn).
      const challenge = await challengeStore.consume(metadata.nonce);
      if (!challenge || challenge.keyId !== metadata.keyid) fail('CHALLENGE_USED');
      return { subject: record.subject, keyId: metadata.keyid, record };
    },
    async verifyNodeRequest(req, rawBody = Buffer.alloc(0)) {
      if (req.headers.host !== originUrl.host) fail('BAD_HOST');
      if (req.headers.origin && req.headers.origin !== expectedOrigin) fail('BAD_ORIGIN');
      if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//') || req.url.includes('#')) fail('BAD_TARGET');
      return this.verifyRequest({ method: req.method, targetUri: new URL(req.url, expectedOrigin).href,
        headers: req.headers, rawHeaders: req.rawHeaders, rawBody });
    }
  };
}

/** Check signed proof of possession during caller-authorized enrollment. */
export function verifyEnrollmentProof({ email, origin, token, challenge, publicKey, signature }) {
  const { jwk, key } = canonicalJwk(publicKey);
  if (typeof email !== 'string' || typeof token !== 'string' || typeof challenge !== 'string'
      || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  const text = ['ENROLL-V1', new URL(origin).origin, email.trim().toLowerCase(), token, challenge, jwk.x, jwk.y].join('\n');
  return verifySignature('sha256', Buffer.from(text, 'utf8'), { key, dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url'));
}
