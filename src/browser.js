/** KeyProve browser client. No framework, bundler, or third-party packages required. */
import {
  COVERED_GET, COVERED_POST, SIGNATURE_ALGORITHM, SIGNATURE_TAG,
  signatureBase, signatureHeader, signatureInput, contentDigest, jwkThumbprintSource
} from './signatures.js';

const encoder = new TextEncoder();
const BACKUP_TYPE = 'browser-key-auth-backup'; // Compatible with KeyProve Lab v1 backup exports.
const MIN_ITERATIONS = 600_000;
const MAX_ITERATIONS = 2_000_000;

function enc(s) { return encoder.encode(s); }
function b64url(bytes) {
  let raw = '';
  for (const x of new Uint8Array(bytes)) raw += String.fromCharCode(x);
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
}
function b64(bytes) {
  let raw = '';
  for (const x of new Uint8Array(bytes)) raw += String.fromCharCode(x);
  return btoa(raw);
}
function unb64url(value, max = 8192) {
  if (typeof value !== 'string' || !value || value.length > max || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid base64url value');
  }
  const data = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(data, c => c.charCodeAt(0));
}
function emailOf(value) {
  if (typeof value !== 'string') throw new TypeError('Email must be a string');
  const email = value.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) throw new Error('Invalid email');
  return email;
}
function publicJwk(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk
      || unb64url(jwk.x, 100).length !== 32 || unb64url(jwk.y, 100).length !== 32) {
    throw new Error('Expected a P-256 public JWK');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
function aad(bundle) {
  return enc(JSON.stringify([BACKUP_TYPE, 1, bundle.email, bundle.publicKey.x, bundle.publicKey.y]));
}
export function validateCredential(bundle) {
  if (!bundle || bundle.type !== BACKUP_TYPE || bundle.version !== 1 || emailOf(bundle.email) !== bundle.email) {
    throw new Error('Unsupported encrypted credential');
  }
  publicJwk(bundle.publicKey);
  const e = bundle.encryption;
  if (!e || e.kdf !== 'PBKDF2-SHA256' || e.cipher !== 'AES-256-GCM'
      || !Number.isInteger(e.iterations) || e.iterations < MIN_ITERATIONS || e.iterations > MAX_ITERATIONS
      || unb64url(e.salt, 100).length !== 16 || unb64url(e.iv, 100).length !== 12
      || unb64url(e.wrappedPrivateKey).length < 80) {
    throw new Error('Invalid encrypted credential parameters');
  }
  return bundle;
}
async function wrappingKey(password, salt, iterations) {
  if (typeof password !== 'string') throw new TypeError('Password must be a string');
  const base = await crypto.subtle.importKey('raw', enc(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base,
    { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}
export async function generateCredential({ email, password, iterations = MIN_ITERATIONS }) {
  email = emailOf(email);
  if (typeof password !== 'string' || password.length < 12) throw new Error('Password must have at least 12 characters');
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new Error('Unsupported PBKDF2 iteration count');
  }
  // Web Crypto requires an extractable private key briefly in order to wrap it.
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const publicKey = publicJwk(await crypto.subtle.exportKey('jwk', pair.publicKey));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const bundle = {
    type: BACKUP_TYPE, version: 1, email, publicKey,
    encryption: { kdf: 'PBKDF2-SHA256', iterations, salt: b64url(salt),
      cipher: 'AES-256-GCM', iv: b64url(iv), wrappedPrivateKey: '' }
  };
  const wrap = await wrappingKey(password, salt, iterations);
  const ciphertext = await crypto.subtle.wrapKey('pkcs8', pair.privateKey, wrap,
    { name: 'AES-GCM', iv, additionalData: aad(bundle), tagLength: 128 });
  bundle.encryption.wrappedPrivateKey = b64url(ciphertext);
  // Only return a non-extractable signing key, never the original extractable handle.
  const privateKey = await unlockCredential(bundle, password);
  return { bundle, privateKey, publicKey };
}
export async function unlockCredential(bundle, password) {
  validateCredential(bundle);
  const wrap = await wrappingKey(password, unb64url(bundle.encryption.salt), bundle.encryption.iterations);
  const privateKey = await crypto.subtle.unwrapKey('pkcs8', unb64url(bundle.encryption.wrappedPrivateKey),
    wrap, { name: 'AES-GCM', iv: unb64url(bundle.encryption.iv),
      additionalData: aad(bundle), tagLength: 128 },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const pub = await crypto.subtle.importKey('jwk', publicJwk(bundle.publicKey),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const test = enc('BROWSER-KEY-AUTH-LOCAL-PAIR-CHECK-V1');
  const proof = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, test);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, proof, test)) {
    throw new Error('Private key does not match public key');
  }
  return privateKey;
}
export async function keyIdFromPublicKey(publicKey) {
  const source = jwkThumbprintSource(publicJwk(publicKey));
  return 'jwk-sha256-' + b64url(await crypto.subtle.digest('SHA-256', enc(source)));
}
/** An enrollment authorization token/challenge is issued by the host app, not KeyProve. */
export async function signEnrollment({ email, origin, token, challenge, publicKey, privateKey }) {
  email = emailOf(email);
  const jwk = publicJwk(publicKey);
  if (typeof token !== 'string' || typeof challenge !== 'string') throw new Error('Invalid enrollment challenge');
  const msg = ['ENROLL-V1', new URL(origin).origin, email, token, challenge, jwk.x, jwk.y].join('\n');
  return b64url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, enc(msg)));
}
/** Sign the *exact* request body string that fetch will transmit. */
export async function signRequest({ url, method = 'GET', body, contentType = 'application/json', nonce,
  privateKey, publicKey, created = Math.floor(Date.now() / 1000) }) {
  const target = new URL(url);
  if (!/^https?:$/.test(target.protocol) || target.hash) throw new Error('Expected a fragment-free HTTP(S) URL');
  method = String(method).toUpperCase();
  if (!/^[A-Z]+$/.test(method)) throw new Error('Invalid HTTP method');
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonce)) throw new Error('Expected a server-issued 32-byte nonce');
  if (body !== undefined && typeof body !== 'string') throw new Error('Request body must be the exact string sent on the wire');
  if ((method === 'GET' || method === 'HEAD') && body !== undefined) throw new Error('GET/HEAD cannot include a body');
  const hasBody = method !== 'GET' && method !== 'HEAD';
  const bodyText = hasBody ? (body ?? '') : undefined;
  const covered = hasBody ? COVERED_POST : COVERED_GET;
  const parameters = [['created', created], ['nonce', nonce],
    ['keyid', await keyIdFromPublicKey(publicKey)], ['alg', SIGNATURE_ALGORITHM], ['tag', SIGNATURE_TAG]];
  const fields = {};
  const headers = {};
  if (hasBody) {
    const digest = contentDigest(b64(await crypto.subtle.digest('SHA-256', enc(bodyText))));
    fields['content-type'] = contentType;
    fields['content-digest'] = digest;
    headers['Content-Type'] = contentType;
    headers['Content-Digest'] = digest;
  }
  const base = signatureBase({ components: covered, parameters, method, targetUri: target.href, fields });
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, enc(base));
  headers['Signature-Input'] = signatureInput(covered, parameters);
  headers.Signature = signatureHeader(b64(sig));
  return { headers, body: bodyText };
}
/**
 * Two-round-trip API: obtain challenge, then submit signed request.
 * Challenge endpoint request/response: POST JSON {keyId} -> {nonce}.
 * Caller supplies a credential unlocked in memory, not a password.
 */
export async function signedFetch({ url, method = 'GET', body, challengeUrl, privateKey, publicKey,
  fetchImpl = fetch, contentType = 'application/json' }) {
  const uri = new URL(url);
  if (new URL(challengeUrl).origin !== uri.origin) throw new Error('Challenge and request must share an origin');
  const keyId = await keyIdFromPublicKey(publicKey);
  const challengeResponse = await fetchImpl(challengeUrl, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    cache: 'no-store', credentials: 'omit', body: JSON.stringify({ keyId })
  });
  if (!challengeResponse.ok) throw new Error(`Challenge request failed: HTTP ${challengeResponse.status}`);
  const challenge = await challengeResponse.json();
  const signed = await signRequest({ url: uri.href, method, body, contentType,
    nonce: challenge.nonce, privateKey, publicKey });
  return fetchImpl(uri.href, {
    method, headers: signed.headers, cache: 'no-store', credentials: 'omit',
    ...(signed.body === undefined ? {} : { body: signed.body })
  });
}

/** Optional IndexedDB helper. Only encrypted bundles are persisted. */
const DB_NAME = 'keyprove-credentials-v1';
const STORE = 'encryptedKeys';
async function withStore(mode, operation) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE, { keyPath: 'email' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE, mode);
      const request = operation(transaction.objectStore(STORE));
      transaction.oncomplete = () => resolve(request.result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally { db.close(); }
}
export async function saveCredential(bundle) {
  validateCredential(bundle);
  return withStore('readwrite', store => store.put(bundle));
}
export async function getCredential(email) {
  return (await withStore('readonly', store => store.get(emailOf(email)))) || null;
}
export async function listCredentials() {
  return withStore('readonly', store => store.getAll());
}
export async function deleteCredential(email) {
  return withStore('readwrite', store => store.delete(emailOf(email)));
}
