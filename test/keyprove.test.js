import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { generateCredential, unlockCredential, signRequest, keyIdFromPublicKey,
  signEnrollment, validateCredential, signedFetch } from '../src/browser.js';
import { createVerifier, createMemoryChallengeStore, verifyEnrollmentProof,
  keyIdFromPublicKey as serverKeyId, KeyproveError } from '../src/server.js';
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const ORIGIN = 'http://localhost:3100';
const password = 'long and strong example password 2026!';
let cached;
async function fixture() {
  cached ||= await generateCredential({ email: 'alice@example.com', password });
  return cached;
}
function verifierFor(publicKey, options = {}) {
  const keyId = serverKeyId(publicKey);
  const verifier = createVerifier({ expectedOrigin: ORIGIN,
    resolveKey: async id => id === keyId ? { publicKey, subject: 'alice@example.com' } : null,
    ...options });
  return { verifier, keyId };
}
const codeOf = e => e instanceof KeyproveError && !!e.code;

test('encrypted browser credential and local non-extractable key, including import backup', async () => {
  const { bundle, privateKey, publicKey } = await fixture();
  assert.equal(bundle.type, 'browser-key-auth-backup');
  assert.equal(bundle.version, 1);
  assert.equal(bundle.encryption.iterations, 600000);
  assert.equal(privateKey.extractable, false);
  assert.equal(privateKey.usages[0], 'sign');
  assert.equal(await keyIdFromPublicKey(publicKey), serverKeyId(publicKey));
  await assert.rejects(webcrypto.subtle.exportKey('pkcs8', privateKey));
  const restored = JSON.parse(JSON.stringify(bundle));
  assert.ok(validateCredential(restored));
  const unlocked = await unlockCredential(restored, password);
  assert.equal(unlocked.extractable, false);
  await assert.rejects(unlockCredential(restored, 'wrong password'));
  restored.email = 'bob@example.com';
  await assert.rejects(unlockCredential(restored, password));
});

test('enrollment signs registered public key and context', async () => {
  const { privateKey, publicKey } = await fixture();
  const signature = await signEnrollment({ email: 'alice@example.com', origin: ORIGIN,
    token: 'sample-token', challenge: 'sample-challenge', privateKey, publicKey });
  assert.equal(verifyEnrollmentProof({ email: 'alice@example.com', origin: ORIGIN,
    token: 'sample-token', challenge: 'sample-challenge', signature, publicKey }), true);
  assert.equal(verifyEnrollmentProof({ email: 'bob@example.com', origin: ORIGIN,
    token: 'sample-token', challenge: 'sample-challenge', signature, publicKey }), false);
});

test('signed GET/POST, replay rejection, tampering, request binding and no unauthenticated challenge burn', async () => {
  const { privateKey, publicKey } = await fixture();
  const { verifier, keyId } = verifierFor(publicKey);
  const { nonce } = await verifier.issueChallenge(keyId);
  const url = ORIGIN + '/api/private/me?limit=1';
  const a = await signRequest({ url, method: 'GET', nonce, privateKey, publicKey });
  assert.equal((await verifier.verifyRequest({ method: 'GET', targetUri: url, headers: a.headers })).subject, 'alice@example.com');
  await assert.rejects(verifier.verifyRequest({ method: 'GET', targetUri: url, headers: a.headers }), e => e.code === 'CHALLENGE_USED');
  const { nonce: nonce2 } = await verifier.issueChallenge(keyId);
  const b = await signRequest({ url, method: 'GET', nonce: nonce2, privateKey, publicKey });
  await assert.rejects(verifier.verifyRequest({ method: 'GET', targetUri: ORIGIN + '/api/private/me?limit=2', headers: b.headers }), e => e.code === 'BAD_SIGNATURE');
  assert.equal((await verifier.verifyRequest({ method: 'GET', targetUri: url, headers: b.headers })).subject, 'alice@example.com');

  const body = JSON.stringify({ amount: 100 });
  const { nonce: nonce3 } = await verifier.issueChallenge(keyId);
  const c = await signRequest({ url: ORIGIN + '/api/private/transaction', method: 'POST',
    body, nonce: nonce3, privateKey, publicKey });
  await assert.rejects(verifier.verifyRequest({ method: 'POST', targetUri: ORIGIN + '/api/private/transaction',
    headers: c.headers, rawBody: JSON.stringify({ amount: 1000 }) }), e => e.code === 'BAD_DIGEST');
  assert.equal((await verifier.verifyRequest({ method: 'POST', targetUri: ORIGIN + '/api/private/transaction',
    headers: c.headers, rawBody: body })).subject, 'alice@example.com');
  await assert.rejects(verifier.verifyRequest({ method: 'POST', targetUri: ORIGIN + '/api/private/transaction',
    headers: c.headers, rawBody: body }), e => e.code === 'CHALLENGE_USED');
});

test('invalid signing metadata, wrong origins, duplicate headers and revoked keys fail closed', async () => {
  const { privateKey, publicKey } = await fixture();
  const { verifier, keyId } = verifierFor(publicKey);
  const { nonce } = await verifier.issueChallenge(keyId);
  const url = ORIGIN + '/api/private/me';
  const a = await signRequest({ url, nonce, privateKey, publicKey });
  const tampered = { ...a.headers, 'Signature-Input': a.headers['Signature-Input'].replace('keyprove-v1', 'other-app') };
  await assert.rejects(verifier.verifyRequest({ method: 'GET', targetUri: url, headers: tampered }), codeOf);
  await assert.rejects(verifier.verifyRequest({ method: 'GET', targetUri: 'http://another.local/api/private/me', headers: a.headers }), codeOf);
  const duplicate = ['Signature-Input', a.headers['Signature-Input'], 'signature-input', a.headers['Signature-Input'],
    'Signature', a.headers.Signature];
  await assert.rejects(verifier.verifyRequest({ method: 'GET', targetUri: url, headers: a.headers, rawHeaders: duplicate }), codeOf);
  assert.equal((await verifier.verifyRequest({ method: 'GET', targetUri: url, headers: a.headers })).subject, 'alice@example.com');
  const revoked = createVerifier({ expectedOrigin: ORIGIN, resolveKey: async () => ({ publicKey, revoked: true }) });
  await assert.rejects(revoked.issueChallenge(keyId), e => e.code === 'UNKNOWN_KEY');
});

test('signedFetch asks for a challenge and uses same-origin signed request', async () => {
  const { privateKey, publicKey } = await fixture();
  const { verifier, keyId } = verifierFor(publicKey);
  const calls = [];
  const fakeFetch = async (url, opts) => {
    calls.push({ url, opts });
    if (url.endsWith('/api/challenge')) {
      assert.equal(JSON.parse(opts.body).keyId, keyId);
      return { ok: true, json: async () => verifier.issueChallenge(keyId) };
    }
    assert.equal((await verifier.verifyRequest({ method: opts.method, targetUri: url,
      headers: opts.headers, rawBody: opts.body || '' })).subject, 'alice@example.com');
    return { ok: true, status: 200, json: async () => ({ ok: true }) };
  };
  const res = await signedFetch({ url: ORIGIN + '/api/private/echo', method: 'POST', body: '{"hi":1}',
    challengeUrl: ORIGIN + '/api/challenge', publicKey, privateKey, fetchImpl: fakeFetch });
  assert.equal(res.status, 200);
  assert.equal(calls.length, 2);
  await assert.rejects(signedFetch({ url: ORIGIN + '/api/private/me',
    challengeUrl: 'https://evil.example/api/challenge', publicKey, privateKey, fetchImpl: fakeFetch }));
});

test('imports an encrypted backup produced by the original KeyProve Lab', async () => {
  const { readFileSync } = await import('node:fs');
  const bundle = JSON.parse(readFileSync(new URL('./fixtures/old-lab-v1.json', import.meta.url), 'utf8'));
  const privateKey = await unlockCredential(bundle, 'old lab backup sample password 2026');
  assert.equal(privateKey.extractable, false);
  const { verifier, keyId } = verifierFor(bundle.publicKey);
  const { nonce } = await verifier.issueChallenge(keyId);
  const url = ORIGIN + '/api/private/me';
  const signed = await signRequest({ url, nonce, privateKey, publicKey: bundle.publicKey });
  const result = await verifier.verifyRequest({ method: 'GET', targetUri: url, headers: signed.headers });
  assert.equal(result.subject, 'alice@example.com');
});
