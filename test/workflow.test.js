import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  createKeyprove, createMemoryStorage, createVerifier, KeyproveError
} from '../src/node.js';
import { generateCredential, signEnrollment, signRequest, keyIdFromPublicKey } from '../src/browser.js';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const origin = 'http://localhost:3130';
const ADMIN = 'test-admin-secret-should-be-strong-123456789';
const password = 'an intentionally long test password';
const newApp = opts => createKeyprove({ storage: createMemoryStorage(), adminToken: ADMIN, ...opts });

async function enroll(app, email = 'alice@example.com') {
  const invite = await app.issueRegistrationToken({ adminToken: ADMIN, email });
  const start = await app.startRegistration({ email, invitationToken: invite.token, origin });
  const credential = await generateCredential({ email, password });
  const signature = await signEnrollment({ email, origin, token: start.token,
    challenge: start.challenge, publicKey: credential.publicKey, privateKey: credential.privateKey });
  const finish = await app.finishRegistration({ email, token: start.token,
    challenge: start.challenge, publicKey: credential.publicKey, signature });
  return { invite, start, credential, signature, finish };
}

test('admin invitation, enrollment, signed request and replay all work with generic callbacks', async () => {
  const types = [];
  const memory = createMemoryStorage();
  const storage = {
    async save(type, id, data) { types.push(`save:${type}`); return memory.save(type, id, data); },
    async get(type, id) { types.push(`get:${type}`); return memory.get(type, id); },
    async consume(type, id) { types.push(`consume:${type}`); return memory.consume(type, id); }
  };
  const app = newApp({ storage });
  await assert.rejects(app.issueRegistrationToken({ email: 'alice@example.com', adminToken: 'wrong' }),
    e => e.code === 'ADMIN_UNAUTHORIZED');
  const registration = await enroll(app);
  assert.equal(registration.finish.email, 'alice@example.com');
  assert.equal(registration.finish.keyId, await keyIdFromPublicKey(registration.credential.publicKey));
  assert(types.includes('save:publicKey') && types.includes('consume:invitation'));
  assert.equal((await memory.get('publicKey', registration.finish.keyId)).subject, 'alice@example.com');
  assert.equal(await memory.get('invitation', (await import('node:crypto')).createHash('sha256')
    .update(registration.invite.token).digest('hex')), null);
  await assert.rejects(app.startRegistration({ email: 'alice@example.com',
    invitationToken: registration.invite.token, origin }), e => e.code === 'INVALID_INVITATION');
  const { nonce } = await app.issueChallenge(registration.finish.keyId);
  const uri = `${origin}/private/me`;
  const request = await signRequest({ url: uri, nonce,
    privateKey: registration.credential.privateKey, publicKey: registration.credential.publicKey });
  const verified = await app.verifyRequest({ method: 'GET', targetUri: uri, headers: request.headers });
  assert.equal(verified.subject, 'alice@example.com');
  await assert.rejects(app.verifyRequest({ method: 'GET', targetUri: uri, headers: request.headers }),
    e => e.code === 'CHALLENGE_USED');
});

test('invalid enroll proof does not consume registration invitation; concurrent enroll cannot reuse it', async () => {
  const app = newApp();
  const invite = await app.issueRegistrationToken({ email: 'bob@example.com', adminToken: ADMIN });
  const startA = await app.startRegistration({ email: 'bob@example.com', invitationToken: invite.token, origin });
  const startB = await app.startRegistration({ email: 'bob@example.com', invitationToken: invite.token, origin });
  const a = await generateCredential({ email: 'bob@example.com', password });
  const b = await generateCredential({ email: 'bob@example.com', password });
  const mkFinish = async (start, credential) => app.finishRegistration({ email: 'bob@example.com',
    token: start.token, challenge: start.challenge, publicKey: credential.publicKey,
    signature: await signEnrollment({ email: 'bob@example.com', origin, token: start.token,
      challenge: start.challenge, publicKey: credential.publicKey, privateKey: credential.privateKey }) });
  await assert.rejects(app.finishRegistration({ email: 'bob@example.com', token: startA.token,
    challenge: startA.challenge, publicKey: a.publicKey, signature: 'invalid' }),
    e => e.code === 'INVALID_ENROLLMENT_PROOF');
  const result = await Promise.allSettled([mkFinish(startA, a), mkFinish(startB, b)]);
  assert.equal(result.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(result.filter(x => x.status === 'rejected').length, 1);
});

test('origin optional but trusted absolute target required in Node helper', async () => {
  const app = newApp();
  const { credential, finish } = await enroll(app);
  const nonce = (await app.issueChallenge(finish.keyId)).nonce;
  const targetUri = `${origin}/private/me`;
  const signed = await signRequest({ url: targetUri, nonce, publicKey: credential.publicKey,
    privateKey: credential.privateKey });
  const req = { method: 'GET', url: '/private/me',
    headers: { ...Object.fromEntries(Object.entries(signed.headers).map(([k,v]) => [k.toLowerCase(),v])), host: 'spoofed.test' },
    rawHeaders: Object.entries(signed.headers).flat() };
  await assert.rejects(app.verifyNodeRequest(req), e => e.code === 'TRUSTED_TARGET_REQUIRED');
  await assert.rejects(app.verifyNodeRequest(req, Buffer.alloc(0), { targetUri: `${origin}/different` }),
    e => e.code === 'BAD_TARGET');
  assert.equal((await app.verifyNodeRequest(req, Buffer.alloc(0), { targetUri })).subject, 'alice@example.com');
  const strict = createVerifier({ expectedOrigin: 'http://localhost:4000',
    resolveKey: async () => ({ subject: 'alice@example.com', publicKey: credential.publicKey }) });
  await assert.rejects(strict.verifyRequest({ method: 'GET', targetUri, headers: signed.headers }),
    e => e.code === 'BAD_TARGET');
});

test('framework-neutral handle supports callbacks and provides complete page assets', async () => {
  const app = newApp();
  const capture = [];
  const invoke = async (action, payload, authorization, more = {}) => app.handle(action, {
    readRequest: async () => ({ method: 'POST', origin, headers: { authorization }, body: payload }),
    sendResponse: response => capture.push(response), ...more
  });
  const noAuth = await invoke('admin-invite', { email: 'alice@example.com' });
  assert.equal(noAuth.status, 403);
  const invite = await invoke('admin-invite', { email: 'alice@example.com' }, `Bearer ${ADMIN}`);
  assert.equal(invite.status, 200);
  const token = JSON.parse(invite.body).token;
  assert.match(token, /^[A-Za-z0-9_-]{32}$/);
  const start = await invoke('registration-start', { email: 'alice@example.com', invitationToken: token });
  assert.equal(start.status, 200);
  const data = JSON.parse(start.body);
  const cred = await generateCredential({ email: 'alice@example.com', password });
  const sig = await signEnrollment({ email: 'alice@example.com', origin, token: data.token,
    challenge: data.challenge, publicKey: cred.publicKey, privateKey: cred.privateKey });
  const end = await invoke('registration-finish', { email: 'alice@example.com', token: data.token,
    challenge: data.challenge, publicKey: cred.publicKey, signature: sig });
  assert.equal(end.status, 200);
  const challenge = await invoke('challenge', { keyId: JSON.parse(end.body).keyId });
  assert.equal(challenge.status, 200);
  for (const name of ['registration-page', 'login-page', 'admin-page']) {
    const page = await app.handle(name, { pageOptions: { assetsBase: '/auth/assets' } });
    assert.equal(page.status, 200);
    assert.match(page.body, /data-keyprove-ui=/);
    assert.match(page.headers['Content-Security-Policy'], /script-src 'self'/);
  }
  for (const asset of ['ui.js', 'browser.js', 'signatures.js', 'ui.css']) {
    const response = await app.handle('asset', { asset });
    assert.equal(response.status, 200);
    assert(response.body.length > 100);
  }
  assert(capture.length >= 4);
});
