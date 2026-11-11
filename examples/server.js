/** Fully runnable localhost demonstration of the published high-level API. */
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { createKeyprove, createMemoryStorage } from '@ashkiani/keyprove/server';

const port = 3130;
const origin = `http://localhost:${port}`;
const adminToken = randomBytes(24).toString('base64url'); // Demo only; production: use a server secret.
const auth = createKeyprove({ storage: createMemoryStorage(), adminToken }); // expectedOrigin deliberately omitted.
const pageOptions = {
  assetsBase: '/auth/assets', registrationStart: '/auth/register/start',
  registrationFinish: '/auth/register/finish', invitationUrl: '/auth/admin/invite',
  challengeUrl: '/auth/challenge', testUrl: '/private/me',
  registrationPageUrl: '/auth/register', loginPageUrl: '/auth/login'
};

function send(res, { status, headers, body }) {
  res.writeHead(status, headers);
  res.end(body);
}
async function requestBody(req) {
  const chunks = []; let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 32_768) throw new Error('Request body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
const paths = new Map([
  ['/auth/register', 'registration-page'], ['/auth/login', 'login-page'],
  ['/auth/admin', 'admin-page'], ['/auth/register/start', 'registration-start'],
  ['/auth/register/finish', 'registration-finish'], ['/auth/admin/invite', 'admin-invite'],
  ['/auth/challenge', 'challenge']
]);

createServer(async (req, res) => {
  try {
    const url = new URL(req.url, origin);
    if (url.pathname === '/' && req.method === 'GET') {
      res.writeHead(302, { Location: '/auth/admin', 'Cache-Control': 'no-store' });
      return res.end();
    }
    const action = paths.get(url.pathname);
    if (action || (req.method === 'GET' && url.pathname.startsWith('/auth/assets/'))) {
      const body = (action && !action.endsWith('-page')) ? await requestBody(req) : Buffer.alloc(0);
      return auth.handle(action ?? 'asset', {
        asset: url.pathname.split('/').pop(), pageOptions,
        readRequest: () => ({ method: req.method, headers: req.headers,
          body: body.toString('utf8'), origin }),
        sendResponse: result => send(res, result)
      });
    }
    if (url.pathname === '/private/me' && req.method === 'GET') {
      const identity = await auth.verifyNodeRequest(req, Buffer.alloc(0), {
        targetUri: `${origin}${req.url}` // trusted origin from server config, not Host header
      });
      return send(res, { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        body: JSON.stringify({ authenticated: true, subject: identity.subject, keyId: identity.keyId }) });
    }
    if (url.pathname === '/private/echo' && req.method === 'POST') {
      const rawBody = await requestBody(req);
      const identity = await auth.verifyNodeRequest(req, rawBody, { targetUri: `${origin}${req.url}` });
      return send(res, { status: 200, headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject: identity.subject, text: rawBody.toString('utf8') }) });
    }
    send(res, { status: 404, headers: { 'Content-Type': 'text/plain' }, body: 'Not found' });
  } catch (error) {
    send(res, { status: 401, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      body: JSON.stringify({ error: error.code || 'REQUEST_REJECTED' }) });
  }
}).listen(port, '127.0.0.1', () => {
  process.stdout.write(`KeyProve demo: ${origin}/auth/admin\n`);
  process.stdout.write(`Admin token (local demo only): ${adminToken}\n`);
  process.stdout.write(`Register: ${origin}/auth/register\nUnlock: ${origin}/auth/login\n`);
});
