# KeyProve

KeyProve is a framework-independent proof-of-possession authentication library for Node.js and browsers. It uses [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html): the client signs each protected request with a private key and the server verifies it using a registered public key. Single-use challenges prevent replay of previously accepted requests.

KeyProve also supplies optional end-to-end enrollment: administrator-issued invitations, browser-generated and password-encrypted private keys, public-key registration, and minimal registration, invitation, and unlock interfaces. The host application decides which routes to expose and what authenticated users are authorized to do.

**No database, HTTP framework, or frontend framework is required.** Persistence and HTTP communication are provided through callbacks. The package has no third-party runtime dependencies.

> **Security:** KeyProve implements a constrained RFC 9421 signing profile, not every optional RFC feature. It has not undergone an independent security audit. Use HTTPS outside localhost, rate-limit public endpoints, and review the [security considerations](#security-considerations) before production use.

## Requirements

- Node.js 20 or newer on the server.
- Modern browsers with Web Crypto, IndexedDB, and ES modules for browser credentials and optional UI.
- A trustworthy browser origin and HTTPS for deployment. Localhost HTTP is suitable for local development.

## Install

```sh
npm install @ashkiani/keyprove
```

```js
import { createKeyprove, createMemoryStorage } from '@ashkiani/keyprove/server';
```

The browser module is available as `@ashkiani/keyprove/browser`, and the optional browser UI as `@ashkiani/keyprove/ui`. They can be bundled or served on the application's origin as described below.

## Complete flow

1. **Invitation:** An administrator authorizes an email address. KeyProve generates a random invitation token, stores **only its SHA-256 hash** through the host's storage callback, and returns the plaintext token once for the administrator to deliver.
2. **Enrollment:** The user enters the email and token. KeyProve checks the saved invitation and issues a short-lived enrollment token and challenge.
3. **Browser keys:** KeyProve's browser code creates an ECDSA P-256 key pair, encrypts the private key with a password-derived AES-256-GCM key, and signs the enrollment data. The private key and password are not sent to the server.
4. **Registration:** KeyProve verifies the proof, atomically consumes the invitation and enrollment token, and saves the registered public key through a callback.
5. **Unlock:** The browser unlocks its encrypted private key into a non-extractable Web Crypto `CryptoKey` in memory.
6. **Protected request:** The browser requests a one-time challenge and signs the actual HTTP request. KeyProve verifies the signature and atomically consumes the challenge; the host application then applies its authorization policy.

The encrypted credential can be exported and imported on another browser or device. Deleting a local credential does **not** revoke its registered public key on the server.

## Server configuration

```js
const keyprove = createKeyprove({
  adminToken: process.env.KEYPROVE_ADMIN_TOKEN,
  // expectedOrigin: 'https://api.example.com', // optional
  storage: {
    async save(type, id, record) { /* insert record; reject duplicate ID */ },
    async get(type, id) { /* return record or null */ },
    async consume(type, id) { /* atomically return-and-delete, or null */ }
  }
});
```

The storage callbacks are **application-supplied**, so they can use MongoDB, SQL, files, or another system. KeyProve defines its records and controls expiration and single use. Supported record types are `invitation`, `enrollment`, `publicKey`, and `challenge`.

| Callback | Required behavior |
|---|---|
| `save(type, id, record)` | **Create-only:** do not overwrite existing records with the same `(type, id)`. Reject duplicates. |
| `get(type, id)` | Return the stored record or `null`, without mutating it. |
| `consume(type, id)` | **Atomically** remove and return the record once, or return `null`. This must be atomic across all server processes sharing the same storage. |

KeyProve stores a hash of the plaintext invitation token. Your database does not need to store recoverable invitation codes. The administrator must copy or deliver the code when issued. Record expiry is enforced by KeyProve even if the storage layer has no TTL mechanism.

`createMemoryStorage()` is included for single-process demonstrations and testing. It loses registrations on restart and must **not** be used as a persistent or multi-instance authentication store.

### Operations

```js
// Must be called only after the host authorizes an admin request.
const invitation = await keyprove.issueRegistrationToken({
  email: 'alice@example.com',
  adminToken: process.env.KEYPROVE_ADMIN_TOKEN
});
// { email, token, expiresAt } — show the token to the administrator only.

const start = await keyprove.startRegistration({
  email, invitationToken, origin: 'https://api.example.com'
});
// { token, challenge, origin, expiresInSeconds }

const registration = await keyprove.finishRegistration({
  email, token: start.token, challenge: start.challenge, publicKey, signature
});
// { email, keyId }; KeyProve calls storage.save('publicKey', keyId, record).

const challenge = await keyprove.issueChallenge(keyId);
const identity = await keyprove.verifyRequest({
  method, targetUri, headers, rawHeaders, rawBody
});
// identity.subject, identity.keyId, identity.record
```

The registration signature is created by `signEnrollment()` in the browser. Applications should never use the invitation code as an authentication credential for protected requests.

### No hardcoded routes or response format dependencies

The host can invoke KeyProve operations directly or use `handle()`, which accepts generic request and response callbacks:

```js
// Your application's route handler determines when this is called.
await keyprove.handle('registration-start', {
  readRequest: async () => ({
    method: req.method,
    headers: req.headers,
    body: req.body,                        // Parsed JSON or JSON text
    origin: 'https://api.example.com'      // Trusted backend origin
  }),
  sendResponse: ({ status, headers, body }) => {
    res.status(status).set(headers).send(body);  // Express example only
  }
});
```

Supported `handle()` actions are `admin-invite`, `registration-start`, `registration-finish`, `challenge`, `registration-page`, `login-page`, `admin-page`, and `asset`. The administrator invitation action expects `Authorization: Bearer <admin token>`; the token must be provided by the host from an appropriate secret source such as an environment variable. Do not accept an admin token in a URL query string.

`handle()` returns `{ status, headers, body }` if no `sendResponse` callback is supplied. It neither defines routes nor creates an HTTP server. For a runnable example using only Node.js built-ins, see [examples/server.js](examples/server.js).

### Per-request verification without a fixed expected origin

`expectedOrigin` is optional. KeyProve **always** requires the RFC 9421 signature to cover `@method` and `@target-uri` and always enforces one-time challenges. If configured, `expectedOrigin` additionally restricts signed requests to that backend origin.

When omitted, the application must provide the **trusted absolute target URI**:

```js
const identity = await keyprove.verifyNodeRequest(req, rawBody, {
  targetUri: `https://api.example.com${req.url}` // Based on trusted server configuration
});
```

Do not construct that URI by blindly trusting `Host`, `Origin`, `Forwarded`, or `X-Forwarded-*` headers. `rawBody` must be the **exact received bytes**. KeyProve does not decide whether a route requires authentication, and it does not enforce application-specific user permissions.

## Ready-to-use pages and browser code

Optional pages include:

- **Invitation page:** Administrator enters their authorization token and the email address; the newly issued invitation is displayed once.
- **Registration page:** User enters email, invitation, and a password. Browser generates and encrypts keys; server verifies enrollment and stores the public key.
- **Unlock page:** User selects a credential stored in IndexedDB and enters its password. Local encrypted key export, import, and deletion are also available.

The host chooses the routes. To serve a registration page through the response callback:

```js
await keyprove.handle('registration-page', {
  pageOptions: {
    assetsBase: '/auth/assets',
    registrationStart: '/auth/register/start',
    registrationFinish: '/auth/register/finish'
  },
  sendResponse: ({ status, headers, body }) => res.status(status).set(headers).send(body)
});
```

Serve the JavaScript and stylesheet through the same callback interface:

```js
await keyprove.handle('asset', {
  asset: 'ui.js', // Also browser.js, signatures.js, ui.css
  sendResponse: ({ status, headers, body }) => res.status(status).set(headers).send(body)
});
```

The HTML page imports `ui.js`, which imports `browser.js` and `signatures.js`. Serve all these assets at the configured `assetsBase` **on the same origin as the page**. Do not expose all of `node_modules` as a web-accessible directory.

### Embed the UI in an existing frontend

The optional browser UI is also available as plain ES modules (no React or bundler required):

```js
import { mountLogin, mountRegistration } from '/auth/assets/ui.js';

mountLogin({
  container: document.getElementById('login'),
  onUnlock: ({ email, privateKey, publicKey }) => {
    // Keep privateKey in page memory and pass it to signedFetch().
  },
  onLock: () => {
    // Clear the host application's reference to the unlocked key.
  }
});

mountRegistration({
  container: document.getElementById('register'),
  startUrl: '/auth/register/start',
  finishUrl: '/auth/register/finish'
});
```

`mountAdmin()` is also available. For custom interfaces, import `generateCredential()`, `unlockCredential()`, `saveCredential()`, `signEnrollment()`, and `signedFetch()` from `@ashkiani/keyprove/browser` instead.

The browser generates the key pair; **the Node server never receives the plaintext private key or the unlock password**. The optional unlock page keeps its key available in that page's memory. For an existing single-page frontend, use the embedded `onUnlock` callback so the host app can use the key for future signed requests without navigating away. Encrypted IndexedDB storage is origin-specific.

## Runnable local example

The repository includes a small HTTP application under `examples/server.js` that uses the public package API and in-memory storage for testing:

```sh
npm run demo
```

Visit `http://localhost:3130/auth/admin`, enter the administrator token printed in the terminal, issue an invitation, then open `/auth/register` to register and `/auth/login` to unlock and test a signed request. Restarting this example clears all registrations.

Run automated tests with `npm test`.

## Existing lower-level API

The v0.1.0 API remains exported:

- `@ashkiani/keyprove/server`: `createVerifier()`, `createMemoryChallengeStore()`, `verifyEnrollmentProof()`, `keyIdFromPublicKey()` and `KeyproveError`.
- `@ashkiani/keyprove/browser`: `generateCredential()`, `unlockCredential()`, `saveCredential()`, `getCredential()`, `listCredentials()`, `deleteCredential()`, `validateCredential()`, `signEnrollment()`, `signRequest()`, `signedFetch()`, `keyIdFromPublicKey()`.
- `@ashkiani/keyprove/signatures`: the existing RFC 9421 signature helpers.

The original encrypted credential backup format and existing RFC 9421 signing profile are unchanged.

## Security considerations

- **Invitation authentication:** Admin-token checks do not replace network protections and rate limiting. Use a long randomly generated admin token from a protected server-side secret, transmit it over HTTPS, and do not expose it to non-admin users. Protect administrative and registration endpoints against abuse.
- **Enrollment is not email ownership verification:** Possession of an invitation token authorizes enrollment for the associated email; KeyProve does not deliver an email or verify that its recipient owns that mailbox. Choose a trusted delivery method.
- **Persistent atomic operations:** `consume()` must be atomic across instances. `save()` must enforce uniqueness; database outages or failures between consuming an invitation and storing a key can require the administrator to issue another invitation. Multi-record transactions are not provided by this generic callback interface.
- **Password-protected browser keys:** Encrypted credential backups are vulnerable to offline password guessing if passwords are weak. `extractable: false` prevents ordinary Web Crypto export but does not stop malicious same-origin code from using an unlocked key.
- **HTTPS and JavaScript integrity:** Use HTTPS in deployed environments. Signed requests do not protect against compromised frontend JavaScript, a compromised server, or an attacker controlling the user's device.
- **Signed target integrity:** Preserve the exact request content bytes and supply a trusted absolute target URI when `expectedOrigin` is omitted. Do not confuse the backend's intended destination with browser `Origin`/CORS policy.
- **Replay and concurrency:** One challenge per protected request; a valid signature is verified before consuming its nonce. External storage must enforce atomic consumption.
- **Authorization and revocation:** Successful cryptographic authentication does not imply permission to perform an operation. The host application decides access policy and how keys are revoked. Local deletion does not revoke server-side keys.
- **Deployment:** The packaged pages are optional and minimal. Applications are responsible for secure hosting, CSRF considerations for any cookie-authenticated administrative features, input/body limits, rate limiting, monitoring, and origin policy.

## Standards

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html): HTTP Message Signatures. KeyProve supports one `sig1` request signature with ECDSA P-256/SHA-256 and mandatory metadata (`created`, `nonce`, `keyid`, `alg`, `tag`).
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html): signed `Content-Digest` for request bodies.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html): JWK thumbprints used for key IDs.

KeyProve enforces a stricter request-signing profile than the general-purpose RFC, and does not implement all possible algorithms, HTTP components, or response signatures. It is not an independently audited authentication product.

## License

MIT. See [LICENSE](LICENSE).
