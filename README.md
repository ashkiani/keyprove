# KeyProve

KeyProve provides proof-of-possession authentication for HTTP requests using [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html). Clients sign each protected request with a private key; the server verifies the signature with a registered public key and rejects reused challenges. The browser module can generate credentials, encrypt private keys with a user-provided password, and store encrypted credentials in IndexedDB.

The package is **independent of any database or web framework**. Applications supply their own key lookup, enrollment policy, permission checks, and challenge storage. KeyProve does not require bearer sessions or shared API keys.

> **Security status:** This is a narrowly scoped RFC 9421 implementation, not a general-purpose HTTP Message Signatures library. It has not undergone an independent security audit. Review the [security considerations](#security-considerations) before deploying it in a security-sensitive environment.

## Requirements

- Node.js 20 or newer for server-side verification.
- A modern browser with Web Crypto, IndexedDB, and ES module support for browser credential management.
- HTTPS in deployed applications (localhost HTTP is suitable for local development).
- No third-party runtime dependencies.

## Installation

```sh
npm install @ashkiani/keyprove
```

Node.js imports:

```js
import { createVerifier, createMemoryChallengeStore } from '@ashkiani/keyprove/server';
```

For browser code compiled with a bundler:

```js
import { generateCredential, unlockCredential, signedFetch } from '@ashkiani/keyprove/browser';
```

For **vanilla JavaScript without a bundler**, serve `src/browser.js` and `src/signatures.js` from the installed package under the same directory on your application's own origin, then import the browser module using your site's URL (for example, `/vendor/keyprove/browser.js`). Do not serve the entire `node_modules` directory publicly.

## Authentication flow

1. **Enrollment:** Your application authorizes the user or device. The browser generates an ECDSA P-256 key pair, encrypts the private key with a password, and provides the public key for registration. Your server verifies the enrollment proof and stores the key and account association.
2. **Unlock:** The browser decrypts the local credential using the password and imports a non-extractable signing key. Neither the password nor the private key is sent to the server.
3. **Challenge:** Before a protected request, the client asks the server for a fresh challenge associated with its registered key ID.
4. **Request signing:** The client signs the request's method, target URI, required content fields, and RFC 9421 signature parameters, including the challenge.
5. **Verification:** The server resolves the public key, validates the signature and request body, and atomically consumes the one-time challenge. Your application then decides whether the authenticated identity is authorized to perform the operation.

## Server usage

```js
import {
  createVerifier,
  createMemoryChallengeStore
} from '@ashkiani/keyprove/server';

// Example storage adapter. Replace with your application's registered-key store.
const registeredKeys = new Map();
// Each record must contain at least:
// { publicKey: <P-256 public JWK>, subject: <application user ID> }

const verifier = createVerifier({
  expectedOrigin: 'https://example.com',
  resolveKey: async keyId => registeredKeys.get(keyId) ?? null,
  challengeStore: createMemoryChallengeStore()
});
```

Connect the verifier to your own HTTP routes:

```js
// Unauthenticated challenge endpoint: receive { keyId } from the client.
const challenge = await verifier.issueChallenge(keyId);
// Respond with JSON: { nonce, expiresInSeconds }.

// Protected endpoint: supply the original raw HTTP request body bytes.
const identity = await verifier.verifyNodeRequest(req, rawBody);
// identity.subject and identity.keyId were authenticated.
// Your application must still enforce authorization before performing the operation.
```

The code above illustrates the integration points; it is **not a complete HTTP server**. The caller must implement routing, registration, authorization, request-body capture, error handling, and rate limits. `rawBody` must contain the exact received body bytes; serializing an already parsed JSON object is not equivalent.

### Public key registration

KeyProve does not decide whether someone may register. Once your application has independently verified enrollment authorization, use:

```js
import {
  keyIdFromPublicKey,
  verifyEnrollmentProof
} from '@ashkiani/keyprove/server';

// Verify the signed proof along with your OWN invitation or enrollment checks.
const valid = verifyEnrollmentProof({
  email, origin: 'https://example.com', token, challenge, publicKey, signature
});

if (valid) {
  const keyId = keyIdFromPublicKey(publicKey);
  // Atomically consume the authorized, short-lived enrollment token/challenge.
  // Store { keyId, publicKey, subject } in your application's trusted key store.
}
```

`verifyEnrollmentProof()` checks possession of the matching private key, **not** ownership of the email address or permission to enroll. Your application must independently bind and validate the enrollment token, challenge, and identity and ensure they cannot be reused. The enrollment proof is application-specific, not part of RFC 9421.

### Challenge store

The default `createMemoryChallengeStore()` is suitable only for a **single Node.js process**. For a clustered or multi-instance deployment, provide a shared store with atomic consumption:

```js
{
  async save(nonce, { keyId, expiresAt }) { /* persist challenge */ },
  async consume(nonce) { /* return once, then delete atomically; otherwise null */ }
}
```

An ordinary read followed by delete is **not sufficient** across concurrent processes. The verifier also checks expiry and key association. Rate-limit challenge issuance and enrollment endpoints in the host application.

## Browser usage

The examples below use an import path for files served from your own website; adapt the URL to match your deployment.

```js
import {
  generateCredential,
  saveCredential,
  getCredential,
  unlockCredential,
  signEnrollment,
  signedFetch
} from '/vendor/keyprove/browser.js';

// After the application authorizes enrollment:
const { bundle, publicKey, privateKey } = await generateCredential({
  email: 'alice@example.com',
  password: userSuppliedPassword
});
await saveCredential(bundle); // Persists encrypted credential data in IndexedDB.

// Obtain { token, challenge } from your application's enrollment endpoint.
// Send the publicKey and this signature to its enrollment-completion endpoint.
const signature = await signEnrollment({
  email: bundle.email,
  origin: location.origin,
  token,
  challenge,
  publicKey,
  privateKey
});

// On a later visit, unlock the locally stored encrypted credential:
const stored = await getCredential('alice@example.com');
const unlockedKey = await unlockCredential(stored, userSuppliedPassword);

// Signed request: automatically obtains and signs a single-use challenge.
const response = await signedFetch({
  url: `${location.origin}/api/private/me`,
  challengeUrl: `${location.origin}/api/challenge`,
  method: 'GET',
  privateKey: unlockedKey,
  publicKey: stored.publicKey
});
```

`signEnrollment()` **does not send** the enrollment request. Your application sends the returned signature, public key, and required enrollment fields to its own backend. To sign a request manually, use `signRequest({ url, method, body, nonce, privateKey, publicKey })`, then transmit the exact returned body and headers without modification.

For encrypted credential backup and recovery, use `validateCredential()`, `listCredentials()`, and `deleteCredential()` along with JSON export/import of the encrypted credential bundle. The backup format is compatible with version-1 KeyProve Lab backups; it does **not** automatically migrate IndexedDB entries between different browser origins.

## Supported signing profile

KeyProve implements a deliberately constrained request-signing profile:

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html): `Signature-Input` and `Signature` HTTP fields; signature label `sig1`; `ecdsa-p256-sha256`.
- Covered components: `@method` and `@target-uri`, with `content-type` and signed [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) `content-digest` for methods other than GET and HEAD (including empty bodies).
- Signed signature parameters: `created`, `nonce`, `keyid`, `alg`, and `tag=keyprove-v1`.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html): JWK thumbprints for public-key IDs.
- Cryptographically random 32-byte challenges, 60-second default lifetime, and mandatory one-time use.
- Password-protected browser credential backups using PBKDF2-HMAC-SHA256 (600,000 iterations by default) and AES-256-GCM. Unlocked signing keys are imported as non-extractable Web Crypto keys.

Other conformant RFC 9421 signatures may be rejected if they fall outside this application's required profile. The library does not provide arbitrary-algorithm verification, response signatures, or a general-purpose HTTP Structured Fields parser.

## Security considerations

- **Authentication is not authorization.** Applications must independently manage registration eligibility, accounts, permissions, revocation, and recovery.
- **TLS is still required.** HTTP signatures do not protect against malicious scripts served by a compromised origin, or active interception of unprotected web traffic.
- **Non-extractable does not mean inaccessible.** Malicious JavaScript on the same origin can use an unlocked key to sign requests. A compromised device or browser remains a serious threat.
- **Encrypted credential backups can be attacked offline.** Their security depends on the password and its key derivation settings. Use strong, unique passwords.
- **Replay resistance depends on atomic challenge consumption.** Use shared, atomic challenge storage when multiple server instances are involved.
- **The deployment's externally visible origin matters.** Configure trusted host/proxy behavior carefully; do not blindly trust attacker-supplied forwarding headers.
- **Every protected request requires an extra challenge round trip.** Applications must plan for that latency and appropriately handle timeouts and errors.
- **This implementation is not independently audited.** Its RFC 9421 support is limited to the documented signing and verification profile.

## Development tests

```sh
npm test
npm pack --dry-run
```

The automated tests cover credential encryption/unlocking, key compatibility, the published RFC 9421 ECDSA test vector, signed requests, replay rejection, and tampering detection.

## License

MIT. See [LICENSE](LICENSE).
