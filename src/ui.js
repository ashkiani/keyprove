/** Optional vanilla-JS KeyProve user interfaces; execute under your app's origin. */
import {
  generateCredential, saveCredential, getCredential, listCredentials, deleteCredential,
  unlockCredential, validateCredential, signEnrollment, signedFetch
} from './browser.js';

function element(tag, attrs = {}, text) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'className') el.className = v;
    else if (k === 'type' || k === 'name' || k === 'placeholder' || k === 'accept' || k === 'minLength') el[k] = v;
    else el.setAttribute(k, v);
  }
  if (text !== undefined) el.textContent = text;
  return el;
}
function field(form, labelText, type = 'text', opts = {}) {
  const label = element('label', {}, labelText);
  const input = element('input', { type, ...opts });
  label.append(input);
  form.append(label);
  return input;
}
function status(container) {
  const msg = element('p', { className: 'kp-status', role: 'status', 'aria-live': 'polite' });
  container.append(msg);
  return (text, isError = false) => {
    msg.textContent = String(text);
    msg.classList.toggle('kp-error', isError);
  };
}
function downloadBundle(bundle) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
  const a = element('a', { href: url, download: `keyprove-${bundle.email}.json` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
async function postJson(url, body, headers = {}) {
  const response = await fetch(url, { method: 'POST', cache: 'no-store', credentials: 'omit',
    headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function requireContainer(container) {
  if (!(container instanceof Element)) throw new TypeError('A DOM container is required');
  container.replaceChildren();
  return container;
}

/** Existing sites can embed registration, supplying their own endpoints. */
export function mountRegistration({ container, startUrl, finishUrl, onRegistered } = {}) {
  requireContainer(container);
  const form = element('form', { className: 'kp-form' });
  const email = field(form, 'Email', 'email', { required: '' });
  const invite = field(form, 'Invitation token', 'text', { required: '', autocomplete: 'off' });
  const password = field(form, 'Password (at least 12 characters)', 'password', { required: '', minLength: 12, autocomplete: 'new-password' });
  const confirm = field(form, 'Confirm password', 'password', { required: '', minLength: 12, autocomplete: 'new-password' });
  const submit = element('button', { type: 'submit' }, 'Register');
  form.append(submit);
  container.append(form);
  const inform = status(container);
  form.addEventListener('submit', async e => {
    e.preventDefault();
    submit.disabled = true;
    inform('Registering…');
    let created;
    try {
      if (password.value !== confirm.value) throw new Error('Passwords do not match');
      const registrationOrigin = new URL(finishUrl, location.href).origin;
      const start = await postJson(startUrl, { email: email.value, invitationToken: invite.value });
      created = await generateCredential({ email: email.value, password: password.value });
      const signature = await signEnrollment({ email: created.bundle.email, origin: registrationOrigin,
        token: start.token, challenge: start.challenge, publicKey: created.publicKey, privateKey: created.privateKey });
      const result = await postJson(finishUrl, { email: created.bundle.email, token: start.token,
        challenge: start.challenge, publicKey: created.publicKey, signature });
      try { await saveCredential(created.bundle); }
      catch (storageError) {
        // The server has already enrolled this key. Never silently lose the credential.
        downloadBundle(created.bundle);
        throw new Error(`Registered, but local storage failed. An encrypted backup download was started: ${storageError.message}`);
      }
      password.value = confirm.value = invite.value = '';
      inform(`Registered ${result.email}. The encrypted credential is stored in this browser.`);
      onRegistered?.({ ...result, bundle: created.bundle });
    } catch (err) { inform(err.message, true); }
    finally { submit.disabled = false; }
  });
  return { destroy: () => container.replaceChildren() };
}

/** An unlocked CryptoKey is returned to the embedding application, in memory. */
export function mountLogin({ container, onUnlock, onLock, challengeUrl, testUrl } = {}) {
  requireContainer(container);
  let unlocked = null;
  const form = element('form', { className: 'kp-form' });
  const label = element('label', {}, 'Stored credential');
  const select = element('select', { required: '' });
  label.append(select); form.append(label);
  const password = field(form, 'Password', 'password', { required: '' });
  form.append(element('button', { type: 'submit' }, 'Unlock'));
  container.append(form);
  const actions = element('div', { className: 'kp-actions' });
  const refreshButton = element('button', { type: 'button' }, 'Refresh');
  const lockButton = element('button', { type: 'button' }, 'Lock');
  const exportButton = element('button', { type: 'button' }, 'Export encrypted backup');
  const deleteButton = element('button', { type: 'button' }, 'Delete local credential');
  const fileInput = element('input', { type: 'file', accept: 'application/json,.json' });
  actions.append(refreshButton, lockButton, exportButton, deleteButton, fileInput);
  container.append(actions);
  const inform = status(container);
  const refresh = async () => {
    const bundles = await listCredentials();
    select.replaceChildren(...bundles.map(bundle => {
      const option = element('option', { value: bundle.email }, bundle.email);
      option.value = bundle.email;
      return option;
    }));
    if (!bundles.length) inform('No stored credentials. Register or import an encrypted backup.');
    return bundles;
  };
  form.addEventListener('submit', async e => {
    e.preventDefault();
    try {
      const bundle = await getCredential(select.value);
      if (!bundle) throw new Error('Credential not found');
      const privateKey = await unlockCredential(bundle, password.value);
      unlocked = { email: bundle.email, publicKey: bundle.publicKey, privateKey };
      password.value = '';
      inform(`Unlocked ${bundle.email}. This key is held in memory in the current page.`);
      onUnlock?.(unlocked);
      if (testUrl && challengeUrl) {
        const button = element('button', { type: 'button' }, 'Test signed request');
        const existing = container.querySelector('[data-kp-test]');
        existing?.remove();
        button.setAttribute('data-kp-test', '');
        button.addEventListener('click', async () => {
          try {
            const response = await signedFetch({ url: new URL(testUrl, location.href).href,
              challengeUrl: new URL(challengeUrl, location.href).href, ...unlocked });
            inform(`Signed request: HTTP ${response.status} — ${await response.text()}`);
          } catch (err) { inform(err.message, true); }
        });
        container.append(button);
      }
    } catch (err) { inform(err.message, true); }
  });
  refreshButton.addEventListener('click', () => refresh().catch(err => inform(err.message, true)));
  lockButton.addEventListener('click', () => { unlocked = null; onLock?.();
    container.querySelector('[data-kp-test]')?.remove();
    inform('Locked. Unlock the credential again to sign requests.'); });
  exportButton.addEventListener('click', async () => {
    try { const bundle = await getCredential(select.value); if (!bundle) throw new Error('Select a credential'); downloadBundle(bundle); }
    catch (err) { inform(err.message, true); }
  });
  deleteButton.addEventListener('click', async () => {
    try { if (!select.value) throw new Error('Select a credential');
      await deleteCredential(select.value); unlocked = null; onLock?.();
      container.querySelector('[data-kp-test]')?.remove(); await refresh(); inform('Local credential deleted. Server-side revocation is separate.'); }
    catch (err) { inform(err.message, true); }
  });
  fileInput.addEventListener('change', async () => {
    try {
      if (!fileInput.files?.[0]) return;
      const bundle = validateCredential(JSON.parse(await fileInput.files[0].text()));
      await saveCredential(bundle); await refresh(); select.value = bundle.email;
      inform('Encrypted credential imported. Unlock it with its password.');
    } catch (err) { inform(err.message, true); }
    finally { fileInput.value = ''; }
  });
  refresh().catch(err => inform(err.message, true));
  return { destroy: () => container.replaceChildren(), getUnlocked: () => unlocked };
}

export function mountAdmin({ container, invitationUrl } = {}) {
  requireContainer(container);
  const form = element('form', { className: 'kp-form' });
  const adminToken = field(form, 'Administrator token', 'password', { required: '', autocomplete: 'off' });
  const email = field(form, 'Email to invite', 'email', { required: '' });
  form.append(element('button', { type: 'submit' }, 'Issue invitation'));
  container.append(form);
  const inform = status(container);
  const output = element('pre', { className: 'kp-token' });
  container.append(output);
  form.addEventListener('submit', async e => {
    e.preventDefault(); output.textContent = '';
    try {
      const result = await postJson(invitationUrl, { email: email.value },
        { Authorization: `Bearer ${adminToken.value}` });
      output.textContent = `Email: ${result.email}\nInvitation: ${result.token}\nExpires: ${result.expiresAt}`;
      adminToken.value = '';
      inform('Invitation created. Copy the token now; only its hash is stored.');
    } catch (err) { inform(err.message, true); }
  });
  return { destroy: () => container.replaceChildren() };
}

if (typeof document !== 'undefined') {
  const initialize = () => {
    const root = document.querySelector('[data-keyprove-ui]');
    if (!root) return;
    const config = root.dataset;
    if (config.keyproveUi === 'register') mountRegistration({ container: root,
      startUrl: config.registerStart, finishUrl: config.registerFinish });
    else if (config.keyproveUi === 'login') mountLogin({ container: root,
      challengeUrl: config.challengeUrl, testUrl: config.testUrl });
    else if (config.keyproveUi === 'admin') mountAdmin({ container: root, invitationUrl: config.invitationUrl });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
  else initialize();
}
