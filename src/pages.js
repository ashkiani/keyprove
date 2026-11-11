/** Optional, framework-neutral ready-to-use pages and static UI assets. */
import { readFileSync } from 'node:fs';

function safePath(value, fallback) {
  value ??= fallback;
  if (typeof value !== 'string' || !/^\/[A-Za-z0-9_./-]*$/.test(value) || value.includes('..') || value.includes('//')) {
    throw new TypeError('Expected a same-origin absolute path');
  }
  return value.replace(/\/$/, '');
}
function esc(value) {
  return value.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}
function page(type, { assetsBase = '/keyprove/assets', registrationStart = '/keyprove/register/start',
  registrationFinish = '/keyprove/register/finish', invitationUrl = '/keyprove/admin/invite',
  challengeUrl = '/keyprove/challenge', testUrl,
  registrationPageUrl = '/keyprove/register', loginPageUrl = '/keyprove/login' } = {}) {
  const assets = safePath(assetsBase, '/keyprove/assets');
  const attrs = {
    'data-keyprove-ui': type,
    'data-register-start': safePath(registrationStart, '/keyprove/register/start'),
    'data-register-finish': safePath(registrationFinish, '/keyprove/register/finish'),
    'data-invitation-url': safePath(invitationUrl, '/keyprove/admin/invite'),
    'data-challenge-url': safePath(challengeUrl, '/keyprove/challenge'),
    ...(testUrl === undefined ? {} : { 'data-test-url': safePath(testUrl, '/keyprove/test') })
  };
  const title = { register: 'Register a credential', login: 'Unlock credentials', admin: 'Issue an invitation' }[type];
  const regPage = safePath(registrationPageUrl, '/keyprove/register');
  const unlockPage = safePath(loginPageUrl, '/keyprove/login');
  const attrText = Object.entries(attrs).map(([k,v]) => `${k}="${esc(v)}"`).join(' ');
  return `<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<meta name="robots" content="noindex">\n<title>${title} · KeyProve</title>\n<link rel="stylesheet" href="${esc(assets)}/ui.css">\n</head>\n<body><main class="kp-shell"><h1>${title}</h1><nav class="kp-nav"><a href="${esc(regPage)}">Register</a> · <a href="${esc(unlockPage)}">Unlock</a></nav><div id="keyprove-ui" ${attrText}></div></main>\n<script type="module" src="${esc(assets)}/ui.js"></script>\n</body></html>`;
}
export const registrationPage = options => page('register', options);
export const loginPage = options => page('login', options);
export const adminPage = options => page('admin', options);

const ASSETS = Object.freeze({
  'browser.js': 'text/javascript; charset=utf-8',
  'signatures.js': 'text/javascript; charset=utf-8',
  'ui.js': 'text/javascript; charset=utf-8',
  'ui.css': 'text/css; charset=utf-8'
});
export function getUiAsset(name) {
  if (!Object.hasOwn(ASSETS, name)) throw new TypeError('Unknown KeyProve UI asset');
  return { contentType: ASSETS[name], body: readFileSync(new URL(`./${name}`, import.meta.url), 'utf8') };
}
