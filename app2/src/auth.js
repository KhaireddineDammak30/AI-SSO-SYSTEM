// app2/src/auth.js
import { jwtDecode } from 'jwt-decode';
const API = process.env.REACT_APP_AUTH || 'http://localhost:4000';

/**
 * Step 1: send identifier (username or email) + password.
 * Throws if not 200 OK.
 */
export async function login(identifier, password) {
  const r = await fetch(`${API}/login`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ identifier, password })
  });
  if (!r.ok) {
    let err = 'Login failed';
    try { ({ msg: err } = await r.json()); } catch {}
    throw new Error(err);
  }
  return r.json(); // { mfaRequired, qrData? }
}

/**
 * Step 2: send the same identifier + TOTP token.
 * Throws if not 200 OK.
 */
export async function verifyMfa(identifier, code) {
  const r = await fetch(`${API}/verify-mfa`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ identifier, token: code })
  });
  if (!r.ok) {
    let err = 'TOTP verification failed';
    try { ({ msg: err } = await r.json()); } catch {}
    throw new Error(err);
  }
  const { token } = await r.json();
  localStorage.setItem('jwt', token);
  window.dispatchEvent(new Event('sso-login'));
  return token;
}

export function getToken() {
  return localStorage.getItem('jwt');
}

export function logout() {
  localStorage.removeItem('jwt');
  window.dispatchEvent(new Event('sso-logout'));
}

export function userInfo() {
  const t = getToken();
  return t ? jwtDecode(t) : null;
}
