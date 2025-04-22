// src/auth.js
import { jwtDecode } from 'jwt-decode';    // named import
const API = process.env.REACT_APP_AUTH || 'http://localhost:4000';

/** 
 * Login step 1: POST username/password.
 * Throws if not 200 OK.
 * Returns { mfaRequired, qrData? } on success.
 */
export async function login(identifier, password) {
  const r = await fetch(`${API}/login`, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ identifier, password })
  });
  if (!r.ok) {
    let err = 'Login failed';
    try { ({ msg: err } = await r.json()); } catch {}
    throw new Error(err);
  }
  return r.json();
}

/** 
 * Login step 2: POST username + TOTP.
 * Throws if not 200 OK.
 * Stores JWT on success.
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


/** Returns the raw JWT or null */
export function getToken() {
  return localStorage.getItem('jwt');
}

/** Clears JWT and notifies listeners */
export function logout() {
  localStorage.removeItem('jwt');
  window.dispatchEvent(new Event('sso-logout'));
}

/** Decodes token payload or returns null */
export function userInfo() {
  const t = getToken();
  return t ? jwtDecode(t) : null;
}
