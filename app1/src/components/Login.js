import { useState } from 'react';
import { login, verifyMfa } from '../auth';
import { Link, useNavigate } from 'react-router-dom';

export default function Login() {
  const navigate = useNavigate();

  // hooks at the top
  const [step,   setStep  ] = useState(0);
  const [form,   setForm  ] = useState({ identifier:'', p:'', code:'' });  const [qr,     setQr    ] = useState(null);
  const [error,  setError ] = useState('');
  const [busy,   setBusy  ] = useState(false);

  const handleSubmit = async e => {
    e.preventDefault();
    setError('');
    setBusy(true);

    if (step === 0) {
      // password step
      try {
        const res = await login(form.identifier.trim(), form.p);        if (res.qrData) setQr(res.qrData);
        setStep(1);
      } catch {
        setError('❌ Login failed. Check username/password.');
      } finally {
        setBusy(false);
      }
    } else {
      // TOTP step
      try {
        await verifyMfa(form.identifier.trim(), form.code.replace(/\s+/g,''));        // navigate directly to dashboard
        navigate('/dashboard');
      } catch {
        setError('❌ Invalid code. Try again.');
      } finally {
        setBusy(false);
      }
    }
  };

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      {step === 0 ? (
        <>
          <h2>Sign In</h2>
          <input
            placeholder="Username or email"
            value={form.identifier}
            onChange={e => setForm({ ...form, identifier: e.target.value })}            
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={form.p}
            onChange={e => setForm({ ...form, p: e.target.value })}
            required
          />
          <button disabled={busy}>Next</button>
          <Link to="/register">Need an account? Sign up</Link>
        </>
      ) : (
        <>
          <h2>Two‑Factor Authentication</h2>
          {qr && (
            <img
              src={qr}
              alt="Scan this QR in your Authenticator"
              style={styles.qr}
            />
          )}
          <input
            placeholder="6‑digit code"
            value={form.code}
            onChange={e => setForm({ ...form, code: e.target.value })}
            required
          />
          <button disabled={busy}>Verify</button>
        </>
      )}

      {error && <div style={styles.error}>{error}</div>}
    </form>
  );
}

const styles = {
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
    maxWidth: 320,
    margin: 'auto',
    paddingTop: 40,
  },
  qr: {
    width: 200,
    margin: '12px auto',
  },
  error: {
    color: 'crimson',
    minHeight: 24,
  },
};

