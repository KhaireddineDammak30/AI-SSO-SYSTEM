import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
const API = process.env.REACT_APP_AUTH || 'http://localhost:4000';

export default function Register() {
  const navigate = useNavigate();
  const [username, setUsername]   = useState('');
  const [email,      setEmail]      = useState('');
  const [password, setPassword]   = useState('');
  const [confirm,  setConfirm]    = useState('');
  const [department, setDepartment] = useState('cloud');
  const [role,      setRole]      = useState('engineer');
  const [idNumber,  setIdNumber]  = useState('');
  const [error, setError]         = useState('');
  const [message, setMessage]     = useState('');
  const [busy, setBusy]           = useState(false);

  const handleSubmit = async e => {
    e.preventDefault(); setError(''); setMessage('');
    if (password!==confirm) { setError('⚠️ Passwords do not match.'); return; }
    if (!/^\d{8}$/.test(idNumber)) {
      setError('⚠️ ID Number must be exactly 8 digits.'); return;
    }
    setBusy(true);
    try {
      const res = await fetch(`${API}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username:   username.trim(),
          email:      email.trim().toLowerCase(),
          password,
          department,
          role,
          idNumber
        })
      });

      if (res.ok) {
        setMessage('✅ Account created! Please log in.');
        setTimeout(() => navigate('/login'), 1200);
      } else if (res.status === 409) {
        setError('⚠️ Username already taken.');
      } else {
        const txt = await res.text();
        setError(`❌ Registration failed (${res.status}): ${txt}`);
      }
    } catch (err) {
      setError(`❌ Cannot connect to auth‑server at ${API}`);
      console.error(err);
    } finally {
      setBusy(false);
    }
  };


  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      <h2>Create Account</h2>
      <input
       type="email"
       placeholder="Email address"
       value={email}
       onChange={e => setEmail(e.target.value)}
       required
     />
      <input placeholder="Username" value={username} onChange={e=>setUsername(e.target.value)} required/>
      <input type="password" placeholder="Password" value={password} onChange={e=>setPassword(e.target.value)} required/>
      <input type="password" placeholder="Confirm Password" value={confirm} onChange={e=>setConfirm(e.target.value)} required/>
      <label>Department:
        <select value={department} onChange={e=>setDepartment(e.target.value)}>
          <option value="cloud">Cloud</option>
          <option value="network">Network</option>
          <option value="security">Security</option>
          <option value="maintenance">Maintenance</option>
        </select>
      </label>
      <label>Role:
        <select value={role} onChange={e=>setRole(e.target.value)}>
          <option value="manager">Manager</option>
          <option value="head">Head of Department</option>
          <option value="engineer">Engineer</option>
          <option value="technician">Technician</option>
        </select>
      </label>
      <input type="text" placeholder="ID Number (8 digits)" value={idNumber}
             onChange={e=>setIdNumber(e.target.value)} pattern="\d{8}" required/>
      <button type="submit" disabled={
    busy ||
    !username.trim()  ||  // no empty usernames
    !email.trim()     ||  // must have an email
    !password         ||
    password !== confirm ||  // ensure password === confirm
    !/^\d{8}$/.test(idNumber) // idNumber must be 8 digits
  }>
        {busy?'Creating…':'Create Account'}
      </button>
      {error   && <div style={styles.error  }>{error  }</div>}
      {message && <div style={styles.success}>{message}</div>}
      <Link to="/login">Already have an account? Log in</Link>
    </form>
  );
}

const styles = {
  form:    { display:'flex',flexDirection:'column',gap:12,maxWidth:320,margin:'auto',paddingTop:40 },
  error:   { color:'crimson',minHeight:24 },
  success: { color:'green',minHeight:24 }
};
