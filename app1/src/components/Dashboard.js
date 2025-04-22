import { useEffect, useState } from 'react';
import { getToken, logout as clientLogout } from '../auth';
import { useNavigate } from 'react-router-dom';

export default function Dashboard() {
  const [me, setMe] = useState(null);
  const navigate    = useNavigate();

  useEffect(() => {
    const token = getToken();
    if (!token) {
      return navigate('/login');
    }

    fetch('http://localhost:4000/me', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => {
        if (!r.ok) {
          clientLogout();
          navigate('/login');
        }
        return r.json();
      })
      .then(setMe)
      .catch(() => {
        clientLogout();
        navigate('/login');
      });
  }, [navigate]);

  if (!me) return <>Loading…</>;

  const handleLogout = async () => {
    const token = getToken();
    if (token) {
      // tell the server to log the logout event
      await fetch('http://localhost:4000/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      }).catch(() => { /* ignore network errors */ });
    }
    // clear the stored token and navigate back
    clientLogout();
    navigate('/login');
  };

  return (
    <div style={styles.container}>
      <h2>Welcome {me.username} 🎉</h2>
      <p>Dept: {me.department} — Role: {me.role} — ID: {me.idNumber}</p>
      <button onClick={handleLogout} style={styles.btn}>Logout</button>
    </div>
  );
}

const styles = {
  container: { textAlign: 'center', paddingTop: 40 },
  btn: { marginTop: 20, padding: '8px 12px', cursor: 'pointer' },
};
