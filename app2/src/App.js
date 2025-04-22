import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login       from './components/Login';
import Register    from './components/Register';
import Dashboard   from './components/Dashboard';
import SSOListener from './components/SSOListener';

function RequireAuth({ children }) {
  return (
    <>
      <SSOListener />
      {children}
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"            element={<Navigate to="/login" replace />} />
        <Route path="/login"       element={<Login />} />
        <Route path="/register"    element={<Register />} />
        <Route path="/dashboard"   element={
          <RequireAuth>
            <Dashboard />
          </RequireAuth>
        }/>
        <Route path="*"            element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
