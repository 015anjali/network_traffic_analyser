import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import NavBar from './components/NavBar';
import Login from './components/Auth/Login';
import Home from './pages/Home';
import Live from './pages/Live';
import Upload from './pages/Upload';
import History from './pages/History';
import Devices from './pages/Devices';
import DeviceDetails from './pages/DeviceDetails';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Check for existing session
    const savedAuth = localStorage.getItem('netflow_auth');
    const savedUser = localStorage.getItem('netflow_user');
    
    if (savedAuth === 'true' && savedUser) {
      setIsAuthenticated(true);
      setUser(JSON.parse(savedUser));
    }
  }, []);

  const handleLogin = (userData) => {
    setIsAuthenticated(true);
    setUser(userData);
    localStorage.setItem('netflow_auth', 'true');
    localStorage.setItem('netflow_user', JSON.stringify(userData));
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUser(null);
    localStorage.removeItem('netflow_auth');
    localStorage.removeItem('netflow_user');
  };

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <Login onLogin={handleLogin} />
      </div>
    );
  }

  return (
    <Router>
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <NavBar user={user} onLogout={handleLogout} />
        <main className="pt-16">
          <AnimatePresence mode="wait">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/live" element={<Live />} />
              <Route path="/upload" element={<Upload />} />
              <Route path="/history" element={<History />} />
              <Route path="/devices" element={<Devices />} />
              <Route path="/devices/:device_id" element={<DeviceDetails />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </AnimatePresence>
        </main>
      </div>
    </Router>
  );
}

export default App;