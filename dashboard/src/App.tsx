import { Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Layout from './components/Layout';
import Overview from './pages/Overview';
import AuditLog from './pages/AuditLog';
import Policies from './pages/Policies';
import Enclave from './pages/Enclave';
import Login from './pages/Login';

function App() {
  const [apiKey, setApiKey] = useState<string | null>(() => 
    localStorage.getItem('clawguard_api_key')
  );

  useEffect(() => {
    if (apiKey) {
      localStorage.setItem('clawguard_api_key', apiKey);
    } else {
      localStorage.removeItem('clawguard_api_key');
    }
  }, [apiKey]);

  if (!apiKey) {
    return <Login onLogin={setApiKey} />;
  }

  return (
    <Layout apiKey={apiKey} onLogout={() => setApiKey(null)}>
      <Routes>
        <Route path="/" element={<Overview apiKey={apiKey} />} />
        <Route path="/audit" element={<AuditLog apiKey={apiKey} />} />
        <Route path="/policies" element={<Policies apiKey={apiKey} />} />
        <Route path="/enclave" element={<Enclave apiKey={apiKey} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

export default App;
