import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import './App.css';

// Icon components
const LockIcon = () => (
  <svg className="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
  </svg>
);

const UnlockIcon = () => (
  <svg className="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
  </svg>
);

const NetworkIcon = () => (
  <svg className="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
  </svg>
);

const LoadingSpinner = () => (
  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
  </svg>
);

const App = () => {
  const [encryptInput, setEncryptInput] = useState('');
  const [encryptOutput, setEncryptOutput] = useState('');
  const [encryptKey, setEncryptKey] = useState('');
  const [decryptInput, setDecryptInput] = useState('');
  const [decryptOutput, setDecryptOutput] = useState('');
  const [decryptKey, setDecryptKey] = useState('');
  const [sniffDevice, setSniffDevice] = useState('wlan0');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('encrypt');
  const [currentTime, setCurrentTime] = useState(new Date());
  const [apiStatus, setApiStatus] = useState('CHECKING...');

  // Update time every second for the cyber aesthetic
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Check API status on component mount
  useEffect(() => {
    const checkApiStatus = async () => {
      try {
        const res = await fetch('/api/v1/cyber/status');
        if (res.ok) {
          setApiStatus('OPERATIONAL');
        } else {
          setApiStatus('DEGRADED');
        }
      } catch (error) {
        setApiStatus('OFFLINE');
      }
    };
    checkApiStatus();
  }, []);

  const handleEncrypt = async () => {
    if (!encryptInput || !encryptOutput || !encryptKey) {
      setResponse('Error: All fields are required for encryption');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch('/api/v1/cyber/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          input: encryptInput,
          output: encryptOutput,
          key: encryptKey,
        }),
      });

      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }

      const data = await res.json();
      setResponse(JSON.stringify(data, null, 2));
    } catch (error) {
      setResponse('Error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    if (!decryptInput || !decryptOutput || !decryptKey) {
      setResponse('Error: All fields are required for decryption');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch('/api/v1/cyber/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          input: decryptInput,
          output: decryptOutput,
          key: decryptKey,
        }),
      });

      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }

      const data = await res.json();
      setResponse(JSON.stringify(data, null, 2));
    } catch (error) {
      setResponse('Error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSniff = async () => {
    if (!sniffDevice) {
      setResponse('Error: Network device is required');
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/cyber/network/scan?device=${encodeURIComponent(sniffDevice)}&duration=10`);

      if (!res.ok) {
        throw new Error(`HTTP error! status: ${res.status}`);
      }

      const data = await res.json();
      setResponse(JSON.stringify(data, null, 2));
    } catch (error) {
      setResponse('Error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-black via-cyber-dark to-cyber-gray bg-circuit flex flex-col font-cyber text-gray-100">
      <Navbar />

      {/* Header with cyber aesthetic */}
      <div className="bg-cyber-dark/90 backdrop-blur-sm border-b border-cyber-light/30">
        <div className="container mx-auto px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold text-cyber-blue animate-glow">
                CYBERVAULT
                <span className="text-cyber-green ml-2">CONTROL PANEL</span>
              </h1>
              <p className="text-cyber-light mt-2 font-mono text-sm">
                Advanced Security Operations Terminal v2.0
              </p>
            </div>
            <div className="text-right">
              <div className="text-cyber-blue font-mono text-sm">
                {currentTime.toLocaleTimeString()}
              </div>
              <div className={`font-mono text-xs ${
                apiStatus === 'OPERATIONAL' ? 'text-cyber-green' :
                apiStatus === 'DEGRADED' ? 'text-cyber-orange' : 'text-cyber-red'
              }`}>
                API: {apiStatus}
              </div>
            </div>
          </div>
        </div>
      </div>

      <main className="container mx-auto p-8 flex-grow">
        {/* Tab Navigation */}
        <div className="flex mb-8 bg-cyber-gray/30 p-2 rounded-lg border border-cyber-light/20">
          <button
            data-tab="encrypt"
            onClick={() => setActiveTab('encrypt')}
            className={`flex items-center px-6 py-3 rounded-md transition-all duration-200 ${
              activeTab === 'encrypt'
                ? 'bg-cyber-blue text-cyber-black shadow-lg'
                : 'text-cyber-light hover:text-cyber-blue hover:bg-cyber-light/10'
            }`}
          >
            <LockIcon />
            ENCRYPT
          </button>
          <button
            data-tab="decrypt"
            onClick={() => setActiveTab('decrypt')}
            className={`flex items-center px-6 py-3 rounded-md transition-all duration-200 ${
              activeTab === 'decrypt'
                ? 'bg-cyber-green text-cyber-black shadow-lg'
                : 'text-cyber-light hover:text-cyber-green hover:bg-cyber-light/10'
            }`}
          >
            <UnlockIcon />
            DECRYPT
          </button>
          <button
            data-tab="sniff"
            onClick={() => setActiveTab('sniff')}
            className={`flex items-center px-6 py-3 rounded-md transition-all duration-200 ${
              activeTab === 'sniff'
                ? 'bg-cyber-orange text-cyber-black shadow-lg'
                : 'text-cyber-light hover:text-cyber-orange hover:bg-cyber-light/10'
            }`}
          >
            <NetworkIcon />
            NETWORK SCAN
          </button>
        </div>

        {/* Encryption Section */}
        {activeTab === 'encrypt' && (
          <div className="bg-gradient-to-r from-cyber-gray/40 to-cyber-light/20 p-8 rounded-xl border border-cyber-blue/30 shadow-2xl backdrop-blur-sm mb-8">
            <h2 className="text-2xl font-bold mb-6 text-cyber-blue flex items-center">
              <LockIcon />
              FILE ENCRYPTION MODULE
            </h2>
            <div className="grid gap-4">
              <input
                type="text"
                placeholder="Source File Path"
                className="bg-cyber-dark/60 border border-cyber-blue/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-blue focus:outline-none focus:ring-2 focus:ring-cyber-blue/50 font-mono"
                value={encryptInput}
                onChange={(e) => setEncryptInput(e.target.value)}
              />
              <input
                type="text"
                placeholder="Encrypted Output Path"
                className="bg-cyber-dark/60 border border-cyber-blue/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-blue focus:outline-none focus:ring-2 focus:ring-cyber-blue/50 font-mono"
                value={encryptOutput}
                onChange={(e) => setEncryptOutput(e.target.value)}
              />
              <input
                type="password"
                placeholder="Encryption Key (max 31 chars)"
                maxLength="31"
                className="bg-cyber-dark/60 border border-cyber-blue/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-blue focus:outline-none focus:ring-2 focus:ring-cyber-blue/50 font-mono"
                value={encryptKey}
                onChange={(e) => setEncryptKey(e.target.value)}
              />
              <button
                onClick={handleEncrypt}
                disabled={loading}
                className="bg-gradient-to-r from-cyber-blue to-blue-600 text-white p-4 rounded-lg hover:from-blue-600 hover:to-cyber-blue transition-all duration-200 font-bold flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
              >
                {loading ? <LoadingSpinner /> : <LockIcon />}
                {loading ? 'ENCRYPTING...' : 'INITIATE ENCRYPTION'}
              </button>
            </div>
          </div>
        )}

        {/* Decryption Section */}
        {activeTab === 'decrypt' && (
          <div className="bg-gradient-to-r from-cyber-gray/40 to-cyber-light/20 p-8 rounded-xl border border-cyber-green/30 shadow-2xl backdrop-blur-sm mb-8">
            <h2 className="text-2xl font-bold mb-6 text-cyber-green flex items-center">
              <UnlockIcon />
              FILE DECRYPTION MODULE
            </h2>
            <div className="grid gap-4">
              <input
                type="text"
                placeholder="Encrypted File Path"
                className="bg-cyber-dark/60 border border-cyber-green/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-green focus:outline-none focus:ring-2 focus:ring-cyber-green/50 font-mono"
                value={decryptInput}
                onChange={(e) => setDecryptInput(e.target.value)}
              />
              <input
                type="text"
                placeholder="Decrypted Output Path"
                className="bg-cyber-dark/60 border border-cyber-green/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-green focus:outline-none focus:ring-2 focus:ring-cyber-green/50 font-mono"
                value={decryptOutput}
                onChange={(e) => setDecryptOutput(e.target.value)}
              />
              <input
                type="password"
                placeholder="Decryption Key (max 31 chars)"
                maxLength="31"
                className="bg-cyber-dark/60 border border-cyber-green/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-green focus:outline-none focus:ring-2 focus:ring-cyber-green/50 font-mono"
                value={decryptKey}
                onChange={(e) => setDecryptKey(e.target.value)}
              />
              <button
                onClick={handleDecrypt}
                disabled={loading}
                className="bg-gradient-to-r from-cyber-green to-green-600 text-black p-4 rounded-lg hover:from-green-600 hover:to-cyber-green transition-all duration-200 font-bold flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
              >
                {loading ? <LoadingSpinner /> : <UnlockIcon />}
                {loading ? 'DECRYPTING...' : 'INITIATE DECRYPTION'}
              </button>
            </div>
          </div>
        )}

        {/* Packet Sniffing Section */}
        {activeTab === 'sniff' && (
          <div className="bg-gradient-to-r from-cyber-gray/40 to-cyber-light/20 p-8 rounded-xl border border-cyber-orange/30 shadow-2xl backdrop-blur-sm mb-8">
            <h2 className="text-2xl font-bold mb-6 text-cyber-orange flex items-center">
              <NetworkIcon />
              NETWORK PACKET ANALYZER
            </h2>
            <div className="grid gap-4">
              <input
                type="text"
                placeholder="Network Interface (e.g., wlan0, eth0)"
                className="bg-cyber-dark/60 border border-cyber-orange/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-orange focus:outline-none focus:ring-2 focus:ring-cyber-orange/50 font-mono"
                value={sniffDevice}
                onChange={(e) => setSniffDevice(e.target.value)}
              />
              <button
                onClick={handleSniff}
                disabled={loading}
                className="bg-gradient-to-r from-cyber-orange to-orange-600 text-black p-4 rounded-lg hover:from-orange-600 hover:to-cyber-orange transition-all duration-200 font-bold flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed shadow-lg"
              >
                {loading ? <LoadingSpinner /> : <NetworkIcon />}
                {loading ? 'ANALYZING NETWORK...' : 'START NETWORK SCAN'}
              </button>
            </div>
          </div>
        )}

        {/* Response Terminal */}
        {response && (
          <div className="bg-cyber-black/80 border border-cyber-blue/30 p-6 rounded-xl shadow-2xl backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-cyber-blue">SYSTEM RESPONSE</h3>
              <button
                onClick={() => setResponse('')}
                className="text-cyber-red hover:text-red-400 transition-colors"
              >
                ✕ CLEAR
              </button>
            </div>
            <div className="bg-black/60 p-4 rounded-lg border border-cyber-green/20 overflow-auto max-h-96">
              <pre className="text-cyber-green font-mono text-sm whitespace-pre-wrap">{response}</pre>
            </div>
          </div>
        )}
      </main>

      <Footer />
    </div>
  );
};

export default App;
