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

const PathSuggestion = ({ label, path, onClick, color = "cyber-blue" }) => (
  <button
    onClick={() => onClick(path)}
    className={`px-3 py-1 text-xs border border-${color}/30 bg-${color}/10 text-${color} rounded hover:bg-${color}/20 transition-colors`}
  >
    {label}
  </button>
);

const CommonPaths = {
  input: [
    { label: "Documents", path: "/home/user/Documents/document.pdf" },
    { label: "Downloads", path: "/home/user/Downloads/file.zip" },
    { label: "Desktop", path: "/home/user/Desktop/important.txt" },
    { label: "Temp", path: "/tmp/test_file.txt" },
    { label: "Current Dir", path: "./sensitive_data.doc" }
  ],
  output: [
    { label: "Encrypted", path: "/tmp/encrypted_file.enc" },
    { label: "Secure Dir", path: "/home/user/Documents/secure/file.enc" },
    { label: "Backup", path: "/backup/encrypted_backup.enc" },
    { label: "Desktop", path: "/home/user/Desktop/encrypted.enc" },
    { label: "Downloads", path: "/home/user/Downloads/output.enc" }
  ]
};

// File Browser Component
const FileBrowser = ({
  isOpen,
  onClose,
  currentPath,
  directories,
  files,
  onSelectFile,
  onSelectDirectory,
  onBrowsePath,
  mode
}) => {
  if (!isOpen) return null;

  const isOutputMode = mode.includes('output');

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
      <div className="bg-cyber-dark border border-cyber-blue/50 rounded-lg p-6 max-w-4xl w-full max-h-[80vh] overflow-hidden">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-xl font-bold text-cyber-blue">
            📁 Select {isOutputMode ? 'Output Location' : 'File'}
          </h3>
          <button
            onClick={onClose}
            className="text-cyber-red hover:text-red-400 text-2xl font-bold"
          >
            ✕
          </button>
        </div>

        {/* Current Path */}
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-cyber-light text-sm">Current Path:</span>
            <code className="bg-cyber-black/60 px-2 py-1 rounded text-cyber-green text-sm">
              {currentPath}
            </code>
          </div>

          {/* Quick Path Navigation */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => onBrowsePath('/tmp')}
              className="px-3 py-1 bg-cyber-blue/20 text-cyber-blue border border-cyber-blue/30 rounded text-sm hover:bg-cyber-blue/30"
            >
              /tmp
            </button>
            <button
              onClick={() => onBrowsePath('/home')}
              className="px-3 py-1 bg-cyber-green/20 text-cyber-green border border-cyber-green/30 rounded text-sm hover:bg-cyber-green/30"
            >
              /home
            </button>
            <button
              onClick={() => onBrowsePath('/var')}
              className="px-3 py-1 bg-cyber-orange/20 text-cyber-orange border border-cyber-orange/30 rounded text-sm hover:bg-cyber-orange/30"
            >
              /var
            </button>
          </div>
        </div>

        {/* File/Directory List */}
        <div className="bg-cyber-black/40 border border-cyber-light/20 rounded max-h-96 overflow-y-auto">
          {/* Directories */}
          {directories.map((dir, index) => (
            <div
              key={`dir-${index}`}
              onClick={() => onSelectDirectory(dir.path)}
              className="flex items-center gap-3 p-3 border-b border-cyber-light/10 hover:bg-cyber-blue/10 cursor-pointer"
            >
              <span className="text-cyber-blue text-lg">📁</span>
              <span className="text-cyber-light">{dir.name}</span>
              {!dir.readable && <span className="text-cyber-red text-xs">🚫</span>}
            </div>
          ))}

          {/* Files */}
          {files.map((file, index) => (
            <div
              key={`file-${index}`}
              onClick={() => onSelectFile(file.path)}
              className="flex items-center justify-between p-3 border-b border-cyber-light/10 hover:bg-cyber-green/10 cursor-pointer"
            >
              <div className="flex items-center gap-3">
                <span className="text-cyber-green text-lg">📄</span>
                <span className="text-cyber-light">{file.name}</span>
                {file.extension && (
                  <span className="text-cyber-orange text-xs bg-cyber-orange/20 px-2 py-1 rounded">
                    .{file.extension}
                  </span>
                )}
              </div>
              <div className="text-xs text-cyber-light">
                {(file.size / 1024).toFixed(1)} KB
              </div>
            </div>
          ))}

          {directories.length === 0 && files.length === 0 && (
            <div className="p-8 text-center text-cyber-light">
              📂 No files or directories found
            </div>
          )}
        </div>

        {/* Custom Path Input */}
        {isOutputMode && (
          <div className="mt-4">
            <label className="block text-cyber-light text-sm mb-2">Or enter custom path:</label>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="/tmp/custom_output.enc"
                className="flex-1 bg-cyber-dark/60 border border-cyber-blue/30 p-2 rounded text-gray-100 placeholder-cyber-light/60 focus:border-cyber-blue focus:outline-none text-sm font-mono"
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    onSelectFile(e.target.value);
                  }
                }}
              />
              <button
                onClick={(e) => {
                  const input = e.target.previousElementSibling;
                  if (input.value) onSelectFile(input.value);
                }}
                className="px-4 py-2 bg-cyber-blue text-cyber-black rounded hover:bg-blue-400 text-sm font-bold"
              >
                Use Path
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const App = () => {
  const [encryptInput, setEncryptInput] = useState('/tmp/document.txt');
  const [encryptOutput, setEncryptOutput] = useState('/tmp/document.txt.enc');
  const [encryptKey, setEncryptKey] = useState('');
  const [decryptInput, setDecryptInput] = useState('/tmp/document.txt.enc');
  const [decryptOutput, setDecryptOutput] = useState('/tmp/document_decrypted.txt');
  const [decryptKey, setDecryptKey] = useState('');
  const [sniffDevice, setSniffDevice] = useState('auto');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('home');
  const [currentTime, setCurrentTime] = useState(new Date());
  const [apiStatus, setApiStatus] = useState('CHECKING...');
  const [showFileBrowser, setShowFileBrowser] = useState(false);
  const [browserMode, setBrowserMode] = useState(''); // 'encrypt-input', 'encrypt-output', 'decrypt-input', 'decrypt-output'
  const [currentPath, setCurrentPath] = useState('/tmp');
  const [browserFiles, setBrowserFiles] = useState([]);
  const [browserDirectories, setBrowserDirectories] = useState([]);

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

  // File browser functions
  const browseFiles = async (path = '/tmp') => {
    try {
      const res = await fetch(`/api/v1/cyber/files/browse?path=${encodeURIComponent(path)}`);
      const data = await res.json();

      if (data.success) {
        setCurrentPath(data.current_path);
        setBrowserDirectories(data.directories || []);
        setBrowserFiles(data.files || []);
      } else {
        setResponse('Error browsing files: ' + data.message);
      }
    } catch (error) {
      setResponse('Error browsing files: ' + error.message);
    }
  };

  const openFileBrowser = (mode) => {
    setBrowserMode(mode);
    setShowFileBrowser(true);
    browseFiles('/tmp');
  };

  const selectFile = (filePath) => {
    switch (browserMode) {
      case 'encrypt-input':
        setEncryptInput(filePath);
        break;
      case 'encrypt-output':
        setEncryptOutput(filePath);
        break;
      case 'decrypt-input':
        setDecryptInput(filePath);
        break;
      case 'decrypt-output':
        setDecryptOutput(filePath);
        break;
    }
    setShowFileBrowser(false);
  };

  const selectDirectory = (dirPath) => {
    if (dirPath === currentPath) return;
    browseFiles(dirPath);
  };

  const handleFileUpload = (event, mode) => {
    const file = event.target.files[0];
    if (file) {
      // For demo purposes, we'll use the filename with a temporary path
      const tempPath = `/tmp/${file.name}`;
      switch (mode) {
        case 'encrypt-input':
          setEncryptInput(tempPath);
          break;
        case 'decrypt-input':
          setDecryptInput(tempPath);
          break;
      }
      // Note: In a real implementation, you'd upload the file to the server
      setResponse(`File "${file.name}" selected. Note: File upload simulation - actual file would be uploaded to server.`);
    }
  };

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

      // Enhanced response formatting for network analysis
      if (data.scan_result) {
        try {
          const scanData = JSON.parse(data.scan_result);
          let formattedResponse = `🌐 NETWORK SCAN RESULTS\n`;
          formattedResponse += `═══════════════════════════════════════\n\n`;

          if (scanData.network_analysis) {
            const analysis = scanData.network_analysis;

            formattedResponse += `📊 PACKET STATISTICS:\n`;
            formattedResponse += `   Total Packets: ${analysis.packet_stats?.total_packets || 0}\n`;
            formattedResponse += `   Total Bytes: ${analysis.packet_stats?.total_bytes || 0}\n`;
            formattedResponse += `   TCP: ${analysis.packet_stats?.tcp_packets || 0} | UDP: ${analysis.packet_stats?.udp_packets || 0} | ICMP: ${analysis.packet_stats?.icmp_packets || 0}\n\n`;

            if (analysis.interfaces && analysis.interfaces.length > 0) {
              formattedResponse += `🔌 NETWORK INTERFACES:\n`;
              analysis.interfaces.forEach(iface => {
                formattedResponse += `   ${iface.name}: ${iface.ip} (${iface.active ? 'ACTIVE' : 'INACTIVE'})\n`;
              });
              formattedResponse += '\n';
            }

            if (analysis.top_sources && analysis.top_sources.length > 0) {
              formattedResponse += `📤 TOP SOURCE IPs:\n`;
              analysis.top_sources.forEach(src => {
                formattedResponse += `   ${src.ip}: ${src.packets} packets\n`;
              });
              formattedResponse += '\n';
            }

            if (analysis.top_destinations && analysis.top_destinations.length > 0) {
              formattedResponse += `📥 TOP DESTINATION IPs:\n`;
              analysis.top_destinations.forEach(dest => {
                formattedResponse += `   ${dest.ip}: ${dest.packets} packets\n`;
              });
              formattedResponse += '\n';
            }

            if (analysis.top_ports && analysis.top_ports.length > 0) {
              formattedResponse += `🔌 TOP PORTS:\n`;
              analysis.top_ports.forEach(port => {
                formattedResponse += `   Port ${port.port}: ${port.packets} packets\n`;
              });
            }
          }

          setResponse(formattedResponse);
        } catch (parseError) {
          // Fallback to raw JSON if parsing fails
          setResponse(JSON.stringify(data, null, 2));
        }
      } else {
        setResponse(JSON.stringify(data, null, 2));
      }
    } catch (error) {
      setResponse('Error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-black via-cyber-dark to-cyber-gray bg-circuit flex flex-col font-cyber text-gray-100">
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

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

        {/* Home/Dashboard Section */}
        {activeTab === 'home' && (
          <div className="bg-gradient-to-r from-cyber-gray/40 to-cyber-light/20 p-8 rounded-xl border border-cyber-green/30 shadow-2xl backdrop-blur-sm mb-8">
            <h2 className="text-3xl font-bold mb-6 text-cyber-green text-center">
              🚀 WELCOME TO CYBERVAULT
            </h2>
            <div className="grid md:grid-cols-3 gap-6 mb-8">
              <div className="bg-cyber-dark/60 p-6 rounded-lg border border-cyber-blue/30">
                <div className="flex items-center mb-4">
                  <LockIcon />
                  <h3 className="text-xl font-bold text-cyber-blue">FILE ENCRYPTION</h3>
                </div>
                <p className="text-cyber-light text-sm">
                  Secure your files with military-grade AES encryption. Protect sensitive data from unauthorized access.
                </p>
                <button
                  onClick={() => setActiveTab('encrypt')}
                  className="mt-4 bg-cyber-blue text-cyber-black px-4 py-2 rounded font-bold hover:bg-blue-400 transition-colors"
                >
                  START ENCRYPTION
                </button>
              </div>
              <div className="bg-cyber-dark/60 p-6 rounded-lg border border-cyber-green/30">
                <div className="flex items-center mb-4">
                  <UnlockIcon />
                  <h3 className="text-xl font-bold text-cyber-green">FILE DECRYPTION</h3>
                </div>
                <p className="text-cyber-light text-sm">
                  Decrypt your protected files safely. Restore access to your encrypted data with the correct key.
                </p>
                <button
                  onClick={() => setActiveTab('decrypt')}
                  className="mt-4 bg-cyber-green text-cyber-black px-4 py-2 rounded font-bold hover:bg-green-400 transition-colors"
                >
                  START DECRYPTION
                </button>
              </div>
              <div className="bg-cyber-dark/60 p-6 rounded-lg border border-cyber-orange/30">
                <div className="flex items-center mb-4">
                  <NetworkIcon />
                  <h3 className="text-xl font-bold text-cyber-orange">NETWORK ANALYSIS</h3>
                </div>
                <p className="text-cyber-light text-sm">
                  Monitor network traffic and analyze packet data. Essential for security assessments and monitoring.
                </p>
                <button
                  onClick={() => setActiveTab('sniff')}
                  className="mt-4 bg-cyber-orange text-cyber-black px-4 py-2 rounded font-bold hover:bg-orange-400 transition-colors"
                >
                  START SCAN
                </button>
              </div>
            </div>

            {/* System Status Dashboard */}
            <div className="bg-cyber-black/60 p-6 rounded-lg border border-cyber-light/20">
              <h3 className="text-xl font-bold text-cyber-light mb-4">SYSTEM STATUS</h3>
              <div className="grid md:grid-cols-4 gap-4 text-center">
                <div className="bg-cyber-gray/30 p-4 rounded">
                  <div className="text-2xl font-bold text-cyber-green">{currentTime.toLocaleTimeString()}</div>
                  <div className="text-xs text-cyber-light">SYSTEM TIME</div>
                </div>
                <div className="bg-cyber-gray/30 p-4 rounded">
                  <div className={`text-2xl font-bold ${
                    apiStatus === 'OPERATIONAL' ? 'text-cyber-green' :
                    apiStatus === 'DEGRADED' ? 'text-cyber-orange' : 'text-cyber-red'
                  }`}>
                    {apiStatus}
                  </div>
                  <div className="text-xs text-cyber-light">API STATUS</div>
                </div>
                <div className="bg-cyber-gray/30 p-4 rounded">
                  <div className="text-2xl font-bold text-cyber-blue">v2.0.0</div>
                  <div className="text-xs text-cyber-light">VERSION</div>
                </div>
                <div className="bg-cyber-gray/30 p-4 rounded">
                  <div className="text-2xl font-bold text-cyber-orange">SECURE</div>
                  <div className="text-xs text-cyber-light">ENCRYPTION</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Encryption Section */}
        {activeTab === 'encrypt' && (
          <div className="bg-gradient-to-r from-cyber-gray/40 to-cyber-light/20 p-8 rounded-xl border border-cyber-blue/30 shadow-2xl backdrop-blur-sm mb-8">
            <h2 className="text-2xl font-bold mb-6 text-cyber-blue flex items-center">
              <LockIcon />
              FILE ENCRYPTION MODULE
            </h2>
            <div className="grid gap-4">
              <div>
                <label className="block text-cyber-light text-sm mb-2">Source File Path</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Source File Path"
                    className="flex-1 bg-cyber-dark/60 border border-cyber-blue/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-blue focus:outline-none focus:ring-2 focus:ring-cyber-blue/50 font-mono"
                    value={encryptInput}
                    onChange={(e) => setEncryptInput(e.target.value)}
                  />
                  <button
                    onClick={() => openFileBrowser('encrypt-input')}
                    className="px-4 py-4 bg-cyber-blue/20 border border-cyber-blue/50 text-cyber-blue rounded-lg hover:bg-cyber-blue/30 transition-colors"
                    title="Browse Files"
                  >
                    📁
                  </button>
                  <label className="px-4 py-4 bg-cyber-green/20 border border-cyber-green/50 text-cyber-green rounded-lg hover:bg-cyber-green/30 transition-colors cursor-pointer" title="Upload File">
                    📤
                    <input
                      type="file"
                      className="hidden"
                      onChange={(e) => handleFileUpload(e, 'encrypt-input')}
                    />
                  </label>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  <span className="text-xs text-cyber-light">Quick paths:</span>
                  {CommonPaths.input.map((item, index) => (
                    <PathSuggestion
                      key={index}
                      label={item.label}
                      path={item.path}
                      onClick={setEncryptInput}
                      color="cyber-blue"
                    />
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-cyber-light text-sm mb-2">Encrypted Output Path</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Encrypted Output Path"
                    className="flex-1 bg-cyber-dark/60 border border-cyber-blue/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-blue focus:outline-none focus:ring-2 focus:ring-cyber-blue/50 font-mono"
                    value={encryptOutput}
                    onChange={(e) => setEncryptOutput(e.target.value)}
                  />
                  <button
                    onClick={() => openFileBrowser('encrypt-output')}
                    className="px-4 py-4 bg-cyber-blue/20 border border-cyber-blue/50 text-cyber-blue rounded-lg hover:bg-cyber-blue/30 transition-colors"
                    title="Browse Folders"
                  >
                    📂
                  </button>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  <span className="text-xs text-cyber-light">Quick paths:</span>
                  {CommonPaths.output.map((item, index) => (
                    <PathSuggestion
                      key={index}
                      label={item.label}
                      path={item.path}
                      onClick={setEncryptOutput}
                      color="cyber-blue"
                    />
                  ))}
                </div>
              </div>
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
              <div>
                <label className="block text-cyber-light text-sm mb-2">Encrypted File Path</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Encrypted File Path"
                    className="flex-1 bg-cyber-dark/60 border border-cyber-green/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-green focus:outline-none focus:ring-2 focus:ring-cyber-green/50 font-mono"
                    value={decryptInput}
                    onChange={(e) => setDecryptInput(e.target.value)}
                  />
                  <button
                    onClick={() => openFileBrowser('decrypt-input')}
                    className="px-4 py-4 bg-cyber-green/20 border border-cyber-green/50 text-cyber-green rounded-lg hover:bg-cyber-green/30 transition-colors"
                    title="Browse Files"
                  >
                    📁
                  </button>
                  <label className="px-4 py-4 bg-cyber-orange/20 border border-cyber-orange/50 text-cyber-orange rounded-lg hover:bg-cyber-orange/30 transition-colors cursor-pointer" title="Upload Encrypted File">
                    📤
                    <input
                      type="file"
                      className="hidden"
                      onChange={(e) => handleFileUpload(e, 'decrypt-input')}
                    />
                  </label>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  <span className="text-xs text-cyber-light">Quick paths:</span>
                  {CommonPaths.output.map((item, index) => (
                    <PathSuggestion
                      key={index}
                      label={item.label}
                      path={item.path}
                      onClick={setDecryptInput}
                      color="cyber-green"
                    />
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-cyber-light text-sm mb-2">Decrypted Output Path</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Decrypted Output Path"
                    className="flex-1 bg-cyber-dark/60 border border-cyber-green/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-green focus:outline-none focus:ring-2 focus:ring-cyber-green/50 font-mono"
                    value={decryptOutput}
                    onChange={(e) => setDecryptOutput(e.target.value)}
                  />
                  <button
                    onClick={() => openFileBrowser('decrypt-output')}
                    className="px-4 py-4 bg-cyber-green/20 border border-cyber-green/50 text-cyber-green rounded-lg hover:bg-cyber-green/30 transition-colors"
                    title="Browse Folders"
                  >
                    📂
                  </button>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  <span className="text-xs text-cyber-light">Quick paths:</span>
                  {CommonPaths.input.map((item, index) => (
                    <PathSuggestion
                      key={index}
                      label={item.label}
                      path={item.path.replace('.enc', '_decrypted.txt')}
                      onClick={setDecryptOutput}
                      color="cyber-green"
                    />
                  ))}
                </div>
              </div>
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
              <div>
                <label className="block text-cyber-light text-sm mb-2">Network Interface</label>
                <input
                  type="text"
                  placeholder="Network Interface (auto-detect or specify: eth0, wlan0)"
                  className="w-full bg-cyber-dark/60 border border-cyber-orange/30 p-4 rounded-lg text-gray-100 placeholder-cyber-light/60 focus:border-cyber-orange focus:outline-none focus:ring-2 focus:ring-cyber-orange/50 font-mono"
                  value={sniffDevice}
                  onChange={(e) => setSniffDevice(e.target.value)}
                />
                <div className="flex flex-wrap gap-2 mt-2">
                  <span className="text-xs text-cyber-light">Quick options:</span>
                  <PathSuggestion label="Auto-detect" path="auto" onClick={setSniffDevice} color="cyber-orange" />
                  <PathSuggestion label="Ethernet" path="eth0" onClick={setSniffDevice} color="cyber-orange" />
                  <PathSuggestion label="WiFi" path="wlan0" onClick={setSniffDevice} color="cyber-orange" />
                  <PathSuggestion label="Docker" path="docker0" onClick={setSniffDevice} color="cyber-orange" />
                  <PathSuggestion label="Bridge" path="virbr0" onClick={setSniffDevice} color="cyber-orange" />
                </div>
                <div className="bg-cyber-dark/40 p-3 rounded mt-2 border border-cyber-orange/20">
                  <p className="text-xs text-cyber-light">
                    <strong className="text-cyber-orange">Enhanced Network Scanning:</strong> Automatically detects all network interfaces,
                    analyzes packet types (TCP/UDP/ICMP), tracks top source/destination IPs, monitors common ports,
                    and provides comprehensive network activity statistics.
                  </p>
                </div>
              </div>
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

      {/* File Browser Modal */}
      <FileBrowser
        isOpen={showFileBrowser}
        onClose={() => setShowFileBrowser(false)}
        currentPath={currentPath}
        directories={browserDirectories}
        files={browserFiles}
        onSelectFile={selectFile}
        onSelectDirectory={selectDirectory}
        onBrowsePath={browseFiles}
        mode={browserMode}
      />
    </div>
  );
};

export default App;
