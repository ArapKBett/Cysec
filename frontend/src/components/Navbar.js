import React, { useState, useEffect } from 'react';

const Navbar = ({ activeTab, setActiveTab }) => {
  const [connectionStatus, setConnectionStatus] = useState('SECURE');
  const [systemLoad, setSystemLoad] = useState(Math.floor(Math.random() * 100));

  useEffect(() => {
    // Simulate system monitoring
    const interval = setInterval(() => {
      setSystemLoad(prev => {
        const change = (Math.random() - 0.5) * 20;
        return Math.max(0, Math.min(100, prev + change));
      });
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = () => {
    if (systemLoad < 30) return 'text-cyber-green';
    if (systemLoad < 70) return 'text-cyber-orange';
    return 'text-cyber-red';
  };

  return (
    <nav className="bg-gradient-to-r from-cyber-black via-cyber-dark to-cyber-gray border-b border-cyber-blue/30 backdrop-blur-sm sticky top-0 z-50 shadow-2xl">
      <div className="container mx-auto px-8 py-4">
        <div className="flex justify-between items-center">
          {/* Logo and Brand */}
          <div className="flex items-center space-x-4">
            <div className="relative">
              <img src="/logo.png" alt="CyberVault" className="h-12 w-12 rounded-full border-2 border-cyber-blue shadow-lg animate-pulse-slow" />
              <div className="absolute -top-1 -right-1 w-4 h-4 bg-cyber-green rounded-full animate-ping"></div>
            </div>
            <div>
              <span className="text-cyber-blue text-2xl font-bold font-cyber tracking-wider">
                CYBER<span className="text-cyber-green">VAULT</span>
              </span>
              <div className="text-xs text-cyber-light font-mono">
                SECURITY OPERATIONS CENTER
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="hidden md:flex space-x-8">
            <NavLink
              text="HOME"
              active={activeTab === 'home'}
              onClick={() => setActiveTab('home')}
            />
            <NavLink
              text="ENCRYPT"
              active={activeTab === 'encrypt'}
              onClick={() => setActiveTab('encrypt')}
            />
            <NavLink
              text="DECRYPT"
              active={activeTab === 'decrypt'}
              onClick={() => setActiveTab('decrypt')}
            />
            <NavLink
              text="NETWORK"
              active={activeTab === 'sniff'}
              onClick={() => setActiveTab('sniff')}
            />
          </div>

          {/* Status Panel */}
          <div className="flex items-center space-x-6">
            {/* Connection Status */}
            <div className="text-right">
              <div className="text-cyber-green text-sm font-bold font-mono">
                {connectionStatus}
              </div>
              <div className="text-xs text-cyber-light">
                CONNECTION
              </div>
            </div>

            {/* System Load */}
            <div className="text-right">
              <div className={`text-sm font-bold font-mono ${getStatusColor()}`}>
                {systemLoad.toFixed(0)}%
              </div>
              <div className="text-xs text-cyber-light">
                SYS LOAD
              </div>
            </div>

            {/* Power Indicator */}
            <div className="relative">
              <div className="w-3 h-3 bg-cyber-green rounded-full animate-pulse"></div>
              <div className="absolute inset-0 w-3 h-3 bg-cyber-green rounded-full animate-ping"></div>
            </div>
          </div>
        </div>

        {/* Mobile Menu Button */}
        <div className="md:hidden mt-4">
          <div className="flex justify-center space-x-6">
            <NavLink
              text="ENCRYPT"
              mobile
              active={activeTab === 'encrypt'}
              onClick={() => setActiveTab('encrypt')}
            />
            <NavLink
              text="DECRYPT"
              mobile
              active={activeTab === 'decrypt'}
              onClick={() => setActiveTab('decrypt')}
            />
            <NavLink
              text="NETWORK"
              mobile
              active={activeTab === 'sniff'}
              onClick={() => setActiveTab('sniff')}
            />
          </div>
        </div>
      </div>

      {/* Scanning Line Effect */}
      <div className="h-px bg-gradient-to-r from-transparent via-cyber-blue to-transparent relative overflow-hidden">
        <div className="absolute inset-0 bg-cyber-blue/50 animate-scan"></div>
      </div>
    </nav>
  );
};

const NavLink = ({ text, mobile = false, onClick, active = false }) => {
  return (
    <button
      onClick={onClick}
      className={`
        relative font-cyber font-bold tracking-wider transition-all duration-200
        ${mobile ? 'text-sm' : 'text-base'}
        ${active
          ? 'text-cyber-blue border-b-2 border-cyber-blue'
          : 'text-cyber-light hover:text-cyber-blue'
        }
        before:absolute before:bottom-0 before:left-0
        before:bg-cyber-blue before:transition-all before:duration-200
        hover:before:w-full
        ${active ? 'before:w-full before:h-0.5' : 'before:w-0 before:h-0.5'}
        after:absolute after:inset-0 after:border after:border-transparent
        hover:after:border-cyber-blue/20 after:transition-all after:duration-200
        after:rounded
      `}
    >
      {text}
    </button>
  );
};

export default Navbar;
