import React, { useState, useEffect } from 'react';

const Footer = () => {
  const [uptime, setUptime] = useState('00:00:00');
  const [startTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      const diff = now - startTime;
      const hours = Math.floor(diff / 3600000).toString().padStart(2, '0');
      const minutes = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0');
      const seconds = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0');
      setUptime(`${hours}:${minutes}:${seconds}`);
    }, 1000);

    return () => clearInterval(timer);
  }, [startTime]);

  return (
    <footer className="bg-gradient-to-r from-cyber-black via-cyber-dark to-cyber-gray border-t border-cyber-blue/30 backdrop-blur-sm">
      {/* Top scanning line */}
      <div className="h-px bg-gradient-to-r from-transparent via-cyber-green to-transparent relative overflow-hidden">
        <div className="absolute inset-0 bg-cyber-green/50 animate-scan"></div>
      </div>

      <div className="container mx-auto px-8 py-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          {/* Left Section - Copyright */}
          <div className="text-center md:text-left">
            <p className="text-cyber-blue font-cyber font-bold text-lg">
              CYBERVAULT
            </p>
            <p className="text-cyber-light text-sm font-mono">
              &copy; 2025 Arap Bett. All Rights Reserved.
            </p>
            <p className="text-cyber-green text-xs font-mono mt-1">
              SECURITY OPERATIONS TERMINAL
            </p>
          </div>

          {/* Center Section - Tech Stack */}
          <div className="text-center">
            <p className="text-cyber-orange text-sm font-bold mb-2">
              POWERED BY
            </p>
            <div className="flex justify-center space-x-2 text-xs font-mono">
              <TechBadge text="C" color="cyber-blue" />
              <TechBadge text="C++" color="cyber-green" />
              <TechBadge text="JAVA" color="cyber-orange" />
              <TechBadge text="REACT" color="cyber-purple" />
              <TechBadge text="TAILWIND" color="cyber-blue" />
            </div>
          </div>

          {/* Right Section - System Info */}
          <div className="text-center md:text-right">
            <div className="space-y-1 text-xs font-mono">
              <div className="flex items-center justify-center md:justify-end space-x-2">
                <span className="text-cyber-light">UPTIME:</span>
                <span className="text-cyber-green">{uptime}</span>
              </div>
              <div className="flex items-center justify-center md:justify-end space-x-2">
                <span className="text-cyber-light">VERSION:</span>
                <span className="text-cyber-blue">2.0.SECURE</span>
              </div>
              <div className="flex items-center justify-center md:justify-end space-x-2">
                <span className="text-cyber-light">STATUS:</span>
                <div className="flex items-center space-x-1">
                  <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse"></div>
                  <span className="text-cyber-green">OPERATIONAL</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Warning */}
        <div className="mt-6 pt-4 border-t border-cyber-light/20">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-2 text-cyber-orange text-xs font-mono">
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              <span>AUTHORIZED PERSONNEL ONLY • SECURITY MONITORING ACTIVE</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

const TechBadge = ({ text, color }) => {
  return (
    <span className={`px-2 py-1 bg-${color}/20 text-${color} border border-${color}/30 rounded text-xs`}>
      {text}
    </span>
  );
};

export default Footer;
